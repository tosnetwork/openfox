package servicebridge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	maxTOSCTLBytes       = 512 << 20
	maxLifecycleOutput   = 64 << 10
	defaultLifecycleTime = 2 * time.Minute
)

var walletNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// LifecycleSender sends the Service Actor lifecycle messages a rail party
// needs after the call: respond (provider), expire and claim_refund (buyer).
// Every message is signed by a wallet inside tosctl custody.
type LifecycleSender interface {
	Respond(ctx context.Context, actor string, requestID uint64, responseHash [32]byte, attestorController string) error
	Expire(ctx context.Context, actor string, requestID uint64) error
	ClaimRefund(ctx context.Context, actor string, requestID uint64, destination string) error
}

// TOSCTLLifecycleConfig pins the tosctl binary by SHA-256.
type TOSCTLLifecycleConfig struct {
	BinaryPath   string
	BinarySHA256 string
	ConfigPath   string
	VaultURL     string
	WalletName   string
	Timeout      time.Duration
}

// TOSCTLLifecycle runs `tosctl agent service send` from a sealed in-memory
// snapshot of the pinned binary, with only the vault URL in its environment.
type TOSCTLLifecycle struct {
	binary  []byte
	config  string
	vault   string
	wallet  string
	timeout time.Duration
	run     func(ctx context.Context, args []string) ([]byte, error)
}

// NewTOSCTLLifecycle reads the binary once and refuses any other bytes.
func NewTOSCTLLifecycle(config TOSCTLLifecycleConfig) (*TOSCTLLifecycle, error) {
	if !filepath.IsAbs(config.BinaryPath) || filepath.Clean(config.BinaryPath) != config.BinaryPath ||
		!filepath.IsAbs(config.ConfigPath) || filepath.Clean(config.ConfigPath) != config.ConfigPath ||
		!hex64Pattern.MatchString(config.BinarySHA256) || !walletNamePattern.MatchString(config.WalletName) {
		return nil, errors.New("servicebridge: invalid tosctl lifecycle configuration")
	}
	if config.VaultURL != "" && (len(config.VaultURL) > 4096 || strings.ContainsRune(config.VaultURL, 0) ||
		(!strings.HasPrefix(config.VaultURL, "file://") && !strings.HasPrefix(config.VaultURL, "hashicorp://"))) {
		return nil, errors.New("servicebridge: invalid tosctl vault URL")
	}
	if config.Timeout == 0 {
		config.Timeout = defaultLifecycleTime
	}
	if config.Timeout < time.Second || config.Timeout > 10*time.Minute {
		return nil, errors.New("servicebridge: tosctl timeout is outside its bound")
	}
	info, err := os.Stat(config.BinaryPath)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxTOSCTLBytes {
		return nil, errors.New("servicebridge: the tosctl binary is not a bounded regular file")
	}
	binary, err := os.ReadFile(config.BinaryPath)
	if err != nil {
		return nil, errors.New("servicebridge: read the tosctl binary")
	}
	digest := sha256.Sum256(binary)
	if hex.EncodeToString(digest[:]) != config.BinarySHA256 {
		return nil, errors.New("servicebridge: the tosctl binary does not have the pinned SHA-256")
	}
	sender := &TOSCTLLifecycle{
		binary: binary, config: config.ConfigPath, vault: config.VaultURL, wallet: config.WalletName,
		timeout: config.Timeout,
	}
	sender.run = sender.execute
	return sender, nil
}

func (s *TOSCTLLifecycle) execute(ctx context.Context, args []string) ([]byte, error) {
	executable, err := sealedExecutable(s.binary)
	if err != nil {
		return nil, err
	}
	defer executable.Close()
	call, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	command := exec.CommandContext(call, fmt.Sprintf("/proc/self/fd/%d", executable.Fd()), args...)
	command.Env = []string{}
	if s.vault != "" {
		command.Env = []string{"VAULT_URL=" + s.vault}
	}
	var stdout, stderr limitedBuffer
	stdout.limit, stderr.limit = maxLifecycleOutput, maxLifecycleOutput
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		// tosctl diagnostics can echo configuration; only the exit status
		// leaves this boundary.
		return nil, fmt.Errorf("servicebridge: tosctl %s failed: %v", args[3], exitStatus(err))
	}
	return stdout.Bytes(), nil
}

func exitStatus(err error) string {
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return "exit status " + strconv.Itoa(exit.ExitCode())
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timed out"
	}
	return "did not run"
}

type limitedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(value []byte) (int, error) {
	if b.Len()+len(value) > b.limit {
		return 0, errors.New("servicebridge: tosctl output exceeded its bound")
	}
	return b.Buffer.Write(value)
}

func (s *TOSCTLLifecycle) send(ctx context.Context, operation, actor string, requestID uint64, extra ...string) error {
	if s == nil || ctx == nil || !rawAddressPattern.MatchString(actor) {
		return errors.New("servicebridge: invalid lifecycle send")
	}
	args := append([]string{
		"agent", "service", "send", "--operation", operation, "--config", s.config, "--address", actor,
		"--from", s.wallet, "--request-id", strconv.FormatUint(requestID, 10),
	}, extra...)
	args = append(args, "--yes")
	_, err := s.run(ctx, args)
	return err
}

// Respond sends respond with the attestor controller signing the request
// bound SRP2 domain inside tosctl.
func (s *TOSCTLLifecycle) Respond(
	ctx context.Context,
	actor string,
	requestID uint64,
	responseHash [32]byte,
	attestorController string,
) error {
	if !walletNamePattern.MatchString(attestorController) || responseHash == ([32]byte{}) {
		return errors.New("servicebridge: invalid respond")
	}
	return s.send(ctx, "respond", actor, requestID, "--response-hash", hex.EncodeToString(responseHash[:]),
		"--attestor-controller", attestorController)
}

// Expire sends expire for an overdue request.
func (s *TOSCTLLifecycle) Expire(ctx context.Context, actor string, requestID uint64) error {
	return s.send(ctx, "expire", actor, requestID)
}

// ClaimRefund sends claim_refund from the caller wallet to destination.
func (s *TOSCTLLifecycle) ClaimRefund(ctx context.Context, actor string, requestID uint64, destination string) error {
	if !rawAddressPattern.MatchString(destination) {
		return errors.New("servicebridge: invalid refund destination")
	}
	return s.send(ctx, "claim-refund", actor, requestID, "--destination", destination)
}
