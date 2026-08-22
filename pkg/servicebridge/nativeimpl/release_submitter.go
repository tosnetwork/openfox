package nativeimpl

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/tosnetwork/tosutils-go/address"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

// TOSCTLReleaseSubmitterConfig configures the provider-side escrow release
// broadcaster. It mirrors the buyer's funding sender: it drives tosctl to build
// an internal message from the provider wallet to the escrow carrying the signed
// release body, then broadcasts the prepared message. tosctl holds the wallet
// key; this process never does.
type TOSCTLReleaseSubmitterConfig struct {
	BinaryPath      string
	ConfigPath      string
	WalletName      string
	ProviderAddress string // raw workchain-0 address of the provider wallet (the payer)
	AttachedNanoTOS uint64
	Timeout         time.Duration
}

type releaseCommandRunner interface {
	run(context.Context, string, ...string) ([]byte, error)
}

// TOSCTLReleaseSubmitter implements ReleaseSubmitter by shelling out to tosctl.
type TOSCTLReleaseSubmitter struct {
	binary, config, wallet, provider string
	attached                         uint64
	timeout                          time.Duration
	runner                           releaseCommandRunner
}

// NewTOSCTLReleaseSubmitter validates the tosctl configuration and returns a
// submitter. The binary must be a root/owner-owned regular executable with no
// group/other write bit, and the config file must not be group/other accessible.
func NewTOSCTLReleaseSubmitter(c TOSCTLReleaseSubmitterConfig) (*TOSCTLReleaseSubmitter, error) {
	if !secureExecutable(c.BinaryPath) || !secureConfigFile(c.ConfigPath) ||
		c.WalletName == "" || strings.TrimSpace(c.WalletName) != c.WalletName || len(c.WalletName) > 128 ||
		!isRawWorkchainZero(c.ProviderAddress) {
		return nil, errors.New("nativeimpl: invalid tosctl release submitter configuration")
	}
	if c.AttachedNanoTOS == 0 {
		c.AttachedNanoTOS = 100_000_000
	}
	if c.AttachedNanoTOS > 1_000_000_000 {
		return nil, errors.New("nativeimpl: release gas budget is out of range")
	}
	if c.Timeout == 0 {
		c.Timeout = 90 * time.Second
	}
	if c.Timeout < time.Second || c.Timeout > 5*time.Minute {
		return nil, errors.New("nativeimpl: invalid tosctl release submitter timeout")
	}
	return &TOSCTLReleaseSubmitter{
		binary: c.BinaryPath, config: c.ConfigPath, wallet: c.WalletName, provider: c.ProviderAddress,
		attached: c.AttachedNanoTOS, timeout: c.Timeout, runner: execReleaseRunner{},
	}, nil
}

// SubmitRelease builds and broadcasts the escrow release. It fails closed if
// tosctl prepares a message that does not match the exact release the settler
// signed — same body, same escrow destination, same provider payer — so a
// tampered or misdirected broadcast is refused rather than submitted.
func (s *TOSCTLReleaseSubmitter) SubmitRelease(
	ctx context.Context,
	escrowAddress string,
	releaseBody *cell.Cell,
) error {
	if s == nil || ctx == nil || releaseBody == nil || !isRawWorkchainZero(escrowAddress) {
		return errors.New("nativeimpl: invalid escrow release broadcast request")
	}
	bodyBOC := base64.StdEncoding.EncodeToString(releaseBody.ToBOC())
	bodyHash := fmt.Sprintf("tvm-cell-sha256:%x", releaseBody.Hash())

	preparedRaw, err := s.run(ctx, "wallet", "--config", s.config, "send", "--from", s.wallet,
		"--to", escrowAddress, "--amount-nanotos", fmt.Sprint(s.attached), "--body-boc", bodyBOC, "--build-only")
	if err != nil {
		return errors.New("nativeimpl: tosctl could not prepare the escrow release")
	}
	var prepared struct {
		Version       string `json:"version"`
		Wallet        string `json:"wallet"`
		Payer         string `json:"payer"`
		Destination   string `json:"destination"`
		AmountNanoTOS uint64 `json:"amount_nanotos"`
		BodyHash      string `json:"body_hash"`
		StateInitHash string `json:"state_init_hash"`
		MessageBOC    string `json:"message_boc_base64"`
	}
	decoder := json.NewDecoder(bytes.NewReader(preparedRaw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&prepared) != nil || prepared.Version != "tosctl.wallet-prepared-send.v1" ||
		prepared.Wallet != s.wallet || !sameAddress(prepared.Payer, s.provider) ||
		!sameAddress(prepared.Destination, escrowAddress) || prepared.AmountNanoTOS != s.attached ||
		prepared.BodyHash != bodyHash || prepared.StateInitHash != "" || prepared.MessageBOC == "" {
		return errors.New("nativeimpl: tosctl prepared a conflicting escrow release message")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("nativeimpl: tosctl prepared release output has trailing data")
	}
	messageBOC, err := base64.StdEncoding.DecodeString(prepared.MessageBOC)
	if err != nil {
		return errors.New("nativeimpl: tosctl prepared an invalid release message BOC")
	}
	message, err := cell.FromBOC(messageBOC)
	if err != nil {
		return errors.New("nativeimpl: tosctl prepared an invalid release message BOC")
	}
	messageHash := fmt.Sprintf("tvm-cell-sha256:%x", message.Hash())

	broadcastRaw, err := s.run(ctx, "wallet", "--config", s.config, "broadcast-prepared",
		"--message-boc", prepared.MessageBOC, "--yes")
	if err != nil {
		return errors.New("nativeimpl: tosctl escrow release broadcast outcome is ambiguous")
	}
	var result struct {
		Version     string `json:"version"`
		MessageHash string `json:"message_hash"`
		Status      string `json:"status"`
	}
	broadcastDecoder := json.NewDecoder(bytes.NewReader(broadcastRaw))
	broadcastDecoder.DisallowUnknownFields()
	if broadcastDecoder.Decode(&result) != nil || result.Version != "tosctl.wallet-prepared-broadcast.v1" ||
		result.MessageHash != messageHash || result.Status != "submitted" {
		return errors.New("nativeimpl: tosctl escrow release broadcast outcome is ambiguous")
	}
	var broadcastTrailing any
	if err := broadcastDecoder.Decode(&broadcastTrailing); !errors.Is(err, io.EOF) {
		return errors.New("nativeimpl: tosctl release broadcast output has trailing data")
	}
	return nil
}

var _ ReleaseSubmitter = (*TOSCTLReleaseSubmitter)(nil)

func (s *TOSCTLReleaseSubmitter) run(ctx context.Context, args ...string) ([]byte, error) {
	call, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	return s.runner.run(call, s.binary, args...)
}

type execReleaseRunner struct{}

func (execReleaseRunner) run(ctx context.Context, binary string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, binary, args...)
	output := releaseCappedBuffer{limit: 1 << 20}
	command.Stdout, command.Stderr = &output, &output
	err := command.Run()
	return output.Bytes(), err
}

type releaseCappedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *releaseCappedBuffer) Write(value []byte) (int, error) {
	remaining := b.limit - b.Len()
	if remaining <= 0 {
		return 0, errors.New("tosctl output exceeded limit")
	}
	if len(value) > remaining {
		written, _ := b.Buffer.Write(value[:remaining])
		return written, errors.New("tosctl output exceeded limit")
	}
	return b.Buffer.Write(value)
}

func secureExecutable(path string) bool {
	info, err := os.Lstat(path)
	if err != nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return filepath.IsAbs(path) && filepath.Clean(path) == path && info.Mode().IsRegular() &&
		info.Mode().Perm()&0o022 == 0 && info.Mode().Perm()&0o111 != 0 && ok &&
		(stat.Uid == 0 || stat.Uid == uint32(os.Geteuid()))
}

func secureConfigFile(path string) bool {
	info, err := os.Lstat(path)
	if err != nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return filepath.IsAbs(path) && filepath.Clean(path) == path && info.Mode().IsRegular() &&
		info.Mode().Perm()&0o077 == 0 && ok && stat.Uid == uint32(os.Geteuid())
}

func isRawWorkchainZero(value string) bool {
	parsed, err := address.ParseRawAddr(value)
	return err == nil && parsed != nil && parsed.Workchain() == 0 && parsed.StringRaw() == value
}

func sameAddress(left, right string) bool {
	a, errA := parseAnyAddress(left)
	b, errB := parseAnyAddress(right)
	return errA == nil && errB == nil && a.Workchain() == b.Workchain() && bytes.Equal(a.Data(), b.Data())
}

func parseAnyAddress(value string) (*address.Address, error) {
	if parsed, err := address.ParseRawAddr(value); err == nil {
		return parsed, nil
	}
	return address.ParseAddr(value)
}
