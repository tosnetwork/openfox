package servicebridge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	// maxTOSCTLJSONOutput bounds the output of a command that prints signed
	// message BOCs (a registration carries the registry code and an
	// ML-DSA-44 key and signature).
	maxTOSCTLJSONOutput = 1 << 20
	maxTOSCTLTimeout    = 10 * time.Minute
)

// TOSCTLCall is one tosctl invocation. The runner adds --config itself, so
// a caller can never point tosctl at another configuration.
type TOSCTLCall struct {
	// Label names the command in errors, for example "wallet send". It is
	// the only part of the invocation an error repeats.
	Label string
	Args  []string
	// Timeout defaults to two minutes; MaxOutput to 64 KiB.
	Timeout   time.Duration
	MaxOutput int
}

// TOSCTLRunner runs the pinned tosctl. Every signature and every chain send
// of the setup commands goes through it, so tests replace it with a fake and
// production has exactly one way to reach custody.
type TOSCTLRunner interface {
	Run(ctx context.Context, call TOSCTLCall) ([]byte, error)
}

// TOSCTLFailure is a fixed classification of a failed tosctl run. tosctl's
// own diagnostics never leave the runner: they can quote the configuration
// or the vault. Only one of these constants does.
type TOSCTLFailure string

// Failure classes, each recognized by a fixed phrase tosctl prints.
const (
	TOSCTLFailureUnclassified  TOSCTLFailure = ""
	TOSCTLFailureNotFound      TOSCTLFailure = "the vault or configuration holds no such entry"
	TOSCTLFailureAlreadyExists TOSCTLFailure = "an entry of that name already exists"
	TOSCTLFailureBalance       TOSCTLFailure = "the wallet balance does not cover the amount and fees"
	TOSCTLFailureWalletState   TOSCTLFailure = "the wallet is not an active account"
	TOSCTLFailureOccupied      TOSCTLFailure = "an account already exists at the derived address"
	TOSCTLFailureUnconfirmed   TOSCTLFailure = "the message was broadcast but its inclusion was not observed"
	TOSCTLFailureWrongChain    TOSCTLFailure = "the tosctl chain RPC serves another chain or network label"
	// TOSCTLFailureUnsafeDirectory is tosctl refusing a configuration or
	// vault under a directory another user can modify. It is reported so
	// the owner can act; it is not one of the checks that clear a step.
	TOSCTLFailureUnsafeDirectory TOSCTLFailure = "the tosctl configuration is under a directory another user can " +
		"modify; every ancestor must be owned by the user running OpenFox or by root"
)

var tosctlFailurePhrases = []struct {
	phrase  string
	failure TOSCTLFailure
}{
	{"[E100: Not found]", TOSCTLFailureNotFound},
	{"[E101: Already exists]", TOSCTLFailureAlreadyExists},
	{"insufficient balance", TOSCTLFailureBalance},
	{"Wrong amount value", TOSCTLFailureBalance},
	{"wallet is not active", TOSCTLFailureWalletState},
	{"is uninitialized", TOSCTLFailureWalletState},
	{"is frozen", TOSCTLFailureWalletState},
	{"an account already exists at", TOSCTLFailureOccupied},
	{"Transaction timeout expired", TOSCTLFailureUnconfirmed},
	{"the RPC serves another chain", TOSCTLFailureWrongChain},
	{"network label does not match this chain", TOSCTLFailureWrongChain},
	{"which another user can modify", TOSCTLFailureUnsafeDirectory},
}

// tosctlErrorPrefix starts the one line tosctl ends a failed run with.
const tosctlErrorPrefix = "command failed: "

// classifyTOSCTLDiagnostic classifies a failed run by tosctl's final error
// line alone: the last line of its diagnostics, which is "command failed:
// <cause>". A phrase in an earlier progress or warning line says nothing
// about why the run ended, and classifying by it could take a broadcast
// message for one refused before broadcasting. Diagnostics that were cut
// at the bound may have lost that line, so they classify as nothing.
func classifyTOSCTLDiagnostic(stderr []byte, truncated bool) TOSCTLFailure {
	if truncated {
		return TOSCTLFailureUnclassified
	}
	lines := bytes.Split(bytes.TrimRight(stderr, "\r\n \t"), []byte("\n"))
	final := bytes.TrimRight(lines[len(lines)-1], "\r")
	if !bytes.HasPrefix(final, []byte(tosctlErrorPrefix)) {
		return TOSCTLFailureUnclassified
	}
	for _, candidate := range tosctlFailurePhrases {
		if bytes.Contains(final, []byte(candidate.phrase)) {
			return candidate.failure
		}
	}
	return TOSCTLFailureUnclassified
}

// TOSCTLError is a failed tosctl run: the command label, how it ended and a
// fixed failure class. It carries no tosctl output.
type TOSCTLError struct {
	Label  string
	Status string
	Reason TOSCTLFailure
}

func (e *TOSCTLError) Error() string {
	if e.Reason == TOSCTLFailureUnclassified {
		return fmt.Sprintf("servicebridge: tosctl %s failed: %s", e.Label, e.Status)
	}
	return fmt.Sprintf("servicebridge: tosctl %s failed: %s (%s)", e.Label, e.Status, e.Reason)
}

// tosctlFailure returns the failure class of err, if it is a tosctl error.
func tosctlFailure(err error) TOSCTLFailure {
	var failure *TOSCTLError
	if errors.As(err, &failure) {
		return failure.Reason
	}
	return TOSCTLFailureUnclassified
}

// SealedTOSCTL runs tosctl from a sealed in-memory snapshot of the binary
// whose SHA-256 was checked, with only the vault URL in its environment.
type SealedTOSCTL struct {
	binary []byte
	config string
	vault  string
}

func validVaultURL(value string) bool {
	return value == "" || (len(value) <= 4096 && !strings.ContainsRune(value, 0) &&
		(strings.HasPrefix(value, "file://") || strings.HasPrefix(value, "hashicorp://")))
}

// NewSealedTOSCTL reads the binary once and refuses any bytes but the
// pinned ones.
func NewSealedTOSCTL(config TOSCTLConfig, vaultURL string) (*SealedTOSCTL, error) {
	if !filepath.IsAbs(config.ConfigPath) || filepath.Clean(config.ConfigPath) != config.ConfigPath {
		return nil, errors.New("servicebridge: the tosctl configuration path must be absolute and clean")
	}
	if !validVaultURL(vaultURL) {
		return nil, errors.New("servicebridge: invalid tosctl vault URL")
	}
	binary, err := readPinnedBinary(config.Binary, config.SHA256, "tosctl")
	if err != nil {
		return nil, fmt.Errorf("servicebridge: %w", err)
	}
	return &SealedTOSCTL{binary: binary, config: config.ConfigPath, vault: vaultURL}, nil
}

// HashTOSCTL returns the SHA-256 of a bounded regular tosctl binary, for an
// owner who pins it on first use.
func HashTOSCTL(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", errors.New("servicebridge: the tosctl path must be absolute and clean")
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxTOSCTLBytes {
		return "", errors.New("servicebridge: the tosctl binary is not a bounded regular file")
	}
	binary, err := os.ReadFile(path)
	if err != nil {
		return "", errors.New("servicebridge: read the tosctl binary")
	}
	digest := sha256.Sum256(binary)
	return hex.EncodeToString(digest[:]), nil
}

// Run implements TOSCTLRunner.
func (s *SealedTOSCTL) Run(ctx context.Context, call TOSCTLCall) ([]byte, error) {
	if s == nil || ctx == nil || call.Label == "" || len(call.Args) == 0 {
		return nil, errors.New("servicebridge: invalid tosctl call")
	}
	for _, argument := range call.Args {
		// The configuration is the runner's; a caller's would redirect
		// custody.
		if argument == "--config" || argument == "-c" || strings.HasPrefix(argument, "--config=") ||
			strings.HasPrefix(argument, "--config-fd") || strings.ContainsRune(argument, 0) {
			return nil, errors.New("servicebridge: a tosctl call may not name a configuration")
		}
	}
	if call.Timeout == 0 {
		call.Timeout = defaultLifecycleTime
	}
	if call.MaxOutput == 0 {
		call.MaxOutput = maxLifecycleOutput
	}
	if call.Timeout < time.Second || call.Timeout > maxTOSCTLTimeout || call.MaxOutput < 0 ||
		call.MaxOutput > maxTOSCTLJSONOutput {
		return nil, errors.New("servicebridge: tosctl call bounds are outside their limits")
	}
	executable, err := sealedExecutable(s.binary)
	if err != nil {
		return nil, err
	}
	defer executable.Close()
	bounded, cancel := context.WithTimeout(ctx, call.Timeout)
	defer cancel()
	args := append(append([]string(nil), call.Args...), "--config", s.config)
	command := exec.CommandContext(bounded, fmt.Sprintf("/proc/self/fd/%d", executable.Fd()), args...)
	command.Env, command.Dir = []string{}, "/"
	if s.vault != "" {
		command.Env = []string{"VAULT_URL=" + s.vault}
	}
	var stdout, stderr limitedBuffer
	stdout.limit, stderr.limit, stderr.truncate = call.MaxOutput, maxLifecycleOutput, true
	command.Stdout, command.Stderr = &stdout, &stderr
	if runErr := command.Run(); runErr != nil {
		status := exitStatus(runErr)
		if errors.Is(bounded.Err(), context.DeadlineExceeded) {
			status = "timed out"
		}
		return nil, &TOSCTLError{
			Label: call.Label, Status: status, Reason: classifyTOSCTLDiagnostic(stderr.Bytes(), stderr.truncated),
		}
	}
	return stdout.Bytes(), nil
}

// decodeTOSCTLJSON strictly decodes one JSON value tosctl printed: unknown
// fields and trailing data are refused. With leadingText the value is the
// last non-empty line, for the commands that print progress text before a
// one-line JSON result; nothing else tolerates text.
func decodeTOSCTLJSON(label string, output []byte, leadingText bool, value any) error {
	if leadingText {
		lines := bytes.Split(bytes.TrimRight(output, "\r\n \t"), []byte("\n"))
		output = lines[len(lines)-1]
	}
	decoder := json.NewDecoder(bytes.NewReader(output))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return fmt.Errorf("servicebridge: tosctl %s returned a malformed answer", label)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("servicebridge: tosctl %s returned trailing data", label)
	}
	return nil
}

// runTOSCTLJSON runs one command and strictly decodes its JSON answer.
func runTOSCTLJSON(ctx context.Context, runner TOSCTLRunner, call TOSCTLCall, leadingText bool, value any) error {
	if runner == nil {
		return errors.New("servicebridge: no tosctl runner")
	}
	output, err := runner.Run(ctx, call)
	if err != nil {
		return err
	}
	return decodeTOSCTLJSON(call.Label, output, leadingText, value)
}
