package nativeimpl

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

type fakeReleaseRunner struct {
	prepared       map[string]any
	broadcast      map[string]any
	prepareErr     error
	broadcastErr   error
	prepareCalls   int
	broadcastCalls int
	gotEscrowTo    string
}

func (f *fakeReleaseRunner) run(_ context.Context, _ string, args ...string) ([]byte, error) {
	if containsArg(args, "--build-only") {
		f.prepareCalls++
		f.gotEscrowTo = argValue(args, "--to")
		if f.prepareErr != nil {
			return nil, f.prepareErr
		}
		return mustJSON(f.prepared), nil
	}
	if containsArg(args, "broadcast-prepared") {
		f.broadcastCalls++
		if f.broadcastErr != nil {
			return nil, f.broadcastErr
		}
		return mustJSON(f.broadcast), nil
	}
	return nil, fmt.Errorf("unexpected tosctl args: %v", args)
}

func containsArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

func argValue(args []string, flag string) string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func mustJSON(v map[string]any) []byte {
	raw, _ := json.Marshal(v)
	return raw
}

// secureFiles writes an executable and a config file with the strict perms the
// submitter requires (owner-only, no group/other write) and returns their paths.
func secureFiles(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	binary := filepath.Join(dir, "tosctl")
	config := filepath.Join(dir, "config.json")
	if err := os.WriteFile(binary, []byte("#!/bin/true\n"), 0o700); err != nil {
		t.Fatalf("write binary: %v", err)
	}
	if err := os.WriteFile(config, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	// Defend against umask leaving unexpected bits.
	_ = os.Chmod(binary, 0o700)
	_ = os.Chmod(config, 0o600)
	return binary, config
}

const providerAddr = "0:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func newReleaseSubmitter(t *testing.T) *TOSCTLReleaseSubmitter {
	t.Helper()
	binary, config := secureFiles(t)
	s, err := NewTOSCTLReleaseSubmitter(TOSCTLReleaseSubmitterConfig{
		BinaryPath: binary, ConfigPath: config, WalletName: "provider-wallet", ProviderAddress: providerAddr,
	})
	if err != nil {
		t.Fatalf("new submitter: %v", err)
	}
	return s
}

func releaseFixture(t *testing.T, escrow string) (*cell.Cell, *fakeReleaseRunner) {
	t.Helper()
	body := cell.BeginCell().MustStoreUInt(0xdeadbeef, 32).EndCell()
	bodyHash := fmt.Sprintf("tvm-cell-sha256:%x", body.Hash())
	message := cell.BeginCell().MustStoreUInt(0x1234, 16).EndCell()
	messageBOC := base64.StdEncoding.EncodeToString(message.ToBOC())
	messageHash := fmt.Sprintf("tvm-cell-sha256:%x", message.Hash())
	runner := &fakeReleaseRunner{
		prepared: map[string]any{
			"version": "tosctl.wallet-prepared-send.v1", "wallet": "provider-wallet",
			"payer": providerAddr, "destination": escrow, "amount_nanotos": 100_000_000,
			"body_hash": bodyHash, "state_init_hash": "", "message_boc_base64": messageBOC,
		},
		broadcast: map[string]any{
			"version": "tosctl.wallet-prepared-broadcast.v1", "message_hash": messageHash, "status": "submitted",
		},
	}
	return body, runner
}

func TestReleaseSubmitterBroadcastsPreparedRelease(t *testing.T) {
	s := newReleaseSubmitter(t)
	escrow := "0:" + hex64
	body, runner := releaseFixture(t, escrow)
	s.runner = runner

	if err := s.SubmitRelease(context.Background(), escrow, body); err != nil {
		t.Fatalf("submit release: %v", err)
	}
	if runner.prepareCalls != 1 || runner.broadcastCalls != 1 {
		t.Fatalf("release must prepare once and broadcast once, got %d/%d", runner.prepareCalls, runner.broadcastCalls)
	}
	if runner.gotEscrowTo != escrow {
		t.Fatalf("release must be addressed to the escrow, got --to %q", runner.gotEscrowTo)
	}
}

func TestReleaseSubmitterRejectsConflictingPreparedBody(t *testing.T) {
	s := newReleaseSubmitter(t)
	escrow := "0:" + hex64
	body, runner := releaseFixture(t, escrow)
	runner.prepared["body_hash"] = "tvm-cell-sha256:" + hex64 // not the body we signed
	s.runner = runner

	if err := s.SubmitRelease(context.Background(), escrow, body); err == nil {
		t.Fatalf("a prepared message with a different body must not be broadcast")
	}
	if runner.broadcastCalls != 0 {
		t.Fatalf("nothing may be broadcast when the prepared body mismatches")
	}
}

func TestReleaseSubmitterRejectsMisdirectedRelease(t *testing.T) {
	s := newReleaseSubmitter(t)
	escrow := "0:" + hex64
	body, runner := releaseFixture(t, escrow)
	runner.prepared["destination"] = "0:" + repeatHex("cc") // wrong escrow
	s.runner = runner

	if err := s.SubmitRelease(context.Background(), escrow, body); err == nil {
		t.Fatalf("a release addressed elsewhere must fail closed")
	}
	if runner.broadcastCalls != 0 {
		t.Fatalf("nothing may be broadcast when the destination differs")
	}
}

func TestReleaseSubmitterRejectsUnsubmittedBroadcast(t *testing.T) {
	s := newReleaseSubmitter(t)
	escrow := "0:" + hex64
	body, runner := releaseFixture(t, escrow)
	runner.broadcast["status"] = "pending"
	s.runner = runner

	if err := s.SubmitRelease(context.Background(), escrow, body); err == nil {
		t.Fatalf("an unconfirmed broadcast must be reported as ambiguous")
	}
}

func TestReleaseSubmitterRejectsNonRawEscrow(t *testing.T) {
	s := newReleaseSubmitter(t)
	body := cell.BeginCell().MustStoreUInt(1, 8).EndCell()
	if err := s.SubmitRelease(context.Background(), "EQnot-raw", body); err == nil {
		t.Fatalf("a non-raw escrow address must be refused before any tosctl call")
	}
}

func TestNewReleaseSubmitterRejectsInsecureConfig(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "tosctl")
	config := filepath.Join(dir, "config.json")
	_ = os.WriteFile(binary, []byte("x"), 0o700)
	_ = os.WriteFile(config, []byte("{}"), 0o644) // group/other readable
	_ = os.Chmod(config, 0o644)
	if _, err := NewTOSCTLReleaseSubmitter(TOSCTLReleaseSubmitterConfig{
		BinaryPath: binary, ConfigPath: config, WalletName: "w", ProviderAddress: providerAddr,
	}); err == nil {
		t.Fatalf("a group/other-accessible config must be rejected")
	}
}
