package nativeimpl

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type signerCommandRunner struct {
	key    ed25519.PrivateKey
	wallet string
	mutate func(map[string]any)
	err    error
	args   []string
}

func (r *signerCommandRunner) run(_ context.Context, _ string, args ...string) ([]byte, error) {
	r.args = append([]string(nil), args...)
	if r.err != nil {
		return nil, r.err
	}
	message, err := hex.DecodeString(args[len(args)-1])
	if err != nil {
		return nil, err
	}
	value := map[string]any{
		"schema": "tosctl-ed25519-signature-v1", "algorithm": "Ed25519", "wallet": r.wallet,
		"address": "EQ-test-only", "public_key_hex": hex.EncodeToString(r.key.Public().(ed25519.PublicKey)),
		"message_hex": hex.EncodeToString(message), "signature_hex": hex.EncodeToString(ed25519.Sign(r.key, message)),
	}
	if r.mutate != nil {
		r.mutate(value)
	}
	return json.Marshal(value)
}

func TestTOSCTLExecutionSignerValidatesCustodyOutput(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := testTOSCTLSigner(t, public)
	runner := &signerCommandRunner{key: private, wallet: "execution-signer"}
	signer.runner = runner
	hash := make([]byte, 32)
	hash[0] = 0x42
	signature, err := signer.SignSettlementIntent(context.Background(), hash)
	if err != nil || !ed25519.Verify(public, hash, signature) {
		t.Fatalf("sign: %v", err)
	}
	if len(runner.args) != 8 || runner.args[0] != "wallet" || runner.args[3] != "sign" ||
		runner.args[5] != "execution-signer" || runner.args[6] != "--message-hex" {
		t.Fatalf("unexpected tosctl command: %v", runner.args)
	}
}

func TestTOSCTLExecutionSignerRejectsConflictingOrFailedOutput(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	for name, runner := range map[string]*signerCommandRunner{
		"wrong key":     {key: private, wallet: "execution-signer", mutate: func(v map[string]any) { v["public_key_hex"] = hex.EncodeToString(make([]byte, 32)) }},
		"wrong message": {key: private, wallet: "execution-signer", mutate: func(v map[string]any) { v["message_hex"] = strings.Repeat("ff", 32) }},
		"bad signature": {key: private, wallet: "execution-signer", mutate: func(v map[string]any) { v["signature_hex"] = hex.EncodeToString(make([]byte, 64)) }},
		"command error": {key: private, wallet: "execution-signer", err: errors.New("vault unavailable")},
	} {
		t.Run(name, func(t *testing.T) {
			signer := testTOSCTLSigner(t, public)
			signer.runner = runner
			if _, err := signer.SignSettlementIntent(context.Background(), make([]byte, 32)); err == nil {
				t.Fatal("conflicting custody output must fail closed")
			}
		})
	}
}

func TestTOSCTLExecutionSignerRejectsBadIntentLength(t *testing.T) {
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	signer := testTOSCTLSigner(t, public)
	if _, err := signer.SignSettlementIntent(context.Background(), make([]byte, 31)); err == nil {
		t.Fatal("non-hash input must be rejected")
	}
}

func testTOSCTLSigner(t *testing.T, public ed25519.PublicKey) *TOSCTLExecutionSigner {
	t.Helper()
	directory := t.TempDir()
	binary := filepath.Join(directory, "tosctl")
	config := filepath.Join(directory, "config.json")
	if err := os.WriteFile(binary, []byte("binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	signer, err := NewTOSCTLExecutionSigner(TOSCTLExecutionSignerConfig{
		BinaryPath: binary, ConfigPath: config,
		WalletName: "execution-signer", ExpectedPublicKey: public,
	})
	if err != nil {
		t.Fatal(err)
	}
	return signer
}
