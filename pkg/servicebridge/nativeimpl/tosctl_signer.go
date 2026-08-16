package nativeimpl

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
)

// TOSCTLExecutionSignerConfig keeps the execution key inside the same tosctl
// custody boundary used for release funding. ExpectedPublicKey is the exact key
// committed by the Accepted Quote authorization.
type TOSCTLExecutionSignerConfig struct {
	BinaryPath        string
	ConfigPath        string
	WalletName        string
	ExpectedPublicKey ed25519.PublicKey
	Timeout           time.Duration
}

// TOSCTLExecutionSigner signs settlement-intent hashes without reading private
// key material into the provider process.
type TOSCTLExecutionSigner struct {
	binary, config, wallet string
	public                 ed25519.PublicKey
	timeout                time.Duration
	runner                 releaseCommandRunner
}

func NewTOSCTLExecutionSigner(c TOSCTLExecutionSignerConfig) (*TOSCTLExecutionSigner, error) {
	if !secureExecutable(c.BinaryPath) || !secureConfigFile(c.ConfigPath) ||
		c.WalletName == "" || strings.TrimSpace(c.WalletName) != c.WalletName || len(c.WalletName) > 128 ||
		len(c.ExpectedPublicKey) != ed25519.PublicKeySize {
		return nil, errors.New("nativeimpl: invalid tosctl execution signer configuration")
	}
	if c.Timeout == 0 {
		c.Timeout = 30 * time.Second
	}
	if c.Timeout < time.Second || c.Timeout > 2*time.Minute {
		return nil, errors.New("nativeimpl: invalid tosctl execution signer timeout")
	}
	return &TOSCTLExecutionSigner{binary: c.BinaryPath, config: c.ConfigPath, wallet: c.WalletName,
		public: append(ed25519.PublicKey(nil), c.ExpectedPublicKey...), timeout: c.Timeout, runner: execReleaseRunner{}}, nil
}

func (s *TOSCTLExecutionSigner) SignSettlementIntent(ctx context.Context, intentHash []byte) ([]byte, error) {
	if s == nil || ctx == nil || len(intentHash) != 32 {
		return nil, errors.New("nativeimpl: settlement intent must be a 32-byte hash")
	}
	call, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	raw, err := s.runner.run(call, s.binary, "wallet", "--config", s.config, "sign", "--name", s.wallet,
		"--message-hex", hex.EncodeToString(intentHash))
	if err != nil {
		return nil, errors.New("nativeimpl: tosctl could not sign the settlement intent")
	}
	var result struct {
		Schema       string `json:"schema"`
		Algorithm    string `json:"algorithm"`
		Wallet       string `json:"wallet"`
		Address      string `json:"address"`
		PublicKeyHex string `json:"public_key_hex"`
		MessageHex   string `json:"message_hex"`
		SignatureHex string `json:"signature_hex"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || result.Schema != "tosctl-ed25519-signature-v1" ||
		result.Algorithm != "Ed25519" || result.Wallet != s.wallet || result.Address == "" ||
		result.PublicKeyHex != hex.EncodeToString(s.public) || result.MessageHex != hex.EncodeToString(intentHash) {
		return nil, errors.New("nativeimpl: tosctl returned a conflicting settlement signature")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("nativeimpl: tosctl signature output has trailing data")
	}
	signature, err := hex.DecodeString(result.SignatureHex)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(s.public, intentHash, signature) {
		return nil, errors.New("nativeimpl: tosctl returned an invalid settlement signature")
	}
	return signature, nil
}

var _ ExecutionSigner = (*TOSCTLExecutionSigner)(nil)
