package nativeimpl

import (
	"context"
	"crypto/ed25519"
	"errors"
)

// Ed25519ExecutionSigner signs the settlement-intent hash with an in-process
// execution-signer key. It is the self-custody implementation of ExecutionSigner
// and matches the escrow's verification exactly: the escrow checks an Ed25519
// signature over the 32-byte settlement-intent cell hash.
//
// Providers that keep the key outside the process (a hardware signer, or
// `tosctl wallet sign`, which is the custody model cmd/native-receipt-release
// expects) should implement ExecutionSigner as a shell-out instead; this type is
// for self-custody and tests, and never exposes the key.
type Ed25519ExecutionSigner struct {
	key ed25519.PrivateKey
}

// NewEd25519ExecutionSigner validates the key length and returns a signer. It
// copies the key so the caller cannot mutate it afterwards.
func NewEd25519ExecutionSigner(key ed25519.PrivateKey) (*Ed25519ExecutionSigner, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("nativeimpl: execution signer needs a 64-byte Ed25519 private key")
	}
	owned := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	copy(owned, key)
	return &Ed25519ExecutionSigner{key: owned}, nil
}

// PublicKey returns the execution signer's public key, which must equal the key
// committed in the Accepted Quote's execution-signer authorization.
func (s *Ed25519ExecutionSigner) PublicKey() ed25519.PublicKey {
	return s.key.Public().(ed25519.PublicKey)
}

// SignSettlementIntent signs the 32-byte settlement-intent hash. It refuses any
// other length so a caller can never sign an arbitrary payload through this
// boundary.
func (s *Ed25519ExecutionSigner) SignSettlementIntent(_ context.Context, intentHash []byte) ([]byte, error) {
	if len(intentHash) != 32 {
		return nil, errors.New("nativeimpl: settlement intent hash must be 32 bytes")
	}
	return ed25519.Sign(s.key, intentHash), nil
}

var _ ExecutionSigner = (*Ed25519ExecutionSigner)(nil)
