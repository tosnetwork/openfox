package nativeimpl

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestEd25519ExecutionSignerRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	signer, err := NewEd25519ExecutionSigner(priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	if !bytes.Equal(signer.PublicKey(), pub) {
		t.Fatalf("public key does not match the committed execution signer key")
	}

	intentHash := make([]byte, 32)
	if _, err := rand.Read(intentHash); err != nil {
		t.Fatalf("rand: %v", err)
	}
	sig, err := signer.SignSettlementIntent(context.Background(), intentHash)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("signature must be %d bytes, got %d", ed25519.SignatureSize, len(sig))
	}
	if !ed25519.Verify(pub, intentHash, sig) {
		t.Fatalf("escrow-style verification of the intent-hash signature failed")
	}
}

func TestEd25519ExecutionSignerRejectsNon32ByteHash(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := NewEd25519ExecutionSigner(priv)
	if _, err := signer.SignSettlementIntent(context.Background(), make([]byte, 31)); err == nil {
		t.Fatalf("must refuse to sign a non-32-byte payload")
	}
}

func TestNewEd25519ExecutionSignerRejectsShortKey(t *testing.T) {
	if _, err := NewEd25519ExecutionSigner(make(ed25519.PrivateKey, 10)); err == nil {
		t.Fatalf("must reject an undersized private key")
	}
}

func TestEd25519ExecutionSignerCopiesKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := NewEd25519ExecutionSigner(priv)
	for i := range priv {
		priv[i] = 0 // caller zeroes their copy
	}
	intentHash := make([]byte, 32)
	sig, err := signer.SignSettlementIntent(context.Background(), intentHash)
	if err != nil || len(sig) != ed25519.SignatureSize {
		t.Fatalf("signer must keep its own key copy: err=%v", err)
	}
	if !ed25519.Verify(signer.PublicKey(), intentHash, sig) {
		t.Fatalf("signature invalid after caller mutated their key copy")
	}
}
