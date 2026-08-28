package earning

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"
)

func TestHTTPOutcomeCarrierRequiresPinnedReceiptKey(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded := "ed25519:" + hex.EncodeToString(privateKey.Public().(ed25519.PublicKey))
	carrier, err := NewHTTPOutcomeCarrier("carrier:test", "http://127.0.0.1:8080/v1/operations", "read", "relay", encoded, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !carrier.carrierKey.Equal(privateKey.Public()) {
		t.Fatal("HTTP Outcome Carrier did not retain the pinned receipt key")
	}
	if _, err = NewHTTPOutcomeCarrier("carrier:test", "http://127.0.0.1:8080/v1/operations", "read", "relay", "", time.Second); err == nil {
		t.Fatal("HTTP Outcome Carrier accepted an unpinned receipt authority")
	}
}
