package prediction

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestVaultTransitArchiveReceiptSignerUsesPinnedEd25519Key(t *testing.T) {
	privateKey := ed25519.NewKeyFromSeed(vaultSignerTestBytes(0x71, ed25519.SeedSize))
	publicKey := privateKey.Public().(ed25519.PublicKey)
	var publicKeyCalls, signingCalls int
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("X-Vault-Token") != "operator-token" {
			t.Fatal("Vault request omitted its configured capability")
		}
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v1/transit/keys/oracle-replica-a":
			if request.Method != http.MethodGet {
				t.Fatalf("public-key request used method %s", request.Method)
			}
			publicKeyCalls++
			_ = json.NewEncoder(writer).Encode(map[string]any{"data": map[string]any{
				"type": "ed25519", "keys": map[string]any{"7": map[string]string{
					"public_key": base64.StdEncoding.EncodeToString(publicKey),
				}},
			}})
		case "/v1/transit/sign/oracle-replica-a":
			if request.Method != http.MethodPost || request.Header.Get("Content-Type") != "application/json" {
				t.Fatalf(
					"signing request shape is invalid: method=%s content-type=%q",
					request.Method,
					request.Header.Get("Content-Type"),
				)
			}
			var input struct {
				Input      string `json:"input"`
				KeyVersion uint   `json:"key_version"`
			}
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil || input.KeyVersion != 7 {
				t.Fatalf("signing request key version is invalid: %+v err=%v", input, err)
			}
			digest, err := base64.StdEncoding.DecodeString(input.Input)
			if err != nil || len(digest) != sha256.Size {
				t.Fatalf("signing request did not carry the exact digest: %x err=%v", digest, err)
			}
			signingCalls++
			signature := ed25519.Sign(privateKey, digest)
			_ = json.NewEncoder(writer).Encode(map[string]any{"data": map[string]string{
				"signature": "vault:v7:" + base64.StdEncoding.EncodeToString(signature),
			}})
		default:
			t.Fatalf("unexpected Vault Transit path %q", request.URL.Path)
		}
	}))
	defer server.Close()

	signer, err := newVaultTransitArchiveReceiptSigner(VaultTransitArchiveReceiptSignerConfig{
		Address: server.URL, Token: "operator-token", TransitMount: "transit", KeyName: "oracle-replica-a",
		KeyVersion: 7, ExpectedPublicKey: publicKey,
	}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	returnedKey, err := signer.ArchiveReceiptPublicKey(t.Context())
	if err != nil || !bytes.Equal(returnedKey, publicKey) || publicKeyCalls != 1 {
		t.Fatalf(
			"pinned Vault public key was not obtained exactly once: key=%x calls=%d err=%v",
			returnedKey,
			publicKeyCalls,
			err,
		)
	}
	digest := sha256.Sum256([]byte("exact archive receipt digest"))
	signature, err := signer.SignArchiveReceiptDigest(t.Context(), digest)
	if err != nil || signingCalls != 1 || !ed25519.Verify(publicKey, digest[:], signature[:]) {
		t.Fatalf("Vault signature did not bind the exact receipt digest: calls=%d err=%v", signingCalls, err)
	}
}

func TestVaultTransitArchiveReceiptSignerFailsClosedOnIdentityAndSignatureMismatch(t *testing.T) {
	privateKey := ed25519.NewKeyFromSeed(vaultSignerTestBytes(0x72, ed25519.SeedSize))
	publicKey := privateKey.Public().(ed25519.PublicKey)
	otherPrivateKey := ed25519.NewKeyFromSeed(vaultSignerTestBytes(0x73, ed25519.SeedSize))
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v1/transit/keys/oracle-replica-a":
			_ = json.NewEncoder(writer).Encode(map[string]any{"data": map[string]any{
				"type": "ed25519", "keys": map[string]any{"3": map[string]string{
					"public_key": base64.StdEncoding.EncodeToString(otherPrivateKey.Public().(ed25519.PublicKey)),
				}},
			}})
		case "/v1/transit/sign/oracle-replica-a":
			digest := sha256.Sum256([]byte("receipt"))
			_ = json.NewEncoder(writer).Encode(map[string]any{"data": map[string]string{
				"signature": "vault:v3:" + base64.StdEncoding.EncodeToString(ed25519.Sign(otherPrivateKey, digest[:])),
			}})
		default:
			t.Fatalf("unexpected Vault Transit path %q", request.URL.Path)
		}
	}))
	defer server.Close()
	signer, err := newVaultTransitArchiveReceiptSigner(VaultTransitArchiveReceiptSignerConfig{
		Address: server.URL, Token: "operator-token", TransitMount: "transit", KeyName: "oracle-replica-a",
		KeyVersion: 3, ExpectedPublicKey: publicKey,
	}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.ArchiveReceiptPublicKey(t.Context()); err == nil {
		t.Fatal("signer accepted a Vault public key that differed from the operator pin")
	}
	digest := sha256.Sum256([]byte("receipt"))
	if _, err := signer.SignArchiveReceiptDigest(t.Context(), digest); err == nil {
		t.Fatal("signer accepted a signature from a key that differed from the operator pin")
	}
}

func TestVaultTransitArchiveReceiptSignerRejectsUnsafeConfigurationAndResponses(t *testing.T) {
	key := ed25519.NewKeyFromSeed(vaultSignerTestBytes(0x74, ed25519.SeedSize))
	publicKey := key.Public().(ed25519.PublicKey)
	for _, configuration := range []VaultTransitArchiveReceiptSignerConfig{
		{Address: "http://vault.example", Token: "token", TransitMount: "transit", KeyName: "key", KeyVersion: 1, ExpectedPublicKey: publicKey},
		{Address: "https://vault.example/path", Token: "token", TransitMount: "transit", KeyName: "key", KeyVersion: 1, ExpectedPublicKey: publicKey},
		{Address: "https://vault.example", Token: "", TransitMount: "transit", KeyName: "key", KeyVersion: 1, ExpectedPublicKey: publicKey},
		{Address: "https://vault.example", Token: "token", TransitMount: "nested/transit", KeyName: "key", KeyVersion: 1, ExpectedPublicKey: publicKey},
		{Address: "https://vault.example", Token: "token", TransitMount: "transit", KeyName: "key", KeyVersion: 0, ExpectedPublicKey: publicKey},
	} {
		if signer, err := NewVaultTransitArchiveReceiptSigner(configuration); err == nil || signer != nil {
			t.Fatalf("unsafe Vault signer configuration was accepted: %+v", configuration)
		}
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{"data": map[string]any{
			"type": "ed25519", "keys": map[string]any{"1": map[string]string{"public_key": "not-base64"}},
		}})
	}))
	defer server.Close()
	signer, err := newVaultTransitArchiveReceiptSigner(VaultTransitArchiveReceiptSignerConfig{
		Address: server.URL, Token: "token", TransitMount: "transit", KeyName: "key", KeyVersion: 1,
		ExpectedPublicKey: publicKey,
	}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, publicKeyErr := signer.ArchiveReceiptPublicKey(context.Background())
	if publicKeyErr == nil || !strings.Contains(publicKeyErr.Error(), "public key") {
		t.Fatalf("malformed Vault public-key reply did not fail closed: %v", publicKeyErr)
	}
}

func TestVaultTransitArchiveReceiptSignerRejectsOversizeReply(t *testing.T) {
	key := ed25519.NewKeyFromSeed(vaultSignerTestBytes(0x75, ed25519.SeedSize))
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"data":{"type":"ed25519","keys":{`))
		_, _ = writer.Write(bytes.Repeat([]byte{' '}, maximumVaultTransitReplyBytes))
		_, _ = writer.Write([]byte(`}}}`))
	}))
	defer server.Close()
	signer, err := newVaultTransitArchiveReceiptSigner(VaultTransitArchiveReceiptSignerConfig{
		Address: server.URL, Token: "token", TransitMount: "transit", KeyName: "key", KeyVersion: 1,
		ExpectedPublicKey: key.Public().(ed25519.PublicKey),
	}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.ArchiveReceiptPublicKey(t.Context()); err == nil {
		t.Fatal("oversize Vault response was accepted")
	}
}

func vaultSignerTestBytes(value byte, count int) []byte {
	return bytes.Repeat([]byte{value}, count)
}
