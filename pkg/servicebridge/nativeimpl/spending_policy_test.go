package nativeimpl

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/tosnetwork/openfox/pkg/servicebridge"
)

func writeSignedSpendingPolicy(t *testing.T) string {
	t.Helper()
	policy := e2ePolicy()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x63}, ed25519.SeedSize))
	message, err := servicebridge.CanonicalSpendingPolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(privateKey, message)
	document := spendingPolicyDocument{Schema: "tos.openfox.spending-policy.v1",
		OwnerPublicKeyHex: hex.EncodeToString(privateKey.Public().(ed25519.PublicKey)),
		OwnerSignatureHex: hex.EncodeToString(signature), Asset: spendingPolicyAsset{
			Master: policy.Asset.Master, WalletCodeHash: policy.Asset.WalletCodeHash,
			Network: spendingPolicyNetwork{ID: policy.Asset.Network.ID,
				GenesisRootHash: policy.Asset.Network.GenesisRootHash, GenesisFileHash: policy.Asset.Network.GenesisFileHash},
			Workchain: policy.Asset.Workchain, MasterCodeHash: policy.Asset.MasterCodeHash, Decimals: policy.Asset.Decimals,
		}, MaxAtomicPurchase: policy.MaxAtomicPurchase, DailyBudgetAtomic: policy.DailyBudgetAtomic,
		WindowSeconds: uint64(policy.Window.Seconds()), ExpiryUnix: policy.Expiry.Unix(),
		CapabilityAllow: []string{"cap_" + hex64}, ConfirmationMode: policy.ConfirmationMode}
	raw, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadSignedSpendingPolicyVerifiesOwnerSignature(t *testing.T) {
	policy, owner, err := LoadSignedSpendingPolicy(writeSignedSpendingPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(owner) != ed25519.PublicKeySize || !policy.CapabilityAllow["cap_"+hex64] ||
		servicebridge.VerifySpendingPolicySignature(policy, owner) != nil {
		t.Fatalf("policy = %+v", policy)
	}
}

func TestLoadSignedSpendingPolicyRejectsMutationAndPublicFile(t *testing.T) {
	path := writeSignedSpendingPolicy(t)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte(`"max_atomic_purchase": 100000000`),
		[]byte(`"max_atomic_purchase": 100000001`), 1)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadSignedSpendingPolicy(path); err == nil {
		t.Fatal("loader accepted a policy changed after signing")
	}
	path = writeSignedSpendingPolicy(t)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadSignedSpendingPolicy(path); err == nil {
		t.Fatal("loader accepted a public policy file")
	}
}
