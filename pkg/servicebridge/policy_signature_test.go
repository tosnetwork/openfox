package servicebridge

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func signedPolicy(t *testing.T) (SpendingPolicy, ed25519.PublicKey) {
	t.Helper()
	policy := basePolicy()
	policy.Asset.Network = Network{ID: "tos-local", GenesisRootHash: "sha256:root", GenesisFileHash: "sha256:file"}
	policy.Asset.MasterCodeHash = "tvm-cell-sha256:master"
	policy.Asset.Decimals = 9
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	message, err := CanonicalSpendingPolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	policy.OwnerSignature = ed25519.Sign(privateKey, message)
	return policy, publicKey
}

func TestSpendingPolicySignatureIsDeterministicAndVerified(t *testing.T) {
	policy, publicKey := signedPolicy(t)
	if err := VerifySpendingPolicySignature(policy, publicKey); err != nil {
		t.Fatal(err)
	}
	left, err := CanonicalSpendingPolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	policy.CapabilityAllow = map[string]bool{"cap_second": true, "cap_sw": true}
	right, err := CanonicalSpendingPolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	policy.CapabilityAllow = map[string]bool{"cap_sw": true, "cap_second": true}
	reordered, err := CanonicalSpendingPolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	if string(right) != string(reordered) || string(left) == string(right) {
		t.Fatal("canonical policy did not sort or bind its allow-list")
	}
}

func TestSpendingPolicySignatureRejectsMutationAndFalseAllowEntry(t *testing.T) {
	policy, publicKey := signedPolicy(t)
	policy.MaxAtomicPurchase++
	if err := VerifySpendingPolicySignature(policy, publicKey); err == nil {
		t.Fatal("signature accepted a changed spending ceiling")
	}
	policy, _ = signedPolicy(t)
	policy.CapabilityAllow["cap_disabled"] = false
	if _, err := CanonicalSpendingPolicy(policy); err == nil {
		t.Fatal("canonical policy accepted a false allow-list entry")
	}
}
