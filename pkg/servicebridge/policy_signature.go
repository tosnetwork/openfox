package servicebridge

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"sort"
	"time"
)

const spendingPolicySignatureDomain = "tos.openfox.spending-policy.v1\x00"

type canonicalSpendingPolicy struct {
	Asset             canonicalPolicyAsset `json:"asset"`
	MaxAtomicPurchase uint64               `json:"max_atomic_purchase"`
	DailyBudgetAtomic uint64               `json:"daily_budget_atomic"`
	WindowSeconds     uint64               `json:"window_seconds"`
	ExpiryUnix        int64                `json:"expiry_unix"`
	CapabilityAllow   []string             `json:"capability_allow"`
	ConfirmationMode  ConfirmationMode     `json:"confirmation_mode"`
}

type canonicalPolicyAsset struct {
	Master         string                 `json:"master"`
	WalletCodeHash string                 `json:"wallet_code_hash"`
	Network        canonicalPolicyNetwork `json:"network"`
	Workchain      int32                  `json:"workchain"`
	MasterCodeHash string                 `json:"master_code_hash"`
	Decimals       uint32                 `json:"decimals"`
}

type canonicalPolicyNetwork struct {
	ID              string `json:"id"`
	GenesisRootHash string `json:"genesis_root_hash"`
	GenesisFileHash string `json:"genesis_file_hash"`
}

// CanonicalSpendingPolicy returns the domain-separated bytes an owner signs.
// False allow-list entries are rejected so equivalent maps have one encoding.
func CanonicalSpendingPolicy(policy SpendingPolicy) ([]byte, error) {
	if policy.Asset.Master == "" || policy.Asset.WalletCodeHash == "" || policy.Asset.Network.ID == "" ||
		policy.Asset.Network.GenesisRootHash == "" || policy.Asset.Network.GenesisFileHash == "" ||
		policy.Asset.MasterCodeHash == "" || policy.Asset.Decimals == 0 || policy.MaxAtomicPurchase == 0 ||
		policy.DailyBudgetAtomic < policy.MaxAtomicPurchase || policy.Window < time.Minute ||
		policy.Window > 366*24*time.Hour || policy.Window%time.Second != 0 || policy.Expiry.Unix() <= 0 ||
		policy.Expiry.Nanosecond() != 0 ||
		len(policy.CapabilityAllow) == 0 ||
		(policy.ConfirmationMode != ConfirmAuto && policy.ConfirmationMode != ConfirmManual) {
		return nil, errors.New("servicebridge: invalid canonical spending policy")
	}
	capabilities := make([]string, 0, len(policy.CapabilityAllow))
	for capability, allowed := range policy.CapabilityAllow {
		if capability == "" || !allowed {
			return nil, errors.New("servicebridge: invalid capability allow-list")
		}
		capabilities = append(capabilities, capability)
	}
	sort.Strings(capabilities)
	canonical := canonicalSpendingPolicy{Asset: canonicalPolicyAsset{
		Master: policy.Asset.Master, WalletCodeHash: policy.Asset.WalletCodeHash, Network: canonicalPolicyNetwork{
			ID: policy.Asset.Network.ID, GenesisRootHash: policy.Asset.Network.GenesisRootHash,
			GenesisFileHash: policy.Asset.Network.GenesisFileHash,
		},
		Workchain: policy.Asset.Workchain, MasterCodeHash: policy.Asset.MasterCodeHash, Decimals: policy.Asset.Decimals,
	}, MaxAtomicPurchase: policy.MaxAtomicPurchase, DailyBudgetAtomic: policy.DailyBudgetAtomic,
		WindowSeconds: uint64(policy.Window / time.Second), ExpiryUnix: policy.Expiry.UTC().Unix(),
		CapabilityAllow: capabilities, ConfirmationMode: policy.ConfirmationMode}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return nil, err
	}
	return append([]byte(spendingPolicySignatureDomain), encoded...), nil
}

// VerifySpendingPolicySignature verifies the RFC 8032 owner signature over the
// canonical domain-separated policy. Production composition calls this before
// accepting a policy; the private key never enters OpenFox.
func VerifySpendingPolicySignature(policy SpendingPolicy, owner ed25519.PublicKey) error {
	if len(owner) != ed25519.PublicKeySize || len(policy.OwnerSignature) != ed25519.SignatureSize {
		return errors.New("servicebridge: invalid spending policy signature material")
	}
	message, err := CanonicalSpendingPolicy(policy)
	if err != nil {
		return err
	}
	if !ed25519.Verify(owner, message, policy.OwnerSignature) {
		return errors.New("servicebridge: spending policy owner signature is invalid")
	}
	return nil
}
