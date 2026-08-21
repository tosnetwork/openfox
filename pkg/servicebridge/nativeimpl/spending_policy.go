package nativeimpl

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"time"

	"github.com/tosnetwork/openfox/pkg/servicebridge"
)

type spendingPolicyDocument struct {
	Schema            string                         `json:"schema"`
	OwnerPublicKeyHex string                         `json:"owner_public_key_hex"`
	OwnerSignatureHex string                         `json:"owner_signature_hex"`
	Asset             spendingPolicyAsset            `json:"asset"`
	MaxAtomicPurchase uint64                         `json:"max_atomic_purchase"`
	DailyBudgetAtomic uint64                         `json:"daily_budget_atomic"`
	WindowSeconds     uint64                         `json:"window_seconds"`
	ExpiryUnix        int64                          `json:"expiry_unix"`
	CapabilityAllow   []string                       `json:"capability_allow"`
	ConfirmationMode  servicebridge.ConfirmationMode `json:"confirmation_mode"`
}

type spendingPolicyAsset struct {
	Master         string                `json:"master"`
	WalletCodeHash string                `json:"wallet_code_hash"`
	Network        spendingPolicyNetwork `json:"network"`
	Workchain      int32                 `json:"workchain"`
	MasterCodeHash string                `json:"master_code_hash"`
	Decimals       uint32                `json:"decimals"`
}

type spendingPolicyNetwork struct {
	ID              string `json:"id"`
	GenesisRootHash string `json:"genesis_root_hash"`
	GenesisFileHash string `json:"genesis_file_hash"`
}

// LoadSignedSpendingPolicy strictly loads and verifies an owner policy before
// it can reach NewChainNativeBuyer. The file is operational authority and must
// be owner-only even though it contains no private key.
func LoadSignedSpendingPolicy(path string) (servicebridge.SpendingPolicy, ed25519.PublicKey, error) {
	if !secureConfigFile(path) {
		return servicebridge.SpendingPolicy{}, nil, errors.New("nativeimpl: spending policy must be an owner-private absolute regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 || len(raw) > 1<<20 {
		return servicebridge.SpendingPolicy{}, nil, errors.New("nativeimpl: read spending policy")
	}
	var document spendingPolicyDocument
	if err := decodeStrictJSON(raw, &document); err != nil || document.Schema != "tos.openfox.spending-policy.v1" ||
		document.WindowSeconds == 0 || document.WindowSeconds > 366*24*60*60 || document.ExpiryUnix <= 0 ||
		len(document.CapabilityAllow) == 0 {
		return servicebridge.SpendingPolicy{}, nil, errors.New("nativeimpl: invalid spending policy document")
	}
	publicKey, err := hex.DecodeString(document.OwnerPublicKeyHex)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return servicebridge.SpendingPolicy{}, nil, errors.New("nativeimpl: invalid spending policy owner key")
	}
	signature, err := hex.DecodeString(document.OwnerSignatureHex)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return servicebridge.SpendingPolicy{}, nil, errors.New("nativeimpl: invalid spending policy signature")
	}
	allow := make(map[string]bool, len(document.CapabilityAllow))
	for _, capability := range document.CapabilityAllow {
		if capability == "" || allow[capability] {
			return servicebridge.SpendingPolicy{}, nil, errors.New("nativeimpl: invalid spending policy allow-list")
		}
		allow[capability] = true
	}
	policy := servicebridge.SpendingPolicy{Asset: servicebridge.AssetIdentity{
		Master: document.Asset.Master, WalletCodeHash: document.Asset.WalletCodeHash, Network: servicebridge.Network{
			ID: document.Asset.Network.ID, GenesisRootHash: document.Asset.Network.GenesisRootHash,
			GenesisFileHash: document.Asset.Network.GenesisFileHash,
		},
		Workchain: document.Asset.Workchain, MasterCodeHash: document.Asset.MasterCodeHash, Decimals: document.Asset.Decimals,
	}, MaxAtomicPurchase: document.MaxAtomicPurchase, DailyBudgetAtomic: document.DailyBudgetAtomic,
		Window: time.Duration(document.WindowSeconds) * time.Second, Expiry: time.Unix(document.ExpiryUnix, 0).UTC(),
		CapabilityAllow: allow, ConfirmationMode: document.ConfirmationMode, OwnerSignature: signature}
	if err := servicebridge.VerifySpendingPolicySignature(policy, ed25519.PublicKey(publicKey)); err != nil {
		return servicebridge.SpendingPolicy{}, nil, err
	}
	return policy, ed25519.PublicKey(publicKey), nil
}
