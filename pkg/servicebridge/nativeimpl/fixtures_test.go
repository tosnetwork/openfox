package nativeimpl

import (
	"strings"
	"time"

	"github.com/tosnetwork/openfox/pkg/servicebridge"
)

const hex64 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func repeatHex(pair string) string { return strings.Repeat(pair, 32) }

// e2ePolicy is an owner spending policy over the test stablecoin.
func e2ePolicy() servicebridge.SpendingPolicy {
	return servicebridge.SpendingPolicy{
		Asset: servicebridge.AssetIdentity{
			Master:         "0:" + repeatHex("ab"),
			WalletCodeHash: "tvm-cell-sha256:" + hex64,
			Network: servicebridge.Network{ID: "tos-local", GenesisRootHash: hex64,
				GenesisFileHash: strings.Repeat("b", 64)},
			Workchain: 0, MasterCodeHash: "tvm-cell-sha256:" + hex64, Decimals: 9,
		},
		MaxAtomicPurchase: 100_000_000,
		DailyBudgetAtomic: 100_000_000,
		Window:            24 * time.Hour,
		Expiry:            time.Unix(1786800000, 0).Add(365 * 24 * time.Hour),
		CapabilityAllow:   map[string]bool{"cap_" + hex64: true},
		ConfirmationMode:  servicebridge.ConfirmAuto,
		OwnerSignature:    []byte("owner-signature"),
	}
}
