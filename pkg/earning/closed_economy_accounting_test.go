package earning

import (
	"testing"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

func TestOwnerLocalClosedEconomyProjectionReproducesSocialExperimentFixture(t *testing.T) {
	asset := commerce.AssetIdentityV1{AssetNamespace: "tos.asset", AssetIdentifier: "native", Unit: "nanotos"}
	scope := OwnerLocalClosedEconomyScope{
		AccountingPolicyDigest: ownerLocalAccountingDigest(t, "social-experiment-policy"),
		EconomicPerimeterID:    "campaign:eight-agent-generic-intent-social-earning:2026-08-31",
		Asset:                  asset,
		ParticipantAgentIDs: []string{
			"agent:data-curator",
			"agent:evidence-verifier",
			"agent:guarantor-analyst",
			"agent:localization-writer",
			"agent:security-auditor",
			"agent:software-builder",
			"agent:storage-provider",
			"agent:transaction-operator",
		},
	}
	amount := func(value string) commerce.AtomicAmountV1 {
		return commerce.AtomicAmountV1{Asset: asset, AmountAtomic: value}
	}
	transfers := []OwnerLocalClosedEconomyTransfer{
		{TransferReference: ownerLocalAccountingDigest(t, "buildfox-to-marketfox"),
			BuyerAgentID: "agent:software-builder", SellerAgentID: "agent:storage-provider",
			Amount: amount("2500000000"), ConservativeReserve: amount("400000000")},
		{TransferReference: ownerLocalAccountingDigest(t, "prooffox-to-marketfox"),
			BuyerAgentID: "agent:evidence-verifier", SellerAgentID: "agent:storage-provider",
			Amount: amount("2500000000"), ConservativeReserve: amount("400000000")},
		{TransferReference: ownerLocalAccountingDigest(t, "marketfox-to-datafox"),
			BuyerAgentID: "agent:storage-provider", SellerAgentID: "agent:data-curator",
			Amount: amount("2000000000"), ConservativeReserve: amount("300000000")},
		{TransferReference: ownerLocalAccountingDigest(t, "riskfox-to-prooffox"),
			BuyerAgentID: "agent:guarantor-analyst", SellerAgentID: "agent:evidence-verifier",
			Amount: amount("2200000000"), ConservativeReserve: amount("300000000")},
	}

	projection, err := ProjectOwnerLocalClosedEconomy(scope, append(transfers, transfers[0]))
	if err != nil {
		t.Fatal(err)
	}
	if projection.TransferCount != 4 || projection.Asset != asset ||
		projection.InternalSellerGrossReceiptsAtomic != "9200000000" ||
		projection.InternalBuyerSpendAtomic != "9200000000" ||
		projection.IntraPerimeterTransferNetAtomic != "0" ||
		projection.ConservativeReserveAtomic != "1400000000" ||
		projection.ProjectedClosedEconomyNetAtomic != "-1400000000" {
		t.Fatalf("social experiment accounting projection = %+v", projection)
	}
}

func TestOwnerLocalClosedEconomyProjectionFailsClosedAcrossPerimeterAssetAndReplay(t *testing.T) {
	asset := commerce.AssetIdentityV1{AssetNamespace: "tos.asset", AssetIdentifier: "native", Unit: "nanotos"}
	scope := OwnerLocalClosedEconomyScope{AccountingPolicyDigest: ownerLocalAccountingDigest(t, "policy"),
		EconomicPerimeterID: "campaign:test", Asset: asset,
		ParticipantAgentIDs: []string{"agent:buyer", "agent:seller"}}
	base := OwnerLocalClosedEconomyTransfer{TransferReference: ownerLocalAccountingDigest(t, "payment"),
		BuyerAgentID: "agent:buyer", SellerAgentID: "agent:seller",
		Amount:              commerce.AtomicAmountV1{Asset: asset, AmountAtomic: "10"},
		ConservativeReserve: commerce.AtomicAmountV1{Asset: asset, AmountAtomic: "2"}}

	outside := base
	outside.BuyerAgentID = "agent:outside"
	if _, err := ProjectOwnerLocalClosedEconomy(scope, []OwnerLocalClosedEconomyTransfer{outside}); err == nil {
		t.Fatal("cross-perimeter transfer was silently netted")
	}
	wrongAsset := base
	wrongAsset.Amount.Asset = commerce.AssetIdentityV1{AssetNamespace: "tos.asset", AssetIdentifier: "other", Unit: "nanotos"}
	if _, err := ProjectOwnerLocalClosedEconomy(scope, []OwnerLocalClosedEconomyTransfer{wrongAsset}); err == nil {
		t.Fatal("cross-asset transfer was silently aggregated")
	}
	wrongReserveAsset := base
	wrongReserveAsset.ConservativeReserve.Asset = commerce.AssetIdentityV1{
		AssetNamespace: "tos.asset", AssetIdentifier: "other", Unit: "nanotos"}
	if _, err := ProjectOwnerLocalClosedEconomy(scope, []OwnerLocalClosedEconomyTransfer{wrongReserveAsset}); err == nil {
		t.Fatal("cross-asset conservative reserve was silently aggregated")
	}
	conflict := base
	conflict.Amount.AmountAtomic = "11"
	if _, err := ProjectOwnerLocalClosedEconomy(scope, []OwnerLocalClosedEconomyTransfer{base, conflict}); err == nil {
		t.Fatal("conflicting exact transfer replay was silently double counted")
	}
	unsorted := scope
	unsorted.ParticipantAgentIDs = []string{"agent:seller", "agent:buyer"}
	if _, err := ProjectOwnerLocalClosedEconomy(unsorted, []OwnerLocalClosedEconomyTransfer{base}); err == nil {
		t.Fatal("non-canonical accounting perimeter was accepted")
	}
}

func TestOwnerLocalClosedEconomyProjectionUsesArbitraryPrecisionAtomicAmounts(t *testing.T) {
	asset := commerce.AssetIdentityV1{AssetNamespace: "tos.asset", AssetIdentifier: "native", Unit: "nanotos"}
	scope := OwnerLocalClosedEconomyScope{AccountingPolicyDigest: ownerLocalAccountingDigest(t, "large-policy"),
		EconomicPerimeterID: "campaign:large", Asset: asset,
		ParticipantAgentIDs: []string{"agent:buyer", "agent:seller"}}
	transfer := OwnerLocalClosedEconomyTransfer{TransferReference: ownerLocalAccountingDigest(t, "large-payment"),
		BuyerAgentID: "agent:buyer", SellerAgentID: "agent:seller",
		Amount:              commerce.AtomicAmountV1{Asset: asset, AmountAtomic: "18446744073709551616"},
		ConservativeReserve: commerce.AtomicAmountV1{Asset: asset, AmountAtomic: "1"}}
	projection, err := ProjectOwnerLocalClosedEconomy(scope, []OwnerLocalClosedEconomyTransfer{transfer})
	if err != nil {
		t.Fatal(err)
	}
	if projection.InternalSellerGrossReceiptsAtomic != transfer.Amount.AmountAtomic ||
		projection.InternalBuyerSpendAtomic != transfer.Amount.AmountAtomic ||
		projection.IntraPerimeterTransferNetAtomic != "0" || projection.ProjectedClosedEconomyNetAtomic != "-1" {
		t.Fatalf("large atomic projection overflowed: %+v", projection)
	}
}

func ownerLocalAccountingDigest(t *testing.T, label string) string {
	t.Helper()
	digest, err := codec.Digest("tos.openfox.owner-local-accounting-test.v1", label)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}
