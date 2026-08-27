package earning

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	guarantor "github.com/tosnetwork/tos-service-protocol/pkg/agentguarantor"
)

type guarantorSnapshotAuthority struct {
	EconomicAuthority
	reservations []ExposureReservation
}

func (authority guarantorSnapshotAuthority) Snapshot() (uint64, PortfolioLimits, []ExposureReservation) {
	return 1, PortfolioLimits{}, append([]ExposureReservation(nil), authority.reservations...)
}

func TestEvaluateGuarantorQuoteReservesGrossExposureAndPricesRisk(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	asset := commerce.AssetIdentityV1{AssetNamespace: "tos.asset", AssetIdentifier: "native", Unit: "nano"}
	request := guarantor.AuthorizedCoverageQuoteRequestV1{
		Body: guarantor.CoverageQuoteRequestBodyV1{SelectedAssuranceLevel: guarantor.AssuranceCollateralAttested,
			MaximumFee: commerce.AtomicAmountV1{Asset: asset, AmountAtomic: "80"}},
		RequestedTerms: guarantor.RequestedCoverageTermsV1{CoverageAsset: asset,
			RequestedAggregatePayout: commerce.AtomicAmountV1{Asset: asset, AmountAtomic: "1000"},
			SelectedAssuranceLevel:   guarantor.AssuranceCollateralAttested},
	}
	decision, err := EvaluateGuarantorQuote(request, GuarantorRiskPolicy{MaximumAggregateExposureAtomic: "10000",
		MaximumPerCoverageAtomic: "2000", MaximumPerCounterpartyAtomic: "3000", MinimumPremiumPPM: 10_000,
		MaximumClaimProbabilityPPM: 100_000, CapitalCostPPM: 20_000,
		MaximumActiveOffers: 10, MaximumActiveCoverages: 10, MaximumActiveClaims: 100,
		PermittedAssuranceLevels: []guarantor.AssuranceLevel{guarantor.AssuranceCollateralAttested}},
		GuarantorRiskEstimate{ClaimProbabilityPPM: 50_000, OperationalCostAtomic: "5", CollateralCreditAtomic: "0",
			EvidenceSetDigest: "sha256:" + strings.Repeat("a", 64), EstimatedAtUnix: uint64(now.Add(-time.Minute).Unix()),
			ExpiresAtUnix: uint64(now.Add(time.Minute).Unix())},
		GuarantorPortfolioSnapshot{AggregateReservedAtomic: "100", CounterpartyReservedAtomic: "20"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Admitted || decision.GrossExposureAtomic != "1000" || decision.NetExposureAtomic != "1000" ||
		decision.ExpectedLossAtomic != "50" || decision.CapitalCostAtomic != "20" || decision.MinimumRequiredFeeAtomic != "75" {
		t.Fatalf("unexpected underwriting decision: %#v", decision)
	}
}

func TestEvaluateGuarantorQuoteFailsClosed(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	asset := commerce.AssetIdentityV1{AssetNamespace: "tos.asset", AssetIdentifier: "native", Unit: "nano"}
	request := guarantor.AuthorizedCoverageQuoteRequestV1{Body: guarantor.CoverageQuoteRequestBodyV1{
		SelectedAssuranceLevel: guarantor.AssuranceUnsecuredSigned, MaximumFee: commerce.AtomicAmountV1{Asset: asset, AmountAtomic: "100"}},
		RequestedTerms: guarantor.RequestedCoverageTermsV1{CoverageAsset: asset,
			RequestedAggregatePayout: commerce.AtomicAmountV1{Asset: asset, AmountAtomic: "1000"}, SelectedAssuranceLevel: guarantor.AssuranceUnsecuredSigned}}
	policy := GuarantorRiskPolicy{MaximumAggregateExposureAtomic: "10000", MaximumPerCoverageAtomic: "2000",
		MaximumPerCounterpartyAtomic: "3000", MaximumClaimProbabilityPPM: 100_000,
		MaximumActiveOffers: 10, MaximumActiveCoverages: 10, MaximumActiveClaims: 100,
		PermittedAssuranceLevels: []guarantor.AssuranceLevel{guarantor.AssuranceUnsecuredSigned}}
	if _, err := EvaluateGuarantorQuote(request, policy, GuarantorRiskEstimate{ClaimProbabilityPPM: 10_000,
		OperationalCostAtomic: "0", CollateralCreditAtomic: "0", EvidenceSetDigest: "sha256:" + strings.Repeat("a", 64),
		EstimatedAtUnix: uint64(now.Add(-2 * time.Hour).Unix()), ExpiresAtUnix: uint64(now.Add(-time.Hour).Unix())},
		GuarantorPortfolioSnapshot{AggregateReservedAtomic: "0", CounterpartyReservedAtomic: "0"}, now); err == nil {
		t.Fatal("stale underwriting evidence was accepted")
	}
	if _, err := EvaluateGuarantorQuote(request, policy, GuarantorRiskEstimate{ClaimProbabilityPPM: 10_000,
		OperationalCostAtomic: "0", CollateralCreditAtomic: "1", EvidenceSetDigest: "sha256:" + strings.Repeat("a", 64),
		EstimatedAtUnix: uint64(now.Add(-time.Minute).Unix()), ExpiresAtUnix: uint64(now.Add(time.Minute).Unix())},
		GuarantorPortfolioSnapshot{AggregateReservedAtomic: "0", CounterpartyReservedAtomic: "0"}, now); err == nil {
		t.Fatal("unsecured coverage received collateral credit")
	}
}

func TestGuarantorPortfolioNeverAddsDifferentAssetUnits(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "guarantor")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenGuarantorJournal(directory, "owner:test", "agent:guarantor")
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	digest := func(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }
	native := commerce.AssetIdentityV1{AssetNamespace: "tos.asset", AssetIdentifier: "native", Unit: "nano"}
	token := commerce.AssetIdentityV1{AssetNamespace: "tos.jetton", AssetIdentifier: digest("9"), Unit: "micro"}
	positions := []GuarantorOfferPosition{
		{QuoteRequestDigest: digest("a"), CoveredPartyAgentID: "agent:party", CoverageAsset: native,
			GrossExposureAtomic: "100", NetExposureAtomic: "100", AcceptByUnix: 2_000_000_100, ReservationExpiresAt: 2_000_000_200,
			Record: guarantor.OfferRecord{OfferID: digest("1"), ReservationID: digest("2"), AgreementDigest: digest("3"),
				Status: guarantor.OfferReservedUnsigned, StateRevision: 1, LastEvidenceDigest: digest("4")}},
		{QuoteRequestDigest: digest("b"), CoveredPartyAgentID: "agent:party", CoverageAsset: token,
			GrossExposureAtomic: "900000000000", NetExposureAtomic: "900000000000",
			AcceptByUnix: 2_000_000_100, ReservationExpiresAt: 2_000_000_200,
			Record: guarantor.OfferRecord{OfferID: digest("5"), ReservationID: digest("6"), AgreementDigest: digest("7"),
				Status: guarantor.OfferReservedUnsigned, StateRevision: 1, LastEvidenceDigest: digest("8")}},
	}
	for _, position := range positions {
		if err := journal.ReserveUnsignedOffer(position); err != nil {
			t.Fatal(err)
		}
	}
	coordinator := GuarantorProviderCoordinator{Journal: journal, Authority: guarantorSnapshotAuthority{reservations: []ExposureReservation{
		{ReservationID: digest("2"), MaximumLossAtomic: 100},
		{ReservationID: digest("6"), MaximumLossAtomic: 900_000_000_000},
	}}}
	if snapshot := coordinator.portfolioFor("agent:party", native); snapshot.AggregateReservedAtomic != "100" ||
		snapshot.CounterpartyReservedAtomic != "100" || snapshot.ActiveOffers != 0 {
		t.Fatalf("native portfolio was contaminated by token atomic units: %#v", snapshot)
	}
	if snapshot := coordinator.portfolioFor("agent:party", token); snapshot.AggregateReservedAtomic != "900000000000" ||
		snapshot.CounterpartyReservedAtomic != "900000000000" || snapshot.ActiveOffers != 0 {
		t.Fatalf("token portfolio was contaminated by native atomic units: %#v", snapshot)
	}
}

func TestLocalGuarantorCoordinatorCannotOverstateAssurance(t *testing.T) {
	profileDigest := "sha256:" + strings.Repeat("c", 64)
	terms := guarantor.CoverageTermsV1{SelectedAssuranceLevel: guarantor.AssuranceCollateralAttested,
		CollateralTerms: &guarantor.CollateralTermsV1{CustodyAdapterProfile: commerce.ProfileRefV1{ProfileDigest: profileDigest}}}
	coordinator := GuarantorProviderCoordinator{CollateralAdapterEnabled: true,
		CollateralAdapterProfileDigests: []string{profileDigest}}
	if err := coordinator.validateAssuranceDeployment(terms); err == nil {
		t.Fatal("collateral assurance was advertised without a finalized Adapter verifier")
	}
	terms.SelectedAssuranceLevel = guarantor.AssuranceIndependentlyEnforced
	coordinator.IndependentCollateralEnabled = true
	if err := coordinator.validateAssuranceDeployment(terms); err == nil {
		t.Fatal("local coordinator advertised independently enforceable operation authority")
	}
}
