package earning

import (
	"errors"
	"math/big"
	"time"

	"github.com/tosnetwork/openfox/pkg/config"
	guarantor "github.com/tosnetwork/tos-service-protocol/pkg/agentguarantor"
)

const guarantorPPM = uint64(1_000_000)

// GuarantorRiskPolicy is private owner policy. It is deliberately not learned
// from an Intent, request, counterparty, or model response.
type GuarantorRiskPolicy struct {
	MaximumAggregateExposureAtomic string
	MaximumPerCoverageAtomic       string
	MaximumPerCounterpartyAtomic   string
	MinimumPremiumPPM              uint32
	MaximumClaimProbabilityPPM     uint32
	CapitalCostPPM                 uint32
	PermittedAssuranceLevels       []guarantor.AssuranceLevel
	MaximumActiveOffers            uint32
	MaximumActiveCoverages         uint32
	MaximumActiveClaims            uint32
}

// GuarantorRiskEstimate is evidence-backed underwriting input. Unknown or
// stale probability/cost/collateral evidence is rejected rather than guessed.
type GuarantorRiskEstimate struct {
	ClaimProbabilityPPM    uint32
	OperationalCostAtomic  string
	CollateralCreditAtomic string
	EvidenceSetDigest      string
	EstimatedAtUnix        uint64
	ExpiresAtUnix          uint64
}

type GuarantorPortfolioSnapshot struct {
	AggregateReservedAtomic    string
	CounterpartyReservedAtomic string
	ActiveOffers               uint32
	ActiveCoverages            uint32
	ActiveClaims               uint32
}

type GuarantorRiskDecision struct {
	Admitted                   bool
	Reason                     string
	GrossExposureAtomic        string
	NetExposureAtomic          string
	ExpectedLossAtomic         string
	CapitalCostAtomic          string
	MinimumRequiredFeeAtomic   string
	CollateralCreditAtomic     string
	UnderwritingEvidenceDigest string
}

func ConfiguredGuarantorRiskPolicy(settings config.EarningAgentGuarantorSettings) (GuarantorRiskPolicy, error) {
	levels := make([]guarantor.AssuranceLevel, len(settings.AssuranceLevels))
	for index, level := range settings.AssuranceLevels {
		levels[index] = guarantor.AssuranceLevel(level)
	}
	policy := GuarantorRiskPolicy{MaximumAggregateExposureAtomic: settings.MaximumAggregateExposureAtomic,
		MaximumPerCoverageAtomic:     settings.MaximumPerCoverageAtomic,
		MaximumPerCounterpartyAtomic: settings.MaximumPerCounterpartyAtomic, MinimumPremiumPPM: settings.MinimumPremiumPPM,
		MaximumClaimProbabilityPPM: settings.MaximumExpectedClaimProbability, CapitalCostPPM: settings.CapitalCostPPM,
		PermittedAssuranceLevels: levels, MaximumActiveOffers: settings.MaximumActiveOffers,
		MaximumActiveCoverages: settings.MaximumActiveCoverages, MaximumActiveClaims: settings.MaximumActiveClaims}
	if _, err := positiveBig(policy.MaximumAggregateExposureAtomic); err != nil {
		return GuarantorRiskPolicy{}, errors.New("configured Guarantor policy is invalid")
	}
	return policy, nil
}

// EvaluateGuarantorQuote performs integer-only, fail-closed underwriting. It
// never lowers the beneficiary-facing cap; collateral only reduces the
// provider's private net-exposure reservation after exact evidence is present.
func EvaluateGuarantorQuote(request guarantor.AuthorizedCoverageQuoteRequestV1, policy GuarantorRiskPolicy,
	estimate GuarantorRiskEstimate, portfolio GuarantorPortfolioSnapshot, now time.Time) (GuarantorRiskDecision, error) {
	terms := request.RequestedTerms
	gross, err := positiveBig(terms.RequestedAggregatePayout.AmountAtomic)
	if err != nil || terms.RequestedAggregatePayout.Asset != terms.CoverageAsset ||
		request.Body.SelectedAssuranceLevel != terms.SelectedAssuranceLevel {
		return GuarantorRiskDecision{}, errors.New("Guarantor underwriting request is invalid")
	}
	maximumAggregate, err := positiveBig(policy.MaximumAggregateExposureAtomic)
	if err != nil {
		return GuarantorRiskDecision{}, errors.New("Guarantor aggregate exposure policy is invalid")
	}
	maximumCoverage, err := positiveBig(policy.MaximumPerCoverageAtomic)
	if err != nil {
		return GuarantorRiskDecision{}, errors.New("Guarantor per-coverage policy is invalid")
	}
	maximumCounterparty, err := positiveBig(policy.MaximumPerCounterpartyAtomic)
	if err != nil || policy.MinimumPremiumPPM > uint32(guarantorPPM) ||
		policy.MaximumClaimProbabilityPPM == 0 || policy.MaximumClaimProbabilityPPM > uint32(guarantorPPM) ||
		policy.CapitalCostPPM > uint32(guarantorPPM) || !containsAssurance(policy.PermittedAssuranceLevels, terms.SelectedAssuranceLevel) {
		return GuarantorRiskDecision{}, errors.New("Guarantor owner policy is invalid or does not permit the assurance level")
	}
	operationalCost, err := nonnegativeBig(estimate.OperationalCostAtomic)
	if err != nil || estimate.ClaimProbabilityPPM > policy.MaximumClaimProbabilityPPM ||
		estimate.ClaimProbabilityPPM > uint32(guarantorPPM) || !canonicalSHA256(estimate.EvidenceSetDigest) ||
		estimate.EstimatedAtUnix == 0 || estimate.ExpiresAtUnix <= estimate.EstimatedAtUnix ||
		uint64(now.UTC().Unix()) >= estimate.ExpiresAtUnix {
		return GuarantorRiskDecision{}, errors.New("Guarantor underwriting evidence is missing, stale, or outside owner policy")
	}
	collateralCredit, err := nonnegativeBig(estimate.CollateralCreditAtomic)
	if err != nil {
		return GuarantorRiskDecision{}, errors.New("Guarantor collateral credit is invalid")
	}
	// A quote is issued before activation proves an exclusive finalized lock.
	// Therefore no estimated collateral value may reduce either portfolio or
	// custody reservation at firm-offer admission.
	if collateralCredit.Sign() != 0 {
		return GuarantorRiskDecision{}, errors.New("firm Guarantor offers cannot net unactivated collateral")
	}
	netExposure := new(big.Int).Set(gross)
	expectedLoss := ppmCeil(gross, uint64(estimate.ClaimProbabilityPPM))
	capitalCost := ppmCeil(netExposure, uint64(policy.CapitalCostPPM))
	minimumRateFee := ppmCeil(gross, uint64(policy.MinimumPremiumPPM))
	requiredFee := new(big.Int).Add(expectedLoss, capitalCost)
	requiredFee.Add(requiredFee, operationalCost)
	if requiredFee.Cmp(minimumRateFee) < 0 {
		requiredFee.Set(minimumRateFee)
	}
	decision := GuarantorRiskDecision{GrossExposureAtomic: gross.String(), NetExposureAtomic: netExposure.String(),
		ExpectedLossAtomic: expectedLoss.String(), CapitalCostAtomic: capitalCost.String(), MinimumRequiredFeeAtomic: requiredFee.String(),
		CollateralCreditAtomic: collateralCredit.String(), UnderwritingEvidenceDigest: estimate.EvidenceSetDigest}
	usedAggregate, aggregateErr := nonnegativeBig(portfolio.AggregateReservedAtomic)
	usedCounterparty, counterpartyErr := nonnegativeBig(portfolio.CounterpartyReservedAtomic)
	maximumFee, maximumFeeErr := nonnegativeBig(request.Body.MaximumFee.AmountAtomic)
	if aggregateErr != nil || counterpartyErr != nil || maximumFeeErr != nil || request.Body.MaximumFee.Asset != terms.CoverageAsset {
		return GuarantorRiskDecision{}, errors.New("Guarantor portfolio or fee input is invalid")
	}
	if gross.Cmp(maximumCoverage) > 0 || new(big.Int).Add(usedAggregate, netExposure).Cmp(maximumAggregate) > 0 ||
		new(big.Int).Add(usedCounterparty, netExposure).Cmp(maximumCounterparty) > 0 {
		decision.Reason = "exposure_limit"
		return decision, nil
	}
	if policy.MaximumActiveOffers == 0 || policy.MaximumActiveCoverages == 0 || policy.MaximumActiveClaims == 0 ||
		portfolio.ActiveOffers >= policy.MaximumActiveOffers || portfolio.ActiveCoverages >= policy.MaximumActiveCoverages ||
		portfolio.ActiveClaims >= policy.MaximumActiveClaims {
		decision.Reason = "portfolio_capacity"
		return decision, nil
	}
	if maximumFee.Cmp(requiredFee) < 0 {
		decision.Reason = "insufficient_premium"
		return decision, nil
	}
	decision.Admitted, decision.Reason = true, "admitted"
	return decision, nil
}

func positiveBig(value string) (*big.Int, error) {
	parsed, err := nonnegativeBig(value)
	if err != nil || parsed.Sign() == 0 {
		return nil, errors.New("amount must be positive")
	}
	return parsed, nil
}

func nonnegativeBig(value string) (*big.Int, error) {
	if value == "" || len(value) > 128 || len(value) > 1 && value[0] == '0' {
		return nil, errors.New("amount is not canonical")
	}
	parsed, ok := new(big.Int).SetString(value, 10)
	if !ok || parsed.Sign() < 0 {
		return nil, errors.New("amount is not a nonnegative integer")
	}
	return parsed, nil
}

func ppmCeil(value *big.Int, ppm uint64) *big.Int {
	product := new(big.Int).Mul(new(big.Int).Set(value), new(big.Int).SetUint64(ppm))
	product.Add(product, new(big.Int).SetUint64(guarantorPPM-1))
	return product.Div(product, new(big.Int).SetUint64(guarantorPPM))
}

func containsAssurance(values []guarantor.AssuranceLevel, wanted guarantor.AssuranceLevel) bool {
	previous := guarantor.AssuranceLevel("")
	for _, value := range values {
		if value <= previous {
			return false
		}
		if value == wanted {
			return true
		}
		previous = value
	}
	return false
}
