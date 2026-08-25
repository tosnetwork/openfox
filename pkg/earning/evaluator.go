package earning

import (
	"errors"
	"math/big"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

const probabilityScale = uint64(1_000_000)

type EconomicEstimate struct {
	RevenueAtomic             string `json:"revenue_atomic"`
	PaymentProbabilityPPM     uint32 `json:"payment_probability_ppm"`
	CompletionProbabilityPPM  uint32 `json:"completion_probability_ppm"`
	ComputeCostAtomic         string `json:"compute_cost_atomic"`
	ModelCostAtomic           string `json:"model_cost_atomic"`
	APICostAtomic             string `json:"api_cost_atomic"`
	ToolCostAtomic            string `json:"tool_cost_atomic"`
	SubcontractCostAtomic     string `json:"subcontract_cost_atomic"`
	OpportunityCostAtomic     string `json:"opportunity_cost_atomic"`
	FailureReserveAtomic      string `json:"failure_reserve_atomic"`
	DisputeReserveAtomic      string `json:"dispute_reserve_atomic"`
	PrivacyLegalReserveAtomic string `json:"privacy_legal_reserve_atomic"`
	MaximumLossAtomic         string `json:"maximum_loss_atomic"`
	EstimatedAtUnix           uint64 `json:"estimated_at_unix"`
	ExpiresAtUnix             uint64 `json:"expires_at_unix"`
	EvidenceDigest            string `json:"evidence_digest"`
}

type EconomicPolicy struct {
	MinimumExpectedProfitAtomic     string `json:"minimum_expected_profit_atomic"`
	MinimumROIPPM                   uint32 `json:"minimum_roi_ppm"`
	MaximumLossAtomic               string `json:"maximum_loss_atomic"`
	MinimumPaymentProbabilityPPM    uint32 `json:"minimum_payment_probability_ppm"`
	MinimumCompletionProbabilityPPM uint32 `json:"minimum_completion_probability_ppm"`
}

type EconomicDecision struct {
	Eligible              bool   `json:"eligible"`
	ExpectedRevenueAtomic string `json:"expected_revenue_atomic"`
	TotalCostAtomic       string `json:"total_cost_atomic"`
	ExpectedNetAtomic     string `json:"expected_net_atomic"`
	ROIPPM                uint64 `json:"roi_ppm"`
	Reason                string `json:"reason"`
}

func EvaluateEconomics(estimate EconomicEstimate, policy EconomicPolicy, now time.Time) (EconomicDecision, error) {
	if estimate.PaymentProbabilityPPM > uint32(probabilityScale) || estimate.CompletionProbabilityPPM > uint32(probabilityScale) ||
		estimate.PaymentProbabilityPPM == 0 || estimate.CompletionProbabilityPPM == 0 || estimate.EstimatedAtUnix == 0 ||
		estimate.ExpiresAtUnix <= estimate.EstimatedAtUnix || !now.UTC().Before(time.Unix(int64(estimate.ExpiresAtUnix), 0).UTC()) || estimate.EvidenceDigest == "" {
		return EconomicDecision{}, errors.New("economic evidence is stale or invalid")
	}
	revenue, err := nonnegativeInteger(estimate.RevenueAtomic)
	if err != nil {
		return EconomicDecision{}, err
	}
	costFields := []string{estimate.ComputeCostAtomic, estimate.ModelCostAtomic, estimate.APICostAtomic, estimate.ToolCostAtomic,
		estimate.SubcontractCostAtomic, estimate.OpportunityCostAtomic, estimate.FailureReserveAtomic, estimate.DisputeReserveAtomic,
		estimate.PrivacyLegalReserveAtomic}
	totalCost := new(big.Int)
	for _, field := range costFields {
		value, parseErr := nonnegativeInteger(field)
		if parseErr != nil {
			return EconomicDecision{}, parseErr
		}
		totalCost.Add(totalCost, value)
	}
	maximumLoss, err := nonnegativeInteger(estimate.MaximumLossAtomic)
	if err != nil {
		return EconomicDecision{}, err
	}
	policyMinimum, err := nonnegativeInteger(policy.MinimumExpectedProfitAtomic)
	if err != nil {
		return EconomicDecision{}, err
	}
	policyMaximumLoss, err := nonnegativeInteger(policy.MaximumLossAtomic)
	if err != nil || policy.MinimumROIPPM > uint32(probabilityScale) || policy.MinimumPaymentProbabilityPPM > uint32(probabilityScale) ||
		policy.MinimumCompletionProbabilityPPM > uint32(probabilityScale) {
		return EconomicDecision{}, errors.New("economic policy is invalid")
	}
	expected := new(big.Int).Mul(revenue, new(big.Int).SetUint64(uint64(estimate.PaymentProbabilityPPM)))
	expected.Mul(expected, new(big.Int).SetUint64(uint64(estimate.CompletionProbabilityPPM)))
	expected.Quo(expected, new(big.Int).SetUint64(probabilityScale*probabilityScale))
	net := new(big.Int).Sub(new(big.Int).Set(expected), totalCost)
	roi := uint64(0)
	if totalCost.Sign() == 0 {
		if net.Sign() > 0 {
			roi = probabilityScale
		}
	} else if net.Sign() > 0 {
		scaled := new(big.Int).Mul(net, new(big.Int).SetUint64(probabilityScale))
		scaled.Quo(scaled, totalCost)
		if scaled.IsUint64() {
			roi = scaled.Uint64()
		} else {
			roi = ^uint64(0)
		}
	}
	decision := EconomicDecision{ExpectedRevenueAtomic: expected.String(), TotalCostAtomic: totalCost.String(), ExpectedNetAtomic: net.String(), ROIPPM: roi}
	switch {
	case estimate.PaymentProbabilityPPM < policy.MinimumPaymentProbabilityPPM:
		decision.Reason = "payment probability is below policy"
	case estimate.CompletionProbabilityPPM < policy.MinimumCompletionProbabilityPPM:
		decision.Reason = "completion probability is below policy"
	case maximumLoss.Cmp(policyMaximumLoss) > 0:
		decision.Reason = "maximum loss exceeds policy"
	case net.Cmp(policyMinimum) < 0:
		decision.Reason = "expected profit is below policy"
	case roi < uint64(policy.MinimumROIPPM):
		decision.Reason = "risk-adjusted ROI is below policy"
	default:
		decision.Eligible = true
		decision.Reason = "opportunity satisfies deterministic economic policy"
	}
	return decision, nil
}

type CandidateAssessment struct {
	IntentDigest string
	Intent       commerce.SignedAgentIntent
	Inventory    InventorySnapshot
	Estimate     EconomicEstimate
	Decision     EconomicDecision
	CarrierIDs   []string
}

func nonnegativeInteger(value string) (*big.Int, error) {
	if value == "" {
		value = "0"
	}
	if len(value) > 78 || len(value) > 1 && value[0] == '0' {
		return nil, errors.New("economic amount is not a canonical unsigned integer")
	}
	parsed, ok := new(big.Int).SetString(value, 10)
	if !ok || parsed.Sign() < 0 {
		return nil, errors.New("economic amount is invalid")
	}
	return parsed, nil
}
