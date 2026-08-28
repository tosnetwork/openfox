package earning

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/openfox/pkg/providers"
)

type estimatorProvider struct {
	response string
	messages *[]providers.Message
}

func (provider estimatorProvider) Chat(_ context.Context, messages []providers.Message, tools []providers.ToolDefinition, _ string,
	_ map[string]any) (*providers.LLMResponse, error) {
	if len(messages) != 2 || len(tools) != 0 {
		panic("economic analyst received tools or wrong prompt")
	}
	if provider.messages != nil {
		*provider.messages = append([]providers.Message(nil), messages...)
	}
	return &providers.LLMResponse{Content: provider.response}, nil
}
func (estimatorProvider) GetDefaultModel() string { return "test-model" }

func TestLLMEconomicEstimatorProducesEvidenceButNoAuthority(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	intent := earningIntent(t, now, privateKey)
	inventory := InventorySnapshot{OwnerID: "owner:test", AgentID: "agent:worker", CreatedAtUnix: uint64(now.Unix()),
		ExpiresAtUnix: uint64(now.Add(time.Minute).Unix()), SourceGeneration: 1, PortfolioRevision: 1, PolicyRevision: 1,
		ConsistencyToken: "snapshot:1", SupportedSettlementAdapters: []string{"tos.payment.direct.v1"}}
	var messages []providers.Message
	provider := estimatorProvider{response: `{"strategy_disposition":"pursue","revenue_atomic":"100","payment_probability_ppm":900000,"completion_probability_ppm":800000,"compute_cost_atomic":"5","model_cost_atomic":"5","api_cost_atomic":"0","tool_cost_atomic":"0","subcontract_cost_atomic":"0","opportunity_cost_atomic":"1","failure_reserve_atomic":"2","dispute_reserve_atomic":"2","privacy_legal_reserve_atomic":"0","maximum_loss_atomic":"15","validity_seconds":60,"strategy_rationale":"bounded local review"}`, messages: &messages}
	estimate, err := (LLMEconomicEstimator{Provider: provider, Now: func() time.Time { return now }}).Estimate(context.Background(), intent, inventory)
	if err != nil || estimate.EvidenceDigest == "" || estimate.RevenueAtomic != "100" ||
		estimate.StrategyDisposition != EconomicStrategyPursue || estimate.StrategyRationale != "bounded local review" {
		t.Fatalf("estimate=%+v err=%v", estimate, err)
	}
	if len(messages) != 2 || !strings.Contains(messages[0].Content, `"revenue_atomic"`) ||
		!strings.Contains(messages[0].Content, `"maximum_loss_atomic"`) {
		t.Fatal("economic analyst prompt omitted its exact bounded output schema")
	}
	bad := provider
	bad.response = provider.response[:len(provider.response)-1] + `,"authority":"pay"}`
	if _, err := (LLMEconomicEstimator{Provider: bad, Now: func() time.Time { return now }}).Estimate(context.Background(), intent, inventory); err == nil {
		t.Fatal("model-added authority field was accepted")
	}
	missingDisposition := provider
	missingDisposition.response = strings.Replace(provider.response, `"strategy_disposition":"pursue",`, "", 1)
	if _, err := (LLMEconomicEstimator{Provider: missingDisposition, Now: func() time.Time { return now }}).Estimate(context.Background(), intent, inventory); err == nil {
		t.Fatal("economic analysis without an explicit strategy disposition was accepted")
	}
}

func TestLLMEconomicEstimatorDeclineIsAValidFailClosedDecision(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	intent := earningIntent(t, now, privateKey)
	inventory := InventorySnapshot{OwnerID: "owner:test", AgentID: "agent:worker", CreatedAtUnix: uint64(now.Unix()),
		ExpiresAtUnix: uint64(now.Add(time.Minute).Unix()), SourceGeneration: 1, PortfolioRevision: 1, PolicyRevision: 1,
		ConsistencyToken: "snapshot:1", SupportedSettlementAdapters: []string{"tos.payment.direct.v1"}}
	provider := estimatorProvider{response: `{"strategy_disposition":"decline","revenue_atomic":"100","payment_probability_ppm":900000,"completion_probability_ppm":800000,"compute_cost_atomic":"5","model_cost_atomic":"5","api_cost_atomic":"0","tool_cost_atomic":"0","subcontract_cost_atomic":"0","opportunity_cost_atomic":"1","failure_reserve_atomic":"2","dispute_reserve_atomic":"2","privacy_legal_reserve_atomic":"0","maximum_loss_atomic":"15","validity_seconds":60,"strategy_rationale":"the owner does not accept work below 2 TOS"}`}
	estimate, err := (LLMEconomicEstimator{Provider: provider, Now: func() time.Time { return now }}).Estimate(context.Background(), intent, inventory)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := EvaluateEconomics(estimate, EconomicPolicy{MinimumExpectedProfitAtomic: "1", MaximumLossAtomic: "100"}, now)
	if err != nil || decision.Eligible || decision.StrategyDisposition != EconomicStrategyDecline ||
		decision.StrategyRationale != "the owner does not accept work below 2 TOS" ||
		decision.Reason != "opportunity conflicts with the Agent's natural-language strategy" {
		t.Fatalf("decline decision=%+v err=%v", decision, err)
	}
}
