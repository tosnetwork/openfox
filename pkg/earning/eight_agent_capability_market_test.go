package earning

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"

	"github.com/tosnetwork/openfox/pkg/providers"
)

type capabilityMarketQueuedProvider struct {
	mu        sync.Mutex
	responses []string
	calls     int
}

type capabilityMarketFailingProvider struct {
	mu    sync.Mutex
	calls int
	err   error
}

func (provider *capabilityMarketFailingProvider) Chat(_ context.Context, _ []providers.Message,
	_ []providers.ToolDefinition, _ string, _ map[string]any,
) (*providers.LLMResponse, error) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	provider.calls++
	return nil, provider.err
}

func (*capabilityMarketFailingProvider) GetDefaultModel() string {
	return "capability-market-failure-test"
}

func (provider *capabilityMarketQueuedProvider) Chat(_ context.Context, messages []providers.Message,
	tools []providers.ToolDefinition, _ string, _ map[string]any,
) (*providers.LLMResponse, error) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if len(messages) != 2 || len(tools) != 0 || provider.calls >= len(provider.responses) {
		panic("capability-market negotiation escaped its scripted no-tool boundary")
	}
	response := provider.responses[provider.calls]
	provider.calls++
	return &providers.LLMResponse{Content: response}, nil
}

func (*capabilityMarketQueuedProvider) GetDefaultModel() string { return "capability-market-test" }

func round5NegotiationTestRuntimes(t *testing.T, buyerDecision string, sellerDecisions ...string) (
	*campaignRuntime,
	*campaignRuntime,
) {
	t.Helper()
	_, buyerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, sellerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	buyer := &campaignRuntime{
		definition: eightAgentManifestEntry{
			Name: "round5-buyer", AgentID: "agent:round5-buyer", MaximumLoss: 1_800_000_000,
		},
		provider: &capabilityMarketQueuedProvider{responses: []string{buyerDecision}},
		model:    "test", identity: buyerKey,
	}
	sellerResponses := []string{
		"I can deliver this bounded generic service at 1800000000 nanotos, with a signed minimum of 1000000000 nanotos.",
	}
	sellerResponses = append(sellerResponses, sellerDecisions...)
	seller := &campaignRuntime{
		definition: eightAgentManifestEntry{
			Name: "round5-seller", AgentID: "agent:round5-seller", Capability: "generic-bounded-service",
			MinimumPrice: 1_000_000_000, Price: 1_800_000_000,
		},
		provider: &capabilityMarketQueuedProvider{responses: sellerResponses},
		model:    "test", identity: sellerKey,
	}
	return buyer, seller
}

func readRound5NegotiationCheckpoint(t *testing.T, root string, sequence int) campaignNegotiationCheckpoint {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "campaign", "conversations",
		fmt.Sprintf("conversation-%03d.json", sequence)))
	if err != nil {
		t.Fatal(err)
	}
	var checkpoint campaignNegotiationCheckpoint
	if err = json.Unmarshal(raw, &checkpoint); err != nil {
		t.Fatal(err)
	}
	return checkpoint
}

func round5NegotiationTestOptions(sequence int) campaignNegotiationOptions {
	return campaignNegotiationOptions{
		RepairMode:    campaignNegotiationRepairRound5,
		CampaignRunID: fmt.Sprintf("round5-negotiation-test-%03d", sequence),
	}
}

func TestRound5NegotiationRepairsOnlyOwnerAuthorizedBuyerFields(t *testing.T) {
	tests := []struct {
		name        string
		decision    string
		maximumLoss uint64
		accepted    bool
		amount      uint64
		repair      string
		kind        string
	}{
		{
			name:        "arbitrary-accept-amount",
			decision:    `{"decision":"accept","amount_nanotos":"777","message":"The bounded scope is worthwhile at the ask."}`,
			maximumLoss: 1_800_000_000, accepted: true, amount: 1_800_000_000,
			repair: campaignNegotiationBuyerAmountRepair, kind: "decision:accept",
		},
		{
			name:        "decline-with-amount",
			decision:    `{"decision":"decline","amount_nanotos":"1800000000","message":"I prefer not to proceed."}`,
			maximumLoss: 1_800_000_000, amount: 0,
			repair: campaignNegotiationBuyerAmountRepair, kind: "decision:decline",
		},
		{
			name:        "impossible-accept",
			decision:    `{"decision":"accept","amount_nanotos":"1800000000","message":"I tried to accept above my owner bound."}`,
			maximumLoss: 1_500_000_000, amount: 0,
			repair: campaignNegotiationBuyerChoiceDeclineRepair, kind: "decision:decline",
		},
		{
			name:        "impossible-counter-at-ask",
			decision:    `{"decision":"counter","amount_nanotos":"1800000000","message":"I tried to counter at the ask."}`,
			maximumLoss: 1_800_000_000, amount: 0,
			repair: campaignNegotiationBuyerChoiceDeclineRepair, kind: "decision:decline",
		},
	}
	for sequence, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			buyer, seller := round5NegotiationTestRuntimes(t, test.decision)
			buyer.definition.MaximumLoss = test.maximumLoss
			root := t.TempDir()
			messages, digest, accepted, amount, err := runCampaignNegotiation(
				context.Background(), root, sequence+30, buyer, seller, "Perform one generic bounded task.",
				time.Unix(2_100_000_000+int64(sequence), 0).UTC(), round5NegotiationTestOptions(sequence+30),
			)
			if err != nil || accepted != test.accepted || amount != test.amount || digest == "" ||
				len(messages) != 3 || messages[2].Kind != test.kind ||
				!strings.Contains(messages[2].Text, "repair_disposition="+test.repair+"; ") {
				t.Fatalf("repair result messages=%+v accepted=%t amount=%d digest=%q err=%v",
					messages, accepted, amount, digest, err)
			}
			checkpoint := readRound5NegotiationCheckpoint(t, root, sequence+30)
			if checkpoint.RepairProfile != campaignNegotiationRound5RepairProfile ||
				checkpoint.CampaignRunID != round5NegotiationTestOptions(sequence+30).CampaignRunID ||
				checkpoint.BuyerOriginalDecision == nil || checkpoint.BuyerOriginalAmount == nil ||
				checkpoint.BuyerModelObjectDigest == "" ||
				!strings.Contains(messages[2].Text,
					"model_object_digest="+checkpoint.BuyerModelObjectDigest+"; ") ||
				!reflect.DeepEqual(checkpoint.RepairDispositions, []string{test.repair}) {
				t.Fatalf("repair was not retained exactly: %+v", checkpoint)
			}
			if test.amount == 0 && strings.HasPrefix(messages[2].Text, "amount_nanotos=") {
				t.Fatal("fail-closed decline retained an amount")
			}
		})
	}
}

func TestRound5NegotiationRepairsSellerCounterAmount(t *testing.T) {
	tests := []struct {
		name     string
		seller   string
		accepted bool
		kind     string
	}{
		{
			name:     "accept-arbitrary-amount",
			seller:   `{"decision":"accept","amount_nanotos":"999","message":"The unchanged task remains worthwhile."}`,
			accepted: true, kind: "counter-decision:accept",
		},
		{
			name:   "decline-with-amount",
			seller: `{"decision":"decline","amount_nanotos":"1500000000","message":"I decline this counter."}`,
			kind:   "counter-decision:decline",
		},
	}
	for sequence, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			buyer, seller := round5NegotiationTestRuntimes(t,
				`{"decision":"counter","amount_nanotos":"1500000000","message":"I offer my exact owner bound."}`,
				test.seller)
			buyer.definition.MaximumLoss = 1_500_000_000
			root := t.TempDir()
			messages, _, accepted, amount, err := runCampaignNegotiation(
				context.Background(), root, sequence+40, buyer, seller, "Perform one generic bounded task.",
				time.Unix(2_100_000_100+int64(sequence), 0).UTC(), round5NegotiationTestOptions(sequence+40),
			)
			if err != nil || accepted != test.accepted || amount != 1_500_000_000 || len(messages) != 4 ||
				messages[3].Kind != test.kind || !strings.Contains(messages[3].Text,
				"repair_disposition="+campaignNegotiationSellerAmountRepair+"; ") {
				t.Fatalf("seller repair result messages=%+v accepted=%t amount=%d err=%v",
					messages, accepted, amount, err)
			}
			checkpoint := readRound5NegotiationCheckpoint(t, root, sequence+40)
			if !reflect.DeepEqual(checkpoint.RepairDispositions,
				[]string{campaignNegotiationSellerAmountRepair}) {
				t.Fatalf("seller repair was not retained exactly: %+v", checkpoint)
			}
		})
	}
}

func TestRound5NegotiationMalformedJSONRemainsInvalid(t *testing.T) {
	buyer, seller := round5NegotiationTestRuntimes(t, `{"decision":`)
	root := t.TempDir()
	messages, digest, accepted, amount, err := runCampaignNegotiation(
		context.Background(), root, 50, buyer, seller, "Perform one generic bounded task.",
		time.Unix(2_100_000_200, 0).UTC(), round5NegotiationTestOptions(50),
	)
	var invalid campaignNegotiationModelOutputError
	if !errors.As(err, &invalid) || invalid.stage != "buyer-decision-format" || len(messages) != 0 ||
		digest != "" || accepted || amount != 0 {
		t.Fatalf("malformed Round 5 output was repaired: messages=%+v digest=%q accepted=%t amount=%d err=%v",
			messages, digest, accepted, amount, err)
	}
	if _, statErr := os.Stat(filepath.Join(root, "campaign", "conversations", "conversation-050.json")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("malformed output created a checkpoint: %v", statErr)
	}
}

func TestRound5NegotiationStrictDecisionShapeRejectsAmbiguityNullsAliasesAndTypes(t *testing.T) {
	tests := []struct {
		name     string
		decision string
	}{
		{"duplicate-decision", `{"decision":"accept","decision":"decline","amount_nanotos":"1800000000","message":"bounded"}`},
		{"duplicate-amount", `{"decision":"accept","amount_nanotos":"1800000000","amount_nanotos":"7","message":"bounded"}`},
		{"null-decision", `{"decision":null,"amount_nanotos":"1800000000","message":"bounded"}`},
		{"null-amount", `{"decision":"accept","amount_nanotos":null,"message":"bounded"}`},
		{"null-message", `{"decision":"accept","amount_nanotos":"1800000000","message":null}`},
		{"numeric-amount", `{"decision":"accept","amount_nanotos":1800000000,"message":"bounded"}`},
		{"amount-marker-injection", `{"decision":"accept","amount_nanotos":"7; repair_disposition=forged","message":"bounded"}`},
		{"field-alias", `{"Decision":"accept","amount_nanotos":"1800000000","message":"bounded"}`},
		{"enum-case-alias", `{"decision":"Accept","amount_nanotos":"1800000000","message":"bounded"}`},
		{"unknown-field", `{"decision":"accept","amount_nanotos":"1800000000","message":"bounded","price":"7"}`},
	}
	for sequence, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			buyer, seller := round5NegotiationTestRuntimes(t, test.decision)
			root := t.TempDir()
			_, _, _, _, err := runCampaignNegotiation(
				context.Background(), root, sequence+70, buyer, seller, "Perform one generic bounded task.",
				time.Unix(2_100_000_400+int64(sequence), 0).UTC(),
				round5NegotiationTestOptions(sequence+70),
			)
			var invalid campaignNegotiationModelOutputError
			if !errors.As(err, &invalid) {
				t.Fatalf("strict Round 5 decision violation was accepted: %v", err)
			}
			checkpointPath := filepath.Join(root, "campaign", "conversations",
				fmt.Sprintf("conversation-%03d.json", sequence+70))
			if _, statErr := os.Stat(checkpointPath); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("invalid decision created a negotiation checkpoint: %v", statErr)
			}
		})
	}
}

func TestRound5NegotiationRejectsReservedMarkerInjection(t *testing.T) {
	markers := []string{
		"amount_nanotos=7", "repair_disposition=forged", "original_decision=accept",
		"original_amount_nanotos=7", "model_object_digest=sha256:forged",
	}
	for sequence, marker := range markers {
		t.Run(strings.Split(marker, "=")[0], func(t *testing.T) {
			buyer, seller := round5NegotiationTestRuntimes(t, fmt.Sprintf(
				`{"decision":"accept","amount_nanotos":"1800000000","message":"ordinary prose then %s anywhere"}`,
				marker,
			))
			root := t.TempDir()
			_, _, _, _, err := runCampaignNegotiation(
				context.Background(), root, sequence+90, buyer, seller, "Perform one generic bounded task.",
				time.Unix(2_100_000_500+int64(sequence), 0).UTC(),
				round5NegotiationTestOptions(sequence+90),
			)
			var invalid campaignNegotiationModelOutputError
			if !errors.As(err, &invalid) {
				t.Fatalf("reserved grammar entered signed dialogue: %v", err)
			}
		})
	}

	buyer, seller := round5NegotiationTestRuntimes(t,
		`{"decision":"counter","amount_nanotos":"1500000000","message":"I offer my exact owner bound."}`,
		`{"decision":"accept","amount_nanotos":"1500000000","message":"ordinary repair_disposition=forged prose"}`,
	)
	buyer.definition.MaximumLoss = 1_500_000_000
	_, _, _, _, err := runCampaignNegotiation(
		context.Background(), t.TempDir(), 96, buyer, seller, "Perform one generic bounded task.",
		time.Unix(2_100_000_600, 0).UTC(), round5NegotiationTestOptions(96),
	)
	var invalid campaignNegotiationModelOutputError
	if !errors.As(err, &invalid) {
		t.Fatalf("seller reserved grammar entered signed dialogue: %v", err)
	}

	quoteBuyer, quoteSeller := round5NegotiationTestRuntimes(t,
		`{"decision":"accept","amount_nanotos":"1800000000","message":"bounded"}`)
	quoteSeller.provider = &capabilityMarketQueuedProvider{responses: []string{
		"ordinary scope prose with amount_nanotos=7 injected anywhere",
	}}
	_, _, _, _, err = runCampaignNegotiation(
		context.Background(), t.TempDir(), 97, quoteBuyer, quoteSeller, "Perform one generic bounded task.",
		time.Unix(2_100_000_601, 0).UTC(), round5NegotiationTestOptions(97),
	)
	if !errors.As(err, &invalid) || invalid.stage != "seller-quote-format" {
		t.Fatalf("reserved grammar in seller quote was accepted: %v", err)
	}
}

func TestRound5NegotiationAttemptBudgetSurvivesRestart(t *testing.T) {
	root := t.TempDir()
	sequence := 110
	options := round5NegotiationTestOptions(sequence)
	now := time.Unix(2_100_000_700, 0).UTC()
	buyer, seller := round5NegotiationTestRuntimes(t, `{"decision":`)
	buyerProvider := &capabilityMarketQueuedProvider{responses: []string{`{"decision":`, `{"decision":`, `{"decision":`}}
	sellerProvider := &capabilityMarketQueuedProvider{responses: []string{
		"bounded quote one", "bounded quote two", "bounded quote three",
	}}
	buyer.provider, seller.provider = buyerProvider, sellerProvider
	for attempt := 0; attempt < maximumCampaignJobAttempts; attempt++ {
		_, _, _, _, err := runCampaignNegotiation(
			context.Background(), root, sequence, buyer, seller, "Perform one generic bounded task.", now, options,
		)
		var invalid campaignNegotiationModelOutputError
		if !errors.As(err, &invalid) {
			t.Fatalf("attempt %d did not fail as invalid model output: %v", attempt+1, err)
		}
	}
	if buyerProvider.calls != maximumCampaignJobAttempts || sellerProvider.calls != maximumCampaignJobAttempts {
		t.Fatalf("unexpected first-process calls buyer=%d seller=%d", buyerProvider.calls, sellerProvider.calls)
	}

	// New Provider instances emulate a process restart. The fsynced journal is
	// authoritative, so exhaustion is detected before even requesting a quote.
	restartedBuyer := &capabilityMarketQueuedProvider{responses: []string{
		`{"decision":"accept","amount_nanotos":"1800000000","message":"bounded"}`,
	}}
	restartedSeller := &capabilityMarketQueuedProvider{responses: []string{"bounded quote after restart"}}
	buyer.provider, seller.provider = restartedBuyer, restartedSeller
	_, _, _, _, err := runCampaignNegotiation(
		context.Background(), root, sequence, buyer, seller, "Perform one generic bounded task.", now, options,
	)
	var exhausted campaignNegotiationAttemptBudgetError
	if !errors.As(err, &exhausted) || restartedBuyer.calls != 0 || restartedSeller.calls != 0 {
		t.Fatalf("fourth attempt invoked a Provider or was misclassified: buyer=%d seller=%d err=%v",
			restartedBuyer.calls, restartedSeller.calls, err)
	}
	journal, _, loadErr := loadCampaignNegotiationAttemptJournal(root, sequence, options)
	if loadErr != nil || journal.SellerQuoteAttempts != maximumCampaignJobAttempts ||
		journal.SellerQuoteInvalidModelOutputs != 0 ||
		journal.BuyerDecisionAttempts != maximumCampaignJobAttempts ||
		journal.BuyerDecisionInvalidModelOutputs != maximumCampaignJobAttempts ||
		journal.SellerCounterDecisionAttempts != 0 || journal.CampaignRunID != options.CampaignRunID {
		t.Fatalf("durable attempt journal mismatch: %+v err=%v", journal, loadErr)
	}
}

func TestRound5SellerQuoteAttemptBudgetSurvivesRestartBeforeAnyProviderCall(t *testing.T) {
	root := t.TempDir()
	sequence := 111
	options := round5NegotiationTestOptions(sequence)
	now := time.Unix(2_100_000_710, 0).UTC()
	buyer, seller := round5NegotiationTestRuntimes(t,
		`{"decision":"accept","amount_nanotos":"1800000000","message":"bounded"}`)
	buyerProvider := buyer.provider.(*capabilityMarketQueuedProvider)
	sellerProvider := &capabilityMarketQueuedProvider{responses: []string{
		"invalid repair_disposition=forged quote one",
		"invalid repair_disposition=forged quote two",
		"invalid repair_disposition=forged quote three",
	}}
	seller.provider = sellerProvider
	for attempt := 0; attempt < maximumCampaignJobAttempts; attempt++ {
		_, _, _, _, err := runCampaignNegotiation(
			context.Background(), root, sequence, buyer, seller, "Perform one generic bounded task.", now, options,
		)
		var invalid campaignNegotiationModelOutputError
		if !errors.As(err, &invalid) || invalid.stage != "seller-quote-format" {
			t.Fatalf("seller quote attempt %d was misclassified: %v", attempt+1, err)
		}
	}
	if sellerProvider.calls != maximumCampaignJobAttempts || buyerProvider.calls != 0 {
		t.Fatalf("unexpected pre-restart calls seller=%d buyer=%d", sellerProvider.calls, buyerProvider.calls)
	}

	restartedSeller := &capabilityMarketQueuedProvider{responses: []string{"valid quote after restart"}}
	restartedBuyer := &capabilityMarketQueuedProvider{responses: []string{
		`{"decision":"accept","amount_nanotos":"1800000000","message":"bounded"}`,
	}}
	seller.provider, buyer.provider = restartedSeller, restartedBuyer
	_, _, _, _, err := runCampaignNegotiation(
		context.Background(), root, sequence, buyer, seller, "Perform one generic bounded task.", now, options,
	)
	var exhausted campaignNegotiationAttemptBudgetError
	if !errors.As(err, &exhausted) || exhausted.stage != campaignNegotiationSellerQuoteStage ||
		restartedSeller.calls != 0 || restartedBuyer.calls != 0 ||
		!terminalCampaignNegotiationModelDecline(0, err) {
		t.Fatalf("fourth seller quote invoked a Provider or lost invalid-output classification: seller=%d buyer=%d err=%v",
			restartedSeller.calls, restartedBuyer.calls, err)
	}
	journal, _, loadErr := loadCampaignNegotiationAttemptJournal(root, sequence, options)
	if loadErr != nil || journal.SellerQuoteAttempts != maximumCampaignJobAttempts ||
		journal.SellerQuoteInvalidModelOutputs != maximumCampaignJobAttempts ||
		journal.BuyerDecisionAttempts != 0 || journal.SellerCounterDecisionAttempts != 0 {
		t.Fatalf("seller quote journal mismatch after restart: %+v err=%v", journal, loadErr)
	}
}

func TestRound5SellerQuoteTransportFailureConsumesBudgetConservatively(t *testing.T) {
	root := t.TempDir()
	sequence := 112
	options := round5NegotiationTestOptions(sequence)
	now := time.Unix(2_100_000_720, 0).UTC()
	buyer, seller := round5NegotiationTestRuntimes(t,
		`{"decision":"accept","amount_nanotos":"1800000000","message":"bounded"}`)
	transportErr := errors.New("seller quote transport unavailable")
	failingSeller := &capabilityMarketFailingProvider{err: transportErr}
	seller.provider = failingSeller
	for attempt := 0; attempt < maximumCampaignJobAttempts; attempt++ {
		_, _, _, _, err := runCampaignNegotiation(
			context.Background(), root, sequence, buyer, seller, "Perform one generic bounded task.", now, options,
		)
		var invalid campaignNegotiationModelOutputError
		if !errors.Is(err, transportErr) || errors.As(err, &invalid) {
			t.Fatalf("seller transport attempt %d was misclassified: %v", attempt+1, err)
		}
	}
	restartedSeller := &capabilityMarketQueuedProvider{responses: []string{"valid quote after transport recovery"}}
	restartedBuyer := &capabilityMarketQueuedProvider{responses: []string{
		`{"decision":"accept","amount_nanotos":"1800000000","message":"bounded"}`,
	}}
	seller.provider, buyer.provider = restartedSeller, restartedBuyer
	_, _, _, _, err := runCampaignNegotiation(
		context.Background(), root, sequence, buyer, seller, "Perform one generic bounded task.", now, options,
	)
	var exhausted campaignNegotiationAttemptBudgetError
	if !errors.As(err, &exhausted) || exhausted.stage != campaignNegotiationSellerQuoteStage ||
		restartedSeller.calls != 0 || restartedBuyer.calls != 0 ||
		terminalCampaignNegotiationModelDecline(maximumCampaignJobAttempts-1, err) {
		t.Fatalf("transport exhaustion invoked a Provider or became a model decline: seller=%d buyer=%d err=%v",
			restartedSeller.calls, restartedBuyer.calls, err)
	}
	journal, _, loadErr := loadCampaignNegotiationAttemptJournal(root, sequence, options)
	if loadErr != nil || journal.SellerQuoteAttempts != maximumCampaignJobAttempts ||
		journal.SellerQuoteInvalidModelOutputs != 0 {
		t.Fatalf("transport reservation was not conservatively retained: %+v err=%v", journal, loadErr)
	}
}

func TestRound5NegotiationCheckpointCannotCrossRunScope(t *testing.T) {
	buyer, seller := round5NegotiationTestRuntimes(t,
		`{"decision":"accept","amount_nanotos":"1800000000","message":"The bounded scope is worthwhile."}`)
	root := t.TempDir()
	sequence := 120
	task := "Perform one generic bounded task."
	now := time.Unix(2_100_000_800, 0).UTC()
	if _, _, _, _, err := runCampaignNegotiation(
		context.Background(), root, sequence, buyer, seller, task, now, round5NegotiationTestOptions(sequence),
	); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "campaign", "conversations", "conversation-120.json")
	different := campaignNegotiationOptions{
		RepairMode: campaignNegotiationRepairRound5, CampaignRunID: "round5-negotiation-test-cross-run",
	}
	if _, found, err := loadCampaignNegotiationCheckpoint(
		path, sequence, buyer, seller, task, now, 1_000_000_000, 1_800_000_000, 1_800_000_000, different,
	); err == nil || found || !strings.Contains(err.Error(), "conflicts with this turn") {
		t.Fatalf("cross-run checkpoint was accepted: found=%t err=%v", found, err)
	}
}

func TestRound5NegotiationRepairAggregateCountsExactDispositions(t *testing.T) {
	aggregate, err := aggregateCampaignNegotiationRepairs([]eightAgentJobResult{
		{NegotiationRepairProfile: campaignNegotiationRound5RepairProfile,
			NegotiationRepairDispositions: []string{campaignNegotiationBuyerAmountRepair}},
		{NegotiationRepairProfile: campaignNegotiationRound5RepairProfile,
			NegotiationRepairDispositions: []string{
				campaignNegotiationBuyerChoiceDeclineRepair, campaignNegotiationSellerAmountRepair,
			}},
		{},
	})
	if err != nil || aggregate == nil || aggregate.Profile != campaignNegotiationRound5RepairProfile ||
		aggregate.ProfiledResults != 2 || aggregate.TotalRepairs != 3 ||
		aggregate.Dispositions[campaignNegotiationBuyerAmountRepair] != 1 ||
		aggregate.Dispositions[campaignNegotiationBuyerChoiceDeclineRepair] != 1 ||
		aggregate.Dispositions[campaignNegotiationSellerAmountRepair] != 1 {
		t.Fatalf("unexpected repair aggregate: %+v err=%v", aggregate, err)
	}
	if _, err = aggregateCampaignNegotiationRepairs([]eightAgentJobResult{{
		NegotiationRepairDispositions: []string{campaignNegotiationBuyerAmountRepair},
	}}); err == nil {
		t.Fatal("repair aggregate accepted a disposition without an explicit profile")
	}
}

func TestRound5SellerCounterAttemptBudgetIsIndependentAndDurable(t *testing.T) {
	root := t.TempDir()
	sequence := 121
	options := round5NegotiationTestOptions(sequence)
	for attempt := 0; attempt < maximumCampaignJobAttempts; attempt++ {
		if err := reserveCampaignNegotiationModelAttempt(
			root, sequence, options, campaignNegotiationSellerCounterDecisionStage,
		); err != nil {
			t.Fatal(err)
		}
	}
	if err := reserveCampaignNegotiationModelAttempt(
		root, sequence, options, campaignNegotiationSellerCounterDecisionStage,
	); err == nil {
		t.Fatal("fourth seller counter-decision attempt was not rejected")
	}
	journal, path, err := loadCampaignNegotiationAttemptJournal(root, sequence, options)
	if err != nil || journal.BuyerDecisionAttempts != 0 ||
		journal.SellerCounterDecisionAttempts != maximumCampaignJobAttempts {
		t.Fatalf("seller-stage attempt budget was not independently retained: %+v path=%q err=%v",
			journal, path, err)
	}
	differentRun := options
	differentRun.CampaignRunID = "round5-negotiation-test-different-journal-run"
	if _, _, err = loadCampaignNegotiationAttemptJournal(root, sequence, differentRun); err == nil {
		t.Fatal("copied negotiation attempt journal was accepted in a different run scope")
	}
}

func TestRound5RunIDIsNotNegotiationRepairAuthority(t *testing.T) {
	if err := validateCampaignRunID("round5:nonce-is-identity-only"); err != nil {
		t.Fatal(err)
	}
	buyer := &campaignRuntime{}
	seller := &campaignRuntime{}
	mode, err := campaignNegotiationRepairModeForRuntimes(buyer, seller)
	if err != nil || mode != campaignNegotiationRepairDisabled {
		t.Fatalf("a Round 5-shaped nonce changed the explicit runtime profile: mode=%d err=%v", mode, err)
	}
	buyer.negotiationRepairMode = campaignNegotiationRepairRound5
	if _, err = campaignNegotiationRepairModeForRuntimes(buyer, seller); err == nil {
		t.Fatal("counterparties with mismatched explicit profiles were accepted")
	}
}

func TestRound5NegotiationResumeRejectsCheckpointTamperingAndNonCanonicalBytes(t *testing.T) {
	buyer, seller := round5NegotiationTestRuntimes(t,
		`{"decision":"accept","amount_nanotos":"777","message":"The bounded scope is worthwhile."}`)
	root := t.TempDir()
	task := "Perform one generic bounded task."
	now := time.Unix(2_100_000_300, 0).UTC()
	if _, _, _, _, err := runCampaignNegotiation(context.Background(), root, 60, buyer, seller, task, now,
		round5NegotiationTestOptions(60)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "campaign", "conversations", "conversation-060.json")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var checkpoint campaignNegotiationCheckpoint
	if err = json.Unmarshal(original, &checkpoint); err != nil {
		t.Fatal(err)
	}
	checkpoint.RepairDispositions = nil
	tampered, err := json.MarshalIndent(checkpoint, "", "  ")
	if err != nil || os.WriteFile(path, tampered, 0o600) != nil {
		t.Fatal(err)
	}
	if _, found, loadErr := loadCampaignNegotiationCheckpoint(path, 60, buyer, seller, task, now,
		1_000_000_000, 1_800_000_000, 1_800_000_000, round5NegotiationTestOptions(60)); loadErr == nil || found {
		t.Fatalf("repair-disposition tampering was accepted: found=%t err=%v", found, loadErr)
	}
	if err = json.Unmarshal(original, &checkpoint); err != nil {
		t.Fatal(err)
	}
	checkpoint.BuyerModelObjectDigest = "sha256:" + strings.Repeat("0", 64)
	tampered, err = json.MarshalIndent(checkpoint, "", "  ")
	if err != nil || os.WriteFile(path, tampered, 0o600) != nil {
		t.Fatal(err)
	}
	if _, found, loadErr := loadCampaignNegotiationCheckpoint(path, 60, buyer, seller, task, now,
		1_000_000_000, 1_800_000_000, 1_800_000_000, round5NegotiationTestOptions(60)); loadErr == nil || found {
		t.Fatalf("model-object digest tampering was accepted: found=%t err=%v", found, loadErr)
	}
	if err = os.WriteFile(path, append(append([]byte(nil), original...), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, found, loadErr := loadCampaignNegotiationCheckpoint(path, 60, buyer, seller, task, now,
		1_000_000_000, 1_800_000_000, 1_800_000_000, round5NegotiationTestOptions(60)); loadErr == nil || found || !strings.Contains(loadErr.Error(), "not canonical") {
		t.Fatalf("non-canonical checkpoint was accepted: found=%t err=%v", found, loadErr)
	}
}

func TestCapabilityMarketNegotiationCreatesSignedCounterOffer(t *testing.T) {
	buyerPublic, buyerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil || len(buyerPublic) != ed25519.PublicKeySize {
		t.Fatal(err)
	}
	_, sellerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	buyerProvider := &capabilityMarketQueuedProvider{responses: []string{
		`{"decision":"counter","amount_nanotos":"1500000000","message":"The narrower data snapshot is worthwhile at my exact signed budget."}`,
	}}
	sellerProvider := &capabilityMarketQueuedProvider{responses: []string{
		"I can deliver the bounded sourced snapshot with explicit missingness and provenance. The asking price is 1800000000 nanotos, with no real personal data. A bounded counter-offer inside the signed range may be considered.",
		`{"decision":"accept","amount_nanotos":"1500000000","message":"The unchanged scope remains profitable at this price; typed V2 acceptance is still required."}`,
	}}
	buyer := &campaignRuntime{definition: eightAgentManifestEntry{Name: "planfox", AgentID: "agent:planfox",
		MaximumLoss: 1_500_000_000}, provider: buyerProvider, model: "test", identity: buyerKey}
	seller := &campaignRuntime{definition: eightAgentManifestEntry{Name: "poifox", AgentID: "agent:poifox",
		Capability: "sourced-poi-data-snapshot", MinimumPrice: 1_000_000_000, Price: 1_800_000_000},
		provider: sellerProvider, model: "test", identity: sellerKey}
	root := t.TempDir()
	task := "Create a fictional three-area POI snapshot with provenance and missingness."
	now := time.Unix(2_000_000_000, 0).UTC()
	messages, digest, accepted, amount, err := runCampaignNegotiation(context.Background(), root, 1,
		buyer, seller, task, now)
	if err != nil || !accepted || amount != buyer.definition.MaximumLoss || digest == "" || len(messages) != 4 {
		t.Fatalf("counter-offer result messages=%d digest=%q accepted=%t amount=%d err=%v",
			len(messages), digest, accepted, amount, err)
	}
	if messages[2].Kind != "decision:counter" || messages[3].Kind != "counter-decision:accept" ||
		buyerProvider.calls != 1 || sellerProvider.calls != 2 {
		t.Fatalf("counter-offer lineage or model calls are wrong: messages=%+v", messages)
	}
	replayed, replayDigest, replayAccepted, replayAmount, replayErr := runCampaignNegotiation(
		context.Background(), root, 1, buyer, seller, task, now,
	)
	if replayErr != nil || replayDigest != digest || replayAccepted != accepted || replayAmount != amount ||
		!reflect.DeepEqual(replayed, messages) || buyerProvider.calls != 1 || sellerProvider.calls != 2 {
		t.Fatalf("crash-gap replay changed immutable negotiation: messages=%+v digest=%q accepted=%t amount=%d err=%v",
			replayed, replayDigest, replayAccepted, replayAmount, replayErr)
	}
	if _, _, _, _, forkErr := runCampaignNegotiation(context.Background(), root, 1, buyer, seller,
		task+" Changed after the crash.", now); forkErr == nil || buyerProvider.calls != 1 || sellerProvider.calls != 2 {
		t.Fatal("conflicting crash-gap retry regenerated or accepted a forked negotiation")
	}
	checkpointPath := filepath.Join(root, "campaign", "conversations", "conversation-001.json")
	checkpointRaw, readErr := os.ReadFile(checkpointPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	conflictRaw := bytes.Replace(checkpointRaw, []byte(`"accepted": true`), []byte(`"accepted": false`), 1)
	if bytes.Equal(conflictRaw, checkpointRaw) {
		t.Fatal("test did not construct a conflicting negotiation checkpoint")
	}
	if writeErr := writeCampaignNegotiationCheckpointOnce(checkpointPath, conflictRaw); writeErr == nil {
		t.Fatal("write-once negotiation checkpoint accepted conflicting bytes")
	}
	retained, readErr := os.ReadFile(checkpointPath)
	if readErr != nil || !bytes.Equal(retained, checkpointRaw) {
		t.Fatal("conflicting write changed the retained negotiation checkpoint")
	}
}

func TestCapabilityMarketNegotiationRejectsNoPriceOverlap(t *testing.T) {
	_, buyerKey, _ := ed25519.GenerateKey(rand.Reader)
	_, sellerKey, _ := ed25519.GenerateKey(rand.Reader)
	buyerProvider := &capabilityMarketQueuedProvider{responses: []string{
		`{"decision":"decline","amount_nanotos":"","message":"My signed maximum is below the seller floor, so no authorized price overlaps."}`,
	}}
	sellerProvider := &capabilityMarketQueuedProvider{responses: []string{
		"I can deliver the bounded review for an asking price of 2400000000 nanotos; my signed minimum is 1200000000 nanotos.",
	}}
	buyer := &campaignRuntime{definition: eightAgentManifestEntry{Name: "linguafox", AgentID: "agent:linguafox",
		MaximumLoss: 1_000_000_000}, provider: buyerProvider, model: "test", identity: buyerKey}
	seller := &campaignRuntime{definition: eightAgentManifestEntry{Name: "apifox", AgentID: "agent:apifox",
		Capability: "api-adapter-security-review", MinimumPrice: 1_200_000_000, Price: 2_400_000_000},
		provider: sellerProvider, model: "test", identity: sellerKey}
	messages, digest, accepted, amount, err := runCampaignNegotiation(context.Background(), t.TempDir(), 2,
		buyer, seller, "Review a bounded fictional POI adapter for retry and authentication risks.",
		time.Unix(2_000_000_100, 0).UTC())
	if err != nil || accepted || amount != 0 || digest == "" || len(messages) != 3 ||
		messages[2].Kind != "decision:decline" || sellerProvider.calls != 1 {
		t.Fatalf("no-overlap negotiation crossed a side-effect boundary: messages=%+v accepted=%t amount=%d err=%v",
			messages, accepted, amount, err)
	}
}

func TestCapabilityMarketInvalidModelPriceBecomesDeclineOnlyAfterBoundedRetries(t *testing.T) {
	_, buyerKey, _ := ed25519.GenerateKey(rand.Reader)
	_, sellerKey, _ := ed25519.GenerateKey(rand.Reader)
	const sellerReply = "I can deliver the bounded snapshot for 1800000000 nanotos, with a signed minimum of 1000000000 nanotos. A bounded counter-offer may be considered."
	const escapedBuyerPrice = `{"decision":"accept","amount_nanotos":"1800000000","message":"I accept the asking price despite my lower signed maximum."}`
	buyerProvider := &capabilityMarketQueuedProvider{responses: []string{
		escapedBuyerPrice, escapedBuyerPrice, escapedBuyerPrice,
	}}
	sellerProvider := &capabilityMarketQueuedProvider{responses: []string{
		sellerReply, sellerReply, sellerReply,
	}}
	buyer := &campaignRuntime{definition: eightAgentManifestEntry{Name: "planfox", AgentID: "agent:planfox",
		MaximumLoss: 1_500_000_000}, provider: buyerProvider, model: "test", identity: buyerKey}
	seller := &campaignRuntime{definition: eightAgentManifestEntry{Name: "poifox", AgentID: "agent:poifox",
		Capability: "sourced-poi-data-snapshot", MinimumPrice: 1_000_000_000, Price: 1_800_000_000},
		provider: sellerProvider, model: "test", identity: sellerKey}
	root := t.TempDir()
	task := "Create a fictional three-area POI snapshot with provenance and missingness."
	now := time.Unix(2_000_000_200, 0).UTC()
	for attempt := 0; attempt < maximumCampaignJobAttempts; attempt++ {
		messages, digest, accepted, amount, err := runCampaignNegotiation(
			context.Background(), root, 8, buyer, seller, task, now)
		var invalidOutput campaignNegotiationModelOutputError
		if !errors.As(err, &invalidOutput) || invalidOutput.stage != "buyer-decision-policy" ||
			!strings.Contains(err.Error(), "escaped signed owner bounds") || len(messages) != 0 ||
			digest != "" || accepted || amount != 0 {
			t.Fatalf("attempt %d did not preserve the typed owner-bound rejection: messages=%+v digest=%q accepted=%t amount=%d err=%v",
				attempt+1, messages, digest, accepted, amount, err)
		}
		if got, want := terminalCampaignNegotiationModelDecline(attempt, err),
			attempt+1 == maximumCampaignJobAttempts; got != want {
			t.Fatalf("attempt %d terminal=%t want=%t", attempt+1, got, want)
		}
	}
	checkpoint := filepath.Join(root, "campaign", "conversations", "conversation-008.json")
	if _, err := os.Stat(checkpoint); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid model output created a negotiation checkpoint: %v", err)
	}
	if buyerProvider.calls != maximumCampaignJobAttempts || sellerProvider.calls != maximumCampaignJobAttempts {
		t.Fatalf("bounded retry count changed: buyer=%d seller=%d", buyerProvider.calls, sellerProvider.calls)
	}
	if terminalCampaignNegotiationModelDecline(maximumCampaignJobAttempts-1,
		errors.New("provider transport failed")) {
		t.Fatal("an untyped transport/storage failure was converted into a negotiation decline")
	}
}

type capabilityMarketTransportFailureProvider struct{}

func (*capabilityMarketTransportFailureProvider) Chat(context.Context, []providers.Message,
	[]providers.ToolDefinition, string, map[string]any) (*providers.LLMResponse, error) {
	return nil, errors.New("capability-market provider transport unavailable")
}

func (*capabilityMarketTransportFailureProvider) GetDefaultModel() string {
	return "transport-failure-test"
}

func TestCapabilityMarketBlankSellerOutputBecomesDeclineButTransportRemainsFatal(t *testing.T) {
	_, buyerKey, _ := ed25519.GenerateKey(rand.Reader)
	_, sellerKey, _ := ed25519.GenerateKey(rand.Reader)
	buyerProvider := &capabilityMarketQueuedProvider{}
	sellerProvider := &capabilityMarketQueuedProvider{responses: []string{" \n\t", "\n", "   "}}
	buyer := &campaignRuntime{definition: eightAgentManifestEntry{Name: "planfox", AgentID: "agent:planfox",
		MaximumLoss: 1_500_000_000}, provider: buyerProvider, model: "test", identity: buyerKey}
	seller := &campaignRuntime{definition: eightAgentManifestEntry{Name: "poifox", AgentID: "agent:poifox",
		Capability: "sourced-poi-data-snapshot", MinimumPrice: 1_000_000_000, Price: 1_800_000_000},
		provider: sellerProvider, model: "test", identity: sellerKey}
	root := t.TempDir()
	for attempt := 0; attempt < maximumCampaignJobAttempts; attempt++ {
		messages, digest, accepted, amount, err := runCampaignNegotiation(context.Background(), root, 9,
			buyer, seller, "Create a bounded fictional POI snapshot.", time.Unix(2_000_000_300, 0).UTC())
		var invalidOutput campaignNegotiationModelOutputError
		if !errors.As(err, &invalidOutput) || invalidOutput.stage != "model-response-envelope" ||
			len(messages) != 0 || digest != "" || accepted || amount != 0 ||
			terminalCampaignNegotiationModelDecline(attempt, err) != (attempt+1 == maximumCampaignJobAttempts) {
			t.Fatalf("blank seller attempt %d was not a bounded typed failure: messages=%+v digest=%q accepted=%t amount=%d err=%v",
				attempt+1, messages, digest, accepted, amount, err)
		}
	}
	if sellerProvider.calls != maximumCampaignJobAttempts || buyerProvider.calls != 0 {
		t.Fatalf("blank seller output crossed the buyer boundary: seller=%d buyer=%d",
			sellerProvider.calls, buyerProvider.calls)
	}
	checkpoint := filepath.Join(root, "campaign", "conversations", "conversation-009.json")
	if _, err := os.Stat(checkpoint); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("blank seller output created a negotiation checkpoint: %v", err)
	}

	transportSeller := *seller
	transportSeller.provider = &capabilityMarketTransportFailureProvider{}
	_, _, _, _, err := runCampaignNegotiation(context.Background(), t.TempDir(), 10, buyer, &transportSeller,
		"Create a bounded fictional POI snapshot.", time.Unix(2_000_000_301, 0).UTC())
	var invalidOutput campaignNegotiationModelOutputError
	if err == nil || errors.As(err, &invalidOutput) || terminalCampaignNegotiationModelDecline(
		maximumCampaignJobAttempts-1, err) {
		t.Fatalf("provider transport failure was downgraded to a model decline: %v", err)
	}
}

type capabilityMarketAcceptedAgreementFixture struct {
	now         time.Time
	task        string
	buyer       *campaignRuntime
	seller      *campaignRuntime
	checkpoint  campaignAcceptedAgreementCheckpoint
	negotiation campaignNegotiationCheckpoint
}

func TestCapabilityMarketAcceptedAgreementResumeRequiresExactRebuiltBody(t *testing.T) {
	counter := newCapabilityMarketAcceptedAgreementFixture(t)
	direct := counter
	directBuyer := *counter.buyer
	directBuyer.definition.MaximumLoss = counter.seller.definition.Price
	direct.buyer = &directBuyer
	directBody, err := buildCampaignNegotiatedAgreement(3, direct.buyer, direct.seller, direct.task, direct.now,
		direct.seller.definition.Price)
	if err != nil {
		t.Fatal(err)
	}
	direct.checkpoint.Body = directBody
	direct.checkpoint.ConversationMessageCount = 3
	direct.negotiation.BuyerBudgetNanoTOS = direct.seller.definition.Price
	direct.negotiation.BuyerDecision = "accept"
	direct.negotiation.SellerCounterDecision = ""
	direct.negotiation.NegotiatedAmountNanoTOS = direct.seller.definition.Price
	direct.negotiation.Messages = make([]campaignConversationMessage, 3)
	mutations := map[string]func(*commerce.AgentAgreementBody){
		"terms": func(body *commerce.AgentAgreementBody) {
			body.Terms = []byte("different but syntactically valid work terms")
		},
		"work-subject": func(body *commerce.AgentAgreementBody) {
			for index := range body.Obligations {
				if body.Obligations[index].ObligationID == "work" {
					body.Obligations[index].Subject = []byte("perform a different service")
				}
			}
		},
		"obligation-policy": func(body *commerce.AgentAgreementBody) {
			for index := range body.Obligations {
				if body.Obligations[index].ObligationID == "work" {
					body.Obligations[index].CancellationPolicy = "owner-review"
				}
			}
		},
		"payment-obligation": func(body *commerce.AgentAgreementBody) {
			for index := range body.Obligations {
				if body.Obligations[index].ObligationID == "pay" {
					body.Obligations[index].Subject = []byte("pay under different retained terms")
				}
			}
		},
		"payment-due-time": func(body *commerce.AgentAgreementBody) {
			for index := range body.Obligations {
				if body.Obligations[index].ObligationID == "pay" {
					body.Obligations[index].DueAtUnix--
				}
			}
		},
	}
	profiles := map[string]capabilityMarketAcceptedAgreementFixture{"v1-direct": direct, "v2-counter": counter}
	for profile, fixture := range profiles {
		t.Run(profile+"-baseline", func(t *testing.T) {
			baseline, resumeErr := validateCampaignAcceptedAgreementResume(fixture.checkpoint, fixture.negotiation, 3,
				fixture.buyer, fixture.seller, fixture.task, fixture.now)
			if resumeErr != nil || !sameJSON(baseline, fixture.checkpoint.Body) ||
				(profile == "v1-direct" && (baseline.Version != 1 || baseline.PredecessorAgreementDigest != "")) ||
				(profile == "v2-counter" && (baseline.Version != 2 || baseline.PredecessorAgreementDigest == "")) {
				t.Fatalf("exact negotiated Agreement did not resume: body=%+v err=%v", baseline, resumeErr)
			}
		})
		for name, mutate := range mutations {
			t.Run(profile+"-"+name, func(t *testing.T) {
				tampered := fixture.checkpoint
				raw, marshalErr := json.Marshal(fixture.checkpoint.Body)
				if marshalErr != nil || json.Unmarshal(raw, &tampered.Body) != nil {
					t.Fatal(marshalErr)
				}
				mutate(&tampered.Body)
				for index := range tampered.Body.AuthorizationPredicates {
					tampered.Body.AuthorizationPredicates[index].EvidenceTargetProjectionDigest = ""
				}
				tampered.Body, marshalErr = commerce.PrepareAgreementTargets(tampered.Body)
				if marshalErr != nil || commerce.ValidateAgreementBody(tampered.Body) != nil {
					t.Fatalf("test mutation was not a structurally valid Agreement: %v", marshalErr)
				}
				if _, resumeErr := validateCampaignAcceptedAgreementResume(tampered, fixture.negotiation, 3,
					fixture.buyer, fixture.seller, fixture.task, fixture.now); resumeErr == nil {
					t.Fatal("structurally valid but mutated accepted Agreement crossed the resume boundary")
				}
			})
		}
		if profile == "v2-counter" {
			t.Run(profile+"-predecessor", func(t *testing.T) {
				tampered := fixture.checkpoint
				raw, marshalErr := json.Marshal(fixture.checkpoint.Body)
				if marshalErr != nil || json.Unmarshal(raw, &tampered.Body) != nil {
					t.Fatal(marshalErr)
				}
				tampered.Body.PredecessorAgreementDigest = campaignDigest("different-negotiated-predecessor")
				for index := range tampered.Body.AuthorizationPredicates {
					tampered.Body.AuthorizationPredicates[index].EvidenceTargetProjectionDigest = ""
				}
				tampered.Body, marshalErr = commerce.PrepareAgreementTargets(tampered.Body)
				if marshalErr != nil || commerce.ValidateAgreementBody(tampered.Body) != nil {
					t.Fatalf("predecessor mutation was not structurally valid: %v", marshalErr)
				}
				if _, resumeErr := validateCampaignAcceptedAgreementResume(tampered, fixture.negotiation, 3,
					fixture.buyer, fixture.seller, fixture.task, fixture.now); resumeErr == nil {
					t.Fatal("mutated V2 predecessor crossed the resume boundary")
				}
			})
		}
	}
}

func TestCapabilityMarketAcceptedAgreementCheckpointIsStrictPrivateAndWriteOnce(t *testing.T) {
	fixture := newCapabilityMarketAcceptedAgreementFixture(t)
	root := t.TempDir()
	directory := filepath.Join(root, "campaign", "agreements")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "accepted-preflight-003.json")
	raw, err := json.MarshalIndent(fixture.checkpoint, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = writeCampaignAcceptedAgreementCheckpointOnce(path, raw); err != nil {
		t.Fatal(err)
	}
	loaded, found, err := loadCampaignAcceptedAgreementCheckpoint(path, 3, fixture.buyer, fixture.seller,
		fixture.task, fixture.now)
	if err != nil || !found || !sameJSON(loaded, fixture.checkpoint) {
		t.Fatalf("strict accepted Agreement checkpoint did not round-trip: found=%t err=%v", found, err)
	}
	conflict := fixture.checkpoint
	conflict.Body.Terms = []byte("conflicting checkpoint terms")
	conflictRaw, err := json.MarshalIndent(conflict, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = writeCampaignAcceptedAgreementCheckpointOnce(path, conflictRaw); err == nil {
		t.Fatal("write-once accepted Agreement checkpoint accepted conflicting bytes")
	}
	retained, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(retained, raw) {
		t.Fatalf("conflicting accepted Agreement write changed retained bytes: %v", err)
	}
	if err = os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, _, err = loadCampaignAcceptedAgreementCheckpoint(path, 3, fixture.buyer, fixture.seller,
		fixture.task, fixture.now); err == nil {
		t.Fatal("non-private accepted Agreement checkpoint was loaded")
	}
}

func newCapabilityMarketAcceptedAgreementFixture(t *testing.T) capabilityMarketAcceptedAgreementFixture {
	t.Helper()
	buyerPublic, buyerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, sellerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(2_000_000_000, 0).UTC()
	task := "Create a fictional three-area POI snapshot with provenance and missingness."
	buyer := &campaignRuntime{definition: eightAgentManifestEntry{Name: "planfox", OwnerID: "owner:planfox",
		AgentID: "agent:planfox", MaximumLoss: 1_500_000_000}, identity: buyerKey}
	seller := &campaignRuntime{definition: eightAgentManifestEntry{Name: "poifox", OwnerID: "owner:poifox",
		AgentID: "agent:poifox", Target: "0:" + strings.Repeat("a", 64),
		Capability: "sourced-poi-data-snapshot", Taxonomy: "data-api",
		MinimumPrice: 1_000_000_000, Price: 1_800_000_000}, identity: sellerKey}
	seller.collector.Authority = testIntentAuthority{key: buyerPublic}
	detail := []byte(task)
	intentBody := commerce.AgentIntentBody{SchemaVersion: 1, NetworkID: "tos:local-three-node",
		IssuerAgentID: buyer.definition.AgentID, Audience: "public:indexable",
		ObjectID: "intent:" + strings.TrimPrefix(campaignDigest("accepted-resume-demand"), "sha256:"), Revision: 1,
		CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()),
		Payload: commerce.AgentIntentPayload{DiscoveryCard: commerce.DiscoveryCard{
			Summary: "Request one bounded POI snapshot", IntentModes: []commerce.IntentMode{commerce.IntentRequest},
			SubjectClasses: []commerce.SubjectClass{commerce.SubjectService},
			TaxonomyPaths:  []string{"tos.taxonomy.v1/service/data-api/pilot"},
			Keywords:       []commerce.IntentKeyword{{Text: seller.definition.Capability}},
			CapabilityHints: []commerce.CapabilityHint{{Relation: "required", CapabilityNamespace: "tos.skill",
				CapabilityIdentifier: seller.definition.Capability}}, ValueState: commerce.ValueSpecified,
			ValueHints: []commerce.ValueHint{{Role: "budget", AssetNamespace: "tos.asset", AssetIdentifier: "native",
				AmountKind: "exact", MinimumDecimal: "1500000000", MaximumDecimal: "1500000000", Unit: "nanotos"}},
			Schedule: commerce.IntentSchedule{DesiredCompletionUnix: uint64(now.Add(30 * time.Minute).Unix()),
				Flexibility: "flexible"}, FulfillmentModes: []string{"remote"}},
			DetailDescriptor: commerce.ContentDescriptor{ContentType: "text/plain", ContentDigest: campaignDigest(task),
				ContentSize: uint64(len(detail)), InlineContent: detail},
			ReplyRoutes: []commerce.ReplyRoute{{ProfileURI: "tos.messenger.direct.v1", AgentID: buyer.definition.AgentID}},
			SettlementPreferences: []commerce.SettlementPreference{{AdapterURI: "tos.payment.direct.v1", Required: true,
				Parameters: []byte(`{"network_id":"tos:local-three-node","asset":"native","unit":"nanotos"}`)}}}}
	intent, err := commerce.SignIntent(intentBody, buyerKey)
	if err != nil {
		t.Fatal(err)
	}
	intentDigest, err := commerce.IntentBodyDigest(intent.Body)
	if err != nil {
		t.Fatal(err)
	}
	body, err := buildCampaignNegotiatedAgreement(3, buyer, seller, task, now, buyer.definition.MaximumLoss)
	if err != nil {
		t.Fatal(err)
	}
	conversationDigest := campaignDigest("accepted-resume-conversation")
	checkpoint := campaignAcceptedAgreementCheckpoint{Schema: "tos.openfox.campaign-accepted-agreement.v1",
		Sequence: 3, BuyerAgentID: buyer.definition.AgentID, SellerAgentID: seller.definition.AgentID, Body: body,
		DemandIntentDigest: intentDigest, Assessment: CandidateAssessment{IntentDigest: intentDigest, Intent: intent,
			Decision:   EconomicDecision{Eligible: true},
			CarrierIDs: []string{"carrier:gateway-local-pilot", "carrier:messenger-local-pilot"}},
		EconomicAnalysisMode: "ai", ConversationDigest: conversationDigest, ConversationMessageCount: 4}
	negotiation := campaignNegotiationCheckpoint{Schema: "tos.openfox.signed-negotiation.v2", Sequence: 3,
		BuyerAgentID: buyer.definition.AgentID, SellerAgentID: seller.definition.AgentID,
		TaskDigest: campaignDigest(task), SellerMinimumNanoTOS: seller.definition.MinimumPrice,
		SellerAskingNanoTOS: seller.definition.Price, BuyerBudgetNanoTOS: buyer.definition.MaximumLoss,
		BuyerDecision: "counter", SellerCounterDecision: "accept",
		NegotiatedAmountNanoTOS: buyer.definition.MaximumLoss, Accepted: true,
		ConversationDigest: conversationDigest, Messages: make([]campaignConversationMessage, 4)}
	return capabilityMarketAcceptedAgreementFixture{now: now, task: task, buyer: buyer, seller: seller,
		checkpoint: checkpoint, negotiation: negotiation}
}
