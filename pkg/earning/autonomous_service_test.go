package earning

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

type cursorCarrier struct {
	id     string
	result CarrierResult
}

func (carrier cursorCarrier) ID() string { return carrier.id }
func (carrier cursorCarrier) Search(_ context.Context, query IntentQuery) ([]CarrierResult, error) {
	if query.Cursor == "seq:1" {
		return nil, nil
	}
	return []CarrierResult{carrier.result}, nil
}

func TestAutonomousServiceReplaysUntilHandlerCommits(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	intent := earningIntent(t, now, privateKey)
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenOpportunityJournal(directory, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	inventory := InventorySnapshot{OwnerID: "owner:test", AgentID: "agent:worker", CreatedAtUnix: uint64(now.Unix()),
		ExpiresAtUnix: uint64(now.Add(time.Minute).Unix()), SourceGeneration: 1, PortfolioRevision: 1, PolicyRevision: 1,
		ConsistencyToken: "snapshot:1", Capabilities: []Capability{{Namespace: "openfox.skill", Identifier: "security-review", Version: "1",
			State: CapabilityReady, Authority: "owner:test", EvidenceDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			RevocationGeneration: 1, ExpiresAtUnix: uint64(now.Add(time.Minute).Unix())}}, SupportedSettlementAdapters: []string{"tos.payment.direct.v1"}}
	estimate := EconomicEstimate{RevenueAtomic: "100", PaymentProbabilityPPM: 1_000_000, CompletionProbabilityPPM: 1_000_000,
		ComputeCostAtomic: "10", MaximumLossAtomic: "10", EstimatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(time.Minute).Unix()),
		EvidenceDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	carrier := cursorCarrier{id: "carrier:a", result: CarrierResult{Intent: intent, CarrierID: "carrier:a", Cursor: "seq:1"}}
	collector := Collector{Carriers: []Carrier{carrier}, Authority: testIntentAuthority{key: publicKey}, Inventory: staticInventory{value: inventory},
		Estimator: staticEstimator{value: estimate}, Policy: EconomicPolicy{MinimumExpectedProfitAtomic: "1", MaximumLossAtomic: "100"},
		Journal: journal, Now: func() time.Time { return now }}
	attempts := 0
	service := AutonomousService{Collector: collector, Handler: CandidateHandlerFunc(func(context.Context, CandidateAssessment) error {
		attempts++
		if attempts == 1 {
			return errors.New("temporary Messenger outage")
		}
		return nil
	}), Config: AutonomousServiceConfig{Query: IntentQuery{Modes: []commerce.IntentMode{commerce.IntentRequest}, MaximumResults: 10},
		Interval: time.Minute, CycleTimeout: 10 * time.Second}, Now: func() time.Time { return now }}
	if err := service.RunCycle(context.Background()); err == nil {
		t.Fatal("handler failure was hidden")
	}
	if err := service.RunCycle(context.Background()); err != nil {
		t.Fatalf("durable replay failed: %v", err)
	}
	if err := service.RunCycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	status := service.Status()
	if attempts != 2 || status.CandidatesCommitted != 1 || status.Failures != 1 {
		t.Fatalf("attempts=%d status=%+v", attempts, status)
	}
}
