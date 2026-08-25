package earning

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

type testIntentAuthority struct{ key ed25519.PublicKey }

func (authority testIntentAuthority) AuthorizeIntentKey(_ string, key ed25519.PublicKey, _ time.Time) error {
	if !key.Equal(authority.key) {
		return errors.New("wrong key")
	}
	return nil
}

type staticInventory struct{ value InventorySnapshot }

func (source staticInventory) Snapshot(context.Context) (InventorySnapshot, error) {
	return source.value, nil
}

type staticEstimator struct{ value EconomicEstimate }

func (source staticEstimator) Estimate(context.Context, commerce.SignedAgentIntent, InventorySnapshot) (EconomicEstimate, error) {
	return source.value, nil
}

type staticCarrier struct {
	id      string
	results []CarrierResult
}

func (carrier staticCarrier) ID() string { return carrier.id }
func (carrier staticCarrier) Search(context.Context, IntentQuery) ([]CarrierResult, error) {
	return append([]CarrierResult(nil), carrier.results...), nil
}

func earningIntent(t *testing.T, now time.Time, privateKey ed25519.PrivateKey) commerce.SignedAgentIntent {
	t.Helper()
	detail := []byte("perform one bounded security review")
	digest := sha256.Sum256(detail)
	body := commerce.AgentIntentBody{SchemaVersion: 1, NetworkID: "tos:testnet", IssuerAgentID: "agent:" + strings.Repeat("a", 64),
		Audience: "public:indexable", ObjectID: "intent:" + strings.Repeat("b", 64), Revision: 1,
		CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()), Payload: commerce.AgentIntentPayload{
			DiscoveryCard: commerce.DiscoveryCard{Summary: "Security review", IntentModes: []commerce.IntentMode{commerce.IntentBuy, commerce.IntentRequest},
				SubjectClasses: []commerce.SubjectClass{commerce.SubjectService}, TaxonomyPaths: []string{"tos.taxonomy.v1/service/security/review"},
				Keywords: []commerce.IntentKeyword{{Text: "review", Language: "en"}}, ValueState: commerce.ValueSpecified,
				ValueHints: []commerce.ValueHint{{Role: "budget", AssetNamespace: "tos.asset", AssetIdentifier: "native", AmountKind: "exact", MinimumDecimal: "50", MaximumDecimal: "50", Unit: "total"}},
				Schedule:   commerce.IntentSchedule{Flexibility: "flexible"}, FulfillmentModes: []string{"remote"}},
			DetailDescriptor: commerce.ContentDescriptor{ContentType: "text/plain", ContentDigest: "sha256:" + hex.EncodeToString(digest[:]),
				ContentSize: uint64(len(detail)), InlineContent: detail},
			ReplyRoutes: []commerce.ReplyRoute{{ProfileURI: "tos.messenger.direct.v1", AgentID: "agent:" + strings.Repeat("a", 64)}}}}
	signed, err := commerce.SignIntent(body, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestCollectorDeduplicatesCarriersAndEvaluatesProfit(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(2_000_000_000, 0).UTC()
	intent := earningIntent(t, now, privateKey)
	inventory := InventorySnapshot{OwnerID: "owner:test", AgentID: "agent:worker", CreatedAtUnix: uint64(now.Unix()),
		ExpiresAtUnix: uint64(now.Add(time.Minute).Unix()), SourceGeneration: 1, PortfolioRevision: 1, PolicyRevision: 1,
		ConsistencyToken: "snapshot:1", Capabilities: []Capability{{Namespace: "openfox.skill", Identifier: "security-review", Version: "1",
			State: CapabilityReady, Authority: "owner:test", EvidenceDigest: "sha256:test", RevocationGeneration: 1, ExpiresAtUnix: uint64(now.Add(time.Minute).Unix())}},
		SupportedSettlementAdapters: []string{"tos.payment.direct.v1"}}
	estimate := EconomicEstimate{RevenueAtomic: "100", PaymentProbabilityPPM: 900_000, CompletionProbabilityPPM: 900_000,
		ComputeCostAtomic: "5", ModelCostAtomic: "5", FailureReserveAtomic: "5", DisputeReserveAtomic: "5", MaximumLossAtomic: "20",
		EstimatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(time.Minute).Unix()), EvidenceDigest: "sha256:evidence"}
	resultsA := []CarrierResult{{Intent: intent, CarrierID: "carrier:a"}}
	resultsB := []CarrierResult{{Intent: intent, CarrierID: "carrier:b"}}
	collector := Collector{Carriers: []Carrier{staticCarrier{id: "carrier:a", results: resultsA}, staticCarrier{id: "carrier:b", results: resultsB}},
		Authority: testIntentAuthority{key: publicKey}, Inventory: staticInventory{value: inventory}, Estimator: staticEstimator{value: estimate},
		Policy: EconomicPolicy{MinimumExpectedProfitAtomic: "10", MinimumROIPPM: 100_000, MaximumLossAtomic: "25",
			MinimumPaymentProbabilityPPM: 800_000, MinimumCompletionProbabilityPPM: 800_000}, Now: func() time.Time { return now }}
	assessments, err := collector.Collect(context.Background(), IntentQuery{Modes: []commerce.IntentMode{commerce.IntentRequest},
		SubjectClasses: []commerce.SubjectClass{commerce.SubjectService}, Keywords: []string{"review"}, MaximumResults: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(assessments) != 1 || len(assessments[0].CarrierIDs) != 2 || !assessments[0].Decision.Eligible ||
		assessments[0].Decision.ExpectedRevenueAtomic != "81" || assessments[0].Decision.ExpectedNetAtomic != "61" {
		t.Fatalf("unexpected assessment: %+v", assessments)
	}
}

func TestCollectorPersistsSignedWithdrawalAgainstStaleCarrier(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Unix(2_000_000_000, 0).UTC()
	intent := earningIntent(t, now, privateKey)
	digest, _ := commerce.IntentBodyDigest(intent.Body)
	withdrawal, err := commerce.SignIntentWithdrawal(commerce.AgentIntentWithdrawalBody{SchemaVersion: 1,
		NetworkID: intent.Body.NetworkID, IssuerAgentID: intent.Body.IssuerAgentID, Audience: intent.Body.Audience,
		ObjectID: intent.Body.ObjectID, IntentRevision: intent.Body.Revision, IntentDigest: digest, ReasonCode: "capacity-unavailable",
		CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := OpenOpportunityJournal(privateTempDir(t), 100)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	inventory := InventorySnapshot{OwnerID: "owner:test", AgentID: "agent:worker", CreatedAtUnix: uint64(now.Unix()),
		ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()), SourceGeneration: 1, PortfolioRevision: 1, PolicyRevision: 1,
		ConsistencyToken: "withdrawal-test", SupportedSettlementAdapters: []string{}}
	estimate := EconomicEstimate{RevenueAtomic: "100", PaymentProbabilityPPM: 1_000_000, CompletionProbabilityPPM: 1_000_000,
		ComputeCostAtomic: "1", MaximumLossAtomic: "1", EstimatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()),
		EvidenceDigest: "sha256:estimate"}
	collector := Collector{Carriers: []Carrier{staticCarrier{id: "carrier:a", results: []CarrierResult{
		{Intent: intent, Cursor: "seq:1", CarrierID: "carrier:a"}, {Withdrawal: &withdrawal, Cursor: "seq:2", CarrierID: "carrier:a"}}}},
		Authority: testIntentAuthority{key: publicKey}, Inventory: staticInventory{value: inventory}, Estimator: staticEstimator{value: estimate},
		Policy: EconomicPolicy{MinimumExpectedProfitAtomic: "1", MaximumLossAtomic: "2"}, Journal: journal, Now: func() time.Time { return now }}
	assessments, err := collector.Collect(context.Background(), IntentQuery{MaximumResults: 10})
	if err != nil || len(assessments) != 0 || !journal.IsWithdrawn(digest) {
		t.Fatalf("withdrawn assessments=%+v err=%v", assessments, err)
	}
	collector.Carriers = []Carrier{staticCarrier{id: "carrier:b", results: []CarrierResult{{Intent: intent, Cursor: "seq:1", CarrierID: "carrier:b"}}}}
	assessments, err = collector.Collect(context.Background(), IntentQuery{MaximumResults: 10})
	if err != nil || len(assessments) != 0 {
		t.Fatalf("stale Carrier revived withdrawal: %+v err=%v", assessments, err)
	}
}

func TestEvaluatorFailsClosedOnStaleOrUnprofitableEvidence(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	estimate := EconomicEstimate{RevenueAtomic: "10", PaymentProbabilityPPM: 1_000_000, CompletionProbabilityPPM: 1_000_000,
		ComputeCostAtomic: "20", MaximumLossAtomic: "20", EstimatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(time.Minute).Unix()), EvidenceDigest: "evidence"}
	decision, err := EvaluateEconomics(estimate, EconomicPolicy{MinimumExpectedProfitAtomic: "1", MaximumLossAtomic: "100"}, now)
	if err != nil || decision.Eligible || decision.ExpectedNetAtomic != "-10" {
		t.Fatalf("unprofitable estimate = %+v, %v", decision, err)
	}
	estimate.ExpiresAtUnix = uint64(now.Unix())
	if _, err := EvaluateEconomics(estimate, EconomicPolicy{MinimumExpectedProfitAtomic: "1", MaximumLossAtomic: "100"}, now); err == nil {
		t.Fatal("stale economic evidence was accepted")
	}
}

func TestHTTPCarrierBindsOriginIdentityAuthAndDigest(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	intent := earningIntent(t, now, privateKey)
	digest, _ := commerce.IntentBodyDigest(intent.Body)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/intents" || request.Header.Get("Authorization") != "Bearer secret" || request.URL.Query().Get("limit") != "5" {
			http.Error(writer, "bad request", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{"carrier_id": "carrier:http", "results": []any{map[string]any{
			"intent": intent, "intent_digest": digest, "authorization_level": "cryptographic-self-signature", "stored_at_unix": uint64(now.Unix()),
			"carrier_sequence": uint64(1)}}, "next_cursor": "seq:1"})
	}))
	defer server.Close()
	carrier, err := NewHTTPCarrier("carrier:http", server.URL+"/v1/intents", "secret", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	results, err := carrier.Search(context.Background(), IntentQuery{MaximumResults: 5})
	if err != nil || len(results) != 1 || results[0].CarrierID != "carrier:http" {
		t.Fatalf("results=%+v err=%v", results, err)
	}
	if _, err := NewHTTPCarrier("carrier:bad", "http://example.com/v1/intents", "secret", time.Second); err == nil {
		t.Fatal("plaintext non-loopback Carrier was accepted")
	}
}
