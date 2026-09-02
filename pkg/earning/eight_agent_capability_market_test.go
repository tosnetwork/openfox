package earning

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
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
