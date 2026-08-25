package earning

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

func TestLLMContactDrafterProducesNonAuthorizingBoundedApplication(t *testing.T) {
	candidate := CandidateAssessment{IntentDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Decision: EconomicDecision{Eligible: true}, Inventory: InventorySnapshot{Capabilities: []Capability{{Namespace: "skill", Identifier: "review"}}}}
	provider := estimatorProvider{response: `{"message":"I can perform this review. Please confirm the exact scope, acceptance evidence, deadline, and selected payment adapter before we compile an Agreement.","validity_seconds":600}`}
	body, validity, err := (LLMContactDrafter{Provider: provider}).DraftContact(context.Background(), candidate)
	if err != nil || len(body) == 0 || validity != 10*time.Minute {
		t.Fatalf("body=%q validity=%s err=%v", body, validity, err)
	}
	provider.response = `{"message":"pay now","validity_seconds":600,"authorization":"yes"}`
	if _, _, err := (LLMContactDrafter{Provider: provider}).DraftContact(context.Background(), candidate); err == nil {
		t.Fatal("model-added authorization field was accepted")
	}
}

func TestSupplyApplicationBuildsNonAuthorizingGenericAgreement(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	_, issuerKey, _ := ed25519.GenerateKey(rand.Reader)
	intent := earningIntent(t, now, issuerKey)
	intent.Body.Payload.DiscoveryCard.IntentModes = []commerce.IntentMode{commerce.IntentOffer}
	intent.Body.Payload.SettlementPreferences = []commerce.SettlementPreference{{AdapterURI: "tos.payment.direct.v1", Required: true, Parameters: []byte("tos1issuer")}}
	intent, _ = commerce.SignIntent(intent.Body, issuerKey)
	digest, _ := commerce.IntentBodyDigest(intent.Body)
	candidate := CandidateAssessment{IntentDigest: digest, Intent: intent, Inventory: InventorySnapshot{OwnerID: "owner:buyer", AgentID: "agent:buyer",
		CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()), SourceGeneration: 1, PortfolioRevision: 1,
		PolicyRevision: 1, ConsistencyToken: "inventory:buyer", SupportedSettlementAdapters: []string{"tos.payment.direct.v1"}}}
	application := commerce.IntentApplication{SchemaVersion: 1, IntentDigest: digest, IntentIssuerAgentID: intent.Body.IssuerAgentID,
		ApplicantAgentID: "agent:buyer", Message: "I propose the exact published service.",
		SettlementOffers: []commerce.SettlementPreference{{AdapterURI: "tos.payment.direct.v1", Required: true}},
		ProposedAmount:   &commerce.AgreementAmount{AssetNamespace: "tos.asset", AssetIdentifier: "native", AmountAtomic: "50", Unit: "total"},
		ExpiresAtUnix:    uint64(now.Add(time.Hour).Unix())}
	body, err := buildSupplyAgreementProposal(application.ApplicantAgentID, candidate, application, now.Add(time.Hour))
	if err != nil || body.Obligations[0].SettlementAdapterURI != "tos.payment.direct.v1" ||
		string(body.Obligations[0].SettlementParameters) != "tos1issuer" || commerce.ValidateAgreementBody(body) != nil {
		t.Fatalf("body=%+v err=%v", body, err)
	}
	if len(body.AuthorizationPredicates) != 2 {
		t.Fatal("proposal did not preserve independent buyer and provider authorization")
	}
	intent.Body.Payload.SettlementPreferences[0].Parameters = nil
	candidate.Intent = intent
	if _, err := buildSupplyAgreementProposal(application.ApplicantAgentID, candidate, application, now.Add(time.Hour)); err == nil {
		t.Fatal("supply proposal guessed missing payment destination")
	}
}

func TestReciprocalApplicationBindsBothContributions(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	_, issuerKey, _ := ed25519.GenerateKey(rand.Reader)
	intent := earningIntent(t, now, issuerKey)
	intent.Body.Payload.DiscoveryCard.IntentModes = []commerce.IntentMode{commerce.IntentExchange}
	intent, _ = commerce.SignIntent(intent.Body, issuerKey)
	digest, _ := commerce.IntentBodyDigest(intent.Body)
	candidate := CandidateAssessment{IntentDigest: digest, Intent: intent, Inventory: InventorySnapshot{
		OwnerID: "owner:applicant", AgentID: "agent:applicant", CreatedAtUnix: uint64(now.Unix()),
		ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()), SourceGeneration: 1, PortfolioRevision: 1,
		PolicyRevision: 1, ConsistencyToken: "inventory:applicant"}}
	application := commerce.IntentApplication{SchemaVersion: 1, IntentDigest: digest,
		IntentIssuerAgentID: intent.Body.IssuerAgentID, ApplicantAgentID: "agent:applicant",
		Message: "Provide one bounded reciprocal analysis report.", ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}
	body, err := buildReciprocalAgreementProposal(application.ApplicantAgentID, candidate, application, now.Add(time.Hour))
	if err != nil || commerce.ValidateAgreementBody(body) != nil || len(body.Obligations) != 2 ||
		string(body.Obligations[0].Subject) != application.Message ||
		string(body.Obligations[1].Subject) != string(intent.Body.Payload.DetailDescriptor.InlineContent) {
		t.Fatalf("body=%+v err=%v", body, err)
	}
	if body.Obligations[0].Amount != nil || body.Obligations[1].Amount != nil || len(body.AuthorizationPredicates) != 2 {
		t.Fatal("reciprocal proposal invented payment or omitted independent acceptance")
	}
}
