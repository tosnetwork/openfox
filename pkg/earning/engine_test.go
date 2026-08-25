package earning

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

type exactSink struct {
	key         ed25519.PublicKey
	now         time.Time
	calls       int
	resolutions map[string]commerce.ActionResolution
}

func (sink *exactSink) Submit(_ context.Context, action commerce.AuthorizedAction, fence commerce.WriterFence,
	fields map[string]commerce.SemanticValue, request []byte, _ OutboundMessage) (commerce.ActionResolution, error) {
	if err := commerce.VerifyAuthorizedAction(action, fields, request, fence, localFenceResolver{authorityID: "authority", key: sink.key}, sink.now); err != nil {
		return commerce.ActionResolution{}, err
	}
	sink.calls++
	resolution := commerce.ActionResolution{StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest,
		State: commerce.ActionTerminal, SinkReference: "event:test", StateRevision: 1}
	sink.resolutions[action.StableActionID] = resolution
	return resolution, nil
}

func (sink *exactSink) ResolveAction(_ context.Context, actionID, requestDigest string) (commerce.ActionResolution, error) {
	resolution, found := sink.resolutions[actionID]
	if !found {
		return commerce.ActionResolution{StableActionID: actionID, ExactRequestDigest: requestDigest, State: commerce.ActionUnknown, StateRevision: 1}, nil
	}
	return resolution, nil
}

func TestEngineContactsOnlyCorroboratedProfitableIntentExactlyOnce(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	_, issuerKey, _ := ed25519.GenerateKey(rand.Reader)
	intent := earningIntent(t, now, issuerKey)
	digest, _ := commerce.IntentBodyDigest(intent.Body)
	_, authorityKey, _ := ed25519.GenerateKey(rand.Reader)
	authority, err := OpenPersonalAuthority(privateTempDir(t), "owner", "agent:worker", "authority", authorityKey,
		PortfolioLimits{ComputeUnits: 10, SpendAtomic: 100})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	authority.now = func() time.Time { return now }
	fence, err := authority.AcquireWriter(context.Background(), "runtime", []string{"messenger.contact"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sink := &exactSink{key: authorityKey.Public().(ed25519.PublicKey), now: now, resolutions: map[string]commerce.ActionResolution{}}
	engine := &Engine{OwnerID: "owner", AgentID: "agent:worker", MandateDigest: testDigest, Gates: FeatureGates{Contact: true},
		Authority: authority, Sink: sink, Now: func() time.Time { return now }}
	candidate := CandidateAssessment{IntentDigest: digest, Intent: intent, Inventory: InventorySnapshot{PolicyRevision: 1},
		Decision: EconomicDecision{Eligible: true}, CarrierIDs: []string{"carrier:a", "carrier:b"}}
	request := ContactRequest{RecipientAgentID: intent.Body.IssuerAgentID, IntentDigest: digest, MediaType: "text/plain",
		Body: []byte("I can complete this work for the advertised budget."), ExpiresAtUnix: uint64(now.Add(30 * time.Minute).Unix())}
	first, err := engine.Contact(context.Background(), candidate, request, fence)
	if err != nil || first.State != commerce.ActionTerminal || sink.calls != 1 {
		t.Fatalf("first=%+v calls=%d err=%v", first, sink.calls, err)
	}
	retry, err := engine.Contact(context.Background(), candidate, request, fence)
	if err != nil || retry.StableActionID != first.StableActionID || sink.calls != 1 {
		t.Fatalf("retry=%+v calls=%d err=%v", retry, sink.calls, err)
	}
	candidate.CarrierIDs = []string{"carrier:a"}
	if _, err := engine.Contact(context.Background(), candidate, request, fence); err == nil {
		t.Fatal("single-source autonomous contact was accepted")
	}
	engine.Gates.ObserveOnly = true
	candidate.CarrierIDs = []string{"carrier:a", "carrier:b"}
	if _, err := engine.Contact(context.Background(), candidate, request, fence); err == nil {
		t.Fatal("observe-only mode performed contact")
	}
}

func TestProposerDurablyRecordsExactAgreementAfterMessengerAdmission(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	_, authorityKey, _ := ed25519.GenerateKey(rand.Reader)
	authority, err := OpenPersonalAuthority(privateTempDir(t), "owner", "agent:a", "authority", authorityKey,
		PortfolioLimits{ComputeUnits: 10, SpendAtomic: 100})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	authority.now = func() time.Time { return now }
	fence, err := authority.AcquireWriter(context.Background(), "runtime", []string{"agreement.propose"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sink := &exactSink{key: authorityKey.Public().(ed25519.PublicKey), now: now, resolutions: map[string]commerce.ActionResolution{}}
	profile := commerce.AgentSignatureProfileDigest()
	body := commerce.AgentAgreementBody{SchemaVersion: 1, AgreementID: "agreement:proposal", Version: 1, NetworkContext: "tos:test",
		Participants:     []commerce.AgreementParticipant{{AgentID: "agent:a", Roles: []string{"provider"}}, {AgentID: "agent:b", Roles: []string{"buyer"}}},
		TermsContentType: "text/plain", Terms: []byte("bounded work for exact payment"),
		Obligations: []commerce.AgreementObligation{
			{ObligationID: "pay", Kind: "payment", ObligorAgentID: "agent:b", BeneficiaryAgentID: "agent:a", DependsOnObligationIDs: []string{"work"},
				SubjectContentType: "text/plain", Subject: []byte("pay after delivery"), Amount: &commerce.AgreementAmount{AssetNamespace: "tos.asset", AssetIdentifier: "native", AmountAtomic: "50", Unit: "total"},
				ConfidentialityPolicy: "participants", CancellationPolicy: "due-after-acceptance", DisputePolicy: "manual", SettlementAdapterURI: "tos.payment.direct.v1",
				SettlementParameters: []byte("tos:test"), AuthorizationPredicateIDs: []string{"buyer"}},
			{ObligationID: "work", Kind: "service", ObligorAgentID: "agent:a", BeneficiaryAgentID: "agent:b", SubjectContentType: "text/plain", Subject: []byte("perform work"),
				ConfidentialityPolicy: "participants", CancellationPolicy: "before-start", DisputePolicy: "manual", AuthorizationPredicateIDs: []string{"provider"}},
		},
		AuthorizationPredicates: []commerce.AgreementAuthorizationPredicate{
			{PredicateID: "buyer", AuthoritySubject: commerce.AgreementAuthoritySubject{SubjectKind: "agent", SubjectNamespace: "tos.agent", SubjectIdentifier: "agent:b"},
				ObligationIDs: []string{"pay"}, EvidenceProfileURI: commerce.EvidenceProfileAgentSignature, EvidenceProfileVersion: 1, EvidenceProfileDigest: profile, ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())},
			{PredicateID: "provider", AuthoritySubject: commerce.AgreementAuthoritySubject{SubjectKind: "agent", SubjectNamespace: "tos.agent", SubjectIdentifier: "agent:a"},
				ObligationIDs: []string{"work"}, EvidenceProfileURI: commerce.EvidenceProfileAgentSignature, EvidenceProfileVersion: 1, EvidenceProfileDigest: profile, ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())},
		}, ValidFromUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}
	body, err = commerce.PrepareAgreementTargets(body)
	if err != nil {
		t.Fatal(err)
	}
	engine := &Engine{OwnerID: "owner", AgentID: "agent:a", MandateDigest: testDigest, Gates: FeatureGates{Agreement: true},
		Authority: authority, Sink: sink, Now: func() time.Time { return now }}
	resolution, err := engine.ProposeAgreement(context.Background(), body, []string{"agent:b"}, 1, fence)
	if err != nil || resolution.State != commerce.ActionTerminal {
		t.Fatalf("resolution=%+v err=%v", resolution, err)
	}
	digest, _ := commerce.AgreementBodyDigest(body)
	recorded, found := authority.Engagement(digest)
	if !found || recorded.ProposalActionID != resolution.StableActionID || recorded.State != EngagementProposed {
		t.Fatalf("proposer ledger did not record exact accepted send: %+v", recorded)
	}
}
