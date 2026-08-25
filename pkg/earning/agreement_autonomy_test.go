package earning

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/localapi"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

type emptyMessengerCaller struct{}

func (emptyMessengerCaller) Call(context.Context, localapi.Request) (localapi.Response, error) {
	return localapi.Response{OK: true}, nil
}

func TestAgreementAutonomyAuthorizesOnlyAfterDeterministicPolicy(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	localPublic, localIdentity, _ := ed25519.GenerateKey(rand.Reader)
	remotePublic, _, _ := ed25519.GenerateKey(rand.Reader)
	_, authorityKey, _ := ed25519.GenerateKey(rand.Reader)
	authority, err := OpenPersonalAuthority(privateTempDir(t), "owner", "agent:a", "authority", authorityKey,
		PortfolioLimits{ComputeUnits: 10, SpendAtomic: 100})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	authority.now = func() time.Time { return now }
	profile := commerce.AgentSignatureProfileDigest()
	body := commerce.AgentAgreementBody{SchemaVersion: 1, AgreementID: "agreement:auto", Version: 1, NetworkContext: "tos:test",
		Participants:     []commerce.AgreementParticipant{{AgentID: "agent:a", Roles: []string{"provider"}}, {AgentID: "agent:b", Roles: []string{"buyer"}}},
		TermsContentType: "text/plain", Terms: []byte("one bounded task"), Obligations: []commerce.AgreementObligation{
			{ObligationID: "pay", Kind: "payment", ObligorAgentID: "agent:b", BeneficiaryAgentID: "agent:a", DependsOnObligationIDs: []string{"work"},
				SubjectContentType: "text/plain", Subject: []byte("pay after delivery"), Amount: &commerce.AgreementAmount{AssetNamespace: "tos.asset", AssetIdentifier: "native", AmountAtomic: "10", Unit: "total"},
				ConfidentialityPolicy: "participants", CancellationPolicy: "after-delivery", DisputePolicy: "manual", SettlementAdapterURI: "tos.payment.direct.v1", SettlementParameters: []byte("tos:test"), AuthorizationPredicateIDs: []string{"buyer"}},
			{ObligationID: "work", Kind: "service", ObligorAgentID: "agent:a", BeneficiaryAgentID: "agent:b", SubjectContentType: "text/plain", Subject: []byte("perform work"),
				ConfidentialityPolicy: "participants", CancellationPolicy: "before-start", DisputePolicy: "manual", AuthorizationPredicateIDs: []string{"provider"}},
		}, AuthorizationPredicates: []commerce.AgreementAuthorizationPredicate{
			{PredicateID: "buyer", AuthoritySubject: commerce.AgreementAuthoritySubject{SubjectKind: "agent", SubjectNamespace: "tos.agent", SubjectIdentifier: "agent:b"}, ObligationIDs: []string{"pay"},
				EvidenceProfileURI: commerce.EvidenceProfileAgentSignature, EvidenceProfileVersion: 1, EvidenceProfileDigest: profile, ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())},
			{PredicateID: "provider", AuthoritySubject: commerce.AgreementAuthoritySubject{SubjectKind: "agent", SubjectNamespace: "tos.agent", SubjectIdentifier: "agent:a"}, ObligationIDs: []string{"work"},
				EvidenceProfileURI: commerce.EvidenceProfileAgentSignature, EvidenceProfileVersion: 1, EvidenceProfileDigest: profile, ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())},
		}, ValidFromUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}
	body, err = commerce.PrepareAgreementTargets(body)
	if err != nil {
		t.Fatal(err)
	}
	record, err := authority.RecordAgreementProposal(body, "agent:b", "event:proposal", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}
	fence, err := authority.AcquireWriter(context.Background(), "runtime", []string{"agreement.authorize"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sink := &exactSink{key: authorityKey.Public().(ed25519.PublicKey), now: now, resolutions: map[string]commerce.ActionResolution{}}
	resolver := PinnedIntentAuthorities{"agent:a": localPublic, "agent:b": remotePublic}
	verifier := AgreementEvidenceRouter{AgentAuthority: resolver}
	engine := &Engine{OwnerID: "owner", AgentID: "agent:a", MandateDigest: testDigest, Gates: FeatureGates{Agreement: true}, Authority: authority, Sink: sink, Now: func() time.Time { return now }}
	inventory := CurrentInventory{SnapshotValue: InventorySnapshot{OwnerID: "owner", AgentID: "agent:a", CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()),
		SourceGeneration: 1, PortfolioRevision: 1, PolicyRevision: 1, ConsistencyToken: "inventory:auto", SupportedSettlementAdapters: []string{"tos.payment.direct.v1"}}}
	service := AgreementAutonomy{Coordinator: AgreementCoordinator{Inbox: AgreementInbox{Client: emptyMessengerCaller{}}, Authority: authority, Verifier: verifier},
		Engine: engine, Inventory: inventory, Policy: BoundedAgreementAdmissionPolicy{LocalAgentID: "agent:a", MaximumOutgoingPaymentAtomic: "0"},
		IdentityKey: localIdentity, Verifier: verifier, Fence: func(context.Context) (commerce.WriterFence, error) { return fence, nil }, Now: func() time.Time { return now }}
	if processed, err := service.Process(context.Background(), 10); err != nil || processed != 0 {
		t.Fatalf("processed=%d err=%v", processed, err)
	}
	updated, found := authority.Engagement(record.AgreementDigest)
	if !found || !hasAgentEvidence(updated, "agent:a") || updated.State != EngagementAuthorizing || sink.calls != 1 {
		t.Fatalf("updated=%+v calls=%d", updated, sink.calls)
	}
	if _, err := service.Process(context.Background(), 10); err != nil || sink.calls != 1 {
		t.Fatalf("retry calls=%d err=%v", sink.calls, err)
	}
}
