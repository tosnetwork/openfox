package earning

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strconv"
	"strings"
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

func TestBoundedAgreementAdmissionEnforcesBuyerMaximumLoss(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	tests := []struct {
		name, maximumLoss string
		price             uint64
		want              bool
	}{
		{name: "security-auditor-over", maximumLoss: "2000000000", price: 2_500_000_000},
		{name: "evidence-verifier-over", maximumLoss: "1100000000", price: 1_800_000_000},
		{name: "market-researcher-over", maximumLoss: "1250000000", price: 2_000_000_000},
		{name: "data-curator-over", maximumLoss: "1000000000", price: 2_500_000_000},
		{name: "transaction-operator-over", maximumLoss: "1500000000", price: 2_200_000_000},
		{name: "guarantor-analyst-over", maximumLoss: "2250000000", price: 3_000_000_000},
		{name: "software-builder-equal", maximumLoss: "2500000000", price: 2_500_000_000, want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record, inventory := directBuyerAgreementForAdmission(t, test.price, now)
			decision, err := (BoundedAgreementAdmissionPolicy{LocalAgentID: "agent:buyer",
				MaximumOutgoingPaymentAtomic: "6000000000", MaximumLossAtomic: test.maximumLoss}).
				EvaluateAgreement(t.Context(), record, inventory, now)
			if err != nil || decision.Accept != test.want {
				t.Fatalf("decision=%+v err=%v", decision, err)
			}
			if !test.want && decision.Reason != "Agreement maximum loss exceeds owner policy" {
				t.Fatalf("unexpected deterministic decline reason %q", decision.Reason)
			}
		})
	}
}

func TestAgreementAutonomyRejectsMaximumLossBeforeSignature(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	buyerPublic, buyerIdentity, _ := ed25519.GenerateKey(rand.Reader)
	sellerPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	_, authorityKey, _ := ed25519.GenerateKey(rand.Reader)
	authority, err := OpenPersonalAuthority(privateTempDir(t), "owner:buyer", "agent:buyer", "authority:buyer",
		authorityKey, PortfolioLimits{SpendAtomic: 100, MaximumLossAtomic: 100})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	authority.now = func() time.Time { return now }
	proposal, inventory := directBuyerAgreementForAdmission(t, 101, now)
	record, err := authority.RecordAgreementProposal(proposal.Agreement.Body, "agent:seller", "event:proposal",
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}
	fence, err := authority.AcquireWriter(t.Context(), "runtime", []string{"agreement.authorize"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	resolver := PinnedIntentAuthorities{"agent:buyer": buyerPublic, "agent:seller": sellerPublic}
	verifier := AgreementEvidenceRouter{AgentAuthority: resolver}
	sink := &exactSink{key: authorityKey.Public().(ed25519.PublicKey), now: now,
		resolutions: map[string]commerce.ActionResolution{}}
	engine := &Engine{OwnerID: "owner:buyer", AgentID: "agent:buyer", MandateDigest: testDigest,
		Gates: FeatureGates{Agreement: true}, Authority: authority, Sink: sink, Now: func() time.Time { return now }}
	service := AgreementAutonomy{Coordinator: AgreementCoordinator{Inbox: AgreementInbox{Client: emptyMessengerCaller{}},
		Authority: authority, Verifier: verifier}, Engine: engine, Inventory: CurrentInventory{SnapshotValue: inventory},
		Policy: BoundedAgreementAdmissionPolicy{LocalAgentID: "agent:buyer", MaximumOutgoingPaymentAtomic: "1000",
			MaximumLossAtomic: "100", Portfolio: authority}, IdentityKey: buyerIdentity, Verifier: verifier,
		Fence: func(context.Context) (commerce.WriterFence, error) { return fence, nil }, Now: func() time.Time { return now }}
	if processed, err := service.Process(t.Context(), 10); err != nil || processed != 0 {
		t.Fatalf("processed=%d err=%v", processed, err)
	}
	updated, found := authority.Engagement(record.AgreementDigest)
	if !found || updated.State != EngagementProposed || hasAgentEvidence(updated, "agent:buyer") || sink.calls != 0 {
		t.Fatalf("maximum-loss rejection crossed signature boundary: state=%s evidence=%v sink_calls=%d",
			updated.State, hasAgentEvidence(updated, "agent:buyer"), sink.calls)
	}
}

func TestReserveAgreementRejectsUnpinnedDirectPaymentAssetBeforeSignature(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	_, authorityKey, _ := ed25519.GenerateKey(rand.Reader)
	nativeAsset := commerce.AssetIdentityV1{AssetNamespace: "tos.asset", AssetIdentifier: "native", Unit: "nanotos"}
	authority, err := OpenPersonalAuthority(privateTempDir(t), "owner:buyer", "agent:buyer", "authority:buyer",
		authorityKey, PortfolioLimits{SpendAtomic: 100, MaximumLossAtomic: 100, CustodyNativeAsset: &nativeAsset})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	authority.now = func() time.Time { return now }
	proposal, _ := directBuyerAgreementForAdmission(t, 50, now)
	body := proposal.Agreement.Body
	body.Obligations[0].Amount.AssetIdentifier = "attacker-wrapped"
	for index := range body.AuthorizationPredicates {
		body.AuthorizationPredicates[index].EvidenceTargetProjectionDigest = ""
	}
	body, err = commerce.PrepareAgreementTargets(body)
	if err != nil {
		t.Fatal(err)
	}
	record, err := authority.RecordAgreementProposal(body, "agent:seller", "event:proposal",
		"sha256:"+strings.Repeat("d", 64))
	if err != nil {
		t.Fatal(err)
	}
	fence, err := authority.AcquireWriter(t.Context(), "runtime", []string{"portfolio.reserve"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	attackerAsset := commerce.AssetIdentityV1{AssetNamespace: "tos.asset", AssetIdentifier: "attacker-wrapped", Unit: "nanotos"}
	reservation := ExposureReservation{ReservationID: "sha256:" + strings.Repeat("e", 64),
		AgreementDigest: record.AgreementDigest, Asset: &attackerAsset, SpendAtomic: 50, MaximumLossAtomic: 50}
	engine := &Engine{OwnerID: "owner:buyer", AgentID: "agent:buyer", MandateDigest: testDigest, Authority: authority}
	beforeRevision, _, before := authority.Snapshot()
	if _, _, err := engine.ReserveAgreement(t.Context(), record.AgreementDigest, reservation,
		allowSettlement{}, 1, fence); err == nil {
		t.Fatal("fictional direct-payment asset crossed the pre-sign reservation boundary")
	}
	afterRevision, _, after := authority.Snapshot()
	if afterRevision != beforeRevision || len(after) != len(before) {
		t.Fatalf("rejected asset changed Portfolio state: before=%d/%d after=%d/%d",
			beforeRevision, len(before), afterRevision, len(after))
	}
}

type fixedPortfolioSnapshot struct {
	revision     uint64
	limits       PortfolioLimits
	reservations []ExposureReservation
}

func (snapshot fixedPortfolioSnapshot) Snapshot() (uint64, PortfolioLimits, []ExposureReservation) {
	return snapshot.revision, snapshot.limits, append([]ExposureReservation(nil), snapshot.reservations...)
}

func TestBoundedAgreementAdmissionIncludesAggregatePortfolioExposure(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	record, inventory := directBuyerAgreementForAdmission(t, 40, now)
	inventory.PortfolioRevision = 7
	asset := commerce.AssetIdentityV1{AssetNamespace: "tos.asset", AssetIdentifier: "native", Unit: "nanotos"}
	policy := BoundedAgreementAdmissionPolicy{LocalAgentID: "agent:buyer", MaximumOutgoingPaymentAtomic: "100",
		MaximumLossAtomic: "100", Portfolio: fixedPortfolioSnapshot{revision: 7,
			limits: PortfolioLimits{MaximumLossAtomic: 100}, reservations: []ExposureReservation{{
				ReservationID: "reservation:existing", AgreementDigest: "agreement:existing", Asset: &asset,
				MaximumLossAtomic: 61,
			}}}}
	decision, err := policy.EvaluateAgreement(t.Context(), record, inventory, now)
	if err != nil || decision.Accept || decision.Reason != "Agreement maximum loss exceeds aggregate Portfolio limit" {
		t.Fatalf("aggregate decision=%+v err=%v", decision, err)
	}
	policy.Portfolio = fixedPortfolioSnapshot{revision: 7, limits: PortfolioLimits{MaximumLossAtomic: 100},
		reservations: []ExposureReservation{{ReservationID: "reservation:existing", AgreementDigest: "agreement:existing",
			Asset: &asset, MaximumLossAtomic: 60}}}
	decision, err = policy.EvaluateAgreement(t.Context(), record, inventory, now)
	if err != nil || !decision.Accept {
		t.Fatalf("equal aggregate cap decision=%+v err=%v", decision, err)
	}
}

func directBuyerAgreementForAdmission(t *testing.T, price uint64, now time.Time) (EngagementRecord, InventorySnapshot) {
	t.Helper()
	profile := commerce.AgentSignatureProfileDigest()
	body := commerce.AgentAgreementBody{SchemaVersion: 1, AgreementID: "agreement:buyer-policy:" + strconv.FormatUint(price, 10),
		Version: 1, NetworkContext: "tos:test", Participants: []commerce.AgreementParticipant{
			{AgentID: "agent:buyer", Roles: []string{"buyer"}}, {AgentID: "agent:seller", Roles: []string{"provider"}},
		}, TermsContentType: "text/plain", Terms: []byte("one bounded direct-payment service"), Obligations: []commerce.AgreementObligation{
			{ObligationID: "pay", Kind: "payment", ObligorAgentID: "agent:buyer", BeneficiaryAgentID: "agent:seller",
				DependsOnObligationIDs: []string{"work"}, SubjectContentType: "text/plain", Subject: []byte("pay after delivery"),
				Amount: &commerce.AgreementAmount{AssetNamespace: "tos.asset", AssetIdentifier: "native",
					AmountAtomic: strconv.FormatUint(price, 10), Unit: "nanotos"},
				DueAtUnix: uint64(now.Add(45 * time.Minute).Unix()), ExpiresAtUnix: uint64(now.Add(50 * time.Minute).Unix()),
				ConfidentialityPolicy: "participants", CancellationPolicy: "before-due", DisputePolicy: "evidence",
				SettlementAdapterURI: "tos.payment.direct.v1", SettlementParameters: []byte("tos1seller"),
				AuthorizationPredicateIDs: []string{"buyer"}},
			{ObligationID: "work", Kind: "service", ObligorAgentID: "agent:seller", BeneficiaryAgentID: "agent:buyer",
				SubjectContentType: "text/plain", Subject: []byte("perform bounded work"), ConfidentialityPolicy: "participants",
				CancellationPolicy: "before-start", DisputePolicy: "evidence", AuthorizationPredicateIDs: []string{"seller"}},
		}, AuthorizationPredicates: []commerce.AgreementAuthorizationPredicate{
			{PredicateID: "buyer", AuthoritySubject: commerce.AgreementAuthoritySubject{SubjectKind: "agent", SubjectNamespace: "tos.agent",
				SubjectIdentifier: "agent:buyer"}, ObligationIDs: []string{"pay"}, EvidenceProfileURI: commerce.EvidenceProfileAgentSignature,
				EvidenceProfileVersion: 1, EvidenceProfileDigest: profile, ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())},
			{PredicateID: "seller", AuthoritySubject: commerce.AgreementAuthoritySubject{SubjectKind: "agent", SubjectNamespace: "tos.agent",
				SubjectIdentifier: "agent:seller"}, ObligationIDs: []string{"work"}, EvidenceProfileURI: commerce.EvidenceProfileAgentSignature,
				EvidenceProfileVersion: 1, EvidenceProfileDigest: profile, ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())},
		}, ValidFromUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}
	prepared, err := commerce.PrepareAgreementTargets(body)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := commerce.AgreementBodyDigest(prepared)
	if err != nil {
		t.Fatal(err)
	}
	record := EngagementRecord{Agreement: commerce.AgentAgreement{Body: prepared}, AgreementDigest: digest}
	inventory := InventorySnapshot{OwnerID: "owner:buyer", AgentID: "agent:buyer", CreatedAtUnix: uint64(now.Unix()),
		ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()), SourceGeneration: 1, PortfolioRevision: 1, PolicyRevision: 1,
		ConsistencyToken: "inventory:buyer-policy", SupportedSettlementAdapters: []string{"tos.payment.direct.v1"}}
	return record, inventory
}
