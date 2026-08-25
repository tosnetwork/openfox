package earning

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/paiddemand"
)

type paidProviderKeyResolver struct{ key ed25519.PublicKey }

func (resolver paidProviderKeyResolver) AuthorizeProviderOfferKey(context commerce.ProviderProofContext,
	binding commerce.PaidDemandQuoteBindingBody, key ed25519.PublicKey, at time.Time) error {
	if !resolver.key.Equal(key) || context.ProviderAgentID != binding.ProviderAgentID ||
		at.Before(time.Unix(int64(context.ValidFromUnix), 0)) {
		return errors.New("Provider Offer key is not authorized")
	}
	return nil
}

func TestPaidDemandProviderReservesBeforeOneExactOffer(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	_, authorityKey, _ := ed25519.GenerateKey(rand.Reader)
	authority, err := OpenPersonalAuthority(privateTempDir(t), "owner", "agent:provider", "authority", authorityKey,
		PortfolioLimits{ComputeUnits: 10, ReceivableAtomic: 100})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	authority.now = func() time.Time { return now }
	fence, err := authority.AcquireWriter(context.Background(), "runtime",
		[]string{"portfolio.reserve", "provider.offer"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	body, binding := paidProviderAgreement(t, now)
	digest, _ := commerce.AgreementBodyDigest(body)
	if _, err := authority.RecordAgreementProposal(body, "agent:buyer", "event:proposal", testDigest); err != nil {
		t.Fatal(err)
	}
	sink := &exactSink{key: authorityKey.Public().(ed25519.PublicKey), now: now,
		resolutions: map[string]commerce.ActionResolution{}}
	engine := &Engine{OwnerID: "owner", AgentID: "agent:provider", MandateDigest: testDigest,
		Gates: FeatureGates{TOSEscrow: true}, Authority: authority, Sink: sink, Now: func() time.Time { return now }}
	providerKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	resolver := paidProviderKeyResolver{key: providerKey.Public().(ed25519.PublicKey)}
	proof := commerce.ProviderProofContext{SchemaVersion: 1, NetworkContext: body.NetworkContext,
		ProviderAgentID: "agent:provider", Purpose: "provider-offer.sign",
		PublicKey: "ed25519:" + hex.EncodeToString(providerKey.Public().(ed25519.PublicKey)), AgentGeneration: 1,
		ControllerPolicyDigest: testDigest, DelegationDigest: testDigest, ScopeBoundsDigest: testDigest,
		OwnerMandateDigest: testDigest, IssuanceAuthorityReferenceDigest: testDigest,
		ValidFromUnix: uint64(now.Add(-time.Minute).Unix()), ExpiresAtUnix: binding.AcceptByUnix}
	verifier := commerce.PaidDemandQuoteEvidenceVerifier{Native: paiddemand.NativeEvidenceVerifier{ProviderOffers: resolver}}
	service := PaidDemandProviderService{Engine: engine, Signer: LocalProviderOfferSigner{Context: proof, Key: providerKey},
		OfferResolver: resolver, Evidence: verifier, PolicyRevision: 1}
	if _, _, _, err := service.IssueOffer(context.Background(), binding, "agent:buyer", fence); err == nil {
		t.Fatal("Provider Offer was issued before exposure reservation")
	}
	reservation := ExposureReservation{ReservationID: "reservation:paid-provider", AgreementDigest: digest,
		ComputeUnits: 2, ReceivableAtomic: 100}
	if _, record, err := engine.ReserveAgreement(context.Background(), digest, reservation, allowSettlement{}, 1, fence); err != nil ||
		record.State != EngagementAuthorizing || record.ReservationID != reservation.ReservationID {
		t.Fatalf("pre-offer reservation record=%+v err=%v", record, err)
	}
	offer, resolution, record, err := service.IssueOffer(context.Background(), binding, "agent:buyer", fence)
	if err != nil || resolution.State != commerce.ActionTerminal || record.State != EngagementAuthorizing || sink.calls != 1 {
		t.Fatalf("offer=%+v resolution=%+v record=%+v calls=%d err=%v", offer, resolution, record, sink.calls, err)
	}
	if !hasPaidDemandProfileEvidence(record, "agent:provider") {
		t.Fatal("Provider Offer did not satisfy the Provider Agreement predicate")
	}
	retry, retryResolution, _, err := service.IssueOffer(context.Background(), binding, "agent:buyer", fence)
	firstDigest, _ := commerce.ProviderOfferDigest(offer)
	retryDigest, _ := commerce.ProviderOfferDigest(retry)
	if err != nil || retryResolution.StableActionID != resolution.StableActionID || retryDigest != firstDigest || sink.calls != 1 {
		t.Fatalf("exact retry changed Provider Offer: digest=%s/%s calls=%d err=%v", firstDigest, retryDigest, sink.calls, err)
	}
}

func paidProviderAgreement(t *testing.T, now time.Time) (commerce.AgentAgreementBody, commerce.PaidDemandQuoteBindingBody) {
	t.Helper()
	profile := commerce.PaidDemandQuoteProfileDigest()
	body := commerce.AgentAgreementBody{SchemaVersion: 1, AgreementID: "agreement:paid-provider", Version: 1,
		NetworkContext: "tos:test", Participants: []commerce.AgreementParticipant{
			{AgentID: "agent:buyer", Roles: []string{"buyer"}}, {AgentID: "agent:provider", Roles: []string{"provider"}}},
		TermsContentType: "text/plain", Terms: []byte("review exact source"), Obligations: []commerce.AgreementObligation{
			{ObligationID: "pay", Kind: "payment", ObligorAgentID: "agent:buyer", BeneficiaryAgentID: "agent:provider",
				DependsOnObligationIDs: []string{"work"}, SubjectContentType: "text/plain", Subject: []byte("pay"),
				Amount:                &commerce.AgreementAmount{AssetNamespace: "tos.contract", AssetIdentifier: "0:" + strings.Repeat("1", 64), AmountAtomic: "100", Unit: "atomic"},
				ConfidentialityPolicy: "participants", CancellationPolicy: "chain-profile", DisputePolicy: "objective",
				SettlementAdapterURI: paiddemand.SettlementAdapterURI, SettlementParameters: []byte("0:" + strings.Repeat("2", 64)),
				AuthorizationPredicateIDs: []string{"predicate:buyer"}},
			{ObligationID: "work", Kind: "service", ObligorAgentID: "agent:provider", BeneficiaryAgentID: "agent:buyer",
				SubjectContentType: "text/plain", Subject: []byte("work"), ConfidentialityPolicy: "participants",
				CancellationPolicy: "chain-profile", DisputePolicy: "objective", AuthorizationPredicateIDs: []string{"predicate:provider"}},
		}, AuthorizationPredicates: []commerce.AgreementAuthorizationPredicate{
			{PredicateID: "predicate:buyer", AuthoritySubject: commerce.AgreementAuthoritySubject{SubjectKind: "wallet", SubjectNamespace: "tos.wallet",
				SubjectIdentifier: "0:" + strings.Repeat("3", 64), RepresentedAgentID: "agent:buyer"}, ObligationIDs: []string{"pay"},
				EvidenceProfileURI: commerce.EvidenceProfilePaidDemandQuote, EvidenceProfileVersion: 1, EvidenceProfileDigest: profile,
				ExpiresAtUnix: uint64(now.Add(30 * time.Minute).Unix())},
			{PredicateID: "predicate:provider", AuthoritySubject: commerce.AgreementAuthoritySubject{SubjectKind: "agent", SubjectNamespace: "tos.agent",
				SubjectIdentifier: "agent:provider"}, ObligationIDs: []string{"work"}, EvidenceProfileURI: commerce.EvidenceProfilePaidDemandQuote,
				EvidenceProfileVersion: 1, EvidenceProfileDigest: profile, ExpiresAtUnix: uint64(now.Add(30 * time.Minute).Unix())},
		}, ValidFromUnix: uint64(now.Add(-time.Minute).Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}
	var err error
	body, err = commerce.PrepareAgreementTargets(body)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := commerce.AgreementBodyDigest(body)
	binding := commerce.PaidDemandQuoteBindingBody{SchemaVersion: 1, NetworkContext: body.NetworkContext,
		AgreementBodyDigest: digest, AgreementObligationIDs: []string{"pay", "work"},
		AgreementAuthorizationPredicateIDs: []string{"predicate:buyer", "predicate:provider"},
		AgreementAuthorizationTargetDigests: []string{body.AuthorizationPredicates[0].EvidenceTargetProjectionDigest,
			body.AuthorizationPredicates[1].EvidenceTargetProjectionDigest}, EvidenceProfileURI: commerce.EvidenceProfilePaidDemandQuote,
		EvidenceProfileVersion: 1, EvidenceProfileDigest: profile, DemandMutationDigest: "sha256:" + strings.Repeat("4", 64),
		ProviderOfferID: "offer:paid-provider", ProviderAgentID: "agent:provider", BuyerAgentID: "agent:buyer",
		BuyerWallet: "0:" + strings.Repeat("3", 64), ProviderWallet: "0:" + strings.Repeat("2", 64),
		NativeQuoteTermsProjectionDigest: "tvm-cell-sha256:" + strings.Repeat("5", 64), AcceptByUnix: uint64(now.Add(30 * time.Minute).Unix())}
	return body, binding
}
