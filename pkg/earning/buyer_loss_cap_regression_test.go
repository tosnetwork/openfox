package earning

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

func TestBuyerLossCapAgreementEvidenceRequiresExactLiveHold(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	buyerPublic, buyerKey, _ := ed25519.GenerateKey(rand.Reader)
	sellerPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	_, authorityKey, _ := ed25519.GenerateKey(rand.Reader)
	authority, err := OpenPersonalAuthority(privateTempDir(t), "owner:buyer-cap", "agent:buyer",
		"authority:buyer-cap", authorityKey, buyerLossCapDirectLimits(25))
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	authority.now = func() time.Time { return now }

	template, _ := directBuyerAgreementForAdmission(t, 25, now)
	record, err := authority.RecordAgreementProposal(template.Agreement.Body, "agent:seller", "event:buyer-cap",
		"sha256:"+strings.Repeat("1", 64))
	if err != nil {
		t.Fatal(err)
	}
	verifier := AgreementEvidenceRouter{AgentAuthority: agreementKeyResolver{
		"agent:buyer": buyerPublic, "agent:seller": sellerPublic,
	}}
	evidence := buyerLossCapAcceptance(t, record.Agreement.Body, record.AgreementDigest, "agent:buyer", buyerKey)
	beforeRevision := record.StateRevision
	if _, err = authority.RecordAgreementEvidence(record.AgreementDigest, evidence, verifier); err == nil ||
		!strings.Contains(err.Error(), "live maximum-loss hold") {
		t.Fatalf("local buyer evidence crossed the no-hold boundary: %v", err)
	}
	unchanged, found := authority.Engagement(record.AgreementDigest)
	if !found || unchanged.StateRevision != beforeRevision || hasAgentEvidence(unchanged, "agent:buyer") {
		t.Fatalf("rejected buyer evidence mutated the Agreement: %+v", unchanged)
	}

	fence, err := authority.AcquireWriter(t.Context(), "buyer-cap-runtime", []string{"portfolio.reserve"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	asset := commerce.AssetIdentityV1{AssetNamespace: "tos.asset", AssetIdentifier: "native", Unit: "nanotos"}
	reservation := ExposureReservation{ReservationID: "sha256:" + strings.Repeat("2", 64),
		AgreementDigest: record.AgreementDigest, Asset: &asset, SpendAtomic: 25, MaximumLossAtomic: 25}
	engine := &Engine{OwnerID: "owner:buyer-cap", AgentID: "agent:buyer", MandateDigest: testDigest,
		Authority: authority, Now: func() time.Time { return now }}
	if _, _, err = engine.ReserveAgreement(t.Context(), record.AgreementDigest, reservation,
		allowSettlement{}, 1, fence); err != nil {
		t.Fatal(err)
	}
	callerEvidence, err := cloneAgreementEvidence(evidence)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := authority.RecordAgreementEvidence(record.AgreementDigest, callerEvidence, verifier)
	if err != nil || !hasAgentEvidence(accepted, "agent:buyer") {
		t.Fatalf("exact held buyer evidence was rejected: record=%+v err=%v", accepted, err)
	}
	callerEvidence.PredicateIDs[0] = "attacker"
	callerEvidence.EvidenceTargetProjectionDigests[0] = "sha256:" + strings.Repeat("f", 64)
	callerEvidence.Evidence[0] ^= 0xff
	retained, found := authority.Engagement(record.AgreementDigest)
	if !found || !hasAgentEvidence(retained, "agent:buyer") ||
		retained.Agreement.AuthorizationEvidence[0].PredicateIDs[0] == "attacker" {
		t.Fatalf("Agreement evidence retained mutable caller slices: %+v", retained.Agreement.AuthorizationEvidence)
	}
	if replay, replayErr := authority.RecordAgreementEvidence(record.AgreementDigest, evidence, verifier); replayErr != nil || replay.StateRevision != accepted.StateRevision {
		t.Fatalf("live-hold evidence replay was not idempotent: record=%+v err=%v", replay, replayErr)
	}

	authority.mu.Lock()
	released := authority.doc.Reservations[reservation.ReservationID]
	released.Released = true
	authority.doc.Reservations[reservation.ReservationID] = released
	authority.mu.Unlock()
	if _, err = authority.RecordAgreementEvidence(record.AgreementDigest, evidence, verifier); err == nil ||
		!strings.Contains(err.Error(), "live maximum-loss hold") {
		t.Fatalf("exact evidence replay bypassed a released hold: %v", err)
	}
}

func TestBuyerLossCapSharedEvidenceCannotBypassBackingHold(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	buyerPublic, buyerKey, _ := ed25519.GenerateKey(rand.Reader)
	sellerPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	_, authorityKey, _ := ed25519.GenerateKey(rand.Reader)
	backing, err := OpenPersonalAuthority(privateTempDir(t), "owner:shared-cap", "agent:buyer",
		"authority:shared-cap", authorityKey, buyerLossCapDirectLimits(25))
	if err != nil {
		t.Fatal(err)
	}
	defer backing.Close()
	backing.now = func() time.Time { return now }
	verifier := AgreementEvidenceRouter{AgentAuthority: agreementKeyResolver{
		"agent:buyer": buyerPublic, "agent:seller": sellerPublic,
	}}

	caCert, caKey, _ := issueTestCertificate(t, nil, nil, "buyer-cap-ca", true, nil, now)
	_, _, serverCert := issueTestCertificate(t, caCert, caKey, "buyer-cap.test", false,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, now)
	clientCert, _, clientTLS := issueTestCertificate(t, caCert, caKey, "buyer-cap-runtime", false,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, now)
	spkiHash := sha256.Sum256(clientCert.RawSubjectPublicKeyInfo)
	server := &SharedAuthorityServer{Backing: backing, EvidenceVerifier: verifier,
		ClientsBySPKI: map[string]SharedAuthorityClientGrant{
			"sha256:" + hex.EncodeToString(spkiHash[:]): {OwnerID: "owner:shared-cap", AgentID: "agent:buyer",
				InstanceID: "buyer-cap-runtime", Scopes: []string{"agreement.authorize", "portfolio.reserve"}},
		}}
	testServer := httptest.NewUnstartedServer(server.Handler())
	clientRoots := x509.NewCertPool()
	clientRoots.AddCert(caCert)
	testServer.TLS, err = NewSharedAuthorityServerTLSConfig(serverCert, clientRoots)
	if err != nil {
		t.Fatal(err)
	}
	testServer.StartTLS()
	defer testServer.Close()
	serverRoots := x509.NewCertPool()
	serverRoots.AddCert(caCert)
	httpClient, err := NewSharedAuthorityHTTPClient(clientTLS, serverRoots, "buyer-cap.test", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer httpClient.CloseIdleConnections()
	client, err := NewSharedAuthorityClient(testServer.URL+"/v1/economic-authority", httpClient,
		"authority:shared-cap", authorityKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}

	template, _ := directBuyerAgreementForAdmission(t, 25, now)
	record, err := client.RecordAgreementProposal(template.Agreement.Body, "agent:seller", "event:shared-cap",
		"sha256:"+strings.Repeat("3", 64))
	if err != nil {
		t.Fatal(err)
	}
	evidence := buyerLossCapAcceptance(t, record.Agreement.Body, record.AgreementDigest, "agent:buyer", buyerKey)
	if _, err = client.RecordAgreementEvidence(record.AgreementDigest, evidence, verifier); err == nil ||
		!strings.Contains(err.Error(), "live maximum-loss hold") {
		t.Fatalf("shared record-evidence bypassed the backing no-hold gate: %v", err)
	}
	fence, err := client.AcquireWriter(t.Context(), "buyer-cap-runtime",
		[]string{"agreement.authorize", "portfolio.reserve"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	asset := commerce.AssetIdentityV1{AssetNamespace: "tos.asset", AssetIdentifier: "native", Unit: "nanotos"}
	reservation := ExposureReservation{ReservationID: "sha256:" + strings.Repeat("4", 64),
		AgreementDigest: record.AgreementDigest, Asset: &asset, SpendAtomic: 25, MaximumLossAtomic: 25}
	engine := &Engine{OwnerID: "owner:shared-cap", AgentID: "agent:buyer", MandateDigest: testDigest,
		Authority: client, Now: func() time.Time { return now }}
	if _, _, err = engine.ReserveAgreement(t.Context(), record.AgreementDigest, reservation,
		allowSettlement{}, 1, fence); err != nil {
		t.Fatal(err)
	}
	accepted, err := client.RecordAgreementEvidence(record.AgreementDigest, evidence, verifier)
	if err != nil || !hasAgentEvidence(accepted, "agent:buyer") {
		t.Fatalf("shared evidence with an exact hold failed: record=%+v err=%v", accepted, err)
	}
	if replay, replayErr := client.RecordAgreementEvidence(record.AgreementDigest, evidence, verifier); replayErr != nil || replay.StateRevision != accepted.StateRevision {
		t.Fatalf("shared exact evidence replay did not reach backing idempotence: record=%+v err=%v", replay, replayErr)
	}
	backing.mu.Lock()
	released := backing.doc.Reservations[reservation.ReservationID]
	released.Released = true
	backing.doc.Reservations[reservation.ReservationID] = released
	backing.mu.Unlock()
	if _, err = client.RecordAgreementEvidence(record.AgreementDigest, evidence, verifier); err == nil ||
		!strings.Contains(err.Error(), "live maximum-loss hold") {
		t.Fatalf("shared exact replay bypassed the backing released-hold gate: %v", err)
	}
}

func TestBuyerLossCapRelaySponsorshipAdmissionIsAtomic(t *testing.T) {
	_, providerKey, _ := ed25519.GenerateKey(rand.Reader)
	firstFixture := newRelayTestFixture(t, "agent:provider-cap", providerKey, "https://relay.example")
	secondFixture := newRelayTestFixture(t, "agent:provider-cap", providerKey, "https://relay.example")
	secondFixture.prepared.QuoteBody.RequestID = "request:two"
	firstExecution, firstAgreement, firstObligation := relaySponsorshipFixture(t, firstFixture)
	secondExecution, secondAgreement, secondObligation := relaySponsorshipFixture(t, secondFixture)
	_, authorityKey, _ := ed25519.GenerateKey(rand.Reader)
	directory := privateTempDir(t)
	limits := relaySponsorshipTestLimits(t, firstFixture)
	limits.SpendAtomic, limits.MaximumLossAtomic = 5, 5
	authority, err := OpenPersonalAuthority(directory, "owner:provider-cap", firstFixture.profile.ProviderAgentID,
		"authority:provider-cap", authorityKey, limits)
	if err != nil {
		t.Fatal(err)
	}
	authority.now = func() time.Time { return firstFixture.now }
	fence, err := authority.AcquireWriter(t.Context(), "relay-provider-cap", []string{"payment.domain-bound"}, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	processor := &AgreementSponsorshipProcessor{Engine: &Engine{OwnerID: "owner:provider-cap",
		AgentID: firstFixture.profile.ProviderAgentID, MandateDigest: relayTestDigest("a"),
		Gates: FeatureGates{DirectPayment: true}, Authority: authority, Now: func() time.Time { return firstFixture.now }},
		Sink: &relaySponsorshipPaymentSink{now: firstFixture.now}, Verifier: &relaySponsorshipPaymentSink{now: firstFixture.now},
		FinalityVerifier: RelaySponsorshipFinalityVerifierFunc(func(context.Context, agentrelay.RelayExecutionRequest,
			commerce.AgreementPaymentRequest, commerce.AgreementPaymentEvidence) error {
			return nil
		}),
		NetworkDomain: firstFixture.network, NativeAsset: firstFixture.asset, PolicyRevision: 1,
		WriterFence: fence, Now: func() time.Time { return firstFixture.now }}
	firstMaterial, err := processor.prepareSponsorshipPayment(t.Context(), firstExecution, firstAgreement, firstObligation, nil)
	if err != nil {
		t.Fatal(err)
	}
	secondMaterial, err := processor.prepareSponsorshipPayment(t.Context(), secondExecution, secondAgreement, secondObligation, nil)
	if err != nil {
		t.Fatal(err)
	}
	firstAction, err := authority.SignAction(firstMaterial.action, fence)
	if err != nil {
		t.Fatal(err)
	}
	secondAction, err := authority.SignAction(secondMaterial.action, fence)
	if err != nil {
		t.Fatal(err)
	}

	type admissionResult struct {
		resolution commerce.ActionResolution
		err        error
	}
	start := make(chan struct{})
	results := make(chan admissionResult, 2)
	var workers sync.WaitGroup
	admit := func(action commerce.AuthorizedAction, material relaySponsorshipPaymentMaterial) {
		defer workers.Done()
		<-start
		resolution, _, admitErr := authority.AdmitRelaySponsorshipPayment(action, material.fields,
			material.canonical, fence, material.payment, material.purpose)
		results <- admissionResult{resolution: resolution, err: admitErr}
	}
	workers.Add(2)
	go admit(firstAction, firstMaterial)
	go admit(secondAction, secondMaterial)
	close(start)
	workers.Wait()
	close(results)
	succeeded, rejected := 0, 0
	for result := range results {
		if result.err == nil && result.resolution.State == commerce.ActionPrepared {
			succeeded++
		} else if result.err != nil && strings.Contains(result.err.Error(), "aggregate Portfolio limit") {
			rejected++
		} else {
			t.Fatalf("unexpected atomic sponsorship result: resolution=%+v err=%v", result.resolution, result.err)
		}
	}
	if succeeded != 1 || rejected != 1 {
		t.Fatalf("concurrent sponsorship admission was not linearized: success=%d rejected=%d", succeeded, rejected)
	}
	_, _, reservations := authority.Snapshot()
	if liveReservationCount(reservations) != 1 {
		t.Fatalf("atomic sponsorship left the wrong live exposure set: %+v", reservations)
	}
	if err = authority.Close(); err != nil {
		t.Fatal(err)
	}
	authority, err = OpenPersonalAuthority(directory, "owner:provider-cap", firstFixture.profile.ProviderAgentID,
		"authority:provider-cap", authorityKey, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	_, _, reservations = authority.Snapshot()
	if liveReservationCount(reservations) != 1 {
		t.Fatalf("restart changed the atomically admitted sponsorship hold: %+v", reservations)
	}
}

func TestBuyerLossCapNativeCustodyBearerKeepsItsExactHold(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	fixture := newDirectCustodyLossCapFixture(t, now, 0)
	defer fixture.authority.Close()
	fixture.authority.mu.Lock()
	unsigned := fixture.authority.doc.Engagements[fixture.payment.AgreementBodyDigest]
	fullyAuthorized := unsigned.FullyAuthorizedEvidenceSetDigest
	unsigned.FullyAuthorizedEvidenceSetDigest = ""
	fixture.authority.doc.Engagements[fixture.payment.AgreementBodyDigest] = unsigned
	fixture.authority.mu.Unlock()
	if _, err := fixture.authority.AuthorizeCustodyPayment(fixture.action, fixture.fields,
		fixture.canonical, fixture.fence, fixture.payment, fixture.source, fixture.domain, nil); err == nil {
		t.Fatal("raw payable lifecycle minted custody without a durable fully authorized Agreement")
	}
	fixture.authority.mu.Lock()
	unsigned.FullyAuthorizedEvidenceSetDigest = fullyAuthorized
	fixture.authority.doc.Engagements[fixture.payment.AgreementBodyDigest] = unsigned
	fixture.authority.mu.Unlock()

	authorization, err := fixture.authority.AuthorizeCustodyPayment(fixture.action, fixture.fields,
		fixture.canonical, fixture.fence, fixture.payment, fixture.source, fixture.domain, nil)
	if err != nil {
		t.Fatal(err)
	}
	if authorization.NetworkDomain == nil {
		t.Fatal("custody authorization omitted its exact network domain")
	}
	authorization.NetworkDomain.WorkchainID = -999
	originalDestinationByte := fixture.payment.Destination[0]
	fixture.payment.Destination[0] ^= 0xff
	fixture.authority.mu.Lock()
	retainedIssued := fixture.authority.doc.IssuedCustodyPayments[authorization.AgreementPaymentRequestDigest]
	fixture.authority.mu.Unlock()
	fixture.payment.Destination[0] = originalDestinationByte
	if retainedIssued.Authorization.NetworkDomain == nil ||
		retainedIssued.Authorization.NetworkDomain.WorkchainID != fixture.domain.WorkchainID ||
		!bytes.Equal(retainedIssued.Payment.Destination, fixture.payment.Destination) {
		t.Fatalf("issued custody payment retained caller aliases: %+v", retainedIssued)
	}
	replayed, err := fixture.authority.AuthorizeCustodyPayment(fixture.action, fixture.fields,
		fixture.canonical, fixture.fence, fixture.payment, fixture.source, fixture.domain, nil)
	if err != nil || replayed.NetworkDomain == nil || replayed.NetworkDomain.WorkchainID != fixture.domain.WorkchainID {
		t.Fatalf("exact custody retry minted a different bearer: replay=%+v err=%v", replayed, err)
	}
	if _, err = fixture.authority.AuthorizeCustodyPayment(fixture.action, fixture.fields,
		fixture.canonical, fixture.fence, fixture.payment, "0:other-source", fixture.domain, nil); err == nil ||
		!strings.Contains(err.Error(), "source account") {
		t.Fatalf("un-pinned custody source account was authorized: %v", err)
	}
	external := fixture.payment
	external.SettlementAdapterURI = "external.payment.v1"
	if _, err = fixture.authority.AuthorizeCustodyPayment(fixture.action, fixture.fields,
		fixture.canonical, fixture.fence, external, fixture.source, fixture.domain, nil); err == nil ||
		!strings.Contains(err.Error(), "direct payment adapter") {
		t.Fatalf("external Adapter entered native custody: %v", err)
	}

	partial := fixture.payment
	partial.Amount.AmountAtomic = "24"
	partialFields := make(map[string]commerce.SemanticValue, len(fixture.fields))
	for key, value := range fixture.fields {
		partialFields[key] = value
	}
	partialFields["amount_atomic"] = commerce.ID("24")
	partial.StableActionID, _, err = commerce.DeriveStableActionID(commerce.PaymentActionKind(partial), partialFields)
	if err != nil {
		t.Fatal(err)
	}
	partialCanonical, partialFields, err := commerce.PaymentAuthorizationMaterial(partial)
	if err != nil {
		t.Fatal(err)
	}
	partialAction, err := commerce.BuildAuthorizedAction("owner:direct-cap", "agent:buyer",
		commerce.PaymentActionKind(partial), partialFields, partialCanonical, fixture.fence, 1, testDigest,
		"", "pending", partial.ExpiresAtUnix)
	if err == nil {
		partialAction, err = fixture.authority.SignAction(partialAction, fixture.fence)
	}
	if err == nil {
		_, err = fixture.authority.Admit(partialAction, partialFields, partialCanonical, fixture.fence, nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err = fixture.authority.AuthorizeCustodyPayment(partialAction, partialFields, partialCanonical,
		fixture.fence, partial, fixture.source, fixture.domain, nil); err == nil ||
		!strings.Contains(err.Error(), "different live native custody bearer") {
		t.Fatalf("one reservation authorized two independently executable bearers: %v", err)
	}

	revision, _, _ := fixture.authority.Snapshot()
	release := PortfolioReleaseRequest{ReservationID: fixture.reservationID,
		AgreementDigest: fixture.payment.AgreementBodyDigest, TargetPortfolioRevision: revision + 1,
		TerminalEvidenceSetDigest: "sha256:" + strings.Repeat("9", 64)}
	releaseCanonical, err := codec.Marshal(release)
	if err != nil {
		t.Fatal(err)
	}
	releaseFields := map[string]commerce.SemanticValue{"owner_id": commerce.ID("owner:direct-cap"),
		"agent_id": commerce.ID("agent:buyer"), "reservation_id": commerce.Digest32(fixture.reservationID),
		"target_revision":              commerce.U64(release.TargetPortfolioRevision),
		"terminal_evidence_set_digest": commerce.Digest32(release.TerminalEvidenceSetDigest)}
	releaseAction, err := commerce.BuildAuthorizedAction("owner:direct-cap", "agent:buyer", "portfolio.release",
		releaseFields, releaseCanonical, fixture.fence, 1, testDigest, "", "settling", fixture.fence.Body.ExpiresAtUnix)
	if err == nil {
		releaseAction, err = fixture.authority.SignAction(releaseAction, fixture.fence)
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err = fixture.authority.ReleaseReservation(releaseAction, releaseFields, releaseCanonical, fixture.fence); !errors.Is(err, ErrCustodyAuthorizationLive) {
		t.Fatalf("generic release retired a live native bearer hold: %v", err)
	}
	_, _, reservations := fixture.authority.Snapshot()
	if liveReservationCount(reservations) != 1 {
		t.Fatalf("issued custody bearer no longer owns one live hold: %+v", reservations)
	}
}

type submittedDirectPaymentRecoverySink struct {
	requestDigest string
	evidence      commerce.AgreementPaymentEvidence
	resumes       int
	submits       int
}

func (sink *submittedDirectPaymentRecoverySink) ManagesRelaySponsorshipSubmissionFence() bool {
	return true
}

func (sink *submittedDirectPaymentRecoverySink) SubmitPayment(context.Context, commerce.AuthorizedAction,
	commerce.WriterFence, map[string]commerce.SemanticValue, []byte,
	commerce.AgreementPaymentRequest) (commerce.AgreementPaymentEvidence, error) {
	sink.submits++
	return commerce.AgreementPaymentEvidence{}, errors.New("submitted recovery prepared a replacement payment")
}

func (sink *submittedDirectPaymentRecoverySink) ResumePaymentBroadcast(_ context.Context,
	request commerce.AgreementPaymentRequest, exactRequestDigest string) error {
	digest, err := commerce.AgreementPaymentRequestDigest(request)
	if err != nil || digest != sink.requestDigest || !canonicalSHA256(exactRequestDigest) {
		return errors.New("submitted recovery changed the exact payment")
	}
	sink.resumes++
	return nil
}

func (sink *submittedDirectPaymentRecoverySink) ResolvePayment(_ context.Context,
	request commerce.AgreementPaymentRequest) (commerce.AgreementPaymentEvidence, error) {
	digest, err := commerce.AgreementPaymentRequestDigest(request)
	if err != nil || digest != sink.requestDigest {
		return commerce.AgreementPaymentEvidence{}, errors.New("submitted recovery queried another payment")
	}
	return sink.evidence, nil
}

func (*submittedDirectPaymentRecoverySink) VerifyPaymentEvidence(commerce.AgreementPaymentRequest,
	commerce.AgreementPaymentEvidence, time.Time) error {
	return nil
}

func TestBuyerLossCapSubmittedPaymentResumesExactBOCAndAcceptedRetry(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	fixture := newDirectCustodyLossCapFixture(t, now, 0)
	defer fixture.authority.Close()
	network := agentrelay.NetworkDomain{NetworkID: fixture.domain.NetworkID, GlobalID: fixture.domain.GlobalID,
		ZeroStateRootHash: fixture.domain.ZeroStateRootHash, ZeroStateFileHash: fixture.domain.ZeroStateFileHash,
		WorkchainID: fixture.domain.WorkchainID}
	broadcastCalls := 0
	tosSink := &TOSCTLPaymentSink{Authority: fixture.authority, Executable: "/usr/bin/tosctl",
		ConfigPath: "/tmp/openfox-resume-primary.json", Wallet: "wallet:buyer", SourceAccount: fixture.source,
		NetworkGlobalID: network.GlobalID, RelayNetworkDomain: &network, FeeReserveNanoTOS: 1,
		QuorumConfigPaths: []string{"/tmp/openfox-resume-quorum-2.json", "/tmp/openfox-resume-quorum-3.json"},
		EvidenceDirectory: "/tmp/openfox-resume-evidence", Run: func(_ context.Context, args, _ []string) ([]byte, error) {
			broadcastCalls++
			return json.Marshal(tosctlPaymentBroadcast{Schema: "tosctl.agent-account.agreement-payment-broadcast.v1",
				StableActionID: fixture.payment.StableActionID, Account: fixture.source,
				ExactSignedBOCDigest: "sha256:" + strings.Repeat("a", 64), State: "broadcasting"})
		}}
	if err := tosSink.ResumePaymentBroadcast(t.Context(), fixture.payment,
		fixture.action.ExactRequestDigest); err == nil || broadcastCalls != 0 {
		t.Fatalf("custody broadcast resumed before the exact Submitted boundary: calls=%d err=%v", broadcastCalls, err)
	}
	if _, err := fixture.authority.AuthorizeCustodyPayment(fixture.action, fixture.fields, fixture.canonical,
		fixture.fence, fixture.payment, fixture.source, fixture.domain, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.authority.Transition(fixture.action.StableActionID, fixture.action.ExactRequestDigest,
		commerce.ActionSubmitted, "", nil); err != nil {
		t.Fatal(err)
	}
	if err := tosSink.ResumePaymentBroadcast(t.Context(), fixture.payment,
		"sha256:"+strings.Repeat("f", 64)); err == nil || broadcastCalls != 0 {
		t.Fatalf("custody broadcast accepted the wrong exact request: calls=%d err=%v", broadcastCalls, err)
	}
	if err := tosSink.ResumePaymentBroadcast(t.Context(), fixture.payment,
		fixture.action.ExactRequestDigest); err != nil || broadcastCalls != 1 {
		t.Fatalf("custody did not resume the exact Submitted BOC: calls=%d err=%v", broadcastCalls, err)
	}
	paymentDigest, err := commerce.AgreementPaymentRequestDigest(fixture.payment)
	if err != nil {
		t.Fatal(err)
	}
	evidence := commerce.AgreementPaymentEvidence{PaymentRequestDigest: paymentDigest,
		StableActionID: fixture.payment.StableActionID, ExactTransferReference: "tx:submitted-recovery",
		AdapterEvidenceProfile: "tos.finalized-transfer.v1", ResolvedState: "finalized",
		ResolvedAtUnix: uint64(now.Unix()), FinalityReference: "checkpoint:submitted-recovery",
		Evidence: []byte("finalized exact payment")}
	sink := &submittedDirectPaymentRecoverySink{requestDigest: paymentDigest, evidence: evidence}
	engine := &Engine{OwnerID: "owner:direct-cap", AgentID: "agent:buyer", MandateDigest: testDigest,
		Gates: FeatureGates{DirectPayment: true}, Authority: fixture.authority, Now: func() time.Time { return now }}
	service := PaymentService{Engine: engine, Sink: sink, Verifier: sink}
	if _, _, engagement, err := service.Pay(t.Context(), fixture.payment, 1, fixture.fence); err != nil ||
		engagement.State != EngagementSettled || sink.resumes != 1 || sink.submits != 0 {
		t.Fatalf("submitted exact BOC did not resume: state=%s resumes=%d submits=%d err=%v",
			engagement.State, sink.resumes, sink.submits, err)
	}
	// A crash after ActionAccepted/billing but before the campaign result must
	// resolve the same payment and remain idempotent without another broadcast.
	if _, _, engagement, err := service.Pay(t.Context(), fixture.payment, 1, fixture.fence); err != nil ||
		engagement.State != EngagementSettled || sink.resumes != 1 || sink.submits != 0 {
		t.Fatalf("accepted payment retry was not idempotent: state=%s resumes=%d submits=%d err=%v",
			engagement.State, sink.resumes, sink.submits, err)
	}
}

func TestBuyerLossCapCustodyExpiryIsOwnerPinnedAndDurable(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second).Add(-2 * time.Hour)
	fixture := newDirectCustodyLossCapFixture(t, now, 10)
	authority := fixture.authority
	if _, err := authority.AuthorizeCustodyPayment(fixture.action, fixture.fields, fixture.canonical,
		fixture.fence, fixture.payment, fixture.source, fixture.domain, nil); err != nil {
		t.Fatal(err)
	}
	paymentDigest, err := commerce.AgreementPaymentRequestDigest(fixture.payment)
	if err != nil {
		t.Fatal(err)
	}
	issued := authority.doc.IssuedCustodyPayments[paymentDigest]
	if issued.ReleaseAfterUnix == 0 || issued.FinalityGraceSeconds != fixture.limits.CustodyFinalityGraceSeconds {
		t.Fatalf("custody issuance omitted its owner-pinned horizon: %+v", issued)
	}
	authority.now = func() time.Time { return time.Unix(int64(issued.ReleaseAfterUnix-1), 0).UTC() }
	_, _, reservations := authority.Snapshot()
	if liveReservationCount(reservations) != 1 {
		t.Fatalf("custody hold expired before its owner horizon: %+v", reservations)
	}
	authority.now = func() time.Time { return time.Unix(int64(issued.ReleaseAfterUnix), 0).UTC() }
	_, _, reservations = authority.Snapshot()
	if liveReservationCount(reservations) != 0 {
		t.Fatalf("mature custody tombstone did not release its exact hold: %+v", reservations)
	}
	engagement, found := authority.Engagement(fixture.payment.AgreementBodyDigest)
	if !found || engagement.ExpiredCustodyAuthorization == nil ||
		engagement.CustodyAuthorizationExpiredAtUnix < issued.ReleaseAfterUnix {
		t.Fatalf("custody expiry did not retain a durable bearer tombstone: %+v", engagement)
	}
	if err = authority.Close(); err != nil {
		t.Fatal(err)
	}
	authority, err = OpenPersonalAuthority(fixture.directory, "owner:direct-cap", "agent:buyer",
		"authority:direct-cap", fixture.key, fixture.limits)
	if err != nil {
		t.Fatalf("valid custody tombstone did not survive restart: %v", err)
	}
	authority.mu.Lock()
	next := cloneAuthorityDocument(authority.doc)
	engagement = next.Engagements[fixture.payment.AgreementBodyDigest]
	engagement.ExpiredCustodyAuthorization.Issuance.FinalityGraceSeconds--
	engagement.ExpiredCustodyAuthorization.Issuance.ReleaseAfterUnix--
	next.Engagements[fixture.payment.AgreementBodyDigest] = engagement
	err = authority.persist(next)
	authority.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err = authority.Close(); err != nil {
		t.Fatal(err)
	}
	if reopened, reopenErr := OpenPersonalAuthority(fixture.directory, "owner:direct-cap", "agent:buyer",
		"authority:direct-cap", fixture.key, fixture.limits); reopenErr == nil {
		_ = reopened.Close()
		t.Fatal("shortened custody grace was accepted after restart")
	}
}

func buyerLossCapAcceptance(t *testing.T, body commerce.AgentAgreementBody, digest, agentID string,
	key ed25519.PrivateKey) commerce.AgreementAuthorizationEvidence {
	t.Helper()
	var predicate commerce.AgreementAuthorizationPredicate
	for _, candidate := range body.AuthorizationPredicates {
		if candidate.AuthoritySubject.SubjectKind == "agent" &&
			candidate.AuthoritySubject.SubjectIdentifier == agentID &&
			candidate.EvidenceProfileURI == commerce.EvidenceProfileAgentSignature {
			predicate = candidate
			break
		}
	}
	if predicate.PredicateID == "" {
		t.Fatal("buyer-loss-cap fixture has no local Agent-signature predicate")
	}
	acceptance, err := commerce.SignAgreementAcceptance(commerce.AgreementAcceptanceBody{
		AgreementID: body.AgreementID, AgreementVersion: body.Version, AgreementBodyDigest: digest,
		AcceptingSubject: predicate.AuthoritySubject, PredicateIDs: []string{predicate.PredicateID},
		EvidenceTargetProjectionDigests: []string{predicate.EvidenceTargetProjectionDigest},
		ExpiresAtUnix:                   body.ExpiresAtUnix,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := commerce.AgentSignatureEvidence(body, acceptance)
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}

func liveReservationCount(reservations []ExposureReservation) int {
	count := 0
	for _, reservation := range reservations {
		if !reservation.Released {
			count++
		}
	}
	return count
}

func buyerLossCapDirectLimits(maximum uint64) PortfolioLimits {
	asset := commerce.AssetIdentityV1{AssetNamespace: "tos.asset", AssetIdentifier: "native", Unit: "nanotos"}
	return PortfolioLimits{SpendAtomic: maximum, MaximumLossAtomic: maximum,
		CustodyNetworkDomainDigest: "sha256:" + strings.Repeat("7", 64),
		CustodyNativeAsset:         &asset,
		CustodySourceAccount:       "0:buyer-loss-cap"}
}

type directCustodyLossCapFixture struct {
	authority     *PersonalAuthority
	directory     string
	key           ed25519.PrivateKey
	limits        PortfolioLimits
	fence         commerce.WriterFence
	action        commerce.AuthorizedAction
	fields        map[string]commerce.SemanticValue
	canonical     []byte
	payment       commerce.AgreementPaymentRequest
	domain        commerce.CustodyNetworkDomain
	source        string
	reservationID string
}

func newDirectCustodyLossCapFixture(t *testing.T, now time.Time, grace uint64) directCustodyLossCapFixture {
	t.Helper()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	buyerPublic, buyerKey, _ := ed25519.GenerateKey(rand.Reader)
	sellerPublic, sellerKey, _ := ed25519.GenerateKey(rand.Reader)
	relayDomain := agentrelay.NetworkDomain{NetworkID: "tos:test", GlobalID: -3,
		ZeroStateRootHash: testDigest,
		ZeroStateFileHash: "sha256:" + strings.Repeat("b", 64), WorkchainID: 0}
	domainDigest, err := agentrelay.NetworkDomainDigest(relayDomain)
	if err != nil {
		t.Fatal(err)
	}
	asset := commerce.AssetIdentityV1{AssetNamespace: "tos.asset", AssetIdentifier: "native", Unit: "nanotos"}
	limits := PortfolioLimits{SpendAtomic: 25, MaximumLossAtomic: 25,
		CustodyNetworkDomainDigest: domainDigest, CustodyFinalityGraceSeconds: grace,
		CustodyNativeAsset: &asset, CustodySourceAccount: "0:source"}
	directory := privateTempDir(t)
	authority, err := OpenPersonalAuthority(directory, "owner:direct-cap", "agent:buyer",
		"authority:direct-cap", key, limits)
	if err != nil {
		t.Fatal(err)
	}
	authority.now = func() time.Time { return now }
	fence, err := authority.AcquireWriter(t.Context(), "direct-cap-runtime",
		[]string{"billing.resolve", "payment.domain-bound", "portfolio.release", "portfolio.reserve"}, time.Hour)
	if err != nil {
		_ = authority.Close()
		t.Fatal(err)
	}
	template, _ := directBuyerAgreementForAdmission(t, 25, now)
	record, err := authority.RecordAgreementProposal(template.Agreement.Body, "agent:seller", "event:direct-cap",
		"sha256:"+strings.Repeat("8", 64))
	if err != nil {
		_ = authority.Close()
		t.Fatal(err)
	}
	instances, err := commerce.MaterializeSettlementObligations("owner:direct-cap", "agent:buyer",
		record.AgreementDigest, "pay", testDigest, record.Agreement.Body.Obligations[0])
	if err != nil || len(instances) != 1 {
		_ = authority.Close()
		t.Fatalf("materialize direct custody fixture: instances=%d err=%v", len(instances), err)
	}
	payment, err := commerce.BuildDomainBoundAgreementPaymentRequest("owner:direct-cap", "agent:buyer",
		relayDomain.NetworkID, domainDigest, record.Agreement.Body.Obligations[0].SettlementParameters, instances[0])
	if err != nil {
		_ = authority.Close()
		t.Fatal(err)
	}
	reservationID, err := codec.Digest("tos.test.buyer-loss-cap-reservation.v1", struct {
		AgreementDigest string `json:"agreement_body_digest"`
	}{AgreementDigest: record.AgreementDigest})
	if err != nil {
		_ = authority.Close()
		t.Fatal(err)
	}
	reservation := ExposureReservation{ReservationID: reservationID, AgreementDigest: record.AgreementDigest,
		Asset: &asset, SpendAtomic: 25, MaximumLossAtomic: 25}
	engine := &Engine{OwnerID: "owner:direct-cap", AgentID: "agent:buyer", MandateDigest: testDigest,
		Authority: authority, Now: func() time.Time { return now }}
	if _, _, err = engine.ReserveAgreement(t.Context(), record.AgreementDigest, reservation,
		allowSettlement{}, 1, fence); err != nil {
		_ = authority.Close()
		t.Fatal(err)
	}
	verifier := AgreementEvidenceRouter{AgentAuthority: agreementKeyResolver{
		"agent:buyer": buyerPublic, "agent:seller": sellerPublic,
	}}
	for _, signer := range []struct {
		agentID string
		key     ed25519.PrivateKey
	}{{"agent:buyer", buyerKey}, {"agent:seller", sellerKey}} {
		evidence := buyerLossCapAcceptance(t, record.Agreement.Body, record.AgreementDigest, signer.agentID, signer.key)
		if record, err = authority.RecordAgreementEvidence(record.AgreementDigest, evidence, verifier); err != nil {
			_ = authority.Close()
			t.Fatal(err)
		}
	}
	if _, err = authority.transitionObligation(record.AgreementDigest, "work", ObligationPending,
		ObligationDelivered, "", []string{"sha256:" + strings.Repeat("c", 64)}, "event:delivered"); err != nil {
		_ = authority.Close()
		t.Fatal(err)
	}
	if _, err = authority.transitionObligation(record.AgreementDigest, "pay", ObligationPending,
		ObligationSettling, "", nil, ""); err != nil {
		_ = authority.Close()
		t.Fatal(err)
	}
	settlementState, err := commerce.NewSettlementState(instances[0])
	if err != nil {
		_ = authority.Close()
		t.Fatal(err)
	}
	authority.mu.Lock()
	next := cloneAuthorityDocument(authority.doc)
	next.SettlementLedger[instances[0].ObligationInstanceID] = SettlementLedgerRecord{
		Obligation: instances[0], State: settlementState}
	err = authority.persist(next)
	if err == nil {
		authority.doc = next
	}
	authority.mu.Unlock()
	if err != nil {
		_ = authority.Close()
		t.Fatal(err)
	}
	canonical, fields, err := commerce.PaymentAuthorizationMaterial(payment)
	if err != nil {
		_ = authority.Close()
		t.Fatal(err)
	}
	action, err := commerce.BuildAuthorizedAction("owner:direct-cap", "agent:buyer", commerce.PaymentActionKind(payment),
		fields, canonical, fence, 1, testDigest, "", "pending", payment.ExpiresAtUnix)
	if err == nil {
		action, err = authority.SignAction(action, fence)
	}
	if err == nil {
		_, err = authority.Admit(action, fields, canonical, fence, nil)
	}
	if err != nil {
		_ = authority.Close()
		t.Fatal(err)
	}
	seeded, found := authority.Engagement(record.AgreementDigest)
	if !found || seeded.ReservationID == "" {
		_ = authority.Close()
		t.Fatal("direct custody fixture did not retain its exact reservation")
	}
	return directCustodyLossCapFixture{authority: authority, directory: directory, key: key, limits: limits,
		fence: fence, action: action, fields: fields, canonical: canonical, payment: payment,
		domain: commerce.CustodyNetworkDomain{NetworkID: relayDomain.NetworkID, GlobalID: relayDomain.GlobalID,
			ZeroStateRootHash: relayDomain.ZeroStateRootHash, ZeroStateFileHash: relayDomain.ZeroStateFileHash,
			WorkchainID: relayDomain.WorkchainID},
		source: "0:source", reservationID: seeded.ReservationID}
}
