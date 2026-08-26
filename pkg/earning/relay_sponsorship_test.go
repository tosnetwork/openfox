package earning

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type relaySponsorshipPaymentSink struct {
	now              time.Time
	submits          int
	resolves         int
	events           []string
	ambiguousSubmit  bool
	finalizedRequest *commerce.AgreementPaymentRequest
	evidence         commerce.AgreementPaymentEvidence
	lastAction       commerce.AuthorizedAction
	lastFence        commerce.WriterFence
}

type relayResumableSponsorshipPaymentSink struct {
	*relaySponsorshipPaymentSink
	resumes     int
	sawSnapshot bool
}

func (sink *relayResumableSponsorshipPaymentSink) ResumeRelaySponsorshipBroadcast(_ context.Context,
	_ commerce.AgreementPaymentRequest, snapshot *RelaySponsorshipEvidenceSnapshot) error {
	sink.resumes++
	sink.sawSnapshot = snapshot != nil
	return nil
}

type relayFinalizedSponsorshipResolver struct {
	policy RelaySponsorshipReleasePolicy
	now    time.Time
}

type relayTestSponsorshipAbsenceResolver struct{}

type relaySnapshotTrackingAbsenceResolver struct {
	wantIdentity  string
	sawCapability bool
	sawResolve    bool
}

func (resolver *relaySnapshotTrackingAbsenceResolver) SupportsRelaySponsorshipComponentAbsenceEvidence(
	capability agentrelay.RelayEvidenceCapability, snapshot *RelaySponsorshipEvidenceSnapshot) bool {
	resolver.sawCapability = snapshot != nil && snapshot.SnapshotIdentity == resolver.wantIdentity
	return resolver.sawCapability && capability.UnderlyingActionKind == relayV1UnderlyingActionKind
}

func (resolver *relaySnapshotTrackingAbsenceResolver) SupportsRelayDualAbsenceEvidence(
	capability agentrelay.RelayEvidenceCapability, snapshot *RelaySponsorshipEvidenceSnapshot) bool {
	return resolver.SupportsRelaySponsorshipComponentAbsenceEvidence(capability, snapshot)
}

func (resolver *relaySnapshotTrackingAbsenceResolver) ResolveRelaySponsorshipAbsence(_ context.Context,
	_ agentrelay.RelayExecutionRequest, _ commerce.AgreementPaymentRequest,
	snapshot *RelaySponsorshipEvidenceSnapshot) (RelaySponsorshipAbsenceResult, error) {
	resolver.sawResolve = snapshot != nil && snapshot.SnapshotIdentity == resolver.wantIdentity
	return RelaySponsorshipAbsenceResult{}, ErrRelaySponsorshipAbsenceUnresolved
}

func (resolver *relaySnapshotTrackingAbsenceResolver) ResolveRelaySponsorshipDualAbsence(_ context.Context,
	_ agentrelay.RelayExecutionRequest, _ commerce.AgreementPaymentRequest,
	snapshot RelaySponsorshipEvidenceSnapshot, _ []agentrelay.RelayAbsenceObservationReference,
	_ string, _ []byte) (RelaySponsorshipAbsenceResult, error) {
	resolver.sawResolve = snapshot.SnapshotIdentity == resolver.wantIdentity
	return RelaySponsorshipAbsenceResult{}, ErrRelaySponsorshipAbsenceUnresolved
}

func (relayTestSponsorshipAbsenceResolver) ResolveRelaySponsorshipAbsence(context.Context,
	agentrelay.RelayExecutionRequest, commerce.AgreementPaymentRequest,
	*RelaySponsorshipEvidenceSnapshot) (RelaySponsorshipAbsenceResult, error) {
	return RelaySponsorshipAbsenceResult{}, ErrRelaySponsorshipAbsenceUnresolved
}

func (relayTestSponsorshipAbsenceResolver) ResolveRelaySponsorshipDualAbsence(context.Context,
	agentrelay.RelayExecutionRequest, commerce.AgreementPaymentRequest, RelaySponsorshipEvidenceSnapshot,
	[]agentrelay.RelayAbsenceObservationReference, string, []byte) (RelaySponsorshipAbsenceResult, error) {
	return RelaySponsorshipAbsenceResult{}, ErrRelaySponsorshipAbsenceUnresolved
}

func (relayTestSponsorshipAbsenceResolver) SupportsRelaySponsorshipComponentAbsenceEvidence(
	capability agentrelay.RelayEvidenceCapability, _ *RelaySponsorshipEvidenceSnapshot) bool {
	return capability.UnderlyingActionKind == relayV1UnderlyingActionKind
}

func (resolver relayTestSponsorshipAbsenceResolver) SupportsRelayDualAbsenceEvidence(
	capability agentrelay.RelayEvidenceCapability, snapshot *RelaySponsorshipEvidenceSnapshot) bool {
	return resolver.SupportsRelaySponsorshipComponentAbsenceEvidence(capability, snapshot)
}

func TestRelaySponsorshipAbsenceRecoveryUsesFrozenProviderSnapshot(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	fixture.enableSponsorship(t, agentrelay.ModeSponsorOnly)
	execution := fixture.attempt(t).Execution
	snapshot := RelaySponsorshipEvidenceSnapshot{SchemaVersion: 1,
		EvidenceClass:       string(agentrelay.SponsorshipReleaseObservedUnproven),
		ProfileURI:          execution.QuoteRequest.Body.SponsorshipReleaseProfileURI,
		ProfileDigest:       execution.QuoteRequest.Body.SponsorshipReleaseProfileDigest,
		MaximumTransactions: 1000, SnapshotPath: "/owner/snapshot-a/manifest.json",
		SnapshotIdentity: relayTestDigest("a")}
	resolver := &relaySnapshotTrackingAbsenceResolver{wantIdentity: snapshot.SnapshotIdentity}
	processor := AgreementSponsorshipProcessor{AbsenceResolver: resolver}
	unresolved := agentrelay.SponsorshipResolution{Status: agentrelay.SponsorshipResolutionUnknown}
	got, err := processor.resolveSponsorshipAbsence(t.Context(), execution,
		commerce.AgreementPaymentRequest{}, &snapshot, unresolved)
	if err != nil || got.Status != agentrelay.SponsorshipResolutionUnknown ||
		!resolver.sawCapability || !resolver.sawResolve {
		t.Fatalf("dual-absence recovery did not use the frozen provider snapshot: got=%+v resolver=%+v err=%v",
			got, resolver, err)
	}
}

func (resolver relayFinalizedSponsorshipResolver) RelaySponsorshipEvidenceCapabilities() RelaySponsorshipEvidenceCapabilities {
	return RelaySponsorshipEvidenceCapabilities{SupportedReleasePolicies: []RelaySponsorshipReleasePolicy{resolver.policy},
		TerminalEvidence: true}
}

func (relayFinalizedSponsorshipResolver) SupportsRelaySponsorshipTerminalFinalityProfile(
	agentrelay.FinalityProfile, *RelaySponsorshipEvidenceSnapshot) bool {
	return true
}

func (resolver relayFinalizedSponsorshipResolver) ResolveRelaySponsorshipEvidence(_ context.Context,
	execution agentrelay.RelayExecutionRequest,
	payment commerce.AgreementPaymentRequest) (agentrelay.SponsorshipResolution, error) {
	paymentDigest, err := commerce.AgreementPaymentRequestDigest(payment)
	canonical, _, materialErr := commerce.PaymentAuthorizationMaterial(payment)
	exactDigest, exactErr := commerce.ExactRequestDigest(canonical)
	if err != nil || materialErr != nil || exactErr != nil {
		return agentrelay.SponsorshipResolution{}, errors.Join(err, materialErr, exactErr)
	}
	reserved := execution.ProviderQuote.Body.ReservedSponsorship
	if reserved == nil {
		return agentrelay.SponsorshipResolution{}, errors.New("missing reserved sponsorship")
	}
	if execution.ProviderQuote.Body.SponsorshipTerminalProfile == nil {
		return agentrelay.SponsorshipResolution{}, errors.New("missing sponsorship terminal profile")
	}
	terminalProfile := *execution.ProviderQuote.Body.SponsorshipTerminalProfile
	proofBundle, err := codec.Marshal(map[string]string{"fixture": "relay sponsorship transaction evidence"})
	if err != nil {
		return agentrelay.SponsorshipResolution{}, err
	}
	proofBundleDigest, err := agentrelay.RelaySponsorshipProofBundleDigest(proofBundle)
	if err != nil {
		return agentrelay.SponsorshipResolution{}, err
	}
	terminalClass := agentrelay.SponsorshipTerminalValidatorFinality
	validatorAuthenticated := true
	if resolver.policy.EvidenceClass == agentrelay.SponsorshipReleaseObservedUnproven {
		terminalClass = agentrelay.SponsorshipTerminalClientCorroborated
		validatorAuthenticated = false
	}
	evidence := agentrelay.RelaySponsorshipTransactionEvidence{SchemaVersion: 1,
		TerminalEvidenceClass: terminalClass, ValidatorAuthenticatedPortableProof: validatorAuthenticated,
		NetworkDigest: payment.NetworkDomainDigest, AgreementPaymentRequest: payment,
		AgreementPaymentRequestDigest: paymentDigest, SponsorshipStableActionID: payment.StableActionID,
		SponsorshipExactRequestDigest: exactDigest, ProviderSponsorSourceAccount: "account:provider",
		ProviderSponsorSourceSequence: 7, ProviderSponsorValidUntilUnix: payment.ExpiresAtUnix,
		SignedTopUpTransactionDigest:         relayTestDigest("a"),
		SignedTopUpTransactionCellHash:       "tvm-cell-sha256:" + strings.Repeat("b", 64),
		SponsorshipPaymentCommitmentCellHash: "tvm-cell-sha256:" + strings.Repeat("c", 64),
		DestinationSourceAccount:             string(payment.Destination), Amount: *reserved,
		SubmittedTransactionHash: relayTestDigest("4"), SourceExecutionReference: relayTestDigest("5"),
		DestinationCreditReferences: []string{relayTestDigest("1"), relayTestDigest("2"), relayTestDigest("3")},
		FinalizedCheckpointID:       "checkpoint:sponsorship", FinalizedCheckpointSequence: 9,
		FinalizedCheckpointUnix:          uint64(resolver.now.Unix()),
		ConfirmationDepth:                terminalProfile.MinimumConfirmationDepth,
		SponsorshipTerminalProfileDigest: terminalProfile.ProfileDigest,
		ObservationDigests:               []string{relayTestDigest("1"), relayTestDigest("2"), relayTestDigest("3")},
		ProofBundleDigest:                proofBundleDigest, ProofBundle: proofBundle,
		ObservedAtUnix: uint64(resolver.now.Unix())}
	status := agentrelay.SponsorshipResolutionFinalized
	if terminalClass == agentrelay.SponsorshipTerminalClientCorroborated {
		status = agentrelay.SponsorshipResolutionCorroboratedTerminal
	}
	return agentrelay.SponsorshipResolution{Status: status,
		TransferReference: evidence.SubmittedTransactionHash,
		EvidenceRefs:      append([]string(nil), evidence.ObservationDigests...), TransactionEvidence: &evidence}, nil
}

func (resolver relayFinalizedSponsorshipResolver) ResolveRelaySponsorshipTerminalEvidence(ctx context.Context,
	execution agentrelay.RelayExecutionRequest, payment commerce.AgreementPaymentRequest,
	_ *RelaySponsorshipEvidenceSnapshot) (agentrelay.SponsorshipResolution, error) {
	return resolver.ResolveRelaySponsorshipEvidence(ctx, execution, payment)
}

type rejectingRelaySponsorshipEvidenceVerifier struct{ calls *int }

func (verifier rejectingRelaySponsorshipEvidenceVerifier) VerifySponsorshipTransactionEvidence(context.Context,
	agentrelay.RelaySponsorshipTransactionEvidence, agentrelay.RelaySponsorshipEvidenceContext,
	agentrelay.FinalityProfile) error {
	*verifier.calls = *verifier.calls + 1
	return errors.New("forged portable sponsorship proof")
}

func TestAgreementSponsorshipRejectsStructurallyValidUnverifiedEvidenceBeforeClientBroadcast(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	fixture.prepared.QuoteBody.AssuranceLevel = agentrelay.AssuranceAuthorizedSingleProvider
	fixture.enableSponsorship(t, agentrelay.ModeSponsorAndRelay)
	attempt := fixture.attempt(t)
	_, authorityKey, _ := ed25519.GenerateKey(rand.Reader)
	authority, err := OpenPersonalAuthority(privateTempDir(t), "owner:provider", fixture.profile.ProviderAgentID,
		"authority:provider", authorityKey, PortfolioLimits{})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	authority.now = func() time.Time { return fixture.now }
	fence, err := authority.AcquireWriter(t.Context(), "relay-provider", []string{"payment.direct"}, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	sink := &relaySponsorshipPaymentSink{now: fixture.now}
	policy := relaySponsorshipReleasePolicyFromRequest(attempt.Execution.QuoteRequest.Body)
	resolver := relayFinalizedSponsorshipResolver{policy: policy, now: fixture.now}
	verifyCalls := 0
	processor := &AgreementSponsorshipProcessor{Engine: &Engine{OwnerID: "owner:provider",
		AgentID: fixture.profile.ProviderAgentID, MandateDigest: relayTestDigest("a"),
		Gates: FeatureGates{DirectPayment: true}, Authority: authority, Now: func() time.Time { return fixture.now }},
		Sink: sink, EvidenceResolver: resolver, AbsenceResolver: relayTestSponsorshipAbsenceResolver{},
		TransactionEvidenceVerifier: rejectingRelaySponsorshipEvidenceVerifier{calls: &verifyCalls},
		NetworkDomain:               fixture.network, NativeAsset: fixture.asset, PolicyRevision: 1,
		WriterFence: fence, Now: func() time.Time { return fixture.now }}
	broadcaster := &relayTestBroadcaster{}
	service := fixture.service(agentrelay.NewMemoryJournal(), broadcaster)
	service.Sponsorship = processor
	if _, _, err := service.Journal.ReserveQuote(service.Profile, attempt.Execution.QuoteRequest,
		attempt.Execution.ProviderQuote, fixture.now); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Submit(t.Context(), attempt.Execution, attempt.Agreement); err == nil ||
		verifyCalls != 1 || broadcaster.submits != 0 {
		t.Fatalf("unverified sponsorship evidence reached client transaction broadcast: verify=%d broadcasts=%d err=%v",
			verifyCalls, broadcaster.submits, err)
	}
}

func (sink *relaySponsorshipPaymentSink) SubmitPayment(_ context.Context, action commerce.AuthorizedAction,
	fence commerce.WriterFence, _ map[string]commerce.SemanticValue, _ []byte,
	request commerce.AgreementPaymentRequest) (commerce.AgreementPaymentEvidence, error) {
	sink.submits++
	sink.events = append(sink.events, "submit")
	sink.lastAction = action
	sink.lastFence = fence
	digest, err := commerce.AgreementPaymentRequestDigest(request)
	if err != nil {
		return commerce.AgreementPaymentEvidence{}, err
	}
	copy := request
	copy.Destination = append([]byte(nil), request.Destination...)
	sink.finalizedRequest = &copy
	sink.evidence = commerce.AgreementPaymentEvidence{PaymentRequestDigest: digest, StableActionID: request.StableActionID,
		ExactTransferReference: "tx:sponsorship", AdapterEvidenceProfile: "tos.test.finality.v1",
		ResolvedState: "finalized", ResolvedAtUnix: uint64(sink.now.Unix()),
		FinalityReference: relayTestDigest("f"), Evidence: []byte("independent quorum artifact")}
	if sink.ambiguousSubmit {
		return commerce.AgreementPaymentEvidence{}, errors.New("response lost after custody write")
	}
	return sink.evidence, nil
}

func (sink *relaySponsorshipPaymentSink) ResolvePayment(_ context.Context,
	request commerce.AgreementPaymentRequest) (commerce.AgreementPaymentEvidence, error) {
	sink.resolves++
	sink.events = append(sink.events, "resolve")
	if sink.finalizedRequest == nil || sink.finalizedRequest.StableActionID != request.StableActionID {
		return commerce.AgreementPaymentEvidence{}, errors.New("unknown payment")
	}
	return sink.evidence, nil
}

func (sink *relaySponsorshipPaymentSink) VerifyPaymentEvidence(request commerce.AgreementPaymentRequest,
	evidence commerce.AgreementPaymentEvidence, _ time.Time) error {
	digest, err := commerce.AgreementPaymentRequestDigest(request)
	if err != nil || evidence.PaymentRequestDigest != digest || evidence.StableActionID != request.StableActionID ||
		evidence.ExactTransferReference != "tx:sponsorship" || evidence.ResolvedState != "finalized" ||
		string(request.Destination) == "" || sink.finalizedRequest == nil ||
		string(request.Destination) != string(sink.finalizedRequest.Destination) {
		return errors.New("unverified sponsorship evidence")
	}
	return nil
}

func TestAgreementSponsorshipProcessorPersistsAndQueriesExactPaymentBeforeRetry(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	execution, agreement, obligation := relaySponsorshipFixture(t, fixture)
	_, authorityKey, _ := ed25519.GenerateKey(rand.Reader)
	authority, err := OpenPersonalAuthority(privateTempDir(t), "owner:provider", fixture.profile.ProviderAgentID,
		"authority:provider", authorityKey, PortfolioLimits{})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	authority.now = func() time.Time { return fixture.now }
	fence, err := authority.AcquireWriter(t.Context(), "relay-provider", []string{"payment.direct"}, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	sink := &relaySponsorshipPaymentSink{now: fixture.now, ambiguousSubmit: true}
	processor := &AgreementSponsorshipProcessor{Engine: &Engine{OwnerID: "owner:provider",
		AgentID: fixture.profile.ProviderAgentID, MandateDigest: relayTestDigest("a"),
		Gates: FeatureGates{DirectPayment: true}, Authority: authority, Now: func() time.Time { return fixture.now }},
		Sink: sink, Verifier: sink, FinalityVerifier: RelaySponsorshipFinalityVerifierFunc(func(_ context.Context,
			exact agentrelay.RelayExecutionRequest, payment commerce.AgreementPaymentRequest,
			evidence commerce.AgreementPaymentEvidence) error {
			if exact.ProviderQuote.Body.SponsorshipTerminalProfile == nil ||
				*exact.ProviderQuote.Body.SponsorshipTerminalProfile != fixture.sponsorshipFinality ||
				payment.NetworkID != fixture.network.NetworkID ||
				evidence.FinalityReference == "" {
				return errors.New("wrong exact relay finality profile")
			}
			return nil
		}), NetworkDomain: fixture.network, NativeAsset: fixture.asset, PolicyRevision: 1, WriterFence: fence,
		Now: func() time.Time { return fixture.now }}

	recoveryToken, err := processor.PrepareRecovery(t.Context(), execution, agreement, obligation)
	if err != nil {
		t.Fatal(err)
	}
	resolution, err := processor.EnsureFinalized(t.Context(), execution, agreement, obligation, recoveryToken)
	if err != nil || resolution.Status != agentrelay.SponsorshipResolutionFinalized ||
		resolution.TransferReference != "tx:sponsorship" || len(resolution.EvidenceRefs) != 1 ||
		sink.submits != 1 || sink.resolves != 1 || sink.finalizedRequest == nil ||
		string(sink.finalizedRequest.Destination) != execution.QuoteRequest.Body.SourceAccount ||
		sink.finalizedRequest.Amount.AmountAtomic != obligation.Amount.AmountAtomic ||
		sink.finalizedRequest.StableActionID == execution.AuthorizedAction.StableActionID {
		t.Fatalf("exact sponsorship payment failed: finalized=%v ref=%q evidence=%v submits=%d resolves=%d request=%+v err=%v",
			resolution.Status, resolution.TransferReference, resolution.EvidenceRefs, sink.submits, sink.resolves, sink.finalizedRequest, err)
	}
	firstPaymentID := sink.finalizedRequest.StableActionID
	resolution, err = processor.EnsureFinalized(t.Context(), execution, agreement, obligation, recoveryToken)
	if err != nil || resolution.Status != agentrelay.SponsorshipResolutionFinalized || sink.submits != 1 ||
		sink.resolves != 2 || sink.finalizedRequest.StableActionID != firstPaymentID {
		t.Fatalf("exact retry did not query durable payment first: submits=%d resolves=%d err=%v", sink.submits, sink.resolves, err)
	}

	mutated := obligation
	amount := *mutated.Amount
	amount.AmountAtomic = "6"
	mutated.Amount = &amount
	if _, err := processor.EnsureFinalized(t.Context(), execution, agreement, mutated, recoveryToken); err == nil || sink.submits != 1 {
		t.Fatal("mutated sponsorship amount reached custody")
	}
	wrongNetwork := execution
	wrongNetwork.QuoteRequest.Body.Network.ZeroStateRootHash = relayTestDigest("8")
	if _, err := processor.EnsureFinalized(t.Context(), wrongNetwork, agreement, obligation, recoveryToken); err == nil || sink.submits != 1 {
		t.Fatal("display-identical network with another zero state reached sponsorship custody")
	}
	processor.Engine.Gates.DirectPayment = false
	if _, err := processor.EnsureFinalized(t.Context(), execution, agreement, obligation, recoveryToken); err == nil {
		t.Fatal("default-off direct payment gate did not disable gas sponsorship")
	}
	processor.Engine.Gates.DirectPayment = true
	mutatedToken := recoveryToken
	mutatedToken.OpaqueToken = append([]byte(nil), recoveryToken.OpaqueToken...)
	mutatedToken.OpaqueToken[len(mutatedToken.OpaqueToken)-1] ^= 0x01
	if _, err := processor.EnsureFinalized(t.Context(), execution, agreement, obligation, mutatedToken); err == nil || sink.submits != 1 {
		t.Fatal("mutated recovery token reached custody")
	}
	resolution, err = processor.ResolveFinalized(t.Context(), execution, recoveryToken)
	if err != nil || resolution.Status != agentrelay.SponsorshipResolutionFinalized ||
		resolution.TransferReference != "tx:sponsorship" || len(resolution.EvidenceRefs) != 1 || sink.submits != 1 {
		t.Fatalf("read-only sponsorship recovery failed: status=%v ref=%q evidence=%v err=%v",
			resolution.Status, resolution.TransferReference, resolution.EvidenceRefs, err)
	}
}

func TestAgreementSponsorshipAdmittedPaymentDrainsUnderSuccessorWriter(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	execution, agreement, obligation := relaySponsorshipFixture(t, fixture)
	_, authorityKey, _ := ed25519.GenerateKey(rand.Reader)
	directory := privateTempDir(t)
	authorityA, err := OpenPersonalAuthority(directory, "owner:provider", fixture.profile.ProviderAgentID,
		"authority:provider", authorityKey, PortfolioLimits{})
	if err != nil {
		t.Fatal(err)
	}
	authorityA.now = func() time.Time { return fixture.now }
	fenceA, err := authorityA.AcquireWriter(t.Context(), "relay-provider-a", []string{"payment.direct"}, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	sink := &relaySponsorshipPaymentSink{now: fixture.now}
	newProcessor := func(authority EconomicAuthority, fence commerce.WriterFence) *AgreementSponsorshipProcessor {
		return &AgreementSponsorshipProcessor{Engine: &Engine{OwnerID: "owner:provider",
			AgentID: fixture.profile.ProviderAgentID, MandateDigest: relayTestDigest("a"),
			Gates: FeatureGates{DirectPayment: true}, Authority: authority, Now: func() time.Time { return fixture.now }},
			Sink: sink, Verifier: sink,
			FinalityVerifier: RelaySponsorshipFinalityVerifierFunc(func(context.Context,
				agentrelay.RelayExecutionRequest, commerce.AgreementPaymentRequest,
				commerce.AgreementPaymentEvidence) error {
				return nil
			}),
			NetworkDomain: fixture.network, NativeAsset: fixture.asset, PolicyRevision: 1,
			WriterFence: fence, Now: func() time.Time { return fixture.now }}
	}
	processorA := newProcessor(authorityA, fenceA)
	recovery, err := processorA.PrepareRecovery(t.Context(), execution, agreement, obligation)
	if err != nil {
		t.Fatal(err)
	}
	materialA, err := processorA.prepareSponsorshipPayment(t.Context(), execution, agreement, obligation, nil)
	if err != nil {
		t.Fatal(err)
	}
	actionA, err := authorityA.SignAction(materialA.action, fenceA)
	if err != nil {
		t.Fatal(err)
	}
	admitted, err := authorityA.Admit(actionA, materialA.fields, materialA.canonical, fenceA, nil)
	if err != nil || admitted.State != commerce.ActionPrepared {
		t.Fatalf("writer A could not establish the exact payment admission: admitted=%+v err=%v", admitted, err)
	}
	// A stale writer may have signed work before losing its lease. Keep one
	// exact-request substitution ready to prove that takeover does not revive it.
	staleCanonical := append(append([]byte(nil), materialA.canonical...), 0)
	staleBody, err := commerce.BuildAuthorizedAction(materialA.action.OwnerID, materialA.action.AgentID,
		materialA.action.ActionKind, materialA.fields, staleCanonical, fenceA, materialA.action.PolicyRevision,
		materialA.action.MandateDigest, materialA.action.ApprovalDigest, materialA.action.ExpectedPriorState,
		materialA.action.ExpiresAtUnix)
	if err != nil {
		t.Fatal(err)
	}
	staleAction, err := authorityA.SignAction(staleBody, fenceA)
	if err != nil {
		t.Fatal(err)
	}
	if err := authorityA.Close(); err != nil {
		t.Fatal(err)
	}

	authorityB, err := OpenPersonalAuthority(directory, "owner:provider", fixture.profile.ProviderAgentID,
		"authority:provider", authorityKey, PortfolioLimits{})
	if err != nil {
		t.Fatal(err)
	}
	defer authorityB.Close()
	authorityB.now = func() time.Time { return fixture.now }
	fenceB, err := authorityB.AcquireWriter(t.Context(), "relay-provider-b", []string{"payment.direct"}, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authorityB.Admit(staleAction, materialA.fields, staleCanonical, fenceA, nil); err == nil {
		t.Fatal("writer A admitted a new exact request after writer B took over")
	}
	substituteBody, err := commerce.BuildAuthorizedAction(materialA.action.OwnerID, materialA.action.AgentID,
		materialA.action.ActionKind, materialA.fields, staleCanonical, fenceB, materialA.action.PolicyRevision,
		materialA.action.MandateDigest, materialA.action.ApprovalDigest, materialA.action.ExpectedPriorState,
		materialA.action.ExpiresAtUnix)
	if err != nil {
		t.Fatal(err)
	}
	substituteAction, err := authorityB.SignAction(substituteBody, fenceB)
	if err != nil {
		t.Fatal(err)
	}
	if conflict, err := authorityB.Admit(substituteAction, materialA.fields, staleCanonical, fenceB, nil); err == nil || conflict.State != commerce.ActionConflict {
		t.Fatalf("writer B substituted a different exact payment for A's admission: conflict=%+v err=%v", conflict, err)
	}

	processorB := newProcessor(authorityB, fenceB)
	resolution, err := processorB.EnsureFinalized(t.Context(), execution, agreement, obligation, recovery)
	if err != nil || resolution.Status != agentrelay.SponsorshipResolutionFinalized ||
		resolution.TransferReference != "tx:sponsorship" || sink.resolves != 1 || sink.submits != 1 ||
		len(sink.events) != 2 || sink.events[0] != "resolve" || sink.events[1] != "submit" {
		t.Fatalf("successor writer did not query then drain A's admitted payment exactly: resolution=%+v events=%v err=%v",
			resolution, sink.events, err)
	}
	fenceBDigest, err := commerce.WriterFenceDigest(fenceB)
	if err != nil || sink.lastAction.StableActionID != actionA.StableActionID ||
		sink.lastAction.ExactRequestDigest != actionA.ExactRequestDigest ||
		sink.lastAction.WriterGeneration != fenceB.Body.WriterGeneration ||
		sink.lastAction.WriterFenceDigest != fenceBDigest || sink.lastFence.Body.LeaseID != fenceB.Body.LeaseID {
		t.Fatalf("successor drain changed the semantic payment or reused A's fence: action=%+v fence=%+v err=%v",
			sink.lastAction, sink.lastFence.Body, err)
	}
	actionADigest, actionAErr := commerce.AuthorizedActionDigest(actionA)
	actionBDigest, actionBErr := commerce.AuthorizedActionDigest(sink.lastAction)
	if actionAErr != nil || actionBErr != nil || actionADigest == actionBDigest {
		t.Fatalf("writer takeover did not produce a distinct current authorization envelope: A=%q B=%q errs=%v",
			actionADigest, actionBDigest, errors.Join(actionAErr, actionBErr))
	}
	mutated := obligation
	mutatedAmount := *mutated.Amount
	mutatedAmount.AmountAtomic = "6"
	mutated.Amount = &mutatedAmount
	if _, err := processorB.EnsureFinalized(t.Context(), execution, agreement, mutated, recovery); err == nil ||
		sink.resolves != 1 || sink.submits != 1 {
		t.Fatalf("writer B changed the frozen sponsorship semantics after takeover: events=%v err=%v", sink.events, err)
	}
}

func TestAgreementSponsorshipSubmittedAndUnresolvedNeverCallsCustodyAgain(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	execution, agreement, obligation := relaySponsorshipFixture(t, fixture)
	_, authorityKey, _ := ed25519.GenerateKey(rand.Reader)
	authority, err := OpenPersonalAuthority(privateTempDir(t), "owner:provider", fixture.profile.ProviderAgentID,
		"authority:provider", authorityKey, PortfolioLimits{})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	authority.now = func() time.Time { return fixture.now }
	fence, err := authority.AcquireWriter(t.Context(), "relay-provider", []string{"payment.direct"}, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	sink := &relaySponsorshipPaymentSink{now: fixture.now}
	processor := &AgreementSponsorshipProcessor{Engine: &Engine{OwnerID: "owner:provider",
		AgentID: fixture.profile.ProviderAgentID, MandateDigest: relayTestDigest("a"),
		Gates: FeatureGates{DirectPayment: true}, Authority: authority, Now: func() time.Time { return fixture.now }},
		Sink: sink, Verifier: sink, FinalityVerifier: RelaySponsorshipFinalityVerifierFunc(func(context.Context,
			agentrelay.RelayExecutionRequest, commerce.AgreementPaymentRequest,
			commerce.AgreementPaymentEvidence) error {
			return nil
		}),
		NetworkDomain: fixture.network, NativeAsset: fixture.asset, PolicyRevision: 1, WriterFence: fence,
		Now: func() time.Time { return fixture.now }}
	recovery, err := processor.PrepareRecovery(t.Context(), execution, agreement, obligation)
	if err != nil {
		t.Fatal(err)
	}
	material, err := processor.prepareSponsorshipPayment(t.Context(), execution, agreement, obligation, nil)
	if err != nil {
		t.Fatal(err)
	}
	action, err := authority.SignAction(material.action, fence)
	if err != nil {
		t.Fatal(err)
	}
	admitted, err := authority.Admit(action, material.fields, material.canonical, fence, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.Transition(action.StableActionID, action.ExactRequestDigest,
		commerce.ActionSubmitted, "", nil); err != nil || admitted.State != commerce.ActionPrepared {
		t.Fatalf("could not seed the before-socket ambiguity boundary: admitted=%s err=%v", admitted.State, err)
	}

	if _, err := processor.EnsureFinalized(t.Context(), execution, agreement, obligation, recovery); !errors.Is(err, ErrRelaySubmissionAmbiguous) || sink.submits != 0 || sink.resolves != 1 {
		t.Fatalf("unresolved submitted sponsorship reached custody again: submits=%d resolves=%d err=%v",
			sink.submits, sink.resolves, err)
	}
}

func TestAgreementSponsorshipResumesExactValidatorFinalityBroadcastWithoutSnapshot(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	fixture.prepared.QuoteBody.AssuranceLevel = agentrelay.AssuranceAuthorizedSingleProvider
	execution, agreement, obligation := relaySponsorshipFixture(t, fixture)
	_, authorityKey, _ := ed25519.GenerateKey(rand.Reader)
	authority, err := OpenPersonalAuthority(privateTempDir(t), "owner:provider", fixture.profile.ProviderAgentID,
		"authority:provider", authorityKey, PortfolioLimits{})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	authority.now = func() time.Time { return fixture.now }
	fence, err := authority.AcquireWriter(t.Context(), "relay-provider", []string{"payment.direct"}, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	sink := &relayResumableSponsorshipPaymentSink{
		relaySponsorshipPaymentSink: &relaySponsorshipPaymentSink{now: fixture.now}}
	policy := relaySponsorshipReleasePolicyFromRequest(execution.QuoteRequest.Body)
	resolver := relayFinalizedSponsorshipResolver{policy: policy, now: fixture.now}
	processor := &AgreementSponsorshipProcessor{Engine: &Engine{OwnerID: "owner:provider",
		AgentID: fixture.profile.ProviderAgentID, MandateDigest: relayTestDigest("a"),
		Gates: FeatureGates{DirectPayment: true}, Authority: authority, Now: func() time.Time { return fixture.now }},
		Sink: sink, EvidenceResolver: resolver, AbsenceResolver: relayTestSponsorshipAbsenceResolver{},
		TransactionEvidenceVerifier: relayTestSponsorshipEvidenceVerifier{},
		NetworkDomain:               fixture.network, NativeAsset: fixture.asset, PolicyRevision: 1, WriterFence: fence,
		Now: func() time.Time { return fixture.now }}
	recovery, err := processor.PrepareRecovery(t.Context(), execution, agreement, obligation)
	if err != nil {
		t.Fatal(err)
	}
	material, err := processor.prepareSponsorshipPayment(t.Context(), execution, agreement, obligation, nil)
	if err != nil {
		t.Fatal(err)
	}
	action, err := authority.SignAction(material.action, fence)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = authority.Admit(action, material.fields, material.canonical, fence, nil); err != nil {
		t.Fatal(err)
	}
	if _, err = authority.Transition(action.StableActionID, action.ExactRequestDigest,
		commerce.ActionSubmitted, "", nil); err != nil {
		t.Fatal(err)
	}
	resolution, err := processor.EnsureFinalized(t.Context(), execution, agreement, obligation, recovery)
	if err != nil || resolution.Status != agentrelay.SponsorshipResolutionFinalized ||
		sink.resumes != 1 || sink.sawSnapshot || sink.submits != 0 {
		t.Fatalf("validator-finality recovery did not resume the exact no-snapshot BOC: resolution=%+v resumes=%d snapshot=%t submits=%d err=%v",
			resolution, sink.resumes, sink.sawSnapshot, sink.submits, err)
	}
}

func TestTOSCTLRelaySponsorshipRequiresFullNetworkDomainCustodyPreflight(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	pinned := fixture.network
	preflights := 0
	sink := &TOSCTLPaymentSink{ConfigPath: "/private/tosctl.json", NetworkGlobalID: pinned.GlobalID,
		RelayNetworkDomain: &pinned, RelayNetworkPreflight: func(_ context.Context, configPath string,
			expected agentrelay.NetworkDomain) error {
			preflights++
			if configPath != "/private/tosctl.json" || expected != pinned {
				return errors.New("wrong custody authority")
			}
			return nil
		}}
	if err := sink.verifyRelayNetworkDomain(t.Context(), pinned); err != nil || preflights != 1 {
		t.Fatalf("exact relay custody domain did not pass preflight: calls=%d err=%v", preflights, err)
	}
	foreign := pinned
	foreign.ZeroStateFileHash = relayTestDigest("9")
	if err := sink.verifyRelayNetworkDomain(t.Context(), foreign); err == nil || preflights != 1 {
		t.Fatal("same global ID on another zero-state domain reached custody preflight")
	}
	sink.RelayNetworkPreflight = nil
	if err := sink.verifyRelayNetworkDomain(t.Context(), pinned); err == nil {
		t.Fatal("relay sponsorship accepted tosctl without config/RPC network preflight")
	}
}

func relaySponsorshipFixture(t *testing.T, fixture *relayTestFixture) (agentrelay.RelayExecutionRequest,
	commerce.AgentAgreement, commerce.AgreementObligation) {
	t.Helper()
	fixture.enableSponsorship(t, agentrelay.ModeSponsorAndRelay)
	attempt := fixture.attempt(t)
	execution, agreement := attempt.Execution, attempt.Agreement
	var obligation commerce.AgreementObligation
	for _, candidate := range agreement.Body.Obligations {
		if candidate.ObligationID == execution.SponsorshipObligationID {
			obligation = candidate
			break
		}
	}
	if obligation.ObligationID == "" || strings.TrimSpace(execution.QuoteRequest.Body.SourceAccount) == "" {
		t.Fatal("test sponsorship has no source account")
	}
	return execution, agreement, obligation
}

var _ AgreementPaymentSink = (*relaySponsorshipPaymentSink)(nil)
var _ commerce.PaymentEvidenceVerifier = (*relaySponsorshipPaymentSink)(nil)
