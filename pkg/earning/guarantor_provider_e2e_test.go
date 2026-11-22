package earning

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	commerce "github.com/tosnetwork/ai/protocol/pkg/agentcommerce"
	guarantor "github.com/tosnetwork/ai/protocol/pkg/agentguarantor"
	"github.com/tosnetwork/ai/protocol/pkg/codec"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
)

// guarantorPinnedResolver pins each Guarantor authority subject to one
// ML-DSA-44 custody controller, and each Agent's operation key separately.
type guarantorPinnedResolver struct {
	controllers map[string]string
	operations  map[string]ed25519.PublicKey
}

// testGuarantorController names the fake custody controller an Agent with
// this identity key signs Guarantor objects with.
func testGuarantorController(public ed25519.PublicKey) string {
	return "guarantor-" + hex.EncodeToString(public[:8])
}

func newGuarantorPinnedResolver(keys map[string]ed25519.PublicKey) guarantorPinnedResolver {
	resolver := guarantorPinnedResolver{controllers: map[string]string{}, operations: map[string]ed25519.PublicKey{}}
	for subject, key := range keys {
		resolver.controllers[subject] = testGuarantorController(key)
		resolver.operations[subject] = key
	}
	return resolver
}

func (resolver guarantorPinnedResolver) ResolveGuarantorAuthority(
	scope guarantor.AuthorityResolutionScopeV1,
	keyID string,
	_ time.Time,
	proof []byte,
) error {
	controller, found := resolver.controllers[scope.AuthoritySubject]
	if !found || keyID != testAuthorityCustody.KeyID(controller) || len(proof) == 0 ||
		scope.ProfileURI == "" || scope.ProfileVersion == 0 || scope.ProfileDigest == "" ||
		scope.AuthorizedKind == "" || scope.AuthorizedDigest == "" || scope.SignatureDomain == "" {
		return errors.New("Guarantor historical authority is not pinned")
	}
	return nil
}

func (resolver guarantorPinnedResolver) ResolveNativeAgentKey(scope guarantor.AuthorityResolutionScopeV1,
	keyID [mldsa44.KeyIDSize]byte, at time.Time, proof []byte,
) ([]byte, error) {
	controller := resolver.controllers[scope.AuthoritySubject]
	if err := resolver.ResolveGuarantorAuthority(scope, mldsa44.KeyIDText(keyID), at, proof); err != nil {
		return nil, err
	}
	return testAuthorityCustody.PublicKey(controller), nil
}

func (resolver guarantorPinnedResolver) Verify(
	ctx context.Context,
	use mldsa44.Use,
	payload, publicKey, signature []byte,
) error {
	return testAuthorityCustody.Verify(ctx, use, payload, publicKey, signature)
}

func (resolver guarantorPinnedResolver) AuthorizeAgentOperationKey(agentID string, profile commerce.ProfileRefV1,
	key ed25519.PublicKey, _ time.Time, proof []byte) error {
	wanted, found := resolver.operations[agentID]
	if !found || !wanted.Equal(key) || commerce.ValidateProfileRefV1(profile) != nil || len(proof) == 0 {
		return errors.New("Guarantor publication key is not pinned")
	}
	return nil
}

type guarantorAgreementKeyResolver map[string]ed25519.PublicKey

func (resolver guarantorAgreementKeyResolver) AuthorizeIntentKey(agentID string, key ed25519.PublicKey, _ time.Time) error {
	wanted, found := resolver[agentID]
	if !found || !wanted.Equal(key) {
		return errors.New("Agreement key is not pinned")
	}
	return nil
}

type staticUnderlyingAgreementResolver map[string]commerce.AgentAgreement

func (resolver staticUnderlyingAgreementResolver) ResolveUnderlyingAgreement(bodyDigest string) (commerce.AgentAgreement, error) {
	agreement, found := resolver[bodyDigest]
	if !found {
		return commerce.AgentAgreement{}, errors.New("underlying Agreement is not pinned")
	}
	return agreement, nil
}

type staticGuarantorUnderwriter struct{ estimate GuarantorRiskEstimate }

func (value staticGuarantorUnderwriter) EstimateGuarantorRisk(context.Context,
	guarantor.AuthorizedCoverageQuoteRequestV1, guarantor.ServiceProfileV1, commerce.AgentAgreementBody,
	time.Time) (GuarantorRiskEstimate, error) {
	return value.estimate, nil
}

type staticGuarantorEligibility struct{ proof []byte }

func (value staticGuarantorEligibility) FreshEligibilityProofSet(context.Context, string, []string, time.Time) ([]byte, error) {
	return append([]byte(nil), value.proof...), nil
}

type oneShotGuarantorClosureFailure struct {
	target string
	fired  bool
}

func (failure *oneShotGuarantorClosureFailure) GuarantorClosureCheckpoint(stage string) error {
	if failure != nil && !failure.fired && stage == failure.target {
		failure.fired = true
		return errors.New("injected Guarantor closure crash")
	}
	return nil
}

type staticGuarantorBuckets struct{ policy, correlation string }

func (value staticGuarantorBuckets) RiskBucketDigests(context.Context, guarantor.AuthorizedCoverageQuoteRequestV1,
	commerce.AgentAgreementBody) (string, string, error) {
	return value.policy, value.correlation, nil
}

type staticGuarantorEvidenceVerifier struct{}

func (staticGuarantorEvidenceVerifier) VerifyGuarantorEvidence(context.Context, string, string, string, string) error {
	return nil
}

type guarantorTestPaymentSink struct {
	submissions int
	evidence    map[string]commerce.AgreementPaymentEvidence
	// now is the clock the payment resolves on: the test's authority
	// clock, so evidence is never resolved after the verifier's present.
	now func() time.Time
}

type guarantorEventSink struct {
	messages    []OutboundMessage
	resolutions map[string]commerce.ActionResolution
}

func (sink *guarantorEventSink) Submit(_ context.Context, action commerce.AuthorizedAction, _ commerce.WriterFence,
	_ map[string]commerce.SemanticValue, _ []byte, message OutboundMessage) (commerce.ActionResolution, error) {
	if sink.resolutions == nil {
		sink.resolutions = map[string]commerce.ActionResolution{}
	}
	sink.messages = append(sink.messages, message)
	resolution := commerce.ActionResolution{StableActionID: action.StableActionID,
		ExactRequestDigest: action.ExactRequestDigest, State: commerce.ActionTerminal,
		SinkReference: "messenger:event", StateRevision: 1}
	sink.resolutions[action.StableActionID] = resolution
	return resolution, nil
}

func (sink *guarantorEventSink) ResolveAction(_ context.Context, stableActionID,
	exactRequestDigest string) (commerce.ActionResolution, error) {
	resolution, found := sink.resolutions[stableActionID]
	if !found || resolution.ExactRequestDigest != exactRequestDigest {
		return commerce.ActionResolution{StableActionID: stableActionID,
			ExactRequestDigest: exactRequestDigest, State: commerce.ActionUnknown}, nil
	}
	return resolution, nil
}

type guarantorImmutablePublisher struct{}

func (guarantorImmutablePublisher) PublishImmutableCommerceObject(_ context.Context, contentType,
	digest string, canonical []byte) (commerce.CommerceObjectDescriptorV1, error) {
	return commerce.CommerceObjectDescriptorV1{ContentType: contentType, ContentDigest: digest,
		ContentSize: uint64(len(canonical)), RetrievalHints: []string{"https://storage.example/guarantor/immutable"}}, nil
}

type failAfterTerminalEconomicAuthority struct {
	EconomicAuthority
	failOnce bool
}

type failAfterReservationEconomicAuthority struct {
	EconomicAuthority
	failOnce bool
}

// failBeforeTerminalEconomicAuthority fails one terminal transition without
// making it, as a process that stops just before asking the authority does.
type failBeforeTerminalEconomicAuthority struct {
	EconomicAuthority
	failOnce bool
}

func (authority *failBeforeTerminalEconomicAuthority) Transition(
	stableActionID, exactRequestDigest string, state commerce.ActionResolutionState, sinkReference string,
	evidenceRefs []string,
) (commerce.ActionResolution, error) {
	if authority.failOnce && state == commerce.ActionTerminal {
		authority.failOnce = false
		return commerce.ActionResolution{}, errors.New("injected crash before the terminal authority transition")
	}
	return authority.EconomicAuthority.Transition(stableActionID, exactRequestDigest, state, sinkReference,
		evidenceRefs)
}

// requireTestFirmOfferIssuedWithAPreparedPlan requires the journal to hold
// exactly one firm-offer issuance plan whose offer the journal has already
// issued while the authority still holds the plan's action as prepared, and
// returns that offer.
func requireTestFirmOfferIssuedWithAPreparedPlan(t *testing.T, journal *GuarantorJournal,
	authority EconomicAuthority,
) guarantor.AuthorizedFirmCoverageOfferV1 {
	t.Helper()
	journal.mu.Lock()
	identities := make([]string, 0, len(journal.doc.FirmOfferIssuancePlans))
	for identity := range journal.doc.FirmOfferIssuancePlans {
		identities = append(identities, identity)
	}
	journal.mu.Unlock()
	if len(identities) != 1 {
		t.Fatalf("the journal holds %d firm-offer issuance plans, want one", len(identities))
	}
	plan, found, err := journal.FirmOfferIssuancePlan(identities[0])
	if err != nil || !found {
		t.Fatalf("the journal does not return its firm-offer issuance plan: %v", err)
	}
	issued, found, err := journal.FirmOfferByDigest(plan.OfferDigest)
	if err != nil || !found || !sameJSON(issued, plan.Offer) {
		t.Fatalf("the journal has not issued the planned offer: found=%v err=%v", found, err)
	}
	state := authority.Resolve(plan.Action.StableActionID, plan.Action.ExactRequestDigest).State
	if state != commerce.ActionPrepared {
		t.Fatalf("the planned issuance action is %s at the authority, want prepared", state)
	}
	return issued
}

func (authority *failAfterReservationEconomicAuthority) Admit(action commerce.AuthorizedAction,
	fields map[string]commerce.SemanticValue, request []byte, fence commerce.WriterFence,
	reservation *ExposureReservation) (commerce.ActionResolution, error) {
	resolution, err := authority.EconomicAuthority.Admit(action, fields, request, fence, reservation)
	if err == nil && authority.failOnce && reservation != nil {
		authority.failOnce = false
		return resolution, errors.New("injected crash after atomic exposure reservation")
	}
	return resolution, err
}

func (authority *failAfterTerminalEconomicAuthority) Transition(stableActionID, exactRequestDigest string,
	state commerce.ActionResolutionState, sinkReference string, evidenceRefs []string) (commerce.ActionResolution, error) {
	resolution, err := authority.EconomicAuthority.Transition(stableActionID, exactRequestDigest, state, sinkReference, evidenceRefs)
	if err == nil && authority.failOnce && state == commerce.ActionTerminal {
		authority.failOnce = false
		return resolution, errors.New("injected crash after terminal authority commit")
	}
	return resolution, err
}

func (sink *guarantorTestPaymentSink) SubmitPayment(_ context.Context, _ commerce.AuthorizedAction, _ commerce.WriterFence,
	_ map[string]commerce.SemanticValue, _ []byte, request commerce.AgreementPaymentRequest) (commerce.AgreementPaymentEvidence, error) {
	requestDigest, _ := commerce.AgreementPaymentRequestDigest(request)
	evidence := commerce.AgreementPaymentEvidence{PaymentRequestDigest: requestDigest, StableActionID: request.StableActionID,
		ExactTransferReference: "transfer:guarantor-payout", AdapterEvidenceProfile: "tos.test.payment-evidence.v1",
		ResolvedState: "finalized", ResolvedAtUnix: uint64(sink.now().UTC().Unix()), FinalityReference: "finality:test",
		Evidence: []byte("finalized-payment-evidence")}
	if sink.evidence == nil {
		sink.evidence = map[string]commerce.AgreementPaymentEvidence{}
	}
	sink.submissions++
	sink.evidence[request.StableActionID] = evidence
	return evidence, nil
}

func (sink *guarantorTestPaymentSink) ResolvePayment(_ context.Context,
	request commerce.AgreementPaymentRequest) (commerce.AgreementPaymentEvidence, error) {
	evidence, found := sink.evidence[request.StableActionID]
	if !found {
		return commerce.AgreementPaymentEvidence{}, errors.New("not submitted")
	}
	return evidence, nil
}

func testHex(key ed25519.PublicKey) string {
	const alphabet = "0123456789abcdef"
	encoded := make([]byte, len(key)*2)
	for index, value := range key {
		encoded[index*2], encoded[index*2+1] = alphabet[value>>4], alphabet[value&15]
	}
	return "ed25519:" + string(encoded)
}

// guarantorFallbackScenario selects how the provider lifecycle closes its
// claim: through ordinary decisions, or through a deterministic fallback.
type guarantorFallbackScenario int

const (
	guarantorNoFallback guarantorFallbackScenario = iota
	// guarantorInitialFallback lets the review deadline pass.
	guarantorInitialFallback
	// guarantorNonterminalFallback admits a disputed decision and lets its
	// resolution deadline pass with no response.
	guarantorNonterminalFallback
	// guarantorLateRecoveryFallback closes claim filing after the terminal
	// resolution deadline with the claim still undecided and takes the
	// late-recovery path to its end.
	guarantorLateRecoveryFallback
	// guarantorLateFromDisputedFallback admits a disputed decision, then
	// closes claim filing late and takes the late-recovery fallback from that
	// disputed head.
	guarantorLateFromDisputedFallback
	// guarantorLateFromReviewingFallback admits an approved decision, has it
	// challenged on the ordinary path, then closes claim filing late and takes
	// the late-recovery fallback from that reviewing head.
	guarantorLateFromReviewingFallback
	// guarantorLateCandidateTimesOut challenges the late-recovery candidate
	// and lets its successor deadline pass; the terminal fallback at that
	// deadline replaces it.
	guarantorLateCandidateTimesOut
	// guarantorLateBeforeOrdinaryDeadline admits a disputed decision shortly
	// before the terminal resolution deadline, so its resolution window is
	// still open when claim filing closes late; the late-recovery fallback is
	// admitted at the filing close, before that window ends.
	guarantorLateBeforeOrdinaryDeadline
	// guarantorCollateralAttested runs a collateral-attested coverage whose
	// activation carries a signed collateral lock and signed control evidence,
	// cancels it, and closes it through the initial fallback.
	guarantorCollateralAttested
)

// TestGuarantorLateRecoveryIsTriggeredByTheFilingCloseAlone: the late-recovery
// fallback is refused one second before the late filing close and admitted at
// it, although the disputed head's own resolution deadline has not passed;
// the ordinary fallback from the same head is still refused before that
// deadline.
func TestGuarantorLateRecoveryIsTriggeredByTheFilingCloseAlone(t *testing.T) {
	runGuarantorProviderLifecycle(t, guarantorLateBeforeOrdinaryDeadline)
}

// TestGuarantorLateRecoveryFromAReviewingHeadAfterAnOrdinaryChallenge: an
// ordinary challenge reopens revision ingress; a late filing close then
// admits the late-recovery fallback from the reviewing head, which freezes
// the reopened epoch and carries the revised claim's initial admission.
func TestGuarantorLateRecoveryFromAReviewingHeadAfterAnOrdinaryChallenge(t *testing.T) {
	runGuarantorProviderLifecycle(t, guarantorLateFromReviewingFallback)
}

// TestGuarantorTerminalFallbackAtTheSuccessorDeadlineOfAChallengedLateCandidate:
// a challenged late-recovery candidate with no successor by its deadline is
// replaced by the terminal fallback, which reuses the frozen epoch and
// carries the candidate's one-challenge-round marker.
func TestGuarantorTerminalFallbackAtTheSuccessorDeadlineOfAChallengedLateCandidate(t *testing.T) {
	runGuarantorProviderLifecycle(t, guarantorLateCandidateTimesOut)
}

// TestGuarantorLateRecoveryReplacesADisputedHead: the protocol admits a
// late-recovery fallback from a nonterminal head, and the journal replaces
// that head with it.
func TestGuarantorLateRecoveryReplacesADisputedHead(t *testing.T) {
	runGuarantorProviderLifecycle(t, guarantorLateFromDisputedFallback)
}

// TestGuarantorLateRecoveryPathAllowsOneChallengeAndPaysByItsDeadline closes
// claim filing late, with the claim never decided. The late-recovery fallback
// resolves its filing-close receipt from the journal by descriptor, is
// challenged once, and is replaced by an approved successor that carries the
// candidate's marker. That successor cannot be challenged again; it closes
// and is applied with its payout due within the late-recovery deadline, after
// the terminal resolution deadline the ordinary path is held to.
func TestGuarantorLateRecoveryPathAllowsOneChallengeAndPaysByItsDeadline(t *testing.T) {
	runGuarantorProviderLifecycle(t, guarantorLateRecoveryFallback)
}

func TestGuarantorProviderIssuesReservedOfferAndLinearizesAcceptance(t *testing.T) {
	runGuarantorProviderLifecycle(t, guarantorNoFallback)
}

// TestGuarantorDisputedFallbackReusesTheFrozenEpochAndCloses admits a
// disputed decision, which freezes the claim's revision epoch, and lets its
// resolution deadline pass with no response. The fallback must reuse that
// frozen epoch and cut, consume the nonterminal round, verify as a portable
// receipt, and be closed, applied and settled into the terminal claim set.
func TestGuarantorDisputedFallbackReusesTheFrozenEpochAndCloses(t *testing.T) {
	runGuarantorProviderLifecycle(t, guarantorNonterminalFallback)
}

// TestGuarantorInitialFallbackIsPortableChallengeableAndApplied lets the
// review deadline pass with no Decision Authority action. The
// Agreement-granted fallback must then be admitted, verify as a portable
// receipt within every size bound, and be closed and applied through its
// compact proof. The fallback authority set differs from the Decision
// Authority set, so a proof verified against the wrong set is refused.
func TestGuarantorInitialFallbackIsPortableChallengeableAndApplied(t *testing.T) {
	runGuarantorProviderLifecycle(t, guarantorInitialFallback)
}

func runGuarantorProviderLifecycle(t *testing.T, scenario guarantorFallbackScenario) {
	runGuarantorProviderLifecycleIn(t, scenario, nil)
}

// runGuarantorProviderLifecycleIn runs the lifecycle. Given a process of the
// kill test it instead builds the lifecycle's fixture in that process's
// directory, at that process's fixed time, and hands it to the process's
// driver in place of the lifecycle.
func runGuarantorProviderLifecycleIn(t *testing.T, scenario guarantorFallbackScenario, process *guarantorKillProcess) {
	now := time.Now().UTC().Truncate(time.Second)
	if process != nil {
		now = process.now
	}
	guarantorPublic, guarantorKey, _ := ed25519.GenerateKey(rand.Reader)
	coveredPublic, coveredKey, _ := ed25519.GenerateKey(rand.Reader)
	if process != nil {
		// A process of the kill test draws the two keys above from the entropy
		// every such process shares, and everything after them from its own.
		process.keysGenerated()
	}
	digest := func(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }
	ref := func(ch, name string) commerce.ProfileRefV1 {
		return commerce.ProfileRefV1{ProfileURI: "tos.test." + name + ".v1", ProfileVersion: 1, ProfileDigest: digest(ch)}
	}
	asset := commerce.AssetIdentityV1{AssetNamespace: "tos.asset", AssetIdentifier: "native", Unit: "nano"}
	fallbackSubject := "agent:guarantor"
	if scenario != guarantorNoFallback {
		fallbackSubject = "agent:fallback-authority"
	}
	fallback, err := guarantor.NewDenyZeroTerminalFallbackV1(ref("e", "fallback"), []string{fallbackSubject}, "all",
		map[string]string{"deny_zero": "fallback-deny", "no_eligible_benefit": "fallback-no-benefit",
			"aggregate_exhausted": "fallback-cap-exhausted", "aggregate_limited": "fallback-cap-limited", "full_benefit": "fallback-full"})
	if err != nil {
		t.Fatal(err)
	}
	continuationEntries, err := guarantor.BuildClaimContinuationBudgetEntriesV1(1, 1, 60, 60, 60, 60, 60, 60)
	if err != nil {
		t.Fatal(err)
	}
	// The closure objects carry the claims' authorized decision receipts,
	// about 1.07 MB each under ML-DSA-44, so their negotiated ceilings take
	// the Guarantor object limit rather than 1 MiB.
	closureCeiling := uint64(guarantor.MaxCanonicalObjectBytes)
	capacity := guarantor.ClaimClosureCapacityV1{MaximumClaims: 2, MaximumClaimIngressActions: 4,
		MaximumClaimRevisionsPerClaim: 2, MaximumDecisionAdmissionsPerClaim: 4, MaximumClaimStateTransitionsPerClaim: 8,
		MaximumChallengeRoundsPerClaim: 1, MaximumNonterminalRoundsPerClaim: 1, MaximumPayoutLinesPerClaim: 2,
		MaximumAdmittedClaimEnvelopeBytes: 64 << 10, MaximumClaimIngressReceiptEnvelopeBytes: 128 << 10,
		MaximumClaimIngressCutProofBytes: 1 << 20, MaximumAcceptanceRequestEnvelopeBytes: 1 << 20,
		MaximumAcceptanceReceiptEnvelopeBytes: 1 << 20, MaximumActivationEvidenceEnvelopeBytes: 1 << 20,
		MaximumNonActivationEvidenceEnvelopeBytes: 1 << 20, MaximumCancellationReceiptEnvelopeBytes: 1 << 20,
		MaximumClaimFilingCloseReceiptEnvelopeBytes: 1 << 20, MaximumTerminalClaimSetEnvelopeBytes: closureCeiling,
		MaximumExposureReleaseRequestBytes: closureCeiling, MaximumExposureReleaseReceiptBytes: closureCeiling,
		MaximumCoverageResolutionRequestBytes: closureCeiling, MaximumCoverageResolutionEnvelopeBytes: closureCeiling,
		ComputedWorstCaseAcceptanceRequestEnvelopeBytes: 1 << 20, ComputedWorstCaseAcceptanceReceiptEnvelopeBytes: 1 << 20,
		ComputedWorstCaseActivationEvidenceEnvelopeBytes: 1 << 20, ComputedWorstCaseNonActivationEvidenceEnvelopeBytes: 1 << 20,
		ComputedWorstCaseCancellationReceiptEnvelopeBytes: 1 << 20, ComputedWorstCaseClaimFilingCloseReceiptEnvelopeBytes: 1 << 20,
		ComputedWorstCaseTerminalClaimSetBytes: closureCeiling, ComputedWorstCaseExposureReleaseRequestBytes: closureCeiling,
		ComputedWorstCaseExposureReleaseReceiptBytes: closureCeiling, ComputedWorstCaseCoverageResolutionRequestBytes: closureCeiling,
		ComputedWorstCaseCoverageResolutionEnvelopeBytes: closureCeiling,
		ContinuationBudgetProfile:                        ref("f", "continuation-budget"), ContinuationBudgetEntries: continuationEntries,
		TerminalFallback: fallback}
	trigger, evidence, decisionProfile := ref("1", "trigger"), ref("2", "evidence"), ref("3", "decision")
	claimProfile := guarantor.ClaimProfileV1{ProfileID: "claim:fixed", ProfileVersion: 1, TriggerProfile: trigger,
		EvidenceProfile: evidence, ClaimantAuthorizationProfiles: []commerce.ProfileRefV1{ref("4", "claimant")},
		IngressProfile: ref("5", "claim-ingress"), IngressAuthoritySubjects: []string{"agent:guarantor"},
		IngressAuthorityQuorumRule: "all", AdmissionProfile: ref("6", "claim-admission"),
		AdmissionAuthoritySubjects: []string{"agent:guarantor"}, AdmissionQuorumRule: "all",
		DecisionAdmissionProfile: ref("c", "authority"), DecisionAdmissionAuthoritySubjects: []string{"agent:guarantor"},
		DecisionAdmissionQuorumRule: "all", DecisionProfile: decisionProfile,
		MaximumClaims: 2, MaximumClaimIngressActions: 4, MaximumClaimRevisionsPerClaim: 2,
		MaximumDecisionAdmissionsPerClaim: 4, MaximumClaimStateTransitionsPerClaim: 8, MaximumChallengeRoundsPerClaim: 1,
		MaximumNonterminalRoundsPerClaim: 1, MaximumPayoutLinesPerClaim: 2, MaximumEvidenceItems: 4,
		MaximumEvidenceBytes: 64 << 10, ReviewDeadlineSeconds: 60, MaximumNonterminalResolutionWindowSeconds: 60,
		MaximumSuccessorDecisionWindowSeconds: 60, MaximumClaimIngressResolutionGraceSeconds: 60,
		MaximumLateIngressRecoveryWindowSeconds: 60, PayoutDeadlineSeconds: 60,
		MaximumAdmittedClaimEnvelopeBytes:           capacity.MaximumAdmittedClaimEnvelopeBytes,
		MaximumClaimIngressReceiptEnvelopeBytes:     capacity.MaximumClaimIngressReceiptEnvelopeBytes,
		MaximumClaimIngressCutProofBytes:            capacity.MaximumClaimIngressCutProofBytes,
		MaximumAcceptanceRequestEnvelopeBytes:       capacity.MaximumAcceptanceRequestEnvelopeBytes,
		MaximumAcceptanceReceiptEnvelopeBytes:       capacity.MaximumAcceptanceReceiptEnvelopeBytes,
		MaximumActivationEvidenceEnvelopeBytes:      capacity.MaximumActivationEvidenceEnvelopeBytes,
		MaximumNonActivationEvidenceEnvelopeBytes:   capacity.MaximumNonActivationEvidenceEnvelopeBytes,
		MaximumCancellationReceiptEnvelopeBytes:     capacity.MaximumCancellationReceiptEnvelopeBytes,
		MaximumClaimFilingCloseReceiptEnvelopeBytes: capacity.MaximumClaimFilingCloseReceiptEnvelopeBytes,
		MaximumTerminalClaimSetEnvelopeBytes:        capacity.MaximumTerminalClaimSetEnvelopeBytes,
		MaximumExposureReleaseRequestBytes:          capacity.MaximumExposureReleaseRequestBytes,
		MaximumExposureReleaseReceiptBytes:          capacity.MaximumExposureReleaseReceiptBytes,
		MaximumCoverageResolutionRequestBytes:       capacity.MaximumCoverageResolutionRequestBytes,
		MaximumCoverageResolutionEnvelopeBytes:      capacity.MaximumCoverageResolutionEnvelopeBytes,
		ContinuationBudgetProfile:                   capacity.ContinuationBudgetProfile,
		PermittedTerminalFallbacks:                  []guarantor.DeterministicClaimTerminalFallbackV1{fallback}}
	claimProfileDigest, _ := codec.Digest("tos.service.agent-guarantor-claim-profile.v1", claimProfile)
	// A collateralized scenario selects the collateral-attested profile; every
	// other scenario is unsecured.
	collateralized := scenario == guarantorCollateralAttested
	assurance, collateralProfileDigest := guarantor.AssuranceUnsecuredSigned, ""
	var collateral guarantorCollateralFixture
	if collateralized {
		collateral = newGuarantorCollateralFixture(t, asset, claimProfileDigest, ref)
		assurance, collateralProfileDigest = guarantor.AssuranceCollateralAttested, collateral.profileDigest
	}
	payoutAdapter := ref("8", "payment")
	profile := guarantor.ServiceProfileV1{SchemaVersion: 1, ProfileID: "profile:guarantor", Revision: 1,
		ProviderAgentID: "agent:guarantor", AuthorityDomainDigest: digest("9"),
		CoverageCapabilities: []guarantor.CoverageCapabilityV1{{Category: "service-default",
			BenefitKinds: []guarantor.BenefitKind{guarantor.BenefitFixed}, SupportedUnderlyingProfiles: []commerce.ProfileRefV1{ref("a", "underlying")},
			SupportedClaimProfiles: []commerce.ProfileRefV1{evidence}, SupportedAssets: []commerce.AssetIdentityV1{asset},
			CoverageRanges: []commerce.AtomicAmountRangeV1{{Minimum: commerce.AtomicAmountV1{Asset: asset, AmountAtomic: "1"},
				Maximum: commerce.AtomicAmountV1{Asset: asset, AmountAtomic: "10000"}}},
			FeeRanges: []commerce.AtomicAmountRangeV1{{Minimum: commerce.AtomicAmountV1{Asset: asset, AmountAtomic: "1"},
				Maximum: commerce.AtomicAmountV1{Asset: asset, AmountAtomic: "1000"}}}, MaximumCoverageSeconds: 3600,
			MaximumClaimWindowSeconds: 7200, JurisdictionPolicy: commerce.PolicyRefV1{ContentType: "text/plain",
				ContentDigest: digest("b"), ContentSize: 10}}}, ClaimProfiles: []guarantor.ClaimProfileV1{claimProfile},
		PayoutAdapterProfiles: []commerce.ProfileRefV1{payoutAdapter}, AdmissionLimits: guarantor.AdmissionLimitsV1{
			MaximumQuoteReservations: 10, MaximumActiveCoverages: 10, MaximumActiveClaims: 20,
			MaximumActivePerCoveredParty: 5, MaximumActivationAttemptsPerCoverage: 4, MaximumQuoteRequestsPerWindow: 20,
			QuoteRequestWindowSeconds: 60, MaximumAcceptanceProcessingGraceSeconds: 60},
		Endpoints: guarantor.ServiceEndpointsV1{QuoteRoute: "https://guarantor.example/quote",
			AcceptanceRoute: "https://guarantor.example/accept", ClaimRoute: "https://guarantor.example/claim",
			ResolveRoute: "https://guarantor.example/resolve", EvidenceRoute: "https://guarantor.example/evidence"},
		ExposureAuthorityID: "authority:owner", ExposureAuthorizationProfile: ref("c", "authority"),
		LifecycleAuthorityID: "authority:owner", LifecycleAuthorizationProfile: ref("c", "authority"), PolicyRevision: 1,
		CreatedAtUnix: uint64(now.Add(-time.Minute).Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}
	if collateralized {
		profile.CollateralProfiles = []guarantor.CollateralProfileV1{collateral.profile}
	}
	profileDigest, err := guarantor.ServiceProfileDigest(profile)
	if err != nil {
		t.Fatal(err)
	}
	profileBytes, err := codec.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	profileContentHash := sha256.Sum256(profileBytes)
	intentPayload := commerce.AgentIntentPayload{DiscoveryCard: commerce.DiscoveryCard{Summary: "Bounded guarantor service",
		IntentModes: []commerce.IntentMode{commerce.IntentOffer}, SubjectClasses: []commerce.SubjectClass{commerce.SubjectService},
		TaxonomyPaths: []string{"tos.taxonomy.v1/service/guarantor"}, Keywords: []commerce.IntentKeyword{{Text: "guarantor", Language: "en"}},
		ValueState: commerce.ValueNegotiable, Schedule: commerce.IntentSchedule{Flexibility: "ongoing"}},
		DetailDescriptor: commerce.ContentDescriptor{ContentType: guarantor.ServiceProfileContentType,
			ContentDigest: "sha256:" + hex.EncodeToString(profileContentHash[:]), ContentSize: uint64(len(profileBytes)), InlineContent: profileBytes},
		ReplyRoutes: []commerce.ReplyRoute{{ProfileURI: "tos.messenger.direct.v1", AgentID: profile.ProviderAgentID}}}
	payloadBytes, err := codec.Marshal(intentPayload)
	if err != nil {
		t.Fatal(err)
	}
	payloadProfile := ref("d", "intent-payload")
	payloadProfile.ProfileURI = guarantor.ServiceIntentPayloadProfileURI
	payloadDigest, err := commerce.AgentOperationPayloadDigest(payloadProfile, payloadBytes)
	if err != nil {
		t.Fatal(err)
	}
	operation, err := commerce.SignAgentOperationV1(commerce.AgentOperationBodyV1{SchemaVersion: 1, NetworkID: "tos:test",
		OpcodeNamespace: guarantor.ServiceIntentOpcodeNamespace, OpcodeName: guarantor.ServiceIntentOpcodeName, OpcodeVersion: 1,
		OperationID: "operation:guarantor-profile:1", ActorAgentID: profile.ProviderAgentID, AuthorizationRef: ref("e", "publication-authority"),
		AudienceDescriptor: "public:indexable", ObjectID: profile.ProfileID, OrderingDomain: "publication:" + profile.ProfileID,
		Sequence: profile.Revision, CreatedAtUnix: profile.CreatedAtUnix, NotBeforeUnix: profile.CreatedAtUnix,
		ExpiresAtUnix: profile.ExpiresAtUnix, PayloadProfile: payloadProfile, PayloadDigest: payloadDigest,
		PayloadSize: uint64(len(payloadBytes))}, profile.ProviderAgentID, guarantorKey, []byte("publication-history"))
	if err != nil {
		t.Fatal(err)
	}
	operationDigest, _ := commerce.AgentOperationEnvelopeDigestV1(operation)
	profileArtifact := guarantor.GuarantorServiceProfileArtifactV1{SchemaVersion: 1,
		SelectedServiceIntentOperationDigest: operationDigest, SelectedServiceProfileDigest: profileDigest,
		Revisions: []guarantor.GuarantorServiceProfileRevisionArtifactV1{{SchemaVersion: 1,
			ServiceIntentOperationDigest: operationDigest, ServiceIntentOperation: operation,
			IntentPayload: intentPayload, ServiceProfile: profile}}}
	underlying := commerce.AgentAgreementBody{SchemaVersion: 1, AgreementID: "agreement:underlying", Version: 1,
		NetworkContext: "tos:test", Participants: []commerce.AgreementParticipant{{AgentID: "agent:covered", Roles: []string{"provider"}},
			{AgentID: "agent:guarantor", Roles: []string{"customer"}}},
		TermsContentType: "text/plain", Terms: []byte("covered software work"),
		Obligations: []commerce.AgreementObligation{{ObligationID: "obligation:work", Kind: "service",
			ObligorAgentID: "agent:covered", BeneficiaryAgentID: "agent:guarantor", SubjectContentType: "text/plain",
			Subject: []byte("deliver software"), ConfidentialityPolicy: "participants", CancellationPolicy: "mutual",
			DisputePolicy: "evidence", AuthorizationPredicateIDs: []string{"predicate:underlying-covered"}}},
		AuthorizationPredicates: []commerce.AgreementAuthorizationPredicate{{PredicateID: "predicate:underlying-covered",
			AuthoritySubject: commerce.AgreementAuthoritySubject{SubjectKind: "agent", SubjectNamespace: "tos.agent", SubjectIdentifier: "agent:covered"},
			ObligationIDs:    []string{"obligation:work"}, EvidenceProfileURI: commerce.EvidenceProfileAgentSignature,
			EvidenceProfileVersion: 1, EvidenceProfileDigest: commerce.AgentSignatureProfileDigest(),
			ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}}, ValidFromUnix: uint64(now.Add(-time.Minute).Unix()),
		ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}
	underlying, err = commerce.PrepareAgreementTargets(underlying)
	if err != nil {
		t.Fatal(err)
	}
	underlyingDigest, _ := commerce.AgreementBodyDigest(underlying)
	agreementKeys := guarantorAgreementKeyResolver{"agent:guarantor": guarantorPublic, "agent:covered": coveredPublic}
	baseAgreementVerifier := AgreementEvidenceRouter{AgentAuthority: agreementKeys}
	resolvedUnderlyingAcceptance, err := commerce.SignAgreementAcceptance(commerce.AgreementAcceptanceBody{
		AgreementID: underlying.AgreementID, AgreementVersion: underlying.Version,
		AgreementBodyDigest:             underlyingDigest,
		AcceptingSubject:                underlying.AuthorizationPredicates[0].AuthoritySubject,
		PredicateIDs:                    []string{underlying.AuthorizationPredicates[0].PredicateID},
		EvidenceTargetProjectionDigests: []string{underlying.AuthorizationPredicates[0].EvidenceTargetProjectionDigest},
		ExpiresAtUnix:                   underlying.ExpiresAtUnix}, coveredKey)
	if err != nil {
		t.Fatal(err)
	}
	resolvedUnderlyingEvidence, err := commerce.AgentSignatureEvidence(underlying, resolvedUnderlyingAcceptance)
	if err != nil {
		t.Fatal(err)
	}
	underlyingResolver := staticUnderlyingAgreementResolver{underlyingDigest: {
		Body: underlying, AuthorizationEvidence: []commerce.AgreementAuthorizationEvidence{resolvedUnderlyingEvidence}}}
	// Every deadline follows from one anchor, the coverage Agreement's expiry.
	// Without a late-recovery contingency the terminal resolution deadline is
	// that expiry. With one, the late-recovery terminal deadline is the expiry,
	// late ingress ends one late-candidate closure before it, and the terminal
	// resolution deadline one late-ingress window before that.
	agreementExpiresAt := uint64(now.Add(time.Hour).Unix())
	lateScenario := scenario == guarantorLateRecoveryFallback || scenario == guarantorLateFromDisputedFallback ||
		scenario == guarantorLateFromReviewingFallback || scenario == guarantorLateCandidateTimesOut ||
		scenario == guarantorLateBeforeOrdinaryDeadline
	// Collateral is locked until the Agreement expires, so the hard-effect
	// deadline of a collateralized coverage is one reorg window before that.
	hardEffectDeadline := agreementExpiresAt
	if collateralized {
		hardEffectDeadline = agreementExpiresAt - testCollateralReorgSeconds
	}
	deadlines := deriveGuarantorTestDeadlines(t, capacity, hardEffectDeadline, lateScenario,
		claimProfile.MaximumLateIngressRecoveryWindowSeconds)
	requested := guarantor.RequestedCoverageTermsV1{SchemaVersion: 1, CoverageCategory: "service-default",
		MaximumLateIngressRecoveryWindowSeconds: deadlines.lateIngressWindowSeconds,
		MaximumTerminalResolutionDeadlineUnix:   deadlines.terminalResolution,
		MaximumLateRecoveryTerminalDeadlineUnix: deadlines.lateRecoveryTerminal,
		BenefitKind:                             guarantor.BenefitFixed, CoverageAsset: asset,
		RequestedAggregatePayout: commerce.AtomicAmountV1{Asset: asset, AmountAtomic: "1000"},
		RequestedPerClaim:        commerce.AtomicAmountV1{Asset: asset, AmountAtomic: "500"}, MaximumClaims: 2,
		RequestedClosureCapacity: capacity, RequestedCoverageStartsAtUnix: uint64(now.Add(2 * time.Minute).Unix()),
		RequestedCoverageEndsAtUnix:    uint64(now.Add(30 * time.Minute).Unix()),
		RequestedClaimFilingEndsAtUnix: uint64(now.Add(40 * time.Minute).Unix()), MaximumReviewDeadlineSeconds: 60,
		MaximumChallengeWindowSeconds: 60, MaximumNonterminalResolutionWindowSeconds: 60,
		MaximumSuccessorDecisionWindowSeconds: 60, MaximumPayoutDeadlineSeconds: 60, MaximumAdapterRecoveryWindowSeconds: 60,
		ClaimTriggerProfile: trigger, ClaimEvidenceProfile: evidence, SelectedAssuranceLevel: assurance,
		SelectedCollateralProfileDigest: collateralProfileDigest,
		SelectedClaimProfileDigest:      claimProfileDigest, SelectedPayoutAdapterProfile: payoutAdapter}
	requestedDigest, err := guarantor.RequestedCoverageTermsDigest(requested)
	if err != nil {
		t.Fatal(err)
	}
	requestBody := guarantor.CoverageQuoteRequestBodyV1{SchemaVersion: 1, RequestID: "request:coverage",
		ServiceIntentDigest: digest("d"), ServiceProfileDigest: profileDigest, RequesterAgentID: "agent:covered",
		GuarantorAgentID: "agent:guarantor", CoveredPartyAgentID: "agent:covered", BeneficiaryAgentID: "agent:covered",
		ClaimantSubjects: []string{"agent:covered"}, UnderlyingAgreementBodyDigest: underlyingDigest,
		CoveredObligationIDs: []string{"obligation:work"}, RequestedTermsDigest: requestedDigest,
		MaximumFee:             commerce.AtomicAmountV1{Asset: asset, AmountAtomic: "100"},
		SelectedAssuranceLevel: assurance, SelectedClaimProfileDigest: claimProfileDigest,
		SelectedCollateralProfileDigest: collateralProfileDigest,
		SelectedDecisionProfile:         decisionProfile, SelectedPayoutAdapterProfile: payoutAdapter,
		CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(10 * time.Minute).Unix())}
	requestBodyDigest, _ := codec.Digest("tos.service.agent-guarantor-quote-request-body.v1", requestBody)
	coveredAuthorization, err := guarantor.SignObjectAuthorization(
		context.Background(),
		guarantor.AuthorizationStatementV1{
			SchemaVersion:    1,
			AuthoritySubject: "agent:covered", ProfileURI: ref("d", "request-authority").ProfileURI, ProfileVersion: 1,
			ProfileDigest: ref("d", "request-authority").ProfileDigest, AuthorizedObjectKind: "coverage-quote-request",
			AuthorizedBodyDigest: requestBodyDigest, ValidationTimeUnix: uint64(now.Unix()),
		},
		"tos.service.agent-guarantor-quote-request-signature.v1",
		testAuthorityCustody,
		testGuarantorController(coveredKey.Public().(ed25519.PublicKey)),
		[]byte("covered-history"),
	)
	if err != nil {
		t.Fatal(err)
	}
	quote := guarantor.AuthorizedCoverageQuoteRequestV1{
		Body: requestBody, RequestedTerms: requested,
		Authorizations: []guarantor.ProfileQualifiedObjectAuthorizationV1{coveredAuthorization},
	}
	agreementProfile := commerce.AgentSignatureProfileDigest()
	firmOfferEvidenceProfile := guarantor.FirmOfferAgreementEvidenceProfileV1()
	agreement := commerce.AgentAgreementBody{SchemaVersion: 1, AgreementID: "agreement:coverage", Version: 1,
		NetworkContext: "tos:test", Participants: []commerce.AgreementParticipant{{AgentID: "agent:covered", Roles: []string{"covered"}},
			{AgentID: "agent:guarantor", Roles: []string{"guarantor"}}}, TermsContentType: "text/plain", Terms: []byte("fixed benefit coverage"),
		Obligations: []commerce.AgreementObligation{{ObligationID: "obligation:coverage", Kind: "coverage",
			ObligorAgentID: "agent:guarantor", BeneficiaryAgentID: "agent:covered", SubjectContentType: "text/plain",
			Subject: []byte("guarantee covered work"), ConfidentialityPolicy: "participants", CancellationPolicy: "mutual",
			DisputePolicy: "evidence", AuthorizationPredicateIDs: []string{"predicate:guarantor"}},
			{ObligationID: "obligation:payout", Kind: "guarantor.payout.template", ObligorAgentID: "agent:guarantor",
				BeneficiaryAgentID: "agent:covered", SubjectContentType: "text/plain", Subject: []byte("conditional coverage payout"),
				Amount: &commerce.AgreementAmount{AssetNamespace: asset.AssetNamespace, AssetIdentifier: asset.AssetIdentifier,
					AmountAtomic: "1000", Unit: asset.Unit}, ConfidentialityPolicy: "participants",
				CancellationPolicy: "coverage-terms", DisputePolicy: "evidence", SettlementAdapterURI: payoutAdapter.ProfileURI,
				SettlementParameters: []byte("covered-wallet"), AuthorizationPredicateIDs: []string{"predicate:guarantor"}},
			{ObligationID: "obligation:premium", Kind: "payment", ObligorAgentID: "agent:covered", BeneficiaryAgentID: "agent:guarantor",
				SubjectContentType: "text/plain", Subject: []byte("coverage premium"), Amount: &commerce.AgreementAmount{
					AssetNamespace: asset.AssetNamespace, AssetIdentifier: asset.AssetIdentifier, AmountAtomic: "100", Unit: asset.Unit},
				ConfidentialityPolicy: "participants", CancellationPolicy: "before-activation", DisputePolicy: "evidence",
				SettlementAdapterURI: payoutAdapter.ProfileURI, SettlementParameters: []byte("premium-destination"),
				AuthorizationPredicateIDs: []string{"predicate:covered"}}},
		AuthorizationPredicates: []commerce.AgreementAuthorizationPredicate{{PredicateID: "predicate:covered",
			AuthoritySubject: commerce.AgreementAuthoritySubject{SubjectKind: "agent", SubjectNamespace: "tos.agent", SubjectIdentifier: "agent:covered"},
			ObligationIDs:    []string{"obligation:premium"}, EvidenceProfileURI: commerce.EvidenceProfileAgentSignature,
			EvidenceProfileVersion: 1, EvidenceProfileDigest: agreementProfile, ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())},
			{PredicateID: "predicate:guarantor", AuthoritySubject: commerce.AgreementAuthoritySubject{SubjectKind: "agent",
				SubjectNamespace: "tos.agent", SubjectIdentifier: "agent:guarantor"}, ObligationIDs: []string{"obligation:coverage", "obligation:payout"},
				EvidenceProfileURI: firmOfferEvidenceProfile.ProfileURI, EvidenceProfileVersion: uint32(firmOfferEvidenceProfile.ProfileVersion),
				EvidenceProfileDigest: firmOfferEvidenceProfile.ProfileDigest, ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}},
		ValidFromUnix: uint64(now.Add(-time.Minute).Unix()), ExpiresAtUnix: agreementExpiresAt}
	if collateralized {
		// The collateral obligation is the Guarantor's, under its predicate.
		agreement.Obligations = append([]commerce.AgreementObligation{{ObligationID: testCollateralObligationID,
			Kind: "collateral", ObligorAgentID: "agent:guarantor", BeneficiaryAgentID: "agent:covered",
			SubjectContentType: "text/plain", Subject: []byte("lock coverage collateral"),
			ConfidentialityPolicy: "participants", CancellationPolicy: "coverage-terms", DisputePolicy: "evidence",
			AuthorizationPredicateIDs: []string{"predicate:guarantor"}}}, agreement.Obligations...)
		agreement.AuthorizationPredicates[1].ObligationIDs = []string{testCollateralObligationID,
			"obligation:coverage", "obligation:payout"}
	}
	agreement, err = commerce.PrepareAgreementTargets(agreement)
	if err != nil {
		t.Fatal(err)
	}
	agreementDigest, _ := commerce.AgreementBodyDigest(agreement)
	destination := commerce.PayoutDestinationV1{SchemaVersion: 1, SettlementAdapterProfile: payoutAdapter,
		BeneficiarySubject: "agent:covered", Asset: asset, NetworkOrSystemDigest: digest("f"), DestinationEncoding: "bytes",
		DestinationBytes: []byte("covered-wallet")}
	destinationDigest, _ := commerce.PayoutDestinationDigestV1(destination)
	parameters := commerce.ProfileQualifiedSettlementParametersV1{SchemaVersion: 1, SettlementAdapterProfile: payoutAdapter,
		PayoutDestinationDigest: destinationDigest, AdapterParameters: []byte{0xa0}}
	parameterDigest, _ := commerce.SettlementParametersDigestV1(parameters)
	template := commerce.ConditionalSettlementTemplateV1{TemplateID: "template:payout", AgreementObligationID: "obligation:payout",
		ConditionProfile: ref("1", "trigger"), AuthorizedDecisionProfile: decisionProfile, PayerAgentID: "agent:guarantor",
		PayeeAgentID: "agent:covered", Asset: asset, MaximumPerInstance: commerce.AtomicAmountV1{Asset: asset, AmountAtomic: "500"},
		MaximumAggregateAmount: commerce.AtomicAmountV1{Asset: asset, AmountAtomic: "1000"}, MaximumInstances: 2, FirstSequence: 1,
		SettlementAdapterProfile: payoutAdapter, SettlementParameters: parameters, SettlementParametersDigest: parameterDigest,
		PayoutDestinationBinding: commerce.PayoutDestinationBindingV1{Mode: "agreement_fixed",
			DestinationAuthorizationPredicateID: "predicate:covered", PayoutDestination: destination},
		MaterializationDomain: "tos.test.materialize.v1", CancellationPolicyDigest: digest("1"), DisputePolicyDigest: digest("2")}
	cancellationPolicy := guarantor.CoverageCancellationPolicyV1{SchemaVersion: 1, PolicyID: "policy:covered-party-cancellation",
		Branches: []guarantor.CoverageCancellationPolicyBranchV1{{CancellationBranch: "covered-party-request",
			PermittedRequesterSubjects: []string{"agent:covered"}, RequestAuthorizationProfile: commerce.ProfileRefV1{
				ProfileURI: commerce.EvidenceProfileAgentSignature, ProfileVersion: 1, ProfileDigest: agreementProfile},
			RequestAuthorizationQuorumRule: "all", MaximumAdmissionDelaySeconds: 60}}}
	stageEntries := make([]guarantor.GuarantorStageActionAuthorityV1, 0, len(guarantor.ReleasedGuarantorStagesV1()))
	claimIngressStateDomain, err := guarantor.ClaimIngressStateDomainDigestV1(agreementDigest, "obligation:coverage")
	if err != nil {
		t.Fatal(err)
	}
	for index, stageName := range guarantor.ReleasedGuarantorStagesV1() {
		actionKind, purpose := "", ""
		if stageName == "payout_execution" {
			actionKind, purpose = "payment.domain-bound", "guarantor-payout"
		}
		operation, buildErr := guarantor.NewStageOperationBindingV1(stageName, actionKind, purpose, 1<<20)
		if buildErr != nil {
			t.Fatal(buildErr)
		}
		operationDigest, buildErr := guarantor.StageOperationBindingDigestV1(operation)
		if buildErr != nil {
			t.Fatal(buildErr)
		}
		stateDomain := digest("4")
		if operation.CASDomainSource != "coverage_state_domain" {
			stateDomain = digest(string("56789abc"[index%8]))
		}
		if stageName == "claim_submission_ingress" {
			stateDomain = claimIngressStateDomain
		}
		stageEntries = append(stageEntries, guarantor.GuarantorStageActionAuthorityV1{Stage: stageName,
			OperationActionKind: operation.ActionKind, OperationPurpose: operation.OperationPurpose,
			MaximumRequestBytes: operation.MaximumRequestBytes, OperationBindingDigest: operationDigest, ActionOwnerID: "owner:guarantor",
			ActionAgentID: "agent:guarantor", ActionAuthorityID: "authority:owner", WriterFenceDomainID: "owner:guarantor",
			WriterFenceAuthorityID: "authority:owner", WriterGenerationHighWaterProfile: ref("a", "writer-high-water"),
			ActionResolutionProfile: ref("b", "action-resolution"), AdmissionStateDomainDigest: stateDomain})
	}
	stageBinding := guarantor.GuarantorStageActionAuthorityBindingV1{SchemaVersion: 1,
		AuthorityDomainDigest: digest("f"), Stages: stageEntries}
	terms := guarantor.CoverageTermsV1{SchemaVersion: 1, CoverageID: digest("3"), CoverageVersion: 1,
		ServiceProfileDigest: profileDigest, QuoteRequestDigest: mustGuarantorQuoteDigest(t, quote), GuarantorAgentID: "agent:guarantor",
		CoveredPartyAgentID: "agent:covered", BeneficiaryAgentID: "agent:covered", PermittedClaimantSubjects: []string{"agent:covered"},
		UnderlyingAgreementBodyDigest: requestBody.UnderlyingAgreementBodyDigest, CoveredObligationIDs: requestBody.CoveredObligationIDs,
		CoverageCategory: requested.CoverageCategory, BenefitKind: requested.BenefitKind, SelectedAssuranceLevel: requested.SelectedAssuranceLevel,
		CoverageAsset: asset, MaximumAggregatePayout: requested.RequestedAggregatePayout, MaximumPerClaim: requested.RequestedPerClaim,
		BenefitCalculationProfile: ref("d", "benefit-calculation"),
		MaximumClaims:             2, ClaimClosureCapacity: capacity, CoverageStartsAtUnix: requested.RequestedCoverageStartsAtUnix,
		CoverageEndsAtUnix: requested.RequestedCoverageEndsAtUnix, ClaimFilingEndsAtUnix: requested.RequestedClaimFilingEndsAtUnix,
		ReviewDeadlineSeconds: 60, ChallengeWindowSeconds: 60, NonterminalResolutionWindowSeconds: 60,
		SuccessorDecisionWindowSeconds: 60, PayoutDeadlineSeconds: 60, AdapterRecoveryWindowSeconds: 60,
		NonActivationReasonRules: []guarantor.CoverageNonActivationReasonRuleV1{
			{Reason: "activation_window_expired", EvidenceMode: "deadline_only"},
			{Reason: "mutually_cancelled", EvidenceMode: "agreement_predicates", CancellationAuthorizationPredicateIDs: []string{"predicate:covered", "predicate:guarantor"}},
			{Reason: "prerequisite_failed", EvidenceMode: "terminal_prerequisite_failure", PrerequisiteFailureRules: []guarantor.ActivationPrerequisiteFailureRuleV1{{
				PrerequisiteID: "prerequisite:underlying", TerminalFailureEvidenceProfile: evidence,
				TerminalFailureAuthoritySubjects: []string{"agent:guarantor"}, TerminalFailureQuorumRule: "all",
				PermittedTerminalFailureOutcomes: []string{"failed"}}}},
		},
		CancellationPolicy:               cancellationPolicy,
		TerminalResolutionDeadlineUnix:   deadlines.terminalResolution,
		LateIngressRecoveryWindowSeconds: deadlines.lateIngressWindowSeconds,
		LateIngressRecoveryDeadlineUnix:  deadlines.lateIngressRecovery,
		LateRecoveryTerminalDeadlineUnix: deadlines.lateRecoveryTerminal, CoverageStateDomainDigest: digest("4"),
		SelectedClaimProfileDigest: claimProfileDigest, SelectedPayoutAdapterProfile: payoutAdapter,
		CoverageOperationAdapterProfile: ref("8", "coverage-operation"), ClaimOperationAdapterProfile: ref("9", "claim-operation"),
		ExposureOperationAdapterProfile: ref("a", "exposure-operation"), StageActionAuthorityBinding: stageBinding,
		AcceptanceAuthorityProfile: ref("c", "authority"), LifecycleAuthorizationProfile: ref("c", "authority"),
		ClaimTriggerProfile: trigger, ClaimEvidenceProfile: evidence,
		ClaimantAuthorizationProfiles: []commerce.ProfileRefV1{ref("4", "claimant")}, DecisionProfile: decisionProfile,
		ClaimIngressProfile: ref("5", "claim-ingress"), ClaimIngressAuthoritySubjects: []string{"agent:guarantor"},
		ClaimIngressAuthorityQuorumRule: "all", ClaimAdmissionProfile: ref("6", "claim-admission"),
		ClaimAdmissionAuthoritySubjects: []string{"agent:guarantor"}, ClaimAdmissionQuorumRule: "all",
		DecisionAdmissionProfile:           ref("c", "authority"),
		DecisionAdmissionAuthoritySubjects: []string{"agent:guarantor"}, DecisionAdmissionQuorumRule: "all",
		DecisionAuthoritySubjects: []string{"agent:guarantor"}, DecisionQuorumRule: "all", PayoutTemplate: template,
		PremiumObligationIDs: []string{"obligation:premium"}}
	if collateralized {
		// Locked before coverage starts and until the Agreement expires, and
		// releasable only then: one reorg window after the final deadline.
		terms.SelectedCollateralProfileDigest, terms.CollateralObligationID = collateralProfileDigest, testCollateralObligationID
		terms.CollateralTerms = collateral.terms(t, terms.MaximumAggregatePayout, terms.CoverageStartsAtUnix,
			agreementExpiresAt, ref)
	}
	root := t.TempDir()
	if process != nil {
		// A process of the kill test opens the stores an earlier process left.
		root = process.directory
	}
	authorityDirectory, journalDirectory := filepath.Join(root, "authority"), filepath.Join(root, "guarantor")
	if mkdirErr := os.MkdirAll(authorityDirectory, 0o700); mkdirErr != nil {
		t.Fatal(mkdirErr)
	}
	if mkdirErr := os.MkdirAll(journalDirectory, 0o700); mkdirErr != nil {
		t.Fatal(mkdirErr)
	}
	authority, err := OpenPersonalAuthority(authorityDirectory, "owner:guarantor", "agent:guarantor", "authority:owner",
		testAuthorityKeys(), PortfolioLimits{MaximumLossAtomic: 10_000, LockedCapitalAtomic: 10_000})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	if process != nil {
		// The process runs on the test's logical clock from its first
		// authority call, so its writer fence is issued at that time too.
		authority.now = func() time.Time { return now }
	}
	journal, err := OpenGuarantorJournal(journalDirectory, "owner:guarantor", "agent:guarantor")
	if err != nil {
		t.Fatal(err)
	}
	closeGuarantorJournalOnCleanup(t, journal)
	if scenario == guarantorNoFallback {
		// The complete lifecycle runs every commit method with real receipts:
		// none may change the in-memory document before its commit.
		checkGuarantorJournalCommitsFromACopy(t, journal, journalDirectory)
	}
	scope := []string{"commercial.quote.close", "commercial.quote.issue", "conditional.claim-decision.admit", "conditional.claim.decide", "conditional.claim.ingress",
		"conditional.claim.submit", "conditional.claim.transition", "conditional.claim-filing.close", "conditional.obligation.transition",
		"messenger.send", "payment.direct", "payment.domain-bound", "portfolio.release"}
	if collateralized {
		scope = append(scope, "collateral.transition")
	}
	sort.Strings(scope)
	fence, err := authority.AcquireWriter(context.Background(), "instance:test", scope, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	authorizationProfile := ref("c", "authority")
	guarantorController := testGuarantorController(guarantorPublic)
	signer, _ := NewLocalGuarantorObjectSigner(
		"agent:guarantor",
		authorizationProfile,
		testAuthorityCustody,
		guarantorController,
		[]byte("guarantor-history"),
	)
	actionSigner, _ := NewLocalGuarantorObjectSigner(
		"authority:owner",
		authorizationProfile,
		testAuthorityCustody,
		ActionAuthorityController,
		[]byte("action-authority-history"),
	)
	fallbackSigner, _ := NewLocalGuarantorObjectSigner(
		"agent:guarantor",
		fallback.FallbackProfile,
		testAuthorityCustody,
		guarantorController,
		[]byte("fallback-history"),
	)
	resolver := newGuarantorPinnedResolver(
		map[string]ed25519.PublicKey{"agent:guarantor": guarantorPublic, "agent:covered": coveredPublic},
	)
	// The owner authority signs stage admissions and seals with its Action
	// Authority controller.
	resolver.controllers["authority:owner"] = ActionAuthorityController
	// The custodian signs collateral evidence with its own controller. The
	// finality double starts empty and accepts nothing until it is pinned to
	// the lock.
	resolver.controllers[testCollateralCustodian] = testCollateralCustodianController
	collateralFinality := &pinnedCollateralFinality{}
	coordinator := GuarantorProviderCoordinator{OwnerID: "owner:guarantor", AgentID: "agent:guarantor", MandateDigest: digest("5"),
		PolicyRevision: 1, Policy: GuarantorRiskPolicy{MaximumAggregateExposureAtomic: "10000", MaximumPerCoverageAtomic: "2000",
			MaximumPerCounterpartyAtomic: "3000", MinimumPremiumPPM: 10_000, MaximumClaimProbabilityPPM: 100_000,
			CapitalCostPPM: 10_000, PermittedAssuranceLevels: []guarantor.AssuranceLevel{assurance},
			MaximumActiveOffers: 10, MaximumActiveCoverages: 10, MaximumActiveClaims: 20}, Authority: authority,
		Journal: journal, Signer: signer, ActionAuthoritySigner: actionSigner, FallbackSigner: fallbackSigner, Resolver: resolver,
		Underwriter: staticGuarantorUnderwriter{GuarantorRiskEstimate{ClaimProbabilityPPM: 50_000,
			OperationalCostAtomic: "5", CollateralCreditAtomic: "0", EvidenceSetDigest: digest("6"),
			EstimatedAtUnix: uint64(now.Add(-time.Minute).Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}},
		Eligibility: staticGuarantorEligibility{[]byte("fresh-authority-proof")}, EvidenceVerifier: staticGuarantorEvidenceVerifier{},
		PaymentVerifier:     validPaymentEvidence{},
		RiskBuckets:         staticGuarantorBuckets{digest("7"), digest("8")},
		PublicationResolver: resolver, UnderlyingAgreementResolver: underlyingResolver,
		AgreementVerifier: AgreementEvidenceRouter{AgentAuthority: agreementKeys, Profiles: map[string]ExternalAgreementEvidenceVerifier{
			guarantor.FirmOfferAgreementEvidenceProfileURI: GuarantorFirmOfferAgreementEvidenceVerifier{
				AuthorityResolver: resolver, PublicationResolver: resolver, UnderlyingResolver: underlyingResolver,
				AgreementVerifier: baseAgreementVerifier}}}}
	if collateralized {
		coordinator.CollateralAdapterEnabled = true
		coordinator.CollateralAdapterProfileDigests = []string{collateral.profile.CustodyAdapterProfile.ProfileDigest}
		coordinator.CollateralFinalityVerifier = collateralFinality
	}
	// restartWriter is what a restart of the Provider process does to this
	// lifecycle: the journal is closed and opened from disk, and the writer
	// takes a new generation, so the fence every earlier call ran under is
	// stale. The authority and its clock are the test's and stay.
	restarts := 0
	restartWriter := func() {
		t.Helper()
		journal = reopenTestGuarantorJournal(t, coordinator.Journal, journalDirectory)
		coordinator.Journal = journal
		if scenario == guarantorNoFallback {
			checkGuarantorJournalCommitsFromACopy(t, journal, journalDirectory)
		}
		restarts++
		var acquireErr error
		fence, acquireErr = authority.AcquireWriter(context.Background(), fmt.Sprintf("instance:restart-%d", restarts),
			scope, time.Hour)
		if acquireErr != nil {
			t.Fatalf("take a new writer generation after restart %d: %v", restarts, acquireErr)
		}
	}
	directTerms := terms
	directTerms.StageActionAuthorityBinding.Stages = append([]guarantor.GuarantorStageActionAuthorityV1(nil),
		terms.StageActionAuthorityBinding.Stages...)
	for index := range directTerms.StageActionAuthorityBinding.Stages {
		if directTerms.StageActionAuthorityBinding.Stages[index].Stage == "payout_execution" {
			operation, operationErr := guarantor.NewStageOperationBindingV1("payout_execution", "payment.direct", "guarantor-payout", 1<<20)
			if operationErr != nil {
				t.Fatal(operationErr)
			}
			directTerms.StageActionAuthorityBinding.Stages[index].OperationActionKind = operation.ActionKind
			directTerms.StageActionAuthorityBinding.Stages[index].OperationPurpose = operation.OperationPurpose
			directTerms.StageActionAuthorityBinding.Stages[index].MaximumRequestBytes = operation.MaximumRequestBytes
			directTerms.StageActionAuthorityBinding.Stages[index].OperationBindingDigest, _ = guarantor.StageOperationBindingDigestV1(operation)
		}
	}
	payoutObligation := commerce.SettlementObligation{AgreementBodyDigest: agreementDigest,
		AgreementObligationID: "obligation:payout", ObligationInstanceID: digest("b"), Sequence: 1,
		PayerAgentID: "agent:guarantor", PayeeAgentID: "agent:covered",
		Amount: commerce.AgreementAmount{AssetNamespace: asset.AssetNamespace, AssetIdentifier: asset.AssetIdentifier,
			AmountAtomic: "10", Unit: asset.Unit},
		MaximumAggregateAmount: commerce.AgreementAmount{AssetNamespace: asset.AssetNamespace,
			AssetIdentifier: asset.AssetIdentifier, AmountAtomic: "10", Unit: asset.Unit},
		SettlementAdapterURI: payoutAdapter.ProfileURI, SettlementParametersDigest: parameterDigest,
		StableActionID: digest("c"), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}
	directRequest, err := buildGuarantorPaymentRequest(&coordinator, directTerms, "tos:test", destination, payoutObligation)
	if err != nil || directRequest.SchemaVersion != 1 || directRequest.NetworkID != "tos:test" || directRequest.NetworkDomainDigest != "" {
		t.Fatalf("direct Guarantor payout selected the wrong network identity: request=%#v err=%v", directRequest, err)
	}
	issueInput := GuarantorIssueOfferInput{Request: quote,
		ProfileArtifact: profileArtifact, Agreement: agreement, Terms: terms, CoverageObligationID: "obligation:coverage",
		IssuedAtUnix: uint64(now.Unix()), AcceptByUnix: uint64(now.Add(5 * time.Minute).Unix()),
		ReservationExpiresAtUnix: uint64(now.Add(6 * time.Minute).Unix()), ExpiresAtUnix: uint64(now.Add(10 * time.Minute).Unix())}
	if process != nil {
		process.drive(t, guarantorKillFixture{
			now: now, coordinator: &coordinator, authority: authority, fence: fence, issueInput: issueInput,
			agreement: agreement, agreementDigest: agreementDigest, underlying: underlying,
			underlyingDigest: underlyingDigest, underlyingResolver: underlyingResolver,
			agreementVerifier: baseAgreementVerifier, coveredKey: coveredKey, guarantorKey: guarantorKey,
			terms: terms, asset: asset, destinationDigest: destinationDigest, evidenceProfile: evidence,
		})
		return
	}
	coordinator.Authority = &failAfterReservationEconomicAuthority{EconomicAuthority: authority, failOnce: true}
	if _, _, crashErr := coordinator.IssueFirmOffer(context.Background(), issueInput, fence); crashErr == nil {
		t.Fatal("firm-offer issuance did not surface the injected post-reservation crash")
	}
	coordinator.Authority = authority
	// The process restarts after the crash, with the firm-offer issuance plan
	// stored and the offer not yet reserved in the journal. The journal opened
	// from disk holds that plan, and the issuance below resumes from it: it
	// reserves the plan's position. A document whose plan names another
	// position, reservation or admission domain than its offer derives is
	// refused.
	journal = restartTestGuarantorJournalHoldingAFirmOfferPlan(t, journal, journalDirectory)
	coordinator.Journal = journal
	if scenario == guarantorNoFallback {
		checkGuarantorJournalCommitsFromACopy(t, journal, journalDirectory)
	}
	offer, resolution, err := coordinator.IssueFirmOffer(context.Background(), issueInput, fence)
	if err != nil || resolution.State != commerce.ActionTerminal {
		t.Fatalf("issue offer: state=%s err=%v", resolution.State, err)
	}
	// A distinct offer can expire without acceptance. Closing it must derive a
	// portable zero-acceptance cut, persist an exact release plan before the
	// portfolio side effect, and return signed non-acceptance/release evidence.
	requestBody2 := requestBody
	requestBody2.RequestID = "request:coverage:expiry"
	requestBody2.CreatedAtUnix = uint64(now.Add(time.Second).Unix())
	requestBodyDigest2, _ := codec.Digest("tos.service.agent-guarantor-quote-request-body.v1", requestBody2)
	coveredAuthorization2, signErr := guarantor.SignObjectAuthorization(
		context.Background(),
		guarantor.AuthorizationStatementV1{
			SchemaVersion:    1,
			AuthoritySubject: "agent:covered", ProfileURI: ref("d", "request-authority").ProfileURI, ProfileVersion: 1,
			ProfileDigest: ref("d", "request-authority").ProfileDigest, AuthorizedObjectKind: "coverage-quote-request",
			AuthorizedBodyDigest: requestBodyDigest2, ValidationTimeUnix: requestBody2.CreatedAtUnix,
		},
		"tos.service.agent-guarantor-quote-request-signature.v1",
		testAuthorityCustody,
		testGuarantorController(coveredKey.Public().(ed25519.PublicKey)),
		[]byte("covered-history"),
	)
	if signErr != nil {
		t.Fatal(signErr)
	}
	quote2 := guarantor.AuthorizedCoverageQuoteRequestV1{Body: requestBody2, RequestedTerms: requested,
		Authorizations: []guarantor.ProfileQualifiedObjectAuthorizationV1{coveredAuthorization2}}
	agreement2 := agreement
	agreement2.AuthorizationPredicates = append([]commerce.AgreementAuthorizationPredicate(nil), agreement.AuthorizationPredicates...)
	agreement2.AgreementID = "agreement:coverage:expiry"
	for index := range agreement2.AuthorizationPredicates {
		agreement2.AuthorizationPredicates[index].EvidenceTargetProjectionDigest = ""
	}
	agreement2, err = commerce.PrepareAgreementTargets(agreement2)
	if err != nil {
		t.Fatal(err)
	}
	terms2 := terms
	terms2.CoverageID = digest("e")
	terms2.QuoteRequestDigest = mustGuarantorQuoteDigest(t, quote2)
	terms2.CoverageStateDomainDigest = digest("0")
	expiringInput := GuarantorIssueOfferInput{
		Request: quote2, ProfileArtifact: profileArtifact, Agreement: agreement2, Terms: terms2,
		CoverageObligationID:     "obligation:coverage",
		IssuedAtUnix:             uint64(now.Add(time.Second).Unix()),
		AcceptByUnix:             uint64(now.Add(2 * time.Minute).Unix()),
		ReservationExpiresAtUnix: uint64(now.Add(10 * time.Minute).Unix()),
		ExpiresAtUnix:            uint64(now.Add(15 * time.Minute).Unix()),
	}
	// This issuance stops after the journal has issued the offer and before
	// the authority's terminal transition: the plan is stored, the offer is
	// issued, the action is still prepared. The process restarts, and the
	// repeated issuance must recognize the issued offer and finish, with the
	// offer the plan carries.
	coordinator.Authority = &failBeforeTerminalEconomicAuthority{EconomicAuthority: authority, failOnce: true}
	if _, _, crashErr := coordinator.IssueFirmOffer(context.Background(), expiringInput, fence); crashErr == nil {
		t.Fatal("firm-offer issuance did not surface the injected crash before its terminal transition")
	}
	coordinator.Authority = authority
	issuedBeforeTerminal := requireTestFirmOfferIssuedWithAPreparedPlan(t, journal, authority)
	journal = reopenTestGuarantorJournal(t, journal, journalDirectory)
	coordinator.Journal = journal
	if scenario == guarantorNoFallback {
		checkGuarantorJournalCommitsFromACopy(t, journal, journalDirectory)
	}
	expiringOffer, expiringResolution, issueErr := coordinator.IssueFirmOffer(context.Background(), expiringInput,
		fence)
	if issueErr != nil || expiringResolution.State != commerce.ActionTerminal {
		t.Fatalf("issue expiring offer after a stop between its journal commit and its terminal transition: "+
			"state=%s err=%v", expiringResolution.State, issueErr)
	}
	if !sameJSON(expiringOffer, issuedBeforeTerminal) {
		t.Fatal("the resumed issuance returned another offer than the one the journal had issued")
	}
	if _, found, planErr := journal.FirmOfferIssuancePlan(expiringOffer.Body.OfferID); planErr != nil || found {
		t.Fatalf("the completed issuance left its plan: found=%v err=%v", found, planErr)
	}
	if replayed, replayedResolution, replayErr := coordinator.IssueFirmOffer(context.Background(), expiringInput,
		fence); replayErr != nil || replayedResolution.State != commerce.ActionTerminal ||
		!sameJSON(replayed, expiringOffer) {
		t.Fatalf("repeating the completed issuance: state=%s err=%v", replayedResolution.State, replayErr)
	}
	late := now.Add(4 * time.Minute)
	authority.now = func() time.Time { return late }
	// Every journal commit of this closure loses its directory sync once. The
	// coordinator stops at each with the committed-but-not-synced error and
	// commits nothing further in that call; called again it resumes from what
	// the journal holds and reaches the same closure, each step committed
	// once.
	closeSyncLoss := &journalSyncLossFault{remaining: 3}
	removeCloseSyncLoss := closeSyncLoss.install(journal)
	var expiredClosed GuarantorCloseExpiredOfferResult
	closeStops := repeatUntilTestGuarantorCommitsAreSynced(t, closeSyncLoss, "closing the expired offer", func() error {
		var closeErr error
		expiredClosed, closeErr = coordinator.CloseExpiredOffer(context.Background(), GuarantorCloseExpiredOfferInput{
			Offer: expiringOffer,
		}, fence)
		return closeErr
	})
	removeCloseSyncLoss()
	if closeStops != 3 || closeSyncLoss.lost != 3 {
		t.Fatalf("closing the expired offer stopped %d times for %d commits that lost their sync, want 3 and 3",
			closeStops, closeSyncLoss.lost)
	}
	var closeErr error
	if expiredClosed.ExpiryResolution.State != commerce.ActionTerminal ||
		expiredClosed.ReleaseResolution.State != commerce.ActionTerminal || expiredClosed.NonAcceptanceEvidence.Body.AcceptedCount != 0 ||
		expiredClosed.ReleaseReceipt.Body.State != "released_unaccepted" {
		t.Fatalf("close expiring offer: %#v err=%v", expiredClosed, closeErr)
	}
	replayedClose, closeErr := coordinator.CloseExpiredOffer(context.Background(), GuarantorCloseExpiredOfferInput{
		Offer: expiringOffer}, fence)
	if closeErr != nil || !sameJSON(replayedClose.ReleaseReceipt, expiredClosed.ReleaseReceipt) {
		t.Fatalf("replay closed offer: %#v err=%v", replayedClose, closeErr)
	}
	// Keep the test on its logical protocol clock. Under -race the preceding
	// maximum-envelope checks can take minutes of wall time; wall time must not
	// turn a valid 90-second protocol fixture into an accidental expiry.
	authority.now = func() time.Time { return now }
	offerDigest, _ := guarantor.FirmOfferDigest(offer)
	agreementEvidence := make([]commerce.AgreementAuthorizationEvidence, 0, 2)
	for _, predicate := range agreement.AuthorizationPredicates {
		if predicate.EvidenceProfileURI == guarantor.FirmOfferAgreementEvidenceProfileURI {
			continue
		}
		key := coveredKey
		accepted, signErr := commerce.SignAgreementAcceptance(commerce.AgreementAcceptanceBody{AgreementID: agreement.AgreementID,
			AgreementVersion: agreement.Version, AgreementBodyDigest: agreementDigest, AcceptingSubject: predicate.AuthoritySubject,
			PredicateIDs: []string{predicate.PredicateID}, EvidenceTargetProjectionDigests: []string{predicate.EvidenceTargetProjectionDigest},
			ExpiresAtUnix: agreement.ExpiresAtUnix}, key)
		if signErr != nil {
			t.Fatal(signErr)
		}
		evidenceItem, evidenceErr := commerce.AgentSignatureEvidence(agreement, accepted)
		if evidenceErr != nil {
			t.Fatal(evidenceErr)
		}
		agreementEvidence = append(agreementEvidence, evidenceItem)
	}
	firmOfferEvidence, err := guarantor.NewFirmOfferAgreementEvidenceV1(offer, agreement, resolver, resolver,
		underlyingResolver, baseAgreementVerifier, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	agreementEvidence = append(agreementEvidence, firmOfferEvidence)
	sort.Slice(agreementEvidence, func(i, j int) bool {
		left, _ := codec.Marshal(agreementEvidence[i])
		right, _ := codec.Marshal(agreementEvidence[j])
		return string(left) < string(right)
	})
	evidenceSet := guarantor.GuarantorAgreementAuthorizationEvidenceSetV1{SchemaVersion: 1, AgreementID: agreement.AgreementID,
		AgreementVersion: agreement.Version, AgreementBodyDigest: agreementDigest, Evidence: agreementEvidence}
	evidenceSetDigest, _ := guarantor.AgreementAuthorizationEvidenceSetDigestV1(evidenceSet)
	acceptanceBody := guarantor.CoverageAcceptanceRequestBodyV1{SchemaVersion: 1, CoverageAgreementBodyDigest: agreementDigest,
		AuthorizedFirmOfferEnvelopeDigest: offerDigest, CompleteAuthorizationEvidenceSetDigest: evidenceSetDigest,
		AcceptingSubject: "agent:covered", SubmissionAuthorizationProfile: commerce.ProfileRefV1{
			ProfileURI: commerce.EvidenceProfileAgentSignature, ProfileVersion: 1, ProfileDigest: agreementProfile},
		CreatedAtUnix: uint64(now.Add(time.Minute).Unix()), ExpiresAtUnix: uint64(now.Add(4 * time.Minute).Unix())}
	acceptanceBodyDigest, _ := codec.Digest("tos.service.agent-guarantor-acceptance-request-body.v1", acceptanceBody)
	acceptanceAuthorization, _ := guarantor.SignObjectAuthorization(
		context.Background(),
		guarantor.AuthorizationStatementV1{
			SchemaVersion:    1,
			AuthoritySubject: "agent:covered", ProfileURI: acceptanceBody.SubmissionAuthorizationProfile.ProfileURI,
			ProfileVersion: 1, ProfileDigest: acceptanceBody.SubmissionAuthorizationProfile.ProfileDigest,
			AuthorizedObjectKind: "coverage-acceptance-request", AuthorizedBodyDigest: acceptanceBodyDigest,
			ValidationTimeUnix: uint64(now.Add(time.Minute).Unix()),
		},
		"tos.service.agent-guarantor-acceptance-request-signature.v1",
		testAuthorityCustody,
		testGuarantorController(coveredKey.Public().(ed25519.PublicKey)),
		[]byte("covered-history"),
	)
	acceptance := guarantor.AuthorizedCoverageAcceptanceRequestV1{
		Body:                     acceptanceBody,
		CoverageAgreementBody:    agreement,
		AuthorizationEvidenceSet: evidenceSet,
		Authorizations:           []guarantor.ProfileQualifiedObjectAuthorizationV1{acceptanceAuthorization},
	}
	authority.now = func() time.Time { return now.Add(time.Minute) }
	acceptanceEvent, err := guarantor.BuildCommerceProfileEventV1(context.Background(), "acceptance-request", acceptance,
		guarantor.CommerceEventContextV1{AgreementBodyDigest: agreementDigest, ObligationIDs: []string{"obligation:coverage"},
			CreatedAtUnix: uint64(now.Add(time.Minute).Unix()), ExpiresAtUnix: acceptanceBody.ExpiresAtUnix},
		guarantorImmutablePublisher{})
	if err != nil {
		t.Fatal(err)
	}
	acceptanceCanonical, err := codec.Marshal(acceptance)
	if err != nil {
		t.Fatal(err)
	}
	eventSink := &guarantorEventSink{}
	providerRuntime, runtimeErr := NewGuarantorProviderRuntime(GuarantorProviderRuntimeConfig{
		Inbox: CommerceProfileInbox{Client: emptyMessengerCaller{}, Verifier: guarantor.CommerceObjectVerifierV1{}}, Coordinator: &coordinator,
		Engine: &Engine{OwnerID: "owner:guarantor", AgentID: "agent:guarantor", MandateDigest: digest("5"),
			Gates: FeatureGates{AgentGuarantor: true}, Authority: authority, Sink: eventSink},
		Fence: func(context.Context) (commerce.WriterFence, error) { return fence, nil },
		Planner: GuarantorFirmOfferPlannerFunc(func(context.Context, *ClaimedCommerceProfileEvent,
			guarantor.AuthorizedCoverageQuoteRequestV1) (GuarantorIssueOfferInput, error) {
			return GuarantorIssueOfferInput{}, errors.New("not used by acceptance route")
		}), PolicyRevision: 1, MaximumEventTTL: time.Hour, ImmutablePublisher: guarantorImmutablePublisher{}})
	if runtimeErr != nil {
		t.Fatalf("assemble production Guarantor Provider runtime: %v", runtimeErr)
	}
	if err = providerRuntime.Handler.HandleGuarantorProfileEvent(context.Background(), &ClaimedCommerceProfileEvent{
		SenderAgentID: "agent:covered", ProfileEvent: acceptanceEvent, CanonicalObjectBytes: acceptanceCanonical}); err != nil {
		t.Fatalf("accept coverage through Provider event handler: %v", err)
	}
	if len(eventSink.messages) != 1 || eventSink.messages[0].Kind != "commerce.profile-event" {
		t.Fatalf("Provider handler did not send exactly one typed acceptance receipt: %#v", eventSink.messages)
	}
	_, _, coverages := testGuarantorSnapshot(t, journal)
	if len(coverages) != 1 || coverages[0].Record.CoverageStatus != guarantor.CoveragePendingAuthorization {
		t.Fatalf("unexpected accepted coverage projection: %#v", coverages)
	}
	if coverages[0].AcceptanceReceipt == nil || coverages[0].AcceptanceReceipt.Body.AcceptedCoverageRevision != 1 {
		t.Fatal("Provider event handler did not durably retain the acceptance receipt")
	}
	receipt := *coverages[0].AcceptanceReceipt
	underlyingPredicate := underlying.AuthorizationPredicates[0]
	underlyingAcceptance, err := commerce.SignAgreementAcceptance(commerce.AgreementAcceptanceBody{AgreementID: underlying.AgreementID,
		AgreementVersion: underlying.Version, AgreementBodyDigest: underlyingDigest, AcceptingSubject: underlyingPredicate.AuthoritySubject,
		PredicateIDs:                    []string{underlyingPredicate.PredicateID},
		EvidenceTargetProjectionDigests: []string{underlyingPredicate.EvidenceTargetProjectionDigest},
		ExpiresAtUnix:                   underlying.ExpiresAtUnix}, coveredKey)
	if err != nil {
		t.Fatal(err)
	}
	underlyingEvidence, err := commerce.AgentSignatureEvidence(underlying, underlyingAcceptance)
	if err != nil {
		t.Fatal(err)
	}
	activationPrerequisites := guarantor.CanonicalGuarantorEvidenceSetV1{SchemaVersion: 1,
		Purpose: "coverage-activation", ContextDigest: agreementDigest,
		Items: []guarantor.CanonicalGuarantorEvidenceItemV1{{ContentType: "application/cbor",
			EvidenceProfileDigest: digest("6"), EvidenceEnvelopeDigest: digest("7"), Representation: "inline",
			CanonicalEnvelopeBytes: []byte("finalized-premium-payment-evidence")}}}
	activationInput := GuarantorActivateCoverageInput{
		Offer: offer, AcceptanceReceipt: receipt, UnderlyingAgreement: underlying,
		UnderlyingAuthorizationEvidence: guarantor.GuarantorAgreementAuthorizationEvidenceSetV1{SchemaVersion: 1,
			AgreementID: underlying.AgreementID, AgreementVersion: underlying.Version,
			AgreementBodyDigest: underlyingDigest, Evidence: []commerce.AgreementAuthorizationEvidence{underlyingEvidence}},
		PrerequisiteEvidenceSet: &activationPrerequisites,
		ActivatedAtUnix:         uint64(now.Add(2 * time.Minute).Unix())}
	var collateralLockDigest, collateralControlDigest string
	premiumPrerequisites := activationPrerequisites.Items
	if collateralized {
		// The collateral is locked and its control attested after acceptance
		// and before coverage starts; only then does the finality double know
		// a finalized lock.
		lockedAt := now.Add(time.Minute)
		lock, finalized := signedCollateralLock(t, &coordinator, fence, terms, agreementDigest,
			coverages[0].Record.LastEvidenceDigest, lockedAt)
		collateralFinality.finalized = append(collateralFinality.finalized, finalized)
		control := signedCollateralControl(t, signer, terms, agreementDigest, lockedAt, agreementExpiresAt)
		activationPrerequisites, collateralLockDigest, collateralControlDigest = collateralActivationPrerequisites(t,
			terms, agreementDigest, lock, control, premiumPrerequisites...)
		activationInput.CollateralLockEvidence, activationInput.CollateralControlEvidence = &lock, &control
	}
	baseAuthority := coordinator.Authority
	coordinator.Authority = &failAfterTerminalEconomicAuthority{EconomicAuthority: baseAuthority, failOnce: true}
	if _, _, crashErr := coordinator.ActivateCoverage(context.Background(), activationInput, fence); crashErr == nil {
		t.Fatal("activation did not surface the injected post-terminal crash")
	}
	_, _, afterCrash := testGuarantorSnapshot(t, journal)
	if len(afterCrash) != 1 || afterCrash[0].Record.CoverageStatus != guarantor.CoveragePendingAuthorization ||
		afterCrash[0].ActivationEvidence != nil {
		t.Fatalf("activation crash left a half-active coverage: %#v", afterCrash)
	}
	// The activation stopped with its action terminal at the authority and
	// nothing in the journal but its plan. The process restarts under a new
	// writer generation, and the activation is repeated with a later time: it
	// resumes from the plan and asks the authority for no second admission.
	// Its first commit, which records the terminal result in the admission
	// log, loses its directory sync, and the activation stops with that.
	coordinator.Authority = baseAuthority
	restartWriter()
	firstActivationAt := activationInput.ActivatedAtUnix
	activationInput.ActivatedAtUnix++
	admissions := &admissionCountingAuthority{EconomicAuthority: baseAuthority}
	coordinator.Authority = admissions
	activationWrites, removeActivationScript := scriptTestGuarantorDocumentWrites(journal, "unsynced")
	_, _, failedActivationErr := coordinator.ActivateCoverage(context.Background(), activationInput, fence)
	removeActivationScript()
	if admissions.admitted != 0 || *activationWrites != 1 ||
		!errors.Is(failedActivationErr, ErrGuarantorJournalCommittedNotSynced) {
		t.Errorf("an activation resumed from its plan whose first commit lost its sync: %d admissions, "+
			"%d document writes, err=%v; want no admission, one write and the unconfirmed commit",
			admissions.admitted, *activationWrites, failedActivationErr)
	}
	// While that commit cannot be confirmed the journal is not read as if it
	// held nothing: a replayed acceptance is not refused as naming an unknown
	// offer, an activation is not refused as having no pending coverage and no
	// portfolio is summed. Each fails with the error that says nothing was
	// done, and nothing is sent.
	_, removeFailingWrites := scriptTestGuarantorDocumentWrites(journal, "fail", "fail", "fail", "fail", "fail", "fail")
	replayedAcceptanceErr := providerRuntime.Handler.HandleGuarantorProfileEvent(context.Background(),
		&ClaimedCommerceProfileEvent{
			SenderAgentID: "agent:covered", ProfileEvent: acceptanceEvent,
			CanonicalObjectBytes: acceptanceCanonical,
		})
	_, _, unreadActivationErr := coordinator.ActivateCoverage(context.Background(), activationInput, fence)
	_, unreadPortfolioErr := coordinator.portfolioFor("agent:covered", terms.CoverageAsset)
	removeFailingWrites()
	for name, unreadErr := range map[string]error{
		"a replayed acceptance": replayedAcceptanceErr,
		"an activation":         unreadActivationErr, "a portfolio": unreadPortfolioErr,
	} {
		if !errors.Is(unreadErr, ErrGuarantorJournalDurabilityUnconfirmed) {
			t.Errorf("%s on a journal whose commit cannot be confirmed: got %v, want the unconfirmed-durability error",
				name, unreadErr)
		}
	}
	if len(eventSink.messages) != 1 {
		t.Fatalf("a replayed acceptance on an unreadable journal sent a message: %d sent", len(eventSink.messages))
	}
	activation, resolution, err := coordinator.ActivateCoverage(context.Background(), activationInput, fence)
	if err != nil || resolution.State != commerce.ActionTerminal || activation.Body.ActivatedCoverageRevision != 2 {
		t.Fatalf("activate coverage: state=%s body=%#v err=%v", resolution.State, activation.Body, err)
	}
	// The resumed activation is the one the stopped call prepared: activated
	// at that call's time, under that call's writer generation, with no
	// second admission, and its plan is gone with the commit.
	coordinator.Authority = baseAuthority
	activationInput.ActivatedAtUnix = firstActivationAt
	if activation.Body.ActivatedAtUnix != firstActivationAt ||
		activation.Body.WriterGeneration >= fence.Body.WriterGeneration || admissions.admitted != 0 {
		t.Fatalf("the resumed activation: activated at %d under generation %d with %d admissions; want the stopped "+
			"call's time %d, a generation before %d and no admission", activation.Body.ActivatedAtUnix,
			activation.Body.WriterGeneration, admissions.admitted, firstActivationAt, fence.Body.WriterGeneration)
	}
	if _, found, planErr := journal.ActionPlan(guarantorPlanCoverageActivation, agreementDigest, ""); planErr != nil ||
		found {
		t.Fatalf("the committed activation left its plan: found=%v err=%v", found, planErr)
	}
	_, _, coverages = testGuarantorSnapshot(t, journal)
	if coverages[0].Record.CoverageStatus != guarantor.CoverageActive || coverages[0].Record.ClaimFilingStatus != guarantor.FilingOpen {
		t.Fatalf("coverage did not activate atomically: %#v", coverages[0].Record)
	}
	if collateralized {
		// Activation stored both collateral prerequisites in the journal.
		for name, stored := range map[string]struct{ digest, mediaType string }{
			"lock":    {collateralLockDigest, guarantor.CollateralEvidenceContentTypeV1},
			"control": {collateralControlDigest, guarantor.CollateralControlEvidenceContentTypeV1}} {
			record, found := coverages[0].ImmutableEvidence[stored.digest]
			_, fileErr := os.Lstat(filepath.Join(journalDirectory, guarantorEvidenceDirectory,
				strings.TrimPrefix(stored.digest, "sha256:")))
			if !found || record.ContentType != stored.mediaType || record.ContentSize == 0 || fileErr != nil {
				t.Fatalf("activation did not store the collateral %s evidence in the journal: record=%#v file=%v",
					name, record, fileErr)
			}
		}
	}
	authority.now = func() time.Time { return now.Add(4 * time.Minute) }
	manifest := guarantor.ClaimEvidenceManifestV1{SchemaVersion: 1, Items: []guarantor.ClaimEvidenceDescriptorV1{{
		PredicateID: "evidence:failure", EvidenceProfile: evidence, ContentType: "application/json",
		ContentDigest: digest("a"), ContentSize: 64, DisclosurePolicyDigest: digest("b")}}, TotalDeclaredBytes: 64}
	manifestDigest, err := guarantor.ValidateClaimEvidenceManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	incidentDigest := digest("c")
	recovery := guarantor.OtherRecoveryDeclarationV1{SchemaVersion: 1, CoverageAgreementBodyDigest: agreementDigest,
		CoverageObligationID: "obligation:coverage", UnderlyingAgreementBodyDigest: underlyingDigest, ClaimRevision: 1,
		BeneficiaryAgentID: "agent:covered", IncidentKeyDigest: incidentDigest, CoverageAsset: asset,
		DeclaredAtUnix: uint64(now.Add(3 * time.Minute).Unix())}
	recoveryDigest, err := guarantor.ValidateOtherRecoveryDeclaration(recovery, manifest)
	if err != nil {
		t.Fatal(err)
	}
	triggered := guarantor.TriggeredObligationSetV1{SchemaVersion: 1,
		UnderlyingAgreementBodyDigest: underlyingDigest, ObligationIDs: []string{"obligation:work"}}
	triggeredDigest, _ := guarantor.TriggeredObligationSetDigestV1(triggered)
	claimID, _ := guarantor.ClaimID(agreementDigest, "obligation:coverage", incidentDigest, "agent:covered", triggeredDigest)
	claimBody := guarantor.CoverageClaimBodyV1{SchemaVersion: 1, ClaimID: claimID, ClaimRevision: 1,
		CoverageAgreementBodyDigest: agreementDigest, CoverageObligationID: "obligation:coverage",
		UnderlyingAgreementBodyDigest: underlyingDigest,
		TriggeredObligationSet:        triggered,
		ClaimantSubject:               "agent:covered", ClaimantAuthorizationProfile: terms.ClaimantAuthorizationProfiles[0],
		BeneficiaryAgentID: "agent:covered", IncidentKeyDigest: incidentDigest,
		OccurredAtUnix: uint64(now.Add(2 * time.Minute).Unix()),
		ClaimedAmount:  commerce.AtomicAmountV1{Asset: asset, AmountAtomic: "400"}, EvidenceManifestDigest: manifestDigest,
		OtherRecoveryDeclarationDigest: recoveryDigest, PayoutDestinationDigest: destinationDigest,
		CreatedAtUnix: uint64(now.Add(3 * time.Minute).Unix()), ExpiresAtUnix: uint64(now.Add(10 * time.Minute).Unix())}
	claimBodyDigest, err := guarantor.ClaimBodyDigest(claimBody)
	if err != nil {
		t.Fatal(err)
	}
	claimAuthorization, err := guarantor.SignObjectAuthorization(
		context.Background(),
		guarantor.AuthorizationStatementV1{
			SchemaVersion:        1,
			AuthoritySubject:     "agent:covered",
			ProfileURI:           terms.ClaimantAuthorizationProfiles[0].ProfileURI,
			ProfileVersion:       terms.ClaimantAuthorizationProfiles[0].ProfileVersion,
			ProfileDigest:        terms.ClaimantAuthorizationProfiles[0].ProfileDigest,
			AuthorizedObjectKind: "coverage-claim",
			AuthorizedBodyDigest: claimBodyDigest,
			ValidationTimeUnix:   uint64(now.Add(3 * time.Minute).Unix()),
		},
		"tos.service.agent-guarantor-claim-signature.v1",
		testAuthorityCustody,
		testGuarantorController(coveredKey.Public().(ed25519.PublicKey)),
		[]byte("covered-history"),
	)
	if err != nil {
		t.Fatal(err)
	}
	claim := guarantor.AuthorizedCoverageClaimV1{
		Body:                     claimBody,
		EvidenceManifest:         manifest,
		OtherRecoveryDeclaration: recovery,
		Authorizations:           []guarantor.ProfileQualifiedObjectAuthorizationV1{claimAuthorization},
	}
	// The claim is admitted by a process that dies after each of its two
	// terminal transitions, the ingress and the admission, and restarts under
	// a new writer generation; then by a caller that never sees the return.
	// Every repetition returns the committed receipts.
	claimResult := requireCommittedGuarantorReceiptReplays(t, "admitting the claim", &coordinator, authority,
		restartWriter, 2, func() (GuarantorClaimAdmissionResult, error) {
			return coordinator.AdmitClaim(context.Background(), agreementDigest, claim, fence)
		}, func() error {
			other := claim
			other.Body.CreatedAtUnix++
			_, otherErr := coordinator.AdmitClaim(context.Background(), agreementDigest, other, fence)
			return otherErr
		})
	if claimResult.IngressResolution.State != commerce.ActionTerminal ||
		claimResult.AdmissionResolution.State != commerce.ActionTerminal {
		t.Fatalf("admit claim: result=%#v err=%v", claimResult, err)
	}
	// Every scenario revises the claim once; on the late-recovery path the
	// fallback finds the claim's initial admission in the filing close's cut.
	revisionResult := claimResult
	{
		revisedRecovery := recovery
		revisedRecovery.ClaimRevision = 2
		revisedRecovery.DeclaredAtUnix = uint64(now.Add(3*time.Minute + time.Second).Unix())
		revisedRecoveryDigest, _ := guarantor.ValidateOtherRecoveryDeclaration(revisedRecovery, manifest)
		revisedBody := claimBody
		revisedBody.ClaimRevision = 2
		revisedBody.PredecessorClaimDigest = claimBodyDigest
		revisedBody.OtherRecoveryDeclarationDigest = revisedRecoveryDigest
		revisedBody.CreatedAtUnix = uint64(now.Add(3*time.Minute + time.Second).Unix())
		revisedBodyDigest, _ := guarantor.ClaimBodyDigest(revisedBody)
		revisedAuthorization, _ := guarantor.SignObjectAuthorization(
			context.Background(),
			guarantor.AuthorizationStatementV1{
				SchemaVersion:        1,
				AuthoritySubject:     "agent:covered",
				ProfileURI:           terms.ClaimantAuthorizationProfiles[0].ProfileURI,
				ProfileVersion:       terms.ClaimantAuthorizationProfiles[0].ProfileVersion,
				ProfileDigest:        terms.ClaimantAuthorizationProfiles[0].ProfileDigest,
				AuthorizedObjectKind: "coverage-claim",
				AuthorizedBodyDigest: revisedBodyDigest,
				ValidationTimeUnix:   revisedBody.CreatedAtUnix,
			},
			"tos.service.agent-guarantor-claim-signature.v1",
			testAuthorityCustody,
			testGuarantorController(coveredKey.Public().(ed25519.PublicKey)),
			[]byte("covered-history"),
		)
		revisedClaim := guarantor.AuthorizedCoverageClaimV1{
			Body:                     revisedBody,
			EvidenceManifest:         manifest,
			OtherRecoveryDeclaration: revisedRecovery,
			Authorizations:           []guarantor.ProfileQualifiedObjectAuthorizationV1{revisedAuthorization},
		}
		revisionResult, err = coordinator.AdmitClaim(context.Background(), agreementDigest, revisedClaim, fence)
		if err != nil || revisionResult.IngressResolution.State != commerce.ActionTerminal ||
			revisionResult.AdmissionResolution.State != commerce.ActionTerminal {
			t.Fatalf("admit claim revision: result=%#v err=%v", revisionResult, err)
		}
		if _, err := coordinator.AdmitClaim(context.Background(), agreementDigest, claim, fence); err == nil {
			t.Fatal("stale claim revision was accepted after the lineage advanced")
		}
		claim = revisedClaim
	}
	// exerciseFallback admits the deterministic fallback at fallbackAt and
	// carries it through portable verification, challenge close, application
	// and coverage closure.
	exerciseFallback := func(fallbackAt time.Time, wantPath string) guarantor.AuthorizedClaimDecisionAdmissionReceiptV1 {
		authority.now = func() time.Time { return fallbackAt }
		fallbackAdmission, err := coordinator.AdmitInitialFallbackDecision(context.Background(),
			GuarantorAdmitInitialFallbackInput{AgreementDigest: agreementDigest, ClaimID: claimID}, fence)
		if err != nil || fallbackAdmission.Resolution.State != commerce.ActionTerminal ||
			fallbackAdmission.Receipt.Body.AdmittedClaimState != "denied" ||
			fallbackAdmission.Receipt.Body.DecisionPath != wantPath {
			t.Fatalf("admit %s: resolution=%#v err=%v", wantPath, fallbackAdmission.Resolution, err)
		}
		receipt := fallbackAdmission.Receipt
		if err := guarantor.VerifyClaimDecisionAdmissionReceiptV1(receipt, terms, coordinator.AgreementVerifier,
			coordinator.resolverFor(agreementDigest), authority, fallbackAt); err != nil {
			t.Fatalf("the admitted fallback receipt is not portable: %v", err)
		}
		wire, err := guarantor.Canonical(receipt)
		request := receipt.StageActionAdmissionEvidence.CanonicalRequest
		if err != nil || len(wire) > guarantor.MaxCanonicalObjectBytes || len(request) > guarantor.MaximumStageRequestBytesV1 {
			t.Fatalf("fallback receipt exceeds its bounds: receipt=%d request=%d err=%v", len(wire), len(request), err)
		}
		t.Logf("portable Guarantor fallback admission=%d bytes, request=%d bytes", len(wire), len(request))
		closeAt := fallbackAt.Add(time.Duration(terms.ChallengeWindowSeconds+1) * time.Second)
		authority.now = func() time.Time { return closeAt }
		closed, err := coordinator.TransitionClaimDecision(context.Background(), GuarantorTransitionClaimInput{
			AgreementDigest: agreementDigest, DecisionAdmissionReceipt: receipt, TransitionKind: "challenge_close"}, fence)
		if err != nil || closed.Resolution.State != commerce.ActionTerminal ||
			closed.Receipt.Body.ResultingClaimState != "final_denied" {
			t.Fatalf("close fallback challenge window: result=%#v err=%v", closed.Resolution, err)
		}
		if err := guarantor.VerifyClaimDecisionAdmissionReceiptProofV1(closed.Receipt.DecisionAdmissionProof, terms,
			coordinator.resolverFor(agreementDigest), closeAt); err != nil {
			t.Fatalf("the fallback decision's compact proof does not verify: %v", err)
		}
		applied, err := coordinator.ApplyClaimDecision(context.Background(), GuarantorApplyDecisionInput{
			AgreementDigest: agreementDigest, DecisionAdmissionReceipt: receipt, TerminalTransitionReceipt: closed.Receipt}, fence)
		if err != nil || applied.Resolution.State != commerce.ActionTerminal || len(applied.Payouts.Obligations) != 0 {
			t.Fatalf("apply fallback denial: result=%#v err=%v", applied.Resolution, err)
		}
		// Closing the coverage puts the fallback decision into the terminal
		// claim set, whose verifier checks it against the fallback authority set.
		closeCoverageAt := now.Add(45 * time.Minute)
		authority.now = func() time.Time { return closeCoverageAt }
		closedCoverage, err := coordinator.CloseCoverage(context.Background(), GuarantorCloseCoverageInput{Offer: offer,
			ActivationEvidence: activation}, fence)
		if err != nil || closedCoverage.CoverageResolution.Body.TerminalState != "closed" ||
			closedCoverage.ExposureRelease.Body.RealizedLoss.AmountAtomic != "0" {
			t.Fatalf("close coverage after a fallback denial: err=%v", err)
		}
		if err := guarantor.VerifyTerminalClaimSetV1(closedCoverage.TerminalClaimSet, offer, coordinator.AgreementVerifier,
			coordinator.resolverFor(agreementDigest), authority, coordinator.PaymentVerifier, closeCoverageAt); err != nil {
			t.Fatalf("the terminal claim set holding a fallback decision does not verify: %v", err)
		}
		return receipt
	}
	if collateralized {
		// Claim admission above already re-verified the collateralized
		// activation through the journal resolver. Each verification is now
		// checked on its own: it passes through that resolver, and is refused
		// without the finality verifier or without a stored prerequisite.
		ctx := context.Background()
		check := collateralVerificationCheck{coordinator: &coordinator, journalDir: journalDirectory,
			agreementDigest: agreementDigest, prerequisites: []string{collateralLockDigest, collateralControlDigest}}
		admittedAt := time.Unix(int64(revisionResult.AdmissionReceipt.Body.AdmittedAtUnix), 0).UTC()
		check.run(t, "claim admission", func(resolver guarantor.AuthorityKeyResolver) error {
			return guarantor.VerifyClaimAdmissionReceiptV1(revisionResult.AdmissionReceipt, terms,
				coordinator.AgreementVerifier, resolver, authority, admittedAt)
		})

		// The claim is closed by the initial fallback, and the coverage with it.
		fallbackAt := admittedAt.Add(time.Duration(terms.ReviewDeadlineSeconds+1) * time.Second)
		authority.now = func() time.Time { return fallbackAt }
		denied, err := coordinator.AdmitInitialFallbackDecision(ctx, GuarantorAdmitInitialFallbackInput{
			AgreementDigest: agreementDigest, ClaimID: claimID}, fence)
		if err != nil || denied.Receipt.Body.AdmittedClaimState != "denied" {
			t.Fatalf("admit the initial fallback of the collateralized coverage: resolution=%#v err=%v", denied.Resolution, err)
		}
		challengeClosedAt := fallbackAt.Add(time.Duration(terms.ChallengeWindowSeconds+1) * time.Second)
		authority.now = func() time.Time { return challengeClosedAt }
		final, err := coordinator.TransitionClaimDecision(ctx, GuarantorTransitionClaimInput{AgreementDigest: agreementDigest,
			DecisionAdmissionReceipt: denied.Receipt, TransitionKind: "challenge_close"}, fence)
		if err != nil || final.Receipt.Body.ResultingClaimState != "final_denied" {
			t.Fatalf("close the fallback's challenge window: resolution=%#v err=%v", final.Resolution, err)
		}
		if _, err := coordinator.ApplyClaimDecision(ctx, GuarantorApplyDecisionInput{AgreementDigest: agreementDigest,
			DecisionAdmissionReceipt: denied.Receipt, TerminalTransitionReceipt: final.Receipt}, fence); err != nil {
			t.Fatalf("apply the fallback denial: %v", err)
		}
		coverageClosedAt := now.Add(45 * time.Minute)
		authority.now = func() time.Time { return coverageClosedAt }
		closed, err := coordinator.CloseCoverage(ctx, GuarantorCloseCoverageInput{Offer: offer,
			ActivationEvidence: activation}, fence)
		if err != nil || closed.CoverageResolution.Body.TerminalState != "closed" {
			t.Fatalf("close the collateralized coverage: state=%q err=%v", closed.CoverageResolution.Body.TerminalState, err)
		}
		check.run(t, "closure", func(resolver guarantor.AuthorityKeyResolver) error {
			return guarantor.VerifyTerminalClaimSetV1(closed.TerminalClaimSet, offer, coordinator.AgreementVerifier,
				resolver, authority, coordinator.PaymentVerifier, coverageClosedAt)
		})

		// A coverage is cancelled only from its activation, before any claim,
		// so cancellation runs on a second collateralized coverage with its own
		// lock, on the same logical clock as the first.
		authority.now = func() time.Time { return now }
		fence, err = authority.AcquireWriter(ctx, "instance:collateral-cancellation", scope, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		cancelRequestBody := requestBody
		cancelRequestBody.RequestID = "request:coverage:collateral-cancellation"
		cancelRequestBody.CreatedAtUnix = uint64(now.Add(3 * time.Second).Unix())
		cancelQuote := signGuarantorTestQuote(t, cancelRequestBody, requested, ref("d", "request-authority"), coveredKey)
		cancelAgreement := agreement
		cancelAgreement.AuthorizationPredicates = append([]commerce.AgreementAuthorizationPredicate(nil),
			agreement.AuthorizationPredicates...)
		cancelAgreement.AgreementID = "agreement:coverage:collateral-cancellation"
		for index := range cancelAgreement.AuthorizationPredicates {
			cancelAgreement.AuthorizationPredicates[index].EvidenceTargetProjectionDigest = ""
		}
		cancelAgreement, err = commerce.PrepareAgreementTargets(cancelAgreement)
		if err != nil {
			t.Fatal(err)
		}
		cancelAgreementDigest, _ := commerce.AgreementBodyDigest(cancelAgreement)
		cancelTerms := terms
		cancelTerms.CoverageID, cancelTerms.CoverageStateDomainDigest = digest("d"), digest("c")
		cancelTerms.QuoteRequestDigest = mustGuarantorQuoteDigest(t, cancelQuote)
		cancelOffer, _, err := coordinator.IssueFirmOffer(ctx, GuarantorIssueOfferInput{Request: cancelQuote,
			ProfileArtifact: profileArtifact, Agreement: cancelAgreement, Terms: cancelTerms,
			CoverageObligationID: "obligation:coverage", IssuedAtUnix: uint64(now.Add(3 * time.Second).Unix()),
			AcceptByUnix: uint64(now.Add(time.Minute).Unix()), ReservationExpiresAtUnix: uint64(now.Add(6 * time.Minute).Unix()),
			ExpiresAtUnix: uint64(now.Add(10 * time.Minute).Unix())}, fence)
		if err != nil {
			t.Fatalf("issue the cancellable collateralized offer: %v", err)
		}
		cancelAcceptance := signGuarantorTestAcceptance(t, cancelAgreement, cancelOffer, "agent:covered",
			map[string]ed25519.PrivateKey{"agent:covered": coveredKey, "agent:guarantor": guarantorKey},
			commerce.ProfileRefV1{ProfileURI: commerce.EvidenceProfileAgentSignature, ProfileVersion: 1,
				ProfileDigest: agreementProfile}, underlyingResolver, baseAgreementVerifier,
			now.Add(35*time.Second), now.Add(95*time.Second))
		cancelAcceptanceReceipt, _, err := coordinator.AcceptCoverage(ctx, GuarantorAcceptCoverageInput{Offer: cancelOffer,
			Request: cancelAcceptance, CoverageObligationID: "obligation:coverage",
			ReceivedAtUnix: uint64(now.Add(35 * time.Second).Unix())}, fence)
		if err != nil {
			t.Fatalf("accept the cancellable collateralized coverage: %v", err)
		}
		authority.now = func() time.Time { return now.Add(time.Minute) }
		cancelLock, cancelFinalized := signedCollateralLock(t, &coordinator, fence, cancelTerms, cancelAgreementDigest,
			digest("9"), now.Add(time.Minute))
		collateralFinality.finalized = append(collateralFinality.finalized, cancelFinalized)
		cancelControl := signedCollateralControl(t, signer, cancelTerms, cancelAgreementDigest, now.Add(time.Minute),
			agreementExpiresAt)
		cancelPrerequisites, cancelLockDigest, cancelControlDigest := collateralActivationPrerequisites(t, cancelTerms,
			cancelAgreementDigest, cancelLock, cancelControl, premiumPrerequisites...)
		cancelActivation, _, err := coordinator.ActivateCoverage(ctx, GuarantorActivateCoverageInput{Offer: cancelOffer,
			AcceptanceReceipt: cancelAcceptanceReceipt, UnderlyingAgreement: underlying,
			UnderlyingAuthorizationEvidence: guarantor.GuarantorAgreementAuthorizationEvidenceSetV1{SchemaVersion: 1,
				AgreementID: underlying.AgreementID, AgreementVersion: underlying.Version,
				AgreementBodyDigest: underlyingDigest, Evidence: []commerce.AgreementAuthorizationEvidence{underlyingEvidence}},
			PrerequisiteEvidenceSet: &cancelPrerequisites, CollateralLockEvidence: &cancelLock,
			CollateralControlEvidence: &cancelControl, ActivatedAtUnix: cancelTerms.CoverageStartsAtUnix}, fence)
		if err != nil {
			t.Fatalf("activate the cancellable collateralized coverage: %v", err)
		}
		cancelCreated := now.Add(2*time.Minute + 10*time.Second)
		cancelledAt := cancelCreated.Add(5 * time.Second)
		cancelReceipt, cancelResolution, err := coordinator.CancelCoverage(ctx, GuarantorCancelCoverageInput{
			Request: signedTestCancellationRequest(t, cancelAgreement, cancelAgreementDigest, cancellationPolicy,
				testGuarantorController(coveredPublic), cancelCreated),
			AdmittedAtUnix: uint64(cancelledAt.Unix())}, fence)
		if err != nil || cancelResolution.State != commerce.ActionTerminal || cancelReceipt.Body.State != "coverage_ended" {
			t.Fatalf("cancel the collateralized coverage: state=%s err=%v", cancelResolution.State, err)
		}
		cancelCheck := collateralVerificationCheck{coordinator: &coordinator, journalDir: journalDirectory,
			agreementDigest: cancelAgreementDigest, prerequisites: []string{cancelLockDigest, cancelControlDigest}}
		cancelCheck.run(t, "cancellation", func(resolver guarantor.AuthorityKeyResolver) error {
			return guarantor.VerifyCoverageCancellationReceiptV1(cancelReceipt, cancelActivation,
				coordinator.AgreementVerifier, resolver, authority, cancelledAt)
		})
		return
	}
	if scenario == guarantorInitialFallback {
		admittedAt := time.Unix(int64(revisionResult.AdmissionReceipt.Body.AdmittedAtUnix), 0).UTC()
		exerciseFallback(admittedAt.Add(time.Duration(terms.ReviewDeadlineSeconds+1)*time.Second), "initial_terminal_fallback")
		return
	}
	claimEnvelopeDigest, _ := guarantor.ClaimEnvelopeDigest(claim)
	decisionEvidence := guarantor.CanonicalGuarantorEvidenceSetV1{SchemaVersion: 1, Purpose: "claim-decision-evidence",
		ContextDigest: claimEnvelopeDigest, Items: []guarantor.CanonicalGuarantorEvidenceItemV1{{
			ContentType: "application/octet-stream", EvidenceProfileDigest: evidence.ProfileDigest,
			EvidenceEnvelopeDigest: digest("d"), Representation: "inline", CanonicalEnvelopeBytes: []byte("verified-failure")}}}
	decisionEvidenceDigest, _ := guarantor.CanonicalGuarantorEvidenceSetDigestV1(decisionEvidence)
	triggeredObligationsDigest, _ := guarantor.TriggeredObligationSetDigestV1(claim.Body.TriggeredObligationSet)
	policyApplication := guarantor.ClaimDecisionPolicyApplicationV1{SchemaVersion: 1,
		CoverageAgreementBodyDigest: agreementDigest, CoverageObligationID: "obligation:coverage",
		AuthorizedClaimEnvelopeDigest: claimEnvelopeDigest, DecisionPath: "initial",
		BenefitCalculationProfile: terms.BenefitCalculationProfile, TriggeredObligationSetDigest: triggeredObligationsDigest,
		EvidenceSetDigest: decisionEvidenceDigest, OtherRecoveryDeclarationDigest: claim.Body.OtherRecoveryDeclarationDigest,
		ApplicablePolicyClauseIDs: []string{"clause:service-default"}, PolicyInputProjection: []byte("fixed-benefit:400"),
		FullEligibleBenefitAmount: commerce.AtomicAmountV1{Asset: asset, AmountAtomic: "400"}}
	policyApplicationDigest, _ := guarantor.ClaimDecisionPolicyApplicationDigestV1(policyApplication)
	disputed := scenario == guarantorNonterminalFallback || scenario == guarantorLateFromDisputedFallback ||
		scenario == guarantorLateBeforeOrdinaryDeadline
	// The decision is made three minutes in and admitted a minute later,
	// except where its resolution window must still be open at a late filing
	// close: there it is made and admitted ten seconds before the terminal
	// resolution deadline.
	decidedAt, decisionAdmittedAt := now.Add(3*time.Minute), now.Add(4*time.Minute)
	if scenario == guarantorLateBeforeOrdinaryDeadline {
		decidedAt = time.Unix(int64(terms.TerminalResolutionDeadlineUnix)-10, 0).UTC()
		decisionAdmittedAt = decidedAt
	}
	decisionReason := guarantor.ClaimDecisionReasonV1{SchemaVersion: 1, DecisionProfile: decisionProfile,
		Result: guarantor.DecisionApproved, ReasonCode: "verified_failure",
		ApplicablePolicyClauseIDs: []string{"clause:service-default"}, EvidencePredicateIDs: []string{"evidence:failure"}}
	if disputed {
		decisionReason.Result = guarantor.DecisionDisputed
	}
	decisionReasonDigest, _ := guarantor.ClaimDecisionReasonDigestV1(decisionReason)
	// lateFilingClose closes claim filing twenty seconds after the terminal
	// resolution deadline, inside the late-ingress window, with the claim not
	// yet final, and returns the filing-close receipt and a writer fence at
	// that time.
	lateFilingClose := func(instance string) (*guarantor.AuthorizedClaimFilingCloseReceiptV1, commerce.WriterFence, time.Time) {
		ctx := context.Background()
		lateAt := time.Unix(int64(terms.TerminalResolutionDeadlineUnix)+20, 0).UTC()
		authority.now = func() time.Time { return lateAt }
		lateFence, err := authority.AcquireWriter(ctx, instance, scope, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if _, closeErr := coordinator.CloseCoverage(ctx, GuarantorCloseCoverageInput{Offer: offer,
			ActivationEvidence: activation}, lateFence); closeErr == nil {
			t.Fatal("coverage closed with a claim that is not final")
		}
		var filing *guarantor.AuthorizedClaimFilingCloseReceiptV1
		_, _, positions := testGuarantorSnapshot(t, journal)
		for index := range positions {
			if positions[index].Record.CoverageAgreementBodyDigest == agreementDigest {
				filing = positions[index].FilingCloseReceipt
			}
		}
		if filing == nil || filing.Body.ClosedAtUnix <= terms.TerminalResolutionDeadlineUnix {
			t.Fatalf("no late filing close was recorded: %#v", filing)
		}
		return filing, lateFence, lateAt
	}
	// checkInitialAdmissionProof: the revision admission a late fallback
	// carries holds the claim's initial admission proof and verifies with it.
	// The proof lies outside the admission's signed body, so removing or
	// replacing it leaves every signature valid and only the proof's own checks
	// refuse: without it, and when the proof presented under the initial
	// admission's digest is another admission's sealed proof. The fallback pins
	// the carried admission by digest, so it is refused with the proof removed.
	checkInitialAdmissionProof := func(receipt guarantor.AuthorizedClaimDecisionAdmissionReceiptV1, at time.Time) {
		t.Helper()
		admission := receipt.AuthorizedClaimAdmissionReceipt
		proof := admission.InitialClaimAdmissionProof
		initialDigest := admission.Body.InitialClaimAdmissionReceiptDigest
		if admission.Body.AdmissionKind != "revision" || proof == nil ||
			proof.ReceiptEnvelopeDigest != initialDigest || proof.ReceiptBody.AdmissionKind != "initial" {
			t.Fatalf("the revised claim's late fallback does not carry its initial admission proof: %#v", proof)
		}
		if err := guarantor.VerifyClaimAdmissionReceiptV1(admission, terms, coordinator.AgreementVerifier,
			coordinator.resolverFor(agreementDigest), authority, at); err != nil {
			t.Fatalf("the revision admission with its initial admission proof does not verify: %v", err)
		}
		missing := admission
		missing.InitialClaimAdmissionProof = nil
		if err := guarantor.VerifyClaimAdmissionReceiptV1(missing, terms, coordinator.AgreementVerifier,
			coordinator.resolverFor(agreementDigest), authority, at); err == nil ||
			!strings.Contains(err.Error(), "lacks its initial claim admission proof") {
			t.Fatalf("a revision admission without its initial admission proof was not refused: %v", err)
		}
		stripped := receipt
		stripped.AuthorizedClaimAdmissionReceipt = missing
		if err := guarantor.VerifyClaimDecisionAdmissionReceiptV1(stripped, terms, coordinator.AgreementVerifier,
			coordinator.resolverFor(agreementDigest), authority, at); err == nil ||
			!strings.Contains(err.Error(), "claim admission reference differs from the carried receipt") {
			t.Fatalf("a late fallback whose revision admission lost its initial proof was not refused: %v", err)
		}
		position, err := coordinator.coveragePosition(agreementDigest)
		if err != nil {
			t.Fatal(err)
		}
		revision, found := position.ClaimAdmissionReceipts[guarantorClaimRevisionKey(claimID, 2)]
		if !found {
			t.Fatal("the claim's revision admission is not stored")
		}
		// The revision admission's own sealed proof, relabelled as the initial
		// admission: digest, kind and claim match what the binder checks, so
		// only the proof's own validation (its body against its seal) refuses it.
		relabelled, err := coordinator.sealClaimAdmissionProof(revision, terms, at)
		if err != nil {
			t.Fatal(err)
		}
		relabelled.ReceiptEnvelopeDigest = initialDigest
		relabelled.ReceiptDescriptor.ContentDigest = initialDigest
		relabelled.ReceiptBody.AdmissionKind = "initial"
		substituted := admission
		substituted.InitialClaimAdmissionProof = &relabelled
		if err := guarantor.VerifyClaimAdmissionReceiptV1(substituted, terms, coordinator.AgreementVerifier,
			coordinator.resolverFor(agreementDigest), authority, at); err == nil ||
			!strings.Contains(err.Error(), "initial claim admission proof is invalid") {
			t.Fatalf("another admission's sealed proof was accepted as the initial admission: %v", err)
		}
	}
	if scenario == guarantorLateRecoveryFallback || scenario == guarantorLateCandidateTimesOut {
		ctx := context.Background()
		// Claim filing closes a minute after the terminal resolution deadline
		// with the claim still undecided; closure stops there.
		filing, lateFence, lateAt := lateFilingClose("instance:late-recovery")
		filingDigest, _ := guarantor.ClaimFilingCloseReceiptDigestV1(*filing)

		// The late-recovery candidate resolves its filing close from the
		// journal by descriptor.
		candidateAt := lateAt.Add(10 * time.Second)
		authority.now = func() time.Time { return candidateAt }
		candidate, err := coordinator.AdmitInitialFallbackDecision(ctx, GuarantorAdmitInitialFallbackInput{
			AgreementDigest: agreementDigest, ClaimID: claimID, LateFilingReceipt: filing}, lateFence)
		if err != nil || candidate.Receipt.Body.DecisionPath != "late_recovery_terminal_fallback" ||
			candidate.Receipt.Body.LateFilingCloseReceiptDigest != filingDigest {
			t.Fatalf("admit late-recovery candidate: resolution=%#v err=%v", candidate.Resolution, err)
		}
		if err := guarantor.VerifyClaimDecisionAdmissionReceiptV1(candidate.Receipt, terms, coordinator.AgreementVerifier,
			coordinator.resolverFor(agreementDigest), authority, candidateAt); err != nil {
			t.Fatalf("the late-recovery candidate is not portable: %v", err)
		}
		if err := guarantor.VerifyClaimDecisionAdmissionReceiptV1(candidate.Receipt, terms, coordinator.AgreementVerifier,
			resolver, authority, candidateAt); err == nil {
			t.Fatal("the late-recovery candidate verified without an immutable evidence resolver")
		}
		checkInitialAdmissionProof(candidate.Receipt, candidateAt)

		// Its one challenge round leaves revision ingress frozen.
		challengeAt := candidateAt.Add(10 * time.Second)
		authority.now = func() time.Time { return challengeAt }
		challenged, err := coordinator.TransitionClaimDecision(ctx, GuarantorTransitionClaimInput{
			AgreementDigest: agreementDigest, DecisionAdmissionReceipt: candidate.Receipt, TransitionKind: "challenge_admission"}, lateFence)
		if err != nil || challenged.Receipt.Body.ResultingClaimState != "reviewing" {
			t.Fatalf("challenge the late-recovery candidate: resolution=%#v err=%v", challenged.Resolution, err)
		}
		epoch, err := journal.RevisionEpoch(agreementDigest, claimID)
		if err != nil || epoch.State != revisionEpochFrozen || epoch.StateRevision != candidate.Receipt.Body.FrozenRevisionEpochStateRevision {
			t.Fatalf("the late candidate's challenge changed the revision epoch: %#v err=%v", epoch, err)
		}
		if _, err := journal.ClaimRevisionAdmissionCut(agreementDigest, claimID, uint64(challengeAt.Unix())); err == nil ||
			!strings.Contains(err.Error(), "epoch is frozen") {
			t.Fatalf("a fresh cut of the frozen revision epoch was not refused: %v", err)
		}
		if scenario == guarantorLateCandidateTimesOut {
			// No successor arrives: at its deadline the terminal fallback
			// replaces the challenged candidate, reusing the frozen epoch and
			// carrying the candidate's marker in place of a filing close.
			deadlineAt := time.Unix(int64(challenged.Receipt.Body.SuccessorDecisionDueAtUnix), 0).UTC()
			// The ordinary fallback's trigger is the head's own deadline: one
			// second before it the fallback is refused.
			authority.now = func() time.Time { return deadlineAt.Add(-time.Second) }
			if _, err := coordinator.AdmitInitialFallbackDecision(ctx, GuarantorAdmitInitialFallbackInput{
				AgreementDigest: agreementDigest, ClaimID: claimID}, lateFence); err == nil ||
				!strings.Contains(err.Error(), "Guarantor fallback deadline has not elapsed") {
				t.Fatalf("an ordinary fallback one second before the successor deadline was not refused: %v", err)
			}
			authority.now = func() time.Time { return deadlineAt }
			timedOut, err := coordinator.AdmitInitialFallbackDecision(ctx, GuarantorAdmitInitialFallbackInput{
				AgreementDigest: agreementDigest, ClaimID: claimID}, lateFence)
			if err != nil || timedOut.Receipt.Body.DecisionPath != "terminal_fallback" ||
				timedOut.Receipt.Body.PriorClaimState != "reviewing" ||
				timedOut.Receipt.Body.LateFilingCloseReceiptDigest != candidate.Receipt.Body.LateFilingCloseReceiptDigest {
				t.Fatalf("admit the terminal fallback at the late candidate's successor deadline: resolution=%#v err=%v",
					timedOut.Resolution, err)
			}
			body := timedOut.Receipt.Body
			if body.FrozenRevisionEpoch != candidate.Receipt.Body.FrozenRevisionEpoch ||
				body.FrozenRevisionEpochStateRevision != candidate.Receipt.Body.FrozenRevisionEpochStateRevision ||
				body.ClaimRevisionIngressCutProofDigest != candidate.Receipt.Body.ClaimRevisionIngressCutProofDigest {
				t.Fatalf("the terminal fallback did not reuse the late candidate's frozen epoch: %#v", body)
			}
			if err := guarantor.VerifyClaimDecisionAdmissionReceiptV1(timedOut.Receipt, terms, coordinator.AgreementVerifier,
				coordinator.resolverFor(agreementDigest), authority, deadlineAt); err != nil {
				t.Fatalf("the terminal fallback after the late candidate is not portable: %v", err)
			}
			// Without the candidate's marker, or with another digest in its
			// place, the same fallback is refused.
			for name, marker := range map[string]string{"removed": "",
				"changed": "sha256:" + strings.Repeat("7", 64)} {
				altered := timedOut.Receipt
				altered.Body.LateFilingCloseReceiptDigest = marker
				if err := guarantor.VerifyClaimDecisionAdmissionReceiptV1(altered, terms, coordinator.AgreementVerifier,
					coordinator.resolverFor(agreementDigest), authority, deadlineAt); err == nil ||
					!strings.Contains(err.Error(), "is not its late-recovery marker") {
					t.Fatalf("the terminal fallback with its marker %s was not refused: %v", name, err)
				}
			}
			// The journal keeps the fallback as the head, and reloads.
			if err := journal.Close(); err != nil {
				t.Fatal(err)
			}
			reloaded, err := OpenGuarantorJournal(journalDirectory, "owner:guarantor", "agent:guarantor")
			if err != nil {
				t.Fatalf("reload the journal after the terminal fallback: %v", err)
			}
			closeGuarantorJournalOnCleanup(t, reloaded)
			_, _, positions := testGuarantorSnapshot(t, reloaded)
			for index := range positions {
				if positions[index].Record.CoverageAgreementBodyDigest == agreementDigest &&
					!sameJSON(positions[index].DecisionAdmissionReceipts[claimID], timedOut.Receipt) {
					t.Fatal("the journal did not keep the terminal fallback as the claim head")
				}
			}
			return
		}

		// The approved successor reuses the frozen epoch and carries the
		// candidate's marker.
		successorAt := challengeAt.Add(10 * time.Second)
		authority.now = func() time.Time { return successorAt }
		candidateDecisionDigest, _ := guarantor.ClaimDecisionDigestV1(candidate.Receipt.AuthorizedClaimDecision)
		successorPolicy := policyApplication
		successorPolicy.DecisionPath = "successor"
		successorPolicyDigest, _ := guarantor.ClaimDecisionPolicyApplicationDigestV1(successorPolicy)
		successorBody := guarantor.ClaimDecisionBodyV1{SchemaVersion: 1, ClaimID: claimID,
			CoverageAgreementBodyDigest: agreementDigest, CoverageObligationID: "obligation:coverage",
			AuthorizedClaimEnvelopeDigest: claimEnvelopeDigest, DecisionSequence: 2, DecisionRevision: 1,
			PredecessorAuthorizedClaimDecisionDigest: candidateDecisionDigest,
			DecisionPath:                             "successor", ExpectedClaimRevision: claim.Body.ClaimRevision, DecisionProfile: decisionProfile,
			DecisionAuthoritySubjects: []string{"agent:guarantor"}, DecisionQuorumRule: "all",
			Result: guarantor.DecisionApproved, ApprovedAmount: commerce.AtomicAmountV1{Asset: asset, AmountAtomic: "400"},
			EvidenceSetDigest: decisionEvidenceDigest, PolicyApplicationDigest: successorPolicyDigest,
			ReasonDigest: decisionReasonDigest,
			PayoutLines: []guarantor.ClaimPayoutLineV1{{DecisionLineIndex: 1,
				Amount: commerce.AtomicAmountV1{Asset: asset, AmountAtomic: "400"}, PayoutDestinationDigest: destinationDigest,
				NotBeforeAfterTerminalCloseSeconds: 0, DueAfterTerminalCloseSeconds: 30,
				ExpiresAfterTerminalCloseSeconds: 90}}, ChallengeWindowSeconds: 60,
			DecidedAtUnix: uint64(successorAt.Unix()), ExpiresAtUnix: uint64(successorAt.Add(10 * time.Minute).Unix())}
		successorBodyDigest, _ := guarantor.ClaimDecisionBodyDigestV1(successorBody, terms)
		successorAuthorization, err := guarantor.SignObjectAuthorization(ctx, guarantor.AuthorizationStatementV1{
			SchemaVersion: 1, AuthoritySubject: "agent:guarantor", ProfileURI: decisionProfile.ProfileURI,
			ProfileVersion: decisionProfile.ProfileVersion, ProfileDigest: decisionProfile.ProfileDigest,
			AuthorizedObjectKind: "claim-decision", AuthorizedBodyDigest: successorBodyDigest,
			ValidationTimeUnix: uint64(successorAt.Unix())}, "tos.service.agent-guarantor-claim-decision-signature.v1",
			testAuthorityCustody, testGuarantorController(guarantorKey.Public().(ed25519.PublicKey)), []byte("guarantor-history"))
		if err != nil {
			t.Fatal(err)
		}
		successor, err := coordinator.AdmitClaimDecision(ctx, GuarantorAdmitDecisionInput{AgreementDigest: agreementDigest,
			Decision: guarantor.AuthorizedClaimDecisionV1{Body: successorBody, PolicyApplication: successorPolicy,
				DecisionReason: decisionReason, DecisionEvidenceSet: decisionEvidence,
				Authorizations: []guarantor.ProfileQualifiedObjectAuthorizationV1{successorAuthorization}}}, lateFence)
		if err != nil || successor.Receipt.Body.AdmittedClaimState != "approved" ||
			successor.Receipt.Body.LateFilingCloseReceiptDigest != filingDigest {
			t.Fatalf("admit the late-recovery successor: resolution=%#v err=%v", successor.Resolution, err)
		}

		// The late path allows one challenge round: the successor is final.
		// OpenFox refuses before building the action; its own error, distinct
		// from the protocol verifier's, shows that check ran.
		secondChallengeAt := successorAt.Add(10 * time.Second)
		authority.now = func() time.Time { return secondChallengeAt }
		if _, err := coordinator.TransitionClaimDecision(ctx, GuarantorTransitionClaimInput{
			AgreementDigest: agreementDigest, DecisionAdmissionReceipt: successor.Receipt,
			TransitionKind: "challenge_admission"}, lateFence); err == nil ||
			!strings.Contains(err.Error(), "Guarantor late-recovery successor cannot be challenged") {
			t.Fatalf("OpenFox did not refuse a second challenge on the late-recovery path: %v", err)
		}

		// It closes and is applied, with its payout due after the terminal
		// resolution deadline and within the late-recovery deadline.
		closeAt := successorAt.Add(time.Duration(terms.ChallengeWindowSeconds+1) * time.Second)
		authority.now = func() time.Time { return closeAt }
		closed, err := coordinator.TransitionClaimDecision(ctx, GuarantorTransitionClaimInput{
			AgreementDigest: agreementDigest, DecisionAdmissionReceipt: successor.Receipt, TransitionKind: "challenge_close"}, lateFence)
		if err != nil || closed.Receipt.Body.ResultingClaimState != "final_approved" {
			t.Fatalf("close the late-recovery successor: resolution=%#v err=%v", closed.Resolution, err)
		}
		applied, err := coordinator.ApplyClaimDecision(ctx, GuarantorApplyDecisionInput{AgreementDigest: agreementDigest,
			DecisionAdmissionReceipt: successor.Receipt, TerminalTransitionReceipt: closed.Receipt}, lateFence)
		if err != nil || applied.Resolution.State != commerce.ActionTerminal || len(applied.Payouts.Obligations) != 1 {
			t.Fatalf("apply the late-recovery successor: resolution=%#v err=%v", applied.Resolution, err)
		}
		payout := applied.Payouts.Obligations[0]
		if payout.ExpiresAtUnix <= terms.TerminalResolutionDeadlineUnix || payout.ExpiresAtUnix > terms.LateRecoveryTerminalDeadlineUnix {
			t.Fatalf("late payout expiry %d is outside (%d, %d]", payout.ExpiresAtUnix,
				terms.TerminalResolutionDeadlineUnix, terms.LateRecoveryTerminalDeadlineUnix)
		}

		// The payout is made within its window, and the coverage closes with a
		// terminal claim set holding the late-path decision.
		lateSink := &guarantorTestPaymentSink{now: func() time.Time { return authority.now() }}
		latePayouts := GuarantorPayoutService{Coordinator: &coordinator, Sink: lateSink,
			Verifier: validPaymentEvidence{}, Enabled: true}
		paid, paidResolution, paidRecord, err := latePayouts.Pay(ctx, agreementDigest, claimID,
			payout.ObligationInstanceID, "tos:test", lateFence)
		if err != nil || paidResolution.State != commerce.ActionTerminal || paidRecord.PayoutStatus != guarantor.PayoutPaid ||
			paid.ResolvedState != "finalized" {
			t.Fatalf("pay the late-path payout: state=%s err=%v", paidResolution.State, err)
		}
		lateClosedAt := authority.now()
		lateClose, err := coordinator.CloseCoverage(ctx, GuarantorCloseCoverageInput{Offer: offer,
			ActivationEvidence: activation}, lateFence)
		if err != nil || lateClose.CoverageResolution.Body.TerminalState != "closed" ||
			lateClose.ExposureRelease.Body.RealizedLoss.AmountAtomic != "400" {
			t.Fatalf("close the coverage after the late-recovery path: err=%v", err)
		}
		if err := guarantor.VerifyTerminalClaimSetV1(lateClose.TerminalClaimSet, offer, coordinator.AgreementVerifier,
			coordinator.resolverFor(agreementDigest), authority, coordinator.PaymentVerifier, lateClosedAt); err != nil {
			t.Fatalf("the terminal claim set holding the late-path decision does not verify: %v", err)
		}
		return
	}
	decisionBody := guarantor.ClaimDecisionBodyV1{SchemaVersion: 1, ClaimID: claimID,
		CoverageAgreementBodyDigest: agreementDigest, CoverageObligationID: "obligation:coverage",
		AuthorizedClaimEnvelopeDigest: claimEnvelopeDigest, DecisionSequence: 1, DecisionRevision: 1,
		DecisionPath: "initial", ExpectedClaimRevision: 2, DecisionProfile: decisionProfile,
		DecisionAuthoritySubjects: []string{"agent:guarantor"}, DecisionQuorumRule: "all",
		Result: guarantor.DecisionApproved, ApprovedAmount: commerce.AtomicAmountV1{Asset: asset, AmountAtomic: "400"},
		EvidenceSetDigest: decisionEvidenceDigest, PolicyApplicationDigest: policyApplicationDigest,
		ReasonDigest: decisionReasonDigest,
		PayoutLines: []guarantor.ClaimPayoutLineV1{{DecisionLineIndex: 1,
			Amount: commerce.AtomicAmountV1{Asset: asset, AmountAtomic: "400"}, PayoutDestinationDigest: destinationDigest,
			NotBeforeAfterTerminalCloseSeconds: 0, DueAfterTerminalCloseSeconds: 30,
			ExpiresAfterTerminalCloseSeconds: 90}}, ChallengeWindowSeconds: 60,
		DecidedAtUnix: uint64(decidedAt.Unix()), ExpiresAtUnix: uint64(decidedAt.Add(7 * time.Minute).Unix())}
	if disputed {
		// A nonterminal result carries no amount, payout or challenge window
		// and opens the Agreement's nonterminal resolution window instead.
		decisionBody.Result = guarantor.DecisionDisputed
		decisionBody.ApprovedAmount = commerce.AtomicAmountV1{Asset: asset, AmountAtomic: "0"}
		decisionBody.PayoutLines = nil
		decisionBody.ChallengeWindowSeconds = 0
		decisionBody.ResolutionWindowSeconds = terms.NonterminalResolutionWindowSeconds
	}
	decisionBodyDigest, _ := guarantor.ClaimDecisionBodyDigestV1(decisionBody, terms)
	decisionAuthorization, err := guarantor.SignObjectAuthorization(
		context.Background(),
		guarantor.AuthorizationStatementV1{
			SchemaVersion:        1,
			AuthoritySubject:     "agent:guarantor",
			ProfileURI:           decisionProfile.ProfileURI,
			ProfileVersion:       decisionProfile.ProfileVersion,
			ProfileDigest:        decisionProfile.ProfileDigest,
			AuthorizedObjectKind: "claim-decision",
			AuthorizedBodyDigest: decisionBodyDigest,
			ValidationTimeUnix:   uint64(decidedAt.Unix()),
		},
		"tos.service.agent-guarantor-claim-decision-signature.v1",
		testAuthorityCustody,
		testGuarantorController(guarantorKey.Public().(ed25519.PublicKey)),
		[]byte("guarantor-history"),
	)
	if err != nil {
		t.Fatal(err)
	}
	decision := guarantor.AuthorizedClaimDecisionV1{
		Body: decisionBody, PolicyApplication: policyApplication,
		DecisionReason: decisionReason, DecisionEvidenceSet: decisionEvidence,
		Authorizations: []guarantor.ProfileQualifiedObjectAuthorizationV1{decisionAuthorization}}
	authority.now = func() time.Time { return decisionAdmittedAt }
	decisionInput := GuarantorAdmitDecisionInput{AgreementDigest: agreementDigest, Decision: decision}
	decisionAdmission := requireCommittedGuarantorReceiptReplays(t, "admitting the claim decision", &coordinator,
		authority, restartWriter, 1, func() (GuarantorDecisionAdmissionResult, error) {
			return coordinator.AdmitClaimDecision(context.Background(), decisionInput, fence)
		}, func() error {
			other := decisionInput
			other.Decision.Body.DecidedAtUnix++
			_, otherErr := coordinator.AdmitClaimDecision(context.Background(), other, fence)
			return otherErr
		})
	wantAdmittedState := "approved"
	if disputed {
		wantAdmittedState = "disputed"
	}
	if err != nil || decisionAdmission.Resolution.State != commerce.ActionTerminal ||
		decisionAdmission.Receipt.Body.AdmittedClaimState != wantAdmittedState {
		t.Fatalf("admit claim decision: result=%#v err=%v", decisionAdmission.Resolution, err)
	}
	if scenario == guarantorLateFromReviewingFallback {
		// An ordinary challenge reopens revision ingress; filing then closes
		// late and the late-recovery fallback replaces the reviewing head.
		ctx := context.Background()
		challengeAt := time.Unix(int64(decisionAdmission.Receipt.Body.ChallengeStartsAtUnix)+1, 0).UTC()
		authority.now = func() time.Time { return challengeAt }
		challenged, err := coordinator.TransitionClaimDecision(ctx, GuarantorTransitionClaimInput{
			AgreementDigest: agreementDigest, DecisionAdmissionReceipt: decisionAdmission.Receipt,
			TransitionKind: "challenge_admission"}, fence)
		if err != nil || challenged.Receipt.Body.ResultingClaimState != "reviewing" {
			t.Fatalf("challenge the ordinary decision: resolution=%#v err=%v", challenged.Resolution, err)
		}
		reopened, err := journal.RevisionEpoch(agreementDigest, claimID)
		if err != nil || reopened.State != revisionEpochOpen {
			t.Fatalf("the ordinary challenge did not reopen revision ingress: %#v err=%v", reopened, err)
		}
		filing, lateFence, lateAt := lateFilingClose("instance:late-reviewing")
		filingDigest, _ := guarantor.ClaimFilingCloseReceiptDigestV1(*filing)
		fallbackAt := lateAt.Add(10 * time.Second)
		authority.now = func() time.Time { return fallbackAt }
		late, err := coordinator.AdmitInitialFallbackDecision(ctx, GuarantorAdmitInitialFallbackInput{
			AgreementDigest: agreementDigest, ClaimID: claimID, LateFilingReceipt: filing}, lateFence)
		if err != nil || late.Receipt.Body.DecisionPath != "late_recovery_terminal_fallback" ||
			late.Receipt.Body.PriorClaimState != "reviewing" || late.Receipt.Body.LateFilingCloseReceiptDigest != filingDigest ||
			late.Receipt.PredecessorClaimStateTransitionReceipt == nil {
			t.Fatalf("admit a late-recovery fallback from the reviewing head: resolution=%#v err=%v", late.Resolution, err)
		}
		if err := guarantor.VerifyClaimDecisionAdmissionReceiptV1(late.Receipt, terms, coordinator.AgreementVerifier,
			coordinator.resolverFor(agreementDigest), authority, fallbackAt); err != nil {
			t.Fatalf("the late fallback from the reviewing head is not portable: %v", err)
		}
		checkInitialAdmissionProof(late.Receipt, fallbackAt)
		frozen, err := journal.RevisionEpoch(agreementDigest, claimID)
		if err != nil || frozen.State != revisionEpochFrozen || frozen.Epoch != reopened.Epoch ||
			frozen.StateRevision != reopened.StateRevision+1 {
			t.Fatalf("the late fallback did not freeze the reopened epoch: %#v err=%v", frozen, err)
		}
		return
	}
	if disputed {
		head := decisionAdmission.Receipt.Body
		if head.ResolutionDueAtUnix == 0 {
			t.Fatal("disputed decision opened no resolution window")
		}
		if scenario == guarantorLateBeforeOrdinaryDeadline {
			ctx := context.Background()
			// The writer is acquired one second before the filing close, so the
			// refusal at that second is the trigger's and not a stale writer's.
			beforeClose := time.Unix(int64(terms.TerminalResolutionDeadlineUnix)+19, 0).UTC()
			authority.now = func() time.Time { return beforeClose }
			lateFence, err := authority.AcquireWriter(ctx, "instance:late-trigger", scope, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			closedAt := beforeClose.Add(time.Second)
			authority.now = func() time.Time { return closedAt }
			if _, closeErr := coordinator.CloseCoverage(ctx, GuarantorCloseCoverageInput{Offer: offer,
				ActivationEvidence: activation}, lateFence); closeErr == nil {
				t.Fatal("coverage closed with a disputed claim")
			}
			position, err := coordinator.coveragePosition(agreementDigest)
			if err != nil {
				t.Fatal(err)
			}
			filing := position.FilingCloseReceipt
			if filing == nil || filing.Body.ClosedAtUnix != uint64(closedAt.Unix()) ||
				filing.Body.ClosedAtUnix <= terms.TerminalResolutionDeadlineUnix ||
				filing.Body.ClosedAtUnix >= head.ResolutionDueAtUnix {
				t.Fatalf("the late filing close is not inside the disputed head's open resolution window: %#v due=%d",
					filing, head.ResolutionDueAtUnix)
			}
			lateInput := GuarantorAdmitInitialFallbackInput{AgreementDigest: agreementDigest, ClaimID: claimID,
				LateFilingReceipt: filing}
			// One second before the filing close the late trigger has not fired.
			authority.now = func() time.Time { return beforeClose }
			if _, err := coordinator.AdmitInitialFallbackDecision(ctx, lateInput, lateFence); err == nil ||
				!strings.Contains(err.Error(), "Guarantor fallback deadline has not elapsed") {
				t.Fatalf("a late-recovery fallback before its filing close was not refused by its trigger: %v", err)
			}
			// The ordinary fallback keeps its own trigger: at the filing close
			// the head's resolution deadline has not passed.
			authority.now = func() time.Time { return closedAt }
			if _, err := coordinator.AdmitInitialFallbackDecision(ctx, GuarantorAdmitInitialFallbackInput{
				AgreementDigest: agreementDigest, ClaimID: claimID}, lateFence); err == nil ||
				!strings.Contains(err.Error(), "Guarantor fallback deadline has not elapsed") {
				t.Fatalf("an ordinary fallback before the head's resolution deadline was not refused: %v", err)
			}
			// At the filing close the late-recovery fallback is admitted, with
			// the head's resolution deadline still ahead.
			late, err := coordinator.AdmitInitialFallbackDecision(ctx, lateInput, lateFence)
			if err != nil || late.Receipt.Body.DecisionPath != "late_recovery_terminal_fallback" ||
				late.Receipt.Body.PriorClaimState != "disputed" ||
				late.Receipt.Body.FallbackTriggerCutoffUnix != filing.Body.ClosedAtUnix ||
				late.Receipt.Body.AdmittedAtUnix != filing.Body.ClosedAtUnix ||
				late.Receipt.Body.AdmittedAtUnix >= head.ResolutionDueAtUnix {
				t.Fatalf("admit a late-recovery fallback at its filing close, before the head's resolution deadline: "+
					"resolution=%#v err=%v", late.Resolution, err)
			}
			if err := guarantor.VerifyClaimDecisionAdmissionReceiptV1(late.Receipt, terms, coordinator.AgreementVerifier,
				coordinator.resolverFor(agreementDigest), authority, closedAt); err != nil {
				t.Fatalf("the late fallback admitted at its filing close is not portable: %v", err)
			}
			return
		}
		if scenario == guarantorLateFromDisputedFallback {
			// Claim filing closes late while the claim is still disputed; the
			// late-recovery fallback replaces the disputed head in the journal.
			ctx := context.Background()
			lateAt := time.Unix(int64(terms.TerminalResolutionDeadlineUnix)+20, 0).UTC()
			authority.now = func() time.Time { return lateAt }
			lateFence, err := authority.AcquireWriter(ctx, "instance:late-disputed", scope, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			if _, closeErr := coordinator.CloseCoverage(ctx, GuarantorCloseCoverageInput{Offer: offer,
				ActivationEvidence: activation}, lateFence); closeErr == nil {
				t.Fatal("coverage closed with a disputed claim")
			}
			_, _, positions := testGuarantorSnapshot(t, journal)
			var filing *guarantor.AuthorizedClaimFilingCloseReceiptV1
			for index := range positions {
				if positions[index].Record.CoverageAgreementBodyDigest == agreementDigest {
					filing = positions[index].FilingCloseReceipt
				}
			}
			if filing == nil {
				t.Fatal("no late filing close was recorded")
			}
			late, err := coordinator.AdmitInitialFallbackDecision(ctx, GuarantorAdmitInitialFallbackInput{
				AgreementDigest: agreementDigest, ClaimID: claimID, LateFilingReceipt: filing}, lateFence)
			if err != nil || late.Receipt.Body.DecisionPath != "late_recovery_terminal_fallback" ||
				late.Receipt.Body.PriorClaimState != "disputed" ||
				late.Receipt.Body.NonterminalRoundsUsedAfter != head.NonterminalRoundsUsedAfter+1 {
				t.Fatalf("admit a late-recovery fallback from the disputed head: resolution=%#v err=%v", late.Resolution, err)
			}
			checkInitialAdmissionProof(late.Receipt, authority.now())
			_, _, positions = testGuarantorSnapshot(t, journal)
			for index := range positions {
				if positions[index].Record.CoverageAgreementBodyDigest == agreementDigest &&
					!sameJSON(positions[index].DecisionAdmissionReceipts[claimID], late.Receipt) {
					t.Fatal("the journal did not replace the disputed head with the late-recovery fallback")
				}
			}
			return
		}
		fallbackReceipt := exerciseFallback(time.Unix(int64(head.ResolutionDueAtUnix)+1, 0).UTC(), "terminal_fallback")
		epoch := fallbackReceipt.Body
		if epoch.FrozenRevisionEpoch != head.FrozenRevisionEpoch ||
			epoch.FrozenRevisionEpochStateRevision != head.FrozenRevisionEpochStateRevision ||
			epoch.ClaimRevisionIngressCutProofDigest != head.ClaimRevisionIngressCutProofDigest ||
			epoch.NonterminalRoundsUsedAfter != head.NonterminalRoundsUsedAfter+1 {
			t.Fatalf("disputed fallback did not reuse the frozen epoch or consume its round: head=%#v fallback=%#v", head, epoch)
		}
		return
	}
	authority.now = func() time.Time { return now.Add(5 * time.Minute) }
	closeInput := GuarantorTransitionClaimInput{
		AgreementDigest: agreementDigest, DecisionAdmissionReceipt: decisionAdmission.Receipt,
		TransitionKind: "challenge_close",
	}
	terminalTransition := requireCommittedGuarantorReceiptReplays(t, "closing the claim challenge", &coordinator,
		authority, restartWriter, 1, func() (GuarantorClaimTransitionResult, error) {
			return coordinator.TransitionClaimDecision(context.Background(), closeInput, fence)
		}, func() error {
			other := closeInput
			other.TransitionKind = "challenge_admission"
			_, otherErr := coordinator.TransitionClaimDecision(context.Background(), other, fence)
			return otherErr
		})
	if terminalTransition.Resolution.State != commerce.ActionTerminal ||
		terminalTransition.Receipt.Body.ResultingClaimState != "final_approved" {
		t.Fatalf("close claim challenge: result=%#v err=%v", terminalTransition, err)
	}
	// Guarantor objects are measured under the Guarantor codec limits.
	admissionWire, admissionErr := guarantor.Canonical(decisionAdmission.Receipt)
	transitionWire, transitionErr := guarantor.Canonical(terminalTransition.Receipt)
	if admissionErr != nil || transitionErr != nil {
		t.Fatalf("encode portable Guarantor decision: %v %v", admissionErr, transitionErr)
	}
	t.Logf("portable Guarantor decision admission=%d transition=%d bytes", len(admissionWire), len(transitionWire))
	applyInput := GuarantorApplyDecisionInput{
		AgreementDigest: agreementDigest, DecisionAdmissionReceipt: decisionAdmission.Receipt,
		TerminalTransitionReceipt: terminalTransition.Receipt,
	}
	application := requireCommittedGuarantorReceiptReplays(t, "applying the claim decision", &coordinator,
		authority, restartWriter, 1, func() (GuarantorDecisionApplicationResult, error) {
			return coordinator.ApplyClaimDecision(context.Background(), applyInput, fence)
		}, nil)
	payouts, resolution := application.Payouts, application.Resolution
	if resolution.State != commerce.ActionTerminal || len(payouts.Obligations) != 1 ||
		payouts.Obligations[0].Amount.AmountAtomic != "400" || application.Receipt.Body.ResultingApplicationTokenState != "consumed" {
		t.Fatalf("apply claim decision: result=%#v err=%v", application, err)
	}
	applicationWire, err := guarantor.Canonical(application.Receipt)
	if err != nil || len(applicationWire) > guarantor.MaxCanonicalObjectBytes {
		t.Fatalf("portable decision application exceeds the complete-object ceiling: bytes=%d err=%v", len(applicationWire), err)
	}
	paymentSink := &guarantorTestPaymentSink{now: func() time.Time { return authority.now() }}
	payoutService := GuarantorPayoutService{Coordinator: &coordinator,
		Sink: paymentSink, Verifier: validPaymentEvidence{}, Enabled: true,
		FailureInjector: func(point string) error {
			if point == "after_external_payout_before_terminal_commit" {
				return errors.New("injected crash after external payout")
			}
			return nil
		}}
	_, crashResolution, _, crashErr := payoutService.Pay(context.Background(), agreementDigest, claimID,
		payouts.Obligations[0].ObligationInstanceID, "tos:test", fence)
	if crashErr == nil || crashResolution.State != commerce.ActionSubmitted || paymentSink.submissions != 1 {
		t.Fatalf("payout crash boundary was not retained: state=%s submissions=%d err=%v",
			crashResolution.State, paymentSink.submissions, crashErr)
	}
	payoutService.FailureInjector = nil
	paymentEvidence, resolution, claimRecord, err := payoutService.Pay(context.Background(),
		agreementDigest, claimID, payouts.Obligations[0].ObligationInstanceID, "tos:test", fence)
	if err != nil || resolution.State != commerce.ActionTerminal || claimRecord.PayoutStatus != guarantor.PayoutPaid ||
		paymentEvidence.ResolvedState != "finalized" || paymentSink.submissions != 1 {
		t.Fatalf("pay claim: state=%s claim=%#v evidence=%#v err=%v", resolution.State, claimRecord, paymentEvidence, err)
	}
	// Exact replay is resolved by the authority and journal rather than moving
	// value or incrementing the paid aggregate a second time.
	replayEvidence, replayResolution, replayRecord, replayErr := payoutService.Pay(context.Background(),
		agreementDigest, claimID, payouts.Obligations[0].ObligationInstanceID, "tos:test", fence)
	if replayErr != nil || replayResolution.State != commerce.ActionTerminal || replayRecord.PayoutStatus != guarantor.PayoutPaid ||
		replayEvidence.ExactTransferReference != paymentEvidence.ExactTransferReference || paymentSink.submissions != 1 {
		t.Fatalf("terminal payout replay was not recovered exactly: state=%s record=%#v err=%v", replayResolution.State, replayRecord, replayErr)
	}
	authority.now = func() time.Time { return now.Add(45 * time.Minute) }
	crash := &oneShotGuarantorClosureFailure{target: "exposure_release_plan_prepared"}
	coordinator.ClosureFailureInjector = crash
	partialClose, partialCloseErr := coordinator.CloseCoverage(context.Background(), GuarantorCloseCoverageInput{Offer: offer,
		ActivationEvidence: activation}, fence)
	if partialCloseErr == nil || partialClose.TerminalClaimSet.Body.SchemaVersion != 1 || !crash.fired {
		t.Fatalf("closure crash checkpoint did not leave a recoverable portable predecessor: err=%v", partialCloseErr)
	}
	_, _, crashPositions := testGuarantorSnapshot(t, journal)
	var frozenReleasePlan *GuarantorExposureReleasePlan
	for index := range crashPositions {
		if crashPositions[index].Record.CoverageAgreementBodyDigest == agreementDigest {
			frozenReleasePlan = crashPositions[index].ExposureReleasePlan
		}
	}
	if frozenReleasePlan == nil {
		t.Fatal("closure crash did not persist its exact exposure-release plan")
	}
	frozenReleaseActionID, frozenReleaseRequest := frozenReleasePlan.Action.StableActionID,
		frozenReleasePlan.Action.ExactRequestDigest
	coordinator.ClosureFailureInjector = nil
	// The process restarts after the crash. The journal is opened again from
	// disk and holds nothing of the journal that stored the plan, so recovery
	// resumes from what the document alone carries. A document whose plan was
	// changed, or whose terminal claim set or reservation is no longer the one
	// the plan releases for, is refused.
	journal = restartTestGuarantorJournal(t, journal, journalDirectory, agreementDigest,
		tamperedTestExposureReleasePlan(t))
	coordinator.Journal = journal
	if scenario == guarantorNoFallback {
		checkGuarantorJournalCommitsFromACopy(t, journal, journalDirectory)
	}
	// A reauthorization may replace only the authorization of the stored plan.
	requireExposureReleaseReauthorizationRefusesAChangedPlan(t, journal, agreementDigest)
	// A different writer generation takes over after the crash. Recovery must
	// reauthorize the exact same release/resolution semantics rather than mint a
	// successor identity or relying on the predecessor writer lease.
	recoveryFence, err := authority.AcquireWriter(context.Background(), "instance:recovery", scope, time.Hour)
	if err != nil || recoveryFence.Body.WriterGeneration <= fence.Body.WriterGeneration {
		t.Fatalf("acquire recovery writer fence: fence=%#v err=%v", recoveryFence, err)
	}
	fence = recoveryFence
	closed, err := coordinator.CloseCoverage(context.Background(), GuarantorCloseCoverageInput{Offer: offer,
		ActivationEvidence: activation}, fence)
	if err != nil || closed.CoverageResolution.Body.TerminalState != "closed" ||
		closed.ExposureRelease.Body.State != "released" || closed.TerminalClaimSet.Body.AdmissionHighWater != 1 {
		t.Fatalf("close coverage: result=%#v err=%v", closed, err)
	}
	if closed.ExposureRelease.Body.StableActionID != frozenReleaseActionID ||
		closed.ExposureRelease.Body.ExactRequestDigest != frozenReleaseRequest ||
		closed.ExposureRelease.Body.WriterGeneration != fence.Body.WriterGeneration {
		t.Fatal("takeover changed release semantics or failed to bind the current writer generation")
	}
	replayedCoverageClose, replayCloseErr := coordinator.CloseCoverage(context.Background(), GuarantorCloseCoverageInput{Offer: offer,
		ActivationEvidence: activation}, fence)
	if replayCloseErr != nil || !sameJSON(replayedCoverageClose, closed) {
		t.Fatalf("terminal coverage closure did not replay byte-identically: err=%v", replayCloseErr)
	}
	if closed.ExposureRelease.Body.RealizedLoss.AmountAtomic != "400" ||
		closed.ExposureRelease.Body.ReturnedToAvailableExposure.AmountAtomic != "600" ||
		closed.ExposureRelease.Body.RetainedDefaultedLiability.AmountAtomic != "0" ||
		closed.ExposureRelease.Body.PortfolioDisposition != "mixed" {
		t.Fatalf("paid payout was incorrectly restored as underwriting capacity: %#v", closed.ExposureRelease.Body)
	}
	for name, envelope := range map[string]any{"terminal claim set": closed.TerminalClaimSet,
		"exposure release": closed.ExposureRelease, "coverage resolution": closed.CoverageResolution} {
		wire, encodeErr := guarantor.Canonical(envelope)
		t.Logf("portable %s=%d bytes", name, len(wire))
		if encodeErr != nil || len(wire) > guarantor.MaxCanonicalObjectBytes {
			t.Fatalf("portable %s exceeds the complete-object ceiling: bytes=%d err=%v", name, len(wire), encodeErr)
		}
	}
	forgedTerminal := closed.TerminalClaimSet
	forgedTerminal.ClaimResolutionBundles = append([]guarantor.ClaimTerminalResolutionBundleV1(nil), closed.TerminalClaimSet.ClaimResolutionBundles...)
	forgedBundle := &forgedTerminal.ClaimResolutionBundles[0]
	forgedBundle.MaterializedPayoutObligationSet.MaterializationState = "not_applicable"
	forgedBundle.MaterializedPayoutObligationSet.MaterializedLines = nil
	forgedBundle.MaterializedPayoutObligationSet.Obligations = nil
	forgedBundle.TerminalPayoutEvidenceSet.PayoutExecutionEvidence = nil
	forgedBundle.TerminalPayoutEvidenceSet.Disposition = "not_applicable"
	forgedTerminal.Body.ClaimResolutions = []guarantor.ClaimTerminalResolutionRefV1{forgedBundle.ResolutionRef}
	forgedTerminal.Body.CumulativePaidAmount.AmountAtomic = "0"
	if guarantor.ValidateTerminalClaimSetV1(forgedTerminal) == nil {
		t.Fatal("approved claim closed with an empty payout set and no payment evidence")
	}
	defaultedTerminal := closed.TerminalClaimSet
	defaultedTerminal.Body.CumulativePaidAmount.AmountAtomic = "0"
	defaultedTerminal.Body.CumulativeDefaultedAmount.AmountAtomic = "400"
	defaultedTerminal.Body.CoverageClosureReason = "terminal_default"
	defaultedTerminal.Body.ResolutionTargetTerminalState = "defaulted"
	defaultDisposition, err := guarantor.ComputeExposureDispositionV1(offer.ExposureAdmissionReceipt,
		defaultedTerminal.Body)
	if err != nil || defaultDisposition.ReturnedToAvailableExposure.AmountAtomic != "600" ||
		defaultDisposition.RealizedLoss.AmountAtomic != "0" ||
		defaultDisposition.RetainedDefaultedLiability.AmountAtomic != "400" ||
		defaultDisposition.PortfolioDisposition != "mixed" {
		t.Fatalf("retained terminal default restored unsafe underwriting capacity: disposition=%#v err=%v", defaultDisposition, err)
	}
	tamperedResolution := closed.CoverageResolution
	tamperedResolution.StageActionAdmissionEvidence.CanonicalRequest[0] ^= 1
	if err := guarantor.VerifyCoverageResolutionV1(tamperedResolution, offer, coordinator.AgreementVerifier,
		coordinator.Resolver, coordinator.Authority, coordinator.PaymentVerifier, authority.now()); err == nil {
		t.Fatal("coverage-resolution verifier accepted a request that no longer binds its exposure-release digest")
	}
	_, _, coverages = testGuarantorSnapshot(t, journal)
	if coverages[0].Record.CoverageStatus != guarantor.CoverageClosed ||
		coverages[0].Record.ClaimFilingStatus != guarantor.FilingFrozen {
		t.Fatalf("coverage did not close after portable release evidence: %#v", coverages[0].Record)
	}
	_, _, reservations := authority.Snapshot()
	if len(reservations) != 2 || !reservations[0].Released || !reservations[1].Released {
		t.Fatalf("provider exposure remained reserved after terminal closure: %#v", reservations)
	}
	// A separately accepted offer that receives no activation admission is
	// closed by an objective, portable zero-admission cut. This exercises the
	// non-activation branch without weakening the normal claim/close scenario.
	// Keep this second lifecycle on the same logical clock. Race instrumentation
	// makes the maximum-envelope path much slower than these deliberately short
	// protocol expiries, but wall-clock duration is not lifecycle evidence.
	authority.now = func() time.Time { return now }
	fence, err = authority.AcquireWriter(context.Background(), "instance:post-recovery", scope, time.Hour)
	if err != nil {
		t.Fatalf("acquire post-recovery writer fence: %v", err)
	}
	nonActivationRequestBody := requestBody
	nonActivationRequestBody.RequestID = "request:coverage:non-activation"
	nonActivationRequestBody.CreatedAtUnix = uint64(now.Add(2 * time.Second).Unix())
	nonActivationQuote := signGuarantorTestQuote(t, nonActivationRequestBody, requested,
		ref("d", "request-authority"), coveredKey)
	nonActivationAgreement := agreement
	nonActivationAgreement.AuthorizationPredicates = append([]commerce.AgreementAuthorizationPredicate(nil), agreement.AuthorizationPredicates...)
	nonActivationAgreement.AgreementID = "agreement:coverage:non-activation"
	for index := range nonActivationAgreement.AuthorizationPredicates {
		nonActivationAgreement.AuthorizationPredicates[index].EvidenceTargetProjectionDigest = ""
	}
	nonActivationAgreement, err = commerce.PrepareAgreementTargets(nonActivationAgreement)
	if err != nil {
		t.Fatal(err)
	}
	nonActivationAgreementDigest, _ := commerce.AgreementBodyDigest(nonActivationAgreement)
	nonActivationTerms := terms
	nonActivationTerms.CoverageID = digest("f")
	nonActivationTerms.QuoteRequestDigest = mustGuarantorQuoteDigest(t, nonActivationQuote)
	nonActivationTerms.CoverageStateDomainDigest = digest("e")
	nonActivationOffer, nonActivationResolution, err := coordinator.IssueFirmOffer(context.Background(), GuarantorIssueOfferInput{
		Request: nonActivationQuote, ProfileArtifact: profileArtifact, Agreement: nonActivationAgreement,
		Terms: nonActivationTerms, CoverageObligationID: "obligation:coverage", IssuedAtUnix: uint64(now.Add(2 * time.Second).Unix()),
		AcceptByUnix: uint64(now.Add(time.Minute).Unix()), ReservationExpiresAtUnix: uint64(now.Add(6 * time.Minute).Unix()),
		ExpiresAtUnix: uint64(now.Add(10 * time.Minute).Unix())}, fence)
	if err != nil || nonActivationResolution.State != commerce.ActionTerminal {
		t.Fatalf("issue non-activation offer: state=%s err=%v", nonActivationResolution.State, err)
	}
	nonActivationAcceptance := signGuarantorTestAcceptance(t, nonActivationAgreement, nonActivationOffer,
		"agent:covered", map[string]ed25519.PrivateKey{"agent:covered": coveredKey, "agent:guarantor": guarantorKey},
		commerce.ProfileRefV1{ProfileURI: commerce.EvidenceProfileAgentSignature, ProfileVersion: 1,
			ProfileDigest: agreementProfile}, underlyingResolver, baseAgreementVerifier,
		now.Add(30*time.Second), now.Add(90*time.Second))
	// This acceptance makes four journal commits: the admission, its plan,
	// the acceptance itself and the recorded terminal result. The first two
	// are written undisturbed; the acceptance and the recorded result each
	// lose their directory sync once. The coordinator reports each one and
	// stops. The acceptance that is in the journal is never rejected, the
	// call that only records the terminal result is not returned as a plain
	// success, and the acceptance is returned once, from the journal, when
	// every commit is confirmed.
	acceptSyncLoss := &journalSyncLossFault{skip: 2, remaining: 2}
	removeAcceptSyncLoss := acceptSyncLoss.install(journal)
	rejections := &rejectionCountingAuthority{EconomicAuthority: coordinator.Authority}
	coordinator.Authority = rejections
	var nonActivationReceipt guarantor.AuthorizedCoverageAcceptanceReceiptV1
	var unsyncedAcceptances []guarantor.AuthorizedCoverageAcceptanceReceiptV1
	acceptStops := repeatUntilTestGuarantorCommitsAreSynced(t, acceptSyncLoss, "accepting the coverage", func() error {
		var acceptErr error
		nonActivationReceipt, nonActivationResolution, acceptErr = coordinator.AcceptCoverage(context.Background(),
			GuarantorAcceptCoverageInput{
				Offer: nonActivationOffer, Request: nonActivationAcceptance,
				CoverageObligationID: "obligation:coverage", ReceivedAtUnix: uint64(now.Add(30 * time.Second).Unix()),
			}, fence)
		if acceptErr != nil && nonActivationReceipt.Body.SchemaVersion != 0 {
			unsyncedAcceptances = append(unsyncedAcceptances, nonActivationReceipt)
		}
		return acceptErr
	})
	removeAcceptSyncLoss()
	coordinator.Authority = rejections.EconomicAuthority
	if acceptStops != 2 || acceptSyncLoss.lost != 2 || rejections.rejections != 0 {
		t.Fatalf("accepting the coverage stopped %d times for %d commits that lost their sync and asked for "+
			"%d rejections, want 2, 2 and none", acceptStops, acceptSyncLoss.lost, rejections.rejections)
	}
	// The acceptance was reported with its receipt when its own commit lost
	// its sync and again when recording the terminal result did; both are the
	// receipt finally returned.
	if len(unsyncedAcceptances) != 2 || !sameJSON(unsyncedAcceptances[0], nonActivationReceipt) ||
		!sameJSON(unsyncedAcceptances[1], nonActivationReceipt) {
		t.Fatalf("the acceptance reported with a lost sync is not the one returned: %d reported",
			len(unsyncedAcceptances))
	}
	if nonActivationResolution.State != commerce.ActionTerminal {
		t.Fatalf("accept non-activation coverage: state=%s", nonActivationResolution.State)
	}
	nonActivationInput := GuarantorConfirmNonActivationInput{Offer: nonActivationOffer, AcceptanceReceipt: nonActivationReceipt,
		ResolvedAtUnix: nonActivationTerms.CoverageStartsAtUnix}
	coordinator.Authority = &failAfterTerminalEconomicAuthority{EconomicAuthority: baseAuthority, failOnce: true}
	if _, _, crashErr := coordinator.ConfirmActivationWindowExpired(context.Background(), nonActivationInput, fence); crashErr == nil {
		t.Fatal("non-activation did not surface the injected post-terminal crash")
	}
	nonActivationEvidence, nonActivationResolution, err := coordinator.ConfirmActivationWindowExpired(context.Background(),
		nonActivationInput, fence)
	if err != nil || nonActivationResolution.State != commerce.ActionTerminal ||
		nonActivationEvidence.Body.Reason != "activation_window_expired" || nonActivationEvidence.Body.ActivationAdmissionHighWater != 0 {
		t.Fatalf("confirm non-activation: state=%s body=%#v err=%v", nonActivationResolution.State, nonActivationEvidence.Body, err)
	}
	replayedNonActivation, replayResolution, replayErr := coordinator.ConfirmActivationWindowExpired(context.Background(),
		nonActivationInput, fence)
	if replayErr != nil || replayResolution.State != commerce.ActionTerminal || !sameJSON(replayedNonActivation, nonActivationEvidence) {
		t.Fatalf("non-activation replay was not exact: state=%s err=%v", replayResolution.State, replayErr)
	}
	_, _, allCoverages := testGuarantorSnapshot(t, journal)
	var foundNonActivation bool
	for _, candidate := range allCoverages {
		foundNonActivation = foundNonActivation || candidate.Record.CoverageAgreementBodyDigest == nonActivationAgreementDigest &&
			candidate.Record.CoverageStatus == guarantor.CoverageNotActivatedConfirmed
	}
	if !foundNonActivation {
		t.Fatal("non-activated coverage was not durably projected")
	}
	nonActivationRelease, nonActivationReleaseResolution, err := coordinator.ReleaseNonActivatedExposure(
		context.Background(), nonActivationOffer, nonActivationEvidence, fence)
	if err != nil || nonActivationReleaseResolution.State != commerce.ActionTerminal ||
		nonActivationRelease.Body.RemainingReservedExposure.AmountAtomic != "0" {
		t.Fatalf("release non-activated exposure: state=%s body=%#v err=%v",
			nonActivationReleaseResolution.State, nonActivationRelease.Body, err)
	}
	replayedNonActivationRelease, replayReleaseResolution, replayReleaseErr := coordinator.ReleaseNonActivatedExposure(
		context.Background(), nonActivationOffer, nonActivationEvidence, fence)
	if replayReleaseErr != nil || replayReleaseResolution.State != commerce.ActionTerminal ||
		!sameJSON(replayedNonActivationRelease, nonActivationRelease) {
		t.Fatalf("non-activation release replay was not exact: state=%s err=%v", replayReleaseResolution.State, replayReleaseErr)
	}

	// Active cancellation is a separate Agreement-selected branch. It binds the
	// requester's exact profile, timing, prior scheduled end commitment and
	// admission evidence, and exact replay returns the same signed receipt.
	cancellationRequestBody := requestBody
	cancellationRequestBody.RequestID = "request:coverage:cancellation"
	cancellationRequestBody.CreatedAtUnix = uint64(now.Add(3 * time.Second).Unix())
	cancellationQuote := signGuarantorTestQuote(t, cancellationRequestBody, requested,
		ref("d", "request-authority"), coveredKey)
	cancellationAgreement := agreement
	cancellationAgreement.AuthorizationPredicates = append([]commerce.AgreementAuthorizationPredicate(nil), agreement.AuthorizationPredicates...)
	cancellationAgreement.AgreementID = "agreement:coverage:cancellation"
	for index := range cancellationAgreement.AuthorizationPredicates {
		cancellationAgreement.AuthorizationPredicates[index].EvidenceTargetProjectionDigest = ""
	}
	cancellationAgreement, err = commerce.PrepareAgreementTargets(cancellationAgreement)
	if err != nil {
		t.Fatal(err)
	}
	cancellationAgreementDigest, _ := commerce.AgreementBodyDigest(cancellationAgreement)
	cancellationTerms := terms
	cancellationTerms.CoverageID = digest("d")
	cancellationTerms.QuoteRequestDigest = mustGuarantorQuoteDigest(t, cancellationQuote)
	cancellationTerms.CoverageStateDomainDigest = digest("c")
	cancellationOffer, cancellationResolution, err := coordinator.IssueFirmOffer(context.Background(), GuarantorIssueOfferInput{
		Request: cancellationQuote, ProfileArtifact: profileArtifact, Agreement: cancellationAgreement,
		Terms: cancellationTerms, CoverageObligationID: "obligation:coverage", IssuedAtUnix: uint64(now.Add(3 * time.Second).Unix()),
		AcceptByUnix: uint64(now.Add(time.Minute).Unix()), ReservationExpiresAtUnix: uint64(now.Add(6 * time.Minute).Unix()),
		ExpiresAtUnix: uint64(now.Add(10 * time.Minute).Unix())}, fence)
	if err != nil || cancellationResolution.State != commerce.ActionTerminal {
		t.Fatalf("issue cancellable offer: state=%s err=%v", cancellationResolution.State, err)
	}
	cancellationAcceptance := signGuarantorTestAcceptance(t, cancellationAgreement, cancellationOffer,
		"agent:covered", map[string]ed25519.PrivateKey{"agent:covered": coveredKey, "agent:guarantor": guarantorKey},
		commerce.ProfileRefV1{ProfileURI: commerce.EvidenceProfileAgentSignature, ProfileVersion: 1,
			ProfileDigest: agreementProfile}, underlyingResolver, baseAgreementVerifier,
		now.Add(35*time.Second), now.Add(95*time.Second))
	cancellationAcceptanceReceipt, cancellationResolution, err := coordinator.AcceptCoverage(context.Background(),
		GuarantorAcceptCoverageInput{Offer: cancellationOffer, Request: cancellationAcceptance,
			CoverageObligationID: "obligation:coverage", ReceivedAtUnix: uint64(now.Add(35 * time.Second).Unix())}, fence)
	if err != nil || cancellationResolution.State != commerce.ActionTerminal {
		t.Fatalf("accept cancellable coverage: state=%s err=%v", cancellationResolution.State, err)
	}
	cancellationPrerequisites := activationPrerequisites
	cancellationPrerequisites.ContextDigest = cancellationAgreementDigest
	cancellationActivation, cancellationResolution, err := coordinator.ActivateCoverage(context.Background(),
		GuarantorActivateCoverageInput{Offer: cancellationOffer, AcceptanceReceipt: cancellationAcceptanceReceipt,
			UnderlyingAgreement: underlying, UnderlyingAuthorizationEvidence: guarantor.GuarantorAgreementAuthorizationEvidenceSetV1{
				SchemaVersion: 1, AgreementID: underlying.AgreementID, AgreementVersion: underlying.Version,
				AgreementBodyDigest: underlyingDigest, Evidence: []commerce.AgreementAuthorizationEvidence{underlyingEvidence}},
			PrerequisiteEvidenceSet: &cancellationPrerequisites, ActivatedAtUnix: cancellationTerms.CoverageStartsAtUnix}, fence)
	if err != nil || cancellationResolution.State != commerce.ActionTerminal {
		t.Fatalf("activate cancellable coverage: state=%s err=%v", cancellationResolution.State, err)
	}
	cancellationPolicyDigest, _ := guarantor.CoverageCancellationPolicyDigestV1(cancellationPolicy)
	cancelCreated := now.Add(2*time.Minute + 10*time.Second)
	cancelBody := guarantor.CoverageCancellationRequestBodyV1{SchemaVersion: 1,
		CoverageAgreementBodyDigest: cancellationAgreementDigest, CoverageObligationID: "obligation:coverage",
		CancellationPolicyDigest: cancellationPolicyDigest, CancellationBranch: "covered-party-request",
		RequesterSubject: "agent:covered", EffectiveNotBeforeUnix: uint64(cancelCreated.Unix()),
		EffectiveNotAfterUnix: uint64(cancelCreated.Add(30 * time.Second).Unix()), CreatedAtUnix: uint64(cancelCreated.Unix()),
		ExpiresAtUnix: uint64(cancelCreated.Add(45 * time.Second).Unix())}
	cancelBodyDigest, _ := codec.Digest("tos.service.agent-guarantor-cancellation-request-body.v1", cancelBody)
	cancelAuthorization, err := guarantor.SignObjectAuthorization(
		context.Background(),
		guarantor.AuthorizationStatementV1{
			SchemaVersion:    1,
			AuthoritySubject: "agent:covered", ProfileURI: commerce.EvidenceProfileAgentSignature, ProfileVersion: 1,
			ProfileDigest: agreementProfile, AuthorizedObjectKind: "coverage-cancellation-request",
			AuthorizedBodyDigest: cancelBodyDigest, ValidationTimeUnix: uint64(cancelCreated.Unix()),
		},
		"tos.service.agent-guarantor-cancellation-request-signature.v1",
		testAuthorityCustody,
		testGuarantorController(coveredKey.Public().(ed25519.PublicKey)),
		[]byte("covered-history"),
	)
	if err != nil {
		t.Fatal(err)
	}
	cancelRequest := guarantor.AuthorizedCoverageCancellationRequestV1{
		Body:                  cancelBody,
		CoverageAgreementBody: cancellationAgreement,
		Authorizations:        []guarantor.ProfileQualifiedObjectAuthorizationV1{cancelAuthorization}}
	cancelInput := GuarantorCancelCoverageInput{Request: cancelRequest, AdmittedAtUnix: uint64(cancelCreated.Add(5 * time.Second).Unix())}
	coordinator.Authority = &failAfterTerminalEconomicAuthority{EconomicAuthority: baseAuthority, failOnce: true}
	if _, _, crashErr := coordinator.CancelCoverage(context.Background(), cancelInput, fence); crashErr == nil {
		t.Fatal("cancellation did not surface the injected post-terminal crash")
	}
	cancelReceipt, cancellationResolution, err := coordinator.CancelCoverage(context.Background(), cancelInput, fence)
	if err != nil || cancellationResolution.State != commerce.ActionTerminal || cancelReceipt.Body.State != "coverage_ended" ||
		cancelReceipt.Body.IncidentEligibilityEndsAtUnix != uint64(cancelCreated.Add(5*time.Second).Unix()) {
		t.Fatalf("cancel active coverage: state=%s body=%#v err=%v", cancellationResolution.State, cancelReceipt.Body, err)
	}
	replayedCancel, replayCancelResolution, replayCancelErr := coordinator.CancelCoverage(context.Background(),
		cancelInput, fence)
	if replayCancelErr != nil || replayCancelResolution.State != commerce.ActionTerminal || !sameJSON(replayedCancel, cancelReceipt) {
		t.Fatalf("cancellation replay was not exact: state=%s err=%v", replayCancelResolution.State, replayCancelErr)
	}
	if cancellationActivation.Body.CoverageAgreementBodyDigest != cancellationAgreementDigest {
		t.Fatal("cancellation activation was rebound to another Agreement")
	}
	// Two more offers are issued for their acceptances alone: one whose own
	// commit fails after the authority made it terminal, which is resumed and
	// never rejected, and one the journal refuses, which is rejected while
	// the authority can still reject it.
	requireAcceptanceIsRejectedOnlyWhilePrepared(t, &coordinator, restartWriter, func() commerce.WriterFence {
		return fence
	}, func(
		name string, issuedAt time.Time, coverageID, stateDomain string,
	) (commerce.AgentAgreementBody, guarantor.AuthorizedFirmCoverageOfferV1) {
		body := requestBody
		body.RequestID = "request:coverage:" + name
		body.CreatedAtUnix = uint64(issuedAt.Unix())
		quote := signGuarantorTestQuote(t, body, requested, ref("d", "request-authority"), coveredKey)
		offerAgreement := agreement
		offerAgreement.AuthorizationPredicates = append([]commerce.AgreementAuthorizationPredicate(nil),
			agreement.AuthorizationPredicates...)
		offerAgreement.AgreementID = "agreement:coverage:" + name
		for index := range offerAgreement.AuthorizationPredicates {
			offerAgreement.AuthorizationPredicates[index].EvidenceTargetProjectionDigest = ""
		}
		offerAgreement, prepareErr := commerce.PrepareAgreementTargets(offerAgreement)
		if prepareErr != nil {
			t.Fatal(prepareErr)
		}
		offerTerms := terms
		offerTerms.CoverageID, offerTerms.CoverageStateDomainDigest = coverageID, stateDomain
		offerTerms.QuoteRequestDigest = mustGuarantorQuoteDigest(t, quote)
		issued, issuedResolution, issueErr := coordinator.IssueFirmOffer(context.Background(), GuarantorIssueOfferInput{
			Request: quote, ProfileArtifact: profileArtifact, Agreement: offerAgreement, Terms: offerTerms,
			CoverageObligationID: "obligation:coverage", IssuedAtUnix: uint64(issuedAt.Unix()),
			AcceptByUnix:             uint64(now.Add(time.Minute).Unix()),
			ReservationExpiresAtUnix: uint64(now.Add(6 * time.Minute).Unix()),
			ExpiresAtUnix:            uint64(now.Add(10 * time.Minute).Unix()),
		}, fence)
		if issueErr != nil || issuedResolution.State != commerce.ActionTerminal {
			t.Fatalf("issue the %s offer: state=%s err=%v", name, issuedResolution.State, issueErr)
		}
		return offerAgreement, issued
	}, func(offerAgreement commerce.AgentAgreementBody, issued guarantor.AuthorizedFirmCoverageOfferV1,
	) guarantor.AuthorizedCoverageAcceptanceRequestV1 {
		return signGuarantorTestAcceptance(t, offerAgreement, issued, "agent:covered",
			map[string]ed25519.PrivateKey{"agent:covered": coveredKey, "agent:guarantor": guarantorKey},
			commerce.ProfileRefV1{
				ProfileURI: commerce.EvidenceProfileAgentSignature, ProfileVersion: 1, ProfileDigest: agreementProfile,
			}, underlyingResolver, baseAgreementVerifier, now.Add(30*time.Second), now.Add(90*time.Second))
	}, now)
	authority.now = func() time.Time { return now.Add(41 * time.Minute) }
	coordinator.Authority = authority
	// This closure crashes once its coverage-resolution plan is stored, and the
	// process restarts: the journal opened from disk resumes the stored plan to
	// the resolution the plan names. A document whose plan was changed, or
	// whose exposure release is no longer the one the plan resolves from, is
	// refused.
	resolutionCrash := &oneShotGuarantorClosureFailure{target: "coverage_resolution_plan_prepared"}
	coordinator.ClosureFailureInjector = resolutionCrash
	if _, crashErr := coordinator.CloseCoverage(context.Background(), GuarantorCloseCoverageInput{
		Offer: cancellationOffer, ActivationEvidence: cancellationActivation, CancellationReceipt: &cancelReceipt,
	},
		fence); crashErr == nil || !resolutionCrash.fired {
		t.Fatalf("the closure did not stop at its stored coverage-resolution plan: %v", crashErr)
	}
	coordinator.ClosureFailureInjector = nil
	var frozenResolutionPlan *GuarantorCoverageResolutionPlan
	_, _, crashPositions = testGuarantorSnapshot(t, journal)
	for index := range crashPositions {
		if crashPositions[index].Record.CoverageAgreementBodyDigest == cancellationAgreementDigest {
			frozenResolutionPlan = crashPositions[index].CoverageResolutionPlan
		}
	}
	if frozenResolutionPlan == nil {
		t.Fatal("the closure crash did not persist its coverage-resolution plan")
	}
	journal = restartTestGuarantorJournal(t, journal, journalDirectory, cancellationAgreementDigest,
		tamperedTestCoverageResolutionPlan(t, "closed"))
	coordinator.Journal = journal
	requireCoverageResolutionReauthorizationRefusesAChangedPlan(t, journal, cancellationAgreementDigest)
	cancelledClose, err := coordinator.CloseCoverage(context.Background(), GuarantorCloseCoverageInput{
		Offer: cancellationOffer, ActivationEvidence: cancellationActivation, CancellationReceipt: &cancelReceipt}, fence)
	if err != nil || cancelledClose.TerminalClaimSet.Body.CoverageClosureReason != "accepted_cancellation" ||
		cancelledClose.FilingCloseReceipt.Body.IncidentEligibilityEndsAtUnix != cancelReceipt.Body.IncidentEligibilityEndsAtUnix {
		t.Fatalf("close cancelled coverage: result=%#v err=%v", cancelledClose, err)
	}
	cancelledState := string(guarantor.CoverageCancelled)
	if resolved := cancelledClose.CoverageResolution.Body; resolved.TerminalState != cancelledState ||
		resolved.StableActionID != frozenResolutionPlan.Action.StableActionID ||
		resolved.ExactRequestDigest != frozenResolutionPlan.Action.ExactRequestDigest ||
		resolved.PriorCoverageRevision != frozenResolutionPlan.RequestBody.ExpectedRevision ||
		resolved.ResolvedCoverageRevision != frozenResolutionPlan.RequestBody.TargetRevision ||
		resolved.ResolvedAtUnix != frozenResolutionPlan.CreatedAtUnix {
		t.Fatalf("the closure resumed after a restart is not the one its stored plan names: %#v", resolved)
	}
	tampered := closed.CoverageResolution
	tampered.AuthorizedExposureReleaseReceipt.AuthorizedTerminalClaimSetEvidence.
		ClaimResolutionBundles[0].TerminalPayoutEvidenceSet.PayoutExecutionEvidence[0].
		StageActionAdmissionEvidence.CanonicalRequest[0] ^= 1
	if guarantor.VerifyCoverageResolutionV1(tampered, offer, coordinator.AgreementVerifier, resolver, authority,
		validPaymentEvidence{}, authority.AuthorityNow()) == nil {
		t.Fatal("portable terminal evidence accepted a substituted payment request")
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenGuarantorJournal(journalDirectory, "owner:guarantor", "agent:guarantor")
	if err != nil {
		t.Fatalf("reopen terminal Guarantor journal: %v", err)
	}
	closeGuarantorJournalOnCleanup(t, reopened)
	_, _, recovered := testGuarantorSnapshot(t, reopened)
	if len(recovered) != 3 {
		t.Fatalf("unexpected recovered Guarantor coverage count: %#v", recovered)
	}
	var recoveredTerminal bool
	for _, candidate := range recovered {
		recoveredTerminal = recoveredTerminal || candidate.Record.CoverageStatus == guarantor.CoverageClosed &&
			candidate.PaidAtomic == "400" && len(candidate.PayoutEvidence) == 1
	}
	if !recoveredTerminal {
		t.Fatalf("terminal Guarantor state was not recovered exactly: %#v", recovered)
	}
}

func signGuarantorTestQuote(t *testing.T, body guarantor.CoverageQuoteRequestBodyV1,
	requested guarantor.RequestedCoverageTermsV1, profile commerce.ProfileRefV1,
	key ed25519.PrivateKey) guarantor.AuthorizedCoverageQuoteRequestV1 {
	t.Helper()
	bodyDigest, err := codec.Digest("tos.service.agent-guarantor-quote-request-body.v1", body)
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := guarantor.SignObjectAuthorization(context.Background(), guarantor.AuthorizationStatementV1{
		SchemaVersion:        1,
		AuthoritySubject:     body.RequesterAgentID,
		ProfileURI:           profile.ProfileURI,
		ProfileVersion:       profile.ProfileVersion,
		ProfileDigest:        profile.ProfileDigest,
		AuthorizedObjectKind: "coverage-quote-request",
		AuthorizedBodyDigest: bodyDigest,
		ValidationTimeUnix:   body.CreatedAtUnix,
	}, "tos.service.agent-guarantor-quote-request-signature.v1", testAuthorityCustody, testGuarantorController(key.Public().(ed25519.PublicKey)), []byte("covered-history"))
	if err != nil {
		t.Fatal(err)
	}
	return guarantor.AuthorizedCoverageQuoteRequestV1{
		Body: body, RequestedTerms: requested,
		Authorizations: []guarantor.ProfileQualifiedObjectAuthorizationV1{authorization},
	}
}

func signGuarantorTestAcceptance(t *testing.T, agreement commerce.AgentAgreementBody,
	offer guarantor.AuthorizedFirmCoverageOfferV1, acceptingSubject string, keys map[string]ed25519.PrivateKey,
	profile commerce.ProfileRefV1, underlyingResolver guarantor.UnderlyingAgreementResolver,
	agreementVerifier commerce.AgreementEvidenceVerifier, createdAt, expiresAt time.Time) guarantor.AuthorizedCoverageAcceptanceRequestV1 {
	t.Helper()
	agreementDigest, err := commerce.AgreementBodyDigest(agreement)
	if err != nil {
		t.Fatal(err)
	}
	evidence := make([]commerce.AgreementAuthorizationEvidence, 0, len(agreement.AuthorizationPredicates))
	for _, predicate := range agreement.AuthorizationPredicates {
		if predicate.EvidenceProfileURI == guarantor.FirmOfferAgreementEvidenceProfileURI {
			continue
		}
		key := keys[predicate.AuthoritySubject.SubjectIdentifier]
		accepted, signErr := commerce.SignAgreementAcceptance(commerce.AgreementAcceptanceBody{AgreementID: agreement.AgreementID,
			AgreementVersion: agreement.Version, AgreementBodyDigest: agreementDigest, AcceptingSubject: predicate.AuthoritySubject,
			PredicateIDs: []string{predicate.PredicateID}, EvidenceTargetProjectionDigests: []string{predicate.EvidenceTargetProjectionDigest},
			ExpiresAtUnix: agreement.ExpiresAtUnix}, key)
		if signErr != nil {
			t.Fatal(signErr)
		}
		item, itemErr := commerce.AgentSignatureEvidence(agreement, accepted)
		if itemErr != nil {
			t.Fatal(itemErr)
		}
		evidence = append(evidence, item)
	}
	pins := make(map[string]ed25519.PublicKey, len(keys))
	for subject, key := range keys {
		pins[subject] = key.Public().(ed25519.PublicKey)
	}
	publicKeys := newGuarantorPinnedResolver(pins)
	firmEvidence, err := guarantor.NewFirmOfferAgreementEvidenceV1(offer, agreement, publicKeys, publicKeys,
		underlyingResolver, agreementVerifier, createdAt)
	if err != nil {
		t.Fatal(err)
	}
	evidence = append(evidence, firmEvidence)
	sort.Slice(evidence, func(i, j int) bool {
		left, _ := codec.Marshal(evidence[i])
		right, _ := codec.Marshal(evidence[j])
		return string(left) < string(right)
	})
	evidenceSet := guarantor.GuarantorAgreementAuthorizationEvidenceSetV1{SchemaVersion: 1, AgreementID: agreement.AgreementID,
		AgreementVersion: agreement.Version, AgreementBodyDigest: agreementDigest, Evidence: evidence}
	evidenceDigest, _ := guarantor.AgreementAuthorizationEvidenceSetDigestV1(evidenceSet)
	offerDigest, _ := guarantor.FirmOfferDigest(offer)
	body := guarantor.CoverageAcceptanceRequestBodyV1{SchemaVersion: 1, CoverageAgreementBodyDigest: agreementDigest,
		AuthorizedFirmOfferEnvelopeDigest: offerDigest, CompleteAuthorizationEvidenceSetDigest: evidenceDigest,
		AcceptingSubject: acceptingSubject, SubmissionAuthorizationProfile: profile,
		CreatedAtUnix: uint64(createdAt.Unix()), ExpiresAtUnix: uint64(expiresAt.Unix())}
	bodyDigest, _ := codec.Digest("tos.service.agent-guarantor-acceptance-request-body.v1", body)
	authorization, err := guarantor.SignObjectAuthorization(context.Background(), guarantor.AuthorizationStatementV1{
		SchemaVersion:    1,
		AuthoritySubject: acceptingSubject, ProfileURI: profile.ProfileURI, ProfileVersion: profile.ProfileVersion,
		ProfileDigest: profile.ProfileDigest, AuthorizedObjectKind: "coverage-acceptance-request",
		AuthorizedBodyDigest: bodyDigest, ValidationTimeUnix: uint64(createdAt.Unix()),
	}, "tos.service.agent-guarantor-acceptance-request-signature.v1", testAuthorityCustody, testGuarantorController(keys[acceptingSubject].Public().(ed25519.PublicKey)), []byte("covered-history"))
	if err != nil {
		t.Fatal(err)
	}
	return guarantor.AuthorizedCoverageAcceptanceRequestV1{
		Body:                     body,
		CoverageAgreementBody:    agreement,
		AuthorizationEvidenceSet: evidenceSet,
		Authorizations:           []guarantor.ProfileQualifiedObjectAuthorizationV1{authorization},
	}
}

// guarantorTestDeadlines are coverage terms' deadlines derived from one
// hard-effect deadline. Without a late-recovery contingency the three late
// values are zero.
type guarantorTestDeadlines struct {
	terminalResolution       uint64
	lateIngressWindowSeconds uint64
	lateIngressRecovery      uint64
	lateRecoveryTerminal     uint64
}

// guarantorLateCandidateClosureSeconds is the closure time the late-recovery
// path reserves: the budget entry of a challengeable candidate with at most
// one remaining challenge round.
func guarantorLateCandidateClosureSeconds(t *testing.T, capacity guarantor.ClaimClosureCapacityV1) uint64 {
	t.Helper()
	key := "challengeable_candidate:r=0"
	if capacity.MaximumChallengeRoundsPerClaim >= 1 {
		key = "challengeable_candidate:r=1"
	}
	for _, entry := range capacity.ContinuationBudgetEntries {
		if entry.ProfileStateKey == key {
			return entry.MaximumRemainingClosureSeconds
		}
	}
	t.Fatalf("the continuation budget has no %s entry", key)
	return 0
}

// deriveGuarantorTestDeadlines applies the deadline derivation to a
// hard-effect deadline: with a late contingency the late-recovery terminal
// deadline is that deadline, late ingress ends one late-candidate closure
// before it and the terminal resolution deadline one window before that;
// without one the terminal resolution deadline is the hard-effect deadline.
func deriveGuarantorTestDeadlines(t *testing.T, capacity guarantor.ClaimClosureCapacityV1, hardEffectDeadline uint64,
	lateContingency bool, lateIngressWindowSeconds uint64) guarantorTestDeadlines {
	t.Helper()
	if !lateContingency {
		return guarantorTestDeadlines{terminalResolution: hardEffectDeadline}
	}
	closure := guarantorLateCandidateClosureSeconds(t, capacity)
	if lateIngressWindowSeconds == 0 || closure == 0 || hardEffectDeadline < closure ||
		hardEffectDeadline-closure < lateIngressWindowSeconds {
		t.Fatalf("no late-recovery deadlines fit before %d: closure=%d window=%d", hardEffectDeadline, closure,
			lateIngressWindowSeconds)
	}
	lateIngress := hardEffectDeadline - closure
	return guarantorTestDeadlines{terminalResolution: lateIngress - lateIngressWindowSeconds,
		lateIngressWindowSeconds: lateIngressWindowSeconds, lateIngressRecovery: lateIngress,
		lateRecoveryTerminal: hardEffectDeadline}
}

func mustGuarantorQuoteDigest(t *testing.T, request guarantor.AuthorizedCoverageQuoteRequestV1) string {
	t.Helper()
	digest, err := guarantor.QuoteRequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}
