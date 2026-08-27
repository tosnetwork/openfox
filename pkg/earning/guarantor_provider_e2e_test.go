package earning

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	guarantor "github.com/tosnetwork/tos-service-protocol/pkg/agentguarantor"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type guarantorPinnedResolver map[string]ed25519.PublicKey

func (resolver guarantorPinnedResolver) ResolveGuarantorAuthority(scope guarantor.AuthorityResolutionScopeV1, publicKey string, _ time.Time, proof []byte) error {
	wanted, found := resolver[scope.AuthoritySubject]
	if !found || publicKey != "ed25519:"+strings.ToLower(strings.TrimPrefix(testHex(wanted), "ed25519:")) || len(proof) == 0 ||
		scope.ProfileURI == "" || scope.ProfileVersion == 0 || scope.ProfileDigest == "" ||
		scope.AuthorizedKind == "" || scope.AuthorizedDigest == "" || scope.SignatureDomain == "" {
		return errors.New("Guarantor historical authority is not pinned")
	}
	return nil
}

func (resolver guarantorPinnedResolver) AuthorizeAgentOperationKey(agentID string, profile commerce.ProfileRefV1,
	key ed25519.PublicKey, _ time.Time, proof []byte) error {
	wanted, found := resolver[agentID]
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
		ResolvedState: "finalized", ResolvedAtUnix: uint64(time.Now().UTC().Unix()), FinalityReference: "finality:test",
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

func TestGuarantorProviderIssuesReservedOfferAndLinearizesAcceptance(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	guarantorPublic, guarantorKey, _ := ed25519.GenerateKey(rand.Reader)
	coveredPublic, coveredKey, _ := ed25519.GenerateKey(rand.Reader)
	digest := func(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }
	ref := func(ch, name string) commerce.ProfileRefV1 {
		return commerce.ProfileRefV1{ProfileURI: "tos.test." + name + ".v1", ProfileVersion: 1, ProfileDigest: digest(ch)}
	}
	asset := commerce.AssetIdentityV1{AssetNamespace: "tos.asset", AssetIdentifier: "native", Unit: "nano"}
	fallback, err := guarantor.NewDenyZeroTerminalFallbackV1(ref("e", "fallback"), []string{"agent:guarantor"}, "all",
		map[string]string{"deny_zero": "fallback-deny", "no_eligible_benefit": "fallback-no-benefit",
			"aggregate_exhausted": "fallback-cap-exhausted", "aggregate_limited": "fallback-cap-limited", "full_benefit": "fallback-full"})
	if err != nil {
		t.Fatal(err)
	}
	continuationEntries, err := guarantor.BuildClaimContinuationBudgetEntriesV1(1, 1, 60, 60, 60, 60, 60, 60)
	if err != nil {
		t.Fatal(err)
	}
	capacity := guarantor.ClaimClosureCapacityV1{MaximumClaims: 2, MaximumClaimIngressActions: 4,
		MaximumClaimRevisionsPerClaim: 2, MaximumDecisionAdmissionsPerClaim: 4, MaximumClaimStateTransitionsPerClaim: 8,
		MaximumChallengeRoundsPerClaim: 1, MaximumNonterminalRoundsPerClaim: 1, MaximumPayoutLinesPerClaim: 2,
		MaximumAdmittedClaimEnvelopeBytes: 64 << 10, MaximumClaimIngressReceiptEnvelopeBytes: 128 << 10,
		MaximumClaimIngressCutProofBytes: 1 << 20, MaximumAcceptanceRequestEnvelopeBytes: 1 << 20,
		MaximumAcceptanceReceiptEnvelopeBytes: 1 << 20, MaximumActivationEvidenceEnvelopeBytes: 1 << 20,
		MaximumNonActivationEvidenceEnvelopeBytes: 1 << 20, MaximumCancellationReceiptEnvelopeBytes: 1 << 20,
		MaximumClaimFilingCloseReceiptEnvelopeBytes: 1 << 20, MaximumTerminalClaimSetEnvelopeBytes: 1 << 20,
		MaximumExposureReleaseRequestBytes: 1 << 20, MaximumExposureReleaseReceiptBytes: 1 << 20,
		MaximumCoverageResolutionRequestBytes: 1 << 20, MaximumCoverageResolutionEnvelopeBytes: 1 << 20,
		ComputedWorstCaseAcceptanceRequestEnvelopeBytes: 1 << 20, ComputedWorstCaseAcceptanceReceiptEnvelopeBytes: 1 << 20,
		ComputedWorstCaseActivationEvidenceEnvelopeBytes: 1 << 20, ComputedWorstCaseNonActivationEvidenceEnvelopeBytes: 1 << 20,
		ComputedWorstCaseCancellationReceiptEnvelopeBytes: 1 << 20, ComputedWorstCaseClaimFilingCloseReceiptEnvelopeBytes: 1 << 20,
		ComputedWorstCaseTerminalClaimSetBytes: 1 << 20, ComputedWorstCaseExposureReleaseRequestBytes: 1 << 20,
		ComputedWorstCaseExposureReleaseReceiptBytes: 1 << 20, ComputedWorstCaseCoverageResolutionRequestBytes: 1 << 20,
		ComputedWorstCaseCoverageResolutionEnvelopeBytes: 1 << 20,
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
	requested := guarantor.RequestedCoverageTermsV1{SchemaVersion: 1, CoverageCategory: "service-default",
		BenefitKind: guarantor.BenefitFixed, CoverageAsset: asset,
		RequestedAggregatePayout: commerce.AtomicAmountV1{Asset: asset, AmountAtomic: "1000"},
		RequestedPerClaim:        commerce.AtomicAmountV1{Asset: asset, AmountAtomic: "500"}, MaximumClaims: 2,
		RequestedClosureCapacity: capacity, RequestedCoverageStartsAtUnix: uint64(now.Add(2 * time.Minute).Unix()),
		RequestedCoverageEndsAtUnix:    uint64(now.Add(30 * time.Minute).Unix()),
		RequestedClaimFilingEndsAtUnix: uint64(now.Add(40 * time.Minute).Unix()), MaximumReviewDeadlineSeconds: 60,
		MaximumChallengeWindowSeconds: 60, MaximumNonterminalResolutionWindowSeconds: 60,
		MaximumSuccessorDecisionWindowSeconds: 60, MaximumPayoutDeadlineSeconds: 60, MaximumAdapterRecoveryWindowSeconds: 60,
		ClaimTriggerProfile: trigger, ClaimEvidenceProfile: evidence, SelectedAssuranceLevel: guarantor.AssuranceUnsecuredSigned,
		SelectedClaimProfileDigest: claimProfileDigest, SelectedPayoutAdapterProfile: payoutAdapter}
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
		SelectedAssuranceLevel: guarantor.AssuranceUnsecuredSigned, SelectedClaimProfileDigest: claimProfileDigest,
		SelectedDecisionProfile: decisionProfile, SelectedPayoutAdapterProfile: payoutAdapter,
		CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(10 * time.Minute).Unix())}
	requestBodyDigest, _ := codec.Digest("tos.service.agent-guarantor-quote-request-body.v1", requestBody)
	coveredAuthorization, err := guarantor.SignObjectAuthorization(guarantor.AuthorizationStatementV1{SchemaVersion: 1,
		AuthoritySubject: "agent:covered", ProfileURI: ref("d", "request-authority").ProfileURI, ProfileVersion: 1,
		ProfileDigest: ref("d", "request-authority").ProfileDigest, AuthorizedObjectKind: "coverage-quote-request",
		AuthorizedBodyDigest: requestBodyDigest, ValidationTimeUnix: uint64(now.Unix())},
		"tos.service.agent-guarantor-quote-request-signature.v1", coveredKey, []byte("covered-history"))
	if err != nil {
		t.Fatal(err)
	}
	quote := guarantor.AuthorizedCoverageQuoteRequestV1{Body: requestBody, RequestedTerms: requested,
		Authorizations: []guarantor.ProfileQualifiedObjectAuthorizationV1{coveredAuthorization}}
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
		ValidFromUnix: uint64(now.Add(-time.Minute).Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}
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
		CancellationPolicy:             cancellationPolicy,
		TerminalResolutionDeadlineUnix: uint64(now.Add(55 * time.Minute).Unix()), CoverageStateDomainDigest: digest("4"),
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
	root := t.TempDir()
	authorityDirectory, journalDirectory := filepath.Join(root, "authority"), filepath.Join(root, "guarantor")
	if err := os.Mkdir(authorityDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(journalDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	authority, err := OpenPersonalAuthority(authorityDirectory, "owner:guarantor", "agent:guarantor", "authority:owner",
		guarantorKey, PortfolioLimits{MaximumLossAtomic: 10_000, LockedCapitalAtomic: 10_000})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	journal, err := OpenGuarantorJournal(journalDirectory, "owner:guarantor", "agent:guarantor")
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	scope := []string{"commercial.quote.close", "commercial.quote.issue", "conditional.claim-decision.admit", "conditional.claim.decide", "conditional.claim.ingress",
		"conditional.claim.submit", "conditional.claim.transition", "conditional.claim-filing.close", "conditional.obligation.transition",
		"messenger.send", "payment.direct", "payment.domain-bound", "portfolio.release"}
	sort.Strings(scope)
	fence, err := authority.AcquireWriter(context.Background(), "instance:test", scope, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	authorizationProfile := ref("c", "authority")
	signer, _ := NewLocalGuarantorObjectSigner("agent:guarantor", authorizationProfile, guarantorKey, []byte("guarantor-history"))
	actionSigner, _ := NewLocalGuarantorObjectSigner("authority:owner", authorizationProfile, guarantorKey, []byte("action-authority-history"))
	fallbackSigner, _ := NewLocalGuarantorObjectSigner("agent:guarantor", fallback.FallbackProfile, guarantorKey, []byte("fallback-history"))
	resolver := guarantorPinnedResolver{"agent:guarantor": guarantorPublic, "agent:covered": coveredPublic, "authority:owner": guarantorPublic}
	coordinator := GuarantorProviderCoordinator{OwnerID: "owner:guarantor", AgentID: "agent:guarantor", MandateDigest: digest("5"),
		PolicyRevision: 1, Policy: GuarantorRiskPolicy{MaximumAggregateExposureAtomic: "10000", MaximumPerCoverageAtomic: "2000",
			MaximumPerCounterpartyAtomic: "3000", MinimumPremiumPPM: 10_000, MaximumClaimProbabilityPPM: 100_000,
			CapitalCostPPM: 10_000, PermittedAssuranceLevels: []guarantor.AssuranceLevel{guarantor.AssuranceUnsecuredSigned},
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
	coordinator.Authority = &failAfterReservationEconomicAuthority{EconomicAuthority: authority, failOnce: true}
	if _, _, crashErr := coordinator.IssueFirmOffer(context.Background(), issueInput, fence); crashErr == nil {
		t.Fatal("firm-offer issuance did not surface the injected post-reservation crash")
	}
	coordinator.Authority = authority
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
	coveredAuthorization2, signErr := guarantor.SignObjectAuthorization(guarantor.AuthorizationStatementV1{SchemaVersion: 1,
		AuthoritySubject: "agent:covered", ProfileURI: ref("d", "request-authority").ProfileURI, ProfileVersion: 1,
		ProfileDigest: ref("d", "request-authority").ProfileDigest, AuthorizedObjectKind: "coverage-quote-request",
		AuthorizedBodyDigest: requestBodyDigest2, ValidationTimeUnix: requestBody2.CreatedAtUnix},
		"tos.service.agent-guarantor-quote-request-signature.v1", coveredKey, []byte("covered-history"))
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
	expiringOffer, expiringResolution, issueErr := coordinator.IssueFirmOffer(context.Background(), GuarantorIssueOfferInput{
		Request: quote2, ProfileArtifact: profileArtifact, Agreement: agreement2, Terms: terms2, CoverageObligationID: "obligation:coverage",
		IssuedAtUnix: uint64(now.Add(time.Second).Unix()), AcceptByUnix: uint64(now.Add(2 * time.Minute).Unix()),
		ReservationExpiresAtUnix: uint64(now.Add(10 * time.Minute).Unix()), ExpiresAtUnix: uint64(now.Add(15 * time.Minute).Unix())}, fence)
	if issueErr != nil || expiringResolution.State != commerce.ActionTerminal {
		t.Fatalf("issue expiring offer: state=%s err=%v", expiringResolution.State, issueErr)
	}
	late := now.Add(4 * time.Minute)
	authority.now = func() time.Time { return late }
	expiredClosed, closeErr := coordinator.CloseExpiredOffer(context.Background(), GuarantorCloseExpiredOfferInput{
		Offer: expiringOffer}, fence)
	if closeErr != nil || expiredClosed.ExpiryResolution.State != commerce.ActionTerminal ||
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
	acceptanceAuthorization, _ := guarantor.SignObjectAuthorization(guarantor.AuthorizationStatementV1{SchemaVersion: 1,
		AuthoritySubject: "agent:covered", ProfileURI: acceptanceBody.SubmissionAuthorizationProfile.ProfileURI,
		ProfileVersion: 1, ProfileDigest: acceptanceBody.SubmissionAuthorizationProfile.ProfileDigest,
		AuthorizedObjectKind: "coverage-acceptance-request", AuthorizedBodyDigest: acceptanceBodyDigest,
		ValidationTimeUnix: uint64(now.Add(time.Minute).Unix())}, "tos.service.agent-guarantor-acceptance-request-signature.v1",
		coveredKey, []byte("covered-history"))
	acceptance := guarantor.AuthorizedCoverageAcceptanceRequestV1{Body: acceptanceBody, CoverageAgreementBody: agreement,
		AuthorizationEvidenceSet: evidenceSet, Authorizations: []guarantor.ProfileQualifiedObjectAuthorizationV1{acceptanceAuthorization}}
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
	_, _, coverages := journal.Snapshot()
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
	baseAuthority := coordinator.Authority
	coordinator.Authority = &failAfterTerminalEconomicAuthority{EconomicAuthority: baseAuthority, failOnce: true}
	if _, _, crashErr := coordinator.ActivateCoverage(context.Background(), activationInput, fence); crashErr == nil {
		t.Fatal("activation did not surface the injected post-terminal crash")
	}
	_, _, afterCrash := journal.Snapshot()
	if len(afterCrash) != 1 || afterCrash[0].Record.CoverageStatus != guarantor.CoveragePendingAuthorization ||
		afterCrash[0].ActivationEvidence != nil {
		t.Fatalf("activation crash left a half-active coverage: %#v", afterCrash)
	}
	activation, resolution, err := coordinator.ActivateCoverage(context.Background(), activationInput, fence)
	if err != nil || resolution.State != commerce.ActionTerminal || activation.Body.ActivatedCoverageRevision != 2 {
		t.Fatalf("activate coverage: state=%s body=%#v err=%v", resolution.State, activation.Body, err)
	}
	_, _, coverages = journal.Snapshot()
	if coverages[0].Record.CoverageStatus != guarantor.CoverageActive || coverages[0].Record.ClaimFilingStatus != guarantor.FilingOpen {
		t.Fatalf("coverage did not activate atomically: %#v", coverages[0].Record)
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
	claimAuthorization, err := guarantor.SignObjectAuthorization(guarantor.AuthorizationStatementV1{SchemaVersion: 1,
		AuthoritySubject: "agent:covered", ProfileURI: terms.ClaimantAuthorizationProfiles[0].ProfileURI,
		ProfileVersion: terms.ClaimantAuthorizationProfiles[0].ProfileVersion,
		ProfileDigest:  terms.ClaimantAuthorizationProfiles[0].ProfileDigest, AuthorizedObjectKind: "coverage-claim",
		AuthorizedBodyDigest: claimBodyDigest, ValidationTimeUnix: uint64(now.Add(3 * time.Minute).Unix())},
		"tos.service.agent-guarantor-claim-signature.v1", coveredKey, []byte("covered-history"))
	if err != nil {
		t.Fatal(err)
	}
	claim := guarantor.AuthorizedCoverageClaimV1{Body: claimBody, EvidenceManifest: manifest,
		OtherRecoveryDeclaration: recovery, Authorizations: []guarantor.ProfileQualifiedObjectAuthorizationV1{claimAuthorization}}
	claimResult, err := coordinator.AdmitClaim(context.Background(), agreementDigest, claim, fence)
	if err != nil || claimResult.IngressResolution.State != commerce.ActionTerminal ||
		claimResult.AdmissionResolution.State != commerce.ActionTerminal {
		t.Fatalf("admit claim: result=%#v err=%v", claimResult, err)
	}
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
	revisedAuthorization, _ := guarantor.SignObjectAuthorization(guarantor.AuthorizationStatementV1{SchemaVersion: 1,
		AuthoritySubject: "agent:covered", ProfileURI: terms.ClaimantAuthorizationProfiles[0].ProfileURI,
		ProfileVersion: terms.ClaimantAuthorizationProfiles[0].ProfileVersion,
		ProfileDigest:  terms.ClaimantAuthorizationProfiles[0].ProfileDigest, AuthorizedObjectKind: "coverage-claim",
		AuthorizedBodyDigest: revisedBodyDigest, ValidationTimeUnix: revisedBody.CreatedAtUnix},
		"tos.service.agent-guarantor-claim-signature.v1", coveredKey, []byte("covered-history"))
	revisedClaim := guarantor.AuthorizedCoverageClaimV1{Body: revisedBody, EvidenceManifest: manifest,
		OtherRecoveryDeclaration: revisedRecovery, Authorizations: []guarantor.ProfileQualifiedObjectAuthorizationV1{revisedAuthorization}}
	revisionResult, err := coordinator.AdmitClaim(context.Background(), agreementDigest, revisedClaim, fence)
	if err != nil || revisionResult.IngressResolution.State != commerce.ActionTerminal ||
		revisionResult.AdmissionResolution.State != commerce.ActionTerminal {
		t.Fatalf("admit claim revision: result=%#v err=%v", revisionResult, err)
	}
	if _, err := coordinator.AdmitClaim(context.Background(), agreementDigest, claim, fence); err == nil {
		t.Fatal("stale claim revision was accepted after the lineage advanced")
	}
	claim = revisedClaim
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
	decisionReason := guarantor.ClaimDecisionReasonV1{SchemaVersion: 1, DecisionProfile: decisionProfile,
		Result: guarantor.DecisionApproved, ReasonCode: "verified_failure",
		ApplicablePolicyClauseIDs: []string{"clause:service-default"}, EvidencePredicateIDs: []string{"evidence:failure"}}
	decisionReasonDigest, _ := guarantor.ClaimDecisionReasonDigestV1(decisionReason)
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
		DecidedAtUnix: uint64(now.Add(3 * time.Minute).Unix()), ExpiresAtUnix: uint64(now.Add(10 * time.Minute).Unix())}
	decisionBodyDigest, _ := guarantor.ClaimDecisionBodyDigestV1(decisionBody, terms)
	decisionAuthorization, err := guarantor.SignObjectAuthorization(guarantor.AuthorizationStatementV1{SchemaVersion: 1,
		AuthoritySubject: "agent:guarantor", ProfileURI: decisionProfile.ProfileURI, ProfileVersion: decisionProfile.ProfileVersion,
		ProfileDigest: decisionProfile.ProfileDigest, AuthorizedObjectKind: "claim-decision", AuthorizedBodyDigest: decisionBodyDigest,
		ValidationTimeUnix: uint64(now.Add(3 * time.Minute).Unix())}, "tos.service.agent-guarantor-claim-decision-signature.v1",
		guarantorKey, []byte("guarantor-history"))
	if err != nil {
		t.Fatal(err)
	}
	decision := guarantor.AuthorizedClaimDecisionV1{Body: decisionBody, PolicyApplication: policyApplication,
		DecisionReason: decisionReason, DecisionEvidenceSet: decisionEvidence,
		Authorizations: []guarantor.ProfileQualifiedObjectAuthorizationV1{decisionAuthorization}}
	decisionAdmission, err := coordinator.AdmitClaimDecision(context.Background(), GuarantorAdmitDecisionInput{
		AgreementDigest: agreementDigest, Decision: decision}, fence)
	if err != nil || decisionAdmission.Resolution.State != commerce.ActionTerminal ||
		decisionAdmission.Receipt.Body.AdmittedClaimState != "approved" {
		t.Fatalf("admit claim decision: result=%#v err=%v", decisionAdmission, err)
	}
	authority.now = func() time.Time { return now.Add(5 * time.Minute) }
	terminalTransition, err := coordinator.TransitionClaimDecision(context.Background(), GuarantorTransitionClaimInput{
		AgreementDigest: agreementDigest, DecisionAdmissionReceipt: decisionAdmission.Receipt,
		TransitionKind: "challenge_close"}, fence)
	if err != nil || terminalTransition.Resolution.State != commerce.ActionTerminal ||
		terminalTransition.Receipt.Body.ResultingClaimState != "final_approved" {
		t.Fatalf("close claim challenge: result=%#v err=%v", terminalTransition, err)
	}
	admissionWire, _ := codec.Marshal(decisionAdmission.Receipt)
	transitionWire, _ := codec.Marshal(terminalTransition.Receipt)
	t.Logf("portable Guarantor decision admission=%d transition=%d bytes", len(admissionWire), len(transitionWire))
	application, err := coordinator.ApplyClaimDecision(context.Background(), GuarantorApplyDecisionInput{
		AgreementDigest: agreementDigest, DecisionAdmissionReceipt: decisionAdmission.Receipt,
		TerminalTransitionReceipt: terminalTransition.Receipt}, fence)
	payouts, resolution := application.Payouts, application.Resolution
	if err != nil || resolution.State != commerce.ActionTerminal || len(payouts.Obligations) != 1 ||
		payouts.Obligations[0].Amount.AmountAtomic != "400" || application.Receipt.Body.ResultingApplicationTokenState != "consumed" {
		t.Fatalf("apply claim decision: result=%#v err=%v", application, err)
	}
	applicationWire, err := codec.Marshal(application.Receipt)
	if err != nil || len(applicationWire) > guarantor.MaxCanonicalObjectBytes {
		t.Fatalf("portable decision application exceeds the complete-object ceiling: bytes=%d err=%v", len(applicationWire), err)
	}
	paymentSink := &guarantorTestPaymentSink{}
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
	_, _, crashPositions := journal.Snapshot()
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
		wire, encodeErr := codec.Marshal(envelope)
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
	_, _, coverages = journal.Snapshot()
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
	nonActivationReceipt, nonActivationResolution, err := coordinator.AcceptCoverage(context.Background(),
		GuarantorAcceptCoverageInput{Offer: nonActivationOffer, Request: nonActivationAcceptance,
			CoverageObligationID: "obligation:coverage", ReceivedAtUnix: uint64(now.Add(30 * time.Second).Unix())}, fence)
	if err != nil || nonActivationResolution.State != commerce.ActionTerminal {
		t.Fatalf("accept non-activation coverage: state=%s err=%v", nonActivationResolution.State, err)
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
	_, _, allCoverages := journal.Snapshot()
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
	cancelAuthorization, err := guarantor.SignObjectAuthorization(guarantor.AuthorizationStatementV1{SchemaVersion: 1,
		AuthoritySubject: "agent:covered", ProfileURI: commerce.EvidenceProfileAgentSignature, ProfileVersion: 1,
		ProfileDigest: agreementProfile, AuthorizedObjectKind: "coverage-cancellation-request",
		AuthorizedBodyDigest: cancelBodyDigest, ValidationTimeUnix: uint64(cancelCreated.Unix())},
		"tos.service.agent-guarantor-cancellation-request-signature.v1", coveredKey, []byte("covered-history"))
	if err != nil {
		t.Fatal(err)
	}
	cancelRequest := guarantor.AuthorizedCoverageCancellationRequestV1{Body: cancelBody,
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
	authority.now = func() time.Time { return now.Add(41 * time.Minute) }
	coordinator.Authority = authority
	cancelledClose, err := coordinator.CloseCoverage(context.Background(), GuarantorCloseCoverageInput{
		Offer: cancellationOffer, ActivationEvidence: cancellationActivation, CancellationReceipt: &cancelReceipt}, fence)
	if err != nil || cancelledClose.TerminalClaimSet.Body.CoverageClosureReason != "accepted_cancellation" ||
		cancelledClose.FilingCloseReceipt.Body.IncidentEligibilityEndsAtUnix != cancelReceipt.Body.IncidentEligibilityEndsAtUnix {
		t.Fatalf("close cancelled coverage: result=%#v err=%v", cancelledClose, err)
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
	defer reopened.Close()
	_, _, recovered := reopened.Snapshot()
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
	authorization, err := guarantor.SignObjectAuthorization(guarantor.AuthorizationStatementV1{SchemaVersion: 1,
		AuthoritySubject: body.RequesterAgentID, ProfileURI: profile.ProfileURI, ProfileVersion: profile.ProfileVersion,
		ProfileDigest: profile.ProfileDigest, AuthorizedObjectKind: "coverage-quote-request", AuthorizedBodyDigest: bodyDigest,
		ValidationTimeUnix: body.CreatedAtUnix}, "tos.service.agent-guarantor-quote-request-signature.v1", key,
		[]byte("covered-history"))
	if err != nil {
		t.Fatal(err)
	}
	return guarantor.AuthorizedCoverageQuoteRequestV1{Body: body, RequestedTerms: requested,
		Authorizations: []guarantor.ProfileQualifiedObjectAuthorizationV1{authorization}}
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
	publicKeys := make(guarantorPinnedResolver, len(keys))
	for subject, key := range keys {
		publicKeys[subject] = key.Public().(ed25519.PublicKey)
	}
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
	authorization, err := guarantor.SignObjectAuthorization(guarantor.AuthorizationStatementV1{SchemaVersion: 1,
		AuthoritySubject: acceptingSubject, ProfileURI: profile.ProfileURI, ProfileVersion: profile.ProfileVersion,
		ProfileDigest: profile.ProfileDigest, AuthorizedObjectKind: "coverage-acceptance-request",
		AuthorizedBodyDigest: bodyDigest, ValidationTimeUnix: uint64(createdAt.Unix())},
		"tos.service.agent-guarantor-acceptance-request-signature.v1", keys[acceptingSubject], []byte("covered-history"))
	if err != nil {
		t.Fatal(err)
	}
	return guarantor.AuthorizedCoverageAcceptanceRequestV1{Body: body, CoverageAgreementBody: agreement,
		AuthorizationEvidenceSet: evidenceSet, Authorizations: []guarantor.ProfileQualifiedObjectAuthorizationV1{authorization}}
}

func mustGuarantorQuoteDigest(t *testing.T, request guarantor.AuthorizedCoverageQuoteRequestV1) string {
	t.Helper()
	digest, err := guarantor.QuoteRequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}
