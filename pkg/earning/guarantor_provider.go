package earning

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	guarantor "github.com/tosnetwork/tos-service-protocol/pkg/agentguarantor"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type GuarantorObjectSigner interface {
	SignObject(kind, bodyDigest, signatureDomain string, validationTime time.Time) (guarantor.ProfileQualifiedObjectAuthorizationV1, error)
}

type LocalGuarantorObjectSigner struct {
	subject         string
	profile         commerce.ProfileRefV1
	key             ed25519.PrivateKey
	historicalProof []byte
}

func NewLocalGuarantorObjectSigner(subject string, profile commerce.ProfileRefV1, key ed25519.PrivateKey,
	historicalProof []byte) (*LocalGuarantorObjectSigner, error) {
	if subject == "" || commerce.ValidateProfileRefV1(profile) != nil || len(key) != ed25519.PrivateKeySize ||
		len(historicalProof) == 0 || len(historicalProof) > 64<<10 {
		return nil, errors.New("local Guarantor object signer is invalid")
	}
	return &LocalGuarantorObjectSigner{subject: subject, profile: profile, key: append(ed25519.PrivateKey(nil), key...),
		historicalProof: append([]byte(nil), historicalProof...)}, nil
}

func (signer *LocalGuarantorObjectSigner) SignObject(kind, bodyDigest, signatureDomain string,
	validationTime time.Time) (guarantor.ProfileQualifiedObjectAuthorizationV1, error) {
	if signer == nil || kind == "" || !canonicalSHA256(bodyDigest) || signatureDomain == "" || validationTime.IsZero() {
		return guarantor.ProfileQualifiedObjectAuthorizationV1{}, errors.New("Guarantor signing request is invalid")
	}
	return guarantor.SignObjectAuthorization(guarantor.AuthorizationStatementV1{SchemaVersion: 1,
		AuthoritySubject: signer.subject, ProfileURI: signer.profile.ProfileURI, ProfileVersion: signer.profile.ProfileVersion,
		ProfileDigest: signer.profile.ProfileDigest, AuthorizedObjectKind: kind, AuthorizedBodyDigest: bodyDigest,
		ValidationTimeUnix: uint64(validationTime.UTC().Unix())}, signatureDomain, signer.key, signer.historicalProof)
}

type GuarantorIssueOfferInput struct {
	Request                  guarantor.AuthorizedCoverageQuoteRequestV1
	ProfileArtifact          guarantor.GuarantorServiceProfileArtifactV1
	Agreement                commerce.AgentAgreementBody
	Terms                    guarantor.CoverageTermsV1
	CoverageObligationID     string
	AcceptByUnix             uint64
	ReservationExpiresAtUnix uint64
	ExpiresAtUnix            uint64
	IssuedAtUnix             uint64
}

type GuarantorProviderCoordinator struct {
	OwnerID                         string
	AgentID                         string
	MandateDigest                   string
	PolicyRevision                  uint64
	Policy                          GuarantorRiskPolicy
	Authority                       EconomicAuthority
	Journal                         *GuarantorJournal
	Signer                          GuarantorObjectSigner
	ActionAuthoritySigner           GuarantorObjectSigner
	FallbackSigner                  GuarantorObjectSigner
	Resolver                        guarantor.AuthorityKeyResolver
	PublicationResolver             commerce.AgentOperationAuthorityResolver
	AgreementVerifier               commerce.AgreementEvidenceVerifier
	UnderlyingAgreementResolver     guarantor.UnderlyingAgreementResolver
	EvidenceVerifier                GuarantorEvidenceVerifier
	PaymentVerifier                 commerce.PaymentEvidenceVerifier
	Underwriter                     GuarantorUnderwriter
	Eligibility                     GuarantorEligibilityAuthority
	RiskBuckets                     GuarantorRiskBucketAuthority
	CollateralAdapterEnabled        bool
	IndependentCollateralEnabled    bool
	CollateralAdapterProfileDigests []string
	CollateralFinalityVerifier      guarantor.CollateralAdapterFinalityVerifier
	ClosureFailureInjector          GuarantorClosureFailureInjector
}

// GuarantorClosureFailureInjector is used by deterministic crash campaigns.
// Production coordinators leave it nil; it cannot alter protocol data.
type GuarantorClosureFailureInjector interface {
	GuarantorClosureCheckpoint(string) error
}

type GuarantorEvidenceVerifier interface {
	VerifyGuarantorEvidence(context.Context, string, string, string, string) error
}

type GuarantorUnderwriter interface {
	EstimateGuarantorRisk(context.Context, guarantor.AuthorizedCoverageQuoteRequestV1, guarantor.ServiceProfileV1,
		commerce.AgentAgreementBody, time.Time) (GuarantorRiskEstimate, error)
}

type GuarantorEligibilityAuthority interface {
	// FreshEligibilityProofSet must return byte-identical historical finality
	// evidence when called again with the same purpose, subjects and instant.
	// Recovery refuses a reconstructed signed result if those bytes differ.
	FreshEligibilityProofSet(context.Context, string, []string, time.Time) ([]byte, error)
}

type GuarantorRiskBucketAuthority interface {
	RiskBucketDigests(context.Context, guarantor.AuthorizedCoverageQuoteRequestV1,
		commerce.AgentAgreementBody) (string, string, error)
}

type GuarantorClaimAdmissionResult struct {
	ClaimDigest         string
	IngressReceipt      guarantor.AuthorizedClaimSubmissionIngressReceiptV1
	AdmissionReceipt    guarantor.AuthorizedClaimAdmissionReceiptV1
	IngressResolution   commerce.ActionResolution
	AdmissionResolution commerce.ActionResolution
}

type GuarantorActivateCoverageInput struct {
	Offer                           guarantor.AuthorizedFirmCoverageOfferV1
	AcceptanceReceipt               guarantor.AuthorizedCoverageAcceptanceReceiptV1
	UnderlyingAgreement             commerce.AgentAgreementBody
	UnderlyingAuthorizationEvidence guarantor.GuarantorAgreementAuthorizationEvidenceSetV1
	PrerequisiteEvidenceSet         *guarantor.CanonicalGuarantorEvidenceSetV1
	CollateralLockEvidence          *guarantor.AuthorizedCollateralEvidenceV1
	ActivatedAtUnix                 uint64
}

// ActivateCoverage performs the accepted->active and not_open->open changes in
// one durable journal CAS. The returned envelope is portable: a beneficiary
// can verify the exact request, action, writer generation and terminal result
// without trusting the provider's private journal.
func (coordinator *GuarantorProviderCoordinator) ActivateCoverage(ctx context.Context, input GuarantorActivateCoverageInput,
	fence commerce.WriterFence) (guarantor.AuthorizedCoverageActivationEvidenceV1, commerce.ActionResolution, error) {
	if err := ctx.Err(); err != nil {
		return guarantor.AuthorizedCoverageActivationEvidenceV1{}, commerce.ActionResolution{}, err
	}
	if coordinator == nil || coordinator.Authority == nil || coordinator.Journal == nil || coordinator.Signer == nil ||
		coordinator.Resolver == nil || coordinator.PublicationResolver == nil || coordinator.AgreementVerifier == nil ||
		coordinator.UnderlyingAgreementResolver == nil || coordinator.Eligibility == nil ||
		input.ActivatedAtUnix == 0 {
		return guarantor.AuthorizedCoverageActivationEvidenceV1{}, commerce.ActionResolution{}, errors.New("Guarantor activation coordinator is incomplete")
	}
	activatedAt := time.Unix(int64(input.ActivatedAtUnix), 0).UTC()
	if err := coordinator.Authority.ConfirmCurrentWriterFence(fence, activatedAt); err != nil {
		return guarantor.AuthorizedCoverageActivationEvidenceV1{}, commerce.ActionResolution{}, err
	}
	if err := guarantor.VerifyFirmOffer(input.Offer, input.Offer.AuthorizedQuoteRequest,
		input.AcceptanceReceipt.AuthorizedAcceptanceRequest.CoverageAgreementBody, coordinator.Resolver,
		coordinator.PublicationResolver, coordinator.UnderlyingAgreementResolver, coordinator.AgreementVerifier,
		time.Unix(int64(input.AcceptanceReceipt.Body.AcceptedAtUnix), 0).UTC()); err != nil {
		return guarantor.AuthorizedCoverageActivationEvidenceV1{}, commerce.ActionResolution{}, err
	}
	if err := guarantor.VerifyCoverageAcceptanceReceiptV1(input.AcceptanceReceipt, input.Offer,
		coordinator.AgreementVerifier, coordinator.Resolver, coordinator.Authority, activatedAt); err != nil {
		return guarantor.AuthorizedCoverageActivationEvidenceV1{}, commerce.ActionResolution{}, err
	}
	terms := input.Offer.CoverageTerms
	if input.ActivatedAtUnix < terms.CoverageStartsAtUnix || input.ActivatedAtUnix >= terms.CoverageEndsAtUnix ||
		(input.PrerequisiteEvidenceSet != nil && guarantor.ValidateCanonicalGuarantorEvidenceSetV1(*input.PrerequisiteEvidenceSet) != nil) {
		return guarantor.AuthorizedCoverageActivationEvidenceV1{}, commerce.ActionResolution{}, errors.New("Guarantor activation schedule or prerequisite evidence is invalid")
	}
	underlyingDigest, err := commerce.AgreementBodyDigest(input.UnderlyingAgreement)
	if err != nil || underlyingDigest != terms.UnderlyingAgreementBodyDigest {
		return guarantor.AuthorizedCoverageActivationEvidenceV1{}, commerce.ActionResolution{}, errors.New("underlying Agreement differs from the accepted coverage")
	}
	if err := commerce.ValidateAgreementAuthorization(commerce.AgentAgreement{Body: input.UnderlyingAgreement,
		AuthorizationEvidence: input.UnderlyingAuthorizationEvidence.Evidence}, coordinator.AgreementVerifier, activatedAt); err != nil {
		return guarantor.AuthorizedCoverageActivationEvidenceV1{}, commerce.ActionResolution{}, errors.New("underlying Agreement authorization is incomplete")
	}
	if err := guarantor.VerifyCoveredUnderlyingAgreementV1(commerce.AgentAgreement{Body: input.UnderlyingAgreement,
		AuthorizationEvidence: input.UnderlyingAuthorizationEvidence.Evidence}, terms.UnderlyingAgreementBodyDigest,
		terms.CoveredPartyAgentID, terms.GuarantorAgentID, terms.CoveredObligationIDs,
		coordinator.AgreementVerifier, activatedAt); err != nil {
		return guarantor.AuthorizedCoverageActivationEvidenceV1{}, commerce.ActionResolution{}, err
	}
	agreementDigest := input.AcceptanceReceipt.Body.CoverageAgreementBodyDigest
	collateralEvidenceDigest := ""
	switch terms.SelectedAssuranceLevel {
	case guarantor.AssuranceUnsecuredSigned:
		if input.CollateralLockEvidence != nil {
			return guarantor.AuthorizedCoverageActivationEvidenceV1{}, commerce.ActionResolution{}, errors.New("unsecured Guarantor activation carries collateral evidence")
		}
	case guarantor.AssuranceCollateralAttested, guarantor.AssuranceIndependentlyEnforced:
		if !coordinator.CollateralAdapterEnabled || input.CollateralLockEvidence == nil || terms.CollateralTerms == nil ||
			coordinator.CollateralFinalityVerifier == nil ||
			(terms.SelectedAssuranceLevel == guarantor.AssuranceIndependentlyEnforced && !coordinator.IndependentCollateralEnabled) ||
			!containsString(coordinator.CollateralAdapterProfileDigests, terms.CollateralTerms.CustodyAdapterProfile.ProfileDigest) {
			return guarantor.AuthorizedCoverageActivationEvidenceV1{}, commerce.ActionResolution{}, errors.New("selected Guarantor collateral Adapter is not owner-enabled")
		}
		if err := guarantor.VerifyCollateralEvidenceV1(*input.CollateralLockEvidence, terms,
			coordinator.Resolver, coordinator.Authority, activatedAt, coordinator.CollateralFinalityVerifier, false); err != nil {
			return guarantor.AuthorizedCoverageActivationEvidenceV1{}, commerce.ActionResolution{}, err
		}
		collateral := input.CollateralLockEvidence
		if collateral.Body.CoverageAgreementBodyDigest != agreementDigest ||
			collateral.Body.CollateralObligationID != terms.CollateralObligationID || collateral.Body.TransitionKind != "lock" ||
			collateral.ResultingPositionState.Status != guarantor.CollateralLocked ||
			collateral.ResultingPositionState.AllocatedAmount != terms.CollateralTerms.Amount {
			return guarantor.AuthorizedCoverageActivationEvidenceV1{}, commerce.ActionResolution{}, errors.New("Guarantor activation collateral lock differs from accepted terms")
		}
		collateralEvidenceDigest, err = guarantor.CollateralEvidenceDigestV1(*collateral)
		if err != nil || input.PrerequisiteEvidenceSet == nil ||
			!guarantorEvidenceSetContains(*input.PrerequisiteEvidenceSet, collateralEvidenceDigest) {
			return guarantor.AuthorizedCoverageActivationEvidenceV1{}, commerce.ActionResolution{}, errors.New("Guarantor collateral lock is absent from activation prerequisites")
		}
	default:
		return guarantor.AuthorizedCoverageActivationEvidenceV1{}, commerce.ActionResolution{}, errors.New("unsupported Guarantor assurance level")
	}
	var coverage GuarantorCoveragePosition
	_, _, coverages := coordinator.Journal.Snapshot()
	for _, candidate := range coverages {
		if candidate.Record.CoverageAgreementBodyDigest == agreementDigest {
			coverage = candidate
		}
	}
	if coverage.Record.CoverageStatus != guarantor.CoveragePendingAuthorization ||
		coverage.Record.ClaimFilingStatus != guarantor.FilingNotOpen {
		return guarantor.AuthorizedCoverageActivationEvidenceV1{}, commerce.ActionResolution{}, errors.New("Guarantor coverage is not pending activation")
	}
	if len(terms.PremiumObligationIDs) > 0 && input.PrerequisiteEvidenceSet == nil {
		return guarantor.AuthorizedCoverageActivationEvidenceV1{}, commerce.ActionResolution{}, errors.New("Guarantor activation fee prerequisite evidence is absent")
	}
	prerequisiteDigest := ""
	if input.PrerequisiteEvidenceSet != nil {
		prerequisiteDigest, _ = guarantor.CanonicalGuarantorEvidenceSetDigestV1(*input.PrerequisiteEvidenceSet)
		if coordinator.EvidenceVerifier == nil || coordinator.EvidenceVerifier.VerifyGuarantorEvidence(ctx,
			"coverage-activation-prerequisites", prerequisiteDigest, agreementDigest, coverage.Record.CoverageObligationID) != nil {
			return guarantor.AuthorizedCoverageActivationEvidenceV1{}, commerce.ActionResolution{}, errors.New("Guarantor activation prerequisites did not verify")
		}
	}
	rawEligibilityProof, err := coordinator.Eligibility.FreshEligibilityProofSet(ctx, "coverage-activation",
		[]string{terms.GuarantorAgentID, terms.CoveredPartyAgentID, terms.BeneficiaryAgentID}, activatedAt)
	if err != nil || len(rawEligibilityProof) == 0 || len(rawEligibilityProof) > 64<<10 {
		return guarantor.AuthorizedCoverageActivationEvidenceV1{}, commerce.ActionResolution{}, errors.New("fresh Guarantor activation eligibility proof is unavailable")
	}
	acceptanceDigest, _ := guarantor.CoverageAcceptanceReceiptDigestV1(input.AcceptanceReceipt)
	offerDigest, _ := guarantor.FirmOfferDigest(input.Offer)
	exposureDigest, _ := guarantor.ExposureAdmissionReceiptDigestV1(input.Offer.ExposureAdmissionReceipt)
	underlyingEvidenceDigest, _ := guarantor.AgreementAuthorizationEvidenceSetDigestV1(input.UnderlyingAuthorizationEvidence)
	commitment := guarantor.CoverageEndCommitmentV1{SchemaVersion: 1, CoverageAgreementBodyDigest: agreementDigest,
		CoverageObligationID: coverage.Record.CoverageObligationID, CoverageStateDomainDigest: terms.CoverageStateDomainDigest,
		EndBranch: "scheduled", IncidentEligibilityEndsAtUnix: terms.CoverageEndsAtUnix}
	endDigest, _ := guarantor.CoverageEndCommitmentDigestV1(commitment)
	refs := []guarantor.TransitionEvidenceDigestRefV1{
		{EvidenceRole: "acceptance_receipt", DigestKind: "authorized_envelope", ObjectDigest: acceptanceDigest},
		{EvidenceRole: "exposure_receipt", DigestKind: "authorized_envelope", ObjectDigest: exposureDigest},
		{EvidenceRole: "firm_offer", DigestKind: "authorized_envelope", ObjectDigest: offerDigest},
		{EvidenceRole: "underlying_agreement_authorization", DigestKind: "canonical_set", ObjectDigest: underlyingEvidenceDigest},
		{EvidenceRole: "coverage_end_commitment", DigestKind: "canonical_object", ObjectDigest: endDigest},
	}
	if prerequisiteDigest != "" {
		refs = append(refs, guarantor.TransitionEvidenceDigestRefV1{EvidenceRole: "activation_prerequisites",
			DigestKind: "canonical_set", ObjectDigest: prerequisiteDigest})
	}
	if collateralEvidenceDigest != "" {
		refs = append(refs, guarantor.TransitionEvidenceDigestRefV1{EvidenceRole: "collateral_lock",
			DigestKind: "authorized_envelope", ObjectDigest: collateralEvidenceDigest})
	}
	sort.Slice(refs, func(i, j int) bool {
		left, _ := codec.Marshal(refs[i])
		right, _ := codec.Marshal(refs[j])
		return string(left) < string(right)
	})
	projection := guarantor.TransitionEvidenceProjectionV1{SchemaVersion: 1, Purpose: "coverage-activation",
		CoverageAgreementBodyDigest: agreementDigest, ObligationID: coverage.Record.CoverageObligationID,
		TargetState: "active", EvidenceDigests: refs}
	projectionDigest, err := guarantor.TransitionEvidenceProjectionDigestV1(projection)
	if err != nil {
		return guarantor.AuthorizedCoverageActivationEvidenceV1{}, commerce.ActionResolution{}, err
	}
	actionBody := guarantor.CoverageActivationActionBodyV1{SchemaVersion: 1, UnderlyingAgreementBody: input.UnderlyingAgreement,
		UnderlyingAuthorizationEvidenceSet: input.UnderlyingAuthorizationEvidence,
		AuthorizedAcceptanceReceipt:        input.AcceptanceReceipt, PrerequisiteEvidenceSet: input.PrerequisiteEvidenceSet,
		TargetCoverageEndCommitment: commitment, TransitionEvidenceProjection: projection,
		ExpectedCoverageRevision: coverage.Record.CoverageRevision, TargetCoverageRevision: coverage.Record.CoverageRevision + 1,
		ExpectedClaimFilingState: "not_open", TargetClaimFilingState: "open",
		ExpectedClaimFilingStateRevision: coverage.Record.FilingStateRevision,
		TargetClaimFilingStateRevision:   coverage.Record.FilingStateRevision + 1}
	canonicalRequest, err := codec.Marshal(actionBody)
	if err != nil {
		return guarantor.AuthorizedCoverageActivationEvidenceV1{}, commerce.ActionResolution{}, err
	}
	fields := map[string]commerce.SemanticValue{"owner_id": commerce.ID(coordinator.OwnerID), "agent_id": commerce.ID(coordinator.AgentID),
		"agreement_body_digest": commerce.Digest32(agreementDigest), "obligation_id": commerce.ID(coverage.Record.CoverageObligationID),
		"expected_state_revision": commerce.U64(coverage.Record.CoverageRevision), "target_state": commerce.State("active"),
		"evidence_set_digest": commerce.Digest32(projectionDigest)}
	action, err := commerce.BuildAuthorizedAction(coordinator.OwnerID, coordinator.AgentID, "conditional.obligation.transition",
		fields, canonicalRequest, fence, coordinator.PolicyRevision, coordinator.MandateDigest, "", coverage.Record.LastEvidenceDigest,
		minUint64(terms.CoverageEndsAtUnix, fence.Body.ExpiresAtUnix))
	if err == nil {
		action, err = coordinator.Authority.SignAction(action, fence)
	}
	if err != nil {
		return guarantor.AuthorizedCoverageActivationEvidenceV1{}, commerce.ActionResolution{}, err
	}
	activationDomainID, err := guarantor.ActivationAdmissionDomainIDV1(agreementDigest)
	if err != nil {
		return guarantor.AuthorizedCoverageActivationEvidenceV1{}, commerce.ActionResolution{}, err
	}
	activationAdmission, err := coordinator.Journal.BeginAdmission(activationDomainID, action.StableActionID,
		action.ExactRequestDigest, activatedAt)
	if err != nil {
		return guarantor.AuthorizedCoverageActivationEvidenceV1{}, commerce.ActionResolution{}, err
	}
	eligibilityProofSet, err := buildGuarantorEligibilityProofSet(rawEligibilityProof, action, acceptanceDigest,
		[]string{terms.GuarantorAgentID, terms.CoveredPartyAgentID, terms.BeneficiaryAgentID}, "coverage-activation",
		action.ExactRequestDigest, terms.CoverageStateDomainDigest, terms.LifecycleAuthorizationProfile,
		activationDomainID, activationAdmission.Sequence, input.ActivatedAtUnix)
	if err != nil {
		return guarantor.AuthorizedCoverageActivationEvidenceV1{}, commerce.ActionResolution{}, err
	}
	resolution, err := coordinator.Authority.Admit(action, fields, canonicalRequest, fence, nil)
	if err != nil {
		if commerce.ValidateActionResolution(resolution) == nil && isGuarantorAdmissionTerminal(resolution.State) {
			_, _ = coordinator.Journal.ResolveAdmission(activationDomainID, resolution)
		}
		return guarantor.AuthorizedCoverageActivationEvidenceV1{}, resolution, err
	}
	actionDigest, err := commerce.AuthorizedActionDigest(action)
	if err != nil {
		return guarantor.AuthorizedCoverageActivationEvidenceV1{}, resolution, err
	}
	if resolution.State == commerce.ActionPrepared {
		resolution, err = coordinator.Authority.Transition(action.StableActionID, action.ExactRequestDigest,
			commerce.ActionTerminal, actionDigest, []string{actionDigest})
		if err != nil {
			return guarantor.AuthorizedCoverageActivationEvidenceV1{}, resolution, err
		}
	} else if resolution.State != commerce.ActionTerminal {
		return guarantor.AuthorizedCoverageActivationEvidenceV1{}, resolution,
			errors.New("Guarantor activation action did not resolve terminally")
	}
	if _, err = coordinator.Journal.ResolveAdmission(activationDomainID, resolution); err != nil {
		return guarantor.AuthorizedCoverageActivationEvidenceV1{}, resolution, err
	}
	stage, err := coordinator.buildGuarantorStage(terms, "coverage_activation",
		"application/vnd.tos.service.agent-guarantor-coverage-activation-action.v1+cbor", canonicalRequest,
		action, resolution, fence, activatedAt)
	if err != nil {
		return guarantor.AuthorizedCoverageActivationEvidenceV1{}, resolution, err
	}
	coverageAuthorizationDigest, _ := guarantor.AgreementAuthorizationEvidenceSetDigestV1(
		input.AcceptanceReceipt.AuthorizedAcceptanceRequest.AuthorizationEvidenceSet)
	eligibilityDigest, _ := guarantor.AuthorityAdmissionEligibilityProofSetDigestV1(eligibilityProofSet)
	body := guarantor.CoverageActivationEvidenceBodyV1{SchemaVersion: 1, AuthorityID: action.AuthorityID,
		CoverageAgreementBodyDigest: agreementDigest, CoverageObligationID: coverage.Record.CoverageObligationID,
		CoverageStateDomainDigest: terms.CoverageStateDomainDigest, AuthorizationEvidenceSetDigest: coverageAuthorizationDigest,
		UnderlyingAgreementBodyDigest: underlyingDigest, UnderlyingAuthorizationEvidenceSetDigest: underlyingEvidenceDigest,
		AuthorizedFirmOfferEnvelopeDigest: offerDigest, AcceptanceReceiptDigest: acceptanceDigest, ExposureReceiptDigest: exposureDigest,
		PrerequisiteEvidenceSetDigest: prerequisiteDigest, SelectedAssuranceLevel: terms.SelectedAssuranceLevel,
		SelectedClaimProfileDigest: terms.SelectedClaimProfileDigest, TransitionEvidenceProjectionDigest: projectionDigest,
		AuthorizedActionDigest: actionDigest, StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest,
		WriterGeneration: action.WriterGeneration, WriterFenceDigest: action.WriterFenceDigest,
		PriorCoverageRevision: coverage.Record.CoverageRevision, ActivatedCoverageRevision: coverage.Record.CoverageRevision + 1,
		PriorClaimFilingState: "not_open", ActivatedClaimFilingState: "open",
		PriorClaimFilingStateRevision:        coverage.Record.FilingStateRevision,
		ActivatedClaimFilingStateRevision:    coverage.Record.FilingStateRevision + 1,
		ResultingCoverageEndCommitmentDigest: endDigest, ActivatedAtUnix: input.ActivatedAtUnix,
		CoverageEndsAtUnix: terms.CoverageEndsAtUnix, AuthorityAdmissionEligibilityProofSetDigest: eligibilityDigest}
	bodyDigest, _ := codec.Digest("tos.service.agent-guarantor-activation-evidence-body.v1", body)
	authorization, err := coordinator.Signer.SignObject("activation-evidence", bodyDigest,
		"tos.service.agent-guarantor-activation-evidence-signature.v1", activatedAt)
	if err != nil {
		return guarantor.AuthorizedCoverageActivationEvidenceV1{}, resolution, err
	}
	evidence := guarantor.AuthorizedCoverageActivationEvidenceV1{Body: body, StageActionAdmissionEvidence: stage,
		UnderlyingAgreementBody: input.UnderlyingAgreement, AuthorizedAcceptanceReceipt: input.AcceptanceReceipt,
		CoverageEndCommitment: commitment, UnderlyingAuthorizationEvidenceSet: input.UnderlyingAuthorizationEvidence,
		PrerequisiteEvidenceSet: input.PrerequisiteEvidenceSet, TransitionEvidenceProjection: projection,
		AuthorityAdmissionEligibilityProofSet: eligibilityProofSet,
		Authorizations:                        []guarantor.ProfileQualifiedObjectAuthorizationV1{authorization}}
	if err := guarantor.VerifyCoverageActivationEvidenceV1(evidence, input.Offer, coordinator.AgreementVerifier,
		coordinator.Resolver, coordinator.Authority, coordinator.CollateralFinalityVerifier, activatedAt); err != nil {
		return guarantor.AuthorizedCoverageActivationEvidenceV1{}, resolution, err
	}
	if _, err := coordinator.Journal.CommitActivationEvidence(agreementDigest, coverage.Record.CoverageRevision,
		coverage.Record.FilingStateRevision, evidence); err != nil {
		return guarantor.AuthorizedCoverageActivationEvidenceV1{}, resolution, err
	}
	return evidence, resolution, nil
}

func (coordinator *GuarantorProviderCoordinator) AdmitClaim(ctx context.Context, agreementDigest string,
	claim guarantor.AuthorizedCoverageClaimV1, fence commerce.WriterFence) (GuarantorClaimAdmissionResult, error) {
	if err := ctx.Err(); err != nil {
		return GuarantorClaimAdmissionResult{}, err
	}
	if coordinator == nil || coordinator.Authority == nil || coordinator.Journal == nil || coordinator.Resolver == nil ||
		coordinator.Signer == nil || coordinator.Eligibility == nil ||
		!canonicalSHA256(agreementDigest) {
		return GuarantorClaimAdmissionResult{}, errors.New("Guarantor claim coordinator is incomplete")
	}
	now := coordinator.Authority.AuthorityNow()
	if now.IsZero() || coordinator.Authority.ConfirmCurrentWriterFence(fence, now) != nil {
		return GuarantorClaimAdmissionResult{}, errors.New("Guarantor claim writer is stale")
	}
	var coverage GuarantorCoveragePosition
	_, _, positions := coordinator.Journal.Snapshot()
	for _, candidate := range positions {
		if candidate.Record.CoverageAgreementBodyDigest == agreementDigest {
			coverage = candidate
		}
	}
	if coverage.Record.CoverageAgreementBodyDigest == "" ||
		guarantor.VerifyClaim(claim, coverage.Terms, agreementDigest, coverage.Record.CoverageObligationID,
			coordinator.Resolver, now) != nil {
		return GuarantorClaimAdmissionResult{}, errors.New("Guarantor claim is not valid for the active coverage")
	}
	claimDigest, err := guarantor.ClaimEnvelopeDigest(claim)
	if err != nil {
		return GuarantorClaimAdmissionResult{}, err
	}
	canonicalClaimEnvelope, err := codec.Marshal(claim)
	if err != nil || uint64(len(canonicalClaimEnvelope)) > coverage.Terms.ClaimClosureCapacity.MaximumAdmittedClaimEnvelopeBytes {
		if err == nil {
			err = errors.New("Guarantor claim exceeds the accepted envelope bound")
		}
		return GuarantorClaimAdmissionResult{}, err
	}
	ingressRequest := guarantor.ClaimSubmissionIngressActionBodyV1{SchemaVersion: 1,
		AuthorizedClaim: claim, TargetIngressState: "received"}
	canonicalClaim, err := codec.Marshal(ingressRequest)
	if err != nil {
		return GuarantorClaimAdmissionResult{}, err
	}
	ingressFields := map[string]commerce.SemanticValue{"owner_id": commerce.ID(coordinator.OwnerID), "agent_id": commerce.ID(coordinator.AgentID),
		"agreement_body_digest": commerce.Digest32(agreementDigest), "obligation_id": commerce.ID(coverage.Record.CoverageObligationID),
		"claim_id": commerce.ID(claim.Body.ClaimID), "claim_revision": commerce.U64(claim.Body.ClaimRevision)}
	ingressAction, err := commerce.BuildAuthorizedAction(coordinator.OwnerID, coordinator.AgentID, "conditional.claim.ingress",
		ingressFields, canonicalClaim, fence, coordinator.PolicyRevision, coordinator.MandateDigest, "",
		coverage.Record.LastEvidenceDigest, claim.Body.ExpiresAtUnix)
	if err != nil {
		return GuarantorClaimAdmissionResult{}, err
	}
	ingressAction, err = coordinator.Authority.SignAction(ingressAction, fence)
	if err != nil {
		return GuarantorClaimAdmissionResult{}, err
	}
	ingressLogID, err := guarantor.ClaimIngressLogIDV1(agreementDigest, coverage.Record.CoverageObligationID,
		func() string {
			if claim.Body.ClaimRevision == 1 {
				return ""
			}
			return claim.Body.ClaimID
		}())
	if err != nil {
		return GuarantorClaimAdmissionResult{}, err
	}
	if _, err = coordinator.Journal.BeginClaimIngressAdmission(ingressLogID, ingressAction.StableActionID,
		ingressAction.ExactRequestDigest, now); err != nil {
		return GuarantorClaimAdmissionResult{}, err
	}
	ingressResolution, err := coordinator.Authority.Admit(ingressAction, ingressFields, canonicalClaim, fence, nil)
	if err != nil || ingressResolution.State != commerce.ActionPrepared {
		return GuarantorClaimAdmissionResult{IngressResolution: ingressResolution},
			firstError(err, errors.New("Guarantor claim ingress was not prepared"))
	}
	ingressResolution, err = coordinator.Authority.Transition(ingressAction.StableActionID, ingressAction.ExactRequestDigest,
		commerce.ActionTerminal, claimDigest, []string{claimDigest})
	if err != nil {
		return GuarantorClaimAdmissionResult{IngressResolution: ingressResolution}, err
	}
	if _, err = coordinator.Journal.ResolveAdmission(ingressLogID, ingressResolution); err != nil {
		return GuarantorClaimAdmissionResult{IngressResolution: ingressResolution}, err
	}
	priorIngressRoot, admittedIngressRoot, ingressSequence, err := coordinator.Journal.AdmissionEntryRoots(
		ingressLogID, ingressAction.StableActionID)
	if err != nil {
		return GuarantorClaimAdmissionResult{IngressResolution: ingressResolution}, err
	}
	ingressActionDigest, err := commerce.AuthorizedActionDigest(ingressAction)
	if err != nil {
		return GuarantorClaimAdmissionResult{IngressResolution: ingressResolution}, err
	}
	rawIngressEligibility, err := coordinator.Eligibility.FreshEligibilityProofSet(ctx, "claim-submission-ingress",
		coverage.Terms.ClaimIngressAuthoritySubjects, now)
	if err != nil {
		return GuarantorClaimAdmissionResult{IngressResolution: ingressResolution}, err
	}
	ingressEligibility, err := buildGuarantorEligibilityProofSet(rawIngressEligibility, ingressAction, claimDigest,
		coverage.Terms.ClaimIngressAuthoritySubjects, "claim-ingress-receipt", claimDigest,
		coverage.Terms.ClaimIngressProfile.ProfileDigest, coverage.Terms.ClaimIngressProfile,
		ingressLogID, ingressSequence, uint64(now.Unix()))
	if err != nil {
		return GuarantorClaimAdmissionResult{IngressResolution: ingressResolution}, err
	}
	ingressEligibilityDigest, err := guarantor.AuthorityAdmissionEligibilityProofSetDigestV1(ingressEligibility)
	if err != nil {
		return GuarantorClaimAdmissionResult{IngressResolution: ingressResolution}, err
	}
	ingressStateDomain, err := guarantor.ClaimIngressStateDomainDigestV1(agreementDigest, coverage.Record.CoverageObligationID)
	if err != nil {
		return GuarantorClaimAdmissionResult{IngressResolution: ingressResolution}, err
	}
	ingressStage, err := coordinator.buildGuarantorStage(coverage.Terms, "claim_submission_ingress",
		"application/vnd.tos.service.agent-guarantor-claim-ingress-action.v1+cbor", canonicalClaim,
		ingressAction, ingressResolution, fence, now)
	if err != nil {
		return GuarantorClaimAdmissionResult{IngressResolution: ingressResolution}, err
	}
	claimBodyDigest, err := guarantor.ClaimBodyDigest(claim.Body)
	if err != nil {
		return GuarantorClaimAdmissionResult{IngressResolution: ingressResolution}, err
	}
	ingressKind := "revision"
	if claim.Body.ClaimRevision == 1 {
		ingressKind = "initial"
	}
	ingressBody := guarantor.ClaimSubmissionIngressReceiptBodyV1{SchemaVersion: 1,
		AuthorityID: ingressAction.AuthorityID, CoverageAgreementBodyDigest: agreementDigest,
		CoverageObligationID: coverage.Record.CoverageObligationID, ClaimID: claim.Body.ClaimID,
		ClaimRevision: claim.Body.ClaimRevision, IngressKind: ingressKind, ClaimBodyDigest: claimBodyDigest,
		AuthorizedClaimEnvelopeDigest: claimDigest, IngressStateDomainDigest: ingressStateDomain,
		ClaimIngressLogID: ingressLogID, ClaimIngressSequence: ingressSequence,
		PriorClaimIngressLogRoot: priorIngressRoot, AdmittedClaimIngressLogRoot: admittedIngressRoot,
		IngressSlotRevision: 1, State: "received", AuthorizedActionDigest: ingressActionDigest,
		StableActionID: ingressAction.StableActionID, ExactRequestDigest: ingressAction.ExactRequestDigest,
		WriterGeneration: ingressAction.WriterGeneration, WriterFenceDigest: ingressAction.WriterFenceDigest,
		ReceivedAtUnix: uint64(now.Unix()), AuthorityAdmissionEligibilityProofSetDigest: ingressEligibilityDigest}
	ingressBodyDigest, err := codec.Digest("tos.service.agent-guarantor-claim-ingress-receipt-body.v1", ingressBody)
	if err != nil {
		return GuarantorClaimAdmissionResult{IngressResolution: ingressResolution}, err
	}
	ingressAuthorization, err := coordinator.Signer.SignObject("claim-ingress-receipt", ingressBodyDigest,
		"tos.service.agent-guarantor-claim-ingress-receipt-signature.v1", now)
	if err != nil {
		return GuarantorClaimAdmissionResult{IngressResolution: ingressResolution}, err
	}
	ingressReceipt := guarantor.AuthorizedClaimSubmissionIngressReceiptV1{Body: ingressBody,
		StageActionAdmissionEvidence: ingressStage, AuthorizedClaim: claim,
		AuthorityAdmissionEligibilityProofSet: ingressEligibility,
		Authorizations:                        []guarantor.ProfileQualifiedObjectAuthorizationV1{ingressAuthorization}}
	ingressReceiptDigest, err := guarantor.ClaimIngressReceiptDigestV1(ingressReceipt)
	if err != nil {
		return GuarantorClaimAdmissionResult{IngressResolution: ingressResolution}, err
	}
	preview, err := coordinator.Journal.PreviewClaimAdmission(agreementDigest, claim, claimDigest)
	if err != nil {
		return GuarantorClaimAdmissionResult{IngressReceipt: ingressReceipt, IngressResolution: ingressResolution}, err
	}
	if coverage.ActivationEvidence == nil {
		return GuarantorClaimAdmissionResult{IngressReceipt: ingressReceipt, IngressResolution: ingressResolution},
			errors.New("Guarantor claim has no portable activation predecessor")
	}
	effect := guarantor.ClaimSubmissionAuthorityInstanceEffectV1{SchemaVersion: 1,
		AuthorizedClaimIngressReceipt: ingressReceipt, AuthorizedCoverageActivationEvidence: *coverage.ActivationEvidence,
		ExpectedCoverageEndCommitment: coverage.ActivationEvidence.CoverageEndCommitment,
		ExpectedCoverageRevision:      preview.PriorCoverageRevision}
	canonicalEffect, err := codec.Marshal(effect)
	if err != nil {
		return GuarantorClaimAdmissionResult{IngressReceipt: ingressReceipt, IngressResolution: ingressResolution}, err
	}
	effectDigest, err := commerce.DownstreamEffectDescriptorDigest(canonicalEffect)
	if err != nil {
		return GuarantorClaimAdmissionResult{IngressReceipt: ingressReceipt, IngressResolution: ingressResolution}, err
	}
	instance, err := coordinator.Authority.AllocateInstance(commerce.AuthorityInstanceAllocationRequest{OwnerID: coordinator.OwnerID,
		AgentID: coordinator.AgentID, PurposeKind: "conditional.claim.submit", MandateDigest: coordinator.MandateDigest,
		ApprovalDigestOrZero: zeroSHA256Digest(), DownstreamEffectDescriptorDigest: effectDigest,
		PredecessorAuthorityInstanceID: zeroSHA256Digest()}, fence)
	if err != nil {
		return GuarantorClaimAdmissionResult{IngressResolution: ingressResolution}, err
	}
	admissionRequestBody := guarantor.ClaimSubmissionActionBodyV1{SchemaVersion: 1,
		AuthorityInstanceID: instance.AuthorityInstanceID, AuthorityInstanceRecord: instance,
		AuthorityInstanceEffect: effect}
	admissionRequest, err := codec.Marshal(admissionRequestBody)
	if err != nil {
		return GuarantorClaimAdmissionResult{IngressReceipt: ingressReceipt, IngressResolution: ingressResolution}, err
	}
	admissionFields := map[string]commerce.SemanticValue{"owner_id": commerce.ID(coordinator.OwnerID), "agent_id": commerce.ID(coordinator.AgentID),
		"agreement_body_digest": commerce.Digest32(agreementDigest), "obligation_id": commerce.ID(coverage.Record.CoverageObligationID),
		"authority_instance_id": commerce.Digest32(instance.AuthorityInstanceID), "claim_body_digest": commerce.Digest32(claimBodyDigest)}
	admissionAction, err := commerce.BuildAuthorizedAction(coordinator.OwnerID, coordinator.AgentID, "conditional.claim.submit",
		admissionFields, admissionRequest, fence, coordinator.PolicyRevision, coordinator.MandateDigest, "", ingressReceiptDigest,
		claim.Body.ExpiresAtUnix)
	if err != nil {
		return GuarantorClaimAdmissionResult{IngressResolution: ingressResolution}, err
	}
	admissionAction, err = coordinator.Authority.SignAction(admissionAction, fence)
	if err != nil {
		return GuarantorClaimAdmissionResult{IngressResolution: ingressResolution}, err
	}
	admissionResolution, err := coordinator.Authority.Admit(admissionAction, admissionFields, admissionRequest, fence, nil)
	if err != nil || admissionResolution.State != commerce.ActionPrepared {
		return GuarantorClaimAdmissionResult{IngressResolution: ingressResolution, AdmissionResolution: admissionResolution},
			firstError(err, errors.New("Guarantor claim admission was not prepared"))
	}
	admissionResolution, err = coordinator.Authority.Transition(admissionAction.StableActionID, admissionAction.ExactRequestDigest,
		commerce.ActionTerminal, claimDigest, []string{claimDigest})
	if err != nil {
		return GuarantorClaimAdmissionResult{IngressReceipt: ingressReceipt, IngressResolution: ingressResolution,
			AdmissionResolution: admissionResolution}, err
	}
	admissionActionDigest, err := commerce.AuthorizedActionDigest(admissionAction)
	if err != nil {
		return GuarantorClaimAdmissionResult{IngressReceipt: ingressReceipt, IngressResolution: ingressResolution,
			AdmissionResolution: admissionResolution}, err
	}
	rawAdmissionEligibility, err := coordinator.Eligibility.FreshEligibilityProofSet(ctx, "claim-admission",
		coverage.Terms.ClaimAdmissionAuthoritySubjects, now)
	if err != nil {
		return GuarantorClaimAdmissionResult{IngressReceipt: ingressReceipt, IngressResolution: ingressResolution,
			AdmissionResolution: admissionResolution}, err
	}
	admissionEligibility, err := buildGuarantorEligibilityProofSet(rawAdmissionEligibility, admissionAction,
		ingressReceiptDigest, coverage.Terms.ClaimAdmissionAuthoritySubjects, "claim-admission-receipt", claimDigest,
		coverage.Terms.ClaimAdmissionProfile.ProfileDigest, coverage.Terms.ClaimAdmissionProfile,
		coverage.Terms.CoverageStateDomainDigest, preview.ClaimRevisionAdmissionSequence, uint64(now.Unix()))
	if err != nil {
		return GuarantorClaimAdmissionResult{IngressReceipt: ingressReceipt, IngressResolution: ingressResolution,
			AdmissionResolution: admissionResolution}, err
	}
	admissionEligibilityDigest, err := guarantor.AuthorityAdmissionEligibilityProofSetDigestV1(admissionEligibility)
	if err != nil {
		return GuarantorClaimAdmissionResult{IngressReceipt: ingressReceipt, IngressResolution: ingressResolution,
			AdmissionResolution: admissionResolution}, err
	}
	admissionStageName := "claim_revision_admission"
	if preview.Initial {
		admissionStageName = "initial_claim_admission"
	}
	admissionStage, err := coordinator.buildGuarantorStage(coverage.Terms, admissionStageName,
		"application/vnd.tos.service.agent-guarantor-claim-admission-action.v1+cbor", admissionRequest,
		admissionAction, admissionResolution, fence, now)
	if err != nil {
		return GuarantorClaimAdmissionResult{IngressReceipt: ingressReceipt, IngressResolution: ingressResolution,
			AdmissionResolution: admissionResolution}, err
	}
	endDigest, err := guarantor.CoverageEndCommitmentDigestV1(effect.ExpectedCoverageEndCommitment)
	if err != nil {
		return GuarantorClaimAdmissionResult{IngressReceipt: ingressReceipt, IngressResolution: ingressResolution,
			AdmissionResolution: admissionResolution}, err
	}
	admissionKind := "revision"
	if preview.Initial {
		admissionKind = "initial"
	}
	admissionBody := guarantor.ClaimAdmissionReceiptBodyV1{SchemaVersion: 1,
		AuthorityID: admissionAction.AuthorityID, CoverageAgreementBodyDigest: agreementDigest,
		CoverageObligationID: coverage.Record.CoverageObligationID, ClaimID: claim.Body.ClaimID,
		AuthorizedClaimEnvelopeDigest: claimDigest, ClaimSubmissionIngressReceiptDigest: ingressReceiptDigest,
		AuthorityInstanceID: instance.AuthorityInstanceID, AuthorityInstanceAllocationRequestDigest: instance.RequestDigest,
		AuthorizedActionDigest: admissionActionDigest, StableActionID: admissionAction.StableActionID,
		ExactRequestDigest: admissionAction.ExactRequestDigest, PriorCoverageRevision: preview.PriorCoverageRevision,
		AdmittedCoverageRevision: preview.AdmittedCoverageRevision, PriorCoverageEndCommitmentDigest: endDigest,
		ResultingCoverageEndCommitmentDigest: endDigest, PriorClaimRevision: preview.PriorClaimRevision,
		AdmittedClaimRevision: preview.AdmittedClaimRevision, AdmissionKind: admissionKind,
		ClaimAdmissionLogID: preview.ClaimAdmissionLogID, ClaimAdmissionSequence: preview.ClaimAdmissionSequence,
		InitialClaimAdmissionReceiptDigest:        preview.InitialAdmissionReceiptDigest,
		ClaimRevisionLogID:                        preview.ClaimRevisionLogID,
		ClaimRevisionAdmissionSequence:            preview.ClaimRevisionAdmissionSequence,
		PredecessorRevisionAdmissionReceiptDigest: preview.PredecessorAdmissionReceiptDigest,
		PriorClaimAdmissionLogRoot:                preview.PriorClaimAdmissionLogRoot,
		AdmittedClaimAdmissionLogRoot:             preview.AdmittedClaimAdmissionLogRoot,
		PriorClaimRevisionLogRoot:                 preview.PriorClaimRevisionLogRoot,
		AdmittedClaimRevisionLogRoot:              preview.AdmittedClaimRevisionLogRoot,
		WriterGeneration:                          admissionAction.WriterGeneration, WriterFenceDigest: admissionAction.WriterFenceDigest,
		AdmittedAtUnix: uint64(now.Unix()), AuthorityAdmissionEligibilityProofSetDigest: admissionEligibilityDigest}
	admissionBodyDigest, err := codec.Digest("tos.service.agent-guarantor-claim-admission-receipt-body.v1", admissionBody)
	if err != nil {
		return GuarantorClaimAdmissionResult{IngressReceipt: ingressReceipt, IngressResolution: ingressResolution,
			AdmissionResolution: admissionResolution}, err
	}
	admissionAuthorization, err := coordinator.Signer.SignObject("claim-admission-receipt", admissionBodyDigest,
		"tos.service.agent-guarantor-claim-admission-receipt-signature.v1", now)
	if err != nil {
		return GuarantorClaimAdmissionResult{IngressReceipt: ingressReceipt, IngressResolution: ingressResolution,
			AdmissionResolution: admissionResolution}, err
	}
	admissionReceipt := guarantor.AuthorizedClaimAdmissionReceiptV1{Body: admissionBody,
		StageActionAdmissionEvidence: admissionStage, AuthorizedClaimIngressReceipt: ingressReceipt,
		CoverageEndCommitment: effect.ExpectedCoverageEndCommitment, AuthorityInstanceRecord: instance,
		AuthorityAdmissionEligibilityProofSet: admissionEligibility,
		Authorizations:                        []guarantor.ProfileQualifiedObjectAuthorizationV1{admissionAuthorization}}
	if err = guarantor.VerifyClaimAdmissionReceiptV1(admissionReceipt, coverage.Terms, coordinator.AgreementVerifier,
		coordinator.Resolver, coordinator.Authority, now); err != nil {
		return GuarantorClaimAdmissionResult{IngressReceipt: ingressReceipt, AdmissionReceipt: admissionReceipt,
			IngressResolution: ingressResolution, AdmissionResolution: admissionResolution}, err
	}
	if _, err = coordinator.Journal.CommitClaimAdmission(agreementDigest, ingressReceipt, admissionReceipt, preview); err != nil {
		return GuarantorClaimAdmissionResult{IngressReceipt: ingressReceipt, AdmissionReceipt: admissionReceipt,
			IngressResolution: ingressResolution, AdmissionResolution: admissionResolution}, err
	}
	return GuarantorClaimAdmissionResult{ClaimDigest: claimDigest, IngressReceipt: ingressReceipt,
		AdmissionReceipt: admissionReceipt, IngressResolution: ingressResolution,
		AdmissionResolution: admissionResolution}, nil
}

type GuarantorApplyDecisionInput struct {
	AgreementDigest           string
	DecisionAdmissionReceipt  guarantor.AuthorizedClaimDecisionAdmissionReceiptV1
	TerminalTransitionReceipt guarantor.AuthorizedClaimStateTransitionReceiptV1
}

type GuarantorDecisionApplicationResult struct {
	Payouts    guarantor.MaterializedPayoutObligationSetV1
	Receipt    guarantor.AuthorizedClaimDecisionApplicationReceiptV1
	Resolution commerce.ActionResolution
}

func (coordinator *GuarantorProviderCoordinator) ApplyClaimDecision(ctx context.Context,
	input GuarantorApplyDecisionInput, fence commerce.WriterFence) (GuarantorDecisionApplicationResult, error) {
	if err := ctx.Err(); err != nil {
		return GuarantorDecisionApplicationResult{}, err
	}
	if coordinator == nil || coordinator.Authority == nil || coordinator.Journal == nil || coordinator.Signer == nil ||
		coordinator.Resolver == nil || coordinator.AgreementVerifier == nil || !canonicalSHA256(input.AgreementDigest) {
		return GuarantorDecisionApplicationResult{}, errors.New("Guarantor decision application coordinator is incomplete")
	}
	now := coordinator.Authority.AuthorityNow().UTC()
	if now.IsZero() || coordinator.Authority.ConfirmCurrentWriterFence(fence, now) != nil {
		return GuarantorDecisionApplicationResult{}, errors.New("Guarantor decision application writer is stale")
	}
	coverage, err := coordinator.coveragePosition(input.AgreementDigest)
	if err != nil {
		return GuarantorDecisionApplicationResult{}, err
	}
	admission := input.DecisionAdmissionReceipt
	transition := input.TerminalTransitionReceipt
	if err := guarantor.VerifyClaimDecisionAdmissionReceiptV1(admission, coverage.Terms, coordinator.AgreementVerifier,
		coordinator.Resolver, coordinator.Authority, now); err != nil {
		return GuarantorDecisionApplicationResult{}, err
	}
	admissionEnvelopeDigest, err := guarantor.ClaimDecisionAdmissionReceiptDigestV1(admission)
	if err != nil {
		return GuarantorDecisionApplicationResult{}, err
	}
	if err := guarantor.VerifyClaimStateTransitionReceiptV1(transition, coverage.Terms, coordinator.AgreementVerifier,
		coordinator.Resolver, coordinator.Authority, now); err != nil || transition.Body.TransitionKind != "challenge_close" ||
		transition.DecisionAdmissionProof.ReceiptEnvelopeDigest != admissionEnvelopeDigest {
		return GuarantorDecisionApplicationResult{}, errors.New("Guarantor decision application lacks the exact terminal challenge close")
	}
	decision := admission.AuthorizedClaimDecision
	claimID := decision.Body.ClaimID
	claim, claimFound := coverage.ClaimEnvelopes[claimID]
	record, recordFound := coverage.Claims[claimID]
	token, tokenFound := coverage.DecisionApplicationTokens[claimID]
	if !claimFound || !recordFound || !tokenFound || !sameJSON(coverage.DecisionAdmissionReceipts[claimID], admission) ||
		!sameJSON(coverage.ClaimStateTransitionReceipts[claimID], transition) || token.State != "pending" ||
		record.ClaimStateRevision != transition.Body.ResultingClaimStateRevision {
		return GuarantorDecisionApplicationResult{}, errors.New("Guarantor decision application has no current pending token")
	}
	transitionDigest, err := guarantor.ClaimStateTransitionReceiptDigestV1(transition)
	if err != nil {
		return GuarantorDecisionApplicationResult{}, err
	}
	payouts, err := guarantor.MaterializeClaimPayout(coordinator.OwnerID, coordinator.AgentID, coordinator.MandateDigest,
		coverage.Terms.PayoutTemplate.AgreementObligationID, coverage.Terms, decision,
		transitionDigest, transition.Body.TransitionedAtUnix, coverage.NextPayoutSequence)
	if err != nil {
		return GuarantorDecisionApplicationResult{}, err
	}
	pendingAfter, err := atomicSub(coverage.AggregatePendingDecisionReserveAtomic, token.ReservedApprovedAmount.AmountAtomic)
	if err != nil {
		return GuarantorDecisionApplicationResult{}, err
	}
	targetPending := commerce.AtomicAmountV1{Asset: coverage.Terms.CoverageAsset, AmountAtomic: pendingAfter}
	decisionDigest, err := guarantor.ClaimDecisionDigestV1(decision)
	if err != nil {
		return GuarantorDecisionApplicationResult{}, err
	}
	claimAdmissionDigest, err := guarantor.ClaimAdmissionReceiptDigestV1(admission.AuthorizedClaimAdmissionReceipt)
	if err != nil {
		return GuarantorDecisionApplicationResult{}, err
	}
	admissionDigest, err := guarantor.ClaimDecisionAdmissionReceiptDigestV1(admission)
	if err != nil {
		return GuarantorDecisionApplicationResult{}, err
	}
	endDigest, err := guarantor.CoverageEndCommitmentDigestV1(admission.CoverageEndCommitment)
	if err != nil {
		return GuarantorDecisionApplicationResult{}, err
	}
	templateDigest, err := commerce.ConditionalSettlementTemplateDigestV1(coverage.Terms.PayoutTemplate)
	if err != nil {
		return GuarantorDecisionApplicationResult{}, err
	}
	requestBody := guarantor.ClaimDecisionApplicationActionBodyV1{SchemaVersion: 1,
		AuthorizedClaimDecisionDigest: decisionDigest, AuthorizedClaimAdmissionReceiptDigest: claimAdmissionDigest,
		AuthorizedClaimDecisionAdmissionReceiptDigest:       admissionDigest,
		AuthorizedTerminalClaimStateTransitionReceiptDigest: transitionDigest,
		DecisionApplicationToken:                            token, ExpectedCoverageEndCommitmentDigest: endDigest,
		PayoutTemplateDigest: templateDigest, ExpectedCurrentCoverageRevision: coverage.Record.CoverageRevision,
		TargetCoverageRevision: coverage.Record.CoverageRevision + 1,
		ExpectedAggregatePendingDecisionReserve: commerce.AtomicAmountV1{Asset: coverage.Terms.CoverageAsset,
			AmountAtomic: coverage.AggregatePendingDecisionReserveAtomic}, TargetAggregatePendingDecisionReserve: targetPending,
		ExpectedApplicationTokenRevision: token.TokenRevision, ExpectedClaimStateRevision: record.ClaimStateRevision,
		TargetClaimState: transition.Body.ResultingClaimState, ExpectedNextPayoutSequence: coverage.NextPayoutSequence,
		ExpectedMaterializedPayoutLineDigest: coverage.MaterializedPayoutLineDigest}
	canonicalRequest, err := codec.Marshal(requestBody)
	if err != nil {
		return GuarantorDecisionApplicationResult{}, err
	}
	bound, err := guarantor.FindStageActionAuthorityV1(coverage.Terms.StageActionAuthorityBinding, "decision_application")
	if err != nil {
		return GuarantorDecisionApplicationResult{}, err
	}
	claimDigest, _ := guarantor.ClaimEnvelopeDigest(claim)
	fields := guarantor.ClaimDecisionApplicationSemanticFieldsV1(bound, requestBody, decision, claimDigest)
	action, err := commerce.BuildAuthorizedAction(coordinator.OwnerID, coordinator.AgentID, "conditional.claim.decide", fields,
		canonicalRequest, fence, coordinator.PolicyRevision, coordinator.MandateDigest, "", record.LastEvidenceDigest,
		coverage.Terms.TerminalResolutionDeadlineUnix)
	if err != nil {
		return GuarantorDecisionApplicationResult{}, err
	}
	action, err = coordinator.Authority.SignAction(action, fence)
	if err != nil {
		return GuarantorDecisionApplicationResult{}, err
	}
	resolution, err := coordinator.Authority.Admit(action, fields, canonicalRequest, fence, nil)
	if err != nil || resolution.State != commerce.ActionPrepared {
		return GuarantorDecisionApplicationResult{Payouts: payouts, Resolution: resolution},
			firstError(err, errors.New("Guarantor decision application action was not prepared"))
	}
	tokenDigest, _ := guarantor.DecisionApplicationTokenDigestV1(token)
	payoutDigest, _ := codec.Digest(guarantor.PayoutSetDomain, payouts)
	actionDigest, _ := commerce.AuthorizedActionDigest(action)
	resultingLineDigest := coverage.MaterializedPayoutLineDigest
	if len(payouts.MaterializedLines) > 0 {
		resultingLineDigest, _ = codec.Digest("tos.service.agent-guarantor-materialized-payout-line.v1",
			payouts.MaterializedLines[len(payouts.MaterializedLines)-1])
	}
	cumulativeAfter, err := atomicAdd(coverage.CumulativeAppliedApprovedAtomic, token.ReservedApprovedAmount.AmountAtomic)
	if err != nil {
		return GuarantorDecisionApplicationResult{Payouts: payouts, Resolution: resolution}, err
	}
	resultingNext := coverage.NextPayoutSequence + uint64(len(payouts.MaterializedLines))
	body := guarantor.ClaimDecisionApplicationReceiptBodyV1{SchemaVersion: 1, AuthorityID: action.AuthorityID,
		CoverageAgreementBodyDigest: input.AgreementDigest, CoverageObligationID: coverage.Record.CoverageObligationID,
		ClaimID: claimID, AuthorizedClaimDecisionDigest: decisionDigest, ClaimDecisionAdmissionReceiptDigest: admissionDigest,
		TerminalClaimStateTransitionReceiptDigest: transitionDigest, DecisionApplicationTokenID: token.TokenID,
		DecisionApplicationTokenDigest: tokenDigest, PriorApplicationTokenRevision: token.TokenRevision,
		ResultingApplicationTokenRevision: token.TokenRevision + 1, ResultingApplicationTokenState: "consumed",
		MaterializedPayoutObligationSetDigest: payoutDigest, AuthorizedActionDigest: actionDigest,
		StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest,
		WriterGeneration: action.WriterGeneration, WriterFenceDigest: action.WriterFenceDigest,
		PriorCoverageRevision: coverage.Record.CoverageRevision, AppliedCoverageRevision: coverage.Record.CoverageRevision + 1,
		PriorCoverageEndCommitmentDigest: endDigest, ResultingCoverageEndCommitmentDigest: endDigest,
		PriorClaimStateRevision: record.ClaimStateRevision, AppliedClaimStateRevision: record.ClaimStateRevision,
		PriorNextPayoutSequence: coverage.NextPayoutSequence, ResultingNextPayoutSequence: resultingNext,
		PriorMaterializedPayoutLineDigest:     coverage.MaterializedPayoutLineDigest,
		ResultingMaterializedPayoutLineDigest: resultingLineDigest,
		CumulativeApprovedBefore: commerce.AtomicAmountV1{Asset: coverage.Terms.CoverageAsset,
			AmountAtomic: coverage.CumulativeAppliedApprovedAtomic},
		CumulativeApprovedAfter:               commerce.AtomicAmountV1{Asset: coverage.Terms.CoverageAsset, AmountAtomic: cumulativeAfter},
		AggregatePendingDecisionReserveBefore: requestBody.ExpectedAggregatePendingDecisionReserve,
		AggregatePendingDecisionReserveAfter:  targetPending, AppliedAtUnix: uint64(now.Unix())}
	bodyDigest, err := codec.Digest("tos.service.agent-guarantor-claim-decision-application-receipt-body.v1", body)
	if err != nil {
		return GuarantorDecisionApplicationResult{Payouts: payouts, Resolution: resolution}, err
	}
	authorization, err := coordinator.Signer.SignObject("claim-decision-application-receipt", bodyDigest,
		"tos.service.agent-guarantor-claim-decision-application-signature.v1", now)
	if err != nil {
		return GuarantorDecisionApplicationResult{Payouts: payouts, Resolution: resolution}, err
	}
	resolution, err = coordinator.Authority.Transition(action.StableActionID, action.ExactRequestDigest,
		commerce.ActionTerminal, payoutDigest, sortedGuarantorEvidence(decisionDigest, admissionDigest, transitionDigest, payoutDigest, bodyDigest))
	if err != nil {
		return GuarantorDecisionApplicationResult{Payouts: payouts, Resolution: resolution}, err
	}
	stage, err := coordinator.buildGuarantorStage(coverage.Terms, "decision_application",
		"application/vnd.tos.service.agent-guarantor-decision-application.v1+cbor", canonicalRequest, action, resolution, fence, now)
	if err != nil {
		return GuarantorDecisionApplicationResult{Payouts: payouts, Resolution: resolution}, err
	}
	receipt := guarantor.AuthorizedClaimDecisionApplicationReceiptV1{Body: body, StageActionAdmissionEvidence: stage,
		CoverageEndCommitment: admission.CoverageEndCommitment, AuthorizedTerminalClaimStateTransitionReceipt: transition,
		DecisionApplicationToken: token, MaterializedPayoutObligationSet: payouts,
		Authorizations: []guarantor.ProfileQualifiedObjectAuthorizationV1{authorization}}
	if err := guarantor.VerifyClaimDecisionApplicationReceiptV1(receipt, coverage.Terms, coordinator.AgreementVerifier,
		coordinator.Resolver, coordinator.Authority, now); err != nil {
		return GuarantorDecisionApplicationResult{Payouts: payouts, Receipt: receipt, Resolution: resolution}, err
	}
	if _, err := coordinator.Journal.CommitDecisionApplication(input.AgreementDigest, receipt); err != nil {
		return GuarantorDecisionApplicationResult{Payouts: payouts, Receipt: receipt, Resolution: resolution}, err
	}
	return GuarantorDecisionApplicationResult{Payouts: payouts, Receipt: receipt, Resolution: resolution}, nil
}

type GuarantorAcceptCoverageInput struct {
	Offer                guarantor.AuthorizedFirmCoverageOfferV1
	Request              guarantor.AuthorizedCoverageAcceptanceRequestV1
	CoverageObligationID string
	ReceivedAtUnix       uint64
}

type GuarantorCloseExpiredOfferInput struct {
	Offer guarantor.AuthorizedFirmCoverageOfferV1
}

type GuarantorCloseExpiredOfferResult struct {
	NonAcceptanceEvidence guarantor.AuthorizedOfferNonAcceptanceEvidenceV1
	ReleaseReceipt        guarantor.AuthorizedPreAcceptanceExposureReleaseReceiptV1
	ExpiryResolution      commerce.ActionResolution
	ReleaseResolution     commerce.ActionResolution
}

func (coordinator *GuarantorProviderCoordinator) CloseExpiredOffer(ctx context.Context,
	input GuarantorCloseExpiredOfferInput, fence commerce.WriterFence) (GuarantorCloseExpiredOfferResult, error) {
	if err := ctx.Err(); err != nil {
		return GuarantorCloseExpiredOfferResult{}, err
	}
	if coordinator == nil || coordinator.Authority == nil || coordinator.Journal == nil || coordinator.Signer == nil ||
		coordinator.Resolver == nil {
		return GuarantorCloseExpiredOfferResult{}, errors.New("Guarantor offer close coordinator is incomplete")
	}
	now := coordinator.Authority.AuthorityNow().UTC()
	if now.IsZero() || coordinator.Authority.ConfirmCurrentWriterFence(fence, now) != nil {
		return GuarantorCloseExpiredOfferResult{}, errors.New("Guarantor offer close writer is stale")
	}
	profile, err := guarantor.ResolveServiceProfileArtifactV1(input.Offer.ServiceProfileArtifact,
		coordinator.PublicationResolver, now)
	if err != nil {
		return GuarantorCloseExpiredOfferResult{}, err
	}
	profileDigest, err := guarantor.ServiceProfileDigest(profile)
	if err != nil || profileDigest != input.Offer.Body.ServiceProfileDigest {
		return GuarantorCloseExpiredOfferResult{}, errors.New("Guarantor offer close service profile differs")
	}
	cutoff, overflow := addUint64(input.Offer.Body.AcceptByUnix, profile.AdmissionLimits.MaximumAcceptanceProcessingGraceSeconds)
	if overflow || uint64(now.Unix()) <= cutoff {
		return GuarantorCloseExpiredOfferResult{}, errors.New("Guarantor offer acceptance drain has not ended")
	}
	offerDigest, err := guarantor.FirmOfferDigest(input.Offer)
	if err != nil {
		return GuarantorCloseExpiredOfferResult{}, err
	}
	var offerPosition GuarantorOfferPosition
	_, offers, _ := coordinator.Journal.Snapshot()
	for _, candidate := range offers {
		if candidate.Record.OfferID == input.Offer.Body.OfferID {
			offerPosition = candidate
		}
	}
	if offerPosition.Record.Status == guarantor.OfferReleased && offerPosition.NonAcceptanceEvidence != nil &&
		offerPosition.PreAcceptanceReleaseReceipt != nil {
		expiry := coordinator.Authority.Resolve(offerPosition.NonAcceptanceEvidence.Body.StableActionID,
			offerPosition.NonAcceptanceEvidence.Body.ExactRequestDigest)
		release := coordinator.Authority.Resolve(offerPosition.PreAcceptanceReleaseReceipt.Body.StableActionID,
			offerPosition.PreAcceptanceReleaseReceipt.Body.ExactRequestDigest)
		return GuarantorCloseExpiredOfferResult{NonAcceptanceEvidence: *offerPosition.NonAcceptanceEvidence,
			ReleaseReceipt: *offerPosition.PreAcceptanceReleaseReceipt, ExpiryResolution: expiry, ReleaseResolution: release}, nil
	}
	if (offerPosition.Record.Status != guarantor.OfferIssued && offerPosition.Record.Status != guarantor.OfferExpired) ||
		offerPosition.OfferEnvelopeDigest != offerDigest {
		return GuarantorCloseExpiredOfferResult{}, errors.New("Guarantor offer is not an exact live issued offer")
	}
	acceptanceDomainID, _ := codec.Digest("tos.service.agent-guarantor-acceptance-admission-domain.v1", struct {
		OfferID string `json:"offer_id"`
	}{input.Offer.Body.OfferID})
	cut, err := coordinator.Journal.FreezeAdmissionCut(acceptanceDomainID, input.Offer.Body.AcceptByUnix)
	if err != nil {
		return GuarantorCloseExpiredOfferResult{}, err
	}
	for _, entry := range cut.Entries {
		if entry.Resolution.State != commerce.ActionRejected && entry.Resolution.State != commerce.ActionConflict {
			return GuarantorCloseExpiredOfferResult{}, errors.New("Guarantor offer has an accepted or unresolved acceptance action")
		}
	}
	issuance := coordinator.Authority.Resolve(input.Offer.ExposureAdmissionReceipt.Body.StableActionID,
		input.Offer.ExposureAdmissionReceipt.Body.ExactRequestDigest)
	if issuance.State != commerce.ActionTerminal {
		return GuarantorCloseExpiredOfferResult{}, errors.New("Guarantor offer issuance is not terminal")
	}
	result := GuarantorCloseExpiredOfferResult{}
	if offerPosition.Record.Status == guarantor.OfferExpired && offerPosition.NonAcceptanceEvidence != nil {
		result.NonAcceptanceEvidence = *offerPosition.NonAcceptanceEvidence
		result.ExpiryResolution = coordinator.Authority.Resolve(result.NonAcceptanceEvidence.Body.StableActionID,
			result.NonAcceptanceEvidence.Body.ExactRequestDigest)
		if result.ExpiryResolution.State == commerce.ActionPrepared {
			nonAcceptanceDigest, digestErr := guarantor.OfferNonAcceptanceDigestV1(result.NonAcceptanceEvidence)
			if digestErr != nil {
				return result, digestErr
			}
			result.ExpiryResolution, err = coordinator.Authority.Transition(
				result.NonAcceptanceEvidence.Body.StableActionID,
				result.NonAcceptanceEvidence.Body.ExactRequestDigest,
				commerce.ActionTerminal, nonAcceptanceDigest, []string{nonAcceptanceDigest})
			if err != nil {
				return result, err
			}
		}
		if result.ExpiryResolution.State != commerce.ActionTerminal {
			return result, errors.New("Guarantor offer expiry action is not terminal")
		}
	} else {
		expiryBody := guarantor.OfferNonAcceptanceResolutionActionBodyV1{SchemaVersion: 1,
			AuthorityInstanceID: input.Offer.Body.OfferID, AuthorizedFirmOffer: input.Offer,
			IssuanceActionResolution: issuance, ReleaseReason: "acceptance_window_closed",
			AcceptanceCutoffUnix: input.Offer.Body.AcceptByUnix, ExpectedReservationRevision: offerPosition.Record.StateRevision,
			ExpectedOfferStateRevision: offerPosition.Record.StateRevision, TargetOfferStateRevision: offerPosition.Record.StateRevision + 1}
		expiryRequest, marshalErr := codec.Marshal(expiryBody)
		if marshalErr != nil {
			return result, marshalErr
		}
		expiryFields := map[string]commerce.SemanticValue{"owner_id": commerce.ID(coordinator.OwnerID), "agent_id": commerce.ID(coordinator.AgentID),
			"agreement_body_digest": commerce.Digest32(input.Offer.Body.CoverageAgreementBodyDigest),
			"authority_instance_id": commerce.Digest32(input.Offer.Body.OfferID), "reservation_id": commerce.Digest32(input.Offer.Body.ReservationID),
			"expected_offer_state_revision": commerce.U64(offerPosition.Record.StateRevision), "target_state": commerce.State("expired")}
		expiryAction, buildErr := commerce.BuildAuthorizedAction(coordinator.OwnerID, coordinator.AgentID, "commercial.quote.close",
			expiryFields, expiryRequest, fence, coordinator.PolicyRevision, coordinator.MandateDigest, "", offerDigest, fence.Body.ExpiresAtUnix)
		if buildErr == nil {
			expiryAction, buildErr = coordinator.Authority.SignAction(expiryAction, fence)
		}
		if buildErr != nil {
			return result, buildErr
		}
		expiryResolution, admitErr := coordinator.Authority.Admit(expiryAction, expiryFields, expiryRequest, fence, nil)
		if admitErr != nil || expiryResolution.State != commerce.ActionPrepared {
			return result, firstError(admitErr, errors.New("Guarantor offer expiry was not prepared"))
		}
		actionDigest, _ := commerce.AuthorizedActionDigest(expiryAction)
		nonAcceptanceBody := guarantor.OfferNonAcceptanceEvidenceBodyV1{SchemaVersion: 1, AuthorityID: expiryAction.AuthorityID,
			AuthorityInstanceID: input.Offer.Body.OfferID, ReservationID: input.Offer.Body.ReservationID,
			AuthorizedFirmOfferEnvelopeDigest: offerDigest, AcceptanceAdmissionLogID: cut.DomainID,
			AcceptanceAdmissionHighWater: cut.HighWater, AcceptanceAdmissionLogRoot: cut.LogRoot,
			AcceptanceCutoffUnix: input.Offer.Body.AcceptByUnix, SequencedByCutoffCount: uint64(len(cut.Entries)),
			TerminalRejectedCount: uint64(len(cut.Entries)), ExpectedReservationRevision: offerPosition.Record.StateRevision,
			PriorOfferStateRevision: offerPosition.Record.StateRevision, ResolvedOfferStateRevision: offerPosition.Record.StateRevision + 1,
			AuthorizedActionDigest: actionDigest, StableActionID: expiryAction.StableActionID,
			ExactRequestDigest: expiryAction.ExactRequestDigest, WriterGeneration: expiryAction.WriterGeneration,
			WriterFenceDigest: expiryAction.WriterFenceDigest, ResolvedAtUnix: uint64(now.Unix())}
		bodyDigest, _ := codec.Digest("tos.service.agent-guarantor-offer-non-acceptance-body.v1", nonAcceptanceBody)
		authorization, signErr := coordinator.Signer.SignObject("offer-non-acceptance", bodyDigest,
			"tos.service.agent-guarantor-offer-non-acceptance-signature.v1", now)
		if signErr != nil {
			return result, signErr
		}
		nonAcceptance := guarantor.AuthorizedOfferNonAcceptanceEvidenceV1{Body: nonAcceptanceBody,
			AuthorizedFirmOffer: input.Offer, IssuanceActionResolution: issuance,
			Authorizations: []guarantor.ProfileQualifiedObjectAuthorizationV1{authorization}}
		if verifyErr := guarantor.VerifyOfferNonAcceptanceV1(nonAcceptance, coordinator.Resolver, now); verifyErr != nil {
			return result, verifyErr
		}
		nonAcceptanceDigest, _ := guarantor.OfferNonAcceptanceDigestV1(nonAcceptance)
		if _, transitionErr := coordinator.Journal.ExpireOffer(input.Offer.Body.OfferID,
			offerPosition.Record.StateRevision, nonAcceptance, now); transitionErr != nil {
			return result, transitionErr
		}
		expiryResolution, transitionErr := coordinator.Authority.Transition(expiryAction.StableActionID,
			expiryAction.ExactRequestDigest, commerce.ActionTerminal, nonAcceptanceDigest, []string{nonAcceptanceDigest})
		if transitionErr != nil {
			return result, transitionErr
		}
		result.NonAcceptanceEvidence, result.ExpiryResolution = nonAcceptance, expiryResolution
		offerPosition.Record.StateRevision++
	}
	nonAcceptanceDigest, _ := guarantor.OfferNonAcceptanceDigestV1(result.NonAcceptanceEvidence)
	exposureReceiptDigest, _ := guarantor.ExposureAdmissionReceiptDigestV1(input.Offer.ExposureAdmissionReceipt)
	projection := guarantor.PreAcceptanceExposureReleaseEvidenceProjectionV1{SchemaVersion: 1,
		AuthorityInstanceID: input.Offer.Body.OfferID, ReservationID: input.Offer.Body.ReservationID,
		ExposureReceiptDigest: exposureReceiptDigest, AuthorizedFirmOfferEnvelopeDigest: offerDigest,
		ReleaseReason: "acceptance_window_closed", NonAcceptanceEvidenceDigest: nonAcceptanceDigest}
	projectionDigest, _ := codec.Digest("tos.service.agent-guarantor-pre-acceptance-release-evidence-projection.v1", projection)
	var plan GuarantorPreAcceptanceReleasePlan
	if offerPosition.PreAcceptanceReleasePlan != nil {
		plan = *offerPosition.PreAcceptanceReleasePlan
	} else {
		portfolioRevision, _, _ := coordinator.Authority.Snapshot()
		releaseBody := guarantor.PreAcceptanceExposureReleaseActionBodyV1{SchemaVersion: 1, ReleaseVariant: "pre_acceptance",
			AuthorizedNonAcceptanceEvidence: result.NonAcceptanceEvidence, ReleaseEvidenceProjection: projection,
			ExpectedPortfolioRevision: portfolioRevision, TargetPortfolioRevision: portfolioRevision + 1,
			ExpectedReservedExposure: input.Offer.ExposureAdmissionReceipt.Body.ReservedExposure}
		releaseBytes, marshalErr := codec.Marshal(releaseBody)
		if marshalErr != nil {
			return result, marshalErr
		}
		releaseFields := map[string]commerce.SemanticValue{"owner_id": commerce.ID(coordinator.OwnerID), "agent_id": commerce.ID(coordinator.AgentID),
			"reservation_id": commerce.Digest32(input.Offer.Body.ReservationID), "target_revision": commerce.U64(portfolioRevision + 1),
			"terminal_evidence_set_digest": commerce.Digest32(nonAcceptanceDigest)}
		releaseAction, buildErr := commerce.BuildAuthorizedAction(coordinator.OwnerID, coordinator.AgentID, "portfolio.release", releaseFields,
			releaseBytes, fence, coordinator.PolicyRevision, coordinator.MandateDigest, "", nonAcceptanceDigest,
			minUint64(input.Offer.ExposureAdmissionReceipt.Body.ExpiresAtUnix, fence.Body.ExpiresAtUnix))
		if buildErr == nil {
			releaseAction, buildErr = coordinator.Authority.SignAction(releaseAction, fence)
		}
		if buildErr != nil {
			return result, buildErr
		}
		plan = GuarantorPreAcceptanceReleasePlan{Action: releaseAction, Fields: releaseFields, CanonicalRequest: releaseBytes,
			RequestBody: releaseBody, BasePortfolioRevision: portfolioRevision, TargetPortfolioRevision: portfolioRevision + 1,
			ReleasedAtUnix: uint64(now.Unix())}
		if _, storeErr := coordinator.Journal.StoreOfferReleasePlan(input.Offer.Body.OfferID, plan); storeErr != nil {
			return result, storeErr
		}
	}
	effectiveReleaseAction := plan.Action
	releaseResolution := coordinator.Authority.Resolve(plan.Action.StableActionID, plan.Action.ExactRequestDigest)
	if releaseResolution.State != commerce.ActionTerminal {
		effectiveReleaseAction, err = commerce.BuildAuthorizedAction(plan.Action.OwnerID, plan.Action.AgentID,
			plan.Action.ActionKind, plan.Fields, plan.CanonicalRequest, fence, plan.Action.PolicyRevision,
			plan.Action.MandateDigest, plan.Action.ApprovalDigest, plan.Action.ExpectedPriorState,
			minUint64(input.Offer.ExposureAdmissionReceipt.Body.ExpiresAtUnix, fence.Body.ExpiresAtUnix))
		if err == nil {
			effectiveReleaseAction, err = coordinator.Authority.SignAction(effectiveReleaseAction, fence)
		}
		if err != nil {
			return result, err
		}
		if !sameJSON(effectiveReleaseAction, plan.Action) {
			if _, err := coordinator.Journal.RefreshOfferReleasePlanAction(input.Offer.Body.OfferID,
				effectiveReleaseAction); err != nil {
				return result, err
			}
			plan.Action = effectiveReleaseAction
		}
		releaseResolution, err = coordinator.Authority.ReleaseReservation(effectiveReleaseAction, plan.Fields,
			plan.CanonicalRequest, fence)
		if err != nil {
			return result, err
		}
	}
	releaseBody := guarantor.PreAcceptanceExposureReleaseReceiptBodyV1{SchemaVersion: 1, AuthorityID: effectiveReleaseAction.AuthorityID,
		GuarantorAgentID: coordinator.AgentID, AuthorityInstanceID: input.Offer.Body.OfferID,
		ReservationID: input.Offer.Body.ReservationID, ExposureReceiptDigest: exposureReceiptDigest,
		AuthorizedFirmOfferEnvelopeDigest: offerDigest, ReleaseReason: "acceptance_window_closed",
		NonAcceptanceEvidenceDigest: nonAcceptanceDigest, ReleaseEvidenceProjectionDigest: projectionDigest,
		StableActionID: effectiveReleaseAction.StableActionID, ExactRequestDigest: effectiveReleaseAction.ExactRequestDigest,
		WriterGeneration: effectiveReleaseAction.WriterGeneration, WriterFenceDigest: effectiveReleaseAction.WriterFenceDigest,
		BasePortfolioRevision: plan.BasePortfolioRevision, ReleasedPortfolioRevision: plan.TargetPortfolioRevision,
		ReleasedExposure:          input.Offer.ExposureAdmissionReceipt.Body.ReservedExposure,
		RemainingReservedExposure: commerce.AtomicAmountV1{Asset: input.Offer.ExposureAdmissionReceipt.Body.ReservedExposure.Asset, AmountAtomic: "0"},
		State:                     "released_unaccepted", ReleasedAtUnix: plan.ReleasedAtUnix}
	releaseBody.AuthorizedActionDigest, _ = commerce.AuthorizedActionDigest(effectiveReleaseAction)
	releaseBodyDigest, _ := codec.Digest("tos.service.agent-guarantor-pre-acceptance-release-receipt-body.v1", releaseBody)
	releaseAuthorization, err := coordinator.Signer.SignObject("pre-acceptance-exposure-release", releaseBodyDigest,
		"tos.service.agent-guarantor-pre-acceptance-release-receipt-signature.v1", time.Unix(int64(plan.ReleasedAtUnix), 0).UTC())
	if err != nil {
		return result, err
	}
	releaseReceipt := guarantor.AuthorizedPreAcceptanceExposureReleaseReceiptV1{Body: releaseBody,
		AuthorizedNonAcceptanceEvidence: result.NonAcceptanceEvidence, ReleaseEvidenceProjection: projection,
		Authorizations: []guarantor.ProfileQualifiedObjectAuthorizationV1{releaseAuthorization}}
	if _, err := guarantor.PreAcceptanceExposureReleaseReceiptDigestV1(releaseReceipt); err != nil {
		return result, err
	}
	if _, err := coordinator.Journal.ReleaseExpiredOffer(input.Offer.Body.OfferID,
		offerPosition.Record.StateRevision, releaseReceipt); err != nil {
		return result, err
	}
	result.ReleaseReceipt, result.ReleaseResolution = releaseReceipt, releaseResolution
	return result, nil
}

func addUint64(left, right uint64) (uint64, bool) {
	if ^uint64(0)-left < right {
		return 0, true
	}
	return left + right, false
}

func (coordinator *GuarantorProviderCoordinator) AcceptCoverage(ctx context.Context, input GuarantorAcceptCoverageInput,
	fence commerce.WriterFence) (guarantor.AuthorizedCoverageAcceptanceReceiptV1, commerce.ActionResolution, error) {
	if err := ctx.Err(); err != nil {
		return guarantor.AuthorizedCoverageAcceptanceReceiptV1{}, commerce.ActionResolution{}, err
	}
	if coordinator == nil || coordinator.Authority == nil || coordinator.Journal == nil || coordinator.Signer == nil ||
		coordinator.Resolver == nil || coordinator.PublicationResolver == nil || coordinator.AgreementVerifier == nil ||
		coordinator.UnderlyingAgreementResolver == nil || coordinator.Eligibility == nil ||
		input.CoverageObligationID == "" || input.ReceivedAtUnix == 0 {
		return guarantor.AuthorizedCoverageAcceptanceReceiptV1{}, commerce.ActionResolution{}, errors.New("Guarantor acceptance coordinator is incomplete")
	}
	receivedAt := time.Unix(int64(input.ReceivedAtUnix), 0).UTC()
	if err := coordinator.Authority.ConfirmCurrentWriterFence(fence, receivedAt); err != nil {
		return guarantor.AuthorizedCoverageAcceptanceReceiptV1{}, commerce.ActionResolution{}, err
	}
	if err := guarantor.VerifyFirmOffer(input.Offer, input.Offer.AuthorizedQuoteRequest,
		input.Request.CoverageAgreementBody, coordinator.Resolver, coordinator.PublicationResolver,
		coordinator.UnderlyingAgreementResolver, coordinator.AgreementVerifier, receivedAt); err != nil {
		return guarantor.AuthorizedCoverageAcceptanceReceiptV1{}, commerce.ActionResolution{}, fmt.Errorf("verify firm offer before acceptance: %w", err)
	}
	if err := guarantor.VerifyCoverageAcceptanceRequestV1(input.Request, input.Offer, coordinator.AgreementVerifier,
		coordinator.Resolver, receivedAt); err != nil {
		return guarantor.AuthorizedCoverageAcceptanceReceiptV1{}, commerce.ActionResolution{}, fmt.Errorf("verify coverage-acceptance request: %w", err)
	}
	rawEligibilityProof, err := coordinator.Eligibility.FreshEligibilityProofSet(ctx, "coverage-acceptance",
		[]string{input.Request.Body.AcceptingSubject, coordinator.AgentID}, receivedAt)
	if err != nil || len(rawEligibilityProof) == 0 || len(rawEligibilityProof) > 64<<10 {
		return guarantor.AuthorizedCoverageAcceptanceReceiptV1{}, commerce.ActionResolution{}, errors.New("fresh Guarantor acceptance eligibility proof is unavailable")
	}
	offerDigest, _ := guarantor.FirmOfferDigest(input.Offer)
	requestDigest, _ := guarantor.CoverageAcceptanceRequestDigestV1(input.Request)
	agreementDigest := input.Request.Body.CoverageAgreementBodyDigest
	var priorOfferRevision uint64
	var storedReceipt *guarantor.AuthorizedCoverageAcceptanceReceiptV1
	_, positions, coverages := coordinator.Journal.Snapshot()
	for _, position := range positions {
		if position.Record.OfferID == input.Offer.Body.OfferID && position.OfferEnvelopeDigest == offerDigest {
			if position.Record.Status == guarantor.OfferIssued {
				priorOfferRevision = position.Record.StateRevision
			} else if position.Record.Status == guarantor.OfferAccepted {
				for _, coverage := range coverages {
					if coverage.Record.CoverageAgreementBodyDigest == agreementDigest && coverage.AcceptanceReceipt != nil {
						priorOfferRevision = coverage.AcceptanceReceipt.Body.PriorOfferStateRevision
						receipt := *coverage.AcceptanceReceipt
						storedReceipt = &receipt
					}
				}
			}
		}
	}
	if priorOfferRevision == 0 {
		return guarantor.AuthorizedCoverageAcceptanceReceiptV1{}, commerce.ActionResolution{}, errors.New("Guarantor acceptance has no exact live offer")
	}
	bound, err := guarantor.AuxiliaryStageActionAuthorityV1(input.Offer.CoverageTerms.StageActionAuthorityBinding,
		"coverage_acceptance")
	if err != nil {
		return guarantor.AuthorizedCoverageAcceptanceReceiptV1{}, commerce.ActionResolution{}, err
	}
	projection := guarantor.TransitionEvidenceProjectionV1{SchemaVersion: 1, Purpose: "coverage-acceptance",
		CoverageAgreementBodyDigest: agreementDigest, ObligationID: input.CoverageObligationID, TargetState: "accepted",
		EvidenceDigests: []guarantor.TransitionEvidenceDigestRefV1{{EvidenceRole: "acceptance-request",
			DigestKind: "authorized_envelope", ObjectDigest: requestDigest}}}
	projectionDigest, err := guarantor.TransitionEvidenceProjectionDigestV1(projection)
	if err != nil {
		return guarantor.AuthorizedCoverageAcceptanceReceiptV1{}, commerce.ActionResolution{}, err
	}
	actionRequest := guarantor.CoverageAcceptanceAdmissionActionBodyV1{SchemaVersion: 1,
		AuthorizedAcceptanceRequest: input.Request, TransitionEvidenceProjection: projection,
		ExpectedReservationRevision: input.Offer.ExposureAdmissionReceipt.Body.AdmittedPortfolioRevision,
		ExpectedOfferStateRevision:  priorOfferRevision, TargetOfferStateRevision: priorOfferRevision + 1,
		ExpectedCoverageRevision: 0, TargetCoverageRevision: 1, ExpectedClaimFilingState: "uninitialized",
		TargetClaimFilingState: "not_open", ExpectedClaimFilingStateRevision: 0, TargetClaimFilingStateRevision: 1}
	canonicalRequest, err := codec.Marshal(actionRequest)
	if err != nil {
		return guarantor.AuthorizedCoverageAcceptanceReceiptV1{}, commerce.ActionResolution{}, err
	}
	fields := map[string]commerce.SemanticValue{"owner_id": commerce.ID(coordinator.OwnerID), "agent_id": commerce.ID(coordinator.AgentID),
		"agreement_body_digest": commerce.Digest32(agreementDigest), "obligation_id": commerce.ID(input.CoverageObligationID),
		"expected_state_revision": commerce.U64(priorOfferRevision), "target_state": commerce.State("accepted"),
		"evidence_set_digest": commerce.Digest32(projectionDigest)}
	action, err := commerce.BuildAuthorizedAction(bound.ActionOwnerID, bound.ActionAgentID, "conditional.obligation.transition", fields,
		canonicalRequest, fence, coordinator.PolicyRevision, coordinator.MandateDigest, "", offerDigest,
		input.Request.Body.ExpiresAtUnix)
	if err != nil {
		return guarantor.AuthorizedCoverageAcceptanceReceiptV1{}, commerce.ActionResolution{}, err
	}
	action, err = coordinator.Authority.SignAction(action, fence)
	if err != nil {
		return guarantor.AuthorizedCoverageAcceptanceReceiptV1{}, commerce.ActionResolution{}, err
	}
	admissionDomainID, err := guarantor.CoverageAcceptanceAdmissionDomainIDV1(bound.AdmissionStateDomainDigest, input.Offer.Body.OfferID)
	if err != nil {
		return guarantor.AuthorizedCoverageAcceptanceReceiptV1{}, commerce.ActionResolution{}, err
	}
	acceptanceAdmission, err := coordinator.Journal.BeginAdmission(admissionDomainID, action.StableActionID,
		action.ExactRequestDigest, receivedAt)
	if err != nil {
		return guarantor.AuthorizedCoverageAcceptanceReceiptV1{}, commerce.ActionResolution{}, err
	}
	eligibilityProofSet, err := buildGuarantorEligibilityProofSet(rawEligibilityProof, action, requestDigest,
		[]string{input.Request.Body.AcceptingSubject, coordinator.AgentID}, "coverage-acceptance",
		action.ExactRequestDigest, input.Offer.CoverageTerms.CoverageStateDomainDigest,
		input.Offer.CoverageTerms.LifecycleAuthorizationProfile, admissionDomainID, acceptanceAdmission.Sequence,
		input.ReceivedAtUnix)
	if err != nil {
		return guarantor.AuthorizedCoverageAcceptanceReceiptV1{}, commerce.ActionResolution{}, err
	}
	resolution, err := coordinator.Authority.Admit(action, fields, canonicalRequest, fence, nil)
	if err != nil {
		return guarantor.AuthorizedCoverageAcceptanceReceiptV1{}, resolution, err
	}
	if isTerminalActionResolution(resolution.State) {
		_, _ = coordinator.Journal.ResolveAdmission(admissionDomainID, resolution)
		if resolution.State == commerce.ActionTerminal && storedReceipt != nil {
			return *storedReceipt, resolution, nil
		}
		return guarantor.AuthorizedCoverageAcceptanceReceiptV1{}, resolution,
			errors.New("Guarantor acceptance was already terminal without a recoverable receipt")
	}
	if resolution.State != commerce.ActionPrepared {
		return guarantor.AuthorizedCoverageAcceptanceReceiptV1{}, resolution,
			errors.New("Guarantor acceptance action was not prepared")
	}
	acceptanceEvidenceRefs := []string{requestDigest, projectionDigest}
	sort.Strings(acceptanceEvidenceRefs)
	resolution, err = coordinator.Authority.Transition(action.StableActionID, action.ExactRequestDigest,
		commerce.ActionTerminal, projectionDigest, acceptanceEvidenceRefs)
	if err != nil {
		return guarantor.AuthorizedCoverageAcceptanceReceiptV1{}, resolution, err
	}
	stage, err := coordinator.buildGuarantorStage(input.Offer.CoverageTerms, "coverage_acceptance",
		"application/vnd.tos.service.agent-guarantor-acceptance-admission.v1+cbor", canonicalRequest,
		action, resolution, fence, receivedAt)
	if err != nil {
		return guarantor.AuthorizedCoverageAcceptanceReceiptV1{}, resolution, fmt.Errorf("build coverage-acceptance stage: %w", err)
	}
	proofDigest, _ := guarantor.AuthorityAdmissionEligibilityProofSetDigestV1(eligibilityProofSet)
	receiptBody := guarantor.CoverageAcceptanceReceiptBodyV1{SchemaVersion: 1, AuthorityID: action.AuthorityID,
		CoverageAgreementBodyDigest: agreementDigest, AuthorizedFirmOfferEnvelopeDigest: offerDigest,
		AuthorizedAcceptanceRequestEnvelopeDigest: requestDigest,
		ExposureAdmissionReceiptDigest:            input.Offer.Body.ExposureAdmissionReceiptDigest, ReservationID: input.Offer.Body.ReservationID,
		TransitionEvidenceProjectionDigest: projectionDigest, AuthorizedActionDigest: mustActionDigest(action),
		StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest,
		WriterGeneration: action.WriterGeneration, WriterFenceDigest: action.WriterFenceDigest,
		PriorOfferStateRevision: priorOfferRevision, AcceptedOfferStateRevision: priorOfferRevision + 1,
		PriorCoverageRevision: 0, AcceptedCoverageRevision: 1,
		PriorClaimFilingState: "uninitialized", AcceptedClaimFilingState: "not_open",
		PriorClaimFilingStateRevision: 0, AcceptedClaimFilingStateRevision: 1,
		ReceivedAtUnix: input.ReceivedAtUnix, AcceptedAtUnix: input.ReceivedAtUnix,
		AuthorityAdmissionEligibilityProofSetDigest: proofDigest}
	bodyDigest, _ := codec.Digest("tos.service.agent-guarantor-acceptance-receipt-body.v1", receiptBody)
	authorization, err := coordinator.Signer.SignObject("coverage-acceptance-receipt", bodyDigest,
		"tos.service.agent-guarantor-acceptance-receipt-signature.v1", receivedAt)
	if err != nil {
		return guarantor.AuthorizedCoverageAcceptanceReceiptV1{}, resolution, err
	}
	receipt := guarantor.AuthorizedCoverageAcceptanceReceiptV1{Body: receiptBody, StageActionAdmissionEvidence: stage,
		AuthorizedAcceptanceRequest: input.Request, TransitionEvidenceProjection: projection,
		AuthorityAdmissionEligibilityProofSet: eligibilityProofSet,
		Authorizations:                        []guarantor.ProfileQualifiedObjectAuthorizationV1{authorization}}
	if err := guarantor.VerifyCoverageAcceptanceReceiptV1(receipt, input.Offer, coordinator.AgreementVerifier,
		coordinator.Resolver, coordinator.Authority, receivedAt); err != nil {
		return guarantor.AuthorizedCoverageAcceptanceReceiptV1{}, resolution, fmt.Errorf("verify coverage-acceptance receipt: %w", err)
	}
	coverage, err := coordinator.Journal.AcceptOffer(input.Offer.Body.OfferID, agreementDigest, input.Offer.CoverageTerms,
		input.CoverageObligationID, requestDigest, receipt, receivedAt)
	if err != nil {
		rejected, transitionErr := coordinator.Authority.Transition(action.StableActionID, action.ExactRequestDigest,
			commerce.ActionRejected, requestDigest, []string{requestDigest})
		if transitionErr == nil {
			_, _ = coordinator.Journal.ResolveAdmission(admissionDomainID, rejected)
			resolution = rejected
		}
		return guarantor.AuthorizedCoverageAcceptanceReceiptV1{}, resolution, err
	}
	if coverage.Record.CoverageRevision != receipt.Body.AcceptedCoverageRevision ||
		coverage.Record.FilingStateRevision != receipt.Body.AcceptedClaimFilingStateRevision {
		return guarantor.AuthorizedCoverageAcceptanceReceiptV1{}, resolution, errors.New("Guarantor acceptance journal produced an unexpected revision")
	}
	_, err = coordinator.Journal.ResolveAdmission(admissionDomainID, resolution)
	return receipt, resolution, err
}

func isTerminalActionResolution(state commerce.ActionResolutionState) bool {
	return state == commerce.ActionTerminal || state == commerce.ActionRejected || state == commerce.ActionConflict ||
		state == commerce.ActionAccepted
}

func guarantorEvidenceSetContains(set guarantor.CanonicalGuarantorEvidenceSetV1, digest string) bool {
	for _, item := range set.Items {
		if item.EvidenceEnvelopeDigest == digest {
			return true
		}
	}
	return false
}

func (coordinator *GuarantorProviderCoordinator) IssueFirmOffer(ctx context.Context, input GuarantorIssueOfferInput,
	fence commerce.WriterFence) (guarantor.AuthorizedFirmCoverageOfferV1, commerce.ActionResolution, error) {
	if err := ctx.Err(); err != nil {
		return guarantor.AuthorizedFirmCoverageOfferV1{}, commerce.ActionResolution{}, err
	}
	if coordinator == nil || coordinator.Authority == nil || coordinator.Journal == nil || coordinator.Signer == nil ||
		coordinator.Resolver == nil || coordinator.PublicationResolver == nil || coordinator.UnderlyingAgreementResolver == nil ||
		coordinator.AgreementVerifier == nil || coordinator.Underwriter == nil || coordinator.Eligibility == nil || coordinator.RiskBuckets == nil ||
		coordinator.OwnerID == "" || coordinator.AgentID == "" || coordinator.PolicyRevision == 0 ||
		!canonicalSHA256(coordinator.MandateDigest) || input.CoverageObligationID == "" {
		return guarantor.AuthorizedFirmCoverageOfferV1{}, commerce.ActionResolution{}, errors.New("Guarantor provider coordinator is incomplete")
	}
	issuedAt := time.Unix(int64(input.IssuedAtUnix), 0).UTC()
	if input.IssuedAtUnix == 0 || input.AcceptByUnix <= input.IssuedAtUnix ||
		input.ReservationExpiresAtUnix <= input.AcceptByUnix || input.ExpiresAtUnix < input.ReservationExpiresAtUnix {
		return guarantor.AuthorizedFirmCoverageOfferV1{}, commerce.ActionResolution{}, errors.New("Guarantor offer schedule is invalid")
	}
	if err := coordinator.Authority.ConfirmCurrentWriterFence(fence, issuedAt); err != nil {
		return guarantor.AuthorizedFirmCoverageOfferV1{}, commerce.ActionResolution{}, err
	}
	profile, err := guarantor.ResolveServiceProfileArtifactV1(input.ProfileArtifact,
		coordinator.PublicationResolver, issuedAt)
	if err != nil {
		return guarantor.AuthorizedFirmCoverageOfferV1{}, commerce.ActionResolution{}, err
	}
	if err := guarantor.VerifyQuoteRequest(input.Request, profile, coordinator.Resolver,
		coordinator.UnderlyingAgreementResolver, coordinator.AgreementVerifier, issuedAt); err != nil {
		return guarantor.AuthorizedFirmCoverageOfferV1{}, commerce.ActionResolution{}, err
	}
	if err := guarantor.ValidateCoverageTermsAgainstServiceProfile(input.Terms, profile); err != nil || commerce.ValidateAgreementBody(input.Agreement) != nil {
		return guarantor.AuthorizedFirmCoverageOfferV1{}, commerce.ActionResolution{}, errors.New("Guarantor coverage Agreement or terms are invalid")
	}
	if err := coordinator.validateAssuranceDeployment(input.Terms); err != nil {
		return guarantor.AuthorizedFirmCoverageOfferV1{}, commerce.ActionResolution{}, err
	}
	agreementDigest, _ := commerce.AgreementBodyDigest(input.Agreement)
	requestDigest, _ := guarantor.QuoteRequestDigest(input.Request)
	termsDigest, _ := guarantor.CoverageTermsDigest(input.Terms)
	profileDigest, _ := guarantor.ServiceProfileDigest(profile)
	if input.Terms.QuoteRequestDigest != requestDigest || input.Terms.ServiceProfileDigest != profileDigest ||
		input.Terms.GuarantorAgentID != coordinator.AgentID || input.Terms.CoveredPartyAgentID != input.Request.Body.CoveredPartyAgentID ||
		input.Terms.BeneficiaryAgentID != input.Request.Body.BeneficiaryAgentID || input.Terms.CoverageEndsAtUnix > input.Terms.ClaimFilingEndsAtUnix {
		return guarantor.AuthorizedFirmCoverageOfferV1{}, commerce.ActionResolution{}, errors.New("Guarantor terms differ from the quote request")
	}
	estimate, err := coordinator.Underwriter.EstimateGuarantorRisk(ctx, input.Request, profile, input.Agreement, issuedAt)
	if err != nil {
		return guarantor.AuthorizedFirmCoverageOfferV1{}, commerce.ActionResolution{}, err
	}
	policyBucketDigest, correlationBucketDigest, err := coordinator.RiskBuckets.RiskBucketDigests(ctx, input.Request, input.Agreement)
	if err != nil || !canonicalSHA256(policyBucketDigest) || !canonicalSHA256(correlationBucketDigest) {
		return guarantor.AuthorizedFirmCoverageOfferV1{}, commerce.ActionResolution{}, errors.New("owner Guarantor risk buckets are unavailable")
	}
	rawEligibilityProof, err := coordinator.Eligibility.FreshEligibilityProofSet(ctx, "firm-offer-issuance",
		[]string{input.Request.Body.RequesterAgentID, input.Request.Body.CoveredPartyAgentID, input.Request.Body.BeneficiaryAgentID}, issuedAt)
	if err != nil || len(rawEligibilityProof) == 0 || len(rawEligibilityProof) > 64<<10 {
		return guarantor.AuthorizedFirmCoverageOfferV1{}, commerce.ActionResolution{}, errors.New("fresh Guarantor quote eligibility proof is unavailable")
	}
	portfolio := coordinator.portfolioFor(input.Request.Body.CoveredPartyAgentID, input.Terms.CoverageAsset)
	decision, err := EvaluateGuarantorQuote(input.Request, coordinator.Policy, estimate, portfolio, issuedAt)
	if err != nil || !decision.Admitted {
		if err != nil {
			return guarantor.AuthorizedFirmCoverageOfferV1{}, commerce.ActionResolution{}, err
		}
		return guarantor.AuthorizedFirmCoverageOfferV1{}, commerce.ActionResolution{}, errors.New("Guarantor quote rejected: " + decision.Reason)
	}
	baseRevision, _, _ := coordinator.Authority.Snapshot()
	if baseRevision == 0 {
		return guarantor.AuthorizedFirmCoverageOfferV1{}, commerce.ActionResolution{}, errors.New("Guarantor economic authority is unavailable")
	}
	scope := guarantor.ProviderExposureReservationScopeV1{SchemaVersion: 1, OwnerID: coordinator.OwnerID,
		GuarantorAgentID: coordinator.AgentID, CoverageAgreementBodyDigest: agreementDigest,
		CoverageObligationID: input.CoverageObligationID, CoverageAsset: input.Terms.CoverageAsset,
		MaximumAggregatePayout: input.Terms.MaximumAggregatePayout, SelectedAssuranceLevel: input.Terms.SelectedAssuranceLevel,
		PolicyBucketDigest: policyBucketDigest, CorrelationBucketDigest: correlationBucketDigest,
		DefaultLiabilityDisposition: "retain", ReservationExpiresAtUnix: input.ReservationExpiresAtUnix}
	scopeDigest, err := guarantor.ExposureReservationScopeDigestV1(scope)
	if err != nil {
		return guarantor.AuthorizedFirmCoverageOfferV1{}, commerce.ActionResolution{}, err
	}
	descriptor := guarantor.ProviderExposureAdmissionDescriptorV1{SchemaVersion: 1, GuarantorAgentID: coordinator.AgentID,
		ServiceProfileDigest: profileDigest, QuoteRequestDigest: requestDigest, CoverageID: input.Terms.CoverageID,
		CoverageVersion: input.Terms.CoverageVersion, CoverageAgreementBodyDigest: agreementDigest, CoverageTermsDigest: termsDigest,
		ReservationScope: scope, ReservationScopeDigest: scopeDigest, ReservedExposure: input.Terms.MaximumAggregatePayout,
		CollateralCredit:   commerce.AtomicAmountV1{Asset: input.Terms.CoverageAsset, AmountAtomic: decision.CollateralCreditAtomic},
		PolicyBucketDigest: policyBucketDigest, CorrelationBucketDigest: correlationBucketDigest,
		BasePortfolioRevision: baseRevision, ReservationExpiresAtUnix: input.ReservationExpiresAtUnix}
	claimants := append([]string(nil), input.Terms.PermittedClaimantSubjects...)
	sort.Strings(claimants)
	acceptanceSet := map[string]struct{}{}
	for _, predicate := range input.Agreement.AuthorizationPredicates {
		acceptanceSet[predicate.AuthoritySubject.SubjectIdentifier] = struct{}{}
	}
	acceptanceSubjects := make([]string, 0, len(acceptanceSet))
	for subject := range acceptanceSet {
		acceptanceSubjects = append(acceptanceSubjects, subject)
	}
	sort.Strings(acceptanceSubjects)
	recipientSet := guarantor.FirmOfferRecipientSetV1{SchemaVersion: 1,
		RequesterAgentID: input.Request.Body.RequesterAgentID, GuarantorAgentID: coordinator.AgentID,
		CoveredPartyAgentID: input.Terms.CoveredPartyAgentID, BeneficiaryAgentID: input.Terms.BeneficiaryAgentID,
		ClaimantSubjects: claimants, AcceptanceSubjects: acceptanceSubjects}
	recipientDigest, err := guarantor.FirmOfferRecipientSetDigestV1(recipientSet)
	if err != nil {
		return guarantor.AuthorizedFirmCoverageOfferV1{}, commerce.ActionResolution{}, err
	}
	zeroDigest := zeroSHA256Digest()
	var guarantorEvidenceProfile commerce.ProfileRefV1
	guarantorTargets := make([]guarantor.GuarantorSatisfiedPredicateTargetV1, 0, 1)
	for _, predicate := range input.Agreement.AuthorizationPredicates {
		if predicate.AuthoritySubject.SubjectIdentifier != coordinator.AgentID {
			continue
		}
		candidate := commerce.ProfileRefV1{ProfileURI: predicate.EvidenceProfileURI,
			ProfileVersion: uint64(predicate.EvidenceProfileVersion), ProfileDigest: predicate.EvidenceProfileDigest}
		if guarantorEvidenceProfile.ProfileURI != "" && guarantorEvidenceProfile != candidate {
			return guarantor.AuthorizedFirmCoverageOfferV1{}, commerce.ActionResolution{}, errors.New("Guarantor Agreement predicates use conflicting evidence profiles")
		}
		guarantorEvidenceProfile = candidate
		guarantorTargets = append(guarantorTargets, guarantor.GuarantorSatisfiedPredicateTargetV1{
			PredicateID: predicate.PredicateID, TargetProjectionDigest: predicate.EvidenceTargetProjectionDigest})
	}
	sort.Slice(guarantorTargets, func(i, j int) bool {
		left, _ := codec.Marshal(guarantorTargets[i])
		right, _ := codec.Marshal(guarantorTargets[j])
		return string(left) < string(right)
	})
	if len(guarantorTargets) == 0 || commerce.ValidateProfileRefV1(guarantorEvidenceProfile) != nil {
		return guarantor.AuthorizedFirmCoverageOfferV1{}, commerce.ActionResolution{}, errors.New("coverage Agreement lacks the Guarantor authorization predicate")
	}
	preallocationTemplate := guarantor.FirmCoverageOfferBodyV1{SchemaVersion: 1, OfferID: zeroDigest,
		OfferVersion: 1, QuoteRequestDigest: requestDigest,
		ServiceIntentDigest: input.ProfileArtifact.SelectedServiceIntentOperationDigest, ServiceProfileDigest: profileDigest,
		CoverageID: input.Terms.CoverageID, CoverageVersion: input.Terms.CoverageVersion,
		CoverageAgreementBodyDigest: agreementDigest, CoverageTermsDigest: termsDigest, GuarantorAgentID: coordinator.AgentID,
		CoveredPartyAgentID: input.Terms.CoveredPartyAgentID, BeneficiaryAgentID: input.Terms.BeneficiaryAgentID,
		UnderlyingAgreementBodyDigest: input.Terms.UnderlyingAgreementBodyDigest,
		CoveredObligationIDs:          append([]string(nil), input.Terms.CoveredObligationIDs...),
		CoverageObligationID:          input.CoverageObligationID, PremiumObligationIDs: append([]string(nil), input.Terms.PremiumObligationIDs...),
		CollateralObligationID:     input.Terms.CollateralObligationID,
		PayoutTemplateObligationID: input.Terms.PayoutTemplate.AgreementObligationID,
		GuarantorPredicateTargets:  append([]guarantor.GuarantorSatisfiedPredicateTargetV1(nil), guarantorTargets...),
		GuarantorEvidenceProfile:   guarantorEvidenceProfile, ReservationID: zeroDigest,
		ExposureAdmissionReceiptDigest: zeroDigest, MaxAcceptances: 1,
		ValidFromUnix: input.IssuedAtUnix, AcceptByUnix: input.AcceptByUnix,
		AcceptanceProcessingGraceSeconds: profile.AdmissionLimits.MaximumAcceptanceProcessingGraceSeconds,
		WithdrawalPolicy:                 "forbidden", ExpiresAtUnix: input.ExpiresAtUnix,
		RequiredExtensions: append([]commerce.ProfileRefV1(nil), input.Terms.RequiredExtensions...),
		OptionalExtensions: append([]commerce.ProfileRefV1(nil), input.Terms.OptionalExtensions...)}
	effect := guarantor.FirmOfferAuthorityInstanceEffectV1{SchemaVersion: 1, GuarantorAgentID: coordinator.AgentID,
		AuthorizedQuoteRequestEnvelopeDigest: requestDigest, CoverageAgreementBodyDigest: agreementDigest,
		CoverageTermsDigest: termsDigest, RecipientSet: recipientSet, RecipientSetDigest: recipientDigest,
		ReservationScope: scope, ReservationScopeDigest: scopeDigest, ReservedExposure: input.Terms.MaximumAggregatePayout,
		PreallocationOfferTemplate: preallocationTemplate}
	effectBytes, err := guarantor.Canonical(effect)
	if err != nil {
		return guarantor.AuthorizedFirmCoverageOfferV1{}, commerce.ActionResolution{}, err
	}
	effectDigest, err := commerce.DownstreamEffectDescriptorDigest(effectBytes)
	if err != nil {
		return guarantor.AuthorizedFirmCoverageOfferV1{}, commerce.ActionResolution{}, err
	}
	instance, err := coordinator.Authority.AllocateInstance(commerce.AuthorityInstanceAllocationRequest{OwnerID: coordinator.OwnerID,
		AgentID: coordinator.AgentID, PurposeKind: "firm-offer", MandateDigest: coordinator.MandateDigest,
		ApprovalDigestOrZero: zeroSHA256Digest(), DownstreamEffectDescriptorDigest: effectDigest,
		PredecessorAuthorityInstanceID: zeroSHA256Digest()}, fence)
	if err != nil {
		return guarantor.AuthorizedFirmCoverageOfferV1{}, commerce.ActionResolution{}, err
	}
	if priorPlan, found := coordinator.Journal.FirmOfferIssuancePlan(instance.AuthorityInstanceID); found {
		priorResolution := coordinator.Authority.Resolve(priorPlan.Action.StableActionID, priorPlan.Action.ExactRequestDigest)
		if priorResolution.State != commerce.ActionUnknown {
			if err := guarantor.VerifyFirmOffer(priorPlan.Offer, input.Request, input.Agreement, coordinator.Resolver,
				coordinator.PublicationResolver, coordinator.UnderlyingAgreementResolver,
				coordinator.AgreementVerifier, issuedAt); err != nil {
				return guarantor.AuthorizedFirmCoverageOfferV1{}, priorResolution, errors.New("persisted Guarantor firm-offer plan no longer verifies")
			}
			return coordinator.resumeFirmOfferIssuancePlan(priorPlan, priorResolution)
		}
		if err := coordinator.Journal.DiscardUnadmittedFirmOfferIssuancePlan(instance.AuthorityInstanceID,
			coordinator.Authority); err != nil {
			return guarantor.AuthorizedFirmCoverageOfferV1{}, priorResolution, err
		}
	}
	descriptorDigest, err := guarantor.ExposureAdmissionDescriptorDigestV1(descriptor)
	if err != nil {
		return guarantor.AuthorizedFirmCoverageOfferV1{}, commerce.ActionResolution{}, err
	}
	reservationID, err := guarantor.ReservationIDV1(coordinator.AgentID, instance.AuthorityInstanceID, descriptorDigest)
	if err != nil {
		return guarantor.AuthorizedFirmCoverageOfferV1{}, commerce.ActionResolution{}, err
	}
	unsignedTemplate := preallocationTemplate
	unsignedTemplate.OfferID = instance.AuthorityInstanceID
	unsignedTemplate.ReservationID = reservationID
	requestBody := guarantor.FirmOfferIssuanceActionBodyV1{SchemaVersion: 1,
		AuthorityInstanceID: instance.AuthorityInstanceID, AuthorityInstanceRecord: instance,
		AuthorityInstanceEffect: effect, AuthorizedQuoteRequest: input.Request,
		ServiceProfileArtifact: input.ProfileArtifact, UnsignedOfferTemplate: unsignedTemplate,
		ExposureAdmissionDescriptor: descriptor, ExpectedPortfolioRevision: baseRevision}
	if err := guarantor.ValidateFirmOfferIssuanceActionBodyV1(requestBody); err != nil {
		return guarantor.AuthorizedFirmCoverageOfferV1{}, commerce.ActionResolution{}, err
	}
	canonicalRequest, err := codec.Marshal(requestBody)
	if err != nil {
		return guarantor.AuthorizedFirmCoverageOfferV1{}, commerce.ActionResolution{}, err
	}
	fields := map[string]commerce.SemanticValue{"owner_id": commerce.ID(coordinator.OwnerID), "agent_id": commerce.ID(coordinator.AgentID),
		"agreement_body_digest": commerce.Digest32(agreementDigest), "quote_request_digest": commerce.Digest32(requestDigest),
		"recipient_set_digest": commerce.Digest32(recipientDigest), "authority_instance_id": commerce.Digest32(instance.AuthorityInstanceID),
		"offer_terms_digest": commerce.Digest32(termsDigest)}
	action, err := commerce.BuildAuthorizedAction(coordinator.OwnerID, coordinator.AgentID, "commercial.quote.issue", fields,
		canonicalRequest, fence, coordinator.PolicyRevision, coordinator.MandateDigest, "", agreementDigest, input.ExpiresAtUnix)
	if err != nil {
		return guarantor.AuthorizedFirmCoverageOfferV1{}, commerce.ActionResolution{}, err
	}
	action, err = coordinator.Authority.SignAction(action, fence)
	if err != nil {
		return guarantor.AuthorizedFirmCoverageOfferV1{}, commerce.ActionResolution{}, err
	}
	offerAdmissionDomain, err := codec.Digest("tos.service.agent-guarantor-firm-offer-admission-domain.v1", struct {
		AuthorityInstanceID string `json:"authority_instance_id"`
	}{instance.AuthorityInstanceID})
	if err != nil {
		return guarantor.AuthorizedFirmCoverageOfferV1{}, commerce.ActionResolution{}, err
	}
	offerAdmission, err := coordinator.Journal.BeginAdmission(offerAdmissionDomain, action.StableActionID,
		action.ExactRequestDigest, issuedAt)
	if err != nil {
		return guarantor.AuthorizedFirmCoverageOfferV1{}, commerce.ActionResolution{}, err
	}
	eligibilityProofSet, err := buildGuarantorEligibilityProofSet(rawEligibilityProof, action, requestDigest,
		[]string{input.Request.Body.RequesterAgentID, input.Request.Body.CoveredPartyAgentID, input.Request.Body.BeneficiaryAgentID},
		"firm-offer-issuance", action.ExactRequestDigest, profile.AuthorityDomainDigest,
		profile.ExposureAuthorizationProfile, offerAdmissionDomain, offerAdmission.Sequence, input.IssuedAtUnix)
	if err != nil {
		return guarantor.AuthorizedFirmCoverageOfferV1{}, commerce.ActionResolution{}, err
	}
	grossExposure, ok := new(big.Int).SetString(decision.GrossExposureAtomic, 10)
	if !ok || !grossExposure.IsUint64() || decision.NetExposureAtomic != decision.GrossExposureAtomic {
		return guarantor.AuthorizedFirmCoverageOfferV1{}, commerce.ActionResolution{}, errors.New("Guarantor local authority exposure exceeds its uint64 deployment profile")
	}
	coverageAsset := input.Terms.CoverageAsset
	reservation := ExposureReservation{ReservationID: reservationID, AgreementDigest: agreementDigest, Asset: &coverageAsset,
		MaximumLossAtomic: grossExposure.Uint64()}
	var resolution commerce.ActionResolution
	actionDigest, _ := commerce.AuthorizedActionDigest(action)
	proofDigest, _ := guarantor.AuthorityAdmissionEligibilityProofSetDigestV1(eligibilityProofSet)
	receiptBody := guarantor.ProviderExposureAdmissionReceiptBodyV1{SchemaVersion: 1, AuthorityID: action.AuthorityID,
		GuarantorAgentID: coordinator.AgentID, DescriptorDigest: descriptorDigest, AuthorizedActionDigest: actionDigest,
		ReservationID: reservationID, StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest,
		WriterGeneration: action.WriterGeneration, WriterFenceDigest: action.WriterFenceDigest, BasePortfolioRevision: baseRevision,
		AdmittedPortfolioRevision: baseRevision + 1, ReservedExposure: input.Terms.MaximumAggregatePayout, State: "reserved",
		AdmittedAtUnix: input.IssuedAtUnix, ExpiresAtUnix: input.ReservationExpiresAtUnix,
		AuthorityAdmissionEligibilityProofSetDigest: proofDigest}
	receiptBodyDigest, _ := codec.Digest("tos.service.agent-guarantor-exposure-receipt-body.v1", receiptBody)
	receiptAuthorization, err := coordinator.Signer.SignObject("exposure-admission-receipt", receiptBodyDigest,
		"tos.service.agent-guarantor-exposure-receipt-signature.v1", issuedAt)
	if err != nil {
		return guarantor.AuthorizedFirmCoverageOfferV1{}, resolution, err
	}
	receipt := guarantor.AuthorizedProviderExposureAdmissionReceiptV1{Body: receiptBody, Descriptor: descriptor,
		AuthorityAdmissionEligibilityProofSet: eligibilityProofSet,
		Authorizations:                        []guarantor.ProfileQualifiedObjectAuthorizationV1{receiptAuthorization}}
	receiptDigest, err := guarantor.ExposureAdmissionReceiptDigestV1(receipt)
	if err != nil {
		return guarantor.AuthorizedFirmCoverageOfferV1{}, resolution, err
	}
	offerBody := unsignedTemplate
	offerBody.ExposureAdmissionReceiptDigest = receiptDigest
	offerBodyDigest, _ := codec.Digest("tos.service.agent-guarantor-firm-offer-body.v1", offerBody)
	offerAuthorization, err := coordinator.Signer.SignObject("firm-coverage-offer", offerBodyDigest,
		"tos.service.agent-guarantor-firm-offer-signature.v1", issuedAt)
	if err != nil {
		return guarantor.AuthorizedFirmCoverageOfferV1{}, resolution, err
	}
	offer := guarantor.AuthorizedFirmCoverageOfferV1{Body: offerBody, CoverageTerms: input.Terms,
		ExposureAdmissionReceipt: receipt, AuthorizedQuoteRequest: input.Request,
		ServiceProfileArtifact: input.ProfileArtifact,
		Authorizations:         []guarantor.ProfileQualifiedObjectAuthorizationV1{offerAuthorization}}
	if err := guarantor.VerifyFirmOffer(offer, input.Request, input.Agreement, coordinator.Resolver,
		coordinator.PublicationResolver, coordinator.UnderlyingAgreementResolver,
		coordinator.AgreementVerifier, issuedAt); err != nil {
		return guarantor.AuthorizedFirmCoverageOfferV1{}, resolution, err
	}
	offerDigest, _ := guarantor.FirmOfferDigest(offer)
	position := GuarantorOfferPosition{QuoteRequestDigest: requestDigest, CoveredPartyAgentID: input.Terms.CoveredPartyAgentID,
		CoverageAsset:       input.Terms.CoverageAsset,
		GrossExposureAtomic: decision.GrossExposureAtomic, NetExposureAtomic: decision.NetExposureAtomic,
		AcceptByUnix: input.AcceptByUnix, ReservationExpiresAt: input.ReservationExpiresAtUnix, AuthorizedFirmOffer: &offer,
		Record: guarantor.OfferRecord{OfferID: instance.AuthorityInstanceID, ReservationID: reservationID,
			AgreementDigest: agreementDigest, Status: guarantor.OfferReservedUnsigned, StateRevision: 3,
			LastEvidenceDigest: descriptorDigest}}
	plan := GuarantorFirmOfferIssuancePlan{AuthorityInstanceID: instance.AuthorityInstanceID,
		AdmissionDomainID: offerAdmissionDomain, Action: action, Fields: fields,
		CanonicalRequest: canonicalRequest, Reservation: reservation, Offer: offer,
		OfferDigest: offerDigest, ReceiptDigest: receiptDigest, Position: position}
	if err := coordinator.Journal.SaveFirmOfferIssuancePlan(plan); err != nil {
		return guarantor.AuthorizedFirmCoverageOfferV1{}, resolution, err
	}
	resolution, err = coordinator.Authority.Admit(action, fields, canonicalRequest, fence, &reservation)
	if err != nil || (resolution.State != commerce.ActionPrepared && resolution.State != commerce.ActionTerminal) {
		return guarantor.AuthorizedFirmCoverageOfferV1{}, resolution,
			firstError(err, errors.New("Guarantor exposure action was not prepared or recovered terminal"))
	}
	if resolution.State == commerce.ActionTerminal {
		if _, err := coordinator.Journal.ResolveAdmission(offerAdmissionDomain, resolution); err != nil {
			return guarantor.AuthorizedFirmCoverageOfferV1{}, resolution, err
		}
		if err := coordinator.Journal.CompleteFirmOfferIssuancePlan(instance.AuthorityInstanceID, offerDigest); err != nil {
			return guarantor.AuthorizedFirmCoverageOfferV1{}, resolution, err
		}
		return offer, resolution, nil
	}
	if err := coordinator.Journal.ReserveUnsignedOffer(position); err != nil {
		return guarantor.AuthorizedFirmCoverageOfferV1{}, resolution, err
	}
	if _, err := coordinator.Journal.CommitFirmOffer(instance.AuthorityInstanceID, offerDigest); err != nil {
		return guarantor.AuthorizedFirmCoverageOfferV1{}, resolution, err
	}
	resolution, err = coordinator.Authority.Transition(action.StableActionID, action.ExactRequestDigest, commerce.ActionTerminal,
		offerDigest, sortedGuarantorEvidence(receiptDigest, offerDigest))
	if err == nil {
		_, err = coordinator.Journal.ResolveAdmission(offerAdmissionDomain, resolution)
	}
	if err == nil {
		err = coordinator.Journal.CompleteFirmOfferIssuancePlan(instance.AuthorityInstanceID, offerDigest)
	}
	return offer, resolution, err
}

func (coordinator *GuarantorProviderCoordinator) validateAssuranceDeployment(terms guarantor.CoverageTermsV1) error {
	switch terms.SelectedAssuranceLevel {
	case guarantor.AssuranceUnsecuredSigned:
		return nil
	case guarantor.AssuranceCollateralAttested:
		if !coordinator.CollateralAdapterEnabled || coordinator.CollateralFinalityVerifier == nil ||
			terms.CollateralTerms == nil || !containsString(coordinator.CollateralAdapterProfileDigests,
			terms.CollateralTerms.CustodyAdapterProfile.ProfileDigest) {
			return errors.New("collateral-attested Guarantor offer has no owner-enabled finalized Adapter")
		}
		return nil
	case guarantor.AssuranceIndependentlyEnforced:
		// This coordinator owns the local coverage, claim, and exposure CAS
		// domains. It must never advertise an assurance level whose defining
		// property is that those mutations remain reachable after this
		// Guarantor runtime and its control roots are removed. Such offers are
		// issued only by a separately deployed Independent*OperationAdapter.
		return errors.New("independently-enforceable Guarantor offers require external operation Adapters")
	default:
		return errors.New("unsupported Guarantor assurance deployment")
	}
}

func (coordinator *GuarantorProviderCoordinator) resumeFirmOfferIssuancePlan(plan GuarantorFirmOfferIssuancePlan,
	resolution commerce.ActionResolution) (guarantor.AuthorizedFirmCoverageOfferV1, commerce.ActionResolution, error) {
	if resolution.State == commerce.ActionPrepared {
		if err := coordinator.Journal.ReserveUnsignedOffer(plan.Position); err != nil {
			return guarantor.AuthorizedFirmCoverageOfferV1{}, resolution, err
		}
		if _, err := coordinator.Journal.CommitFirmOffer(plan.AuthorityInstanceID, plan.OfferDigest); err != nil {
			return guarantor.AuthorizedFirmCoverageOfferV1{}, resolution, err
		}
		var err error
		resolution, err = coordinator.Authority.Transition(plan.Action.StableActionID, plan.Action.ExactRequestDigest,
			commerce.ActionTerminal, plan.OfferDigest, sortedGuarantorEvidence(plan.ReceiptDigest, plan.OfferDigest))
		if err != nil {
			return guarantor.AuthorizedFirmCoverageOfferV1{}, resolution, err
		}
	}
	if resolution.State != commerce.ActionTerminal {
		return guarantor.AuthorizedFirmCoverageOfferV1{}, resolution, errors.New("persisted Guarantor firm-offer plan has a non-recoverable authority state")
	}
	if _, err := coordinator.Journal.ResolveAdmission(plan.AdmissionDomainID, resolution); err != nil {
		return guarantor.AuthorizedFirmCoverageOfferV1{}, resolution, err
	}
	if err := coordinator.Journal.CompleteFirmOfferIssuancePlan(plan.AuthorityInstanceID, plan.OfferDigest); err != nil {
		return guarantor.AuthorizedFirmCoverageOfferV1{}, resolution, err
	}
	return plan.Offer, resolution, nil
}

func (coordinator *GuarantorProviderCoordinator) portfolioFor(counterparty string,
	asset commerce.AssetIdentityV1) GuarantorPortfolioSnapshot {
	_, offers, coverages := coordinator.Journal.Snapshot()
	aggregate, party := new(big.Int), new(big.Int)
	var activeOffers, activeCoverages, activeClaims uint32
	coveredPartyByReservation := make(map[string]string, len(offers))
	assetByReservation := make(map[string]commerce.AssetIdentityV1, len(offers))
	reservationReleased := make(map[string]bool, len(offers))
	for _, offer := range offers {
		coveredPartyByReservation[offer.Record.ReservationID] = offer.CoveredPartyAgentID
		assetByReservation[offer.Record.ReservationID] = offer.CoverageAsset
		if offer.CoverageAsset == asset &&
			(offer.Record.Status == guarantor.OfferIssued || offer.Record.Status == guarantor.OfferAcceptanceResolving) {
			activeOffers++
		}
	}
	if coordinator.Authority != nil {
		_, _, reservations := coordinator.Authority.Snapshot()
		for _, reservation := range reservations {
			reservationReleased[reservation.ReservationID] = reservation.Released
			if reservation.Released || assetByReservation[reservation.ReservationID] != asset {
				continue
			}
			value := new(big.Int).SetUint64(reservation.MaximumLossAtomic)
			aggregate.Add(aggregate, value)
			if coveredPartyByReservation[reservation.ReservationID] == counterparty {
				party.Add(party, value)
			}
		}
	}
	for _, coverage := range coverages {
		terminalCoverage := coverage.Record.CoverageStatus == guarantor.CoverageClosed ||
			coverage.Record.CoverageStatus == guarantor.CoverageCancelled ||
			coverage.Record.CoverageStatus == guarantor.CoverageClosedNotActivated ||
			coverage.Record.CoverageStatus == guarantor.CoverageExhausted ||
			coverage.Record.CoverageStatus == guarantor.CoverageDefaulted
		if !terminalCoverage && coverage.Terms.CoverageAsset == asset {
			activeCoverages++
			activeClaims += uint32(len(coverage.Claims))
		}
		// A released reservation may still have consumed realized loss or a
		// retained default liability. Those buckets remain part of aggregate
		// underwriting exposure even though the unused residual was returned.
		if reservationReleased[coverage.Record.ReservationID] && coverage.Terms.CoverageAsset == asset {
			paid, paidErr := nonnegativeBig(coverage.PaidAtomic)
			defaulted, defaultedErr := nonnegativeBig(coverage.DefaultedAtomic)
			if paidErr == nil && defaultedErr == nil {
				consumed := new(big.Int).Add(paid, defaulted)
				aggregate.Add(aggregate, consumed)
				if coveredPartyByReservation[coverage.Record.ReservationID] == counterparty {
					party.Add(party, consumed)
				}
			}
		}
	}
	return GuarantorPortfolioSnapshot{AggregateReservedAtomic: aggregate.String(), CounterpartyReservedAtomic: party.String(),
		ActiveOffers: activeOffers, ActiveCoverages: activeCoverages, ActiveClaims: activeClaims}
}

func firstError(primary, fallback error) error {
	if primary != nil {
		return primary
	}
	return fallback
}

func sortGuarantorAuthorizations(values []guarantor.ProfileQualifiedObjectAuthorizationV1) {
	sort.Slice(values, func(i, j int) bool {
		left, _ := codec.Marshal(values[i])
		right, _ := codec.Marshal(values[j])
		return string(left) < string(right)
	})
}

func sortedGuarantorEvidence(values ...string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}
