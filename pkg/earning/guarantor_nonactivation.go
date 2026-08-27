package earning

import (
	"context"
	"errors"
	"sort"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	guarantor "github.com/tosnetwork/tos-service-protocol/pkg/agentguarantor"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type GuarantorConfirmNonActivationInput struct {
	Offer             guarantor.AuthorizedFirmCoverageOfferV1
	AcceptanceReceipt guarantor.AuthorizedCoverageAcceptanceReceiptV1
	ResolvedAtUnix    uint64
}

// ConfirmActivationWindowExpired implements the objective zero-activation
// branch. Silence is insufficient: it freezes and embeds the complete
// activation-admission prefix and refuses any successful or unresolved entry.
func (coordinator *GuarantorProviderCoordinator) ConfirmActivationWindowExpired(ctx context.Context,
	input GuarantorConfirmNonActivationInput, fence commerce.WriterFence) (guarantor.AuthorizedCoverageNonActivationEvidenceV1,
	commerce.ActionResolution, error) {
	if err := ctx.Err(); err != nil {
		return guarantor.AuthorizedCoverageNonActivationEvidenceV1{}, commerce.ActionResolution{}, err
	}
	if coordinator == nil || coordinator.Authority == nil || coordinator.Journal == nil || coordinator.Signer == nil ||
		coordinator.Resolver == nil || coordinator.PublicationResolver == nil || coordinator.AgreementVerifier == nil ||
		coordinator.UnderlyingAgreementResolver == nil || coordinator.Eligibility == nil || input.ResolvedAtUnix == 0 {
		return guarantor.AuthorizedCoverageNonActivationEvidenceV1{}, commerce.ActionResolution{}, errors.New("Guarantor non-activation coordinator is incomplete")
	}
	now := time.Unix(int64(input.ResolvedAtUnix), 0).UTC()
	if coordinator.Authority.ConfirmCurrentWriterFence(fence, now) != nil {
		return guarantor.AuthorizedCoverageNonActivationEvidenceV1{}, commerce.ActionResolution{}, errors.New("Guarantor non-activation writer is stale")
	}
	terms := input.Offer.CoverageTerms
	if err := guarantor.VerifyFirmOffer(input.Offer, input.Offer.AuthorizedQuoteRequest,
		input.AcceptanceReceipt.AuthorizedAcceptanceRequest.CoverageAgreementBody, coordinator.Resolver,
		coordinator.PublicationResolver, coordinator.UnderlyingAgreementResolver, coordinator.AgreementVerifier,
		time.Unix(int64(input.AcceptanceReceipt.Body.AcceptedAtUnix), 0).UTC()); err != nil {
		return guarantor.AuthorizedCoverageNonActivationEvidenceV1{}, commerce.ActionResolution{}, err
	}
	if input.ResolvedAtUnix < terms.CoverageStartsAtUnix || terms.SelectedAssuranceLevel != guarantor.AssuranceUnsecuredSigned {
		return guarantor.AuthorizedCoverageNonActivationEvidenceV1{}, commerce.ActionResolution{}, errors.New("Guarantor non-activation cutoff or assurance is invalid")
	}
	agreementDigest := input.AcceptanceReceipt.Body.CoverageAgreementBodyDigest
	if err := guarantor.VerifyCoverageAcceptanceReceiptV1(input.AcceptanceReceipt, input.Offer,
		coordinator.AgreementVerifier, coordinator.Resolver, coordinator.Authority, now); err != nil {
		return guarantor.AuthorizedCoverageNonActivationEvidenceV1{}, commerce.ActionResolution{}, err
	}
	var position GuarantorCoveragePosition
	_, _, coverages := coordinator.Journal.Snapshot()
	for _, candidate := range coverages {
		if candidate.Record.CoverageAgreementBodyDigest == agreementDigest {
			position = candidate
		}
	}
	if position.Record.CoverageStatus == guarantor.CoverageNotActivatedConfirmed && position.NonActivationEvidence != nil {
		stored := *position.NonActivationEvidence
		resolution := coordinator.Authority.Resolve(stored.Body.StableActionID, stored.Body.ExactRequestDigest)
		if resolution.State != commerce.ActionTerminal {
			return guarantor.AuthorizedCoverageNonActivationEvidenceV1{}, resolution,
				errors.New("Guarantor non-activation journal is ahead of its action authority")
		}
		return stored, resolution, nil
	}
	if position.Record.CoverageStatus != guarantor.CoveragePendingAuthorization ||
		position.Record.ClaimFilingStatus != guarantor.FilingNotOpen {
		return guarantor.AuthorizedCoverageNonActivationEvidenceV1{}, commerce.ActionResolution{}, errors.New("Guarantor coverage is not pending activation")
	}
	domainID, err := guarantor.ActivationAdmissionDomainIDV1(agreementDigest)
	if err != nil {
		return guarantor.AuthorizedCoverageNonActivationEvidenceV1{}, commerce.ActionResolution{}, err
	}
	cut, err := coordinator.Journal.FreezeAdmissionCut(domainID, terms.CoverageStartsAtUnix)
	if err != nil {
		return guarantor.AuthorizedCoverageNonActivationEvidenceV1{}, commerce.ActionResolution{}, err
	}
	for _, entry := range cut.Entries {
		if entry.Resolution.State != commerce.ActionRejected && entry.Resolution.State != commerce.ActionConflict {
			return guarantor.AuthorizedCoverageNonActivationEvidenceV1{}, commerce.ActionResolution{}, errors.New("activation was accepted or remains unresolved")
		}
	}
	cutProof := guarantor.ActivationAdmissionCutProofV1{SchemaVersion: 1,
		CoverageAgreementBodyDigest: agreementDigest, ActivationAdmissionLogID: domainID,
		ActivationCutoffUnix: terms.CoverageStartsAtUnix, AdmissionHighWater: cut.HighWater,
		AdmissionLogRoot: cut.LogRoot, Entries: append([]guarantor.GuarantorAdmissionLogEntryV1(nil), cut.Entries...)}
	cutDigest, err := guarantor.ActivationAdmissionCutProofDigestV1(cutProof)
	if err != nil {
		return guarantor.AuthorizedCoverageNonActivationEvidenceV1{}, commerce.ActionResolution{}, err
	}
	reason := guarantor.CoverageNonActivationReasonEvidenceV1{SchemaVersion: 1,
		CoverageAgreementBodyDigest: agreementDigest, CoverageObligationID: position.Record.CoverageObligationID,
		Reason: "activation_window_expired", ActivationAdmissionCutProofDigest: cutDigest}
	reasonDigest, _ := guarantor.CoverageNonActivationReasonEvidenceDigestV1(reason)
	acceptanceDigest, _ := guarantor.CoverageAcceptanceReceiptDigestV1(input.AcceptanceReceipt)
	offerDigest, _ := guarantor.FirmOfferDigest(input.Offer)
	exposureDigest, _ := guarantor.ExposureAdmissionReceiptDigestV1(input.Offer.ExposureAdmissionReceipt)
	refs := []guarantor.TransitionEvidenceDigestRefV1{
		{EvidenceRole: "acceptance_receipt", DigestKind: "authorized_envelope", ObjectDigest: acceptanceDigest},
		{EvidenceRole: "activation_admission_cut", DigestKind: "canonical_object", ObjectDigest: cutDigest},
		{EvidenceRole: "non_activation_reason", DigestKind: "canonical_object", ObjectDigest: reasonDigest},
	}
	sort.Slice(refs, func(i, j int) bool {
		left, _ := codec.Marshal(refs[i])
		right, _ := codec.Marshal(refs[j])
		return string(left) < string(right)
	})
	projection := guarantor.TransitionEvidenceProjectionV1{SchemaVersion: 1, Purpose: "coverage-non-activation",
		CoverageAgreementBodyDigest: agreementDigest, ObligationID: position.Record.CoverageObligationID,
		TargetState: "not_activated_confirmed", EvidenceDigests: refs}
	projectionDigest, _ := guarantor.TransitionEvidenceProjectionDigestV1(projection)
	requestBody := guarantor.CoverageNonActivationActionBodyV1{SchemaVersion: 1,
		AuthorizedAcceptanceReceipt: input.AcceptanceReceipt, ActivationAdmissionCutProof: cutProof,
		NonActivationReasonEvidence: reason, TransitionEvidenceProjection: projection,
		ExpectedCoverageRevision: position.Record.CoverageRevision, TargetCoverageRevision: position.Record.CoverageRevision + 1,
		TargetCoverageState: "not_activated_confirmed", ExpectedClaimFilingState: "not_open",
		TargetClaimFilingState: "not_open", ExpectedClaimFilingStateRevision: position.Record.FilingStateRevision,
		TargetClaimFilingStateRevision: position.Record.FilingStateRevision}
	canonicalRequest, err := codec.Marshal(requestBody)
	if err != nil {
		return guarantor.AuthorizedCoverageNonActivationEvidenceV1{}, commerce.ActionResolution{}, err
	}
	fields := map[string]commerce.SemanticValue{"owner_id": commerce.ID(coordinator.OwnerID), "agent_id": commerce.ID(coordinator.AgentID),
		"agreement_body_digest": commerce.Digest32(agreementDigest), "obligation_id": commerce.ID(position.Record.CoverageObligationID),
		"expected_state_revision": commerce.U64(position.Record.CoverageRevision), "target_state": commerce.State("not_activated_confirmed"),
		"evidence_set_digest": commerce.Digest32(projectionDigest)}
	action, err := commerce.BuildAuthorizedAction(coordinator.OwnerID, coordinator.AgentID, "conditional.obligation.transition",
		fields, canonicalRequest, fence, coordinator.PolicyRevision, coordinator.MandateDigest, "", position.Record.LastEvidenceDigest,
		fence.Body.ExpiresAtUnix)
	if err == nil {
		action, err = coordinator.Authority.SignAction(action, fence)
	}
	if err != nil {
		return guarantor.AuthorizedCoverageNonActivationEvidenceV1{}, commerce.ActionResolution{}, err
	}
	actionDomainID, err := codec.Digest("tos.service.agent-guarantor-non-activation-admission-domain.v1", struct {
		CoverageAgreementBodyDigest string `json:"coverage_agreement_body_digest"`
	}{agreementDigest})
	if err != nil {
		return guarantor.AuthorizedCoverageNonActivationEvidenceV1{}, commerce.ActionResolution{}, err
	}
	admissionEntry, err := coordinator.Journal.BeginAdmission(actionDomainID, action.StableActionID, action.ExactRequestDigest, now)
	if err != nil {
		return guarantor.AuthorizedCoverageNonActivationEvidenceV1{}, commerce.ActionResolution{}, err
	}
	resolution, err := coordinator.Authority.Admit(action, fields, canonicalRequest, fence, nil)
	if err != nil || resolution.State != commerce.ActionPrepared && resolution.State != commerce.ActionTerminal {
		return guarantor.AuthorizedCoverageNonActivationEvidenceV1{}, resolution,
			firstError(err, errors.New("Guarantor non-activation action did not resolve safely"))
	}
	actionDigest, _ := commerce.AuthorizedActionDigest(action)
	rawProof, err := coordinator.Eligibility.FreshEligibilityProofSet(ctx, "coverage-non-activation",
		[]string{terms.GuarantorAgentID, terms.CoveredPartyAgentID, terms.BeneficiaryAgentID}, now)
	if err != nil || len(rawProof) == 0 || len(rawProof) > 64<<10 {
		return guarantor.AuthorizedCoverageNonActivationEvidenceV1{}, resolution, errors.New("fresh Guarantor non-activation eligibility proof is unavailable")
	}
	eligibility, err := buildGuarantorEligibilityProofSet(rawProof, action, acceptanceDigest,
		[]string{terms.GuarantorAgentID, terms.CoveredPartyAgentID, terms.BeneficiaryAgentID}, "coverage-non-activation",
		action.ExactRequestDigest, terms.CoverageStateDomainDigest, terms.LifecycleAuthorizationProfile,
		actionDomainID, admissionEntry.Sequence, input.ResolvedAtUnix)
	if err != nil {
		return guarantor.AuthorizedCoverageNonActivationEvidenceV1{}, resolution, err
	}
	eligibilityDigest, _ := guarantor.AuthorityAdmissionEligibilityProofSetDigestV1(eligibility)
	body := guarantor.CoverageNonActivationEvidenceBodyV1{SchemaVersion: 1, AuthorityID: action.AuthorityID,
		CoverageAgreementBodyDigest: agreementDigest, CoverageObligationID: position.Record.CoverageObligationID,
		CoverageStateDomainDigest: terms.CoverageStateDomainDigest, AuthorizedFirmOfferEnvelopeDigest: offerDigest,
		AcceptanceReceiptDigest: acceptanceDigest, ExposureReceiptDigest: exposureDigest, Reason: reason.Reason,
		ActivationCutoffUnix: terms.CoverageStartsAtUnix, ActivationAdmissionLogID: domainID,
		ActivationAdmissionHighWater: cut.HighWater, ActivationAdmissionLogRoot: cut.LogRoot,
		ActivationAdmissionCutProofDigest: cutDigest, NonActivationReasonEvidenceDigest: reasonDigest,
		TransitionEvidenceProjectionDigest: projectionDigest, AuthorizedActionDigest: actionDigest,
		StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest,
		WriterGeneration: action.WriterGeneration, WriterFenceDigest: action.WriterFenceDigest,
		PriorCoverageRevision: position.Record.CoverageRevision, ResolvedCoverageRevision: position.Record.CoverageRevision + 1,
		PriorClaimFilingState: "not_open", ResultingClaimFilingState: "not_open",
		PriorClaimFilingStateRevision:     position.Record.FilingStateRevision,
		ResultingClaimFilingStateRevision: position.Record.FilingStateRevision, ResolvedAtUnix: input.ResolvedAtUnix,
		AuthorityAdmissionEligibilityProofSetDigest: eligibilityDigest}
	bodyDigest, _ := codec.Digest("tos.service.agent-guarantor-non-activation-evidence-body.v1", body)
	if resolution.State == commerce.ActionPrepared {
		resolution, err = coordinator.Authority.Transition(action.StableActionID, action.ExactRequestDigest,
			commerce.ActionTerminal, bodyDigest, []string{bodyDigest})
		if err != nil {
			return guarantor.AuthorizedCoverageNonActivationEvidenceV1{}, resolution, err
		}
	}
	if resolution.State != commerce.ActionTerminal || resolution.SinkReference != bodyDigest {
		return guarantor.AuthorizedCoverageNonActivationEvidenceV1{}, resolution,
			errors.New("Guarantor non-activation terminal result conflicts with the reconstructed evidence")
	}
	if _, err = coordinator.Journal.ResolveAdmission(actionDomainID, resolution); err != nil {
		return guarantor.AuthorizedCoverageNonActivationEvidenceV1{}, resolution, err
	}
	stage, err := coordinator.buildGuarantorStage(terms, "coverage_non_activation",
		"application/vnd.tos.service.agent-guarantor-coverage-non-activation-action.v1+cbor", canonicalRequest,
		action, resolution, fence, now)
	if err != nil {
		return guarantor.AuthorizedCoverageNonActivationEvidenceV1{}, resolution, err
	}
	authorization, err := coordinator.Signer.SignObject("non-activation-evidence", bodyDigest,
		"tos.service.agent-guarantor-non-activation-evidence-signature.v1", now)
	if err != nil {
		return guarantor.AuthorizedCoverageNonActivationEvidenceV1{}, resolution, err
	}
	evidence := guarantor.AuthorizedCoverageNonActivationEvidenceV1{Body: body, StageActionAdmissionEvidence: stage,
		AuthorizedAcceptanceReceipt: input.AcceptanceReceipt, ActivationAdmissionCutProof: cutProof,
		NonActivationReasonEvidence: reason, TransitionEvidenceProjection: projection,
		AuthorityAdmissionEligibilityProofSet: eligibility,
		Authorizations:                        []guarantor.ProfileQualifiedObjectAuthorizationV1{authorization}}
	if err := guarantor.VerifyCoverageNonActivationEvidenceV1(evidence, input.Offer, coordinator.AgreementVerifier,
		coordinator.Resolver, coordinator.Authority, now); err != nil {
		return guarantor.AuthorizedCoverageNonActivationEvidenceV1{}, resolution, err
	}
	if _, err := coordinator.Journal.ConfirmNonActivation(agreementDigest, position.Record.CoverageRevision,
		position.Record.FilingStateRevision, evidence); err != nil {
		return guarantor.AuthorizedCoverageNonActivationEvidenceV1{}, resolution, err
	}
	return evidence, resolution, nil
}
