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

type GuarantorCancelCoverageInput struct {
	Request        guarantor.AuthorizedCoverageCancellationRequestV1
	AdmittedAtUnix uint64
}

func (coordinator *GuarantorProviderCoordinator) CancelCoverage(ctx context.Context, input GuarantorCancelCoverageInput,
	fence commerce.WriterFence) (guarantor.AuthorizedCoverageCancellationReceiptV1, commerce.ActionResolution, error) {
	if err := ctx.Err(); err != nil {
		return guarantor.AuthorizedCoverageCancellationReceiptV1{}, commerce.ActionResolution{}, err
	}
	if coordinator == nil || coordinator.Authority == nil || coordinator.Journal == nil || coordinator.Signer == nil ||
		coordinator.Resolver == nil || coordinator.AgreementVerifier == nil || coordinator.Eligibility == nil || input.AdmittedAtUnix == 0 {
		return guarantor.AuthorizedCoverageCancellationReceiptV1{}, commerce.ActionResolution{}, errors.New("Guarantor cancellation coordinator is incomplete")
	}
	if !validGuarantorUnix(input.AdmittedAtUnix) {
		return guarantor.AuthorizedCoverageCancellationReceiptV1{}, commerce.ActionResolution{}, errors.New("Guarantor cancellation time is outside the supported Unix range")
	}
	admittedAt := time.Unix(int64(input.AdmittedAtUnix), 0).UTC()
	if coordinator.Authority.ConfirmCurrentWriterFence(fence, admittedAt) != nil {
		return guarantor.AuthorizedCoverageCancellationReceiptV1{}, commerce.ActionResolution{}, errors.New("Guarantor cancellation writer is stale")
	}
	agreementDigest, err := commerce.AgreementBodyDigest(input.Request.CoverageAgreementBody)
	if err != nil {
		return guarantor.AuthorizedCoverageCancellationReceiptV1{}, commerce.ActionResolution{}, err
	}
	var position GuarantorCoveragePosition
	_, _, coverages := coordinator.Journal.Snapshot()
	for _, candidate := range coverages {
		if candidate.Record.CoverageAgreementBodyDigest == agreementDigest {
			position = candidate
		}
	}
	if position.Record.CoverageStatus == guarantor.CoverageEnded && position.CancellationReceipt != nil {
		stored := *position.CancellationReceipt
		requestDigest, digestErr := guarantor.CoverageCancellationRequestDigestV1(input.Request)
		if digestErr != nil || stored.Body.AuthorizedCancellationRequestDigest != requestDigest {
			return guarantor.AuthorizedCoverageCancellationReceiptV1{}, commerce.ActionResolution{},
				errors.New("Guarantor cancellation conflicts with the admitted request")
		}
		resolution := coordinator.Authority.Resolve(stored.Body.StableActionID, stored.Body.ExactRequestDigest)
		if resolution.State != commerce.ActionTerminal {
			return guarantor.AuthorizedCoverageCancellationReceiptV1{}, resolution,
				errors.New("Guarantor cancellation journal is ahead of its action authority")
		}
		return stored, resolution, nil
	}
	if position.Record.CoverageStatus != guarantor.CoverageActive || position.ActivationEvidence == nil {
		return guarantor.AuthorizedCoverageCancellationReceiptV1{}, commerce.ActionResolution{}, errors.New("Guarantor coverage is not actively cancellable")
	}
	terms := position.Terms
	if err := guarantor.VerifyCoverageCancellationRequestV1(input.Request, terms.CancellationPolicy,
		coordinator.Resolver, admittedAt); err != nil {
		return guarantor.AuthorizedCoverageCancellationReceiptV1{}, commerce.ActionResolution{}, err
	}
	var branch *guarantor.CoverageCancellationPolicyBranchV1
	for index := range terms.CancellationPolicy.Branches {
		if terms.CancellationPolicy.Branches[index].CancellationBranch == input.Request.Body.CancellationBranch {
			branch = &terms.CancellationPolicy.Branches[index]
		}
	}
	if branch == nil || input.AdmittedAtUnix >= terms.CoverageEndsAtUnix ||
		input.Request.Body.CreatedAtUnix < position.ActivationEvidence.Body.ActivatedAtUnix {
		return guarantor.AuthorizedCoverageCancellationReceiptV1{}, commerce.ActionResolution{}, errors.New("Guarantor cancellation is outside active coverage")
	}
	earliest, overflow := addUint64(position.ActivationEvidence.Body.ActivatedAtUnix, branch.EarliestAfterActivationSeconds)
	latest, overflowLatest := addUint64(input.Request.Body.CreatedAtUnix, branch.MaximumAdmissionDelaySeconds)
	if overflow || overflowLatest || input.AdmittedAtUnix < guarantorMaxUint64(input.Request.Body.CreatedAtUnix,
		earliest, input.Request.Body.EffectiveNotBeforeUnix) || input.AdmittedAtUnix > minThreeUint64(latest,
		input.Request.Body.EffectiveNotAfterUnix, input.Request.Body.ExpiresAtUnix) {
		return guarantor.AuthorizedCoverageCancellationReceiptV1{}, commerce.ActionResolution{}, errors.New("Guarantor cancellation timing predicate failed")
	}
	requestDigest, _ := guarantor.CoverageCancellationRequestDigestV1(input.Request)
	activationDigest, _ := guarantor.CoverageActivationEvidenceDigestV1(*position.ActivationEvidence)
	priorCommitment := position.ActivationEvidence.CoverageEndCommitment
	priorCommitmentDigest, _ := guarantor.CoverageEndCommitmentDigestV1(priorCommitment)
	refs := []guarantor.TransitionEvidenceDigestRefV1{
		{EvidenceRole: "activation_evidence", DigestKind: "authorized_envelope", ObjectDigest: activationDigest},
		{EvidenceRole: "cancellation_request", DigestKind: "authorized_envelope", ObjectDigest: requestDigest},
		{EvidenceRole: "prior_coverage_end_commitment", DigestKind: "canonical_object", ObjectDigest: priorCommitmentDigest},
	}
	sort.Slice(refs, func(i, j int) bool {
		left, _ := codec.Marshal(refs[i])
		right, _ := codec.Marshal(refs[j])
		return string(left) < string(right)
	})
	projection := guarantor.TransitionEvidenceProjectionV1{SchemaVersion: 1, Purpose: "coverage-cancellation",
		CoverageAgreementBodyDigest: agreementDigest, ObligationID: position.Record.CoverageObligationID,
		TargetState: "coverage_ended", EvidenceDigests: refs}
	projectionDigest, _ := guarantor.TransitionEvidenceProjectionDigestV1(projection)
	requestBody := guarantor.CoverageCancellationActionBodyV1{SchemaVersion: 1,
		AuthorizedCancellationRequest: input.Request, ExpectedCoverageEndCommitment: priorCommitment,
		TransitionEvidenceProjection: projection, ExpectedCoverageRevision: position.Record.CoverageRevision,
		TargetCoverageRevision: position.Record.CoverageRevision + 1, TargetCoverageState: "coverage_ended"}
	canonicalRequest, err := codec.Marshal(requestBody)
	if err != nil {
		return guarantor.AuthorizedCoverageCancellationReceiptV1{}, commerce.ActionResolution{}, err
	}
	fields := map[string]commerce.SemanticValue{"owner_id": commerce.ID(coordinator.OwnerID), "agent_id": commerce.ID(coordinator.AgentID),
		"agreement_body_digest": commerce.Digest32(agreementDigest), "obligation_id": commerce.ID(position.Record.CoverageObligationID),
		"expected_state_revision": commerce.U64(position.Record.CoverageRevision), "target_state": commerce.State("coverage_ended"),
		"evidence_set_digest": commerce.Digest32(projectionDigest)}
	action, err := commerce.BuildAuthorizedAction(coordinator.OwnerID, coordinator.AgentID, "conditional.obligation.transition",
		fields, canonicalRequest, fence, coordinator.PolicyRevision, coordinator.MandateDigest, "", position.Record.LastEvidenceDigest,
		minUint64(terms.ClaimFilingEndsAtUnix, fence.Body.ExpiresAtUnix))
	if err == nil {
		action, err = coordinator.Authority.SignAction(action, fence)
	}
	if err != nil {
		return guarantor.AuthorizedCoverageCancellationReceiptV1{}, commerce.ActionResolution{}, err
	}
	domainID, _ := codec.Digest("tos.service.agent-guarantor-cancellation-admission-domain.v1", struct {
		CoverageAgreementBodyDigest string `json:"coverage_agreement_body_digest"`
	}{agreementDigest})
	entry, err := coordinator.Journal.BeginAdmission(domainID, action.StableActionID, action.ExactRequestDigest, admittedAt)
	if err != nil {
		return guarantor.AuthorizedCoverageCancellationReceiptV1{}, commerce.ActionResolution{}, err
	}
	resolution, err := coordinator.Authority.Admit(action, fields, canonicalRequest, fence, nil)
	if err != nil || resolution.State != commerce.ActionPrepared && resolution.State != commerce.ActionTerminal {
		return guarantor.AuthorizedCoverageCancellationReceiptV1{}, resolution,
			firstError(err, errors.New("Guarantor cancellation action did not resolve safely"))
	}
	actionDigest, _ := commerce.AuthorizedActionDigest(action)
	rawProof, err := coordinator.Eligibility.FreshEligibilityProofSet(ctx, "coverage-cancellation",
		[]string{input.Request.Body.RequesterSubject, terms.GuarantorAgentID}, admittedAt)
	if err != nil || len(rawProof) == 0 || len(rawProof) > 64<<10 {
		return guarantor.AuthorizedCoverageCancellationReceiptV1{}, resolution, errors.New("fresh cancellation authority proof is unavailable")
	}
	eligibility, err := buildGuarantorEligibilityProofSet(rawProof, action, requestDigest,
		[]string{input.Request.Body.RequesterSubject, terms.GuarantorAgentID}, "coverage-cancellation-request",
		requestDigest, terms.CoverageStateDomainDigest, terms.LifecycleAuthorizationProfile,
		domainID, entry.Sequence, input.AdmittedAtUnix)
	if err != nil {
		return guarantor.AuthorizedCoverageCancellationReceiptV1{}, resolution, err
	}
	proofDigest, _ := guarantor.AuthorityAdmissionEligibilityProofSetDigestV1(eligibility)
	body := guarantor.CoverageCancellationReceiptBodyV1{SchemaVersion: 1, AuthorityID: action.AuthorityID,
		CoverageAgreementBodyDigest: agreementDigest, CoverageObligationID: position.Record.CoverageObligationID,
		CoverageStateDomainDigest: terms.CoverageStateDomainDigest, PriorCoverageEndCommitmentDigest: priorCommitmentDigest,
		AuthorizedCancellationRequestDigest: requestDigest, CancellationPolicyDigest: input.Request.Body.CancellationPolicyDigest,
		CancellationBranch: input.Request.Body.CancellationBranch, EffectiveAtUnix: input.AdmittedAtUnix,
		IncidentEligibilityEndsAtUnix: input.AdmittedAtUnix, ClaimFilingEndsAtUnix: terms.ClaimFilingEndsAtUnix,
		TransitionEvidenceProjectionDigest: projectionDigest, AuthorizedActionDigest: actionDigest,
		StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest,
		WriterGeneration: action.WriterGeneration, WriterFenceDigest: action.WriterFenceDigest,
		PriorCoverageRevision: position.Record.CoverageRevision, EndedCoverageRevision: position.Record.CoverageRevision + 1,
		State: "coverage_ended", AdmittedAtUnix: input.AdmittedAtUnix,
		AuthorityAdmissionEligibilityProofSetDigest: proofDigest}
	bodyDigest, _ := codec.Digest("tos.service.agent-guarantor-cancellation-receipt-body.v1", body)
	if resolution.State == commerce.ActionPrepared {
		resolution, err = coordinator.Authority.Transition(action.StableActionID, action.ExactRequestDigest,
			commerce.ActionTerminal, bodyDigest, []string{bodyDigest})
		if err != nil {
			return guarantor.AuthorizedCoverageCancellationReceiptV1{}, resolution, err
		}
	}
	if resolution.State != commerce.ActionTerminal || resolution.SinkReference != bodyDigest {
		return guarantor.AuthorizedCoverageCancellationReceiptV1{}, resolution,
			errors.New("Guarantor cancellation terminal result conflicts with the reconstructed receipt")
	}
	if _, err = coordinator.Journal.ResolveAdmission(domainID, resolution); err != nil {
		return guarantor.AuthorizedCoverageCancellationReceiptV1{}, resolution, err
	}
	stage, err := coordinator.buildGuarantorStage(terms, "coverage_cancellation",
		"application/vnd.tos.service.agent-guarantor-coverage-cancellation-action.v1+cbor", canonicalRequest,
		action, resolution, fence, admittedAt)
	if err != nil {
		return guarantor.AuthorizedCoverageCancellationReceiptV1{}, resolution, err
	}
	authorization, err := coordinator.Signer.SignObject("coverage-cancellation-receipt", bodyDigest,
		"tos.service.agent-guarantor-cancellation-receipt-signature.v1", admittedAt)
	if err != nil {
		return guarantor.AuthorizedCoverageCancellationReceiptV1{}, resolution, err
	}
	receipt := guarantor.AuthorizedCoverageCancellationReceiptV1{Body: body, StageActionAdmissionEvidence: stage,
		AuthorizedCancellationRequest: input.Request, TransitionEvidenceProjection: projection,
		AuthorityAdmissionEligibilityProofSet: eligibility,
		Authorizations:                        []guarantor.ProfileQualifiedObjectAuthorizationV1{authorization}}
	if err := guarantor.VerifyCoverageCancellationReceiptV1(receipt, *position.ActivationEvidence,
		coordinator.AgreementVerifier, coordinator.Resolver, coordinator.Authority, admittedAt); err != nil {
		return guarantor.AuthorizedCoverageCancellationReceiptV1{}, resolution, err
	}
	if _, err := coordinator.Journal.ApplyCancellation(agreementDigest, position.Record.CoverageRevision, receipt); err != nil {
		return guarantor.AuthorizedCoverageCancellationReceiptV1{}, resolution, err
	}
	return receipt, resolution, nil
}

func guarantorMaxUint64(values ...uint64) uint64 {
	var result uint64
	for _, value := range values {
		if value > result {
			result = value
		}
	}
	return result
}

func minThreeUint64(first, second, third uint64) uint64 {
	return minUint64(minUint64(first, second), third)
}
