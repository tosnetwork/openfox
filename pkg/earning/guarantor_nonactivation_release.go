package earning

import (
	"context"
	"errors"
	"fmt"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	guarantor "github.com/tosnetwork/tos-service-protocol/pkg/agentguarantor"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

// ReleaseNonActivatedExposure closes the provider's private reservation after
// portable non-activation evidence proves that no covered incident can ever
// exist.  It is a separately fenced action and is safe to retry after crash.
func (coordinator *GuarantorProviderCoordinator) ReleaseNonActivatedExposure(ctx context.Context,
	offer guarantor.AuthorizedFirmCoverageOfferV1, evidence guarantor.AuthorizedCoverageNonActivationEvidenceV1,
	fence commerce.WriterFence) (guarantor.AuthorizedNonActivationExposureReleaseReceiptV1, commerce.ActionResolution, error) {
	if err := ctx.Err(); err != nil {
		return guarantor.AuthorizedNonActivationExposureReleaseReceiptV1{}, commerce.ActionResolution{}, err
	}
	if coordinator == nil || coordinator.Authority == nil || coordinator.Journal == nil || coordinator.Signer == nil ||
		coordinator.Resolver == nil || coordinator.AgreementVerifier == nil {
		return guarantor.AuthorizedNonActivationExposureReleaseReceiptV1{}, commerce.ActionResolution{},
			errors.New("Guarantor non-activation release coordinator is incomplete")
	}
	now := coordinator.Authority.AuthorityNow().UTC()
	if now.IsZero() || coordinator.Authority.ConfirmCurrentWriterFence(fence, now) != nil {
		return guarantor.AuthorizedNonActivationExposureReleaseReceiptV1{}, commerce.ActionResolution{},
			errors.New("Guarantor non-activation release writer is stale")
	}
	if err := guarantor.VerifyCoverageNonActivationEvidenceV1(evidence, offer, coordinator.AgreementVerifier,
		coordinator.Resolver, coordinator.Authority, now); err != nil {
		return guarantor.AuthorizedNonActivationExposureReleaseReceiptV1{}, commerce.ActionResolution{}, err
	}
	agreementDigest := evidence.Body.CoverageAgreementBodyDigest
	position, err := coordinator.coveragePosition(agreementDigest)
	if err != nil || position.Record.CoverageStatus != guarantor.CoverageNotActivatedConfirmed ||
		position.NonActivationEvidence == nil || len(position.ClaimAdmissionSequence) != 0 {
		return guarantor.AuthorizedNonActivationExposureReleaseReceiptV1{}, commerce.ActionResolution{},
			errors.New("Guarantor non-activation release has an ineligible local state")
	}
	if position.NonActivationReleaseReceipt != nil {
		stored := *position.NonActivationReleaseReceipt
		resolution := coordinator.Authority.Resolve(stored.Body.StableActionID, stored.Body.ExactRequestDigest)
		if resolution.State != commerce.ActionTerminal {
			return guarantor.AuthorizedNonActivationExposureReleaseReceiptV1{}, resolution,
				errors.New("Guarantor non-activation release journal is ahead of its authority")
		}
		return stored, resolution, nil
	}
	nonActivationDigest, _ := guarantor.CoverageNonActivationEvidenceDigestV1(evidence)
	portfolioRevision, _, _ := coordinator.Authority.Snapshot()
	requestBody := guarantor.ExposureReleaseActionBodyV1{ReservationID: position.Record.ReservationID,
		AgreementDigest: agreementDigest, TargetPortfolioRevision: portfolioRevision + 1,
		TerminalEvidenceSetDigest: nonActivationDigest}
	request, err := codec.Marshal(requestBody)
	if err != nil {
		return guarantor.AuthorizedNonActivationExposureReleaseReceiptV1{}, commerce.ActionResolution{}, err
	}
	fields := map[string]commerce.SemanticValue{
		"owner_id": commerce.ID(coordinator.OwnerID), "agent_id": commerce.ID(coordinator.AgentID),
		"reservation_id":               commerce.Digest32(position.Record.ReservationID),
		"target_revision":              commerce.U64(portfolioRevision + 1),
		"terminal_evidence_set_digest": commerce.Digest32(nonActivationDigest),
	}
	action, err := commerce.BuildAuthorizedAction(coordinator.OwnerID, coordinator.AgentID, "portfolio.release",
		fields, request, fence, coordinator.PolicyRevision, coordinator.MandateDigest, "", nonActivationDigest,
		fence.Body.ExpiresAtUnix)
	if err == nil {
		action, err = coordinator.Authority.SignAction(action, fence)
	}
	if err != nil {
		return guarantor.AuthorizedNonActivationExposureReleaseReceiptV1{}, commerce.ActionResolution{}, err
	}
	resolution, err := coordinator.Authority.ReleaseReservation(action, fields, request, fence)
	if err != nil || resolution.State != commerce.ActionTerminal {
		return guarantor.AuthorizedNonActivationExposureReleaseReceiptV1{}, resolution,
			firstError(err, errors.New("Guarantor non-activation exposure release is not terminal"))
	}
	stage, err := coordinator.buildGuarantorStage(position.Terms, "post_acceptance_exposure_release",
		"application/vnd.tos.service.agent-guarantor-exposure-release-action.v1+cbor", request,
		action, resolution, fence, now)
	if err != nil {
		return guarantor.AuthorizedNonActivationExposureReleaseReceiptV1{}, resolution, err
	}
	exposureDigest, _ := guarantor.ExposureAdmissionReceiptDigestV1(offer.ExposureAdmissionReceipt)
	zero := commerce.AtomicAmountV1{Asset: position.Terms.CoverageAsset, AmountAtomic: "0"}
	body := guarantor.NonActivationExposureReleaseReceiptBodyV1{SchemaVersion: 1, AuthorityID: action.AuthorityID,
		GuarantorAgentID: coordinator.AgentID, CoverageAgreementBodyDigest: agreementDigest,
		CoverageObligationID: position.Record.CoverageObligationID, ReservationID: position.Record.ReservationID,
		ExposureAdmissionReceiptDigest: exposureDigest, NonActivationEvidenceDigest: nonActivationDigest,
		AuthorizedActionDigest: mustActionDigest(action), StableActionID: action.StableActionID,
		ExactRequestDigest: action.ExactRequestDigest, WriterGeneration: action.WriterGeneration,
		WriterFenceDigest: action.WriterFenceDigest, BaseReleaseStateRevision: portfolioRevision,
		ReleasedReleaseStateRevision: portfolioRevision + 1, ReleasedExposure: offer.ExposureAdmissionReceipt.Body.ReservedExposure,
		RemainingReservedExposure: zero, State: "released", ReleasedAtUnix: uint64(now.Unix())}
	bodyDigest, err := codec.Digest("tos.service.agent-guarantor-non-activation-exposure-release-body.v1", body)
	if err != nil {
		return guarantor.AuthorizedNonActivationExposureReleaseReceiptV1{}, resolution, err
	}
	authorization, err := coordinator.Signer.SignObject("non-activation-exposure-release-receipt", bodyDigest,
		"tos.service.agent-guarantor-non-activation-exposure-release-signature.v1", now)
	if err != nil {
		return guarantor.AuthorizedNonActivationExposureReleaseReceiptV1{}, resolution, err
	}
	receipt := guarantor.AuthorizedNonActivationExposureReleaseReceiptV1{Body: body,
		StageActionAdmissionEvidence: stage, AuthorizedExposureAdmissionReceipt: offer.ExposureAdmissionReceipt,
		AuthorizedNonActivationEvidence: evidence,
		Authorizations:                  []guarantor.ProfileQualifiedObjectAuthorizationV1{authorization}}
	if err := guarantor.VerifyNonActivationExposureReleaseReceiptV1(receipt, offer, coordinator.AgreementVerifier,
		coordinator.Resolver, coordinator.Authority, now); err != nil {
		return receipt, resolution, fmt.Errorf("verify Guarantor non-activation release: %w", err)
	}
	if _, err := coordinator.Journal.CommitNonActivationRelease(agreementDigest, receipt); err != nil {
		return receipt, resolution, err
	}
	return receipt, resolution, nil
}
