package earning

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	guarantor "github.com/tosnetwork/tos-service-protocol/pkg/agentguarantor"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

// resumeCoverageClosureFromTerminalSet completes the two remaining economic
// effects from persisted, portable predecessors. It never derives a second
// semantic action after a crash: a prepared plan is queried and replayed with
// its exact request. A newer writer may replace only the authorization envelope
// while preserving the stable action and exact request identities.
func (coordinator *GuarantorProviderCoordinator) resumeCoverageClosureFromTerminalSet(ctx context.Context,
	input GuarantorCloseCoverageInput, position GuarantorCoveragePosition,
	fence commerce.WriterFence) (GuarantorCloseCoverageResult, error) {
	if err := ctx.Err(); err != nil {
		return GuarantorCloseCoverageResult{}, err
	}
	if position.FilingCloseReceipt == nil || position.TerminalClaimSet == nil {
		return GuarantorCloseCoverageResult{}, errors.New("Guarantor closure recovery lacks its portable predecessors")
	}
	now := coordinator.Authority.AuthorityNow().UTC()
	terminalSet := *position.TerminalClaimSet
	if err := guarantor.VerifyTerminalClaimSetV1(terminalSet, input.Offer, coordinator.AgreementVerifier,
		coordinator.Resolver, coordinator.Authority, coordinator.PaymentVerifier, now); err != nil {
		return GuarantorCloseCoverageResult{}, fmt.Errorf("verify persisted terminal claim set: %w", err)
	}
	agreementDigest := terminalSet.Body.CoverageAgreementBodyDigest
	terminalDigest, _ := guarantor.TerminalClaimSetDigestV1(terminalSet)
	disposition, err := guarantor.ComputeExposureDispositionV1(input.Offer.ExposureAdmissionReceipt, terminalSet.Body)
	if err != nil {
		return GuarantorCloseCoverageResult{}, err
	}
	realized, realizedOK := new(big.Int).SetString(disposition.RealizedLoss.AmountAtomic, 10)
	retained, retainedOK := new(big.Int).SetString(disposition.RetainedDefaultedLiability.AmountAtomic, 10)
	if !realizedOK || !retainedOK || !realized.IsUint64() || !retained.IsUint64() {
		return GuarantorCloseCoverageResult{}, errors.New("Guarantor recovered exposure disposition exceeds local capacity")
	}

	releaseReceipt := guarantor.AuthorizedExposureReleaseReceiptV1{}
	if position.ExposureReleaseReceipt != nil {
		releaseReceipt = *position.ExposureReleaseReceipt
		if err := guarantor.VerifyExposureReleaseReceiptV1(releaseReceipt, input.Offer, coordinator.AgreementVerifier,
			coordinator.Resolver, coordinator.Authority, coordinator.PaymentVerifier, now); err != nil {
			return GuarantorCloseCoverageResult{}, fmt.Errorf("verify persisted exposure release: %w", err)
		}
	} else {
		plan := position.ExposureReleasePlan
		if plan == nil {
			portfolioRevision, _, _ := coordinator.Authority.Snapshot()
			requestBody := guarantor.ExposureReleaseActionBodyV1{ReservationID: position.Record.ReservationID,
				AgreementDigest: agreementDigest, TargetPortfolioRevision: portfolioRevision + 1,
				TerminalEvidenceSetDigest: terminalDigest}
			request, encodeErr := codec.Marshal(requestBody)
			if encodeErr != nil {
				return GuarantorCloseCoverageResult{}, encodeErr
			}
			fields := map[string]commerce.SemanticValue{"owner_id": commerce.ID(coordinator.OwnerID),
				"agent_id": commerce.ID(coordinator.AgentID), "reservation_id": commerce.Digest32(position.Record.ReservationID),
				"target_revision": commerce.U64(portfolioRevision + 1), "terminal_evidence_set_digest": commerce.Digest32(terminalDigest)}
			action, buildErr := commerce.BuildAuthorizedAction(coordinator.OwnerID, coordinator.AgentID, "portfolio.release",
				fields, request, fence, coordinator.PolicyRevision, coordinator.MandateDigest, "", terminalDigest,
				minUint64(position.Terms.TerminalResolutionDeadlineUnix, fence.Body.ExpiresAtUnix))
			if buildErr == nil {
				action, buildErr = coordinator.Authority.SignAction(action, fence)
			}
			if buildErr != nil {
				return GuarantorCloseCoverageResult{}, buildErr
			}
			prepared := GuarantorExposureReleasePlan{Action: action, WriterFence: fence, Fields: fields,
				CanonicalRequest: request, RequestBody: requestBody, Disposition: disposition, CreatedAtUnix: uint64(now.Unix())}
			prepared, buildErr = coordinator.Journal.PrepareExposureReleasePlan(agreementDigest, prepared)
			if buildErr != nil {
				return GuarantorCloseCoverageResult{}, buildErr
			}
			plan = &prepared
		}
		if !sameJSON(plan.Disposition, disposition) {
			return GuarantorCloseCoverageResult{}, errors.New("persisted exposure-release plan changed terminal loss disposition")
		}
		resolution := coordinator.Authority.Resolve(plan.Action.StableActionID, plan.Action.ExactRequestDigest)
		if resolution.State == commerce.ActionUnknown || resolution.State == commerce.ActionPrepared {
			plan, err = coordinator.reauthorizeExposureReleasePlanIfNeeded(agreementDigest, position, plan, fence, now)
			if err != nil {
				return GuarantorCloseCoverageResult{}, err
			}
			resolution, err = coordinator.Authority.ReleaseGuarantorReservation(plan.Action, plan.Fields,
				plan.CanonicalRequest, plan.WriterFence, realized.Uint64(), retained.Uint64())
		}
		if err != nil || resolution.State != commerce.ActionTerminal {
			return GuarantorCloseCoverageResult{}, firstError(err, errors.New("persisted Guarantor exposure release is unresolved"))
		}
		at := time.Unix(int64(plan.CreatedAtUnix), 0).UTC()
		stage, stageErr := coordinator.buildGuarantorStage(position.Terms, "post_acceptance_exposure_release",
			"application/vnd.tos.service.agent-guarantor-exposure-release-action.v1+cbor", plan.CanonicalRequest,
			plan.Action, resolution, plan.WriterFence, at)
		if stageErr != nil {
			return GuarantorCloseCoverageResult{}, stageErr
		}
		exposureAdmissionDigest, _ := guarantor.ExposureAdmissionReceiptDigestV1(input.Offer.ExposureAdmissionReceipt)
		dispositionDigest, _ := guarantor.ExposureDispositionComputationDigestV1(disposition)
		zero := commerce.AtomicAmountV1{Asset: position.Terms.CoverageAsset, AmountAtomic: "0"}
		body := guarantor.ExposureReleaseReceiptBodyV1{SchemaVersion: 1, AuthorityID: plan.Action.AuthorityID,
			GuarantorAgentID: coordinator.AgentID, CoverageAgreementBodyDigest: agreementDigest,
			CoverageObligationID: position.Record.CoverageObligationID, ReservationID: position.Record.ReservationID,
			ExposureAdmissionReceiptDigest: exposureAdmissionDigest, TerminalClaimSetEvidenceDigest: terminalDigest,
			ExposureDispositionComputationDigest: dispositionDigest, AuthorizedActionDigest: mustActionDigest(plan.Action),
			StableActionID: plan.Action.StableActionID, ExactRequestDigest: plan.Action.ExactRequestDigest,
			WriterGeneration: plan.Action.WriterGeneration, WriterFenceDigest: plan.Action.WriterFenceDigest,
			BaseReleaseStateRevision:     plan.RequestBody.TargetPortfolioRevision - 1,
			ReleasedReleaseStateRevision: plan.RequestBody.TargetPortfolioRevision,
			ReleasedExposure:             position.Terms.MaximumAggregatePayout, RemainingReservedExposure: zero,
			PortfolioDisposition: disposition.PortfolioDisposition, ReturnedToAvailableExposure: disposition.ReturnedToAvailableExposure,
			RealizedLoss: disposition.RealizedLoss, RetainedDefaultedLiability: disposition.RetainedDefaultedLiability,
			State: "released", ReleasedAtUnix: plan.CreatedAtUnix}
		bodyDigest, _ := codec.Digest("tos.service.agent-guarantor-exposure-release-receipt-body.v1", body)
		authorization, signErr := coordinator.Signer.SignObject("exposure-release-receipt", bodyDigest,
			"tos.service.agent-guarantor-exposure-release-receipt-signature.v1", at)
		if signErr != nil {
			return GuarantorCloseCoverageResult{}, signErr
		}
		releaseReceipt = guarantor.AuthorizedExposureReleaseReceiptV1{Body: body, StageActionAdmissionEvidence: stage,
			AuthorizedExposureAdmissionReceipt: input.Offer.ExposureAdmissionReceipt,
			AuthorizedTerminalClaimSetEvidence: terminalSet, ExposureDispositionComputation: disposition,
			Authorizations: []guarantor.ProfileQualifiedObjectAuthorizationV1{authorization}}
		if _, err = coordinator.Journal.CommitExposureReleaseReceipt(agreementDigest, releaseReceipt); err != nil {
			return GuarantorCloseCoverageResult{}, err
		}
	}

	position, err = coordinator.coveragePosition(agreementDigest)
	if err != nil {
		return GuarantorCloseCoverageResult{}, err
	}
	if position.CoverageResolution != nil {
		return GuarantorCloseCoverageResult{FilingCloseReceipt: *position.FilingCloseReceipt, TerminalClaimSet: terminalSet,
			ExposureRelease: releaseReceipt, CoverageResolution: *position.CoverageResolution}, nil
	}
	releaseDigest, _ := guarantor.ExposureReleaseReceiptDigestV1(releaseReceipt)
	targetStatus, targetState, err := guarantorTerminalCoverageTarget(terminalSet.Body.ResolutionTargetTerminalState)
	if err != nil {
		return GuarantorCloseCoverageResult{}, err
	}
	plan := position.CoverageResolutionPlan
	if plan == nil {
		requestBody := guarantor.CoverageResolutionActionBodyV1{SchemaVersion: 1,
			ExposureReleaseReceiptDigest: releaseDigest, ExpectedRevision: position.Record.CoverageRevision,
			TargetRevision: position.Record.CoverageRevision + 1}
		request, encodeErr := codec.Marshal(requestBody)
		if encodeErr != nil {
			return GuarantorCloseCoverageResult{}, encodeErr
		}
		fields := map[string]commerce.SemanticValue{"owner_id": commerce.ID(coordinator.OwnerID), "agent_id": commerce.ID(coordinator.AgentID),
			"agreement_body_digest": commerce.Digest32(agreementDigest), "obligation_id": commerce.ID(position.Record.CoverageObligationID),
			"expected_state_revision": commerce.U64(position.Record.CoverageRevision), "target_state": commerce.State(targetState),
			"evidence_set_digest": commerce.Digest32(releaseDigest)}
		action, buildErr := commerce.BuildAuthorizedAction(coordinator.OwnerID, coordinator.AgentID, "conditional.obligation.transition",
			fields, request, fence, coordinator.PolicyRevision, coordinator.MandateDigest, "", releaseDigest,
			minUint64(position.Terms.TerminalResolutionDeadlineUnix, fence.Body.ExpiresAtUnix))
		if buildErr == nil {
			action, buildErr = coordinator.Authority.SignAction(action, fence)
		}
		if buildErr != nil {
			return GuarantorCloseCoverageResult{}, buildErr
		}
		prepared := GuarantorCoverageResolutionPlan{Action: action, WriterFence: fence, Fields: fields,
			CanonicalRequest: request, RequestBody: requestBody, TargetStatus: targetStatus, TargetState: targetState,
			CreatedAtUnix: uint64(now.Unix())}
		prepared, buildErr = coordinator.Journal.PrepareCoverageResolutionPlan(agreementDigest, prepared)
		if buildErr != nil {
			return GuarantorCloseCoverageResult{}, buildErr
		}
		plan = &prepared
	}
	resolution := coordinator.Authority.Resolve(plan.Action.StableActionID, plan.Action.ExactRequestDigest)
	if resolution.State == commerce.ActionUnknown || resolution.State == commerce.ActionPrepared {
		plan, err = coordinator.reauthorizeCoverageResolutionPlanIfNeeded(agreementDigest, position, plan, fence, now)
		if err != nil {
			return GuarantorCloseCoverageResult{}, err
		}
		resolution, err = coordinator.Authority.Admit(plan.Action, plan.Fields, plan.CanonicalRequest, plan.WriterFence, nil)
	}
	if err != nil || (resolution.State != commerce.ActionPrepared && resolution.State != commerce.ActionTerminal) {
		return GuarantorCloseCoverageResult{}, firstError(err, errors.New("persisted Guarantor coverage resolution is unresolved"))
	}
	if resolution.State != commerce.ActionTerminal {
		resolution, err = coordinator.Authority.Transition(plan.Action.StableActionID, plan.Action.ExactRequestDigest,
			commerce.ActionTerminal, releaseDigest, []string{releaseDigest})
		if err != nil {
			return GuarantorCloseCoverageResult{}, err
		}
	}
	at := time.Unix(int64(plan.CreatedAtUnix), 0).UTC()
	stage, err := coordinator.buildGuarantorStage(position.Terms, "coverage_resolution",
		"application/vnd.tos.service.agent-guarantor-coverage-resolution-action.v1+cbor", plan.CanonicalRequest,
		plan.Action, resolution, plan.WriterFence, at)
	if err != nil {
		return GuarantorCloseCoverageResult{}, err
	}
	body := guarantor.CoverageResolutionBodyV1{SchemaVersion: 1, AuthorityID: plan.Action.AuthorityID,
		CoverageAgreementBodyDigest: agreementDigest, CoverageObligationID: position.Record.CoverageObligationID,
		CoverageEndCommitmentDigest: terminalSet.Body.CoverageEndCommitmentDigest,
		ActivationEvidenceDigest:    terminalSet.Body.ActivationEvidenceDigest, TerminalClaimSetEvidenceDigest: terminalDigest,
		ExposureReleaseReceiptDigest: releaseDigest, PriorCoverageRevision: plan.RequestBody.ExpectedRevision,
		ResolvedCoverageRevision: plan.RequestBody.TargetRevision, TerminalState: plan.TargetState,
		AuthorizedActionDigest: mustActionDigest(plan.Action), StableActionID: plan.Action.StableActionID,
		ExactRequestDigest: plan.Action.ExactRequestDigest, WriterGeneration: plan.Action.WriterGeneration,
		WriterFenceDigest: plan.Action.WriterFenceDigest, ResolvedAtUnix: plan.CreatedAtUnix}
	bodyDigest, _ := codec.Digest("tos.service.agent-guarantor-resolution-body.v1", body)
	authorization, err := coordinator.Signer.SignObject("coverage-resolution", bodyDigest,
		"tos.service.agent-guarantor-resolution-signature.v1", at)
	if err != nil {
		return GuarantorCloseCoverageResult{}, err
	}
	coverageResolution := guarantor.AuthorizedCoverageResolutionV1{Body: body, StageActionAdmissionEvidence: stage,
		AuthorizedExposureReleaseReceipt: releaseReceipt,
		Authorizations:                   []guarantor.ProfileQualifiedObjectAuthorizationV1{authorization}}
	if _, err = coordinator.Journal.CommitCoverageResolution(agreementDigest, coverageResolution); err != nil {
		return GuarantorCloseCoverageResult{}, err
	}
	return GuarantorCloseCoverageResult{FilingCloseReceipt: *position.FilingCloseReceipt, TerminalClaimSet: terminalSet,
		ExposureRelease: releaseReceipt, CoverageResolution: coverageResolution}, nil
}

func (coordinator *GuarantorProviderCoordinator) reauthorizeExposureReleasePlanIfNeeded(agreementDigest string,
	position GuarantorCoveragePosition, plan *GuarantorExposureReleasePlan, fence commerce.WriterFence,
	now time.Time) (*GuarantorExposureReleasePlan, error) {
	if plan == nil || plan.Action.WriterGeneration == fence.Body.WriterGeneration {
		return plan, nil
	}
	if fence.Body.WriterGeneration < plan.Action.WriterGeneration {
		return nil, errors.New("stale writer cannot recover a Guarantor exposure release")
	}
	deadline := guarantorClosureActionDeadline(position)
	action, err := commerce.BuildAuthorizedAction(coordinator.OwnerID, coordinator.AgentID, "portfolio.release",
		plan.Fields, plan.CanonicalRequest, fence, coordinator.PolicyRevision, coordinator.MandateDigest,
		plan.Action.ApprovalDigest, plan.Action.ExpectedPriorState, minUint64(deadline, fence.Body.ExpiresAtUnix))
	if err == nil {
		action, err = coordinator.Authority.SignAction(action, fence)
	}
	if err != nil {
		return nil, fmt.Errorf("reauthorize Guarantor exposure release: %w", err)
	}
	if action.StableActionID != plan.Action.StableActionID || action.ExactRequestDigest != plan.Action.ExactRequestDigest {
		return nil, errors.New("Guarantor exposure-release reauthorization changed semantic identity")
	}
	next := *plan
	next.Action, next.WriterFence, next.CreatedAtUnix = action, fence, uint64(now.Unix())
	next, err = coordinator.Journal.ReauthorizeExposureReleasePlan(agreementDigest, next)
	return &next, err
}

func (coordinator *GuarantorProviderCoordinator) reauthorizeCoverageResolutionPlanIfNeeded(agreementDigest string,
	position GuarantorCoveragePosition, plan *GuarantorCoverageResolutionPlan, fence commerce.WriterFence,
	now time.Time) (*GuarantorCoverageResolutionPlan, error) {
	if plan == nil || plan.Action.WriterGeneration == fence.Body.WriterGeneration {
		return plan, nil
	}
	if fence.Body.WriterGeneration < plan.Action.WriterGeneration {
		return nil, errors.New("stale writer cannot recover a Guarantor coverage resolution")
	}
	deadline := guarantorClosureActionDeadline(position)
	action, err := commerce.BuildAuthorizedAction(coordinator.OwnerID, coordinator.AgentID, "conditional.obligation.transition",
		plan.Fields, plan.CanonicalRequest, fence, coordinator.PolicyRevision, coordinator.MandateDigest,
		plan.Action.ApprovalDigest, plan.Action.ExpectedPriorState, minUint64(deadline, fence.Body.ExpiresAtUnix))
	if err == nil {
		action, err = coordinator.Authority.SignAction(action, fence)
	}
	if err != nil {
		return nil, fmt.Errorf("reauthorize Guarantor coverage resolution: %w", err)
	}
	if action.StableActionID != plan.Action.StableActionID || action.ExactRequestDigest != plan.Action.ExactRequestDigest {
		return nil, errors.New("Guarantor coverage-resolution reauthorization changed semantic identity")
	}
	next := *plan
	next.Action, next.WriterFence, next.CreatedAtUnix = action, fence, uint64(now.Unix())
	next, err = coordinator.Journal.ReauthorizeCoverageResolutionPlan(agreementDigest, next)
	return &next, err
}

func guarantorClosureActionDeadline(position GuarantorCoveragePosition) uint64 {
	if position.FilingCloseReceipt != nil &&
		position.FilingCloseReceipt.Body.ClosedAtUnix > position.Terms.TerminalResolutionDeadlineUnix {
		return position.Terms.LateRecoveryTerminalDeadlineUnix
	}
	return position.Terms.TerminalResolutionDeadlineUnix
}

func guarantorTerminalCoverageTarget(state string) (guarantor.CoverageStatus, string, error) {
	switch state {
	case "closed":
		return guarantor.CoverageClosed, state, nil
	case "cancelled":
		return guarantor.CoverageCancelled, state, nil
	case "defaulted":
		return guarantor.CoverageDefaulted, state, nil
	case "exhausted":
		return guarantor.CoverageExhausted, state, nil
	default:
		return "", "", errors.New("Guarantor terminal claim set has an unknown coverage target")
	}
}
