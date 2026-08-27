package earning

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	guarantor "github.com/tosnetwork/tos-service-protocol/pkg/agentguarantor"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type GuarantorCloseCoverageInput struct {
	Offer               guarantor.AuthorizedFirmCoverageOfferV1
	ActivationEvidence  guarantor.AuthorizedCoverageActivationEvidenceV1
	CancellationReceipt *guarantor.AuthorizedCoverageCancellationReceiptV1
}

type GuarantorCloseCoverageResult struct {
	FilingCloseReceipt guarantor.AuthorizedClaimFilingCloseReceiptV1
	TerminalClaimSet   guarantor.AuthorizedTerminalClaimSetEvidenceV1
	ExposureRelease    guarantor.AuthorizedExposureReleaseReceiptV1
	CoverageResolution guarantor.AuthorizedCoverageResolutionV1
}

func (coordinator *GuarantorProviderCoordinator) CloseCoverage(ctx context.Context, input GuarantorCloseCoverageInput,
	fence commerce.WriterFence) (GuarantorCloseCoverageResult, error) {
	if err := ctx.Err(); err != nil {
		return GuarantorCloseCoverageResult{}, err
	}
	if coordinator == nil || coordinator.Authority == nil || coordinator.Journal == nil || coordinator.Signer == nil ||
		coordinator.Resolver == nil || coordinator.AgreementVerifier == nil || coordinator.PaymentVerifier == nil {
		return GuarantorCloseCoverageResult{}, errors.New("Guarantor closure coordinator is incomplete")
	}
	now := coordinator.Authority.AuthorityNow().UTC()
	if now.IsZero() || coordinator.Authority.ConfirmCurrentWriterFence(fence, now) != nil {
		return GuarantorCloseCoverageResult{}, errors.New("Guarantor closure writer is stale")
	}
	if err := guarantor.VerifyCoverageActivationEvidenceV1(input.ActivationEvidence, input.Offer,
		coordinator.AgreementVerifier, coordinator.Resolver, coordinator.Authority,
		coordinator.CollateralFinalityVerifier, now); err != nil {
		return GuarantorCloseCoverageResult{}, err
	}
	agreementDigest := input.ActivationEvidence.Body.CoverageAgreementBodyDigest
	position, err := coordinator.coveragePosition(agreementDigest)
	if err != nil {
		return GuarantorCloseCoverageResult{}, err
	}
	if position.CoverageResolution != nil {
		if position.FilingCloseReceipt == nil || position.TerminalClaimSet == nil || position.ExposureReleaseReceipt == nil {
			return GuarantorCloseCoverageResult{}, errors.New("terminal Guarantor coverage has an incomplete portable closure journal")
		}
		if err := guarantor.VerifyCoverageResolutionV1(*position.CoverageResolution, input.Offer,
			coordinator.AgreementVerifier, coordinator.Resolver, coordinator.Authority,
			coordinator.PaymentVerifier, now); err != nil {
			return GuarantorCloseCoverageResult{}, fmt.Errorf("verify persisted coverage resolution: %w", err)
		}
		return GuarantorCloseCoverageResult{FilingCloseReceipt: *position.FilingCloseReceipt,
			TerminalClaimSet: *position.TerminalClaimSet, ExposureRelease: *position.ExposureReleaseReceipt,
			CoverageResolution: *position.CoverageResolution}, nil
	}
	if position.TerminalClaimSet != nil {
		return coordinator.resumeCoverageClosureFromTerminalSet(ctx, input, position, fence)
	}
	filingCutoff := position.Terms.ClaimFilingEndsAtUnix
	incidentEnd := position.Terms.CoverageEndsAtUnix
	filingReason, endReason, priorState := "normal", "normal_expiry", "active"
	endCommitment := input.ActivationEvidence.CoverageEndCommitment
	if input.CancellationReceipt != nil {
		if err := guarantor.VerifyCoverageCancellationReceiptV1(*input.CancellationReceipt, input.ActivationEvidence,
			coordinator.AgreementVerifier, coordinator.Resolver, coordinator.Authority, now); err != nil {
			return GuarantorCloseCoverageResult{}, err
		}
		cancellationDigest, digestErr := guarantor.CoverageCancellationReceiptDigestV1(*input.CancellationReceipt)
		if digestErr != nil {
			return GuarantorCloseCoverageResult{}, digestErr
		}
		filingCutoff = input.CancellationReceipt.Body.ClaimFilingEndsAtUnix
		incidentEnd = input.CancellationReceipt.Body.IncidentEligibilityEndsAtUnix
		filingReason, endReason, priorState = "accepted_cancellation", "accepted_cancellation", "coverage_ended"
		endCommitment = guarantor.CoverageEndCommitmentV1{SchemaVersion: 1,
			CoverageAgreementBodyDigest: agreementDigest, CoverageObligationID: position.Record.CoverageObligationID,
			CoverageStateDomainDigest: position.Terms.CoverageStateDomainDigest, EndBranch: "accepted_cancellation",
			IncidentEligibilityEndsAtUnix: incidentEnd, CoverageEndEvidenceDigest: cancellationDigest}
	}
	var filingReceipt guarantor.AuthorizedClaimFilingCloseReceiptV1
	var filingReceiptDigest, activationDigest, endDigest string
	claimLogID := "claim-log:" + agreementDigest[len("sha256:"):]
	frozen := position
	if position.FilingCloseReceipt != nil {
		filingReceipt = *position.FilingCloseReceipt
		if err := guarantor.VerifyClaimFilingCloseReceiptV1(filingReceipt, input.Offer,
			coordinator.AgreementVerifier, coordinator.Resolver, coordinator.Authority, now); err != nil {
			return GuarantorCloseCoverageResult{}, fmt.Errorf("verify persisted filing-close receipt: %w", err)
		}
		filingReceiptDigest, err = guarantor.ClaimFilingCloseReceiptDigestV1(filingReceipt)
		activationDigest, _ = guarantor.CoverageActivationEvidenceDigestV1(input.ActivationEvidence)
		endDigest, _ = guarantor.CoverageEndCommitmentDigestV1(endCommitment)
		if err != nil || filingReceipt.Body.CoverageEndCommitmentDigest != endDigest ||
			filingReceipt.Body.ActivationEvidenceDigest != activationDigest {
			return GuarantorCloseCoverageResult{}, errors.New("persisted Guarantor filing-close lineage conflicts with closure input")
		}
	} else {
		wantStatus := guarantor.CoverageActive
		if input.CancellationReceipt != nil {
			wantStatus = guarantor.CoverageEnded
		}
		if position.Record.CoverageStatus != wantStatus || uint64(now.Unix()) < filingCutoff {
			return GuarantorCloseCoverageResult{}, errors.New("Guarantor coverage is not ready for normal closure")
		}
		activationDigest, err = guarantor.CoverageActivationEvidenceDigestV1(input.ActivationEvidence)
		if err != nil {
			return GuarantorCloseCoverageResult{}, fmt.Errorf("digest coverage activation evidence: %w", err)
		}
		endDigest, err = guarantor.CoverageEndCommitmentDigestV1(endCommitment)
		if err != nil {
			return GuarantorCloseCoverageResult{}, fmt.Errorf("digest coverage end commitment: %w", err)
		}
		ingressCut, err := coordinator.Journal.InitialClaimIngressAdmissionCut(agreementDigest, filingCutoff)
		if err != nil {
			return GuarantorCloseCoverageResult{}, fmt.Errorf("freeze initial claim ingress cut: %w", err)
		}
		if ingressCut.PendingOrAmbiguousCount != 0 {
			return GuarantorCloseCoverageResult{}, errors.New("Guarantor filing close is blocked by timely unresolved claim ingress")
		}
		ingressCutDigest, err := guarantor.ClaimIngressAdmissionCutProofDigestV1(ingressCut)
		if err != nil {
			return GuarantorCloseCoverageResult{}, fmt.Errorf("digest initial claim ingress cut: %w", err)
		}
		filingProjection := guarantor.TransitionEvidenceProjectionV1{SchemaVersion: 1, Purpose: "claim-filing-close",
			CoverageAgreementBodyDigest: agreementDigest, ObligationID: position.Record.CoverageObligationID,
			TargetState: "frozen", EvidenceDigests: []guarantor.TransitionEvidenceDigestRefV1{
				{EvidenceRole: "activation", DigestKind: "authorized_envelope", ObjectDigest: activationDigest}}}
		if input.CancellationReceipt != nil {
			cancellationDigest, _ := guarantor.CoverageCancellationReceiptDigestV1(*input.CancellationReceipt)
			filingProjection.EvidenceDigests = append(filingProjection.EvidenceDigests,
				guarantor.TransitionEvidenceDigestRefV1{EvidenceRole: "coverage_cancellation", DigestKind: "authorized_envelope", ObjectDigest: cancellationDigest})
		}
		sort.Slice(filingProjection.EvidenceDigests, func(i, j int) bool {
			left, _ := codec.Marshal(filingProjection.EvidenceDigests[i])
			right, _ := codec.Marshal(filingProjection.EvidenceDigests[j])
			return string(left) < string(right)
		})
		filingProjectionDigest, err := guarantor.TransitionEvidenceProjectionDigestV1(filingProjection)
		if err != nil {
			return GuarantorCloseCoverageResult{}, fmt.Errorf("digest filing-close evidence projection: %w", err)
		}
		activationCopy := input.ActivationEvidence
		filingRequest := guarantor.ClaimFilingCloseActionBodyV1{SchemaVersion: 1,
			CoverageAgreementBodyDigest: agreementDigest, CoverageObligationID: position.Record.CoverageObligationID,
			ClaimAdmissionLogID: claimLogID, ClaimIngressAdmissionCutProof: ingressCut,
			FilingCloseReason: filingReason, FilingCutoffUnix: filingCutoff, ExpectedCoverageState: priorState,
			ExpectedCoverageEndCommitmentDigest: endDigest, CoverageEndReason: endReason,
			ActivationEvidenceDigest: activationDigest,
			ExpectedCoverageRevision: position.Record.CoverageRevision, TargetCoverageRevision: position.Record.CoverageRevision + 1,
			ExpectedClaimFilingStateRevision: position.Record.FilingStateRevision, TargetClaimFilingState: "frozen",
			ExpectedClaimAdmissionHighWater: uint64(len(position.ClaimAdmissionSequence)),
			ExpectedClaimAdmissionLogRoot:   position.ClaimAdmissionLogRoot, TransitionEvidenceProjection: filingProjection}
		if input.CancellationReceipt != nil {
			filingRequest.CoverageCancellationReceiptDigest, _ = guarantor.CoverageCancellationReceiptDigestV1(*input.CancellationReceipt)
		}
		canonicalFiling, err := codec.Marshal(filingRequest)
		if err != nil {
			return GuarantorCloseCoverageResult{}, fmt.Errorf("encode filing-close request: %w", err)
		}
		filingFields := map[string]commerce.SemanticValue{"owner_id": commerce.ID(coordinator.OwnerID), "agent_id": commerce.ID(coordinator.AgentID),
			"agreement_body_digest": commerce.Digest32(agreementDigest), "obligation_id": commerce.ID(position.Record.CoverageObligationID),
			"claim_admission_log_id": commerce.ID(claimLogID), "expected_coverage_revision": commerce.U64(position.Record.CoverageRevision),
			"expected_claim_filing_state_revision": commerce.U64(position.Record.FilingStateRevision),
			"filing_cutoff_unix":                   commerce.U64(filingCutoff), "target_state": commerce.State("frozen")}
		filingActionDeadline := position.Terms.TerminalResolutionDeadlineUnix
		if uint64(now.Unix()) > filingActionDeadline {
			filingActionDeadline = position.Terms.LateIngressRecoveryDeadlineUnix
			if filingActionDeadline == 0 || uint64(now.Unix()) > filingActionDeadline {
				return GuarantorCloseCoverageResult{}, errors.New("Guarantor late filing-close recovery deadline elapsed")
			}
		}
		filingAction, err := commerce.BuildAuthorizedAction(coordinator.OwnerID, coordinator.AgentID, "conditional.claim-filing.close",
			filingFields, canonicalFiling, fence, coordinator.PolicyRevision, coordinator.MandateDigest, "", position.Record.LastEvidenceDigest,
			minUint64(filingActionDeadline, fence.Body.ExpiresAtUnix))
		if err == nil {
			filingAction, err = coordinator.Authority.SignAction(filingAction, fence)
		}
		if err != nil {
			return GuarantorCloseCoverageResult{}, err
		}
		filingResolution, err := coordinator.Authority.Admit(filingAction, filingFields, canonicalFiling, fence, nil)
		if err != nil || (filingResolution.State != commerce.ActionPrepared && filingResolution.State != commerce.ActionTerminal) {
			return GuarantorCloseCoverageResult{}, firstError(err, errors.New("Guarantor filing-close action was not prepared"))
		}
		filingActionDigest, _ := commerce.AuthorizedActionDigest(filingAction)
		frozenRecord, err := guarantor.FreezeClaimFiling(position.Record, position.Record.CoverageRevision,
			position.Record.FilingStateRevision, uint64(len(position.ClaimAdmissionSequence)),
			position.ClaimAdmissionLogRoot, filingActionDigest, false)
		if err != nil {
			return GuarantorCloseCoverageResult{}, err
		}
		frozen.Record = frozenRecord
		if filingResolution.State != commerce.ActionTerminal {
			filingResolution, err = coordinator.Authority.Transition(filingAction.StableActionID, filingAction.ExactRequestDigest,
				commerce.ActionTerminal, filingActionDigest, []string{filingActionDigest})
			if err != nil {
				return GuarantorCloseCoverageResult{}, err
			}
		}
		filingStage, err := coordinator.buildGuarantorStage(position.Terms, "filing_close",
			"application/vnd.tos.service.agent-guarantor-claim-filing-close-action.v1+cbor", canonicalFiling, filingAction,
			filingResolution, fence, now)
		if err != nil {
			return GuarantorCloseCoverageResult{}, err
		}
		filingBody := guarantor.ClaimFilingCloseReceiptBodyV1{SchemaVersion: 1, AuthorityID: filingAction.AuthorityID,
			CoverageAgreementBodyDigest: agreementDigest, CoverageObligationID: position.Record.CoverageObligationID,
			CoverageStateDomainDigest: position.Terms.CoverageStateDomainDigest, CoverageEndCommitmentDigest: endDigest,
			ClaimAdmissionLogID: claimLogID, ClaimIngressAdmissionCutProofDigest: ingressCutDigest,
			FrozenClaimIngressHighWater: ingressCut.AdmissionHighWater, FrozenClaimIngressLogRoot: ingressCut.AdmissionLogRoot,
			FrozenClaimAdmissionHighWater: uint64(len(position.ClaimAdmissionSequence)), FrozenClaimAdmissionLogRoot: position.ClaimAdmissionLogRoot,
			FilingCloseReason: filingReason, FilingCutoffUnix: filingCutoff, PriorCoverageState: priorState,
			CoverageEndReason: endReason, IncidentEligibilityEndsAtUnix: incidentEnd,
			CoverageEndEvidenceDigest: endCommitment.CoverageEndEvidenceDigest,
			ActivationEvidenceDigest:  activationDigest, PriorCoverageRevision: position.Record.CoverageRevision,
			ClosedCoverageRevision: frozen.Record.CoverageRevision, PriorClaimFilingState: "open", ResultingClaimFilingState: "frozen",
			PriorClaimFilingStateRevision:      position.Record.FilingStateRevision,
			ResultingClaimFilingStateRevision:  frozen.Record.FilingStateRevision,
			TransitionEvidenceProjectionDigest: filingProjectionDigest, AuthorizedActionDigest: filingActionDigest,
			StableActionID: filingAction.StableActionID, ExactRequestDigest: filingAction.ExactRequestDigest,
			WriterGeneration: filingAction.WriterGeneration, WriterFenceDigest: filingAction.WriterFenceDigest, ClosedAtUnix: uint64(now.Unix())}
		if input.CancellationReceipt != nil {
			filingBody.CoverageCancellationReceiptDigest, _ = guarantor.CoverageCancellationReceiptDigestV1(*input.CancellationReceipt)
		}
		filingBodyDigest, err := codec.Digest("tos.service.agent-guarantor-claim-filing-close-receipt-body.v1", filingBody)
		if err != nil {
			return GuarantorCloseCoverageResult{}, fmt.Errorf("digest filing-close receipt body: %w", err)
		}
		filingAuthorization, err := coordinator.Signer.SignObject("claim-filing-close-receipt", filingBodyDigest,
			"tos.service.agent-guarantor-claim-filing-close-signature.v1", now)
		if err != nil {
			return GuarantorCloseCoverageResult{}, err
		}
		filingReceipt = guarantor.AuthorizedClaimFilingCloseReceiptV1{Body: filingBody, StageActionAdmissionEvidence: filingStage,
			CoverageEndCommitment: endCommitment, ClaimIngressAdmissionCutProof: ingressCut,
			AuthorizedActivationEvidence:  &activationCopy,
			AuthorizedCancellationReceipt: input.CancellationReceipt,
			TransitionEvidenceProjection:  filingProjection,
			Authorizations:                []guarantor.ProfileQualifiedObjectAuthorizationV1{filingAuthorization}}
		filingReceiptDigest, err = guarantor.ClaimFilingCloseReceiptDigestV1(filingReceipt)
		if err != nil {
			return GuarantorCloseCoverageResult{}, err
		}
		frozen, err = coordinator.Journal.CommitClaimFilingCloseReceipt(agreementDigest, filingReceipt)
		if err != nil {
			return GuarantorCloseCoverageResult{}, err
		}
	}

	bundles, approved, paid, defaulted, err := terminalClaimBundles(coordinator, frozen, now)
	if err != nil {
		return GuarantorCloseCoverageResult{FilingCloseReceipt: filingReceipt}, err
	}
	asset := position.Terms.CoverageAsset
	zero := commerce.AtomicAmountV1{Asset: asset, AmountAtomic: "0"}
	claimRefs := make([]guarantor.ClaimTerminalResolutionRefV1, len(bundles))
	for index := range bundles {
		claimRefs[index] = bundles[index].ResolutionRef
	}
	closureReason, targetTerminalState := endReason, "closed"
	resolvedCoverageStatus := guarantor.CoverageClosed
	if input.CancellationReceipt != nil {
		targetTerminalState, resolvedCoverageStatus = "cancelled", guarantor.CoverageCancelled
	}
	maximum, _ := new(big.Int).SetString(position.Terms.MaximumAggregatePayout.AmountAtomic, 10)
	if defaulted.Sign() > 0 {
		closureReason, targetTerminalState, resolvedCoverageStatus = "terminal_default", "defaulted", guarantor.CoverageDefaulted
	} else if maximum != nil && paid.Cmp(maximum) == 0 {
		closureReason, targetTerminalState, resolvedCoverageStatus = "aggregate_exhaustion", "exhausted", guarantor.CoverageExhausted
	}
	refSet := guarantor.ClaimTerminalResolutionRefSetV1{SchemaVersion: 1,
		CoverageAgreementBodyDigest: agreementDigest, CoverageObligationID: position.Record.CoverageObligationID,
		AdmissionHighWater: uint64(len(bundles)), Refs: claimRefs}
	refSetDigest, err := guarantor.ClaimTerminalResolutionRefSetDigestV1(refSet)
	if err != nil {
		return GuarantorCloseCoverageResult{}, fmt.Errorf("digest terminal claim resolution set: %w", err)
	}
	cancellationDigest := ""
	if input.CancellationReceipt != nil {
		cancellationDigest, err = guarantor.CoverageCancellationReceiptDigestV1(*input.CancellationReceipt)
		if err != nil {
			return GuarantorCloseCoverageResult{}, err
		}
	}
	contextValue := guarantor.CoverageClosureEvidenceContextV1{SchemaVersion: 1,
		CoverageAgreementBodyDigest: agreementDigest, CoverageObligationID: position.Record.CoverageObligationID,
		ClaimFilingCloseReceiptDigest: filingReceiptDigest, CoverageCancellationReceiptDigest: cancellationDigest,
		CoverageEndCommitmentDigest: endDigest, FilingCloseReason: filingReason, CoverageEndReason: endReason,
		IncidentEligibilityEndsAtUnix: incidentEnd, CoverageEndEvidenceDigest: endCommitment.CoverageEndEvidenceDigest,
		ActivationEvidenceDigest: activationDigest, CoverageClosureReason: closureReason,
		ResolutionTargetTerminalState: targetTerminalState, AdmissionHighWater: uint64(len(bundles)),
		ClaimAdmissionLogRoot: frozen.Record.ClaimAdmissionLogRoot, ClaimResolutionSetDigest: refSetDigest,
		CumulativeApprovedAmount:  commerce.AtomicAmountV1{Asset: asset, AmountAtomic: approved.String()},
		CumulativePaidAmount:      commerce.AtomicAmountV1{Asset: asset, AmountAtomic: paid.String()},
		CumulativeDefaultedAmount: commerce.AtomicAmountV1{Asset: asset, AmountAtomic: defaulted.String()},
		OutstandingApprovedAmount: zero, ReleaseNotBeforeUnix: uint64(now.Unix())}
	contextDigest, err := guarantor.CoverageClosureEvidenceContextDigestV1(contextValue)
	if err != nil {
		return GuarantorCloseCoverageResult{}, err
	}
	closureItems := make([]guarantor.CanonicalGuarantorEvidenceItemV1, 0, len(bundles)+1)
	filingBytes, _ := codec.Marshal(filingReceipt)
	closureItems = append(closureItems, guarantor.CanonicalGuarantorEvidenceItemV1{
		ContentType:            "application/vnd.tos.service.agent-guarantor-claim-filing-close-envelope.v1+cbor",
		EvidenceProfileDigest:  position.Terms.ClaimAdmissionProfile.ProfileDigest,
		EvidenceEnvelopeDigest: filingReceiptDigest, Representation: "content_addressed",
		ImmutableDescriptor: &guarantor.ImmutableEvidenceDescriptorV1{
			ContentType:   "application/vnd.tos.service.agent-guarantor-claim-filing-close-envelope.v1+cbor",
			ContentDigest: filingReceiptDigest, ContentSize: uint64(len(filingBytes)),
			RetrievalPolicyDigest: position.Terms.ClaimAdmissionProfile.ProfileDigest}})
	for _, bundle := range bundles {
		bundleBytes, encodeErr := codec.Marshal(bundle)
		bundleDigest, digestErr := codec.Digest("tos.service.agent-guarantor-claim-terminal-resolution-bundle.v1", bundle)
		if encodeErr != nil {
			return GuarantorCloseCoverageResult{}, fmt.Errorf("encode terminal claim resolution bundle: %w", encodeErr)
		}
		if digestErr != nil {
			return GuarantorCloseCoverageResult{}, fmt.Errorf("digest terminal claim resolution bundle: %w", digestErr)
		}
		closureItems = append(closureItems, guarantor.CanonicalGuarantorEvidenceItemV1{
			ContentType:            "application/vnd.tos.service.agent-guarantor-claim-terminal-resolution-bundle.v1+cbor",
			EvidenceProfileDigest:  position.Terms.ClaimAdmissionProfile.ProfileDigest,
			EvidenceEnvelopeDigest: bundleDigest, Representation: "content_addressed",
			ImmutableDescriptor: &guarantor.ImmutableEvidenceDescriptorV1{
				ContentType:   "application/vnd.tos.service.agent-guarantor-claim-terminal-resolution-bundle.v1+cbor",
				ContentDigest: bundleDigest, ContentSize: uint64(len(bundleBytes)),
				RetrievalPolicyDigest: position.Terms.ClaimAdmissionProfile.ProfileDigest}})
	}
	sort.Slice(closureItems, func(i, j int) bool {
		left, _ := codec.Marshal(closureItems[i])
		right, _ := codec.Marshal(closureItems[j])
		return string(left) < string(right)
	})
	closureEvidenceSet := guarantor.CanonicalGuarantorEvidenceSetV1{SchemaVersion: 1,
		Purpose: "coverage-closure", ContextDigest: contextDigest, Items: closureItems}
	closureEvidenceSetDigest, err := guarantor.CanonicalGuarantorEvidenceSetDigestV1(closureEvidenceSet)
	if err != nil {
		return GuarantorCloseCoverageResult{}, err
	}
	transitionProjection := guarantor.TransitionEvidenceProjectionV1{SchemaVersion: 1, Purpose: "coverage-closure",
		CoverageAgreementBodyDigest: agreementDigest, ObligationID: position.Record.CoverageObligationID,
		TargetState: "release_pending", EvidenceDigests: []guarantor.TransitionEvidenceDigestRefV1{
			{EvidenceRole: "claim-filing-close", DigestKind: "authorized_envelope", ObjectDigest: filingReceiptDigest},
			{EvidenceRole: "claim-resolution-set", DigestKind: "canonical_set", ObjectDigest: refSetDigest},
			{EvidenceRole: "closure-evidence-set", DigestKind: "canonical_set", ObjectDigest: closureEvidenceSetDigest}}}
	sort.Slice(transitionProjection.EvidenceDigests, func(i, j int) bool {
		left, _ := codec.Marshal(transitionProjection.EvidenceDigests[i])
		right, _ := codec.Marshal(transitionProjection.EvidenceDigests[j])
		return string(left) < string(right)
	})
	transitionProjectionDigest, err := guarantor.TransitionEvidenceProjectionDigestV1(transitionProjection)
	if err != nil {
		return GuarantorCloseCoverageResult{}, err
	}
	closureRequest := guarantor.CoverageClosureActionBodyV1{SchemaVersion: 1,
		CoverageAgreementBodyDigest: agreementDigest, CoverageObligationID: position.Record.CoverageObligationID,
		ClaimFilingCloseReceiptDigest: filingReceiptDigest, ExpectedCoverageEndCommitmentDigest: endDigest,
		ClaimResolutionBundles: bundles, ClaimResolutionRefSet: refSet, ClosureReason: closureReason,
		ExpectedCoverageRevision: frozen.Record.CoverageRevision, TargetCoverageRevision: frozen.Record.CoverageRevision + 1,
		TargetCoverageState: "release_pending", ExpectedClaimSetRevision: 0, TargetClaimSetRevision: 1,
		CoverageClosureEvidenceContext: contextValue, TerminalPrerequisiteEvidenceSet: closureEvidenceSet,
		TransitionEvidenceProjection: transitionProjection}
	canonicalClosure, err := codec.Marshal(closureRequest)
	if err != nil {
		return GuarantorCloseCoverageResult{}, fmt.Errorf("encode coverage-closure request: %w", err)
	}
	closureFields := map[string]commerce.SemanticValue{"owner_id": commerce.ID(coordinator.OwnerID), "agent_id": commerce.ID(coordinator.AgentID),
		"agreement_body_digest": commerce.Digest32(agreementDigest), "obligation_id": commerce.ID(position.Record.CoverageObligationID),
		"expected_state_revision": commerce.U64(frozen.Record.CoverageRevision), "target_state": commerce.State("release_pending"),
		"evidence_set_digest": commerce.Digest32(closureEvidenceSetDigest)}
	closureAction, err := commerce.BuildAuthorizedAction(coordinator.OwnerID, coordinator.AgentID, "conditional.obligation.transition",
		closureFields, canonicalClosure, fence, coordinator.PolicyRevision, coordinator.MandateDigest, "", filingReceiptDigest,
		minUint64(position.Terms.TerminalResolutionDeadlineUnix, fence.Body.ExpiresAtUnix))
	if err == nil {
		closureAction, err = coordinator.Authority.SignAction(closureAction, fence)
	}
	if err != nil {
		return GuarantorCloseCoverageResult{}, err
	}
	closureResolution, err := coordinator.Authority.Admit(closureAction, closureFields, canonicalClosure, fence, nil)
	if err != nil || closureResolution.State != commerce.ActionPrepared {
		return GuarantorCloseCoverageResult{}, firstError(err, errors.New("Guarantor coverage-closure action was not prepared"))
	}
	closureActionDigest, _ := commerce.AuthorizedActionDigest(closureAction)
	releasePendingRecord, err := guarantor.TransitionCoverage(frozen.Record, frozen.Record.CoverageRevision,
		guarantor.CoverageReleasePending, closureActionDigest)
	if err != nil {
		return GuarantorCloseCoverageResult{}, err
	}
	releasePending := frozen
	releasePending.Record = releasePendingRecord
	closureResolution, err = coordinator.Authority.Transition(closureAction.StableActionID, closureAction.ExactRequestDigest,
		commerce.ActionTerminal, closureActionDigest, []string{closureActionDigest})
	if err != nil {
		return GuarantorCloseCoverageResult{}, err
	}
	closureStage, err := coordinator.buildGuarantorStage(position.Terms, "coverage_closure",
		"application/vnd.tos.service.agent-guarantor-coverage-closure-action.v1+cbor", canonicalClosure,
		closureAction, closureResolution, fence, now)
	if err != nil {
		return GuarantorCloseCoverageResult{}, err
	}
	terminalBody := guarantor.TerminalClaimSetBodyV1{SchemaVersion: 1, CoverageAgreementBodyDigest: agreementDigest,
		CoverageObligationID:            position.Record.CoverageObligationID,
		ClaimAdmissionProfileDigest:     position.Terms.ClaimAdmissionProfile.ProfileDigest,
		ClaimAdmissionAuthoritySubjects: append([]string(nil), position.Terms.ClaimAdmissionAuthoritySubjects...),
		ClaimAdmissionLogID:             claimLogID, ClaimFilingCloseReceiptDigest: filingReceiptDigest,
		CoverageCancellationReceiptDigest: cancellationDigest, CoverageEndCommitmentDigest: endDigest,
		FilingCloseReason: filingReason, CoverageEndReason: endReason, IncidentEligibilityEndsAtUnix: incidentEnd,
		CoverageEndEvidenceDigest: endCommitment.CoverageEndEvidenceDigest,
		ActivationEvidenceDigest:  activationDigest, CoverageClosureReason: closureReason,
		ResolutionTargetTerminalState: targetTerminalState, FilingCloseCoverageRevision: frozen.Record.CoverageRevision,
		CoverageClosureContextDigest: contextDigest, CoverageClosureEvidenceSetDigest: closureEvidenceSetDigest,
		TransitionEvidenceProjectionDigest: transitionProjectionDigest,
		PriorCoverageRevision:              frozen.Record.CoverageRevision, ReleasePendingCoverageRevision: releasePending.Record.CoverageRevision,
		AdmissionHighWater: uint64(len(bundles)), ClaimAdmissionLogRoot: frozen.Record.ClaimAdmissionLogRoot,
		ClaimResolutions: claimRefs, CumulativeApprovedAmount: commerce.AtomicAmountV1{Asset: asset, AmountAtomic: approved.String()},
		CumulativePaidAmount:      commerce.AtomicAmountV1{Asset: asset, AmountAtomic: paid.String()},
		CumulativeDefaultedAmount: commerce.AtomicAmountV1{Asset: asset, AmountAtomic: defaulted.String()},
		OutstandingApprovedAmount: zero, ClaimSetRevision: 1, FilingClosedAtUnix: uint64(now.Unix()),
		AllClaimsTerminalAtUnix: uint64(now.Unix()), ReleaseNotBeforeUnix: uint64(now.Unix()),
		AuthorizedActionDigest: closureActionDigest, StableActionID: closureAction.StableActionID,
		ExactRequestDigest: closureAction.ExactRequestDigest, WriterGeneration: closureAction.WriterGeneration,
		WriterFenceDigest: closureAction.WriterFenceDigest, CreatedAtUnix: uint64(now.Unix()),
		RequiredExtensions: append([]guarantor.ProfileRefV1(nil), position.Terms.RequiredExtensions...),
		OptionalExtensions: append([]guarantor.ProfileRefV1(nil), position.Terms.OptionalExtensions...)}
	terminalBodyDigest, err := codec.Digest("tos.service.agent-guarantor-terminal-claim-set-body.v1", terminalBody)
	if err != nil {
		return GuarantorCloseCoverageResult{}, fmt.Errorf("digest terminal claim set body: %w", err)
	}
	terminalAuthorization, err := coordinator.Signer.SignObject("terminal-claim-set", terminalBodyDigest,
		"tos.service.agent-guarantor-terminal-claim-set-signature.v1", now)
	if err != nil {
		return GuarantorCloseCoverageResult{}, err
	}
	terminalSet := guarantor.AuthorizedTerminalClaimSetEvidenceV1{Body: terminalBody, StageActionAdmissionEvidence: closureStage,
		AuthorizedClaimFilingCloseReceipt: filingReceipt, ClaimResolutionBundles: bundles,
		ClaimResolutionRefSet: refSet, CoverageClosureEvidenceContext: contextValue,
		CoverageClosureEvidenceSet: closureEvidenceSet, TransitionEvidenceProjection: transitionProjection,
		Authorizations: []guarantor.ProfileQualifiedObjectAuthorizationV1{terminalAuthorization}}
	terminalSetDigest, err := guarantor.TerminalClaimSetDigestV1(terminalSet)
	if err != nil {
		return GuarantorCloseCoverageResult{}, err
	}
	releasePending, err = coordinator.Journal.CommitTerminalClaimSet(agreementDigest, terminalSet)
	if err != nil {
		return GuarantorCloseCoverageResult{}, err
	}
	if coordinator.ClosureFailureInjector != nil {
		if err := coordinator.ClosureFailureInjector.GuarantorClosureCheckpoint("terminal_claim_set_committed"); err != nil {
			return GuarantorCloseCoverageResult{FilingCloseReceipt: filingReceipt, TerminalClaimSet: terminalSet}, err
		}
	}
	disposition, err := guarantor.ComputeExposureDispositionV1(input.Offer.ExposureAdmissionReceipt, terminalBody)
	if err != nil {
		return GuarantorCloseCoverageResult{}, fmt.Errorf("compute terminal exposure disposition: %w", err)
	}
	dispositionDigest, err := guarantor.ExposureDispositionComputationDigestV1(disposition)
	if err != nil {
		return GuarantorCloseCoverageResult{}, fmt.Errorf("digest terminal exposure disposition: %w", err)
	}
	realizedLoss, ok := new(big.Int).SetString(disposition.RealizedLoss.AmountAtomic, 10)
	retainedLiability, retainedOK := new(big.Int).SetString(disposition.RetainedDefaultedLiability.AmountAtomic, 10)
	if !ok || !retainedOK || !realizedLoss.IsUint64() || !retainedLiability.IsUint64() {
		return GuarantorCloseCoverageResult{}, errors.New("terminal exposure disposition exceeds the local portfolio integer range")
	}

	portfolioRevision, _, _ := coordinator.Authority.Snapshot()
	releaseRequest := guarantor.ExposureReleaseActionBodyV1{ReservationID: position.Record.ReservationID, AgreementDigest: agreementDigest,
		TargetPortfolioRevision: portfolioRevision + 1, TerminalEvidenceSetDigest: terminalSetDigest}
	canonicalRelease, err := codec.Marshal(releaseRequest)
	if err != nil {
		return GuarantorCloseCoverageResult{}, fmt.Errorf("encode exposure-release request: %w", err)
	}
	releaseFields := map[string]commerce.SemanticValue{"owner_id": commerce.ID(coordinator.OwnerID), "agent_id": commerce.ID(coordinator.AgentID),
		"reservation_id": commerce.Digest32(position.Record.ReservationID), "target_revision": commerce.U64(portfolioRevision + 1),
		"terminal_evidence_set_digest": commerce.Digest32(terminalSetDigest)}
	releaseAction, err := commerce.BuildAuthorizedAction(coordinator.OwnerID, coordinator.AgentID, "portfolio.release", releaseFields,
		canonicalRelease, fence, coordinator.PolicyRevision, coordinator.MandateDigest, "", terminalSetDigest,
		minUint64(guarantorClosureActionDeadline(frozen), fence.Body.ExpiresAtUnix))
	if err == nil {
		releaseAction, err = coordinator.Authority.SignAction(releaseAction, fence)
	}
	if err != nil {
		return GuarantorCloseCoverageResult{}, err
	}
	releasePlan := GuarantorExposureReleasePlan{Action: releaseAction, WriterFence: fence, Fields: releaseFields,
		CanonicalRequest: canonicalRelease, RequestBody: releaseRequest, Disposition: disposition,
		CreatedAtUnix: uint64(now.Unix())}
	releasePlan, err = coordinator.Journal.PrepareExposureReleasePlan(agreementDigest, releasePlan)
	if err != nil {
		return GuarantorCloseCoverageResult{}, err
	}
	if coordinator.ClosureFailureInjector != nil {
		if err := coordinator.ClosureFailureInjector.GuarantorClosureCheckpoint("exposure_release_plan_prepared"); err != nil {
			return GuarantorCloseCoverageResult{FilingCloseReceipt: filingReceipt, TerminalClaimSet: terminalSet}, err
		}
	}
	releaseAction, releaseFields, canonicalRelease = releasePlan.Action, releasePlan.Fields, releasePlan.CanonicalRequest
	releaseResolution, err := coordinator.Authority.ReleaseGuarantorReservation(releaseAction, releaseFields, canonicalRelease, fence,
		realizedLoss.Uint64(), retainedLiability.Uint64())
	if err != nil || releaseResolution.State != commerce.ActionTerminal {
		return GuarantorCloseCoverageResult{}, firstError(err, errors.New("Guarantor exposure release did not become terminal"))
	}
	releaseStage, err := coordinator.buildGuarantorStage(position.Terms, "post_acceptance_exposure_release",
		"application/vnd.tos.service.agent-guarantor-exposure-release-action.v1+cbor", canonicalRelease,
		releaseAction, releaseResolution, fence, now)
	if err != nil {
		return GuarantorCloseCoverageResult{}, err
	}
	exposureReceiptDigest, err := guarantor.ExposureAdmissionReceiptDigestV1(input.Offer.ExposureAdmissionReceipt)
	if err != nil {
		return GuarantorCloseCoverageResult{}, fmt.Errorf("digest exposure admission receipt: %w", err)
	}
	releaseBody := guarantor.ExposureReleaseReceiptBodyV1{SchemaVersion: 1, AuthorityID: releaseAction.AuthorityID,
		GuarantorAgentID: coordinator.AgentID, CoverageAgreementBodyDigest: agreementDigest,
		CoverageObligationID: position.Record.CoverageObligationID, ReservationID: position.Record.ReservationID,
		ExposureAdmissionReceiptDigest: exposureReceiptDigest, TerminalClaimSetEvidenceDigest: terminalSetDigest,
		ExposureDispositionComputationDigest: dispositionDigest,
		AuthorizedActionDigest:               mustActionDigest(releaseAction), StableActionID: releaseAction.StableActionID,
		ExactRequestDigest: releaseAction.ExactRequestDigest, WriterGeneration: releaseAction.WriterGeneration,
		WriterFenceDigest: releaseAction.WriterFenceDigest, BaseReleaseStateRevision: portfolioRevision,
		ReleasedReleaseStateRevision: portfolioRevision + 1, ReleasedExposure: position.Terms.MaximumAggregatePayout,
		RemainingReservedExposure: zero, PortfolioDisposition: disposition.PortfolioDisposition,
		ReturnedToAvailableExposure: disposition.ReturnedToAvailableExposure, RealizedLoss: disposition.RealizedLoss,
		RetainedDefaultedLiability: disposition.RetainedDefaultedLiability,
		State:                      "released", ReleasedAtUnix: uint64(now.Unix())}
	releaseBodyDigest, err := codec.Digest("tos.service.agent-guarantor-exposure-release-receipt-body.v1", releaseBody)
	if err != nil {
		return GuarantorCloseCoverageResult{}, fmt.Errorf("digest exposure release receipt body: %w", err)
	}
	releaseAuthorization, err := coordinator.Signer.SignObject("exposure-release-receipt", releaseBodyDigest,
		"tos.service.agent-guarantor-exposure-release-receipt-signature.v1", now)
	if err != nil {
		return GuarantorCloseCoverageResult{}, err
	}
	releaseReceipt := guarantor.AuthorizedExposureReleaseReceiptV1{Body: releaseBody, StageActionAdmissionEvidence: releaseStage,
		AuthorizedExposureAdmissionReceipt: input.Offer.ExposureAdmissionReceipt, AuthorizedTerminalClaimSetEvidence: terminalSet,
		ExposureDispositionComputation: disposition,
		Authorizations:                 []guarantor.ProfileQualifiedObjectAuthorizationV1{releaseAuthorization}}
	releaseReceiptDigest, err := guarantor.ExposureReleaseReceiptDigestV1(releaseReceipt)
	if err != nil {
		return GuarantorCloseCoverageResult{}, err
	}
	if _, err := coordinator.Journal.CommitExposureReleaseReceipt(agreementDigest, releaseReceipt); err != nil {
		return GuarantorCloseCoverageResult{}, err
	}

	resolutionRequest := guarantor.CoverageResolutionActionBodyV1{SchemaVersion: 1, ExposureReleaseReceiptDigest: releaseReceiptDigest,
		ExpectedRevision: releasePending.Record.CoverageRevision, TargetRevision: releasePending.Record.CoverageRevision + 1}
	canonicalResolution, err := codec.Marshal(resolutionRequest)
	if err != nil {
		return GuarantorCloseCoverageResult{}, fmt.Errorf("encode coverage-resolution request: %w", err)
	}
	resolutionFields := map[string]commerce.SemanticValue{"owner_id": commerce.ID(coordinator.OwnerID), "agent_id": commerce.ID(coordinator.AgentID),
		"agreement_body_digest": commerce.Digest32(agreementDigest), "obligation_id": commerce.ID(position.Record.CoverageObligationID),
		"expected_state_revision": commerce.U64(releasePending.Record.CoverageRevision), "target_state": commerce.State(targetTerminalState),
		"evidence_set_digest": commerce.Digest32(releaseReceiptDigest)}
	resolutionAction, err := commerce.BuildAuthorizedAction(coordinator.OwnerID, coordinator.AgentID, "conditional.obligation.transition",
		resolutionFields, canonicalResolution, fence, coordinator.PolicyRevision, coordinator.MandateDigest, "", releaseReceiptDigest,
		minUint64(guarantorClosureActionDeadline(frozen), fence.Body.ExpiresAtUnix))
	if err == nil {
		resolutionAction, err = coordinator.Authority.SignAction(resolutionAction, fence)
	}
	if err != nil {
		return GuarantorCloseCoverageResult{}, err
	}
	resolutionPlan := GuarantorCoverageResolutionPlan{Action: resolutionAction, WriterFence: fence, Fields: resolutionFields,
		CanonicalRequest: canonicalResolution, RequestBody: resolutionRequest, TargetStatus: resolvedCoverageStatus,
		TargetState: targetTerminalState, CreatedAtUnix: uint64(now.Unix())}
	resolutionPlan, err = coordinator.Journal.PrepareCoverageResolutionPlan(agreementDigest, resolutionPlan)
	if err != nil {
		return GuarantorCloseCoverageResult{}, err
	}
	if coordinator.ClosureFailureInjector != nil {
		if err := coordinator.ClosureFailureInjector.GuarantorClosureCheckpoint("coverage_resolution_plan_prepared"); err != nil {
			return GuarantorCloseCoverageResult{FilingCloseReceipt: filingReceipt, TerminalClaimSet: terminalSet,
				ExposureRelease: releaseReceipt}, err
		}
	}
	resolutionAction, resolutionFields, canonicalResolution = resolutionPlan.Action, resolutionPlan.Fields, resolutionPlan.CanonicalRequest
	resolutionResult, err := coordinator.Authority.Admit(resolutionAction, resolutionFields, canonicalResolution, fence, nil)
	if err != nil || resolutionResult.State != commerce.ActionPrepared {
		return GuarantorCloseCoverageResult{}, firstError(err, errors.New("Guarantor resolution was not prepared"))
	}
	resolvedRecord, err := guarantor.TransitionCoverage(releasePending.Record, releasePending.Record.CoverageRevision,
		resolvedCoverageStatus, releaseReceiptDigest)
	if err != nil {
		return GuarantorCloseCoverageResult{}, err
	}
	resolved := releasePending
	resolved.Record = resolvedRecord
	resolutionResult, err = coordinator.Authority.Transition(resolutionAction.StableActionID, resolutionAction.ExactRequestDigest,
		commerce.ActionTerminal, releaseReceiptDigest, []string{releaseReceiptDigest})
	if err != nil {
		return GuarantorCloseCoverageResult{}, err
	}
	resolutionStage, err := coordinator.buildGuarantorStage(position.Terms, "coverage_resolution",
		"application/vnd.tos.service.agent-guarantor-coverage-resolution-action.v1+cbor", canonicalResolution,
		resolutionAction, resolutionResult, fence, now)
	if err != nil {
		return GuarantorCloseCoverageResult{}, err
	}
	resolutionBody := guarantor.CoverageResolutionBodyV1{SchemaVersion: 1, AuthorityID: resolutionAction.AuthorityID,
		CoverageAgreementBodyDigest: agreementDigest, CoverageObligationID: position.Record.CoverageObligationID,
		CoverageEndCommitmentDigest: endDigest, ActivationEvidenceDigest: activationDigest,
		TerminalClaimSetEvidenceDigest: terminalSetDigest, ExposureReleaseReceiptDigest: releaseReceiptDigest,
		PriorCoverageRevision: releasePending.Record.CoverageRevision, ResolvedCoverageRevision: resolved.Record.CoverageRevision,
		TerminalState: targetTerminalState, AuthorizedActionDigest: mustActionDigest(resolutionAction), StableActionID: resolutionAction.StableActionID,
		ExactRequestDigest: resolutionAction.ExactRequestDigest, WriterGeneration: resolutionAction.WriterGeneration,
		WriterFenceDigest: resolutionAction.WriterFenceDigest, ResolvedAtUnix: uint64(now.Unix())}
	resolutionBodyDigest, err := codec.Digest("tos.service.agent-guarantor-resolution-body.v1", resolutionBody)
	if err != nil {
		return GuarantorCloseCoverageResult{}, fmt.Errorf("digest coverage resolution body: %w", err)
	}
	resolutionAuthorization, err := coordinator.Signer.SignObject("coverage-resolution", resolutionBodyDigest,
		"tos.service.agent-guarantor-resolution-signature.v1", now)
	if err != nil {
		return GuarantorCloseCoverageResult{}, err
	}
	coverageResolution := guarantor.AuthorizedCoverageResolutionV1{Body: resolutionBody,
		StageActionAdmissionEvidence: resolutionStage, AuthorizedExposureReleaseReceipt: releaseReceipt,
		Authorizations: []guarantor.ProfileQualifiedObjectAuthorizationV1{resolutionAuthorization}}
	if _, err := guarantor.CoverageResolutionDigestV1(coverageResolution); err != nil {
		return GuarantorCloseCoverageResult{}, fmt.Errorf("digest complete coverage resolution: %w", err)
	}
	if err := guarantor.VerifyCoverageResolutionV1(coverageResolution, input.Offer, coordinator.AgreementVerifier,
		coordinator.Resolver, coordinator.Authority, coordinator.PaymentVerifier, now); err != nil {
		return GuarantorCloseCoverageResult{}, fmt.Errorf("verify complete coverage resolution: %w", err)
	}
	if _, err := coordinator.Journal.CommitCoverageResolution(agreementDigest, coverageResolution); err != nil {
		return GuarantorCloseCoverageResult{}, err
	}
	return GuarantorCloseCoverageResult{FilingCloseReceipt: filingReceipt, TerminalClaimSet: terminalSet,
		ExposureRelease: releaseReceipt, CoverageResolution: coverageResolution}, nil
}

func (coordinator *GuarantorProviderCoordinator) coveragePosition(agreementDigest string) (GuarantorCoveragePosition, error) {
	_, _, coverages := coordinator.Journal.Snapshot()
	for _, position := range coverages {
		if position.Record.CoverageAgreementBodyDigest == agreementDigest {
			return position, nil
		}
	}
	return GuarantorCoveragePosition{}, errors.New("Guarantor coverage does not exist")
}

func (coordinator *GuarantorProviderCoordinator) buildGuarantorStage(terms guarantor.CoverageTermsV1, stage, contentType string, request []byte,
	action commerce.AuthorizedAction, resolution commerce.ActionResolution, fence commerce.WriterFence,
	at time.Time) (guarantor.PortableStageActionAdmissionEvidenceV1, error) {
	bound, err := guarantor.FindStageActionAuthorityV1(terms.StageActionAuthorityBinding, stage)
	if err != nil && (stage == "coverage_acceptance" || stage == "collateral_transition") {
		bound, err = guarantor.AuxiliaryStageActionAuthorityV1(terms.StageActionAuthorityBinding, stage)
	}
	if err != nil {
		return guarantor.PortableStageActionAdmissionEvidenceV1{}, err
	}
	operation, err := guarantor.StageOperationBindingForAuthorityV1(bound)
	if err != nil {
		return guarantor.PortableStageActionAdmissionEvidenceV1{}, err
	}
	if action.OwnerID != bound.ActionOwnerID || action.AgentID != bound.ActionAgentID || action.AuthorityID != bound.ActionAuthorityID ||
		action.ActionKind != operation.ActionKind {
		return guarantor.PortableStageActionAdmissionEvidenceV1{}, errors.New("Guarantor action differs from the Agreement-bound stage authority")
	}
	if uint64(len(request)) > operation.MaximumRequestBytes {
		return guarantor.PortableStageActionAdmissionEvidenceV1{}, fmt.Errorf("Guarantor %s request has %d bytes, exceeds Agreement bound %d",
			stage, len(request), operation.MaximumRequestBytes)
	}
	actionDigest, err := commerce.AuthorizedActionDigest(action)
	if err != nil {
		return guarantor.PortableStageActionAdmissionEvidenceV1{}, err
	}
	body := guarantor.PortableStageActionAdmissionBodyV1{SchemaVersion: 1, Stage: stage, OperationID: operation.OperationID,
		OperationBindingDigest: bound.OperationBindingDigest, AdmittedAtUnix: uint64(at.Unix()), CanonicalRequestDigest: action.ExactRequestDigest,
		AuthorizedActionDigest: actionDigest, WriterFenceDigest: action.WriterFenceDigest, AdmissionState: "accepted",
		AdmissionStateRevision: resolution.StateRevision}
	bodyDigest, _ := codec.Digest("tos.service.agent-guarantor-stage-action-admission.v1", body)
	if coordinator.ActionAuthoritySigner == nil {
		return guarantor.PortableStageActionAdmissionEvidenceV1{}, errors.New("Agreement-bound Guarantor action authority signer is unavailable")
	}
	authorization, err := coordinator.ActionAuthoritySigner.SignObject("stage-action-admission-evidence", bodyDigest,
		"tos.service.agent-guarantor-stage-action-admission-signature.v1", at)
	if err != nil {
		return guarantor.PortableStageActionAdmissionEvidenceV1{}, err
	}
	return guarantor.PortableStageActionAdmissionEvidenceV1{Body: body, CanonicalRequestContentType: contentType,
		CanonicalRequest: append([]byte(nil), request...), AuthorizedAction: action, WriterFence: fence,
		ActionResolution: resolution, ActionAdmissionAuthorization: authorization}, nil
}

func terminalClaimBundles(coordinator *GuarantorProviderCoordinator, position GuarantorCoveragePosition,
	now time.Time) ([]guarantor.ClaimTerminalResolutionBundleV1, *big.Int, *big.Int, *big.Int, error) {
	if coordinator == nil || coordinator.ActionAuthoritySigner == nil || now.IsZero() {
		return nil, nil, nil, nil, errors.New("Guarantor terminal proof signer is unavailable")
	}
	type sequenced struct {
		sequence uint64
		claimID  string
	}
	ordered := make([]sequenced, 0, len(position.ClaimAdmissionSequence))
	for claimID, sequence := range position.ClaimAdmissionSequence {
		ordered = append(ordered, sequenced{sequence, claimID})
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].sequence < ordered[j].sequence })
	bundles := make([]guarantor.ClaimTerminalResolutionBundleV1, 0, len(ordered))
	approved, paid, defaulted := new(big.Int), new(big.Int), new(big.Int)
	for index, item := range ordered {
		if item.sequence != uint64(index+1) {
			return nil, nil, nil, nil, errors.New("Guarantor claim admission sequence has a gap")
		}
		decision, decisionFound := position.Decisions[item.claimID]
		record, recordFound := position.Claims[item.claimID]
		payouts, payoutFound := position.MaterializedPayouts[item.claimID]
		application, applicationFound := position.DecisionApplicationReceipts[item.claimID]
		decisionAdmission, decisionAdmissionFound := position.DecisionAdmissionReceipts[item.claimID]
		transitionReceipt, transitionFound := position.ClaimStateTransitionReceipts[item.claimID]
		finalRevision := position.ClaimRevisionSequence[item.claimID]
		initialAdmission, initialFound := position.ClaimAdmissionReceipts[guarantorClaimRevisionKey(item.claimID, 1)]
		finalAdmission, finalFound := position.ClaimAdmissionReceipts[guarantorClaimRevisionKey(item.claimID, finalRevision)]
		if !decisionFound || !recordFound || !payoutFound || !applicationFound || !decisionAdmissionFound ||
			!transitionFound || !initialFound || !finalFound || finalRevision == 0 {
			return nil, nil, nil, nil, errors.New("Guarantor terminal claim bundle is incomplete")
		}
		if record.ClaimStatus != guarantor.ClaimFinalApproved && record.ClaimStatus != guarantor.ClaimFinalPartiallyApproved && record.ClaimStatus != guarantor.ClaimFinalDenied {
			return nil, nil, nil, nil, errors.New("Guarantor claim is nonterminal")
		}
		executions := make([]guarantor.AuthorizedGuarantorPayoutExecutionEvidenceV1, 0, len(payouts.Obligations))
		settlementItems := make([]guarantor.CanonicalGuarantorEvidenceItemV1, 0, len(payouts.Obligations))
		for _, obligation := range payouts.Obligations {
			execution, found := position.PayoutExecutionEvidence[obligation.ObligationInstanceID]
			if !found {
				return nil, nil, nil, nil, errors.New("Guarantor payout lacks terminal evidence")
			}
			executionDigest, digestErr := guarantor.GuarantorPayoutExecutionEvidenceDigestV1(execution)
			executionBytes, encodeErr := codec.Marshal(execution)
			if digestErr != nil || encodeErr != nil {
				return nil, nil, nil, nil, errors.New("Guarantor payout execution evidence cannot be encoded")
			}
			executions = append(executions, execution)
			settlementItems = append(settlementItems, guarantor.CanonicalGuarantorEvidenceItemV1{
				ContentType:            "application/vnd.tos.service.agent-guarantor-payout-execution-evidence.v1+cbor",
				EvidenceProfileDigest:  position.Terms.SelectedPayoutAdapterProfile.ProfileDigest,
				EvidenceEnvelopeDigest: executionDigest, Representation: "inline", CanonicalEnvelopeBytes: executionBytes})
		}
		sort.Slice(settlementItems, func(i, j int) bool {
			left, _ := codec.Marshal(settlementItems[i])
			right, _ := codec.Marshal(settlementItems[j])
			return string(left) < string(right)
		})
		claim := finalAdmission.AuthorizedClaimIngressReceipt.AuthorizedClaim
		claimDigest, _ := guarantor.ClaimEnvelopeDigest(claim)
		decisionDigest, _ := guarantor.ClaimDecisionDigestV1(decision)
		payoutDigest, _ := codec.Digest(guarantor.PayoutSetDomain, payouts)
		claimPaid, claimDefaulted := new(big.Int), new(big.Int)
		amount, _ := new(big.Int).SetString(decision.Body.ApprovedAmount.AmountAtomic, 10)
		approved.Add(approved, amount)
		for paymentIndex, execution := range executions {
			terminalAmount, ok := new(big.Int).SetString(payouts.Obligations[paymentIndex].Amount.AmountAtomic, 10)
			if !ok {
				return nil, nil, nil, nil, errors.New("Guarantor terminal payout amount is invalid")
			}
			if execution.AgreementPaymentEvidence.ResolvedState == "finalized" {
				paid.Add(paid, terminalAmount)
				claimPaid.Add(claimPaid, terminalAmount)
			} else if execution.AgreementPaymentEvidence.ResolvedState == "defaulted" {
				defaulted.Add(defaulted, terminalAmount)
				claimDefaulted.Add(claimDefaulted, terminalAmount)
			} else {
				return nil, nil, nil, nil, errors.New("Guarantor payout evidence is nonterminal")
			}
		}
		disposition := "resolved"
		if decision.Body.Result == guarantor.DecisionDenied {
			disposition = "not_applicable"
			markerValue := guarantor.GuarantorNoPayoutMarkerV1{SchemaVersion: 1,
				CoverageAgreementBodyDigest: position.Record.CoverageAgreementBodyDigest, ClaimID: item.claimID,
				AuthorizedClaimDecisionDigest: decisionDigest, MaterializedPayoutObligationSetDigest: payoutDigest}
			marker, _ := codec.Marshal(markerValue)
			markerDigest, _ := codec.Digest("tos.service.agent-guarantor-no-payout-marker.v1", markerValue)
			settlementItems = []guarantor.CanonicalGuarantorEvidenceItemV1{{ContentType: "application/vnd.tos.service.agent-guarantor-no-payout.v1+cbor",
				EvidenceProfileDigest:  position.Terms.SelectedPayoutAdapterProfile.ProfileDigest,
				EvidenceEnvelopeDigest: markerDigest, Representation: "inline", CanonicalEnvelopeBytes: marker}}
		} else if claimDefaulted.Sign() > 0 {
			disposition = "defaulted"
		}
		terminalSettlementSet := guarantor.CanonicalGuarantorEvidenceSetV1{SchemaVersion: 1,
			Purpose: "terminal-payout", ContextDigest: decisionDigest, Items: settlementItems}
		terminalPayoutSet := guarantor.TerminalPayoutEvidenceSetV1{SchemaVersion: 1,
			CoverageAgreementBodyDigest: position.Record.CoverageAgreementBodyDigest, ClaimID: item.claimID,
			AuthorizedClaimDecisionDigest: decisionDigest, MaterializedPayoutObligationSetDigest: payoutDigest,
			Disposition: disposition, ApprovedAmount: decision.Body.ApprovedAmount,
			PaidAmount:              commerce.AtomicAmountV1{Asset: position.Terms.CoverageAsset, AmountAtomic: claimPaid.String()},
			DefaultedAmount:         commerce.AtomicAmountV1{Asset: position.Terms.CoverageAsset, AmountAtomic: claimDefaulted.String()},
			OutstandingAmount:       commerce.AtomicAmountV1{Asset: position.Terms.CoverageAsset, AmountAtomic: "0"},
			PayoutExecutionEvidence: executions, TerminalSettlementEvidenceSet: terminalSettlementSet}
		paymentDigest, digestErr := guarantor.TerminalPayoutEvidenceSetDigestV1(terminalPayoutSet)
		if digestErr != nil {
			return nil, nil, nil, nil, digestErr
		}
		initialDigest, _ := guarantor.ClaimAdmissionReceiptDigestV1(initialAdmission)
		finalAdmissionDigest, _ := guarantor.ClaimAdmissionReceiptDigestV1(finalAdmission)
		decisionAdmissionDigest, _ := guarantor.ClaimDecisionAdmissionReceiptDigestV1(decisionAdmission)
		applicationDigest, _ := guarantor.ClaimDecisionApplicationReceiptDigestV1(application)
		transitionDigest, _ := guarantor.ClaimStateTransitionReceiptDigestV1(transitionReceipt)
		ref := guarantor.ClaimTerminalResolutionRefV1{ClaimAdmissionSequence: item.sequence, ClaimID: item.claimID,
			InitialClaimAdmissionReceiptDigest: initialDigest, FinalClaimRevision: finalRevision,
			FinalClaimRevisionAdmissionReceiptDigest: finalAdmissionDigest,
			ClaimRevisionAdmissionHighWater:          finalAdmission.Body.ClaimRevisionAdmissionSequence,
			ClaimRevisionAdmissionLogRoot:            finalAdmission.Body.AdmittedClaimRevisionLogRoot,
			ClaimRevisionIngressHighWater:            finalAdmission.AuthorizedClaimIngressReceipt.Body.ClaimIngressSequence,
			ClaimRevisionIngressLogRoot:              finalAdmission.AuthorizedClaimIngressReceipt.Body.AdmittedClaimIngressLogRoot,
			TerminalAuthorizedClaimEnvelopeDigest:    claimDigest, TerminalDecisionDigest: decisionDigest,
			TerminalDecisionAdmissionReceiptDigest: decisionAdmissionDigest,
			DecisionApplicationReceiptDigest:       applicationDigest, TerminalClaimState: record.ClaimStatus,
			ClaimStateRevision: record.ClaimStateRevision, TerminalClaimStateTransitionReceiptDigest: transitionDigest,
			MaterializedPayoutObligationSetDigest: payoutDigest, TerminalPayoutEvidenceSetDigest: paymentDigest}
		buildAdmissionProof := func(receipt guarantor.AuthorizedClaimAdmissionReceiptV1) (guarantor.ClaimAdmissionReceiptProofV1, error) {
			seal, descriptor, sealErr := guarantor.NewClaimAdmissionReceiptSealBodyV1(receipt, position.Terms, now)
			if sealErr != nil {
				return guarantor.ClaimAdmissionReceiptProofV1{}, sealErr
			}
			sealDigest, digestErr := codec.Digest(guarantor.ClaimAdmissionReceiptSealDomainV1, seal)
			if digestErr != nil {
				return guarantor.ClaimAdmissionReceiptProofV1{}, digestErr
			}
			stageName := "claim_revision_admission"
			if receipt.Body.AdmissionKind == "initial" {
				stageName = "initial_claim_admission"
			}
			bound, boundErr := guarantor.FindStageActionAuthorityV1(position.Terms.StageActionAuthorityBinding, stageName)
			if boundErr != nil || bound.ActionAuthorityID == "" {
				return guarantor.ClaimAdmissionReceiptProofV1{}, errors.New("Guarantor claim-admission seal authority is unavailable")
			}
			sealAuthorization, signErr := coordinator.ActionAuthoritySigner.SignObject("claim-admission-receipt-seal", sealDigest,
				"tos.service.agent-guarantor-claim-admission-receipt-seal-signature.v1", now)
			if signErr != nil || sealAuthorization.AuthoritySubject != bound.ActionAuthorityID {
				return guarantor.ClaimAdmissionReceiptProofV1{}, errors.New("Guarantor claim-admission seal authority differs from the bound stage authority")
			}
			return guarantor.BuildClaimAdmissionReceiptProofV1(receipt, position.Terms, descriptor, seal, sealAuthorization)
		}
		initialProof, proofErr := buildAdmissionProof(initialAdmission)
		if proofErr != nil {
			return nil, nil, nil, nil, proofErr
		}
		revisionProofs := make([]guarantor.ClaimAdmissionReceiptProofV1, 0, finalRevision-1)
		for revision := uint64(2); revision <= finalRevision; revision++ {
			receipt, found := position.ClaimAdmissionReceipts[guarantorClaimRevisionKey(item.claimID, revision)]
			if !found {
				return nil, nil, nil, nil, errors.New("Guarantor claim revision receipt history is incomplete")
			}
			proof, proofErr := buildAdmissionProof(receipt)
			if proofErr != nil {
				return nil, nil, nil, nil, proofErr
			}
			revisionProofs = append(revisionProofs, proof)
		}
		applicationSeal, applicationDescriptor, proofErr := guarantor.NewDecisionApplicationReceiptSealBodyV1(application,
			position.Terms, now)
		if proofErr != nil {
			return nil, nil, nil, nil, proofErr
		}
		applicationSealDigest, _ := codec.Digest(guarantor.DecisionApplicationReceiptSealDomainV1, applicationSeal)
		applicationSealAuthorization, proofErr := coordinator.ActionAuthoritySigner.SignObject("decision-application-receipt-seal",
			applicationSealDigest, "tos.service.agent-guarantor-decision-application-receipt-seal-signature.v1", now)
		if proofErr != nil {
			return nil, nil, nil, nil, proofErr
		}
		applicationProof, proofErr := guarantor.BuildDecisionApplicationReceiptProofV1(application, position.Terms,
			applicationDescriptor, applicationSeal, applicationSealAuthorization)
		if proofErr != nil {
			return nil, nil, nil, nil, proofErr
		}
		bundles = append(bundles, guarantor.ClaimTerminalResolutionBundleV1{ResolutionRef: ref,
			InitialClaimAdmissionReceiptProof: initialProof, RevisionAdmissionReceiptProofs: revisionProofs,
			TerminalAuthorizedDecision: decision, DecisionAdmissionReceiptProofs: []guarantor.ClaimDecisionAdmissionReceiptProofV1{transitionReceipt.DecisionAdmissionProof},
			DecisionApplicationReceiptProof: applicationProof, ClaimStateTransitionReceipts: []guarantor.AuthorizedClaimStateTransitionReceiptV1{transitionReceipt},
			MaterializedPayoutObligationSet: payouts, TerminalPayoutEvidenceSet: terminalPayoutSet})
	}
	if new(big.Int).Add(new(big.Int).Set(paid), defaulted).Cmp(approved) != 0 {
		return nil, nil, nil, nil, errors.New("Guarantor closure has outstanding approved value")
	}
	return bundles, approved, paid, defaulted, nil
}

func mustActionDigest(action commerce.AuthorizedAction) string {
	digest, _ := commerce.AuthorizedActionDigest(action)
	return digest
}
