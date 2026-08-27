package earning

import (
	"context"
	"errors"
	"fmt"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	guarantor "github.com/tosnetwork/tos-service-protocol/pkg/agentguarantor"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type GuarantorAdmitDecisionInput struct {
	AgreementDigest string
	Decision        guarantor.AuthorizedClaimDecisionV1
}

type GuarantorDecisionAdmissionResult struct {
	Receipt    guarantor.AuthorizedClaimDecisionAdmissionReceiptV1
	Resolution commerce.ActionResolution
}

type GuarantorTransitionClaimInput struct {
	AgreementDigest          string
	DecisionAdmissionReceipt guarantor.AuthorizedClaimDecisionAdmissionReceiptV1
	TransitionKind           string
	TransitionEvidenceSet    guarantor.CanonicalGuarantorEvidenceSetV1
}

type GuarantorClaimTransitionResult struct {
	Receipt    guarantor.AuthorizedClaimStateTransitionReceiptV1
	Resolution commerce.ActionResolution
}

func currentCoverageEndCommitment(position GuarantorCoveragePosition) (guarantor.CoverageEndCommitmentV1, error) {
	if position.CancellationReceipt != nil {
		body := position.CancellationReceipt.Body
		return guarantor.CoverageEndCommitmentV1{SchemaVersion: 1,
			CoverageAgreementBodyDigest: body.CoverageAgreementBodyDigest, CoverageObligationID: body.CoverageObligationID,
			CoverageStateDomainDigest: body.CoverageStateDomainDigest, EndBranch: "accepted_cancellation",
			IncidentEligibilityEndsAtUnix: body.IncidentEligibilityEndsAtUnix,
			CoverageEndEvidenceDigest:     mustGuarantorDigest(guarantor.CancellationReceiptDomain, *position.CancellationReceipt)}, nil
	}
	if position.ActivationEvidence != nil {
		return position.ActivationEvidence.CoverageEndCommitment, nil
	}
	if position.NonActivationEvidence != nil {
		return guarantor.CoverageEndCommitmentV1{}, errors.New("never-activated coverage cannot admit a claim decision")
	}
	return guarantor.CoverageEndCommitmentV1{}, errors.New("Guarantor coverage has no portable end commitment")
}

func mustGuarantorDigest(domain string, value any) string {
	digest, _ := codec.Digest(domain, value)
	return digest
}

func (coordinator *GuarantorProviderCoordinator) AdmitClaimDecision(ctx context.Context,
	input GuarantorAdmitDecisionInput, fence commerce.WriterFence) (GuarantorDecisionAdmissionResult, error) {
	if err := ctx.Err(); err != nil {
		return GuarantorDecisionAdmissionResult{}, err
	}
	if coordinator == nil || coordinator.Authority == nil || coordinator.Journal == nil || coordinator.Signer == nil ||
		coordinator.ActionAuthoritySigner == nil ||
		coordinator.Resolver == nil || coordinator.AgreementVerifier == nil || coordinator.Eligibility == nil ||
		!canonicalSHA256(input.AgreementDigest) {
		return GuarantorDecisionAdmissionResult{}, errors.New("Guarantor decision admission coordinator is incomplete")
	}
	now := coordinator.Authority.AuthorityNow().UTC()
	if now.IsZero() || coordinator.Authority.ConfirmCurrentWriterFence(fence, now) != nil {
		return GuarantorDecisionAdmissionResult{}, errors.New("Guarantor decision admission writer is stale")
	}
	position, err := coordinator.coveragePosition(input.AgreementDigest)
	if err != nil {
		return GuarantorDecisionAdmissionResult{}, err
	}
	claim, found := position.ClaimEnvelopes[input.Decision.Body.ClaimID]
	record, recordFound := position.Claims[input.Decision.Body.ClaimID]
	claimAdmission, admissionFound := position.ClaimAdmissionReceipts[guarantorClaimRevisionKey(
		input.Decision.Body.ClaimID, input.Decision.Body.ExpectedClaimRevision)]
	isInitial := input.Decision.Body.DecisionPath == "initial" && record.ClaimStatus == guarantor.ClaimAdmitted && record.DecisionSequence == 0
	isSuccessor := input.Decision.Body.DecisionPath == "successor" && record.ClaimStatus == guarantor.ClaimReviewing &&
		record.DecisionSequence > 0 && input.Decision.Body.DecisionSequence == record.DecisionSequence+1
	var predecessorTransition *guarantor.AuthorizedClaimStateTransitionReceiptV1
	var priorToken *guarantor.DecisionApplicationTokenV1
	if isSuccessor {
		transition, transitionFound := position.ClaimStateTransitionReceipts[record.ClaimID]
		priorDecision, decisionFound := position.Decisions[record.ClaimID]
		priorDecisionDigest, _ := guarantor.ClaimDecisionDigestV1(priorDecision)
		if !transitionFound || !decisionFound || transition.Body.ResultingClaimState != "reviewing" ||
			transition.Body.ResultingClaimStateRevision != record.ClaimStateRevision ||
			input.Decision.Body.PredecessorAuthorizedClaimDecisionDigest != priorDecisionDigest ||
			uint64(now.Unix()) > transition.Body.SuccessorDecisionDueAtUnix {
			return GuarantorDecisionAdmissionResult{}, errors.New("Guarantor successor decision has no current reviewing head")
		}
		predecessorTransition = &transition
		if transition.Body.TransitionKind == "challenge_admission" {
			token, tokenFound := position.DecisionApplicationTokens[record.ClaimID]
			if !tokenFound || token.State != "pending" {
				return GuarantorDecisionAdmissionResult{}, errors.New("Guarantor challenged successor has no pending application token")
			}
			priorToken = &token
		}
	}
	if !found || !recordFound || !admissionFound || (!isInitial && !isSuccessor) {
		return GuarantorDecisionAdmissionResult{}, errors.New("Guarantor decision admission has no eligible current claim head")
	}
	if err := guarantor.ValidateClaimDecision(input.Decision, claim, position.Terms, coordinator.Resolver,
		position.Terms.DecisionAuthoritySubjects, now); err != nil {
		return GuarantorDecisionAdmissionResult{}, err
	}
	decisionDigest, err := guarantor.ClaimDecisionDigestV1(input.Decision)
	if err != nil {
		return GuarantorDecisionAdmissionResult{}, err
	}
	claimAdmissionDigest, err := guarantor.ClaimAdmissionReceiptDigestV1(claimAdmission)
	if err != nil {
		return GuarantorDecisionAdmissionResult{}, err
	}
	cut, err := coordinator.Journal.ClaimRevisionAdmissionCut(input.AgreementDigest, input.Decision.Body.ClaimID,
		uint64(now.Unix()))
	if err != nil {
		return GuarantorDecisionAdmissionResult{}, err
	}
	epoch := guarantor.ClaimRevisionEpochExpectationV1{SchemaVersion: 1,
		CoverageAgreementBodyDigest: input.AgreementDigest, CoverageObligationID: position.Record.CoverageObligationID,
		ClaimID: input.Decision.Body.ClaimID, RevisionEpoch: input.Decision.Body.ExpectedClaimRevision,
		RevisionIngressLogID: cut.ClaimIngressLogID, ExpectedEpochState: "open",
		ExpectedEpochStateRevision: cut.PriorEpochStateRevision, ExpectedClaimRevision: input.Decision.Body.ExpectedClaimRevision}
	variant := guarantor.AuthorizedDecisionAdmissionVariantV1{AuthorizedClaimDecisionDigest: decisionDigest,
		AuthorizedClaimAdmissionReceiptDigest: claimAdmissionDigest, ClaimRevisionEpochExpectation: epoch,
		ExpectedClaimStateRevision:    record.ClaimStateRevision,
		ExpectedChallengeRoundsUsed:   position.ChallengeRoundsUsed[record.ClaimID],
		ExpectedNonterminalRoundsUsed: position.NonterminalRoundsUsed[record.ClaimID]}
	if predecessorTransition != nil {
		variant.PredecessorClaimStateTransitionReceiptDigest, _ = guarantor.ClaimStateTransitionReceiptDigestV1(*predecessorTransition)
		variant.PredecessorDecisionAdmissionReceiptDigest = predecessorTransition.DecisionAdmissionProof.ReceiptEnvelopeDigest
	}
	actionBody := guarantor.ClaimDecisionAdmissionActionBodyV1{SchemaVersion: 1, AdmissionMode: "authorized_decision",
		AuthorizedDecisionVariant: &variant}
	request, err := codec.Marshal(actionBody)
	if err != nil {
		return GuarantorDecisionAdmissionResult{}, err
	}
	bound, err := guarantor.FindStageActionAuthorityV1(position.Terms.StageActionAuthorityBinding, "terminal_decision")
	if err != nil {
		return GuarantorDecisionAdmissionResult{}, err
	}
	headDigest, identityDigest, err := guarantor.AuthorizedDecisionAdmissionSourceIdentityV1(variant, input.Decision)
	if err != nil {
		return GuarantorDecisionAdmissionResult{}, err
	}
	fields := guarantor.DecisionAdmissionSemanticFieldsV1(bound, actionBody, input.Decision, headDigest, identityDigest)
	action, err := commerce.BuildAuthorizedAction(coordinator.OwnerID, coordinator.AgentID,
		"conditional.claim-decision.admit", fields, request, fence, coordinator.PolicyRevision, coordinator.MandateDigest,
		"", record.LastEvidenceDigest, position.Terms.TerminalResolutionDeadlineUnix)
	if err != nil {
		return GuarantorDecisionAdmissionResult{}, err
	}
	action, err = coordinator.Authority.SignAction(action, fence)
	if err != nil {
		return GuarantorDecisionAdmissionResult{}, err
	}
	resolution, err := coordinator.Authority.Admit(action, fields, request, fence, nil)
	if err != nil || resolution.State != commerce.ActionPrepared {
		return GuarantorDecisionAdmissionResult{Resolution: resolution},
			firstError(err, errors.New("Guarantor decision admission action was not prepared"))
	}
	rawEligibility, err := coordinator.Eligibility.FreshEligibilityProofSet(ctx, "claim-decision-admission",
		position.Terms.DecisionAdmissionAuthoritySubjects, now)
	if err != nil {
		return GuarantorDecisionAdmissionResult{Resolution: resolution}, err
	}
	eligibility, err := buildGuarantorEligibilityProofSet(rawEligibility, action, decisionDigest,
		position.Terms.DecisionAdmissionAuthoritySubjects, "claim-decision-admission-receipt", decisionDigest,
		position.Terms.DecisionAdmissionProfile.ProfileDigest, position.Terms.DecisionAdmissionProfile,
		position.Terms.CoverageStateDomainDigest, input.Decision.Body.DecisionSequence, uint64(now.Unix()))
	if err != nil {
		return GuarantorDecisionAdmissionResult{Resolution: resolution}, err
	}
	eligibilityDigest, err := guarantor.AuthorityAdmissionEligibilityProofSetDigestV1(eligibility)
	if err != nil {
		return GuarantorDecisionAdmissionResult{Resolution: resolution}, err
	}
	endCommitment, err := currentCoverageEndCommitment(position)
	if err != nil {
		return GuarantorDecisionAdmissionResult{Resolution: resolution}, err
	}
	endDigest, err := guarantor.CoverageEndCommitmentDigestV1(endCommitment)
	if err != nil {
		return GuarantorDecisionAdmissionResult{Resolution: resolution}, err
	}
	actionDigest, err := commerce.AuthorizedActionDigest(action)
	if err != nil {
		return GuarantorDecisionAdmissionResult{Resolution: resolution}, err
	}
	cutDigest, err := guarantor.ClaimIngressAdmissionCutProofDigestV1(cut)
	if err != nil {
		return GuarantorDecisionAdmissionResult{Resolution: resolution}, err
	}
	targetStatus, targetState, err := claimStatusFromDecisionResult(input.Decision.Body.Result)
	if err != nil {
		return GuarantorDecisionAdmissionResult{Resolution: resolution}, err
	}
	pendingBase := position.AggregatePendingDecisionReserveAtomic
	if priorToken != nil {
		pendingBase, err = atomicSub(pendingBase, priorToken.ReservedApprovedAmount.AmountAtomic)
		if err != nil {
			return GuarantorDecisionAdmissionResult{Resolution: resolution}, err
		}
	}
	pendingAfter, err := atomicAdd(pendingBase, input.Decision.Body.ApprovedAmount.AmountAtomic)
	if err != nil {
		return GuarantorDecisionAdmissionResult{Resolution: resolution}, err
	}
	tokenID, err := guarantor.DecisionApplicationTokenIDV1(input.AgreementDigest, position.Record.CoverageObligationID,
		record.ClaimID, decisionDigest, input.Decision.Body.DecisionSequence, input.Decision.Body.DecisionRevision)
	if err != nil {
		return GuarantorDecisionAdmissionResult{Resolution: resolution}, err
	}
	token := guarantor.DecisionApplicationTokenV1{SchemaVersion: 1, TokenID: tokenID,
		CoverageAgreementBodyDigest: input.AgreementDigest, CoverageObligationID: position.Record.CoverageObligationID,
		ClaimID: record.ClaimID, AuthorizedClaimDecisionDigest: decisionDigest,
		DecisionSequence: input.Decision.Body.DecisionSequence, DecisionRevision: 1,
		ReservedApprovedAmount: input.Decision.Body.ApprovedAmount, TokenRevision: 1, State: "pending"}
	challengeStarts, challengeEnds := uint64(0), uint64(0)
	resolutionStarts, resolutionDue := uint64(0), uint64(0)
	if targetStatus == guarantor.ClaimApproved || targetStatus == guarantor.ClaimPartiallyApproved || targetStatus == guarantor.ClaimDenied {
		challengeStarts = uint64(now.Unix())
		challengeEnds = challengeStarts + position.Terms.ChallengeWindowSeconds
	} else {
		resolutionStarts = uint64(now.Unix())
		resolutionDue = resolutionStarts + position.Terms.NonterminalResolutionWindowSeconds
	}
	body := guarantor.ClaimDecisionAdmissionReceiptBodyV1{SchemaVersion: 1, AuthorityID: action.AuthorityID,
		CoverageAgreementBodyDigest: input.AgreementDigest, CoverageObligationID: position.Record.CoverageObligationID,
		ClaimID: record.ClaimID, AuthorizedClaimDecisionDigest: decisionDigest, AdmissionMode: "authorized_decision",
		AuthorizedClaimAdmissionReceiptDigest: mustGuarantorDigest(guarantor.ClaimAdmissionReceiptEnvelopeDomain, claimAdmission),
		ClaimRevisionIngressCutProofDigest:    cutDigest, FrozenRevisionEpoch: epoch.RevisionEpoch,
		PriorRevisionEpochStateRevision:     epoch.ExpectedEpochStateRevision,
		FrozenRevisionEpochStateRevision:    cut.FrozenEpochStateRevision,
		FrozenClaimRevisionIngressHighWater: cut.AdmissionHighWater, FrozenClaimRevisionIngressLogRoot: cut.AdmissionLogRoot,
		PredecessorDecisionAdmissionReceiptDigest:    variant.PredecessorDecisionAdmissionReceiptDigest,
		PredecessorClaimStateTransitionReceiptDigest: variant.PredecessorClaimStateTransitionReceiptDigest,
		DecisionSequence: input.Decision.Body.DecisionSequence, DecisionRevision: 1, DecisionPath: input.Decision.Body.DecisionPath,
		PriorCoverageRevision: position.Record.CoverageRevision, AdmittedCoverageRevision: position.Record.CoverageRevision + 1,
		PriorCoverageEndCommitmentDigest: endDigest, ResultingCoverageEndCommitmentDigest: endDigest,
		PriorClaimState: stringLowerClaimStatus(record.ClaimStatus), AdmittedClaimState: targetState,
		PriorClaimStateRevision: record.ClaimStateRevision, AdmittedClaimStateRevision: record.ClaimStateRevision + 1,
		ChallengeRoundsUsedBefore: position.ChallengeRoundsUsed[record.ClaimID], ChallengeRoundsUsedAfter: position.ChallengeRoundsUsed[record.ClaimID],
		NonterminalRoundsUsedBefore: position.NonterminalRoundsUsed[record.ClaimID], NonterminalRoundsUsedAfter: position.NonterminalRoundsUsed[record.ClaimID],
		ChallengeStartsAtUnix: challengeStarts, ChallengeEndsAtUnix: challengeEnds,
		ResolutionStartsAtUnix: resolutionStarts, ResolutionDueAtUnix: resolutionDue,
		ResultingApplicationToken: &token,
		AggregatePendingDecisionReserveBefore: commerce.AtomicAmountV1{Asset: position.Terms.CoverageAsset,
			AmountAtomic: position.AggregatePendingDecisionReserveAtomic},
		AggregatePendingDecisionReserveAfter: commerce.AtomicAmountV1{Asset: position.Terms.CoverageAsset, AmountAtomic: pendingAfter},
		AuthorizedActionDigest:               actionDigest, StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest,
		WriterGeneration: action.WriterGeneration, WriterFenceDigest: action.WriterFenceDigest, AdmittedAtUnix: uint64(now.Unix()),
		AuthorityAdmissionEligibilityProofSetDigest: eligibilityDigest}
	if priorToken != nil {
		body.PriorApplicationTokenDigest, _ = guarantor.DecisionApplicationTokenDigestV1(*priorToken)
		body.PriorApplicationTokenTerminalState = "replaced"
	}
	if targetStatus == guarantor.ClaimEvidenceRequired || targetStatus == guarantor.ClaimDisputed {
		body.ResultingApplicationToken = nil
	}
	bodyDigest, err := codec.Digest("tos.service.agent-guarantor-claim-decision-admission-receipt-body.v1", body)
	if err != nil {
		return GuarantorDecisionAdmissionResult{Resolution: resolution}, err
	}
	authorization, err := coordinator.Signer.SignObject("claim-decision-admission-receipt", bodyDigest,
		"tos.service.agent-guarantor-claim-decision-admission-signature.v1", now)
	if err != nil {
		return GuarantorDecisionAdmissionResult{Resolution: resolution}, err
	}
	resolution, err = coordinator.Authority.Transition(action.StableActionID, action.ExactRequestDigest,
		commerce.ActionTerminal, bodyDigest, sortedGuarantorEvidence(decisionDigest, bodyDigest))
	if err != nil {
		return GuarantorDecisionAdmissionResult{Resolution: resolution}, err
	}
	stage, err := coordinator.buildGuarantorStage(position.Terms, "terminal_decision",
		"application/vnd.tos.service.agent-guarantor-claim-decision-admission.v1+cbor", request, action, resolution, fence, now)
	if err != nil {
		return GuarantorDecisionAdmissionResult{Resolution: resolution}, err
	}
	receipt := guarantor.AuthorizedClaimDecisionAdmissionReceiptV1{Body: body, StageActionAdmissionEvidence: stage,
		AuthorizedClaimDecision: input.Decision, AuthorizedClaimAdmissionReceipt: claimAdmission,
		ClaimRevisionIngressCutProof: cut, CoverageEndCommitment: endCommitment,
		PriorPendingApplicationToken: priorToken, PredecessorClaimStateTransitionReceipt: predecessorTransition,
		AuthorityAdmissionEligibilityProofSet: eligibility,
		Authorizations:                        []guarantor.ProfileQualifiedObjectAuthorizationV1{authorization}}
	if err := guarantor.VerifyClaimDecisionAdmissionReceiptV1(receipt, position.Terms, coordinator.AgreementVerifier,
		coordinator.Resolver, coordinator.Authority, now); err != nil {
		return GuarantorDecisionAdmissionResult{Receipt: receipt, Resolution: resolution}, fmt.Errorf("verify Guarantor decision admission: %w", err)
	}
	if _, err := coordinator.Journal.CommitDecisionAdmission(input.AgreementDigest, receipt); err != nil {
		return GuarantorDecisionAdmissionResult{Receipt: receipt, Resolution: resolution}, err
	}
	return GuarantorDecisionAdmissionResult{Receipt: receipt, Resolution: resolution}, nil
}

func (coordinator *GuarantorProviderCoordinator) TransitionClaimDecision(ctx context.Context,
	input GuarantorTransitionClaimInput, fence commerce.WriterFence) (GuarantorClaimTransitionResult, error) {
	if err := ctx.Err(); err != nil {
		return GuarantorClaimTransitionResult{}, err
	}
	if coordinator == nil || coordinator.Authority == nil || coordinator.Journal == nil || coordinator.Signer == nil ||
		coordinator.ActionAuthoritySigner == nil || coordinator.Resolver == nil || coordinator.AgreementVerifier == nil || coordinator.Eligibility == nil ||
		!canonicalSHA256(input.AgreementDigest) {
		return GuarantorClaimTransitionResult{}, errors.New("Guarantor claim transition coordinator is incomplete")
	}
	now := coordinator.Authority.AuthorityNow().UTC()
	if now.IsZero() || coordinator.Authority.ConfirmCurrentWriterFence(fence, now) != nil {
		return GuarantorClaimTransitionResult{}, errors.New("Guarantor claim transition writer is stale")
	}
	position, err := coordinator.coveragePosition(input.AgreementDigest)
	if err != nil {
		return GuarantorClaimTransitionResult{}, err
	}
	decisionAdmission := input.DecisionAdmissionReceipt
	if err := guarantor.VerifyClaimDecisionAdmissionReceiptV1(decisionAdmission, position.Terms,
		coordinator.AgreementVerifier, coordinator.Resolver, coordinator.Authority, now); err != nil {
		return GuarantorClaimTransitionResult{}, fmt.Errorf("verify current Guarantor decision admission: %w", err)
	}
	claimID := decisionAdmission.Body.ClaimID
	record, found := position.Claims[claimID]
	if !found || !sameJSON(position.DecisionAdmissionReceipts[claimID], decisionAdmission) ||
		record.ClaimStateRevision != decisionAdmission.Body.AdmittedClaimStateRevision {
		return GuarantorClaimTransitionResult{}, errors.New("Guarantor claim transition has no current decision head")
	}
	decisionAdmissionDigest, err := guarantor.ClaimDecisionAdmissionReceiptDigestV1(decisionAdmission)
	if err != nil {
		return GuarantorClaimTransitionResult{}, err
	}
	sealBody, receiptDescriptor, err := guarantor.NewClaimDecisionAdmissionReceiptSealBodyV1(decisionAdmission,
		position.Terms, now)
	if err != nil {
		return GuarantorClaimTransitionResult{}, err
	}
	sealDigest, err := codec.Digest(guarantor.ClaimDecisionAdmissionReceiptSealDomainV1, sealBody)
	if err != nil {
		return GuarantorClaimTransitionResult{}, err
	}
	sealAuthorization, err := coordinator.ActionAuthoritySigner.SignObject("claim-decision-admission-receipt-seal",
		sealDigest, "tos.service.agent-guarantor-claim-decision-admission-receipt-seal-signature.v1", now)
	if err != nil {
		return GuarantorClaimTransitionResult{}, err
	}
	decisionProof, err := guarantor.BuildClaimDecisionAdmissionReceiptProofV1(decisionAdmission, position.Terms,
		receiptDescriptor, sealBody, sealAuthorization)
	if err != nil {
		return GuarantorClaimTransitionResult{}, err
	}
	evidenceSet := input.TransitionEvidenceSet
	if len(evidenceSet.Items) == 0 {
		admissionBytes, marshalErr := codec.Marshal(decisionAdmission)
		if marshalErr != nil {
			return GuarantorClaimTransitionResult{}, marshalErr
		}
		evidenceSet = guarantor.CanonicalGuarantorEvidenceSetV1{SchemaVersion: 1,
			Purpose: "claim-" + input.TransitionKind, ContextDigest: decisionAdmissionDigest,
			Items: []guarantor.CanonicalGuarantorEvidenceItemV1{{ContentType: "application/vnd.tos.service.agent-guarantor-claim-decision-admission.v1+cbor",
				EvidenceProfileDigest:  position.Terms.DecisionAdmissionProfile.ProfileDigest,
				EvidenceEnvelopeDigest: decisionAdmissionDigest, Representation: "content_addressed",
				ImmutableDescriptor: &guarantor.ImmutableEvidenceDescriptorV1{ContentType: "application/vnd.tos.service.agent-guarantor-claim-decision-admission.v1+cbor",
					ContentDigest: decisionAdmissionDigest, ContentSize: uint64(len(admissionBytes)),
					RetrievalPolicyDigest: position.Terms.DecisionAdmissionProfile.ProfileDigest}}}}
	}
	switch input.TransitionKind {
	case "challenge_close":
		evidenceSet.Purpose = "claim-challenge-close"
	case "challenge_admission":
		evidenceSet.Purpose = "claim-challenge-admission"
	case "nonterminal_response_admission":
		evidenceSet.Purpose = "claim-nonterminal-response-admission"
	default:
		return GuarantorClaimTransitionResult{}, errors.New("Guarantor claim transition kind is unknown")
	}
	evidenceSet.ContextDigest = decisionAdmissionDigest
	evidenceSetDigest, err := guarantor.CanonicalGuarantorEvidenceSetDigestV1(evidenceSet)
	if err != nil {
		return GuarantorClaimTransitionResult{}, err
	}
	targetState := "reviewing"
	targetChallenge := position.ChallengeRoundsUsed[claimID]
	targetNonterminal := position.NonterminalRoundsUsed[claimID]
	successorDue := uint64(0)
	if input.TransitionKind == "challenge_admission" {
		targetChallenge++
		successorDue = uint64(now.Unix()) + position.Terms.SuccessorDecisionWindowSeconds
	} else if input.TransitionKind == "nonterminal_response_admission" {
		targetNonterminal++
		successorDue = decisionAdmission.Body.ResolutionDueAtUnix
	} else {
		switch decisionAdmission.Body.AdmittedClaimState {
		case "approved":
			targetState = "final_approved"
		case "partially_approved":
			targetState = "final_partially_approved"
		case "denied":
			targetState = "final_denied"
		default:
			return GuarantorClaimTransitionResult{}, errors.New("non-challengeable decision cannot close")
		}
	}
	projection := guarantor.TransitionEvidenceProjectionV1{SchemaVersion: 1, Purpose: "claim-state-transition",
		CoverageAgreementBodyDigest: input.AgreementDigest, ObligationID: position.Record.CoverageObligationID,
		ClaimID: claimID, TargetState: targetState, EvidenceDigests: []guarantor.TransitionEvidenceDigestRefV1{{
			EvidenceRole: "decision_admission", DigestKind: "authorized_envelope", ObjectDigest: decisionAdmissionDigest}}}
	projectionDigest, err := guarantor.TransitionEvidenceProjectionDigestV1(projection)
	if err != nil {
		return GuarantorClaimTransitionResult{}, err
	}
	requestBody := guarantor.ClaimStateTransitionActionBodyV1{SchemaVersion: 1,
		CoverageAgreementBodyDigest: input.AgreementDigest, CoverageObligationID: position.Record.CoverageObligationID,
		ClaimID: claimID, TransitionKind: input.TransitionKind, ExpectedClaimStateRevision: record.ClaimStateRevision,
		TargetState: targetState, ExpectedChallengeRoundsUsed: position.ChallengeRoundsUsed[claimID],
		TargetChallengeRoundsUsed: targetChallenge, ExpectedNonterminalRoundsUsed: position.NonterminalRoundsUsed[claimID],
		TargetNonterminalRoundsUsed: targetNonterminal, SuccessorDecisionDueAtUnix: successorDue,
		AuthorizedClaimDecisionAdmissionReceiptDigest: decisionAdmissionDigest, TransitionEvidenceProjection: projection,
		TransitionEvidenceSet: evidenceSet}
	request, err := codec.Marshal(requestBody)
	if err != nil {
		return GuarantorClaimTransitionResult{}, err
	}
	bound, err := guarantor.FindStageActionAuthorityV1(position.Terms.StageActionAuthorityBinding, "claim_state_transition")
	if err != nil {
		return GuarantorClaimTransitionResult{}, err
	}
	fields := guarantor.ClaimStateTransitionSemanticFieldsV1(bound, requestBody, evidenceSetDigest)
	action, err := commerce.BuildAuthorizedAction(coordinator.OwnerID, coordinator.AgentID, "conditional.claim.transition",
		fields, request, fence, coordinator.PolicyRevision, coordinator.MandateDigest, "", record.LastEvidenceDigest,
		position.Terms.TerminalResolutionDeadlineUnix)
	if err != nil {
		return GuarantorClaimTransitionResult{}, err
	}
	action, err = coordinator.Authority.SignAction(action, fence)
	if err != nil {
		return GuarantorClaimTransitionResult{}, err
	}
	resolution, err := coordinator.Authority.Admit(action, fields, request, fence, nil)
	if err != nil || resolution.State != commerce.ActionPrepared {
		return GuarantorClaimTransitionResult{Resolution: resolution},
			firstError(err, errors.New("Guarantor claim transition was not prepared"))
	}
	rawProof, err := coordinator.Eligibility.FreshEligibilityProofSet(ctx, "claim-state-transition",
		position.Terms.DecisionAdmissionAuthoritySubjects, now)
	if err != nil {
		return GuarantorClaimTransitionResult{Resolution: resolution}, err
	}
	eligibility, err := buildGuarantorEligibilityProofSet(rawProof, action, decisionAdmissionDigest,
		position.Terms.DecisionAdmissionAuthoritySubjects, "claim-state-transition-receipt", projectionDigest,
		position.Terms.DecisionAdmissionProfile.ProfileDigest, position.Terms.DecisionAdmissionProfile,
		bound.AdmissionStateDomainDigest, record.ClaimStateRevision+1, uint64(now.Unix()))
	if err != nil {
		return GuarantorClaimTransitionResult{Resolution: resolution}, err
	}
	proofDigest, _ := guarantor.AuthorityAdmissionEligibilityProofSetDigestV1(eligibility)
	actionDigest, _ := commerce.AuthorizedActionDigest(action)
	body := guarantor.ClaimStateTransitionReceiptBodyV1{SchemaVersion: 1, AuthorityID: action.AuthorityID,
		CoverageAgreementBodyDigest: input.AgreementDigest, CoverageObligationID: position.Record.CoverageObligationID,
		ClaimID: claimID, TransitionKind: input.TransitionKind, TransitionEvidenceProjectionDigest: projectionDigest,
		AuthorizedActionDigest: actionDigest, StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest,
		WriterGeneration: action.WriterGeneration, WriterFenceDigest: action.WriterFenceDigest,
		PriorClaimState: stringLowerClaimStatus(record.ClaimStatus), ResultingClaimState: targetState,
		PriorClaimStateRevision: record.ClaimStateRevision, ResultingClaimStateRevision: record.ClaimStateRevision + 1,
		ChallengeRoundsUsedBefore: position.ChallengeRoundsUsed[claimID], ChallengeRoundsUsedAfter: targetChallenge,
		NonterminalRoundsUsedBefore: position.NonterminalRoundsUsed[claimID], NonterminalRoundsUsedAfter: targetNonterminal,
		SuccessorDecisionDueAtUnix: successorDue, TransitionedAtUnix: uint64(now.Unix()),
		AuthorityAdmissionEligibilityProofSetDigest: proofDigest}
	bodyDigest, err := codec.Digest("tos.service.agent-guarantor-claim-state-transition-receipt-body.v1", body)
	if err != nil {
		return GuarantorClaimTransitionResult{Resolution: resolution}, err
	}
	authorization, err := coordinator.Signer.SignObject("claim-state-transition-receipt", bodyDigest,
		"tos.service.agent-guarantor-claim-state-transition-signature.v1", now)
	if err != nil {
		return GuarantorClaimTransitionResult{Resolution: resolution}, err
	}
	resolution, err = coordinator.Authority.Transition(action.StableActionID, action.ExactRequestDigest,
		commerce.ActionTerminal, bodyDigest, sortedGuarantorEvidence(decisionAdmissionDigest, projectionDigest, bodyDigest))
	if err != nil {
		return GuarantorClaimTransitionResult{Resolution: resolution}, err
	}
	stage, err := coordinator.buildGuarantorStage(position.Terms, "claim_state_transition",
		"application/vnd.tos.service.agent-guarantor-claim-state-transition.v1+cbor", request, action, resolution, fence, now)
	if err != nil {
		return GuarantorClaimTransitionResult{Resolution: resolution}, err
	}
	receipt := guarantor.AuthorizedClaimStateTransitionReceiptV1{Body: body, StageActionAdmissionEvidence: stage,
		DecisionAdmissionProof: decisionProof, TransitionEvidenceProjection: projection,
		TransitionEvidenceSet: evidenceSet, AuthorityAdmissionEligibilityProofSet: eligibility,
		Authorizations: []guarantor.ProfileQualifiedObjectAuthorizationV1{authorization}}
	if err := guarantor.VerifyClaimStateTransitionReceiptV1(receipt, position.Terms, coordinator.AgreementVerifier,
		coordinator.Resolver, coordinator.Authority, now); err != nil {
		return GuarantorClaimTransitionResult{Receipt: receipt, Resolution: resolution}, fmt.Errorf("verify Guarantor claim transition: %w", err)
	}
	if _, err := coordinator.Journal.CommitClaimStateTransition(input.AgreementDigest, receipt); err != nil {
		return GuarantorClaimTransitionResult{Receipt: receipt, Resolution: resolution}, err
	}
	return GuarantorClaimTransitionResult{Receipt: receipt, Resolution: resolution}, nil
}
