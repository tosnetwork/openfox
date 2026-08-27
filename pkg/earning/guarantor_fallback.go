package earning

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	guarantor "github.com/tosnetwork/tos-service-protocol/pkg/agentguarantor"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type GuarantorAdmitInitialFallbackInput struct {
	AgreementDigest   string
	ClaimID           string
	LateFilingReceipt *guarantor.AuthorizedClaimFilingCloseReceiptV1
}

// AdmitInitialFallbackDecision materializes the Agreement-granted timeout
// decision inside the fenced admission transaction. V1's production OpenFox
// path intentionally supports the closed deny-zero function first: no caller,
// model, or Guarantor signer supplies a result or amount.
func (coordinator *GuarantorProviderCoordinator) AdmitInitialFallbackDecision(ctx context.Context,
	input GuarantorAdmitInitialFallbackInput, fence commerce.WriterFence) (GuarantorDecisionAdmissionResult, error) {
	if err := ctx.Err(); err != nil {
		return GuarantorDecisionAdmissionResult{}, err
	}
	if coordinator == nil || coordinator.Authority == nil || coordinator.Journal == nil || coordinator.Signer == nil ||
		coordinator.Resolver == nil || coordinator.AgreementVerifier == nil ||
		coordinator.Eligibility == nil || !canonicalSHA256(input.AgreementDigest) || !canonicalSHA256(input.ClaimID) {
		return GuarantorDecisionAdmissionResult{}, errors.New("Guarantor fallback coordinator is incomplete")
	}
	now := coordinator.Authority.AuthorityNow().UTC()
	if now.IsZero() || coordinator.Authority.ConfirmCurrentWriterFence(fence, now) != nil {
		return GuarantorDecisionAdmissionResult{}, errors.New("Guarantor fallback writer is stale")
	}
	position, err := coordinator.coveragePosition(input.AgreementDigest)
	if err != nil {
		return GuarantorDecisionAdmissionResult{}, err
	}
	fallback := position.Terms.ClaimClosureCapacity.TerminalFallback
	if fallback.OutcomeRule != "deny_zero" {
		return GuarantorDecisionAdmissionResult{}, errors.New("OpenFox has no released total-function evaluator for this fallback profile")
	}
	claim, found := position.ClaimEnvelopes[input.ClaimID]
	record, recordFound := position.Claims[input.ClaimID]
	claimAdmission, admissionFound := position.ClaimAdmissionReceipts[guarantorClaimRevisionKey(input.ClaimID, record.ClaimRevision)]
	if !found || !recordFound || !admissionFound {
		return GuarantorDecisionAdmissionResult{}, errors.New("Guarantor fallback has no admitted claim head")
	}
	sourceState, decisionPath, priorState := "", "terminal_fallback", stringLowerClaimStatus(record.ClaimStatus)
	decisionSequence := record.DecisionSequence + 1
	predecessorDecisionDigest := ""
	var currentDecision *guarantor.AuthorizedClaimDecisionAdmissionReceiptV1
	var currentTransition *guarantor.AuthorizedClaimStateTransitionReceiptV1
	var priorToken *guarantor.DecisionApplicationTokenV1
	cutoff, ok := uint64(0), false
	switch record.ClaimStatus {
	case guarantor.ClaimAdmitted:
		if record.DecisionSequence != 0 {
			return GuarantorDecisionAdmissionResult{}, errors.New("Guarantor initial fallback sequence is invalid")
		}
		sourceState, decisionPath, decisionSequence = "initial_reviewing", "initial_terminal_fallback", 1
		cutoff, ok = safeAddUnix(claimAdmission.Body.AdmittedAtUnix, position.Terms.ReviewDeadlineSeconds)
	case guarantor.ClaimEvidenceRequired, guarantor.ClaimDisputed:
		current, exists := position.DecisionAdmissionReceipts[input.ClaimID]
		if !exists || current.Body.ResolutionDueAtUnix == 0 {
			return GuarantorDecisionAdmissionResult{}, errors.New("Guarantor nonterminal fallback has no decision head")
		}
		currentDecision = &current
		sourceState = stringLowerClaimStatus(record.ClaimStatus)
		cutoff, ok = current.Body.ResolutionDueAtUnix, true
		predecessorDecisionDigest = current.Body.AuthorizedClaimDecisionDigest
	case guarantor.ClaimReviewing:
		current, decisionExists := position.DecisionAdmissionReceipts[input.ClaimID]
		transition, transitionExists := position.ClaimStateTransitionReceipts[input.ClaimID]
		if !decisionExists || !transitionExists || transition.Body.SuccessorDecisionDueAtUnix == 0 {
			return GuarantorDecisionAdmissionResult{}, errors.New("Guarantor reviewing fallback has no transition head")
		}
		currentDecision, currentTransition = &current, &transition
		if transition.Body.TransitionKind == "challenge_admission" {
			sourceState = "reviewing_after_challenge"
			token, exists := position.DecisionApplicationTokens[input.ClaimID]
			if !exists || token.State != "pending" {
				return GuarantorDecisionAdmissionResult{}, errors.New("Guarantor reviewing fallback has no pending challenged token")
			}
			priorToken = &token
		} else if transition.Body.TransitionKind == "nonterminal_response_admission" {
			sourceState = "reviewing_after_nonterminal_response"
		} else {
			return GuarantorDecisionAdmissionResult{}, errors.New("Guarantor reviewing fallback transition is not eligible")
		}
		cutoff, ok = transition.Body.SuccessorDecisionDueAtUnix, true
		predecessorDecisionDigest = current.Body.AuthorizedClaimDecisionDigest
	default:
		return GuarantorDecisionAdmissionResult{}, errors.New("Guarantor claim state is not fallback-eligible")
	}
	if !ok || uint64(now.Unix()) < cutoff {
		return GuarantorDecisionAdmissionResult{}, errors.New("Guarantor fallback deadline has not elapsed")
	}
	lateRecovery := input.LateFilingReceipt != nil
	if lateRecovery {
		filing := *input.LateFilingReceipt
		if position.FilingCloseReceipt == nil || !sameJSON(*position.FilingCloseReceipt, filing) ||
			filing.Body.ClosedAtUnix <= position.Terms.TerminalResolutionDeadlineUnix ||
			filing.Body.ClosedAtUnix > position.Terms.LateIngressRecoveryDeadlineUnix ||
			uint64(now.Unix()) > position.Terms.LateIngressRecoveryDeadlineUnix {
			return GuarantorDecisionAdmissionResult{}, errors.New("Guarantor late fallback lacks its exact bounded filing-close predecessor")
		}
		decisionPath, cutoff = "late_recovery_terminal_fallback", filing.Body.ClosedAtUnix
	}
	claimDigest, err := guarantor.ClaimEnvelopeDigest(claim)
	if err != nil {
		return GuarantorDecisionAdmissionResult{}, err
	}
	evidenceSet := fallbackDecisionEvidenceSet(claim, claimDigest)
	evidenceDigest, err := guarantor.CanonicalGuarantorEvidenceSetDigestV1(evidenceSet)
	if err != nil {
		return GuarantorDecisionAdmissionResult{}, err
	}
	triggeredDigest, err := guarantor.TriggeredObligationSetDigestV1(claim.Body.TriggeredObligationSet)
	if err != nil {
		return GuarantorDecisionAdmissionResult{}, err
	}
	selectedReason, foundReason := fallbackReasonRule(fallback, "deny_zero")
	if !foundReason {
		return GuarantorDecisionAdmissionResult{}, errors.New("Guarantor deny-zero fallback reason is absent")
	}
	zero := commerce.AtomicAmountV1{Asset: position.Terms.CoverageAsset, AmountAtomic: "0"}
	policy := guarantor.ClaimDecisionPolicyApplicationV1{SchemaVersion: 1,
		CoverageAgreementBodyDigest: input.AgreementDigest, CoverageObligationID: position.Record.CoverageObligationID,
		AuthorizedClaimEnvelopeDigest: claimDigest, DecisionPath: decisionPath,
		BenefitCalculationProfile:    position.Terms.BenefitCalculationProfile,
		TriggeredObligationSetDigest: triggeredDigest, EvidenceSetDigest: evidenceDigest,
		OtherRecoveryDeclarationDigest: claim.Body.OtherRecoveryDeclarationDigest,
		ApplicablePolicyClauseIDs:      append([]string(nil), selectedReason.ApplicablePolicyClauseIDs...),
		PolicyInputProjection:          []byte{}, FullEligibleBenefitAmount: zero}
	policyDigest, err := guarantor.ClaimDecisionPolicyApplicationDigestV1(policy)
	if err != nil {
		return GuarantorDecisionAdmissionResult{}, err
	}
	predicates := make([]string, len(claim.EvidenceManifest.Items))
	for index, item := range claim.EvidenceManifest.Items {
		predicates[index] = item.PredicateID
	}
	reason := guarantor.ClaimDecisionReasonV1{SchemaVersion: 1, DecisionProfile: fallback.FallbackProfile,
		Result: guarantor.DecisionDenied, ReasonCode: selectedReason.ReasonCode,
		ApplicablePolicyClauseIDs: append([]string(nil), selectedReason.ApplicablePolicyClauseIDs...),
		EvidencePredicateIDs:      predicates}
	reasonDigest, err := guarantor.ClaimDecisionReasonDigestV1(reason)
	if err != nil {
		return GuarantorDecisionAdmissionResult{}, err
	}
	decisionBody := guarantor.ClaimDecisionBodyV1{SchemaVersion: 1,
		CoverageAgreementBodyDigest: input.AgreementDigest, CoverageObligationID: position.Record.CoverageObligationID,
		ClaimID: input.ClaimID, AuthorizedClaimEnvelopeDigest: claimDigest, DecisionSequence: decisionSequence, DecisionRevision: 1,
		PredecessorAuthorizedClaimDecisionDigest: predecessorDecisionDigest,
		DecisionPath:                             decisionPath, ExpectedClaimRevision: claim.Body.ClaimRevision,
		DecisionProfile: fallback.FallbackProfile, DecisionAuthoritySubjects: append([]string(nil), fallback.FallbackAuthoritySubjects...),
		DecisionQuorumRule: fallback.FallbackQuorumRule, Result: guarantor.DecisionDenied, ApprovedAmount: zero,
		EvidenceSetDigest: evidenceDigest, PolicyApplicationDigest: policyDigest, ReasonDigest: reasonDigest,
		ChallengeWindowSeconds: position.Terms.ChallengeWindowSeconds, DecidedAtUnix: uint64(now.Unix()),
		ExpiresAtUnix: minUint64(func() uint64 {
			if lateRecovery {
				return position.Terms.LateIngressRecoveryDeadlineUnix
			}
			return position.Terms.TerminalResolutionDeadlineUnix
		}(), uint64(now.Add(30*24*time.Hour).Unix()))}
	decision := guarantor.AuthorizedClaimDecisionV1{Body: decisionBody, DecisionEvidenceSet: evidenceSet,
		PolicyApplication: policy, DecisionReason: reason, Authorizations: nil}
	if err := guarantor.ValidateClaimDecision(decision, claim, position.Terms, coordinator.Resolver,
		fallback.FallbackAuthoritySubjects, now); err != nil {
		return GuarantorDecisionAdmissionResult{}, err
	}
	decisionDigest, _ := guarantor.ClaimDecisionDigestV1(decision)
	claimAdmissionDigest, _ := guarantor.ClaimAdmissionReceiptDigestV1(claimAdmission)
	cut, err := coordinator.Journal.ClaimRevisionAdmissionCut(input.AgreementDigest, input.ClaimID, uint64(now.Unix()))
	if err != nil {
		return GuarantorDecisionAdmissionResult{}, err
	}
	epoch := guarantor.ClaimRevisionEpochExpectationV1{SchemaVersion: 1,
		CoverageAgreementBodyDigest: input.AgreementDigest, CoverageObligationID: position.Record.CoverageObligationID,
		ClaimID: input.ClaimID, RevisionEpoch: claim.Body.ClaimRevision, RevisionIngressLogID: cut.ClaimIngressLogID,
		ExpectedEpochState: "open", ExpectedEpochStateRevision: cut.PriorEpochStateRevision,
		ExpectedClaimRevision: claim.Body.ClaimRevision}
	fallbackDigest, _ := guarantor.DeterministicClaimTerminalFallbackDigestV1(fallback)
	variant := guarantor.DeterministicFallbackAdmissionVariantV1{CoverageAgreementBodyDigest: input.AgreementDigest,
		CoverageObligationID: position.Record.CoverageObligationID, ClaimID: input.ClaimID,
		AuthorizedClaimAdmissionReceipt: claimAdmission, ClaimRevisionEpochExpectation: epoch,
		FallbackProfileDigest: fallbackDigest, SourceClaimRevision: claim.Body.ClaimRevision,
		CurrentDecisionAdmissionReceipt: currentDecision, CurrentClaimStateTransitionReceipt: currentTransition,
		LateFilingCloseReceipt:   input.LateFilingReceipt,
		SourceClaimStateRevision: record.ClaimStateRevision, SourceClaimState: sourceState,
		ExpectedChallengeRoundsUsed:   position.ChallengeRoundsUsed[input.ClaimID],
		ExpectedNonterminalRoundsUsed: position.NonterminalRoundsUsed[input.ClaimID], TriggerCutoffUnix: cutoff, DecisionSequence: decisionSequence}
	actionBody := guarantor.ClaimDecisionAdmissionActionBodyV1{SchemaVersion: 1, AdmissionMode: "deterministic_fallback",
		DeterministicFallbackVariant: &variant}
	request, err := codec.Marshal(actionBody)
	if err != nil {
		return GuarantorDecisionAdmissionResult{}, err
	}
	bound, err := guarantor.FindStageActionAuthorityV1(position.Terms.StageActionAuthorityBinding, "terminal_decision")
	if err != nil {
		return GuarantorDecisionAdmissionResult{}, err
	}
	headDigest, identityDigest, err := guarantor.DeterministicFallbackAdmissionSourceIdentityV1(variant)
	if err != nil {
		return GuarantorDecisionAdmissionResult{}, err
	}
	fields := guarantor.DecisionAdmissionSemanticFieldsV1(bound, actionBody, decision, headDigest, identityDigest)
	action, err := commerce.BuildAuthorizedAction(coordinator.OwnerID, coordinator.AgentID,
		"conditional.claim-decision.admit", fields, request, fence, coordinator.PolicyRevision, coordinator.MandateDigest,
		"", record.LastEvidenceDigest, func() uint64 {
			if lateRecovery {
				return position.Terms.LateIngressRecoveryDeadlineUnix
			}
			return position.Terms.TerminalResolutionDeadlineUnix
		}())
	if err == nil {
		action, err = coordinator.Authority.SignAction(action, fence)
	}
	if err != nil {
		return GuarantorDecisionAdmissionResult{}, err
	}
	resolution, err := coordinator.Authority.Admit(action, fields, request, fence, nil)
	if err != nil || resolution.State != commerce.ActionPrepared {
		return GuarantorDecisionAdmissionResult{Resolution: resolution}, firstError(err, errors.New("Guarantor fallback was not prepared"))
	}
	rawEligibility, err := coordinator.Eligibility.FreshEligibilityProofSet(ctx, "claim-decision-fallback-admission",
		position.Terms.DecisionAdmissionAuthoritySubjects, now)
	if err != nil {
		return GuarantorDecisionAdmissionResult{Resolution: resolution}, err
	}
	eligibility, err := buildGuarantorEligibilityProofSet(rawEligibility, action, decisionDigest,
		position.Terms.DecisionAdmissionAuthoritySubjects, "claim-decision-admission-receipt", decisionDigest, fallbackDigest,
		fallback.FallbackProfile, position.Terms.CoverageStateDomainDigest, decisionSequence, uint64(now.Unix()))
	if err != nil {
		return GuarantorDecisionAdmissionResult{Resolution: resolution}, err
	}
	eligibilityDigest, _ := guarantor.AuthorityAdmissionEligibilityProofSetDigestV1(eligibility)
	endCommitment, err := currentCoverageEndCommitment(position)
	if err != nil {
		return GuarantorDecisionAdmissionResult{Resolution: resolution}, err
	}
	endDigest, _ := guarantor.CoverageEndCommitmentDigestV1(endCommitment)
	actionDigest, _ := commerce.AuthorizedActionDigest(action)
	cutDigest, _ := guarantor.ClaimIngressAdmissionCutProofDigestV1(cut)
	tokenID, _ := guarantor.DecisionApplicationTokenIDV1(input.AgreementDigest, position.Record.CoverageObligationID,
		input.ClaimID, decisionDigest, decisionSequence, 1)
	token := guarantor.DecisionApplicationTokenV1{SchemaVersion: 1, TokenID: tokenID,
		CoverageAgreementBodyDigest: input.AgreementDigest, CoverageObligationID: position.Record.CoverageObligationID,
		ClaimID: input.ClaimID, AuthorizedClaimDecisionDigest: decisionDigest, DecisionSequence: decisionSequence, DecisionRevision: 1,
		ReservedApprovedAmount: zero, TokenRevision: 1, State: "pending"}
	body := guarantor.ClaimDecisionAdmissionReceiptBodyV1{SchemaVersion: 1, AuthorityID: action.AuthorityID,
		CoverageAgreementBodyDigest: input.AgreementDigest, CoverageObligationID: position.Record.CoverageObligationID,
		ClaimID: input.ClaimID, AuthorizedClaimDecisionDigest: decisionDigest, AdmissionMode: "deterministic_fallback",
		FallbackTriggerCutoffUnix: cutoff, AuthorizedClaimAdmissionReceiptDigest: claimAdmissionDigest,
		ClaimRevisionIngressCutProofDigest: cutDigest, FrozenRevisionEpoch: epoch.RevisionEpoch,
		PriorRevisionEpochStateRevision: epoch.ExpectedEpochStateRevision, FrozenRevisionEpochStateRevision: cut.FrozenEpochStateRevision,
		FrozenClaimRevisionIngressHighWater: cut.AdmissionHighWater, FrozenClaimRevisionIngressLogRoot: cut.AdmissionLogRoot,
		DecisionSequence: decisionSequence, DecisionRevision: 1, DecisionPath: decisionPath,
		PriorCoverageRevision: position.Record.CoverageRevision, AdmittedCoverageRevision: position.Record.CoverageRevision + 1,
		PriorCoverageEndCommitmentDigest: endDigest, ResultingCoverageEndCommitmentDigest: endDigest,
		PriorClaimState: priorState, AdmittedClaimState: "denied", PriorClaimStateRevision: record.ClaimStateRevision,
		AdmittedClaimStateRevision: record.ClaimStateRevision + 1,
		ChallengeRoundsUsedBefore:  position.ChallengeRoundsUsed[input.ClaimID], ChallengeRoundsUsedAfter: position.ChallengeRoundsUsed[input.ClaimID],
		NonterminalRoundsUsedBefore: position.NonterminalRoundsUsed[input.ClaimID], NonterminalRoundsUsedAfter: position.NonterminalRoundsUsed[input.ClaimID],
		ChallengeStartsAtUnix: uint64(now.Unix()), ChallengeEndsAtUnix: uint64(now.Unix()) + position.Terms.ChallengeWindowSeconds,
		ResultingApplicationToken:             &token,
		AggregatePendingDecisionReserveBefore: commerce.AtomicAmountV1{Asset: position.Terms.CoverageAsset, AmountAtomic: position.AggregatePendingDecisionReserveAtomic},
		AggregatePendingDecisionReserveAfter:  commerce.AtomicAmountV1{Asset: position.Terms.CoverageAsset, AmountAtomic: position.AggregatePendingDecisionReserveAtomic},
		AuthorizedActionDigest:                actionDigest, StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest,
		WriterGeneration: action.WriterGeneration, WriterFenceDigest: action.WriterFenceDigest, AdmittedAtUnix: uint64(now.Unix()),
		AuthorityAdmissionEligibilityProofSetDigest: eligibilityDigest}
	if lateRecovery {
		body.LateFilingCloseReceiptDigest, _ = guarantor.ClaimFilingCloseReceiptDigestV1(*input.LateFilingReceipt)
	}
	if currentDecision != nil {
		body.PredecessorDecisionAdmissionReceiptDigest, _ = guarantor.ClaimDecisionAdmissionReceiptDigestV1(*currentDecision)
	}
	if currentTransition != nil {
		body.PredecessorClaimStateTransitionReceiptDigest, _ = guarantor.ClaimStateTransitionReceiptDigestV1(*currentTransition)
	}
	if priorToken != nil {
		body.PriorApplicationTokenDigest, _ = guarantor.DecisionApplicationTokenDigestV1(*priorToken)
		body.PriorApplicationTokenTerminalState = "replaced"
		remaining, subErr := atomicSub(position.AggregatePendingDecisionReserveAtomic, priorToken.ReservedApprovedAmount.AmountAtomic)
		if subErr != nil {
			return GuarantorDecisionAdmissionResult{Resolution: resolution}, subErr
		}
		body.AggregatePendingDecisionReserveAfter.AmountAtomic = remaining
	}
	bodyDigest, _ := codec.Digest("tos.service.agent-guarantor-claim-decision-admission-receipt-body.v1", body)
	receiptAuthorization, err := coordinator.Signer.SignObject("claim-decision-admission-receipt", bodyDigest,
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
		AuthorizedClaimDecision: decision, AuthorizedClaimAdmissionReceipt: claimAdmission,
		ClaimRevisionIngressCutProof: cut, CoverageEndCommitment: endCommitment,
		LateFilingCloseReceipt:                input.LateFilingReceipt,
		PriorPendingApplicationToken:          priorToken,
		AuthorityAdmissionEligibilityProofSet: eligibility,
		Authorizations:                        []guarantor.ProfileQualifiedObjectAuthorizationV1{receiptAuthorization}}
	if err := guarantor.VerifyClaimDecisionAdmissionReceiptV1(receipt, position.Terms, coordinator.AgreementVerifier,
		coordinator.Resolver, coordinator.Authority, now); err != nil {
		return GuarantorDecisionAdmissionResult{Receipt: receipt, Resolution: resolution}, fmt.Errorf("verify Guarantor fallback: %w", err)
	}
	if _, err := coordinator.Journal.CommitDecisionAdmission(input.AgreementDigest, receipt); err != nil {
		return GuarantorDecisionAdmissionResult{Receipt: receipt, Resolution: resolution}, err
	}
	return GuarantorDecisionAdmissionResult{Receipt: receipt, Resolution: resolution}, nil
}

func fallbackDecisionEvidenceSet(claim guarantor.AuthorizedCoverageClaimV1, claimDigest string) guarantor.CanonicalGuarantorEvidenceSetV1 {
	items := make([]guarantor.CanonicalGuarantorEvidenceItemV1, len(claim.EvidenceManifest.Items))
	for index, item := range claim.EvidenceManifest.Items {
		items[index] = guarantor.CanonicalGuarantorEvidenceItemV1{ContentType: item.ContentType,
			EvidenceProfileDigest: item.EvidenceProfile.ProfileDigest, EvidenceEnvelopeDigest: item.ContentDigest,
			Representation: "content_addressed", ImmutableDescriptor: &guarantor.ImmutableEvidenceDescriptorV1{
				ContentType: item.ContentType, ContentDigest: item.ContentDigest, ContentSize: item.ContentSize,
				RetrievalPolicyDigest: item.DisclosurePolicyDigest}}
	}
	sort.Slice(items, func(i, j int) bool {
		left, _ := codec.Marshal(items[i])
		right, _ := codec.Marshal(items[j])
		return string(left) < string(right)
	})
	return guarantor.CanonicalGuarantorEvidenceSetV1{SchemaVersion: 1, Purpose: "claim-decision-evidence", ContextDigest: claimDigest, Items: items}
}

func fallbackReasonRule(value guarantor.DeterministicClaimTerminalFallbackV1, outcome string) (guarantor.DeterministicFallbackReasonRuleV1, bool) {
	for _, rule := range value.ReasonRules {
		if rule.OutcomeCase == outcome {
			return rule, true
		}
	}
	return guarantor.DeterministicFallbackReasonRuleV1{}, false
}

func safeAddUnix(left, right uint64) (uint64, bool) {
	result := left + right
	return result, result >= left
}
