package earning

import (
	"errors"

	commerce "github.com/tosnetwork/ai/protocol/pkg/agentcommerce"
	guarantor "github.com/tosnetwork/ai/protocol/pkg/agentguarantor"
)

// A coordinator call commits its receipt to the journal before it returns it.
// A caller that never saw the return, because the process stopped or the
// commit lost its directory sync, repeats the same request. By then the head
// the request was made against has moved, so building the receipt again is
// refused. The functions here find the committed receipt instead, by the
// identity of the request: the envelope digest of the object the caller
// submitted. They sign nothing and commit nothing.
//
// Each returns found=false when the journal holds no receipt at the head the
// request names, which leaves the request to the coordinator's ordinary path,
// and an error when the head holds the receipt of a different request.

// errGuarantorJournalAheadOfAuthority reports a committed receipt whose action
// the authority does not hold as terminal. A receipt is committed only after
// its action is terminal, so this is a damaged or foreign authority store and
// the receipt is not returned.
var errGuarantorJournalAheadOfAuthority = errors.New("Guarantor journal is ahead of its action authority")

// committedActionResolution returns the terminal resolution of the action a
// committed receipt names.
func (coordinator *GuarantorProviderCoordinator) committedActionResolution(stableActionID,
	exactRequestDigest string,
) (commerce.ActionResolution, error) {
	resolution := coordinator.Authority.Resolve(stableActionID, exactRequestDigest)
	if resolution.State != commerce.ActionTerminal {
		return resolution, errGuarantorJournalAheadOfAuthority
	}
	return resolution, nil
}

// committedCoverageActivation returns the activation evidence committed for a
// coverage when the repeated request activates the same acceptance with the
// same prerequisite set. An activation of that coverage under another
// acceptance receipt or another prerequisite set is a conflict.
func (coordinator *GuarantorProviderCoordinator) committedCoverageActivation(coverage GuarantorCoveragePosition,
	input GuarantorActivateCoverageInput,
) (guarantor.AuthorizedCoverageActivationEvidenceV1, commerce.ActionResolution, bool, error) {
	if coverage.ActivationEvidence == nil {
		return guarantor.AuthorizedCoverageActivationEvidenceV1{}, commerce.ActionResolution{}, false, nil
	}
	stored := *coverage.ActivationEvidence
	acceptanceDigest, err := guarantor.CoverageAcceptanceReceiptDigestV1(input.AcceptanceReceipt)
	if err != nil {
		return guarantor.AuthorizedCoverageActivationEvidenceV1{}, commerce.ActionResolution{}, false, err
	}
	prerequisiteDigest := ""
	if input.PrerequisiteEvidenceSet != nil {
		prerequisiteDigest, err = guarantor.CanonicalGuarantorEvidenceSetDigestV1(*input.PrerequisiteEvidenceSet)
		if err != nil {
			return guarantor.AuthorizedCoverageActivationEvidenceV1{}, commerce.ActionResolution{}, false, err
		}
	}
	if stored.Body.AcceptanceReceiptDigest != acceptanceDigest ||
		stored.Body.PrerequisiteEvidenceSetDigest != prerequisiteDigest {
		return guarantor.AuthorizedCoverageActivationEvidenceV1{}, commerce.ActionResolution{}, false,
			errors.New("Guarantor activation conflicts with the activation committed for its coverage")
	}
	resolution, err := coordinator.committedActionResolution(stored.Body.StableActionID, stored.Body.ExactRequestDigest)
	if err != nil {
		return guarantor.AuthorizedCoverageActivationEvidenceV1{}, resolution, false, err
	}
	return stored, resolution, true, nil
}

// committedClaimAdmission returns the receipts committed for claim when claim
// is the current revision of its claim. An earlier revision is not replayed:
// the lineage has advanced past it and the ordinary path refuses it.
func (coordinator *GuarantorProviderCoordinator) committedClaimAdmission(coverage GuarantorCoveragePosition,
	claim guarantor.AuthorizedCoverageClaimV1,
) (GuarantorClaimAdmissionResult, bool, error) {
	admission, found := coverage.ClaimAdmissionReceipts[guarantorClaimRevisionKey(claim.Body.ClaimID,
		claim.Body.ClaimRevision)]
	record, recordFound := coverage.Claims[claim.Body.ClaimID]
	if !found || !recordFound || record.ClaimRevision != claim.Body.ClaimRevision {
		return GuarantorClaimAdmissionResult{}, false, nil
	}
	claimDigest, err := guarantor.ClaimEnvelopeDigest(claim)
	if err != nil {
		return GuarantorClaimAdmissionResult{}, false, err
	}
	if admission.Body.AuthorizedClaimEnvelopeDigest != claimDigest {
		return GuarantorClaimAdmissionResult{}, false,
			errors.New("Guarantor claim conflicts with the claim admitted under its revision")
	}
	ingress := admission.AuthorizedClaimIngressReceipt
	ingressResolution, err := coordinator.committedActionResolution(ingress.Body.StableActionID,
		ingress.Body.ExactRequestDigest)
	if err != nil {
		return GuarantorClaimAdmissionResult{IngressResolution: ingressResolution}, false, err
	}
	admissionResolution, err := coordinator.committedActionResolution(admission.Body.StableActionID,
		admission.Body.ExactRequestDigest)
	if err != nil {
		return GuarantorClaimAdmissionResult{
			IngressResolution:   ingressResolution,
			AdmissionResolution: admissionResolution,
		}, false, err
	}
	return GuarantorClaimAdmissionResult{
		ClaimDigest: claimDigest, IngressReceipt: ingress,
		AdmissionReceipt: admission, IngressResolution: ingressResolution,
		AdmissionResolution: admissionResolution,
	}, true, nil
}

// committedDecisionAdmission returns the receipt committed for decision when
// decision is the claim's current decision head. Another decision with the
// head's sequence is a conflict; a decision with another sequence is left to
// the ordinary path, which admits a successor and refuses everything else.
func (coordinator *GuarantorProviderCoordinator) committedDecisionAdmission(position GuarantorCoveragePosition,
	decision guarantor.AuthorizedClaimDecisionV1,
) (GuarantorDecisionAdmissionResult, bool, error) {
	stored, found := position.DecisionAdmissionReceipts[decision.Body.ClaimID]
	if !found || stored.AuthorizedClaimDecision.Body.DecisionSequence != decision.Body.DecisionSequence {
		return GuarantorDecisionAdmissionResult{}, false, nil
	}
	decisionDigest, err := guarantor.ClaimDecisionDigestV1(decision)
	if err != nil {
		return GuarantorDecisionAdmissionResult{}, false, err
	}
	storedDigest, err := guarantor.ClaimDecisionDigestV1(stored.AuthorizedClaimDecision)
	if err != nil {
		return GuarantorDecisionAdmissionResult{}, false, err
	}
	if storedDigest != decisionDigest {
		return GuarantorDecisionAdmissionResult{}, false,
			errors.New("Guarantor decision conflicts with the decision admitted at its sequence")
	}
	resolution, err := coordinator.committedActionResolution(stored.Body.StableActionID, stored.Body.ExactRequestDigest)
	if err != nil {
		return GuarantorDecisionAdmissionResult{Resolution: resolution}, false, err
	}
	return GuarantorDecisionAdmissionResult{Receipt: stored, Resolution: resolution}, true, nil
}

// claimTransitionEvidenceSet returns the evidence set of a claim state
// transition: the caller's, or, when the caller supplies none, the one naming
// the decision admission alone. Its purpose and context follow from the
// transition kind and the decision admission, whatever the caller set.
func claimTransitionEvidenceSet(input GuarantorTransitionClaimInput, terms guarantor.CoverageTermsV1,
	decisionAdmissionDigest string,
) (guarantor.CanonicalGuarantorEvidenceSetV1, error) {
	evidenceSet := input.TransitionEvidenceSet
	if len(evidenceSet.Items) == 0 {
		admissionBytes, err := guarantor.Canonical(input.DecisionAdmissionReceipt)
		if err != nil {
			return guarantor.CanonicalGuarantorEvidenceSetV1{}, err
		}
		const contentType = "application/vnd.tos.service.agent-guarantor-claim-decision-admission.v1+cbor"
		evidenceSet = guarantor.CanonicalGuarantorEvidenceSetV1{
			SchemaVersion: 1,
			Items: []guarantor.CanonicalGuarantorEvidenceItemV1{{
				ContentType:            contentType,
				EvidenceProfileDigest:  terms.DecisionAdmissionProfile.ProfileDigest,
				EvidenceEnvelopeDigest: decisionAdmissionDigest, Representation: "content_addressed",
				ImmutableDescriptor: &guarantor.ImmutableEvidenceDescriptorV1{
					ContentType:   contentType,
					ContentDigest: decisionAdmissionDigest, ContentSize: uint64(len(admissionBytes)),
					RetrievalPolicyDigest: terms.DecisionAdmissionProfile.ProfileDigest,
				},
			}},
		}
	}
	switch input.TransitionKind {
	case "challenge_close":
		evidenceSet.Purpose = "claim-challenge-close"
	case "challenge_admission":
		evidenceSet.Purpose = "claim-challenge-admission"
	case "nonterminal_response_admission":
		evidenceSet.Purpose = "claim-nonterminal-response-admission"
	default:
		return guarantor.CanonicalGuarantorEvidenceSetV1{}, errors.New("Guarantor claim transition kind is unknown")
	}
	evidenceSet.ContextDigest = decisionAdmissionDigest
	return evidenceSet, nil
}

// committedClaimTransition returns the receipt committed for a claim state
// transition when the claim's current decision head, named by
// decisionAdmissionDigest, already holds a transition. The request is the
// same when it asks for the same kind with the same evidence set; any other
// transition of that head is a conflict.
func (coordinator *GuarantorProviderCoordinator) committedClaimTransition(position GuarantorCoveragePosition,
	input GuarantorTransitionClaimInput, claimID, decisionAdmissionDigest string,
) (GuarantorClaimTransitionResult, bool, error) {
	stored, found := position.ClaimStateTransitionReceipts[claimID]
	if !found || stored.DecisionAdmissionProof.ReceiptEnvelopeDigest != decisionAdmissionDigest {
		return GuarantorClaimTransitionResult{}, false, nil
	}
	evidenceSet, err := claimTransitionEvidenceSet(input, position.Terms, decisionAdmissionDigest)
	if err != nil {
		return GuarantorClaimTransitionResult{}, false, err
	}
	evidenceSetDigest, err := guarantor.CanonicalGuarantorEvidenceSetDigestV1(evidenceSet)
	if err != nil {
		return GuarantorClaimTransitionResult{}, false, err
	}
	storedSetDigest, err := guarantor.CanonicalGuarantorEvidenceSetDigestV1(stored.TransitionEvidenceSet)
	if err != nil {
		return GuarantorClaimTransitionResult{}, false, err
	}
	if stored.Body.TransitionKind != input.TransitionKind || storedSetDigest != evidenceSetDigest {
		return GuarantorClaimTransitionResult{}, false,
			errors.New("Guarantor claim transition conflicts with the transition committed for its decision head")
	}
	resolution, err := coordinator.committedActionResolution(stored.Body.StableActionID, stored.Body.ExactRequestDigest)
	if err != nil {
		return GuarantorClaimTransitionResult{Resolution: resolution}, false, err
	}
	return GuarantorClaimTransitionResult{Receipt: stored, Resolution: resolution}, true, nil
}

// committedDecisionApplication returns the receipt committed for applying the
// decision admission and terminal transition named by their envelope digests.
// An application of the claim's current decision head under another terminal
// transition is a conflict.
func (coordinator *GuarantorProviderCoordinator) committedDecisionApplication(coverage GuarantorCoveragePosition,
	claimID, decisionAdmissionDigest, transitionDigest string,
) (GuarantorDecisionApplicationResult, bool, error) {
	stored, found := coverage.DecisionApplicationReceipts[claimID]
	if !found || stored.Body.ClaimDecisionAdmissionReceiptDigest != decisionAdmissionDigest {
		return GuarantorDecisionApplicationResult{}, false, nil
	}
	if stored.Body.TerminalClaimStateTransitionReceiptDigest != transitionDigest {
		return GuarantorDecisionApplicationResult{}, false,
			errors.New("Guarantor decision application conflicts with the application committed for its decision")
	}
	resolution, err := coordinator.committedActionResolution(stored.Body.StableActionID, stored.Body.ExactRequestDigest)
	if err != nil {
		return GuarantorDecisionApplicationResult{Resolution: resolution}, false, err
	}
	return GuarantorDecisionApplicationResult{
		Payouts: stored.MaterializedPayoutObligationSet, Receipt: stored,
		Resolution: resolution,
	}, true, nil
}
