package earning

import (
	"errors"
	"fmt"

	guarantor "github.com/tosnetwork/ai/protocol/pkg/agentguarantor"
)

// GuarantorRevisionEpochState is the sink's state of one claim's revision
// ingress epoch. Revision ingress is admitted only while the epoch is open;
// a decision admission freezes it (open to frozen) or, from a head that left
// it frozen, reuses it unchanged; a challenge or nonterminal-response
// transition opens the next epoch, except the challenge of a late-recovery
// candidate, which leaves it frozen.
type GuarantorRevisionEpochState struct {
	Epoch         uint64 `json:"epoch"`
	State         string `json:"state"`
	StateRevision uint64 `json:"state_revision"`
	// FrozenCut is the cut the freezing admission recorded; a reuse admission
	// carries it byte for byte.
	FrozenCut *guarantor.ClaimIngressAdmissionCutProofV1 `json:"frozen_cut,omitempty"`
}

const (
	revisionEpochOpen   = "open"
	revisionEpochFrozen = "frozen"
)

// RevisionEpoch returns a claim's current revision epoch.
func (journal *GuarantorJournal) RevisionEpoch(agreementDigest, claimID string) (GuarantorRevisionEpochState, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if err := journal.ensureAttached(); err != nil {
		return GuarantorRevisionEpochState{}, err
	}
	position, found := journal.doc.Coverages[agreementDigest]
	if _, claimFound := position.Claims[claimID]; !found || !claimFound {
		return GuarantorRevisionEpochState{}, errors.New("Guarantor revision epoch has no admitted claim")
	}
	state := revisionEpochOf(position, claimID)
	if state.FrozenCut != nil {
		cut := *state.FrozenCut
		state.FrozenCut = &cut
	}
	return state, nil
}

// revisionEpochExpectationAndCut is what a decision admission names for the
// claim's current epoch: the open epoch with a fresh cut, or the frozen
// epoch with the cut that froze it.
func (coordinator *GuarantorProviderCoordinator) revisionEpochExpectationAndCut(agreementDigest, obligationID,
	claimID string, claimRevision uint64, now uint64) (guarantor.ClaimRevisionEpochExpectationV1,
	guarantor.ClaimIngressAdmissionCutProofV1, error) {
	state, err := coordinator.Journal.RevisionEpoch(agreementDigest, claimID)
	if err != nil {
		return guarantor.ClaimRevisionEpochExpectationV1{}, guarantor.ClaimIngressAdmissionCutProofV1{}, err
	}
	var cut guarantor.ClaimIngressAdmissionCutProofV1
	expected := state.StateRevision
	if state.State == revisionEpochFrozen {
		if state.FrozenCut == nil {
			return guarantor.ClaimRevisionEpochExpectationV1{}, guarantor.ClaimIngressAdmissionCutProofV1{},
				errors.New("Guarantor frozen revision epoch has no cut")
		}
		cut = *state.FrozenCut
	} else {
		cut, err = coordinator.Journal.ClaimRevisionAdmissionCut(agreementDigest, claimID, now)
		if err != nil {
			return guarantor.ClaimRevisionEpochExpectationV1{}, guarantor.ClaimIngressAdmissionCutProofV1{}, err
		}
	}
	return guarantor.ClaimRevisionEpochExpectationV1{SchemaVersion: 1,
		CoverageAgreementBodyDigest: agreementDigest, CoverageObligationID: obligationID, ClaimID: claimID,
		RevisionEpoch: cut.RevisionEpoch, RevisionIngressLogID: cut.ClaimIngressLogID, ExpectedEpochState: state.State,
		ExpectedEpochStateRevision: expected, ExpectedClaimRevision: claimRevision}, cut, nil
}

// lateRecoveryCandidateMarker is the late filing-close digest a decision
// following predecessor carries: the challenged late-recovery candidate's own
// digest, or none for any other head.
func lateRecoveryCandidateMarker(predecessor *guarantor.AuthorizedClaimStateTransitionReceiptV1) string {
	if predecessor == nil || predecessor.Body.TransitionKind != "challenge_admission" ||
		predecessor.DecisionAdmissionProof.AuthorizedClaimDecision.Body.DecisionPath != "late_recovery_terminal_fallback" {
		return ""
	}
	return predecessor.DecisionAdmissionProof.ReceiptBody.LateFilingCloseReceiptDigest
}

// revisionEpochOf is the claim's current epoch. Every claim's epoch is
// recorded from its first admission; a claim without a record has no epoch
// state, which every admission and cut refuses instead of guessing one.
func revisionEpochOf(position GuarantorCoveragePosition, claimID string) GuarantorRevisionEpochState {
	return position.RevisionEpochs[claimID]
}

// applyDecisionRevisionEpochCAS is the sink-side compare-and-swap of a
// decision admission on the claim's revision epoch. From an open epoch the
// admission must freeze exactly it: same epoch, prior state revision equal to
// the current one, frozen state revision one higher, and a cut of that epoch.
// From a frozen epoch it must reuse it: same epoch and state revision, and the
// frozen cut byte for byte.
func applyDecisionRevisionEpochCAS(state GuarantorRevisionEpochState,
	receipt guarantor.AuthorizedClaimDecisionAdmissionReceiptV1) (GuarantorRevisionEpochState, error) {
	body := receipt.Body
	cut := receipt.ClaimRevisionIngressCutProof
	switch state.State {
	case revisionEpochOpen:
		if body.FrozenRevisionEpoch != state.Epoch || cut.RevisionEpoch != state.Epoch ||
			body.PriorRevisionEpochStateRevision != state.StateRevision ||
			body.FrozenRevisionEpochStateRevision != state.StateRevision+1 ||
			cut.PriorEpochStateRevision != state.StateRevision || cut.FrozenEpochStateRevision != state.StateRevision+1 {
			return state, errors.New("Guarantor decision admission's revision epoch is stale: it does not freeze the open epoch")
		}
		frozenCut := cut
		return GuarantorRevisionEpochState{Epoch: state.Epoch, State: revisionEpochFrozen,
			StateRevision: state.StateRevision + 1, FrozenCut: &frozenCut}, nil
	case revisionEpochFrozen:
		if state.FrozenCut == nil || body.FrozenRevisionEpoch != state.Epoch ||
			body.FrozenRevisionEpochStateRevision != state.StateRevision || !sameJSON(*state.FrozenCut, cut) {
			return state, errors.New("Guarantor decision admission's revision epoch is stale: it does not reuse the frozen epoch")
		}
		return state, nil
	default:
		return state, fmt.Errorf("Guarantor revision epoch state %q is unknown", state.State)
	}
}

// reopenRevisionEpochAfter returns the epoch a transition leaves. A challenge
// or nonterminal response opens the next epoch, except the challenge of a
// late-recovery candidate, which keeps revision ingress frozen.
func reopenRevisionEpochAfter(state GuarantorRevisionEpochState,
	receipt guarantor.AuthorizedClaimStateTransitionReceiptV1) (GuarantorRevisionEpochState, error) {
	kind := receipt.Body.TransitionKind
	if kind != "challenge_admission" && kind != "nonterminal_response_admission" {
		return state, nil
	}
	if receipt.DecisionAdmissionProof.AuthorizedClaimDecision.Body.DecisionPath == "late_recovery_terminal_fallback" {
		return state, nil
	}
	if state.State != revisionEpochFrozen {
		return state, errors.New("Guarantor transition reopens a revision epoch that is not frozen")
	}
	next, fits := safeAddUnix(state.Epoch, 1)
	revision, revisionFits := safeAddUnix(state.StateRevision, 1)
	if !fits || !revisionFits {
		return state, errors.New("Guarantor revision epoch counter overflows")
	}
	return GuarantorRevisionEpochState{Epoch: next, State: revisionEpochOpen, StateRevision: revision}, nil
}
