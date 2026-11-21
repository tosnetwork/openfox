package earning

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	guarantor "github.com/tosnetwork/ai/protocol/pkg/agentguarantor"
)

func revisionEpochTestCut(epoch, prior, frozen uint64, root string) guarantor.ClaimIngressAdmissionCutProofV1 {
	return guarantor.ClaimIngressAdmissionCutProofV1{SchemaVersion: 1, CutKind: "claim_revisions",
		RevisionEpoch: epoch, PriorEpochStateRevision: prior, FrozenEpochStateRevision: frozen,
		AdmissionLogRoot: "sha256:" + strings.Repeat(root, 64)}
}

func revisionEpochTestAdmission(cut guarantor.ClaimIngressAdmissionCutProofV1) guarantor.AuthorizedClaimDecisionAdmissionReceiptV1 {
	return guarantor.AuthorizedClaimDecisionAdmissionReceiptV1{
		Body: guarantor.ClaimDecisionAdmissionReceiptBodyV1{FrozenRevisionEpoch: cut.RevisionEpoch,
			PriorRevisionEpochStateRevision: cut.PriorEpochStateRevision, FrozenRevisionEpochStateRevision: cut.FrozenEpochStateRevision},
		ClaimRevisionIngressCutProof: cut}
}

func TestDecisionAdmissionFreezesOrReusesTheRevisionEpoch(t *testing.T) {
	open := GuarantorRevisionEpochState{Epoch: 2, State: revisionEpochOpen, StateRevision: 3}
	freezingCut := revisionEpochTestCut(2, 3, 4, "a")
	frozen, err := applyDecisionRevisionEpochCAS(open, revisionEpochTestAdmission(freezingCut))
	if err != nil || frozen.State != revisionEpochFrozen || frozen.Epoch != 2 || frozen.StateRevision != 4 ||
		frozen.FrozenCut == nil || !sameJSON(*frozen.FrozenCut, freezingCut) {
		t.Fatalf("freezing the open epoch: state=%#v err=%v", frozen, err)
	}
	reused, err := applyDecisionRevisionEpochCAS(frozen, revisionEpochTestAdmission(freezingCut))
	if err != nil || !sameJSON(reused, frozen) {
		t.Fatalf("reusing the frozen epoch: state=%#v err=%v", reused, err)
	}

	stale := map[string]struct {
		state GuarantorRevisionEpochState
		cut   guarantor.ClaimIngressAdmissionCutProofV1
	}{
		"open epoch, stale prior state revision": {open, revisionEpochTestCut(2, 2, 3, "a")},
		"open epoch, another epoch":              {open, revisionEpochTestCut(3, 3, 4, "a")},
		"open epoch, frozen revision skipped":    {open, revisionEpochTestCut(2, 3, 5, "a")},
		"frozen epoch, another cut":              {frozen, revisionEpochTestCut(2, 3, 4, "b")},
		"frozen epoch, a second freeze":          {frozen, revisionEpochTestCut(2, 4, 5, "a")},
		"frozen epoch, another epoch":            {frozen, revisionEpochTestCut(1, 3, 4, "a")},
	}
	for name, test := range stale {
		if _, err := applyDecisionRevisionEpochCAS(test.state, revisionEpochTestAdmission(test.cut)); err == nil ||
			!strings.Contains(err.Error(), "revision epoch is stale") {
			t.Errorf("%s: got %v, want a stale-epoch refusal", name, err)
		}
	}
	// A body that disagrees with its own cut is refused even when the cut fits.
	mismatched := revisionEpochTestAdmission(freezingCut)
	mismatched.Body.PriorRevisionEpochStateRevision = 2
	if _, err := applyDecisionRevisionEpochCAS(open, mismatched); err == nil {
		t.Error("a decision body disagreeing with its cut froze the epoch")
	}
}

func TestTransitionsReopenTheRevisionEpochExceptOnTheLatePath(t *testing.T) {
	frozen := GuarantorRevisionEpochState{Epoch: 2, State: revisionEpochFrozen, StateRevision: 4,
		FrozenCut: &guarantor.ClaimIngressAdmissionCutProofV1{RevisionEpoch: 2}}
	transition := func(kind, path string) guarantor.AuthorizedClaimStateTransitionReceiptV1 {
		var receipt guarantor.AuthorizedClaimStateTransitionReceiptV1
		receipt.Body.TransitionKind = kind
		receipt.DecisionAdmissionProof.AuthorizedClaimDecision.Body.DecisionPath = path
		return receipt
	}
	for _, kind := range []string{"challenge_admission", "nonterminal_response_admission"} {
		next, err := reopenRevisionEpochAfter(frozen, transition(kind, "initial"))
		if err != nil || next.State != revisionEpochOpen || next.Epoch != 3 || next.StateRevision != 5 || next.FrozenCut != nil {
			t.Errorf("%s: state=%#v err=%v, want the next open epoch", kind, next, err)
		}
	}
	for name, receipt := range map[string]guarantor.AuthorizedClaimStateTransitionReceiptV1{
		"challenge of a late-recovery candidate": transition("challenge_admission", "late_recovery_terminal_fallback"),
		"challenge close":                        transition("challenge_close", "initial"),
	} {
		next, err := reopenRevisionEpochAfter(frozen, receipt)
		if err != nil || !sameJSON(next, frozen) {
			t.Errorf("%s: state=%#v err=%v, want the frozen epoch kept", name, next, err)
		}
	}
	open := GuarantorRevisionEpochState{Epoch: 2, State: revisionEpochOpen, StateRevision: 3}
	if _, err := reopenRevisionEpochAfter(open, transition("challenge_admission", "initial")); err == nil {
		t.Error("a transition reopened an epoch that was never frozen")
	}
}

func TestJournalServesImmutableEvidenceAndFailsClosed(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "guarantor")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenGuarantorJournal(directory, "owner:guarantor", "agent:guarantor")
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	receipt := guarantor.ClaimIngressAdmissionCutProofV1{SchemaVersion: 1, CutKind: "initial_claims",
		AdmissionLogRoot: "sha256:" + strings.Repeat("c", 64)}
	wire, err := guarantor.Canonical(receipt)
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("d", 64)
	position := GuarantorCoveragePosition{}
	if err := storeImmutableEvidence(&position, guarantorClaimFilingCloseMediaType, digest, receipt); err != nil {
		t.Fatal(err)
	}
	if err := storeImmutableEvidence(&position, guarantorClaimFilingCloseMediaType, digest, receipt); err != nil {
		t.Fatalf("storing the same receipt twice was refused: %v", err)
	}
	other := receipt
	other.CutKind = "claim_revisions"
	if err := storeImmutableEvidence(&position, guarantorClaimFilingCloseMediaType, digest, other); err == nil {
		t.Fatal("a different receipt was stored under an existing digest")
	}
	journal.mu.Lock()
	journal.doc.Coverages["sha256:"+strings.Repeat("e", 64)] = position
	journal.mu.Unlock()

	descriptor := guarantor.ImmutableEvidenceDescriptorV1{ContentType: guarantorClaimFilingCloseMediaType,
		ContentDigest: digest, ContentSize: uint64(len(wire))}
	resolver := GuarantorJournalEvidenceResolver{Journal: journal}
	served, err := resolver.ResolveImmutableGuarantorEvidence(descriptor)
	if err != nil || string(served) != string(wire) {
		t.Fatalf("the stored receipt was not served exactly: err=%v", err)
	}
	refusals := map[string]guarantor.ImmutableEvidenceDescriptorV1{}
	missing := descriptor
	missing.ContentDigest = "sha256:" + strings.Repeat("f", 64)
	refusals["missing"] = missing
	otherType := descriptor
	otherType.ContentType = guarantorDecisionAdmissionMediaType
	refusals["another media type"] = otherType
	otherSize := descriptor
	otherSize.ContentSize++
	refusals["another length"] = otherSize
	oversized := descriptor
	oversized.ContentSize = guarantor.MaxCanonicalObjectBytes + 1
	refusals["oversized"] = oversized
	empty := descriptor
	empty.ContentSize = 0
	refusals["empty"] = empty
	for name, test := range refusals {
		if _, err := resolver.ResolveImmutableGuarantorEvidence(test); err == nil {
			t.Errorf("%s: the resolver served a receipt", name)
		}
	}
	if _, err := (GuarantorJournalEvidenceResolver{}).ResolveImmutableGuarantorEvidence(descriptor); err == nil {
		t.Error("a resolver without a journal served a receipt")
	}
}
