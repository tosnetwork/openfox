package earning

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	commerce "github.com/tosnetwork/ai/protocol/pkg/agentcommerce"
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

// openTestGuarantorJournal opens a fresh journal in a private directory.
func openTestGuarantorJournal(t *testing.T) (*GuarantorJournal, string) {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "guarantor")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenGuarantorJournal(directory, "owner:guarantor", "agent:guarantor")
	if err != nil {
		t.Fatal(err)
	}
	closeGuarantorJournalOnCleanup(t, journal)
	return journal, directory
}

// openTestGuarantorJournalErr reopens directory's journal for a load check
// and returns only the load error; a journal that does open is closed when
// the test ends.
func openTestGuarantorJournalErr(t *testing.T, directory string) error {
	t.Helper()
	journal, err := OpenGuarantorJournal(directory, "owner:guarantor", "agent:guarantor")
	if err == nil {
		closeGuarantorJournalOnCleanup(t, journal)
	}
	return err
}

// closeGuarantorJournalOnCleanup closes a journal a test opened however the
// test ends. The journal holds a process-wide economic-domain lock, so a
// journal left open by one failing test would fail every later test that
// opens the same domain with a lock error instead of its own result.
func closeGuarantorJournalOnCleanup(t *testing.T, journal *GuarantorJournal) {
	t.Helper()
	t.Cleanup(func() { _ = journal.Close() })
}

// rewriteTestGuarantorJournal persists a changed copy of the journal document
// and closes the journal, so the next open loads exactly that document.
func rewriteTestGuarantorJournal(t *testing.T, journal *GuarantorJournal, change func(*guarantorJournalDocument)) {
	t.Helper()
	journal.mu.Lock()
	doc := cloneGuarantorDocument(journal.doc)
	change(&doc)
	err := journal.persist(doc)
	journal.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
}

// testCoverageWithClaim is a minimal loadable coverage position holding one
// claim whose current decision admission froze epoch 1 with
// testFrozenCut; its epoch record is left for the test to set.
func testCoverageWithClaim(claimID string) GuarantorCoveragePosition {
	decision := revisionEpochTestAdmission(testFrozenCut)
	decision.Body.ClaimID = claimID
	return GuarantorCoveragePosition{
		Claims:                    map[string]guarantor.ClaimRecord{claimID: {ClaimID: claimID, ClaimRevision: 1, ClaimStateRevision: 2}},
		Decisions:                 map[string]guarantor.AuthorizedClaimDecisionV1{},
		DecisionAdmissionReceipts: map[string]guarantor.AuthorizedClaimDecisionAdmissionReceiptV1{claimID: decision},
		MaterializedPayouts:       map[string]guarantor.MaterializedPayoutObligationSetV1{},
		PayoutEvidence:            map[string]commerce.AgreementPaymentEvidence{},
		PayoutRequests:            map[string]commerce.AgreementPaymentRequest{},
		PaidByObligation:          map[string]string{},
		ClaimAdmissionSequence:    map[string]uint64{claimID: 1},
		ClaimAdmissionLogRoot:     "sha256:" + strings.Repeat("a", 64),
	}
}

// testFrozenCut is the cut testCoverageWithClaim's decision admission froze.
var testFrozenCut = revisionEpochTestCut(1, 1, 2, "a")

// testFrozenEpoch is the epoch record testCoverageWithClaim's receipts imply.
func testFrozenEpoch() GuarantorRevisionEpochState {
	cut := testFrozenCut
	return GuarantorRevisionEpochState{Epoch: 1, State: revisionEpochFrozen, StateRevision: 2, FrozenCut: &cut}
}

func TestJournalRefusesTheRetiredSchemaAndMissingEpochs(t *testing.T) {
	journal, directory := openTestGuarantorJournal(t)
	rewriteTestGuarantorJournal(t, journal, func(doc *guarantorJournalDocument) {
		doc.Schema = retiredGuarantorJournalSchema
	})
	if err := openTestGuarantorJournalErr(t, directory); err == nil ||
		!strings.Contains(err.Error(), "retired v1 schema") {
		t.Fatalf("a v1 journal was not refused with its reason: %v", err)
	}
	journal, directory = openTestGuarantorJournal(t)
	rewriteTestGuarantorJournal(t, journal, func(doc *guarantorJournalDocument) {
		doc.Schema = retiredGuarantorJournalSchemaV2
	})
	if err := openTestGuarantorJournalErr(t, directory); err == nil || !strings.Contains(err.Error(), "retired v2 schema") {
		t.Fatalf("a v2 journal was not refused with its reason: %v", err)
	}
	journal, directory = openTestGuarantorJournal(t)
	rewriteTestGuarantorJournal(t, journal, func(doc *guarantorJournalDocument) {
		doc.Schema = retiredGuarantorJournalSchemaV3
	})
	err := openTestGuarantorJournalErr(t, directory)
	if err == nil || !strings.Contains(err.Error(), "retired v3 schema") {
		t.Fatalf("a v3 journal was not refused with its reason: %v", err)
	}

	claimID := "sha256:" + strings.Repeat("b", 64)
	agreement := "sha256:" + strings.Repeat("c", 64)
	journal, directory = openTestGuarantorJournal(t)
	rewriteTestGuarantorJournal(t, journal, func(doc *guarantorJournalDocument) {
		doc.Coverages[agreement] = testCoverageWithClaim(claimID)
	})
	if err := openTestGuarantorJournalErr(t, directory); err == nil ||
		!strings.Contains(err.Error(), "no valid revision epoch record") {
		t.Fatalf("a claim with a decision admission but no epoch record was loaded: %v", err)
	}

	journal, directory = openTestGuarantorJournal(t)
	rewriteTestGuarantorJournal(t, journal, func(doc *guarantorJournalDocument) {
		position := testCoverageWithClaim(claimID)
		position.RevisionEpochs = map[string]GuarantorRevisionEpochState{claimID: testFrozenEpoch()}
		doc.Coverages[agreement] = position
	})
	reopened, err := OpenGuarantorJournal(directory, "owner:guarantor", "agent:guarantor")
	if err != nil {
		t.Fatalf("a v2 journal with its epoch record was refused: %v", err)
	}
	closeGuarantorJournalOnCleanup(t, reopened)
	state, err := reopened.RevisionEpoch(agreement, claimID)
	if err != nil || state.State != revisionEpochFrozen || state.StateRevision != 2 {
		t.Fatalf("the loaded epoch is %#v, err=%v", state, err)
	}
	if _, err := reopened.ClaimRevisionAdmissionCut(agreement, claimID, 1); err == nil {
		t.Fatal("the loaded frozen epoch was cut again")
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
	closeGuarantorJournalOnCleanup(t, journal)
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
	holder := "sha256:" + strings.Repeat("e", 64)
	neighbour := "sha256:" + strings.Repeat("9", 64)
	journal.mu.Lock()
	journal.doc.Coverages[holder] = position
	journal.doc.Coverages[neighbour] = GuarantorCoveragePosition{ImmutableEvidence: map[string]GuarantorStoredEvidence{}}
	journal.mu.Unlock()
	// The receipt is served from its own file, which the commit writes.
	if _, err := journal.ImmutableEvidence(holder, guarantor.ImmutableEvidenceDescriptorV1{
		ContentType: guarantorClaimFilingCloseMediaType, ContentDigest: digest, ContentSize: uint64(len(wire))}); err == nil {
		t.Fatal("a receipt was served before the commit that writes it")
	}
	journal.mu.Lock()
	err = journal.commit(journal.doc)
	journal.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	descriptor := guarantor.ImmutableEvidenceDescriptorV1{ContentType: guarantorClaimFilingCloseMediaType,
		ContentDigest: digest, ContentSize: uint64(len(wire))}
	resolver := GuarantorJournalEvidenceResolver{Journal: journal, AgreementDigest: holder}
	// Retrieval is scoped to the Agreement being verified: another coverage's
	// receipt, and a coverage the journal does not hold, are not served.
	for name, agreement := range map[string]string{"another coverage": neighbour,
		"an unknown coverage": "sha256:" + strings.Repeat("8", 64), "no Agreement": ""} {
		scoped := GuarantorJournalEvidenceResolver{Journal: journal, AgreementDigest: agreement}
		if _, err := scoped.ResolveImmutableGuarantorEvidence(descriptor); err == nil {
			t.Errorf("%s: the receipt was served outside its coverage", name)
		}
	}
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

// TestJournalLoadCrossChecksTheRevisionEpochAgainstItsReceipts: a loaded
// claim's epoch record must be exactly what its stored decision admission and
// the transition after it imply: frozen with that admission's cut and frozen
// fields, or the next open epoch after a reopening transition.
func TestJournalLoadCrossChecksTheRevisionEpochAgainstItsReceipts(t *testing.T) {
	claimID := "sha256:" + strings.Repeat("b", 64)
	agreement := "sha256:" + strings.Repeat("c", 64)
	decisionDigest, err := guarantor.ClaimDecisionAdmissionReceiptDigestV1(testCoverageWithClaim(claimID).DecisionAdmissionReceipts[claimID])
	if err != nil {
		t.Fatal(err)
	}
	transition := func(kind, path, decision string) guarantor.AuthorizedClaimStateTransitionReceiptV1 {
		var receipt guarantor.AuthorizedClaimStateTransitionReceiptV1
		receipt.Body.ClaimID, receipt.Body.TransitionKind = claimID, kind
		receipt.DecisionAdmissionProof.ReceiptEnvelopeDigest = decision
		receipt.DecisionAdmissionProof.AuthorizedClaimDecision.Body.DecisionPath = path
		return receipt
	}
	reopened := GuarantorRevisionEpochState{Epoch: 2, State: revisionEpochOpen, StateRevision: 3}
	otherCut := revisionEpochTestCut(1, 1, 2, "b")
	const contradicts, unchecked = "contradicts its receipts", "cannot be checked"
	cases := map[string]struct {
		change func(*GuarantorCoveragePosition)
		want   string
	}{
		"frozen with the decision's cut": {func(p *GuarantorCoveragePosition) {}, ""},
		"open although frozen": {func(p *GuarantorCoveragePosition) {
			p.RevisionEpochs[claimID] = GuarantorRevisionEpochState{Epoch: 1, State: revisionEpochOpen, StateRevision: 2}
		}, contradicts},
		"open in the next epoch without a reopening transition": {func(p *GuarantorCoveragePosition) {
			p.RevisionEpochs[claimID] = reopened
		}, contradicts},
		"frozen with another cut": {func(p *GuarantorCoveragePosition) {
			state := testFrozenEpoch()
			state.FrozenCut = &otherCut
			p.RevisionEpochs[claimID] = state
		}, contradicts},
		"frozen at another state revision": {func(p *GuarantorCoveragePosition) {
			state := testFrozenEpoch()
			state.StateRevision = 3
			p.RevisionEpochs[claimID] = state
		}, contradicts},
		"decision body disagrees with its cut": {func(p *GuarantorCoveragePosition) {
			decision := p.DecisionAdmissionReceipts[claimID]
			decision.Body.FrozenRevisionEpochStateRevision = 3
			p.DecisionAdmissionReceipts[claimID] = decision
		}, unchecked},
		"decision of another claim": {func(p *GuarantorCoveragePosition) {
			decision := p.DecisionAdmissionReceipts[claimID]
			decision.Body.ClaimID = agreement
			p.DecisionAdmissionReceipts[claimID] = decision
		}, unchecked},
		"open after a reopening challenge": {func(p *GuarantorCoveragePosition) {
			p.ClaimStateTransitionReceipts[claimID] = transition("challenge_admission", "initial", decisionDigest)
			p.RevisionEpochs[claimID] = reopened
		}, ""},
		"open after a nonterminal response": {func(p *GuarantorCoveragePosition) {
			p.ClaimStateTransitionReceipts[claimID] = transition("nonterminal_response_admission", "initial", decisionDigest)
			p.RevisionEpochs[claimID] = reopened
		}, ""},
		"frozen although a challenge reopened it": {func(p *GuarantorCoveragePosition) {
			p.ClaimStateTransitionReceipts[claimID] = transition("challenge_admission", "initial", decisionDigest)
		}, contradicts},
		"frozen after the challenge of a late-recovery candidate": {func(p *GuarantorCoveragePosition) {
			p.ClaimStateTransitionReceipts[claimID] = transition("challenge_admission", "late_recovery_terminal_fallback", decisionDigest)
		}, ""},
		"open after the challenge of a late-recovery candidate": {func(p *GuarantorCoveragePosition) {
			p.ClaimStateTransitionReceipts[claimID] = transition("challenge_admission", "late_recovery_terminal_fallback", decisionDigest)
			p.RevisionEpochs[claimID] = reopened
		}, contradicts},
		"frozen after a challenge close": {func(p *GuarantorCoveragePosition) {
			p.ClaimStateTransitionReceipts[claimID] = transition("challenge_close", "initial", decisionDigest)
		}, ""},
		"transition after another decision": {func(p *GuarantorCoveragePosition) {
			p.ClaimStateTransitionReceipts[claimID] = transition("challenge_admission", "initial", "sha256:"+strings.Repeat("1", 64))
			p.RevisionEpochs[claimID] = reopened
		}, unchecked},
		"no decision, first open epoch": {func(p *GuarantorCoveragePosition) {
			delete(p.DecisionAdmissionReceipts, claimID)
			p.RevisionEpochs[claimID] = GuarantorRevisionEpochState{Epoch: 1, State: revisionEpochOpen, StateRevision: 1}
		}, ""},
		"no decision, frozen": {func(p *GuarantorCoveragePosition) {
			delete(p.DecisionAdmissionReceipts, claimID)
		}, contradicts},
		"no decision, a later open epoch": {func(p *GuarantorCoveragePosition) {
			delete(p.DecisionAdmissionReceipts, claimID)
			p.RevisionEpochs[claimID] = reopened
		}, contradicts},
		"transition without a decision": {func(p *GuarantorCoveragePosition) {
			delete(p.DecisionAdmissionReceipts, claimID)
			p.ClaimStateTransitionReceipts[claimID] = transition("challenge_admission", "initial", decisionDigest)
			p.RevisionEpochs[claimID] = reopened
		}, unchecked},
	}
	for name, test := range cases {
		// Each case runs as its own subtest, so its journals are closed before
		// the next case opens the same economic domain.
		t.Run(name, func(t *testing.T) {
			journal, directory := openTestGuarantorJournal(t)
			rewriteTestGuarantorJournal(t, journal, func(doc *guarantorJournalDocument) {
				position := testCoverageWithClaim(claimID)
				position.RevisionEpochs = map[string]GuarantorRevisionEpochState{claimID: testFrozenEpoch()}
				position.ClaimStateTransitionReceipts = map[string]guarantor.AuthorizedClaimStateTransitionReceiptV1{}
				test.change(&position)
				doc.Coverages[agreement] = position
			})
			err := openTestGuarantorJournalErr(t, directory)
			if test.want == "" && err != nil {
				t.Errorf("a consistent epoch record was refused: %v", err)
			}
			if test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
				t.Errorf("got %v, want a refusal containing %q", err, test.want)
			}
		})
	}
}

// TestActivationPrerequisitesAreSuppliedExactlyAndServedFromTheJournal: every
// collateral prerequisite the set names must be supplied with its exact bytes;
// once stored and committed, the journal serves it to that coverage only, and
// before the commit the pending resolver serves exactly the pending bytes.
func TestActivationPrerequisitesAreSuppliedExactlyAndServedFromTheJournal(t *testing.T) {
	agreement := "sha256:" + strings.Repeat("c", 64)
	wire := []byte("collateral lock evidence bytes")
	lockDigest := "sha256:" + strings.Repeat("4", 64)
	item := guarantor.CanonicalGuarantorEvidenceItemV1{ContentType: guarantor.CollateralEvidenceContentTypeV1,
		EvidenceEnvelopeDigest: lockDigest, Representation: "content_addressed",
		ImmutableDescriptor: &guarantor.ImmutableEvidenceDescriptorV1{ContentType: guarantor.CollateralEvidenceContentTypeV1,
			ContentDigest: lockDigest, ContentSize: uint64(len(wire))}}
	lock := map[string]GuarantorStoredEvidence{lockDigest: {ContentType: guarantor.CollateralEvidenceContentTypeV1, Wire: wire}}
	set := &guarantor.CanonicalGuarantorEvidenceSetV1{Items: []guarantor.CanonicalGuarantorEvidenceItemV1{item}}
	supplied, err := matchActivationPrerequisites(set, lock)
	if err != nil || len(supplied) != 1 || string(supplied[lockDigest].Wire) != string(wire) {
		t.Fatalf("a supplied prerequisite was not mapped exactly: %v", err)
	}
	if none, err := guarantorActivationPrerequisites(nil, nil, nil, nil); err != nil || len(none) != 0 {
		t.Fatalf("an activation without collateral prerequisites: %v %v", none, err)
	}
	resized := item
	descriptor := *item.ImmutableDescriptor
	descriptor.ContentSize++
	resized.ImmutableDescriptor = &descriptor
	retyped := map[string]GuarantorStoredEvidence{lockDigest: {ContentType: guarantor.CollateralControlEvidenceContentTypeV1, Wire: wire}}
	withControl := map[string]GuarantorStoredEvidence{lockDigest: lock[lockDigest],
		"sha256:" + strings.Repeat("5", 64): {ContentType: guarantor.CollateralControlEvidenceContentTypeV1, Wire: []byte("control")}}
	for name, test := range map[string]struct {
		set      *guarantor.CanonicalGuarantorEvidenceSetV1
		supplied map[string]GuarantorStoredEvidence
		want     string
	}{
		"named but not supplied": {set, nil, "is not supplied with its exact bytes"},
		"supplied with another length": {&guarantor.CanonicalGuarantorEvidenceSetV1{
			Items: []guarantor.CanonicalGuarantorEvidenceItemV1{resized}}, lock, "is not supplied with its exact bytes"},
		"supplied under another media type": {set, retyped, "is not supplied with its exact bytes"},
		"supplied but not named":            {nil, lock, "is not named by the prerequisite set"},
		"control supplied but not named":    {set, withControl, "is not named by the prerequisite set"},
	} {
		if _, err := matchActivationPrerequisites(test.set, test.supplied); err == nil ||
			!strings.Contains(err.Error(), test.want) {
			t.Errorf("%s: got %v, want %q", name, err, test.want)
		}
	}

	// The journal serves a committed prerequisite to its own coverage only.
	journal, directory := openTestGuarantorJournal(t)
	journal.mu.Lock()
	stored := testCoverageWithClaim("sha256:" + strings.Repeat("b", 64))
	stored.RevisionEpochs = map[string]GuarantorRevisionEpochState{"sha256:" + strings.Repeat("b", 64): testFrozenEpoch()}
	for digest, prerequisite := range supplied {
		if err := storeImmutableWire(&stored, prerequisite.ContentType, digest, prerequisite.Wire); err != nil {
			journal.mu.Unlock()
			t.Fatal(err)
		}
	}
	conflicting := stored
	if err := storeImmutableWire(&conflicting, guarantor.CollateralEvidenceContentTypeV1, lockDigest,
		[]byte("other bytes")); err == nil {
		journal.mu.Unlock()
		t.Fatal("a prerequisite conflicting with a stored receipt was stored")
	}
	next := cloneGuarantorDocument(journal.doc)
	next.Coverages[agreement] = stored
	next.Revision++
	err = journal.commit(next)
	journal.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenGuarantorJournal(directory, "owner:guarantor", "agent:guarantor")
	if err != nil {
		t.Fatal(err)
	}
	closeGuarantorJournalOnCleanup(t, reopened)
	served, err := (GuarantorJournalEvidenceResolver{Journal: reopened, AgreementDigest: agreement}).
		ResolveImmutableGuarantorEvidence(*item.ImmutableDescriptor)
	if err != nil || string(served) != string(wire) {
		t.Fatalf("the committed prerequisite was not served from the reopened journal: %v", err)
	}
	other := "sha256:" + strings.Repeat("9", 64)
	if _, err := (GuarantorJournalEvidenceResolver{Journal: reopened, AgreementDigest: other}).
		ResolveImmutableGuarantorEvidence(*item.ImmutableDescriptor); err == nil {
		t.Fatal("the prerequisite was served for another coverage")
	}

	// Before the commit, the pending resolver serves exactly the pending bytes,
	// falls back to the journal, and refuses anything else.
	resolver := pendingEvidenceResolver{AuthorityKeyResolver: GuarantorJournalEvidenceResolver{Journal: reopened,
		AgreementDigest: agreement}, pending: map[string]GuarantorStoredEvidence{"sha256:" + strings.Repeat("5", 64): {
		ContentType: guarantor.CollateralControlEvidenceContentTypeV1, Wire: []byte("pending")}}}
	pendingDescriptor := guarantor.ImmutableEvidenceDescriptorV1{ContentType: guarantor.CollateralControlEvidenceContentTypeV1,
		ContentDigest: "sha256:" + strings.Repeat("5", 64), ContentSize: uint64(len("pending"))}
	if served, err := resolver.ResolveImmutableGuarantorEvidence(pendingDescriptor); err != nil || string(served) != "pending" {
		t.Fatalf("the pending prerequisite was not served: %v", err)
	}
	if served, err := resolver.ResolveImmutableGuarantorEvidence(*item.ImmutableDescriptor); err != nil || string(served) != string(wire) {
		t.Fatalf("the journal prerequisite was not served under the pending resolver: %v", err)
	}
	wrongType := pendingDescriptor
	wrongType.ContentType = guarantor.CollateralEvidenceContentTypeV1
	if _, err := resolver.ResolveImmutableGuarantorEvidence(wrongType); err == nil {
		t.Fatal("a pending prerequisite was served under another media type")
	}
	if _, err := (pendingEvidenceResolver{}).ResolveImmutableGuarantorEvidence(*item.ImmutableDescriptor); err == nil {
		t.Fatal("a pending resolver without a journal served evidence it does not hold")
	}
}

// TestJournalGrowthTowardTheReceiptCap fills one coverage's immutable-evidence
// store through journal commits, first with receipts of the measured
// decision-admission size and then with small receipts up to the per-coverage
// receipt cap, and reports the journal document size and commit time.
func TestJournalGrowthTowardTheReceiptCap(t *testing.T) {
	if testing.Short() {
		t.Skip("journal growth measurement")
	}
	const measuredReceiptBytes = 1_069_384 // measured ML-DSA-44 decision admission receipt
	const largeReceipts = 64
	agreement := "sha256:" + strings.Repeat("c", 64)
	journal, directory := openTestGuarantorJournal(t)
	journal.mu.Lock()
	journal.doc.Coverages[agreement] = testCoverageWithClaim("sha256:" + strings.Repeat("b", 64))
	journal.mu.Unlock()
	commitReceipt := func(index int, size int) (time.Duration, error) {
		// Varied bytes, so the measured size is not flattered by compression
		// or repetition anywhere in the stack.
		wire := make([]byte, size)
		for offset := range wire {
			wire[offset] = byte(offset*131 + index*7)
		}
		digest := fmt.Sprintf("sha256:%064x", index+1)
		journal.mu.Lock()
		defer journal.mu.Unlock()
		started := time.Now()
		position := journal.doc.Coverages[agreement]
		if err := storeImmutableWire(&position, guarantorDecisionAdmissionMediaType, digest, wire); err != nil {
			return 0, err
		}
		next := cloneGuarantorDocument(journal.doc)
		next.Coverages[agreement] = position
		next.Revision++
		err := journal.commit(next)
		return time.Since(started), err
	}
	documentSize := func() int64 {
		info, err := os.Stat(filepath.Join(directory, guarantorJournalFile))
		if err != nil {
			t.Fatal(err)
		}
		return info.Size()
	}
	for index := 0; index < largeReceipts; index++ {
		elapsed, err := commitReceipt(index, measuredReceiptBytes)
		if err != nil {
			t.Logf("measured-size receipt %d refused: %v (document %d bytes)", index+1, err, documentSize())
			t.Fatalf("the journal cannot hold %d measured-size receipts for one coverage", largeReceipts)
		}
		if index+1 == 1 || index+1 == 16 || index+1 == largeReceipts {
			t.Logf("%d measured-size receipts: document %d bytes, commit %s", index+1, documentSize(), elapsed)
		}
	}
	// Fill the rest of the store up to one below the cap in a single commit,
	// then measure one ordinary commit at the cap.
	journal.mu.Lock()
	position := journal.doc.Coverages[agreement]
	for index := largeReceipts; index < maximumGuarantorStoredEvidenceReceipts-1; index++ {
		if err := storeImmutableWire(&position, guarantorDecisionAdmissionMediaType,
			fmt.Sprintf("sha256:%064x", index+1), []byte(fmt.Sprintf("small receipt %d", index))); err != nil {
			journal.mu.Unlock()
			t.Fatalf("receipt %d below the cap refused: %v", index+1, err)
		}
	}
	next := cloneGuarantorDocument(journal.doc)
	next.Coverages[agreement] = position
	next.Revision++
	err := journal.commit(next)
	journal.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	elapsed, err := commitReceipt(maximumGuarantorStoredEvidenceReceipts-1, measuredReceiptBytes)
	if err != nil {
		t.Fatalf("the last receipt below the cap was refused: %v", err)
	}
	size := documentSize()
	t.Logf("%d receipts (the cap): document %d bytes, commit %s", maximumGuarantorStoredEvidenceReceipts, size, elapsed)
	// The document records each receipt by media type, length and hash only,
	// so even a full store stays far below the 64 MiB document ceiling.
	if size > 4<<20 {
		t.Fatalf("a full evidence store makes the journal document %d bytes", size)
	}
	if _, err := commitReceipt(maximumGuarantorStoredEvidenceReceipts, 1024); err == nil ||
		!strings.Contains(err.Error(), "immutable evidence store is full") {
		t.Fatalf("a receipt over the per-coverage cap was not refused clearly: %v", err)
	}
}

// TestStoredEvidenceFilesAreCheckedOnServeAndLoad: a committed receipt is
// served only while its file holds exactly the recorded bytes, and a journal
// whose receipt file is missing is refused at load.
func TestStoredEvidenceFilesAreCheckedOnServeAndLoad(t *testing.T) {
	agreement := "sha256:" + strings.Repeat("c", 64)
	digest := "sha256:" + strings.Repeat("d", 64)
	wire := []byte("an immutable receipt")
	journal, directory := openTestGuarantorJournal(t)
	journal.mu.Lock()
	position := testCoverageWithClaim("sha256:" + strings.Repeat("b", 64))
	position.RevisionEpochs = map[string]GuarantorRevisionEpochState{"sha256:" + strings.Repeat("b", 64): testFrozenEpoch()}
	if err := storeImmutableWire(&position, guarantorDecisionAdmissionMediaType, digest, wire); err != nil {
		journal.mu.Unlock()
		t.Fatal(err)
	}
	next := cloneGuarantorDocument(journal.doc)
	next.Coverages[agreement] = position
	next.Revision++
	err := journal.commit(next)
	journal.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(directory, guarantorJournalFile))
	if err != nil || strings.Contains(string(raw), "YW4gaW1tdXRhYmxlIHJlY2VpcHQ") {
		t.Fatalf("the receipt bytes are inside the journal document: %v", err)
	}
	descriptor := guarantor.ImmutableEvidenceDescriptorV1{ContentType: guarantorDecisionAdmissionMediaType,
		ContentDigest: digest, ContentSize: uint64(len(wire))}
	resolver := GuarantorJournalEvidenceResolver{Journal: journal, AgreementDigest: agreement}
	if served, err := resolver.ResolveImmutableGuarantorEvidence(descriptor); err != nil || string(served) != string(wire) {
		t.Fatalf("the committed receipt was not served: %v", err)
	}
	file := filepath.Join(directory, guarantorEvidenceDirectory, strings.TrimPrefix(digest, "sha256:"))
	tampered := append([]byte(nil), wire...)
	tampered[0] ^= 1
	if err := os.WriteFile(file, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.ResolveImmutableGuarantorEvidence(descriptor); err == nil ||
		!strings.Contains(err.Error(), "differs from the journal record") {
		t.Fatalf("a tampered receipt file was served: %v", err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err := openTestGuarantorJournalErr(t, directory); err == nil ||
		!strings.Contains(err.Error(), "has no file of its recorded length") {
		t.Fatalf("a journal whose receipt file is missing was loaded: %v", err)
	}
}
