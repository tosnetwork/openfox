package earning

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	commerce "github.com/tosnetwork/ai/protocol/pkg/agentcommerce"
	guarantor "github.com/tosnetwork/ai/protocol/pkg/agentguarantor"

	"github.com/tosnetwork/openfox/pkg/fileutil"
)

// cloneGuarantorDocument is a deep copy of a journal document for tests that
// build or change a document by hand.
func cloneGuarantorDocument(doc guarantorJournalDocument) guarantorJournalDocument {
	raw, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}
	var cloned guarantorJournalDocument
	if err := json.Unmarshal(raw, &cloned); err != nil {
		panic(err)
	}
	return cloned
}

var errInjectedJournalWrite = errors.New("injected journal write failure")

// journalWriteFault makes a journal's document write, its evidence file
// writes, or both fail without touching the disk. With documentAfterRename
// the document is written and renamed into place and the write then fails
// the way a failed directory sync does.
type journalWriteFault struct {
	document            bool
	evidence            bool
	documentAfterRename bool
}

func (fault *journalWriteFault) install(journal *GuarantorJournal) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	journal.writeFile = func(root *os.Root, name string, data []byte, perm os.FileMode) error {
		if name == guarantorJournalFile && fault.document || name != guarantorJournalFile && fault.evidence {
			return errInjectedJournalWrite
		}
		if err := fileutil.WriteFileAtomicRoot(root, name, data, perm); err != nil {
			return err
		}
		if name == guarantorJournalFile && fault.documentAfterRename {
			return fmt.Errorf("%w: %w", fileutil.ErrReplacedNotSynced, errInjectedJournalWrite)
		}
		return nil
	}
}

// TestGuarantorJournalCommitThatFailsAfterItsRenameIsCommitted: a document
// write that fails after the new document was renamed into place has replaced
// the document on disk, so the commit has happened. Memory is replaced too,
// the caller is told so with a distinct error, and repeating the call does
// not commit again.
func TestGuarantorJournalCommitThatFailsAfterItsRenameIsCommitted(t *testing.T) {
	fixture := newJournalDurabilityFixture(t)
	journal, directory := fixture.journal, fixture.directory
	fault := &journalWriteFault{documentAfterRename: true}
	fault.install(journal)
	documentFile := filepath.Join(directory, guarantorJournalFile)
	for _, operation := range fixture.operations(t) {
		before, err := os.ReadFile(documentFile)
		if err != nil {
			t.Fatal(err)
		}
		fault.documentAfterRename = true
		err = operation.run()
		if !errors.Is(err, ErrGuarantorJournalCommittedNotSynced) || !errors.Is(err, errInjectedJournalWrite) {
			t.Fatalf("%s with a failing directory sync: got %v, want the committed-but-not-synced error", operation.name, err)
		}
		committed, readErr := os.ReadFile(documentFile)
		if readErr != nil || bytes.Equal(committed, before) {
			t.Fatalf("%s: the document on disk did not change although its rename happened: %v", operation.name, readErr)
		}
		assertGuarantorJournalMemoryIsOnDisk(t, journal, directory, operation.name+" after its directory sync failed")
		// The same call again writes nothing: it returns its committed result,
		// or is refused by its compare-and-swap on the state it already moved.
		fault.documentAfterRename = false
		if err := operation.run(); errors.Is(err, ErrGuarantorJournalCommittedNotSynced) ||
			errors.Is(err, errInjectedJournalWrite) {
			t.Fatalf("%s repeated after it was committed: %v", operation.name, err)
		}
		repeated, readErr := os.ReadFile(documentFile)
		if readErr != nil || !bytes.Equal(repeated, committed) {
			t.Fatalf("%s: repeating a committed call wrote the document again: %v", operation.name, readErr)
		}
	}
}

// TestGuarantorJournalSharesNoMemoryWithItsCallers: what a caller hands to a
// commit and what the journal hands back are copies. Changing a stored
// receipt's caller-owned bytes, a returned position, a snapshot, a plan, a
// cut or a revision epoch afterwards changes nothing in the journal.
func TestGuarantorJournalSharesNoMemoryWithItsCallers(t *testing.T) {
	fixture := newJournalDurabilityFixture(t)
	journal, directory := fixture.journal, fixture.directory
	digest := func(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }
	unchanged := func(after string) {
		t.Helper()
		assertGuarantorJournalMemoryIsOnDisk(t, journal, directory, after)
	}

	// A receipt handed to a commit, and the position the commit returns.
	filing := guarantor.AuthorizedClaimFilingCloseReceiptV1{
		Authorizations: []guarantor.ProfileQualifiedObjectAuthorizationV1{{AuthoritySubject: "agent:guarantor"}}}
	filing.Body.SchemaVersion, filing.Body.CoverageAgreementBodyDigest = 1, fixture.decided
	filing.Body.FrozenClaimAdmissionLogRoot = digest("a")
	returned, err := journal.CommitClaimFilingCloseReceipt(fixture.decided, filing)
	if err != nil {
		t.Fatal(err)
	}
	filing.Authorizations[0].AuthoritySubject = "agent:changed-by-the-caller"
	unchanged("after the caller changed the receipt it had stored")
	returned.FilingCloseReceipt.Authorizations[0].AuthoritySubject = "agent:changed-in-the-returned-position"
	returned.Claims[fixture.decidedClaim] = guarantor.ClaimRecord{ClaimID: "changed"}
	for key := range returned.ImmutableEvidence {
		delete(returned.ImmutableEvidence, key)
	}
	unchanged("after the caller changed the position a commit returned")

	// Everything the journal hands back.
	_, offers, coverages := journal.Snapshot()
	for index := range offers {
		if offers[index].PreAcceptanceReleasePlan != nil {
			offers[index].PreAcceptanceReleasePlan.Action.WriterGeneration = 99
		}
	}
	for index := range coverages {
		coverages[index].Claims["changed"] = guarantor.ClaimRecord{ClaimID: "changed"}
		for key, decision := range coverages[index].DecisionAdmissionReceipts {
			decision.ClaimRevisionIngressCutProof.Entries = append(decision.ClaimRevisionIngressCutProof.Entries,
				guarantor.ClaimIngressResolutionEntryV1{ClaimIngressSequence: 99})
			coverages[index].DecisionAdmissionReceipts[key] = decision
		}
		if coverages[index].FilingCloseReceipt != nil {
			coverages[index].FilingCloseReceipt.Authorizations[0].AuthoritySubject = "agent:changed-in-a-snapshot"
		}
	}
	unchanged("after the caller changed a snapshot")
	epoch, err := journal.RevisionEpoch(fixture.decided, fixture.decidedClaim)
	if err != nil || epoch.FrozenCut == nil {
		t.Fatalf("the decided claim's revision epoch: %#v err=%v", epoch, err)
	}
	epoch.FrozenCut.AdmissionLogRoot = digest("9")
	unchanged("after the caller changed a returned revision epoch")
	resolution := commerce.ActionResolution{StableActionID: fixture.preparedAction,
		ExactRequestDigest: fixture.preparedRequest, State: commerce.ActionRejected, StateRevision: 2,
		EvidenceRefs: []string{digest("d")}}
	entry, err := journal.ResolveAdmission(fixture.domain, resolution)
	if err != nil {
		t.Fatal(err)
	}
	resolution.EvidenceRefs[0] = digest("e")
	entry.Resolution.EvidenceRefs[0] = digest("f")
	unchanged("after the caller changed an admission resolution it stored and the entry returned")
	cut, err := journal.FreezeAdmissionCut(fixture.domain, uint64(fixture.at.Unix()))
	if err != nil || len(cut.Entries) != 1 {
		t.Fatalf("the admission cut: %#v err=%v", cut, err)
	}
	cut.Entries[0].Resolution.EvidenceRefs[0] = digest("0")
	unchanged("after the caller changed a returned admission cut")

	// The journal still holds what was committed.
	_, _, coverages = journal.Snapshot()
	for _, coverage := range coverages {
		if coverage.FilingCloseReceipt != nil &&
			coverage.FilingCloseReceipt.Authorizations[0].AuthoritySubject != "agent:guarantor" {
			t.Fatalf("the stored filing-close receipt was changed through shared memory: %q",
				coverage.FilingCloseReceipt.Authorizations[0].AuthoritySubject)
		}
	}
}

// guarantorJournalDiffersFromDisk reports how the in-memory document differs
// from the document file: in its encoded bytes, or by holding staged evidence
// bytes, which are not part of the encoding. The caller holds the journal.
func guarantorJournalDiffersFromDisk(journal *GuarantorJournal, directory string) string {
	memory, err := json.Marshal(journal.doc)
	if err != nil {
		return "the in-memory document cannot be encoded: " + err.Error()
	}
	disk, err := os.ReadFile(filepath.Join(directory, guarantorJournalFile))
	if err != nil {
		return "the document file cannot be read: " + err.Error()
	}
	if !bytes.Equal(memory, disk) {
		return "the in-memory document is not the document on disk"
	}
	for agreement, coverage := range journal.doc.Coverages {
		for digest, stored := range coverage.ImmutableEvidence {
			if stored.Wire != nil {
				return "the in-memory document holds staged evidence " + digest + " of coverage " + agreement
			}
		}
	}
	return ""
}

func assertGuarantorJournalMemoryIsOnDisk(t *testing.T, journal *GuarantorJournal, directory, when string) {
	t.Helper()
	journal.mu.Lock()
	difference := guarantorJournalDiffersFromDisk(journal, directory)
	journal.mu.Unlock()
	if difference != "" {
		t.Fatalf("%s: %s", when, difference)
	}
}

// checkGuarantorJournalCommitsFromACopy checks, at every document write of a
// lifecycle, that the in-memory document is still exactly the last one
// written: no commit method changed it before its commit. It reports the
// first difference with the revision being written.
func checkGuarantorJournalCommitsFromACopy(t *testing.T, journal *GuarantorJournal, directory string) {
	t.Helper()
	reported := false
	journal.mu.Lock()
	defer journal.mu.Unlock()
	journal.writeFile = func(root *os.Root, name string, data []byte, perm os.FileMode) error {
		// commit holds the journal while it writes the document.
		if name == guarantorJournalFile && !reported {
			if difference := guarantorJournalDiffersFromDisk(journal, directory); difference != "" {
				reported = true
				t.Errorf("before the commit that follows revision %d: %s", journal.doc.Revision, difference)
			}
		}
		return fileutil.WriteFileAtomicRoot(root, name, data, perm)
	}
}

// journalDurabilityFixture is a loaded journal holding a coverage whose claim
// has a decision head and a frozen filing state, a coverage whose claim is
// admitted and undecided, an expired offer with a release plan, and one
// prepared admission.
type journalDurabilityFixture struct {
	journal         *GuarantorJournal
	directory       string
	decided         string
	decidedClaim    string
	undecided       string
	undecidedClaim  string
	offerID         string
	domain          string
	preparedAction  string
	preparedRequest string
	at              time.Time
	// releasePlan is the expired offer's release plan as the fixture stores it.
	releasePlan GuarantorPreAcceptanceReleasePlan
}

func newJournalDurabilityFixture(t *testing.T) journalDurabilityFixture {
	t.Helper()
	digest := func(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }
	fixture := journalDurabilityFixture{decided: digest("c"), decidedClaim: digest("b"), undecided: digest("d"),
		undecidedClaim: digest("e"), offerID: digest("7"), domain: digest("8"), preparedAction: digest("1"),
		preparedRequest: digest("2"), at: time.Unix(2_000_000_000, 0).UTC()}
	fixture.releasePlan = testGuarantorOfferReleasePlan(t, testExpiredGuarantorOffer(fixture.offerID), 1)
	journal, directory := openTestGuarantorJournal(t)
	rewriteTestGuarantorJournal(t, journal, func(doc *guarantorJournalDocument) {
		decided := testCoverageWithClaim(fixture.decidedClaim)
		decided.RevisionEpochs = map[string]GuarantorRevisionEpochState{fixture.decidedClaim: testFrozenEpoch()}
		decided.Claims[fixture.decidedClaim] = guarantor.ClaimRecord{ClaimID: fixture.decidedClaim, ClaimRevision: 1,
			ClaimStateRevision: 2, ClaimStatus: guarantor.ClaimDenied, DecisionSequence: 1}
		decided.Record.ClaimFilingStatus = guarantor.FilingFrozen
		doc.Coverages[fixture.decided] = decided

		undecided := testCoverageWithClaim(fixture.undecidedClaim)
		delete(undecided.DecisionAdmissionReceipts, fixture.undecidedClaim)
		undecided.RevisionEpochs = map[string]GuarantorRevisionEpochState{
			fixture.undecidedClaim: {Epoch: 1, State: revisionEpochOpen, StateRevision: 1}}
		undecided.Claims[fixture.undecidedClaim] = guarantor.ClaimRecord{ClaimID: fixture.undecidedClaim,
			ClaimRevision: 1, ClaimStateRevision: 2, ClaimStatus: guarantor.ClaimAdmitted}
		doc.Coverages[fixture.undecided] = undecided

		expired := testExpiredGuarantorOffer(fixture.offerID)
		expired.PreAcceptanceReleasePlan = &fixture.releasePlan
		doc.Offers[fixture.offerID] = expired
	})
	reopened, err := OpenGuarantorJournal(directory, "owner:guarantor", "agent:guarantor")
	if err != nil {
		t.Fatalf("load the durability fixture: %v", err)
	}
	closeGuarantorJournalOnCleanup(t, reopened)
	fixture.journal, fixture.directory = reopened, directory
	// A loaded document differs from its file by the defaults load fills in;
	// after one commit the in-memory document is exactly the bytes on disk.
	if _, err := reopened.BeginAdmission(fixture.domain, fixture.preparedAction, fixture.preparedRequest, fixture.at); err != nil {
		t.Fatalf("the fixture's first commit: %v", err)
	}
	assertGuarantorJournalMemoryIsOnDisk(t, reopened, directory, "after the fixture's first commit")
	return fixture
}

// journalDurabilityOperation is one commit method call with its own input.
// evidenceDigest names the receipt it stages, if it stages one.
type journalDurabilityOperation struct {
	name           string
	evidenceDigest string
	run            func() error
}

func (fixture journalDurabilityFixture) operations(t *testing.T) []journalDurabilityOperation {
	t.Helper()
	digest := func(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }
	journal := fixture.journal

	filing := guarantor.AuthorizedClaimFilingCloseReceiptV1{
		Authorizations: []guarantor.ProfileQualifiedObjectAuthorizationV1{{AuthoritySubject: "agent:guarantor"}}}
	filing.Body.SchemaVersion, filing.Body.CoverageAgreementBodyDigest = 1, fixture.decided
	filing.Body.FrozenClaimAdmissionLogRoot = digest("a")
	filingDigest, err := guarantor.ClaimFilingCloseReceiptDigestV1(filing)
	if err != nil {
		t.Fatal(err)
	}

	head := testCoverageWithClaim(fixture.decidedClaim).DecisionAdmissionReceipts[fixture.decidedClaim]
	headDigest, err := guarantor.ClaimDecisionAdmissionReceiptDigestV1(head)
	if err != nil {
		t.Fatal(err)
	}
	var transition guarantor.AuthorizedClaimStateTransitionReceiptV1
	transition.Body.ClaimID, transition.Body.CoverageAgreementBodyDigest = fixture.decidedClaim, fixture.decided
	transition.Body.TransitionKind = "challenge_close"
	transition.Body.PriorClaimState, transition.Body.PriorClaimStateRevision = "denied", 2
	transition.Body.ResultingClaimState, transition.Body.ResultingClaimStateRevision = "final_denied", 3
	transition.DecisionAdmissionProof.ReceiptEnvelopeDigest = headDigest

	decision := revisionEpochTestAdmission(revisionEpochTestCut(1, 1, 2, "a"))
	decision.Body.ClaimID, decision.Body.CoverageAgreementBodyDigest = fixture.undecidedClaim, fixture.undecided
	decision.Body.DecisionPath, decision.Body.DecisionSequence = "initial", 1
	decision.Body.PriorClaimState, decision.Body.PriorClaimStateRevision = "admitted", 2
	decision.Body.AdmittedClaimState, decision.Body.AdmittedClaimStateRevision = "denied", 3
	decision.Body.AdmittedCoverageRevision = 1
	decision.Body.AggregatePendingDecisionReserveBefore.AmountAtomic = "0"
	decision.Body.AggregatePendingDecisionReserveAfter.AmountAtomic = "0"
	decision.AuthorizedClaimDecision.Body.ExpectedClaimRevision = 1
	decision.AuthorizedClaimDecision.Body.Result = guarantor.DecisionDenied
	decision.AuthorizedClaimDecision.Body.ApprovedAmount.AmountAtomic = "0"
	decisionDigest, err := guarantor.ClaimDecisionAdmissionReceiptDigestV1(decision)
	if err != nil {
		t.Fatal(err)
	}

	offer := GuarantorOfferPosition{QuoteRequestDigest: digest("1"), CoveredPartyAgentID: "agent:covered",
		CoverageAsset:       commerce.AssetIdentityV1{AssetNamespace: "tos.asset", AssetIdentifier: "native", Unit: "nano"},
		GrossExposureAtomic: "1000", NetExposureAtomic: "600", AcceptByUnix: 2_000_000_100,
		ReservationExpiresAt: 2_000_000_200, Record: guarantor.OfferRecord{OfferID: digest("6"),
			ReservationID: digest("3"), AgreementDigest: digest("4"), Status: guarantor.OfferReservedUnsigned,
			StateRevision: 3, LastEvidenceDigest: digest("5")}}
	reauthorized := fixture.releasePlan.Action
	reauthorized.WriterGeneration = 2
	resolution := commerce.ActionResolution{StableActionID: fixture.preparedAction,
		ExactRequestDigest: fixture.preparedRequest, State: commerce.ActionRejected, StateRevision: 2,
		EvidenceRefs: []string{digest("d")}}

	return []journalDurabilityOperation{
		{name: "offer reservation", run: func() error { return journal.ReserveUnsignedOffer(offer) }},
		{name: "release plan reauthorization", run: func() error {
			_, err := journal.RefreshOfferReleasePlanAction(fixture.offerID, reauthorized)
			return err
		}},
		{name: "admission", run: func() error {
			_, err := journal.BeginAdmission(fixture.domain, digest("9"), digest("a"), fixture.at)
			return err
		}},
		{name: "admission resolution", run: func() error {
			_, err := journal.ResolveAdmission(fixture.domain, resolution)
			return err
		}},
		{name: "filing-close receipt", evidenceDigest: filingDigest, run: func() error {
			_, err := journal.CommitClaimFilingCloseReceipt(fixture.decided, filing)
			return err
		}},
		{name: "claim state transition", run: func() error {
			_, err := journal.CommitClaimStateTransition(fixture.decided, transition)
			return err
		}},
		{name: "decision admission", evidenceDigest: decisionDigest, run: func() error {
			_, err := journal.CommitDecisionAdmission(fixture.undecided, decision)
			return err
		}},
	}
}

// TestFailedGuarantorJournalCommitLeavesMemoryAsOnDisk: a commit whose evidence
// file write or document write fails changes nothing in memory, in any map,
// behind any pointer, or as staged evidence; the next successful commit carries
// nothing of the failed ones; and each failed commit then succeeds unchanged.
func TestFailedGuarantorJournalCommitLeavesMemoryAsOnDisk(t *testing.T) {
	fixture := newJournalDurabilityFixture(t)
	journal, directory := fixture.journal, fixture.directory
	operations := fixture.operations(t)
	fault := &journalWriteFault{}
	fault.install(journal)
	evidencePath := func(digest string) string {
		return filepath.Join(directory, guarantorEvidenceDirectory, strings.TrimPrefix(digest, "sha256:"))
	}
	before, err := os.ReadFile(filepath.Join(directory, guarantorJournalFile))
	if err != nil {
		t.Fatal(err)
	}

	// An evidence file that cannot be written: nothing is staged or recorded.
	fault.document, fault.evidence = false, true
	for _, operation := range operations {
		if operation.evidenceDigest == "" {
			continue
		}
		if err := operation.run(); !errors.Is(err, errInjectedJournalWrite) {
			t.Fatalf("%s with a failing evidence write: got %v, want the injected failure", operation.name, err)
		}
		assertGuarantorJournalMemoryIsOnDisk(t, journal, directory, operation.name+" after its evidence write failed")
		if _, err := os.Lstat(evidencePath(operation.evidenceDigest)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s left an evidence file although its write failed: %v", operation.name, err)
		}
	}

	// A document that cannot be written, after the evidence files were.
	fault.document, fault.evidence = true, false
	for _, operation := range operations {
		if err := operation.run(); !errors.Is(err, errInjectedJournalWrite) {
			t.Fatalf("%s with a failing document write: got %v, want the injected failure", operation.name, err)
		}
		assertGuarantorJournalMemoryIsOnDisk(t, journal, directory, operation.name+" after its document write failed")
		if operation.evidenceDigest != "" {
			if _, err := os.Lstat(evidencePath(operation.evidenceDigest)); err != nil {
				t.Fatalf("%s did not write its evidence file before the document: %v", operation.name, err)
			}
		}
	}
	unchanged, err := os.ReadFile(filepath.Join(directory, guarantorJournalFile))
	if err != nil || !bytes.Equal(unchanged, before) {
		t.Fatalf("a failed commit changed the document on disk: %v", err)
	}

	// The next successful commit carries nothing of the failed ones.
	fault.document, fault.evidence = false, false
	digest := func(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }
	if _, err := journal.BeginAdmission(digest("0"), digest("1"), digest("2"), fixture.at); err != nil {
		t.Fatalf("a commit after the failed ones: %v", err)
	}
	assertGuarantorJournalMemoryIsOnDisk(t, journal, directory, "after the commit that followed the failed ones")
	raw, err := os.ReadFile(filepath.Join(directory, guarantorJournalFile))
	if err != nil {
		t.Fatal(err)
	}
	var persisted guarantorJournalDocument
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatal(err)
	}
	decided, undecided := persisted.Coverages[fixture.decided], persisted.Coverages[fixture.undecided]
	log := persisted.AdmissionLogs[fixture.domain]
	plan := persisted.Offers[fixture.offerID].PreAcceptanceReleasePlan
	if len(persisted.Offers) != 1 || plan == nil || plan.Action.WriterGeneration != 1 ||
		len(log.Entries) != 1 || log.Entries[fixture.preparedAction].Resolution.State != commerce.ActionPrepared ||
		decided.FilingCloseReceipt != nil || len(decided.ClaimStateTransitionReceipts) != 0 ||
		len(decided.ImmutableEvidence) != 0 || decided.Claims[fixture.decidedClaim].ClaimStateRevision != 2 ||
		len(undecided.DecisionAdmissionReceipts) != 0 || len(undecided.Decisions) != 0 ||
		len(undecided.ImmutableEvidence) != 0 || undecided.RevisionEpochs[fixture.undecidedClaim].State != revisionEpochOpen ||
		undecided.Claims[fixture.undecidedClaim].ClaimStatus != guarantor.ClaimAdmitted ||
		undecided.Record.CoverageRevision != 0 {
		t.Fatalf("the commit after the failed ones persisted their leftovers: %s", raw)
	}

	// Each failed commit then succeeds exactly as if it had never been tried.
	for _, operation := range operations {
		if err := operation.run(); err != nil {
			t.Fatalf("%s after its failed attempts: %v", operation.name, err)
		}
		assertGuarantorJournalMemoryIsOnDisk(t, journal, directory, operation.name+" after it succeeded")
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	reloaded, err := OpenGuarantorJournal(directory, "owner:guarantor", "agent:guarantor")
	if err != nil {
		t.Fatalf("reload after the retried commits: %v", err)
	}
	closeGuarantorJournalOnCleanup(t, reloaded)
	for _, operation := range operations {
		if operation.evidenceDigest == "" {
			continue
		}
		if _, err := os.Lstat(evidencePath(operation.evidenceDigest)); err != nil {
			t.Fatalf("%s: its committed evidence file is gone after a reload: %v", operation.name, err)
		}
	}
}

// commitTestGuarantorEvidence commits one receipt to agreement's coverage the
// way a commit method does, creating the coverage if the journal has none.
func commitTestGuarantorEvidence(t *testing.T, journal *GuarantorJournal, agreement, digest string, wire []byte) error {
	t.Helper()
	journal.mu.Lock()
	defer journal.mu.Unlock()
	next, err := journal.workingCopy()
	if err != nil {
		return err
	}
	position, found := next.Coverages[agreement]
	if !found {
		claimID := "sha256:" + strings.Repeat("b", 64)
		position = testCoverageWithClaim(claimID)
		position.RevisionEpochs = map[string]GuarantorRevisionEpochState{claimID: testFrozenEpoch()}
	}
	if err := storeImmutableWire(&position, guarantorDecisionAdmissionMediaType, digest, wire); err != nil {
		return err
	}
	next.Coverages[agreement] = position
	next.Revision++
	return journal.commit(next)
}

// TestOpeningAGuarantorJournalSweepsCrashLeftovers: opening a journal removes
// the receipt file of a commit whose document was never written and the
// temporary files of interrupted writes, and nothing else: a file a record
// names is kept and still served, and so is anything with another name or of
// another kind.
func TestOpeningAGuarantorJournalSweepsCrashLeftovers(t *testing.T) {
	digest := func(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }
	agreement, named, uncommitted := digest("c"), digest("d"), digest("e")
	namedWire := []byte("a receipt its coverage names")
	journal, directory := openTestGuarantorJournal(t)
	if err := commitTestGuarantorEvidence(t, journal, agreement, named, namedWire); err != nil {
		t.Fatal(err)
	}
	// A commit that wrote its receipt file and then could not write its
	// document leaves that file with no record naming it.
	fault := &journalWriteFault{document: true}
	fault.install(journal)
	if err := commitTestGuarantorEvidence(t, journal, agreement, uncommitted,
		[]byte("a receipt whose document was never written")); !errors.Is(err, errInjectedJournalWrite) {
		t.Fatalf("the uncommitted receipt: got %v, want the injected failure", err)
	}
	evidence := filepath.Join(directory, guarantorEvidenceDirectory)
	file := func(name string) string { return filepath.Join(evidence, name) }
	hexName := func(ch string) string { return strings.Repeat(ch, 64) }
	write := func(path string) {
		t.Helper()
		if err := os.WriteFile(path, []byte("leftover"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(file(hexName("f")))                         // an orphan receipt file
	write(file(".tmp-4242-1700000000000000000"))      // an interrupted receipt write
	write(filepath.Join(directory, ".tmp-4242-1700")) // an interrupted document write
	write(file("README"))                             // not a receipt name
	write(file(".tmp-notes"))                         // not an atomic-write temporary
	write(file(hexName("a")[:63]))                    // one digit short of a receipt name
	if err := os.Mkdir(file(hexName("1")), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(file("README"), file(hexName("2"))); err != nil {
		t.Fatal(err)
	}
	removed := []string{file(strings.TrimPrefix(uncommitted, "sha256:")), file(hexName("f")),
		file(".tmp-4242-1700000000000000000"), filepath.Join(directory, ".tmp-4242-1700")}
	kept := []string{file(strings.TrimPrefix(named, "sha256:")), file("README"), file(".tmp-notes"),
		file(hexName("a")[:63]), file(hexName("1")), file(hexName("2")),
		filepath.Join(directory, guarantorJournalFile)}
	for _, path := range append(append([]string(nil), removed...), kept...) {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("the test did not set up %s: %v", path, err)
		}
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenGuarantorJournal(directory, "owner:guarantor", "agent:guarantor")
	if err != nil {
		t.Fatalf("open a journal with crash leftovers: %v", err)
	}
	closeGuarantorJournalOnCleanup(t, reopened)
	for _, path := range removed {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("the crash leftover %s was not removed: %v", path, err)
		}
	}
	for _, path := range kept {
		if _, err := os.Lstat(path); err != nil {
			t.Errorf("%s was removed or is unreadable: %v", path, err)
		}
	}
	served, err := (GuarantorJournalEvidenceResolver{Journal: reopened, AgreementDigest: agreement}).
		ResolveImmutableGuarantorEvidence(guarantor.ImmutableEvidenceDescriptorV1{
			ContentType: guarantorDecisionAdmissionMediaType, ContentDigest: named, ContentSize: uint64(len(namedWire))})
	if err != nil || !bytes.Equal(served, namedWire) {
		t.Fatalf("the named receipt is not served after the sweep: %v", err)
	}
	if _, err := reopened.VerifyStoredEvidence(); err != nil {
		t.Fatalf("the swept journal fails its integrity check: %v", err)
	}
}

// TestVerifyStoredEvidenceHashesEveryReceipt: opening a journal checks each
// receipt file's length only; the explicit integrity check reads and hashes
// every receipt, counts a receipt two coverages name once, and names the
// receipt whose bytes differ from its record.
func TestVerifyStoredEvidenceHashesEveryReceipt(t *testing.T) {
	digest := func(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }
	first, second := digest("c"), digest("9")
	receipts := map[string][]byte{digest("d"): []byte("the first receipt"),
		digest("e"): []byte("the second, longer receipt"), digest("f"): []byte("a receipt both coverages name")}
	journal, directory := openTestGuarantorJournal(t)
	for _, commit := range []struct{ agreement, digest string }{{first, digest("d")}, {first, digest("e")},
		{first, digest("f")}, {second, digest("f")}} {
		if err := commitTestGuarantorEvidence(t, journal, commit.agreement, commit.digest, receipts[commit.digest]); err != nil {
			t.Fatal(err)
		}
	}
	var total uint64
	for _, wire := range receipts {
		total += uint64(len(wire))
	}
	report, err := journal.VerifyStoredEvidence()
	if err != nil || report.Receipts != uint64(len(receipts)) || report.Bytes != total {
		t.Fatalf("integrity check of an intact store: report=%#v err=%v, want %d receipts and %d bytes",
			report, err, len(receipts), total)
	}

	// Same length, other bytes: the journal still opens, and serves the other
	// receipts; the integrity check finds it.
	tampered := filepath.Join(directory, guarantorEvidenceDirectory, strings.TrimPrefix(digest("e"), "sha256:"))
	changed := append([]byte(nil), receipts[digest("e")]...)
	changed[len(changed)-1] ^= 1
	if err := os.WriteFile(tampered, changed, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenGuarantorJournal(directory, "owner:guarantor", "agent:guarantor")
	if err != nil {
		t.Fatalf("a journal with a same-length changed receipt did not open: %v", err)
	}
	closeGuarantorJournalOnCleanup(t, reopened)
	if _, err := reopened.VerifyStoredEvidence(); err == nil || !strings.Contains(err.Error(), digest("e")) ||
		!strings.Contains(err.Error(), "differs from the journal record") {
		t.Fatalf("the integrity check did not name the changed receipt: %v", err)
	}
	if err := os.WriteFile(tampered, receipts[digest("e")], 0o600); err != nil {
		t.Fatal(err)
	}
	if report, err := reopened.VerifyStoredEvidence(); err != nil || report.Receipts != uint64(len(receipts)) {
		t.Fatalf("integrity check after the receipt was restored: report=%#v err=%v", report, err)
	}
	// A receipt file that lost bytes after the journal was opened.
	if err := os.WriteFile(tampered, receipts[digest("e")][:4], 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.VerifyStoredEvidence(); err == nil || !strings.Contains(err.Error(), digest("e")) ||
		!strings.Contains(err.Error(), "of another length") {
		t.Fatalf("the integrity check did not name the truncated receipt: %v", err)
	}
}
