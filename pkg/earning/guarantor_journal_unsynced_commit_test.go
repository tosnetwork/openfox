package earning

import (
	"bytes"
	"context"
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

// unsyncedTestGuarantorJournal is the durability fixture after one commit
// whose document was renamed into place and whose directory sync failed, with
// the fault still installed. run is the call that made the commit, and the
// bytes are the document it committed.
func unsyncedTestGuarantorJournal(t *testing.T) (journalDurabilityFixture, *journalWriteFault, func() error, []byte) {
	t.Helper()
	digest := func(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }
	fixture := newJournalDurabilityFixture(t)
	fault := &journalWriteFault{documentAfterRename: true}
	fault.install(fixture.journal)
	run := func() error {
		_, err := fixture.journal.BeginAdmission(fixture.domain, digest("b"), digest("f"), fixture.at)
		return err
	}
	if err := run(); !errors.Is(err, ErrGuarantorJournalCommittedNotSynced) {
		t.Fatalf("the commit whose directory sync failed: got %v, want the committed-but-not-synced error", err)
	}
	committed, err := os.ReadFile(filepath.Join(fixture.directory, guarantorJournalFile))
	if err != nil {
		t.Fatal(err)
	}
	return fixture, fault, run, committed
}

// TestAGuarantorCommitThatLostItsSyncIsNeverASilentSuccess: after a commit
// whose directory sync failed, repeating the call does not succeed while the
// document still cannot be written with a completed sync, whether the write
// fails before or after its rename. It commits nothing a second time. Once
// the document can be written, repeating the call returns its committed
// result and the document is the one that was committed.
func TestAGuarantorCommitThatLostItsSyncIsNeverASilentSuccess(t *testing.T) {
	fixture, fault, run, committed := unsyncedTestGuarantorJournal(t)
	documentFile := filepath.Join(fixture.directory, guarantorJournalFile)
	unchanged := func(when string) {
		t.Helper()
		now, err := os.ReadFile(documentFile)
		if err != nil || !bytes.Equal(now, committed) {
			t.Fatalf("%s: the document is no longer the one that was committed: %v", when, err)
		}
	}
	for _, failing := range []struct {
		name  string
		fault journalWriteFault
	}{
		{"its directory sync still fails", journalWriteFault{documentAfterRename: true}},
		{"its write fails", journalWriteFault{document: true}},
	} {
		*fault = failing.fault
		if err := run(); err == nil {
			t.Fatalf("repeating the call while %s returned success", failing.name)
		}
		unchanged("repeating the call while " + failing.name)
	}
	*fault = journalWriteFault{}
	if err := run(); err != nil {
		t.Fatalf("repeating the call once the document can be written: %v", err)
	}
	unchanged("repeating the call once the document can be written")
	assertGuarantorJournalMemoryIsOnDisk(t, fixture.journal, fixture.directory, "after the commit was confirmed")
}

// TestOpeningAGuarantorJournalConfirmsWhatItLoads: a writer that lost a
// commit's directory sync and stopped leaves a document that reads back and
// whose durability nothing records. The next writer's open syncs the journal
// directory and the evidence directory before it hands the journal out, and
// fails when a sync fails. After an open that succeeded, repeating the call
// whose commit lost its sync returns the committed result without writing.
// An inspection syncs nothing.
func TestOpeningAGuarantorJournalConfirmsWhatItLoads(t *testing.T) {
	digest := func(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }
	fixture, _, _, committed := unsyncedTestGuarantorJournal(t)
	documentFile := filepath.Join(fixture.directory, guarantorJournalFile)
	// The writer stops with the sync still failing.
	if err := fixture.journal.Close(); !errors.Is(err, ErrGuarantorJournalDurabilityUnconfirmed) {
		t.Fatalf("closing the unconfirmed journal: got %v, want the unconfirmed-durability error", err)
	}
	var synced []string
	failAt := ""
	syncDirectory := func(root *os.Root, directory string) error {
		synced = append(synced, directory)
		if directory == failAt {
			return errInjectedJournalWrite
		}
		return fileutil.SyncDirectoryRoot(root, directory)
	}
	open := func(readOnly bool) (*GuarantorJournal, error) {
		synced = nil
		return openGuarantorJournalSyncedBy(fixture.directory, "owner:guarantor", "agent:guarantor", readOnly,
			syncDirectory)
	}
	everySync := []string{".", guarantorEvidenceDirectory}
	for _, failing := range everySync {
		failAt = failing
		opened, err := open(false)
		if err == nil {
			_ = opened.Close()
			t.Fatalf("the journal opened although the sync of %q failed", failing)
		}
		if !errors.Is(err, errInjectedJournalWrite) {
			t.Fatalf("the open whose sync of %q failed: got %v, want the injected failure", failing, err)
		}
		if now, readErr := os.ReadFile(documentFile); readErr != nil || !bytes.Equal(now, committed) {
			t.Fatalf("the failed open changed the document: %v", readErr)
		}
	}

	// An inspection is not a writer: it confirms nothing and syncs nothing.
	failAt = "."
	inspected, err := open(true)
	if err != nil || len(synced) != 0 {
		t.Fatalf("a read-only open: err=%v, synced %v, want no sync", err, synced)
	}
	if err = inspected.Close(); err != nil {
		t.Fatal(err)
	}

	failAt = ""
	reopened, err := open(false)
	if err != nil {
		t.Fatalf("the open whose syncs succeed: %v", err)
	}
	closeGuarantorJournalOnCleanup(t, reopened)
	if !sameJSON(synced, everySync) {
		t.Fatalf("the open synced %v, want %v", synced, everySync)
	}
	// The call whose commit lost its sync is repeated on the journal opened
	// from disk: it returns the committed result and writes nothing.
	writes := countTestGuarantorDocumentWrites(reopened)
	synced = nil
	if _, err = reopened.BeginAdmission(fixture.domain, digest("b"), digest("f"), fixture.at); err != nil {
		t.Fatalf("repeating the call after the restart: %v", err)
	}
	if *writes != 0 || len(synced) != 0 {
		t.Fatalf("the repeated call wrote the document %d times and synced %v, want neither", *writes, synced)
	}
	if now, readErr := os.ReadFile(documentFile); readErr != nil || !bytes.Equal(now, committed) {
		t.Fatalf("the document after the restart is not the one committed: %v", readErr)
	}

	// A journal created by the open is confirmed the same way.
	empty := filepath.Join(t.TempDir(), "guarantor")
	if err = os.Mkdir(empty, 0o700); err != nil {
		t.Fatal(err)
	}
	synced = nil
	created, err := openGuarantorJournalSyncedBy(empty, "owner:guarantor", "agent:another", false, syncDirectory)
	if err != nil {
		t.Fatal(err)
	}
	closeGuarantorJournalOnCleanup(t, created)
	if !sameJSON(synced, everySync) {
		t.Fatalf("the open that created a journal synced %v, want %v", synced, everySync)
	}
}

// journalSyncLossFault makes document writes that commit something new lose
// their directory sync: the document is written and renamed into place and
// the write then reports the failed sync. It does so for the next remaining
// new documents and counts them in lost. Writing the same document again,
// which is how the journal confirms a commit, goes through. The first skip
// new documents are written undisturbed, so a test can lose the sync of a
// call's last commit alone.
type journalSyncLossFault struct {
	skip      int
	remaining int
	lost      int
	last      []byte
}

// install puts the fault in front of the journal's current write function and
// returns a function that takes it out again.
func (fault *journalSyncLossFault) install(journal *GuarantorJournal) func() {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	underneath := journal.writeFile
	journal.writeFile = func(root *os.Root, name string, data []byte, perm os.FileMode) error {
		if err := underneath(root, name, data, perm); err != nil || name != guarantorJournalFile {
			return err
		}
		repeated := bytes.Equal(data, fault.last)
		fault.last = append([]byte(nil), data...)
		if repeated || fault.remaining == 0 {
			return nil
		}
		if fault.skip > 0 {
			fault.skip--
			return nil
		}
		fault.remaining--
		fault.lost++
		return fmt.Errorf("%w: %w", fileutil.ErrReplacedNotSynced, errInjectedJournalWrite)
	}
	return func() {
		journal.mu.Lock()
		defer journal.mu.Unlock()
		journal.writeFile = underneath
	}
}

// repeatUntilTestGuarantorCommitsAreSynced calls call the way a caller that
// stops at a commit which lost its sync and tries again does, until it
// succeeds, and returns how many times it stopped. It fails the test when a
// call returns success although a commit inside it lost its sync, goes on to
// commit more after one did, or fails for another reason.
func repeatUntilTestGuarantorCommitsAreSynced(t *testing.T, fault *journalSyncLossFault, name string,
	call func() error,
) int {
	t.Helper()
	for stops := 0; stops < 32; stops++ {
		lostBefore := fault.lost
		err := call()
		lost := fault.lost - lostBefore
		switch {
		case err == nil && lost == 0:
			return stops
		case err == nil:
			t.Fatalf("%s returned success although %d commit(s) inside it lost their directory sync", name, lost)
		case !errors.Is(err, ErrGuarantorJournalCommittedNotSynced):
			t.Fatalf("%s after %d stop(s): %v", name, stops, err)
		case lost != 1:
			t.Fatalf("%s reported a commit that lost its sync, but %d commits lost theirs in that call", name, lost)
		}
	}
	t.Fatalf("%s did not complete", name)
	return 0
}

// admissionCountingAuthority counts the admissions a coordinator asks its
// authority for.
type admissionCountingAuthority struct {
	EconomicAuthority
	admitted int
}

func (authority *admissionCountingAuthority) Admit(action commerce.AuthorizedAction,
	fields map[string]commerce.SemanticValue, request []byte, fence commerce.WriterFence,
	reservation *ExposureReservation,
) (commerce.ActionResolution, error) {
	authority.admitted++
	return authority.EconomicAuthority.Admit(action, fields, request, fence, reservation)
}

// scriptTestGuarantorDocumentWrites makes journal's next document writes end
// as outcomes say, in order: "fail" writes nothing and fails, "unsynced"
// writes the document and reports a lost directory sync, anything else writes
// it. Writes after the last outcome go through. It returns the number of
// document writes made and a function that takes the script out again.
func scriptTestGuarantorDocumentWrites(journal *GuarantorJournal, outcomes ...string) (*int, func()) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	writes, underneath := new(int), journal.writeFile
	journal.writeFile = func(root *os.Root, name string, data []byte, perm os.FileMode) error {
		if name != guarantorJournalFile {
			return underneath(root, name, data, perm)
		}
		outcome := ""
		if *writes < len(outcomes) {
			outcome = outcomes[*writes]
		}
		*writes++
		if outcome == "fail" {
			return errInjectedJournalWrite
		}
		if err := underneath(root, name, data, perm); err != nil || outcome != "unsynced" {
			return err
		}
		return fmt.Errorf("%w: %w", fileutil.ErrReplacedNotSynced, errInjectedJournalWrite)
	}
	return writes, func() {
		journal.mu.Lock()
		defer journal.mu.Unlock()
		journal.writeFile = underneath
	}
}

// requireAcceptanceIsRejectedOnlyWhilePrepared accepts two newly issued offers
// against the real authority, which rejects only an action it has not made
// terminal. issue issues an offer of its own Agreement, open for one minute
// from now, and sign signs its acceptance request; restart restarts the
// writer and fence returns its current fence.
//
// The first acceptance's own commit fails after the authority made its action
// terminal. It is not rejected, which the authority would refuse, and it is
// not lost: the process restarts, the acceptance is repeated at a later time
// and completes from its plan, received when the stopped call received it.
//
// The second acceptance arrives after its offer's cutoff, inside the
// processing grace the protocol allows, so the journal refuses it. The
// coordinator learns that while the action is only prepared and rejects it:
// the authority holds the rejection, the admission log records it, and the
// commit that records it loses its sync and is reported with the refusal.
func requireAcceptanceIsRejectedOnlyWhilePrepared(t *testing.T, coordinator *GuarantorProviderCoordinator,
	restart func(), fence func() commerce.WriterFence,
	issue func(name string, issuedAt time.Time, coverageID, stateDomain string) (commerce.AgentAgreementBody,
		guarantor.AuthorizedFirmCoverageOfferV1),
	sign func(commerce.AgentAgreementBody,
		guarantor.AuthorizedFirmCoverageOfferV1) guarantor.AuthorizedCoverageAcceptanceRequestV1,
	now time.Time,
) {
	t.Helper()
	digest := func(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }
	base := coordinator.Authority
	counting := &rejectionCountingAuthority{EconomicAuthority: base}
	coordinator.Authority = counting
	defer func() { coordinator.Authority = base }()
	accept := func(offer guarantor.AuthorizedFirmCoverageOfferV1,
		request guarantor.AuthorizedCoverageAcceptanceRequestV1, receivedAt time.Time,
	) (guarantor.AuthorizedCoverageAcceptanceReceiptV1, commerce.ActionResolution, error) {
		return coordinator.AcceptCoverage(context.Background(), GuarantorAcceptCoverageInput{
			Offer: offer, Request: request, CoverageObligationID: "obligation:coverage",
			ReceivedAtUnix: uint64(receivedAt.Unix()),
		}, fence())
	}
	planned := func(offer guarantor.AuthorizedFirmCoverageOfferV1) bool {
		_, found, err := coordinator.Journal.ActionPlan(guarantorPlanCoverageAcceptance, offer.Body.OfferID, "")
		if err != nil {
			t.Fatalf("read the acceptance plan: %v", err)
		}
		return found
	}

	agreement, offer := issue("unrecorded-acceptance", now.Add(4*time.Second), digest("2"), digest("3"))
	request := sign(agreement, offer)
	_, _, coveragesBefore := testGuarantorSnapshot(t, coordinator.Journal)
	receivedAt := now.Add(30 * time.Second)
	// The admission and the plan are written; the acceptance's own commit
	// fails and writes nothing.
	writes, removeScript := scriptTestGuarantorDocumentWrites(coordinator.Journal, "", "", "fail")
	receipt, resolution, err := accept(offer, request, receivedAt)
	removeScript()
	if *writes != 3 || counting.rejections != 0 || resolution.State != commerce.ActionTerminal ||
		receipt.Body.SchemaVersion != 0 || !errors.Is(err, errInjectedJournalWrite) {
		t.Fatalf("the acceptance whose commit failed: %d document writes, %d rejections, state %s, err=%v; "+
			"want three writes, no rejection, a terminal action and the write failure", *writes,
			counting.rejections, resolution.State, err)
	}
	if _, _, coverages := testGuarantorSnapshot(t, coordinator.Journal); len(coverages) != len(coveragesBefore) ||
		!planned(offer) {
		t.Fatalf("the acceptance whose commit failed left %d coverages, want %d and its plan", len(coverages),
			len(coveragesBefore))
	}
	restart()
	receipt, resolution, err = accept(offer, request, receivedAt.Add(10*time.Second))
	if err != nil || resolution.State != commerce.ActionTerminal || counting.rejections != 0 ||
		receipt.Body.ReceivedAtUnix != uint64(receivedAt.Unix()) {
		t.Fatalf("the acceptance repeated after a restart: state %s, %d rejections, received at %d, err=%v; "+
			"want it completed as received at %d", resolution.State, counting.rejections,
			receipt.Body.ReceivedAtUnix, err, receivedAt.Unix())
	}
	if _, _, coverages := testGuarantorSnapshot(t, coordinator.Journal); len(coverages) != len(coveragesBefore)+1 ||
		planned(offer) {
		t.Fatalf("the resumed acceptance left %d coverages, want %d and no plan", len(coverages),
			len(coveragesBefore)+1)
	}

	agreement, offer = issue("refused-acceptance", now.Add(5*time.Second), digest("6"), digest("7"))
	request = sign(agreement, offer)
	// The admission and the plan are written; the recorded rejection is
	// written and loses its sync.
	writes, removeScript = scriptTestGuarantorDocumentWrites(coordinator.Journal, "", "", "unsynced")
	receipt, resolution, err = accept(offer, request, now.Add(70*time.Second))
	removeScript()
	if *writes != 3 || counting.rejections != 1 || resolution.State != commerce.ActionRejected ||
		receipt.Body.SchemaVersion != 0 {
		t.Fatalf("the acceptance the journal refuses: %d document writes, %d rejections, state %s, err=%v; "+
			"want three writes, one rejection and no receipt", *writes, counting.rejections, resolution.State, err)
	}
	if err == nil || !strings.Contains(err.Error(), "not eligible for acceptance") ||
		!errors.Is(err, ErrGuarantorJournalCommittedNotSynced) {
		t.Fatalf("the acceptance whose recorded rejection lost its sync: got %v, want the journal's refusal "+
			"and the commit whose durability is unconfirmed", err)
	}
	if state := base.Resolve(resolution.StableActionID, resolution.ExactRequestDigest).State; state !=
		commerce.ActionRejected {
		t.Fatalf("the refused acceptance is %s at the authority, want rejected", state)
	}
	if err = coordinator.Journal.ConfirmDurable(); err != nil {
		t.Fatalf("confirm the recorded rejection: %v", err)
	}
	// The stopped call left its plan. The repeated request finds the action
	// rejected, removes the plan and is refused; it is not rejected twice.
	_, resolution, err = accept(offer, request, now.Add(70*time.Second))
	if err == nil || resolution.State != commerce.ActionRejected || counting.rejections != 1 || planned(offer) {
		t.Fatalf("the refused acceptance repeated: state %s, %d rejections, err=%v; want it refused as rejected "+
			"once, with no plan left", resolution.State, counting.rejections, err)
	}
	if _, _, coverages := testGuarantorSnapshot(t, coordinator.Journal); len(coverages) != len(coveragesBefore)+1 {
		t.Fatalf("the refused acceptance left %d coverages, want %d", len(coverages), len(coveragesBefore)+1)
	}
}

// rejectionCountingAuthority counts the transitions to rejected that a
// coordinator asks its authority for.
type rejectionCountingAuthority struct {
	EconomicAuthority
	rejections int
}

func (authority *rejectionCountingAuthority) Transition(stableActionID, exactRequestDigest string,
	state commerce.ActionResolutionState, sinkReference string, evidenceRefs []string,
) (commerce.ActionResolution, error) {
	if state == commerce.ActionRejected {
		authority.rejections++
	}
	return authority.EconomicAuthority.Transition(stableActionID, exactRequestDigest, state, sinkReference,
		evidenceRefs)
}
