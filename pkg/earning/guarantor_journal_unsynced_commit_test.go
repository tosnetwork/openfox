package earning

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	commerce "github.com/tosnetwork/ai/protocol/pkg/agentcommerce"

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

// journalSyncLossFault makes document writes that commit something new lose
// their directory sync: the document is written and renamed into place and
// the write then reports the failed sync. It does so for the next remaining
// new documents and counts them in lost. Writing the same document again,
// which is how the journal confirms a commit, goes through.
type journalSyncLossFault struct {
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
	call func() error) int {
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

// rejectionCountingAuthority counts the transitions to rejected that a
// coordinator asks its authority for.
type rejectionCountingAuthority struct {
	EconomicAuthority
	rejections int
}

func (authority *rejectionCountingAuthority) Transition(stableActionID, exactRequestDigest string,
	state commerce.ActionResolutionState, sinkReference string, evidenceRefs []string) (commerce.ActionResolution, error) {
	if state == commerce.ActionRejected {
		authority.rejections++
	}
	return authority.EconomicAuthority.Transition(stableActionID, exactRequestDigest, state, sinkReference, evidenceRefs)
}
