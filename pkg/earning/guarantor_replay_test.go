package earning

import (
	"errors"
	"strings"
	"testing"
)

// requireCommittedGuarantorReceiptReplays makes one coordinator call the way
// a caller that never sees its return does, and requires the committed
// receipt every time:
//
//   - the call's last commit, the one that stores its receipt, loses its
//     directory sync: the call returns the committed-but-not-synced error and
//     the head the request was made against is gone. commits is how many
//     commits the call makes; the ones before the last are left alone;
//   - the same request is made again on the same journal;
//   - the process restarts, the journal is opened from disk, and the same
//     request is made once more.
//
// Every repetition must return what the stopped call returned with its error
// and must commit nothing. different, when given, makes a different request
// for the same head and must be refused as a conflict. The coordinator is left
// with the journal opened from disk.
func requireCommittedGuarantorReceiptReplays[Result any](t *testing.T, name string,
	coordinator *GuarantorProviderCoordinator, directory string, commits int,
	call func() (Result, error), different func() error,
) Result {
	t.Helper()
	fault := &journalSyncLossFault{skip: commits - 1, remaining: 1}
	remove := fault.install(coordinator.Journal)
	committed, err := call()
	remove()
	if !errors.Is(err, ErrGuarantorJournalCommittedNotSynced) || fault.lost != 1 || fault.skip != 0 {
		t.Fatalf("%s with its last of %d commits losing its sync: lost=%d skipped all but %d err=%v", name, commits,
			fault.lost, fault.skip, err)
	}
	if err = coordinator.Journal.ConfirmDurable(); err != nil {
		t.Fatalf("confirm the commit of %s: %v", name, err)
	}
	revision, _, _ := testGuarantorSnapshot(t, coordinator.Journal)
	requireSame := func(when string) {
		t.Helper()
		replayed, replayErr := call()
		if replayErr != nil {
			t.Fatalf("%s repeated %s: %v", name, when, replayErr)
		}
		if !sameJSON(replayed, committed) {
			t.Fatalf("%s repeated %s returned another result than the committed one", name, when)
		}
		if after, _, _ := testGuarantorSnapshot(t, coordinator.Journal); after != revision {
			t.Fatalf("%s repeated %s committed something: revision %d, want %d", name, when, after, revision)
		}
	}
	requireSame("on the same journal")
	coordinator.Journal = reopenTestGuarantorJournal(t, coordinator.Journal, directory)
	requireSame("after a restart")
	if different != nil {
		err = different()
		if err == nil || !strings.Contains(err.Error(), "conflicts with") {
			t.Fatalf("a different request for the head of %s: got %v, want a conflict", name, err)
		}
		if after, _, _ := testGuarantorSnapshot(t, coordinator.Journal); after != revision {
			t.Fatalf("a refused request for the head of %s committed something: revision %d, want %d", name, after,
				revision)
		}
	}
	return committed
}
