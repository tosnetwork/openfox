package earning

import (
	"errors"
	"strings"
	"testing"
	"time"

	commerce "github.com/tosnetwork/ai/protocol/pkg/agentcommerce"
)

// stopTestGuarantorCallAfterEachTerminalTransition makes one coordinator call
// stop the way a process that dies does, once after each of its stops
// terminal transitions: the authority has made the action terminal and the
// call returns before it commits anything for it. After each stop the process
// restarts, which restart does: the journal is opened from disk and the
// writer takes a new generation. The call is then made again. Each stopped
// call must fail with the injected stop, leave an action plan in the journal
// and leave the authority holding a plan's action as terminal.
func stopTestGuarantorCallAfterEachTerminalTransition(t *testing.T, name string,
	coordinator *GuarantorProviderCoordinator, restart func(), stops int, call func() error,
) {
	t.Helper()
	base := coordinator.Authority
	for stop := 1; stop <= stops; stop++ {
		coordinator.Authority = &failAfterTerminalEconomicAuthority{EconomicAuthority: base, failOnce: true}
		err := call()
		coordinator.Authority = base
		if err == nil || !strings.Contains(err.Error(), "injected crash after terminal authority commit") {
			t.Fatalf("%s, stop %d of %d after a terminal transition: got %v, want the injected stop", name, stop,
				stops, err)
		}
		terminal := 0
		coordinator.Journal.mu.Lock()
		plans := len(coordinator.Journal.doc.ActionPlans)
		for _, plan := range coordinator.Journal.doc.ActionPlans {
			state := base.Resolve(plan.Action.StableActionID, plan.Action.ExactRequestDigest).State
			if state == commerce.ActionTerminal {
				terminal++
			}
		}
		coordinator.Journal.mu.Unlock()
		if plans == 0 || terminal == 0 {
			t.Fatalf("%s, stop %d of %d: the journal holds %d action plans, %d of them terminal at the authority; "+
				"want a plan whose action is terminal", name, stop, stops, plans, terminal)
		}
		restart()
	}
}

// requireCommittedGuarantorReceiptReplays makes one coordinator call the way
// a caller that never sees its return does, and requires the committed
// receipt every time:
//
//   - the call first stops once after each of its stops terminal transitions,
//     with the authority terminal and nothing committed for it, and the
//     process restarts under a new writer generation and a later clock;
//   - the call that then completes loses the directory sync of its commit,
//     the one that stores its receipt: it returns the committed-but-not-synced
//     error with the receipt, and the head the request was made against is
//     gone;
//   - the same request is made again on the same journal;
//   - the process restarts once more and the same request is made again.
//
// Every repetition must return what the completing call returned with its
// error and must commit nothing, and no action plan is left. different, when
// given, makes a different request for the same head and must be refused as a
// conflict.
//
// The call that completes, and every repetition, runs with the authority's
// clock a second later than the stopped calls ran: the receipt is the one the
// stopped call prepared, at that call's time. The clock is as it was when
// this returns.
func requireCommittedGuarantorReceiptReplays[Result any](t *testing.T, name string,
	coordinator *GuarantorProviderCoordinator, authority *PersonalAuthority, restart func(), stops int,
	call func() (Result, error), different func() error,
) Result {
	t.Helper()
	stopTestGuarantorCallAfterEachTerminalTransition(t, name, coordinator, restart, stops, func() error {
		_, err := call()
		return err
	})
	clock := authority.now
	defer func() { authority.now = clock }()
	authority.now = func() time.Time { return clock().Add(time.Second) }
	fault := &journalSyncLossFault{remaining: 1}
	remove := fault.install(coordinator.Journal)
	committed, err := call()
	remove()
	if !errors.Is(err, ErrGuarantorJournalCommittedNotSynced) || fault.lost != 1 {
		t.Fatalf("%s resumed after %d stops, with its commit losing its sync: lost=%d err=%v", name, stops,
			fault.lost, err)
	}
	if err = coordinator.Journal.ConfirmDurable(); err != nil {
		t.Fatalf("confirm the commit of %s: %v", name, err)
	}
	coordinator.Journal.mu.Lock()
	plans := len(coordinator.Journal.doc.ActionPlans)
	coordinator.Journal.mu.Unlock()
	if plans != 0 {
		t.Fatalf("%s committed its receipt and left %d action plans", name, plans)
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
	restart()
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
