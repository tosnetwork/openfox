package earning

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	commerce "github.com/tosnetwork/ai/protocol/pkg/agentcommerce"
)

// failAfterReleaseEconomicAuthority fails one release of a reservation after
// the authority underneath has made it, as a process that stops there does.
type failAfterReleaseEconomicAuthority struct {
	EconomicAuthority
	failOnce bool
}

func (authority *failAfterReleaseEconomicAuthority) ReleaseReservation(action commerce.AuthorizedAction,
	fields map[string]commerce.SemanticValue, request []byte, fence commerce.WriterFence,
) (commerce.ActionResolution, error) {
	resolution, err := authority.EconomicAuthority.ReleaseReservation(action, fields, request, fence)
	if err == nil && authority.failOnce {
		authority.failOnce = false
		return resolution, errors.New("injected crash after the authority released the reservation")
	}
	return resolution, err
}

// errTestStoppedBeforeTerminal is what a call stopped right before a terminal
// transition returns.
var errTestStoppedBeforeTerminal = errors.New("injected stop before the terminal transition")

// stopBeforeTerminalEconomicAuthority refuses the first terminal transition
// it is asked for, as a process killed right before it: the action stays
// prepared at the authority underneath.
type stopBeforeTerminalEconomicAuthority struct {
	EconomicAuthority
	stopped bool
}

func (authority *stopBeforeTerminalEconomicAuthority) Transition(stableActionID, exactRequestDigest string,
	state commerce.ActionResolutionState, sinkReference string, evidenceRefs []string,
) (commerce.ActionResolution, error) {
	if state == commerce.ActionTerminal && !authority.stopped {
		authority.stopped = true
		return commerce.ActionResolution{}, errTestStoppedBeforeTerminal
	}
	return authority.EconomicAuthority.Transition(stableActionID, exactRequestDigest, state, sinkReference,
		evidenceRefs)
}

// reportedStateEconomicAuthority reports every action in one state, as a
// damaged or foreign authority store would.
type reportedStateEconomicAuthority struct {
	EconomicAuthority
	state commerce.ActionResolutionState
}

func (authority *reportedStateEconomicAuthority) Resolve(stableActionID, exactRequestDigest string,
) commerce.ActionResolution {
	return commerce.ActionResolution{
		StableActionID: stableActionID, ExactRequestDigest: exactRequestDigest,
		State: authority.state, StateRevision: 1,
	}
}

// testGuarantorActionPlans returns a copy of the action plans the journal
// holds, by key.
func testGuarantorActionPlans(journal *GuarantorJournal) map[string]GuarantorActionPlan {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	plans := make(map[string]GuarantorActionPlan, len(journal.doc.ActionPlans))
	for key, plan := range journal.doc.ActionPlans {
		plans[key] = plan
	}
	return plans
}

// stopTestGuarantorCallAroundEachTerminalTransition makes one coordinator
// call stop the way a process killed at each side of each of its stops
// terminal transitions does, restarting under a new writer generation after
// every stop. For each transition:
//
//   - the call stops right before it: the action is prepared and the journal
//     holds its plan;
//   - the call is repeated one second later and stops there again;
//   - the call is repeated ten minutes later and stops right after it: the
//     action is terminal and nothing is committed for it.
//
// The first call for each transition runs at the authority's clock as it is
// on entry; the repetitions run with the clock moved forward as above, and
// call gets the same offset, for a call whose time is part of its input. A
// restart takes its writer at the entry clock. Every repetition must resume
// the stored plan as it is: no stop may change a plan that was stored before
// it. The clock is as it was when this returns.
//
// Without prepared, the call only stops right after each transition, at the
// entry clock: the lifecycle scenarios that share a step with the one that
// stops it on both sides run it this way, which keeps the package's run
// time bounded.
func stopTestGuarantorCallAroundEachTerminalTransition(t *testing.T, name string,
	coordinator *GuarantorProviderCoordinator, authority *PersonalAuthority, restart func(), stops int,
	prepared bool, call func(later time.Duration) error,
) {
	t.Helper()
	base := coordinator.Authority
	clock := authority.now
	defer func() { authority.now = clock }()
	run := func(stopper EconomicAuthority, later time.Duration) error {
		coordinator.Authority = stopper
		authority.now = func() time.Time { return clock().Add(later) }
		defer func() { coordinator.Authority, authority.now = base, clock }()
		return call(later)
	}
	requirePlans := func(step string, state commerce.ActionResolutionState, before map[string]GuarantorActionPlan) {
		t.Helper()
		plans := testGuarantorActionPlans(coordinator.Journal)
		found := 0
		for key, plan := range plans {
			if base.Resolve(plan.Action.StableActionID, plan.Action.ExactRequestDigest).State == state {
				found++
			}
			if prior, stored := before[key]; stored && !sameJSON(prior, plan) {
				t.Fatalf("%s, %s: the plan stored for %s was changed by a repetition of its request", name, step, key)
			}
		}
		if found == 0 {
			t.Fatalf("%s, %s: the journal holds %d action plans and none whose action is %s", name, step,
				len(plans), state)
		}
	}
	const muchLater = 10 * time.Minute
	for stop := 1; stop <= stops; stop++ {
		// Each transition is first prepared by a call at the entry clock, which
		// resumes the plans of the transitions before it. That call is the
		// first for its own transition, and the steps after this call expect
		// its receipt at the entry clock.
		const first = time.Duration(0)
		if !prepared {
			step := fmt.Sprintf("stop %d of %d, after the terminal transition", stop, stops)
			if err := run(&failAfterTerminalEconomicAuthority{EconomicAuthority: base, failOnce: true},
				first); err == nil || !strings.Contains(err.Error(), "injected crash after terminal authority commit") {
				t.Fatalf("%s, %s: got %v, want the injected stop", name, step, err)
			}
			requirePlans(step, commerce.ActionTerminal, nil)
			restart()
			continue
		}
		step := fmt.Sprintf("stop %d of %d, before the terminal transition", stop, stops)
		if err := run(&stopBeforeTerminalEconomicAuthority{EconomicAuthority: base}, first); err == nil ||
			!strings.Contains(err.Error(), errTestStoppedBeforeTerminal.Error()) {
			t.Fatalf("%s, %s: got %v, want the injected stop", name, step, err)
		}
		requirePlans(step, commerce.ActionPrepared, nil)
		prepared := testGuarantorActionPlans(coordinator.Journal)
		restart()
		step = fmt.Sprintf("stop %d of %d, before the terminal transition, repeated a second later", stop, stops)
		if err := run(&stopBeforeTerminalEconomicAuthority{EconomicAuthority: base}, first+time.Second); err == nil ||
			!strings.Contains(err.Error(), errTestStoppedBeforeTerminal.Error()) {
			t.Fatalf("%s, %s under a newer writer: got %v, want the injected stop", name, step, err)
		}
		requirePlans(step, commerce.ActionPrepared, prepared)
		restart()
		step = fmt.Sprintf("stop %d of %d, after the terminal transition, repeated ten minutes later", stop, stops)
		stopAfter := &failAfterTerminalEconomicAuthority{EconomicAuthority: base, failOnce: true}
		if err := run(stopAfter, first+muchLater); err == nil ||
			!strings.Contains(err.Error(), "injected crash after terminal authority commit") {
			t.Fatalf("%s, %s under a newer writer: got %v, want the injected stop", name, step, err)
		}
		requirePlans(step, commerce.ActionTerminal, prepared)
		restart()
	}
}

// requireCommittedGuarantorReceiptReplays makes one coordinator call the way
// a caller that never sees its return does, and requires the committed
// receipt every time:
//
//   - the call first stops before, if prepared, and after each of its stops
//     terminal transitions (stopTestGuarantorCallAroundEachTerminalTransition), and the
//     process restarts under a new writer generation after each stop, the
//     repetitions running with a later clock;
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
	prepared bool, call func() (Result, error), different func() error,
) Result {
	t.Helper()
	stopTestGuarantorCallAroundEachTerminalTransition(t, name, coordinator, authority, restart, stops, prepared,
		func(time.Duration) error {
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
	// A committed receipt whose action the authority does not hold as terminal
	// is not returned: the authority store is damaged or foreign.
	for _, state := range []commerce.ActionResolutionState{commerce.ActionPrepared, commerce.ActionUnknown} {
		base := coordinator.Authority
		coordinator.Authority = &reportedStateEconomicAuthority{EconomicAuthority: base, state: state}
		_, aheadErr := call()
		coordinator.Authority = base
		if !errors.Is(aheadErr, errGuarantorJournalAheadOfAuthority) {
			t.Fatalf("%s repeated with its action %s at the authority: got %v, want the journal ahead of its "+
				"authority", name, state, aheadErr)
		}
		if after, _, _ := testGuarantorSnapshot(t, coordinator.Journal); after != revision {
			t.Fatalf("%s repeated with its action %s at the authority committed something: revision %d, want %d",
				name, state, after, revision)
		}
	}
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
