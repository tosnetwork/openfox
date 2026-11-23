package earning

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	commerce "github.com/tosnetwork/ai/protocol/pkg/agentcommerce"
	guarantor "github.com/tosnetwork/ai/protocol/pkg/agentguarantor"
)

// actionPlanTestAgreement is the coverage Agreement of the fixture's coverage.
var actionPlanTestAgreement = "sha256:" + strings.Repeat("c", 64)

// actionPlanFixture is a journal holding one coverage, beside a real
// authority that issues the writer fences and signs the actions of the plans
// a test stores.
type actionPlanFixture struct {
	journal   *GuarantorJournal
	directory string
	authority *PersonalAuthority
	fence     commerce.WriterFence
	scope     []string
}

func newActionPlanFixture(t *testing.T) *actionPlanFixture {
	t.Helper()
	journal, directory := openTestGuarantorJournal(t)
	claimID := "sha256:" + strings.Repeat("b", 64)
	rewriteTestGuarantorJournal(t, journal, func(doc *guarantorJournalDocument) {
		position := testCoverageWithClaim(claimID)
		position.RevisionEpochs = map[string]GuarantorRevisionEpochState{claimID: testFrozenEpoch()}
		position.Record.CoverageAgreementBodyDigest = actionPlanTestAgreement
		position.Record.ReservationID = "sha256:" + strings.Repeat("2", 64)
		doc.Coverages[actionPlanTestAgreement] = position
	})
	journal, err := OpenGuarantorJournal(directory, "owner:guarantor", "agent:guarantor")
	if err != nil {
		t.Fatal(err)
	}
	closeGuarantorJournalOnCleanup(t, journal)
	authorityDirectory := filepath.Join(t.TempDir(), "authority")
	if err = os.Mkdir(authorityDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	authority, err := OpenPersonalAuthority(authorityDirectory, "owner:guarantor", "agent:guarantor", "authority:owner",
		testAuthorityKeys(), PortfolioLimits{MaximumLossAtomic: 10_000, LockedCapitalAtomic: 10_000})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = authority.Close() })
	fixture := &actionPlanFixture{
		journal: journal, directory: directory, authority: authority,
		scope: []string{"conditional.obligation.transition", "portfolio.release"},
	}
	sort.Strings(fixture.scope)
	fixture.fence = fixture.nextFence(t)
	return fixture
}

// nextFence takes the next writer generation.
func (fixture *actionPlanFixture) nextFence(t *testing.T) commerce.WriterFence {
	t.Helper()
	fence, err := fixture.authority.AcquireWriter(context.Background(), "instance:test", fixture.scope, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return fence
}

// plan returns a cancellation plan for the fixture's coverage, authorized
// under fence, whose request is request.
func (fixture *actionPlanFixture) plan(t *testing.T, fence commerce.WriterFence, request string,
) GuarantorActionPlan {
	t.Helper()
	fields := map[string]commerce.SemanticValue{
		"owner_id": commerce.ID("owner:guarantor"), "agent_id": commerce.ID("agent:guarantor"),
		"agreement_body_digest":   commerce.Digest32(actionPlanTestAgreement),
		"obligation_id":           commerce.ID("obligation:coverage"),
		"expected_state_revision": commerce.U64(1), "target_state": commerce.State("coverage_ended"),
		"evidence_set_digest": commerce.Digest32("sha256:" + strings.Repeat("e", 64)),
	}
	canonical, err := guarantor.Canonical(struct {
		Request string `json:"request"`
	}{request})
	if err != nil {
		t.Fatal(err)
	}
	action, err := commerce.BuildAuthorizedAction("owner:guarantor", "agent:guarantor",
		"conditional.obligation.transition", fields, canonical, fence, 1, "sha256:"+strings.Repeat("5", 64), "",
		"sha256:"+strings.Repeat("a", 64), fence.Body.ExpiresAtUnix)
	if err == nil {
		action, err = fixture.authority.SignAction(action, fence)
	}
	if err != nil {
		t.Fatal(err)
	}
	return GuarantorActionPlan{
		Kind: guarantorPlanCoverageCancellation, ScopeID: actionPlanTestAgreement, Action: action, WriterFence: fence,
		Fields: fields, CanonicalRequest: canonical, PreparedAtUnix: fence.Body.IssuedAtUnix,
	}
}

// coordinator returns a coordinator over the fixture's journal and authority
// with the identity its plans are authorized for.
func (fixture *actionPlanFixture) coordinator() *GuarantorProviderCoordinator {
	return &GuarantorProviderCoordinator{
		OwnerID: "owner:guarantor", AgentID: "agent:guarantor", PolicyRevision: 1,
		MandateDigest: "sha256:" + strings.Repeat("5", 64), Authority: fixture.authority, Journal: fixture.journal,
	}
}

// prepare makes the fixture's cancellation plan the first call would: the
// call at at, under a writer fence taken at at, stores the plan and the
// authority admits its action. It returns the plan as stored.
func (fixture *actionPlanFixture) prepare(t *testing.T, coordinator *GuarantorProviderCoordinator,
	at time.Time,
) GuarantorActionPlan {
	t.Helper()
	fixture.authority.now = func() time.Time { return at }
	fixture.fence = fixture.nextFence(t)
	plan := fixture.plan(t, fixture.fence, "cancel")
	planned, err := coordinator.plannedAction(plan.Kind, plan.ScopeID, "", fixture.fence)
	if err != nil || planned.resuming() {
		t.Fatalf("look up the plan of a first call: resuming=%v err=%v", planned.resuming(), err)
	}
	action, err := coordinator.authorizePlannedAction(planned, "owner:guarantor", "agent:guarantor",
		"conditional.obligation.transition", plan.Fields, plan.CanonicalRequest, fixture.fence,
		plan.Action.ExpectedPriorState, fixture.fence.Body.ExpiresAtUnix)
	if err != nil {
		t.Fatal(err)
	}
	resolution, err := coordinator.admitPlannedAction(planned, action, plan.Fields, plan.CanonicalRequest,
		fixture.fence, at)
	if err != nil || resolution.State != commerce.ActionPrepared {
		t.Fatalf("admit the planned action: state=%s err=%v", resolution.State, err)
	}
	stored, found, err := fixture.journal.ActionPlan(plan.Kind, plan.ScopeID, "")
	if err != nil || !found {
		t.Fatalf("the prepared plan is not stored: found=%v err=%v", found, err)
	}
	return stored
}

// unreachableTestSharedAuthority is a shared authority client whose server
// refuses every connection.
func unreachableTestSharedAuthority(t *testing.T) *SharedAuthorityClient {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err = listener.Close(); err != nil {
		t.Fatal(err)
	}
	return &SharedAuthorityClient{
		Endpoint:   "http://" + address + "/authority",
		HTTPClient: &http.Client{Timeout: time.Second},
	}
}

func (fixture *actionPlanFixture) revision(t *testing.T) uint64 {
	t.Helper()
	revision, _, _ := testGuarantorSnapshot(t, fixture.journal)
	return revision
}

// TestGuarantorJournalStoresOnlyAnActionPlanItWouldLoad: an action plan is
// stored once per head, read back with its semantic fields, kept across a
// restart, and refused when it is not one a load would accept or when its
// head already holds another.
func TestGuarantorJournalStoresOnlyAnActionPlanItWouldLoad(t *testing.T) {
	fixture := newActionPlanFixture(t)
	plan := fixture.plan(t, fixture.fence, "cancel")
	before := fixture.revision(t)
	for name, change := range map[string]func(plan *GuarantorActionPlan){
		"an unknown kind":            func(plan *GuarantorActionPlan) { plan.Kind = "coverage_revival" },
		"a kind with another action": func(plan *GuarantorActionPlan) { plan.Kind = guarantorPlanClaimIngress },
		"a scope that is no digest":  func(plan *GuarantorActionPlan) { plan.ScopeID = "coverage" },
		"a coverage the journal does not hold": func(plan *GuarantorActionPlan) {
			plan.ScopeID = "sha256:" + strings.Repeat("d", 64)
		},
		"no time":                   func(plan *GuarantorActionPlan) { plan.PreparedAtUnix = 0 },
		"another owner's action":    func(plan *GuarantorActionPlan) { plan.Action.OwnerID = "owner:other" },
		"another stable identity":   func(plan *GuarantorActionPlan) { plan.Action.StableActionID = plan.ScopeID },
		"another request":           func(plan *GuarantorActionPlan) { plan.CanonicalRequest = []byte{0xa0} },
		"another writer generation": func(plan *GuarantorActionPlan) { plan.Action.WriterGeneration++ },
		"another writer fence":      func(plan *GuarantorActionPlan) { plan.WriterFence.Body.LeaseID = "lease:other" },
		"fields for another coverage": func(plan *GuarantorActionPlan) {
			fields := map[string]commerce.SemanticValue{}
			for field, value := range plan.Fields {
				fields[field] = value
			}
			fields["agreement_body_digest"] = commerce.Digest32("sha256:" + strings.Repeat("d", 64))
			plan.Fields = fields
		},
		"a time after its writer fence's lease": func(plan *GuarantorActionPlan) {
			plan.PreparedAtUnix = plan.WriterFence.Body.ExpiresAtUnix
		},
		"a time before its writer fence was issued": func(plan *GuarantorActionPlan) {
			plan.PreparedAtUnix = plan.WriterFence.Body.IssuedAtUnix - uint64(commerce.MaxIntentClockSkew/time.Second) - 1
		},
	} {
		changed := plan
		change(&changed)
		if err := fixture.journal.PrepareActionPlan(changed); err == nil {
			t.Errorf("an action plan with %s was stored", name)
		}
	}
	if after := fixture.revision(t); after != before {
		t.Fatalf("refused action plans changed the journal: revision %d, want %d", after, before)
	}
	if err := fixture.journal.PrepareActionPlan(plan); err != nil {
		t.Fatalf("store a valid action plan: %v", err)
	}
	if err := fixture.journal.PrepareActionPlan(plan); err != nil || fixture.revision(t) != before+1 {
		t.Fatalf("storing the same action plan again: revision %d, want %d, err=%v", fixture.revision(t), before+1, err)
	}
	if err := fixture.journal.PrepareActionPlan(fixture.plan(t, fixture.fence, "another")); err == nil ||
		!strings.Contains(err.Error(), "conflicts with the plan stored") {
		t.Fatalf("a second action plan for a head that holds one: got %v", err)
	}
	requireStored := func(journal *GuarantorJournal, when string) {
		t.Helper()
		stored, found, err := journal.ActionPlan(plan.Kind, plan.ScopeID, plan.SubjectID)
		if err != nil || !found || !sameJSON(stored, plan) || !reflect.DeepEqual(stored.Fields, plan.Fields) {
			t.Fatalf("the action plan %s: found=%v err=%v, or it is not the plan stored", when, found, err)
		}
	}
	requireStored(fixture.journal, "read back")
	fixture.journal = reopenTestGuarantorJournal(t, fixture.journal, fixture.directory)
	requireStored(fixture.journal, "loaded from disk")
	if _, found, err := fixture.journal.ActionPlan(guarantorPlanCoverageActivation, plan.ScopeID, ""); err != nil ||
		found {
		t.Fatalf("a head without a plan returned one: found=%v err=%v", found, err)
	}
}

// TestGuarantorJournalRefusesATamperedActionPlan: a document whose action
// plan was changed on disk is refused at load; the same document written back
// unchanged loads.
func TestGuarantorJournalRefusesATamperedActionPlan(t *testing.T) {
	fixture := newActionPlanFixture(t)
	plan := fixture.plan(t, fixture.fence, "cancel")
	if err := fixture.journal.PrepareActionPlan(plan); err != nil {
		t.Fatal(err)
	}
	if err := fixture.journal.Close(); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(filepath.Join(fixture.directory, guarantorJournalFile))
	if err != nil {
		t.Fatal(err)
	}
	key := guarantorActionPlanKey(plan.Kind, plan.ScopeID, plan.SubjectID)
	stored := func(doc map[string]any) map[string]any {
		entry, found := doc["action_plans"].(map[string]any)[key].(map[string]any)
		if !found {
			t.Fatalf("the document holds no action plan under %s", key)
		}
		return entry
	}
	action := func(doc map[string]any) map[string]any {
		entry, found := stored(doc)["authorized_action"].(map[string]any)
		if !found {
			t.Fatal("the stored action plan has no action object")
		}
		return entry
	}
	other := "sha256:" + strings.Repeat("d", 64)
	for name, change := range map[string]func(doc map[string]any){
		"its kind":              func(doc map[string]any) { stored(doc)["kind"] = guarantorPlanNonActivation },
		"an unknown kind":       func(doc map[string]any) { stored(doc)["kind"] = "coverage_revival" },
		"its scope":             func(doc map[string]any) { stored(doc)["scope_id"] = other },
		"its subject":           func(doc map[string]any) { stored(doc)["subject_id"] = "claim" },
		"its time removed":      func(doc map[string]any) { stored(doc)["prepared_at_unix"] = 0 },
		"its stable identity":   func(doc map[string]any) { action(doc)["stable_action_id"] = other },
		"its request digest":    func(doc map[string]any) { action(doc)["exact_request_digest"] = other },
		"its action's owner":    func(doc map[string]any) { action(doc)["owner_id"] = "owner:other" },
		"its writer generation": func(doc map[string]any) { action(doc)["writer_generation"] = 99 },
		"its request":           func(doc map[string]any) { stored(doc)["canonical_request"] = "oA==" },
		"its fields removed":    func(doc map[string]any) { delete(stored(doc), "semantic_fields") },
		"an unknown member":     func(doc map[string]any) { stored(doc)["note"] = "x" },
		"its key": func(doc map[string]any) {
			plans := doc["action_plans"].(map[string]any)
			plans[guarantorActionPlanKey(plan.Kind, other, "")] = plans[key]
			delete(plans, key)
		},
		"its coverage removed": func(doc map[string]any) { doc["coverages"] = map[string]any{} },
		"an empty plan map":    func(doc map[string]any) { doc["action_plans"] = map[string]any{} },
		"its time moved past its writer fence's lease": func(doc map[string]any) {
			stored(doc)["prepared_at_unix"] = plan.WriterFence.Body.ExpiresAtUnix
		},
		"its time moved before its writer fence was issued": func(doc map[string]any) {
			stored(doc)["prepared_at_unix"] = plan.WriterFence.Body.IssuedAtUnix -
				uint64(commerce.MaxIntentClockSkew/time.Second) - 1
		},
	} {
		editTestGuarantorJournalFile(t, fixture.directory, original, change)
		// A journal that loads is closed at once: left open it would hold the
		// journal's lock and every later case would be refused for that.
		loaded, loadErr := OpenGuarantorJournal(fixture.directory, "owner:guarantor", "agent:guarantor")
		if loadErr == nil {
			t.Errorf("a journal whose action plan has %s changed was loaded", name)
			if closeErr := loaded.Close(); closeErr != nil {
				t.Fatal(closeErr)
			}
		}
	}
	editTestGuarantorJournalFile(t, fixture.directory, original, func(map[string]any) {})
	if loadErr := openTestGuarantorJournalErr(t, fixture.directory); loadErr != nil {
		t.Fatalf("the unchanged journal with its action plan was refused: %v", loadErr)
	}
}

// TestGuarantorActionPlanIsDiscardedOrResumedByWhatTheAuthorityHolds: a plan
// whose action the authority never saw is discarded and the head is free; a
// plan whose action is prepared or terminal is resumed as stored, with its
// action, fence and time, by its own writer generation and by a newer one,
// and refused to an older one.
func TestGuarantorActionPlanIsDiscardedOrResumedByWhatTheAuthorityHolds(t *testing.T) {
	fixture := newActionPlanFixture(t)
	coordinator := fixture.coordinator()
	kind, scope := guarantorPlanCoverageCancellation, actionPlanTestAgreement
	first := time.Unix(2_000_000_000, 0).UTC()
	fixture.authority.now = func() time.Time { return first }
	fixture.fence = fixture.nextFence(t)
	plan := fixture.plan(t, fixture.fence, "cancel")
	lookup := func(fence commerce.WriterFence, _ time.Time) guarantorPlannedAction {
		t.Helper()
		planned, err := coordinator.plannedAction(kind, scope, "", fence)
		if err != nil {
			t.Fatalf("look the action plan up: %v", err)
		}
		return planned
	}
	authorize := func(planned guarantorPlannedAction, fence commerce.WriterFence, request []byte,
	) (commerce.AuthorizedAction, error) {
		return coordinator.authorizePlannedAction(planned, "owner:guarantor", "agent:guarantor",
			"conditional.obligation.transition", plan.Fields, request, fence, plan.Action.ExpectedPriorState,
			fence.Body.ExpiresAtUnix)
	}

	// Never admitted: discarded.
	if err := fixture.journal.PrepareActionPlan(plan); err != nil {
		t.Fatal(err)
	}
	if planned := lookup(fixture.fence, first); planned.resuming() {
		t.Fatal("a plan whose action the authority never saw is resumed")
	}
	if _, found, err := fixture.journal.ActionPlan(kind, scope, ""); err != nil || found {
		t.Fatalf("a plan whose action the authority never saw was kept: found=%v err=%v", found, err)
	}

	// Prepared: the first call stores the plan and admits the action.
	planned := lookup(fixture.fence, first)
	action, err := authorize(planned, fixture.fence, plan.CanonicalRequest)
	if err != nil {
		t.Fatal(err)
	}
	fields, request := plan.Fields, plan.CanonicalRequest
	resolution, err := coordinator.admitPlannedAction(planned, action, fields, request, fixture.fence, first)
	if err != nil || resolution.State != commerce.ActionPrepared {
		t.Fatalf("admit the planned action: state=%s err=%v", resolution.State, err)
	}
	// Its own generation keeps the plan, its fence and its time.
	later := first.Add(time.Minute)
	same := lookup(fixture.fence, later)
	if !same.resuming() || !same.at(later).Equal(first) || !sameJSON(same.fence(fixture.fence), fixture.fence) {
		t.Fatalf("the plan's own generation does not keep the prepared plan: %#v", same)
	}
	// A different request for the head is refused.
	if _, err = authorize(same, fixture.fence, []byte{0xa0}); err == nil ||
		!strings.Contains(err.Error(), "conflicts with the action already prepared") {
		t.Fatalf("a different request for a head with a prepared plan: got %v", err)
	}
	// A newer generation keeps it too: the stored action, its fence and time.
	fixture.authority.now = func() time.Time { return later }
	newer := fixture.nextFence(t)
	resumed := lookup(newer, later)
	if !resumed.resuming() || !resumed.at(later).Equal(first) || !sameJSON(resumed.fence(newer), fixture.fence) {
		t.Fatalf("a newer generation does not keep the prepared plan: %#v", resumed)
	}
	again, err := authorize(resumed, newer, plan.CanonicalRequest)
	if err != nil || !sameJSON(again, action) {
		t.Fatalf("a newer generation does not take the prepared action as stored: err=%v", err)
	}
	stored, found, err := fixture.journal.ActionPlan(kind, scope, "")
	if err != nil || !found || !sameJSON(stored.Action, action) || !sameJSON(stored.WriterFence, fixture.fence) ||
		stored.PreparedAtUnix != uint64(first.Unix()) {
		t.Fatalf("the resumed plan is not the one stored: found=%v err=%v", found, err)
	}
	older := fixture.fence
	older.Body.WriterGeneration--
	if _, staleErr := coordinator.plannedAction(kind, scope, "", older); staleErr == nil ||
		!strings.Contains(staleErr.Error(), "stale writer") {
		t.Fatalf("an older generation looked a newer generation's prepared plan up: %v", staleErr)
	}

	// Terminal: any generation keeps the plan as stored, and the result the
	// authority recorded must be the one the call rebuilds.
	sink := "sha256:" + strings.Repeat("7", 64)
	resolution, err = coordinator.settlePlannedAction(resolution, again, sink, []string{sink})
	if err != nil || resolution.State != commerce.ActionTerminal {
		t.Fatalf("settle the planned action: state=%s err=%v", resolution.State, err)
	}
	newest := fixture.nextFence(t)
	terminal := lookup(newest, later.Add(time.Minute))
	if !terminal.resuming() || !terminal.at(later.Add(time.Minute)).Equal(first) ||
		!sameJSON(terminal.fence(newest), fixture.fence) {
		t.Fatalf("a terminal plan is not kept as stored by a newer generation: %#v", terminal)
	}
	if _, err = coordinator.settlePlannedAction(resolution, again, sink, []string{sink}); err != nil {
		t.Fatalf("settling a terminal action with the result it has: %v", err)
	}
	otherSink := "sha256:" + strings.Repeat("8", 64)
	if _, err = coordinator.settlePlannedAction(resolution, again, otherSink, []string{otherSink}); err == nil ||
		!strings.Contains(err.Error(), "conflicts with the receipt rebuilt") {
		t.Fatalf("settling a terminal action with another result: got %v", err)
	}
	if err = fixture.journal.DiscardUnadmittedActionPlan(kind, scope, "", fixture.authority); err == nil {
		t.Fatal("a plan whose action is terminal was discarded")
	}
	// An action the authority knows without a plan is not built on.
	fixture.journal.mu.Lock()
	delete(fixture.journal.doc.ActionPlans, guarantorActionPlanKey(kind, scope, ""))
	fixture.journal.mu.Unlock()
	orphan := lookup(newest, later)
	_, err = coordinator.admitPlannedAction(orphan, again, fields, request, newest, later)
	if err == nil || !strings.Contains(err.Error(), "holds no plan for it") {
		t.Fatalf("admitting an action the authority holds as terminal without a plan: got %v", err)
	}
}

// TestGuarantorPreparedActionPlanResumesAtItsOwnTimeUnderANewerWriter: a plan
// whose action is prepared, looked up by a newer writer generation a second
// and ten minutes after it was stored, is resumed with its own action, writer
// fence and time, whatever time the call has, and the stored plan does not
// change. A request the plan holds is then rebuilt exactly, at the plan's
// time, and the action the call takes is the stored one.
func TestGuarantorPreparedActionPlanResumesAtItsOwnTimeUnderANewerWriter(t *testing.T) {
	fixture := newActionPlanFixture(t)
	coordinator := fixture.coordinator()
	first := time.Unix(2_000_000_000, 0).UTC()
	stored := fixture.prepare(t, coordinator, first)
	for _, delay := range []time.Duration{time.Second, 10 * time.Minute} {
		later := first.Add(delay)
		fixture.authority.now = func() time.Time { return later }
		newer := fixture.nextFence(t)
		resumed, err := coordinator.plannedAction(stored.Kind, stored.ScopeID, "", newer)
		if err != nil || !resumed.resuming() {
			t.Fatalf("%s later, a newer writer looks the prepared plan up: resuming=%v err=%v", delay,
				resumed.resuming(), err)
		}
		if !resumed.at(later).Equal(first) || resumed.atUnix(uint64(later.Unix())) != uint64(first.Unix()) ||
			!sameJSON(resumed.fence(newer), stored.WriterFence) {
			t.Fatalf("%s later, the resumed call has the time %s and generation %d; want the plan's %s and %d",
				delay, resumed.at(later), resumed.fence(newer).Body.WriterGeneration, first,
				stored.WriterFence.Body.WriterGeneration)
		}
		action, err := coordinator.authorizePlannedAction(resumed, "owner:guarantor", "agent:guarantor",
			"conditional.obligation.transition", stored.Fields, stored.CanonicalRequest, resumed.fence(newer),
			stored.Action.ExpectedPriorState, stored.WriterFence.Body.ExpiresAtUnix)
		if err != nil || !sameJSON(action, stored.Action) {
			t.Fatalf("%s later, the resumed call does not take the stored action: err=%v", delay, err)
		}
		after, found, err := fixture.journal.ActionPlan(stored.Kind, stored.ScopeID, "")
		if err != nil || !found || !sameJSON(after, stored) {
			t.Fatalf("%s later, resuming the prepared plan changed it: found=%v err=%v", delay, found, err)
		}
	}
}

// TestGuarantorActionPlanIsKeptWhileItsAuthorityCannotBeReached: an authority
// that does not answer says nothing about an action. A plan whose action is
// prepared is neither discarded nor resumed while its authority cannot be
// reached, and neither is a firm-offer plan; once the authority answers, the
// call resumes the plan as stored.
func TestGuarantorActionPlanIsKeptWhileItsAuthorityCannotBeReached(t *testing.T) {
	fixture := newActionPlanFixture(t)
	coordinator := fixture.coordinator()
	first := time.Unix(2_000_000_000, 0).UTC()
	stored := fixture.prepare(t, coordinator, first)
	unreachable := unreachableTestSharedAuthority(t)
	if state := unreachable.Resolve(stored.Action.StableActionID,
		stored.Action.ExactRequestDigest).State; state == commerce.ActionUnknown {
		t.Fatal("an authority that cannot be reached reports the action unknown")
	}
	if _, err := ResolveGuarantorAction(unreachable, stored.Action.StableActionID,
		stored.Action.ExactRequestDigest); err == nil {
		t.Fatal("an authority that cannot be reached is reported with a state of the action")
	}
	coordinator.Authority = unreachable
	if _, err := coordinator.plannedAction(stored.Kind, stored.ScopeID, "", fixture.fence); err == nil {
		t.Fatal("a plan was looked up while its authority could not be reached")
	}
	if err := fixture.journal.DiscardUnadmittedActionPlan(stored.Kind, stored.ScopeID, "", unreachable); err == nil {
		t.Fatal("a plan was discarded while its authority could not be reached")
	}
	if kept, found, err := fixture.journal.ActionPlan(stored.Kind, stored.ScopeID, ""); err != nil || !found ||
		!sameJSON(kept, stored) {
		t.Fatalf("the plan is not kept while its authority cannot be reached: found=%v err=%v", found, err)
	}
	// A firm-offer plan names its action the same way; it is not discarded
	// either while the authority cannot say whether it knows the action.
	instance := "sha256:" + strings.Repeat("9", 64)
	fixture.journal.mu.Lock()
	fixture.journal.doc.FirmOfferIssuancePlans = map[string]GuarantorFirmOfferIssuancePlan{
		instance: {AuthorityInstanceID: instance, Action: stored.Action},
	}
	fixture.journal.mu.Unlock()
	discardErr := fixture.journal.DiscardUnadmittedFirmOfferIssuancePlan(instance, unreachable)
	fixture.journal.mu.Lock()
	_, firmOfferKept := fixture.journal.doc.FirmOfferIssuancePlans[instance]
	delete(fixture.journal.doc.FirmOfferIssuancePlans, instance)
	fixture.journal.mu.Unlock()
	if discardErr == nil || !firmOfferKept {
		t.Fatalf("a firm-offer plan while its authority could not be reached: kept=%v err=%v", firmOfferKept,
			discardErr)
	}
	coordinator.Authority = fixture.authority
	resumed, err := coordinator.plannedAction(stored.Kind, stored.ScopeID, "", fixture.fence)
	if err != nil || !resumed.resuming() || !sameJSON(*resumed.resume, stored) {
		t.Fatalf("once the authority answers, the plan is not resumed as stored: err=%v", err)
	}
}

// TestGuarantorPreparedActionPlanIsAbandonedAtItsAuthorityFirst: a prepared
// plan is listed, and abandoning it rejects its action at the authority and
// then discards the plan, under the current writer only. While the authority
// cannot be reached, or the writer is not current, nothing changes.
func TestGuarantorPreparedActionPlanIsAbandonedAtItsAuthorityFirst(t *testing.T) {
	fixture := newActionPlanFixture(t)
	coordinator := fixture.coordinator()
	first := time.Unix(2_000_000_000, 0).UTC()
	stored := fixture.prepare(t, coordinator, first)
	kind, scope := stored.Kind, stored.ScopeID
	if plans, err := fixture.journal.ActionPlans(); err != nil || len(plans) != 1 || !sameJSON(plans[0], stored) {
		t.Fatalf("the stored plans are listed as %d plans, err=%v", len(plans), err)
	}
	requireKept := func(when string) {
		t.Helper()
		kept, found, err := fixture.journal.ActionPlan(kind, scope, "")
		if err != nil || !found || !sameJSON(kept, stored) {
			t.Fatalf("%s, the plan is not kept: found=%v err=%v", when, found, err)
		}
		if state := fixture.authority.Resolve(stored.Action.StableActionID,
			stored.Action.ExactRequestDigest).State; state != commerce.ActionPrepared {
			t.Fatalf("%s, the action is %s at the authority, want prepared", when, state)
		}
	}
	if _, _, err := fixture.journal.AbandonPreparedActionPlan(kind, scope, "", unreachableTestSharedAuthority(t),
		fixture.fence, first); err == nil {
		t.Fatal("a plan was abandoned while its authority could not be reached")
	}
	requireKept("while the authority cannot be reached")
	stale := fixture.fence
	current := fixture.nextFence(t)
	if _, _, err := fixture.journal.AbandonPreparedActionPlan(kind, scope, "", fixture.authority, stale,
		first); err == nil {
		t.Fatal("a plan was abandoned under a writer that is not current")
	}
	requireKept("under a writer that is not current")
	abandoned, resolution, err := fixture.journal.AbandonPreparedActionPlan(kind, scope, "", fixture.authority,
		current, first)
	if err != nil || resolution.State != commerce.ActionRejected || !sameJSON(abandoned, stored) {
		t.Fatalf("abandon the prepared plan: state=%s err=%v", resolution.State, err)
	}
	if state := fixture.authority.Resolve(stored.Action.StableActionID,
		stored.Action.ExactRequestDigest).State; state != commerce.ActionRejected {
		t.Fatalf("the abandoned action is %s at the authority, want rejected", state)
	}
	if plans, listErr := fixture.journal.ActionPlans(); listErr != nil || len(plans) != 0 {
		t.Fatalf("the abandoned plan is still listed: %d plans, err=%v", len(plans), listErr)
	}
	if _, _, err = fixture.journal.AbandonPreparedActionPlan(kind, scope, "", fixture.authority, current,
		first); err == nil || !strings.Contains(err.Error(), "no action plan") {
		t.Fatalf("abandoning a head without a plan: got %v", err)
	}
}

// TestGuarantorActionPlanAbandonmentRefusesATerminalAction: a plan whose
// action is terminal is completed by repeating its request, never abandoned,
// and is kept.
func TestGuarantorActionPlanAbandonmentRefusesATerminalAction(t *testing.T) {
	first := time.Unix(2_000_000_000, 0).UTC()
	kind, scope := guarantorPlanCoverageCancellation, actionPlanTestAgreement
	terminalFixture := newActionPlanFixture(t)
	terminalCoordinator := terminalFixture.coordinator()
	terminal := terminalFixture.prepare(t, terminalCoordinator, first)
	sink := "sha256:" + strings.Repeat("7", 64)
	if _, err := terminalFixture.authority.Transition(terminal.Action.StableActionID,
		terminal.Action.ExactRequestDigest, commerce.ActionTerminal, sink, []string{sink}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := terminalFixture.journal.AbandonPreparedActionPlan(kind, scope, "", terminalFixture.authority,
		terminalFixture.fence, first); err == nil || !strings.Contains(err.Error(), "terminal") {
		t.Fatalf("abandoning a plan whose action is terminal: got %v", err)
	}
	if kept, found, keptErr := terminalFixture.journal.ActionPlan(kind, scope, ""); keptErr != nil || !found ||
		!sameJSON(kept, terminal) {
		t.Fatalf("a plan whose action is terminal is not kept: found=%v err=%v", found, keptErr)
	}
}

// TestGuarantorActionPlanAbandonmentDiscardsAnUnadmittedPlan: a plan whose
// action the authority never saw is only discarded.
func TestGuarantorActionPlanAbandonmentDiscardsAnUnadmittedPlan(t *testing.T) {
	kind, scope := guarantorPlanCoverageCancellation, actionPlanTestAgreement
	unadmittedFixture := newActionPlanFixture(t)
	unadmitted := unadmittedFixture.plan(t, unadmittedFixture.fence, "cancel")
	if err := unadmittedFixture.journal.PrepareActionPlan(unadmitted); err != nil {
		t.Fatal(err)
	}
	_, resolution, err := unadmittedFixture.journal.AbandonPreparedActionPlan(kind, scope, "",
		unadmittedFixture.authority, unadmittedFixture.fence, time.Unix(int64(unadmitted.PreparedAtUnix), 0))
	if err != nil || resolution.State != commerce.ActionUnknown {
		t.Fatalf("abandon a plan the authority never saw: state=%s err=%v", resolution.State, err)
	}
	if _, found, foundErr := unadmittedFixture.journal.ActionPlan(kind, scope, ""); foundErr != nil || found {
		t.Fatalf("a plan the authority never saw is kept after its abandonment: found=%v err=%v", found, foundErr)
	}
}
