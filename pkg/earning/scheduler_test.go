package earning

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-ai/pkg/commercegate"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

func TestDurableSchedulerIsWriterFencedAndExactlyOnce(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	authority, err := OpenPersonalAuthority(privateTempDir(t), "owner-1", "agent-1", "authority-1", key, PortfolioLimits{ComputeUnits: 10})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	now := time.Unix(1_800_000_000, 0)
	authority.now = func() time.Time { return now }
	fence, err := authority.AcquireWriter(context.Background(), "runtime-a", []string{"schedule.entry.transition"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	entry := commerce.EngagementScheduleEntry{SchemaVersion: 1, ScheduleEntryID: "schedule:one", AgreementBodyDigest: testDigest, ExecutionObligationID: "work:one",
		ExecutionID: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", State: commerce.ScheduleQueued,
		StateRevision: 1, DispatchGeneration: 1, DeadlineUnix: uint64(now.Add(time.Hour).Unix()), ComputeUnits: 1,
		MemoryBytes: 1, ConcurrencyUnits: 1, CancelClass: "safe", PreemptClass: "safe", IrreversibleBoundary: "before-delivery",
		WriterGeneration: fence.Body.WriterGeneration}
	request := ScheduleTransitionRequest{ScheduleEntryID: entry.ScheduleEntryID, TargetState: commerce.ScheduleQueued,
		TargetDispatchGeneration: 1, InitialEntry: &entry}
	canonical, _ := codec.Marshal(request)
	fields := scheduleFields(entry, 0, commerce.ScheduleQueued, 1)
	action, err := commerce.BuildAuthorizedAction("owner-1", "agent-1", "schedule.entry.transition", fields, canonical, fence, 1,
		testDigest, "", "absent", uint64(now.Add(30*time.Minute).Unix()))
	if err != nil {
		t.Fatal(err)
	}
	action, err = authority.SignAction(action, fence)
	if err != nil {
		t.Fatal(err)
	}
	first, err := authority.AdmitScheduleTransition(action, canonical, fence)
	if err != nil || first.State != commerce.ActionTerminal {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	if retry, err := authority.AdmitScheduleTransition(action, canonical, fence); err != nil || !reflect.DeepEqual(retry, first) {
		t.Fatalf("retry=%+v err=%v", retry, err)
	}
	newFence, err := authority.AcquireWriter(context.Background(), "runtime-b", []string{"schedule.entry.transition"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	transition := ScheduleTransitionRequest{ScheduleEntryID: entry.ScheduleEntryID, ExpectedStateRevision: 1,
		TargetState: commerce.ScheduleReady, TargetDispatchGeneration: 1}
	canonical, _ = codec.Marshal(transition)
	fields = scheduleFields(entry, 1, commerce.ScheduleReady, 1)
	newAction, err := commerce.BuildAuthorizedAction("owner-1", "agent-1", "schedule.entry.transition", fields, canonical, newFence, 2,
		testDigest, "", "queued", uint64(now.Add(30*time.Minute).Unix()))
	if err != nil {
		t.Fatal(err)
	}
	newAction, err = authority.SignAction(newAction, newFence)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.AdmitScheduleTransition(newAction, canonical, fence); err == nil {
		t.Fatal("stale writer transitioned schedule")
	}
	if _, err := authority.AdmitScheduleTransition(newAction, canonical, newFence); err != nil {
		t.Fatal(err)
	}
	entries, _ := authority.ScheduleSnapshot()
	if len(entries) != 1 || entries[0].State != commerce.ScheduleReady || entries[0].WriterGeneration != newFence.Body.WriterGeneration {
		t.Fatalf("entries=%+v", entries)
	}
}

func TestSchedulerServiceDurablyStagesOneExecution(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	authority, err := OpenPersonalAuthority(privateTempDir(t), "owner-1", "agent-1", "authority-1", key, PortfolioLimits{ComputeUnits: 10})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	now := time.Unix(1_900_000_000, 0).UTC()
	authority.now = func() time.Time { return now }
	fence, err := authority.AcquireWriter(context.Background(), "runtime", []string{"schedule.entry.transition"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	service := SchedulerService{Authority: authority, OwnerID: "owner-1", AgentID: "agent-1", MandateDigest: testDigest, PolicyRevision: 1}
	plan := commercegate.Plan{OwnerID: "owner-1", AgentID: "agent-1", AgreementBodyDigest: testDigest, ExecutionObligationID: "work",
		AcceptedInputManifestDigest:         "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		PredecessorTerminalResolutionDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		ReservationID:                       "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", PolicyRevision: 1,
		WriterGeneration: fence.Body.WriterGeneration, LeaseLossPolicy: commercegate.LeaseLossKill}
	entry, created, err := service.EnsureExecution(context.Background(), plan, now.Add(30*time.Minute), fence)
	if err != nil || !created || entry.State != commerce.ScheduleQueued {
		t.Fatalf("entry=%+v created=%v err=%v", entry, created, err)
	}
	retry, created, err := service.EnsureExecution(context.Background(), plan, now.Add(30*time.Minute), fence)
	if err != nil || created || retry.ScheduleEntryID != entry.ScheduleEntryID {
		t.Fatalf("retry=%+v created=%v err=%v", retry, created, err)
	}
	for _, state := range []commerce.EngagementScheduleState{commerce.ScheduleReady, commerce.ScheduleDispatched, commerce.ScheduleRunning, commerce.ScheduleSucceeded} {
		entry, err = service.Transition(context.Background(), entry, state, fence)
		if err != nil || entry.State != state {
			t.Fatalf("state=%s entry=%+v err=%v", state, entry, err)
		}
	}
}

func TestSchedulerDependencyAdmissionIsAtomicAndCycleSafe(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	authority, err := OpenPersonalAuthority(privateTempDir(t), "owner-1", "agent-1", "authority-1", key, PortfolioLimits{ComputeUnits: 10})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	now := time.Unix(1_900_000_000, 0).UTC()
	authority.now = func() time.Time { return now }
	fence, err := authority.AcquireWriter(context.Background(), "runtime", []string{"schedule.dependency.transition"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	service := SchedulerService{Authority: authority, OwnerID: "owner-1", AgentID: "agent-1", MandateDigest: testDigest, PolicyRevision: 1}
	a := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	b := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	first := commerce.PortfolioDependency{SchemaVersion: 1, UpstreamAgreementDigest: a, UpstreamObligationID: "one",
		DownstreamAgreementDigest: b, DownstreamObligationID: "two", DependencyType: "requires", DependencyClass: "blocking",
		FailurePropagation: "cancel", EvidenceDrivenReleaseRequired: true}
	if _, err := service.AddDependency(context.Background(), first, fence); err != nil {
		t.Fatal(err)
	}
	cycle := commerce.PortfolioDependency{SchemaVersion: 1, UpstreamAgreementDigest: b, UpstreamObligationID: "two",
		DownstreamAgreementDigest: a, DownstreamObligationID: "one", DependencyType: "requires", DependencyClass: "blocking",
		FailurePropagation: "cancel", EvidenceDrivenReleaseRequired: true}
	if _, err := service.AddDependency(context.Background(), cycle, fence); err == nil {
		t.Fatal("blocking dependency cycle was admitted")
	}
	if _, err := service.RemoveDependency(context.Background(), first, nil, fence); err == nil {
		t.Fatal("evidence-driven dependency was removed without evidence")
	}
	evidence := "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	if _, err := service.RemoveDependency(context.Background(), first, []string{evidence}, fence); err != nil {
		t.Fatal(err)
	}
	_, dependencies := authority.ScheduleSnapshot()
	if len(dependencies) != 0 {
		t.Fatalf("dependencies=%+v", dependencies)
	}
}

func TestSchedulerPropagatesFailureWithoutCancellingAgreementAuthority(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	authority, err := OpenPersonalAuthority(privateTempDir(t), "owner-1", "agent-1", "authority-1", key, PortfolioLimits{ComputeUnits: 10})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	now := time.Unix(1_900_000_000, 0).UTC()
	authority.now = func() time.Time { return now }
	fence, err := authority.AcquireWriter(context.Background(), "runtime",
		[]string{"schedule.dependency.transition", "schedule.entry.transition"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	service := SchedulerService{Authority: authority, OwnerID: "owner-1", AgentID: "agent-1", MandateDigest: testDigest, PolicyRevision: 1}
	upstream := "sha256:" + strings.Repeat("a", 64)
	downstream := "sha256:" + strings.Repeat("b", 64)
	entry := commerce.EngagementScheduleEntry{SchemaVersion: 1, ScheduleEntryID: "schedule:downstream", AgreementBodyDigest: downstream,
		ExecutionObligationID: "downstream-work", ExecutionID: "sha256:" + strings.Repeat("d", 64), State: commerce.ScheduleQueued,
		StateRevision: 1, DispatchGeneration: 1, DeadlineUnix: uint64(now.Add(time.Hour).Unix()), ComputeUnits: 1,
		ConcurrencyUnits: 1, CancelClass: "before-start", PreemptClass: "drain", IrreversibleBoundary: "execution-start",
		WriterGeneration: fence.Body.WriterGeneration}
	if _, err := service.mutate(context.Background(), commerce.EngagementScheduleEntry{}, entry, &entry, fence); err != nil {
		t.Fatal(err)
	}
	dependency := commerce.PortfolioDependency{SchemaVersion: 1, UpstreamAgreementDigest: upstream, UpstreamObligationID: "upstream-work",
		DownstreamAgreementDigest: downstream, DownstreamObligationID: "downstream-work", DependencyType: "subcontract-result",
		DependencyClass: "blocking", FailurePropagation: "cancel", EvidenceDrivenReleaseRequired: true}
	if _, err := service.AddDependency(context.Background(), dependency, fence); err != nil {
		t.Fatal(err)
	}
	evidence := []string{"sha256:" + strings.Repeat("e", 64)}
	changed, err := service.PropagateTerminalDependency(context.Background(), upstream, "upstream-work", "failed", evidence, fence)
	if err != nil || changed != 2 {
		t.Fatalf("changed=%d err=%v", changed, err)
	}
	entries, dependencies := authority.ScheduleSnapshot()
	if len(entries) != 1 || entries[0].State != commerce.ScheduleCancelled || len(dependencies) != 0 {
		t.Fatalf("entries=%+v dependencies=%+v", entries, dependencies)
	}
	// Scheduler propagation never manufactures or changes an Agreement record.
	if len(authority.EngagementSnapshot()) != 0 {
		t.Fatal("dependency propagation changed Agreement authority")
	}
}

func scheduleFields(entry commerce.EngagementScheduleEntry, expected uint64, target commerce.EngagementScheduleState,
	dispatch uint64) map[string]commerce.SemanticValue {
	return map[string]commerce.SemanticValue{"owner_id": commerce.ID("owner-1"), "agent_id": commerce.ID("agent-1"),
		"schedule_entry_id": commerce.ID(entry.ScheduleEntryID), "agreement_body_digest": commerce.Digest32(entry.AgreementBodyDigest),
		"execution_id": commerce.Digest32(entry.ExecutionID), "expected_state_revision": commerce.U64(expected),
		"target_state": commerce.State(string(target)), "target_dispatch_generation": commerce.U64(dispatch)}
}
