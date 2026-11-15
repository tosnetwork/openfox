package servicebridge

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/tosnetwork/tos-ai/pkg/executorservice"
	"github.com/tosnetwork/tos-ai/pkg/railgate"
)

var serviceFixtureStart = time.Unix(2_000_000_000, 0)

func serviceState(t *testing.T) string {
	t.Helper()
	state := filepath.Join(t.TempDir(), "state")
	if err := ensurePrivateDirectory(state); err != nil {
		t.Fatal(err)
	}
	return state
}

func slotCount(t *testing.T, state string) int {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(state, "slots"))
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".json" {
			count++
		}
	}
	return count
}

func TestAServiceExecutionIsAttestedAndDeliveredFromTheNodesOwnObjects(t *testing.T) {
	ctx := context.Background()
	service := startRealExecutor(t, shortSocketDir(t), &fakeRuntime{}, nil)
	fixture := newGateFixture(t, serviceFixtureStart)
	node := openServiceNode(t, fixture, serviceState(t), ownClient(t, service.socket))
	if err := node.provider.HandleTask(ctx, fixture.message); err != nil {
		t.Fatal(err)
	}
	record := node.record(t)
	if record.State != ProviderResponding || node.lifecycle.responds != 1 || record.Recovered {
		t.Fatalf("after the run: state %s, %d responds, recovered %v", record.State, node.lifecycle.responds,
			record.Recovered)
	}
	if state := node.slotState(t); state != railgate.SlotCompleted {
		t.Fatalf("the gate slot is %s", state)
	}
	if service.backend.runs() != 1 {
		t.Fatalf("the job ran %d times", service.backend.runs())
	}
	boc, err := base64.StdEncoding.DecodeString(record.ReceiptBOCBase64)
	if err != nil {
		t.Fatal(err)
	}
	receipt, _, err := decodeReceipt(boc)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.ArtifactDigest != record.ArtifactDigest || receipt.SandboxDigest != fixture.manifestDigest ||
		receipt.ToolchainDigest != fixture.manifest.ToolchainDigest {
		t.Fatalf("the Receipt does not bind the stored artifact and the manifest: %+v", receipt)
	}
	// Both objects are the service's bytes, held under the node's state
	// directory.
	for _, digest := range []string{receipt.ArtifactDigest, receipt.ReportDigest} {
		own, getErr := node.runner.Get(ctx, digest)
		if getErr != nil {
			t.Fatalf("the node does not hold %s: %v", digest, getErr)
		}
		theirs, getErr := service.store.Get(ctx, digest)
		if getErr != nil || !bytes.Equal(own, theirs) || sha256Text(sha256Sum(own)) != digest {
			t.Fatalf("the node's copy of %s is not the service's object: %v", digest, getErr)
		}
		object := filepath.Join(node.state, "executor-service", "artifacts", "objects", digest[len("sha256:"):])
		if _, statErr := os.Stat(object); statErr != nil {
			t.Fatalf("the object is not under the node's state directory: %v", statErr)
		}
	}
	if _, statErr := os.Stat(node.provider.sourcePath(recordKey(record))); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("the staged source outlived the execution: %v", statErr)
	}
	// A resent task never runs or responds again.
	if err = node.provider.HandleTask(ctx, fixture.message); err != nil {
		t.Fatal(err)
	}
	if service.backend.runs() != 1 || node.lifecycle.responds != 1 {
		t.Fatalf("a resent task ran %d times and responded %d times", service.backend.runs(),
			node.lifecycle.responds)
	}

	// Delivery and retention need neither the service nor its files.
	service.stop(t)
	if err = os.RemoveAll(filepath.Dir(filepath.Dir(service.socket))); err != nil {
		t.Fatal(err)
	}
	node.history.finalize(record.ResponseHash)
	if err = node.provider.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if state := node.record(t).State; state != ProviderDelivering || len(node.transport.packets()) == 0 {
		t.Fatalf("after the finalized respond: state %s, %d packets", state, len(node.transport.packets()))
	}
	fixture.clock.Set(time.Unix(int64(record.RetentionEndUnix)+1, 0))
	if err = node.provider.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if state := node.record(t).State; state != ProviderExpired {
		t.Fatalf("after the retention: state %s", state)
	}
	if _, err = node.runner.Get(ctx, record.ArtifactDigest); err == nil {
		t.Fatal("the artifact outlived its retention")
	}
}

func TestEveryServiceAnswerLeadsToItsProviderState(t *testing.T) {
	const pending = ProviderExecuting
	cases := []struct {
		name  string
		reply scriptedAnswer
		state string
		slot  railgate.SlotState
		class error
		is    error
	}{
		{"busy", scriptedAnswer{Status: executorservice.StatusBusy}, pending, railgate.SlotStarted,
			ErrExecutionPending, executorservice.ErrBusy},
		{"unavailable", scriptedAnswer{Status: executorservice.StatusUnavailable}, pending, railgate.SlotStarted,
			ErrExecutionPending, executorservice.ErrUnavailable},
		{"in_progress", scriptedAnswer{Status: executorservice.StatusInProgress}, pending, railgate.SlotStarted,
			ErrExecutionPending, executorservice.ErrInProgress},
		{"timeout", scriptedAnswer{Status: executorservice.StatusTimeout}, pending, railgate.SlotStarted,
			ErrExecutionPending, executorservice.ErrTimeout},
		{"storage_full", scriptedAnswer{Status: executorservice.StatusStorageFull}, pending, railgate.SlotStarted,
			ErrExecutionPending, executorservice.ErrStorageFull},
		{"retention_full", scriptedAnswer{Status: executorservice.StatusRetentionFull}, pending,
			railgate.SlotStarted, ErrExecutionPending, executorservice.ErrRetentionFull},
		{"objects_unavailable", scriptedAnswer{Status: executorservice.StatusObjectsUnavailable}, pending,
			railgate.SlotStarted, ErrExecutionPending, executorservice.ErrObjectsUnavailable},
		{"not_allowed", scriptedAnswer{Status: executorservice.StatusNotAllowed}, pending, railgate.SlotStarted,
			ErrExecutionPending, executorservice.ErrNotAllowed},
		{"invalid_request", scriptedAnswer{Status: executorservice.StatusInvalidRequest}, pending,
			railgate.SlotStarted, ErrExecutionPending, executorservice.ErrInvalidRequest},
		{"limits_refused", scriptedAnswer{Status: executorservice.StatusLimitsRefused}, pending,
			railgate.SlotStarted, ErrExecutionPending, executorservice.ErrLimitsRefused},
		{"an unknown status", scriptedAnswer{Status: "paused"}, pending, railgate.SlotStarted,
			ErrExecutionPending, executorservice.ErrProtocol},
		{"a dropped connection", scriptedAnswer{Drop: true}, pending, railgate.SlotStarted,
			ErrExecutionPending, executorservice.ErrProtocol},
		{"ambiguous", scriptedAnswer{Status: executorservice.StatusAmbiguous}, ProviderUnknown,
			railgate.SlotStarted, ErrExecutionUnknown, executorservice.ErrAmbiguous},
		{"conflict", scriptedAnswer{Status: executorservice.StatusConflict}, ProviderUnknown,
			railgate.SlotStarted, ErrExecutionUnknown, executorservice.ErrConflict},
		{"execution_failed", scriptedAnswer{Status: executorservice.StatusExecutionFailed}, ProviderFailed,
			railgate.SlotFailed, ErrExecutionFailed, executorservice.ErrExecutionFailed},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			service := startScriptedExecutor(t, func(scriptedRequest) scriptedAnswer { return test.reply })
			fixture := newGateFixture(t, serviceFixtureStart)
			node := openServiceNode(t, fixture, serviceState(t), ownClient(t, service.socket))
			err := node.provider.HandleTask(ctx, fixture.message)
			if !errors.Is(err, test.class) || !errors.Is(err, test.is) {
				t.Fatalf("the answer was reported as %v", err)
			}
			for _, other := range []error{ErrExecutionPending, ErrExecutionUnknown, ErrExecutionFailed} {
				if other != test.class && errors.Is(err, other) {
					t.Fatalf("the answer is also reported as %v", other)
				}
			}
			if state := node.record(t).State; state != test.state {
				t.Fatalf("the record is %s, not %s", state, test.state)
			}
			if state := node.slotState(t); state != test.slot {
				t.Fatalf("the slot is %s, not %s", state, test.slot)
			}
			if node.lifecycle.responds != 0 {
				t.Fatal("an execution without a verified outcome was attested")
			}
			// From now on the service has the outcome.
			service.setAnswer(func(request scriptedRequest) scriptedAnswer {
				return scriptedSuccess(request, []byte("artifact"), []byte("report"))
			})
			asked := len(service.seen())
			for round := 0; round < 2; round++ {
				if tickErr := node.provider.Tick(ctx); tickErr != nil {
					t.Fatal(tickErr)
				}
			}
			seen := service.seen()
			if test.state != pending {
				// A terminal answer is final: the service is not asked
				// again and nothing is ever attested.
				if len(seen) != asked || node.record(t).State != test.state || node.lifecycle.responds != 0 {
					t.Fatalf("after a terminal answer: %d more requests, state %s, %d responds",
						len(seen)-asked, node.record(t).State, node.lifecycle.responds)
				}
				return
			}
			if len(seen) != asked+1 || !reflect.DeepEqual(seen[0], seen[len(seen)-1]) {
				t.Fatalf("the request was not sent again unchanged, exactly once: %d requests", len(seen))
			}
			if !bytes.Equal(seen[0].Source, fixture.archive) ||
				seen[0].Header.ManifestDigest != fixture.manifestDigest ||
				seen[0].Header.Limits != serviceLimits(fixture.manifest.Limits) ||
				seen[0].Header.RetainUntilUnix != int64(fixture.deadline) {
				t.Fatalf("the request does not carry the task and the manifest: %+v", seen[0].Header)
			}
			record := node.record(t)
			if record.State != ProviderResponding || node.lifecycle.responds != 1 || record.Recovered ||
				node.slotState(t) != railgate.SlotCompleted {
				t.Fatalf("after the outcome arrived: state %s, %d responds, slot %s", record.State,
					node.lifecycle.responds, node.slotState(t))
			}
		})
	}
}

func TestATaskIsNotAdmittedWhileTheServiceCannotRunIt(t *testing.T) {
	ctx := context.Background()
	unready := goodDescription()
	unready.Ready = false
	otherImage := goodDescription()
	otherImage.ImageDigest = sha256Text(sha256Sum([]byte("another image")))
	tighter := goodDescription()
	tighter.Limits.MemoryBytes = 1 << 20
	for name, description := range map[string]executorservice.Description{
		"the backend is not ready": unready, "another image": otherImage, "tighter limits": tighter,
	} {
		t.Run(name, func(t *testing.T) {
			service := startScriptedExecutor(t, func(request scriptedRequest) scriptedAnswer {
				return scriptedSuccess(request, []byte("artifact"), []byte("report"))
			})
			service.setDescription(description)
			fixture := newGateFixture(t, serviceFixtureStart)
			node := openServiceNode(t, fixture, serviceState(t), ownClient(t, service.socket))
			if err := node.provider.HandleTask(ctx, fixture.message); err == nil {
				t.Fatal("a task was admitted for a service that cannot run it")
			}
			records, err := node.provider.Records()
			if err != nil {
				t.Fatal(err)
			}
			if len(records) != 0 || slotCount(t, node.state) != 0 || len(service.seen()) != 0 {
				t.Fatalf("the refused task left %d records, %d slots and %d requests", len(records),
					slotCount(t, node.state), len(service.seen()))
			}
			// The same task is admitted once the service can run it.
			service.setDescription(goodDescription())
			if err = node.provider.HandleTask(ctx, fixture.message); err != nil {
				t.Fatal(err)
			}
			if node.record(t).State != ProviderResponding || node.lifecycle.responds != 1 {
				t.Fatalf("the task did not run once the service was ready: %s", node.record(t).State)
			}
		})
	}
	t.Run("no service", func(t *testing.T) {
		fixture := newGateFixture(t, serviceFixtureStart)
		absent := filepath.Join(shortSocketDir(t), "absent.sock")
		node := openServiceNode(t, fixture, serviceState(t), ownClient(t, absent))
		if err := node.provider.HandleTask(ctx, fixture.message); err == nil {
			t.Fatal("a task was admitted with no executor service")
		}
		if slotCount(t, node.state) != 0 {
			t.Fatal("a task took a slot with no executor service")
		}
	})
}

const (
	crashNodeStateEnv  = "SERVICEBRIDGE_SERVICE_NODE_STATE"
	crashNodeSocketEnv = "SERVICEBRIDGE_SERVICE_NODE_SOCKET"
	crashNodeStartEnv  = "SERVICEBRIDGE_SERVICE_NODE_START"
)

// The child half: a provider node that admits the task and waits for its
// run. The parent kills it while the run is held.
func TestServiceNodeCrashChild(t *testing.T) {
	state := os.Getenv(crashNodeStateEnv)
	if state == "" {
		t.Skip("runs only as the child of TestANodeKilledDuringARunAttestsItsOneOutcomeAfterRestart")
	}
	start, err := strconv.ParseInt(os.Getenv(crashNodeStartEnv), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	fixture := newGateFixture(t, time.Unix(start, 0))
	node := openServiceNode(t, fixture, state, ownClient(t, os.Getenv(crashNodeSocketEnv)))
	t.Fatalf("the node outlived its run: %v", node.provider.HandleTask(context.Background(), fixture.message))
}

// A node that dies while its execution runs must, after its restart, send
// the same request again and attest the one outcome: the gate calls the slot
// ambiguous, but the execution belongs to the service, which neither ran it
// twice nor lost it.
func TestANodeKilledDuringARunAttestsItsOneOutcomeAfterRestart(t *testing.T) {
	if os.Getenv(crashNodeStateEnv) != "" {
		t.Skip("the child does not recurse")
	}
	ctx := context.Background()
	backend := &fakeRuntime{started: make(chan struct{}, 1), gate: make(chan struct{})}
	service := startRealExecutor(t, shortSocketDir(t), backend, nil)
	state := serviceState(t)
	child := exec.Command(os.Args[0], "-test.run=^TestServiceNodeCrashChild$", "-test.count=1")
	child.Env = append(os.Environ(), crashNodeStateEnv+"="+state, crashNodeSocketEnv+"="+service.socket,
		crashNodeStartEnv+"="+strconv.FormatInt(serviceFixtureStart.Unix(), 10))
	output := &bytes.Buffer{}
	child.Stdout, child.Stderr = output, output
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-backend.started:
	case <-time.After(60 * time.Second):
		_ = child.Process.Kill()
		_ = child.Wait()
		t.Fatalf("the child node never started its run:\n%s", output)
	}
	if err := child.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait()

	// The restart: opening the gate recovers the slot the dead node left.
	fixture := newGateFixture(t, serviceFixtureStart)
	node := openServiceNode(t, fixture, state, ownClient(t, service.socket))
	if record := node.record(t); record.State != ProviderExecuting {
		t.Fatalf("the dead node left the record %s", record.State)
	}
	if slot := node.slotState(t); slot != railgate.SlotAmbiguous {
		t.Fatalf("the reopened gate calls the slot %s", slot)
	}
	// The run is still held: the service says so and nothing is attested.
	err := node.provider.Tick(ctx)
	if !errors.Is(err, executorservice.ErrInProgress) || !errors.Is(err, ErrExecutionPending) {
		t.Fatalf("asking for a running execution: %v", err)
	}
	if node.record(t).State != ProviderExecuting || node.lifecycle.responds != 0 || backend.runs() != 1 {
		t.Fatalf("while the run is held: state %s, %d responds, %d runs", node.record(t).State,
			node.lifecycle.responds, backend.runs())
	}
	close(backend.gate)
	deadline := time.Now().Add(30 * time.Second)
	for node.record(t).State == ProviderExecuting {
		if time.Now().After(deadline) {
			t.Fatalf("the outcome never arrived: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
		err = node.provider.Tick(ctx)
	}
	if err != nil {
		t.Fatalf("the round that read the outcome: %v", err)
	}
	record := node.record(t)
	if record.State != ProviderResponding || !record.Recovered || node.lifecycle.responds != 1 {
		t.Fatalf("after the outcome: state %s, recovered %v, %d responds", record.State, record.Recovered,
			node.lifecycle.responds)
	}
	for round := 0; round < 3; round++ {
		if err = node.provider.Tick(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if backend.runs() != 1 || node.lifecycle.responds != 1 {
		t.Fatalf("the job ran %d times and was responded to %d times", backend.runs(), node.lifecycle.responds)
	}
	artifact, err := node.runner.Get(ctx, record.ArtifactDigest)
	if err != nil {
		t.Fatal(err)
	}
	if theirs, getErr := service.store.Get(ctx, record.ArtifactDigest); getErr != nil || !bytes.Equal(artifact, theirs) {
		t.Fatalf("the recovered artifact is not the service's: %v", getErr)
	}
	// An ambiguous respond is sent again only through the fresh check, and
	// the result is delivered once the respond is finalized.
	fixture.clock.Set(serviceFixtureStart.Add(2 * FirstRedelivery))
	if err = node.provider.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if node.lifecycle.responds != 2 {
		t.Fatalf("the respond retry of a recovered execution was sent %d times", node.lifecycle.responds-1)
	}
	node.history.finalize(record.ResponseHash)
	if err = node.provider.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if node.record(t).State != ProviderDelivering || len(node.transport.packets()) == 0 {
		t.Fatalf("the recovered result was not delivered: %s", node.record(t).State)
	}
}

// The gate, not the record, decides whether a slot it calls ambiguous may be
// attested: only a record whose outcome was read from the service is
// rechecked past it.
func TestOnlyARecoveredExecutionIsRecheckedPastAnAmbiguousSlot(t *testing.T) {
	ctx := context.Background()
	service := startScriptedExecutor(t, func(scriptedRequest) scriptedAnswer {
		return scriptedAnswer{Status: executorservice.StatusInProgress}
	})
	fixture := newGateFixture(t, serviceFixtureStart)
	state := serviceState(t)
	node := openServiceNode(t, fixture, state, ownClient(t, service.socket))
	if err := node.provider.HandleTask(ctx, fixture.message); !errors.Is(err, ErrExecutionPending) {
		t.Fatal(err)
	}
	if err := node.gate.Close(); err != nil {
		t.Fatal(err)
	}
	node = openServiceNode(t, fixture, state, ownClient(t, service.socket))
	if slot := node.slotState(t); slot != railgate.SlotAmbiguous {
		t.Fatalf("the reopened gate calls the slot %s", slot)
	}
	// A record that claims an attested result without the recovery mark,
	// as a subprocess execution interrupted by a restart would be.
	record := node.record(t)
	record.State, record.ResponseHash = ProviderExecuted, hex.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	if err := node.provider.store(recordKey(record), record, false); err != nil {
		t.Fatal(err)
	}
	if err := node.provider.Tick(ctx); err == nil {
		t.Fatal("an ambiguous slot was rechecked for a record that was not recovered")
	}
	if node.lifecycle.responds != 0 || node.record(t).State != ProviderExecuted {
		t.Fatalf("an ambiguous execution was attested: %d responds", node.lifecycle.responds)
	}
}

func TestTheNodeStopsWaitingWhenRespondNoLongerFits(t *testing.T) {
	ctx := context.Background()
	backend := &fakeRuntime{started: make(chan struct{}, 1), gate: make(chan struct{})}
	service := startRealExecutor(t, shortSocketDir(t), backend, nil)
	fixture := newGateFixture(t, serviceFixtureStart)
	node := openServiceNode(t, fixture, serviceState(t), ownClient(t, service.socket))
	cutoff := time.Unix(int64(fixture.deadline), 0).Add(-2 * time.Minute)
	// One second of waiting is left.
	fixture.clock.Set(cutoff.Add(-time.Second))
	returned := make(chan error, 1)
	began := time.Now()
	go func() { returned <- node.provider.HandleTask(ctx, fixture.message) }()
	var err error
	select {
	case err = <-returned:
	case <-time.After(15 * time.Second):
		close(backend.gate)
		t.Fatalf("the node still waits %s after the cut-off: %v", time.Since(began), <-returned)
	}
	if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, ErrExecutionPending) {
		t.Fatalf("the wait ended with %v", err)
	}
	if waited := time.Since(began); waited < 900*time.Millisecond {
		t.Fatalf("the node gave up after %s, before the cut-off", waited)
	}
	if node.record(t).State != ProviderExecuting || node.lifecycle.responds != 0 {
		t.Fatalf("at the cut-off: state %s", node.record(t).State)
	}
	fixture.clock.Set(cutoff)
	if err = node.provider.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	record := node.record(t)
	if record.State != ProviderAbandoned {
		t.Fatalf("past the cut-off the record is %s", record.State)
	}
	if _, statErr := os.Stat(node.provider.sourcePath(recordKey(record))); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("the staged source outlived the abandoned execution: %v", statErr)
	}
	// The run finishes later; its outcome is never asked for or attested.
	close(backend.gate)
	deadline := time.Now().Add(30 * time.Second)
	for {
		result, askErr := ownClient(t, service.socket).Execute(ctx, executorservice.ExecuteRequest{
			ExecutionID: "sha256:" + record.ExecutionID, QuoteCommitment: record.QuoteCommitment,
			InputDigest: "sha256:" + record.InputDigest, ManifestDigest: fixture.manifestDigest,
			Limits: serviceLimits(fixture.manifest.Limits), RetainUntilUnix: int64(fixture.deadline),
			SourceArchive: fixture.archive,
		})
		if askErr == nil {
			if result.Outcome.ExitCode != 0 {
				t.Fatal("the held run did not succeed")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the held run never finished: %v", askErr)
		}
		time.Sleep(20 * time.Millisecond)
	}
	for round := 0; round < 2; round++ {
		if err = node.provider.Tick(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if node.record(t).State != ProviderAbandoned || node.lifecycle.responds != 0 || backend.runs() != 1 {
		t.Fatalf("after the late outcome: state %s, %d responds", node.record(t).State, node.lifecycle.responds)
	}
}

func TestRespondCutoffLeavesTheRespondBudgetBeforeTheDeadline(t *testing.T) {
	if cutoff, ok := respondCutoff(1000, 2*time.Minute); !ok || cutoff != 880 {
		t.Fatalf("cutoff %d %v", cutoff, ok)
	}
	if cutoff, ok := respondCutoff(1000, 1500*time.Millisecond); !ok || cutoff != 998 {
		t.Fatalf("a fraction of a second is not rounded up: %d %v", cutoff, ok)
	}
	for _, budget := range []time.Duration{0, -time.Second, 1000 * time.Second, 2000 * time.Second} {
		if _, ok := respondCutoff(1000, budget); ok {
			t.Fatalf("a budget of %s leaves a cut-off before a deadline of 1000", budget)
		}
	}
	if _, ok := respondCutoff(^uint64(0), time.Second); ok {
		t.Fatal("a deadline outside the clock's range has a cut-off")
	}
}

func TestAProviderHasExactlyOneExecutor(t *testing.T) {
	service := startScriptedExecutor(t, func(scriptedRequest) scriptedAnswer { return scriptedAnswer{Drop: true} })
	fixture := newGateFixture(t, serviceFixtureStart)
	node := openServiceNode(t, fixture, serviceState(t), ownClient(t, service.socket))
	good := node.provider.config
	good.Directory = filepath.Join(t.TempDir(), "provider")
	if _, err := NewProvider(good); err != nil {
		t.Fatalf("the complete configuration was refused: %v", err)
	}
	both := good
	both.Runner = &SubprocessRunner{}
	neither := good
	neither.Service = nil
	noVerifier := good
	noVerifier.Verifier = nil
	noBudget := good
	noBudget.RespondBudget = 0
	for name, config := range map[string]ProviderConfig{
		"both executors": both, "no executor": neither, "a service without the verifier": noVerifier,
		"a service without a respond budget": noBudget,
	} {
		if _, err := NewProvider(config); err == nil {
			t.Errorf("%s: the configuration was accepted", name)
		}
	}
}

// The service binds an execution id to its limits, so a request is sent
// again with the limits it was admitted under even if the node has since
// been started with another manifest.
func TestARepeatedRequestCarriesTheAdmittedManifestWhateverTheNodeNowRuns(t *testing.T) {
	ctx := context.Background()
	service := startScriptedExecutor(t, func(scriptedRequest) scriptedAnswer {
		return scriptedAnswer{Status: executorservice.StatusInProgress}
	})
	fixture := newGateFixture(t, serviceFixtureStart)
	state := serviceState(t)
	node := openServiceNode(t, fixture, state, ownClient(t, service.socket))
	if err := node.provider.HandleTask(ctx, fixture.message); !errors.Is(err, ErrExecutionPending) {
		t.Fatal(err)
	}
	admitted := fixture.manifest.Limits
	if err := node.gate.Close(); err != nil {
		t.Fatal(err)
	}
	// The restarted node is configured with tighter limits, another
	// manifest digest and another toolchain.
	fixture.manifest.Limits.MemoryBytes /= 2
	fixture.manifest.Limits.WallClockMillis /= 2
	admittedDigest := fixture.manifestDigest
	node = openServiceNodeWith(t, fixture, state, ownClient(t, service.socket),
		sha256Text(sha256Sum([]byte("another manifest"))))
	service.setAnswer(func(request scriptedRequest) scriptedAnswer {
		// The service says it keeps its copy for one second only.
		answer := scriptedSuccess(request, []byte("artifact"), []byte("report"))
		answer.RetainUntilUnix = 1
		return answer
	})
	if err := node.provider.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	seen := service.seen()
	if len(seen) != 2 || !reflect.DeepEqual(seen[0], seen[1]) || seen[1].Header.Limits != serviceLimits(admitted) ||
		seen[1].Header.ManifestDigest != admittedDigest {
		t.Fatalf("the repeated request differs from the admitted one: %+v", seen)
	}
	record := node.record(t)
	if record.State != ProviderResponding || node.lifecycle.responds != 1 {
		t.Fatalf("the outcome was not attested: %s", record.State)
	}
	// The result is served from the node's copy, however briefly the
	// service keeps its own.
	if artifact, err := node.runner.Get(ctx, record.ArtifactDigest); err != nil || string(artifact) != "artifact" {
		t.Fatalf("the node does not hold the artifact: %v", err)
	}
}

func TestAStalledServiceDoesNotHoldAnAdmission(t *testing.T) {
	previous := describeTimeout
	describeTimeout = 300 * time.Millisecond
	t.Cleanup(func() { describeTimeout = previous })
	service := startScriptedExecutor(t, func(scriptedRequest) scriptedAnswer { return scriptedAnswer{Drop: true} })
	service.mutex.Lock()
	service.stall = true
	service.mutex.Unlock()
	fixture := newGateFixture(t, serviceFixtureStart)
	node := openServiceNode(t, fixture, serviceState(t), ownClient(t, service.socket))
	began := time.Now()
	// A context without a deadline, as the dispatch loop's is.
	err := node.provider.HandleTask(context.Background(), fixture.message)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(began) > 10*time.Second {
		t.Fatalf("a stalled service held the task for %s: %v", time.Since(began), err)
	}
	if slotCount(t, node.state) != 0 {
		t.Fatal("the task took a slot")
	}
}
