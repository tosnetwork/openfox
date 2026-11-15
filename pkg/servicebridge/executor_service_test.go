package servicebridge

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/tosnetwork/tos-ai/pkg/artifactstore"
	"github.com/tosnetwork/tos-ai/pkg/executorservice"
	"github.com/tosnetwork/tos-ai/pkg/softwarework"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
)

// memoryExecutor is an in-process executor service client. It hands the
// runner answers the real client would never let through, so the runner's
// own checks are exercised.
type memoryExecutor struct {
	description executorservice.Description
	describeErr error
	result      func(executorservice.ExecuteRequest) (executorservice.ExecuteResult, error)
	requests    []executorservice.ExecuteRequest
}

func (m *memoryExecutor) Describe(context.Context) (executorservice.Description, error) {
	return m.description, m.describeErr
}

func (m *memoryExecutor) Execute(
	_ context.Context,
	request executorservice.ExecuteRequest,
) (executorservice.ExecuteResult, error) {
	m.requests = append(m.requests, request)
	return m.result(request)
}

var (
	runnerManifest  = sha256Text(sha256Sum([]byte("published manifest")))
	runnerToolchain = softwarework.FrozenV1ImageDigest
)

func runnerRequest() ServiceExecution {
	archive := fill(2048, 3)
	return ServiceExecution{
		Request: softwarework.Request{
			QuoteCommitment: "tvm-cell-" + sha256Text(sha256Sum([]byte("quote"))),
			ExecutionID:     sha256Text(sha256Sum([]byte("execution"))),
			InputDigest:     sha256Text(sha256Sum([]byte("input"))),
			SourceDigest:    sha256Text(sha256Sum(archive)), SourceArchive: archive,
		},
		ManifestDigest: runnerManifest, ToolchainDigest: runnerToolchain, Limits: RailLimits(),
		ServiceRetainUntilUnix: 2_000_003_500, RetainUntilUnix: 2_000_090_000,
	}
}

// honestResult is the success the service records for request.
func honestResult(request executorservice.ExecuteRequest) executorservice.ExecuteResult {
	artifact, report := []byte("the artifact"), []byte("the report")
	return executorservice.ExecuteResult{
		Outcome: softwarework.Outcome{
			QuoteCommitment: request.QuoteCommitment, ExecutionID: request.ExecutionID,
			InputDigest: request.InputDigest, ResultDigest: sha256Text(sha256Sum([]byte("result"))),
			Artifact: artifactstore.Descriptor{
				Digest: sha256Text(sha256Sum(artifact)), MediaType: softwarework.ArtifactMediaType,
				SizeBytes: uint64(len(artifact)),
			},
			Report: artifactstore.Descriptor{
				Digest: sha256Text(sha256Sum(report)), MediaType: softwarework.ReportMediaType,
				SizeBytes: uint64(len(report)),
			},
			SourceDigest: sha256Text(sha256Sum(request.SourceArchive)), ToolchainDigest: runnerToolchain,
			SandboxDigest: request.ManifestDigest, ExitCode: 0, CompletedAtUnix: 1_900_000_000,
		},
		Artifact: artifact, Report: report,
	}
}

func newMemoryRunner(t *testing.T, client ExecutorService) *SocketRunner {
	t.Helper()
	runner, err := NewSocketRunner(SocketRunnerConfig{
		StateDir: filepath.Join(t.TempDir(), "executor-service"), ManifestDigest: runnerManifest,
		ToolchainDigest: runnerToolchain, Limits: RailLimits(), Client: client,
	})
	if err != nil {
		t.Fatal(err)
	}
	return runner
}

func storedObjects(t *testing.T, runner *SocketRunner, result executorservice.ExecuteResult) int {
	t.Helper()
	stored := 0
	for _, digest := range []string{
		result.Outcome.Artifact.Digest, result.Outcome.Report.Digest,
		sha256Text(sha256Sum(result.Artifact)), sha256Text(sha256Sum(result.Report)),
	} {
		if _, err := runner.Get(context.Background(), digest); err == nil {
			stored++
		}
	}
	return stored
}

func TestTheRunnerSendsTheManifestBindingsAndKeepsTheVerifiedObjects(t *testing.T) {
	client := &memoryExecutor{}
	client.result = func(request executorservice.ExecuteRequest) (executorservice.ExecuteResult, error) {
		return honestResult(request), nil
	}
	runner := newMemoryRunner(t, client)
	execution := runnerRequest()
	outcome, err := runner.Execute(context.Background(), execution)
	if err != nil {
		t.Fatal(err)
	}
	sent := client.requests[0]
	if sent.ExecutionID != execution.Request.ExecutionID || sent.QuoteCommitment != execution.Request.QuoteCommitment ||
		sent.InputDigest != execution.Request.InputDigest || sent.ManifestDigest != runnerManifest ||
		sent.Limits != serviceLimits(RailLimits()) || sent.RetainUntilUnix != execution.ServiceRetainUntilUnix ||
		string(sent.SourceArchive) != string(execution.Request.SourceArchive) {
		t.Fatalf("the request does not carry the execution: %+v", sent)
	}
	for digest, want := range map[string]string{
		outcome.Artifact.Digest: "the artifact", outcome.Report.Digest: "the report",
	} {
		got, getErr := runner.Get(context.Background(), digest)
		if getErr != nil || string(got) != want {
			t.Fatalf("the node does not hold %s: %v", digest, getErr)
		}
	}
}

func TestTheRunnerRefusesEveryAnswerThatIsNotThisRequestsVerifiedSuccess(t *testing.T) {
	other := sha256Text(sha256Sum([]byte("something else")))
	cases := map[string]func(*executorservice.ExecuteResult){
		"another quote":            func(r *executorservice.ExecuteResult) { r.Outcome.QuoteCommitment = "tvm-cell-" + other },
		"another execution":        func(r *executorservice.ExecuteResult) { r.Outcome.ExecutionID = other },
		"another input":            func(r *executorservice.ExecuteResult) { r.Outcome.InputDigest = other },
		"another source":           func(r *executorservice.ExecuteResult) { r.Outcome.SourceDigest = other },
		"another sandbox":          func(r *executorservice.ExecuteResult) { r.Outcome.SandboxDigest = other },
		"another image":            func(r *executorservice.ExecuteResult) { r.Outcome.ToolchainDigest = other },
		"a failed run":             func(r *executorservice.ExecuteResult) { r.Outcome.ExitCode = 1 },
		"no completion time":       func(r *executorservice.ExecuteResult) { r.Outcome.CompletedAtUnix = 0 },
		"another artifact type":    func(r *executorservice.ExecuteResult) { r.Outcome.Artifact.MediaType = "text/plain" },
		"another report type":      func(r *executorservice.ExecuteResult) { r.Outcome.Report.MediaType = "text/plain" },
		"altered artifact bytes":   func(r *executorservice.ExecuteResult) { r.Artifact[0] ^= 1 },
		"another artifact digest":  func(r *executorservice.ExecuteResult) { r.Outcome.Artifact.Digest = other },
		"truncated artifact bytes": func(r *executorservice.ExecuteResult) { r.Artifact = r.Artifact[:4] },
		"another artifact size":    func(r *executorservice.ExecuteResult) { r.Outcome.Artifact.SizeBytes++ },
		"altered report bytes":     func(r *executorservice.ExecuteResult) { r.Report[0] ^= 1 },
		"another report digest":    func(r *executorservice.ExecuteResult) { r.Outcome.Report.Digest = other },
		"another report size":      func(r *executorservice.ExecuteResult) { r.Outcome.Report.SizeBytes++ },
	}
	for name, alter := range cases {
		t.Run(name, func(t *testing.T) {
			client := &memoryExecutor{}
			var answered executorservice.ExecuteResult
			client.result = func(request executorservice.ExecuteRequest) (executorservice.ExecuteResult, error) {
				answered = honestResult(request)
				alter(&answered)
				return answered, nil
			}
			runner := newMemoryRunner(t, client)
			_, err := runner.Execute(context.Background(), runnerRequest())
			if !errors.Is(err, ErrExecutionPending) {
				t.Fatalf("the answer was not refused as unverified: %v", err)
			}
			if stored := storedObjects(t, runner, answered); stored != 0 {
				t.Fatalf("%d objects of a refused answer were kept", stored)
			}
		})
	}
}

func TestTheRunnerSendsNothingForARequestThatNamesAnotherSource(t *testing.T) {
	client := &memoryExecutor{}
	client.result = func(request executorservice.ExecuteRequest) (executorservice.ExecuteResult, error) {
		return honestResult(request), nil
	}
	runner := newMemoryRunner(t, client)
	for name, alter := range map[string]func(*ServiceExecution){
		"another source digest": func(e *ServiceExecution) { e.Request.SourceDigest = sha256Text(sha256Sum(nil)) },
		"no source":             func(e *ServiceExecution) { e.Request.SourceArchive = nil },
		"an oversize source": func(e *ServiceExecution) {
			e.Request.SourceArchive = make([]byte, MaxInlineInputBytes+1)
			e.Request.SourceDigest = sha256Text(sha256Sum(e.Request.SourceArchive))
		},
		"no service retention": func(e *ServiceExecution) { e.ServiceRetainUntilUnix = 0 },
		"no manifest":          func(e *ServiceExecution) { e.ManifestDigest = "" },
		"no toolchain":         func(e *ServiceExecution) { e.ToolchainDigest = "" },
		"a zero limit":         func(e *ServiceExecution) { e.Limits.MemoryBytes = 0 },
		"no node retention":    func(e *ServiceExecution) { e.RetainUntilUnix = 0 },
	} {
		execution := runnerRequest()
		alter(&execution)
		if _, err := runner.Execute(context.Background(), execution); err == nil {
			t.Errorf("%s: the execution was accepted", name)
		}
	}
	if len(client.requests) != 0 {
		t.Fatalf("%d invalid executions reached the service", len(client.requests))
	}
}

func TestEveryServiceErrorHasOneMeaning(t *testing.T) {
	cases := []struct {
		err   error
		class error
	}{
		{executorservice.ErrExecutionFailed, ErrExecutionFailed},
		{executorservice.ErrAmbiguous, ErrExecutionUnknown},
		{executorservice.ErrConflict, ErrExecutionUnknown},
		{executorservice.ErrBusy, ErrExecutionPending},
		{executorservice.ErrInProgress, ErrExecutionPending},
		{executorservice.ErrUnavailable, ErrExecutionPending},
		{executorservice.ErrLimitsRefused, ErrExecutionPending},
		{executorservice.ErrNotAllowed, ErrExecutionPending},
		{executorservice.ErrStorageFull, ErrExecutionPending},
		{executorservice.ErrRetentionFull, ErrExecutionPending},
		{executorservice.ErrObjectsUnavailable, ErrExecutionPending},
		{executorservice.ErrInvalidRequest, ErrExecutionPending},
		{executorservice.ErrTimeout, ErrExecutionPending},
		{executorservice.ErrProtocol, ErrExecutionPending},
		{executorservice.ErrServerIdentity, ErrExecutionPending},
		{context.Canceled, ErrExecutionPending},
		{context.DeadlineExceeded, ErrExecutionPending},
		{errors.New("executor service: connect to the service socket"), ErrExecutionPending},
	}
	for _, test := range cases {
		// As the client returns it: possibly wrapped.
		for _, err := range []error{test.err, fmt.Errorf("wrapped: %w", test.err)} {
			classified := classifyServiceError(err)
			matched := 0
			for _, class := range []error{ErrExecutionPending, ErrExecutionUnknown, ErrExecutionFailed} {
				if errors.Is(classified, class) {
					matched++
				}
			}
			if !errors.Is(classified, test.class) || matched != 1 || !errors.Is(classified, test.err) {
				t.Errorf("%v is classified as %v", test.err, classified)
			}
		}
	}
}

func TestTamperedObjectsAndForeignOutcomesFromTheSocketAreNeverAttested(t *testing.T) {
	other := sha256Text(sha256Sum([]byte("something else")))
	cases := map[string]func(*scriptedAnswer){
		"altered artifact bytes":   func(a *scriptedAnswer) { a.Artifact = []byte("artifacT") },
		"altered report bytes":     func(a *scriptedAnswer) { a.Report = []byte("reporT") },
		"an outcome of another id": func(a *scriptedAnswer) { a.Outcome.ExecutionID = other },
		"an outcome of another quote": func(a *scriptedAnswer) {
			a.Outcome.QuoteCommitment = "tvm-cell-" + other
		},
		"an outcome of another input":   func(a *scriptedAnswer) { a.Outcome.InputDigest = other },
		"an outcome of another source":  func(a *scriptedAnswer) { a.Outcome.SourceDigest = other },
		"an outcome of another sandbox": func(a *scriptedAnswer) { a.Outcome.SandboxDigest = other },
		"an outcome of another image":   func(a *scriptedAnswer) { a.Outcome.ToolchainDigest = other },
		"bytes after the report":        func(a *scriptedAnswer) { a.Report = append(a.Report, 'x') },
	}
	for name, alter := range cases {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			service := startScriptedExecutor(t, func(request scriptedRequest) scriptedAnswer {
				answer := scriptedSuccess(request, []byte("artifact"), []byte("report"))
				alter(&answer)
				return answer
			})
			fixture := newGateFixture(t, serviceFixtureStart)
			node := openServiceNode(t, fixture, serviceState(t), ownClient(t, service.socket))
			err := node.provider.HandleTask(ctx, fixture.message)
			if !errors.Is(err, ErrExecutionPending) {
				t.Fatalf("the answer was not refused as unverified: %v", err)
			}
			record := node.record(t)
			if record.State != ProviderExecuting || node.lifecycle.responds != 0 || record.ResponseHash != "" {
				t.Fatalf("an unverified answer moved the record to %s with %d responds", record.State,
					node.lifecycle.responds)
			}
			objects, readErr := os.ReadDir(filepath.Join(node.state, "executor-service", "artifacts", "objects"))
			if readErr != nil || len(objects) != 0 {
				t.Fatalf("%d objects of an unverified answer were kept: %v", len(objects), readErr)
			}
		})
	}
}

func TestASocketNotServedByRootIsNeverUsed(t *testing.T) {
	if os.Getuid() == 0 {
		t.Fatal("this test serves the socket as the test user to prove a non-root server is refused; run it " +
			"unprivileged")
	}
	ctx := context.Background()
	service := startScriptedExecutor(t, func(request scriptedRequest) scriptedAnswer {
		return scriptedSuccess(request, []byte("artifact"), []byte("report"))
	})
	// The client a node opens, which requires root to serve the socket.
	client, err := OpenExecutorService(service.socket)
	if err != nil {
		t.Fatal(err)
	}
	fixture := newGateFixture(t, serviceFixtureStart)
	node := openServiceNode(t, fixture, serviceState(t), client)
	if err = node.runner.Ready(ctx); !errors.Is(err, executorservice.ErrServerIdentity) {
		t.Fatalf("a socket served by uid %d was found ready: %v", os.Getuid(), err)
	}
	if err = node.provider.HandleTask(ctx, fixture.message); !errors.Is(err, executorservice.ErrServerIdentity) {
		t.Fatalf("a task was admitted for a socket not served by root: %v", err)
	}
	if slotCount(t, node.state) != 0 {
		t.Fatal("the refused task took a slot")
	}
	_, err = node.runner.Execute(ctx, runnerRequest())
	if !errors.Is(err, executorservice.ErrServerIdentity) || !errors.Is(err, ErrExecutionPending) {
		t.Fatalf("an execution was sent to a socket not served by root: %v", err)
	}
	if len(service.seen()) != 0 {
		t.Fatal("a request reached a server of another identity")
	}
}

func TestTheProviderSectionNamesExactlyOneExecutor(t *testing.T) {
	socket := ProviderNode{ExecutorSocket: DefaultExecutorSocket}
	subprocess := ProviderNode{
		ExecutorBinary: "/opt/executor", ExecutorSHA256: "00", ContainerdSocket: "/run/c.sock", FIFODir: "/var/fifo",
	}
	if mode, err := socket.ExecutorMode(); err != nil || mode != ExecutorModeSocket {
		t.Fatalf("socket: %s %v", mode, err)
	}
	if mode, err := subprocess.ExecutorMode(); err != nil || mode != ExecutorModeSubprocess {
		t.Fatalf("subprocess: %s %v", mode, err)
	}
	refused := map[string]ProviderNode{
		"neither":            {},
		"a relative socket":  {ExecutorSocket: "run/executor.sock"},
		"an unclean socket":  {ExecutorSocket: "/run/../run/executor.sock"},
		"socket and binary":  {ExecutorSocket: DefaultExecutorSocket, ExecutorBinary: "/opt/executor"},
		"socket and pin":     {ExecutorSocket: DefaultExecutorSocket, ExecutorSHA256: "00"},
		"socket and runtime": {ExecutorSocket: DefaultExecutorSocket, ContainerdSocket: "/run/c.sock"},
		"socket and FIFO":    {ExecutorSocket: DefaultExecutorSocket, FIFODir: "/var/fifo"},
		"socket and whole section": {
			ExecutorSocket:   DefaultExecutorSocket,
			ExecutorBinary:   "/opt/executor",
			ContainerdSocket: "/run/c.sock",
		},
	}
	for name, section := range refused {
		if mode, err := section.ExecutorMode(); err == nil {
			t.Errorf("%s: accepted as %s", name, mode)
		}
	}
	var absent *ProviderNode
	if _, err := absent.ExecutorMode(); err == nil {
		t.Error("a missing provider section names an executor")
	}
}

func TestTheServiceMustFitTheManifest(t *testing.T) {
	limits := RailLimits()
	good := goodDescription()
	if problem := describedLimitsProblem(good, limits); problem != "" {
		t.Fatalf("the frozen preset refuses the rail limits: %s", problem)
	}
	if problem := describedImageProblem(good, softwarework.FrozenV1ImageDigest); problem != "" {
		t.Fatalf("the frozen image is refused: %s", problem)
	}
	if describedImageProblem(good, sha256Text(sha256Sum([]byte("another")))) == "" {
		t.Error("another image than the manifest toolchain fits")
	}
	for name, alter := range map[string]func(*executorservice.Description, *nativecore.SoftwareWorkLimitsV1){
		"cpu": func(d *executorservice.Description, _ *nativecore.SoftwareWorkLimitsV1) {
			d.Limits.CPUMillis = limits.CPUMillis - 1
		},
		"memory": func(d *executorservice.Description, _ *nativecore.SoftwareWorkLimitsV1) {
			d.Limits.MemoryBytes = limits.MemoryBytes - 1
		},
		"scratch": func(d *executorservice.Description, _ *nativecore.SoftwareWorkLimitsV1) {
			d.Limits.ScratchBytes = limits.ScratchBytes - 1
		},
		"output": func(d *executorservice.Description, _ *nativecore.SoftwareWorkLimitsV1) {
			d.Limits.OutputBytes = limits.OutputBytes - 1
		},
		"wall clock": func(d *executorservice.Description, _ *nativecore.SoftwareWorkLimitsV1) {
			d.Limits.WallClockMillis = limits.WallClockMillis - 1
		},
		"a zero manifest limit": func(_ *executorservice.Description, l *nativecore.SoftwareWorkLimitsV1) {
			l.OutputBytes = 0
		},
		"the source bound": func(d *executorservice.Description, _ *nativecore.SoftwareWorkLimitsV1) {
			d.MaxSourceBytes = MaxInlineInputBytes - 1
		},
	} {
		description, manifest := goodDescription(), RailLimits()
		alter(&description, &manifest)
		if describedLimitsProblem(description, manifest) == "" {
			t.Errorf("%s: limits the service would refuse fit", name)
		}
	}
}
