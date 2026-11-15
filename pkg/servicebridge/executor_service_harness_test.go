package servicebridge

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/tosnetwork/ai/execution/pkg/artifactstore"
	"github.com/tosnetwork/ai/execution/pkg/executor"
	"github.com/tosnetwork/ai/execution/pkg/executorservice"
	"github.com/tosnetwork/ai/execution/pkg/softwarework"
)

// fakeRuntime stands in for the container runtime behind the service's real
// policy executor, journal and store.
type fakeRuntime struct {
	mutex   sync.Mutex
	calls   int
	exit    int
	started chan struct{}
	gate    chan struct{}
}

func (f *fakeRuntime) RunIsolated(ctx context.Context, _ executor.ContainerRequest, _ []byte) (executor.Result, error) {
	f.mutex.Lock()
	f.calls++
	gate, exit, started := f.gate, f.exit, f.started
	f.mutex.Unlock()
	if started != nil {
		started <- struct{}{}
	}
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return executor.Result{}, ctx.Err()
		}
	}
	return executor.Result{
		ExitCode: exit, Output: []byte("ok  \texample.test/rail\t0.002s\n"),
		Usage: executor.Usage{CPUMillis: 1, PeakMemory: 1024, DiskWritten: 10, Duration: time.Millisecond},
	}, nil
}

func (f *fakeRuntime) runs() int {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	return f.calls
}

// shortSocketDir is a private directory whose path fits a socket address.
func shortSocketDir(t *testing.T) string {
	t.Helper()
	created, err := os.MkdirTemp("", "xs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(created) })
	resolved, err := filepath.EvalSymlinks(created)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

// ownClient is a client of a service this test process serves. The
// production client, OpenExecutorService, requires root to serve the socket.
func ownClient(t *testing.T, socket string) ExecutorService {
	t.Helper()
	client, err := executorservice.NewClient(executorservice.ClientConfig{
		SocketPath: socket, ServerUID: uint32(os.Getuid()),
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// realExecutor is the executor service's own server, wired as its daemon
// wires it, on a fake runtime.
type realExecutor struct {
	server  *executorservice.Server
	store   *artifactstore.Store
	journal *softwarework.Journal
	backend *fakeRuntime
	socket  string
	served  chan error
	stopped sync.Once
}

func startRealExecutor(
	t *testing.T,
	root string,
	backend *fakeRuntime,
	edit func(*executorservice.Config),
) *realExecutor {
	t.Helper()
	state := filepath.Join(root, "service-state")
	socketDir := filepath.Join(root, "s")
	for _, directory := range []string{state, socketDir} {
		if err := os.Mkdir(directory, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			t.Fatal(err)
		}
	}
	bound, err := executor.NewPolicyExecutor(softwarework.FrozenV1Policy(), backend)
	if err != nil {
		t.Fatal(err)
	}
	store, err := artifactstore.Open(filepath.Join(state, "artifacts"), artifactstore.MaxObjectBytesHard)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := softwarework.OpenJournal(filepath.Join(state, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	allowed := uint32(os.Getuid())
	config := executorservice.Config{
		AllowedUID: &allowed, Executor: bound, Store: store, Journal: journal,
		Ready:    func(context.Context) error { return nil },
		Identity: executorservice.Identity{Version: "test-version", Commit: "test-commit"},
	}
	if edit != nil {
		edit(&config)
	}
	server, err := executorservice.NewServer(config)
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(socketDir, "x.sock")
	listener, err := executorservice.Listen(socket, uint32(os.Getegid()))
	if err != nil {
		t.Fatal(err)
	}
	service := &realExecutor{
		server: server, store: store, journal: journal, backend: backend, socket: socket,
		served: make(chan error, 1),
	}
	go func() { service.served <- server.Serve(listener) }()
	t.Cleanup(func() { service.stop(t) })
	return service
}

// stop shuts the service down; a run still held by its gate is canceled.
func (s *realExecutor) stop(t *testing.T) {
	t.Helper()
	s.stopped.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.server.Shutdown(ctx)
		if err := <-s.served; err != nil {
			t.Errorf("serve: %v", err)
		}
		if err := s.journal.Close(); err != nil {
			t.Errorf("close the service journal: %v", err)
		}
	})
}

// scriptedRequest is one execute request a scripted service received.
type scriptedRequest struct {
	Header executeFields
	Source []byte
}

// executeFields is the execute header of the service protocol.
type executeFields struct {
	ExecutionID     string                 `json:"execution_id"`
	QuoteCommitment string                 `json:"quote_commitment"`
	InputDigest     string                 `json:"input_digest"`
	ManifestDigest  string                 `json:"manifest_digest"`
	Limits          executorservice.Limits `json:"limits"`
	RetainUntilUnix int64                  `json:"retain_until_unix"`
	SourceDigest    string                 `json:"source_digest"`
	SourceBytes     uint64                 `json:"source_bytes"`
}

// scriptedAnswer is what a scripted service answers one execute request
// with. Drop closes the connection without an answer.
type scriptedAnswer struct {
	Status  executorservice.Status
	Outcome *softwarework.Outcome
	// RetainUntilUnix is the deadline the service says it applied; zero
	// answers with the deadline that was asked for.
	RetainUntilUnix int64
	Artifact        []byte
	Report          []byte
	Drop            bool
}

// scriptedExecutor speaks the service protocol on a real Unix socket and
// answers what the test tells it to, for the answers the real server gives
// only in states a test cannot arrange.
type scriptedExecutor struct {
	socket   string
	listener *net.UnixListener
	done     chan struct{}

	mutex sync.Mutex
	// stall holds every connection open without an answer.
	stall       bool
	description executorservice.Description
	answer      func(scriptedRequest) scriptedAnswer
	requests    []scriptedRequest
}

func goodDescription() executorservice.Description {
	return executorservice.Description{
		Version: "scripted", Commit: "scripted", ImageDigest: softwarework.FrozenV1ImageDigest,
		ImageReference: softwarework.FrozenV1ImageReference, Limits: executorservice.FrozenLimits(), PIDs: 64,
		MaxSourceBytes: executorservice.MaxSourceBytes, MaxObjectBytes: executorservice.MaxObjectBytes,
		MaxExecutions: 1, DefaultRetentionSeconds: 7 * 86400, MaxRetentionSeconds: 31 * 86400, Ready: true,
	}
}

func startScriptedExecutor(t *testing.T, answer func(scriptedRequest) scriptedAnswer) *scriptedExecutor {
	t.Helper()
	socket := filepath.Join(shortSocketDir(t), "x.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	service := &scriptedExecutor{
		socket: socket, listener: listener, done: make(chan struct{}), description: goodDescription(),
		answer: answer,
	}
	go service.serve()
	t.Cleanup(func() {
		_ = listener.Close()
		<-service.done
	})
	return service
}

func (s *scriptedExecutor) setAnswer(answer func(scriptedRequest) scriptedAnswer) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.answer = answer
}

func (s *scriptedExecutor) setDescription(description executorservice.Description) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.description = description
}

func (s *scriptedExecutor) seen() []scriptedRequest {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return append([]scriptedRequest(nil), s.requests...)
}

func (s *scriptedExecutor) serve() {
	defer close(s.done)
	for {
		conn, err := s.listener.AcceptUnix()
		if err != nil {
			return
		}
		s.handle(conn)
		_ = conn.Close()
	}
}

func (s *scriptedExecutor) handle(conn *net.UnixConn) {
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	var prefix [4]byte
	if _, err := io.ReadFull(conn, prefix[:]); err != nil {
		return
	}
	raw := make([]byte, binary.BigEndian.Uint32(prefix[:]))
	if _, err := io.ReadFull(conn, raw); err != nil {
		return
	}
	var header struct {
		Schema    string         `json:"schema"`
		Operation string         `json:"operation"`
		Execute   *executeFields `json:"execute"`
	}
	if err := json.Unmarshal(raw, &header); err != nil || header.Schema != executorservice.RequestSchema {
		return
	}
	source, err := io.ReadAll(conn)
	if err != nil {
		return
	}
	s.mutex.Lock()
	stall := s.stall
	s.mutex.Unlock()
	if stall {
		// Longer than the caller is prepared to wait.
		time.Sleep(1500 * time.Millisecond)
		return
	}
	response := map[string]any{"schema": executorservice.ResponseSchema, "status": executorservice.StatusOK}
	var payload [][]byte
	if header.Operation == executorservice.OperationDescribe {
		s.mutex.Lock()
		response["describe"] = s.description
		s.mutex.Unlock()
	} else {
		request := scriptedRequest{Header: *header.Execute, Source: source}
		s.mutex.Lock()
		s.requests = append(s.requests, request)
		answer := s.answer
		s.mutex.Unlock()
		reply := answer(request)
		if reply.Drop {
			return
		}
		response["status"] = reply.Status
		if reply.Outcome != nil {
			response["outcome"] = reply.Outcome
			response["retain_until_unix"] = reply.RetainUntilUnix
			if reply.RetainUntilUnix == 0 {
				response["retain_until_unix"] = request.Header.RetainUntilUnix
			}
		}
		payload = [][]byte{reply.Artifact, reply.Report}
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		return
	}
	frame := make([]byte, 4, 4+len(encoded))
	binary.BigEndian.PutUint32(frame, uint32(len(encoded)))
	if _, err := conn.Write(append(frame, encoded...)); err != nil {
		return
	}
	for _, part := range payload {
		if _, err := conn.Write(part); err != nil {
			return
		}
	}
}

// scriptedSuccess is a well-formed success of request with the given
// objects, as the real service would record it.
func scriptedSuccess(request scriptedRequest, artifact, report []byte) scriptedAnswer {
	outcome := softwarework.Outcome{
		QuoteCommitment: request.Header.QuoteCommitment, ExecutionID: request.Header.ExecutionID,
		InputDigest: request.Header.InputDigest, ResultDigest: sha256Text(sha256Sum([]byte("result"))),
		Artifact: artifactstore.Descriptor{
			Digest: sha256Text(sha256Sum(artifact)), MediaType: softwarework.ArtifactMediaType,
			SizeBytes: uint64(len(artifact)),
		},
		Report: artifactstore.Descriptor{
			Digest: sha256Text(sha256Sum(report)), MediaType: softwarework.ReportMediaType,
			SizeBytes: uint64(len(report)),
		},
		SourceDigest: request.Header.SourceDigest, ToolchainDigest: softwarework.FrozenV1ImageDigest,
		SandboxDigest: request.Header.ManifestDigest, ExitCode: 0, CompletedAtUnix: 1_900_000_000,
	}
	return scriptedAnswer{Status: executorservice.StatusOK, Outcome: &outcome, Artifact: artifact, Report: report}
}
