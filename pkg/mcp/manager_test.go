package mcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tosnetwork/openfox/pkg/config"
	runtimeevents "github.com/tosnetwork/openfox/pkg/events"
)

func TestExpandHomeCommandPath(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	t.Setenv("USERPROFILE", homeDir)

	want := filepath.Join(homeDir, "bin", "my-mcp")
	got := expandHomeCommandPath("~" + string(os.PathSeparator) + filepath.Join("bin", "my-mcp"))
	if got != want {
		t.Fatalf("expandHomeCommandPath() = %q, want %q", got, want)
	}

	if got := expandHomeCommandPath("npx"); got != "npx" {
		t.Fatalf("expandHomeCommandPath() should leave bare commands unchanged, got %q", got)
	}
}

func TestLoadFromMCPConfig_EmptyWorkspaceWithRelativeEnvFile(t *testing.T) {
	mgr := newTestManager()

	mcpCfg := config.MCPConfig{
		ToolConfig: config.ToolConfig{
			Enabled: true,
		},
		Servers: map[string]config.MCPServerConfig{
			"test-server": {
				Enabled: true,
				Command: "echo",
				Args:    []string{"ok"},
				EnvFile: ".env",
			},
		},
	}

	err := mgr.LoadFromMCPConfig(context.Background(), mcpCfg, "")
	if err == nil {
		t.Fatal("expected error for relative env_file with empty workspace path, got nil")
	}

	if !strings.Contains(err.Error(), "workspace path is empty") {
		t.Fatalf("expected workspace path validation error, got: %v", err)
	}
}

func TestNewManager_InitialState(t *testing.T) {
	mgr := newTestManager()
	if mgr == nil {
		t.Fatal("expected manager instance, got nil")
	}
	if len(mgr.GetServers()) != 0 {
		t.Fatalf("expected no servers on new manager, got %d", len(mgr.GetServers()))
	}
}

func TestConnectServerPublishesRuntimeEvents(t *testing.T) {
	originalConnectServerFunc := connectServerFunc
	t.Cleanup(func() {
		connectServerFunc = originalConnectServerFunc
	})

	eventBus := runtimeevents.NewBus()
	defer func() {
		if err := eventBus.Close(); err != nil {
			t.Errorf("event bus close failed: %v", err)
		}
	}()

	_, eventsCh, err := eventBus.Channel().OfKind(
		runtimeevents.KindMCPServerConnected,
		runtimeevents.KindMCPServerFailed,
	).SubscribeChan(t.Context(), runtimeevents.SubscribeOptions{Name: "mcp-events", Buffer: 2})
	if err != nil {
		t.Fatalf("SubscribeChan failed: %v", err)
	}

	connectServerFunc = func(
		_ context.Context,
		name string,
		cfg config.MCPServerConfig,
		_ *os.File,
		_ func() error,
		_ bool,
	) (*ServerConnection, error) {
		if name == "bad" {
			return nil, fmt.Errorf("connect failed")
		}
		return &ServerConnection{
			Name:   name,
			Config: cfg,
			Tools:  []*sdkmcp.Tool{{Name: "echo"}},
		}, nil
	}

	mgr := newTestManager(WithRuntimeEvents(eventBus))
	err = mgr.ConnectServer(context.Background(), "good", config.MCPServerConfig{
		Type:    "stdio",
		Command: "echo",
	})
	if err != nil {
		t.Fatalf("ConnectServer(good) error = %v", err)
	}
	connected := receiveMCPRuntimeEvent(t, eventsCh)
	if connected.Kind != runtimeevents.KindMCPServerConnected ||
		connected.Source.Name != "good" ||
		connected.Severity != runtimeevents.SeverityInfo {
		t.Fatalf("connected event = %+v", connected)
	}
	if connected.Attrs["server"] != "good" ||
		connected.Attrs["type"] != "stdio" ||
		connected.Attrs["tool_count"] != 1 {
		t.Fatalf("connected attrs = %#v", connected.Attrs)
	}

	err = mgr.ConnectServer(context.Background(), "bad", config.MCPServerConfig{
		Type:    "stdio",
		Command: "echo",
	})
	if err == nil {
		t.Fatal("expected ConnectServer(bad) to fail")
	}
	failed := receiveMCPRuntimeEvent(t, eventsCh)
	if failed.Kind != runtimeevents.KindMCPServerFailed ||
		failed.Source.Name != "bad" ||
		failed.Severity != runtimeevents.SeverityError {
		t.Fatalf("failed event = %+v", failed)
	}
	if failed.Attrs["server"] != "bad" || failed.Attrs["error"] != "connect failed" {
		t.Fatalf("failed attrs = %#v", failed.Attrs)
	}
}

func receiveMCPRuntimeEvent(t *testing.T, ch <-chan runtimeevents.Event) runtimeevents.Event {
	t.Helper()

	select {
	case evt, ok := <-ch:
		if !ok {
			t.Fatal("runtime event channel closed before expected event")
		}
		return evt
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for runtime event")
		return runtimeevents.Event{}
	}
}

func TestLoadFromMCPConfig_DisabledOrEmptyServers(t *testing.T) {
	mgr := newTestManager()

	err := mgr.LoadFromMCPConfig(
		context.Background(),
		config.MCPConfig{ToolConfig: config.ToolConfig{Enabled: false}},
		"/tmp",
	)
	if err != nil {
		t.Fatalf("expected nil error when MCP disabled, got: %v", err)
	}

	err = mgr.LoadFromMCPConfig(
		context.Background(),
		config.MCPConfig{ToolConfig: config.ToolConfig{Enabled: true}},
		"/tmp",
	)
	if err != nil {
		t.Fatalf("expected nil error when no servers configured, got: %v", err)
	}
}

func TestGetServers_ReturnsCopy(t *testing.T) {
	mgr := newTestManager()
	mgr.servers["s1"] = &ServerConnection{Name: "s1"}

	servers := mgr.GetServers()
	delete(servers, "s1")

	if _, ok := mgr.GetServer("s1"); !ok {
		t.Fatal("expected internal manager state to remain unchanged")
	}
}

func TestGetAllTools_FiltersEmptyTools(t *testing.T) {
	mgr := newTestManager()
	mgr.servers["empty"] = &ServerConnection{Name: "empty", Tools: nil}
	mgr.servers["with-tools"] = &ServerConnection{Name: "with-tools", Tools: []*sdkmcp.Tool{{}}}

	all := mgr.GetAllTools()
	if _, ok := all["empty"]; ok {
		t.Fatal("expected server without tools to be excluded")
	}
	if _, ok := all["with-tools"]; !ok {
		t.Fatal("expected server with tools to be included")
	}
}

func TestCallTool_ErrorsForClosedOrMissingServer(t *testing.T) {
	t.Run("manager closed", func(t *testing.T) {
		mgr := newTestManager()
		mgr.closed.Store(true)

		_, err := mgr.CallTool(context.Background(), "s1", "tool", nil)
		if err == nil || !strings.Contains(err.Error(), "manager is closed") {
			t.Fatalf("expected manager closed error, got: %v", err)
		}
	})

	t.Run("server missing", func(t *testing.T) {
		mgr := newTestManager()

		_, err := mgr.CallTool(context.Background(), "missing", "tool", nil)
		if err == nil || !strings.Contains(err.Error(), "not found") {
			t.Fatalf("expected server not found error, got: %v", err)
		}
	})
}

func TestConnectServer_StreamableHTTPRequestResponseMode(t *testing.T) {
	for _, transportType := range []string{"http", "streamable-http"} {
		t.Run(transportType, func(t *testing.T) {
			server := sdkmcp.NewServer(&sdkmcp.Implementation{
				Name:    "streamable-test-server",
				Version: "1.0.0",
			}, nil)
			sdkmcp.AddTool(server, &sdkmcp.Tool{
				Name:        "echo",
				Description: "Echo test tool",
			}, func(ctx context.Context, req *sdkmcp.CallToolRequest, args map[string]any) (*sdkmcp.CallToolResult, any, error) {
				return &sdkmcp.CallToolResult{
					Content: []sdkmcp.Content{
						&sdkmcp.TextContent{Text: "ok"},
					},
				}, nil, nil
			})

			type observedRequest struct {
				Method        string
				SessionID     string
				Authorization string
			}

			var (
				mu       sync.Mutex
				observed []observedRequest
			)

			handler := sdkmcp.NewStreamableHTTPHandler(func(*http.Request) *sdkmcp.Server {
				return server
			}, nil)
			httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				observed = append(observed, observedRequest{
					Method:        r.Method,
					SessionID:     r.Header.Get("Mcp-Session-Id"),
					Authorization: r.Header.Get("Authorization"),
				})
				mu.Unlock()
				handler.ServeHTTP(w, r)
			}))
			defer httpServer.Close()
			priorSafeClient := safeMCPHTTPClientFunc
			safeMCPHTTPClientFunc = func(_ string, headers map[string]string) (*http.Client, error) {
				client := httpServer.Client()
				client.Transport = &headerTransport{base: client.Transport, headers: headers}
				return client, nil
			}
			defer func() { safeMCPHTTPClientFunc = priorSafeClient }()

			conn, err := connectServer(context.Background(), "streamable", config.MCPServerConfig{
				Enabled: true,
				Type:    transportType,
				URL:     httpServer.URL,
				Headers: map[string]string{
					"Authorization": "Bearer test-token",
				},
			}, nil, nil, false)
			if err != nil {
				t.Fatalf("connectServer(%q) error = %v", transportType, err)
			}
			if got := len(conn.Tools); got != 1 {
				t.Fatalf("len(conn.Tools) = %d, want 1", got)
			}
			if got := conn.Session.ID(); got == "" {
				t.Fatal("expected non-empty streamable session ID")
			}
			if err := conn.Session.Close(); err != nil {
				t.Fatalf("Session.Close() error = %v", err)
			}

			mu.Lock()
			defer mu.Unlock()

			var (
				getCount            int
				postCount           int
				deleteCount         int
				postWithSession     bool
				deleteWithSession   bool
				requestsWithAuth    int
				requestsWithoutAuth []string
			)

			for _, req := range observed {
				switch req.Method {
				case http.MethodGet:
					getCount++
				case http.MethodPost:
					postCount++
					if req.SessionID != "" {
						postWithSession = true
					}
				case http.MethodDelete:
					deleteCount++
					if req.SessionID != "" {
						deleteWithSession = true
					}
				}

				if req.Authorization == "Bearer test-token" {
					requestsWithAuth++
				} else {
					requestsWithoutAuth = append(requestsWithoutAuth, req.Method)
				}
			}

			if getCount != 0 {
				t.Fatalf("expected no standalone GET requests for %q transport, saw %d", transportType, getCount)
			}
			if postCount == 0 {
				t.Fatal("expected POST requests during streamable HTTP handshake")
			}
			if deleteCount != 1 {
				t.Fatalf("DELETE count = %d, want 1", deleteCount)
			}
			if !postWithSession {
				t.Fatal("expected at least one POST request with Mcp-Session-Id")
			}
			if !deleteWithSession {
				t.Fatal("expected DELETE request with Mcp-Session-Id")
			}
			if requestsWithAuth != len(observed) {
				t.Fatalf("Authorization header missing on requests: %v", requestsWithoutAuth)
			}
		})
	}
}

func TestCallTool_DoesNotReplayWhenHTTPServerLosesSession(t *testing.T) {
	originalConnectServerFunc := connectServerFunc
	t.Cleanup(func() {
		connectServerFunc = originalConnectServerFunc
	})

	staleConn, staleTransport, err := newScriptedServerConnection(
		"session-1",
		nil,
		fmt.Errorf(`sending "tools/call": failed to connect (session ID: session-1): %w`, sdkmcp.ErrSessionMissing),
	)
	if err != nil {
		t.Fatalf("newScriptedServerConnection(stale) error = %v", err)
	}
	freshConn, freshTransport, err := newScriptedServerConnection(
		"session-2",
		&sdkmcp.CallToolResult{
			Content: []sdkmcp.Content{
				&sdkmcp.TextContent{Text: "reconnected"},
			},
		},
		nil,
	)
	if err != nil {
		t.Fatalf("newScriptedServerConnection(fresh) error = %v", err)
	}

	connectCalls := 0
	connectServerFunc = func(ctx context.Context, name string, cfg config.MCPServerConfig, _ *os.File, _ func() error, _ bool) (*ServerConnection, error) {
		connectCalls++
		if connectCalls == 1 {
			return freshConn, nil
		}
		return nil, fmt.Errorf("unexpected reconnect attempt %d", connectCalls)
	}

	mgr := newTestManager()
	mgr.servers["flaky"] = staleConn

	actionID := bytes.Repeat([]byte{31}, 32)
	result, err := mgr.CallToolWithAction(context.Background(), actionID, "flaky", "echo", map[string]any{
		"query": "hello",
	})
	if result != nil || !errors.Is(err, ErrAmbiguousToolEffect) {
		t.Fatalf("CallTool() = %#v, %v; want ambiguous without replay", result, err)
	}
	if connectCalls != 0 {
		t.Fatalf("connectCalls = %d, want 0", connectCalls)
	}
	if staleTransport.toolCallCalls != 1 {
		t.Fatalf("stale toolCallCalls = %d, want 1", staleTransport.toolCallCalls)
	}
	if freshTransport.toolCallCalls != 0 {
		t.Fatalf("fresh toolCallCalls = %d, want 0", freshTransport.toolCallCalls)
	}
	if _, retryErr := mgr.CallToolWithAction(context.Background(), actionID, "flaky", "echo", map[string]any{"query": "hello"}); retryErr == nil {
		t.Fatal("ambiguous MCP Action was replayed")
	}
	_ = freshConn
}

func TestClose_IdempotentOnEmptyManager(t *testing.T) {
	mgr := newTestManager()

	if err := mgr.Close(); err != nil {
		t.Fatalf("first close should succeed, got: %v", err)
	}
	if err := mgr.Close(); err != nil {
		t.Fatalf("second close should be idempotent, got: %v", err)
	}
}

func newScriptedServerConnection(
	sessionID string,
	toolCallResult *sdkmcp.CallToolResult,
	toolCallErr error,
) (*ServerConnection, *scriptedTransport, error) {
	transport := &scriptedTransport{
		sessionID:      sessionID,
		toolCallResult: toolCallResult,
		toolCallErr:    toolCallErr,
	}

	client := sdkmcp.NewClient(&sdkmcp.Implementation{
		Name:    "openfox-test",
		Version: "1.0.0",
	}, nil)
	session, err := client.Connect(context.Background(), transport, nil)
	if err != nil {
		return nil, nil, err
	}

	return &ServerConnection{
		Name:    "flaky",
		Config:  config.MCPServerConfig{Enabled: true, Type: "http", URL: "https://example.invalid/mcp"},
		Client:  client,
		Session: session,
		Tools: []*sdkmcp.Tool{
			{
				Name:        "echo",
				Description: "Echo test tool",
				InputSchema: map[string]any{"type": "object"},
			},
		},
	}, transport, nil
}

type scriptedTransport struct {
	sessionID      string
	toolCallResult *sdkmcp.CallToolResult
	toolCallErr    error

	mu             sync.Mutex
	toolCallCalls  int
	lastToolParams []byte
	closed         bool
	incoming       chan jsonrpc.Message
}

func (t *scriptedTransport) Connect(context.Context) (sdkmcp.Connection, error) {
	if t.incoming == nil {
		t.incoming = make(chan jsonrpc.Message, 4)
	}
	return t, nil
}

func (t *scriptedTransport) Read(ctx context.Context) (jsonrpc.Message, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case msg, ok := <-t.incoming:
		if !ok {
			return nil, io.EOF
		}
		return msg, nil
	}
}

func (t *scriptedTransport) Write(ctx context.Context, msg jsonrpc.Message) error {
	req, ok := msg.(*jsonrpc.Request)
	if !ok {
		return nil
	}

	switch req.Method {
	case "server/discover":
		// Current MCP clients probe the new discovery method before falling
		// back to the legacy initialize handshake. This scripted legacy server
		// must reject that probe with the protocol-defined error, rather than
		// closing the connection and making the reconnect test nondeterministic.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case t.incoming <- &jsonrpc.Response{ID: req.ID, Error: &jsonrpc.Error{Code: jsonrpc.CodeMethodNotFound, Message: "server/discover is unsupported"}}:
			return nil
		}
	case "initialize":
		payload, err := json.Marshal(&sdkmcp.InitializeResult{
			ProtocolVersion: "2025-11-25",
			ServerInfo: &sdkmcp.Implementation{
				Name:    "scripted-test-server",
				Version: "1.0.0",
			},
			Capabilities: &sdkmcp.ServerCapabilities{
				Tools: &sdkmcp.ToolCapabilities{},
			},
		})
		if err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case t.incoming <- &jsonrpc.Response{ID: req.ID, Result: payload}:
			return nil
		}

	case "notifications/initialized":
		return nil

	case "tools/call":
		t.mu.Lock()
		t.toolCallCalls++
		t.lastToolParams = append([]byte(nil), req.Params...)
		t.mu.Unlock()

		if t.toolCallErr != nil {
			return t.toolCallErr
		}

		payload, err := json.Marshal(t.toolCallResult)
		if err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case t.incoming <- &jsonrpc.Response{ID: req.ID, Result: payload}:
			return nil
		}
	}

	return fmt.Errorf("unexpected method %q", req.Method)
}

func (t *scriptedTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	close(t.incoming)
	return nil
}

func (t *scriptedTransport) SessionID() string {
	return t.sessionID
}

type statefulJSONArgument struct{ calls atomic.Int32 }

func (value *statefulJSONArgument) MarshalJSON() ([]byte, error) {
	if value.calls.Add(1) == 1 {
		return []byte(`{"value":"authorized"}`), nil
	}
	return []byte(`{"value":"substituted"}`), nil
}

func TestCallToolFreezesPlainJSONOnceBeforeAuthorizationAndPipeWrite(t *testing.T) {
	connection, transport, err := newScriptedServerConnection("sealed", &sdkmcp.CallToolResult{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	value := &statefulJSONArgument{}
	mgr := newTestManager(WithEffectAuthorizer(func(_ context.Context, server string, _ config.MCPServerConfig, observation ConnectionObservation, tool string, exact, digest []byte) ([]byte, error) {
		want, err := mcpToolEffectRequestDigestFromWire(server, observation, tool, exact)
		if err != nil || !bytes.Equal(want, digest) || !bytes.Contains(exact, []byte(`"authorized"`)) {
			return nil, errors.New("authorizer did not receive exact frozen arguments")
		}
		return bytes.Repeat([]byte{31}, sha256.Size), nil
	}))
	mgr.servers["sealed"] = connection
	if _, err := mgr.CallTool(context.Background(), "sealed", "write", map[string]any{"payload": value}); err != nil {
		t.Fatal(err)
	}
	transport.mu.Lock()
	wire := append([]byte(nil), transport.lastToolParams...)
	transport.mu.Unlock()
	if value.calls.Load() != 1 || !bytes.Contains(wire, []byte(`"authorized"`)) || bytes.Contains(wire, []byte(`"substituted"`)) {
		t.Fatalf("pipe bytes were reserialized from mutable arguments: calls=%d wire=%s", value.calls.Load(), wire)
	}
}

func newTestManager(opts ...ManagerOption) *Manager {
	journal := &testEffectJournal{records: map[string][]byte{}}
	opts = append(opts,
		WithConnectionAuthorizer(func(context.Context, string, config.MCPServerConfig) (ConnectionAuthorization, error) {
			return ConnectionAuthorization{}, nil
		}),
		WithSessionVerifier(func(context.Context, string, config.MCPServerConfig, ConnectionObservation) error { return nil }),
		WithEffectAuthorizer(func(context.Context, string, config.MCPServerConfig, ConnectionObservation, string, []byte, []byte) ([]byte, error) {
			return bytes.Repeat([]byte{31}, sha256.Size), nil
		}),
		WithEffectJournal(journal),
	)
	return NewManager(opts...)
}

type testEffectJournal struct {
	mu      sync.Mutex
	records map[string][]byte
}

func (j *testEffectJournal) PrepareMCPAction(actionID, request []byte) ([]byte, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	key := string(actionID)
	if _, exists := j.records[key]; exists {
		return nil, ErrAmbiguousToolEffect
	}
	j.records[key] = append([]byte(nil), request...)
	return bytes.Repeat([]byte{9}, sha256.Size), nil
}

func (j *testEffectJournal) ResolveMCPAction(actionID, request, token []byte, disposition string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if prior, exists := j.records[string(actionID)]; !exists || !bytes.Equal(prior, request) || !bytes.Equal(token, bytes.Repeat([]byte{9}, sha256.Size)) {
		return errors.New("unknown test MCP Action")
	}
	return nil
}
