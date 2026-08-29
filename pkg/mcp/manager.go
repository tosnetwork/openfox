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
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tosnetwork/openfox/pkg/config"
	runtimeevents "github.com/tosnetwork/openfox/pkg/events"
	"github.com/tosnetwork/openfox/pkg/isolation"
	"github.com/tosnetwork/openfox/pkg/logger"
)

// headerTransport is an http.RoundTripper that adds custom headers to requests
type headerTransport struct {
	base    http.RoundTripper
	headers map[string]string
}

func expandHomeCommandPath(command string) string {
	if command == "" || command[0] != '~' {
		return command
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return command
	}
	if command == "~" {
		return home
	}
	if strings.HasPrefix(command, "~/") || strings.HasPrefix(command, "~\\") {
		return filepath.Join(home, command[2:])
	}
	return command
}

func (t *headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone the request to avoid modifying the original
	req = req.Clone(req.Context())

	// Add custom headers
	for key, value := range t.headers {
		req.Header.Set(key, value)
	}

	// Use the base transport
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}

// ServerConnection represents a connection to an MCP server
type ServerConnection struct {
	Name        string
	Config      config.MCPServerConfig
	Observation ConnectionObservation
	Client      *mcp.Client
	Session     *mcp.ClientSession
	Tools       []*mcp.Tool
	reconnectMu sync.Mutex
}

// Manager manages multiple MCP server connections
type Manager struct {
	servers          map[string]*ServerConnection
	runtimeEvents    runtimeevents.Bus
	authorizer       ConnectionAuthorizer
	verifier         SessionVerifier
	effectAuthorizer EffectAuthorizer
	effectJournal    EffectJournal
	closeHooks       []func() error
	mu               sync.RWMutex
	closed           atomic.Bool    // changed from bool to atomic.Bool to avoid TOCTOU race
	wg               sync.WaitGroup // tracks in-flight CallTool calls
}

type ConnectionAuthorization struct {
	Executable *os.File
	// BeforeStart revalidates the already-prepared one-shot use immediately
	// before the isolated process is exec'd. Consequential local MCP is
	// deliberately limited to a hermetic, no-ambient-resource profile.
	BeforeStart func() error
	Hermetic    bool
	Resolve     func(disposition string) error
}

var (
	ErrCapabilityAuthorizationRequired = errors.New("trusted capability authorization is required before MCP connection")
	// ErrAmbiguousToolEffect means the request may have reached the MCP sink.
	// Callers must resolve the same semantic Action; they must never retry it as
	// a fresh tool invocation.
	ErrAmbiguousToolEffect = errors.New("MCP tool effect outcome is ambiguous")
)

// ConnectionAuthorizer is the fail-closed boundary between untrusted MCP
// configuration and process/network creation. Implementations must validate an
// exact admitted artifact, current authority, use lease and use binding before
// returning nil. The callback runs before env files are read or any endpoint is
// contacted.
type ConnectionAuthorizer func(context.Context, string, config.MCPServerConfig) (ConnectionAuthorization, error)

type ConnectionObservation struct {
	TransportType        string
	ServerName           string
	ServerVersion        string
	ProtocolVersion      string
	ToolDescriptorDigest []byte
}

type SessionVerifier func(context.Context, string, config.MCPServerConfig, ConnectionObservation) error

// EffectAuthorizer returns the only released semantic Action identity allowed
// for the exact request digest. The identity must be committed by the signed
// capability-use closure; callers and the model cannot allocate it at runtime.
type EffectAuthorizer func(context.Context, string, config.MCPServerConfig, ConnectionObservation, string, []byte, []byte) ([]byte, error)
type EffectJournal interface {
	PrepareMCPAction(actionID, exactRequestDigest []byte) ([]byte, error)
	ResolveMCPAction(actionID, exactRequestDigest, resolutionToken []byte, disposition string) error
}

var connectServerFunc = connectServer
var safeMCPHTTPClientFunc = safeMCPHTTPClient

// ManagerOption configures an MCP manager.
type ManagerOption func(*Manager)

// WithRuntimeEvents injects the runtime event bus used for MCP observations.
func WithRuntimeEvents(eventBus runtimeevents.Bus) ManagerOption {
	return func(m *Manager) {
		m.runtimeEvents = eventBus
	}
}

func WithConnectionAuthorizer(authorizer ConnectionAuthorizer) ManagerOption {
	return func(m *Manager) {
		m.authorizer = authorizer
	}
}

func WithSessionVerifier(verifier SessionVerifier) ManagerOption {
	return func(m *Manager) {
		m.verifier = verifier
	}
}

func WithEffectAuthorizer(authorizer EffectAuthorizer) ManagerOption {
	return func(m *Manager) { m.effectAuthorizer = authorizer }
}

func WithEffectJournal(journal EffectJournal) ManagerOption {
	return func(m *Manager) { m.effectJournal = journal }
}

func WithCloseHook(hook func() error) ManagerOption {
	return func(m *Manager) {
		if hook != nil {
			m.closeHooks = append(m.closeHooks, hook)
		}
	}
}

// ServerEventPayload describes MCP server connection events.
type ServerEventPayload struct {
	Server    string `json:"server"`
	Type      string `json:"type,omitempty"`
	URL       string `json:"url,omitempty"`
	Command   string `json:"command,omitempty"`
	Tool      string `json:"tool,omitempty"`
	ToolCount int    `json:"tool_count,omitempty"`
	Error     string `json:"error,omitempty"`
}

// NewManager creates a new MCP manager
func NewManager(opts ...ManagerOption) *Manager {
	m := &Manager{
		servers: make(map[string]*ServerConnection),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(m)
		}
	}
	return m
}

// LoadFromConfig loads MCP servers from configuration
func (m *Manager) LoadFromConfig(ctx context.Context, cfg *config.Config) error {
	return m.LoadFromMCPConfig(ctx, cfg.Tools.MCP, cfg.WorkspacePath())
}

// LoadFromMCPConfig loads MCP servers from MCP configuration and workspace path.
// This is the minimal dependency version that doesn't require the full Config object.
func (m *Manager) LoadFromMCPConfig(
	ctx context.Context,
	mcpCfg config.MCPConfig,
	workspacePath string,
) error {
	if !mcpCfg.Enabled {
		logger.InfoCF("mcp", "MCP integration is disabled", nil)
		return nil
	}

	if len(mcpCfg.Servers) == 0 {
		logger.InfoCF("mcp", "No MCP servers configured", nil)
		return nil
	}

	logger.InfoCF("mcp", "Initializing MCP servers",
		map[string]any{
			"count": len(mcpCfg.Servers),
		})

	var wg sync.WaitGroup
	errs := make(chan error, len(mcpCfg.Servers))
	enabledCount := 0

	for name, serverCfg := range mcpCfg.Servers {
		if !serverCfg.Enabled {
			logger.DebugCF("mcp", "Skipping disabled server",
				map[string]any{
					"server": name,
				})
			continue
		}

		enabledCount++
		wg.Add(1)
		go func(name string, serverCfg config.MCPServerConfig, workspace string) {
			defer wg.Done()

			// Resolve relative envFile paths relative to workspace
			if serverCfg.EnvFile != "" && !filepath.IsAbs(serverCfg.EnvFile) {
				if workspace == "" {
					err := fmt.Errorf(
						"workspace path is empty while resolving relative envFile %q for server %s",
						serverCfg.EnvFile,
						name,
					)
					logger.ErrorCF("mcp", "Invalid MCP server configuration",
						map[string]any{
							"server":   name,
							"env_file": serverCfg.EnvFile,
							"error":    err.Error(),
						})
					errs <- err
					return
				}
				serverCfg.EnvFile = filepath.Join(workspace, serverCfg.EnvFile)
			}

			if err := m.ConnectServer(ctx, name, serverCfg); err != nil {
				logger.ErrorCF("mcp", "Failed to connect to MCP server",
					map[string]any{
						"server": name,
						"error":  err.Error(),
					})
				errs <- fmt.Errorf("failed to connect to server %s: %w", name, err)
			}
		}(name, serverCfg, workspacePath)
	}

	wg.Wait()
	close(errs)

	// Collect errors
	var allErrors []error
	for err := range errs {
		allErrors = append(allErrors, err)
	}

	connectedCount := len(m.GetServers())

	// If all enabled servers failed to connect, return aggregated error
	if enabledCount > 0 && connectedCount == 0 {
		logger.ErrorCF("mcp", "All MCP servers failed to connect",
			map[string]any{
				"failed": len(allErrors),
				"total":  enabledCount,
			})
		return errors.Join(allErrors...)
	}

	if len(allErrors) > 0 {
		logger.WarnCF("mcp", "Some MCP servers failed to connect",
			map[string]any{
				"failed":    len(allErrors),
				"connected": connectedCount,
				"total":     enabledCount,
			})
		// Don't fail completely if some servers successfully connected
	}

	logger.InfoCF("mcp", "MCP server initialization complete",
		map[string]any{
			"connected": connectedCount,
			"total":     enabledCount,
		})

	return nil
}

// ConnectServer connects to a single MCP server
func (m *Manager) ConnectServer(
	ctx context.Context,
	name string,
	cfg config.MCPServerConfig,
) error {
	if m.authorizer == nil {
		return ErrCapabilityAuthorizationRequired
	}
	if cfg.EnvFile != "" {
		return errors.New("ambient MCP environment files are forbidden; use immutable broker handles")
	}
	authorization, err := m.authorizer(ctx, name, cfg)
	if err != nil {
		return fmt.Errorf("authorize MCP server %q: %w", name, err)
	}
	if authorization.Executable != nil {
		defer authorization.Executable.Close()
	}
	m.publishServerEvent(runtimeevents.KindMCPServerConnecting, name, cfg, 0, nil)
	conn, err := connectServerFunc(ctx, name, cfg, authorization.Executable, authorization.BeforeStart, authorization.Hermetic)
	if err != nil {
		if authorization.Resolve != nil {
			_ = authorization.Resolve("failed")
		}
		m.publishServerEvent(runtimeevents.KindMCPServerFailed, name, cfg, 0, err)
		return err
	}
	if m.verifier == nil {
		_ = conn.Session.Close()
		if authorization.Resolve != nil {
			_ = authorization.Resolve("failed")
		}
		return errors.New("trusted capability session verifier is required after MCP connection")
	}
	if err := m.verifier(ctx, name, cfg, conn.Observation); err != nil {
		_ = conn.Session.Close()
		if authorization.Resolve != nil {
			_ = authorization.Resolve("failed")
		}
		return fmt.Errorf("verify MCP session %q: %w", name, err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed.Load() {
		_ = conn.Session.Close()
		if authorization.Resolve != nil {
			_ = authorization.Resolve("killed")
		}
		m.publishServerEvent(runtimeevents.KindMCPServerFailed, name, cfg, 0, fmt.Errorf("manager is closed"))
		return fmt.Errorf("manager is closed")
	}

	m.servers[name] = conn
	if authorization.Resolve != nil {
		resolve := authorization.Resolve
		m.closeHooks = append(m.closeHooks, func() error { return resolve("succeeded") })
	}
	for _, tool := range conn.Tools {
		toolName := ""
		if tool != nil {
			toolName = tool.Name
		}
		m.publishToolDiscovered(name, cfg, toolName)
	}
	m.publishServerEvent(runtimeevents.KindMCPServerConnected, name, cfg, len(conn.Tools), nil)
	return nil
}

func connectServer(
	ctx context.Context,
	name string,
	cfg config.MCPServerConfig,
	sealedExecutable *os.File,
	beforeStart func() error,
	hermetic bool,
) (*ServerConnection, error) {
	logger.InfoCF("mcp", "Connecting to MCP server",
		map[string]any{
			"server":     name,
			"command":    cfg.Command,
			"args_count": len(cfg.Args),
		})

	// Create client
	client := mcp.NewClient(&mcp.Implementation{
		Name:    "openfox",
		Version: "1.0.0",
	}, nil)

	// Create transport based on configuration
	// Auto-detect transport type if not explicitly specified
	var transport mcp.Transport
	transportType := config.EffectiveMCPTransportType(cfg)
	if transportType == "" {
		return nil, fmt.Errorf("either URL or command must be provided")
	}

	switch transportType {
	case "sse", "http":
		if cfg.URL == "" {
			return nil, fmt.Errorf("URL is required for SSE/HTTP transport")
		}

		// Configure DisableStandaloneSSE based on transport type.
		// - "http": Streamable HTTP request-response mode. Disable the standalone
		//   SSE stream to avoid compatibility issues with servers that don't
		//   support the optional GET listener.
		// - "sse": Bidirectional mode. Enable the standalone SSE stream to receive
		//   server-initiated notifications (e.g., ToolListChangedNotification).
		// - Empty or auto-detected: Defaults to "sse" behavior (standalone SSE enabled).
		disableStandaloneSSE := transportType == "http"

		logger.DebugCF("mcp", "Using SSE/HTTP transport",
			map[string]any{
				"server":               name,
				"url":                  cfg.URL,
				"disableStandaloneSSE": disableStandaloneSSE,
			})

		httpClient, err := safeMCPHTTPClientFunc(cfg.URL, cfg.Headers)
		if err != nil {
			return nil, err
		}
		sseTransport := &mcp.StreamableClientTransport{
			Endpoint:             cfg.URL,
			DisableStandaloneSSE: disableStandaloneSSE,
			HTTPClient:           httpClient,
		}

		if len(cfg.Headers) > 0 {
			logger.DebugCF("mcp", "Added custom HTTP headers",
				map[string]any{
					"server":       name,
					"header_count": len(cfg.Headers),
				})
		}

		transport = sseTransport
	case "stdio":
		if cfg.Command == "" {
			return nil, fmt.Errorf("command is required for stdio transport")
		}
		cfg.Command = expandHomeCommandPath(cfg.Command)
		if !filepath.IsAbs(cfg.Command) {
			return nil, errors.New("admitted MCP stdio entrypoint must be an absolute executable path")
		}
		if !isolation.CurrentConfig().Enabled {
			return nil, errors.New("consequential MCP stdio execution requires enabled process isolation")
		}
		if sealedExecutable == nil || runtime.GOOS != "linux" {
			return nil, errors.New("consequential MCP stdio requires a sealed executable handle on Linux")
		}
		if !hermetic || beforeStart == nil {
			return nil, errors.New("consequential MCP stdio requires a current-authority guard and hermetic launch profile")
		}
		if len(cfg.Env) != 0 || cfg.EnvFile != "" {
			return nil, errors.New("consequential MCP stdio forbids ambient environment configuration")
		}
		logger.DebugCF("mcp", "Using stdio transport",
			map[string]any{
				"server":  name,
				"command": cfg.Command,
			})
		// Create command with context
		cmd := exec.CommandContext(ctx, "/proc/self/fd/3", cfg.Args...)
		cmd.ExtraFiles = []*os.File{sealedExecutable}

		cmd.Env = []string{}
		transport = &isolatedCommandTransport{Command: cmd, BeforeStart: beforeStart, Hermetic: true}
	default:
		return nil, fmt.Errorf(
			"unsupported transport type: %s (supported: stdio, sse, http, streamable-http)",
			transportType,
		)
	}

	// Connect to server
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}

	// Get server info
	initResult := session.InitializeResult()
	logger.InfoCF("mcp", "Connected to MCP server",
		map[string]any{
			"server":        name,
			"serverName":    initResult.ServerInfo.Name,
			"serverVersion": initResult.ServerInfo.Version,
			"protocol":      initResult.ProtocolVersion,
		})

	// List available tools if supported
	tools, err := listServerTools(ctx, name, session, initResult)
	if err != nil {
		_ = session.Close()
		return nil, err
	}
	descriptorBytes, err := json.Marshal(tools)
	if err != nil {
		_ = session.Close()
		return nil, fmt.Errorf("encode MCP tool descriptors: %w", err)
	}
	descriptorDigest := sha256.Sum256(descriptorBytes)

	return &ServerConnection{
		Name:   name,
		Config: cfg,
		Observation: ConnectionObservation{TransportType: transportType, ServerName: initResult.ServerInfo.Name,
			ServerVersion: initResult.ServerInfo.Version, ProtocolVersion: initResult.ProtocolVersion, ToolDescriptorDigest: descriptorDigest[:]},
		Client:  client,
		Session: session,
		Tools:   tools,
	}, nil
}

// GetServers returns all connected servers
func (m *Manager) GetServers() map[string]*ServerConnection {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]*ServerConnection, len(m.servers))
	for k, v := range m.servers {
		result[k] = v
	}
	return result
}

// GetServer returns a specific server connection
func (m *Manager) GetServer(name string) (*ServerConnection, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	conn, ok := m.servers[name]
	return conn, ok
}

// CallTool calls a tool on a specific server
func (m *Manager) CallTool(
	ctx context.Context,
	serverName, toolName string,
	arguments map[string]any,
) (*mcp.CallToolResult, error) {
	return m.callToolWithExpectedAction(ctx, nil, serverName, toolName, arguments)
}

// CallToolWithAction executes one exact request under a caller-retained stable
// Action ID. Retrying an ambiguous Action, or allocating a new Action for an
// identical still-ambiguous request, is rejected by the durable journal.
func (m *Manager) CallToolWithAction(
	ctx context.Context,
	actionID []byte,
	serverName, toolName string,
	arguments map[string]any,
) (*mcp.CallToolResult, error) {
	return m.callToolWithExpectedAction(ctx, actionID, serverName, toolName, arguments)
}

func (m *Manager) callToolWithExpectedAction(ctx context.Context, expectedActionID []byte, serverName, toolName string, arguments map[string]any) (*mcp.CallToolResult, error) {
	// Check if closed before acquiring lock (fast path)
	if m.closed.Load() {
		return nil, fmt.Errorf("manager is closed")
	}

	m.mu.RLock()
	// Double-check after acquiring lock to prevent TOCTOU race
	if m.closed.Load() {
		m.mu.RUnlock()
		return nil, fmt.Errorf("manager is closed")
	}
	conn, ok := m.servers[serverName]
	if ok {
		m.wg.Add(1) // Add to WaitGroup while holding the lock
	}
	m.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("server %s not found", serverName)
	}
	defer m.wg.Done()
	if m.effectAuthorizer == nil {
		return nil, ErrCapabilityAuthorizationRequired
	}
	if m.effectJournal == nil {
		return nil, errors.New("durable MCP Action journal is required")
	}
	argumentWire, err := freezeMCPArguments(arguments)
	if err != nil {
		return nil, errors.New("encode exact MCP arguments")
	}
	params := &mcp.CallToolParams{Name: toolName, Arguments: json.RawMessage(argumentWire)}
	requestDigest, err := mcpToolEffectRequestDigestFromWire(serverName, conn.Observation, toolName, argumentWire)
	if err != nil {
		return nil, errors.New("encode exact MCP request")
	}
	actionID, err := m.effectAuthorizer(ctx, serverName, conn.Config, conn.Observation, toolName, argumentWire, requestDigest)
	if err != nil {
		_ = conn.Session.Close()
		return nil, fmt.Errorf("authorize MCP tool effect: %w", err)
	}
	if len(actionID) != sha256.Size {
		return nil, errors.New("MCP effect authority did not return a released 32-byte Action ID")
	}
	if expectedActionID != nil && !bytes.Equal(expectedActionID, actionID) {
		return nil, errors.New("caller-retained MCP Action ID conflicts with the signed effect authorization")
	}
	resolutionToken, err := m.effectJournal.PrepareMCPAction(actionID, requestDigest)
	if err != nil {
		return nil, fmt.Errorf("prepare MCP Action %x: %w", actionID, err)
	}

	result, err := conn.Session.CallTool(ctx, params)
	if err != nil {
		_ = m.effectJournal.ResolveMCPAction(actionID, requestDigest, resolutionToken, "ambiguous")
		if shouldReconnectCallError(err) {
			logger.WarnCF("mcp", "MCP server session was lost during tool call; refusing unsafe replay",
				map[string]any{
					"server": serverName,
					"tool":   toolName,
					"error":  err.Error(),
				})

			_ = conn.Session.Close()
			return nil, fmt.Errorf("%w: %v", ErrAmbiguousToolEffect, err)
		}

		return nil, fmt.Errorf("failed to call tool: %w", err)
	}
	disposition := "succeeded"
	if result == nil || result.IsError {
		disposition = "failed"
	}
	if err := m.effectJournal.ResolveMCPAction(actionID, requestDigest, resolutionToken, disposition); err != nil {
		return nil, fmt.Errorf("%w: MCP Action %x result could not be durably resolved: %v", ErrAmbiguousToolEffect, actionID, err)
	}

	return result, nil
}

// MCPToolEffectRequestDigest is the single canonical request projection used
// by the plan compiler and immediately before the MCP pipe write.
func MCPToolEffectRequestDigest(serverName string, observation ConnectionObservation, toolName string, arguments map[string]any) ([]byte, error) {
	argumentWire, err := freezeMCPArguments(arguments)
	if err != nil {
		return nil, err
	}
	return mcpToolEffectRequestDigestFromWire(serverName, observation, toolName, argumentWire)
}

func freezeMCPArguments(arguments map[string]any) ([]byte, error) {
	if arguments == nil {
		arguments = map[string]any{}
	}
	raw, err := json.Marshal(arguments)
	if err != nil {
		return nil, err
	}
	// Decode and encode a closed plain-JSON object. This invokes any caller
	// supplied Marshaler exactly once, rejects trailing data/non-objects, and
	// detaches every nested map/slice before authorization and transport use.
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var closed map[string]any
	if decoder.Decode(&closed) != nil || decoder.Decode(&struct{}{}) != io.EOF || closed == nil {
		return nil, errors.New("MCP arguments must be one plain JSON object")
	}
	canonical, err := json.Marshal(closed)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), canonical...), nil
}

func mcpToolEffectRequestDigestFromWire(serverName string, observation ConnectionObservation, toolName string, argumentWire []byte) ([]byte, error) {
	if serverName == "" || toolName == "" {
		return nil, errors.New("MCP effect server and tool are required")
	}
	if len(argumentWire) == 0 || !json.Valid(argumentWire) {
		return nil, errors.New("MCP effect arguments are not canonical JSON")
	}
	requestWire, err := json.Marshal(struct {
		Server      string                `json:"server"`
		Observation ConnectionObservation `json:"observation"`
		Tool        string                `json:"tool"`
		Arguments   json.RawMessage       `json:"arguments"`
	}{serverName, observation, toolName, json.RawMessage(argumentWire)})
	if err != nil {
		return nil, err
	}
	requestDigest := sha256.Sum256(append([]byte("tos.openfox-mcp-tool-action.v1\x00"), requestWire...))
	return requestDigest[:], nil
}

func listServerTools(
	ctx context.Context,
	name string,
	session *mcp.ClientSession,
	initResult *mcp.InitializeResult,
) ([]*mcp.Tool, error) {
	var tools []*mcp.Tool
	if initResult.Capabilities.Tools == nil {
		return tools, nil
	}

	for tool, err := range session.Tools(ctx, nil) {
		if err != nil {
			logger.WarnCF("mcp", "Error listing tool",
				map[string]any{
					"server": name,
					"error":  err.Error(),
				})
			continue
		}
		tools = append(tools, tool)
	}

	logger.InfoCF("mcp", "Listed tools from MCP server",
		map[string]any{
			"server":    name,
			"toolCount": len(tools),
		})

	return tools, nil
}

func shouldReconnectCallError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, mcp.ErrSessionMissing) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), mcp.ErrSessionMissing.Error())
}

func (m *Manager) reconnectServer(
	ctx context.Context,
	serverName string,
	staleConn *ServerConnection,
) (*ServerConnection, error) {
	if staleConn == nil {
		return nil, fmt.Errorf("server %s not found", serverName)
	}

	staleConn.reconnectMu.Lock()
	defer staleConn.reconnectMu.Unlock()

	if m.closed.Load() {
		return nil, fmt.Errorf("manager is closed")
	}

	m.mu.RLock()
	currentConn, ok := m.servers[serverName]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("server %s not found", serverName)
	}
	if currentConn != staleConn {
		return currentConn, nil
	}

	if m.authorizer == nil || m.verifier == nil {
		return nil, ErrCapabilityAuthorizationRequired
	}
	authorization, err := m.authorizer(ctx, serverName, staleConn.Config)
	if err != nil {
		return nil, fmt.Errorf("authorize MCP reconnect: %w", err)
	}
	if authorization.Executable != nil {
		defer authorization.Executable.Close()
	}
	freshConn, err := connectServerFunc(ctx, serverName, staleConn.Config, authorization.Executable, authorization.BeforeStart, authorization.Hermetic)
	if err != nil {
		return nil, err
	}
	if err := m.verifier(ctx, serverName, staleConn.Config, freshConn.Observation); err != nil {
		_ = freshConn.Session.Close()
		return nil, fmt.Errorf("verify MCP reconnect: %w", err)
	}

	m.mu.Lock()
	if m.closed.Load() {
		m.mu.Unlock()
		_ = freshConn.Session.Close()
		return nil, fmt.Errorf("manager is closed")
	}

	currentConn, ok = m.servers[serverName]
	if !ok {
		m.mu.Unlock()
		_ = freshConn.Session.Close()
		return nil, fmt.Errorf("server %s not found", serverName)
	}

	if currentConn == staleConn {
		m.servers[serverName] = freshConn
		staleToClose := staleConn
		m.mu.Unlock()
		_ = staleToClose.Session.Close()
		return freshConn, nil
	}

	m.mu.Unlock()
	_ = freshConn.Session.Close()
	return currentConn, nil
}

// Close closes all server connections
func (m *Manager) Close() error {
	// Use Swap to atomically set closed=true and get the previous value
	// This prevents TOCTOU race with CallTool's closed check
	if m.closed.Swap(true) {
		return nil // already closed
	}

	// Wait for all in-flight CallTool calls to finish before closing sessions
	// After closed=true is set, no new CallTool can start (they check closed first)
	m.wg.Wait()

	m.mu.Lock()
	defer m.mu.Unlock()

	logger.InfoCF("mcp", "Closing all MCP server connections",
		map[string]any{
			"count": len(m.servers),
		})

	var errs []error
	for name, conn := range m.servers {
		if err := conn.Session.Close(); err != nil {
			logger.ErrorCF("mcp", "Failed to close server connection",
				map[string]any{
					"server": name,
					"error":  err.Error(),
				})
			errs = append(errs, fmt.Errorf("server %s: %w", name, err))
		}
	}
	for _, hook := range m.closeHooks {
		if err := hook(); err != nil {
			errs = append(errs, err)
		}
	}
	m.closeHooks = nil

	m.servers = make(map[string]*ServerConnection)

	if len(errs) > 0 {
		return fmt.Errorf("failed to close %d server(s): %w", len(errs), errors.Join(errs...))
	}

	return nil
}

// GetAllTools returns all tools from all connected servers
func (m *Manager) GetAllTools() map[string][]*mcp.Tool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string][]*mcp.Tool)
	for name, conn := range m.servers {
		if len(conn.Tools) > 0 {
			result[name] = conn.Tools
		}
	}
	return result
}
