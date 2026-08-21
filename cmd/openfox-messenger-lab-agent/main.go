// Command openfox-messenger-lab-agent runs one long-lived OpenFox Messenger
// channel process for multi-process encrypted group-chat acceptance. Its
// optional AgentLoop mode uses a local deterministic provider so the real Agent
// runtime can be exercised without external model credentials. It makes no
// production transport claim.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/tosnetwork/openfox/pkg/agent"
	"github.com/tosnetwork/openfox/pkg/bus"
	"github.com/tosnetwork/openfox/pkg/channels/tosmessengerlab"
	"github.com/tosnetwork/openfox/pkg/config"
	"github.com/tosnetwork/openfox/pkg/fileutil"
	"github.com/tosnetwork/openfox/pkg/providers"
)

const (
	controlSchema      = "openfox.messenger-lab-agent-control.v1"
	stateSchema        = "openfox.messenger-lab-agent-state.v1"
	maxBodyBytes       = 128 << 10
	replyModeStatic    = "static"
	replyModeAgentLoop = "agent-loop"
	agentLoopRuntime   = "openfox-agent-loop"
)

type stringFlags []string

func (f *stringFlags) String() string         { return strings.Join(*f, ",") }
func (f *stringFlags) Set(value string) error { *f = append(*f, value); return nil }

type channelAPI interface {
	Start(context.Context) error
	Stop(context.Context) error
	SendWithClientID(context.Context, bus.OutboundMessage, string) ([]string, error)
	RoomID(string, []string) (string, bool)
}

type transcriptLine struct {
	Direction      string `json:"direction"`
	AgentID        string `json:"agent_id"`
	EventID        string `json:"event_id"`
	ReplyToEventID string `json:"reply_to_event_id,omitempty"`
	Runtime        string `json:"runtime,omitempty"`
	Content        string `json:"content"`
}

type durableState struct {
	Schema     string           `json:"schema"`
	Transcript []transcriptLine `json:"transcript"`
}

type agentService struct {
	agentID, roomID, triggerPrefix, replyPrefix, replyMode, statePath string
	channel                                                           channelAPI
	mu                                                                sync.Mutex
	state                                                             durableState
	applications                                                      map[string]chan error
}

func main() {
	var members stringFlags
	agentID := flag.String("agent-id", "", "local Agent ID")
	token := flag.String("token", "", "lab bearer token")
	socket := flag.String("socket", "", "this Agent's Messenger/OpenMLS Unix socket")
	cursor := flag.String("cursor", "", "durable channel cursor path")
	state := flag.String("state", "", "durable transcript path")
	control := flag.String("control-socket", "", "private local control Unix socket")
	label := flag.String("room-label", "", "deterministic room label")
	creator := flag.Bool("create-room", false, "create the exact room before serving")
	encryption := flag.String("encryption", "openmls-proxy", "empty or openmls-proxy")
	replyPrefix := flag.String("reply-prefix", "", "reply once to non-reply inbound messages")
	replyMode := flag.String("reply-mode", replyModeStatic, "static or agent-loop")
	agentWorkspace := flag.String("agent-workspace", "", "private durable OpenFox Agent workspace (agent-loop mode)")
	triggerPrefix := flag.String("trigger-prefix", "", "reply only to inbound messages with this prefix")
	flag.Var(&members, "member", "room member Agent ID (repeat)")
	flag.Parse()
	if err := run(*agentID, *token, *socket, *cursor, *state, *control, *label,
		*encryption, *triggerPrefix, *replyPrefix, *replyMode, *agentWorkspace, members, *creator); err != nil {
		fmt.Fprintln(os.Stderr, "openfox-messenger-lab-agent:", err)
		os.Exit(1)
	}
}

func run(agentID, token, socket, cursor, statePath, controlPath, label, encryption,
	triggerPrefix, replyPrefix, replyMode, agentWorkspace string, members []string, creator bool,
) error {
	for _, path := range []string{socket, cursor, statePath, controlPath} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return errors.New("socket, cursor, state, and control-socket must be clean absolute paths")
		}
	}
	if agentID == "" || len(token) < 16 || strings.TrimSpace(label) == "" || len(members) < 2 {
		return errors.New("agent-id, token, room-label, and at least two members are required")
	}
	if replyMode != replyModeStatic && replyMode != replyModeAgentLoop {
		return errors.New("reply-mode must be static or agent-loop")
	}
	if replyMode == replyModeAgentLoop &&
		(!filepath.IsAbs(agentWorkspace) || filepath.Clean(agentWorkspace) != agentWorkspace) {
		return errors.New("agent-workspace must be a clean absolute path in agent-loop mode")
	}
	if replyMode == replyModeAgentLoop && replyPrefix == "" {
		return errors.New("reply-prefix is required in agent-loop mode")
	}
	settings := &config.TOSMessengerLabSettings{
		SocketPath: socket, AgentID: agentID,
		Token: *config.NewSecureString(token), CursorPath: cursor, PollIntervalMS: 50, Encryption: encryption,
	}
	if creator {
		settings.Rooms = []config.TOSMessengerLabRoom{{Label: label, Members: members}}
	}
	messageBus := bus.NewMessageBus()
	channel, err := tosmessengerlab.New(&config.Channel{AllowFrom: []string{"*"}}, settings, messageBus)
	if err != nil {
		return err
	}
	if err := channel.EnableDurableApplication(30 * time.Second); err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if err := channel.Start(ctx); err != nil {
		return err
	}
	defer channel.Stop(context.Background())
	roomID, ok := channel.RoomID(label, members)
	if !ok {
		return errors.New("configured room is not visible to this Agent")
	}
	service := &agentService{
		agentID: agentID, roomID: roomID, triggerPrefix: triggerPrefix, replyPrefix: replyPrefix,
		replyMode: replyMode, statePath: statePath, channel: channel, state: durableState{Schema: stateSchema},
		applications: make(map[string]chan error),
	}
	if err := service.load(); err != nil {
		return err
	}
	listener, err := listenControl(controlPath)
	if err != nil {
		return err
	}
	defer func() { listener.Close(); _ = os.Remove(controlPath) }()
	server := &http.Server{Handler: service.routes(), ReadHeaderTimeout: 2 * time.Second}
	serveErr := make(chan error, 1)
	go func() {
		err := server.Serve(listener)
		if !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
		close(serveErr)
	}()
	pipelineErr := make(chan error, 3)
	if replyMode == replyModeAgentLoop {
		agentBus := bus.NewMessageBus()
		loop, err := newLabAgentLoop(agentID, agentWorkspace, replyPrefix, agentBus)
		if err != nil {
			return err
		}
		defer loop.Close()
		go func() { pipelineErr <- loop.Run(ctx) }()
		go func() { pipelineErr <- service.consumeAgentLoop(ctx, messageBus.InboundChan(), agentBus) }()
		go func() { pipelineErr <- service.sendAgentLoop(ctx, agentBus.OutboundChan()) }()
	} else {
		go func() { pipelineErr <- service.consume(ctx, messageBus.InboundChan()) }()
	}
	select {
	case <-ctx.Done():
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer shutdownCancel()
		return server.Shutdown(shutdownCtx)
	case err := <-serveErr:
		return err
	case err := <-pipelineErr:
		return err
	}
}

type labReplyProvider struct {
	agentID, replyPrefix string
}

func (p *labReplyProvider) Chat(_ context.Context, messages []providers.Message, _ []providers.ToolDefinition,
	_ string, _ map[string]any,
) (*providers.LLMResponse, error) {
	var content string
	for index := len(messages) - 1; index >= 0; index-- {
		if messages[index].Role == "user" {
			content = messages[index].Content
			break
		}
	}
	if content == "" {
		return nil, errors.New("agent-loop lab provider received no user message")
	}
	digest := sha256.Sum256([]byte(content))
	return &providers.LLMResponse{
		Content: p.replyPrefix + p.agentID + "-agentloop-" + hex.EncodeToString(digest[:8]),
	}, nil
}

func (*labReplyProvider) GetDefaultModel() string { return "messenger-lab-deterministic" }

func newLabAgentLoop(agentID, workspace, replyPrefix string, messageBus *bus.MessageBus) (*agent.AgentLoop, error) {
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		return nil, fmt.Errorf("create Agent workspace: %w", err)
	}
	if err := os.Chmod(workspace, 0o700); err != nil {
		return nil, fmt.Errorf("protect Agent workspace: %w", err)
	}
	cfg := config.DefaultConfig()
	cfg.Agents.Defaults.Workspace = workspace
	cfg.Agents.Defaults.ModelName = "messenger-lab-deterministic"
	cfg.Agents.Defaults.MaxToolIterations = 1
	cfg.Agents.List = []config.AgentConfig{{ID: agentID, Name: agentID, Default: true, Workspace: workspace}}
	cfg.ModelList = nil
	cfg.Hooks.Enabled = false
	return agent.NewAgentLoop(cfg, messageBus, &labReplyProvider{agentID: agentID, replyPrefix: replyPrefix}), nil
}

func listenControl(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("control path exists and is not a socket")
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		listener.Close()
		return nil, err
	}
	return listener, nil
}

func (s *agentService) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"schema": controlSchema, "ok": true,
			"agent_id": s.agentID, "room_id": s.roomID, "reply_mode": s.replyMode,
		})
	})
	mux.HandleFunc("GET /v1/transcript", func(w http.ResponseWriter, _ *http.Request) {
		s.mu.Lock()
		lines := append([]transcriptLine(nil), s.state.Transcript...)
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"schema": controlSchema, "transcript": lines})
	})
	mux.HandleFunc("POST /v1/send", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			RequestID string `json:"request_id"`
			Content   string `json:"content"`
		}
		if err := decodeRequest(r.Body, &request); err != nil || strings.TrimSpace(request.Content) == "" ||
			len(request.Content) > maxBodyBytes || request.RequestID == "" {
			http.Error(w, "invalid send request", http.StatusBadRequest)
			return
		}
		ids, err := s.channel.SendWithClientID(r.Context(),
			bus.OutboundMessage{ChatID: s.roomID, Content: request.Content}, request.RequestID)
		if err != nil || len(ids) != 1 {
			http.Error(w, "send failed", http.StatusBadGateway)
			return
		}
		if err := s.record(transcriptLine{
			Direction: "outbound", AgentID: s.agentID,
			EventID: ids[0], Content: request.Content,
		}); err != nil {
			http.Error(w, "persist send failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"schema": controlSchema, "event_id": ids[0]})
	})
	return mux
}

func (s *agentService) consume(ctx context.Context, inbound <-chan bus.InboundMessage) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case message, ok := <-inbound:
			if !ok {
				return errors.New("Messenger lab inbound channel closed")
			}
			if err := s.record(transcriptLine{
				Direction: "inbound", AgentID: message.Sender.PlatformID,
				EventID: message.MessageID, ReplyToEventID: message.Context.ReplyToMessageID,
				Content: message.Content,
			}); err != nil {
				completeApplication(ctx, message, err)
				return fmt.Errorf("persist inbound Messenger event: %w", err)
			}
			completeApplication(ctx, message, nil)
			if s.replyPrefix == "" || s.triggerPrefix != "" && !strings.HasPrefix(message.Content, s.triggerPrefix) ||
				strings.HasPrefix(message.Content, s.replyPrefix) {
				continue
			}
			content := s.replyPrefix + s.agentID + "-for-" + message.MessageID
			digest := sha256.Sum256([]byte(s.agentID + "\x00" + message.MessageID + "\x00" + content))
			clientID := "reply-" + hex.EncodeToString(digest[:])
			ids, err := s.channel.SendWithClientID(ctx, bus.OutboundMessage{
				ChatID: s.roomID, Content: content,
				ReplyToMessageID: message.MessageID,
			}, clientID)
			if err != nil {
				return fmt.Errorf("send automatic Messenger reply: %w", err)
			}
			if len(ids) != 1 {
				return errors.New("automatic Messenger reply returned an invalid Event ID count")
			}
			if err := s.record(transcriptLine{
				Direction: "outbound", AgentID: s.agentID,
				EventID: ids[0], ReplyToEventID: message.MessageID, Content: content,
			}); err != nil {
				return fmt.Errorf("persist automatic Messenger reply: %w", err)
			}
		}
	}
}

func (s *agentService) consumeAgentLoop(
	ctx context.Context,
	inbound <-chan bus.InboundMessage,
	agentBus *bus.MessageBus,
) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case message, ok := <-inbound:
			if !ok {
				return errors.New("Messenger lab inbound channel closed")
			}
			if err := s.record(transcriptLine{
				Direction: "inbound", AgentID: message.Sender.PlatformID,
				EventID: message.MessageID, ReplyToEventID: message.Context.ReplyToMessageID,
				Content: message.Content,
			}); err != nil {
				completeApplication(ctx, message, err)
				return fmt.Errorf("persist inbound Messenger event: %w", err)
			}
			if s.replyPrefix == "" || s.triggerPrefix != "" && !strings.HasPrefix(message.Content, s.triggerPrefix) ||
				strings.HasPrefix(message.Content, s.replyPrefix) {
				completeApplication(ctx, message, nil)
				continue
			}
			if s.agentLoopReplyApplied(message.MessageID) {
				completeApplication(ctx, message, nil)
				continue
			}
			if err := s.registerApplication(message); err != nil {
				completeApplication(ctx, message, err)
				return err
			}
			message.ApplicationResult = nil
			if err := agentBus.PublishInbound(ctx, message); err != nil {
				s.completeRegisteredApplication(ctx, message.MessageID, err)
				return fmt.Errorf("publish Messenger event to AgentLoop: %w", err)
			}
		}
	}
}

func completeApplication(ctx context.Context, message bus.InboundMessage, err error) {
	if message.ApplicationResult == nil {
		return
	}
	select {
	case message.ApplicationResult <- err:
	case <-ctx.Done():
	}
}

func (s *agentService) sendAgentLoop(ctx context.Context, outbound <-chan bus.OutboundMessage) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case message, ok := <-outbound:
			if !ok {
				return errors.New("AgentLoop outbound channel closed")
			}
			if message.Channel != config.ChannelTOSMessengerLab || message.ChatID != s.roomID ||
				message.ReplyToMessageID == "" || !strings.HasPrefix(message.Content, s.replyPrefix) {
				return errors.New("AgentLoop produced an invalid Messenger lab reply")
			}
			digest := sha256.Sum256([]byte(s.agentID + "\x00" + message.ReplyToMessageID + "\x00" + message.Content))
			clientID := "agentloop-reply-" + hex.EncodeToString(digest[:])
			ids, err := s.channel.SendWithClientID(ctx, message, clientID)
			if err != nil {
				s.completeRegisteredApplication(ctx, message.ReplyToMessageID, err)
				return fmt.Errorf("send AgentLoop Messenger reply: %w", err)
			}
			if len(ids) != 1 {
				err := errors.New("AgentLoop Messenger reply returned an invalid Event ID count")
				s.completeRegisteredApplication(ctx, message.ReplyToMessageID, err)
				return err
			}
			if err := s.record(transcriptLine{
				Direction: "outbound", AgentID: s.agentID, EventID: ids[0],
				ReplyToEventID: message.ReplyToMessageID, Runtime: agentLoopRuntime, Content: message.Content,
			}); err != nil {
				s.completeRegisteredApplication(ctx, message.ReplyToMessageID, err)
				return fmt.Errorf("persist AgentLoop Messenger reply: %w", err)
			}
			s.completeRegisteredApplication(ctx, message.ReplyToMessageID, nil)
		}
	}
}

func (s *agentService) agentLoopReplyApplied(messageID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, line := range s.state.Transcript {
		if line.Direction == "outbound" && line.Runtime == agentLoopRuntime &&
			line.ReplyToEventID == messageID {
			return true
		}
	}
	return false
}

func (s *agentService) registerApplication(message bus.InboundMessage) error {
	if message.ApplicationResult == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.applications == nil {
		s.applications = make(map[string]chan error)
	}
	if _, exists := s.applications[message.MessageID]; exists {
		return errors.New("Messenger lab Event already awaits AgentLoop application")
	}
	s.applications[message.MessageID] = message.ApplicationResult
	return nil
}

func (s *agentService) completeRegisteredApplication(ctx context.Context, messageID string, err error) {
	s.mu.Lock()
	result := s.applications[messageID]
	delete(s.applications, messageID)
	s.mu.Unlock()
	if result == nil {
		return
	}
	select {
	case result <- err:
	case <-ctx.Done():
	}
}

func (s *agentService) load() error {
	if err := os.MkdirAll(filepath.Dir(s.statePath), 0o700); err != nil {
		return err
	}
	raw, err := os.ReadFile(s.statePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&s.state); err != nil || s.state.Schema != stateSchema {
		return errors.New("invalid lab Agent state")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) || len(s.state.Transcript) > 4096 {
		return errors.New("invalid lab Agent state")
	}
	return nil
}

func (s *agentService) record(line transcriptLine) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.state.Transcript {
		if existing.EventID == line.EventID && existing.Direction == line.Direction {
			if existing != line {
				return errors.New("transcript Event ID substitution")
			}
			return nil
		}
	}
	if len(s.state.Transcript) >= 4096 {
		s.state.Transcript = append([]transcriptLine(nil), s.state.Transcript[len(s.state.Transcript)-2048:]...)
	}
	s.state.Transcript = append(s.state.Transcript, line)
	raw, err := json.Marshal(s.state)
	if err != nil {
		return err
	}
	return fileutil.WriteFileAtomic(s.statePath, raw, 0o600)
}

func decodeRequest(body io.Reader, target any) error {
	raw, err := io.ReadAll(io.LimitReader(body, maxBodyBytes+1))
	if err != nil || len(raw) > maxBodyBytes {
		return errors.New("request exceeds its bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
