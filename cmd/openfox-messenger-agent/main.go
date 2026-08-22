// Command openfox-messenger-agent is a production-channel acceptance runner.
// It runs a real OpenFox AgentLoop over one tos-messengerd runtime socket and
// exposes only an owner-private local control socket for deterministic sends
// and evidence inspection. It is suitable for two independently operated
// hosts; it contains no peer route, session, endpoint, device, or key input.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
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
	"github.com/tosnetwork/openfox/pkg/channels/tosmessenger"
	"github.com/tosnetwork/openfox/pkg/config"
	"github.com/tosnetwork/openfox/pkg/fileutil"
	"github.com/tosnetwork/openfox/pkg/providers"
)

const (
	stateSchema   = "tos.openfox.production-messenger-agent-state.v1"
	controlSchema = "tos.openfox.production-messenger-agent-control.v1"
	maxBody       = 1 << 20
)

type transcriptLine struct {
	Direction      string `json:"direction"`
	PeerAgentID    string `json:"peer_agent_id,omitempty"`
	RecipientInput string `json:"recipient_input,omitempty"`
	EventID        string `json:"event_id"`
	ReplyToEventID string `json:"reply_to_event_id,omitempty"`
	Content        string `json:"content"`
	RunID          string `json:"run_id"`
	AppliedUnix    int64  `json:"applied_unix"`
}

type durableState struct {
	Schema     string           `json:"schema"`
	Transcript []transcriptLine `json:"transcript"`
}

type service struct {
	agentID, runID, statePath, triggerPrefix string
	channel                                  messengerSender
	mu                                       sync.Mutex
	state                                    durableState
	pending                                  map[string]chan error
}

type messengerSender interface {
	Send(context.Context, bus.OutboundMessage) ([]string, error)
}

func main() {
	agentID := flag.String("agent-id", "", "local canonical AgentID")
	daemonSocket := flag.String("daemon-socket", "", "owner-private tos-messengerd runtime socket")
	workspace := flag.String("workspace", "", "owner-private OpenFox Agent workspace")
	state := flag.String("state", "", "owner-private durable transcript")
	control := flag.String("control-socket", "", "owner-private local control socket")
	trigger := flag.String("trigger-prefix", "", "reply only to messages with this prefix; empty replies to all")
	reply := flag.String("reply-prefix", "ack:", "deterministic acceptance-provider reply prefix")
	flag.Parse()
	if err := run(*agentID, *daemonSocket, *workspace, *state, *control, *trigger, *reply); err != nil {
		fmt.Fprintln(os.Stderr, "openfox-messenger-agent:", err)
		os.Exit(1)
	}
}

func run(agentID, daemonSocket, workspace, statePath, controlPath, triggerPrefix, replyPrefix string) error {
	if !canonicalAgent(agentID) || replyPrefix == "" || len(replyPrefix) > 128 {
		return errors.New("canonical agent-id and bounded reply-prefix are required")
	}
	for _, path := range []string{daemonSocket, workspace, statePath, controlPath} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return errors.New("all runtime paths must be clean and absolute")
		}
	}
	if err := privateDirectory(workspace); err != nil {
		return err
	}
	if err := privateDirectory(filepath.Dir(statePath)); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := waitForSocket(ctx, daemonSocket, 30*time.Second); err != nil {
		return err
	}
	channelBus := bus.NewMessageBus()
	channel, err := tosmessenger.New(&config.Channel{AllowFrom: []string{"*"}}, &config.TOSMessengerSettings{
		SocketPath: daemonSocket, PollIntervalMS: 100, LeaseSeconds: 30, ProactiveLifetimeSeconds: 3600,
	}, channelBus)
	if err != nil {
		return err
	}
	if err := channel.Start(ctx); err != nil {
		return err
	}
	defer channel.Stop(context.Background())
	agentBus := bus.NewMessageBus()
	loop, err := newAgentLoop(agentID, workspace, replyPrefix, agentBus)
	if err != nil {
		return err
	}
	defer loop.Close()
	service := &service{agentID: agentID, statePath: statePath, triggerPrefix: triggerPrefix, channel: channel,
		state: durableState{Schema: stateSchema}, pending: map[string]chan error{}}
	service.runID, err = randomRunID()
	if err != nil {
		return err
	}
	if err := service.load(); err != nil {
		return err
	}
	listener, err := listenControl(controlPath)
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close(); _ = os.Remove(controlPath) }()
	server := &http.Server{Handler: service.routes(), ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10}
	errorsCh := make(chan error, 4)
	go func() { errorsCh <- loop.Run(ctx) }()
	go func() { errorsCh <- service.consume(ctx, channelBus.InboundChan(), agentBus) }()
	go func() { errorsCh <- service.sendReplies(ctx, agentBus.OutboundChan()) }()
	go func() {
		err := server.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errorsCh <- err
	}()
	fmt.Printf("READY agent_id=%s run_id=%s daemon_socket=%s control_socket=%s\n", agentID, service.runID, daemonSocket, controlPath)
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	case err := <-errorsCh:
		return err
	}
}

type deterministicProvider struct{ agentID, prefix string }

func (p deterministicProvider) Chat(_ context.Context, messages []providers.Message, _ []providers.ToolDefinition,
	_ string, _ map[string]any) (*providers.LLMResponse, error) {
	for index := len(messages) - 1; index >= 0; index-- {
		if messages[index].Role == "user" {
			digest := sha256.Sum256([]byte(messages[index].Content))
			return &providers.LLMResponse{Content: p.prefix + p.agentID + ":" + hex.EncodeToString(digest[:8])}, nil
		}
	}
	return nil, errors.New("acceptance provider received no user message")
}

func (deterministicProvider) GetDefaultModel() string { return "messenger-production-acceptance" }

func newAgentLoop(agentID, workspace, prefix string, messageBus *bus.MessageBus) (*agent.AgentLoop, error) {
	cfg := config.DefaultConfig()
	cfg.Agents.Defaults.Workspace = workspace
	cfg.Agents.Defaults.ModelName = "messenger-production-acceptance"
	cfg.Agents.Defaults.MaxToolIterations = 1
	cfg.Agents.List = []config.AgentConfig{{ID: agentID, Name: agentID, Default: true, Workspace: workspace}}
	cfg.ModelList = nil
	cfg.Hooks.Enabled = false
	return agent.NewAgentLoop(cfg, messageBus, deterministicProvider{agentID: agentID, prefix: prefix}), nil
}

func (s *service) consume(ctx context.Context, inbound <-chan bus.InboundMessage, target *bus.MessageBus) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case message, ok := <-inbound:
			if !ok {
				return errors.New("production Messenger inbound channel closed")
			}
			if err := s.record(transcriptLine{Direction: "inbound", PeerAgentID: message.Sender.PlatformID,
				EventID: message.MessageID, ReplyToEventID: message.Context.ReplyToMessageID, Content: message.Content}); err != nil {
				report(message.ApplicationResult, err)
				return err
			}
			// A daemon may redeliver an application lease after this process
			// restarts. Once the durable transcript contains the reply, acknowledge
			// the original event without invoking AgentLoop or sending it again.
			if s.replyApplied(message.MessageID) {
				report(message.ApplicationResult, nil)
				continue
			}
			if s.triggerPrefix != "" && !strings.HasPrefix(message.Content, s.triggerPrefix) {
				report(message.ApplicationResult, nil)
				continue
			}
			s.mu.Lock()
			if _, duplicate := s.pending[message.MessageID]; duplicate {
				s.mu.Unlock()
				err := errors.New("event already awaits AgentLoop application")
				report(message.ApplicationResult, err)
				return err
			}
			s.pending[message.MessageID] = message.ApplicationResult
			s.mu.Unlock()
			message.ApplicationResult = nil
			if err := target.PublishInbound(ctx, message); err != nil {
				s.complete(ctx, message.MessageID, err)
				return err
			}
		}
	}
}

func (s *service) sendReplies(ctx context.Context, outbound <-chan bus.OutboundMessage) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case message, ok := <-outbound:
			if !ok {
				return errors.New("AgentLoop outbound channel closed")
			}
			if message.Channel != config.ChannelTOSMessenger || message.ReplyToMessageID == "" ||
				message.Context.AuthenticatedMessagingOrigin == nil {
				return errors.New("AgentLoop produced a reply without authenticated Messenger origin")
			}
			ids, err := s.channel.Send(ctx, message)
			if err != nil || len(ids) != 1 || !canonicalEventID(first(ids)) {
				s.complete(ctx, message.ReplyToMessageID, errors.Join(err, errors.New("invalid reply Event result")))
				return errors.Join(err, errors.New("send authenticated AgentLoop reply"))
			}
			if err := s.record(transcriptLine{Direction: "outbound", EventID: ids[0],
				ReplyToEventID: message.ReplyToMessageID, Content: message.Content}); err != nil {
				s.complete(ctx, message.ReplyToMessageID, err)
				return err
			}
			s.complete(ctx, message.ReplyToMessageID, nil)
		}
	}
}

func (s *service) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, http.StatusOK, map[string]any{"schema": controlSchema, "ok": true, "agent_id": s.agentID, "run_id": s.runID})
	})
	mux.HandleFunc("GET /v1/transcript", func(writer http.ResponseWriter, _ *http.Request) {
		s.mu.Lock()
		lines := append([]transcriptLine(nil), s.state.Transcript...)
		s.mu.Unlock()
		writeJSON(writer, http.StatusOK, map[string]any{"schema": controlSchema, "agent_id": s.agentID, "run_id": s.runID, "transcript": lines})
	})
	mux.HandleFunc("POST /v1/send", func(writer http.ResponseWriter, request *http.Request) {
		var value struct {
			RequestID string `json:"request_id"`
			Recipient string `json:"recipient"`
			Content   string `json:"content"`
		}
		if decodeRequest(request.Body, &value) != nil || value.RequestID == "" || len(value.RequestID) > 256 ||
			value.Recipient == "" || len(value.Recipient) > 256 || strings.TrimSpace(value.Content) == "" || len(value.Content) > maxBody {
			http.Error(writer, "invalid send request", http.StatusBadRequest)
			return
		}
		digest := sha256.Sum256([]byte("tos.openfox.production-delivery-intent.v1\x00" + value.RequestID))
		ids, err := s.channel.Send(request.Context(), bus.OutboundMessage{Channel: config.ChannelTOSMessenger,
			Recipient: value.Recipient, Content: value.Content, DeliveryIntentID: "intent_" + hex.EncodeToString(digest[:])})
		if err != nil || len(ids) != 1 || !canonicalEventID(first(ids)) {
			http.Error(writer, "send failed", http.StatusBadGateway)
			return
		}
		if err := s.record(transcriptLine{Direction: "outbound", RecipientInput: value.Recipient,
			EventID: ids[0], Content: value.Content}); err != nil {
			http.Error(writer, "persist send failed", http.StatusInternalServerError)
			return
		}
		writeJSON(writer, http.StatusOK, map[string]any{"schema": controlSchema, "event_id": ids[0]})
	})
	return mux
}

func (s *service) record(line transcriptLine) error {
	if !canonicalEventID(line.EventID) || line.Content == "" ||
		(line.ReplyToEventID != "" && !canonicalEventID(line.ReplyToEventID)) || !canonicalRunID(s.runID) ||
		(line.Direction != "inbound" && line.Direction != "outbound") ||
		(line.Direction == "inbound" && (!canonicalAgent(line.PeerAgentID) || line.RecipientInput != "")) ||
		(line.Direction == "outbound" && (line.PeerAgentID != "" ||
			(line.ReplyToEventID == "") != (line.RecipientInput != ""))) {
		return errors.New("invalid transcript line")
	}
	line.AppliedUnix = time.Now().UTC().Unix()
	line.RunID = s.runID
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.state.Transcript {
		if existing.EventID == line.EventID {
			if existing.Direction == line.Direction && existing.Content == line.Content &&
				existing.ReplyToEventID == line.ReplyToEventID && existing.PeerAgentID == line.PeerAgentID &&
				existing.RecipientInput == line.RecipientInput {
				return nil
			}
			return errors.New("Event ID conflicts with durable transcript")
		}
	}
	s.state.Transcript = append(s.state.Transcript, line)
	raw, err := json.Marshal(s.state)
	if err != nil || len(raw) > 16<<20 {
		return errors.New("encode bounded transcript")
	}
	return fileutil.WriteFileAtomic(s.statePath, raw, 0o600)
}

func randomRunID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", errors.New("generate process run identity")
	}
	return "run_" + hex.EncodeToString(raw[:]), nil
}

func (s *service) replyApplied(eventID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, line := range s.state.Transcript {
		if line.Direction == "outbound" && line.ReplyToEventID == eventID {
			return true
		}
	}
	return false
}

func (s *service) load() error {
	info, err := os.Lstat(s.statePath)
	if errors.Is(err, os.ErrNotExist) {
		return s.recordBootstrap()
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > 16<<20 {
		return errors.New("transcript must be a bounded owner-only regular file")
	}
	raw, err := os.ReadFile(s.statePath)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&s.state) != nil || s.state.Schema != stateSchema {
		return errors.New("invalid durable transcript")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing transcript data")
	}
	seen := make(map[string]struct{}, len(s.state.Transcript))
	for _, line := range s.state.Transcript {
		if !validStoredLine(line) {
			return errors.New("invalid durable transcript line")
		}
		if _, duplicate := seen[line.EventID]; duplicate {
			return errors.New("duplicate durable transcript Event ID")
		}
		seen[line.EventID] = struct{}{}
	}
	return nil
}

func validStoredLine(line transcriptLine) bool {
	return canonicalEventID(line.EventID) && line.Content != "" && canonicalRunID(line.RunID) && line.AppliedUnix > 0 &&
		(line.ReplyToEventID == "" || canonicalEventID(line.ReplyToEventID)) &&
		(line.Direction == "inbound" || line.Direction == "outbound") &&
		(line.Direction != "inbound" || (canonicalAgent(line.PeerAgentID) && line.RecipientInput == "")) &&
		(line.Direction != "outbound" || (line.PeerAgentID == "" &&
			(line.ReplyToEventID == "") == (line.RecipientInput != "")))
}

func (s *service) recordBootstrap() error {
	raw, _ := json.Marshal(s.state)
	return fileutil.WriteFileAtomic(s.statePath, raw, 0o600)
}

func (s *service) complete(ctx context.Context, eventID string, err error) {
	s.mu.Lock()
	result := s.pending[eventID]
	delete(s.pending, eventID)
	s.mu.Unlock()
	reportContext(ctx, result, err)
}

func report(result chan error, err error) { reportContext(context.Background(), result, err) }
func reportContext(ctx context.Context, result chan error, err error) {
	if result == nil {
		return
	}
	select {
	case result <- err:
	case <-ctx.Done():
	}
}

func decodeRequest(body io.Reader, target any) error {
	decoder := json.NewDecoder(io.LimitReader(body, maxBody+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing request data")
	}
	return nil
}

func listenControl(path string) (net.Listener, error) {
	if err := privateDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("control path is occupied")
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

func privateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errors.New("runtime directory must already exist with mode 0700")
	}
	return nil
}

func waitForSocket(ctx context.Context, path string, timeout time.Duration) error {
	deadline, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		connection, err := (&net.Dialer{Timeout: time.Second}).DialContext(deadline, "unix", path)
		if err == nil {
			return connection.Close()
		}
		select {
		case <-deadline.Done():
			return errors.New("tos-messengerd runtime socket did not become ready")
		case <-ticker.C:
		}
	}
}

func canonicalAgent(value string) bool {
	if len(value) != len("agent_")+64 || !strings.HasPrefix(value, "agent_") || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "agent_"))
	return err == nil
}

func canonicalEventID(value string) bool {
	if len(value) != len("evt_")+64 || !strings.HasPrefix(value, "evt_") || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "evt_"))
	return err == nil
}

func canonicalRunID(value string) bool {
	if len(value) != len("run_")+32 || !strings.HasPrefix(value, "run_") || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "run_"))
	return err == nil
}

func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	raw, _ := json.Marshal(value)
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = writer.Write(raw)
}
