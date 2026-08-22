package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tosnetwork/openfox/pkg/bus"
	"github.com/tosnetwork/openfox/pkg/channels/tosmessengerlab"
)

type fakeChannel struct {
	mu          sync.Mutex
	sent        []bus.OutboundMessage
	removed     bool
	roomVisible bool
	membership  tosmessengerlab.MembershipStatus
}

func (*fakeChannel) Start(context.Context) error { return nil }
func (*fakeChannel) Stop(context.Context) error  { return nil }
func (f *fakeChannel) RoomID(string, []string) (string, bool) {
	return "room_test", f.roomVisible
}

func (f *fakeChannel) RoomIDs() []string {
	if f.removed {
		return nil
	}
	return []string{"room-a"}
}

func (f *fakeChannel) MembershipStatus(context.Context) (tosmessengerlab.MembershipStatus, error) {
	return f.membership, nil
}

func (f *fakeChannel) Send(_ context.Context, message bus.OutboundMessage) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, message)
	return []string{"message-" + string(rune('0'+len(f.sent)))}, nil
}

func (f *fakeChannel) SendWithClientID(ctx context.Context, message bus.OutboundMessage, _ string) ([]string, error) {
	return f.Send(ctx, message)
}

func newTestService(t *testing.T) (*agentService, *fakeChannel) {
	t.Helper()
	channel := &fakeChannel{roomVisible: true}
	service := &agentService{
		agentID: "agent-a", roomID: "room-a", triggerPrefix: "probe:", replyPrefix: "ack:",
		statePath: filepath.Join(t.TempDir(), "state", "agent.json"), channel: channel,
		state: durableState{Schema: stateSchema},
	}
	if err := service.load(); err != nil {
		t.Fatal(err)
	}
	return service, channel
}

func TestResolveRoomRestoresRemovedTerminalIdentity(t *testing.T) {
	channel := &fakeChannel{membership: tosmessengerlab.MembershipStatus{
		RoomID: "room_terminal", RoomLabel: "builders", Members: []string{"agent-b", "agent-a"},
		ActiveMember: false, MLSEpoch: 3,
	}}
	roomID, err := resolveRoom(context.Background(), channel, "builders", []string{"agent-a", "agent-b"})
	if err != nil || roomID != "room_terminal" {
		t.Fatalf("room=%q err=%v", roomID, err)
	}
	channel.membership.ActiveMember = true
	if _, err := resolveRoom(context.Background(), channel, "builders", []string{"agent-a", "agent-b"}); err == nil {
		t.Fatal("invisible active membership was accepted as terminal removal")
	}
}

func TestControlSendAndTranscriptAreDurable(t *testing.T) {
	service, channel := newTestService(t)
	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/send",
		strings.NewReader(`{"request_id":"request-1","content":"hello room"}`),
	)
	response := httptest.NewRecorder()
	service.routes().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("send status=%d body=%s", response.Code, response.Body.String())
	}
	channel.mu.Lock()
	if len(channel.sent) != 1 || channel.sent[0].ChatID != "room-a" || channel.sent[0].Content != "hello room" {
		t.Fatalf("sent=%+v", channel.sent)
	}
	channel.mu.Unlock()

	restarted := &agentService{statePath: service.statePath, state: durableState{Schema: stateSchema}}
	if err := restarted.load(); err != nil {
		t.Fatal(err)
	}
	if len(restarted.state.Transcript) != 1 || restarted.state.Transcript[0].Direction != "outbound" ||
		restarted.state.Transcript[0].ClientID != "request-1" {
		t.Fatalf("state=%+v", restarted.state)
	}
	info, err := os.Stat(service.statePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode=%v", info.Mode())
	}
}

func TestConsumePersistsInboundAndRepliesWithoutLooping(t *testing.T) {
	service, channel := newTestService(t)
	inbound := make(chan bus.InboundMessage, 2)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		if err := service.consume(ctx, inbound); err != nil {
			t.Errorf("consume: %v", err)
		}
		close(done)
	}()
	inbound <- bus.InboundMessage{
		MessageID: "event-1", Content: "ignored old history",
		Sender: bus.SenderInfo{PlatformID: "agent-founder"},
	}
	inbound <- bus.InboundMessage{
		MessageID: "event-2", Content: "probe: opening",
		Sender: bus.SenderInfo{PlatformID: "agent-founder"},
	}
	inbound <- bus.InboundMessage{
		MessageID: "event-3", Content: "ack:someone",
		Sender: bus.SenderInfo{PlatformID: "agent-peer"},
	}
	deadline := time.Now().Add(time.Second)
	for {
		channel.mu.Lock()
		sent := len(channel.sent)
		channel.mu.Unlock()
		service.mu.Lock()
		received := len(service.state.Transcript)
		service.mu.Unlock()
		if sent == 1 && received == 4 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("sent=%d transcript=%d", sent, received)
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	channel.mu.Lock()
	defer channel.mu.Unlock()
	if channel.sent[0].Content != "ack:agent-a-for-event-2" || channel.sent[0].ReplyToMessageID != "event-2" {
		t.Fatalf("reply=%+v", channel.sent[0])
	}
}

func TestAgentLoopModeRunsRealTurnAndBindsReply(t *testing.T) {
	service, channel := newTestService(t)
	service.replyMode = replyModeAgentLoop
	transportBus := bus.NewMessageBus()
	agentBus := bus.NewMessageBus()
	loop, err := newLabAgentLoop(
		service.agentID,
		filepath.Join(t.TempDir(), "agent-workspace"),
		service.replyPrefix,
		agentBus,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer loop.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errorsCh := make(chan error, 3)
	go func() { errorsCh <- loop.Run(ctx) }()
	go func() { errorsCh <- service.consumeAgentLoop(ctx, transportBus.InboundChan(), agentBus) }()
	go func() { errorsCh <- service.sendAgentLoop(ctx, agentBus.OutboundChan()) }()
	application := make(chan error, 1)
	inbound := bus.InboundMessage{
		Context: bus.InboundContext{
			Channel: "tos_messenger_lab", ChatID: service.roomID, ChatType: "group",
			SenderID: "tos_messenger_lab:agent-founder", MessageID: "event-agentloop-1",
		},
		Sender:            bus.SenderInfo{PlatformID: "agent-founder"},
		Content:           "probe: actual AgentLoop turn",
		ApplicationResult: application,
	}
	if err := transportBus.PublishInbound(ctx, inbound); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-application:
		if err != nil {
			t.Fatalf("durable AgentLoop application: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("durable AgentLoop application timed out")
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		channel.mu.Lock()
		sent := append([]bus.OutboundMessage(nil), channel.sent...)
		channel.mu.Unlock()
		if len(sent) == 1 {
			if sent[0].ReplyToMessageID != "event-agentloop-1" ||
				!strings.HasPrefix(sent[0].Content, "ack:agent-a-agentloop-") {
				t.Fatalf("reply=%+v", sent[0])
			}
			break
		}
		select {
		case err := <-errorsCh:
			t.Fatalf("AgentLoop pipeline stopped: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("AgentLoop reply timed out")
		}
		time.Sleep(time.Millisecond)
	}
	service.mu.Lock()
	if len(service.state.Transcript) != 2 || service.state.Transcript[1].Runtime != agentLoopRuntime ||
		service.state.Transcript[1].ReplyToEventID != "event-agentloop-1" {
		t.Fatalf("transcript=%+v", service.state.Transcript)
	}
	service.mu.Unlock()
	replayResult := make(chan error, 1)
	inbound.ApplicationResult = replayResult
	if err := transportBus.PublishInbound(ctx, inbound); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-replayResult:
		if err != nil {
			t.Fatalf("exact replay application: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("exact replay was not recognized")
	}
	channel.mu.Lock()
	defer channel.mu.Unlock()
	if len(channel.sent) != 1 {
		t.Fatalf("exact replay ran a second AgentLoop send: %+v", channel.sent)
	}
}

func TestRecordIsIdempotentAndRejectsEventIDSubstitution(t *testing.T) {
	service, _ := newTestService(t)
	line := transcriptLine{Direction: "inbound", AgentID: "agent-peer", EventID: "event-1", Content: "hello"}
	if err := service.record(line); err != nil {
		t.Fatal(err)
	}
	if err := service.record(line); err != nil {
		t.Fatalf("exact replay: %v", err)
	}
	line.Content = "substitution"
	if err := service.record(line); err == nil {
		t.Fatal("Event-ID substitution was accepted")
	}
	if got := len(service.state.Transcript); got != 1 {
		t.Fatalf("transcript entries=%d", got)
	}
}

func TestControlRejectsUnknownAndTrailingJSON(t *testing.T) {
	service, _ := newTestService(t)
	for _, body := range []string{`{"request_id":"r","content":"ok","unknown":true}`, `{"request_id":"r","content":"ok"}{}`} {
		response := httptest.NewRecorder()
		service.routes().ServeHTTP(response,
			httptest.NewRequest(http.MethodPost, "/v1/send", strings.NewReader(body)))
		if response.Code != http.StatusBadRequest {
			t.Fatalf("body=%s status=%d", body, response.Code)
		}
	}
}

func TestHealthBindsAgentAndRoom(t *testing.T) {
	service, _ := newTestService(t)
	response := httptest.NewRecorder()
	service.routes().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/health", nil))
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["schema"] != controlSchema || body["agent_id"] != "agent-a" || body["room_id"] != "room-a" ||
		body["active_member"] != true {
		t.Fatalf("health=%v", body)
	}
}

func TestRemovedAgentStaysHealthyAndCannotSend(t *testing.T) {
	service, channel := newTestService(t)
	channel.removed = true
	health := httptest.NewRecorder()
	service.routes().ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/v1/health", nil))
	var body map[string]any
	if err := json.Unmarshal(health.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if health.Code != http.StatusOK || body["ok"] != true || body["active_member"] != false ||
		body["room_id"] != "room-a" {
		t.Fatalf("removed health status=%d body=%v", health.Code, body)
	}
	send := httptest.NewRecorder()
	service.routes().ServeHTTP(send, httptest.NewRequest(http.MethodPost, "/v1/send",
		strings.NewReader(`{"request_id":"removed-1","content":"must not send"}`)))
	if send.Code != http.StatusGone || len(channel.sent) != 0 {
		t.Fatalf("removed send status=%d sent=%v", send.Code, channel.sent)
	}
}

func TestListenControlRefusesRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sock")
	if err := os.WriteFile(path, []byte("do not replace"), 0o600); err != nil {
		t.Fatal(err)
	}
	if listener, err := listenControl(path); err == nil {
		listener.Close()
		t.Fatal("regular control path was replaced")
	}
}

func TestWaitForUnixListenerWaitsForReadiness(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy.sock")
	listenerReady := make(chan net.Listener, 1)
	go func() {
		time.Sleep(2 * startupProbePeriod)
		listener, err := net.Listen("unix", path)
		if err != nil {
			listenerReady <- nil
			return
		}
		listenerReady <- listener
	}()
	if err := waitForUnixListener(context.Background(), path, time.Second); err != nil {
		t.Fatal(err)
	}
	listener := <-listenerReady
	if listener == nil {
		t.Fatal("test proxy listener failed")
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWaitForUnixListenerRefusesNonSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy.sock")
	if err := os.WriteFile(path, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := waitForUnixListener(context.Background(), path, time.Second)
	if err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Fatalf("error=%v", err)
	}
}

func TestWaitForUnixListenerIsBoundedAndCancelable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.sock")
	err := waitForUnixListener(context.Background(), path, 2*startupProbePeriod)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout error=%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = waitForUnixListener(ctx, path, time.Second)
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel error=%v", err)
	}
}
