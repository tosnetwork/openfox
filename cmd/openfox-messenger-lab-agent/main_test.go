package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tosnetwork/openfox/pkg/bus"
)

type fakeChannel struct {
	mu   sync.Mutex
	sent []bus.OutboundMessage
}

func (*fakeChannel) Start(context.Context) error { return nil }
func (*fakeChannel) Stop(context.Context) error  { return nil }
func (*fakeChannel) RoomID(string, []string) (string, bool) {
	return "room_test", true
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
	channel := &fakeChannel{}
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
	if len(restarted.state.Transcript) != 1 || restarted.state.Transcript[0].Direction != "outbound" {
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
	if body["schema"] != controlSchema || body["agent_id"] != "agent-a" || body["room_id"] != "room-a" {
		t.Fatalf("health=%v", body)
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
