package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/openfox/pkg/bus"
)

type senderFake struct {
	messages []bus.OutboundMessage
	eventID  string
}

const testRunID = "run_11111111111111111111111111111111"

func (f *senderFake) Send(_ context.Context, message bus.OutboundMessage) ([]string, error) {
	f.messages = append(f.messages, message)
	if f.eventID == "" {
		f.eventID = "evt_" + strings.Repeat("1", 64)
	}
	return []string{f.eventID}, nil
}

func TestControlRejectsNonCanonicalDaemonEventID(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	_ = os.Mkdir(directory, 0o700)
	sender := &senderFake{eventID: "model-selected-event"}
	service := &service{agentID: "agent_" + strings.Repeat("a", 64), runID: testRunID, statePath: filepath.Join(directory, "transcript.json"),
		channel: sender, state: durableState{Schema: stateSchema}, pending: map[string]chan error{}}
	_ = service.recordBootstrap()
	request := httptest.NewRequest(http.MethodPost, "/v1/send", strings.NewReader(
		`{"request_id":"operator-1","recipient":"alice.tos","content":"hello"}`))
	response := httptest.NewRecorder()
	service.routes().ServeHTTP(response, request)
	if response.Code != http.StatusBadGateway || len(service.state.Transcript) != 0 {
		t.Fatalf("invalid daemon Event ID admitted: status=%d transcript=%+v", response.Code, service.state.Transcript)
	}
}

func TestConsumeAcknowledgesDurablyAppliedReplyWithoutAgentReplay(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	_ = os.Mkdir(directory, 0o700)
	originalID := "evt_" + strings.Repeat("1", 64)
	replyID := "evt_" + strings.Repeat("2", 64)
	service := &service{agentID: "agent_" + strings.Repeat("a", 64), runID: testRunID, statePath: filepath.Join(directory, "transcript.json"),
		state: durableState{Schema: stateSchema, Transcript: []transcriptLine{
			{Direction: "inbound", PeerAgentID: "agent_" + strings.Repeat("b", 64), EventID: originalID, Content: "ping:hello"},
			{Direction: "outbound", EventID: replyID, ReplyToEventID: originalID, Content: "ack"},
		}}, pending: map[string]chan error{}}
	if err := service.recordBootstrap(); err != nil {
		t.Fatal(err)
	}
	inbound := make(chan bus.InboundMessage, 1)
	application := make(chan error, 1)
	inbound <- bus.InboundMessage{MessageID: originalID, Content: "ping:hello",
		Sender: bus.SenderInfo{PlatformID: "agent_" + strings.Repeat("b", 64)}, ApplicationResult: application}
	target := bus.NewMessageBus()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.consume(ctx, inbound, target) }()
	select {
	case err := <-application:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("replayed application lease was not acknowledged")
	}
	select {
	case replay := <-target.InboundChan():
		t.Fatalf("durably applied event replayed into AgentLoop: %+v", replay)
	default:
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestConsumePublishesFreshInboundEventAndRetainsApplicationLease(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	eventID := "evt_" + strings.Repeat("3", 64)
	service := &service{agentID: "agent_" + strings.Repeat("a", 64), runID: testRunID,
		statePath: filepath.Join(directory, "transcript.json"), state: durableState{Schema: stateSchema},
		pending: map[string]chan error{}}
	if err := service.recordBootstrap(); err != nil {
		t.Fatal(err)
	}
	inbound := make(chan bus.InboundMessage, 1)
	application := make(chan error, 1)
	inbound <- bus.InboundMessage{MessageID: eventID, Content: "ping:fresh",
		Sender: bus.SenderInfo{PlatformID: "agent_" + strings.Repeat("b", 64)}, ApplicationResult: application}
	target := bus.NewMessageBus()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.consume(ctx, inbound, target) }()

	select {
	case message := <-target.InboundChan():
		if message.MessageID != eventID || message.ApplicationResult != nil {
			t.Fatalf("unexpected AgentLoop input: %+v", message)
		}
	case <-time.After(time.Second):
		t.Fatal("fresh event was not published to AgentLoop")
	}
	service.mu.Lock()
	retained := service.pending[eventID]
	service.mu.Unlock()
	if retained != application {
		t.Fatal("application lease was not retained until AgentLoop reply")
	}
	select {
	case result := <-application:
		t.Fatalf("application lease completed before AgentLoop reply: %v", result)
	default:
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestControlSendCarriesOnlyRecipientIntentAndStableRuntimeID(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	sender := &senderFake{}
	service := &service{agentID: "agent_" + strings.Repeat("a", 64), runID: testRunID, statePath: filepath.Join(directory, "transcript.json"),
		channel: sender, state: durableState{Schema: stateSchema}, pending: map[string]chan error{}}
	if err := service.recordBootstrap(); err != nil {
		t.Fatal(err)
	}
	body := `{"request_id":"operator-1","recipient":"alice.tos","content":"ping:hello"}`
	for range 2 {
		request := httptest.NewRequest(http.MethodPost, "/v1/send", strings.NewReader(body))
		response := httptest.NewRecorder()
		service.routes().ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("send status=%d body=%s", response.Code, response.Body.String())
		}
	}
	if len(sender.messages) != 2 || sender.messages[0].Recipient != "alice.tos" || sender.messages[0].ChatID != "" ||
		sender.messages[0].Context.AuthenticatedMessagingOrigin != nil || sender.messages[0].DeliveryIntentID == "" ||
		sender.messages[0].DeliveryIntentID != sender.messages[1].DeliveryIntentID {
		t.Fatalf("unexpected recipient intent: %+v", sender.messages)
	}
	if len(service.state.Transcript) != 1 {
		t.Fatalf("exact retry duplicated durable transcript: %+v", service.state.Transcript)
	}
}

func TestControlRejectsModelRouteAuthorityFields(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	_ = os.Mkdir(directory, 0o700)
	sender := &senderFake{}
	service := &service{agentID: "agent_" + strings.Repeat("a", 64), runID: testRunID, statePath: filepath.Join(directory, "transcript.json"),
		channel: sender, state: durableState{Schema: stateSchema}, pending: map[string]chan error{}}
	_ = service.recordBootstrap()
	request := httptest.NewRequest(http.MethodPost, "/v1/send", strings.NewReader(
		`{"request_id":"operator-1","recipient":"alice.tos","content":"hello","endpoint_id":"mep_model"}`))
	response := httptest.NewRecorder()
	service.routes().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || len(sender.messages) != 0 {
		t.Fatalf("route injection reached Messenger: status=%d messages=%+v", response.Code, sender.messages)
	}
}
