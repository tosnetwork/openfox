package tosmessengerlab

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tosnetwork/openfox/pkg/bus"
	"github.com/tosnetwork/openfox/pkg/config"
)

const (
	testAlice = "agent_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testBob   = "agent_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testRoom  = "room_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	testMsg1  = "msg_1111111111111111111111111111111111111111111111111111111111111111"
	testMsg2  = "msg_2222222222222222222222222222222222222222222222222222222222222222"
)

type fakeHub struct {
	mu             sync.Mutex
	after          []uint64
	sends          int
	clientIDs      []string
	replyToIDs     []string
	inboundReplyTo string
	failFirstSend  bool
}

type removedHub struct {
	createGone   bool
	messagesGone bool
}

func (h *removedHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/rooms":
		if h.createGone {
			w.WriteHeader(http.StatusGone)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Agent was removed from the MLS room"})
			return
		}
		_ = json.NewEncoder(w).Encode(room{RoomID: testRoom, Label: "builders", Members: []string{testAlice, testBob}})
	case r.Method == http.MethodGet && r.URL.Path == "/v1/rooms":
		rooms := []room{}
		if !h.createGone {
			rooms = append(rooms, room{RoomID: testRoom, Label: "builders", Members: []string{testAlice, testBob}})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"rooms": rooms})
	case r.Method == http.MethodGet && r.URL.Path == "/v1/messages" && h.messagesGone:
		w.WriteHeader(http.StatusGone)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Agent was removed from the MLS room"})
	case r.Method == http.MethodGet && r.URL.Path == "/livez":
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true, "active_member": false, "room_id": testRoom, "mls_epoch": 3,
			"room_label": "builders", "members": []string{testAlice, testBob},
			"encryption": "openmls-0.8.1-suite-0x0001",
		})
	default:
		http.Error(w, "unexpected request", http.StatusInternalServerError)
	}
}

func (h *fakeHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/rooms":
		_ = json.NewEncoder(w).Encode(room{RoomID: testRoom, Label: "builders", Members: []string{testAlice, testBob}})
	case r.Method == http.MethodGet && r.URL.Path == "/v1/rooms":
		_ = json.NewEncoder(w).
			Encode(map[string]any{"rooms": []room{{RoomID: testRoom, Label: "builders", Members: []string{testAlice, testBob}}}})
	case r.Method == http.MethodGet && r.URL.Path == "/v1/messages":
		after, _ := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
		h.mu.Lock()
		h.after = append(h.after, after)
		h.mu.Unlock()
		messages := []message{}
		if after < 1 {
			messages = append(
				messages,
				message{
					Sequence:       1,
					MessageID:      testMsg1,
					RoomID:         testRoom,
					SenderAgentID:  testAlice,
					ReplyToEventID: h.inboundReplyTo,
					Content:        "hello Bob",
				},
			)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"messages": messages})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/messages":
		var request struct {
			ClientID       string `json:"client_id"`
			ReplyToEventID string `json:"reply_to_event_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		h.mu.Lock()
		h.sends++
		h.clientIDs = append(h.clientIDs, request.ClientID)
		h.replyToIDs = append(h.replyToIDs, request.ReplyToEventID)
		fail := h.failFirstSend && h.sends == 1
		h.mu.Unlock()
		if fail {
			http.Error(w, "response lost after acceptance", http.StatusBadGateway)
			return
		}
		_ = json.NewEncoder(w).
			Encode(message{Sequence: 2, MessageID: testMsg2, RoomID: testRoom, SenderAgentID: testBob, Content: "hello Alice"})
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func TestChannelReusesClientIDAfterAmbiguousSendFailure(t *testing.T) {
	hub := &fakeHub{failFirstSend: true}
	server := httptest.NewServer(hub)
	defer server.Close()
	channel := newTestChannel(t, server, bus.NewMessageBus(), filepath.Join(t.TempDir(), "cursor.json"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := channel.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if roomID, ok := channel.RoomID("builders", []string{testBob, testAlice}); !ok || roomID != testRoom {
		t.Fatalf("configured room lookup = %q, %v", roomID, ok)
	}
	defer channel.Stop(context.Background())
	outbound := bus.OutboundMessage{ChatID: testRoom, Content: "retry me once"}
	if _, err := channel.Send(ctx, outbound); err == nil {
		t.Fatal("ambiguous first response unexpectedly succeeded")
	}
	if _, err := channel.Send(ctx, outbound); err != nil {
		t.Fatalf("retry failed: %v", err)
	}
	hub.mu.Lock()
	defer hub.mu.Unlock()
	if len(hub.clientIDs) != 2 || hub.clientIDs[0] == "" || hub.clientIDs[0] != hub.clientIDs[1] {
		t.Fatalf("retry client IDs = %v", hub.clientIDs)
	}
}

func TestChannelUsesCallerOwnedStableClientID(t *testing.T) {
	hub := &fakeHub{}
	server := httptest.NewServer(hub)
	defer server.Close()
	channel := newTestChannel(t, server, bus.NewMessageBus(), filepath.Join(t.TempDir(), "cursor.json"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := channel.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer channel.Stop(context.Background())
	outbound := bus.OutboundMessage{ChatID: testRoom, Content: "stable across process restart"}
	for range 2 {
		if _, err := channel.SendWithClientID(ctx, outbound, "request-stable-1"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := channel.SendWithClientID(ctx, outbound, "not valid/client"); err == nil {
		t.Fatal("invalid caller client ID accepted")
	}
	hub.mu.Lock()
	defer hub.mu.Unlock()
	if len(hub.clientIDs) != 2 || hub.clientIDs[0] != "request-stable-1" || hub.clientIDs[1] != hub.clientIDs[0] {
		t.Fatalf("client IDs=%v", hub.clientIDs)
	}
}

func TestChannelCarriesAuthenticatedReplyBinding(t *testing.T) {
	replyTo := "msg_" + strings.Repeat("a", 64)
	hub := &fakeHub{inboundReplyTo: replyTo}
	server := httptest.NewServer(hub)
	defer server.Close()
	messageBus := bus.NewMessageBus()
	channel := newTestChannel(t, server, messageBus, filepath.Join(t.TempDir(), "cursor.json"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := channel.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer channel.Stop(context.Background())
	select {
	case inbound := <-messageBus.InboundChan():
		if inbound.Context.ReplyToMessageID != replyTo {
			t.Fatalf("inbound reply binding = %q", inbound.Context.ReplyToMessageID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for bound reply")
	}
	ids, err := channel.SendWithClientID(ctx, bus.OutboundMessage{
		ChatID: testRoom, Content: "bound response", ReplyToMessageID: replyTo,
	}, "bound-reply-1")
	if err != nil || len(ids) != 1 {
		t.Fatalf("send reply = %v, %v", ids, err)
	}
	if _, err := channel.SendWithClientID(ctx, bus.OutboundMessage{
		ChatID: testRoom, Content: "bad response", ReplyToMessageID: "msg_bad",
	}, "bad-reply-1"); err == nil {
		t.Fatal("malformed reply Event ID was sent")
	}
	hub.mu.Lock()
	if len(hub.replyToIDs) != 1 || hub.replyToIDs[0] != replyTo {
		t.Fatalf("proxy requests lost reply binding: %v", hub.replyToIDs)
	}
	hub.mu.Unlock()
}

func TestChannelCarriesGroupMessagesAndPersistsCursor(t *testing.T) {
	hub := &fakeHub{}
	server := httptest.NewServer(hub)
	defer server.Close()
	cursorPath := filepath.Join(t.TempDir(), "cursor.json")

	messageBus := bus.NewMessageBus()
	channel := newTestChannel(t, server, messageBus, cursorPath)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := channel.Start(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case inbound := <-messageBus.InboundChan():
		if inbound.Content != "hello Bob" || inbound.Context.ChatType != "group" ||
			inbound.Context.ChatID != testRoom ||
			inbound.Context.SenderID != config.ChannelTOSMessengerLab+":"+testAlice {
			t.Fatalf("unexpected inbound: %+v", inbound)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for group message")
	}
	ids, err := channel.Send(ctx, bus.OutboundMessage{ChatID: testRoom, Content: "hello Alice"})
	if err != nil || len(ids) != 1 || ids[0] != testMsg2 {
		t.Fatalf("send = %v, %v", ids, err)
	}
	if err := channel.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}

	restartedBus := bus.NewMessageBus()
	restarted := newTestChannel(t, server, restartedBus, cursorPath)
	if err := restarted.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer restarted.Stop(context.Background())
	time.Sleep(150 * time.Millisecond)
	select {
	case replay := <-restartedBus.InboundChan():
		t.Fatalf("cursor allowed replay: %+v", replay)
	default:
	}
	hub.mu.Lock()
	defer hub.mu.Unlock()
	if len(hub.after) == 0 || hub.after[len(hub.after)-1] != 1 || hub.sends != 1 {
		t.Fatalf("hub observations: after=%v sends=%d", hub.after, hub.sends)
	}
}

func TestDurableApplicationDefersCursorAndRetriesFailure(t *testing.T) {
	hub := &fakeHub{}
	server := httptest.NewServer(hub)
	defer server.Close()
	cursorPath := filepath.Join(t.TempDir(), "cursor.json")
	messageBus := bus.NewMessageBus()
	channel := newTestChannel(t, server, messageBus, cursorPath)
	if err := channel.EnableDurableApplication(time.Second); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := channel.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer channel.Stop(context.Background())
	first := <-messageBus.InboundChan()
	if first.ApplicationResult == nil {
		t.Fatal("durable application result channel missing")
	}
	first.ApplicationResult <- context.Canceled
	var retry bus.InboundMessage
	select {
	case retry = <-messageBus.InboundChan():
	case <-time.After(2 * time.Second):
		t.Fatal("failed application was not retried")
	}
	if retry.MessageID != first.MessageID || retry.ApplicationResult == nil {
		t.Fatalf("retry=%+v", retry)
	}
	if _, err := os.Stat(cursorPath); !os.IsNotExist(err) {
		t.Fatalf("cursor advanced before durable application: %v", err)
	}
	retry.ApplicationResult <- nil
	deadline := time.Now().Add(2 * time.Second)
	for {
		raw, err := os.ReadFile(cursorPath)
		if err == nil {
			var state cursorState
			if json.Unmarshal(raw, &state) == nil && state.Cursors[testRoom] == 1 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("cursor did not advance after durable application")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestChannelMarksOpenMLSProxyTransport(t *testing.T) {
	settings := &config.TOSMessengerLabSettings{
		SocketPath: "/unused", CursorPath: filepath.Join(t.TempDir(), "cursor.json"),
		AgentID: testBob, Token: *config.NewSecureString("bob-token-0000002"), Encryption: "openmls-proxy",
	}
	messageBus := bus.NewMessageBus()
	channel, err := New(&config.Channel{AllowFrom: []string{"*"}}, settings, messageBus)
	if err != nil {
		t.Fatal(err)
	}
	if channel.transportName() != "local-unix-openmls-ciphertext-relay" {
		t.Fatal("encrypted transport metadata missing")
	}
	settings.Encryption = "invented"
	if _, err := New(&config.Channel{AllowFrom: []string{"*"}}, settings, messageBus); err == nil {
		t.Fatal("unknown encryption mode accepted")
	}
}

func TestChannelRetiresRemovedRoomWithoutRetryLoop(t *testing.T) {
	hub := &removedHub{messagesGone: true}
	server := httptest.NewServer(hub)
	defer server.Close()
	cursorPath := filepath.Join(t.TempDir(), "cursor.json")
	channel := newTestChannel(t, server, bus.NewMessageBus(), cursorPath)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := channel.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer channel.Stop(context.Background())
	deadline := time.Now().Add(2 * time.Second)
	for len(channel.RoomIDs()) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("removed room remained in the active poll set")
		}
		time.Sleep(time.Millisecond)
	}
	raw, err := os.ReadFile(cursorPath)
	if err != nil {
		t.Fatal(err)
	}
	var state cursorState
	if err := json.Unmarshal(raw, &state); err != nil || len(state.Cursors) != 0 {
		t.Fatalf("removed cursor state = %+v err=%v", state, err)
	}
	if _, err := channel.Send(ctx, bus.OutboundMessage{ChatID: testRoom, Content: "after removal"}); err == nil {
		t.Fatal("removed room remained sendable")
	}
}

func TestChannelRestartTreatsConfiguredGoneRoomAsTerminalMembership(t *testing.T) {
	hub := &removedHub{createGone: true}
	server := httptest.NewServer(hub)
	defer server.Close()
	channel := newTestChannel(t, server, bus.NewMessageBus(), filepath.Join(t.TempDir(), "cursor.json"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := channel.Start(ctx); err != nil {
		t.Fatalf("removed room made channel startup fail: %v", err)
	}
	defer channel.Stop(context.Background())
	if rooms := channel.RoomIDs(); len(rooms) != 0 {
		t.Fatalf("configured removed room was resurrected: %v", rooms)
	}
	status, err := channel.MembershipStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if status.ActiveMember || status.RoomID != testRoom || status.RoomLabel != "builders" ||
		!slices.Equal(status.Members, []string{testAlice, testBob}) || status.MLSEpoch != 3 {
		t.Fatalf("terminal membership = %+v", status)
	}
}

func newTestChannel(t *testing.T, server *httptest.Server, messageBus *bus.MessageBus, cursorPath string) *Channel {
	t.Helper()
	settings := &config.TOSMessengerLabSettings{
		SocketPath:     "/unused",
		CursorPath:     cursorPath,
		AgentID:        testBob,
		Token:          *config.NewSecureString("bob-token-0000002"),
		PollIntervalMS: 50,
		Rooms:          []config.TOSMessengerLabRoom{{Label: "builders", Members: []string{testAlice, testBob}}},
	}
	channel, err := New(&config.Channel{AllowFrom: []string{"*"}}, settings, messageBus)
	if err != nil {
		t.Fatal(err)
	}
	channel.client = server.Client()
	channel.endpoint = server.URL
	return channel
}

func TestCallEscapesRoomQuery(t *testing.T) {
	value := url.QueryEscape(testRoom)
	if value != testRoom {
		t.Fatalf("canonical room unexpectedly needs escaping: %s", value)
	}
}
