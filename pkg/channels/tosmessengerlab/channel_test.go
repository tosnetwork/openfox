package tosmessengerlab

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
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
)

type fakeHub struct {
	mu            sync.Mutex
	after         []uint64
	sends         int
	clientIDs     []string
	failFirstSend bool
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
					Sequence:      1,
					MessageID:     "msg_1",
					RoomID:        testRoom,
					SenderAgentID: testAlice,
					Content:       "hello Bob",
				},
			)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"messages": messages})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/messages":
		var request struct {
			ClientID string `json:"client_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		h.mu.Lock()
		h.sends++
		h.clientIDs = append(h.clientIDs, request.ClientID)
		fail := h.failFirstSend && h.sends == 1
		h.mu.Unlock()
		if fail {
			http.Error(w, "response lost after acceptance", http.StatusBadGateway)
			return
		}
		_ = json.NewEncoder(w).
			Encode(message{Sequence: 2, MessageID: "msg_2", RoomID: testRoom, SenderAgentID: testBob, Content: "hello Alice"})
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
	if err != nil || len(ids) != 1 || ids[0] != "msg_2" {
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
