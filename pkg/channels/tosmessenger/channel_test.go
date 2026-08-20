package tosmessenger

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/openfox/pkg/bus"
	"github.com/tosnetwork/openfox/pkg/config"
)

func TestChannelPublishesOnlyClaimedAuthenticatedEventWithTypedOrigin(t *testing.T) {
	pending := testPending(t, "hello from authenticated Messenger")
	path, operations, stop := serveInbox(t, pending)
	defer stop()
	messageBus := bus.NewMessageBus()
	channel, err := New(&config.Channel{AllowFrom: []string{"*"}}, &config.TOSMessengerSettings{
		SocketPath: path, LeaseSeconds: 30,
	}, messageBus)
	if err != nil {
		t.Fatal(err)
	}
	if err := channel.pollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case message := <-messageBus.InboundChan():
		origin := message.Context.AuthenticatedMessagingOrigin
		if message.Content != "hello from authenticated Messenger" || message.Context.ChatType != "direct" ||
			origin == nil || origin.AgentID != "agent_"+strings.Repeat("a", 64) ||
			origin.EventID != pending.EventID || origin.EndpointID != pending.SenderEndpointID ||
			origin.ReceivedAtUnix != pending.ReceivedAtUnix {
			t.Fatalf("unexpected authenticated inbound: %+v", message)
		}
	case <-time.After(time.Second):
		t.Fatal("authenticated event was not published")
	}
	if got := <-operations; got != "inbox.pending,inbox.claim,inbox.complete" {
		t.Fatalf("operations = %s", got)
	}
}

func TestChannelPublishesCanonicalRoomMessageAsAuthenticatedGroupChat(t *testing.T) {
	pending := testRoomPending(t, "hello private room")
	path, operations, stop := serveInbox(t, pending)
	defer stop()
	messageBus := bus.NewMessageBus()
	channel, err := New(
		&config.Channel{AllowFrom: []string{"*"}},
		&config.TOSMessengerSettings{SocketPath: path},
		messageBus,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := channel.pollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case message := <-messageBus.InboundChan():
		origin := message.Context.AuthenticatedMessagingOrigin
		if message.Content != "hello private room" || message.Context.ChatType != "group" ||
			message.Context.SpaceType != "room" || message.Context.ChatID != "room_"+strings.Repeat("9", 64) ||
			origin == nil || origin.Kind != "room.message" {
			t.Fatalf("unexpected room inbound: %+v", message)
		}
	case <-time.After(time.Second):
		t.Fatal("authenticated room message was not published")
	}
	if got := <-operations; got != "inbox.pending,inbox.claim,inbox.complete" {
		t.Fatalf("operations = %s", got)
	}
}

func TestEventSubstitutionIsRejectedBeforeBus(t *testing.T) {
	pending := testPending(t, "do not trust rendering")
	var event wireEvent
	if err := json.Unmarshal(pending.Event, &event); err != nil {
		t.Fatal(err)
	}
	event.Rendering = "substituted after the Event ID was derived"
	pending.Event, _ = json.Marshal(event)
	path, operations, stop := serveInbox(t, pending)
	defer stop()
	messageBus := bus.NewMessageBus()
	channel, _ := New(
		&config.Channel{AllowFrom: []string{"*"}},
		&config.TOSMessengerSettings{SocketPath: path},
		messageBus,
	)
	if err := channel.pollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case message := <-messageBus.InboundChan():
		t.Fatalf("substituted event reached bus: %+v", message)
	default:
	}
	if got := <-operations; got != "inbox.pending,inbox.claim,inbox.reject" {
		t.Fatalf("operations = %s", got)
	}
}

func TestDecoderConsumesMessengerGeneratedFixture(t *testing.T) {
	const eventID = "evt_642815c3395336130bae8968b9861001d96da9d670cf08485066bb9f8a69c19c"
	const raw = `{"schema":"tos.messaging.event.v1","network_id":"tos-local","genesis_root_hash":"1111111111111111111111111111111111111111111111111111111111111111","genesis_file_hash":"2222222222222222222222222222222222222222222222222222222222222222","conversation_id":"conv_3333333333333333333333333333333333333333333333333333333333333333","event_id":"evt_642815c3395336130bae8968b9861001d96da9d670cf08485066bb9f8a69c19c","sender_agent_id":"agent_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sender_messaging_endpoint_id":"mep_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","sender_device_id":"dev_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","created_at_unix":1800000000,"expires_at_unix":1800003600,"event_kind":"text","payload_schema":"tos.messaging.payload.text.v1","content_base64":"dG9zLm1lc3NhZ2luZy5wYXlsb2FkLnYxAHRvcy5tZXNzYWdpbmcucGF5bG9hZC50ZXh0LnYxAAAAABl0ZXh0L3BsYWluOyBjaGFyc2V0PXV0Zi04AAAAHGNyb3NzIGltcGxlbWVudGF0aW9uIGZpeHR1cmUAAAAA"}`
	pending := pendingEvent{
		EventID: eventID, SenderEndpointID: "mep_" + strings.Repeat("b", 64),
		ConversationID: "conv_" + strings.Repeat("3", 64), ReceivedAtUnix: 1_800_000_100,
		Event: json.RawMessage(raw),
	}
	event, body, err := decodeAdmittedText(pending)
	if err != nil || event.EventID != eventID || body != "cross implementation fixture" {
		t.Fatalf("Messenger fixture: event=%s body=%q err=%v", event.EventID, body, err)
	}
}

func testPending(t *testing.T, body string) pendingEvent {
	t.Helper()
	content := bytes.NewBufferString(textDomain)
	writeText(content, "text/plain; charset=utf-8")
	writeText(content, body)
	writeText(content, "")
	event := wireEvent{
		Schema: eventSchema, NetworkID: "tos-local", GenesisRootHash: strings.Repeat("1", 64),
		GenesisFileHash: strings.Repeat("2", 64), ConversationID: "conv_" + strings.Repeat("3", 64),
		SenderAgentID: "agent_" + strings.Repeat("a", 64), SenderEndpointID: "mep_" + strings.Repeat("b", 64),
		SenderDeviceID: "dev_" + strings.Repeat("c", 64), CreatedAtUnix: 1_800_000_000,
		ExpiresAtUnix: 1_800_003_600, Kind: "text", PayloadSchema: textSchema,
		ContentBase64: base64.StdEncoding.EncodeToString(content.Bytes()),
	}
	event.EventID = deriveEventID(event, content.Bytes())
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	return pendingEvent{
		EventID: event.EventID, SenderEndpointID: event.SenderEndpointID,
		ConversationID: event.ConversationID, ReceivedAtUnix: 1_800_000_100, Event: raw,
	}
}

func testRoomPending(t *testing.T, body string) pendingEvent {
	t.Helper()
	roomID := "room_" + strings.Repeat("9", 64)
	content := bytes.NewBufferString(roomMessageDomain)
	writeText(content, roomID)
	writeUint64(content, 3)
	writeText(content, "text/plain; charset=utf-8")
	writeText(content, body)
	event := wireEvent{
		Schema:           eventSchema,
		NetworkID:        "tos-local",
		GenesisRootHash:  strings.Repeat("1", 64),
		GenesisFileHash:  strings.Repeat("2", 64),
		ConversationID:   "conv_" + strings.Repeat("3", 64),
		SenderAgentID:    "agent_" + strings.Repeat("a", 64),
		SenderEndpointID: "mep_" + strings.Repeat("b", 64),
		SenderDeviceID:   "dev_" + strings.Repeat("c", 64),
		RoomID:           roomID,
		CreatedAtUnix:    1_800_000_000,
		ExpiresAtUnix:    1_800_003_600,
		Kind:             "room.message",
		PayloadSchema:    roomMessageSchema,
		ContentBase64:    base64.StdEncoding.EncodeToString(content.Bytes()),
	}
	event.EventID = deriveEventID(event, content.Bytes())
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	return pendingEvent{
		EventID:          event.EventID,
		SenderEndpointID: event.SenderEndpointID,
		ConversationID:   event.ConversationID,
		ReceivedAtUnix:   1_800_000_100,
		Event:            raw,
	}
}

func serveInbox(t *testing.T, pending pendingEvent) (string, <-chan string, func()) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "runtime.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	operations := make(chan string, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		seen := make([]string, 0, 3)
		for len(seen) < 3 {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			var header [4]byte
			_, _ = io.ReadFull(connection, header[:])
			raw := make([]byte, binary.BigEndian.Uint32(header[:]))
			_, _ = io.ReadFull(connection, raw)
			var request localRequest
			_ = json.Unmarshal(raw, &request)
			seen = append(seen, request.Op)
			response := localResponse{Schema: responseSchema, OK: true}
			switch request.Op {
			case "inbox.pending":
				response.Events = []pendingEvent{pending}
			case "inbox.claim":
				response.Event = &pending
			}
			body, _ := json.Marshal(response)
			binary.BigEndian.PutUint32(header[:], uint32(len(body)))
			_, _ = connection.Write(header[:])
			_, _ = connection.Write(body)
			_ = connection.Close()
		}
		operations <- strings.Join(seen, ",")
	}()
	return path, operations, func() {
		_ = listener.Close()
		<-done
	}
}
