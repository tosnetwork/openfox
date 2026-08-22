package tosmessenger

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/openfox/pkg/actionauth"
	"github.com/tosnetwork/openfox/pkg/bus"
	"github.com/tosnetwork/openfox/pkg/config"
	"github.com/tosnetwork/openfox/pkg/media"
)

func TestChannelPublishesOnlyDaemonAdmittedAttachmentAndCompletesLease(t *testing.T) {
	body := "hello from a scanned encrypted attachment\n"
	digest := sha256.Sum256([]byte(body))
	attachment := admittedAttachment{
		EventID:       "evt_" + strings.Repeat("1", 64),
		SenderAgentID: "agent_" + strings.Repeat("a", 64), SenderEndpointID: "mep_" + strings.Repeat("b", 64),
		SenderDeviceID: "dev_" + strings.Repeat("c", 64), ConversationID: "conv_" + strings.Repeat("d", 64),
		ReceivedAtUnix: 1_800_000_100, Filename: "note.txt", MediaType: "text/plain",
		PlaintextDigest: "sha256:" + hex.EncodeToString(digest[:]), SizeBytes: uint64(len(body)), Body: body,
		Scans: []attachmentScan{{
			ScannerID: "clamav", ScannerDigest: "sha256:" + strings.Repeat("e", 64),
			Resources: []attachmentScanResource{
				{Name: "clamscan", Digest: "sha256:" + strings.Repeat("1", 64)},
				{Name: "daily.cvd", Digest: "sha256:" + strings.Repeat("2", 64)},
			},
		}},
	}
	path, operations, stop := serveAttachmentInbox(t, attachment)
	defer stop()
	messageBus := bus.NewMessageBus()
	channel, err := New(&config.Channel{AllowFrom: []string{"*"}}, &config.TOSMessengerSettings{
		SocketPath: path, LeaseSeconds: 30, EnableAttachments: true,
	}, messageBus)
	if err != nil {
		t.Fatal(err)
	}
	pollErr := make(chan error, 1)
	go func() { pollErr <- channel.pollOnce(context.Background()) }()
	select {
	case message := <-messageBus.InboundChan():
		origin := message.Context.AuthenticatedMessagingOrigin
		if message.Content != body || origin == nil || origin.Kind != "artifact.encrypted" ||
			origin.EventID != attachment.EventID || message.Context.Raw["attachment_filename"] != "note.txt" ||
			message.Context.Raw["attachment_plaintext_digest"] != attachment.PlaintextDigest {
			t.Fatalf("unexpected admitted attachment: %+v", message)
		}
		message.ApplicationResult <- nil
	case <-time.After(time.Second):
		t.Fatal("admitted attachment was not published")
	}
	if err := <-pollErr; err != nil {
		t.Fatal(err)
	}
	if got := <-operations; got != "inbox.pending,attachments.pending,attachments.claim,inbox.complete" {
		t.Fatalf("operations = %s", got)
	}

	// The daemon is a separate process boundary. OpenFox must not rely on its
	// claim that these bytes match the digest or that scanner evidence is
	// canonical before admitting the body to the bus.
	substituted := attachment
	substituted.Body = "same-size substituted attachment text!\n"
	substituted.SizeBytes = uint64(len(substituted.Body))
	if validAdmittedAttachment(substituted) {
		t.Fatal("attachment body substitution passed the independent digest check")
	}
	malformedScan := attachment
	malformedScan.Scans = append([]attachmentScan(nil), attachment.Scans...)
	malformedScan.Scans[0].ScannerDigest = "sha256:" + strings.Repeat("E", 64)
	if validAdmittedAttachment(malformedScan) {
		t.Fatal("non-canonical scanner digest was accepted")
	}
	malformedResource := attachment
	malformedResource.Scans = append([]attachmentScan(nil), attachment.Scans...)
	malformedResource.Scans[0].Resources = append([]attachmentScanResource(nil), attachment.Scans[0].Resources...)
	malformedResource.Scans[0].Resources[1].Digest = "sha256:" + strings.Repeat("F", 64)
	if validAdmittedAttachment(malformedResource) {
		t.Fatal("non-canonical scanner resource digest was accepted")
	}
	unsortedResources := attachment
	unsortedResources.Scans = append([]attachmentScan(nil), attachment.Scans...)
	unsortedResources.Scans[0].Resources = []attachmentScanResource{
		attachment.Scans[0].Resources[1], attachment.Scans[0].Resources[0],
	}
	if validAdmittedAttachment(unsortedResources) {
		t.Fatal("unsorted scanner resource evidence was accepted")
	}
}

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
	pollErr := make(chan error, 1)
	go func() { pollErr <- channel.pollOnce(context.Background()) }()
	select {
	case message := <-messageBus.InboundChan():
		origin := message.Context.AuthenticatedMessagingOrigin
		if message.Content != "hello from authenticated Messenger" || message.Context.ChatType != "direct" ||
			origin == nil || origin.AgentID != "agent_"+strings.Repeat("a", 64) ||
			origin.EventID != pending.EventID || origin.EndpointID != pending.SenderEndpointID ||
			origin.ReceivedAtUnix != pending.ReceivedAtUnix {
			t.Fatalf("unexpected authenticated inbound: %+v", message)
		}
		message.ApplicationResult <- nil
	case <-time.After(time.Second):
		t.Fatal("authenticated event was not published")
	}
	if err := <-pollErr; err != nil {
		t.Fatal(err)
	}
	if got := <-operations; got != "inbox.pending,inbox.claim,inbox.complete" {
		t.Fatalf("operations = %s", got)
	}
}

func TestIndependentDecoderConsumesMessengerEventV2Vector(t *testing.T) {
	raw := []byte(
		`{"schema":"tos.messaging.event.v2","network_id":"tos-local","genesis_root_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","genesis_file_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","conversation_id":"conv_1111111111111111111111111111111111111111111111111111111111111111","event_id":"evt_907a3ee25f59981718c2021d8dedd81451f45159878e7fc97b95201d216e0614","sender_agent_id":"agent_2222222222222222222222222222222222222222222222222222222222222222","sender_messaging_endpoint_id":"mep_7e03fe8741547ed3530ae38dbc690a42273db8dce07edda055f309d26f24f46a","sender_device_id":"dev_4444444444444444444444444444444444444444444444444444444444444444","created_at_unix":1800000010,"event_kind":"text","payload_schema":"tos.messaging.payload.text.v1","content_base64":"dG9zLm1lc3NhZ2luZy5wYXlsb2FkLnYxAHRvcy5tZXNzYWdpbmcucGF5bG9hZC50ZXh0LnYxAAAAABl0ZXh0L3BsYWluOyBjaGFyc2V0PXV0Zi04AAAABWhlbGxvAAAAAA==","rendering":"hello"}`,
	)
	pending := pendingEvent{
		EventID:          "evt_907a3ee25f59981718c2021d8dedd81451f45159878e7fc97b95201d216e0614",
		SenderEndpointID: "mep_7e03fe8741547ed3530ae38dbc690a42273db8dce07edda055f309d26f24f46a",
		ConversationID:   "conv_" + strings.Repeat("1", 64), ReceivedAtUnix: 1_800_000_011, Event: raw,
	}
	event, body, err := decodeAdmittedText(pending)
	if err != nil || body != "hello" || event.EventID != pending.EventID {
		t.Fatalf("consume Messenger v2 vector: event=%+v body=%q err=%v", event, body, err)
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
	pollErr := make(chan error, 1)
	go func() { pollErr <- channel.pollOnce(context.Background()) }()
	select {
	case message := <-messageBus.InboundChan():
		origin := message.Context.AuthenticatedMessagingOrigin
		if message.Content != "hello private room" || message.Context.ChatType != "group" ||
			message.Context.SpaceType != "room" || message.Context.ChatID != "room_"+strings.Repeat("9", 64) ||
			origin == nil || origin.Kind != "room.message" {
			t.Fatalf("unexpected room inbound: %+v", message)
		}
		message.ApplicationResult <- nil
	case <-time.After(time.Second):
		t.Fatal("authenticated room message was not published")
	}
	if err := <-pollErr; err != nil {
		t.Fatal(err)
	}
	if got := <-operations; got != "inbox.pending,inbox.claim,inbox.complete" {
		t.Fatalf("operations = %s", got)
	}
}

func TestChannelWaitsForDurableRoomModerationBeforeCompletingLease(t *testing.T) {
	pending := testModerationPending(t, "hide", 1)
	path, operations, stop := serveInbox(t, pending)
	defer stop()
	messageBus := bus.NewMessageBus()
	channel, err := New(&config.Channel{AllowFrom: []string{"*"}}, &config.TOSMessengerSettings{
		SocketPath: path,
	}, messageBus)
	if err != nil {
		t.Fatal(err)
	}
	checked := make(chan struct{})
	go func() {
		message := <-messageBus.InboundChan()
		if message.Content != "" || message.RoomModeration == nil || message.ControlResult == nil ||
			message.Context.AuthenticatedMessagingOrigin == nil ||
			message.Context.AuthenticatedMessagingOrigin.Kind != "room.moderation" {
			t.Errorf("unexpected moderation control: %+v", message)
		}
		message.ControlResult <- nil
		close(checked)
	}()
	if err := channel.pollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	<-checked
	if got := <-operations; got != "inbox.pending,inbox.claim,inbox.complete" {
		t.Fatalf("operations = %s", got)
	}
}

func TestChannelLeavesLeaseForRetryWhenApplicationPersistenceFails(t *testing.T) {
	pending := testPending(t, "retry after persistence failure")
	path, requests, stop := serveInboxRequests(t, pending)
	defer stop()
	messageBus := bus.NewMessageBus()
	channel, err := New(&config.Channel{AllowFrom: []string{"*"}}, &config.TOSMessengerSettings{
		SocketPath: path,
	}, messageBus)
	if err != nil {
		t.Fatal(err)
	}
	pollErr := make(chan error, 1)
	go func() { pollErr <- channel.pollOnce(context.Background()) }()
	message := <-messageBus.InboundChan()
	message.ApplicationResult <- errors.New("disk unavailable")
	if err := <-pollErr; err == nil || err.Error() != "disk unavailable" {
		t.Fatalf("poll error=%v", err)
	}
	if first, second := <-requests, <-requests; first != "inbox.pending" || second != "inbox.claim" {
		t.Fatalf("operations=%q,%q", first, second)
	}
	select {
	case operation := <-requests:
		t.Fatalf("lease was completed after persistence failure: %s", operation)
	case <-time.After(20 * time.Millisecond):
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

func TestSendUsesDaemonCompositionAndStableAuthenticatedOrigin(t *testing.T) {
	path, requests, stop := serveCompose(t, 2)
	defer stop()
	roomID := "room_" + strings.Repeat("9", 64)
	channel, err := New(&config.Channel{AllowFrom: []string{"*"}}, &config.TOSMessengerSettings{
		SocketPath: path,
		Routes: []config.TOSMessengerRoute{{
			ChatID: roomID, ConversationID: "conv_" + strings.Repeat("3", 64),
			RoomID: roomID, MembershipEpoch: 3, SessionID: "ses_" + strings.Repeat("8", 64),
			RecipientEndpointID: "mep_" + strings.Repeat("6", 64), LifetimeSeconds: 3600,
		}},
	}, bus.NewMessageBus())
	if err != nil {
		t.Fatal(err)
	}
	channel.SetRunning(true)
	originEvent := "evt_" + strings.Repeat("a", 64)
	message := bus.OutboundMessage{
		ChatID: roomID, Content: "reply from OpenFox",
		ReplyToMessageID: originEvent, Context: bus.InboundContext{
			MessageID:                    originEvent,
			AuthenticatedMessagingOrigin: &actionauth.Origin{EventID: originEvent, ReceivedAtUnix: 1_800_000_100},
		},
	}
	first, err := channel.Send(context.Background(), message)
	if err != nil || len(first) != 1 {
		t.Fatalf("first send: ids=%v err=%v", first, err)
	}
	retry, err := channel.Send(context.Background(), message)
	if err != nil || len(retry) != 1 || retry[0] != first[0] {
		t.Fatalf("retry send: ids=%v err=%v", retry, err)
	}
	one, two := <-requests, <-requests
	if one.Op != "outbox.compose" || one.IdempotencyKey != two.IdempotencyKey ||
		one.ExpiresAtUnix != 1_800_003_700 || one.RoomID != roomID || one.MembershipEpoch != 3 ||
		one.Body != message.Content || one.SessionID == "" || one.RecipientEndpointID == "" {
		t.Fatalf("unexpected compose requests: one=%+v two=%+v", one, two)
	}
}

func TestSendRefusesUntrustedOrUnroutedOutput(t *testing.T) {
	roomID := "room_" + strings.Repeat("9", 64)
	channel, err := New(&config.Channel{AllowFrom: []string{"*"}}, &config.TOSMessengerSettings{
		SocketPath: filepath.Join(t.TempDir(), "absent.sock"),
		Routes: []config.TOSMessengerRoute{{
			ChatID: roomID, ConversationID: "conv_" + strings.Repeat("3", 64),
			RoomID: roomID, MembershipEpoch: 1, SessionID: "ses_" + strings.Repeat("8", 64),
			RecipientEndpointID: "mep_" + strings.Repeat("6", 64),
		}},
	}, bus.NewMessageBus())
	if err != nil {
		t.Fatal(err)
	}
	channel.SetRunning(true)
	if _, err := channel.Send(
		context.Background(),
		bus.OutboundMessage{ChatID: roomID, Content: "model only"},
	); !errors.Is(
		err,
		ErrOutboundUnavailable,
	) {
		t.Fatalf("untrusted output was not refused: %v", err)
	}
	if _, err := channel.Send(context.Background(), bus.OutboundMessage{
		ChatID:  "room_" + strings.Repeat("7", 64),
		Content: "unrouted", Context: bus.InboundContext{
			MessageID: "evt_" + strings.Repeat("a", 64),
			AuthenticatedMessagingOrigin: &actionauth.Origin{
				EventID:        "evt_" + strings.Repeat("a", 64),
				ReceivedAtUnix: 1,
			},
		},
	}); !errors.Is(err, ErrOutboundUnavailable) {
		t.Fatalf("unrouted output was not refused: %v", err)
	}
}

func TestSendMediaStreamsOnlyPlaintextSemanticsAndStableRetry(t *testing.T) {
	body := bytes.Repeat([]byte("x"), outboundAttachmentChunk+17)
	path := filepath.Join(t.TempDir(), "evidence.txt")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	socket, requests, stop := serveAttachmentOutbox(t)
	defer stop()
	roomID := "room_" + strings.Repeat("9", 64)
	channel, err := New(&config.Channel{AllowFrom: []string{"*"}}, &config.TOSMessengerSettings{
		SocketPath: socket, EnableAttachments: true,
		Routes: []config.TOSMessengerRoute{{
			ChatID: roomID, ConversationID: "conv_" + strings.Repeat("3", 64),
			RoomID: roomID, MembershipEpoch: 3, SessionID: "ses_" + strings.Repeat("8", 64),
			RecipientEndpointID: "mep_" + strings.Repeat("6", 64), LifetimeSeconds: 3600,
		}},
	}, bus.NewMessageBus())
	if err != nil {
		t.Fatal(err)
	}
	store := media.NewFileMediaStore()
	ref, err := store.Store(path, media.MediaMeta{
		Filename: "evidence.txt", ContentType: "text/plain",
		CleanupPolicy: media.CleanupPolicyForgetOnly,
	}, "test")
	if err != nil {
		t.Fatal(err)
	}
	channel.SetMediaStore(store)
	channel.SetRunning(true)
	originEvent := "evt_" + strings.Repeat("a", 64)
	message := bus.OutboundMediaMessage{
		ChatID: roomID, Context: bus.InboundContext{
			MessageID:                    originEvent,
			AuthenticatedMessagingOrigin: &actionauth.Origin{EventID: originEvent, ReceivedAtUnix: 1_800_000_100},
		},
		Parts: []bus.MediaPart{{Type: "file", Ref: ref, Filename: "evidence.txt", ContentType: "text/plain"}},
	}
	first, err := channel.SendMedia(context.Background(), message)
	if err != nil || len(first) != 1 {
		t.Fatalf("first media send ids=%v err=%v", first, err)
	}
	retry, err := channel.SendMedia(context.Background(), message)
	if err != nil || len(retry) != 1 || retry[0] != first[0] {
		t.Fatalf("retry media send ids=%v err=%v", retry, err)
	}
	begin, chunkOne, chunkTwo, commitOne, commitTwo, retryBegin := <-requests, <-requests, <-requests, <-requests, <-requests, <-requests
	digest := sha256.Sum256(body)
	if begin.Op != "attachments.outbound.begin" ||
		begin.Filename != "evidence.txt" ||
		begin.MediaType != "text/plain" ||
		begin.PlaintextDigest != "sha256:"+hex.EncodeToString(digest[:]) ||
		begin.PlaintextBytes != uint64(len(body)) ||
		begin.RoomID != roomID ||
		begin.MembershipEpoch != 3 ||
		begin.ReplyToEventID != originEvent {
		t.Fatalf("unexpected attachment begin: %+v", begin)
	}
	if chunkOne.Op != "attachments.outbound.chunk" || chunkOne.UploadID == "" || chunkOne.ChunkIndex != 0 ||
		!bytes.Equal(chunkOne.Chunk, body[:outboundAttachmentChunk]) || chunkTwo.Op != "attachments.outbound.chunk" ||
		chunkTwo.UploadID != chunkOne.UploadID || chunkTwo.ChunkIndex != 1 || !bytes.Equal(chunkTwo.Chunk, body[outboundAttachmentChunk:]) {
		t.Fatalf("unexpected attachment chunks: one=%s/%d/%d two=%s/%d/%d", chunkOne.UploadID, chunkOne.ChunkIndex,
			len(chunkOne.Chunk), chunkTwo.UploadID, chunkTwo.ChunkIndex, len(chunkTwo.Chunk))
	}
	if commitOne.Op != "attachments.outbound.commit" || commitOne.UploadID != chunkOne.UploadID ||
		commitTwo.Op != "attachments.outbound.commit" || commitTwo.UploadID != chunkOne.UploadID ||
		retryBegin.Op != "attachments.outbound.begin" || retryBegin.IdempotencyKey != begin.IdempotencyKey {
		t.Fatalf("unexpected attachment commit/retry: first=%+v second=%+v retry=%+v", commitOne, commitTwo, retryBegin)
	}
}

func TestDecoderRefusesHistoricalMessengerV1AsCurrentInput(t *testing.T) {
	const eventID = "evt_642815c3395336130bae8968b9861001d96da9d670cf08485066bb9f8a69c19c"
	const raw = `{"schema":"tos.messaging.event.v1","network_id":"tos-local","genesis_root_hash":"1111111111111111111111111111111111111111111111111111111111111111","genesis_file_hash":"2222222222222222222222222222222222222222222222222222222222222222","conversation_id":"conv_3333333333333333333333333333333333333333333333333333333333333333","event_id":"evt_642815c3395336130bae8968b9861001d96da9d670cf08485066bb9f8a69c19c","sender_agent_id":"agent_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sender_messaging_endpoint_id":"mep_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","sender_device_id":"dev_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","created_at_unix":1800000000,"expires_at_unix":1800003600,"event_kind":"text","payload_schema":"tos.messaging.payload.text.v1","content_base64":"dG9zLm1lc3NhZ2luZy5wYXlsb2FkLnYxAHRvcy5tZXNzYWdpbmcucGF5bG9hZC50ZXh0LnYxAAAAABl0ZXh0L3BsYWluOyBjaGFyc2V0PXV0Zi04AAAAHGNyb3NzIGltcGxlbWVudGF0aW9uIGZpeHR1cmUAAAAA"}`
	pending := pendingEvent{
		EventID: eventID, SenderEndpointID: "mep_" + strings.Repeat("b", 64),
		ConversationID: "conv_" + strings.Repeat("3", 64), ReceivedAtUnix: 1_800_000_100,
		Event: json.RawMessage(raw),
	}
	if _, _, err := decodeAdmittedText(pending); err == nil {
		t.Fatal("historical Event v1 was accepted as current production input")
	}
}

func TestDecoderSeparatesAuthenticatedRoomModerationFromModelText(t *testing.T) {
	pending := testModerationPending(t, "hide", 1)
	event, body, control, err := decodeAdmitted(pending)
	if err != nil || body != "" || control == nil {
		t.Fatalf("event=%+v body=%q control=%+v err=%v", event, body, control, err)
	}
	if control.DecisionEventID != event.EventID || control.RoomID != event.RoomID ||
		control.TargetEventID != "evt_"+strings.Repeat(
			"4",
			64,
		) || control.Action != "hide" || control.DecisionRevision != 1 {
		t.Fatalf("control=%+v", control)
	}
	if _, _, err := decodeAdmittedText(pending); err == nil {
		t.Fatal("moderation control was accepted as model text")
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

func testModerationPending(t *testing.T, action string, revision uint64) pendingEvent {
	t.Helper()
	roomID := "room_" + strings.Repeat("9", 64)
	content := bytes.NewBufferString(roomModerationDomain)
	writeText(content, roomID)
	writeUint64(content, 3)
	writeUint64(content, 2)
	writeText(content, "evt_"+strings.Repeat("4", 64))
	writeUint64(content, revision)
	writeText(content, action)
	writeText(content, "room policy")
	event := wireEvent{
		Schema: eventSchema, NetworkID: "tos-local", GenesisRootHash: strings.Repeat("1", 64),
		GenesisFileHash: strings.Repeat("2", 64), ConversationID: "conv_" + strings.Repeat("3", 64),
		SenderAgentID: "agent_" + strings.Repeat("a", 64), SenderEndpointID: "mep_" + strings.Repeat("b", 64),
		SenderDeviceID: "dev_" + strings.Repeat("c", 64), RoomID: roomID, CreatedAtUnix: 1_800_000_000,
		ExpiresAtUnix: 1_800_003_600, Kind: "room.moderation", PayloadSchema: roomModerationSchema,
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

func serveAttachmentInbox(t *testing.T, attachment admittedAttachment) (string, <-chan string, func()) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "attachment-runtime.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	operations := make(chan string, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		seen := make([]string, 0, 4)
		for len(seen) < 4 {
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
			case "attachments.pending":
				response.Attachments = []pendingAttachment{{
					EventID:          attachment.EventID,
					SenderEndpointID: attachment.SenderEndpointID, ConversationID: attachment.ConversationID,
					ReceivedAtUnix: attachment.ReceivedAtUnix,
				}}
			case "attachments.claim":
				response.Attachment = &attachment
			}
			encoded, _ := json.Marshal(response)
			binary.BigEndian.PutUint32(header[:], uint32(len(encoded)))
			_, _ = connection.Write(header[:])
			_, _ = connection.Write(encoded)
			_ = connection.Close()
		}
		operations <- strings.Join(seen, ",")
	}()
	return path, operations, func() { _ = listener.Close(); <-done }
}

func serveInboxRequests(t *testing.T, pending pendingEvent) (string, <-chan string, func()) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "runtime-requests.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	requests := make(chan string, 8)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
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
			requests <- request.Op
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
	}()
	return path, requests, func() {
		_ = listener.Close()
		<-done
	}
}

func serveCompose(t *testing.T, count int) (string, <-chan localRequest, func()) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "runtime.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	requests := make(chan localRequest, count)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for index := 0; index < count; index++ {
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
			requests <- request
			response := localResponse{
				Schema: responseSchema, OK: true,
				Fresh: index == 0, EventID: "evt_" + strings.Repeat("d", 64),
			}
			body, _ := json.Marshal(response)
			binary.BigEndian.PutUint32(header[:], uint32(len(body)))
			_, _ = connection.Write(header[:])
			_, _ = connection.Write(body)
			_ = connection.Close()
		}
	}()
	return path, requests, func() { _ = listener.Close(); <-done }
}

func serveAttachmentOutbox(t *testing.T) (string, <-chan localRequest, func()) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "runtime.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	requests := make(chan localRequest, 6)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for index := 0; index < 6; index++ {
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
			requests <- request
			response := localResponse{Schema: responseSchema, OK: true}
			switch index {
			case 0:
				response.UploadID = "attup_" + strings.Repeat("b", 64)
			case 1, 2:
				response.UploadID = "attup_" + strings.Repeat("b", 64)
				response.NextChunk = uint32(index)
			case 3:
				response.UploadID = "attup_" + strings.Repeat("b", 64)
				response.NextChunk = 1
			case 4, 5:
				response.Complete = true
				response.EventID = "evt_" + strings.Repeat("d", 64)
			}
			body, _ := json.Marshal(response)
			binary.BigEndian.PutUint32(header[:], uint32(len(body)))
			_, _ = connection.Write(header[:])
			_, _ = connection.Write(body)
			_ = connection.Close()
		}
	}()
	return path, requests, func() { _ = listener.Close(); <-done }
}
