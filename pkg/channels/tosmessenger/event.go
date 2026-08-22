package tosmessenger

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/tosnetwork/openfox/pkg/bus"
)

const (
	eventSchema          = "tos.messaging.event.v2"
	eventDomain          = "tos.messaging.event-id.v2\x00"
	textSchema           = "tos.messaging.payload.text.v1"
	textDomain           = "tos.messaging.payload.v1\x00" + textSchema + "\x00"
	roomMessageSchema    = "tos.messaging.payload.room-message.v1"
	roomMessageDomain    = "tos.messaging.payload.v1\x00" + roomMessageSchema + "\x00"
	roomModerationSchema = "tos.messaging.payload.room-moderation.v1"
	roomModerationDomain = "tos.messaging.payload.v1\x00" + roomModerationSchema + "\x00"
)

var (
	agentPattern           = regexp.MustCompile(`^agent_[0-9a-f]{64}$`)
	endpointPattern        = regexp.MustCompile(`^mep_[0-9a-f]{64}$`)
	devicePattern          = regexp.MustCompile(`^dev_[0-9a-f]{64}$`)
	eventPattern           = regexp.MustCompile(`^evt_[0-9a-f]{64}$`)
	conversationPattern    = regexp.MustCompile(`^conv_[0-9a-f]{64}$`)
	roomPattern            = regexp.MustCompile(`^room_[0-9a-f]{64}$`)
	hashPattern            = regexp.MustCompile(`^[0-9a-f]{64}$`)
	digestPattern          = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	scannerIDPattern       = regexp.MustCompile(`^[a-z][a-z0-9.-]{0,63}$`)
	scannerResourcePattern = regexp.MustCompile(`^[a-z][a-z0-9.-]{0,63}$`)
)

type wireEvent struct {
	Schema               string   `json:"schema"`
	NetworkID            string   `json:"network_id"`
	GenesisRootHash      string   `json:"genesis_root_hash"`
	GenesisFileHash      string   `json:"genesis_file_hash"`
	ConversationID       string   `json:"conversation_id"`
	EventID              string   `json:"event_id"`
	SenderAgentID        string   `json:"sender_agent_id"`
	SenderEndpointID     string   `json:"sender_messaging_endpoint_id"`
	SenderDeviceID       string   `json:"sender_device_id"`
	RoomID               string   `json:"room_id,omitempty"`
	ThreadID             string   `json:"thread_id,omitempty"`
	ReplyToEventID       string   `json:"reply_to_event_id,omitempty"`
	CausalParents        []string `json:"causal_parents,omitempty"`
	CreatedAtUnix        uint64   `json:"created_at_unix"`
	ExpiresAtUnix        uint64   `json:"expires_at_unix,omitempty"`
	Kind                 string   `json:"event_kind"`
	PayloadSchema        string   `json:"payload_schema"`
	IdempotencyKey       string   `json:"idempotency_key,omitempty"`
	ContentBase64        string   `json:"content_base64,omitempty"`
	Rendering            string   `json:"rendering,omitempty"`
	AttachmentReferences []string `json:"attachment_references,omitempty"`
	ServiceBinding       string   `json:"service_binding,omitempty"`
}

func decodeAdmittedText(pending pendingEvent) (wireEvent, string, error) {
	event, body, moderation, err := decodeAdmitted(pending)
	if err == nil && moderation != nil {
		return wireEvent{}, "", errors.New("admitted event is a moderation control")
	}
	return event, body, err
}

func decodeAdmitted(pending pendingEvent) (wireEvent, string, *bus.RoomModerationControl, error) {
	decoder := json.NewDecoder(bytes.NewReader(pending.Event))
	decoder.DisallowUnknownFields()
	var event wireEvent
	if err := decoder.Decode(&event); err != nil {
		return wireEvent{}, "", nil, errors.New("decode admitted Messaging Event")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return wireEvent{}, "", nil, errors.New("admitted Messaging Event has trailing JSON")
	}
	if event.Schema != eventSchema ||
		event.Kind != "text" && event.Kind != "room.message" && event.Kind != "room.moderation" ||
		event.Kind == "text" && event.PayloadSchema != textSchema ||
		event.Kind == "room.message" && event.PayloadSchema != roomMessageSchema ||
		event.Kind == "room.moderation" && event.PayloadSchema != roomModerationSchema {
		return wireEvent{}, "", nil, errors.New(
			"production OpenFox channel accepts only typed text, room.message, and room.moderation events",
		)
	}
	if event.EventID != pending.EventID || event.SenderEndpointID != pending.SenderEndpointID ||
		event.ConversationID != pending.ConversationID || pending.ReceivedAtUnix == 0 {
		return wireEvent{}, "", nil, errors.New("daemon inbox metadata does not match its Messaging Event")
	}
	if !eventPattern.MatchString(event.EventID) || !agentPattern.MatchString(event.SenderAgentID) ||
		!endpointPattern.MatchString(event.SenderEndpointID) || !devicePattern.MatchString(event.SenderDeviceID) ||
		!conversationPattern.MatchString(event.ConversationID) || !hashPattern.MatchString(event.GenesisRootHash) ||
		!hashPattern.MatchString(event.GenesisFileHash) || event.NetworkID == "" || len(event.NetworkID) > 128 ||
		event.CreatedAtUnix == 0 || event.ExpiresAtUnix != 0 && event.ExpiresAtUnix <= event.CreatedAtUnix ||
		event.RoomID != "" && !roomPattern.MatchString(event.RoomID) || len(event.CausalParents) > 32 ||
		len(event.AttachmentReferences) > 32 {
		return wireEvent{}, "", nil, errors.New("invalid admitted Messaging Event fields")
	}
	for _, parent := range event.CausalParents {
		if !eventPattern.MatchString(parent) {
			return wireEvent{}, "", nil, errors.New("invalid admitted Messaging Event parent")
		}
	}
	content, err := base64.StdEncoding.Strict().DecodeString(event.ContentBase64)
	if err != nil || len(content) == 0 || len(content) > 128<<10 {
		return wireEvent{}, "", nil, errors.New("invalid admitted Messaging Event content")
	}
	if deriveEventID(event, content) != event.EventID {
		return wireEvent{}, "", nil, errors.New("admitted Messaging Event ID does not match its content")
	}
	var body string
	if event.Kind == "text" {
		body, err = decodeTextPayload(content)
	} else if event.Kind == "room.message" {
		body, err = decodeRoomMessagePayload(content, event.RoomID)
	} else {
		var moderation bus.RoomModerationControl
		moderation, err = decodeRoomModerationPayload(content, event.RoomID, event.EventID)
		if err != nil {
			return wireEvent{}, "", nil, err
		}
		return event, "", &moderation, nil
	}
	if err != nil {
		return wireEvent{}, "", nil, err
	}
	return event, body, nil, nil
}

func decodeRoomModerationPayload(
	content []byte,
	eventRoomID, decisionEventID string,
) (bus.RoomModerationControl, error) {
	reader := &canonicalReader{raw: content}
	if string(reader.take(len(roomModerationDomain))) != roomModerationDomain {
		return bus.RoomModerationControl{}, errors.New("room moderation payload is outside its canonical domain")
	}
	control := bus.RoomModerationControl{RoomID: reader.text(512)}
	membershipEpoch := reader.uint64()
	rolePolicyRevision := reader.uint64()
	control.TargetEventID = reader.text(512)
	control.DecisionRevision = reader.uint64()
	control.Action = reader.text(512)
	control.Reason = reader.text(512)
	control.DecisionEventID = decisionEventID
	if reader.err != nil || reader.offset != len(content) || control.RoomID != eventRoomID ||
		!roomPattern.MatchString(control.RoomID) || !eventPattern.MatchString(control.TargetEventID) ||
		membershipEpoch == 0 || rolePolicyRevision == 0 || control.DecisionRevision == 0 ||
		control.Action != "hide" && control.Action != "restore" ||
		control.Reason == "" || strings.ContainsAny(control.Reason, "\x00\r") {
		return bus.RoomModerationControl{}, errors.New("invalid canonical room moderation payload")
	}
	return control, nil
}

func decodeRoomMessagePayload(content []byte, eventRoomID string) (string, error) {
	reader := &canonicalReader{raw: content}
	if string(reader.take(len(roomMessageDomain))) != roomMessageDomain {
		return "", errors.New("room message payload is outside its canonical domain")
	}
	roomID := reader.text(512)
	epoch := reader.uint64()
	mediaType := reader.text(512)
	body := reader.text(128 << 10)
	if reader.err != nil || reader.offset != len(content) || !roomPattern.MatchString(roomID) ||
		roomID != eventRoomID || epoch == 0 ||
		mediaType != "text/plain; charset=utf-8" && mediaType != "text/markdown" ||
		body == "" || strings.ContainsAny(body, "\x00\r") {
		return "", errors.New("invalid canonical room message payload")
	}
	return body, nil
}

func deriveEventID(event wireEvent, content []byte) string {
	buffer := bytes.NewBufferString(eventDomain)
	for _, value := range []string{eventSchema, event.NetworkID} {
		writeText(buffer, value)
	}
	root, rootErr := hex.DecodeString(event.GenesisRootHash)
	file, fileErr := hex.DecodeString(event.GenesisFileHash)
	if rootErr != nil || fileErr != nil || len(root) != 32 || len(file) != 32 {
		return ""
	}
	writeBytes(buffer, root)
	writeBytes(buffer, file)
	for _, value := range []string{
		event.ConversationID, event.SenderAgentID, event.SenderEndpointID, event.SenderDeviceID,
		event.RoomID, event.ThreadID, event.ReplyToEventID,
	} {
		writeText(buffer, value)
	}
	writeUint32(buffer, uint32(len(event.CausalParents)))
	for _, parent := range event.CausalParents {
		writeText(buffer, parent)
	}
	writeUint64(buffer, event.CreatedAtUnix)
	writeUint64(buffer, event.ExpiresAtUnix)
	for _, value := range []string{event.Kind, event.PayloadSchema, event.IdempotencyKey} {
		writeText(buffer, value)
	}
	writeBytes(buffer, content)
	writeText(buffer, event.Rendering)
	writeUint32(buffer, uint32(len(event.AttachmentReferences)))
	for _, reference := range event.AttachmentReferences {
		writeText(buffer, reference)
	}
	writeText(buffer, event.ServiceBinding)
	sum := sha256.Sum256(buffer.Bytes())
	return "evt_" + hex.EncodeToString(sum[:])
}

func decodeTextPayload(content []byte) (string, error) {
	reader := &canonicalReader{raw: content}
	if string(reader.take(len(textDomain))) != textDomain {
		return "", errors.New("text payload is outside its canonical domain")
	}
	mediaType := reader.text(512)
	body := reader.text(128 << 10)
	reply := reader.text(512)
	if reader.err != nil || reader.offset != len(content) ||
		mediaType != "text/plain; charset=utf-8" && mediaType != "text/markdown" || body == "" ||
		strings.ContainsAny(body, "\x00\r") || reply != "" && !eventPattern.MatchString(reply) {
		return "", errors.New("invalid canonical text payload")
	}
	return body, nil
}

type canonicalReader struct {
	raw    []byte
	offset int
	err    error
}

func (r *canonicalReader) take(count int) []byte {
	if r.err != nil || count < 0 || r.offset+count > len(r.raw) {
		r.err = errors.New("canonical value exceeds its input")
		return nil
	}
	value := r.raw[r.offset : r.offset+count]
	r.offset += count
	return value
}

func (r *canonicalReader) text(maximum int) string {
	header := r.take(4)
	if header == nil {
		return ""
	}
	length := int(binary.BigEndian.Uint32(header))
	if length > maximum {
		r.err = errors.New("canonical text exceeds its bound")
		return ""
	}
	raw := r.take(length)
	if raw == nil || !utf8.Valid(raw) {
		r.err = errors.New("canonical text is not UTF-8")
		return ""
	}
	return string(raw)
}

func (r *canonicalReader) uint64() uint64 {
	raw := r.take(8)
	if raw == nil {
		return 0
	}
	return binary.BigEndian.Uint64(raw)
}

func writeText(buffer *bytes.Buffer, value string) {
	writeBytes(buffer, []byte(value))
}

func writeBytes(buffer *bytes.Buffer, value []byte) {
	writeUint32(buffer, uint32(len(value)))
	buffer.Write(value)
}

func writeUint32(buffer *bytes.Buffer, value uint32) {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], value)
	buffer.Write(raw[:])
}

func writeUint64(buffer *bytes.Buffer, value uint64) {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], value)
	buffer.Write(raw[:])
}
