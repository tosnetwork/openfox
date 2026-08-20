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
)

const (
	eventSchema = "tos.messaging.event.v1"
	eventDomain = "tos.messaging.event-id.v1\x00"
	textSchema  = "tos.messaging.payload.text.v1"
	textDomain  = "tos.messaging.payload.v1\x00" + textSchema + "\x00"
)

var (
	agentPattern        = regexp.MustCompile(`^agent_[0-9a-f]{64}$`)
	endpointPattern     = regexp.MustCompile(`^mep_[0-9a-f]{64}$`)
	devicePattern       = regexp.MustCompile(`^dev_[0-9a-f]{64}$`)
	eventPattern        = regexp.MustCompile(`^evt_[0-9a-f]{64}$`)
	conversationPattern = regexp.MustCompile(`^conv_[0-9a-f]{64}$`)
	roomPattern         = regexp.MustCompile(`^room_[0-9a-f]{64}$`)
	hashPattern         = regexp.MustCompile(`^[0-9a-f]{64}$`)
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
	decoder := json.NewDecoder(bytes.NewReader(pending.Event))
	decoder.DisallowUnknownFields()
	var event wireEvent
	if err := decoder.Decode(&event); err != nil {
		return wireEvent{}, "", errors.New("decode admitted Messaging Event")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return wireEvent{}, "", errors.New("admitted Messaging Event has trailing JSON")
	}
	if event.Schema != eventSchema || event.Kind != "text" || event.PayloadSchema != textSchema {
		return wireEvent{}, "", errors.New("production OpenFox channel accepts only text events")
	}
	if event.EventID != pending.EventID || event.SenderEndpointID != pending.SenderEndpointID ||
		event.ConversationID != pending.ConversationID || pending.ReceivedAtUnix == 0 {
		return wireEvent{}, "", errors.New("daemon inbox metadata does not match its Messaging Event")
	}
	if !eventPattern.MatchString(event.EventID) || !agentPattern.MatchString(event.SenderAgentID) ||
		!endpointPattern.MatchString(event.SenderEndpointID) || !devicePattern.MatchString(event.SenderDeviceID) ||
		!conversationPattern.MatchString(event.ConversationID) || !hashPattern.MatchString(event.GenesisRootHash) ||
		!hashPattern.MatchString(event.GenesisFileHash) || event.NetworkID == "" || len(event.NetworkID) > 128 ||
		event.CreatedAtUnix == 0 || event.ExpiresAtUnix != 0 && event.ExpiresAtUnix <= event.CreatedAtUnix ||
		event.RoomID != "" && !roomPattern.MatchString(event.RoomID) || len(event.CausalParents) > 32 ||
		len(event.AttachmentReferences) > 32 {
		return wireEvent{}, "", errors.New("invalid admitted Messaging Event fields")
	}
	for _, parent := range event.CausalParents {
		if !eventPattern.MatchString(parent) {
			return wireEvent{}, "", errors.New("invalid admitted Messaging Event parent")
		}
	}
	content, err := base64.StdEncoding.Strict().DecodeString(event.ContentBase64)
	if err != nil || len(content) == 0 || len(content) > 128<<10 {
		return wireEvent{}, "", errors.New("invalid admitted Messaging Event content")
	}
	if deriveEventID(event, content) != event.EventID {
		return wireEvent{}, "", errors.New("admitted Messaging Event ID does not match its content")
	}
	body, err := decodeTextPayload(content)
	if err != nil {
		return wireEvent{}, "", err
	}
	return event, body, nil
}

func deriveEventID(event wireEvent, content []byte) string {
	buffer := bytes.NewBufferString(eventDomain)
	for _, value := range []string{
		eventSchema, event.NetworkID, event.GenesisRootHash, event.GenesisFileHash,
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
