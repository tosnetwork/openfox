package tosmessenger

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	requestSchema  = "tos.messaging.local-request.v8"
	responseSchema = "tos.messaging.local-response.v5"
	maxFrameBytes  = 2 << 20
)

type localRequest struct {
	Schema              string `json:"schema"`
	Op                  string `json:"op"`
	EventID             string `json:"event_id,omitempty"`
	LeaseID             string `json:"lease_id,omitempty"`
	LeaseSeconds        uint64 `json:"lease_seconds,omitempty"`
	Code                string `json:"code,omitempty"`
	Limit               int    `json:"limit,omitempty"`
	ConversationID      string `json:"conversation_id,omitempty"`
	RoomID              string `json:"room_id,omitempty"`
	ReplyToEventID      string `json:"reply_to_event_id,omitempty"`
	MembershipEpoch     uint64 `json:"membership_epoch,omitempty"`
	MediaType           string `json:"media_type,omitempty"`
	Body                string `json:"body,omitempty"`
	IdempotencyKey      string `json:"idempotency_key,omitempty"`
	SessionID           string `json:"session_id,omitempty"`
	RecipientEndpointID string `json:"recipient_endpoint_id,omitempty"`
	RecipientAgentID    string `json:"recipient_agent_id,omitempty"`
	Recipient           string `json:"recipient,omitempty"`
	ExpiresAtUnix       uint64 `json:"expires_at_unix,omitempty"`
	Filename            string `json:"filename,omitempty"`
	PlaintextDigest     string `json:"plaintext_digest,omitempty"`
	PlaintextBytes      uint64 `json:"plaintext_bytes,omitempty"`
	UploadID            string `json:"upload_id,omitempty"`
	ChunkIndex          uint32 `json:"chunk_index,omitempty"`
	Chunk               []byte `json:"chunk_base64,omitempty"`
}

type pendingEvent struct {
	EventID          string          `json:"event_id"`
	SenderEndpointID string          `json:"sender_messaging_endpoint_id"`
	ConversationID   string          `json:"conversation_id"`
	ReceivedAtUnix   uint64          `json:"received_at_unix"`
	Event            json.RawMessage `json:"event"`
}

type pendingAttachment struct {
	EventID          string `json:"event_id"`
	SenderEndpointID string `json:"sender_messaging_endpoint_id"`
	ConversationID   string `json:"conversation_id"`
	ReceivedAtUnix   uint64 `json:"received_at_unix"`
}

type attachmentScan struct {
	ScannerID     string                   `json:"scanner_id"`
	ScannerDigest string                   `json:"scanner_digest"`
	Resources     []attachmentScanResource `json:"resources,omitempty"`
}

type attachmentScanResource struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
}

type admittedAttachment struct {
	EventID          string           `json:"event_id"`
	SenderAgentID    string           `json:"sender_agent_id"`
	SenderEndpointID string           `json:"sender_messaging_endpoint_id"`
	SenderDeviceID   string           `json:"sender_device_id"`
	ConversationID   string           `json:"conversation_id"`
	RoomID           string           `json:"room_id,omitempty"`
	ReplyToEventID   string           `json:"reply_to_event_id,omitempty"`
	ReceivedAtUnix   uint64           `json:"received_at_unix"`
	Filename         string           `json:"filename"`
	MediaType        string           `json:"media_type"`
	PlaintextDigest  string           `json:"plaintext_digest"`
	SizeBytes        uint64           `json:"size_bytes"`
	Body             string           `json:"body"`
	Scans            []attachmentScan `json:"scans"`
}

type localResponse struct {
	Schema        string              `json:"schema"`
	OK            bool                `json:"ok"`
	Code          string              `json:"code,omitempty"`
	Detail        string              `json:"detail,omitempty"`
	Events        []pendingEvent      `json:"events,omitempty"`
	Event         *pendingEvent       `json:"claimed,omitempty"`
	Attachments   []pendingAttachment `json:"attachments,omitempty"`
	Attachment    *admittedAttachment `json:"attachment,omitempty"`
	Fresh         bool                `json:"fresh,omitempty"`
	EventID       string              `json:"event_id,omitempty"`
	UploadID      string              `json:"upload_id,omitempty"`
	NextChunk     uint32              `json:"next_chunk,omitempty"`
	Complete      bool                `json:"complete,omitempty"`
	AgentID       string              `json:"agent_id,omitempty"`
	CanonicalName string              `json:"canonical_name,omitempty"`
}

func validPendingAttachment(value pendingAttachment) bool {
	return eventPattern.MatchString(value.EventID) && endpointPattern.MatchString(value.SenderEndpointID) &&
		conversationPattern.MatchString(value.ConversationID) && value.ReceivedAtUnix != 0
}

func validAdmittedAttachment(value admittedAttachment) bool {
	digest := sha256.Sum256([]byte(value.Body))
	exactDigest := "sha256:" + hex.EncodeToString(digest[:])
	if !eventPattern.MatchString(value.EventID) || !agentPattern.MatchString(value.SenderAgentID) ||
		!endpointPattern.MatchString(value.SenderEndpointID) || !devicePattern.MatchString(value.SenderDeviceID) ||
		!conversationPattern.MatchString(value.ConversationID) || value.ReceivedAtUnix == 0 ||
		value.RoomID != "" && !roomPattern.MatchString(value.RoomID) ||
		value.ReplyToEventID != "" && !eventPattern.MatchString(value.ReplyToEventID) ||
		value.Filename == "" || len(value.Filename) > 255 || strings.TrimSpace(value.Filename) != value.Filename ||
		strings.ContainsAny(value.Filename, "/\\\x00\r\n") || value.MediaType != "text/plain" ||
		!digestPattern.MatchString(value.PlaintextDigest) || value.PlaintextDigest != exactDigest ||
		value.SizeBytes == 0 || uint64(len(value.Body)) != value.SizeBytes ||
		value.Body == "" || !utf8.ValidString(value.Body) || strings.ContainsAny(value.Body, "\x00\r") ||
		len(value.Scans) == 0 || len(value.Scans) > 4 {
		return false
	}
	previous := ""
	for _, scan := range value.Scans {
		if !scannerIDPattern.MatchString(scan.ScannerID) || scan.ScannerID <= previous ||
			!digestPattern.MatchString(scan.ScannerDigest) || len(scan.Resources) > 8 {
			return false
		}
		previousResource := ""
		for _, resource := range scan.Resources {
			if !scannerResourcePattern.MatchString(resource.Name) || resource.Name <= previousResource ||
				!digestPattern.MatchString(resource.Digest) {
				return false
			}
			previousResource = resource.Name
		}
		previous = scan.ScannerID
	}
	return true
}

func callLocal(ctx context.Context, socket string, timeout time.Duration, request localRequest) (localResponse, error) {
	request.Schema = requestSchema
	body, err := json.Marshal(request)
	if err != nil || len(body) == 0 || len(body) > maxFrameBytes {
		return localResponse{}, errors.New("encode Messenger inbox request")
	}
	connection, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "unix", socket)
	if err != nil {
		return localResponse{}, fmt.Errorf("connect Messenger inbox: %w", err)
	}
	defer connection.Close()
	deadline := time.Now().Add(timeout)
	if value, ok := ctx.Deadline(); ok && value.Before(deadline) {
		deadline = value
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return localResponse{}, err
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(body)))
	if err := writeAll(connection, header[:]); err != nil {
		return localResponse{}, err
	}
	if err := writeAll(connection, body); err != nil {
		return localResponse{}, err
	}
	if _, err := io.ReadFull(connection, header[:]); err != nil {
		return localResponse{}, errors.New("read Messenger inbox response header")
	}
	length := binary.BigEndian.Uint32(header[:])
	if length == 0 || length > maxFrameBytes {
		return localResponse{}, errors.New("invalid Messenger inbox response length")
	}
	raw := make([]byte, length)
	if _, err := io.ReadFull(connection, raw); err != nil {
		return localResponse{}, errors.New("read Messenger inbox response")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var response localResponse
	if err := decoder.Decode(&response); err != nil {
		return localResponse{}, errors.New("decode Messenger inbox response")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return localResponse{}, errors.New("Messenger inbox response has trailing JSON")
	}
	if response.Schema != responseSchema {
		return localResponse{}, errors.New("unsupported Messenger inbox response schema")
	}
	if !response.OK {
		return response, fmt.Errorf("Messenger inbox refused (%s): %s", response.Code, response.Detail)
	}
	return response, nil
}

func writeAll(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		written, err := writer.Write(value)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(value) {
			return io.ErrNoProgress
		}
		value = value[written:]
	}
	return nil
}
