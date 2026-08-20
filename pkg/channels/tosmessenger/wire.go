package tosmessenger

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	requestSchema  = "tos.messaging.local-request.v2"
	responseSchema = "tos.messaging.local-response.v1"
	maxFrameBytes  = 512 << 10
)

type localRequest struct {
	Schema       string `json:"schema"`
	Op           string `json:"op"`
	EventID      string `json:"event_id,omitempty"`
	LeaseID      string `json:"lease_id,omitempty"`
	LeaseSeconds uint64 `json:"lease_seconds,omitempty"`
	Code         string `json:"code,omitempty"`
	Limit        int    `json:"limit,omitempty"`
}

type pendingEvent struct {
	EventID          string          `json:"event_id"`
	SenderEndpointID string          `json:"sender_messaging_endpoint_id"`
	ConversationID   string          `json:"conversation_id"`
	ReceivedAtUnix   uint64          `json:"received_at_unix"`
	Event            json.RawMessage `json:"event"`
}

type localResponse struct {
	Schema string         `json:"schema"`
	OK     bool           `json:"ok"`
	Code   string         `json:"code,omitempty"`
	Detail string         `json:"detail,omitempty"`
	Events []pendingEvent `json:"events,omitempty"`
	Event  *pendingEvent  `json:"claimed,omitempty"`
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
