// Package tosmessengerlab adapts the local-only Messenger group-chat
// acceptance carrier to OpenFox's native channel bus. It intentionally says
// "lab" in its public name: the socket is same-host and not a production route.
// In openmls-proxy mode the private proxy encrypts before the shared carrier.
package tosmessengerlab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/tosnetwork/openfox/pkg/bus"
	"github.com/tosnetwork/openfox/pkg/channels"
	"github.com/tosnetwork/openfox/pkg/config"
)

const (
	defaultPollInterval = 250 * time.Millisecond
	maxResponseBytes    = 256 << 10
)

var roomIDPattern = regexp.MustCompile(`^room_[0-9a-f]{64}$`)

type room struct {
	RoomID        string   `json:"room_id"`
	Label         string   `json:"label"`
	Members       []string `json:"members"`
	CreatedBy     string   `json:"created_by"`
	CreatedAtUnix uint64   `json:"created_at_unix"`
}

type message struct {
	Sequence      uint64 `json:"sequence"`
	MessageID     string `json:"message_id"`
	ClientID      string `json:"client_id"`
	RoomID        string `json:"room_id"`
	SenderAgentID string `json:"sender_agent_id"`
	Content       string `json:"content"`
	CreatedAtUnix uint64 `json:"created_at_unix"`
}

type cursorState struct {
	Schema  string            `json:"schema"`
	Cursors map[string]uint64 `json:"cursors"`
}

type pendingSend struct {
	clientID  string
	expiresAt time.Time
}

type Channel struct {
	*channels.BaseChannel
	settings *config.TOSMessengerLabSettings
	client   *http.Client
	endpoint string

	mu      sync.Mutex
	cursors map[string]uint64
	rooms   map[string]room
	pending map[[sha256.Size]byte]pendingSend
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

func New(bc *config.Channel, settings *config.TOSMessengerLabSettings, messageBus *bus.MessageBus) (*Channel, error) {
	if settings == nil || strings.TrimSpace(settings.SocketPath) == "" ||
		strings.TrimSpace(settings.CursorPath) == "" ||
		strings.TrimSpace(settings.AgentID) == "" ||
		len(settings.Token.String()) < 16 {
		return nil, errors.New(
			"tos_messenger_lab needs socket_path, cursor_path, agent_id, and a token of at least 16 bytes",
		)
	}
	interval := time.Duration(settings.PollIntervalMS) * time.Millisecond
	if interval == 0 {
		interval = defaultPollInterval
	}
	if interval < 50*time.Millisecond || interval > time.Minute {
		return nil, errors.New("tos_messenger_lab poll interval is outside 50ms..1m")
	}
	if settings.Encryption != "" && settings.Encryption != "openmls-proxy" {
		return nil, errors.New("tos_messenger_lab encryption must be empty or openmls-proxy")
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", settings.SocketPath)
	}}
	c := &Channel{
		BaseChannel: channels.NewBaseChannel(config.ChannelTOSMessengerLab, settings, messageBus, bc.AllowFrom),
		settings:    settings,
		client:      &http.Client{Transport: transport, Timeout: 10 * time.Second},
		endpoint:    "http://unix",
		cursors:     map[string]uint64{}, rooms: map[string]room{}, pending: map[[sha256.Size]byte]pendingSend{},
	}
	return c, nil
}

func (c *Channel) Start(ctx context.Context) error {
	if c.IsRunning() {
		return nil
	}
	if err := c.loadCursors(); err != nil {
		return err
	}
	for _, configured := range c.settings.Rooms {
		created, err := c.createRoom(ctx, configured)
		if err != nil {
			return fmt.Errorf("create Messenger lab room %q: %w", configured.Label, err)
		}
		c.rooms[created.RoomID] = created
	}
	rooms, err := c.listRooms(ctx)
	if err != nil {
		return err
	}
	for _, known := range rooms {
		c.rooms[known.RoomID] = known
	}
	runCtx, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	c.SetRunning(true)
	c.wg.Add(1)
	go c.poll(runCtx)
	return nil
}

func (c *Channel) Stop(context.Context) error {
	if c.cancel != nil {
		c.cancel()
	}
	c.wg.Wait()
	c.SetRunning(false)
	c.client.CloseIdleConnections()
	return nil
}

func (c *Channel) Send(ctx context.Context, outbound bus.OutboundMessage) ([]string, error) {
	if !c.IsRunning() {
		return nil, channels.ErrNotRunning
	}
	roomID := strings.TrimSpace(outbound.ChatID)
	if strings.HasPrefix(roomID, config.ChannelTOSMessengerLab+":") {
		roomID = strings.TrimPrefix(roomID, config.ChannelTOSMessengerLab+":")
	}
	c.mu.Lock()
	_, known := c.rooms[roomID]
	c.mu.Unlock()
	if !known {
		return nil, errors.New("unknown Messenger lab room")
	}
	fingerprint, err := json.Marshal(outbound)
	if err != nil {
		return nil, fmt.Errorf("fingerprint Messenger lab outbound: %w", err)
	}
	pendingKey := sha256.Sum256(fingerprint)
	clientID := c.pendingClientID(pendingKey)
	var result message
	err = c.call(
		ctx,
		http.MethodPost,
		"/v1/messages",
		map[string]string{"room_id": roomID, "client_id": clientID, "content": outbound.Content},
		&result,
	)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	if current, ok := c.pending[pendingKey]; ok && current.clientID == clientID {
		delete(c.pending, pendingKey)
	}
	c.mu.Unlock()
	return []string{result.MessageID}, nil
}

// pendingClientID gives OpenFox manager retries the same hub idempotency key.
// A successful send removes it; an ambiguous failure keeps it briefly so an
// accepted request whose response was lost cannot create a duplicate message.
func (c *Channel) pendingClientID(key [sha256.Size]byte) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for fingerprint, pending := range c.pending {
		if !pending.expiresAt.After(now) {
			delete(c.pending, fingerprint)
		}
	}
	if existing, ok := c.pending[key]; ok {
		return existing.clientID
	}
	created := pendingSend{clientID: uuid.NewString(), expiresAt: now.Add(10 * time.Minute)}
	c.pending[key] = created
	return created.clientID
}

// RoomIDs returns the rooms this channel joined. It is primarily useful to
// local acceptance tooling; normal OpenFox routing receives the room ID as its
// chat ID from an inbound message.
func (c *Channel) RoomIDs() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([]string, 0, len(c.rooms))
	for roomID := range c.rooms {
		result = append(result, roomID)
	}
	sort.Strings(result)
	return result
}

// RoomID returns the joined room matching a label and exact member set. This
// keeps acceptance tooling correct when an Agent belongs to multiple rooms.
func (c *Channel) RoomID(label string, members []string) (string, bool) {
	expected := append([]string(nil), members...)
	sort.Strings(expected)
	c.mu.Lock()
	defer c.mu.Unlock()
	for roomID, candidate := range c.rooms {
		actual := append([]string(nil), candidate.Members...)
		sort.Strings(actual)
		if candidate.Label == strings.TrimSpace(label) && slices.Equal(actual, expected) {
			return roomID, true
		}
	}
	return "", false
}

func (c *Channel) poll(ctx context.Context) {
	defer c.wg.Done()
	defer c.SetRunning(false)
	interval := time.Duration(c.settings.PollIntervalMS) * time.Millisecond
	if interval == 0 {
		interval = defaultPollInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := c.pollOnce(ctx); err != nil && ctx.Err() != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (c *Channel) pollOnce(ctx context.Context) error {
	c.mu.Lock()
	roomIDs := make([]string, 0, len(c.rooms))
	for roomID := range c.rooms {
		roomIDs = append(roomIDs, roomID)
	}
	c.mu.Unlock()
	for _, roomID := range roomIDs {
		c.mu.Lock()
		after := c.cursors[roomID]
		c.mu.Unlock()
		var response struct {
			Messages []message `json:"messages"`
		}
		path := "/v1/messages?room_id=" + url.QueryEscape(roomID) + "&after=" + strconv.FormatUint(after, 10)
		if err := c.call(ctx, http.MethodGet, path, nil, &response); err != nil {
			return err
		}
		for _, inbound := range response.Messages {
			if inbound.Sequence <= after {
				continue
			}
			if inbound.SenderAgentID != c.settings.AgentID {
				sender := bus.SenderInfo{
					Platform:    config.ChannelTOSMessengerLab,
					PlatformID:  inbound.SenderAgentID,
					CanonicalID: config.ChannelTOSMessengerLab + ":" + inbound.SenderAgentID,
				}
				inboundCtx := bus.InboundContext{
					Channel:   c.Name(),
					ChatID:    roomID,
					ChatType:  "group",
					SpaceID:   roomID,
					SpaceType: "room",
					SenderID:  sender.CanonicalID,
					MessageID: inbound.MessageID,
					Raw: map[string]string{
						"transport":    c.transportName(),
						"tos_agent_id": inbound.SenderAgentID,
					},
				}
				if err := c.HandleInboundContext(ctx, roomID, inbound.Content, nil, inboundCtx, sender); err != nil {
					return err
				}
			}
			after = inbound.Sequence
			c.mu.Lock()
			c.cursors[roomID] = after
			err := c.persistCursors()
			c.mu.Unlock()
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *Channel) transportName() string {
	if c.settings.Encryption == "openmls-proxy" {
		return "local-unix-openmls-ciphertext-relay"
	}
	return "local-unix-plaintext"
}

func (c *Channel) createRoom(ctx context.Context, configured config.TOSMessengerLabRoom) (room, error) {
	var result room
	err := c.call(
		ctx,
		http.MethodPost,
		"/v1/rooms",
		map[string]any{"label": configured.Label, "members": configured.Members},
		&result,
	)
	return result, err
}

func (c *Channel) listRooms(ctx context.Context) ([]room, error) {
	var result struct {
		Rooms []room `json:"rooms"`
	}
	err := c.call(ctx, http.MethodGet, "/v1/rooms", nil, &result)
	return result.Rooms, err
}

func (c *Channel) call(ctx context.Context, method, path string, requestBody, responseBody any) error {
	var body io.Reader
	if requestBody != nil {
		encoded, err := json.Marshal(requestBody)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.endpoint+path, body)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+c.settings.Token.String())
	request.Header.Set("X-Tos-Agent-Id", c.settings.AgentID)
	request.Header.Set("Content-Type", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if readErr != nil {
		return readErr
	}
	if len(raw) > maxResponseBytes {
		return errors.New("Messenger lab response exceeds its bound")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("Messenger lab returned %s: %s", response.Status, strings.TrimSpace(string(raw)))
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(responseBody); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("Messenger lab response has trailing JSON")
	}
	return nil
}

func (c *Channel) loadCursors() error {
	raw, err := os.ReadFile(c.settings.CursorPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read Messenger lab cursor: %w", err)
	}
	var saved cursorState
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(
		&saved,
	); err != nil || saved.Schema != "openfox.tos-messenger-lab-cursors.v1" ||
		saved.Cursors == nil {
		return errors.New("invalid Messenger lab cursor state")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("Messenger lab cursor has trailing JSON")
	}
	for roomID := range saved.Cursors {
		if !roomIDPattern.MatchString(roomID) {
			return errors.New("invalid Messenger lab room cursor")
		}
	}
	c.cursors = saved.Cursors
	return nil
}

// persistCursors is called with c.mu held.
func (c *Channel) persistCursors() error {
	encoded, marshalErr := json.Marshal(cursorState{Schema: "openfox.tos-messenger-lab-cursors.v1", Cursors: c.cursors})
	if marshalErr != nil {
		return marshalErr
	}
	dir := filepath.Dir(c.settings.CursorPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	temporary, createErr := os.CreateTemp(dir, ".messenger-cursor-*.tmp")
	if createErr != nil {
		return createErr
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, c.settings.CursorPath); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (c *Channel) ReasoningChannelID() string { return "" }
