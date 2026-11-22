package servicebridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
)

// Chat is the relay lane of an OpenFox rail node: it handles the chat
// section of the node configuration and opens the chat carrier on the
// node's relay carrier.
func init() {
	RegisterRelayLane(chatLaneHandler{})
}

// relayChatKeySchema is the key file schema of the chat key set.
const relayChatKeySchema = "tos.openfox.relay-chat-key.v1"

// Relay frame kinds of the chat journal: records carry kinds up to the
// evidence kind, and an unreadable record counts as a room frame, the kind
// with the tighter per-peer cap.
const (
	chatMaxFrameKind        = relayframe.KindEvidence
	chatUnreadableFrameKind = relayframe.KindRoom
)

// OpenChatRelayKeys opens the chat key set: its own directory and its own
// key file schema, never derived from or shared with the rail keys.
func OpenChatRelayKeys(directory, agentID string, relays []string, signer cardSigner,
	now func() time.Time,
) (*RelayKeys, error) {
	return OpenRelayKeysFor(directory, agentID, relays, signer, now, relayChatKeySchema)
}

// NewChatSection wraps a chat configuration as the chat section of a node
// configuration; nil stays no section.
func NewChatSection(chat *ChatConfig) *LaneSection {
	if chat == nil {
		return nil
	}
	return &LaneSection{Value: chat}
}

// ChatSection returns the chat section of a node configuration, or nil
// when it has none.
func ChatSection(config NodeConfig) *ChatConfig {
	if config.Chat == nil {
		return nil
	}
	chat, _ := config.Chat.Value.(*ChatConfig)
	return chat
}

// ChatLaneOf returns the chat carrier of a relay carrier, or nil when it
// carries no chat.
func ChatLaneOf(carrier *RelayCarrier) *ChatCarrier {
	if carrier == nil {
		return nil
	}
	chat, _ := carrier.Lane.(*ChatCarrier)
	return chat
}

// ChatLaneOptions is what NodeOptions.Lane carries for the chat lane.
type ChatLaneOptions struct {
	// Daemon replaces the client of the Messenger carrier socket, for
	// tests.
	Daemon chatDaemon
}

// chatLaneHandler is the chat lane as the rail node sees it.
type chatLaneHandler struct{}

// DecodeSection strictly decodes a chat section.
func (chatLaneHandler) DecodeSection(raw []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var chat ChatConfig
	if err := decoder.Decode(&chat); err != nil {
		return nil, err
	}
	return &chat, nil
}

// Validate checks the chat section against the rest of the configuration.
func (chatLaneHandler) Validate(config NodeConfig) error {
	return validateChatConfig(config)
}

// OwnRelays lists the relays the chat section names itself.
func (chatLaneHandler) OwnRelays(config NodeConfig) []string {
	chat := ChatSection(config)
	if chat == nil {
		return nil
	}
	return chat.RelayURLs
}

// InitSection fills the socket and card paths `init` leaves empty with
// their defaults below the state directory.
func (chatLaneHandler) InitSection(section *LaneSection, stateDir string) *LaneSection {
	var chat ChatConfig
	if section != nil {
		if given, ok := section.Value.(*ChatConfig); ok && given != nil {
			chat = *given
		}
	}
	if chat.CarrierSocket == "" {
		chat.CarrierSocket = filepath.Join(stateDir, "chat-carrier.sock")
	}
	if chat.CardPath == "" {
		chat.CardPath = filepath.Join(stateDir, relayStateDir, "chat-card.json")
	}
	return NewChatSection(&chat)
}

// InitNextStep is the step that follows `init` for a node with chat.
func (chatLaneHandler) InitNextStep(railConfigPath string) string {
	return "chat: openfox earning chat init --rail-config " + railConfigPath + " (issues the chat key and card)"
}

// Opener prepares the chat lane of a node: its relays, the client of the
// Messenger carrier socket and the card lifetime.
func (chatLaneHandler) Opener(config NodeConfig, signer *PacketSigner, options any) (RelayLaneOpener, error) {
	chat := ChatSection(config)
	if chat == nil {
		return nil, errChatInvalidLane
	}
	relays, err := chatRelays(config)
	if err != nil {
		return nil, err
	}
	timeout, err := chat.timeout()
	if err != nil {
		return nil, err
	}
	var daemon chatDaemon
	if given, ok := options.(ChatLaneOptions); ok {
		daemon = given.Daemon
	}
	if daemon == nil {
		client, clientErr := carrierapi.NewClient(chat.MessengerCarrierSocket, timeout)
		if clientErr != nil {
			return nil, fmt.Errorf("servicebridge: the Messenger carrier socket: %w", clientErr)
		}
		daemon = client
	}
	lifetime, err := chat.cardLifetime()
	if err != nil {
		return nil, err
	}
	lane := chatLaneConfig{
		Relays: relays, CardPath: chat.CardPath, Signer: signer, Daemon: daemon, Timeout: timeout,
		CardLifetime: lifetime,
	}
	return lane.open, nil
}

// open opens the chat carrier on a relay carrier.
func (l chatLaneConfig) open(env RelayLaneEnv) (RelayLane, error) {
	chat, err := openChatCarrier(env.Root, env.AgentID, l, env.Verifier, env.Agents, env.pool, env.Now, env.Report)
	if err != nil {
		return nil, err
	}
	return chat, nil
}

// Preflight runs the chat checks.
func (chatLaneHandler) Preflight(p *preflight) {
	p.checkChat()
}

// ReadOutbox lists the chat envelope journal.
func (chatLaneHandler) ReadOutbox(relayRoot string) ([]RelayOutboxView, error) {
	return ReadChatOutbox(filepath.Join(relayRoot, relayChatOutboxDir))
}

// CheckStatus strictly decodes the chat part of a relay status file.
func (chatLaneHandler) CheckStatus(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var status ChatStatus
	if err := decoder.Decode(&status); err != nil {
		return errors.New("servicebridge: the chat part of the relay status does not decode")
	}
	return nil
}

// ReadChatOutbox lists a chat envelope journal without taking ownership of
// it.
func ReadChatOutbox(directory string) ([]RelayOutboxView, error) {
	return ReadRelayOutboxOfKinds(directory, chatMaxFrameKind)
}

// LaneKeys implements RelayLane.
func (c *ChatCarrier) LaneKeys() *RelayKeys { return c.Keys }

// LaneTransport implements RelayLane.
func (c *ChatCarrier) LaneTransport() *RelayTransport { return c.Transport }

// Receive implements RelayLane: a packet opened under a chat key must carry
// a relay frame and goes to the daemon only.
func (c *ChatCarrier) Receive(ctx context.Context, packetJSON []byte) bool {
	return c.receive(ctx, packetJSON)
}

// LaneStatus implements RelayLane.
func (c *ChatCarrier) LaneStatus() any { return c.status() }

// PeerEnvelopeCount is what the envelope journal says a relay may still
// hold for one peer: every chat envelope and the kind-3 ones among them,
// beside their caps. It counts from the journal alone; the carrier also
// drops envelopes no relay lists any more when a count reaches its cap.
type PeerEnvelopeCount struct {
	AgentID           string `json:"agent_id"`
	Envelopes         int    `json:"envelopes"`
	EnvelopeCap       int    `json:"envelope_cap"`
	RoomEnvelopes     int    `json:"room_envelopes"`
	RoomEnvelopeCap   int    `json:"room_envelope_cap"`
	UnreadableCounted int    `json:"unreadable_counted,omitempty"`
}

// ReadPeerEnvelopeCounts counts a journal's stored envelopes per peer
// without taking ownership of it or moving anything: an unreadable record
// counts once for every peer, as the carrier counts it.
func ReadPeerEnvelopeCounts(directory string, now time.Time) ([]PeerEnvelopeCount, error) {
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("servicebridge: read the relay envelope journal")
	}
	reader := &RelayTransport{directory: directory, maxFrameKind: chatMaxFrameKind}
	at := uint64(0)
	if unix := now.Unix(); unix > 0 {
		at = uint64(unix)
	}
	counts := map[string]*PeerEnvelopeCount{}
	unreadable := 0
	for _, entry := range entries {
		if !relayOutboxFilePattern.MatchString(entry.Name()) {
			continue
		}
		record, found, err := reader.load(filepath.Join(directory, entry.Name()))
		if err != nil {
			unreadable++
			continue
		}
		if !found {
			continue
		}
		stored := record.storedEnvelopes(at)
		if len(stored) == 0 {
			continue
		}
		count := counts[record.Recipient]
		if count == nil {
			count = &PeerEnvelopeCount{AgentID: record.Recipient}
			counts[record.Recipient] = count
		}
		for _, envelope := range stored {
			count.Envelopes++
			if envelope.FrameKind == relayframe.KindRoom {
				count.RoomEnvelopes++
			}
		}
	}
	agents := make([]string, 0, len(counts))
	for agent := range counts {
		agents = append(agents, agent)
	}
	slices.Sort(agents)
	out := make([]PeerEnvelopeCount, 0, len(agents))
	for _, agent := range agents {
		count := *counts[agent]
		count.Envelopes, count.RoomEnvelopes = count.Envelopes+unreadable, count.RoomEnvelopes+unreadable
		count.EnvelopeCap, count.RoomEnvelopeCap = ChatPeerEnvelopeCap, ChatPeerRoomEnvelopeCap
		count.UnreadableCounted = unreadable
		out = append(out, count)
	}
	return out, nil
}
