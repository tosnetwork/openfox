package servicebridge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
)

// Layout of the chat lane below state_dir/relay. It shares nothing with the
// rail lane except the relay client pool and the poll loop.
const (
	relayChatKeysDir   = "chat-keys"
	relayChatPeersDir  = "chat-peers"
	relayChatOutboxDir = "chat-outbox"
)

// Chat carriage bounds.
const (
	// ChatPeerEnvelopeCap is the most chat envelopes this node keeps stored
	// for one peer Agent: copies of every generation not yet withdrawn,
	// evidence frames and delivery acknowledgements alike.
	ChatPeerEnvelopeCap = 24
	// maxChatGone bounds the memory of envelopes no relay lists any more.
	maxChatGone = 4096
)

// chatCapability is the zero Capability every chat packet carries: reserved,
// never finalized, so nothing resolves it.
const chatCapability = agentpacketseal.KeyCardCapability

// chatFrameDomain is the separator every relay frame starts with. A packet
// opened under a chat key must carry it; a rail packet never does.
const chatFrameDomain = "tos.messaging.relay-frame.v1\x00"

// chatAckKeyDomain derives the idempotency key of the acknowledgement of one
// copy packet from that packet's nonce, so each generation of a copy gets a
// fresh acknowledgement envelope that no tombstone suppresses.
const chatAckKeyDomain = "tos.openfox.chat-ack-idempotency.v1\x00"

// Chat carriage failures. They are fixed strings: nothing a peer, a relay or
// the Messenger daemon sent is repeated in them.
var (
	errChatNoCard      = errors.New("servicebridge: no valid chat card of the peer is held")
	errChatPeerCap     = errors.New("servicebridge: the chat envelopes stored for the peer reached their cap")
	errChatPermanent   = errors.New("servicebridge: the chat frame can never be sent")
	errChatNotOwnCard  = errors.New("servicebridge: the frame carries a card that is not a held chat card")
	errChatWrongPeer   = errors.New("servicebridge: the idempotency key is journaled for another peer")
	errChatInvalidLane = errors.New("servicebridge: invalid chat carriage configuration")
)

// ChatConfig is the chat carriage section of a node configuration: the
// Messenger daemon's relay route through this node.
type ChatConfig struct {
	// RelayURLs are the relays the chat card names and the node polls for
	// chat; empty means the rail's relay_urls.
	RelayURLs []string `json:"relay_urls,omitempty"`
	// CarrierSocket is where this node serves carrier.carry: the daemon's
	// relay_carriage.carry_socket_path.
	CarrierSocket string `json:"carrier_socket"`
	// MessengerCarrierSocket is where the daemon serves carrier.deliver and
	// carrier.delivery-ack: its relay_carriage.listen_socket_path.
	MessengerCarrierSocket string `json:"messenger_carrier_socket"`
	// CardPath is where this node republishes its current chat card: the
	// daemon's relay_carriage.card_path.
	CardPath string `json:"card_path"`
	// EvidenceExportDir is the daemon's relay_carriage.evidence_export_dir,
	// read by `chat contact export`.
	EvidenceExportDir string `json:"evidence_export_dir,omitempty"`
	// ContactDir is the daemon's discovery.contact_dir, written by `chat
	// contact import`.
	ContactDir string `json:"contact_dir,omitempty"`
	// TimeoutSeconds bounds one carrier operation in both directions, as the
	// daemon's relay_carriage.timeout_seconds does on its side: 0 means 30 s,
	// otherwise 1 to 300. Set both to the same value.
	TimeoutSeconds uint64 `json:"timeout_seconds,omitempty"`
}

// Bounds of the carrier operation timeout.
const (
	defaultChatTimeout = carrierapi.DefaultTimeout
	maxChatTimeout     = 5 * time.Minute
)

// timeout is the carrier operation bound the section names.
func (c ChatConfig) timeout() (time.Duration, error) {
	if c.TimeoutSeconds == 0 {
		return defaultChatTimeout, nil
	}
	if c.TimeoutSeconds > uint64(maxChatTimeout/time.Second) {
		return 0, errors.New("chat.timeout_seconds must be 1 to 300 (0 means 30)")
	}
	return time.Duration(c.TimeoutSeconds) * time.Second, nil
}

// chatRelays returns the chat relay list: its own, or the rail's.
func chatRelays(config NodeConfig) ([]string, error) {
	if config.Chat == nil {
		return nil, errChatInvalidLane
	}
	if len(config.Chat.RelayURLs) > 0 {
		return canonicalRelayURLs(config.Chat.RelayURLs)
	}
	return canonicalRelayURLs(config.RelayURLs)
}

// validateChatConfig checks the chat section against the rest of the node
// configuration. A node that carries chat never sends rail packets through
// the Messenger: a packet inside a copy inside a packet buys nothing and
// halves every bound.
func validateChatConfig(config NodeConfig) error {
	chat := config.Chat
	if chat == nil {
		return nil
	}
	var problems []error
	if config.MessengerSocket != "" {
		problems = append(problems, errors.New("chat carriage and messenger_socket (the Messenger packet "+
			"transport) exclude each other; remove messenger_socket"))
	}
	if len(config.RelayURLs) == 0 {
		problems = append(problems, errors.New("chat carriage needs relay_urls: it shares the relay poll loop"))
	}
	for name, path := range map[string]string{
		"chat.carrier_socket": chat.CarrierSocket, "chat.messenger_carrier_socket": chat.MessengerCarrierSocket,
		"chat.card_path": chat.CardPath,
	} {
		if !cleanAbsolute(path) {
			problems = append(problems, fmt.Errorf("%s must be an absolute clean path", name))
		}
	}
	for name, path := range map[string]string{
		"chat.evidence_export_dir": chat.EvidenceExportDir, "chat.contact_dir": chat.ContactDir,
	} {
		if path != "" && !cleanAbsolute(path) {
			problems = append(problems, fmt.Errorf("%s must be an absolute clean path", name))
		}
	}
	for name, path := range map[string]string{
		"chat.carrier_socket": chat.CarrierSocket, "chat.messenger_carrier_socket": chat.MessengerCarrierSocket,
	} {
		if len(path) > maxUnixSocketPath {
			problems = append(problems, fmt.Errorf("%s exceeds %d bytes", name, maxUnixSocketPath))
		}
	}
	if chat.CarrierSocket != "" && (chat.CarrierSocket == chat.MessengerCarrierSocket ||
		chat.CarrierSocket == config.ReceiverSocket || chat.MessengerCarrierSocket == config.ReceiverSocket) {
		problems = append(problems, errors.New("chat.carrier_socket, chat.messenger_carrier_socket and "+
			"receiver_socket must be three different sockets"))
	}
	if len(chat.RelayURLs) > 0 {
		if _, err := canonicalRelayURLs(chat.RelayURLs); err != nil {
			problems = append(problems, err)
		}
	}
	if _, err := chat.timeout(); err != nil {
		problems = append(problems, err)
	}
	if len(problems) > 0 {
		return fmt.Errorf("servicebridge: chat configuration: %w", errors.Join(problems...))
	}
	return nil
}

// chatDaemon is the Messenger daemon's side of the carrier boundary;
// *carrierapi.Client is the production one.
type chatDaemon interface {
	Deliver(ctx context.Context, packetSenderAgentID string, frame []byte) (carrierapi.Response, error)
	DeliveryAck(ctx context.Context, packetSenderAgentID string, frame []byte) (carrierapi.Response, error)
}

// chatLaneConfig opens the chat lane of a relay carrier.
type chatLaneConfig struct {
	Relays   []string
	CardPath string
	Signer   *PacketSigner
	Daemon   chatDaemon
	// Timeout bounds one carrier.carry the server handles; zero is 30 s.
	Timeout time.Duration
}

// ChatCarrier carries Messenger relay frames: it serves carrier.carry,
// signs each frame into an Agent Packet with the zero Capability, seals it
// to the peer's chat card and deposits it through its own RelayTransport,
// and hands every frame that opens under a chat key to the daemon. It never
// sees Messenger plaintext, keys or session state.
type ChatCarrier struct {
	agentID   string
	Keys      *RelayKeys
	Cards     *PeerCards
	Transport *RelayTransport
	signer    *PacketSigner
	daemon    chatDaemon
	verifier  mldsa44.Verifier
	agents    agentpacket.AgentResolver
	pool      *relayPool
	cardPath  string
	timeout   time.Duration
	now       func() time.Time
	report    func(string, error)
	// peers serializes the cap check and the deposit per peer, so two
	// frames cannot both take the last slot.
	peers sync.Map
	mutex sync.Mutex
	// gone remembers envelopes no relay of theirs listed any more (the peer
	// acknowledged them), until they could have expired anyway.
	gone map[[32]byte]uint64
}

// chatNoOwners refuses every Capability owner lookup: chat cards are never
// bound to a Capability.
type chatNoOwners struct{}

func (chatNoOwners) CapabilityOwner(context.Context, string) (string, error) {
	return "", fmt.Errorf("%w: chat cards are not bound to a Capability", ErrCardRefused)
}

// openChatCarrier opens the chat lane's owner-private state below root.
func openChatCarrier(root, agentID string, lane chatLaneConfig, verifier mldsa44.Verifier,
	agents agentpacket.AgentResolver, pool *relayPool, now func() time.Time, report func(string, error),
) (*ChatCarrier, error) {
	if !cleanAbsolute(root) || !agentIDPattern.MatchString(agentID) || lane.Signer == nil || lane.Daemon == nil ||
		verifier == nil || agents == nil || pool == nil || !cleanAbsolute(lane.CardPath) {
		return nil, errChatInvalidLane
	}
	if lane.Timeout == 0 {
		lane.Timeout = defaultChatTimeout
	}
	if lane.Timeout < time.Second || lane.Timeout > maxChatTimeout {
		return nil, errors.New("servicebridge: the chat carrier timeout is outside 1 s to 300 s")
	}
	if lane.Signer.AgentID != agentID {
		return nil, errors.New("servicebridge: the chat signer signs for another Agent")
	}
	if now == nil {
		now = time.Now
	}
	if report == nil {
		report = func(string, error) {}
	}
	relays, err := canonicalRelayURLs(lane.Relays)
	if err != nil {
		return nil, err
	}
	keys, err := OpenChatRelayKeys(filepath.Join(root, relayChatKeysDir), agentID, relays, lane.Signer, now)
	if err != nil {
		return nil, err
	}
	cards, err := OpenPeerCards(filepath.Join(root, relayChatPeersDir), verifier, agents, chatNoOwners{}, now)
	if err != nil {
		return nil, err
	}
	cards.AllowLoopbackRelays(ownRelaysOnLoopback(relays))
	cards.dropRemoved = true
	transport, err := OpenRelayTransport(filepath.Join(root, relayChatOutboxDir), cards, pool, now)
	if err != nil {
		return nil, err
	}
	if err := transport.setPacketBound(agentpacketseal.MaxPacketJSONBytes); err != nil {
		return nil, err
	}
	return &ChatCarrier{
		agentID: agentID, Keys: keys, Cards: cards, Transport: transport, signer: lane.Signer, daemon: lane.Daemon,
		verifier: verifier, agents: agents, pool: pool, cardPath: lane.CardPath, timeout: lane.Timeout, now: now,
		report: report,
		gone:   map[[32]byte]uint64{},
	}, nil
}

func (c *ChatCarrier) lockPeer(peer string) func() {
	value, _ := c.peers.LoadOrStore(peer, &sync.Mutex{})
	mutex, ok := value.(*sync.Mutex)
	if !ok {
		return func() {}
	}
	mutex.Lock()
	return mutex.Unlock
}

func (c *ChatCarrier) nowUnix() uint64 {
	now := c.now().Unix()
	if now <= 0 {
		return 0
	}
	return uint64(now)
}

// Carry implements carrierapi.Handler: carrier.carry. It answers carried
// only once one relay of the peer's chat card durably accepted the envelope
// journaled under the request's idempotency key; a retry with the same key
// reuses that journaled packet and envelope. Once generation N+1 is accepted
// it withdraws generation N, named by withdraw_idempotency_key.
func (c *ChatCarrier) Carry(ctx context.Context, request carrierapi.Request, raw []byte) carrierapi.Response {
	if c == nil || ctx == nil {
		return carrierapi.Retry()
	}
	peer := request.RecipientAgentID
	if !agentIDPattern.MatchString(peer) || peer == c.agentID ||
		!idempotencyKeyPattern.MatchString(request.IdempotencyKey) ||
		(request.WithdrawIdempotencyKey != "" && !idempotencyKeyPattern.MatchString(request.WithdrawIdempotencyKey)) ||
		request.WithdrawIdempotencyKey == request.IdempotencyKey {
		return carrierapi.Refusal(carrierapi.CodeInvalidRequest)
	}
	frame, err := relayframe.Decode(raw)
	if err != nil {
		return chatFrameRefusal(err)
	}
	// Acknowledgements leave through the inbound path; the daemon carries
	// only copies and evidence frames.
	if frame.Kind != relayframe.KindCopy && frame.Kind != relayframe.KindEvidence {
		return carrierapi.Refusal(carrierapi.CodeKindNotCarried)
	}
	if len(frame.Card) > 0 && !c.ownCard(frame.Card) {
		return carrierapi.Refusal(carrierapi.CodeFrameMalformed)
	}
	now := c.nowUnix()
	if now == 0 {
		return carrierapi.Retry()
	}
	if request.ExpiresAtUnix <= now {
		return carrierapi.Refusal(carrierapi.CodeInvalidRequest)
	}
	expires := saturatingAdd(now, uint64(PacketLifetime/time.Second))
	if request.ExpiresAtUnix < expires {
		expires = request.ExpiresAtUnix
	}
	unlock := c.lockPeer(peer)
	defer unlock()
	if request.WithdrawIdempotencyKey != "" {
		previous, found, lookupErr := c.Transport.journaled(request.WithdrawIdempotencyKey)
		if lookupErr != nil {
			return carrierapi.Retry()
		}
		if found && previous.RecipientAgentID != peer {
			return carrierapi.Refusal(carrierapi.CodeInvalidRequest)
		}
	}
	packet, accepted, err := c.prepare(ctx, peer, request.IdempotencyKey, raw, expires)
	switch {
	case err == nil:
	case errors.Is(err, errChatNoCard):
		return carrierapi.Refusal(carrierapi.CodeNoPeerCard)
	case errors.Is(err, errChatPeerCap):
		return carrierapi.Refusal(carrierapi.CodePeerCap)
	case errors.Is(err, errChatWrongPeer), errors.Is(err, ErrRelayWithdrawn):
		return carrierapi.Refusal(carrierapi.CodeInvalidRequest)
	default:
		c.report("chat.carry", err)
		return carrierapi.Retry()
	}
	// A key a relay already accepted is carried: the daemon died before it
	// recorded the answer, and nothing is deposited again.
	if !accepted {
		if err := c.Transport.Send(ctx, packet); err != nil {
			switch {
			case errors.Is(err, ErrNoPacketRoute):
				return carrierapi.Refusal(carrierapi.CodeNoPeerCard)
			case errors.Is(err, ErrRelayPacketTooLarge):
				return carrierapi.Refusal(carrierapi.CodePacketTooLarge)
			case errors.Is(err, ErrRelayWithdrawn):
				return carrierapi.Refusal(carrierapi.CodeInvalidRequest)
			default:
				// Everything else may pass later, an expired packet included:
				// the next attempt under the key signs a fresh one.
				c.report("chat.carry", err)
				return carrierapi.Retry()
			}
		}
	}
	if request.WithdrawIdempotencyKey != "" {
		// Generation N+1 is accepted: generation N is withdrawn wherever it
		// may be stored. The withdrawal is journaled before carried is
		// answered; a failure to journal it makes the daemon retry the same
		// key, which deposits nothing new and journals it then.
		if _, err := c.Transport.Withdraw(request.WithdrawIdempotencyKey); err != nil {
			c.report("chat.withdraw", err)
			return carrierapi.Retry()
		}
	}
	return carrierapi.Response{Result: carrierapi.ResultCarried}
}

// prepare returns the packet to send under key and whether a relay already
// accepted it.
//
//   - A key a relay accepted is answered from the journal, with no deposit.
//   - A withdrawn key is never sent again (ErrRelayWithdrawn).
//   - A journaled packet still deliverable is reused unchanged, so a retry
//     resends the journaled envelope.
//   - A journaled packet no relay accepted that has expired is replaced by a
//     freshly signed one under the same key; Send then seals it and replaces
//     the record in one atomic write. This is safe: an expired packet can
//     never be accepted by the recipient, so an ambiguous earlier deposit
//     that did land is refused there, and only the fresh one can deliver.
//   - A new key is admitted only when a chat card of the peer is held and
//     the peer's stored envelopes leave room under the cap.
//
// The caller holds the peer lock.
func (c *ChatCarrier) prepare(ctx context.Context, peer, key string, frame []byte,
	expires uint64,
) (OutboundPacket, bool, error) {
	entry, err := c.Transport.journalState(key)
	if err != nil {
		return OutboundPacket{}, false, err
	}
	if entry.Found {
		switch {
		case entry.Packet.RecipientAgentID != peer:
			return OutboundPacket{}, false, errChatWrongPeer
		case entry.Withdrawn:
			return OutboundPacket{}, false, ErrRelayWithdrawn
		case entry.Accepted:
			return entry.Packet, true, nil
		case len(entry.Packet.JSON) > 0 && c.nowUnix() < entry.Packet.ExpiresAtUnix:
			return entry.Packet, false, nil
		}
	}
	if !c.Cards.Has(peer) {
		return OutboundPacket{}, false, errChatNoCard
	}
	if !entry.Found {
		count, countErr := c.storedCount(ctx, peer)
		if countErr != nil {
			return OutboundPacket{}, false, countErr
		}
		if count >= ChatPeerEnvelopeCap {
			return OutboundPacket{}, false, errChatPeerCap
		}
	}
	signed, err := c.signer.sign(ctx, peer, chatCapability, "", frame)
	if err != nil {
		return OutboundPacket{}, false, fmt.Errorf("servicebridge: sign the chat packet: %w", err)
	}
	encoded, err := agentpacket.EncodeJSON(signed)
	if err != nil {
		return OutboundPacket{}, false, errors.New("servicebridge: encode the chat packet")
	}
	return OutboundPacket{RecipientAgentID: peer, JSON: encoded, IdempotencyKey: key, ExpiresAtUnix: expires},
		false, nil
}

// Deliver implements carrierapi.Handler; the daemon serves it, not this side.
func (c *ChatCarrier) Deliver(context.Context, string, []byte) carrierapi.Response {
	return carrierapi.NotServed()
}

// DeliveryAck implements carrierapi.Handler; the daemon serves it.
func (c *ChatCarrier) DeliveryAck(context.Context, string, []byte) carrierapi.Response {
	return carrierapi.NotServed()
}

func chatFrameRefusal(err error) carrierapi.Response {
	switch {
	case errors.Is(err, relayframe.ErrRelayEvidenceTooLarge):
		return carrierapi.Refusal(carrierapi.CodeRelayEvidenceTooLarge)
	case errors.Is(err, relayframe.ErrFrameKindUnsupported), errors.Is(err, relayframe.ErrFrameKind):
		return carrierapi.Refusal(carrierapi.CodeKindNotCarried)
	default:
		return carrierapi.Refusal(carrierapi.CodeFrameMalformed)
	}
}

// ownCard reports whether card is exactly the card of a held chat key.
func (c *ChatCarrier) ownCard(card []byte) bool {
	for _, key := range c.Keys.Held() {
		if bytes.Equal(key.CardJSON, card) {
			return true
		}
	}
	return false
}

// storedCount is how many chat envelopes a relay may still hold for peer.
// The journal's count is exact for what this node deposited but cannot see
// a peer's relay acknowledgement; only when it reaches the cap are the
// peer's mailbox listings (open to anyone) read to drop the envelopes no
// relay lists any more. A listing that fails counts its envelopes as held.
func (c *ChatCarrier) storedCount(ctx context.Context, peer string) (int, error) {
	stored, err := c.Transport.storedFor(peer)
	if err != nil {
		return 0, err
	}
	count := c.liveCount(stored)
	if count < ChatPeerEnvelopeCap {
		return count, nil
	}
	c.refreshGone(ctx, peer, stored)
	return c.liveCount(stored), nil
}

func (c *ChatCarrier) liveCount(stored []storedEnvelope) int {
	now := c.nowUnix()
	c.mutex.Lock()
	defer c.mutex.Unlock()
	count := 0
	for _, envelope := range stored {
		if expiry, gone := c.gone[envelope.EnvelopeID]; gone && now < expiry {
			continue
		}
		count++
	}
	return count
}

// refreshGone lists the peer's mailbox at every relay the counted envelopes
// name and remembers each envelope that no relay of its own lists.
func (c *ChatCarrier) refreshGone(ctx context.Context, peer string, stored []storedEnvelope) {
	listed := map[string]map[[32]byte]bool{}
	for _, envelope := range stored {
		for _, relay := range envelope.Relays {
			if _, done := listed[relay]; done {
				continue
			}
			listed[relay] = c.listing(ctx, relay, peer)
		}
	}
	now := c.nowUnix()
	horizon := saturatingAdd(now, uint64(relayMemoryHorizon/time.Second))
	c.mutex.Lock()
	defer c.mutex.Unlock()
	for id, expiry := range c.gone {
		if now >= expiry {
			delete(c.gone, id)
		}
	}
	for _, envelope := range stored {
		// An envelope with a deposit still due at some relay of its card may
		// be stored there later: it is never taken for gone.
		held := len(envelope.Relays) == 0 || envelope.Pending
		for _, relay := range envelope.Relays {
			ids := listed[relay]
			if ids == nil || ids[envelope.EnvelopeID] {
				held = true
				break
			}
		}
		if held {
			continue
		}
		if len(c.gone) >= maxChatGone {
			c.evictGoneLocked()
		}
		c.gone[envelope.EnvelopeID] = horizon
	}
}

func (c *ChatCarrier) evictGoneLocked() {
	var oldest [32]byte
	var oldestExpiry uint64
	first := true
	for id, expiry := range c.gone {
		if first || expiry < oldestExpiry {
			oldest, oldestExpiry, first = id, expiry, false
		}
	}
	delete(c.gone, oldest)
}

// listing returns the envelope ids a relay lists for agent, or nil when the
// listing failed.
func (c *ChatCarrier) listing(ctx context.Context, relay, agent string) map[[32]byte]bool {
	client, err := c.pool.client(relay)
	if err != nil {
		return nil
	}
	bounded, cancel := context.WithTimeout(ctx, RelayRequestTimeout)
	defer cancel()
	mailbox, err := client.List(bounded, agent)
	if err != nil {
		return nil
	}
	ids := make(map[[32]byte]bool, len(mailbox.Envelopes))
	for _, entry := range mailbox.Envelopes {
		ids[entry.EnvelopeID] = true
	}
	return ids
}

// chatAckKey is the idempotency key of the acknowledgement of one copy
// packet, bound to that packet's nonce.
func chatAckKey(nonce [32]byte) string {
	digest := sha256.Sum256(append([]byte(chatAckKeyDomain), nonce[:]...))
	return "idem_" + hex.EncodeToString(digest[:])
}

// chatPacket decodes a packet opened under a chat key and checks its purpose
// before anything else runs: addressed to this Agent from another one, the
// zero Capability, no Quote, and a relay frame as payload. Nothing is
// verified, written or forwarded for a packet that fails.
func (c *ChatCarrier) chatPacket(raw []byte) (agentpacket.Packet, bool) {
	if len(raw) == 0 || len(raw) > agentpacketseal.MaxPacketJSONBytes {
		return agentpacket.Packet{}, false
	}
	packet, err := agentpacket.DecodeJSON(raw)
	if err != nil || packet.RecipientAgentID != c.agentID || packet.SenderAgentID == c.agentID ||
		packet.CapabilityID != chatCapability || packet.QuoteCommitment != "" ||
		!bytes.HasPrefix(packet.Payload, []byte(chatFrameDomain)) {
		return agentpacket.Packet{}, false
	}
	return packet, true
}

// receive handles one packet that opened under a chat key. It reports
// whether the envelope is relay-acknowledged: every outcome is, refusals
// included, except a retry answer and a failure of finalized state or of the
// daemon socket, which leave it listed for a later poll.
func (c *ChatCarrier) receive(ctx context.Context, raw []byte) bool {
	packet, ok := c.chatPacket(raw)
	if !ok {
		c.report("chat.receive", errors.New("servicebridge: a packet opened under a chat key does not carry a "+
			"relay frame for this Agent; refused and acknowledged"))
		return true
	}
	resolver := &recordingResolver{next: c.agents}
	if err := agentpacket.Verify(ctx, c.verifier, resolver, &agentpacket.ReplayGuard{}, packet, c.now()); err != nil {
		if resolver.failed() || errors.Is(err, mldsa44.ErrUnavailable) || ctx.Err() != nil {
			return false
		}
		c.report("chat.receive", errors.New("servicebridge: a chat packet does not verify; refused and acknowledged"))
		return true
	}
	frame, err := relayframe.Decode(packet.Payload)
	if err != nil {
		c.report("chat.receive", errors.New("servicebridge: a chat packet carries a malformed relay frame; "+
			"refused and acknowledged"))
		return true
	}
	sender := packet.SenderAgentID
	switch frame.Kind {
	case relayframe.KindCopy, relayframe.KindEvidence:
		response, err := c.daemon.Deliver(ctx, sender, packet.Payload)
		if err != nil {
			c.report("chat.deliver", errors.New("servicebridge: the Messenger carrier socket did not answer; "+
				"the envelope stays at the relay"))
			return false
		}
		return c.afterDeliver(ctx, sender, packet.Nonce, frame, response)
	case relayframe.KindDeliveryAck:
		response, err := c.daemon.DeliveryAck(ctx, sender, packet.Payload)
		if err != nil {
			c.report("chat.delivery-ack", errors.New("servicebridge: the Messenger carrier socket did not "+
				"answer; the envelope stays at the relay"))
			return false
		}
		switch response.Result {
		case carrierapi.ResultRetry:
			return false
		case carrierapi.ResultApplied:
			// The ack settled a copy of this node's to the sender: the
			// sender is a peer with an established session.
			c.learn(ctx, sender, frame.Card)
		}
		return true
	default:
		return true
	}
}

// afterDeliver applies the daemon's answer to a copy or evidence frame.
func (c *ChatCarrier) afterDeliver(ctx context.Context, sender string, nonce [32]byte, frame relayframe.Frame,
	response carrierapi.Response,
) bool {
	switch response.Result {
	case carrierapi.ResultRetry:
		return false
	case carrierapi.ResultAdmitted:
		// An evidence frame of an admitted peer was committed.
		c.learn(ctx, sender, frame.Card)
		return true
	case carrierapi.ResultAck:
		// The card is kept only when the daemon admitted the sender; a
		// refused stranger's card is never stored.
		if chatAdmits(response.AckOutcome) {
			c.learn(ctx, sender, frame.Card)
		}
		ack, err := response.AckFrame()
		if err != nil {
			c.report("chat.ack", errors.New("servicebridge: the daemon's ack frame does not decode"))
			return true
		}
		if err := c.sendAck(ctx, sender, nonce, ack); err != nil {
			if errors.Is(err, errChatPermanent) {
				// Without a card of the sender (a refused stranger) or room
				// under its cap, the ack is not sent: the sender re-deposits
				// and is answered duplicate later.
				c.report("chat.ack", err)
				return true
			}
			c.report("chat.ack", err)
			return false
		}
		return true
	default:
		return true
	}
}

// chatAdmits reports the daemon outcomes under which a sender's card may be
// stored: accepted, duplicate and held, never rejected.
func chatAdmits(outcome string) bool {
	return outcome == relayframe.OutcomeAccepted || outcome == relayframe.OutcomeDuplicate ||
		outcome == relayframe.OutcomeHeld
}

// learn verifies an in-band card of sender and keeps it. A card that fails
// is ignored and never invalidates the frame that carried it.
func (c *ChatCarrier) learn(ctx context.Context, sender string, card []byte) {
	if len(card) == 0 {
		return
	}
	if err := c.Cards.Learn(ctx, card, sender, ""); err != nil {
		c.report("chat.card", err)
	}
}

// sendAck deposits the daemon's kind-2 frame for one received copy packet.
// A failure wrapping errChatPermanent will never pass; any other may pass on
// a later poll, which delivers the copy again and gets the same key.
func (c *ChatCarrier) sendAck(ctx context.Context, peer string, nonce [32]byte, ack []byte) error {
	frame, err := relayframe.Decode(ack)
	if err != nil || frame.Kind != relayframe.KindDeliveryAck {
		return fmt.Errorf("%w: the daemon's ack is not a kind-2 frame", errChatPermanent)
	}
	if len(frame.Card) > 0 && !c.ownCard(frame.Card) {
		return fmt.Errorf("%w: %w", errChatPermanent, errChatNotOwnCard)
	}
	now := c.nowUnix()
	if now == 0 {
		return errors.New("servicebridge: the clock is not set")
	}
	key := chatAckKey(nonce)
	unlock := c.lockPeer(peer)
	defer unlock()
	packet, accepted, err := c.prepare(ctx, peer, key, ack,
		saturatingAdd(now, uint64(PacketLifetime/time.Second)))
	switch {
	case err == nil:
	case errors.Is(err, errChatNoCard), errors.Is(err, errChatPeerCap), errors.Is(err, errChatWrongPeer),
		errors.Is(err, ErrRelayWithdrawn):
		return fmt.Errorf("%w: %w", errChatPermanent, err)
	default:
		return err
	}
	if accepted {
		return nil
	}
	if err := c.Transport.Send(ctx, packet); err != nil {
		if errors.Is(err, ErrNoPacketRoute) || errors.Is(err, ErrRelayPacketTooLarge) ||
			errors.Is(err, ErrRelayWithdrawn) {
			return fmt.Errorf("%w: %w", errChatPermanent, err)
		}
		return err
	}
	return nil
}

// Maintain rotates and destroys chat keys and republishes the current chat
// card to the daemon's card path. The card handed out lasts the longest
// lifetime and is replaced once less than half of it is left, so a contact
// file exported now stays usable for at least 15 days.
func (c *ChatCarrier) Maintain(ctx context.Context) error {
	if c == nil || ctx == nil {
		return errChatInvalidLane
	}
	if _, err := c.Keys.Maintain(ctx); err != nil {
		return err
	}
	_, err := c.Republish(ctx)
	return err
}

// Republish issues a chat card when none qualifies and writes the current one
// to the card path when it differs. It reports the card handed out.
func (c *ChatCarrier) Republish(ctx context.Context) (OwnRelayKey, error) {
	if c == nil || ctx == nil {
		return OwnRelayKey{}, errChatInvalidLane
	}
	now := c.nowUnix()
	if now == 0 {
		return OwnRelayKey{}, errors.New("servicebridge: the clock is not set")
	}
	key, err := c.Keys.Current(ctx, offerCardCover(now))
	if err != nil {
		return OwnRelayKey{}, err
	}
	return key, publishChatCard(c.cardPath, key.CardJSON)
}

// publishChatCard writes card to path unless it already holds exactly it.
// The daemon reads the file for every frame it builds.
func publishChatCard(path string, card []byte) error {
	if !cleanAbsolute(path) || len(card) == 0 {
		return errChatInvalidLane
	}
	if len(card) > relayframe.MaxCardBytes {
		return fmt.Errorf("servicebridge: the chat card is %d bytes; a relay frame carries at most %d",
			len(card), relayframe.MaxCardBytes)
	}
	existing, err := readPrivateFile(path, relayframe.MaxCardBytes)
	switch {
	case err == nil && bytes.Equal(existing, card):
		return nil
	case err == nil, errors.Is(err, os.ErrNotExist):
	default:
		return fmt.Errorf("servicebridge: the chat card path holds something else: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return errors.New("servicebridge: create the chat card directory")
	}
	return replaceSynced(path, card)
}

// ListenCarrier opens the private mode-0600 carrier socket now, so a socket
// that cannot be served stops the node at startup, and returns the function
// that serves carrier.carry on it until its context ends.
func (c *ChatCarrier) ListenCarrier(socket string) (func(context.Context) error, error) {
	if c == nil || !cleanAbsolute(socket) {
		return nil, errChatInvalidLane
	}
	listener, err := carrierapi.Listen(socket)
	if err != nil {
		return nil, fmt.Errorf("servicebridge: listen on the chat carrier socket: %w", err)
	}
	return func(ctx context.Context) error {
		if ctx == nil {
			_ = listener.Close()
			return errChatInvalidLane
		}
		return c.serveListener(ctx, listener, socket)
	}, nil
}

func (c *ChatCarrier) serveListener(ctx context.Context, listener net.Listener, socket string) error {
	server, err := carrierapi.NewServer(c, c.timeout)
	if err != nil {
		_ = listener.Close()
		return err
	}
	stopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
		case <-stopped:
		}
		_ = listener.Close()
	}()
	err = server.Serve(ctx, listener)
	close(stopped)
	if socket != "" {
		_ = os.Remove(socket)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// ChatStatus is the chat lane as status shows it.
type ChatStatus struct {
	Keys      []RelayKeyView    `json:"keys"`
	PeerCards []PeerCardView    `json:"peer_cards"`
	CardPath  string            `json:"card_path"`
	Outbox    []RelayOutboxView `json:"outbox,omitempty"`
}

func (c *ChatCarrier) status() *ChatStatus {
	if c == nil {
		return nil
	}
	return &ChatStatus{Keys: relayKeyViews(c.Keys.Held()), PeerCards: c.Cards.List(), CardPath: c.cardPath}
}
