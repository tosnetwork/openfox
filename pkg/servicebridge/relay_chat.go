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
	"strings"
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
	// OwnerSocket is the daemon's owner socket, which `chat room`, `chat
	// invite`, `chat owner submit` and `chat contact import --invite-token-
	// file` call. Empty means room management through openfox is off. It
	// carries owner decisions only as signed envelopes: openfox never holds
	// the owner's signing key.
	OwnerSocket string `json:"owner_socket,omitempty"`
	// TestCardLifetimeSeconds shortens the chat card lifetime for a live
	// test of in-band card renewal: each chat card lasts this long, 600 s to
	// 30 days, and is replaced once less than half of it is left. Only a
	// build with the roomtest tag accepts it; a production build refuses a
	// configuration that names it. Unset is the production rotation.
	TestCardLifetimeSeconds uint64 `json:"test_card_lifetime_seconds,omitempty"`
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
	if chat.OwnerSocket != "" {
		switch {
		case !cleanAbsolute(chat.OwnerSocket):
			problems = append(problems, errors.New("chat.owner_socket must be an absolute clean path"))
		case len(chat.OwnerSocket) > maxUnixSocketPath:
			problems = append(problems, fmt.Errorf("chat.owner_socket exceeds %d bytes", maxUnixSocketPath))
		case chat.OwnerSocket == chat.CarrierSocket || chat.OwnerSocket == chat.MessengerCarrierSocket ||
			chat.OwnerSocket == config.ReceiverSocket:
			problems = append(problems, errors.New("chat.owner_socket must differ from the carrier, Messenger "+
				"carrier and receiver sockets"))
		}
	}
	if len(chat.RelayURLs) > 0 {
		if _, err := canonicalRelayURLs(chat.RelayURLs); err != nil {
			problems = append(problems, err)
		}
	}
	if _, err := chat.timeout(); err != nil {
		problems = append(problems, err)
	}
	if _, err := chat.cardLifetime(); err != nil {
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
	// CardLifetime is the chat test card lifetime; zero is the production
	// rotation.
	CardLifetime time.Duration
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
	// rooms records the room admissions of peer cards; admissions
	// serializes every change of a record with the card change it guards.
	rooms      *roomAdmissions
	admissions sync.Mutex
	// pacer paces kind-3 deposits per relay.
	pacer *roomPacer
	// refusals limits refusal reports to one per (stage, kind, sender,
	// result, code) per refusalReportWindow, guarded by refusalsMutex.
	refusals      map[string]refusalReport
	refusalsMutex sync.Mutex
}

// refusalReportWindow is how often one kind of daemon refusal of one sender
// is reported; repeats inside it are counted into the next report.
const refusalReportWindow = time.Hour

// maxRefusalKeys bounds the refusal report table; when it is full, entries
// whose window has passed are dropped, and if none has, the table restarts.
const maxRefusalKeys = 1024

// refusalReport is the last report of one refusal key.
type refusalReport struct {
	at         time.Time
	suppressed uint64
}

// reportRefusal reports a daemon refusal the carrier relay-acknowledges, at
// most once per key per refusalReportWindow; the next report counts the
// repeats it held back.
func (c *ChatCarrier) reportRefusal(stage string, kind uint8, sender string, response carrierapi.Response) {
	key := fmt.Sprintf("%s|%d|%s|%s|%s", stage, kind, sender, response.Result, response.Code)
	now := c.now()
	c.refusalsMutex.Lock()
	if c.refusals == nil {
		c.refusals = map[string]refusalReport{}
	}
	last, seen := c.refusals[key]
	if seen && now.Sub(last.at) < refusalReportWindow && !now.Before(last.at) {
		last.suppressed = saturatingAdd(last.suppressed, 1)
		c.refusals[key] = last
		c.refusalsMutex.Unlock()
		return
	}
	if !seen && len(c.refusals) >= maxRefusalKeys {
		for other, report := range c.refusals {
			if now.Sub(report.at) >= refusalReportWindow {
				delete(c.refusals, other)
			}
		}
		if len(c.refusals) >= maxRefusalKeys {
			c.refusals = map[string]refusalReport{}
		}
	}
	c.refusals[key] = refusalReport{at: now}
	c.refusalsMutex.Unlock()
	repeats := ""
	if last.suppressed > 0 {
		repeats = fmt.Sprintf(" (%d more since the last report)", last.suppressed)
	}
	subject := fmt.Sprintf("a kind-%d frame", kind)
	if stage == "chat.delivery-ack" {
		subject = "a delivery ack"
	}
	c.report(stage, fmt.Errorf("servicebridge: the daemon answered %s of %s with %s %s; relay-acknowledged%s",
		subject, sender, response.Result, response.Code, repeats))
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
	keys.SetCardLifetime(lane.CardLifetime)
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
	transport.onUnreadable = func(name string, err error) {
		report("chat.journal", fmt.Errorf("servicebridge: chat journal record %s is unreadable; it counts as one "+
			"stored envelope for every peer: %w", name, err))
	}
	transport.onQuarantined = func(name string) {
		report("chat.journal", fmt.Errorf("servicebridge: unreadable chat journal record %s is older than every "+
			"envelope it can describe; moved to %s and no longer counted", name, relayQuarantineDir))
	}
	if err := transport.setPacketBound(agentpacketseal.MaxPacketJSONBytes); err != nil {
		return nil, err
	}
	rooms, err := openRoomAdmissions(filepath.Join(root, relayChatRoomAdmissionsDir))
	if err != nil {
		return nil, err
	}
	pacer := newRoomPacer(now)
	transport.pace = pacer.allow
	carrier := &ChatCarrier{
		agentID: agentID, Keys: keys, Cards: cards, Transport: transport, signer: lane.Signer, daemon: lane.Daemon,
		verifier: verifier, agents: agents, pool: pool, cardPath: lane.CardPath, timeout: lane.Timeout, now: now,
		report: report,
		gone:   map[[32]byte]uint64{},
		rooms:  rooms, pacer: pacer,
	}
	// Admissions of rooms that ended while the node was down go now, before
	// any carriage; a failure is reported and the maintenance pass retries.
	if err := carrier.sweepRoomAdmissions(); err != nil {
		report("chat.room-cards", err)
	}
	return carrier, nil
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
	// copies, room parts and evidence frames.
	if frame.Kind != relayframe.KindCopy && frame.Kind != relayframe.KindEvidence && frame.Kind != relayframe.KindRoom {
		return carrierapi.Refusal(carrierapi.CodeKindNotCarried)
	}
	application, err := roomFrameIsApplication(frame)
	if err != nil {
		return carrierapi.Refusal(carrierapi.CodeFrameMalformed)
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
	if frame.Kind == relayframe.KindEvidence || application {
		// An evidence request or response lives one relay TTL of the peer's
		// card: the relays would not keep it longer, and the daemon deposits
		// an outstanding request again at 80 % of that TTL. A room
		// application object is deposited once and lives as long; handshake
		// parts take the copy rule.
		if card, cardErr := c.Cards.Current(ctx, peer); cardErr == nil {
			if limit := saturatingAdd(now, c.pool.smallestTTL(ctx, card.Card.Relays)); limit < expires {
				expires = limit
			}
		}
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
	packet, accepted, err := c.prepare(ctx, peer, request.IdempotencyKey, frame.Kind, raw, expires)
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
			response := chatSendFailure(err)
			if response.Result == carrierapi.ResultRetry && !errors.Is(err, ErrRelayPaced) {
				c.report("chat.carry", err)
			}
			return response
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
	return carrierapi.Carried(c.cardTTL(ctx, request.IdempotencyKey))
}

// chatSendFailure maps a failed Send of a chat packet to the daemon's answer.
func chatSendFailure(err error) carrierapi.Response {
	switch {
	case errors.Is(err, ErrNoPacketRoute):
		return carrierapi.Refusal(carrierapi.CodeNoPeerCard)
	case errors.Is(err, ErrRelayPacketTooLarge), errors.Is(err, ErrRelayRecordTooLarge):
		// A record the journal could not read back is never written, and the
		// same frame would build the same record again: permanent.
		return carrierapi.Refusal(carrierapi.CodePacketTooLarge)
	case errors.Is(err, ErrRelayWithdrawn):
		return carrierapi.Refusal(carrierapi.CodeInvalidRequest)
	default:
		// Everything else may pass later, an expired packet included: the
		// next attempt under the key signs a fresh one.
		return carrierapi.Retry()
	}
}

// cardTTL is the smallest retention the relays of the card the key's
// envelope is sealed to advertise, which the daemon schedules the next
// generation from. A relay whose description cannot be read counts as the
// protocol ceiling, and so does a key whose record names no relay.
func (c *ChatCarrier) cardTTL(ctx context.Context, key string) uint64 {
	entry, err := c.Transport.journalState(key)
	if err != nil || len(entry.Relays) == 0 {
		return relayTTLCeilingSeconds
	}
	return c.pool.smallestTTL(ctx, entry.Relays)
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
//     the peer's stored envelopes leave room under the cap: 24 chat
//     envelopes, of which at most 16 of kind 3.
//
// The caller holds the peer lock.
func (c *ChatCarrier) prepare(ctx context.Context, peer, key string, kind uint8, frame []byte,
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
		count, roomCount, countErr := c.storedCount(ctx, peer, kind)
		if countErr != nil {
			return OutboundPacket{}, false, countErr
		}
		if !carrierapi.PeerCapAllows(kind, count, roomCount) {
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
	return OutboundPacket{
		RecipientAgentID: peer, JSON: encoded, IdempotencyKey: key, ExpiresAtUnix: expires, FrameKind: kind,
	}, false, nil
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

// storedCount is how many chat envelopes a relay may still hold for peer,
// and how many of them are kind 3. The journal's count is exact for what
// this node deposited but cannot see a peer's relay acknowledgement; only
// when a count would refuse a new envelope of kind are the peer's mailbox
// listings (open to anyone) read to drop the envelopes no relay lists any
// more, one refresh for both counts. A listing that fails counts its
// envelopes as held.
func (c *ChatCarrier) storedCount(ctx context.Context, peer string, kind uint8) (int, int, error) {
	stored, err := c.Transport.storedFor(peer)
	if err != nil {
		return 0, 0, err
	}
	count, roomCount := c.liveCount(stored)
	if carrierapi.PeerCapAllows(kind, count, roomCount) {
		return count, roomCount, nil
	}
	c.refreshGone(ctx, peer, stored)
	count, roomCount = c.liveCount(stored)
	return count, roomCount, nil
}

// liveCount counts the stored envelopes not taken for gone, and the kind-3
// ones among them.
func (c *ChatCarrier) liveCount(stored []storedEnvelope) (int, int) {
	now := c.nowUnix()
	c.mutex.Lock()
	defer c.mutex.Unlock()
	count, roomCount := 0, 0
	for _, envelope := range stored {
		if expiry, gone := c.gone[envelope.EnvelopeID]; gone && now < expiry {
			continue
		}
		count++
		if envelope.FrameKind == relayframe.KindRoom {
			roomCount++
		}
	}
	return count, roomCount
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
	case relayframe.KindCopy, relayframe.KindEvidence, relayframe.KindRoom:
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
			// The ack settled a copy or a room object of this node's to the
			// sender. A copy ack keeps the sender's admission; a room ack
			// renews a card only under an admission already held.
			source := cardRenewed
			if relayframe.IsRoomAck(frame.Part) {
				source = cardRoomRenewed
			}
			c.learnFrom(ctx, sender, frame.Card, source)
		case carrierapi.ResultRefused:
			// An ignored ack (a repeat for a copy already settled) is
			// routine; a refused one is reported.
			c.reportRefusal("chat.delivery-ack", frame.Kind, sender, response)
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
		// An evidence frame of an admitted peer was committed, or a room
		// object or stored part of it was admitted; only part 0 carries a
		// card.
		c.learnFrom(ctx, sender, frame.Card, admittedSource(frame.Kind))
		return true
	case carrierapi.ResultAck:
		// The card is kept only when the daemon admitted the sender; a
		// refused stranger's card is never stored.
		if chatAdmits(response.AckOutcome) {
			c.learnFrom(ctx, sender, frame.Card, ackSource(frame.Kind, response.AckOutcome))
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
		// The daemon refused or ignored the frame: it is relay-acknowledged
		// like every final answer, and the reason is reported so a dropped
		// invite or evidence request names its cause.
		c.reportRefusal("chat.deliver", frame.Kind, sender, response)
		return true
	}
}

// chatAdmits reports the daemon outcomes under which a sender's card may be
// stored: accepted, duplicate and held, never rejected.
func chatAdmits(outcome string) bool {
	return outcome == relayframe.OutcomeAccepted || outcome == relayframe.OutcomeDuplicate ||
		outcome == relayframe.OutcomeHeld
}

// admittedSource is the card source of an admitted frame: room traffic for
// kind 3, the peer's own admission otherwise.
func admittedSource(kind uint8) cardSource {
	if kind == relayframe.KindRoom {
		return cardRoomRenewed
	}
	return cardRenewed
}

// ackSource is the card source of a frame the daemon acknowledged with an
// admitting outcome: a copy accepted or deduplicated is a direct admission
// (the relay route admits copies only under the contact policy), a held one
// keeps the peer's admission, and a room object is room traffic.
func ackSource(kind uint8, outcome string) cardSource {
	switch {
	case kind == relayframe.KindRoom:
		return cardRoomRenewed
	case outcome == relayframe.OutcomeAccepted, outcome == relayframe.OutcomeDuplicate:
		return cardEstablished
	default:
		return cardRenewed
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
	packet, accepted, err := c.prepare(ctx, peer, key, relayframe.KindDeliveryAck, ack,
		saturatingAdd(now, uint64(AckPacketLifetime/time.Second)))
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
			errors.Is(err, ErrRelayRecordTooLarge) || errors.Is(err, ErrRelayWithdrawn) {
			return fmt.Errorf("%w: %w", errChatPermanent, err)
		}
		return err
	}
	return nil
}

// Maintain rotates and destroys chat keys and republishes the current chat
// card to the daemon's card path. The card handed out lasts the longest
// lifetime and is replaced once less than half of it is left, so a contact
// file exported now stays usable for at least 15 days. Every pass also drops
// the room admissions whose room has ended (sweepRoomAdmissions); a failure
// there is reported and does not stop the key work.
func (c *ChatCarrier) Maintain(ctx context.Context) error {
	if c == nil || ctx == nil {
		return errChatInvalidLane
	}
	if err := c.sweepRoomAdmissions(); err != nil {
		c.report("chat.room-cards", err)
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
	// Rooms are the rooms whose rosters admitted peer cards, and
	// RoomAdmissions each such peer's admissions.
	Rooms          []RoomCardsView     `json:"rooms"`
	RoomAdmissions []RoomAdmissionView `json:"room_admissions"`
	// PeerEnvelopes are the journal's per-peer counts against the caps of 24
	// chat and 16 kind-3 envelopes.
	PeerEnvelopes []PeerEnvelopeCount `json:"peer_envelopes"`
	// RoomPacing lists the relays whose kind-3 deposit bucket is not full.
	RoomPacing []RoomPacingView `json:"room_pacing"`
	// Problems names the parts of this status that could not be read.
	Problems []string `json:"problems,omitempty"`
}

func (c *ChatCarrier) status() *ChatStatus {
	if c == nil {
		return nil
	}
	status := &ChatStatus{
		Keys: relayKeyViews(c.Keys.Held()), PeerCards: c.Cards.List(), CardPath: c.cardPath,
		Rooms: []RoomCardsView{}, RoomAdmissions: []RoomAdmissionView{}, PeerEnvelopes: []PeerEnvelopeCount{},
		RoomPacing: c.pacer.views(),
	}
	if admissions, err := readRoomAdmissions(c.rooms.directory); err != nil {
		problem := strings.TrimPrefix(err.Error(), "servicebridge: ")
		status.Problems = append(status.Problems, "room admissions: "+problem)
	} else if admissions != nil {
		status.RoomAdmissions, status.Rooms = admissions, roomCardsViews(admissions)
	}
	if counts, err := ReadPeerEnvelopeCounts(c.Transport.directory, c.now()); err != nil {
		status.Problems = append(status.Problems, "peer envelopes: "+strings.TrimPrefix(err.Error(), "servicebridge: "))
	} else if counts != nil {
		status.PeerEnvelopes = counts
	}
	return status
}
