package servicebridge

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
)

// RelayCardReverify is the longest a verification of a peer's key card is
// relied on before sealing to it. The protocol allows ten minutes between
// the finalized-state check and the seal; a margin is kept for the seal and
// the deposit that follow the check.
const RelayCardReverify = 9 * time.Minute

// Bounds of the peer card directory.
const (
	maxCardsPerPeer = 8
	maxCardPeers    = 1024
	maxCardJSON     = 16 << 10
)

const peerCardSchema = "tos.openfox.relay-peer-card.v1"

// ErrCardRefused reports a key card that does not verify or that finalized
// state does not bind to the Agent it is used for.
var ErrCardRefused = errors.New("servicebridge: the encryption key card is refused")

// errCardUnavailable reports a card check that finalized state could not
// answer; the card is kept and checked again later.
var errCardUnavailable = errors.New("servicebridge: the encryption key card cannot be checked now")

// errPeerCardsFull reports a card of a new peer refused because the card
// directory holds its maximum of peers, none of whose cards has expired.
var errPeerCardsFull = errors.New("servicebridge: the peer card directory is full")

// CapabilityOwners reads a Capability's owner from finalized state.
type CapabilityOwners interface {
	CapabilityOwner(ctx context.Context, capabilityID string) (string, error)
}

// FinalizedCapabilityOwners reads owners from one fresh finalized
// checkpoint per lookup.
type FinalizedCapabilityOwners struct {
	Sessions RegistrySessions
}

// CapabilityOwner implements CapabilityOwners. A revoked or absent
// Capability has no owner a card may be bound to.
func (f FinalizedCapabilityOwners) CapabilityOwner(ctx context.Context, capabilityID string) (string, error) {
	if f.Sessions == nil || ctx == nil || !capabilityPattern.MatchString(capabilityID) {
		return "", errors.New("servicebridge: invalid Capability owner lookup")
	}
	session, err := f.Sessions.BeginRegistrySession(ctx)
	if err != nil {
		return "", fmt.Errorf("%w: %w", errCardUnavailable, err)
	}
	state, found, err := session.ResolveRegistry(ctx, capabilityID)
	if err != nil {
		return "", fmt.Errorf("%w: %w", errCardUnavailable, err)
	}
	capability := state.GetCapability()
	if !found || capability == nil || capability.GetCapabilityId() != capabilityID || capability.GetTombstoned() ||
		!agentIDPattern.MatchString(capability.GetOwnerAgentId()) {
		return "", fmt.Errorf("%w: Capability %s has no finalized live owner", ErrCardRefused, capabilityID)
	}
	return capability.GetOwnerAgentId(), nil
}

// peerCardRecord is one stored peer card. The card itself is public; the
// record is owner-only like all node state.
type peerCardRecord struct {
	Schema           string `json:"schema"`
	AgentID          string `json:"agent_id"`
	CapabilityID     string `json:"capability_id,omitempty"`
	CardPacketBase64 string `json:"card_packet_base64"`
}

// peerCard is a stored card with its decoded key. CapabilityID, when set,
// is the Capability whose finalized owner must be the card's Agent at every
// verification.
type peerCard struct {
	AgentID      string
	CapabilityID string
	JSON         []byte
	Key          agentpacketseal.RecipientKey
	Card         agentpacketseal.KeyCard
	verifiedAt   time.Time
}

// PeerCards holds the verified key cards of the Agents this node seals to:
// a provider's card from its offer file, a buyer's card from its task. A
// card enters only after it verifies against finalized state and is checked
// again before every seal that follows a pause longer than
// RelayCardReverify, which is how removing the signing controller revokes it.
type PeerCards struct {
	directory string
	verifier  mldsa44.Verifier
	agents    agentpacket.AgentResolver
	owners    CapabilityOwners
	now       func() time.Time
	// loopback lets peer cards name relays on a loopback host. Only a
	// node whose own relays are on loopback (a single-host test setup)
	// allows it; otherwise a verified peer could make this node send
	// requests to services on its own host.
	loopback bool
	// dropRemoved makes a reload forget held cards whose files are gone:
	// the chat store, whose contacts the owner may remove while `serve`
	// runs.
	dropRemoved bool
	mutex       sync.Mutex
	cards       map[string][]*peerCard
}

// AllowLoopbackRelays sets whether peer cards may name loopback relays.
func (p *PeerCards) AllowLoopbackRelays(allowed bool) {
	p.mutex.Lock()
	p.loopback = allowed
	p.mutex.Unlock()
}

// loopbackRelay reports whether a relay base URL names a loopback host, or
// a numeric host in any form other than a canonical dotted quad or an IPv6
// literal (127.1, 0x7f.1, 0177.0.0.1 and 2130706433 all reach 127.0.0.1 in
// common resolvers). A name that resolves to a loopback address through DNS
// is not caught: the node would then only POST a ciphertext envelope, or GET
// a mailbox listing, to whatever answers there, and opens nothing it gets.
func loopbackRelay(relay string) bool {
	parsed, err := url.Parse(relay)
	if err != nil {
		return true
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || nonCanonicalNumericHost(host) {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsUnspecified())
}

// nonCanonicalNumericHost reports a host whose last label is numeric (all
// digits, or a 0x form) but that is not four canonical decimal octets.
func nonCanonicalNumericHost(host string) bool {
	if strings.Contains(host, ":") {
		return net.ParseIP(host) == nil
	}
	labels := strings.Split(strings.TrimSuffix(host, "."), ".")
	last := labels[len(labels)-1]
	numeric := strings.HasPrefix(last, "0x")
	if !numeric {
		numeric = last != ""
		for _, c := range last {
			if c < '0' || c > '9' {
				numeric = false
				break
			}
		}
	}
	if !numeric {
		return false
	}
	if len(labels) != 4 {
		return true
	}
	for _, label := range labels {
		if label == "" || len(label) > 3 || (len(label) > 1 && label[0] == '0') {
			return true
		}
		value := 0
		for _, c := range label {
			if c < '0' || c > '9' {
				return true
			}
			value = value*10 + int(c-'0')
		}
		if value > 255 {
			return true
		}
	}
	return false
}

// OpenPeerCards opens the owner-private card directory. Stored cards are
// loaded unverified: each is verified again before its first use.
func OpenPeerCards(directory string, verifier mldsa44.Verifier, agents agentpacket.AgentResolver,
	owners CapabilityOwners, now func() time.Time,
) (*PeerCards, error) {
	if !cleanAbsolute(directory) || verifier == nil || agents == nil || owners == nil {
		return nil, errors.New("servicebridge: invalid peer card configuration")
	}
	if now == nil {
		now = time.Now
	}
	if err := ensurePrivateDirectory(directory); err != nil {
		return nil, err
	}
	cards := &PeerCards{
		directory: directory, verifier: verifier, agents: agents, owners: owners, now: now,
		cards: map[string][]*peerCard{},
	}
	held, err := readPeerCards(directory)
	if err != nil {
		return nil, err
	}
	for _, card := range held {
		cards.cards[card.AgentID] = append(cards.cards[card.AgentID], card)
	}
	for agent := range cards.cards {
		cards.sortLocked(agent)
	}
	return cards, nil
}

// readPeerCards reads the stored cards without changing the directory.
func readPeerCards(directory string) ([]*peerCard, error) {
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("servicebridge: read the peer card directory")
	}
	var out []*peerCard
	for _, entry := range entries {
		if !relayKeyFilePattern.MatchString(entry.Name()) {
			continue
		}
		var record peerCardRecord
		if err := readJSON(filepath.Join(directory, entry.Name()), 64<<10, &record); err != nil {
			return nil, fmt.Errorf("servicebridge: peer card %s: %w", entry.Name(), err)
		}
		card, err := decodePeerRecord(record)
		if err != nil || entry.Name() != peerCardFile(card) {
			return nil, fmt.Errorf("servicebridge: peer card %s is not a well-formed card", entry.Name())
		}
		out = append(out, card)
	}
	return out, nil
}

func decodePeerRecord(record peerCardRecord) (*peerCard, error) {
	if record.Schema != peerCardSchema || !agentIDPattern.MatchString(record.AgentID) ||
		(record.CapabilityID != "" && !capabilityPattern.MatchString(record.CapabilityID)) {
		return nil, errors.New("invalid peer card record")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(record.CardPacketBase64)
	if err != nil {
		return nil, errors.New("invalid peer card record")
	}
	return decodePeerCard(raw, record.AgentID, record.CapabilityID)
}

// decodePeerCard decodes a card packet of agentID without the finalized
// check.
func decodePeerCard(raw []byte, agentID, capabilityID string) (*peerCard, error) {
	if len(raw) == 0 || len(raw) > maxCardJSON {
		return nil, fmt.Errorf("%w: the card packet is outside its bounds", ErrCardRefused)
	}
	card, err := decodeOwnCard(agentID, raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCardRefused, err)
	}
	return &peerCard{
		AgentID: agentID, CapabilityID: capabilityID, JSON: append([]byte(nil), raw...),
		Key:  agentpacketseal.RecipientKey{AgentID: agentID, KeyID: card.KeyID, PublicKey: card.PublicKey},
		Card: card,
	}, nil
}

// peerCardFile names a card's file: one per Agent and key id.
func peerCardFile(card *peerCard) string {
	digest, _ := agentpacketseal.AgentDigest(card.AgentID)
	keyID := card.KeyID()
	sum := sha256.Sum256(append(append([]byte(nil), digest[:]...), keyID[:]...))
	return hex.EncodeToString(sum[:]) + ".json"
}

// KeyID returns the card's key id.
func (c *peerCard) KeyID() [agentpacketseal.KeyIDSize]byte { return c.Key.KeyID }

// Learn verifies a card offered for agentID and keeps it. With a
// capabilityID the card must also belong to that Capability's finalized
// owner, read from chain now and at every later verification: an offer
// file is unsigned, so it is never the source of the owner.
func (p *PeerCards) Learn(ctx context.Context, raw []byte, agentID, capabilityID string) error {
	card, err := p.verified(ctx, raw, agentID, capabilityID)
	if err != nil {
		return err
	}
	return p.keep(card)
}

// verified decodes a card offered for agentID and verifies it against
// finalized state now, without storing it.
func (p *PeerCards) verified(ctx context.Context, raw []byte, agentID, capabilityID string) (*peerCard, error) {
	if p == nil || ctx == nil || !agentIDPattern.MatchString(agentID) {
		return nil, errors.New("servicebridge: invalid key card learning")
	}
	card, err := decodePeerCard(raw, agentID, capabilityID)
	if err != nil {
		return nil, err
	}
	if err := p.verify(ctx, card); err != nil {
		return nil, err
	}
	return card, nil
}

// keep stores a card verified just before.
func (p *PeerCards) keep(card *peerCard) error {
	if p == nil || card == nil {
		return errors.New("servicebridge: invalid key card learning")
	}
	p.mutex.Lock()
	defer p.mutex.Unlock()
	return p.storeLocked(card)
}

// holdsAny reports whether any card of agentID is stored, expired or not:
// what an admission decision counts as held.
func (p *PeerCards) holdsAny(agentID string) (bool, error) {
	if p == nil {
		return false, errors.New("servicebridge: invalid peer card lookup")
	}
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if err := p.reloadLocked(); err != nil {
		return false, fmt.Errorf("servicebridge: read the peer card directory: %w", err)
	}
	return len(p.cards[agentID]) > 0, nil
}

// forgetAgent removes every stored card of agentID, file and memory, and
// reports how many it removed.
func (p *PeerCards) forgetAgent(agentID string) (int, error) {
	if p == nil || !agentIDPattern.MatchString(agentID) {
		return 0, errors.New("servicebridge: invalid peer card removal")
	}
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if err := p.reloadLocked(); err != nil {
		return 0, fmt.Errorf("servicebridge: read the peer card directory: %w", err)
	}
	list := p.cards[agentID]
	for _, card := range list {
		if err := p.removeFile(card); err != nil {
			return 0, err
		}
	}
	delete(p.cards, agentID)
	return len(list), nil
}

// verify checks a card against finalized state now: the signature by a
// controller of the finalized live Agent, the validity window, and, for a
// Capability-bound card, the Capability's finalized owner.
func (p *PeerCards) verify(ctx context.Context, card *peerCard) error {
	packet, err := agentpacket.DecodeJSON(card.JSON)
	if err != nil {
		return fmt.Errorf("%w: the card packet does not decode", ErrCardRefused)
	}
	if !p.loopback {
		for _, relay := range card.Card.Relays {
			if loopbackRelay(relay) {
				return fmt.Errorf("%w: the card names a relay on a loopback host, which only a node whose own "+
					"relays are on loopback accepts", ErrCardRefused)
			}
		}
	}
	if card.CapabilityID != "" {
		owner, ownerErr := p.owners.CapabilityOwner(ctx, card.CapabilityID)
		if ownerErr != nil {
			if errors.Is(ownerErr, ErrCardRefused) {
				return ownerErr
			}
			return fmt.Errorf("%w: %w", errCardUnavailable, ownerErr)
		}
		if owner != card.AgentID {
			return fmt.Errorf("%w: the card is of Agent %s, but the finalized owner of Capability %s is %s",
				ErrCardRefused, card.AgentID, card.CapabilityID, owner)
		}
	}
	resolver := &recordingResolver{next: p.agents}
	now := p.now()
	key, _, err := agentpacketseal.VerifyKeyCard(ctx, p.verifier, resolver, packet, now)
	if err != nil {
		if resolver.failed() || errors.Is(err, mldsa44.ErrUnavailable) || ctx.Err() != nil {
			return fmt.Errorf("%w: %w", errCardUnavailable, err)
		}
		return fmt.Errorf("%w: %v", ErrCardRefused, err)
	}
	if key.AgentID != card.AgentID || key.KeyID != card.Key.KeyID {
		return fmt.Errorf("%w: the card is of another Agent", ErrCardRefused)
	}
	card.verifiedAt = now
	return nil
}

func (p *PeerCards) storeLocked(card *peerCard) error {
	now := p.nowUnix()
	existing := p.cards[card.AgentID]
	if existing == nil && len(p.cards) >= maxCardPeers {
		p.pruneLocked(now)
		if len(p.cards) >= maxCardPeers {
			return errPeerCardsFull
		}
	}
	for index, held := range existing {
		if held.Key.KeyID == card.Key.KeyID {
			// The same key under a card that verified just now replaces the
			// held one; both are signed by the Agent.
			existing[index] = card
			return p.writeLocked(card)
		}
	}
	p.cards[card.AgentID] = append(existing, card)
	p.sortLocked(card.AgentID)
	if list := p.cards[card.AgentID]; len(list) > maxCardsPerPeer {
		dropped := list[maxCardsPerPeer:]
		p.cards[card.AgentID] = list[:maxCardsPerPeer]
		for _, old := range dropped {
			if err := p.removeFile(old); err != nil {
				return err
			}
		}
		if !p.holdsLocked(card) {
			return nil
		}
	}
	return p.writeLocked(card)
}

func (p *PeerCards) holdsLocked(card *peerCard) bool {
	for _, held := range p.cards[card.AgentID] {
		if held == card {
			return true
		}
	}
	return false
}

func (p *PeerCards) writeLocked(card *peerCard) error {
	return writeJSON(filepath.Join(p.directory, peerCardFile(card)), peerCardRecord{
		Schema: peerCardSchema, AgentID: card.AgentID, CapabilityID: card.CapabilityID,
		CardPacketBase64: base64.StdEncoding.EncodeToString(card.JSON),
	}, false)
}

func (p *PeerCards) removeFile(card *peerCard) error {
	if err := os.Remove(filepath.Join(p.directory, peerCardFile(card))); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("servicebridge: remove a peer card")
	}
	return syncDirectory(p.directory)
}

func (p *PeerCards) sortLocked(agent string) {
	list := p.cards[agent]
	sort.Slice(list, func(i, j int) bool {
		return preferCard(list[i].Card.NotBeforeUnix, list[i].Key.KeyID, list[j].Card.NotBeforeUnix, list[j].Key.KeyID)
	})
}

func (p *PeerCards) nowUnix() uint64 {
	now := p.now().Unix()
	if now <= 0 {
		return 0
	}
	return uint64(now)
}

// pruneLocked drops cards that can no longer be sealed to.
func (p *PeerCards) pruneLocked(now uint64) {
	for agent, list := range p.cards {
		kept := list[:0]
		for _, card := range list {
			if now < card.Card.NotAfterUnix {
				kept = append(kept, card)
			} else {
				_ = p.removeFile(card)
			}
		}
		if len(kept) == 0 {
			delete(p.cards, agent)
		} else {
			p.cards[agent] = kept
		}
	}
}

// Has reports whether a card of agentID is held that is not yet expired;
// whether it still verifies is decided at the seal.
func (p *PeerCards) Has(agentID string) bool {
	if p == nil {
		return false
	}
	p.mutex.Lock()
	defer p.mutex.Unlock()
	now := p.nowUnix()
	held := func() bool {
		for _, card := range p.cards[agentID] {
			if now < card.Card.NotAfterUnix {
				return true
			}
		}
		return false
	}
	if p.dropRemoved {
		// A removed contact must not count as held from memory.
		if err := p.reloadLocked(); err != nil {
			return false
		}
		return held()
	}
	if held() {
		return true
	}
	// A directory that cannot be read now leaves the route to what is held
	// in memory; Current reports the failure when a send needs the card.
	if err := p.reloadLocked(); err != nil {
		return false
	}
	return held()
}

// reloadLocked adds cards another process of this node stored since the
// directory was opened: `buy --offer` takes the provider's card while
// `serve` runs. A card it adds is verified again before its first use; a card
// already held keeps its verification.
func (p *PeerCards) reloadLocked() error {
	if p.directory == "" {
		return nil
	}
	stored, err := readPeerCards(p.directory)
	if err != nil {
		return err
	}
	if p.dropRemoved {
		// A card whose file another process removed (`chat contact remove`)
		// is no longer sealed to here either.
		files := make(map[string]bool, len(stored))
		for _, card := range stored {
			files[peerCardFile(card)] = true
		}
		for agent, list := range p.cards {
			kept := list[:0]
			for _, held := range list {
				if files[peerCardFile(held)] {
					kept = append(kept, held)
				}
			}
			if len(kept) == 0 {
				delete(p.cards, agent)
			} else {
				p.cards[agent] = kept
			}
		}
	}
	for _, card := range stored {
		known := false
		for _, held := range p.cards[card.AgentID] {
			if held.Key.KeyID == card.Key.KeyID {
				known = true
				break
			}
		}
		if known {
			continue
		}
		if _, ok := p.cards[card.AgentID]; !ok && len(p.cards) >= maxCardPeers {
			continue
		}
		p.cards[card.AgentID] = append(p.cards[card.AgentID], card)
		p.sortLocked(card.AgentID)
	}
	return nil
}

// Current returns the card to seal a packet for agentID to: of the held
// cards that are inside their window now and still verify against
// finalized state, the one with the greatest not_before (ties: greatest key
// id). A card that no longer verifies is dropped; a check finalized state
// cannot answer fails the call and keeps the card.
func (p *PeerCards) Current(ctx context.Context, agentID string) (*peerCard, error) {
	if p == nil || ctx == nil {
		return nil, ErrNoPacketRoute
	}
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if err := p.reloadLocked(); err != nil {
		return nil, fmt.Errorf("servicebridge: read the peer card directory: %w", err)
	}
	now := p.now()
	list := append([]*peerCard(nil), p.cards[agentID]...)
	var unavailable error
	for _, card := range list {
		if agentpacketseal.CheckKeyCardTime(card.Card, now) != nil {
			continue
		}
		if card.verifiedAt.IsZero() || now.Sub(card.verifiedAt) >= RelayCardReverify || now.Before(card.verifiedAt) {
			err := p.verify(ctx, card)
			if errors.Is(err, errCardUnavailable) {
				unavailable = err
				continue
			}
			if err != nil {
				p.dropLocked(card)
				continue
			}
		}
		if card.AgentID != agentID || card.Key.AgentID != agentID {
			continue
		}
		copied := *card
		return &copied, nil
	}
	if unavailable != nil {
		return nil, unavailable
	}
	return nil, ErrNoPacketRoute
}

// Usable reports whether the held card of agentID with keyID may still be
// sealed or sent to now: inside its window and verified against finalized
// state within RelayCardReverify, verifying it again when that is older. A
// card that is expired, revoked or not held is ErrCardRefused (a revoked one
// is dropped); a check finalized state cannot answer is another error.
func (p *PeerCards) Usable(ctx context.Context, agentID string, keyID [agentpacketseal.KeyIDSize]byte) error {
	if p == nil || ctx == nil {
		return ErrCardRefused
	}
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if err := p.reloadLocked(); err != nil {
		return fmt.Errorf("servicebridge: read the peer card directory: %w", err)
	}
	now := p.now()
	for _, card := range p.cards[agentID] {
		if card.Key.KeyID != keyID {
			continue
		}
		if agentpacketseal.CheckKeyCardTime(card.Card, now) != nil {
			return fmt.Errorf("%w: the card is outside its validity window", ErrCardRefused)
		}
		if !card.verifiedAt.IsZero() && now.Sub(card.verifiedAt) < RelayCardReverify && !now.Before(card.verifiedAt) {
			return nil
		}
		err := p.verify(ctx, card)
		if err != nil && !errors.Is(err, errCardUnavailable) {
			p.dropLocked(card)
		}
		return err
	}
	return fmt.Errorf("%w: the card is not held", ErrCardRefused)
}

func (p *PeerCards) dropLocked(card *peerCard) {
	list := p.cards[card.AgentID]
	kept := list[:0]
	for _, held := range list {
		if held != card {
			kept = append(kept, held)
		}
	}
	if len(kept) == 0 {
		delete(p.cards, card.AgentID)
	} else {
		p.cards[card.AgentID] = kept
	}
	_ = p.removeFile(card)
}

// PeerCardView is a held card as status and preflight show it.
type PeerCardView struct {
	AgentID       string   `json:"agent_id"`
	CapabilityID  string   `json:"capability_id,omitempty"`
	KeyID         string   `json:"key_id"`
	NotBeforeUnix uint64   `json:"not_before_unix"`
	NotAfterUnix  uint64   `json:"not_after_unix"`
	Relays        []string `json:"relays"`
}

// List returns every held card, by Agent and preference.
func (p *PeerCards) List() []PeerCardView {
	if p == nil {
		return nil
	}
	p.mutex.Lock()
	defer p.mutex.Unlock()
	agents := make([]string, 0, len(p.cards))
	for agent := range p.cards {
		agents = append(agents, agent)
	}
	sort.Strings(agents)
	var out []PeerCardView
	for _, agent := range agents {
		for _, card := range p.cards[agent] {
			out = append(out, PeerCardView{
				AgentID: agent, CapabilityID: card.CapabilityID, KeyID: agentpacketseal.KeyIDText(card.Key.KeyID),
				NotBeforeUnix: card.Card.NotBeforeUnix, NotAfterUnix: card.Card.NotAfterUnix,
				Relays: append([]string(nil), card.Card.Relays...),
			})
		}
	}
	return out
}

// VerifyAll checks every held card against finalized state now, without
// dropping any, and reports each result.
func (p *PeerCards) VerifyAll(ctx context.Context) map[string]error {
	out := map[string]error{}
	if p == nil {
		return out
	}
	p.mutex.Lock()
	var all []*peerCard
	for _, list := range p.cards {
		for _, card := range list {
			copied := *card
			all = append(all, &copied)
		}
	}
	p.mutex.Unlock()
	for _, card := range all {
		out[card.AgentID+" "+agentpacketseal.KeyIDText(card.Key.KeyID)] = p.verify(ctx, card)
	}
	return out
}

// recordingResolver remembers whether finalized state failed to answer, so a
// refusal caused by an outage is told apart from one finalized state made.
type recordingResolver struct {
	next  agentpacket.AgentResolver
	mutex sync.Mutex
	err   bool
}

func (r *recordingResolver) ResolveAgent(agentID string) (*nativev1.AgentStateV1, bool, error) {
	state, found, err := r.next.ResolveAgent(agentID)
	if err != nil {
		r.mutex.Lock()
		r.err = true
		r.mutex.Unlock()
	}
	return state, found, err
}

func (r *recordingResolver) failed() bool {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.err
}
