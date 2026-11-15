package servicebridge

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
)

// Encryption key lifetimes of the relay transport.
const (
	// RelayKeyLifetime is the validity window of a key card the node
	// issues; the protocol allows at most 30 days and recommends 7.
	RelayKeyLifetime = 7 * 24 * time.Hour
	// RelaySuccessorLead is how long before the current card's expiry a
	// successor is issued, so it can be published at least 24 hours ahead
	// even when the node runs its maintenance only now and then.
	RelaySuccessorLead = 48 * time.Hour
	// RelayKeyRetention is how long a private key is kept after its card
	// expired: the longest an envelope sealed before expiry can wait at a
	// relay (24 hours) plus the clock skew allowance (5 minutes). The key is
	// destroyed once it has passed.
	RelayKeyRetention = 24*time.Hour + agentpacketseal.ClockSkew
	// maxRelayKeys bounds the keys held at once; issuing stops before it.
	maxRelayKeys = 16
)

const relayKeySchema = "tos.openfox.relay-key.v1"

// relayKeyRecord is one owner-only private key file. It is the only place
// the seed exists outside process memory, and it is never logged.
type relayKeyRecord struct {
	Schema           string   `json:"schema"`
	AgentID          string   `json:"agent_id"`
	KeyID            string   `json:"key_id"`
	SeedBase64       string   `json:"seed_base64"`
	NotBeforeUnix    uint64   `json:"not_before_unix"`
	NotAfterUnix     uint64   `json:"not_after_unix"`
	Relays           []string `json:"relays"`
	CardPacketBase64 string   `json:"card_packet_base64"`
}

var relayKeyFilePattern = regexp.MustCompile(`^[0-9a-f]{64}\.json$`)

// OwnRelayKey is one held encryption key with the card that publishes it.
type OwnRelayKey struct {
	KeyID         [agentpacketseal.KeyIDSize]byte
	NotBeforeUnix uint64
	NotAfterUnix  uint64
	Relays        []string
	// CardJSON is the exact signed key card packet.
	CardJSON []byte
	private  agentpacketseal.PrivateKey
}

// DestroyAtUnix is when the private key is destroyed.
func (k OwnRelayKey) DestroyAtUnix() uint64 {
	return saturatingAdd(k.NotAfterUnix, uint64(RelayKeyRetention/time.Second))
}

// cardSigner signs a key card packet as the local Agent.
type cardSigner interface {
	signKeyCard(ctx context.Context, card agentpacketseal.KeyCard) ([]byte, error)
}

// RelayKeys holds a node's HPKE private keys in an owner-private directory
// and issues, rotates and destroys them with their cards. One process owns
// the directory.
type RelayKeys struct {
	directory string
	agentID   string
	relays    []string
	signer    cardSigner
	now       func() time.Time
	mutex     sync.Mutex
	keys      []OwnRelayKey
}

// OpenRelayKeys loads the held keys, refusing any file that is not exactly
// a key of this Agent, and destroys keys past their retention.
func OpenRelayKeys(directory, agentID string, relays []string, signer cardSigner,
	now func() time.Time,
) (*RelayKeys, error) {
	if !cleanAbsolute(directory) || !agentIDPattern.MatchString(agentID) || signer == nil {
		return nil, errors.New("servicebridge: invalid relay key configuration")
	}
	canonical, err := canonicalRelayURLs(relays)
	if err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	if err := ensurePrivateDirectory(directory); err != nil {
		return nil, err
	}
	keys := &RelayKeys{directory: directory, agentID: agentID, relays: canonical, signer: signer, now: now}
	if err := keys.load(); err != nil {
		return nil, err
	}
	if err := keys.destroyExpired(); err != nil {
		return nil, err
	}
	return keys, nil
}

// canonicalRelayURLs checks relay base URLs and returns them in the
// ascending byte order a key card requires.
func canonicalRelayURLs(relays []string) ([]string, error) {
	if len(relays) == 0 || len(relays) > agentpacketseal.MaxRelays {
		return nil, fmt.Errorf("servicebridge: configure 1 to %d relay URLs", agentpacketseal.MaxRelays)
	}
	out := append([]string(nil), relays...)
	sort.Strings(out)
	for index, relay := range out {
		if err := agentpacketseal.CheckRelayURL(relay); err != nil {
			return nil, fmt.Errorf("servicebridge: relay URL %q is not a canonical base URL: https, or http only to "+
				"127.0.0.1, localhost or ::1; lowercase host; no user, query, fragment, escape or trailing slash",
				relay)
		}
		if index > 0 && out[index-1] == relay {
			return nil, fmt.Errorf("servicebridge: relay URL %q is configured twice", relay)
		}
	}
	return out, nil
}

func (k *RelayKeys) load() error {
	entries, err := os.ReadDir(k.directory)
	if err != nil {
		return errors.New("servicebridge: read the relay key directory")
	}
	for _, entry := range entries {
		if !relayKeyFilePattern.MatchString(entry.Name()) {
			continue
		}
		key, err := k.readKey(filepath.Join(k.directory, entry.Name()))
		if err != nil {
			return fmt.Errorf("servicebridge: relay key file %s: %w", entry.Name(), err)
		}
		k.keys = append(k.keys, key)
	}
	k.sortKeys()
	return nil
}

// readKey decodes one key file and requires every part of it to agree: the
// seed derives the named key id, which is the file name, and the card is a
// card of this Agent for exactly that key, window and relay list.
func (k *RelayKeys) readKey(path string) (OwnRelayKey, error) {
	var record relayKeyRecord
	if err := readJSON(path, 64<<10, &record); err != nil {
		return OwnRelayKey{}, err
	}
	if record.Schema != relayKeySchema || record.AgentID != k.agentID {
		return OwnRelayKey{}, errors.New("not a relay key of this Agent")
	}
	seed, err := base64.StdEncoding.Strict().DecodeString(record.SeedBase64)
	if err != nil {
		return OwnRelayKey{}, errors.New("the seed does not decode")
	}
	private, err := agentpacketseal.NewPrivateKey(k.agentID, seed)
	clear(seed)
	if err != nil {
		return OwnRelayKey{}, errors.New("the seed is not a key of the relay suite")
	}
	if agentpacketseal.KeyIDText(private.KeyID) != record.KeyID ||
		filepath.Base(path) != hex.EncodeToString(private.KeyID[:])+".json" {
		return OwnRelayKey{}, errors.New("the key id does not match the seed")
	}
	cardJSON, err := base64.StdEncoding.Strict().DecodeString(record.CardPacketBase64)
	if err != nil {
		return OwnRelayKey{}, errors.New("the card does not decode")
	}
	card, err := decodeOwnCard(k.agentID, cardJSON)
	if err != nil {
		return OwnRelayKey{}, err
	}
	if card.KeyID != private.KeyID || card.NotBeforeUnix != record.NotBeforeUnix ||
		card.NotAfterUnix != record.NotAfterUnix || !slices.Equal(card.Relays, record.Relays) {
		return OwnRelayKey{}, errors.New("the card does not publish this key")
	}
	return OwnRelayKey{
		KeyID: private.KeyID, NotBeforeUnix: card.NotBeforeUnix, NotAfterUnix: card.NotAfterUnix,
		Relays: card.Relays, CardJSON: cardJSON, private: private,
	}, nil
}

// decodeOwnCard decodes a card packet of agentID without the finalized
// signature check, which needs chain state and is the preflight's.
func decodeOwnCard(agentID string, cardJSON []byte) (agentpacketseal.KeyCard, error) {
	packet, err := agentpacket.DecodeJSON(cardJSON)
	if err != nil || packet.SenderAgentID != agentID || packet.RecipientAgentID != agentpacketseal.KeyCardAudience ||
		packet.CapabilityID != agentpacketseal.KeyCardCapability || packet.QuoteCommitment != "" {
		return agentpacketseal.KeyCard{}, errors.New("the card is not a key card of this Agent")
	}
	card, err := agentpacketseal.DecodeKeyCard(packet.Payload)
	if err != nil {
		return agentpacketseal.KeyCard{}, errors.New("the card body is not a valid key card")
	}
	return card, nil
}

// sortKeys orders keys by sealing preference: greatest not_before first,
// ties by greatest key id.
func (k *RelayKeys) sortKeys() {
	sort.Slice(k.keys, func(i, j int) bool {
		return preferCard(k.keys[i].NotBeforeUnix, k.keys[i].KeyID, k.keys[j].NotBeforeUnix, k.keys[j].KeyID)
	})
}

// preferCard reports whether card a is preferred over card b for sealing.
func preferCard(aNotBefore uint64, aKey [32]byte, bNotBefore uint64, bKey [32]byte) bool {
	if aNotBefore != bNotBefore {
		return aNotBefore > bNotBefore
	}
	return bytes.Compare(aKey[:], bKey[:]) > 0
}

func (k *RelayKeys) nowUnix() (uint64, error) {
	now := k.now()
	if now.Unix() <= 0 {
		return 0, errors.New("servicebridge: the clock is not set")
	}
	return uint64(now.Unix()), nil
}

// destroyExpired removes every key whose retention has passed. Destruction
// deletes the only file holding the seed and syncs the directory; the
// in-memory key is dropped with it.
func (k *RelayKeys) destroyExpired() error {
	now, err := k.nowUnix()
	if err != nil {
		return err
	}
	kept := k.keys[:0]
	var failures []error
	for _, key := range k.keys {
		if now <= key.DestroyAtUnix() {
			kept = append(kept, key)
			continue
		}
		path := filepath.Join(k.directory, hex.EncodeToString(key.KeyID[:])+".json")
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			failures = append(failures, errors.New("servicebridge: destroy an expired relay key"))
			kept = append(kept, key)
		}
	}
	k.keys = kept
	if len(failures) > 0 {
		return errors.Join(failures...)
	}
	return syncDirectory(k.directory)
}

// Maintain destroys keys past retention and issues a successor card when
// the current one expires within RelaySuccessorLead or no longer names the
// configured relays. It reports whether a new card was issued.
func (k *RelayKeys) Maintain(ctx context.Context) (bool, error) {
	if k == nil || ctx == nil {
		return false, errors.New("servicebridge: invalid relay key maintenance")
	}
	k.mutex.Lock()
	defer k.mutex.Unlock()
	if err := k.destroyExpired(); err != nil {
		return false, err
	}
	now, err := k.nowUnix()
	if err != nil {
		return false, err
	}
	minimum := saturatingAdd(now, uint64(RelaySuccessorLead/time.Second))
	_, issued, err := k.currentLocked(ctx, now, minimum)
	return issued, err
}

// Current returns the card to hand out now: valid now, naming the
// configured relays, and expiring no earlier than coverUntil when that can
// be met within the 30-day card bound. A new card is issued when needed.
func (k *RelayKeys) Current(ctx context.Context, coverUntil uint64) (OwnRelayKey, error) {
	if k == nil || ctx == nil {
		return OwnRelayKey{}, errors.New("servicebridge: invalid relay key request")
	}
	k.mutex.Lock()
	defer k.mutex.Unlock()
	now, err := k.nowUnix()
	if err != nil {
		return OwnRelayKey{}, err
	}
	key, _, err := k.currentLocked(ctx, now, coverUntil)
	return key, err
}

func (k *RelayKeys) currentLocked(ctx context.Context, now, coverUntil uint64) (OwnRelayKey, bool, error) {
	longest := saturatingAdd(now, uint64(agentpacketseal.MaxKeyCardLifetime/time.Second))
	if coverUntil > longest {
		coverUntil = longest
	}
	for _, key := range k.keys {
		if key.NotBeforeUnix <= now && now < key.NotAfterUnix && key.NotAfterUnix >= coverUntil &&
			slices.Equal(key.Relays, k.relays) {
			return key, false, nil
		}
	}
	key, err := k.issueLocked(ctx, now, coverUntil)
	return key, err == nil, err
}

// issueLocked draws a new key, signs its card with the packet controller
// and writes both in one owner-only file before the key is used.
func (k *RelayKeys) issueLocked(ctx context.Context, now, coverUntil uint64) (OwnRelayKey, error) {
	if len(k.keys) >= maxRelayKeys {
		return OwnRelayKey{}, fmt.Errorf("servicebridge: %d relay keys are held; no further key is issued until "+
			"older ones are destroyed", maxRelayKeys)
	}
	notAfter := saturatingAdd(now, uint64(RelayKeyLifetime/time.Second))
	if coverUntil > notAfter {
		notAfter = coverUntil
	}
	seed, err := agentpacketseal.GenerateSeed()
	if err != nil {
		return OwnRelayKey{}, errors.New("servicebridge: draw a relay key")
	}
	defer clear(seed)
	private, err := agentpacketseal.NewPrivateKey(k.agentID, seed)
	if err != nil {
		return OwnRelayKey{}, errors.New("servicebridge: derive a relay key")
	}
	public, err := private.PublicKey()
	if err != nil {
		return OwnRelayKey{}, errors.New("servicebridge: derive a relay public key")
	}
	card := agentpacketseal.KeyCard{
		PublicKey: public, KeyID: private.KeyID, NotBeforeUnix: now, NotAfterUnix: notAfter,
		Relays: append([]string(nil), k.relays...),
	}
	cardJSON, err := k.signer.signKeyCard(ctx, card)
	if err != nil {
		return OwnRelayKey{}, fmt.Errorf("servicebridge: sign the relay key card: %w", err)
	}
	record := relayKeyRecord{
		Schema: relayKeySchema, AgentID: k.agentID, KeyID: agentpacketseal.KeyIDText(private.KeyID),
		SeedBase64: base64.StdEncoding.EncodeToString(seed), NotBeforeUnix: now, NotAfterUnix: notAfter,
		Relays: card.Relays, CardPacketBase64: base64.StdEncoding.EncodeToString(cardJSON),
	}
	path := filepath.Join(k.directory, hex.EncodeToString(private.KeyID[:])+".json")
	if err := writeJSON(path, record, true); err != nil {
		return OwnRelayKey{}, err
	}
	key := OwnRelayKey{
		KeyID: private.KeyID, NotBeforeUnix: now, NotAfterUnix: notAfter, Relays: card.Relays, CardJSON: cardJSON,
		private: private,
	}
	k.keys = append(k.keys, key)
	k.sortKeys()
	return key, nil
}

// private returns the held private key with this key id.
func (k *RelayKeys) private(keyID [agentpacketseal.KeyIDSize]byte) (agentpacketseal.PrivateKey, bool) {
	k.mutex.Lock()
	defer k.mutex.Unlock()
	for _, key := range k.keys {
		if key.KeyID == keyID {
			return key.private, true
		}
	}
	// `offer` runs as its own process and may have issued a key since this
	// one loaded the directory.
	if keyID == ([agentpacketseal.KeyIDSize]byte{}) || len(k.keys) >= maxRelayKeys {
		return agentpacketseal.PrivateKey{}, false
	}
	key, err := k.readKey(filepath.Join(k.directory, hex.EncodeToString(keyID[:])+".json"))
	if err != nil {
		return agentpacketseal.PrivateKey{}, false
	}
	now, err := k.nowUnix()
	if err != nil || now > key.DestroyAtUnix() {
		return agentpacketseal.PrivateKey{}, false
	}
	k.keys = append(k.keys, key)
	k.sortKeys()
	return key.private, true
}

// PollRelays is every relay named by a card whose private key is held: the
// node polls all of them.
func (k *RelayKeys) PollRelays() []string {
	k.mutex.Lock()
	defer k.mutex.Unlock()
	seen := map[string]bool{}
	for _, relay := range k.relays {
		seen[relay] = true
	}
	for _, key := range k.keys {
		for _, relay := range key.Relays {
			seen[relay] = true
		}
	}
	out := make([]string, 0, len(seen))
	for relay := range seen {
		out = append(out, relay)
	}
	sort.Strings(out)
	return out
}

// Held lists the held keys, newest first, without their private parts.
func (k *RelayKeys) Held() []OwnRelayKey {
	k.mutex.Lock()
	defer k.mutex.Unlock()
	out := make([]OwnRelayKey, 0, len(k.keys))
	for _, key := range k.keys {
		key.private = agentpacketseal.PrivateKey{}
		key.Relays = append([]string(nil), key.Relays...)
		key.CardJSON = append([]byte(nil), key.CardJSON...)
		out = append(out, key)
	}
	return out
}

// signKeyCard signs a key card packet: an ordinary Agent Packet to the
// all-zero audience, signed by the packet controller like every packet.
func (s *PacketSigner) signKeyCard(ctx context.Context, card agentpacketseal.KeyCard) ([]byte, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, errors.New("servicebridge: draw key card nonce")
	}
	s.mutex.Lock()
	now := uint64(s.now().Unix())
	if s.sequence < now<<16 {
		s.sequence = now << 16
	}
	s.sequence++
	sequence := s.sequence
	s.mutex.Unlock()
	packet, err := agentpacketseal.KeyCardPacket(s.AgentID, s.KeyID, sequence, nonce, now, card)
	if err != nil {
		return nil, err
	}
	signed, err := agentpacket.Sign(ctx, s.Signer, s.Controller, packet)
	if err != nil {
		return nil, err
	}
	return agentpacket.EncodeJSON(signed)
}

func saturatingAdd(a, b uint64) uint64 {
	if a > ^uint64(0)-b {
		return ^uint64(0)
	}
	return a + b
}
