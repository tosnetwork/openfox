package servicebridge

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
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

// Key file schemas. A key file names its purpose, so a chat key file
// copied into the rail key directory (or the reverse) is refused at load:
// no key ever serves both purposes.
const (
	relayKeySchema     = "tos.openfox.relay-key.v1"
	relayChatKeySchema = "tos.openfox.relay-chat-key.v1"
)

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
	// SignerKeyID is the controller key that signed the card.
	SignerKeyID [mldsa44.KeyIDSize]byte
	// CardJSON is the exact signed key card packet.
	CardJSON []byte
	private  agentpacketseal.PrivateKey
}

// DestroyAtUnix is when the private key is destroyed.
func (k OwnRelayKey) DestroyAtUnix() uint64 {
	return saturatingAdd(k.NotAfterUnix, uint64(RelayKeyRetention/time.Second))
}

// cardSigner signs a key card packet as the local Agent. A key set hands
// out only cards its signer's key signed: a card another controller signed
// (before a rotation of the signer) is kept until its key's retention ends,
// so envelopes already sealed to it still open, but it is never handed out
// again; a successor is issued in its place.
type cardSigner interface {
	signKeyCard(ctx context.Context, card agentpacketseal.KeyCard) ([]byte, error)
	cardKeyID() [mldsa44.KeyIDSize]byte
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
	// schema is the purpose of every key file here; empty is the rail's.
	schema string
	mutex  sync.Mutex
	keys   []OwnRelayKey
}

// keySchema is the key file schema of this set's purpose.
func (k *RelayKeys) keySchema() string {
	if k.schema == "" {
		return relayKeySchema
	}
	return k.schema
}

// OpenRelayKeys loads the held keys, refusing any file that is not exactly
// a key of this Agent, and destroys keys past their retention.
func OpenRelayKeys(directory, agentID string, relays []string, signer cardSigner,
	now func() time.Time,
) (*RelayKeys, error) {
	return openRelayKeys(directory, agentID, relays, signer, now, relayKeySchema)
}

// OpenChatRelayKeys opens the chat key set: its own directory and its own
// key file schema, never derived from or shared with the rail keys.
func OpenChatRelayKeys(directory, agentID string, relays []string, signer cardSigner,
	now func() time.Time,
) (*RelayKeys, error) {
	return openRelayKeys(directory, agentID, relays, signer, now, relayChatKeySchema)
}

func openRelayKeys(directory, agentID string, relays []string, signer cardSigner,
	now func() time.Time, schema string,
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
	keys := &RelayKeys{
		directory: directory, agentID: agentID, relays: canonical, signer: signer, now: now, schema: schema,
	}
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
		// No percent escape at all: the relay client refuses one even
		// where the URL parser would accept it.
		if err := agentpacketseal.CheckRelayURL(relay); err != nil || strings.Contains(relay, "%") ||
			numericHostIsNonCanonical(relay) {
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

// rescanLocked adds keys another process of this node wrote since the
// directory was loaded (`offer` and `buy` run beside `serve`), so they are
// polled for and destroyed on time like the node's own.
func (k *RelayKeys) rescanLocked() error {
	entries, err := os.ReadDir(k.directory)
	if err != nil {
		return errors.New("servicebridge: read the relay key directory")
	}
	added := false
	for _, entry := range entries {
		if !relayKeyFilePattern.MatchString(entry.Name()) {
			continue
		}
		known := false
		for _, key := range k.keys {
			if hex.EncodeToString(key.KeyID[:])+".json" == entry.Name() {
				known = true
				break
			}
		}
		if known {
			continue
		}
		key, err := k.readKey(filepath.Join(k.directory, entry.Name()))
		if err != nil {
			return fmt.Errorf("servicebridge: relay key file %s: %w", entry.Name(), err)
		}
		k.keys, added = append(k.keys, key), true
	}
	if added {
		k.sortKeys()
	}
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
	if record.Schema != k.keySchema() || record.AgentID != k.agentID {
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
	card, signerKey, err := decodeOwnCardSigned(k.agentID, cardJSON)
	if err != nil {
		return OwnRelayKey{}, err
	}
	if card.KeyID != private.KeyID || card.NotBeforeUnix != record.NotBeforeUnix ||
		card.NotAfterUnix != record.NotAfterUnix || !slices.Equal(card.Relays, record.Relays) {
		return OwnRelayKey{}, errors.New("the card does not publish this key")
	}
	return OwnRelayKey{
		KeyID: private.KeyID, NotBeforeUnix: card.NotBeforeUnix, NotAfterUnix: card.NotAfterUnix,
		Relays: card.Relays, SignerKeyID: signerKey, CardJSON: cardJSON, private: private,
	}, nil
}

// decodeOwnCard decodes a card packet of agentID without the finalized
// signature check, which needs chain state and is the preflight's.
func decodeOwnCard(agentID string, cardJSON []byte) (agentpacketseal.KeyCard, error) {
	card, _, err := decodeOwnCardSigned(agentID, cardJSON)
	return card, err
}

// decodeOwnCardSigned decodes a card packet of agentID, with the key id of the
// controller that signed it, without the finalized signature check, which
// needs chain state and is the preflight's.
func decodeOwnCardSigned(agentID string, cardJSON []byte) (agentpacketseal.KeyCard, [mldsa44.KeyIDSize]byte,
	error,
) {
	packet, err := agentpacket.DecodeJSON(cardJSON)
	if err != nil || packet.SenderAgentID != agentID || packet.RecipientAgentID != agentpacketseal.KeyCardAudience ||
		packet.CapabilityID != agentpacketseal.KeyCardCapability || packet.QuoteCommitment != "" {
		return agentpacketseal.KeyCard{}, [mldsa44.KeyIDSize]byte{}, errors.New("the card is not a key card of " +
			"this Agent")
	}
	card, err := agentpacketseal.DecodeKeyCard(packet.Payload)
	if err != nil {
		return agentpacketseal.KeyCard{}, [mldsa44.KeyIDSize]byte{}, errors.New("the card body is not a valid key " +
			"card")
	}
	return card, packet.SenderKeyID, nil
}

// handsOut reports whether a held key's card may be handed out now under
// the given signer key: valid now, naming exactly the configured relays,
// and signed by that key.
func handsOut(key OwnRelayKey, now uint64, relays []string, signerKey [mldsa44.KeyIDSize]byte) bool {
	return key.NotBeforeUnix <= now && now < key.NotAfterUnix && slices.Equal(key.Relays, relays) &&
		key.SignerKeyID == signerKey
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
	if err := k.rescanLocked(); err != nil {
		return false, err
	}
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
// configured relays, and expiring no earlier than coverUntil when a held
// card does. A cover past the default lifetime is met by a 30-day card that
// is reused while it runs at least relayLongCoverFloor longer, so it may end
// before a far coverUntil; the peer gets later cards in band. A new card is
// issued only when no held card qualifies.
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

// relayLongCoverFloor is how long a card issued for a long cover must still
// run to be handed out again for another long cover. A target past the
// default lifetime is met by a card of the longest lifetime; until that card
// runs within this floor it is reused, whatever the target, and later cards
// reach the peer in band (each task redelivery, result and acknowledgement
// carries the sender's current card). So a target that moves with the clock,
// or many requests with different deadlines, never issue a key per call.
const relayLongCoverFloor = agentpacketseal.MaxKeyCardLifetime / 2

func (k *RelayKeys) currentLocked(ctx context.Context, now, coverUntil uint64) (OwnRelayKey, bool, error) {
	longest := saturatingAdd(now, uint64(agentpacketseal.MaxKeyCardLifetime/time.Second))
	target := coverUntil
	if target > longest {
		target = longest
	}
	long := target > saturatingAdd(now, uint64(RelayKeyLifetime/time.Second))
	var latest *OwnRelayKey
	signerKey := k.signer.cardKeyID()
	for index := range k.keys {
		key := &k.keys[index]
		if !handsOut(*key, now, k.relays, signerKey) {
			continue
		}
		if key.NotAfterUnix >= target {
			return *key, false, nil
		}
		if latest == nil || key.NotAfterUnix > latest.NotAfterUnix {
			latest = key
		}
	}
	if long && latest != nil &&
		latest.NotAfterUnix >= saturatingAdd(now, uint64(relayLongCoverFloor/time.Second)) {
		return *latest, false, nil
	}
	notAfter := saturatingAdd(now, uint64(RelayKeyLifetime/time.Second))
	if long {
		notAfter = longest
	} else if target > notAfter {
		notAfter = target
	}
	key, err := k.issueLocked(ctx, now, notAfter)
	return key, err == nil, err
}

// issueLocked draws a new key, signs its card with the set's signer (the
// packet controller for rail cards, the card-signing controller for chat
// cards) and writes both in one owner-only file before the key is used.
func (k *RelayKeys) issueLocked(ctx context.Context, now, notAfter uint64) (OwnRelayKey, error) {
	if len(k.keys) >= maxRelayKeys {
		return OwnRelayKey{}, fmt.Errorf("servicebridge: %d relay keys are held; no further key is issued until "+
			"older ones are destroyed", maxRelayKeys)
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
	_, signerKey, err := decodeOwnCardSigned(k.agentID, cardJSON)
	if err != nil || signerKey != k.signer.cardKeyID() {
		return OwnRelayKey{}, errors.New("servicebridge: the signed key card is not signed by the card signer's key")
	}
	record := relayKeyRecord{
		Schema: k.keySchema(), AgentID: k.agentID, KeyID: agentpacketseal.KeyIDText(private.KeyID),
		SeedBase64: base64.StdEncoding.EncodeToString(seed), NotBeforeUnix: now, NotAfterUnix: notAfter,
		Relays: card.Relays, CardPacketBase64: base64.StdEncoding.EncodeToString(cardJSON),
	}
	path := filepath.Join(k.directory, hex.EncodeToString(private.KeyID[:])+".json")
	if err := writeJSON(path, record, true); err != nil {
		return OwnRelayKey{}, err
	}
	key := OwnRelayKey{
		KeyID: private.KeyID, NotBeforeUnix: now, NotAfterUnix: notAfter, Relays: card.Relays,
		SignerKeyID: signerKey, CardJSON: cardJSON, private: private,
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

// cardKeyID is the key that signs this signer's key cards.
func (s *PacketSigner) cardKeyID() [mldsa44.KeyIDSize]byte { return s.KeyID }

// signKeyCard signs a key card packet: an ordinary Agent Packet to the
// all-zero audience, signed by this signer's controller.
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

// numericHostIsNonCanonical reports a relay URL whose host is a numeric
// address in a non-canonical form.
func numericHostIsNonCanonical(relay string) bool {
	parsed, err := url.Parse(relay)
	return err != nil || nonCanonicalNumericHost(strings.ToLower(parsed.Hostname()))
}
