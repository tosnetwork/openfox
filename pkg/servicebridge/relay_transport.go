package servicebridge

import (
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
	"strings"
	"sync"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketrelay"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
)

// Relay transport bounds.
const (
	// RelayEnvelopeTTL is the longest an envelope waits at a relay.
	RelayEnvelopeTTL = 24 * time.Hour
	// relayRedepositFirst and relayRedepositMax pace the background
	// deposits to the relays that have not accepted an envelope yet.
	relayRedepositFirst = 30 * time.Second
	relayRedepositMax   = 5 * time.Minute
)

// Relay transport failures. They are fixed strings: a transport error is
// logged, and nothing a relay answers is repeated.
var (
	// ErrRelayUndelivered reports a send no relay of the recipient's card
	// durably accepted; the courier retries it with the same envelope.
	ErrRelayUndelivered = errors.New("servicebridge: no relay of the recipient's key card accepted the envelope")
	// ErrRelayResealed reports a send every answering relay refused with a
	// conflict: another envelope holds its id there. A fresh seal under a
	// new acknowledgement secret is journaled and the courier retries.
	ErrRelayResealed = errors.New("servicebridge: the envelope id is taken at the recipient's relays; the packet " +
		"was sealed again under a new envelope id for the next attempt")
	// ErrRelayPacketTooLarge reports a packet beyond the receiver's bound.
	ErrRelayPacketTooLarge = errors.New("servicebridge: the packet exceeds the relay receiver's bound")
)

const relayOutboxSchema = "tos.openfox.relay-outbox.v1"

// relayOutboxRecord journals the one envelope a packet send uses. It is
// written before the first deposit, so a retry of an ambiguous deposit
// sends exactly these bytes and the relay recognizes them. The
// acknowledgement secret is not kept: the sender never needs it.
type relayOutboxRecord struct {
	Schema         string   `json:"schema"`
	Recipient      string   `json:"recipient"`
	IdempotencyKey string   `json:"idempotency_key"`
	KeyID          string   `json:"recipient_key_id"`
	Relays         []string `json:"relays"`
	EnvelopeID     string   `json:"envelope_id"`
	EnvelopeBase64 string   `json:"envelope_base64"`
	ExpiresAtUnix  uint64   `json:"expires_at_unix"`
	Accepted       []string `json:"accepted,omitempty"`
	Conflicts      []string `json:"conflicts,omitempty"`
	Seals          int      `json:"seals"`
	// Stopped ends the redundant deposits of an envelope whose card was
	// revoked or expired after a relay accepted it.
	Stopped bool `json:"stopped,omitempty"`
}

func (r relayOutboxRecord) pending() []string {
	if r.Stopped {
		return nil
	}
	var out []string
	for _, relay := range r.Relays {
		if !slices.Contains(r.Accepted, relay) && !slices.Contains(r.Conflicts, relay) {
			out = append(out, relay)
		}
	}
	return out
}

var relayOutboxFilePattern = regexp.MustCompile(`^[0-9a-f]{64}\.json$`)

// RelayTransport delivers packets as end-to-end-encrypted envelopes through
// the relays a recipient named in its signed key card. It seals the exact
// signed packet JSON to the recipient's current verified card, journals the
// envelope before the first deposit, and reports a send done only once one
// relay durably accepted it. The relays learn the recipient, the key id,
// the size and the timing, never the packet.
type RelayTransport struct {
	directory string
	cards     *PeerCards
	pool      *relayPool
	now       func() time.Time
	timeout   time.Duration
	locks     sync.Map
	mutex     sync.Mutex
	retry     map[string]relayRetry
	wake      chan struct{}
}

type relayRetry struct {
	at      time.Time
	backoff time.Duration
}

// OpenRelayTransport opens the owner-private envelope journal.
func OpenRelayTransport(directory string, cards *PeerCards, pool *relayPool,
	now func() time.Time,
) (*RelayTransport, error) {
	if !cleanAbsolute(directory) || cards == nil || pool == nil {
		return nil, errors.New("servicebridge: invalid relay transport configuration")
	}
	if now == nil {
		now = time.Now
	}
	if err := ensurePrivateDirectory(directory); err != nil {
		return nil, err
	}
	return &RelayTransport{
		directory: directory, cards: cards, pool: pool, now: now, timeout: RelayRequestTimeout,
		retry: map[string]relayRetry{}, wake: make(chan struct{}, 1),
	}, nil
}

// Reaches reports whether a card of the recipient is held.
func (t *RelayTransport) Reaches(recipient string) bool {
	return t != nil && t.cards.Has(recipient)
}

func (t *RelayTransport) lock(key string) func() {
	value, _ := t.locks.LoadOrStore(key, &sync.Mutex{})
	mutex, ok := value.(*sync.Mutex)
	if !ok {
		return func() {}
	}
	mutex.Lock()
	return mutex.Unlock
}

func (t *RelayTransport) recordPath(idempotencyKey string) string {
	return filepath.Join(t.directory, strings.TrimPrefix(idempotencyKey, "idem_")+".json")
}

// Send implements PacketTransport. A nil error means one relay of the
// recipient's card answered 200, 201 or 410 for the journaled envelope.
func (t *RelayTransport) Send(ctx context.Context, packet OutboundPacket) error {
	if t == nil || ctx == nil || !agentIDPattern.MatchString(packet.RecipientAgentID) || len(packet.JSON) == 0 ||
		packet.ExpiresAtUnix == 0 || !idempotencyKeyPattern.MatchString(packet.IdempotencyKey) {
		return errors.New("servicebridge: invalid relay packet send")
	}
	if len(packet.JSON) > maxPacketJSON || len(packet.JSON) > agentpacketseal.MaxPacketJSONBytes {
		return ErrRelayPacketTooLarge
	}
	unlock := t.lock(packet.IdempotencyKey)
	defer unlock()
	path := t.recordPath(packet.IdempotencyKey)
	record, found, err := t.load(path)
	if err != nil {
		return err
	}
	now := uint64(t.now().Unix())
	if found && record.Recipient != packet.RecipientAgentID {
		return errors.New("servicebridge: the journaled envelope is for another recipient")
	}
	fresh := !found || now >= record.ExpiresAtUnix
	if fresh {
		if record, err = t.seal(ctx, packet, record.Seals); err != nil {
			return err
		}
		if err = t.store(path, record, !found); err != nil {
			return err
		}
	}
	if len(record.Accepted) > 0 {
		// A relay accepted it before an interruption; the rest is the
		// background loop's.
		return nil
	}
	if !fresh {
		// Journaled bytes are sent again only while the card they were
		// sealed to is still valid and verifies; bytes sealed to a revoked
		// or expired card are replaced by a seal to the current card.
		switch usable := t.sealedCardUsable(ctx, record); {
		case usable == nil:
		case errors.Is(usable, ErrCardRefused):
			if record, err = t.seal(ctx, packet, record.Seals); err != nil {
				return err
			}
			if err = t.store(path, record, false); err != nil {
				return err
			}
		default:
			return usable
		}
	}
	envelope, err := base64.StdEncoding.Strict().DecodeString(record.EnvelopeBase64)
	if err != nil {
		return errors.New("servicebridge: the journaled envelope does not decode")
	}
	var failures int
	for _, relay := range record.pending() {
		outcome := t.deposit(ctx, relay, envelope)
		switch outcome {
		case depositAccepted:
			record.Accepted = append(record.Accepted, relay)
			if err := t.store(path, record, false); err != nil {
				return err
			}
			t.signal()
			return nil
		case depositConflict:
			record.Conflicts = append(record.Conflicts, relay)
			if err := t.store(path, record, false); err != nil {
				return err
			}
		default:
			failures++
		}
	}
	if len(record.Conflicts) > 0 {
		resealed, err := t.seal(ctx, packet, record.Seals)
		if err != nil {
			return errors.Join(ErrRelayResealed, err)
		}
		if err := t.store(path, resealed, false); err != nil {
			return err
		}
		return ErrRelayResealed
	}
	return fmt.Errorf("%w (%d relays failed)", ErrRelayUndelivered, failures)
}

// seal draws a fresh acknowledgement secret and seals the exact packet
// JSON to the recipient's current verified card.
func (t *RelayTransport) seal(ctx context.Context, packet OutboundPacket, seals int) (relayOutboxRecord, error) {
	card, err := t.cards.Current(ctx, packet.RecipientAgentID)
	if err != nil {
		return relayOutboxRecord{}, err
	}
	if card.Key.AgentID != packet.RecipientAgentID {
		return relayOutboxRecord{}, ErrNoPacketRoute
	}
	now := uint64(t.now().Unix())
	expires := saturatingAdd(now, uint64(RelayEnvelopeTTL/time.Second))
	if packet.ExpiresAtUnix < expires {
		expires = packet.ExpiresAtUnix
	}
	if expires <= now {
		return relayOutboxRecord{}, ErrGenerationExpired
	}
	var secret [agentpacketseal.AckSecretSize]byte
	if _, err = rand.Read(secret[:]); err != nil {
		return relayOutboxRecord{}, errors.New("servicebridge: draw an acknowledgement secret")
	}
	envelope, err := agentpacketseal.Seal(card.Key, secret, packet.JSON, expires)
	clear(secret[:])
	if err != nil {
		return relayOutboxRecord{}, errors.New("servicebridge: seal the packet to the recipient's key card")
	}
	header, err := agentpacketseal.ParseEnvelope(envelope)
	if err != nil {
		return relayOutboxRecord{}, errors.New("servicebridge: the sealed envelope does not parse")
	}
	return relayOutboxRecord{
		Schema: relayOutboxSchema, Recipient: packet.RecipientAgentID, IdempotencyKey: packet.IdempotencyKey,
		KeyID: agentpacketseal.KeyIDText(card.Key.KeyID), Relays: append([]string(nil), card.Card.Relays...),
		EnvelopeID: hex.EncodeToString(
			header.EnvelopeID[:],
		), EnvelopeBase64: base64.StdEncoding.EncodeToString(envelope),
		ExpiresAtUnix: expires, Seals: seals + 1,
	}, nil
}

// sealedCardUsable reports whether the card a journaled envelope was sealed
// to may still be sent to: ErrCardRefused when it was revoked, expired or is
// no longer held, another error when finalized state cannot answer now.
func (t *RelayTransport) sealedCardUsable(ctx context.Context, record relayOutboxRecord) error {
	keyID, err := agentpacketseal.ParseKeyIDText(record.KeyID)
	if err != nil {
		return fmt.Errorf("%w: the journaled key id does not parse", ErrCardRefused)
	}
	return t.cards.Usable(ctx, record.Recipient, keyID)
}

type depositClass int

const (
	depositFailed depositClass = iota
	depositAccepted
	depositConflict
)

// deposit sends the journaled bytes to one relay with a bounded timeout.
func (t *RelayTransport) deposit(ctx context.Context, relay string, envelope []byte) depositClass {
	client, err := t.pool.client(relay)
	if err != nil {
		return depositFailed
	}
	bounded, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	outcome, err := client.Deposit(bounded, envelope)
	switch {
	case err != nil:
		return depositFailed
	case outcome.Accepted():
		return depositAccepted
	case outcome.Result == agentpacketrelay.DepositConflict:
		return depositConflict
	default:
		return depositFailed
	}
}

func (t *RelayTransport) load(path string) (relayOutboxRecord, bool, error) {
	var record relayOutboxRecord
	err := readJSON(path, 512<<10, &record)
	if errors.Is(err, os.ErrNotExist) {
		return relayOutboxRecord{}, false, nil
	}
	if err != nil || record.Schema != relayOutboxSchema || !agentIDPattern.MatchString(record.Recipient) ||
		!idempotencyKeyPattern.MatchString(record.IdempotencyKey) || t.recordPath(record.IdempotencyKey) != path {
		return relayOutboxRecord{}, false, errors.New("servicebridge: invalid relay envelope journal record")
	}
	return record, true, nil
}

func (t *RelayTransport) store(path string, record relayOutboxRecord, create bool) error {
	if create {
		if err := writeJSON(path, record, true); !errors.Is(err, os.ErrExist) {
			return err
		}
	}
	return writeJSON(path, record, false)
}

func (t *RelayTransport) signal() {
	select {
	case t.wake <- struct{}{}:
	default:
	}
}

// Redeposit keeps depositing every accepted envelope at the relays of its
// card that have not accepted it yet, for redundancy, until each relay
// accepted it, answered a conflict, or the envelope expired. Expired
// journal records are removed.
func (t *RelayTransport) Redeposit(ctx context.Context) error {
	if t == nil || ctx == nil {
		return errors.New("servicebridge: invalid relay redeposit")
	}
	entries, err := os.ReadDir(t.directory)
	if err != nil {
		return errors.New("servicebridge: read the relay envelope journal")
	}
	var failures []error
	for _, entry := range entries {
		if !relayOutboxFilePattern.MatchString(entry.Name()) {
			continue
		}
		if err := t.redepositOne(ctx, filepath.Join(t.directory, entry.Name())); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (t *RelayTransport) redepositOne(ctx context.Context, path string) error {
	name := strings.TrimSuffix(filepath.Base(path), ".json")
	unlock := t.lock("idem_" + name)
	defer unlock()
	record, found, err := t.load(path)
	if err != nil || !found {
		return err
	}
	now := t.now()
	if uint64(now.Unix()) >= record.ExpiresAtUnix {
		t.forget(record.IdempotencyKey)
		if err = os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.New("servicebridge: remove an expired relay envelope")
		}
		return syncDirectory(t.directory)
	}
	pending := record.pending()
	if len(record.Accepted) == 0 || len(pending) == 0 || record.Stopped {
		t.forget(record.IdempotencyKey)
		return nil
	}
	switch usable := t.sealedCardUsable(ctx, record); {
	case usable == nil:
	case errors.Is(usable, ErrCardRefused):
		// Already durably held by one relay; it is not spread further to
		// a key whose card no longer stands.
		record.Stopped = true
		t.forget(record.IdempotencyKey)
		return t.store(path, record, false)
	default:
		return nil
	}
	t.mutex.Lock()
	retry := t.retry[record.IdempotencyKey]
	t.mutex.Unlock()
	if now.Before(retry.at) {
		return nil
	}
	envelope, err := base64.StdEncoding.Strict().DecodeString(record.EnvelopeBase64)
	if err != nil {
		return errors.New("servicebridge: the journaled envelope does not decode")
	}
	changed, failed := false, false
	for _, relay := range pending {
		switch t.deposit(ctx, relay, envelope) {
		case depositAccepted:
			record.Accepted, changed = append(record.Accepted, relay), true
		case depositConflict:
			record.Conflicts, changed = append(record.Conflicts, relay), true
		default:
			failed = true
		}
	}
	if failed {
		backoff := retry.backoff * 2
		if backoff < relayRedepositFirst {
			backoff = relayRedepositFirst
		}
		if backoff > relayRedepositMax {
			backoff = relayRedepositMax
		}
		t.mutex.Lock()
		t.retry[record.IdempotencyKey] = relayRetry{at: now.Add(backoff), backoff: backoff}
		t.mutex.Unlock()
	} else {
		t.forget(record.IdempotencyKey)
	}
	if changed {
		return t.store(path, record, false)
	}
	return nil
}

func (t *RelayTransport) forget(key string) {
	t.mutex.Lock()
	delete(t.retry, key)
	t.mutex.Unlock()
}

// RelayOutboxView summarizes one journaled envelope for status.
type RelayOutboxView struct {
	Recipient     string   `json:"recipient"`
	EnvelopeID    string   `json:"envelope_id"`
	KeyID         string   `json:"recipient_key_id"`
	ExpiresAtUnix uint64   `json:"expires_at_unix"`
	Accepted      []string `json:"accepted_by"`
	Conflicts     []string `json:"conflicts,omitempty"`
	Pending       []string `json:"pending"`
	Seals         int      `json:"seals"`
}

// ReadRelayOutbox lists the envelope journal without taking ownership of it.
func ReadRelayOutbox(directory string) ([]RelayOutboxView, error) {
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("servicebridge: read the relay envelope journal")
	}
	reader := &RelayTransport{directory: directory}
	var out []RelayOutboxView
	for _, entry := range entries {
		if !relayOutboxFilePattern.MatchString(entry.Name()) {
			continue
		}
		record, found, err := reader.load(filepath.Join(directory, entry.Name()))
		if err != nil {
			return nil, err
		}
		if !found {
			continue
		}
		out = append(out, RelayOutboxView{
			Recipient: record.Recipient, EnvelopeID: record.EnvelopeID, KeyID: record.KeyID,
			ExpiresAtUnix: record.ExpiresAtUnix, Accepted: append([]string{}, record.Accepted...),
			Conflicts: record.Conflicts, Pending: append([]string{}, record.pending()...), Seals: record.Seals,
		})
	}
	return out, nil
}
