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
	// maxRelayWithdrawals bounds the withdrawn envelopes one journal
	// record keeps secrets for; past it the oldest is forgotten and its
	// envelope left to expire at the relays.
	maxRelayWithdrawals = 4
	// relayWithdrawPerPass bounds the withdrawal requests of one
	// background pass over the whole journal.
	relayWithdrawPerPass = 16
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
// sends exactly these bytes and the relay recognizes them.
//
// The record also keeps the envelope's acknowledgement secret and the
// signed packet, so that when the card the envelope was sealed to is
// revoked after relays took it, the sender withdraws it there and seals the
// packet to the recipient's current card. The file is owner-only like all
// node state; the secret is never logged, never in status and is deleted
// with the record or once its withdrawal is done.
type relayOutboxRecord struct {
	Schema         string `json:"schema"`
	Recipient      string `json:"recipient"`
	IdempotencyKey string `json:"idempotency_key"`
	// KeyID, Relays, EnvelopeID, EnvelopeBase64, ExpiresAtUnix, AckSecret
	// and CardNotAfterUnix describe the current envelope; they are empty
	// while a replacement waits for a valid card.
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
	// AckSecret is the current envelope's acknowledgement secret (hex).
	AckSecret string `json:"ack_secret,omitempty"`
	// CardNotAfterUnix is the expiry of the card the envelope is sealed
	// to: a refusal before it is a revocation, after it an expiry.
	CardNotAfterUnix uint64 `json:"card_not_after_unix,omitempty"`
	// PacketBase64 and PacketExpiresAtUnix are the signed packet and its
	// deliverable expiry, for a seal to the recipient's next card.
	PacketBase64        string `json:"packet_base64,omitempty"`
	PacketExpiresAtUnix uint64 `json:"packet_expires_at_unix,omitempty"`
	// Background marks a replacement the transport delivers itself: the
	// courier already counted the packet as sent when a relay accepted the
	// envelope it replaces.
	Background bool `json:"background,omitempty"`
	// Withdrawals are earlier envelopes of this packet, sealed to a card
	// revoked after relays took them, still to be withdrawn.
	Withdrawals []relayWithdrawal `json:"withdrawals,omitempty"`
}

// relayWithdrawal is one envelope to withdraw with its acknowledgement
// secret at the relays that may hold it.
type relayWithdrawal struct {
	EnvelopeID    string   `json:"envelope_id"`
	AckSecret     string   `json:"ack_secret"`
	Relays        []string `json:"relays"`
	ExpiresAtUnix uint64   `json:"expires_at_unix"`
}

// sealed reports whether the record holds a current envelope.
func (r relayOutboxRecord) sealed() bool { return r.EnvelopeBase64 != "" }

// retireAt is when the record and every secret in it are deleted: once the
// current envelope, every envelope still to be withdrawn and, while a
// replacement waits for a card, the packet itself expired.
func (r relayOutboxRecord) retireAt() uint64 {
	at := r.ExpiresAtUnix
	if !r.sealed() && r.PacketExpiresAtUnix > at {
		at = r.PacketExpiresAtUnix
	}
	for _, withdrawal := range r.Withdrawals {
		if withdrawal.ExpiresAtUnix > at {
			at = withdrawal.ExpiresAtUnix
		}
	}
	return at
}

// withdrawCurrent moves the current envelope, sealed to a revoked card, to
// the withdrawals: every relay of its card except those that hold other
// bytes under its id may hold it, an ambiguous deposit included. The record
// then waits for a seal to a valid card.
func (r *relayOutboxRecord) withdrawCurrent() {
	if r.AckSecret != "" {
		var relays []string
		for _, relay := range r.Relays {
			if !slices.Contains(r.Conflicts, relay) {
				relays = append(relays, relay)
			}
		}
		if len(relays) > 0 {
			r.Withdrawals = append(r.Withdrawals, relayWithdrawal{
				EnvelopeID: r.EnvelopeID, AckSecret: r.AckSecret, Relays: relays, ExpiresAtUnix: r.ExpiresAtUnix,
			})
		}
		if excess := len(r.Withdrawals) - maxRelayWithdrawals; excess > 0 {
			r.Withdrawals = append([]relayWithdrawal(nil), r.Withdrawals[excess:]...)
		}
	}
	r.dropCurrent()
}

// dropCurrent forgets the current envelope and its secret.
func (r *relayOutboxRecord) dropCurrent() {
	r.KeyID, r.Relays, r.EnvelopeID, r.EnvelopeBase64, r.AckSecret = "", nil, "", "", ""
	r.Accepted, r.Conflicts, r.Stopped, r.CardNotAfterUnix = nil, nil, false, 0
}

// revokedBy reports whether a refusal of the current envelope's card at
// now is a revocation: the card no longer verifies, or is no longer held,
// before its own expiry. A card refused only because it expired is not:
// the recipient keeps its private key past the expiry for as long as an
// envelope sealed in time can wait, so that envelope is left to be fetched.
func (r relayOutboxRecord) revokedBy(now uint64) bool {
	return r.CardNotAfterUnix != 0 && now < r.CardNotAfterUnix
}

// replace takes a fresh seal of the same packet as the current envelope,
// keeping the withdrawals still due.
func (r *relayOutboxRecord) replace(fresh relayOutboxRecord) {
	withdrawals, background := r.Withdrawals, r.Background
	*r = fresh
	r.Withdrawals, r.Background = withdrawals, background
}

func (r relayOutboxRecord) pending() []string {
	if r.Stopped || !r.sealed() {
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
	// beforeJournal runs just before a new journal record is created; tests
	// use it to interleave a second process.
	beforeJournal func()
	// afterJournal runs once a background pass journaled a withdrawal or
	// a replacement, before any request it leads to; tests kill the
	// process there.
	afterJournal func()
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
	fresh := !found || !record.sealed() || now >= record.ExpiresAtUnix
	if fresh {
		sealed, sealErr := t.seal(ctx, packet, record.Seals)
		if sealErr != nil {
			return sealErr
		}
		switch {
		case found:
			record.replace(sealed)
			err = t.store(path, record)
		default:
			record = sealed
			if t.beforeJournal != nil {
				t.beforeJournal()
			}
			err = writeJSON(path, record, true)
			if errors.Is(err, os.ErrExist) {
				// Another sender journaled this packet first: its envelope
				// may already be at a relay, so it is the one used.
				existing, held, loadErr := t.load(path)
				if loadErr != nil || !held || existing.Recipient != packet.RecipientAgentID {
					return errors.Join(errors.New("servicebridge: read the journaled envelope"), loadErr)
				}
				record, fresh, err = existing, false, nil
			}
		}
		if err != nil {
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
			sealed, sealErr := t.seal(ctx, packet, record.Seals)
			if sealErr != nil {
				return sealErr
			}
			// An ambiguous deposit may have left the old bytes at a relay;
			// sealed to a revoked card, they are withdrawn.
			withdraw := record.revokedBy(now)
			if withdraw {
				record.withdrawCurrent()
			}
			record.replace(sealed)
			if err = t.store(path, record); err != nil {
				return err
			}
			if withdraw {
				t.signal()
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
			if err := t.store(path, record); err != nil {
				return err
			}
			t.signal()
			return nil
		case depositConflict:
			record.Conflicts = append(record.Conflicts, relay)
			if err := t.store(path, record); err != nil {
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
		record.replace(resealed)
		if err := t.store(path, record); err != nil {
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
	ackSecret := hex.EncodeToString(secret[:])
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
		ExpiresAtUnix: expires, Seals: seals + 1, AckSecret: ackSecret, CardNotAfterUnix: card.Card.NotAfterUnix,
		PacketBase64: base64.StdEncoding.EncodeToString(packet.JSON), PacketExpiresAtUnix: packet.ExpiresAtUnix,
	}, nil
}

// journaledPacket is the packet a record keeps for a seal to the next
// card, or false when it keeps none.
func (r relayOutboxRecord) journaledPacket() (OutboundPacket, bool) {
	if r.PacketBase64 == "" || r.PacketExpiresAtUnix == 0 {
		return OutboundPacket{}, false
	}
	encoded, err := base64.StdEncoding.Strict().DecodeString(r.PacketBase64)
	if err != nil || len(encoded) == 0 {
		return OutboundPacket{}, false
	}
	return OutboundPacket{
		RecipientAgentID: r.Recipient, JSON: encoded, IdempotencyKey: r.IdempotencyKey,
		ExpiresAtUnix: r.PacketExpiresAtUnix,
	}, true
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
		!idempotencyKeyPattern.MatchString(record.IdempotencyKey) || t.recordPath(record.IdempotencyKey) != path ||
		(record.AckSecret != "" && !hex64Pattern.MatchString(record.AckSecret)) ||
		len(record.Withdrawals) > maxRelayWithdrawals {
		return relayOutboxRecord{}, false, errors.New("servicebridge: invalid relay envelope journal record")
	}
	for _, withdrawal := range record.Withdrawals {
		if !hex64Pattern.MatchString(withdrawal.EnvelopeID) || !hex64Pattern.MatchString(withdrawal.AckSecret) ||
			len(withdrawal.Relays) == 0 || len(withdrawal.Relays) > agentpacketseal.MaxRelays {
			return relayOutboxRecord{}, false, errors.New("servicebridge: invalid relay envelope journal record")
		}
	}
	return record, true, nil
}

// store replaces a journal record that exists.
func (t *RelayTransport) store(path string, record relayOutboxRecord) error {
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
	budget := relayWithdrawPerPass
	for _, entry := range entries {
		if !relayOutboxFilePattern.MatchString(entry.Name()) {
			continue
		}
		if err := t.redepositOne(ctx, filepath.Join(t.directory, entry.Name()), &budget); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

// redepositOne advances one journal record: it retires the record once
// nothing in it can matter any more, withdraws an accepted envelope whose
// card was revoked and seals the packet to the recipient's current card,
// withdraws earlier envelopes still due, and deposits the current envelope
// at the relays that have not accepted it. Every change is journaled
// before the request it leads to, so a restart resumes where it stopped.
func (t *RelayTransport) redepositOne(ctx context.Context, path string, budget *int) error {
	name := strings.TrimSuffix(filepath.Base(path), ".json")
	unlock := t.lock("idem_" + name)
	defer unlock()
	record, found, err := t.load(path)
	if err != nil || !found {
		return err
	}
	now := t.now()
	nowUnix := uint64(now.Unix())
	if nowUnix >= record.retireAt() {
		// The secrets kept for withdrawals go with the record.
		t.forget(record.IdempotencyKey)
		t.forget(relayWithdrawRetryKey(record.IdempotencyKey))
		if err = os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.New("servicebridge: remove an expired relay envelope")
		}
		return syncDirectory(t.directory)
	}
	changed, depositable := false, false
	live := record.sealed() && nowUnix < record.ExpiresAtUnix && !record.Stopped &&
		(len(record.Accepted) > 0 || record.Background)
	// The card of an envelope that stands at a relay is watched while its
	// secret is kept, so a revocation withdraws it; legacy records without
	// a secret are watched only while redundant deposits are due.
	if live && (len(record.pending()) > 0 || record.AckSecret != "") {
		switch usable := t.sealedCardUsable(ctx, record); {
		case usable == nil:
			depositable = true
		case errors.Is(usable, ErrCardRefused) && record.revokedBy(nowUnix) && record.AckSecret != "":
			record.withdrawCurrent()
			record.Background, changed = true, true
		case errors.Is(usable, ErrCardRefused) && len(record.Accepted) == 0:
			// A replacement no relay took yet whose card expired: sealed
			// again to the current card below.
			record.dropCurrent()
			changed = true
		case errors.Is(usable, ErrCardRefused):
			// Already durably held by one relay; it is not spread further
			// to a key whose card no longer stands, and its card was not
			// revoked: the recipient can still open it until it expires.
			record.Stopped, changed = true, true
			t.forget(record.IdempotencyKey)
		default:
			// Finalized state cannot answer now: nothing is sent to that
			// card this pass.
		}
	}
	if !record.sealed() && record.Background {
		if packet, ok := record.journaledPacket(); ok && nowUnix < packet.ExpiresAtUnix {
			// Without a valid card the record waits; a later pass seals it
			// once one is learned, until the packet expires.
			if fresh, sealErr := t.seal(ctx, packet, record.Seals); sealErr == nil {
				record.replace(fresh)
				changed, depositable = true, true
			}
		}
	}
	if changed {
		if err = t.store(path, record); err != nil {
			return err
		}
		changed = false
		if t.afterJournal != nil {
			t.afterJournal()
		}
	}
	if t.withdraw(ctx, &record, now, budget) {
		changed = true
	}
	pending := record.pending()
	if depositable && len(pending) > 0 && (len(record.Accepted) > 0 || record.Background) {
		if t.depositPending(ctx, &record, pending, now) {
			changed = true
		}
	} else if len(pending) == 0 {
		t.forget(record.IdempotencyKey)
	}
	if changed {
		return t.store(path, record)
	}
	return nil
}

// depositPending deposits the current envelope at the relays that have
// not accepted it, backing off after a failure.
func (t *RelayTransport) depositPending(ctx context.Context, record *relayOutboxRecord, pending []string,
	now time.Time,
) bool {
	t.mutex.Lock()
	retry := t.retry[record.IdempotencyKey]
	t.mutex.Unlock()
	if now.Before(retry.at) {
		return false
	}
	envelope, err := base64.StdEncoding.Strict().DecodeString(record.EnvelopeBase64)
	if err != nil {
		return false
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
	t.backoff(record.IdempotencyKey, retry, failed, now)
	return changed
}

func (t *RelayTransport) backoff(key string, retry relayRetry, failed bool, now time.Time) {
	if !failed {
		t.forget(key)
		return
	}
	backoff := retry.backoff * 2
	if backoff < relayRedepositFirst {
		backoff = relayRedepositFirst
	}
	if backoff > relayRedepositMax {
		backoff = relayRedepositMax
	}
	t.mutex.Lock()
	t.retry[key] = relayRetry{at: now.Add(backoff), backoff: backoff}
	t.mutex.Unlock()
}

func relayWithdrawRetryKey(idempotencyKey string) string { return "withdraw:" + idempotencyKey }

// withdraw acknowledges each envelope still to be withdrawn, with its
// secret, at the relays that may hold it, within the pass budget. 204 and
// 404 both mean it is gone there; a refusal that cannot change (403, other
// 4xx, an unusable URL) ends the attempt at that relay; anything else is
// retried at a later pass. An entry is deleted, secret and all, once no
// relay is left or its envelope expired.
func (t *RelayTransport) withdraw(ctx context.Context, record *relayOutboxRecord, now time.Time, budget *int) bool {
	if len(record.Withdrawals) == 0 {
		return false
	}
	key := relayWithdrawRetryKey(record.IdempotencyKey)
	t.mutex.Lock()
	retry := t.retry[key]
	t.mutex.Unlock()
	if now.Before(retry.at) {
		return false
	}
	nowUnix := uint64(now.Unix())
	changed, failed := false, false
	var kept []relayWithdrawal
	for _, withdrawal := range record.Withdrawals {
		var id, secret [32]byte
		idOK := decodeHex32(withdrawal.EnvelopeID, &id) == nil
		secretOK := decodeHex32(withdrawal.AckSecret, &secret) == nil
		if nowUnix >= withdrawal.ExpiresAtUnix || !idOK || !secretOK {
			clear(secret[:])
			changed = true
			continue
		}
		var remaining []string
		for _, relay := range withdrawal.Relays {
			if *budget <= 0 {
				remaining = append(remaining, relay)
				continue
			}
			*budget--
			if t.acknowledge(ctx, relay, record.Recipient, id, secret) {
				changed = true
			} else {
				remaining, failed = append(remaining, relay), true
			}
		}
		clear(secret[:])
		if len(remaining) > 0 {
			withdrawal.Relays = remaining
			kept = append(kept, withdrawal)
		}
	}
	record.Withdrawals = kept
	t.backoff(key, retry, failed, now)
	return changed
}

// acknowledge withdraws one envelope at one relay; true means the attempt
// at that relay is over.
func (t *RelayTransport) acknowledge(ctx context.Context, relay, agent string, id, secret [32]byte) bool {
	client, err := t.pool.client(relay)
	if err != nil {
		return true
	}
	bounded, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	err = client.Ack(bounded, agent, id, secret)
	switch {
	case err == nil, errors.Is(err, agentpacketrelay.ErrNotFound):
		return true
	case errors.Is(err, agentpacketrelay.ErrRateLimited), errors.Is(err, agentpacketrelay.ErrUnavailable),
		errors.Is(err, agentpacketrelay.ErrRequestTimeout):
		return false
	case errors.Is(err, agentpacketrelay.ErrForbidden), errors.Is(err, agentpacketrelay.ErrRejected),
		errors.Is(err, agentpacketrelay.ErrInvalidArgument):
		return true
	default:
		return false
	}
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
	// AwaitingCard reports a packet whose envelope was withdrawn and that
	// waits for a valid card of the recipient to be sealed again.
	AwaitingCard bool `json:"awaiting_card,omitempty"`
	// Withdrawing lists the envelopes still to be withdrawn, by id and
	// relay; never their secrets.
	Withdrawing []RelayWithdrawalView `json:"withdrawing,omitempty"`
}

// RelayWithdrawalView is one envelope still to be withdrawn.
type RelayWithdrawalView struct {
	EnvelopeID    string   `json:"envelope_id"`
	Relays        []string `json:"relays"`
	ExpiresAtUnix uint64   `json:"expires_at_unix"`
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
		view := RelayOutboxView{
			Recipient: record.Recipient, EnvelopeID: record.EnvelopeID, KeyID: record.KeyID,
			ExpiresAtUnix: record.ExpiresAtUnix, Accepted: append([]string{}, record.Accepted...),
			Conflicts: record.Conflicts, Pending: append([]string{}, record.pending()...), Seals: record.Seals,
			AwaitingCard: !record.sealed(),
		}
		for _, withdrawal := range record.Withdrawals {
			view.Withdrawing = append(view.Withdrawing, RelayWithdrawalView{
				EnvelopeID: withdrawal.EnvelopeID, Relays: append([]string{}, withdrawal.Relays...),
				ExpiresAtUnix: withdrawal.ExpiresAtUnix,
			})
		}
		out = append(out, view)
	}
	return out, nil
}
