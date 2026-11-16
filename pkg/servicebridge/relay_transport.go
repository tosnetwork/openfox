package servicebridge

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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
	// maxRelayOutboxRecordBytes bounds one journal record read back. A
	// record holds the current envelope and the signed packet, each at most
	// agentpacketseal.MaxEnvelopeBytes and stored in base64, plus a few
	// withdrawn envelope ids and secrets and short fields; the slack covers
	// those. A chat record may carry the full sealed packet bound, so a
	// smaller bound would refuse a record this node itself wrote.
	maxRelayOutboxRecordBytes = 2*((agentpacketseal.MaxEnvelopeBytes+2)/3*4) + 64<<10
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
	// ErrRelayWithdrawn reports a send under an idempotency key whose
	// envelope was withdrawn: that packet is never deposited again.
	ErrRelayWithdrawn = errors.New("servicebridge: the envelope of this idempotency key was withdrawn")
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
	// Withdrawn marks a packet its sender superseded (a later generation
	// was accepted): its envelopes are withdrawn and it is never sealed or
	// deposited again.
	Withdrawn bool `json:"withdrawn,omitempty"`
	// AcceptedAtUnix is when a relay first accepted the current envelope:
	// the relays keep it at most their TTL from about then.
	AcceptedAtUnix uint64 `json:"accepted_at_unix,omitempty"`
	// Settled marks a current envelope no relay of its card lists any more
	// before its relay retention ran out: the recipient acknowledged it, and
	// it is not deposited again before its TTL.
	Settled bool `json:"settled,omitempty"`
	// Residual counts withdrawals dropped past maxRelayWithdrawals, secret
	// and all: their envelopes may still be stored until UntilUnix.
	Residual relayResidual `json:"residual,omitempty"`
}

// relayResidual is a count of envelopes that may still be stored at some
// relay although this node no longer holds what it would need to withdraw
// them; they count as stored until the latest of their expiries.
type relayResidual struct {
	Count     int    `json:"count,omitempty"`
	UntilUnix uint64 `json:"until_unix,omitempty"`
}

// maxRelayResidual bounds a record's residual count; it only grows by one
// per withdrawal dropped, which needs a fresh card revocation each.
const maxRelayResidual = 1 << 16

// relayWithdrawal is one envelope to withdraw with its acknowledgement
// secret at the relays that may hold it.
type relayWithdrawal struct {
	EnvelopeID    string   `json:"envelope_id"`
	AckSecret     string   `json:"ack_secret"`
	Relays        []string `json:"relays"`
	ExpiresAtUnix uint64   `json:"expires_at_unix"`
	// Unconfirmed are relays whose withdrawal ended without a confirmation
	// (a refusal that cannot change, or an unusable relay URL): they are not
	// asked again, and the envelope counts as stored there until it expires.
	Unconfirmed []string `json:"unconfirmed,omitempty"`
	// AfterAccepted holds the withdrawal of an envelope replaced before its
	// retention ran out until a relay accepted the replacement, so the
	// packet is never absent from every relay in between.
	AfterAccepted bool `json:"after_accepted,omitempty"`
}

// storedAt is every relay that may still hold the withdrawal's envelope.
func (w relayWithdrawal) storedAt() []string {
	out := append([]string(nil), w.Relays...)
	for _, relay := range w.Unconfirmed {
		if !slices.Contains(out, relay) {
			out = append(out, relay)
		}
	}
	return out
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
	if r.Residual.Count > 0 && r.Residual.UntilUnix > at {
		at = r.Residual.UntilUnix
	}
	return at
}

// withdrawCurrent moves the current envelope, sealed to a revoked card, to
// the withdrawals: every relay of its card except those that hold other
// bytes under its id may hold it, an ambiguous deposit included. The record
// then waits for a seal to a valid card.
func (r *relayOutboxRecord) withdrawCurrent() { r.moveCurrentToWithdrawals(false) }

// moveCurrentToWithdrawals moves the current envelope to the withdrawals;
// afterAccepted holds that withdrawal until a replacement is accepted. A
// withdrawal dropped past maxRelayWithdrawals goes with its secret but keeps
// counting as stored, in Residual, until it expires.
func (r *relayOutboxRecord) moveCurrentToWithdrawals(afterAccepted bool) {
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
				AfterAccepted: afterAccepted,
			})
		}
		if excess := len(r.Withdrawals) - maxRelayWithdrawals; excess > 0 {
			for _, dropped := range r.Withdrawals[:excess] {
				if r.Residual.Count < maxRelayResidual {
					r.Residual.Count++
				}
				if dropped.ExpiresAtUnix > r.Residual.UntilUnix {
					r.Residual.UntilUnix = dropped.ExpiresAtUnix
				}
			}
			r.Withdrawals = append([]relayWithdrawal(nil), r.Withdrawals[excess:]...)
		}
	}
	r.dropCurrent()
}

// dropCurrent forgets the current envelope and its secret.
func (r *relayOutboxRecord) dropCurrent() {
	r.KeyID, r.Relays, r.EnvelopeID, r.EnvelopeBase64, r.AckSecret = "", nil, "", "", ""
	r.Accepted, r.Conflicts, r.Stopped, r.CardNotAfterUnix = nil, nil, false, 0
	r.AcceptedAtUnix, r.Settled = 0, false
}

// accept records that relay accepted the current envelope at now.
func (r *relayOutboxRecord) accept(relay string, now uint64) {
	if len(r.Accepted) == 0 {
		r.AcceptedAtUnix = now
	}
	r.Accepted = append(r.Accepted, relay)
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
	withdrawals, background, residual := r.Withdrawals, r.Background, r.Residual
	*r = fresh
	r.Withdrawals, r.Background, r.Residual = withdrawals, background, residual
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
	// maxPacket bounds the packet JSON this instance seals: the rail keeps
	// the receiver's bound, chat carriage the sealed packet bound.
	maxPacket int
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
	// afterDeposit runs once a relay accepted a send's envelope, before the
	// acceptance is journaled; tests kill the process there.
	afterDeposit func()
	// unreadable remembers the journal files that failed to load, so each
	// is reported once; onUnreadable receives that one report.
	unreadable   sync.Map
	onUnreadable func(name string, err error)
	// refreshBeforeTTL deposits an accepted envelope the recipient has not
	// acknowledged again, under a fresh seal, before the smallest relay TTL
	// of its card runs out (the rail; chat generations are the daemon's).
	refreshBeforeTTL bool
	// onQuarantined receives the name of each unreadable journal file moved
	// to the quarantine directory.
	onQuarantined func(name string)
}

// ErrRelayRecordTooLarge refuses a journal record above the bound the
// journal reads back, so the node never writes a record it cannot read.
var ErrRelayRecordTooLarge = errors.New(
	"servicebridge: the relay journal record exceeds the bound it is read back with")

// writeRecord journals a record after checking it against the read bound;
// create makes a new file, otherwise an existing one is replaced.
func writeRecord(path string, record relayOutboxRecord, create bool) error {
	encoded, err := json.Marshal(record)
	if err != nil {
		return errors.New("servicebridge: encode record")
	}
	if len(encoded) > maxRelayOutboxRecordBytes {
		return ErrRelayRecordTooLarge
	}
	if create {
		return writeSynced(path, encoded)
	}
	return replaceSynced(path, encoded)
}

// noteUnreadable reports a journal file that failed to load, once per file.
func (t *RelayTransport) noteUnreadable(name string, err error) {
	if _, seen := t.unreadable.LoadOrStore(name, struct{}{}); seen || t.onUnreadable == nil {
		return
	}
	t.onUnreadable(name, err)
}

// relayQuarantineDir holds journal files that failed to load and are old
// enough that nothing they describe can still be stored at a relay. They are
// kept, owner-only, for inspection; nothing reads them.
const relayQuarantineDir = "quarantine"

// relayQuarantineAge is how long after its last write an unreadable journal
// file is quarantined. Every envelope a record describes was sealed at or
// before that write and expires at most RelayEnvelopeTTL after its seal; the
// relays' clock may run ahead of this one by up to the deposit expiry skew.
const relayQuarantineAge = RelayEnvelopeTTL + agentpacketrelay.ExpirySkew

// handleUnreadable deals with a journal file that failed to load. A file
// written less than relayQuarantineAge ago is reported once and stays where
// it is (the caller counts it as stored); an older one is moved to the
// quarantine directory, reported, and true is returned: it counts no more.
func (t *RelayTransport) handleUnreadable(name string, loadErr error) bool {
	path := filepath.Join(t.directory, name)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		t.noteUnreadable(name, loadErr)
		return errors.Is(err, os.ErrNotExist)
	}
	age := t.now().Sub(info.ModTime())
	if age < relayQuarantineAge {
		t.noteUnreadable(name, loadErr)
		return false
	}
	if err := t.quarantine(name); err != nil {
		t.noteUnreadable(name, errors.Join(loadErr, err))
		return false
	}
	t.unreadable.Delete(name)
	if t.onQuarantined != nil {
		t.onQuarantined(name)
	}
	return true
}

// quarantine moves one journal file into the quarantine directory, under a
// fresh name if one of that name is already there.
func (t *RelayTransport) quarantine(name string) error {
	directory := filepath.Join(t.directory, relayQuarantineDir)
	if err := ensurePrivateDirectory(directory); err != nil {
		return err
	}
	target := filepath.Join(directory, name)
	for attempt := 1; ; attempt++ {
		if _, err := os.Lstat(target); errors.Is(err, os.ErrNotExist) {
			break
		}
		if attempt > 64 {
			return errors.New("servicebridge: no free name in the relay journal quarantine")
		}
		target = filepath.Join(directory, fmt.Sprintf("%s.%d", name, attempt))
	}
	if err := os.Rename(filepath.Join(t.directory, name), target); err != nil {
		return errors.New("servicebridge: move an unreadable relay journal file to quarantine")
	}
	if err := syncDirectory(directory); err != nil {
		return err
	}
	return syncDirectory(t.directory)
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
		directory: directory, maxPacket: maxPacketJSON, cards: cards, pool: pool, now: now,
		timeout: RelayRequestTimeout, retry: map[string]relayRetry{}, wake: make(chan struct{}, 1),
	}, nil
}

// setPacketBound sets the largest packet JSON this instance seals. It never
// exceeds the sealed packet bound.
func (t *RelayTransport) setPacketBound(bound int) error {
	if t == nil || bound <= 0 || bound > agentpacketseal.MaxPacketJSONBytes {
		return errors.New("servicebridge: invalid relay packet bound")
	}
	t.maxPacket = bound
	return nil
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
	bound := t.maxPacket
	if bound <= 0 {
		bound = maxPacketJSON
	}
	if len(packet.JSON) > bound || len(packet.JSON) > agentpacketseal.MaxPacketJSONBytes {
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
	if found && record.Withdrawn {
		return ErrRelayWithdrawn
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
			err = writeRecord(path, record, true)
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
			if t.afterDeposit != nil {
				t.afterDeposit()
			}
			record.accept(relay, now)
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
	err := readJSON(path, maxRelayOutboxRecordBytes, &record)
	if errors.Is(err, os.ErrNotExist) {
		return relayOutboxRecord{}, false, nil
	}
	if err != nil || record.Schema != relayOutboxSchema || !agentIDPattern.MatchString(record.Recipient) ||
		!idempotencyKeyPattern.MatchString(record.IdempotencyKey) || t.recordPath(record.IdempotencyKey) != path ||
		(record.AckSecret != "" && !hex64Pattern.MatchString(record.AckSecret)) ||
		len(record.Withdrawals) > maxRelayWithdrawals || record.Residual.Count < 0 ||
		record.Residual.Count > maxRelayResidual {
		return relayOutboxRecord{}, false, errors.New("servicebridge: invalid relay envelope journal record")
	}
	for _, withdrawal := range record.Withdrawals {
		if !hex64Pattern.MatchString(withdrawal.EnvelopeID) || !hex64Pattern.MatchString(withdrawal.AckSecret) ||
			len(withdrawal.Relays)+len(withdrawal.Unconfirmed) == 0 ||
			len(withdrawal.Relays)+len(withdrawal.Unconfirmed) > agentpacketseal.MaxRelays {
			return relayOutboxRecord{}, false, errors.New("servicebridge: invalid relay envelope journal record")
		}
	}
	return record, true, nil
}

// store replaces a journal record that exists.
func (t *RelayTransport) store(path string, record relayOutboxRecord) error {
	return writeRecord(path, record, false)
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
	if err != nil {
		// Reported once, and quarantined once old enough; the other records
		// keep being deposited.
		t.handleUnreadable(filepath.Base(path), err)
		return nil
	}
	if !found {
		return nil
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
	if !record.sealed() && record.Background && !record.Withdrawn {
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
	if record.everyRelayConflicts() && record.Background && !record.Withdrawn && nowUnix < record.ExpiresAtUnix {
		// A replacement the courier no longer retries: every relay of its
		// card holds other bytes under its public id (an observer, or one
		// relay copying the id to the others, got there first). As the
		// courier does for its own sends, the packet is sealed again under
		// a fresh secret and journaled before its first deposit, which
		// waits for the deposit backoff; that backoff grows across
		// consecutive rounds of 409s (depositPending counts them as
		// failures), so a relay that answers 409 to every id costs one seal
		// per growing backoff period.
		if packet, ok := record.journaledPacket(); ok && nowUnix < packet.ExpiresAtUnix {
			if fresh, sealErr := t.seal(ctx, packet, record.Seals); sealErr == nil {
				record.replace(fresh)
				if err = t.store(path, record); err != nil {
					return err
				}
				// The round that met the 409s already grew the backoff;
				// one is set here only when none is running (the
				// conflicts were journaled before a restart).
				t.mutex.Lock()
				retry := t.retry[record.IdempotencyKey]
				t.mutex.Unlock()
				if !now.Before(retry.at) {
					t.backoff(record.IdempotencyKey, retry, true, now)
				}
				return nil
			}
		}
	}
	if t.refreshBeforeTTL && depositable {
		if changed {
			if err = t.store(path, record); err != nil {
				return err
			}
			changed = false
		}
		if err = t.refreshBeforeRelayTTL(ctx, path, &record, now); err != nil {
			return err
		}
	}
	if changed {
		return t.store(path, record)
	}
	return nil
}

// refreshBeforeRelayTTL keeps an accepted envelope stored for as long as its
// packet is deliverable. The relays keep it at most their TTL after they took
// it; when the envelope's own expiry is later than that, it is replaced at 80 %
// of the smallest TTL among its card's relays (never sooner than
// MinRelayRedeposit) by a fresh seal of the same packet under a new
// acknowledgement secret, so a new envelope id that no tombstone blocks. The
// replacement is journaled before its deposit, and the old envelope is
// withdrawn only once a relay accepted the replacement, so the packet is never
// absent from every relay in between.
//
// Before replacing, the relays that accepted the envelope are listed (open to
// anyone): when every listing succeeds and none lists it, the recipient took
// it and acknowledged it, and the record is settled instead; a relay that lost
// the envelope looks the same, which the application's own redelivery covers.
// A listing that fails counts as listing it.
func (t *RelayTransport) refreshBeforeRelayTTL(ctx context.Context, path string, record *relayOutboxRecord,
	now time.Time,
) error {
	nowUnix := uint64(now.Unix())
	if !record.sealed() || record.Stopped || record.Withdrawn || record.Settled || len(record.Accepted) == 0 ||
		record.AcceptedAtUnix == 0 || nowUnix >= record.ExpiresAtUnix {
		return nil
	}
	ttl := t.pool.smallestTTL(ctx, record.Relays)
	if record.ExpiresAtUnix <= saturatingAdd(record.AcceptedAtUnix, ttl) {
		// Every relay keeps it until it expires anyway.
		return nil
	}
	// smallestTTL only returns values in 1 s to 24 h; anything else is a
	// fault of this node, reported rather than skipped.
	delay, err := relayRedepositDelay(ttl)
	if err != nil {
		return err
	}
	if nowUnix < saturatingAdd(record.AcceptedAtUnix, uint64(delay/time.Second)) {
		return nil
	}
	if !t.listedAtAcceptingRelays(ctx, *record) {
		record.Settled = true
		t.forget(record.IdempotencyKey)
		return t.store(path, *record)
	}
	packet, ok := record.journaledPacket()
	if !ok || nowUnix >= packet.ExpiresAtUnix {
		return nil
	}
	fresh, sealed := t.sealIfCardHeld(ctx, packet, record.Seals)
	if !sealed {
		// No current card now; a later pass tries again.
		return nil
	}
	record.moveCurrentToWithdrawals(true)
	record.replace(fresh)
	record.Background = true
	if err := t.store(path, *record); err != nil {
		return err
	}
	if t.afterJournal != nil {
		t.afterJournal()
	}
	t.forget(record.IdempotencyKey)
	if t.depositPending(ctx, record, record.pending(), now) {
		if err := t.store(path, *record); err != nil {
			return err
		}
	}
	// The next pass withdraws the replaced envelope once the replacement is
	// held.
	t.signal()
	return nil
}

// sealIfCardHeld seals the packet to the recipient's current card, or
// reports false when no card can take it now (none held, or finalized state
// cannot answer); the background pass then tries again later.
func (t *RelayTransport) sealIfCardHeld(ctx context.Context, packet OutboundPacket,
	seals int,
) (relayOutboxRecord, bool) {
	fresh, err := t.seal(ctx, packet, seals)
	return fresh, err == nil
}

// listedAtAcceptingRelays reports whether any relay that accepted the current
// envelope may still hold it: it lists it, or its listing failed.
func (t *RelayTransport) listedAtAcceptingRelays(ctx context.Context, record relayOutboxRecord) bool {
	var id [32]byte
	if decodeHex32(record.EnvelopeID, &id) != nil {
		return true
	}
	for _, relay := range record.Accepted {
		client, err := t.pool.client(relay)
		if err != nil {
			return true
		}
		bounded, cancel := context.WithTimeout(ctx, t.timeout)
		mailbox, err := client.List(bounded, record.Recipient)
		cancel()
		if err != nil {
			return true
		}
		for _, entry := range mailbox.Envelopes {
			if entry.EnvelopeID == id {
				return true
			}
		}
	}
	return false
}

// everyRelayConflicts reports a current envelope that no relay of its card
// accepted and every one answered 409 for.
func (r relayOutboxRecord) everyRelayConflicts() bool {
	if !r.sealed() || len(r.Accepted) > 0 || len(r.Relays) == 0 {
		return false
	}
	for _, relay := range r.Relays {
		if !slices.Contains(r.Conflicts, relay) {
			return false
		}
	}
	return true
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
			record.accept(relay, uint64(now.Unix()))
			changed = true
		case depositConflict:
			record.Conflicts, changed = append(record.Conflicts, relay), true
		default:
			failed = true
		}
	}
	// A round that leaves a replacement refused by every relay counts as a
	// failure: the backoff keeps growing across consecutive rounds of 409s
	// instead of starting again at its first step with each fresh seal.
	if record.Background && record.everyRelayConflicts() {
		failed = true
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
		if withdrawal.AfterAccepted && len(record.Accepted) == 0 {
			// The replacement is not stored anywhere yet: this envelope stays.
			clear(secret[:])
			kept = append(kept, withdrawal)
			continue
		}
		if withdrawal.AfterAccepted {
			withdrawal.AfterAccepted, changed = false, true
		}
		var remaining []string
		for _, relay := range withdrawal.Relays {
			if *budget <= 0 {
				remaining = append(remaining, relay)
				continue
			}
			*budget--
			switch t.acknowledge(ctx, relay, record.Recipient, id, secret) {
			case withdrawConfirmed:
				changed = true
			case withdrawUnconfirmed:
				// Not asked again; it still counts as stored there until it
				// expires.
				withdrawal.Unconfirmed, changed = append(withdrawal.Unconfirmed, relay), true
			default:
				remaining, failed = append(remaining, relay), true
			}
		}
		clear(secret[:])
		withdrawal.Relays = remaining
		if len(remaining) > 0 || len(withdrawal.Unconfirmed) > 0 {
			kept = append(kept, withdrawal)
		}
	}
	record.Withdrawals = kept
	t.backoff(key, retry, failed, now)
	return changed
}

// withdrawOutcome is how one withdrawal request at one relay ended.
type withdrawOutcome int

const (
	// withdrawRetry: nothing is known; asked again at a later pass.
	withdrawRetry withdrawOutcome = iota
	// withdrawConfirmed: the relay no longer holds the envelope (204, 404).
	withdrawConfirmed
	// withdrawUnconfirmed: the attempt is over without a confirmation (a
	// refusal that cannot change, or an unusable relay URL).
	withdrawUnconfirmed
)

// acknowledge withdraws one envelope at one relay.
func (t *RelayTransport) acknowledge(ctx context.Context, relay, agent string, id, secret [32]byte) withdrawOutcome {
	client, err := t.pool.client(relay)
	if err != nil {
		return withdrawUnconfirmed
	}
	bounded, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	err = client.Ack(bounded, agent, id, secret)
	switch {
	case err == nil, errors.Is(err, agentpacketrelay.ErrNotFound):
		return withdrawConfirmed
	case errors.Is(err, agentpacketrelay.ErrRateLimited), errors.Is(err, agentpacketrelay.ErrUnavailable),
		errors.Is(err, agentpacketrelay.ErrRequestTimeout):
		return withdrawRetry
	case errors.Is(err, agentpacketrelay.ErrForbidden), errors.Is(err, agentpacketrelay.ErrRejected),
		errors.Is(err, agentpacketrelay.ErrInvalidArgument):
		return withdrawUnconfirmed
	default:
		return withdrawRetry
	}
}

func (t *RelayTransport) forget(key string) {
	t.mutex.Lock()
	delete(t.retry, key)
	t.mutex.Unlock()
}

// Withdraw supersedes the packet journaled under idempotencyKey: its current
// envelope joins the withdrawals, at every relay of its card that may hold
// it, and the record is marked so that the packet is never sealed or
// deposited again. The withdrawal itself runs in the background passes with
// the bounds and backoff of the revocation path, retried until each relay
// answered or the envelope expired. It reports whether a record was found;
// an unknown key is nothing to withdraw. Withdrawing again is a no-op.
func (t *RelayTransport) Withdraw(idempotencyKey string) (bool, error) {
	if t == nil || !idempotencyKeyPattern.MatchString(idempotencyKey) {
		return false, errors.New("servicebridge: invalid relay withdrawal")
	}
	unlock := t.lock(idempotencyKey)
	defer unlock()
	path := t.recordPath(idempotencyKey)
	record, found, err := t.load(path)
	if err != nil || !found {
		return false, err
	}
	if record.Withdrawn && !record.sealed() {
		return true, nil
	}
	record.withdrawCurrent()
	record.Withdrawn, record.Background = true, false
	if err := t.store(path, record); err != nil {
		return true, err
	}
	// No redundant deposit of the superseded envelope is due any more.
	t.forget(idempotencyKey)
	if t.afterJournal != nil {
		t.afterJournal()
	}
	t.signal()
	return true, nil
}

// journaled returns the signed packet a record keeps under idempotencyKey,
// so that a retry reuses it instead of signing again, and whether a record
// exists. A record without a usable packet is reported with only its
// recipient, which the caller checks.
func (t *RelayTransport) journaled(idempotencyKey string) (OutboundPacket, bool, error) {
	state, err := t.journalState(idempotencyKey)
	return state.Packet, state.Found, err
}

// journalEntry is what the journal holds under one idempotency key.
type journalEntry struct {
	Found bool
	// Packet is the journaled packet; only its recipient is set when the
	// record keeps no usable packet.
	Packet OutboundPacket
	// Accepted reports that a relay durably accepted the current envelope.
	Accepted bool
	// Withdrawn reports a superseded packet that is never deposited again.
	Withdrawn bool
	// Relays are the relays of the card the current envelope is sealed to.
	Relays []string
}

// journalState reads the record under idempotencyKey.
func (t *RelayTransport) journalState(idempotencyKey string) (journalEntry, error) {
	if t == nil || !idempotencyKeyPattern.MatchString(idempotencyKey) {
		return journalEntry{}, errors.New("servicebridge: invalid relay journal lookup")
	}
	unlock := t.lock(idempotencyKey)
	defer unlock()
	record, found, err := t.load(t.recordPath(idempotencyKey))
	if err != nil || !found {
		return journalEntry{}, err
	}
	entry := journalEntry{
		Found: true, Accepted: len(record.Accepted) > 0, Withdrawn: record.Withdrawn,
		Relays: append([]string(nil), record.Relays...),
	}
	packet, ok := record.journaledPacket()
	if !ok {
		packet = OutboundPacket{RecipientAgentID: record.Recipient, IdempotencyKey: idempotencyKey}
	}
	entry.Packet = packet
	return entry, nil
}

// storedEnvelope is one envelope of the journal a relay may still hold.
type storedEnvelope struct {
	IdempotencyKey string
	EnvelopeID     [32]byte
	Relays         []string
	// Pending reports a current envelope some relay of its card has not
	// answered yet: a later deposit may still store it there.
	Pending bool
}

// storedFor lists, for one recipient, every envelope of the journal a relay
// may still hold: each unexpired current envelope (accepted or not, since an
// ambiguous deposit may have left it stored) and each unexpired envelope
// still to be withdrawn.
func (t *RelayTransport) storedFor(recipient string) ([]storedEnvelope, error) {
	if t == nil || !agentIDPattern.MatchString(recipient) {
		return nil, errors.New("servicebridge: invalid relay journal count")
	}
	entries, err := os.ReadDir(t.directory)
	if err != nil {
		return nil, errors.New("servicebridge: read the relay envelope journal")
	}
	now := uint64(t.now().Unix())
	var out []storedEnvelope
	for _, entry := range entries {
		if !relayOutboxFilePattern.MatchString(entry.Name()) {
			continue
		}
		unlock := t.lock("idem_" + strings.TrimSuffix(entry.Name(), ".json"))
		record, found, err := t.load(filepath.Join(t.directory, entry.Name()))
		unlock()
		if err != nil {
			// One bad record must not stop carriage to every peer. It names
			// no recipient that can be trusted, so it counts as one stored
			// envelope for every peer (conservative under the in-flight cap)
			// and is never taken for gone, until it is old enough that
			// nothing it describes can still be stored; then it is
			// quarantined and frees its slot.
			if t.handleUnreadable(entry.Name(), err) {
				continue
			}
			out = append(out, storedEnvelope{
				IdempotencyKey: "idem_" + strings.TrimSuffix(entry.Name(), ".json"), Pending: true,
			})
			continue
		}
		if !found || record.Recipient != recipient {
			continue
		}
		if record.sealed() && now < record.ExpiresAtUnix {
			var id [32]byte
			if decodeHex32(record.EnvelopeID, &id) == nil {
				out = append(out, storedEnvelope{
					IdempotencyKey: record.IdempotencyKey, EnvelopeID: id,
					Relays: append([]string(nil), record.Relays...), Pending: len(record.pending()) > 0,
				})
			}
		}
		for _, withdrawal := range record.Withdrawals {
			var id [32]byte
			if now >= withdrawal.ExpiresAtUnix || decodeHex32(withdrawal.EnvelopeID, &id) != nil {
				continue
			}
			// Relays whose withdrawal ended unconfirmed still count, until
			// the envelope expires.
			out = append(out, storedEnvelope{
				IdempotencyKey: record.IdempotencyKey, EnvelopeID: id, Relays: withdrawal.storedAt(),
			})
		}
		if record.Residual.Count > 0 && now < record.Residual.UntilUnix {
			// Dropped withdrawals name no relay, so they are never taken for
			// gone.
			for range record.Residual.Count {
				out = append(out, storedEnvelope{IdempotencyKey: record.IdempotencyKey, Pending: true})
			}
		}
	}
	return out, nil
}

// RelayOutboxView summarizes one journaled envelope for status.
type RelayOutboxView struct {
	// Unreadable names a journal file that failed to load; the other
	// fields are then empty.
	Unreadable    string   `json:"unreadable,omitempty"`
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
	// Withdrawn reports a packet its sender superseded: it is never
	// deposited again.
	Withdrawn bool `json:"withdrawn,omitempty"`
	// Withdrawing lists the envelopes still to be withdrawn, by id and
	// relay; never their secrets.
	Withdrawing []RelayWithdrawalView `json:"withdrawing,omitempty"`
}

// RelayWithdrawalView is one envelope still to be withdrawn.
type RelayWithdrawalView struct {
	EnvelopeID    string   `json:"envelope_id"`
	Relays        []string `json:"relays"`
	ExpiresAtUnix uint64   `json:"expires_at_unix"`
	// Unconfirmed lists relays whose withdrawal ended without confirmation;
	// the envelope counts as stored there until it expires.
	Unconfirmed []string `json:"unconfirmed,omitempty"`
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
			out = append(out, RelayOutboxView{Unreadable: entry.Name()})
			continue
		}
		if !found {
			continue
		}
		view := RelayOutboxView{
			Recipient: record.Recipient, EnvelopeID: record.EnvelopeID, KeyID: record.KeyID,
			ExpiresAtUnix: record.ExpiresAtUnix, Accepted: append([]string{}, record.Accepted...),
			Conflicts: record.Conflicts, Pending: append([]string{}, record.pending()...), Seals: record.Seals,
			AwaitingCard: !record.sealed() && !record.Withdrawn, Withdrawn: record.Withdrawn,
		}
		for _, withdrawal := range record.Withdrawals {
			view.Withdrawing = append(view.Withdrawing, RelayWithdrawalView{
				EnvelopeID: withdrawal.EnvelopeID, Relays: append([]string{}, withdrawal.Relays...),
				ExpiresAtUnix: withdrawal.ExpiresAtUnix, Unconfirmed: append([]string(nil), withdrawal.Unconfirmed...),
			})
		}
		out = append(out, view)
	}
	return out, nil
}
