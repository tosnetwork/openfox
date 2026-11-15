package servicebridge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/rand/v2"
	"sort"
	"sync"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketrelay"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
)

// Relay polling pace.
const (
	// RelayPollInterval is the pause between listings of one relay.
	RelayPollInterval = 15 * time.Second
	// RelayPollMinimum is the shortest pause the node ever takes.
	RelayPollMinimum = 5 * time.Second
	// RelayPollMaxBackoff caps the pause after failures.
	RelayPollMaxBackoff = 5 * time.Minute
	// relayPollJitter is the largest random addition, as a fraction.
	relayPollJitter = 0.2
	// relayRetryAfterCap bounds how long one Retry-After hint can stall a
	// relay's polling.
	relayRetryAfterCap = time.Hour
	// maxRelayMemory bounds the not-again and settled memories; evicting
	// an entry only costs a repeated download.
	maxRelayMemory = 8192
	// relayMemoryHorizon is the longest an envelope can be listed, so the
	// longest anything is remembered.
	relayMemoryHorizon = RelayEnvelopeTTL + agentpacketseal.ClockSkew
)

// Fixed poll failure descriptions; nothing a relay answers is repeated.
const (
	relayErrList       = "the mailbox listing failed"
	relayErrRateLimit  = "the relay asked to retry later"
	relayErrDownload   = "an envelope download failed"
	relayErrAck        = "an acknowledgement failed"
	relayErrDialFailed = "the relay URL cannot be used"
)

// settledEnvelope is an envelope id whose packet is durably stored, or was
// refused after it opened: its secret acknowledges it at every relay.
type settledEnvelope struct {
	secret  [agentpacketseal.AckSecretSize]byte
	expires uint64
	acked   map[string]bool
}

// RelayPollState is one relay's polling state as status shows it.
type RelayPollState struct {
	URL                 string `json:"url"`
	LastListUnix        int64  `json:"last_list_unix,omitempty"`
	LastErrorUnix       int64  `json:"last_error_unix,omitempty"`
	LastError           string `json:"last_error,omitempty"`
	ConsecutiveFailures int    `json:"consecutive_failures"`
	Listed              int    `json:"listed"`
	NextPollUnix        int64  `json:"next_poll_unix"`
	backoff             time.Duration
	next                time.Time
}

// RelayInbound polls the relays of every held key, opens envelopes sealed
// to this node, and hands each packet to the receiver's own accept path.
// An envelope is acknowledged only after its frame is durably in the inbox
// (or the packet inside it was refused for good), at every relay that
// listed it.
type RelayInbound struct {
	agentID  string
	keys     *RelayKeys
	receiver *Receiver
	pool     *relayPool
	now      func() time.Time
	report   func(stage string, err error)
	mutex    sync.Mutex
	state    map[string]*RelayPollState
	// failed is the not-again memory of envelopes that did not open, keyed
	// by relay and envelope id and by a digest of the bytes, never by the
	// envelope id alone: a junk copy at one relay never hides the genuine
	// envelope at another.
	failed  map[string]uint64
	settled map[[32]byte]*settledEnvelope
}

// NewRelayInbound assembles the poller.
func NewRelayInbound(agentID string, keys *RelayKeys, receiver *Receiver, pool *relayPool,
	now func() time.Time, report func(string, error),
) (*RelayInbound, error) {
	if !agentIDPattern.MatchString(agentID) || keys == nil || receiver == nil || pool == nil ||
		receiver.LocalAgentID != agentID {
		return nil, errors.New("servicebridge: invalid relay inbound configuration")
	}
	if now == nil {
		now = time.Now
	}
	if report == nil {
		report = func(string, error) {}
	}
	return &RelayInbound{
		agentID: agentID, keys: keys, receiver: receiver, pool: pool, now: now, report: report,
		state: map[string]*RelayPollState{}, failed: map[string]uint64{}, settled: map[[32]byte]*settledEnvelope{},
	}, nil
}

// Due polls every relay whose pause has passed and returns when the next
// one is due.
func (r *RelayInbound) Due(ctx context.Context) time.Time {
	relays := r.keys.PollRelays()
	now := r.now()
	r.mutex.Lock()
	for relay := range r.state {
		if !containsString(relays, relay) {
			delete(r.state, relay)
		}
	}
	for _, relay := range relays {
		if _, ok := r.state[relay]; !ok {
			r.state[relay] = &RelayPollState{URL: relay, next: now}
		}
	}
	r.mutex.Unlock()
	next := now.Add(RelayPollInterval)
	for _, relay := range relays {
		r.mutex.Lock()
		state := r.state[relay]
		due := !now.Before(state.next)
		r.mutex.Unlock()
		if due {
			r.Poll(ctx, relay)
		}
		r.mutex.Lock()
		if state.next.Before(next) {
			next = state.next
		}
		r.mutex.Unlock()
	}
	return next
}

// Poll lists one relay once and processes what it lists.
func (r *RelayInbound) Poll(ctx context.Context, relay string) {
	err, retryAfter := r.poll(ctx, relay)
	now := r.now()
	r.mutex.Lock()
	defer r.mutex.Unlock()
	state, ok := r.state[relay]
	if !ok {
		state = &RelayPollState{URL: relay}
		r.state[relay] = state
	}
	if err == "" {
		state.ConsecutiveFailures, state.backoff, state.LastListUnix = 0, 0, now.Unix()
		state.next = now.Add(jittered(RelayPollInterval))
	} else {
		state.ConsecutiveFailures++
		state.LastError, state.LastErrorUnix = err, now.Unix()
		backoff := state.backoff * 2
		if backoff < RelayPollInterval {
			backoff = RelayPollInterval
		}
		if backoff > RelayPollMaxBackoff {
			backoff = RelayPollMaxBackoff
		}
		state.backoff = backoff
		wait := jittered(backoff)
		if retryAfter > relayRetryAfterCap {
			retryAfter = relayRetryAfterCap
		}
		if retryAfter > wait {
			wait = retryAfter
		}
		state.next = now.Add(wait)
	}
	state.NextPollUnix = state.next.Unix()
}

func jittered(base time.Duration) time.Duration {
	if base < RelayPollMinimum {
		base = RelayPollMinimum
	}
	return base + time.Duration(rand.Float64()*relayPollJitter*float64(base))
}

// poll returns a fixed failure description, or "" when the listing was
// processed (an envelope left for a later poll is not a relay failure).
func (r *RelayInbound) poll(ctx context.Context, relay string) (string, time.Duration) {
	client, err := r.pool.client(relay)
	if err != nil {
		return relayErrDialFailed, 0
	}
	listCtx, cancel := context.WithTimeout(ctx, RelayRequestTimeout)
	mailbox, err := client.List(listCtx, r.agentID)
	cancel()
	if err != nil {
		if errors.Is(err, agentpacketrelay.ErrRateLimited) {
			return relayErrRateLimit, relayRetryAfter(err)
		}
		return relayErrList, relayRetryAfter(err)
	}
	r.mutex.Lock()
	if state, ok := r.state[relay]; ok {
		state.Listed = len(mailbox.Envelopes)
	}
	r.mutex.Unlock()
	r.prune()
	failure := ""
	for _, entry := range mailbox.Envelopes {
		if ctx.Err() != nil {
			return "", 0
		}
		if problem := r.process(ctx, client, relay, entry); problem != "" {
			failure = problem
		}
	}
	return failure, 0
}

func (r *RelayInbound) remembered(key string) bool {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	expiry, ok := r.failed[key]
	return ok && uint64(r.now().Unix()) < expiry
}

func (r *RelayInbound) remember(key string, listedExpiry uint64) {
	horizon := saturatingAdd(uint64(r.now().Unix()), uint64(relayMemoryHorizon/time.Second))
	if listedExpiry == 0 || listedExpiry > horizon {
		listedExpiry = horizon
	}
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if len(r.failed) >= maxRelayMemory {
		r.evictFailedLocked()
	}
	r.failed[key] = listedExpiry
}

func (r *RelayInbound) evictFailedLocked() {
	var oldest string
	var oldestExpiry uint64
	for key, expiry := range r.failed {
		if oldest == "" || expiry < oldestExpiry {
			oldest, oldestExpiry = key, expiry
		}
	}
	delete(r.failed, oldest)
}

func (r *RelayInbound) prune() {
	now := uint64(r.now().Unix())
	r.mutex.Lock()
	defer r.mutex.Unlock()
	for key, expiry := range r.failed {
		if now >= expiry {
			delete(r.failed, key)
		}
	}
	for id, settled := range r.settled {
		if now >= settled.expires {
			delete(r.settled, id)
		}
	}
}

func relayMemoryKey(relay string, id [32]byte) string {
	return relay + "\x00" + hex.EncodeToString(id[:])
}

func bytesMemoryKey(raw []byte) string {
	digest := sha256.Sum256(raw)
	return "sha256\x00" + hex.EncodeToString(digest[:])
}

// process handles one listed envelope by the recipient rules: parse, open
// under the held key its header names, check the acknowledgement hash,
// accept the packet exactly as any carrier's, and only then acknowledge.
func (r *RelayInbound) process(ctx context.Context, client relayAPI, relay string,
	entry agentpacketrelay.MailboxEntry,
) string {
	if settled := r.settledFor(entry.EnvelopeID); settled != nil {
		return r.ackAt(ctx, client, relay, entry.EnvelopeID, settled)
	}
	key := relayMemoryKey(relay, entry.EnvelopeID)
	if r.remembered(key) {
		return ""
	}
	if _, held := r.keys.private(entry.RecipientKeyID); !held {
		// The listing names a key this node does not hold (never issued or
		// destroyed): it cannot be opened or deleted and is left to expire.
		r.remember(key, entry.ExpiresAtUnix)
		return ""
	}
	downloadCtx, cancel := context.WithTimeout(ctx, RelayRequestTimeout)
	raw, err := client.Download(downloadCtx, r.agentID, entry.EnvelopeID)
	cancel()
	if errors.Is(err, agentpacketrelay.ErrNotFound) {
		return ""
	}
	if errors.Is(err, agentpacketrelay.ErrInvalidResponse) {
		r.remember(key, entry.ExpiresAtUnix)
		return ""
	}
	if err != nil {
		return relayErrDownload
	}
	if r.remembered(bytesMemoryKey(raw)) {
		r.remember(key, entry.ExpiresAtUnix)
		return ""
	}
	opened, ok := r.open(raw, entry.EnvelopeID)
	if !ok {
		r.remember(key, entry.ExpiresAtUnix)
		r.remember(bytesMemoryKey(raw), entry.ExpiresAtUnix)
		return ""
	}
	status, message, transient, err := r.receiver.acceptPacket(ctx, opened.PacketJSON)
	if err != nil && transient {
		// Finalized state or the inbox was unavailable: not acknowledged,
		// tried again on a later poll.
		r.report("relay.receive", errors.New("servicebridge: a relayed packet could not be checked or stored now; "+
			"it stays at the relay"))
		return ""
	}
	if err != nil {
		// The packet opened under this node's key but is not acceptable
		// (malformed, another recipient, a signer that is not a finalized
		// controller): it is acknowledged so it does not hold quota.
		r.report("relay.receive", errors.New("servicebridge: a relayed packet was refused and acknowledged"))
	} else if r.receiver.Notify != nil && status != InboxPartial && message != nil {
		r.receiver.Notify(status, *message)
	}
	settled := r.settle(opened)
	return r.ackAt(ctx, client, relay, entry.EnvelopeID, settled)
}

// open runs the first three recipient steps. A failure at any of them is
// the envelope's: it is remembered and never acknowledged.
func (r *RelayInbound) open(raw []byte, listed [32]byte) (agentpacketseal.Opened, bool) {
	header, err := agentpacketseal.ParseEnvelope(raw)
	if err != nil || header.RecipientAgentID != r.agentID || header.EnvelopeID != listed {
		return agentpacketseal.Opened{}, false
	}
	private, held := r.keys.private(header.RecipientKeyID)
	if !held {
		return agentpacketseal.Opened{}, false
	}
	opened, err := agentpacketseal.Open(private, raw)
	if err != nil || opened.Header.EnvelopeID != listed {
		return agentpacketseal.Opened{}, false
	}
	return opened, true
}

func (r *RelayInbound) settledFor(id [32]byte) *settledEnvelope {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	settled, ok := r.settled[id]
	if !ok || uint64(r.now().Unix()) >= settled.expires {
		return nil
	}
	return settled
}

func (r *RelayInbound) settle(opened agentpacketseal.Opened) *settledEnvelope {
	horizon := saturatingAdd(uint64(r.now().Unix()), uint64(relayMemoryHorizon/time.Second))
	expires := opened.Header.ExpiresAtUnix
	if expires == 0 || expires > horizon {
		expires = horizon
	}
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if existing, ok := r.settled[opened.Header.EnvelopeID]; ok {
		return existing
	}
	if len(r.settled) >= maxRelayMemory {
		var oldest [32]byte
		var oldestExpiry uint64
		first := true
		for id, settled := range r.settled {
			if first || settled.expires < oldestExpiry {
				oldest, oldestExpiry, first = id, settled.expires, false
			}
		}
		delete(r.settled, oldest)
	}
	settled := &settledEnvelope{secret: opened.AckSecret, expires: expires, acked: map[string]bool{}}
	r.settled[opened.Header.EnvelopeID] = settled
	return settled
}

// ackAt acknowledges a settled envelope at one relay; a failure leaves it
// listed there and the next poll tries again.
func (r *RelayInbound) ackAt(ctx context.Context, client relayAPI, relay string, id [32]byte,
	settled *settledEnvelope,
) string {
	r.mutex.Lock()
	done := settled.acked[relay]
	secret := settled.secret
	r.mutex.Unlock()
	if done {
		return ""
	}
	ackCtx, cancel := context.WithTimeout(ctx, RelayRequestTimeout)
	err := client.Ack(ackCtx, r.agentID, id, secret)
	cancel()
	if err != nil && !errors.Is(err, agentpacketrelay.ErrNotFound) {
		return relayErrAck
	}
	r.mutex.Lock()
	settled.acked[relay] = true
	r.mutex.Unlock()
	return ""
}

// States returns every relay's polling state, by URL.
func (r *RelayInbound) States() []RelayPollState {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	out := make([]RelayPollState, 0, len(r.state))
	for _, state := range r.state {
		copied := *state
		out = append(out, copied)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].URL < out[j].URL })
	return out
}

func containsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
