package servicebridge

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketrelay"
)

// Relay retention as the relays advertise it (GET /v1/relay max_ttl_seconds).
// A relay keeps an envelope nobody acknowledges until the earlier of its
// expiry and its receipt plus that TTL, so a sender that keeps a packet
// longer deposits it again before the smallest TTL among the card's relays
// runs out.
const (
	// relayTTLCeilingSeconds is the protocol bound, and the value a relay
	// whose description cannot be read counts as. Counting an unread relay
	// as the ceiling lets the card's readable relays set the schedule; when
	// none is readable the schedule falls back to 80 % of the ceiling, which
	// delays delivery to an offline recipient but loses nothing the
	// application's own redelivery does not already cover. A relay whose
	// description cannot be read usually takes no deposits either.
	relayTTLCeilingSeconds = uint64(agentpacketrelay.MaxTTL / time.Second)
	// relayDescriptionRefresh is how long a read description is used before
	// it is read again; relayDescriptionRetry how long after a failed read.
	relayDescriptionRefresh = time.Hour
	relayDescriptionRetry   = 5 * time.Minute
	// relayDescriptionStale is how long a description read before stays in
	// use while new reads fail.
	relayDescriptionStale = 2 * relayDescriptionRefresh
	// relayDescribeTimeout bounds one description read.
	relayDescribeTimeout = 5 * time.Second
	// maxRelayTTLEntries bounds the relays whose description is remembered.
	maxRelayTTLEntries = 4096
	// relayRedepositPercent is the share of the smallest relay TTL after
	// which an envelope is deposited again.
	relayRedepositPercent = 80
	// MinRelayRedeposit is the shortest wait before an envelope is deposited
	// again, whatever a relay advertises, so a relay that advertises a tiny
	// TTL cannot turn its senders into a deposit flood.
	MinRelayRedeposit = 10 * time.Minute
)

// errRelayTTL reports a relay TTL outside 1 s to 24 h.
var errRelayTTL = errors.New("servicebridge: the relay TTL is outside 1 s to 24 h")

type relayTTLEntry struct {
	seconds uint64
	// readAt is when seconds was read; zero when no read ever succeeded.
	readAt time.Time
	// next is when the description is read again.
	next time.Time
}

func (p *relayPool) clock() time.Time {
	if p.now == nil {
		return time.Now()
	}
	return p.now()
}

// relayTTL is the retention one relay advertises, read and cached with a
// bounded refresh; a relay whose description is not known counts as the
// protocol ceiling.
func (p *relayPool) relayTTL(ctx context.Context, relay string) uint64 {
	now := p.clock()
	p.ttlMutex.Lock()
	entry, held := p.ttls[relay]
	p.ttlMutex.Unlock()
	if held && now.Before(entry.next) {
		return entry.value(now)
	}
	seconds, err := p.describeTTL(ctx, relay)
	p.ttlMutex.Lock()
	defer p.ttlMutex.Unlock()
	if err == nil {
		entry = relayTTLEntry{seconds: seconds, readAt: now, next: now.Add(relayDescriptionRefresh)}
	} else {
		entry.next = now.Add(relayDescriptionRetry)
	}
	if _, present := p.ttls[relay]; !present && len(p.ttls) >= maxRelayTTLEntries {
		p.evictTTLLocked()
	}
	p.ttls[relay] = entry
	return entry.value(now)
}

// value is the TTL an entry stands for at now: the last read while it is
// not stale, the ceiling otherwise.
func (e relayTTLEntry) value(now time.Time) uint64 {
	if e.readAt.IsZero() || e.seconds == 0 || now.Sub(e.readAt) >= relayDescriptionStale || now.Before(e.readAt) {
		return relayTTLCeilingSeconds
	}
	return e.seconds
}

func (p *relayPool) evictTTLLocked() {
	var oldest string
	var oldestNext time.Time
	first := true
	for relay, entry := range p.ttls {
		if first || entry.next.Before(oldestNext) {
			oldest, oldestNext, first = relay, entry.next, false
		}
	}
	delete(p.ttls, oldest)
}

func (p *relayPool) describeTTL(ctx context.Context, relay string) (uint64, error) {
	client, err := p.client(relay)
	if err != nil {
		return 0, err
	}
	bounded, cancel := context.WithTimeout(ctx, relayDescribeTimeout)
	defer cancel()
	description, err := client.Describe(bounded)
	if err != nil {
		return 0, err
	}
	// The client refuses a value outside the V1 bound; checked again here
	// because a scheduling decision rests on it.
	if description.MaxTTLSeconds == 0 || description.MaxTTLSeconds > relayTTLCeilingSeconds {
		return 0, errRelayTTL
	}
	return description.MaxTTLSeconds, nil
}

// smallestTTL is the smallest retention among relays, each read
// concurrently; no relay, or none readable, gives the protocol ceiling.
func (p *relayPool) smallestTTL(ctx context.Context, relays []string) uint64 {
	if p == nil || ctx == nil || len(relays) == 0 {
		return relayTTLCeilingSeconds
	}
	values := make([]uint64, len(relays))
	var group sync.WaitGroup
	for index, relay := range relays {
		group.Add(1)
		go func() {
			defer group.Done()
			values[index] = p.relayTTL(ctx, relay)
		}()
	}
	group.Wait()
	smallest := relayTTLCeilingSeconds
	for _, value := range values {
		if value != 0 && value < smallest {
			smallest = value
		}
	}
	return smallest
}

// relayRedepositDelay is how long after an accepted deposit the envelope is
// deposited again: 80 % of the smallest relay TTL, at least
// MinRelayRedeposit (below a 12.5-minute TTL the envelope is then absent for
// part of each interval).
func relayRedepositDelay(ttlSeconds uint64) (time.Duration, error) {
	if ttlSeconds == 0 || ttlSeconds > relayTTLCeilingSeconds {
		return 0, errRelayTTL
	}
	// ttlSeconds is at most 86,400, so the products cannot overflow.
	delay := time.Duration(ttlSeconds*relayRedepositPercent/100) * time.Second
	if delay < MinRelayRedeposit {
		delay = MinRelayRedeposit
	}
	return delay, nil
}
