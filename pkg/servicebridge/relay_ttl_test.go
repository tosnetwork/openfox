package servicebridge

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
)

func TestRelayRedepositDelayIsEightyPercentOfTheTTLWithAFloor(t *testing.T) {
	for _, test := range []struct {
		ttl  uint64
		want time.Duration
	}{
		{3600, 48 * time.Minute},               // test relays
		{10800, 2*time.Hour + 24*time.Minute},  // production relays
		{86400, 19*time.Hour + 12*time.Minute}, // protocol ceiling
		{750, MinRelayRedeposit},               // exactly the floor
		{60, MinRelayRedeposit},                // floored
		{1, MinRelayRedeposit},                 // floored
		{3601, 48 * time.Minute},               // whole seconds, rounded down
	} {
		got, err := relayRedepositDelay(test.ttl)
		if err != nil || got != test.want {
			t.Errorf("ttl %d: %s %v, want %s", test.ttl, got, err, test.want)
		}
	}
	for _, ttl := range []uint64{0, relayTTLCeilingSeconds + 1, ^uint64(0)} {
		if _, err := relayRedepositDelay(ttl); !errors.Is(err, errRelayTTL) {
			t.Errorf("ttl %d: err = %v", ttl, err)
		}
	}
}

// Each relay's description is read once per refresh period; a failed read
// keeps the last value while it is fresh enough, then counts as the ceiling,
// and so does a value no V1 relay can have.
func TestRelayDescriptionsAreReadCachedAndBounded(t *testing.T) {
	clock := newRelayClock()
	pool := newRelayPool(nil)
	pool.now = clock.Now
	ctx := context.Background()
	oneHour, day, unreadable, outOfRange := startFakeRelay(t, clock), startFakeRelay(t, clock),
		startFakeRelay(t, clock), startFakeRelay(t, clock)
	oneHour.setTTL(3600)
	unreadable.describeFails = true
	outOfRange.setTTL(relayTTLCeilingSeconds + 1)
	if got := pool.relayTTL(ctx, oneHour.URL); got != 3600 {
		t.Fatalf("1 h relay: %d", got)
	}
	if got := pool.relayTTL(ctx, day.URL); got != relayTTLCeilingSeconds {
		t.Fatalf("24 h relay: %d", got)
	}
	if got := pool.relayTTL(ctx, unreadable.URL); got != relayTTLCeilingSeconds {
		t.Fatalf("unreadable relay: %d", got)
	}
	if got := pool.relayTTL(ctx, outOfRange.URL); got != relayTTLCeilingSeconds {
		t.Fatalf("out-of-range relay: %d", got)
	}
	// The smallest of a card's relays wins; none, or none readable, is the
	// ceiling.
	if got := pool.smallestTTL(ctx, []string{day.URL, oneHour.URL, unreadable.URL}); got != 3600 {
		t.Fatalf("mixed card: %d", got)
	}
	if got := pool.smallestTTL(ctx, []string{unreadable.URL, outOfRange.URL}); got != relayTTLCeilingSeconds {
		t.Fatalf("unreadable card: %d", got)
	}
	if got := pool.smallestTTL(ctx, nil); got != relayTTLCeilingSeconds {
		t.Fatalf("no relay: %d", got)
	}
	// Cached: no second read within the refresh period.
	pool.relayTTL(ctx, oneHour.URL)
	if got := oneHour.describeCount(); got != 1 {
		t.Fatalf("description read %d times within the refresh period", got)
	}
	// A failed read is retried after the retry period, not every call.
	clock.Advance(time.Minute)
	pool.relayTTL(ctx, unreadable.URL)
	if got := unreadable.describeCount(); got != 1 {
		t.Fatalf("a failed read was retried after a minute: %d", got)
	}
	clock.Advance(relayDescriptionRetry)
	pool.relayTTL(ctx, unreadable.URL)
	if got := unreadable.describeCount(); got != 2 {
		t.Fatalf("a failed read was not retried: %d", got)
	}
	// A relay that stops answering keeps its last value while it is fresh.
	oneHour.mutex.Lock()
	oneHour.describeFails = true
	oneHour.mutex.Unlock()
	clock.Advance(relayDescriptionRefresh)
	if got := pool.relayTTL(ctx, oneHour.URL); got != 3600 {
		t.Fatalf("a recent value was dropped on one failed read: %d", got)
	}
	clock.Advance(relayDescriptionStale)
	if got := pool.relayTTL(ctx, oneHour.URL); got != relayTTLCeilingSeconds {
		t.Fatalf("a stale value is still used: %d", got)
	}
	// A changed TTL is seen at the next read.
	oneHour.mutex.Lock()
	oneHour.describeFails, oneHour.ttl = false, 10800
	oneHour.mutex.Unlock()
	clock.Advance(relayDescriptionRetry)
	if got := pool.relayTTL(ctx, oneHour.URL); got != 10800 {
		t.Fatalf("a changed TTL was not read: %d", got)
	}
}

func TestPacketExpiryFollowsTheBusinessDeadline(t *testing.T) {
	now := uint64(1_900_000_000)
	lifetime := uint64(PacketLifetime / time.Second)
	envelope := func(kind byte, notAfter uint64) Envelope {
		value := testEnvelope()
		value.Kind, value.NotAfterUnix = kind, notAfter
		return value
	}
	for _, test := range []struct {
		name     string
		envelope Envelope
		want     uint64
	}{
		{"task at its response deadline", envelope(FrameTask, now+7200), now + 7200},
		{"result at its retention end", envelope(FrameResult, now+3*3600), now + 3*3600},
		{"result request at its retention end", envelope(FrameResultRequest, now+600), now + 600},
		{"deadline beyond the packet lifetime is capped", envelope(FrameResult, now+30*24*3600), now + lifetime},
		{"no deadline is the packet lifetime", envelope(FrameResult, 0), now + lifetime},
		{"an ack lives an hour", envelope(FrameResultAck, 0), now + 3600},
		{"an ack never outlives its deadline", envelope(FrameResultAck, now+60), now + 60},
		{"an overflowing deadline is capped", envelope(FrameTask, ^uint64(0)), now + lifetime},
	} {
		got, err := packetExpiry(test.envelope, now)
		if err != nil || got != test.want {
			t.Errorf("%s: %d %v, want %d", test.name, got, err, test.want)
		}
	}
	for _, notAfter := range []uint64{now, now - 1, 1} {
		if _, err := packetExpiry(envelope(FrameTask, notAfter), now); !errors.Is(err, ErrDeliveryDeadlinePassed) {
			t.Errorf("deadline %d: err = %v", notAfter, err)
		}
	}
	// The courier signs and journals nothing for a message past its deadline.
	directory := filepath.Join(t.TempDir(), "outbox")
	transport := &recordingTransport{}
	courier, err := OpenCourier(directory, testSigner(t, testSeller), transport)
	if err != nil {
		t.Fatal(err)
	}
	courier.now = func() time.Time { return time.Unix(int64(now), 0) }
	if _, err := courier.Deliver(context.Background(), envelope(FrameTask, now), []byte("late")); !errors.Is(err,
		ErrDeliveryDeadlinePassed) {
		t.Fatalf("a task past its response deadline: %v", err)
	}
	if entries, _ := os.ReadDir(directory); len(entries) != 0 {
		t.Fatal("a message past its deadline was journaled")
	}
	if _, err := courier.Deliver(context.Background(), envelope(FrameTask, now+7200), []byte("task")); err != nil {
		t.Fatal(err)
	}
	for _, packet := range transport.sent {
		if packet.ExpiresAtUnix != now+7200 {
			t.Fatalf("task packet expires at %d, want the response deadline %d", packet.ExpiresAtUnix, now+7200)
		}
	}
}

// railPair is a seller that holds the buyer's card naming relays.
func railPair(t *testing.T, clock *relayClock, relays ...*fakeRelay) (*relayTestNode, *relayTestNode) {
	t.Helper()
	agents := relayAgents()
	seller := newRelayTestNode(t, clock, testSeller, agents, relays[0])
	buyer := newRelayTestNode(t, clock, testBuyer, agents, relays...)
	seller.learn(buyer)
	return seller, buyer
}

func currentEnvelope(t *testing.T, node *relayTestNode) (relayOutboxRecord, [32]byte) {
	t.Helper()
	records := node.journal()
	if len(records) != 1 || !records[0].sealed() {
		t.Fatalf("journal: %d records", len(records))
	}
	return records[0], envelopeID(t, records[0].EnvelopeID)
}

// A rail packet whose deadline outlasts the relays' retention is deposited
// again, under a fresh seal, at 80 % of the smallest TTL of the recipient's
// card (a 1 h relay beside a 24 h one), before the 1 h relay drops it; the
// old envelope is withdrawn once the new one is held, and an envelope the
// recipient took is never deposited again.
func TestARailEnvelopeIsDepositedAgainBeforeAOneHourTTL(t *testing.T) {
	clock := newRelayClock()
	short, long := twoRelays(t, clock)
	short.setTTL(3600)
	seller, buyer := railPair(t, clock, short, long)
	envelope := relayEnvelopeTo(testBuyer)
	envelope.NotAfterUnix = uint64(clock.Now().Add(6 * time.Hour).Unix())
	if _, err := seller.courier.Deliver(context.Background(), envelope, markedBody(40)); err != nil {
		t.Fatal(err)
	}
	seller.redeposit()
	first, firstID := currentEnvelope(t, seller)
	if !short.holds(testBuyer, firstID) || !long.holds(testBuyer, firstID) || first.AcceptedAtUnix == 0 {
		t.Fatalf("the first envelope is not held at both relays: accepted at %d", first.AcceptedAtUnix)
	}
	deposits := len(short.depositLog())
	clock.Advance(48*time.Minute - time.Second)
	seller.redeposit()
	if _, id := currentEnvelope(t, seller); id != firstID || len(short.depositLog()) != deposits {
		t.Fatal("the envelope was replaced before 80 % of the smallest TTL")
	}
	clock.Advance(time.Second)
	seller.redeposit()
	second, secondID := currentEnvelope(t, seller)
	if secondID == firstID || !short.holds(testBuyer, secondID) || !long.holds(testBuyer, secondID) {
		t.Fatal("no fresh envelope was deposited at 48 minutes")
	}
	if len(second.Withdrawals) != 1 || second.Withdrawals[0].EnvelopeID != first.EnvelopeID {
		t.Fatalf("the replaced envelope is not being withdrawn: %+v", second.Withdrawals)
	}
	// The next pass withdraws it; the packet stays held.
	seller.redeposit()
	if short.holds(testBuyer, firstID) || long.holds(testBuyer, firstID) {
		t.Fatal("the replaced envelope was not withdrawn")
	}
	// Past the 1 h relay's retention of the first deposit, the packet is
	// still there.
	clock.Advance(20 * time.Minute)
	if !short.holds(testBuyer, secondID) {
		t.Fatal("the 1 h relay no longer holds the packet")
	}
	buyer.pollAll()
	if messages := buyer.pending(); len(messages) != 1 {
		t.Fatalf("the buyer holds %d messages", len(messages))
	}
	// The buyer acknowledged it at both relays: no relay lists it any more,
	// so the next due pass settles it and deposits nothing.
	deposits = len(short.depositLog())
	clock.Advance(48 * time.Minute)
	seller.redeposit()
	settled, id := currentEnvelope(t, seller)
	if !settled.Settled || id != secondID || len(short.depositLog()) != deposits {
		t.Fatalf("an acknowledged envelope was deposited again: settled=%v", settled.Settled)
	}
	clock.Advance(48 * time.Minute)
	seller.redeposit()
	if len(short.depositLog()) != deposits || len(buyer.pending()) != 1 {
		t.Fatal("a settled envelope was deposited again")
	}
}

// A relay whose description cannot be read counts as the 24 h ceiling: with
// no readable relay on the card nothing is replaced early (the documented
// fallback), and once the description reads again the schedule follows it.
func TestAnUnreadableRelayDescriptionFallsBackToTheCeiling(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	relay.setTTL(3600)
	relay.describeFails = true
	seller, _ := railPair(t, clock, relay)
	envelope := relayEnvelopeTo(testBuyer)
	envelope.NotAfterUnix = uint64(clock.Now().Add(6 * time.Hour).Unix())
	if _, err := seller.courier.Deliver(context.Background(), envelope, markedBody(40)); err != nil {
		t.Fatal(err)
	}
	_, firstID := currentEnvelope(t, seller)
	clock.Advance(50 * time.Minute)
	seller.redeposit()
	if _, id := currentEnvelope(t, seller); id != firstID {
		t.Fatal("an envelope was replaced on a TTL nobody advertised")
	}
	relay.mutex.Lock()
	relay.describeFails = false
	relay.mutex.Unlock()
	clock.Advance(relayDescriptionRetry)
	seller.redeposit()
	if _, id := currentEnvelope(t, seller); id == firstID || !relay.holds(testBuyer, id) {
		t.Fatal("the envelope was not replaced once the 1 h TTL was read")
	}
}

// The carrier reports the smallest advertised TTL of the recipient's chat
// card with every carried answer; an unreadable relay counts as 24 h.
func TestTheCarrierReportsTheSmallestRelayTTLOfTheCard(t *testing.T) {
	for _, test := range []struct {
		name         string
		ttlA, ttlB   uint64
		failA, failB bool
		want         uint64
	}{
		{"1 h test relay beside a 24 h one", 3600, 86400, false, false, 3600},
		{"3 h production relays", 10800, 10800, false, false, 10800},
		{"the 1 h relay's description fails", 3600, 10800, true, false, 10800},
		{"no description readable", 3600, 3600, true, true, relayTTLCeilingSeconds},
	} {
		t.Run(test.name, func(t *testing.T) {
			clock := newRelayClock()
			relayA, relayB := twoRelays(t, clock)
			relayA.setTTL(test.ttlA)
			relayB.setTTL(test.ttlB)
			relayA.describeFails, relayB.describeFails = test.failA, test.failB
			a, b := chatPair(t, clock, relayA.URL, relayB.URL)
			event := chatEventID("ttl")
			for generation := uint32(1); generation <= 2; generation++ {
				response := a.daemon.carry(b.agent, event, generation)
				requireResult(t, response, carrierapi.ResultCarried, "")
				if response.RelayTTLSeconds != test.want {
					t.Fatalf("generation %d reported %d, want %d", generation, response.RelayTTLSeconds, test.want)
				}
			}
		})
	}
}

// The cap of 24 per peer holds on a card that mixes a 1 h and a 24 h relay
// while the 24 h relay refuses every withdrawal (403, given up, unconfirmed).
// Each generation withdraws the previous one, but the 24 h relay keeps all of
// them; the carrier keeps counting every unconfirmed generation until it
// expires, so the relay never holds more than 24 envelopes for the peer. The
// 1 h relay either fails its withdrawals transiently (retried) or confirms
// them, in which case only the unconfirmed relay keeps the count.
func TestThePeerCapHoldsOnAMixedCardWhenWithdrawalsFail(t *testing.T) {
	for _, test := range []struct {
		name      string
		transient bool
	}{
		{"the 1 h relay fails transiently", true},
		{"the 1 h relay confirms", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			clock := newRelayClock()
			short, long := twoRelays(t, clock)
			short.setTTL(3600)
			if test.transient {
				short.ackFails = 1 << 30
			}
			long.ackForbidden = true
			a, b := chatPair(t, clock, short.URL, long.URL)
			event := chatEventID("offline peer")
			refusedAt := uint32(0)
			for generation := uint32(1); generation <= ChatPeerEnvelopeCap+2; generation++ {
				response := a.daemon.carry(b.agent, event, generation)
				if response.Result == carrierapi.ResultRefused {
					requireResult(t, response, carrierapi.ResultRefused, carrierapi.CodePeerCap)
					refusedAt = generation
					break
				}
				requireResult(t, response, carrierapi.ResultCarried, "")
				if response.RelayTTLSeconds != 3600 {
					t.Fatalf("generation %d reported TTL %d", generation, response.RelayTTLSeconds)
				}
				// Background passes: redundant deposits and the withdrawals.
				for range 3 {
					a.redeposit()
					clock.Advance(relayRedepositMax + time.Second)
				}
				if held := long.count(b.agent); held > ChatPeerEnvelopeCap {
					t.Fatalf("the 24 h relay holds %d envelopes for the peer after generation %d", held, generation)
				}
				// The daemon's next generation is due at 80 % of the 1 h TTL.
				clock.Advance(48*time.Minute - 3*(relayRedepositMax+time.Second))
			}
			if refusedAt != ChatPeerEnvelopeCap+1 {
				t.Fatalf("the cap refused generation %d, want %d", refusedAt, ChatPeerEnvelopeCap+1)
			}
			if held := long.count(b.agent); held != ChatPeerEnvelopeCap {
				t.Fatalf("the 24 h relay holds %d envelopes, want exactly the cap", held)
			}
			if !test.transient && short.count(b.agent) > 1 {
				t.Fatalf("the confirming 1 h relay holds %d envelopes", short.count(b.agent))
			}
			// The 24 h relay deleted nothing, and each superseded generation is
			// asked there at most once: a given-up withdrawal is never asked
			// again. (With the 1 h relay failing, its backoff may still delay
			// the first request of the latest generations.)
			requests, deletions := long.ackCounts()
			if deletions != 0 || requests == 0 || requests > ChatPeerEnvelopeCap-1 ||
				!test.transient && requests != ChatPeerEnvelopeCap-1 {
				t.Fatalf("the 24 h relay was asked %d times and deleted %d", requests, deletions)
			}
			for range 3 {
				clock.Advance(relayRedepositMax + time.Second)
				a.redeposit()
			}
			if again, _ := long.ackCounts(); again > ChatPeerEnvelopeCap-1 || !test.transient && again != requests {
				t.Fatalf("a given-up withdrawal was asked again: %d requests", again)
			}
			// Once the oldest generation expired at the 24 h relay, a slot
			// frees.
			clock.Advance(24 * time.Hour)
			requireResult(t, a.daemon.carry(b.agent, event, refusedAt), carrierapi.ResultCarried, "")
		})
	}
}

// Evidence frames live one relay TTL of the card, delivery acks an hour.
func TestEvidenceFramesAndDeliveryAcksHaveShortLifetimes(t *testing.T) {
	clock := newRelayClock()
	relayA, relayB := twoRelays(t, clock)
	relayA.setTTL(3600)
	a, b := chatPair(t, clock, relayA.URL, relayB.URL)
	b.importContact(a)
	now := clock.Now()
	request := a.daemon.frame(relayframe.KindEvidence, []byte{relayframe.EvidenceRequest})
	response, err := a.daemon.carrier.Carry(context.Background(), b.agent, chatCopyKey(t, chatEventID("pull"), 1),
		"", uint64(now.Add(24*time.Hour).Unix()), request)
	if err != nil {
		t.Fatal(err)
	}
	requireResult(t, response, carrierapi.ResultCarried, "")
	views, err := ReadRelayOutbox(filepath.Join(a.dir, relayStateDir, relayChatOutboxDir))
	if err != nil || len(views) != 1 || views[0].ExpiresAtUnix != uint64(now.Add(time.Hour).Unix()) {
		t.Fatalf("evidence request journal: %+v %v", views, err)
	}
	// A copy keeps its own expiry; its ack lives an hour.
	requireResult(t, a.daemon.carry(b.agent, chatEventID("copy"), 1), carrierapi.ResultCarried, "")
	b.pollAll()
	acks, err := ReadRelayOutbox(filepath.Join(b.dir, relayStateDir, relayChatOutboxDir))
	if err != nil || len(acks) != 1 || acks[0].ExpiresAtUnix != uint64(now.Add(AckPacketLifetime).Unix()) {
		t.Fatalf("delivery ack journal: %+v %v", acks, err)
	}
}

// An unreadable chat record counts towards every peer's cap only while
// something it describes may still be stored; after that it is moved to the
// quarantine directory, kept, reported and no longer counted.
func TestAnOldUnreadableChatRecordIsQuarantinedAndFreesItsSlot(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	a, b := chatPair(t, clock, relay.URL)
	outbox := filepath.Join(a.dir, relayStateDir, relayChatOutboxDir)
	name := strings.Repeat("0", 64) + ".json"
	corrupt := filepath.Join(outbox, name)
	if err := os.WriteFile(corrupt, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	young := clock.Now().Add(-relayQuarantineAge + time.Minute)
	if err := os.Chtimes(corrupt, young, young); err != nil {
		t.Fatal(err)
	}
	if stored, err := a.chat.Transport.storedFor(b.agent); err != nil || len(stored) != 1 {
		t.Fatalf("a young unreadable record is not counted: %d %v", len(stored), err)
	}
	old := clock.Now().Add(-relayQuarantineAge - time.Second)
	if err := os.Chtimes(corrupt, old, old); err != nil {
		t.Fatal(err)
	}
	for index := range ChatPeerEnvelopeCap {
		requireResult(t, a.daemon.carry(b.agent, chatEventID(fmt.Sprint("m", index)), 1), carrierapi.ResultCarried, "")
	}
	if _, err := os.Stat(corrupt); !os.IsNotExist(err) {
		t.Fatal("the old unreadable record is still in the journal")
	}
	if raw, err := os.ReadFile(filepath.Join(outbox, relayQuarantineDir, name)); err != nil || string(raw) != "{" {
		t.Fatalf("the quarantined record was not kept: %v", err)
	}
	if !strings.Contains(a.reportText(), "moved to "+relayQuarantineDir) {
		t.Fatalf("the quarantine was not reported: %s", a.reportText())
	}
	// The quarantine directory is not a journal record.
	views, err := ReadRelayOutbox(outbox)
	if err != nil || len(views) != ChatPeerEnvelopeCap {
		t.Fatalf("status after quarantine: %d %v", len(views), err)
	}
	for _, view := range views {
		if view.Unreadable != "" {
			t.Fatal("the quarantined record is still listed")
		}
	}
}

// A journal record too large to be read back is a permanent refusal of the
// frame, never a retry the daemon would repeat forever.
func TestATooLargeJournalRecordIsRefusedAsPacketTooLarge(t *testing.T) {
	for _, test := range []struct {
		err  error
		want carrierapi.Response
	}{
		{fmt.Errorf("store: %w", ErrRelayRecordTooLarge), carrierapi.Refusal(carrierapi.CodePacketTooLarge)},
		{ErrRelayPacketTooLarge, carrierapi.Refusal(carrierapi.CodePacketTooLarge)},
		{ErrNoPacketRoute, carrierapi.Refusal(carrierapi.CodeNoPeerCard)},
		{ErrRelayWithdrawn, carrierapi.Refusal(carrierapi.CodeInvalidRequest)},
		{ErrRelayUndelivered, carrierapi.Retry()},
	} {
		if got := chatSendFailure(test.err); got.Result != test.want.Result || got.Code != test.want.Code {
			t.Errorf("%v: %s %s, want %s %s", test.err, got.Result, got.Code, test.want.Result, test.want.Code)
		}
	}
}

// railDueForRefresh delivers one rail packet with a 6 h deadline through a
// 1 h relay and stops the clock one second before its replacement is due.
func railDueForRefresh(t *testing.T) (*relayClock, *fakeRelay, *relayTestNode, *relayTestNode, [32]byte) {
	t.Helper()
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	relay.setTTL(3600)
	seller, buyer := railPair(t, clock, relay)
	envelope := relayEnvelopeTo(testBuyer)
	envelope.NotAfterUnix = uint64(clock.Now().Add(6 * time.Hour).Unix())
	if _, err := seller.courier.Deliver(context.Background(), envelope, markedBody(40)); err != nil {
		t.Fatal(err)
	}
	seller.redeposit()
	_, id := currentEnvelope(t, seller)
	if !relay.holds(testBuyer, id) {
		t.Fatal("the relay does not hold the first envelope")
	}
	clock.Advance(48*time.Minute - time.Second)
	return clock, relay, seller, buyer, id
}

// A listing that fails is taken as still listing the envelope: the record is
// not settled, and the replacement is deposited. Here the buyer did take the
// envelope, so only the failed listing keeps the replacement going.
func TestAFailedListingCountsAsStillListed(t *testing.T) {
	for _, test := range []struct {
		name        string
		failListing func(*fakeRelay, *relayTestNode)
	}{
		{"500", func(relay *fakeRelay, _ *relayTestNode) {
			relay.mutex.Lock()
			relay.listStatus = 500
			relay.mutex.Unlock()
		}},
		{"timeout", func(relay *fakeRelay, seller *relayTestNode) {
			seller.carrier.Transport.timeout = 200 * time.Millisecond
			relay.mutex.Lock()
			relay.listDelay = time.Second
			relay.mutex.Unlock()
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			clock, relay, seller, buyer, firstID := railDueForRefresh(t)
			buyer.pollAll()
			if relay.holds(testBuyer, firstID) {
				t.Fatal("the buyer did not acknowledge the envelope")
			}
			test.failListing(relay, seller)
			clock.Advance(time.Second)
			seller.redeposit()
			record, id := currentEnvelope(t, seller)
			if record.Settled || id == firstID || !relay.holds(testBuyer, id) {
				t.Fatalf("a failed listing settled the envelope: settled=%v replaced=%v", record.Settled, id != firstID)
			}
		})
	}
}

// The replaced envelope stays, and its withdrawal is not even asked, while no
// relay holds the replacement: the packet is never absent from every relay.
func TestTheReplacedEnvelopeStaysUntilTheReplacementIsHeld(t *testing.T) {
	clock, relay, seller, _, firstID := railDueForRefresh(t)
	relay.mutex.Lock()
	relay.failDeposits = 1 << 30
	relay.mutex.Unlock()
	clock.Advance(time.Second)
	for range 3 {
		seller.redeposit()
		clock.Advance(relayRedepositMax / 2)
	}
	record, id := currentEnvelope(t, seller)
	if id == firstID || len(record.Accepted) != 0 {
		t.Fatalf("no replacement is journaled, or it is held: accepted=%v", record.Accepted)
	}
	if len(record.Withdrawals) != 1 || !record.Withdrawals[0].AfterAccepted {
		t.Fatalf("the replaced envelope's withdrawal is not held back: %+v", record.Withdrawals)
	}
	if requests, _ := relay.ackCounts(); requests != 0 || !relay.holds(testBuyer, firstID) {
		t.Fatalf("the replaced envelope was withdrawn before the replacement was held: %d requests", requests)
	}
	// Once the relay takes the replacement, the old envelope is withdrawn.
	relay.mutex.Lock()
	relay.failDeposits = 0
	relay.mutex.Unlock()
	clock.Advance(relayRedepositMax + time.Second)
	seller.redeposit()
	seller.redeposit()
	if relay.holds(testBuyer, firstID) || !relay.holds(testBuyer, id) {
		t.Fatal("the replaced envelope was not withdrawn after the replacement was held")
	}
}

// A seal failure during a refresh other than "no card now" is returned to
// the background pass, which reports it; "no card now" waits silently for a
// later pass. Either way nothing in the journal changes.
func TestASealFailureDuringARefreshIsReported(t *testing.T) {
	for _, test := range []struct {
		name     string
		err      error
		reported bool
	}{
		{"finalized state cannot answer", fmt.Errorf("%w: resolver down", errCardUnavailable), true},
		{"no card held", ErrNoPacketRoute, false},
		{"card refused", fmt.Errorf("%w: revoked", ErrCardRefused), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			clock, relay, seller, _, firstID := railDueForRefresh(t)
			deposits := len(relay.depositLog())
			seller.carrier.Transport.beforeSeal = func() error { return test.err }
			clock.Advance(time.Second)
			err := seller.carrier.Transport.Redeposit(context.Background())
			if test.reported && !errors.Is(err, test.err) || !test.reported && err != nil {
				t.Fatalf("Redeposit returned %v", err)
			}
			if _, id := currentEnvelope(t, seller); id != firstID || len(relay.depositLog()) != deposits {
				t.Fatal("a failed seal changed the journal or deposited")
			}
		})
	}
}
