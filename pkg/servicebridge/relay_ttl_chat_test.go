package servicebridge

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
)

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
	views, err := ReadChatOutbox(filepath.Join(a.dir, relayStateDir, relayChatOutboxDir))
	if err != nil || len(views) != 1 || views[0].ExpiresAtUnix != uint64(now.Add(time.Hour).Unix()) {
		t.Fatalf("evidence request journal: %+v %v", views, err)
	}
	// A copy keeps its own expiry; its ack lives an hour.
	requireResult(t, a.daemon.carry(b.agent, chatEventID("copy"), 1), carrierapi.ResultCarried, "")
	b.pollAll()
	acks, err := ReadChatOutbox(filepath.Join(b.dir, relayStateDir, relayChatOutboxDir))
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
	views, err := ReadChatOutbox(outbox)
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
