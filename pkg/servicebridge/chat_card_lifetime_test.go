package servicebridge

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
)

// withChatTestCardLifetime opens the test's chat nodes with the chat test
// card lifetime d.
func withChatTestCardLifetime(t *testing.T, d time.Duration) {
	t.Helper()
	chatTestCardLifetime = d
	t.Cleanup(func() { chatTestCardLifetime = 0 })
}

func heldCardOf(t *testing.T, node *chatTestNode, peer string) *peerCard {
	t.Helper()
	card, err := node.chat.Cards.Current(context.Background(), peer)
	if err != nil {
		t.Fatalf("%s holds no usable card of %s: %v", node.agent, peer, err)
	}
	return card
}

// Under the test card lifetime a chat card lasts exactly that long and is
// replaced, at the next maintenance pass, once less than half of it is
// left; the replaced key is kept, so frames sealed to the older card still
// open; a held card with a longer window is never handed out.
func TestTheChatTestCardLifetimeRenewsTheCardAtHalfItsLife(t *testing.T) {
	const lifetime = 30 * time.Minute
	withChatTestCardLifetime(t, lifetime)
	clock := newRelayClock()
	relay := startRealRelay(t, clock)
	a, _ := chatPair(t, clock, relay)
	first, err := a.chat.Republish(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if first.NotAfterUnix-first.NotBeforeUnix != uint64(lifetime/time.Second) {
		t.Fatalf("the card lasts %d s, want %d", first.NotAfterUnix-first.NotBeforeUnix, uint64(lifetime/time.Second))
	}
	if !bytes.Equal(a.daemon.card(), first.CardJSON) {
		t.Fatal("the daemon's card path does not hold the current card")
	}
	clock.Advance(lifetime/2 - time.Minute)
	if err = a.chat.Maintain(context.Background()); err != nil {
		t.Fatal(err)
	}
	same, err := a.chat.Republish(context.Background())
	if err != nil || same.KeyID != first.KeyID {
		t.Fatalf("the card was replaced with more than half of its life left: %v", err)
	}
	clock.Advance(2 * time.Minute)
	if err = a.chat.Maintain(context.Background()); err != nil {
		t.Fatal(err)
	}
	second, err := a.chat.Republish(context.Background())
	if err != nil || second.KeyID == first.KeyID {
		t.Fatalf("the card was not replaced once less than half of it was left: %v", err)
	}
	if second.NotAfterUnix-second.NotBeforeUnix != uint64(lifetime/time.Second) ||
		!bytes.Equal(a.daemon.card(), second.CardJSON) {
		t.Fatal("the successor is not a card of the test lifetime published at the card path")
	}
	if _, held := a.chat.Keys.private(first.KeyID); !held {
		t.Fatal("the replaced key was dropped before its card expired")
	}
	// A key issued under the production rotation (a 30-day card) is not
	// handed out under the test lifetime.
	a.chat.Keys.SetCardLifetime(0)
	long, err := a.chat.Keys.Current(context.Background(), offerCardCover(uint64(clock.Now().Unix())))
	if err != nil || long.NotAfterUnix-long.NotBeforeUnix <= uint64(lifetime/time.Second) {
		t.Fatalf("no production card to test with: %v", err)
	}
	a.chat.Keys.SetCardLifetime(lifetime)
	current, err := a.chat.Republish(context.Background())
	if err != nil || current.KeyID == long.KeyID || current.KeyID != second.KeyID {
		t.Fatalf("a card longer than the test lifetime was handed out: %v", err)
	}
}

// A peer learns the renewed card in band: the next frame after the renewal
// carries it, the peer seals to it, and once the older card expires the
// conversation goes on. A peer that never received a frame after the
// renewal holds only the expired card: its copy is refused no-peer-card
// (it waits for a fresh card) until a frame of the renewed card reaches it.
func TestAPeerLearnsTheRenewedChatCardInBandAndAStaleCardHoldsTheCopyBack(t *testing.T) {
	const lifetime = 30 * time.Minute
	withChatTestCardLifetime(t, lifetime)
	clock := newRelayClock()
	relay := startRealRelay(t, clock)
	a, b := chatPair(t, clock, relay)
	stale := newChatTestNode(t, clock, relayThird, relayAgents(), relay)
	stale.importContact(a)
	stale.admit(a)
	a.admit(stale)
	first, err := a.chat.Republish(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// A's first copy carries its first card; B learns it in band.
	requireResult(t, a.daemon.carry(b.agent, chatEventID("one"), 1), carrierapi.ResultCarried, "")
	b.pollAll()
	if got := heldCardOf(t, b, a.agent); got.Key.KeyID != first.KeyID {
		t.Fatal("B did not learn A's first card in band")
	}
	a.pollAll()
	// Past half of the card's life A renews it; its next copy carries the
	// successor, which B learns and seals to.
	clock.Advance(lifetime/2 + time.Minute)
	if err = a.chat.Maintain(context.Background()); err != nil {
		t.Fatal(err)
	}
	second, err := a.chat.Republish(context.Background())
	if err != nil || second.KeyID == first.KeyID {
		t.Fatalf("A did not renew its card: %v", err)
	}
	requireResult(t, a.daemon.carry(b.agent, chatEventID("two"), 1), carrierapi.ResultCarried, "")
	b.pollAll()
	if got := heldCardOf(t, b, a.agent); got.Key.KeyID != second.KeyID {
		t.Fatalf("B did not learn A's renewed card in band: %s", b.reportText())
	}
	a.pollAll()
	// Past the first card's expiry B still reaches A, sealed to the renewed
	// card, which A opens.
	clock.Advance(lifetime / 2)
	if err = a.chat.Maintain(context.Background()); err != nil {
		t.Fatal(err)
	}
	reply := chatEventID("reply")
	requireResult(t, b.daemon.carry(a.agent, reply, 1), carrierapi.ResultCarried, "")
	a.pollAll()
	if a.daemon.acceptedCount(reply) != 1 {
		t.Fatalf("A did not open B's copy sealed to its renewed card: %s", a.reportText())
	}
	// The stale peer holds only A's first card, now expired: its copy waits
	// for a fresh card.
	requireResult(t, stale.daemon.carry(a.agent, chatEventID("stale"), 1), carrierapi.ResultRefused,
		carrierapi.CodeNoPeerCard)
	// A frame of A's current card reaches it (A holds the stale peer's own
	// current card from its contact file), and its copy goes out.
	if err = stale.chat.Maintain(context.Background()); err != nil {
		t.Fatal(err)
	}
	a.importContact(stale)
	requireResult(t, a.daemon.carry(stale.agent, chatEventID("fresh"), 1), carrierapi.ResultCarried, "")
	stale.pollAll()
	if got := heldCardOf(t, stale, a.agent); got.Key.KeyID == first.KeyID {
		t.Fatal("the stale peer did not learn A's current card in band")
	}
	requireResult(t, stale.daemon.carry(a.agent, chatEventID("after-fresh"), 1), carrierapi.ResultCarried, "")
}
