package servicebridge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
)

func TestFarAndMixedDeadlinesKeepTheKeyCountBoundedForSixtyDays(t *testing.T) {
	clock := newRelayClock()
	agents := relayAgents()
	relay := startFakeRelay(t, clock)
	buyer := newRelayTestNode(t, clock, testBuyer, agents, relay)
	seller := newRelayTestNode(t, clock, testSeller, agents, relay)
	start := clock.Now()
	fixed := uint64(start.Add(20 * 24 * time.Hour).Unix())
	most := 0
	for step := 0; clock.Now().Sub(start) < 60*24*time.Hour; step++ {
		now := uint64(clock.Now().Unix())
		for _, cover := range []uint64{
			now + 40*86400, // past the 30-day bound: the target moves with the clock
			now + 29*86400, // just inside it, also moving
			now + 5*86400,  // short
			fixed,          // one fixed deadline
			now + uint64(step%30)*86400,
		} {
			if _, err := buyer.carrier.Keys.Current(context.Background(), cover); err != nil {
				t.Fatalf("day %.1f: %v", clock.Now().Sub(start).Hours()/24, err)
			}
		}
		if step%6 == 0 {
			if _, err := buyer.carrier.Keys.Maintain(context.Background()); err != nil {
				t.Fatalf("maintenance: %v", err)
			}
		}
		if held := len(buyer.carrier.Keys.Held()); held > most {
			most = held
		}
		clock.Advance(10 * time.Minute)
	}
	if most > 3 {
		t.Fatalf("%d keys were held at once", most)
	}
	// Sends keep working at the end.
	seller.learn(buyer)
	if _, err := seller.courier.Deliver(context.Background(), relayEnvelopeTo(testBuyer), markedBody(10)); err != nil {
		t.Fatal(err)
	}
	buyer.pollAll()
	if len(buyer.pending()) != 1 {
		t.Fatal("the packet was not delivered")
	}
}

func TestEveryMaintenancePassHandsTheCurrentCardToTheOfferHook(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	node := newRelayTestNode(t, clock, testSeller, relayAgents(), relay)
	var seen [][]byte
	fail := true
	node.carrier.SetRotationHook(func(_ context.Context, key OwnRelayKey) error {
		seen = append(seen, key.CardJSON)
		if fail {
			return errors.New("the offer file could not be written")
		}
		return nil
	})
	if err := node.carrier.Maintain(context.Background()); err == nil {
		t.Fatal("the failing hook was not reported")
	}
	// The next pass issues nothing new but publishes again.
	fail = false
	if err := node.carrier.Maintain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 || !bytes.Equal(seen[0], seen[1]) {
		t.Fatalf("the failed publish was not retried: %d calls", len(seen))
	}
}

func TestTheOfferFileIsRewrittenOnlyWhenItsCardChanges(t *testing.T) {
	_, offer, _ := publishedOffer(t)
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	provider := newRelayTestNode(t, clock, offer.ProviderAgentID, relayAgents(), relay)
	dir := t.TempDir()
	manifest := filepath.Join(dir, "manifest.cbor")
	if err := os.WriteFile(manifest, offer.ManifestCBOR, 0o600); err != nil {
		t.Fatal(err)
	}
	node := &Node{Config: NodeConfig{AgentID: offer.ProviderAgentID, Provider: &ProviderNode{
		CapabilityID: offer.CapabilityID, Version: offer.Version, ManifestFile: manifest,
		OfferFile: filepath.Join(dir, "offer.json"),
	}}}
	key, err := provider.carrier.Keys.Current(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = node.republishOffer(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(node.Config.Provider.OfferFile)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	if err = node.republishOffer(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	again, err := os.ReadFile(node.Config.Provider.OfferFile)
	if err != nil || !bytes.Equal(first, again) {
		t.Fatal("an unchanged offer was rewritten")
	}
	written, err := ReadOfferFile(node.Config.Provider.OfferFile)
	if err != nil || !bytes.Equal(written.KeyCard, key.CardJSON) {
		t.Fatalf("the offer file does not carry the current card: %v", err)
	}
}

func TestMaintenanceDestroysKeysAnotherProcessWroteOnTime(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	dir := t.TempDir()
	serving := openRelayTestNode(t, dir, clock, testBuyer, relayAgents(), relay)
	if _, err := serving.carrier.Keys.Current(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	// `offer` in its own process issues a key with another relay set.
	signer := testSigner(t, testBuyer)
	signer.now = clock.Now
	keysDir := filepath.Join(dir, relayStateDir, relayKeysDir)
	other, err := OpenRelayKeys(keysDir, testBuyer, []string{"https://relay.example"}, signer, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	written, err := other.Current(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(keysDir, hex.EncodeToString(written.KeyID[:])+".json")
	clock.Advance(RelayKeyLifetime + RelayKeyRetention + time.Minute)
	if _, err = serving.carrier.Keys.Maintain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a key written by another process outlived its retention")
	}
}

func TestASecondSealerAdoptsTheEnvelopeAlreadyJournaled(t *testing.T) {
	clock := newRelayClock()
	agents := relayAgents()
	relay := startFakeRelay(t, clock)
	dir := t.TempDir()
	first := openRelayTestNode(t, dir, clock, testSeller, agents, relay)
	buyer := newRelayTestNode(t, clock, testBuyer, agents, relay)
	first.learn(buyer)
	// A second process over the same state.
	second := openRelayTestNode(t, dir, clock, testSeller, agents, relay)
	packetJSON := framePacket(t, testSeller, testBuyer)
	digest := sha256.Sum256(packetJSON)
	packet := OutboundPacket{
		RecipientAgentID: testBuyer, JSON: packetJSON, IdempotencyKey: "idem_" + hex.EncodeToString(digest[:]),
		ExpiresAtUnix: uint64(clock.Now().Add(time.Hour).Unix()),
	}
	second.carrier.Transport.beforeJournal = func() {
		if err := first.carrier.Transport.Send(context.Background(), packet); err != nil {
			t.Errorf("the first sender: %v", err)
		}
	}
	if err := second.carrier.Transport.Send(context.Background(), packet); err != nil {
		t.Fatal(err)
	}
	log := relay.depositLog()
	if len(log) != 1 {
		t.Fatalf("%d deposits: the second sender sealed its own envelope", len(log))
	}
	views, err := ReadRelayOutbox(filepath.Join(dir, relayStateDir, relayOutboxDir))
	header, parseErr := agentpacketseal.ParseEnvelope(log[0].raw)
	if err != nil || parseErr != nil || len(views) != 1 ||
		views[0].EnvelopeID != hex.EncodeToString(header.EnvelopeID[:]) {
		t.Fatal("the journal does not hold the deposited envelope")
	}
}

func TestAnInboxRefusalOfAnOpenedPacketIsAcknowledged(t *testing.T) {
	clock := newRelayClock()
	agents := relayAgents()
	relay := startFakeRelay(t, clock)
	buyer := newRelayTestNode(t, clock, testBuyer, agents, relay)
	buyer.card()
	// The inbox holds at most 4 open messages per sender: a fifth partial
	// message is refused for its bounds, which no later poll changes.
	for request := range 5 {
		frames, err := SplitMessage(
			FrameResult,
			testActor,
			uint64(10+request),
			testRequest,
			markedBody(MaxChunkData+10),
		)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := EncodeFrame(frames[0])
		if err != nil {
			t.Fatal(err)
		}
		signed, err := testSigner(t, testSeller).sign(context.Background(), testBuyer, testEnvelope().CapabilityID, "",
			payload)
		if err != nil {
			t.Fatal(err)
		}
		packetJSON, err := agentpacket.EncodeJSON(signed)
		if err != nil {
			t.Fatal(err)
		}
		sealTo(t, relay, buyer, packetJSON)
		clock.Advance(time.Second)
	}
	buyer.pollAll()
	if relay.count(testBuyer) != 0 {
		t.Fatalf("%d envelopes left: an inbox refusal was taken as transient", relay.count(testBuyer))
	}
}

func TestPeerCardsNamingLoopbackRelaysAreRefusedUnlessThisNodeIsOnLoopback(t *testing.T) {
	clock := newRelayClock()
	agents := relayAgents()
	relay := startFakeRelay(t, clock)
	peer := newRelayTestNode(t, clock, testBuyer, agents, relay) // its card names a loopback relay
	cards, err := OpenPeerCards(filepath.Join(t.TempDir(), "peers"), packetKeys, agents, ownersMap{}, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err = cards.Learn(context.Background(), peer.card(), testBuyer, ""); !errors.Is(err, ErrCardRefused) {
		t.Fatalf("a loopback relay card was taken by a node on public relays: %v", err)
	}
	// A card naming a public relay is taken.
	signer := testSigner(t, relayThird)
	signer.now = clock.Now
	public, err := OpenRelayKeys(filepath.Join(t.TempDir(), "keys"), relayThird, []string{"https://relay.example"},
		signer, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	key, err := public.Current(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = cards.Learn(context.Background(), key.CardJSON, relayThird, ""); err != nil {
		t.Fatalf("a public relay card was refused: %v", err)
	}
	// A node whose own relays are on loopback takes loopback peers.
	cards.AllowLoopbackRelays(ownRelaysOnLoopback([]string{relay.URL}))
	if err = cards.Learn(context.Background(), peer.card(), testBuyer, ""); err != nil {
		t.Fatalf("a loopback peer was refused by a loopback node: %v", err)
	}
	for relay, want := range map[string]bool{
		"http://127.0.0.1:8080": true, "http://localhost": true, "http://[::1]:9": true, "https://127.0.0.2": true,
		"https://relay.example": false, "https://10.0.0.1": false,
	} {
		if loopbackRelay(relay) != want {
			t.Errorf("%s: loopback %v", relay, !want)
		}
	}
}
