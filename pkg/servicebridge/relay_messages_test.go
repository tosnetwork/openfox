package servicebridge

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
)

func TestTheOfferFileCarriesTheProvidersKeyCardAndRefusesAForeignOne(t *testing.T) {
	_, offer, _ := publishedOffer(t)
	clock := newRelayClock()
	agents := relayAgents()
	relay := startFakeRelay(t, clock)
	provider := newRelayTestNode(t, clock, offer.ProviderAgentID, agents, relay)
	stranger := newRelayTestNode(t, clock, relayThird, agents, relay)
	offer.KeyCard = provider.card()
	raw, err := EncodeOfferFile(offer, time.Unix(1_900_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err = json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	if fields["schema"] != "tos.openfox.rail-offer.v2" ||
		fields["relay_key_card_base64"] != base64.StdEncoding.EncodeToString(offer.KeyCard) {
		t.Fatalf("offer file fields: %v", fields["schema"])
	}
	decoded, err := DecodeOfferFile(raw)
	if err != nil || !bytes.Equal(decoded.KeyCard, offer.KeyCard) {
		t.Fatalf("the card did not survive the file: %v", err)
	}
	edit := func(change func(map[string]any)) []byte {
		t.Helper()
		var copied map[string]any
		if decodeErr := json.Unmarshal(raw, &copied); decodeErr != nil {
			t.Fatal(decodeErr)
		}
		change(copied)
		out, encodeErr := json.Marshal(copied)
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		return out
	}
	for name, tampered := range map[string][]byte{
		"version 1 schema": edit(func(m map[string]any) { m["schema"] = "tos.openfox.rail-offer.v1" }),
		"another Agent's card": edit(func(m map[string]any) {
			m["relay_key_card_base64"] = base64.StdEncoding.EncodeToString(stranger.card())
		}),
		"card not base64": edit(func(m map[string]any) { m["relay_key_card_base64"] = "*" }),
		"card not a card": edit(func(m map[string]any) {
			m["relay_key_card_base64"] = base64.StdEncoding.EncodeToString([]byte(`{"schema":"x"}`))
		}),
	} {
		if _, decodeErr := DecodeOfferFile(tampered); decodeErr == nil {
			t.Errorf("%s: decoded", name)
		}
	}
	// Without a card the field is absent, not empty.
	offer.KeyCard = nil
	plain, err := EncodeOfferFile(offer, time.Unix(1_900_000_000, 0))
	if err != nil || bytes.Contains(plain, []byte("relay_key_card")) {
		t.Fatalf("a cardless offer file names a card: %v", err)
	}
}

func TestTheTaskCarriesTheBuyersCardInsideItsSignedHeader(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	buyer := newRelayTestNode(t, clock, testBuyer, relayAgents(), relay)
	card := base64.StdEncoding.EncodeToString(buyer.card())
	task := Task{Header: TaskHeader{
		BuyerAgentID: testBuyer, BuyerWallet: "0:" + strings.Repeat("ab", 32), CapabilityID: relayCapability,
		CapabilityVersion: "1.0.0", ExecutionID: strings.Repeat("01", 32), ExecutionNonce: strings.Repeat("02", 32),
		RequestID: 4, CallLT: 9, CallHash: strings.Repeat("03", 32), BuyerKeyCard: card,
	}, Package: []byte{1, 2, 3}, Archive: []byte("archive")}
	encoded, err := EncodeTask(task)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeTask(encoded)
	if err != nil || decoded.Header.BuyerKeyCard != card {
		t.Fatalf("the card did not survive the task: %v", err)
	}
	task.Header.BuyerKeyCard = strings.Repeat("A", base64.StdEncoding.EncodedLen(maxCardJSON)+4)
	if _, err = EncodeTask(task); err == nil {
		t.Fatal("an oversized buyer card was encoded")
	}
	task.Header.BuyerKeyCard = ""
	plain, err := EncodeTask(task)
	if err != nil || bytes.Contains(plain, []byte("buyer_key_card")) {
		t.Fatalf("a cardless task names a card: %v", err)
	}
}

func TestTheProviderTakesOnlyTheTaskSendersOwnCard(t *testing.T) {
	clock := newRelayClock()
	agents := relayAgents()
	relay := startFakeRelay(t, clock)
	seller := newRelayTestNode(t, clock, testSeller, agents, relay)
	buyer := newRelayTestNode(t, clock, testBuyer, agents, relay)
	third := newRelayTestNode(t, clock, relayThird, agents, relay)
	provider := &Provider{config: ProviderConfig{Cards: seller.cards}}
	message := Message{SenderAgentID: testBuyer}
	withCard := func(raw []byte) Task {
		return Task{Header: TaskHeader{BuyerAgentID: testBuyer, BuyerKeyCard: base64.StdEncoding.EncodeToString(raw)}}
	}
	if err := provider.learnBuyerCard(context.Background(), message, withCard(third.card())); err == nil ||
		seller.cards.Has(relayThird) || seller.cards.Has(testBuyer) {
		t.Fatalf("a card of another Agent than the task's sender was taken: %v", err)
	}
	if err := provider.learnBuyerCard(context.Background(), message, withCard(buyer.card())); err != nil ||
		!seller.cards.Has(testBuyer) {
		t.Fatalf("the sender's card was refused: %v", err)
	}
	// Without a relay carrier the card is ignored.
	plain := &Provider{config: ProviderConfig{}}
	if err := plain.learnBuyerCard(context.Background(), message, withCard(third.card())); err != nil {
		t.Fatal(err)
	}
}

func TestTheBuyersCardCoversTheRequestDeadlinesWithinTheCardBound(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	node := newRelayTestNode(t, clock, testBuyer, relayAgents(), relay)
	buyer := &Buyer{config: BuyerConfig{RelayKeys: node.carrier.Keys}}
	now := uint64(clock.Now().Unix())
	encoded, err := buyer.ownKeyCard(context.Background(), PurchaseRecord{
		ResponseDeadline: now + 2*86400, RefundDeadline: now + 10*86400,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(encoded)
	card, err := decodeOwnCard(testBuyer, raw)
	if err != nil || card.NotAfterUnix < now+11*86400 {
		t.Fatalf("the card ends at %d, before the refund deadline plus margin: %v", card.NotAfterUnix, err)
	}
	encoded, err = buyer.ownKeyCard(context.Background(), PurchaseRecord{ResponseDeadline: now + 90*86400})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = base64.StdEncoding.DecodeString(encoded)
	card, err = decodeOwnCard(testBuyer, raw)
	if err != nil || card.NotAfterUnix-card.NotBeforeUnix > uint64(agentpacketseal.MaxKeyCardLifetime/time.Second) {
		t.Fatalf("the card exceeds the 30-day bound: %v", err)
	}
	if encoded, err := (&Buyer{}).ownKeyCard(context.Background(), PurchaseRecord{}); err != nil || encoded != "" {
		t.Fatal("a buyer without relays sent a card")
	}
}

func TestRelayURLsMustBeCanonicalAndPlaintextOnlyOnLoopback(t *testing.T) {
	for _, bad := range []string{
		"http://relay.example", "https://relay.example/", "https://Relay.example", "https://relay.example?x",
		"https://user@relay.example", "ftp://relay.example", "https://relay.example#f", "",
		"https://relay.example/a%20b", "https://127.1", "https://0x7f.0.0.1",
	} {
		if _, err := canonicalRelayURLs([]string{bad}); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	if _, err := canonicalRelayURLs([]string{"https://a.example", "https://a.example"}); err == nil {
		t.Error("a duplicate relay was accepted")
	}
	if _, err := canonicalRelayURLs([]string{
		"https://a", "https://b", "https://c", "https://d",
		"https://e",
	}); err == nil {
		t.Error("five relays were accepted")
	}
	sorted, err := canonicalRelayURLs([]string{"https://b.example", "http://127.0.0.1:8080", "https://a.example/r"})
	if err != nil || sorted[0] != "http://127.0.0.1:8080" || sorted[1] != "https://a.example/r" {
		t.Fatalf("sorted = %v %v", sorted, err)
	}
	if _, err := dialRelay("http://relay.example"); err == nil {
		t.Error("a plaintext relay outside loopback was dialed")
	}
}

func TestTheRoutedTransportPrefersDirectThenRelayThenMessenger(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	seller := newRelayTestNode(t, clock, testSeller, relayAgents(), relay)
	buyer := newRelayTestNode(t, clock, testBuyer, relayAgents(), relay)
	seller.learn(buyer)
	routed := RoutedTransport{Relay: seller.carrier.Transport, Direct: DirectTransport{
		Peers: map[string]string{relayThird: "/run/peer.sock"},
	}}
	if routed.Route(relayThird) != RouteDirect || routed.Route(testBuyer) != RouteRelay ||
		routed.Route(relayStranger) != RouteNone {
		t.Fatalf("routes: %s %s %s", routed.Route(relayThird), routed.Route(testBuyer), routed.Route(relayStranger))
	}
	routed.Fallback = &recordingTransport{}
	if routed.Route(relayStranger) != RouteMessenger || routed.Route(testBuyer) != RouteRelay {
		t.Fatal("a recipient with a card left the relay")
	}
	if _, err := openPacketTransport(NodeConfig{AgentID: testSeller}, seller.carrier.Transport); err != nil {
		t.Fatalf("a relay-only node has no transport: %v", err)
	}
	if err := seller.carrier.Transport.Send(context.Background(), OutboundPacket{
		RecipientAgentID: testBuyer, JSON: bytes.Repeat([]byte{'{'}, maxPacketJSON+1),
		IdempotencyKey: "idem_" + strings.Repeat("0a", 32), ExpiresAtUnix: uint64(clock.Now().Unix()) + 60,
	}); !errors.Is(err, ErrRelayPacketTooLarge) {
		t.Fatalf("an oversized packet: %v", err)
	}
}
