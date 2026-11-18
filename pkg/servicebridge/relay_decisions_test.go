package servicebridge

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/execution/pkg/railgate"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
)

type fixedArtifact []byte

func (f fixedArtifact) Get(context.Context, string) ([]byte, error) { return f, nil }

func TestTheProvidersResultCarriesItsCurrentCardCoveringTheRedeliveryWindow(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	seller := newRelayTestNode(t, clock, testSeller, relayAgents(), relay)
	sent := &recordingTransport{}
	courier, err := OpenCourier(filepath.Join(t.TempDir(), "outbox"), testSigner(t, testSeller), sent)
	if err != nil {
		t.Fatal(err)
	}
	provider := &Provider{config: ProviderConfig{
		Store: fixedArtifact("artifact"), Courier: courier, RelayKeys: seller.carrier.Keys, Now: clock.Now,
	}}
	retention := uint64(clock.Now().Add(20 * 24 * time.Hour).Unix())
	record := ProviderRecord{
		BuyerAgentID: testBuyer, CapabilityID: relayCapability, Actor: "0:" + hex.EncodeToString(testActor[:]),
		RequestID: 3, RequestHash: hex.EncodeToString(testRequest[:]), ResponseHash: strings.Repeat("42", 32),
		ReceiptBOCBase64: base64.StdEncoding.EncodeToString([]byte{1, 2, 3}), RetentionEndUnix: retention,
	}
	if err = provider.deliver(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	packets := sent.packets()
	if len(packets) != 1 {
		t.Fatalf("%d packets", len(packets))
	}
	packet, err := agentpacket.DecodeJSON(packets[0].JSON)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := DecodeFrame(packet.Payload)
	if err != nil {
		t.Fatal(err)
	}
	result, err := DecodeResult(frame.Data)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(result.Header.ProviderKeyCard)
	if err != nil || len(raw) == 0 {
		t.Fatal("the result carries no provider card")
	}
	card, err := decodeOwnCard(testSeller, raw)
	if err != nil || card.NotAfterUnix < retention {
		t.Fatalf("the card does not cover the redelivery window: %v", err)
	}
	// Without relays the result carries no card.
	plain := &Provider{config: ProviderConfig{Store: fixedArtifact("artifact"), Courier: courier, Now: clock.Now}}
	if err := plain.deliver(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	last := sent.packets()[len(sent.packets())-1]
	if bytes.Contains(last.JSON, []byte("provider_key_card")) {
		t.Fatal("a provider without relays sent a card")
	}
}

// resultBuyer is a buyer with one open purchase from testSeller of
// relayCapability, and a relay carrier's card directory.
func resultBuyer(t *testing.T, clock *relayClock, owners ownersMap) (*Buyer, PurchaseRecord, *PeerCards) {
	t.Helper()
	root := t.TempDir()
	directory := filepath.Join(root, "purchases")
	if err := ensurePrivateDirectory(directory); err != nil {
		t.Fatal(err)
	}
	cards, err := OpenPeerCards(filepath.Join(root, "peers"), packetKeys, relayAgents(), owners, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	cards.AllowLoopbackRelays(true)
	buyer := &Buyer{config: BuyerConfig{Directory: directory, Now: clock.Now, Cards: cards}}
	requestID := uint64(3)
	record := PurchaseRecord{
		Phase: PurchaseTaskSent, RequestHash: hex.EncodeToString(testRequest[:]),
		Actor: "0:" + hex.EncodeToString(testActor[:]), RequestID: &requestID, ProviderAgentID: testSeller,
		CapabilityID: relayCapability, CommittedNanoTOS: "1", QuoteCommitment: relayQuoteCommitment,
	}
	if err := ensurePrivateDirectory(buyer.purchaseDir(record.RequestHash)); err != nil {
		t.Fatal(err)
	}
	if err := buyer.savePurchase(record, true); err != nil {
		t.Fatal(err)
	}
	return buyer, record, cards
}

func resultMessage(t *testing.T, sender string, card []byte) Message {
	t.Helper()
	body, err := EncodeResultWithCard([32]byte{0x42}, []byte{1, 2, 3}, []byte{4}, card)
	if err != nil {
		t.Fatal(err)
	}
	return Message{
		SenderAgentID: sender, Kind: FrameResult, ActorAccount: testActor, RequestID: 3, RequestHash: testRequest,
		Body: body, Packet: PacketFields{CapabilityID: relayCapability, QuoteCommitment: relayQuoteCommitment},
	}
}

func TestTheBuyerTakesTheProviderCardOnlyFromItsPurchaseAndOnlyOfTheFinalizedOwner(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	seller := newRelayTestNode(t, clock, testSeller, relayAgents(), relay)
	third := newRelayTestNode(t, clock, relayThird, relayAgents(), relay)

	buyer, record, cards := resultBuyer(t, clock, ownersMap{relayCapability: testSeller})
	// A result from another Agent is refused before its card is looked at.
	if err := buyer.HandleResult(context.Background(), resultMessage(t, relayThird, third.card())); err == nil ||
		cards.Has(relayThird) {
		t.Fatalf("a card came in with a result from another Agent: %v", err)
	}
	// The provider's result carrying another Agent's card: the result is
	// taken, the card is not, and the refusal is recorded.
	if err := buyer.HandleResult(context.Background(), resultMessage(t, testSeller, third.card())); err != nil {
		t.Fatal(err)
	}
	stored, err := buyer.loadPurchase(record.RequestHash)
	if err != nil || stored.ProviderCardRefused == "" || cards.Has(relayThird) || cards.Has(testSeller) {
		t.Fatalf("a foreign card in the provider's result: refused=%q %v", stored.ProviderCardRefused, err)
	}
	if _, err = os.Lstat(filepath.Join(buyer.purchaseDir(record.RequestHash), "result")); err != nil {
		t.Fatal("the result was not stored")
	}
	// The provider's own card is taken.
	if err = buyer.HandleResult(context.Background(), resultMessage(t, testSeller, seller.card())); err != nil {
		t.Fatal(err)
	}
	stored, err = buyer.loadPurchase(record.RequestHash)
	if err != nil || stored.ProviderCardRefused != "" || !cards.Has(testSeller) {
		t.Fatalf("the provider's card was not taken: %q %v", stored.ProviderCardRefused, err)
	}

	// A provider that no longer owns the Capability in finalized state:
	// its own valid card is refused.
	moved, record, movedCards := resultBuyer(t, clock, ownersMap{relayCapability: relayThird})
	if err = moved.HandleResult(context.Background(), resultMessage(t, testSeller, seller.card())); err != nil {
		t.Fatal(err)
	}
	stored, err = moved.loadPurchase(record.RequestHash)
	if err != nil || stored.ProviderCardRefused == "" || movedCards.Has(testSeller) {
		t.Fatal("a card not of the Capability's finalized owner was taken")
	}
}

func TestTheResultCardIsBoundedAndAbsentWithoutRelays(t *testing.T) {
	if _, err := EncodeResultWithCard([32]byte{1}, []byte{1}, []byte{1}, bytes.Repeat([]byte{'x'},
		maxCardJSON+1)); err == nil {
		t.Fatal("an oversized provider card was encoded")
	}
	plain, err := EncodeResult([32]byte{1}, []byte{1}, []byte{1})
	if err != nil || bytes.Contains(plain, []byte("provider_key_card")) {
		t.Fatalf("a cardless result names a card: %v", err)
	}
	withCard, err := EncodeResultWithCard([32]byte{1}, []byte{1}, []byte{1}, []byte("card"))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeResult(withCard)
	if err != nil || decoded.Header.ProviderKeyCard != base64.StdEncoding.EncodeToString([]byte("card")) {
		t.Fatalf("the card did not survive the result: %v", err)
	}
}

func TestJournaledBytesAreNeverResentToARevokedCard(t *testing.T) {
	clock := newRelayClock()
	agents := relayAgents()
	relay := startFakeRelay(t, clock)
	seller := newRelayTestNode(t, clock, testSeller, agents, relay)
	buyer := newRelayTestNode(t, clock, testBuyer, agents, relay)
	seller.learn(buyer)
	relay.failDeposits = 1
	if _, err := seller.courier.Deliver(context.Background(), relayEnvelopeTo(testBuyer), markedBody(20)); err == nil {
		t.Fatal("the failed deposit was reported delivered")
	}
	// The buyer's card-signing controller leaves its finalized policy.
	agents.revoke(testBuyer)
	clock.Advance(RelayCardReverify + time.Second)
	if err := seller.courier.Resume(context.Background()); !errors.Is(err, ErrNoPacketRoute) {
		t.Fatalf("a resend after revocation: %v", err)
	}
	if deposits := relay.depositLog(); len(deposits) != 1 {
		t.Fatalf("the bytes sealed to the revoked card were sent again: %d deposits", len(deposits))
	}
}

func TestJournaledBytesSealedToAnExpiredCardAreResealedToTheCurrentOne(t *testing.T) {
	clock := newRelayClock()
	agents := relayAgents()
	relay := startFakeRelay(t, clock)
	seller := newRelayTestNode(t, clock, testSeller, agents, relay)
	buyer := newRelayTestNode(t, clock, testBuyer, agents, relay)
	seller.learn(buyer)
	first, err := buyer.carrier.Keys.Current(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	// The packet stays deliverable longer than the first card: the courier
	// journals it near the card's end.
	clock.Advance(RelayKeyLifetime - 2*time.Hour)
	if _, err = buyer.carrier.Keys.Maintain(context.Background()); err != nil {
		t.Fatal(err)
	}
	seller.learn(buyer)
	// The seller seals to its preferred card, the successor; force the first
	// card by dropping the successor from the seller's view.
	second, err := buyer.carrier.Keys.Current(context.Background(), 0)
	if err != nil || second.KeyID == first.KeyID {
		t.Fatalf("no successor: %v", err)
	}
	seller.cards.mutex.Lock()
	kept := seller.cards.cards[testBuyer][:0]
	for _, card := range seller.cards.cards[testBuyer] {
		if card.Key.KeyID == first.KeyID {
			kept = append(kept, card)
		} else {
			_ = seller.cards.removeFile(card)
		}
	}
	seller.cards.cards[testBuyer] = kept
	seller.cards.mutex.Unlock()
	relay.failDeposits = 1
	if _, err = seller.courier.Deliver(context.Background(), relayEnvelopeTo(testBuyer), markedBody(20)); err == nil {
		t.Fatal("the failed deposit was reported delivered")
	}
	// The first card expires; the successor is known again.
	clock.Advance(3 * time.Hour)
	seller.learnCard(second.CardJSON)
	if err = seller.courier.Resume(context.Background()); err != nil {
		t.Fatalf("the resend after expiry: %v", err)
	}
	deposits := relay.depositLog()
	if len(deposits) != 2 || bytes.Equal(deposits[0].raw, deposits[1].raw) {
		t.Fatalf("the bytes sealed to the expired card were sent again: %d deposits", len(deposits))
	}
	header, err := agentpacketseal.ParseEnvelope(deposits[1].raw)
	if err != nil || header.RecipientKeyID != second.KeyID {
		t.Fatalf("the reseal is not to the current card: %v", err)
	}
	buyer.pollAll()
	if len(buyer.pending()) != 1 {
		t.Fatal("the resealed packet was not delivered")
	}
}

func TestRedundantDepositsStopWhenTheCardIsRevoked(t *testing.T) {
	clock := newRelayClock()
	agents := relayAgents()
	relayA, relayB := twoRelays(t, clock)
	seller := newRelayTestNode(t, clock, testSeller, agents, relayA)
	buyer := newRelayTestNode(t, clock, testBuyer, agents, relayA, relayB)
	seller.learn(buyer)
	relayB.failDeposits = 100
	if _, err := seller.courier.Deliver(context.Background(), relayEnvelopeTo(testBuyer), markedBody(20)); err != nil {
		t.Fatal(err)
	}
	agents.revoke(testBuyer)
	clock.Advance(RelayCardReverify + time.Second)
	relayB.failDeposits = 0
	if err := seller.carrier.Transport.Redeposit(context.Background()); err != nil {
		t.Fatal(err)
	}
	if relayB.count(testBuyer) != 0 {
		t.Fatal("an envelope sealed to a revoked card was spread to another relay")
	}
	views, err := ReadRelayOutbox(filepath.Join(seller.dir, relayStateDir, relayOutboxDir))
	if err != nil || len(views) != 1 || len(views[0].Pending) != 0 {
		t.Fatalf("the redundancy loop did not stop: %+v %v", views, err)
	}
}

// learnCard takes a card of the peer it names.
func (n *relayTestNode) learnCard(raw []byte) {
	n.t.Helper()
	packet, err := agentpacket.DecodeJSON(raw)
	if err != nil {
		n.t.Fatal(err)
	}
	if err := n.cards.Learn(context.Background(), raw, packet.SenderAgentID, ""); err != nil {
		n.t.Fatal(err)
	}
}

// ackProvider is a provider with one delivering request from testBuyer and
// the seller node's card directory.
func ackProvider(t *testing.T, clock *relayClock, cards *PeerCards) (*Provider, [32]byte) {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "provider")
	if err := ensurePrivateDirectory(directory); err != nil {
		t.Fatal(err)
	}
	provider := &Provider{config: ProviderConfig{Directory: directory, Cards: cards, Now: clock.Now}}
	responseHash := [32]byte{0x42}
	record := ProviderRecord{
		State:           ProviderDelivering,
		BuyerAgentID:    testBuyer,
		CapabilityID:    relayCapability,
		QuoteCommitment: relayQuoteCommitment,
		Actor:           "0:" + hex.EncodeToString(testActor[:]),
		RequestID:       3,
		RequestHash:     hex.EncodeToString(testRequest[:]),
		ResponseHash:    hex.EncodeToString(responseHash[:]),
	}
	key := railgate.SlotKey{QuoteCommitment: record.QuoteCommitment, Actor: record.Actor, RequestID: record.RequestID}
	if err := provider.store(key, record, true); err != nil {
		t.Fatal(err)
	}
	return provider, responseHash
}

func ackFrom(t *testing.T, sender string, responseHash [32]byte, card []byte) Message {
	t.Helper()
	body, err := EncodeAckWithCard(responseHash, card)
	if err != nil {
		t.Fatal(err)
	}
	return Message{
		SenderAgentID: sender, Kind: FrameResultAck, ActorAccount: testActor, RequestID: 3, RequestHash: testRequest,
		Body: body, Packet: PacketFields{CapabilityID: relayCapability, QuoteCommitment: relayQuoteCommitment},
	}
}

func TestAnExpiringBuyerCardIsRefreshedByTheAckAndResultsStillArriveAfterItExpired(t *testing.T) {
	clock := newRelayClock()
	agents := relayAgents()
	relay := startFakeRelay(t, clock)
	seller := newRelayTestNode(t, clock, testSeller, agents, relay)
	buyer := newRelayTestNode(t, clock, testBuyer, agents, relay)
	// The first task brought the buyer's first card.
	first, err := buyer.carrier.Keys.Current(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	seller.learnCard(first.CardJSON)
	// Near its end the buyer rotates; its acknowledgement carries the
	// successor.
	clock.Advance(RelayKeyLifetime - time.Hour)
	if _, err = buyer.carrier.Keys.Maintain(context.Background()); err != nil {
		t.Fatal(err)
	}
	second, err := buyer.carrier.Keys.Current(context.Background(), 0)
	if err != nil || second.KeyID == first.KeyID {
		t.Fatalf("no successor: %v", err)
	}
	provider, responseHash := ackProvider(t, clock, seller.cards)
	refresh := ackFrom(t, testBuyer, responseHash, second.CardJSON)
	if err = provider.HandleAck(context.Background(), refresh); err != nil {
		t.Fatal(err)
	}
	// After the first card expired a packet still reaches the buyer.
	clock.Advance(2 * time.Hour)
	if _, err = seller.courier.Deliver(context.Background(), relayEnvelopeTo(testBuyer), markedBody(30)); err != nil {
		t.Fatalf("no route once the first card expired: %v", err)
	}
	buyer.pollAll()
	if len(buyer.pending()) != 1 {
		t.Fatal("the packet sealed to the refreshed card was not delivered")
	}
}

func TestACardOfAnotherAgentInAnAckIsRefusedAndTheAckStillCounts(t *testing.T) {
	clock := newRelayClock()
	agents := relayAgents()
	relay := startFakeRelay(t, clock)
	seller := newRelayTestNode(t, clock, testSeller, agents, relay)
	third := newRelayTestNode(t, clock, relayThird, agents, relay)
	provider, responseHash := ackProvider(t, clock, seller.cards)
	// Only the request's buyer may acknowledge, card or not.
	if err := provider.HandleAck(context.Background(), ackFrom(t, relayThird, responseHash, third.card())); err == nil {
		t.Fatal("an acknowledgement from another Agent was taken")
	}
	if err := provider.HandleAck(context.Background(), ackFrom(t, testBuyer, responseHash, third.card())); err != nil {
		t.Fatal(err)
	}
	if seller.cards.Has(relayThird) || seller.cards.Has(testBuyer) {
		t.Fatal("a card of another Agent than the acknowledging buyer was taken")
	}
	records, err := provider.Records()
	if err != nil || len(records) != 1 || records[0].State != ProviderAcked ||
		!strings.Contains(records[0].Detail, "key card was not taken") {
		t.Fatalf("records = %+v %v", records, err)
	}
}

func TestTheBuyersAcknowledgementCarriesItsCurrentCard(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	node := newRelayTestNode(t, clock, testBuyer, relayAgents(), relay)
	sent := &recordingTransport{}
	courier, err := OpenCourier(filepath.Join(t.TempDir(), "outbox"), testSigner(t, testBuyer), sent)
	if err != nil {
		t.Fatal(err)
	}
	buyer := &Buyer{config: BuyerConfig{Courier: courier, RelayKeys: node.carrier.Keys, Now: clock.Now}}
	requestID := uint64(3)
	record := PurchaseRecord{
		RequestHash: hex.EncodeToString(testRequest[:]), Actor: "0:" + hex.EncodeToString(testActor[:]),
		RequestID: &requestID, ProviderAgentID: testSeller, CapabilityID: relayCapability,
		ResponseHash: strings.Repeat("42", 32), RefundDeadline: uint64(clock.Now().Add(40 * 24 * time.Hour).Unix()),
	}
	if err = buyer.acknowledge(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	packets := sent.packets()
	if len(packets) != 1 {
		t.Fatalf("%d packets", len(packets))
	}
	packet, err := agentpacket.DecodeJSON(packets[0].JSON)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := DecodeFrame(packet.Payload)
	if err != nil {
		t.Fatal(err)
	}
	ack, err := DecodeAck(frame.Data)
	if err != nil {
		t.Fatal(err)
	}
	current, err := node.carrier.Keys.Current(context.Background(), 0)
	if err != nil || ack.BuyerKeyCard != base64.StdEncoding.EncodeToString(current.CardJSON) {
		t.Fatalf("the acknowledgement does not carry the buyer's current card: %v", err)
	}
}

// relayQuoteCommitment is the Accepted Quote commitment of the relay test
// requests.
var relayQuoteCommitment = "tvm-cell-sha256:" + strings.Repeat("aa", 32)
