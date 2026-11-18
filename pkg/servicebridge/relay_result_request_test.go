package servicebridge

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/execution/pkg/railgate"
	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
	"google.golang.org/protobuf/proto"
)

// awayFixture is a responded request whose result the provider cannot
// deliver yet, with both nodes on one relay.
type awayFixture struct {
	clock    *relayClock
	seller   *relayTestNode
	buyerN   *relayTestNode
	provider *Provider
	buyer    *Buyer
	purchase PurchaseRecord
	key      railgate.SlotKey
}

const awayRetention = 25 * 86400

func newAwayFixture(t *testing.T) *awayFixture {
	t.Helper()
	clock := newRelayClock()
	agents := relayAgents()
	relay := startFakeRelay(t, clock)
	f := &awayFixture{clock: clock}
	f.seller = newRelayTestNode(t, clock, testSeller, agents, relay)
	f.buyerN = newRelayTestNode(t, clock, testBuyer, agents, relay)
	// The provider holds the buyer's ordinary 7-day card from the task.
	first, err := f.buyerN.carrier.Keys.Current(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	f.seller.learnCard(first.CardJSON)
	// The buyer holds the provider's long card from the offer file.
	offerCard, err := f.seller.carrier.Keys.Current(context.Background(), offerCardCover(uint64(clock.Now().Unix())))
	if err != nil {
		t.Fatal(err)
	}
	f.buyerN.learnCard(offerCard.CardJSON)

	directory := filepath.Join(t.TempDir(), "provider")
	if err = ensurePrivateDirectory(directory); err != nil {
		t.Fatal(err)
	}
	f.provider = &Provider{config: ProviderConfig{
		Directory: directory, Cards: f.seller.cards, Store: fixedArtifact("artifact"), Courier: f.seller.courier,
		Now: clock.Now,
	}}
	now := clock.Now()
	responseDeadline := uint64(now.Unix()) + 3600
	record := ProviderRecord{
		State:            ProviderDelivering,
		BuyerAgentID:     testBuyer,
		CapabilityID:     relayCapability,
		QuoteCommitment:  "tvm-cell-sha256:" + strings.Repeat("aa", 32),
		Actor:            "0:" + hex.EncodeToString(testActor[:]),
		RequestID:        3,
		RequestHash:      hex.EncodeToString(testRequest[:]),
		ResponseHash:     strings.Repeat("42", 32),
		ReceiptBOCBase64: base64.StdEncoding.EncodeToString([]byte{1, 2, 3}),
		ResponseDeadline: responseDeadline,
		RetentionEndUnix: responseDeadline + awayRetention,
		NextDeliveryUnix: now.Add(time.Hour).Unix(),
	}
	f.key = railgate.SlotKey{QuoteCommitment: record.QuoteCommitment, Actor: record.Actor, RequestID: record.RequestID}
	if err = f.provider.store(f.key, record, true); err != nil {
		t.Fatal(err)
	}

	purchases := filepath.Join(t.TempDir(), "purchases")
	if err = ensurePrivateDirectory(purchases); err != nil {
		t.Fatal(err)
	}
	f.buyer = &Buyer{config: BuyerConfig{
		Directory: purchases, Courier: f.buyerN.courier, RelayKeys: f.buyerN.carrier.Keys, Now: clock.Now,
	}}
	manifestCBOR, digest, _, err := BuildManifest(ManifestInput{
		ProviderAgentID: testSeller, Actor: pfActor, ActorCodeHash: pfCodeHash,
		Attestor: mldsa44.KeyIDText(pfAttestorID), Version: "1.0.0", RetentionSeconds: awayRetention,
	})
	if err != nil {
		t.Fatal(err)
	}
	requestID := uint64(3)
	f.purchase = PurchaseRecord{
		Phase: PurchaseTaskSent, RequestHash: record.RequestHash, Actor: record.Actor, RequestID: &requestID,
		ProviderAgentID: testSeller, CapabilityID: relayCapability, QuoteCommitment: record.QuoteCommitment,
		ManifestDigest: digest, ResponseDeadline: responseDeadline, ResponseHash: record.ResponseHash,
		CommittedNanoTOS: "1",
	}
	if err = ensurePrivateDirectory(f.buyer.purchaseDir(f.purchase.RequestHash)); err != nil {
		t.Fatal(err)
	}
	pkg, err := proto.Marshal(&nativev1.QuoteProposalPackageV1{
		Proposal: &nativev1.QuoteProposalV1{ManifestDigest: digest}, CanonicalManifestCbor: manifestCBOR,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = writeSynced(filepath.Join(f.buyer.purchaseDir(f.purchase.RequestHash), "quote-package"), pkg); err != nil {
		t.Fatal(err)
	}
	if err = f.buyer.savePurchase(f.purchase, true); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *awayFixture) record(t *testing.T) ProviderRecord {
	t.Helper()
	record, found, err := f.provider.load(f.key)
	if err != nil || !found {
		t.Fatalf("provider record: %v", err)
	}
	return record
}

// sellerTakesResultRequests hands every complete result request in the
// seller's inbox to the provider and returns how many there were.
func (f *awayFixture) sellerTakesResultRequests(t *testing.T) int {
	t.Helper()
	f.seller.pollAll()
	count := 0
	for _, message := range f.seller.pending() {
		if message.Kind != FrameResultRequest {
			continue
		}
		count++
		if err := f.provider.HandleResultRequest(context.Background(), message); err != nil {
			t.Fatalf("result request: %v", err)
		}
		if err := f.seller.inbox.Done(message.Key); err != nil {
			t.Fatal(err)
		}
	}
	return count
}

func TestABuyerBackFromBeyondItsCardsLifeGetsItsResultThroughAResultRequest(t *testing.T) {
	f := newAwayFixture(t)
	// The buyer is away for longer than its card lives.
	f.clock.Advance(RelayKeyLifetime + 24*time.Hour)
	if err := f.provider.deliver(context.Background(), f.record(t)); !errors.Is(err, ErrNoPacketRoute) {
		t.Fatalf("delivery with the buyer card expired: %v", err)
	}
	// The delivery loop backs off after the failed attempt.
	backedOff := f.record(t)
	backedOff.NextDeliveryUnix = f.clock.Now().Add(MaxRedelivery).Unix()
	if err := f.provider.store(f.key, backedOff, false); err != nil {
		t.Fatal(err)
	}
	// The buyer returns, sees the finalized respond and no result.
	if err := f.buyer.complete(context.Background(), f.purchase); err != nil {
		t.Fatal(err)
	}
	if f.sellerTakesResultRequests(t) != 1 {
		t.Fatal("no result request reached the provider")
	}
	record := f.record(t)
	if record.NextDeliveryUnix != f.clock.Now().Unix() {
		t.Fatal("the result request did not move the delivery forward")
	}
	if err := f.provider.deliver(context.Background(), record); err != nil {
		t.Fatalf("delivery after the result request: %v", err)
	}
	f.buyerN.pollAll()
	delivered := false
	for _, message := range f.buyerN.pending() {
		delivered = delivered || message.Kind == FrameResult
	}
	if !delivered {
		t.Fatal("the result did not reach the buyer")
	}
}

func TestAResultRequestFromAnotherAgentOrForAnotherRequestIsRefusedAndMovesNothing(t *testing.T) {
	f := newAwayFixture(t)
	third := newRelayTestNode(t, f.clock, relayThird, relayAgents(), f.seller.relays...)
	before := f.record(t)
	request := func(sender string, card []byte, requestID uint64, hash [32]byte) error {
		body, err := EncodeResultRequest(card)
		if err != nil {
			t.Fatal(err)
		}
		return f.provider.HandleResultRequest(context.Background(), Message{
			SenderAgentID: sender, Kind: FrameResultRequest, ActorAccount: testActor, RequestID: requestID,
			RequestHash: hash, Body: body,
			Packet: PacketFields{CapabilityID: relayCapability, QuoteCommitment: f.key.QuoteCommitment},
		})
	}
	for name, err := range map[string]error{
		"another Agent":   request(relayThird, third.card(), 3, testRequest),
		"another request": request(testBuyer, f.buyerN.card(), 4, testRequest),
		"another hash":    request(testBuyer, f.buyerN.card(), 3, [32]byte{9}),
	} {
		if !errors.Is(err, ErrResultRequestRefused) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A request not yet responded to is refused too.
	unresponded := before
	unresponded.State = ProviderExecuting
	if err := f.provider.store(f.key, unresponded, false); err != nil {
		t.Fatal(err)
	}
	if err := request(testBuyer, f.buyerN.card(), 3, testRequest); !errors.Is(err, ErrResultRequestRefused) {
		t.Fatalf("an unresponded request: %v", err)
	}
	// A request whose result is no longer retained is refused too.
	expired := before
	expired.RetentionEndUnix = uint64(f.clock.Now().Unix())
	if err := f.provider.store(f.key, expired, false); err != nil {
		t.Fatal(err)
	}
	if err := request(testBuyer, f.buyerN.card(), 3, testRequest); !errors.Is(err, ErrResultRequestRefused) {
		t.Fatalf("a request past its retention: %v", err)
	}
	after := f.record(t)
	if after.NextDeliveryUnix != before.NextDeliveryUnix || after.ResultRequestUnix != 0 ||
		f.seller.cards.Has(relayThird) {
		t.Fatal("a refused result request moved the delivery or left a card")
	}
}

func TestResultRequestsAreBoundedOnBothSides(t *testing.T) {
	f := newAwayFixture(t)
	// The buyer sends one when it first sees the state, then none for six
	// hours however often it looks.
	for range 5 {
		if err := f.buyer.complete(context.Background(), f.purchase); err != nil {
			t.Fatal(err)
		}
		stored, err := f.buyer.loadPurchase(f.purchase.RequestHash)
		if err != nil {
			t.Fatal(err)
		}
		f.purchase = stored
		f.clock.Advance(time.Hour)
	}
	envelope, err := envelopeFor(f.purchase, testSeller, FrameResultRequest, 0)
	if err != nil {
		t.Fatal(err)
	}
	if generations, countErr := f.buyerN.courier.Generations(envelope); countErr != nil || generations != 1 {
		t.Fatalf("%d result requests within six hours: %v", generations, countErr)
	}
	f.clock.Advance(ResultRequestEvery)
	if err = f.buyer.complete(context.Background(), f.purchase); err != nil {
		t.Fatal(err)
	}
	if generations, countErr := f.buyerN.courier.Generations(envelope); countErr != nil || generations != 2 {
		t.Fatalf("%d result requests after six hours: %v", generations, countErr)
	}
	// The provider moves the delivery forward at most once per interval.
	body, err := EncodeResultRequest(nil)
	if err != nil {
		t.Fatal(err)
	}
	again := Message{
		SenderAgentID: testBuyer, Kind: FrameResultRequest, ActorAccount: testActor, RequestID: 3,
		RequestHash: testRequest, Body: body,
		Packet: PacketFields{CapabilityID: relayCapability, QuoteCommitment: f.key.QuoteCommitment},
	}
	push := func() int64 {
		pushed := f.record(t)
		pushed.NextDeliveryUnix = f.clock.Now().Add(time.Hour).Unix()
		if storeErr := f.provider.store(f.key, pushed, false); storeErr != nil {
			t.Fatal(storeErr)
		}
		return pushed.NextDeliveryUnix
	}
	push()
	if err = f.provider.HandleResultRequest(context.Background(), again); err != nil {
		t.Fatal(err)
	}
	if f.record(t).NextDeliveryUnix != f.clock.Now().Unix() {
		t.Fatal("the first result request did not move the delivery forward")
	}
	later := push()
	f.clock.Advance(ResultRequestInterval / 2)
	if err = f.provider.HandleResultRequest(context.Background(), again); err != nil {
		t.Fatal(err)
	}
	if f.record(t).NextDeliveryUnix != later {
		t.Fatal("a second result request within the interval moved the delivery again")
	}
	// Past its retention the buyer asks no more.
	f.clock.Advance(awayRetention * time.Second)
	stored, err := f.buyer.loadPurchase(f.purchase.RequestHash)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.buyer.complete(context.Background(), stored); err != nil {
		t.Fatal(err)
	}
	if generations, err := f.buyerN.courier.Generations(envelope); err != nil || generations != 2 {
		t.Fatalf("a result request past the retention: %d %v", generations, err)
	}
}

func TestAResultRequestThatWasNotHandedOffIsSentAgainAtTheNextPass(t *testing.T) {
	f := newAwayFixture(t)
	relay := f.seller.relays[0]
	relay.failDeposits = 1
	if err := f.buyer.complete(context.Background(), f.purchase); err == nil {
		t.Fatal("the failed hand-off was not reported")
	}
	stored, err := f.buyer.loadPurchase(f.purchase.RequestHash)
	if err != nil || stored.ResultRequestUnix != 0 {
		t.Fatalf("a failed hand-off was recorded as sent: %v", err)
	}
	f.clock.Advance(time.Minute)
	if err = f.buyer.complete(context.Background(), stored); err != nil {
		t.Fatalf("the next pass: %v", err)
	}
	stored, err = f.buyer.loadPurchase(f.purchase.RequestHash)
	if err != nil || stored.ResultRequestUnix != f.clock.Now().Unix() {
		t.Fatalf("the request sent at the next pass was not recorded: %v", err)
	}
	envelope, err := envelopeFor(stored, testSeller, FrameResultRequest, 0)
	if err != nil {
		t.Fatal(err)
	}
	if generations, countErr := f.buyerN.courier.Generations(envelope); countErr != nil || generations != 2 {
		t.Fatalf("%d result request generations: %v", generations, countErr)
	}
}
