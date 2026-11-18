package servicebridge

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tosnetwork/ai/execution/pkg/railgate"
)

// A task whose frames are bound to another request than the one its own
// package derives is refused before the gate claims a slot, so the paid
// request stays admissible for a correctly framed resend (section 7.1
// item 6, Q3).
func TestAMisframedTaskNeverTakesItsSlot(t *testing.T) {
	ctx := context.Background()
	service := startRealExecutor(t, shortSocketDir(t), &fakeRuntime{}, nil)
	fixture := newGateFixture(t, serviceFixtureStart)
	node := openServiceNode(t, fixture, serviceState(t), ownClient(t, service.socket))
	for name, mutate := range map[string]func(*Message){
		"request hash": func(m *Message) { m.RequestHash[0] ^= 1 },
		"actor":        func(m *Message) { m.ActorAccount[0] ^= 1 },
	} {
		misframed := fixture.message
		mutate(&misframed)
		if err := node.provider.HandleTask(ctx, misframed); err == nil {
			t.Fatalf("%s: a misframed task was handled", name)
		}
		if records, err := node.provider.Records(); err != nil || len(records) != 0 {
			t.Fatalf("%s: the provider holds %d records, err=%v", name, len(records), err)
		}
	}
	if service.backend.runs() != 0 {
		t.Fatalf("a misframed task ran %d times", service.backend.runs())
	}
	// The slot is still free: the correctly framed task is admitted.
	if err := node.provider.HandleTask(ctx, fixture.message); err != nil {
		t.Fatalf("the correctly framed task was refused after the misframed ones: %v", err)
	}
	if state := node.slotState(t); state != railgate.SlotCompleted {
		t.Fatalf("the gate slot is %s", state)
	}
}

// A task whose packets name another Capability or Accepted Quote than its
// own package is refused before admission (section 2.1, Q1).
func TestATaskWhosePacketsNameAnotherQuoteIsRefused(t *testing.T) {
	provider := testRailProvider()
	message, _ := taskMessage(t, testPackage(t, nil), fill(100, 1), testBuyer)
	if _, _, err := provider.claimFor(message); err != nil {
		t.Fatalf("the task's own packet fields were refused: %v", err)
	}
	for name, mutate := range map[string]func(*PacketFields){
		"capability": func(p *PacketFields) { p.CapabilityID = "cap_" + strings.Repeat("34", 32) },
		"quote":      func(p *PacketFields) { p.QuoteCommitment = "tvm-cell-sha256:" + strings.Repeat("35", 32) },
		"no fields":  func(p *PacketFields) { *p = PacketFields{} },
	} {
		changed := message
		mutate(&changed.Packet)
		if _, _, err := provider.claimFor(changed); !errors.Is(err, ErrPacketFieldsMismatch) {
			t.Errorf("%s: err=%v", name, err)
		}
	}
}

// The inbox keeps the packet fields of a message's first frame and refuses
// a frame of the same message arriving in packets that name others.
func TestTheInboxBindsEveryFrameToTheFirstFramesPacketFields(t *testing.T) {
	inbox, _ := openTestInbox(t, 8, 64)
	body := fill(MaxChunkData+10, 3)
	frames, err := SplitMessage(FrameResult, [32]byte{7}, 1, [32]byte{8}, body)
	if err != nil || len(frames) != 2 {
		t.Fatalf("%d frames err=%v", len(frames), err)
	}
	packet := testPacket(t)
	if _, _, err = inbox.Put(testSeller, packet, frames[0]); err != nil {
		t.Fatal(err)
	}
	other := packet
	other.QuoteCommitment = "tvm-cell-sha256:" + strings.Repeat("36", 32)
	if _, _, err = inbox.Put(testSeller, other, frames[1]); !errors.Is(err, ErrInboxRefused) {
		t.Fatalf("a frame in packets naming another Quote joined: %v", err)
	}
	if _, _, err = inbox.Put(testSeller, PacketFields{}, frames[1]); !errors.Is(err, ErrInboxRefused) {
		t.Fatalf("a frame in packets naming no Quote was stored: %v", err)
	}
	status, message, err := inbox.Put(testSeller, packet, frames[1])
	if err != nil || status != InboxComplete || message.Packet != packet {
		t.Fatalf("status %v, err=%v", status, err)
	}
}

// An assembly an earlier release stored without packet fields takes the
// fields of the next frame that reaches it.
func TestAnAssemblyWithoutPacketFieldsTakesTheNextFramesFields(t *testing.T) {
	inbox, root := openTestInbox(t, 8, 64)
	frames, err := SplitMessage(FrameResult, [32]byte{7}, 1, [32]byte{8}, fill(MaxChunkData+10, 4))
	if err != nil {
		t.Fatal(err)
	}
	packet := testPacket(t)
	if _, _, err = inbox.Put(testSeller, packet, frames[0]); err != nil {
		t.Fatal(err)
	}
	key := assemblyKey(testSeller, frames[0])
	if err = os.Remove(filepath.Join(root, key, packetFile)); err != nil {
		t.Fatal(err)
	}
	status, message, err := inbox.Put(testSeller, packet, frames[1])
	if err != nil || status != InboxComplete || message.Packet != packet {
		t.Fatalf("status %v, err=%v", status, err)
	}
}

// A result that fails acceptance is discarded, never makes the purchase
// final, and the provider's next delivery is taken and examined again
// (section 7.2, Q9).
func TestABuyerDiscardsAResultThatFailsAcceptanceAndTakesTheNextDelivery(t *testing.T) {
	ctx := context.Background()
	f := newAwayFixture(t)
	f.purchase.PriceNanoTOS = "1"
	f.purchase.ExecutionID, f.purchase.InputDigest = strings.Repeat("e1", 32), strings.Repeat("e2", 32)
	if err := f.buyer.savePurchase(f.purchase, false); err != nil {
		t.Fatal(err)
	}
	resultPath := filepath.Join(f.buyer.purchaseDir(f.purchase.RequestHash), "result")
	var responseHash [32]byte
	copy(responseHash[:], []byte(strings.Repeat("\x42", 32)))
	bad, err := EncodeResult(responseHash, []byte{1, 2, 3}, []byte("not the attested artifact"))
	if err != nil {
		t.Fatal(err)
	}
	if err = writeSynced(resultPath, bad); err != nil {
		t.Fatal(err)
	}
	examine := func(round int) {
		t.Helper()
		stored, loadErr := f.buyer.loadPurchase(f.purchase.RequestHash)
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		if completeErr := f.buyer.complete(ctx, stored); completeErr != nil {
			t.Fatalf("round %d: %v", round, completeErr)
		}
		stored, loadErr = f.buyer.loadPurchase(f.purchase.RequestHash)
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		if stored.Phase != PurchaseTaskSent || terminalPurchase(stored.Phase) || stored.RejectedResults != round ||
			!strings.Contains(stored.Failure, "discarded") {
			t.Fatalf("round %d: phase %s, %d rejected, failure %q", round, stored.Phase, stored.RejectedResults,
				stored.Failure)
		}
		if _, statErr := os.Stat(resultPath); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("round %d: the failing result was kept: %v", round, statErr)
		}
	}
	examine(1)
	// The provider delivers again; the buyer takes the delivery.
	if err = f.provider.deliver(ctx, f.record(t)); err != nil {
		t.Fatal(err)
	}
	f.buyerN.pollAll()
	taken := false
	for _, message := range f.buyerN.pending() {
		if message.Kind != FrameResult {
			continue
		}
		if err = f.buyer.HandleResult(ctx, message); err != nil {
			t.Fatal(err)
		}
		taken = true
	}
	if _, err = os.Stat(resultPath); !taken || err != nil {
		t.Fatalf("the redelivery was not stored: taken %v, %v", taken, err)
	}
	// This delivery fails too (the fixture's Receipt is not attested): it is
	// discarded in turn and the purchase is still open.
	examine(2)
}

// A message's first frame must arrive in packets that name a Capability
// and an Accepted Quote: the inbox refuses to open an assembly for one
// that does not.
func TestTheInboxRefusesAFirstFrameInPacketsWithoutFields(t *testing.T) {
	inbox, _ := openTestInbox(t, 8, 64)
	frames, err := SplitMessage(FrameResult, [32]byte{7}, 1, [32]byte{8}, fill(100, 5))
	if err != nil {
		t.Fatal(err)
	}
	packet := testPacket(t)
	for name, fields := range map[string]PacketFields{
		"no fields":     {},
		"no Quote":      {CapabilityID: packet.CapabilityID},
		"no Capability": {QuoteCommitment: packet.QuoteCommitment},
		"malformed":     {CapabilityID: packet.CapabilityID, QuoteCommitment: "sha256:" + strings.Repeat("ab", 32)},
	} {
		if _, _, err = inbox.Put(testSeller, fields, frames[0]); !errors.Is(err, ErrInboxRefused) {
			t.Errorf("%s: err=%v", name, err)
		}
	}
	if pending, err := inbox.Pending(); err != nil || len(pending) != 0 {
		t.Fatalf("a refused frame left %d messages: %v", len(pending), err)
	}
	if status, _, err := inbox.Put(testSeller, packet, frames[0]); err != nil || status != InboxComplete {
		t.Fatalf("the frame with its fields: status %v err=%v", status, err)
	}
}

// A result request whose packets name another Capability or Accepted
// Quote than the request is refused and moves nothing.
func TestAResultRequestInPacketsNamingAnotherQuoteIsRefused(t *testing.T) {
	f := newAwayFixture(t)
	before := f.record(t)
	body, err := EncodeResultRequest(nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, packet := range map[string]PacketFields{
		"another Quote":      {CapabilityID: relayCapability, QuoteCommitment: "tvm-cell-sha256:" + strings.Repeat("ab", 32)},
		"another Capability": {CapabilityID: "cap_" + strings.Repeat("37", 32), QuoteCommitment: f.key.QuoteCommitment},
	} {
		err = f.provider.HandleResultRequest(context.Background(), Message{
			SenderAgentID: testBuyer, Kind: FrameResultRequest, ActorAccount: testActor, RequestID: 3,
			RequestHash: testRequest, Body: body, Packet: packet,
		})
		if !errors.Is(err, ErrResultRequestRefused) || !errors.Is(err, ErrPacketFieldsMismatch) {
			t.Errorf("%s: err=%v", name, err)
		}
	}
	if after := f.record(t); after.NextDeliveryUnix != before.NextDeliveryUnix || after.ResultRequestUnix != 0 {
		t.Fatal("a refused result request moved the delivery")
	}
}
