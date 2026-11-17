package servicebridge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketrelay"
)

// Room carriage against the stand-in daemon: kind-3 frames, their caps and
// pacing, the room card admissions and carrier.withdraw.

func testRoomID(label string) string {
	sum := sha256.Sum256([]byte("room\x00" + label))
	return "room_" + hex.EncodeToString(sum[:])
}

func roomKey(label string) string {
	sum := sha256.Sum256([]byte("room-key\x00" + label))
	return "idem_" + hex.EncodeToString(sum[:])
}

// roomFrames encodes one room object and cuts it into its kind-3 frames at
// the test part size partBytes (0 is the production cut).
func (d *standInDaemon) roomFrames(objectType uint8, roomID string, body []byte, partBytes int) [][]byte {
	d.t.Helper()
	object, err := relayframe.EncodeRoomObject(relayframe.RoomObject{
		Type: objectType, RoomID: roomID, RoomEpoch: 1, MLSEpoch: 1, Body: body,
	})
	if err != nil {
		d.t.Fatal(err)
	}
	frames, err := relayframe.SplitRoomObject(object, d.card(), d.evidence, partBytes)
	if err != nil {
		d.t.Fatal(err)
	}
	return frames
}

// application is one single-part room application frame.
func (d *standInDaemon) application(roomID, label string) []byte {
	d.t.Helper()
	frames := d.roomFrames(relayframe.RoomApplication, roomID, []byte(chatMessengerText+label), 0)
	if len(frames) != 1 {
		d.t.Fatalf("an application object took %d parts", len(frames))
	}
	return frames[0]
}

func (d *standInDaemon) roomFrameCount() int {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	return d.roomDelivered
}

func (d *standInDaemon) roomAckedFor(digest [32]byte) bool {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	return d.roomAcked[digest]
}

// carryFrame asks the node's carrier socket to deposit one frame under key.
func (d *standInDaemon) carryFrame(peer, key, withdraw string, frame []byte) carrierapi.Response {
	d.t.Helper()
	response, err := d.carrier.Carry(context.Background(), peer, key, withdraw,
		uint64(d.clock.Now().Add(7*24*time.Hour).Unix()), frame)
	if err != nil {
		d.t.Fatal(err)
	}
	return response
}

func (d *standInDaemon) admitRoomCards(roomID string, cards ...carrierapi.RoomCard) carrierapi.Response {
	d.t.Helper()
	return d.admitRoomCardsEnding(roomID, d.roomEndsAt, cards...)
}

// admitRoomCardsEnding admits cards under a room with the given end.
func (d *standInDaemon) admitRoomCardsEnding(roomID string, endsAtUnix uint64,
	cards ...carrierapi.RoomCard,
) carrierapi.Response {
	d.t.Helper()
	response, err := d.carrier.RoomCards(context.Background(), roomID, endsAtUnix, cards)
	if err != nil {
		d.t.Fatal(err)
	}
	return response
}

func (d *standInDaemon) forgetRoomCards(roomID string, agents ...string) carrierapi.Response {
	d.t.Helper()
	response, err := d.carrier.ForgetRoomCards(context.Background(), roomID, agents)
	if err != nil {
		d.t.Fatal(err)
	}
	return response
}

// roomCardOf is node's chat card as a roster entry teaches it.
func roomCardOf(node *chatTestNode) carrierapi.RoomCard {
	return carrierapi.RoomCard{AgentID: node.agent, CardBase64: base64.StdEncoding.EncodeToString(node.daemon.card())}
}

func outboxOf(t *testing.T, node *chatTestNode) []RelayOutboxView {
	t.Helper()
	views, err := ReadRelayOutbox(filepath.Join(node.dir, relayStateDir, relayChatOutboxDir))
	if err != nil {
		t.Fatal(err)
	}
	return views
}

func TestARoomObjectIsCarriedInPartsWithItsFrameKindJournaled(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	relay.setTTL(3600)
	a, b := chatPair(t, clock, relay.URL)
	room := testRoomID("parts")
	now := clock.Now()
	// A Commit cut at a test part size travels as several kind-3 parts, each
	// a handshake packet under the copy rule.
	parts := a.daemon.roomFrames(relayframe.RoomCommit, room, bytes.Repeat([]byte{9}, 3000), 1024)
	if len(parts) < 3 {
		t.Fatalf("setup: the Commit took %d parts", len(parts))
	}
	for index, part := range parts {
		requireResult(t, a.daemon.carryFrame(b.agent, roomKey(fmt.Sprint("commit", index)), "", part),
			carrierapi.ResultCarried, "")
	}
	// An application object lives the smallest relay TTL of B's card.
	requireResult(t, a.daemon.carryFrame(b.agent, roomKey("app"), "", a.daemon.application(room, "hello")),
		carrierapi.ResultCarried, "")
	views := outboxOf(t, a)
	if len(views) != len(parts)+1 {
		t.Fatalf("journal holds %d records", len(views))
	}
	application, handshake := 0, 0
	for _, view := range views {
		if view.FrameKind != relayframe.KindRoom {
			t.Fatalf("a room record journals frame kind %d", view.FrameKind)
		}
		switch view.ExpiresAtUnix {
		case uint64(now.Add(time.Hour).Unix()):
			application++
		case uint64(now.Add(PacketLifetime).Unix()):
			handshake++
		default:
			t.Fatalf("a room record expires at %d (now %d)", view.ExpiresAtUnix, now.Unix())
		}
	}
	if application != 1 || handshake != len(parts) {
		t.Fatalf("%d application and %d handshake lifetimes", application, handshake)
	}
	// B delivers every part to its daemon and relay-acknowledges them.
	b.pollAll()
	if b.daemon.roomFrameCount() != len(parts)+1 || relay.count(b.agent) != 0 {
		t.Fatalf("B's daemon got %d room frames, %d still listed: %s", b.daemon.roomFrameCount(), relay.count(b.agent),
			b.reportText())
	}
	// Room traffic creates no admission: B holds no card of A.
	if b.chat.Cards.Has(a.agent) {
		t.Fatal("an admitted room part stored the card of a peer no admission holds")
	}
}

func TestAKind3FrameOfAStrangerIsRefusedAndItsCardNeverStored(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	agents := relayAgents()
	a := newChatTestNode(t, clock, testSeller, agents, relay.URL)
	b := newChatTestNode(t, clock, testBuyer, agents, relay.URL)
	a.importContact(b)
	requireResult(t, a.daemon.carryFrame(b.agent, roomKey("stranger"), "", a.daemon.application(testRoomID("s"), "x")),
		carrierapi.ResultCarried, "")
	b.pollAll()
	if b.daemon.roomFrameCount() != 1 || relay.count(b.agent) != 0 || b.chat.Cards.Has(a.agent) {
		t.Fatalf("a refused room frame: delivered %d, listed %d, card held %v", b.daemon.roomFrameCount(),
			relay.count(b.agent), b.chat.Cards.Has(a.agent))
	}
}

func TestARoomAckReturnsToTheAuthorityAndPart0RenewsOnlyUnderAnAdmission(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	a, b := chatPair(t, clock, relay.URL)
	room := testRoomID("ack")
	// B holds A's card under the room's admission only.
	requireResult(t, b.daemon.admitRoomCards(room, roomCardOf(a)), carrierapi.ResultApplied, "")
	if !b.chat.Cards.Has(a.agent) {
		t.Fatal("the admitted room card is not held")
	}
	commit := a.daemon.roomFrames(relayframe.RoomCommit, room, []byte("mls-commit"), 0)
	if len(commit) != 1 {
		t.Fatal("setup: a small Commit took more than one part")
	}
	requireResult(t, a.daemon.carryFrame(b.agent, roomKey("commit"), "", commit[0]), carrierapi.ResultCarried, "")
	b.pollAll()
	// B answered the Commit with a room ack in a kind-2 frame to A.
	acks := outboxOf(t, b)
	if len(acks) != 1 || acks[0].FrameKind != relayframe.KindDeliveryAck {
		t.Fatalf("B's journal after the room ack: %+v %s", acks, b.reportText())
	}
	a.pollAll()
	frame, err := relayframe.Decode(commit[0])
	if err != nil {
		t.Fatal(err)
	}
	if !a.daemon.roomAckedFor(frame.ObjectDigest) {
		t.Fatalf("A's daemon did not settle the room ack: %s", a.reportText())
	}
	// Forgetting the room's admission drops A's card at B: nothing else
	// holds it. A later part 0 from A then stores nothing.
	requireResult(t, b.daemon.forgetRoomCards(room, a.agent), carrierapi.ResultApplied, "")
	if b.chat.Cards.Has(a.agent) {
		t.Fatal("a card only the forgotten room held is still stored")
	}
	requireResult(t, a.daemon.carryFrame(b.agent, roomKey("after"), "", a.daemon.application(room, "late")),
		carrierapi.ResultCarried, "")
	b.pollAll()
	if b.chat.Cards.Has(a.agent) {
		t.Fatal("room traffic stored the card of a peer whose admission was forgotten")
	}
}

func TestRoomCardsAreAdmittedVerifiedAndForgottenOnlyWithoutAnotherAdmission(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	agents := relayAgents()
	a := newChatTestNode(t, clock, testSeller, agents, relay.URL)
	b := newChatTestNode(t, clock, testBuyer, agents, relay.URL)
	c := newChatTestNode(t, clock, relayThird, agents, relay.URL)
	one, two := testRoomID("one"), testRoomID("two")

	// A card that does not verify as its Agent's, and this node's own, are
	// named refused and skipped; the valid one is admitted.
	forged := carrierapi.RoomCard{AgentID: c.agent, CardBase64: roomCardOf(a).CardBase64}
	own := roomCardOf(b)
	response := b.daemon.admitRoomCards(one, roomCardOf(a), forged, own)
	requireResult(t, response, carrierapi.ResultApplied, "")
	if strings.Join(response.RefusedAgentIDs, ",") != c.agent+","+b.agent {
		t.Fatalf("refused %v", response.RefusedAgentIDs)
	}
	if !b.chat.Cards.Has(a.agent) || b.chat.Cards.Has(c.agent) {
		t.Fatal("the admitted and refused cards are not as expected")
	}
	// Two rooms hold A's card: forgetting one keeps it, the other drops it.
	requireResult(t, b.daemon.admitRoomCards(two, roomCardOf(a)), carrierapi.ResultApplied, "")
	requireResult(t, b.daemon.forgetRoomCards(one, a.agent), carrierapi.ResultApplied, "")
	if !b.chat.Cards.Has(a.agent) {
		t.Fatal("forgetting one room dropped a card another room holds")
	}
	requireResult(t, b.daemon.forgetRoomCards(two, a.agent), carrierapi.ResultApplied, "")
	if b.chat.Cards.Has(a.agent) {
		t.Fatal("a card no admission holds is still stored")
	}
	if views, err := readRoomAdmissions(filepath.Join(b.dir, relayStateDir, relayChatRoomAdmissionsDir)); err != nil ||
		len(views) != 0 {
		t.Fatalf("admission records left: %+v %v", views, err)
	}
	// Forgetting again, or an Agent never admitted, is a no-op.
	requireResult(t, b.daemon.forgetRoomCards(two, a.agent, c.agent), carrierapi.ResultApplied, "")

	// A contact's card stays when a room that also admitted it forgets it.
	b.importContact(c)
	requireResult(t, b.daemon.admitRoomCards(one, roomCardOf(c)), carrierapi.ResultApplied, "")
	requireResult(t, b.daemon.forgetRoomCards(one, c.agent), carrierapi.ResultApplied, "")
	if !b.chat.Cards.Has(c.agent) {
		t.Fatal("forgetting a room dropped a contact's card")
	}
	// A contact imported after the room admission is direct as well.
	requireResult(t, b.daemon.admitRoomCards(two, roomCardOf(a)), carrierapi.ResultApplied, "")
	b.importContact(a)
	requireResult(t, b.daemon.forgetRoomCards(two, a.agent), carrierapi.ResultApplied, "")
	if !b.chat.Cards.Has(a.agent) {
		t.Fatal("forgetting a room dropped a card a later contact import holds")
	}
	// Removing the contact ends the direct admission but keeps the cards the
	// room still holds, with no admission again; the room's forget then
	// removes them whole.
	requireResult(t, b.daemon.admitRoomCards(one, roomCardOf(a)), carrierapi.ResultApplied, "")
	removed, err := removeChatContact(filepath.Join(b.dir, relayStateDir, relayChatPeersDir),
		filepath.Join(b.dir, "contacts"), b.agent, a.agent)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed.RemovedCards) != 0 || strings.Join(removed.KeptForRooms, ",") != one || removed.ContactFile == "" {
		t.Fatalf("contact remove reported %+v", removed)
	}
	if !b.chat.Cards.Has(a.agent) {
		t.Fatal("removing the contact dropped a card a room still holds")
	}
	requireResult(t, b.daemon.forgetRoomCards(one, a.agent), carrierapi.ResultApplied, "")
	if b.chat.Cards.Has(a.agent) {
		t.Fatal("a removed contact's card stayed after its last room forgot it")
	}
}

// A contact who is also admitted under a room keeps its cards through a
// contact remove, so the room keeps carrying to it with no new admission.
func TestRemovingAContactKeepsTheCardsARoomStillHolds(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	a, b := chatPair(t, clock, relay.URL)
	room := testRoomID("held")
	b.importContact(a)
	requireResult(t, b.daemon.admitRoomCards(room, roomCardOf(a)), carrierapi.ResultApplied, "")
	if _, err := removeChatContact(filepath.Join(b.dir, relayStateDir, relayChatPeersDir),
		filepath.Join(b.dir, "contacts"), b.agent, a.agent); err != nil {
		t.Fatal(err)
	}
	views, err := readRoomAdmissions(filepath.Join(b.dir, relayStateDir, relayChatRoomAdmissionsDir))
	if err != nil || len(views) != 1 || views[0].Direct {
		t.Fatalf("admissions after the contact remove: %+v %v", views, err)
	}
	if !b.chat.Cards.Has(a.agent) {
		t.Fatal("the room still admits A but A's card is gone")
	}
	// B still carries a room frame to A in a quiet room.
	requireResult(t, b.daemon.carryFrame(a.agent, roomKey("quiet"), "", b.daemon.application(room, "q")),
		carrierapi.ResultCarried, "")
	// Without a room, the contact remove deletes the cards as before.
	requireResult(t, b.daemon.forgetRoomCards(room, a.agent), carrierapi.ResultApplied, "")
	b.importContact(a)
	removed, err := removeChatContact(filepath.Join(b.dir, relayStateDir, relayChatPeersDir),
		filepath.Join(b.dir, "contacts"), b.agent, a.agent)
	if err != nil || len(removed.RemovedCards) != 1 || len(removed.KeptForRooms) != 0 || b.chat.Cards.Has(a.agent) {
		t.Fatalf("a contact no room admits: %+v %v held %v", removed, err, b.chat.Cards.Has(a.agent))
	}
}

// The admission lock serializes serve's record and card changes with the
// contact commands of another process: a second, independent handle on the
// lock file excludes them, and a held lock past the wait is a clear error.
func TestTheRoomAdmissionLockExcludesAnotherHandle(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	a, b := chatPair(t, clock, relay.URL)
	cardsDir := filepath.Join(b.dir, relayStateDir, relayChatPeersDir)
	previousWait := roomAdmissionLockWait.Load()
	roomAdmissionLockWait.Store(int64(300 * time.Millisecond))
	t.Cleanup(func() { roomAdmissionLockWait.Store(previousWait) })
	unlock, err := lockRoomAdmissions(cardsDir)
	if err != nil {
		t.Fatal(err)
	}
	room := testRoomID("locked")
	admissions := filepath.Join(b.dir, relayStateDir, relayChatRoomAdmissionsDir)
	// serve waits for the lock and answers retry, writing nothing.
	requireResult(t, b.daemon.admitRoomCards(room, roomCardOf(a)), carrierapi.ResultRetry, "")
	if b.chat.Cards.Has(a.agent) {
		t.Fatal("a card was stored while another handle held the admission lock")
	}
	if views, _ := readRoomAdmissions(admissions); len(views) != 0 {
		t.Fatalf("an admission was written while the lock was held: %+v", views)
	}
	// The contact commands wait the same way and fail with a clear error.
	if _, err := removeChatContact(cardsDir, filepath.Join(b.dir, "contacts"), b.agent, a.agent); !errors.Is(err,
		errRoomAdmissionBusy) {
		t.Fatalf("contact remove under a held lock: %v", err)
	}
	if _, err := importChatContact(context.Background(), b.chat.Cards, filepath.Join(b.dir, "contacts"), b.agent,
		a.contactOf()); !errors.Is(err, errRoomAdmissionBusy) {
		t.Fatalf("contact import under a held lock: %v", err)
	}
	// Released within the wait, the admission goes through.
	done := make(chan carrierapi.Response, 1)
	roomAdmissionLockWait.Store(int64(5 * time.Second))
	cards := []carrierapi.RoomCard{roomCardOf(a)}
	go func() {
		response, callErr := b.daemon.carrier.RoomCards(context.Background(), room, b.daemon.roomEndsAt, cards)
		if callErr != nil {
			response = carrierapi.Retry()
		}
		done <- response
	}()
	time.Sleep(100 * time.Millisecond)
	select {
	case response := <-done:
		t.Fatalf("the admission finished while the lock was held: %+v", response)
	default:
	}
	unlock()
	requireResult(t, <-done, carrierapi.ResultApplied, "")
	if !b.chat.Cards.Has(a.agent) {
		t.Fatal("the admission after the lock was released stored nothing")
	}
}

// A store that fails after the admission record was written puts the
// record back: a new peer leaves no record, a held one keeps its rooms.
func TestAFailedCardStorePutsTheAdmissionRecordBack(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a read-only directory does not stop root")
	}
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	a, b := chatPair(t, clock, relay.URL)
	cardsDir := filepath.Join(b.dir, relayStateDir, relayChatPeersDir)
	admissions := filepath.Join(b.dir, relayStateDir, relayChatRoomAdmissionsDir)
	one, two := testRoomID("kept"), testRoomID("failed")
	readOnly := func() {
		if err := os.Chmod(cardsDir, 0o500); err != nil {
			t.Fatal(err)
		}
	}
	writable := func() {
		if err := os.Chmod(cardsDir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(writable)
	readOnly()
	requireResult(t, b.daemon.admitRoomCards(one, roomCardOf(a)), carrierapi.ResultRetry, "")
	if views, err := readRoomAdmissions(admissions); err != nil || len(views) != 0 {
		t.Fatalf("a failed store left a record: %+v %v", views, err)
	}
	writable()
	requireResult(t, b.daemon.admitRoomCards(one, roomCardOf(a)), carrierapi.ResultApplied, "")
	// The same key is stored again under another room: replacing the file
	// fails, and the record keeps only the first room.
	readOnly()
	requireResult(t, b.daemon.admitRoomCards(two, roomCardOf(a)), carrierapi.ResultRetry, "")
	writable()
	views, err := readRoomAdmissions(admissions)
	if err != nil || len(views) != 1 || strings.Join(views[0].Rooms, ",") != one {
		t.Fatalf("the record after a failed store: %+v %v", views, err)
	}
}

func TestARoomCardIsVerifiedAgainstFinalizedStateBeforeItIsStored(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	agents := relayAgents()
	b := newChatTestNode(t, clock, testBuyer, agents, relay.URL)
	c := newChatTestNode(t, clock, relayThird, agents, relay.URL)
	room := testRoomID("verify")
	// Finalized state cannot answer: the batch is retried, nothing stored.
	agents.set(true)
	requireResult(t, b.daemon.admitRoomCards(room, roomCardOf(c)), carrierapi.ResultRetry, "")
	agents.set(false)
	if b.chat.Cards.Has(c.agent) {
		t.Fatal("a card was stored while finalized state could not verify it")
	}
	// The card's signing controller is no longer C's: refused and skipped.
	agents.revoke(c.agent)
	response := b.daemon.admitRoomCards(room, roomCardOf(c))
	requireResult(t, response, carrierapi.ResultApplied, "")
	if len(response.RefusedAgentIDs) != 1 || b.chat.Cards.Has(c.agent) {
		t.Fatalf("a card finalized state refuses: %+v, held %v", response, b.chat.Cards.Has(c.agent))
	}
	if views, err := readRoomAdmissions(filepath.Join(b.dir, relayStateDir, relayChatRoomAdmissionsDir)); err != nil ||
		len(views) != 0 {
		t.Fatalf("a refused card left an admission: %+v %v", views, err)
	}
}

func TestAPeerIsAdmittedUnderAtMostSixtyFourRooms(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	a, b := chatPair(t, clock, relay.URL)
	for index := range maxAgentRoomAdmissions {
		requireResult(t, b.daemon.admitRoomCards(testRoomID(fmt.Sprint("r", index)), roomCardOf(a)),
			carrierapi.ResultApplied, "")
	}
	response := b.daemon.admitRoomCards(testRoomID("one too many"), roomCardOf(a))
	requireResult(t, response, carrierapi.ResultApplied, "")
	if len(response.RefusedAgentIDs) != 1 || response.RefusedAgentIDs[0] != a.agent {
		t.Fatalf("the 65th room admission answered %+v", response)
	}
	// A room already holding the Agent admits it again as a no-op.
	response = b.daemon.admitRoomCards(testRoomID("r0"), roomCardOf(a))
	if len(response.RefusedAgentIDs) != 0 {
		t.Fatalf("a repeated admission was refused: %+v", response)
	}
}

func TestAnAcceptedCopyMakesARoomOnlyCardDirect(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	a, b := chatPair(t, clock, relay.URL)
	room := testRoomID("direct")
	requireResult(t, b.daemon.admitRoomCards(room, roomCardOf(a)), carrierapi.ResultApplied, "")
	// B's daemon accepts a 1:1 copy from A under its contact policy.
	requireResult(t, a.daemon.carry(b.agent, chatEventID("direct"), 1), carrierapi.ResultCarried, "")
	b.pollAll()
	if b.daemon.acceptedCount(chatEventID("direct")) != 1 {
		t.Fatalf("setup: the copy was not accepted: %s", b.reportText())
	}
	requireResult(t, b.daemon.forgetRoomCards(room, a.agent), carrierapi.ResultApplied, "")
	if !b.chat.Cards.Has(a.agent) {
		t.Fatal("forgetting the room dropped the card of a peer an accepted copy admitted")
	}
}

func TestRoomCardsRequestsAreBounded(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	a, b := chatPair(t, clock, relay.URL)
	ctx := context.Background()
	many := make([]string, carrierapi.MaxRoomCards+1)
	for index := range many {
		sum := sha256.Sum256([]byte(fmt.Sprint("agent", index)))
		many[index] = "agent_" + hex.EncodeToString(sum[:])
	}
	room, forget, admit := testRoomID("b"), carrierapi.RoomCardsForget, carrierapi.RoomCardsAdmit
	for name, request := range map[string]carrierapi.Request{
		"bad room":    {RoomID: "room_x", RoomCardsAction: forget, ForgetAgentIDs: []string{a.agent}},
		"no action":   {RoomID: room, ForgetAgentIDs: []string{a.agent}},
		"too many":    {RoomID: room, RoomCardsAction: forget, ForgetAgentIDs: many},
		"empty admit": {RoomID: room, RoomCardsAction: admit},
		"duplicate":   {RoomID: room, RoomCardsAction: forget, ForgetAgentIDs: []string{a.agent, a.agent}},
	} {
		request.Op = carrierapi.OpRoomCards
		requireResult(t, b.chat.RoomCards(ctx, request), carrierapi.ResultRefused, carrierapi.CodeInvalidRequest)
		if b.chat.Cards.Has(a.agent) {
			t.Fatalf("%s: a refused request stored a card", name)
		}
	}
}

// fillKind3 carries count application frames from a to b under fresh keys.
func fillKind3(t *testing.T, a, b *chatTestNode, prefix string, count int) {
	t.Helper()
	room := testRoomID(prefix)
	for index := range count {
		requireResult(t, a.daemon.carryFrame(b.agent, roomKey(fmt.Sprint(prefix, index)), "",
			a.daemon.application(room, fmt.Sprint(index))), carrierapi.ResultCarried, "")
	}
}

func TestTheKind3CapIsSixteenBesideTheChatCapOfTwentyFour(t *testing.T) {
	clock := newRelayClock()
	relay := startConfiguredRelay(t, clock, agentpacketrelay.RateLimit{PerMinute: 6000, Burst: 1000}).URL
	a, b := chatPair(t, clock, relay)
	fillKind3(t, a, b, "fill", ChatPeerRoomEnvelopeCap)
	// The seventeenth kind-3 envelope is refused although the chat cap has
	// room; copies still go.
	requireResult(t, a.daemon.carryFrame(b.agent, roomKey("over"), "", a.daemon.application(testRoomID("o"), "o")),
		carrierapi.ResultRefused, carrierapi.CodePeerCap)
	for index := range ChatPeerEnvelopeCap - ChatPeerRoomEnvelopeCap {
		requireResult(t, a.daemon.carry(b.agent, chatEventID(fmt.Sprint("c", index)), 1), carrierapi.ResultCarried, "")
	}
	requireResult(t, a.daemon.carry(b.agent, chatEventID("c-over"), 1), carrierapi.ResultRefused,
		carrierapi.CodePeerCap)
	status := a.chat.status()
	if len(status.PeerEnvelopes) != 1 || status.PeerEnvelopes[0].Envelopes != ChatPeerEnvelopeCap ||
		status.PeerEnvelopes[0].RoomEnvelopes != ChatPeerRoomEnvelopeCap {
		t.Fatalf("status counts %+v", status.PeerEnvelopes)
	}
	// B relay-acknowledges everything; the listing refresh of the next
	// kind-3 deposit frees both counts at once.
	b.pollAll()
	clock.Advance(roomDepositInterval)
	requireResult(t, a.daemon.carryFrame(b.agent, roomKey("over"), "", a.daemon.application(testRoomID("o"), "o")),
		carrierapi.ResultCarried, "")
	requireResult(t, a.daemon.carry(b.agent, chatEventID("c-over"), 1), carrierapi.ResultCarried, "")
}

func TestAnUnreadableJournalRecordCountsAsKind3ForEveryPeer(t *testing.T) {
	clock := newRelayClock()
	relay := startConfiguredRelay(t, clock, agentpacketrelay.RateLimit{PerMinute: 6000, Burst: 1000}).URL
	a, b := chatPair(t, clock, relay)
	fillKind3(t, a, b, "unreadable", ChatPeerRoomEnvelopeCap-1)
	junk := filepath.Join(a.dir, relayStateDir, relayChatOutboxDir, strings.Repeat("ab", 32)+".json")
	if err := os.WriteFile(junk, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	requireResult(t, a.daemon.carryFrame(b.agent, roomKey("one-more"), "", a.daemon.application(testRoomID("u"), "u")),
		carrierapi.ResultRefused, carrierapi.CodePeerCap)
	// A copy still fits under the 24.
	requireResult(t, a.daemon.carry(b.agent, chatEventID("copy"), 1), carrierapi.ResultCarried, "")
}

func TestKind3DepositsArePacedPerRelayAndOtherKindsAreNot(t *testing.T) {
	clock := newRelayClock()
	relay := startConfiguredRelay(t, clock, agentpacketrelay.RateLimit{PerMinute: 6000, Burst: 1000}).URL
	agents := relayAgents()
	a := newChatTestNode(t, clock, testSeller, agents, relay)
	b := newChatTestNode(t, clock, testBuyer, agents, relay)
	c := newChatTestNode(t, clock, relayThird, agents, relay)
	a.importContact(b)
	a.importContact(c)
	// The burst of 16 goes to B; the next kind-3 deposit to the same relay,
	// for another peer, waits: retry, no deposit, nothing reported.
	fillKind3(t, a, b, "burst", RoomDepositBurst)
	key := roomKey("paced")
	frame := a.daemon.application(testRoomID("p"), "p")
	requireResult(t, a.daemon.carryFrame(c.agent, key, "", frame), carrierapi.ResultRetry, "")
	if count := len(listedAt(t, relay, c.agent)); count != 0 {
		t.Fatalf("a paced deposit reached the relay: %d", count)
	}
	if strings.Contains(a.reportText(), "chat.carry") {
		t.Fatalf("pacing was reported as a failure: %s", a.reportText())
	}
	// Copies are not paced.
	requireResult(t, a.daemon.carry(c.agent, chatEventID("copy"), 1), carrierapi.ResultCarried, "")
	// One token refills every 2 s.
	clock.Advance(roomDepositInterval)
	requireResult(t, a.daemon.carryFrame(c.agent, key, "", frame), carrierapi.ResultCarried, "")
	requireResult(t, a.daemon.carryFrame(c.agent, roomKey("paced-2"), "", frame), carrierapi.ResultRetry, "")
	if pacing := a.chat.status().RoomPacing; len(pacing) != 1 || pacing[0].Tokens != 0 {
		t.Fatalf("pacing status %+v", pacing)
	}
}

func TestTheRoomPacerIsATokenBucketOfThirtyPerMinuteBurstSixteen(t *testing.T) {
	clock := newRelayClock()
	pacer := newRoomPacer(clock.Now)
	take := func(relay string) int {
		allowed := 0
		for pacer.allow(relay, relayframe.KindRoom) {
			allowed++
			if allowed > 1000 {
				t.Fatal("the bucket never empties")
			}
		}
		return allowed
	}
	if got := take("r1"); got != RoomDepositBurst {
		t.Fatalf("burst %d", got)
	}
	for _, kind := range []uint8{relayframe.KindCopy, relayframe.KindDeliveryAck, relayframe.KindEvidence} {
		if !pacer.allow("r1", kind) {
			t.Fatalf("kind %d was paced", kind)
		}
	}
	if got := take("r2"); got != RoomDepositBurst {
		t.Fatalf("another relay's burst %d", got)
	}
	clock.Advance(time.Minute)
	if got := take("r1"); got != RoomDepositBurst {
		t.Fatalf("a minute refilled %d, capped at the burst", got)
	}
	clock.Advance(10 * time.Second)
	if got := take("r1"); got != 5 {
		t.Fatalf("10 s refilled %d", got)
	}
	// Over a long run the rate holds: 30 a minute.
	total := 0
	for range 120 {
		clock.Advance(time.Second)
		total += take("r1")
	}
	if total != 2*RoomDepositsPerMinute {
		t.Fatalf("two minutes allowed %d", total)
	}
	// A clock that went back refills nothing.
	clock.Advance(-time.Hour)
	if got := take("r1"); got != 0 {
		t.Fatalf("a clock set back refilled %d", got)
	}
	if pacer.allow("", relayframe.KindRoom) {
		t.Fatal("a deposit to no relay was allowed")
	}
}

func TestTheRoomPacerBoundsItsRelaysAndDropsFullBucketsFirst(t *testing.T) {
	clock := newRelayClock()
	pacer := newRoomPacer(clock.Now)
	for index := range maxRoomPacingRelays {
		for range RoomDepositBurst {
			if !pacer.allow(fmt.Sprint("relay", index), relayframe.KindRoom) {
				t.Fatal("setup: a token was refused")
			}
		}
	}
	if pacer.allow("one-more", relayframe.KindRoom) {
		t.Fatal("a relay beyond the bound got a bucket while every bucket is in use")
	}
	clock.Advance(time.Minute)
	if !pacer.allow("one-more", relayframe.KindRoom) {
		t.Fatal("full buckets were not dropped for a new relay")
	}
}

func TestCarrierWithdrawWithdrawsTheJournaledEnvelope(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	a, b := chatPair(t, clock, relay.URL)
	ctx := context.Background()
	key := roomKey("withdraw")
	response, err := a.daemon.carrier.Withdraw(ctx, b.agent, key)
	if err != nil {
		t.Fatal(err)
	}
	requireResult(t, response, carrierapi.ResultIgnored, "")
	requireResult(t, a.daemon.carryFrame(b.agent, key, "", a.daemon.application(testRoomID("w"), "w")),
		carrierapi.ResultCarried, "")
	// A key journaled for another peer is refused, and nothing changes.
	response, err = a.daemon.carrier.Withdraw(ctx, relayThird, key)
	if err != nil {
		t.Fatal(err)
	}
	requireResult(t, response, carrierapi.ResultRefused, carrierapi.CodeInvalidRequest)
	if relay.count(b.agent) != 1 {
		t.Fatal("setup: the envelope is not held")
	}
	for range 2 {
		response, err = a.daemon.carrier.Withdraw(ctx, b.agent, key)
		if err != nil {
			t.Fatal(err)
		}
		requireResult(t, response, carrierapi.ResultWithdrawn, "")
	}
	a.redeposit()
	if relay.count(b.agent) != 0 {
		t.Fatal("the withdrawn envelope is still held")
	}
	// The key is final: carrying it again is refused.
	requireResult(t, a.daemon.carryFrame(b.agent, key, "", a.daemon.application(testRoomID("w"), "w")),
		carrierapi.ResultRefused, carrierapi.CodeInvalidRequest)
}

func TestCarryRefusesMalformedRoomFrames(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	a, b := chatPair(t, clock, relay.URL)
	// A part 0 whose room object does not parse.
	junk, err := relayframe.Encode(relayframe.Frame{
		Kind: relayframe.KindRoom, PartIndex: 0, PartCount: 1, Card: a.daemon.card(), Evidence: a.daemon.evidence,
		Part: bytes.Repeat([]byte{1}, 200),
	})
	if err != nil {
		t.Fatal(err)
	}
	requireResult(t, a.daemon.carryFrame(b.agent, roomKey("junk"), "", junk), carrierapi.ResultRefused,
		carrierapi.CodeFrameMalformed)
	// An application object is never split: a part 0 of two naming one is
	// malformed.
	object, err := relayframe.EncodeRoomObject(relayframe.RoomObject{
		Type: relayframe.RoomApplication, RoomID: testRoomID("split"), RoomEpoch: 1, MLSEpoch: 1, Body: []byte("app"),
	})
	if err != nil {
		t.Fatal(err)
	}
	split, err := relayframe.Encode(relayframe.Frame{
		Kind: relayframe.KindRoom, PartIndex: 0, PartCount: 2, ObjectDigest: relayframe.ObjectDigest(object),
		Card: a.daemon.card(), Evidence: a.daemon.evidence, Part: object,
	})
	if err != nil {
		t.Fatal(err)
	}
	requireResult(t, a.daemon.carryFrame(b.agent, roomKey("split"), "", split), carrierapi.ResultRefused,
		carrierapi.CodeFrameMalformed)
	// A room frame carrying another node's card.
	foreign := b.daemon.roomFrames(relayframe.RoomCommit, testRoomID("f"), []byte("c"), 0)
	requireResult(t, a.daemon.carryFrame(b.agent, roomKey("foreign"), "", foreign[0]), carrierapi.ResultRefused,
		carrierapi.CodeFrameMalformed)
	if len(outboxOf(t, a)) != 0 {
		t.Fatal("a refused room frame was journaled")
	}
}

func TestStatusAndPreflightShowRoomsAndTheKind3Counters(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	a, b := chatPair(t, clock, relay.URL)
	room := testRoomID("status")
	requireResult(t, a.daemon.admitRoomCards(room, roomCardOf(b)), carrierapi.ResultApplied, "")
	fillKind3(t, a, b, "status", 2)
	status := a.chat.status()
	if len(status.Rooms) != 1 || status.Rooms[0].RoomID != room || len(status.Rooms[0].Agents) != 1 ||
		len(status.RoomAdmissions) != 1 || !status.RoomAdmissions[0].Direct {
		t.Fatalf("rooms %+v admissions %+v", status.Rooms, status.RoomAdmissions)
	}
	if len(status.PeerEnvelopes) != 1 || status.PeerEnvelopes[0].RoomEnvelopes != 2 ||
		status.PeerEnvelopes[0].RoomEnvelopeCap != ChatPeerRoomEnvelopeCap {
		t.Fatalf("counts %+v", status.PeerEnvelopes)
	}
	run := func() map[string]PreflightCheck {
		p := &preflight{
			config: NodeConfig{StateDir: a.dir}, env: PreflightEnv{Now: clock.Now}, passed: map[string]bool{},
			report: &PreflightReport{OK: true},
		}
		p.checkChatRooms()
		out := map[string]PreflightCheck{}
		for _, check := range p.report.Checks {
			out[check.ID] = check
		}
		return out
	}
	checks := run()
	if checks["chat.rooms"].Status != CheckPass || checks["chat.peer-caps"].Status != CheckPass {
		t.Fatalf("preflight %+v", checks)
	}
	fillKind3(t, a, b, "status-full", ChatPeerRoomEnvelopeCap-2)
	if checks = run(); checks["chat.peer-caps"].Status != CheckWarn {
		t.Fatalf("a peer at the kind-3 cap: %+v", checks["chat.peer-caps"])
	}
	// `chat status` reads the same beside a running node.
	config := NodeConfig{
		AgentID: a.agent, StateDir: a.dir, RelayURLs: []string{relay.URL},
		ReceiverSocket: filepath.Join(a.dir, "rail.sock"),
		Chat: &ChatConfig{
			CarrierSocket:          filepath.Join(a.sockets, "c.sock"),
			MessengerCarrierSocket: filepath.Join(a.sockets, "d.sock"), CardPath: a.daemon.cardPath,
		},
	}
	configPath := filepath.Join(t.TempDir(), "rail.json")
	if err := writeNodeConfig(configPath, config); err != nil {
		t.Fatal(err)
	}
	report, err := ReadChatStatus(configPath, clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Rooms) != 1 || len(report.RoomAdmissions) != 1 || len(report.PeerEnvelopes) != 1 ||
		report.PeerEnvelopes[0].RoomEnvelopes != ChatPeerRoomEnvelopeCap {
		t.Fatalf("chat status %+v %+v %+v", report.Rooms, report.RoomAdmissions, report.PeerEnvelopes)
	}
	for _, view := range report.Outbox {
		if view.FrameKind != relayframe.KindRoom {
			t.Fatalf("chat status shows frame kind %d", view.FrameKind)
		}
	}
	// An unreadable admission record fails the preflight and shows in status.
	record := filepath.Join(a.dir, relayStateDir, relayChatRoomAdmissionsDir,
		strings.TrimPrefix(b.agent, "agent_")+".json")
	if err := os.WriteFile(record, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if checks = run(); checks["chat.rooms"].Status != CheckFail {
		t.Fatalf("an unreadable admission record: %+v", checks["chat.rooms"])
	}
	requireResult(t, a.daemon.forgetRoomCards(room, b.agent), carrierapi.ResultRetry, "")
}
