package servicebridge

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
)

// Room admissions carry their room's end and end with it: the carrier drops
// each one at the end plus carrierapi.RoomEndSlackSeconds, when it opens and
// on every maintenance pass, through the forget path.

func admissionsOf(t *testing.T, node *chatTestNode) []RoomAdmissionView {
	t.Helper()
	views, err := readRoomAdmissions(filepath.Join(node.dir, relayStateDir, relayChatRoomAdmissionsDir))
	if err != nil {
		t.Fatal(err)
	}
	return views
}

// advanceTo moves the clock to the given Unix second.
func advanceTo(clock *relayClock, unix uint64) {
	clock.Advance(time.Unix(int64(unix), 0).Sub(clock.Now()))
}

func maintain(t *testing.T, node *chatTestNode) {
	t.Helper()
	if err := node.chat.Maintain(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestARoomAdmissionIsDroppedAtItsEndPlusTheSlackAndNotBefore(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	a, b := chatPair(t, clock, relay.URL)
	room := testRoomID("ends")
	requireResult(t, b.daemon.admitRoomCards(room, roomCardOf(a)), carrierapi.ResultApplied, "")
	views := admissionsOf(t, b)
	if len(views) != 1 || views[0].RoomEndsAtUnix[room] != b.daemon.roomEndsAt {
		t.Fatalf("the admission does not carry its room's end: %+v", views)
	}
	drop, valid := carrierapi.RoomAdmissionDropAtUnix(b.daemon.roomEndsAt)
	if !valid {
		t.Fatal("setup: no drop time")
	}
	// One second before the drop time the admission and the card stay.
	advanceTo(clock, drop-1)
	maintain(t, b)
	if !b.chat.Cards.Has(a.agent) || len(admissionsOf(t, b)) != 1 {
		t.Fatal("an admission was dropped before its room's end plus the slack")
	}
	// At the drop time the maintenance pass forgets it whole.
	advanceTo(clock, drop)
	maintain(t, b)
	if b.chat.Cards.Has(a.agent) || len(admissionsOf(t, b)) != 0 {
		t.Fatalf("the admission outlived its room: card %v, %+v %s", b.chat.Cards.Has(a.agent),
			admissionsOf(t, b), b.reportText())
	}
}

func TestTheSweepKeepsCardsAnotherAdmissionHolds(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	agents := relayAgents()
	a := newChatTestNode(t, clock, testSeller, agents, relay.URL)
	b := newChatTestNode(t, clock, testBuyer, agents, relay.URL)
	c := newChatTestNode(t, clock, relayThird, agents, relay.URL)
	short, long := testRoomID("short"), testRoomID("long")
	later := b.daemon.roomEndsAt + 7*24*60*60
	// A is admitted by two rooms, C by a room and as a contact.
	requireResult(t, b.daemon.admitRoomCards(short, roomCardOf(a), roomCardOf(c)), carrierapi.ResultApplied, "")
	requireResult(t, b.daemon.admitRoomCardsEnding(long, later, roomCardOf(a)), carrierapi.ResultApplied, "")
	b.importContact(c)
	drop, _ := carrierapi.RoomAdmissionDropAtUnix(b.daemon.roomEndsAt)
	advanceTo(clock, drop)
	maintain(t, b)
	if !b.chat.Cards.Has(a.agent) || !b.chat.Cards.Has(c.agent) {
		t.Fatal("the sweep dropped a card another admission holds")
	}
	views := admissionsOf(t, b)
	if len(views) != 1 || views[0].AgentID != a.agent || strings.Join(views[0].Rooms, ",") != long {
		t.Fatalf("admissions after the first room ended: %+v", views)
	}
	// When the second room ends too, A's cards go; C stays a contact.
	last, _ := carrierapi.RoomAdmissionDropAtUnix(later)
	advanceTo(clock, last)
	maintain(t, b)
	if b.chat.Cards.Has(a.agent) || !b.chat.Cards.Has(c.agent) || len(admissionsOf(t, b)) != 0 {
		t.Fatalf("after both rooms ended: A %v C %v %+v", b.chat.Cards.Has(a.agent), b.chat.Cards.Has(c.agent),
			admissionsOf(t, b))
	}
}

func TestTheSweepRunsWhenTheCarrierOpens(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	a, b := chatPair(t, clock, relay.URL)
	room := testRoomID("restart")
	requireResult(t, b.daemon.admitRoomCards(room, roomCardOf(a)), carrierapi.ResultApplied, "")
	// The node is down across the room's end; the daemon never forgot.
	b.stopping()
	drop, _ := carrierapi.RoomAdmissionDropAtUnix(b.daemon.roomEndsAt)
	advanceTo(clock, drop)
	reopened := openChatTestNode(t, b.dir, clock, b.agent, relayAgents(), relay.URL)
	if len(admissionsOf(t, reopened)) != 0 {
		t.Fatalf("the open-time sweep left %+v: %s", admissionsOf(t, reopened), reopened.reportText())
	}
	held, err := readPeerCards(filepath.Join(b.dir, relayStateDir, relayChatPeersDir))
	if err != nil {
		t.Fatal(err)
	}
	for _, card := range held {
		if card.AgentID == a.agent {
			t.Fatal("the card of an ended room's member survived the restart")
		}
	}
}

func TestARoomAdmissionKeepsItsFixedEnd(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	agents := relayAgents()
	a := newChatTestNode(t, clock, testSeller, agents, relay.URL)
	b := newChatTestNode(t, clock, testBuyer, agents, relay.URL)
	c := newChatTestNode(t, clock, relayThird, agents, relay.URL)
	room := testRoomID("fixed")
	end := b.daemon.roomEndsAt
	requireResult(t, b.daemon.admitRoomCardsEnding(room, end, roomCardOf(a)), carrierapi.ResultApplied, "")
	// Another end for the same room, for the same or another member, is
	// refused, and the held end stays.
	requireResult(t, b.daemon.admitRoomCardsEnding(room, end+1, roomCardOf(a)), carrierapi.ResultRefused,
		carrierapi.CodeInvalidRequest)
	requireResult(t, b.daemon.admitRoomCardsEnding(room, end+1, roomCardOf(c)), carrierapi.ResultRefused,
		carrierapi.CodeInvalidRequest)
	if b.chat.Cards.Has(c.agent) {
		t.Fatal("an admission under another end stored a card")
	}
	views := admissionsOf(t, b)
	if len(views) != 1 || views[0].RoomEndsAtUnix[room] != end {
		t.Fatalf("the held end changed: %+v", views)
	}
	// The same end re-admits as a no-op and admits a new member.
	response := b.daemon.admitRoomCardsEnding(room, end, roomCardOf(a), roomCardOf(c))
	requireResult(t, response, carrierapi.ResultApplied, "")
	if len(response.RefusedAgentIDs) != 0 || !b.chat.Cards.Has(c.agent) {
		t.Fatalf("a same-end admission: %+v", response)
	}
	// Under the admission lock the member's own record is checked again.
	raw, err := base64.StdEncoding.DecodeString(roomCardOf(a).CardBase64)
	if err != nil {
		t.Fatal(err)
	}
	card, err := b.chat.Cards.verified(context.Background(), raw, a.agent, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.chat.admitRoomCard(room, end+1, card); !errors.Is(err, errRoomEndConflict) {
		t.Fatalf("a member's record took another end: %v", err)
	}
	if views = admissionsOf(t, b); views[0].RoomEndsAtUnix[room] != end {
		t.Fatalf("the member's end changed: %+v", views)
	}
}

func TestARoomAdmissionWithoutAnEndIsRefused(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	a, b := chatPair(t, clock, relay.URL)
	ctx := context.Background()
	for name, end := range map[string]uint64{"no end": 0, "overflowing drop time": ^uint64(0)} {
		response := b.chat.RoomCards(ctx, carrierapi.Request{
			Op: carrierapi.OpRoomCards, RoomID: testRoomID("none"), RoomCardsAction: carrierapi.RoomCardsAdmit,
			RoomEndsAtUnix: end, RoomCards: []carrierapi.RoomCard{roomCardOf(a)},
		})
		requireResult(t, response, carrierapi.ResultRefused, carrierapi.CodeInvalidRequest)
		if b.chat.Cards.Has(a.agent) || len(admissionsOf(t, b)) != 0 {
			t.Fatalf("%s: an admission was stored", name)
		}
	}
	// A forget naming an end is refused too.
	requireResult(t, b.chat.RoomCards(ctx, carrierapi.Request{
		Op: carrierapi.OpRoomCards, RoomID: testRoomID("none"), RoomCardsAction: carrierapi.RoomCardsForget,
		RoomEndsAtUnix: b.daemon.roomEndsAt, ForgetAgentIDs: []string{a.agent},
	}), carrierapi.ResultRefused, carrierapi.CodeInvalidRequest)
}

func TestTheSweepSkipsAnUnreadableRecordAndSweepsTheRest(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	agents := relayAgents()
	a := newChatTestNode(t, clock, testSeller, agents, relay.URL)
	b := newChatTestNode(t, clock, testBuyer, agents, relay.URL)
	c := newChatTestNode(t, clock, relayThird, agents, relay.URL)
	room := testRoomID("unreadable")
	requireResult(t, b.daemon.admitRoomCards(room, roomCardOf(a), roomCardOf(c)), carrierapi.ResultApplied, "")
	broken := filepath.Join(b.dir, relayStateDir, relayChatRoomAdmissionsDir,
		strings.TrimPrefix(c.agent, "agent_")+".json")
	if err := os.WriteFile(broken, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	drop, _ := carrierapi.RoomAdmissionDropAtUnix(b.daemon.roomEndsAt)
	advanceTo(clock, drop)
	maintain(t, b)
	if b.chat.Cards.Has(a.agent) {
		t.Fatal("an unreadable record stopped the sweep of the others")
	}
	if !b.chat.Cards.Has(c.agent) {
		t.Fatal("the sweep dropped the cards of a peer whose record it could not read")
	}
	if !strings.Contains(b.reportText(), "skipped by the sweep") {
		t.Fatalf("the unreadable record was not reported: %s", b.reportText())
	}
}
