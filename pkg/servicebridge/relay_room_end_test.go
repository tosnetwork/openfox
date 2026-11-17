package servicebridge

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
)

// A room's end is fixed for its life: whatever order admissions arrive in,
// the store never holds two ends for one room.

// Two concurrent admissions of one new room, for two members, under two
// ends: at most one is applied.
func TestConcurrentAdmissionsCannotSplitARoomsEnd(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	agents := relayAgents()
	a := newChatTestNode(t, clock, testSeller, agents, relay.URL)
	b := newChatTestNode(t, clock, testBuyer, agents, relay.URL)
	c := newChatTestNode(t, clock, relayThird, agents, relay.URL)
	end := b.daemon.roomEndsAt
	cards := []carrierapi.RoomCard{roomCardOf(a), roomCardOf(c)}
	split := 0
	const rounds = 40
	for round := range rounds {
		room := testRoomID("race" + string(rune('a'+round%26)) + string(rune('a'+round/26)))
		var wg sync.WaitGroup
		results := make([]carrierapi.Response, 2)
		start := make(chan struct{})
		for index := range cards {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				results[index] = b.chat.RoomCards(context.Background(), carrierapi.Request{
					Op: carrierapi.OpRoomCards, RoomID: room, RoomCardsAction: carrierapi.RoomCardsAdmit,
					RoomEndsAtUnix: end + uint64(index), RoomCards: []carrierapi.RoomCard{cards[index]},
				})
			}()
		}
		close(start)
		wg.Wait()
		if results[0].Result == carrierapi.ResultApplied && results[1].Result == carrierapi.ResultApplied {
			split++
		}
	}
	if split > 0 {
		t.Fatalf("%d of %d rounds stored two ends for one room", split, rounds)
	}
}

// A shorter end than the room's held one is refused, for a new member and
// for the member that holds it.
func TestAShorterEndIsRefusedForAnotherMember(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	agents := relayAgents()
	a := newChatTestNode(t, clock, testSeller, agents, relay.URL)
	b := newChatTestNode(t, clock, testBuyer, agents, relay.URL)
	c := newChatTestNode(t, clock, relayThird, agents, relay.URL)
	room := testRoomID("shorter")
	end := b.daemon.roomEndsAt
	requireResult(t, b.daemon.admitRoomCardsEnding(room, end, roomCardOf(a)), carrierapi.ResultApplied, "")
	requireResult(t, b.daemon.admitRoomCardsEnding(room, end-1, roomCardOf(c)), carrierapi.ResultRefused,
		carrierapi.CodeInvalidRequest)
	requireResult(t, b.daemon.admitRoomCardsEnding(room, end-1, roomCardOf(a)), carrierapi.ResultRefused,
		carrierapi.CodeInvalidRequest)
}

// An unreadable record of one peer does not hide the end another peer's
// record holds.
func TestAnUnreadableRecordDoesNotHideTheHeldEnd(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	agents := relayAgents()
	a := newChatTestNode(t, clock, testSeller, agents, relay.URL)
	b := newChatTestNode(t, clock, testBuyer, agents, relay.URL)
	c := newChatTestNode(t, clock, relayThird, agents, relay.URL)
	room := testRoomID("hidden")
	end := b.daemon.roomEndsAt
	requireResult(t, b.daemon.admitRoomCardsEnding(room, end, roomCardOf(a)), carrierapi.ResultApplied, "")
	broken := filepath.Join(b.dir, relayStateDir, relayChatRoomAdmissionsDir, strings.Repeat("0", 64)+".json")
	if err := os.WriteFile(broken, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	requireResult(t, b.daemon.admitRoomCardsEnding(room, end+1, roomCardOf(c)), carrierapi.ResultRefused,
		carrierapi.CodeInvalidRequest)
}
