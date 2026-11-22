package servicebridge

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
)

// One record that fails to load does not stop carriage to any peer: it is
// reported once and counts as a stored envelope towards every peer's cap.
func TestAnUnreadableChatRecordDoesNotStopCarriageAndCountsTowardsTheCap(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	a, b := chatPair(t, clock, relay.URL)
	corrupt := filepath.Join(a.dir, relayStateDir, relayChatOutboxDir, strings.Repeat("0", 64)+".json")
	if err := os.WriteFile(corrupt, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	for index := range ChatPeerEnvelopeCap - 1 {
		requireResult(t, a.daemon.carry(b.agent, chatEventID(fmt.Sprint("m", index)), 1), carrierapi.ResultCarried, "")
	}
	// The unreadable record takes the last slot.
	requireResult(t, a.daemon.carry(b.agent, chatEventID("over"), 1), carrierapi.ResultRefused, carrierapi.CodePeerCap)
	if got := strings.Count(a.reportText(), "is unreadable"); got != 1 {
		t.Fatalf("the unreadable record was reported %d times: %s", got, a.reportText())
	}
	views, err := ReadChatOutbox(filepath.Join(a.dir, relayStateDir, relayChatOutboxDir))
	if err != nil {
		t.Fatalf("the status read failed on the unreadable record: %v", err)
	}
	unreadable := 0
	for _, view := range views {
		if view.Unreadable != "" {
			unreadable++
		}
	}
	if unreadable != 1 || len(views) != ChatPeerEnvelopeCap {
		t.Fatalf("the status lists %d unreadable of %d records", unreadable, len(views))
	}
}
