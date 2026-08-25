package earning

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

func TestOpportunityJournalCommitsBeforeCursorAndReplaysPending(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenOpportunityJournal(directory, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Unix(2_000_000_000, 0).UTC()
	intent := earningIntent(t, now, key)
	digest, _ := commerce.IntentBodyDigest(intent.Body)
	result := CarrierResult{Intent: intent, CarrierID: "carrier:a", Cursor: "seq:1"}
	if err := journal.Record(result, digest, now); err != nil {
		t.Fatal(err)
	}
	if cursor, err := journal.Cursor("carrier:a"); err != nil || cursor != "seq:1" {
		t.Fatalf("cursor=%q err=%v", cursor, err)
	}
	pending, err := journal.Observations("carrier:a", 10)
	if err != nil || len(pending) != 1 || pending[0].Cursor != "seq:1" {
		t.Fatalf("pending=%+v err=%v", pending, err)
	}
	if err := journal.MarkProcessed(digest, "carrier:a"); err != nil {
		t.Fatal(err)
	}
	if pending, err = journal.Observations("carrier:a", 10); err != nil || len(pending) != 0 {
		t.Fatalf("processed observation replayed: %+v err=%v", pending, err)
	}
}
