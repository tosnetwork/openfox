package servicebridge

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func privateJournalDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func durableRecord() PurchaseRecord {
	return PurchaseRecord{Key: PurchaseKey{QuoteCommitment: "tvm-cell-sha256:q", EscrowAddress: "0:e"},
		AssetMaster: "0:a", AtomicAmount: 25}
}

func TestFilePurchaseJournalPersistsFundingLeaseAcrossRestart(t *testing.T) {
	directory := privateJournalDirectory(t)
	now := time.Unix(1_900_000_000, 0)
	journal, err := NewFilePurchaseJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	record, err := journal.Begin(durableRecord(), now)
	if err != nil || record.Phase != PhasePrepared {
		t.Fatalf("begin = %+v, %v", record, err)
	}
	acquired, record, err := journal.AcquireFundingLease(record.Key)
	if err != nil || !acquired || record.Phase != PhaseFundingLease {
		t.Fatalf("lease = %t %+v %v", acquired, record, err)
	}
	reopened, err := NewFilePurchaseJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	acquired, record, err = reopened.AcquireFundingLease(record.Key)
	if err != nil || acquired || record.Phase != PhaseFundingLease ||
		ResumeActionFor(record.Phase) != ResumeReconcileNeverRefund {
		t.Fatalf("reopened lease = %t %+v %v", acquired, record, err)
	}
	if reopened.SpentInWindow(now, time.Hour) != 25 {
		t.Fatal("reopened journal lost reserved budget")
	}
}

func TestFilePurchaseJournalRejectsConflictRegressionAndDamagedState(t *testing.T) {
	directory := privateJournalDirectory(t)
	journal, err := NewFilePurchaseJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_900_000_000, 0)
	record, err := journal.Begin(durableRecord(), now)
	if err != nil {
		t.Fatal(err)
	}
	conflict := durableRecord()
	conflict.AtomicAmount++
	if _, err := journal.Begin(conflict, now); !errors.Is(err, ErrJournalConflict) {
		t.Fatalf("conflict = %v", err)
	}
	if err := journal.Advance(record.Key, PhaseIntent); !errors.Is(err, ErrJournalPhase) {
		t.Fatalf("regression = %v", err)
	}
	path := filepath.Join(directory, "purchases.json")
	if err := os.WriteFile(path, []byte(`{"schema":"tos.openfox.purchase-journal.v1","records":[],"authority":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFilePurchaseJournal(directory); err == nil {
		t.Fatal("journal accepted an unknown authority field")
	}
}

func TestFilePurchaseJournalRequiresPrivateDirectoryAndFile(t *testing.T) {
	public := t.TempDir()
	if err := os.Chmod(public, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFilePurchaseJournal(public); err == nil {
		t.Fatal("journal accepted a public directory")
	}
	directory := privateJournalDirectory(t)
	journal, err := NewFilePurchaseJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(journal.path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFilePurchaseJournal(directory); err == nil {
		t.Fatal("journal accepted a public state file")
	}
}
