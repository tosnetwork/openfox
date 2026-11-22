package earning

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// countTestGuarantorDocumentWrites counts the document writes journal makes
// from now on, on top of whatever write function it has.
func countTestGuarantorDocumentWrites(journal *GuarantorJournal) *int {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	writes, underneath := new(int), journal.writeFile
	journal.writeFile = func(root *os.Root, name string, data []byte, perm os.FileMode) error {
		if name == guarantorJournalFile {
			*writes++
		}
		return underneath(root, name, data, perm)
	}
	return writes
}

// TestClosingAnUnconfirmedGuarantorJournalTriesToConfirmIt: a journal closed
// while a commit's durability is unconfirmed writes the committed document
// once more before it lets go. If that fails, Close says so; if it succeeds,
// Close succeeds and the document is the one that was committed. The journal
// is closed in both cases.
func TestClosingAnUnconfirmedGuarantorJournalTriesToConfirmIt(t *testing.T) {
	for _, attempt := range []struct {
		name    string
		fault   journalWriteFault
		confirm bool
	}{
		{"the directory sync still fails", journalWriteFault{documentAfterRename: true}, false},
		{"the document cannot be written", journalWriteFault{document: true}, false},
		{"the document can be written", journalWriteFault{}, true},
	} {
		t.Run(attempt.name, func(t *testing.T) {
			fixture, fault, _, committed := unsyncedTestGuarantorJournal(t)
			*fault = attempt.fault
			writes := countTestGuarantorDocumentWrites(fixture.journal)
			err := fixture.journal.Close()
			if attempt.confirm && err != nil {
				t.Fatalf("closing a journal whose commit could be confirmed: %v", err)
			}
			if !attempt.confirm && !errors.Is(err, ErrGuarantorJournalDurabilityUnconfirmed) {
				t.Fatalf("closing a journal whose commit could not be confirmed: got %v, want the error that says so",
					err)
			}
			if *writes != 1 {
				t.Fatalf("closing the unconfirmed journal wrote the document %d times, want once", *writes)
			}
			now, readErr := os.ReadFile(filepath.Join(fixture.directory, guarantorJournalFile))
			if readErr != nil || !bytes.Equal(now, committed) {
				t.Fatalf("closing left another document than the one committed: %v", readErr)
			}
			// It is closed: nothing is held, and a second close does nothing.
			if err = fixture.journal.Close(); err != nil || *writes != 1 {
				t.Fatalf("closing the closed journal again: err=%v, %d document writes", err, *writes)
			}
			reopened, err := OpenGuarantorJournal(fixture.directory, "owner:guarantor", "agent:guarantor")
			if err != nil {
				t.Fatalf("the closed journal cannot be opened again: %v", err)
			}
			closeGuarantorJournalOnCleanup(t, reopened)
		})
	}
	// A journal with nothing unconfirmed writes nothing when it closes.
	fixture := newJournalDurabilityFixture(t)
	writes := countTestGuarantorDocumentWrites(fixture.journal)
	if err := fixture.journal.Close(); err != nil || *writes != 0 {
		t.Fatalf("closing a confirmed journal: err=%v, %d document writes", err, *writes)
	}
}
