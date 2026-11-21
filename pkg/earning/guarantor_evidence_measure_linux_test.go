package earning

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestMeasureGuarantorEvidenceIntegrityAtTheReceiptCap fills one coverage's
// evidence store to the per-coverage receipt cap with receipts of the measured
// decision-admission size, about 4.4 GB, and reports what opening the journal
// costs with its length checks and what the full integrity check costs, with
// the receipt data in the page cache and after asking the kernel to drop it.
// It only measures; it runs when OPENFOX_MEASURE_GUARANTOR_EVIDENCE is set,
// with TMPDIR on the disk to be measured.
func TestMeasureGuarantorEvidenceIntegrityAtTheReceiptCap(t *testing.T) {
	if os.Getenv("OPENFOX_MEASURE_GUARANTOR_EVIDENCE") == "" {
		t.Skip("set OPENFOX_MEASURE_GUARANTOR_EVIDENCE=1 to write and hash a full evidence store of about 4.4 GB")
	}
	const measuredReceiptBytes = 1_069_384 // measured ML-DSA-44 decision admission receipt
	const receiptsPerCommit = 64
	agreement := "sha256:" + strings.Repeat("c", 64)
	claimID := "sha256:" + strings.Repeat("b", 64)
	journal, directory := openTestGuarantorJournal(t)

	started := time.Now()
	for first := 0; first < maximumGuarantorStoredEvidenceReceipts; first += receiptsPerCommit {
		journal.mu.Lock()
		next, err := journal.workingCopy()
		if err != nil {
			journal.mu.Unlock()
			t.Fatal(err)
		}
		position, found := next.Coverages[agreement]
		if !found {
			position = testCoverageWithClaim(claimID)
			position.RevisionEpochs = map[string]GuarantorRevisionEpochState{claimID: testFrozenEpoch()}
		}
		for index := first; index < first+receiptsPerCommit && index < maximumGuarantorStoredEvidenceReceipts; index++ {
			// Varied bytes, so nothing in the stack can compress or deduplicate them.
			wire := make([]byte, measuredReceiptBytes)
			for offset := range wire {
				wire[offset] = byte(offset*131 + index*7)
			}
			if err := storeImmutableWire(&position, guarantorDecisionAdmissionMediaType,
				fmt.Sprintf("sha256:%064x", index+1), wire); err != nil {
				journal.mu.Unlock()
				t.Fatalf("receipt %d: %v", index+1, err)
			}
		}
		next.Coverages[agreement] = position
		next.Revision++
		err = journal.commit(next)
		journal.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("filled the store: %d receipts of %d bytes in %s", maximumGuarantorStoredEvidenceReceipts,
		measuredReceiptBytes, time.Since(started).Round(time.Millisecond))

	reopen := func(state string) {
		t.Helper()
		if err := journal.Close(); err != nil {
			t.Fatal(err)
		}
		opened := time.Now()
		reopened, err := OpenGuarantorJournal(directory, "owner:guarantor", "agent:guarantor")
		elapsed := time.Since(opened)
		if err != nil {
			t.Fatal(err)
		}
		closeGuarantorJournalOnCleanup(t, reopened)
		journal = reopened
		t.Logf("open with length checks and the crash sweep, %s: %s", state, elapsed.Round(time.Microsecond))
	}
	verify := func(state string) {
		t.Helper()
		checked := time.Now()
		report, err := journal.VerifyStoredEvidence()
		elapsed := time.Since(checked)
		if err != nil || report.Receipts != maximumGuarantorStoredEvidenceReceipts {
			t.Fatalf("integrity check: report=%#v err=%v", report, err)
		}
		t.Logf("full integrity check, %s: %d receipts, %d bytes in %s (%.0f MB/s)", state, report.Receipts,
			report.Bytes, elapsed.Round(time.Millisecond), float64(report.Bytes)/1e6/elapsed.Seconds())
	}
	// evict asks the kernel to drop every receipt file's cached pages. The
	// files were synced when they were written, so their pages are clean.
	evict := func() {
		t.Helper()
		evidence := filepath.Join(directory, guarantorEvidenceDirectory)
		entries, err := os.ReadDir(evidence)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			file, err := os.Open(filepath.Join(evidence, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			adviseErr := unix.Fadvise(int(file.Fd()), 0, 0, unix.FADV_DONTNEED)
			closeErr := file.Close()
			if adviseErr != nil || closeErr != nil {
				t.Fatalf("drop cached pages of %s: %v %v", entry.Name(), adviseErr, closeErr)
			}
		}
	}

	reopen("receipt data in the page cache")
	verify("receipt data in the page cache")
	evict()
	reopen("receipt data dropped from the page cache")
	verify("receipt data dropped from the page cache")
	verify("receipt data read back into the page cache")
}
