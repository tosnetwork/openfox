package earning

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/openfox/pkg/fileutil"
)

// listTestDirectory returns every entry under directory with its kind, size
// and, for a regular file, its content, so two listings compare equal only
// when nothing was created, removed or rewritten.
func listTestDirectory(t *testing.T, directory string) []string {
	t.Helper()
	var entries []string
	err := filepath.WalkDir(directory, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		line := fmt.Sprintf("%s %s %d", strings.TrimPrefix(path, directory), info.Mode(), info.Size())
		if info.Mode().IsRegular() {
			content, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			line += fmt.Sprintf(" %x", content)
		}
		if entry.IsDir() {
			// A directory's size is the file system's business.
			line = fmt.Sprintf("%s %s", strings.TrimPrefix(path, directory), info.Mode())
		}
		entries = append(entries, line)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(entries)
	return entries
}

// TestRetriedGuarantorEvidenceWriteSyncsItsDirectory: a receipt file whose
// write was renamed into place and then failed its directory sync fails its
// commit. The retry finds the file in place and does not write it again, so
// it syncs the evidence directory itself before the document that names the
// file is written, and fails without writing the document when that sync
// fails too.
func TestRetriedGuarantorEvidenceWriteSyncsItsDirectory(t *testing.T) {
	digest := func(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }
	agreement, receipt := digest("c"), digest("d")
	wire := []byte("a receipt whose first write lost its directory sync")
	journal, directory := openTestGuarantorJournal(t)
	documentFile := filepath.Join(directory, guarantorJournalFile)
	receiptFile := filepath.Join(directory, guarantorEvidenceDirectory, strings.TrimPrefix(receipt, "sha256:"))

	var steps []string
	failEvidenceSync, failDirectorySync := true, false
	journal.mu.Lock()
	journal.writeFile = func(root *os.Root, name string, data []byte, perm os.FileMode) error {
		steps = append(steps, "write "+name)
		if err := fileutil.WriteFileAtomicRoot(root, name, data, perm); err != nil {
			return err
		}
		if name != guarantorJournalFile && failEvidenceSync {
			return fmt.Errorf("%w: %w", fileutil.ErrReplacedNotSynced, errInjectedJournalWrite)
		}
		return nil
	}
	journal.syncDirectory = func(root *os.Root, name string) error {
		steps = append(steps, "sync "+name)
		if failDirectorySync {
			return errInjectedJournalWrite
		}
		return fileutil.SyncDirectoryRoot(root, name)
	}
	journal.mu.Unlock()
	before, err := os.ReadFile(documentFile)
	if err != nil {
		t.Fatal(err)
	}
	documentUnchanged := func(when string) {
		t.Helper()
		now, err := os.ReadFile(documentFile)
		if err != nil || !bytes.Equal(now, before) {
			t.Fatalf("%s: the document was written although its receipt's directory entry is not durable: %v", when, err)
		}
	}

	// The first attempt renames the receipt file into place and loses the sync.
	if err := commitTestGuarantorEvidence(t, journal, agreement, receipt, wire); !errors.Is(err, fileutil.ErrReplacedNotSynced) {
		t.Fatalf("the first attempt: got %v, want the failed directory sync", err)
	}
	documentUnchanged("after the first attempt")
	if stored, err := os.ReadFile(receiptFile); err != nil || !bytes.Equal(stored, wire) {
		t.Fatalf("the first attempt did not leave the receipt file in place: %v", err)
	}

	// The retry finds the file and must sync its directory; that sync fails.
	steps, failEvidenceSync, failDirectorySync = nil, false, true
	if err := commitTestGuarantorEvidence(t, journal, agreement, receipt, wire); !errors.Is(err, errInjectedJournalWrite) {
		t.Fatalf("the retry with a failing directory sync: got %v, want the injected failure; steps %v", err, steps)
	}
	documentUnchanged("after the retry whose directory sync failed")
	if want := []string{"sync " + guarantorEvidenceDirectory}; !sameJSON(steps, want) {
		t.Fatalf("the retry with a failing directory sync did %v, want %v", steps, want)
	}

	// The retry whose sync succeeds writes the document after it.
	steps, failDirectorySync = nil, false
	if err := commitTestGuarantorEvidence(t, journal, agreement, receipt, wire); err != nil {
		t.Fatalf("the retry: %v", err)
	}
	if want := []string{"sync " + guarantorEvidenceDirectory, "write " + guarantorJournalFile}; !sameJSON(steps, want) {
		t.Fatalf("the retry did %v, want %v: the evidence directory is synced before the document is written", steps, want)
	}
	assertGuarantorJournalMemoryIsOnDisk(t, journal, directory, "after the retry")
	if _, err := journal.VerifyStoredEvidence(); err != nil {
		t.Fatalf("the receipt committed on the retry fails its integrity check: %v", err)
	}

	// A receipt written for the first time is synced by its own atomic write.
	steps = nil
	other := digest("e")
	if err := commitTestGuarantorEvidence(t, journal, agreement, other, []byte("a receipt written once")); err != nil {
		t.Fatal(err)
	}
	if want := []string{"write " + filepath.Join(guarantorEvidenceDirectory, strings.TrimPrefix(other, "sha256:")),
		"write " + guarantorJournalFile}; !sameJSON(steps, want) {
		t.Fatalf("a first write did %v, want %v", steps, want)
	}
}

// TestInspectingAGuarantorJournalChangesNothing: a journal opened read-only
// loads like the writer's and serves its receipts, and nothing in its
// directory is created, removed or rewritten: the crash leftovers the
// writer's open sweeps stay where they are, and every commit is refused. A
// directory holding no journal is not given one.
func TestInspectingAGuarantorJournalChangesNothing(t *testing.T) {
	digest := func(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }
	agreement, receipt := digest("c"), digest("d")
	wire := []byte("a receipt its coverage names")
	journal, directory := openTestGuarantorJournal(t)
	if err := commitTestGuarantorEvidence(t, journal, agreement, receipt, wire); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	evidence := filepath.Join(directory, guarantorEvidenceDirectory)
	leftovers := []string{filepath.Join(evidence, strings.Repeat("f", 64)),
		filepath.Join(evidence, ".tmp-4242-1700000000000000000-0123456789abcdef"),
		filepath.Join(directory, ".tmp-4242-1700-00ff00ff00ff00ff")}
	for _, leftover := range leftovers {
		if err := os.WriteFile(leftover, []byte("leftover"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	before := listTestDirectory(t, directory)

	inspected, err := OpenGuarantorJournalReadOnly(directory, "owner:guarantor", "agent:guarantor")
	if err != nil {
		t.Fatalf("open the journal read-only: %v", err)
	}
	closeGuarantorJournalOnCleanup(t, inspected)
	revision, _, coverages := testGuarantorSnapshot(t, inspected)
	if revision != 2 || len(coverages) != 1 {
		t.Fatalf("the journal opened read-only holds revision %d and %d coverages", revision, len(coverages))
	}
	if report, err := inspected.VerifyStoredEvidence(); err != nil || report.Receipts != 1 || report.Bytes != uint64(len(wire)) {
		t.Fatalf("the integrity check of a journal opened read-only: report=%#v err=%v", report, err)
	}
	if err := commitTestGuarantorEvidence(t, inspected, agreement, digest("e"), []byte("another receipt")); !errors.Is(err, errGuarantorJournalReadOnly) {
		t.Fatalf("a commit to a journal opened read-only: got %v, want its refusal", err)
	}
	if _, err := inspected.BeginAdmission(digest("8"), digest("1"), digest("2"),
		time.Unix(2_000_000_000, 0).UTC()); !errors.Is(err, errGuarantorJournalReadOnly) {
		t.Fatalf("an admission in a journal opened read-only: got %v, want its refusal", err)
	}
	if err := inspected.Close(); err != nil {
		t.Fatal(err)
	}
	if after := listTestDirectory(t, directory); !sameJSON(after, before) {
		t.Fatalf("inspecting the journal changed its directory:\n got %v\nwant %v", after, before)
	}

	// The writer's open is what sweeps.
	writer, err := OpenGuarantorJournal(directory, "owner:guarantor", "agent:guarantor")
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	for _, leftover := range leftovers {
		if _, err := os.Lstat(leftover); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("the writer's open did not remove the crash leftover %s: %v", leftover, err)
		}
	}

	// No journal is created by an inspection.
	empty := filepath.Join(t.TempDir(), "guarantor")
	if err := os.Mkdir(empty, 0o700); err != nil {
		t.Fatal(err)
	}
	if opened, err := OpenGuarantorJournalReadOnly(empty, "owner:guarantor", "agent:guarantor"); err == nil {
		_ = opened.Close()
		t.Fatal("a directory holding no journal was opened read-only")
	}
	if entries := listTestDirectory(t, empty); len(entries) != 1 {
		t.Fatalf("inspecting a directory holding no journal created %v", entries)
	}
}

// TestAnUnconfirmedGuarantorJournalDoesNothingElse: while a commit's
// durability is unconfirmed, every other call fails with the error that says
// nothing was done, distinct from the one that reports a commit, and changes
// nothing; a snapshot returns nothing. Confirming writes the same document
// again and commits nothing, and the journal then works as before.
func TestAnUnconfirmedGuarantorJournalDoesNothingElse(t *testing.T) {
	fixture, fault, run, committed := unsyncedTestGuarantorJournal(t)
	journal, documentFile := fixture.journal, filepath.Join(fixture.directory, guarantorJournalFile)
	operations := fixture.operations(t)
	refused := func(when string, err error) {
		t.Helper()
		if !errors.Is(err, ErrGuarantorJournalDurabilityUnconfirmed) || errors.Is(err, ErrGuarantorJournalCommittedNotSynced) {
			t.Fatalf("%s: got %v, want only the error that says nothing was done", when, err)
		}
		now, readErr := os.ReadFile(documentFile)
		if readErr != nil || !bytes.Equal(now, committed) {
			t.Fatalf("%s: the document changed: %v", when, readErr)
		}
	}
	for _, failing := range []journalWriteFault{{documentAfterRename: true}, {document: true}} {
		*fault = failing
		refused("repeating the unconfirmed call", run())
		for _, operation := range operations {
			refused(operation.name+" on an unconfirmed journal", operation.run())
		}
		refused("confirming while the document cannot be written", journal.ConfirmDurable())
		revision, offers, coverages, snapshotErr := journal.Snapshot()
		refused("a snapshot of an unconfirmed journal", snapshotErr)
		if revision != 0 || offers != nil || coverages != nil {
			t.Fatalf("an unconfirmed journal handed out a snapshot at revision %d", revision)
		}
		for _, reader := range fixture.readers(t) {
			refused(reader.name+" on an unconfirmed journal", reader.run())
		}
		// An inspection of what is on disk still answers, and confirms nothing.
		if _, err := journal.VerifyStoredEvidence(); err != nil {
			t.Fatalf("the integrity check of an unconfirmed journal: %v", err)
		}
		refused("a second snapshot, after the integrity check", func() error {
			_, _, _, err := journal.Snapshot()
			return err
		}())
	}
	*fault = journalWriteFault{}
	if err := journal.ConfirmDurable(); err != nil {
		t.Fatalf("confirm the commit: %v", err)
	}
	if now, err := os.ReadFile(documentFile); err != nil || !bytes.Equal(now, committed) {
		t.Fatalf("confirming did not leave exactly the committed document: %v", err)
	}
	if err := journal.ConfirmDurable(); err != nil {
		t.Fatalf("confirm a journal with nothing unconfirmed: %v", err)
	}
	revision, _, _ := testGuarantorSnapshot(t, journal)
	for _, reader := range fixture.readers(t) {
		err := reader.run()
		if errors.Is(err, ErrGuarantorJournalDurabilityUnconfirmed) || (reader.answers && err != nil) {
			t.Fatalf("%s after the commit was confirmed: %v", reader.name, err)
		}
	}
	for _, operation := range operations {
		if err := operation.run(); err != nil {
			t.Fatalf("%s after the commit was confirmed: %v", operation.name, err)
		}
	}
	if after, _, _ := testGuarantorSnapshot(t, journal); after != revision+uint64(len(operations)) {
		t.Fatalf("the journal moved from revision %d to %d over %d commits", revision, after, len(operations))
	}
	reopened := reopenTestGuarantorJournal(t, journal, fixture.directory)
	if after, _, _ := testGuarantorSnapshot(t, reopened); after != revision+uint64(len(operations)) {
		t.Fatalf("the reloaded journal is at revision %d", after)
	}
}
