package earning

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	openfoxearning "github.com/tosnetwork/openfox/pkg/earning"
)

const (
	inspectTestOwner = "owner:inspect-test"
	inspectTestAgent = "agent:inspect-test"
)

// inspectTestJournal is a Guarantor journal on disk holding one coverage with
// one stored receipt, plus the files a crash leaves behind, which only the
// Provider's own open may remove.
type inspectTestJournal struct {
	directory   string
	receipt     string
	receiptFile string
	wire        []byte
}

func newInspectTestJournal(t *testing.T) inspectTestJournal {
	t.Helper()
	fixture := inspectTestJournal{
		directory: filepath.Join(t.TempDir(), "guarantor"),
		receipt:   "sha256:" + strings.Repeat("d", 64), wire: []byte("a stored receipt"),
	}
	if err := os.Mkdir(fixture.directory, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := openfoxearning.OpenGuarantorJournal(fixture.directory, inspectTestOwner, inspectTestAgent)
	if err != nil {
		t.Fatal(err)
	}
	if err = journal.Close(); err != nil {
		t.Fatal(err)
	}
	// The coverage and its receipt record are written into the document by
	// hand: only a Provider's complete lifecycle stores a receipt.
	documentFile := filepath.Join(fixture.directory, "agent-guarantor-journal.json")
	raw, err := os.ReadFile(documentFile)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err = json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(fixture.wire)
	empty := map[string]any{}
	document["revision"] = 2
	// The journal loads only a document that is, member for member, what it
	// writes, so the coverage starts from every member an empty one has.
	blank, err := json.Marshal(openfoxearning.GuarantorCoveragePosition{})
	if err != nil {
		t.Fatal(err)
	}
	var coverage map[string]any
	if err = json.Unmarshal(blank, &coverage); err != nil {
		t.Fatal(err)
	}
	for member, value := range map[string]any{
		"claims": empty, "decisions": empty, "materialized_payouts": empty, "payout_evidence": empty,
		"payout_requests": empty, "paid_by_obligation": empty, "claim_admission_sequence": empty,
		"claim_admission_log_root": "sha256:" + strings.Repeat("a", 64), "paid_atomic": "7",
		"immutable_evidence": map[string]any{fixture.receipt: map[string]any{
			"content_type": "application/vnd.tos.service.agent-guarantor-claim-admission.v1+cbor",
			"content_size": len(fixture.wire), "content_sha256": "sha256:" + hex.EncodeToString(sum[:]),
		}},
	} {
		coverage[member] = value
	}
	document["coverages"] = map[string]any{"sha256:" + strings.Repeat("c", 64): coverage}
	edited, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(documentFile, edited, 0o600); err != nil {
		t.Fatal(err)
	}
	evidence := filepath.Join(fixture.directory, "immutable-evidence")
	fixture.receiptFile = filepath.Join(evidence, strings.TrimPrefix(fixture.receipt, "sha256:"))
	interruptedReceipt := filepath.Join(evidence, ".tmp-4242-1700000000000000000-0123456789abcdef")
	interruptedDocument := filepath.Join(fixture.directory, ".tmp-4242-17000000000-00ff00ff00ff00ff")
	for path, content := range map[string][]byte{
		fixture.receiptFile: fixture.wire,
		filepath.Join(evidence, strings.Repeat("f", 64)): []byte("a receipt no record names"),
		interruptedReceipt:  []byte("an interrupted receipt write"),
		interruptedDocument: []byte("an interrupted document write"),
	} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return fixture
}

// listing returns every entry of the journal directory with its mode and, for
// a file, its content: two listings are equal only when nothing was created,
// removed or rewritten.
func (fixture inspectTestJournal) listing(t *testing.T) []string {
	t.Helper()
	var entries []string
	err := filepath.WalkDir(fixture.directory, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		line := fmt.Sprintf("%s %s", strings.TrimPrefix(path, fixture.directory), info.Mode())
		if info.Mode().IsRegular() {
			content, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			line += fmt.Sprintf(" %x", content)
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

func TestTheGuarantorCommandOffersItsInspections(t *testing.T) {
	names := map[string]bool{}
	for _, child := range guarantorCommand().Commands() {
		names[child.Name()] = true
		if child.Args == nil {
			t.Errorf("%s takes positional arguments", child.Name())
		}
	}
	for _, name := range []string{"status", "verify-evidence"} {
		if !names[name] {
			t.Errorf("no %s command", name)
		}
	}
}

// TestGuarantorStatusReadsTheJournalWithoutChangingIt: the status summary
// counts what the journal holds and leaves its directory exactly as it found
// it, crash leftovers included.
func TestGuarantorStatusReadsTheJournalWithoutChangingIt(t *testing.T) {
	fixture := newInspectTestJournal(t)
	// The Provider opened the journal once, so its lock file exists; taking
	// the lock creates nothing.
	before := fixture.listing(t)
	report := guarantorStatusReport{
		OfferCounts: map[string]uint64{}, CoverageCounts: map[string]uint64{},
		ClaimCounts: map[string]uint64{}, PaidAtomicByAsset: map[string]string{},
	}
	if err := summarizeGuarantorJournal(fixture.directory, inspectTestOwner, inspectTestAgent, &report); err != nil {
		t.Fatalf("summarize the journal: %v", err)
	}
	if report.JournalRevision != 2 || len(report.CoverageCounts) != 1 || report.PaidAtomicByAsset["::"] != "7" {
		t.Fatalf("the status summary is %#v", report)
	}
	if after := fixture.listing(t); strings.Join(after, "\n") != strings.Join(before, "\n") {
		t.Fatalf("the status summary changed the journal directory:\n got %v\nwant %v", after, before)
	}
}

// TestGuarantorVerifyEvidenceFailsOnAnyBadReceiptAndChangesNothing: the
// integrity check prints its totals only when every stored receipt passed,
// returns an error, which the command line turns into a non-zero exit status,
// for every failure, and never changes the journal directory.
func TestGuarantorVerifyEvidenceFailsOnAnyBadReceiptAndChangesNothing(t *testing.T) {
	fixture := newInspectTestJournal(t)
	verify := func() (string, error) {
		var output bytes.Buffer
		err := verifyGuarantorJournalEvidence(fixture.directory, inspectTestOwner, inspectTestAgent, &output)
		return output.String(), err
	}
	before := fixture.listing(t)
	output, err := verify()
	if err != nil {
		t.Fatalf("verify an intact journal: %v", err)
	}
	var verified guarantorEvidenceVerification
	if err := json.Unmarshal([]byte(output), &verified); err != nil || !verified.Verified || verified.Receipts != 1 ||
		verified.Bytes != uint64(len(fixture.wire)) || verified.JournalRevision != 2 {
		t.Fatalf("the integrity report of an intact journal is %q: %v", output, err)
	}
	if after := fixture.listing(t); strings.Join(after, "\n") != strings.Join(before, "\n") {
		t.Fatalf("the integrity check changed the journal directory:\n got %v\nwant %v", after, before)
	}

	for name, damage := range map[string]func() error{
		"a receipt of the same length and other bytes": func() error {
			changed := append([]byte(nil), fixture.wire...)
			changed[0] ^= 1
			return os.WriteFile(fixture.receiptFile, changed, 0o600)
		},
		"a receipt that lost bytes": func() error { return os.WriteFile(fixture.receiptFile, fixture.wire[:4], 0o600) },
		"a receipt that is gone":    func() error { return os.Remove(fixture.receiptFile) },
	} {
		if err := damage(); err != nil {
			t.Fatal(err)
		}
		damaged := fixture.listing(t)
		output, err := verify()
		if err == nil || output != "" {
			t.Errorf("%s: the integrity check returned %v and printed %q", name, err, output)
		}
		if after := fixture.listing(t); strings.Join(after, "\n") != strings.Join(damaged, "\n") {
			t.Errorf("%s: the failed integrity check changed the journal directory", name)
		}
		if err := os.WriteFile(fixture.receiptFile, fixture.wire, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := verify(); err != nil {
		t.Fatalf("verify the journal after its receipt was restored: %v", err)
	}

	// A journal that cannot be opened is a failure too.
	for name, directory := range map[string]string{
		"no directory configured":         "",
		"a directory that does not exist": filepath.Join(fixture.directory, "missing"),
		"a directory holding no journal":  filepath.Join(fixture.directory, "immutable-evidence"),
	} {
		var printed bytes.Buffer
		if err := verifyGuarantorJournalEvidence(directory, inspectTestOwner, inspectTestAgent, &printed); err == nil ||
			printed.Len() != 0 {
			t.Errorf("%s: the integrity check returned %v and printed %q", name, err, printed.String())
		}
	}
	otherAgentErr := verifyGuarantorJournalEvidence(fixture.directory, inspectTestOwner, "agent:another",
		new(bytes.Buffer))
	if otherAgentErr == nil {
		t.Error("another Agent's journal passed the integrity check")
	}
}
