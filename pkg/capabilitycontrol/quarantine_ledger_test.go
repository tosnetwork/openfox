package capabilitycontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	trusted "github.com/tosnetwork/tos-service-protocol/pkg/trustedcapability"
)

type testAcquisitionFence struct{ rejectCommit bool }

func (f testAcquisitionFence) AdmitCapabilityAcquisition(_ context.Context, request CapabilityAcquisitionRequest) error {
	if f.rejectCommit && request.Phase == "commit" {
		return errors.New("owner exit")
	}
	return nil
}

func TestQuarantineLedgerReservesBeforeRetentionAndReconciles(t *testing.T) {
	root := filepath.Join(t.TempDir(), "quarantine")
	now := time.Unix(100, 0)
	fence := testAcquisitionFence{}
	ledger, err := OpenQuarantineLedger(root, func() time.Time { return now }, fence, []byte("owner"), []byte("agent"))
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := ledger.Reserve(t.Context(), "owner:one", "source:one", 1)
	if err != nil {
		t.Fatal(err)
	}
	candidate := filepath.Join(root, ".candidate")
	if err := os.Mkdir(candidate, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(candidate, "SKILL.md"), []byte("bounded"), 0o600); err != nil {
		t.Fatal(err)
	}
	digest, _ := HashTree(candidate)
	target, receipt, err := ledger.Commit(t.Context(), reservation.ID, candidate, digest)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(target) != bytesToHex(digest) {
		t.Fatal("content-addressed target mismatch")
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	validated, err := ValidateQuarantineCommitReceipt(t.Context(), receipt, fence)
	if err != nil || validated != target {
		t.Fatalf("validate exact quarantine receipt: %q %v", validated, err)
	}
	conflictingReceipt := receipt
	conflictingReceipt.Transition.ContentDigest = bytes.Repeat([]byte{0xee}, sha256.Size)
	if _, err := ValidateQuarantineCommitReceipt(t.Context(), conflictingReceipt, fence); err == nil {
		t.Fatal("quarantine receipt accepted a substituted closure")
	}
	conflictingRoot := receipt
	conflictingRoot.RootInode++
	if _, err := ValidateQuarantineCommitReceipt(t.Context(), conflictingRoot, fence); err == nil {
		t.Fatal("quarantine receipt accepted a substituted ledger root")
	}
	ledger, err = OpenQuarantineLedger(root, func() time.Time { return now }, testAcquisitionFence{}, []byte("owner"), []byte("agent"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatal("tracked candidate was lost")
	}
	receipts, err := ledger.CommitReceipts()
	if err != nil || len(receipts) != 1 || !acquisitionRequestsEqual(receipts[0].Transition, receipt.Transition) {
		t.Fatalf("durable receipt recovery = %#v, %v", receipts, err)
	}
	receipts[0].Transition.OwnerID[0] ^= 0xff
	receipts, err = ledger.CommitReceipts()
	if err != nil || len(receipts) != 1 || !bytes.Equal(receipts[0].Transition.OwnerID, []byte("owner")) {
		t.Fatalf("caller mutated the durable receipt record: %#v, %v", receipts, err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := Open(filepath.Join(t.TempDir(), "inventory"), []byte("owner"), []byte("agent"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	store.acquisitionFence = fence
	if err := store.RegisterQuarantined(t.Context(), Entry{ArtifactKind: "skill", Namespace: "test", Name: "bounded", Version: "1"}, receipts[0], now); err != nil {
		t.Fatalf("register candidate from recovered durable receipt: %v", err)
	}
	snapshot := store.Snapshot()
	if len(snapshot.Entries) != 1 || snapshot.Entries[bytesToHex(digest)].State != StateQuarantined {
		t.Fatalf("candidate did not enter Inventory: %#v", snapshot.Entries)
	}
}

func TestQuarantineReconciliationRehashesTrackedObject(t *testing.T) {
	root := filepath.Join(t.TempDir(), "quarantine")
	fence := &strictAcquisitionFence{}
	ledger, err := OpenQuarantineLedger(root, func() time.Time { return time.Unix(100, 0) }, fence, []byte("owner"), []byte("agent"))
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := ledger.Reserve(t.Context(), "owner:one", "source:one", 1)
	if err != nil {
		t.Fatal(err)
	}
	candidate := filepath.Join(root, ".candidate")
	if err := os.Mkdir(candidate, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(candidate, "SKILL.md")
	if err := os.WriteFile(path, []byte("content-A"), 0o600); err != nil {
		t.Fatal(err)
	}
	digest, _ := HashTree(candidate)
	target, _, err := ledger.Commit(t.Context(), reservation.ID, candidate, digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(target, "SKILL.md"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "SKILL.md"), []byte("content-B"), 0o600); err != nil {
		t.Fatal(err)
	}
	if reopened, err := OpenQuarantineLedger(root, func() time.Time { return time.Unix(101, 0) }, fence, []byte("owner"), []byte("agent")); err == nil {
		_ = reopened.Close()
		t.Fatal("same-size retained-content substitution survived reconciliation")
	}
}

func TestQuarantineLedgerRateAndTombstoneAreFailClosed(t *testing.T) {
	root := filepath.Join(t.TempDir(), "quarantine")
	ledger, err := OpenQuarantineLedger(root, func() time.Time { return time.Unix(100, 0) }, testAcquisitionFence{}, []byte("owner"), []byte("agent"))
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	for i := uint32(0); i < QuarantineDailyRequests; i++ {
		reservation, err := ledger.Reserve(t.Context(), "owner:one", "source:one", uint64(i+1))
		if err != nil {
			// Aggregate reservation quota is intentionally stricter than the
			// request count. Release each reservation to exercise rate limiting.
			t.Fatal(err)
		}
		if err := ledger.Abort(reservation.ID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ledger.Reserve(t.Context(), "owner:one", "source:one", 99); err == nil {
		t.Fatal("daily model acquisition rate was bypassed")
	}
	if err := ledger.GarbageCollect([]string{}, 0, 1); err != nil {
		t.Fatal(err)
	}
}

func TestQuarantineLedgerRejectsDailyQuotaClockRollback(t *testing.T) {
	root := filepath.Join(t.TempDir(), "quarantine")
	now := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)
	ledger, err := OpenQuarantineLedger(root, func() time.Time { return now }, testAcquisitionFence{}, []byte("owner"), []byte("agent"))
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	first, err := ledger.Reserve(t.Context(), "owner:one", "source:one", 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Abort(first.ID); err != nil {
		t.Fatal(err)
	}
	now = now.Add(24 * time.Hour)
	second, err := ledger.Reserve(t.Context(), "owner:one", "source:two", 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Abort(second.ID); err != nil {
		t.Fatal(err)
	}
	now = now.Add(-24 * time.Hour)
	if _, err := ledger.Reserve(t.Context(), "owner:one", "source:rollback", 3); err == nil {
		t.Fatal("wall-clock rollback reopened an earlier daily quota bucket")
	}
}

func TestQuarantineCommitFailsWhenOwnerExitBeginsAfterReservation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "quarantine")
	ledger, err := OpenQuarantineLedger(root, func() time.Time { return time.Unix(100, 0) }, testAcquisitionFence{rejectCommit: true}, []byte("owner"), []byte("agent"))
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	reservation, err := ledger.Reserve(t.Context(), "owner:one", "source:one", 1)
	if err != nil {
		t.Fatal(err)
	}
	candidate := filepath.Join(root, ".candidate")
	if err := os.Mkdir(candidate, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(candidate, "SKILL.md"), []byte("bounded"), 0o600); err != nil {
		t.Fatal(err)
	}
	digest, _ := HashTree(candidate)
	if _, _, err := ledger.Commit(t.Context(), reservation.ID, candidate, digest); err == nil {
		t.Fatal("quarantine commit survived owner-exit fence")
	}
	if _, err := os.Stat(filepath.Join(root, bytesToHex(digest))); !os.IsNotExist(err) {
		t.Fatal("fenced candidate became durable")
	}
}

func TestQuarantineLedgerCloseFencesSupersededWriter(t *testing.T) {
	root := filepath.Join(t.TempDir(), "quarantine")
	old, err := OpenQuarantineLedger(root, func() time.Time { return time.Unix(100, 0) }, testAcquisitionFence{}, []byte("owner"), []byte("agent"))
	if err != nil {
		t.Fatal(err)
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	replacement, err := OpenQuarantineLedger(root, func() time.Time { return time.Unix(100, 0) }, testAcquisitionFence{}, []byte("owner"), []byte("agent"))
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	if _, err := old.Reserve(t.Context(), "owner:old", "source:old", 1); err == nil {
		t.Fatal("superseded quarantine writer remained callable after lock handoff")
	}
	if _, err := replacement.Reserve(t.Context(), "owner:new", "source:new", 1); err != nil {
		t.Fatal(err)
	}
}

func TestQuarantineLedgerFencesRenamedAndReplacedRoot(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "quarantine")
	ledger, err := OpenQuarantineLedger(root, func() time.Time { return time.Unix(100, 0) }, testAcquisitionFence{}, []byte("owner"), []byte("agent"))
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	reservation, err := ledger.Reserve(t.Context(), "owner:one", "source:one", 1)
	if err != nil {
		t.Fatal(err)
	}
	candidate := filepath.Join(root, ".candidate")
	if err := os.Mkdir(candidate, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(candidate, "SKILL.md"), []byte("bounded"), 0o600); err != nil {
		t.Fatal(err)
	}
	digest, err := HashTree(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(root, root+"-moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ledger.Commit(t.Context(), reservation.ID, candidate, digest); err == nil {
		t.Fatal("renamed quarantine root remained writable through a replaced configured path")
	}
	if _, err := ledger.Reserve(t.Context(), "owner:two", "source:two", 2); err == nil {
		t.Fatal("root replacement did not permanently fence the ledger")
	}
}

func TestQuarantineLedgerRecoversPreparedCommitWithoutNewIdentity(t *testing.T) {
	root := filepath.Join(t.TempDir(), "quarantine")
	ledger, err := OpenQuarantineLedger(root, func() time.Time { return time.Unix(100, 0) }, testAcquisitionFence{}, []byte("owner"), []byte("agent"))
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := ledger.Reserve(t.Context(), "owner:one", "source:one", 1)
	if err != nil {
		t.Fatal(err)
	}
	candidate := filepath.Join(root, ".candidate-recovery")
	if err := os.Mkdir(candidate, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(candidate, "SKILL.md"), []byte("bounded"), 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := captureQuarantineSnapshot(ledger.rootHandle.fd(), filepath.Base(candidate))
	if err != nil {
		t.Fatal(err)
	}
	digest, err := hashQuarantineSnapshot(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	temporaryName, err := stageQuarantineSnapshot(ledger.rootHandle.fd(), ledger.storageRoot, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	pending := ledger.state.Reservations[reservation.ID]
	pending.CommitDigest, pending.CommitBytes, pending.CommitFiles, pending.TemporaryName = bytesToHex(digest), snapshot.Bytes, snapshot.Files, temporaryName
	pending.AuthorityPhase, pending.PriorRevision, pending.NextRevision = "commit-prepared", ledger.state.LedgerRevision, ledger.state.LedgerRevision+1
	ledger.state.Reservations[reservation.ID] = pending
	if err := ledger.persistLocked(); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	recovered, err := OpenQuarantineLedger(root, func() time.Time { return time.Unix(101, 0) }, testAcquisitionFence{}, []byte("owner"), []byte("agent"))
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	if _, err := os.Stat(filepath.Join(root, bytesToHex(digest), "SKILL.md")); err != nil {
		t.Fatal("prepared quarantine commit was not recovered")
	}
	if len(recovered.state.Reservations) != 0 || len(recovered.state.Objects) != 1 {
		t.Fatal("recovered quarantine accounting is incomplete")
	}
}

func TestQuarantineLedgerRemovesUnjournaledCrashStaging(t *testing.T) {
	root := filepath.Join(t.TempDir(), "quarantine")
	ledger, err := OpenQuarantineLedger(root, func() time.Time { return time.Unix(100, 0) }, testAcquisitionFence{}, []byte("owner"), []byte("agent"))
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	orphan := filepath.Join(root, ".download-crashed")
	if err := os.Mkdir(orphan, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(orphan, "untrusted"), []byte("bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	recovered, err := OpenQuarantineLedger(root, func() time.Time { return time.Unix(101, 0) }, testAcquisitionFence{}, []byte("owner"), []byte("agent"))
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	if _, err := os.Stat(orphan); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unjournaled crash staging survived exclusive-writer recovery")
	}
}

func bytesToHex(value []byte) string {
	const alphabet = "0123456789abcdef"
	out := make([]byte, len(value)*2)
	for i, b := range value {
		out[i*2], out[i*2+1] = alphabet[b>>4], alphabet[b&15]
	}
	return string(out)
}

type strictAcquisitionFence struct {
	revision uint64
	ledgerID []byte
	accepted map[uint64][sha256.Size]byte
	requests []CapabilityAcquisitionRequest
}

func (f *strictAcquisitionFence) AdmitCapabilityAcquisition(_ context.Context, request CapabilityAcquisitionRequest) error {
	wire, _ := trusted.MarshalBody(request)
	digest := sha256.Sum256(wire)
	if f.accepted == nil {
		f.accepted = map[uint64][sha256.Size]byte{}
	}
	if prior, ok := f.accepted[request.NextRevision]; ok {
		if prior == digest {
			return nil
		}
		return errors.New("acquisition transition equivocation")
	}
	if request.PriorRevision != f.revision || request.NextRevision != f.revision+1 {
		return errors.New("acquisition revision conflict")
	}
	if f.ledgerID == nil {
		f.ledgerID = append([]byte(nil), request.LedgerID...)
	} else if !bytes.Equal(f.ledgerID, request.LedgerID) {
		return errors.New("acquisition ledger identity conflict")
	}
	f.accepted[request.NextRevision] = digest
	f.revision = request.NextRevision
	f.requests = append(f.requests, request)
	return nil
}

func TestQuarantineLedgerCASBindsContentAndRollbackFailsWithoutDeletingEvidence(t *testing.T) {
	root := filepath.Join(t.TempDir(), "quarantine")
	fence := &strictAcquisitionFence{}
	ledger, err := OpenQuarantineLedger(root, func() time.Time { return time.Unix(100, 0) }, fence, []byte("owner"), []byte("agent"))
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := ledger.Reserve(t.Context(), "owner:one", "source:one", 7)
	if err != nil {
		t.Fatal(err)
	}
	rollbackLedger, err := os.ReadFile(filepath.Join(root, "quarantine-ledger.json"))
	if err != nil {
		t.Fatal(err)
	}
	candidate := filepath.Join(root, ".candidate-cas")
	if err := os.Mkdir(candidate, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(candidate, "SKILL.md"), []byte("exact content"), 0o600); err != nil {
		t.Fatal(err)
	}
	digest, _ := HashTree(candidate)
	target, _, err := ledger.Commit(t.Context(), reservation.ID, candidate, digest)
	if err != nil {
		t.Fatal(err)
	}
	if len(fence.requests) != 2 || fence.requests[1].Phase != "commit" || !bytes.Equal(fence.requests[1].ContentDigest, digest) || fence.requests[1].ContentFiles == 0 {
		t.Fatalf("external commit closure is incomplete: %#v", fence.requests)
	}
	mutated := fence.requests[1]
	mutated.ContentDigest = bytes.Repeat([]byte{0xff}, sha256.Size)
	if err := fence.AdmitCapabilityAcquisition(t.Context(), mutated); err == nil {
		t.Fatal("same acquisition transition accepted substituted content")
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "quarantine-ledger.json"), rollbackLedger, 0o600); err != nil {
		t.Fatal(err)
	}
	if reopened, err := OpenQuarantineLedger(root, func() time.Time { return time.Unix(101, 0) }, fence, []byte("owner"), []byte("agent")); err == nil {
		_ = reopened.Close()
		t.Fatal("rolled-back ledger was accepted")
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatal("rollback recovery deleted externally acknowledged evidence")
	}
}
