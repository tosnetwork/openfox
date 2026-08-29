package capabilitycontrol

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tosnetwork/openfox/pkg/fileutil"
	trusted "github.com/tosnetwork/tos-service-protocol/pkg/trustedcapability"
)

const (
	QuarantineReservationBytes = uint64(64 << 20)
	QuarantineReservationFiles = uint32(4096)
	QuarantineGlobalBytes      = uint64(512 << 20)
	QuarantinePrincipalBytes   = uint64(256 << 20)
	QuarantineSourceBytes      = uint64(256 << 20)
	QuarantineMaxObjects       = 512
	QuarantineDailyRequests    = 32
)

func NewCapabilityAcquisitionID() (string, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return hex.EncodeToString(random), nil
}

type QuarantineReservation struct {
	ID               string `json:"id"`
	Principal        string `json:"principal"`
	SourceID         string `json:"source_id"`
	SourceGeneration uint64 `json:"source_generation"`
	ReservedBytes    uint64 `json:"reserved_bytes"`
	ReservedFiles    uint32 `json:"reserved_files"`
	ExpiresAtUnix    uint64 `json:"expires_at_unix"`
	CommitDigest     string `json:"commit_digest,omitempty"`
	CommitBytes      uint64 `json:"commit_bytes,omitempty"`
	CommitFiles      uint32 `json:"commit_files,omitempty"`
	TemporaryName    string `json:"temporary_name,omitempty"`
	AuthorityPhase   string `json:"authority_phase"`
	PriorRevision    uint64 `json:"prior_revision"`
	NextRevision     uint64 `json:"next_revision"`
}

type QuarantineObjectRecord struct {
	Digest           string `json:"digest"`
	Principal        string `json:"principal"`
	SourceID         string `json:"source_id"`
	SourceGeneration uint64 `json:"source_generation"`
	Bytes            uint64 `json:"bytes"`
	Files            uint32 `json:"files"`
	RetainedAtUnix   uint64 `json:"retained_at_unix"`
	// CommitTransition retains the exact external-authority CAS that made this
	// object durable.  It is deliberately stored with the object rather than
	// only returned to the acquisition caller: a crash or UI/API boundary must
	// not turn successfully quarantined bytes into an inventory dead end.
	CommitTransition CapabilityAcquisitionRequest `json:"commit_transition"`
}

// QuarantineCommitReceipt is the only value accepted by the capability
// inventory registration boundary. The path is derived from the exact external
// CAS transition and is revalidated against the live, exclusively locked
// ledger; callers cannot substitute an arbitrary tree.
type QuarantineCommitReceipt struct {
	SchemaVersion uint16                       `json:"schema_version"`
	LedgerRoot    string                       `json:"ledger_root"`
	RootDevice    uint64                       `json:"root_device"`
	RootInode     uint64                       `json:"root_inode"`
	Transition    CapabilityAcquisitionRequest `json:"transition"`
}

type quarantineSnapshotEntry struct {
	Relative  string
	Mode      os.FileMode
	Directory bool
	Data      []byte
}

type quarantineSnapshot struct {
	Entries []quarantineSnapshotEntry
	Bytes   uint64
	Files   uint32
}

type quarantineLedgerState struct {
	SchemaVersion      uint16                            `json:"schema_version"`
	LedgerID           []byte                            `json:"ledger_id"`
	RootDevice         uint64                            `json:"root_device"`
	RootInode          uint64                            `json:"root_inode"`
	LedgerRevision     uint64                            `json:"ledger_revision"`
	DeletionGeneration uint64                            `json:"deletion_generation"`
	Reservations       map[string]QuarantineReservation  `json:"reservations"`
	Objects            map[string]QuarantineObjectRecord `json:"objects"`
	Tombstones         map[string]uint64                 `json:"tombstones"`
	DailyRequests      map[string]map[string]uint32      `json:"daily_requests"`
	LastRequestDay     string                            `json:"last_request_day,omitempty"`
}

type QuarantineLedger struct {
	root             string
	now              func() time.Time
	mu               sync.Mutex
	lock             *stateLock
	rootHandle       *quarantineRootHandle
	storageRoot      string
	state            quarantineLedgerState
	fence            CapabilityAcquisitionFence
	ownerID, agentID []byte
	closed           bool
	poisoned         bool
}

func OpenQuarantineLedger(root string, now func() time.Time, fence CapabilityAcquisitionFence, ownerID, agentID []byte) (*QuarantineLedger, error) {
	if root == "" || fence == nil || len(ownerID) == 0 || len(agentID) == 0 {
		return nil, errors.New("quarantine root and external acquisition fence are required")
	}
	if now == nil {
		now = time.Now
	}
	clean, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(clean, 0o700); err != nil {
		return nil, err
	}
	rootHandle, err := openQuarantineRootHandle(clean)
	if err != nil {
		return nil, err
	}
	lock, err := acquireStateLock(filepath.Join(rootHandle.storagePath, ".quota-writer.lock"))
	if err != nil {
		_ = rootHandle.close()
		return nil, err
	}
	ledgerID := make([]byte, 16)
	if _, err := rand.Read(ledgerID); err != nil {
		_ = lock.close()
		_ = rootHandle.close()
		return nil, err
	}
	ledger := &QuarantineLedger{root: clean, rootHandle: rootHandle, storageRoot: rootHandle.storagePath, now: now, lock: lock, fence: fence, ownerID: append([]byte(nil), ownerID...), agentID: append([]byte(nil), agentID...), state: quarantineLedgerState{SchemaVersion: 3, LedgerID: ledgerID, RootDevice: rootHandle.device, RootInode: rootHandle.inode,
		Reservations: map[string]QuarantineReservation{}, Objects: map[string]QuarantineObjectRecord{}, Tombstones: map[string]uint64{}, DailyRequests: map[string]map[string]uint32{}}}
	raw, err := os.ReadFile(filepath.Join(ledger.storageRoot, "quarantine-ledger.json"))
	if err == nil {
		if json.Unmarshal(raw, &ledger.state) != nil || ledger.state.SchemaVersion != 3 || len(ledger.state.LedgerID) != 16 || ledger.state.RootDevice != rootHandle.device || ledger.state.RootInode != rootHandle.inode || ledger.state.Reservations == nil || ledger.state.Objects == nil || ledger.state.Tombstones == nil || ledger.state.DailyRequests == nil {
			_ = lock.close()
			_ = rootHandle.close()
			return nil, errors.New("quarantine ledger is corrupt")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		_ = lock.close()
		_ = rootHandle.close()
		return nil, err
	}
	if err := ledger.reconcileLocked(); err != nil {
		_ = lock.close()
		_ = rootHandle.close()
		return nil, err
	}
	return ledger, nil
}

func (l *QuarantineLedger) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	lock := l.lock
	rootHandle := l.rootHandle
	l.lock = nil
	l.rootHandle = nil
	l.mu.Unlock()
	var lockErr error
	if lock != nil {
		lockErr = lock.close()
	}
	return errors.Join(lockErr, rootHandle.close())
}

func (l *QuarantineLedger) Reserve(ctx context.Context, principal, sourceID string, sourceGeneration uint64) (QuarantineReservation, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.poisoned {
		return QuarantineReservation{}, errors.New("quarantine ledger is closed and fenced")
	}
	if err := l.requirePinnedRootLocked(); err != nil {
		return QuarantineReservation{}, err
	}
	if principal == "" || sourceID == "" || len(principal) > 256 || len(sourceID) > 256 || strings.TrimSpace(principal) != principal || strings.TrimSpace(sourceID) != sourceID || sourceGeneration == 0 {
		return QuarantineReservation{}, errors.New("quarantine principal and source provenance are invalid")
	}
	now := l.now().UTC()
	day := now.Format("2006-01-02")
	if l.state.LastRequestDay != "" && day < l.state.LastRequestDay {
		return QuarantineReservation{}, errors.New("quarantine rate-limit clock moved backwards")
	}
	if l.state.DailyRequests[day] == nil {
		l.state.DailyRequests[day] = map[string]uint32{}
	}
	if l.state.DailyRequests[day][principal] >= QuarantineDailyRequests {
		return QuarantineReservation{}, errors.New("quarantine acquisition rate limit reached")
	}
	global, perPrincipal, perSource, objects := l.usageLocked(principal, sourceID)
	if objects >= QuarantineMaxObjects || global+QuarantineReservationBytes > QuarantineGlobalBytes || perPrincipal+QuarantineReservationBytes > QuarantinePrincipalBytes || perSource+QuarantineReservationBytes > QuarantineSourceBytes {
		return QuarantineReservation{}, errors.New("quarantine aggregate quota reached before retrieval")
	}
	acquisitionID, err := NewCapabilityAcquisitionID()
	if err != nil {
		return QuarantineReservation{}, err
	}
	reservation := QuarantineReservation{ID: acquisitionID, Principal: principal, SourceID: sourceID, SourceGeneration: sourceGeneration,
		ReservedBytes: QuarantineReservationBytes, ReservedFiles: QuarantineReservationFiles, ExpiresAtUnix: uint64(now.Add(30 * time.Minute).Unix()),
		AuthorityPhase: "reserve-prepared", PriorRevision: l.state.LedgerRevision, NextRevision: l.state.LedgerRevision + 1}
	l.state.Reservations[reservation.ID] = reservation
	l.state.DailyRequests[day][principal]++
	l.state.LastRequestDay = day
	if err := l.persistLocked(); err != nil {
		delete(l.state.Reservations, reservation.ID)
		l.state.DailyRequests[day][principal]--
		return QuarantineReservation{}, err
	}
	if err := l.fence.AdmitCapabilityAcquisition(ctx, l.acquisitionRequest(reservation, "reserve")); err != nil {
		l.poisoned = true
		return QuarantineReservation{}, errors.Join(errors.New("owner control fenced capability acquisition"), err)
	}
	l.state.LedgerRevision = reservation.NextRevision
	reservation.AuthorityPhase = "reserved"
	l.state.Reservations[reservation.ID] = reservation
	if err := l.persistLocked(); err != nil {
		l.poisoned = true
		return QuarantineReservation{}, err
	}
	return reservation, nil
}

func (l *QuarantineLedger) Abort(reservationID string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.poisoned {
		return errors.New("quarantine ledger is closed and fenced")
	}
	if err := l.requirePinnedRootLocked(); err != nil {
		return err
	}
	if _, ok := l.state.Reservations[reservationID]; !ok {
		return nil
	}
	if reservation := l.state.Reservations[reservationID]; reservation.CommitDigest != "" || reservation.AuthorityPhase != "reserved" {
		return errors.New("quarantine commit is prepared or ambiguous and cannot be aborted")
	}
	delete(l.state.Reservations, reservationID)
	return l.persistLocked()
}

// Commit verifies the exact tree and makes acknowledgement, rename, and
// accounting recoverable under one acquisition identity.
func (l *QuarantineLedger) Commit(ctx context.Context, reservationID, temporaryPath string, digest []byte) (string, QuarantineCommitReceipt, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.poisoned {
		return "", QuarantineCommitReceipt{}, errors.New("quarantine ledger is closed and fenced")
	}
	if err := l.requirePinnedRootLocked(); err != nil {
		return "", QuarantineCommitReceipt{}, err
	}
	reservation, ok := l.state.Reservations[reservationID]
	if !ok || uint64(l.now().UTC().Unix()) >= reservation.ExpiresAtUnix || len(digest) != 32 {
		return "", QuarantineCommitReceipt{}, errors.New("quarantine reservation is absent or expired")
	}
	callerTemporaryName, err := l.directTemporaryName(temporaryPath)
	if err != nil {
		return "", QuarantineCommitReceipt{}, err
	}
	snapshot, err := captureQuarantineSnapshot(l.rootHandle.fd(), callerTemporaryName)
	if err != nil {
		return "", QuarantineCommitReceipt{}, err
	}
	want, err := hashQuarantineSnapshot(snapshot)
	if err != nil || !equalBytes(want, digest) {
		return "", QuarantineCommitReceipt{}, errors.New("quarantine tree digest mismatch")
	}
	bytesUsed, filesUsed := snapshot.Bytes, snapshot.Files
	if bytesUsed > reservation.ReservedBytes || filesUsed > reservation.ReservedFiles {
		return "", QuarantineCommitReceipt{}, errors.New("quarantine candidate exceeds reserved resources")
	}
	key := hex.EncodeToString(digest)
	if _, deleted := l.state.Tombstones[key]; deleted {
		return "", QuarantineCommitReceipt{}, errors.New("quarantine candidate is tombstoned")
	}
	target := filepath.Join(l.storageRoot, key)
	publicTarget := filepath.Join(l.root, key)
	if prior, exists := l.state.Objects[key]; exists {
		retainedDigest, verifyErr := HashTree(target)
		if verifyErr != nil || !equalBytes(retainedDigest, digest) {
			return "", QuarantineCommitReceipt{}, errors.New("existing quarantine object changed")
		}
		if prior.Bytes != bytesUsed || prior.Files != filesUsed {
			return "", QuarantineCommitReceipt{}, errors.New("quarantine digest accounting equivocation")
		}
		// Content-addressed deduplication returns the first durable receipt.  Do
		// not overwrite it with a later acquisition: doing so would invalidate a
		// receipt already handed to another workflow.  The later reservation is
		// local capacity state and can be released without creating a second
		// semantic commit for identical bytes.
		delete(l.state.Reservations, reservation.ID)
		if err := l.persistLocked(); err != nil {
			l.poisoned = true
			return "", QuarantineCommitReceipt{}, err
		}
		if err := os.RemoveAll(filepath.Join(l.storageRoot, callerTemporaryName)); err != nil {
			l.poisoned = true
			return "", QuarantineCommitReceipt{}, err
		}
		return publicTarget, l.receiptForRecord(prior), nil
	}
	if _, err := os.Stat(target); err == nil {
		return "", QuarantineCommitReceipt{}, errors.New("untracked quarantine target exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", QuarantineCommitReceipt{}, err
	}
	temporaryName, err := stageQuarantineSnapshot(l.rootHandle.fd(), l.storageRoot, snapshot)
	if err != nil {
		return "", QuarantineCommitReceipt{}, err
	}
	snapshotPath := filepath.Join(l.storageRoot, temporaryName)
	result, receipt, commitErr := l.prepareAndCommitLocked(ctx, reservation, snapshotPath, temporaryName, key, bytesUsed, filesUsed, target, false)
	if commitErr == nil {
		_ = os.RemoveAll(filepath.Join(l.storageRoot, callerTemporaryName))
	}
	if commitErr == nil {
		result = publicTarget
	}
	return result, receipt, commitErr
}

func (l *QuarantineLedger) prepareAndCommitLocked(ctx context.Context, reservation QuarantineReservation, temporaryPath, temporaryName, key string, bytesUsed uint64, filesUsed uint32, target string, deduplicated bool) (string, QuarantineCommitReceipt, error) {
	reservation.CommitDigest, reservation.CommitBytes, reservation.CommitFiles, reservation.TemporaryName = key, bytesUsed, filesUsed, temporaryName
	reservation.AuthorityPhase, reservation.PriorRevision, reservation.NextRevision = "commit-prepared", l.state.LedgerRevision, l.state.LedgerRevision+1
	l.state.Reservations[reservation.ID] = reservation
	if err := l.persistLocked(); err != nil {
		return "", QuarantineCommitReceipt{}, err
	}
	if err := l.requirePinnedRootLocked(); err != nil {
		return "", QuarantineCommitReceipt{}, err
	}
	if err := l.fence.AdmitCapabilityAcquisition(ctx, l.acquisitionRequest(reservation, "commit")); err != nil {
		l.poisoned = true
		return "", QuarantineCommitReceipt{}, errors.Join(errors.New("owner control fenced capability quarantine commit"), err)
	}
	if deduplicated {
		if err := os.RemoveAll(temporaryPath); err != nil {
			l.poisoned = true
			return "", QuarantineCommitReceipt{}, err
		}
	} else {
		// Publish the exact descriptor-relative, read-only snapshot prepared and
		// fsynced before the authority CAS. The caller staging tree is never used.
		if err := publishStagedQuarantineSnapshot(l.rootHandle.fd(), temporaryName, key); err != nil {
			l.poisoned = true
			return "", QuarantineCommitReceipt{}, err
		}
		publishedDigest, verifyErr := HashTree(target)
		publishedBytes, publishedFiles, usageErr := boundedTreeUsage(target)
		if verifyErr != nil || usageErr != nil || hex.EncodeToString(publishedDigest) != key || publishedBytes != bytesUsed || publishedFiles != filesUsed {
			l.poisoned = true
			return "", QuarantineCommitReceipt{}, errors.New("published quarantine snapshot differs from the acknowledged closure")
		}
	}
	l.state.LedgerRevision = reservation.NextRevision
	transition := l.acquisitionRequest(reservation, "commit")
	l.state.Objects[key] = QuarantineObjectRecord{Digest: key, Principal: reservation.Principal, SourceID: reservation.SourceID,
		SourceGeneration: reservation.SourceGeneration, Bytes: bytesUsed, Files: filesUsed, RetainedAtUnix: uint64(l.now().UTC().Unix()),
		CommitTransition: cloneAcquisitionRequest(transition)}
	delete(l.state.Reservations, reservation.ID)
	if err := l.persistLocked(); err != nil {
		l.poisoned = true
		return "", QuarantineCommitReceipt{}, err
	}
	return target, QuarantineCommitReceipt{SchemaVersion: 1, LedgerRoot: l.root, RootDevice: l.rootHandle.device, RootInode: l.rootHandle.inode, Transition: cloneAcquisitionRequest(transition)}, nil
}

// CommitReceipts returns the durable acquisition-to-inventory handoff values.
// The caller still has to present a receipt to RegisterQuarantined, which
// replays it against the external authority and rehashes the retained bytes.
func (l *QuarantineLedger) CommitReceipts() ([]QuarantineCommitReceipt, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.poisoned {
		return nil, errors.New("quarantine ledger is closed and fenced")
	}
	if err := l.requirePinnedRootLocked(); err != nil {
		return nil, err
	}
	digests := make([]string, 0, len(l.state.Objects))
	for digest := range l.state.Objects {
		digests = append(digests, digest)
	}
	sort.Strings(digests)
	receipts := make([]QuarantineCommitReceipt, 0, len(digests))
	for _, digest := range digests {
		record := l.state.Objects[digest]
		if err := l.validateObjectRecord(record); err != nil {
			l.poisoned = true
			return nil, err
		}
		receipts = append(receipts, l.receiptForRecord(record))
	}
	return receipts, nil
}

func (l *QuarantineLedger) receiptForRecord(record QuarantineObjectRecord) QuarantineCommitReceipt {
	return QuarantineCommitReceipt{SchemaVersion: 1, LedgerRoot: l.root, RootDevice: l.rootHandle.device, RootInode: l.rootHandle.inode,
		Transition: cloneAcquisitionRequest(record.CommitTransition)}
}

func cloneAcquisitionRequest(input CapabilityAcquisitionRequest) CapabilityAcquisitionRequest {
	output := input
	output.OwnerID = append([]byte(nil), input.OwnerID...)
	output.AgentID = append([]byte(nil), input.AgentID...)
	output.LedgerID = append([]byte(nil), input.LedgerID...)
	output.ContentDigest = append([]byte(nil), input.ContentDigest...)
	return output
}

// ValidateQuarantineCommitReceipt replays the exact idempotent authority CAS
// and checks the live ledger plus retained closure. It acquires the same writer
// lock as acquisition, so a partially committed or concurrently replaced
// object can never enter Inventory.
func ValidateQuarantineCommitReceipt(ctx context.Context, receipt QuarantineCommitReceipt, fence CapabilityAcquisitionFence) (string, error) {
	transition := receipt.Transition
	if receipt.SchemaVersion != 1 || receipt.RootDevice == 0 || receipt.RootInode == 0 || fence == nil || !filepath.IsAbs(receipt.LedgerRoot) || filepath.Clean(receipt.LedgerRoot) != receipt.LedgerRoot ||
		transition.SchemaVersion != 1 || transition.Phase != "commit" || len(transition.OwnerID) == 0 || len(transition.AgentID) == 0 || len(transition.LedgerID) != 16 ||
		len(transition.ContentDigest) != 32 || transition.ContentBytes > QuarantineReservationBytes || transition.ContentFiles > QuarantineReservationFiles ||
		transition.NextRevision != transition.PriorRevision+1 {
		return "", errors.New("quarantine commit receipt is incomplete")
	}
	ledger, err := OpenQuarantineLedger(receipt.LedgerRoot, time.Now, fence, transition.OwnerID, transition.AgentID)
	if err != nil {
		return "", err
	}
	defer ledger.Close()
	if ledger.rootHandle.device != receipt.RootDevice || ledger.rootHandle.inode != receipt.RootInode {
		return "", errors.New("quarantine receipt ledger-root identity changed")
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if !equalBytes(ledger.state.LedgerID, transition.LedgerID) || ledger.state.LedgerRevision < transition.NextRevision {
		return "", errors.New("quarantine receipt belongs to a different or rolled-back ledger")
	}
	key := hex.EncodeToString(transition.ContentDigest)
	record, ok := ledger.state.Objects[key]
	if !ok || !acquisitionRequestsEqual(record.CommitTransition, transition) || record.Principal != transition.Principal || record.SourceID != transition.SourceID || record.SourceGeneration != transition.SourceGeneration ||
		record.Bytes != transition.ContentBytes || record.Files != transition.ContentFiles {
		return "", errors.New("quarantine receipt is not retained by the live ledger")
	}
	if err := fence.AdmitCapabilityAcquisition(ctx, transition); err != nil {
		return "", errors.Join(errors.New("quarantine authority did not resolve the exact commit receipt"), err)
	}
	path := filepath.Join(ledger.storageRoot, key)
	digest, err := HashTree(path)
	if err != nil || !equalBytes(digest, transition.ContentDigest) {
		return "", errors.New("quarantine receipt content changed")
	}
	bytesUsed, filesUsed, err := boundedTreeUsage(path)
	if err != nil || bytesUsed != transition.ContentBytes || filesUsed != transition.ContentFiles {
		return "", errors.New("quarantine receipt accounting changed")
	}
	return filepath.Join(ledger.root, key), nil
}

func (l *QuarantineLedger) acquisitionRequest(reservation QuarantineReservation, phase string) CapabilityAcquisitionRequest {
	request := CapabilityAcquisitionRequest{SchemaVersion: 1, OwnerID: append([]byte(nil), l.ownerID...), AgentID: append([]byte(nil), l.agentID...),
		LedgerID: append([]byte(nil), l.state.LedgerID...), AcquisitionID: reservation.ID, Phase: phase, Principal: reservation.Principal,
		SourceID: reservation.SourceID, SourceGeneration: reservation.SourceGeneration, ReservedBytes: reservation.ReservedBytes,
		ReservedFiles: reservation.ReservedFiles, ExpiresAtUnix: reservation.ExpiresAtUnix, PriorRevision: reservation.PriorRevision, NextRevision: reservation.NextRevision}
	if phase == "commit" {
		request.ContentDigest, _ = hex.DecodeString(reservation.CommitDigest)
		request.ContentBytes, request.ContentFiles = reservation.CommitBytes, reservation.CommitFiles
	} else {
		request.ContentDigest = []byte{}
	}
	return request
}

func (l *QuarantineLedger) GarbageCollect(digests []string, expectedGeneration, nextGeneration uint64) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.poisoned {
		return errors.New("quarantine ledger is closed and fenced")
	}
	if err := l.requirePinnedRootLocked(); err != nil {
		return err
	}
	if expectedGeneration != l.state.DeletionGeneration || nextGeneration != expectedGeneration+1 || !sort.StringsAreSorted(digests) {
		return errors.New("quarantine garbage collection authorization is stale or non-canonical")
	}
	for i, digest := range digests {
		if len(digest) != 64 || i > 0 && digest == digests[i-1] {
			return errors.New("quarantine garbage collection digest is invalid")
		}
		if _, ok := l.state.Objects[digest]; !ok {
			return errors.New("quarantine garbage collection target is unknown")
		}
	}
	for _, digest := range digests {
		delete(l.state.Objects, digest)
		l.state.Tombstones[digest] = nextGeneration
	}
	l.state.DeletionGeneration = nextGeneration
	if err := l.persistLocked(); err != nil {
		return err
	}
	for _, digest := range digests {
		if err := os.RemoveAll(filepath.Join(l.storageRoot, digest)); err != nil {
			l.poisoned = true
			return err
		}
	}
	return nil
}

func (l *QuarantineLedger) usageLocked(principal, source string) (global, perPrincipal, perSource uint64, objects int) {
	objects = len(l.state.Objects)
	for _, object := range l.state.Objects {
		global += object.Bytes
		if object.Principal == principal {
			perPrincipal += object.Bytes
		}
		if object.SourceID == source {
			perSource += object.Bytes
		}
	}
	for _, reservation := range l.state.Reservations {
		global += reservation.ReservedBytes
		if reservation.Principal == principal {
			perPrincipal += reservation.ReservedBytes
		}
		if reservation.SourceID == source {
			perSource += reservation.ReservedBytes
		}
	}
	return
}

func (l *QuarantineLedger) reconcileLocked() error {
	now := uint64(l.now().UTC().Unix())
	for id, reservation := range l.state.Reservations {
		if reservation.AuthorityPhase == "reserve-prepared" {
			if err := l.fence.AdmitCapabilityAcquisition(context.Background(), l.acquisitionRequest(reservation, "reserve")); err != nil {
				return errors.Join(errors.New("pending quarantine reservation cannot be authoritatively resolved"), err)
			}
			l.state.LedgerRevision = reservation.NextRevision
			reservation.AuthorityPhase = "reserved"
			l.state.Reservations[id] = reservation
		} else if reservation.AuthorityPhase == "commit-prepared" && reservation.CommitDigest != "" {
			if err := l.recoverCommitLocked(id, reservation); err != nil {
				return err
			}
			continue
		} else if reservation.AuthorityPhase != "reserved" {
			return errors.New("quarantine reservation authority phase is corrupt")
		}
		if now >= reservation.ExpiresAtUnix {
			delete(l.state.Reservations, id)
		}
	}
	entries, err := os.ReadDir(l.storageRoot)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		// The ledger lock is exclusive for the whole acquisition, so no staging
		// directory can still be live when a replacement writer opens. Prepared
		// commits were recovered above. Remove every other private staging tree
		// left by a crash before it can consume quota outside the durable ledger.
		if strings.HasPrefix(entry.Name(), ".") {
			if err := os.RemoveAll(filepath.Join(l.storageRoot, entry.Name())); err != nil {
				return err
			}
			continue
		}
		if len(entry.Name()) != 64 {
			return errors.New("unexpected public directory exists in quarantine")
		}
		if _, ok := l.state.Objects[entry.Name()]; !ok {
			if _, deleted := l.state.Tombstones[entry.Name()]; deleted {
				if err := os.RemoveAll(filepath.Join(l.storageRoot, entry.Name())); err != nil {
					return err
				}
				continue
			}
			return errors.New("untracked content-addressed quarantine object requires authoritative retention recovery")
		}
	}
	for digest, record := range l.state.Objects {
		if err := l.validateObjectRecord(record); err != nil {
			return err
		}
		path := filepath.Join(l.storageRoot, digest)
		actualDigest, digestErr := HashTree(path)
		bytesUsed, filesUsed, err := boundedTreeUsage(path)
		if digestErr != nil || hex.EncodeToString(actualDigest) != digest || err != nil || bytesUsed != record.Bytes || filesUsed != record.Files {
			return errors.New("tracked quarantine object is missing or changed")
		}
	}
	return l.persistLocked()
}

func (l *QuarantineLedger) directTemporaryName(path string) (string, error) {
	clean, err := filepath.Abs(path)
	if err != nil || filepath.Dir(clean) != l.root || !strings.HasPrefix(filepath.Base(clean), ".") {
		return "", errors.New("quarantine candidate must be a private direct-child staging directory")
	}
	return filepath.Base(clean), nil
}

func (l *QuarantineLedger) recoverCommitLocked(id string, reservation QuarantineReservation) error {
	if len(reservation.CommitDigest) != 64 || reservation.TemporaryName == "" || !strings.HasPrefix(reservation.TemporaryName, ".") {
		return errors.New("pending quarantine commit is corrupt")
	}
	target := filepath.Join(l.storageRoot, reservation.CommitDigest)
	// The external sink must resolve an identical acquisition ID idempotently,
	// including after the global fence later closes. A different request is a
	// conflict and leaves the ledger unavailable for manual recovery.
	if err := l.fence.AdmitCapabilityAcquisition(context.Background(), l.acquisitionRequest(reservation, "commit")); err != nil {
		return errors.Join(errors.New("pending quarantine commit cannot be authoritatively resolved"), err)
	}
	if _, err := os.Stat(target); errors.Is(err, os.ErrNotExist) {
		if renameErr := publishStagedQuarantineSnapshot(l.rootHandle.fd(), reservation.TemporaryName, reservation.CommitDigest); renameErr != nil {
			return renameErr
		}
	} else if err != nil {
		return err
	}
	digest, err := HashTree(target)
	if err != nil || hex.EncodeToString(digest) != reservation.CommitDigest {
		return errors.New("recovered quarantine object does not match its committed digest")
	}
	transition := l.acquisitionRequest(reservation, "commit")
	l.state.Objects[reservation.CommitDigest] = QuarantineObjectRecord{Digest: reservation.CommitDigest, Principal: reservation.Principal,
		SourceID: reservation.SourceID, SourceGeneration: reservation.SourceGeneration, Bytes: reservation.CommitBytes,
		Files: reservation.CommitFiles, RetainedAtUnix: uint64(l.now().UTC().Unix()), CommitTransition: cloneAcquisitionRequest(transition)}
	delete(l.state.Reservations, id)
	l.state.LedgerRevision = reservation.NextRevision
	return nil
}

func (l *QuarantineLedger) validateObjectRecord(record QuarantineObjectRecord) error {
	transition := record.CommitTransition
	digest, err := hex.DecodeString(record.Digest)
	if err != nil || len(digest) != sha256.Size || transition.SchemaVersion != 1 || transition.Phase != "commit" ||
		!equalBytes(transition.OwnerID, l.ownerID) || !equalBytes(transition.AgentID, l.agentID) || !equalBytes(transition.LedgerID, l.state.LedgerID) ||
		transition.AcquisitionID == "" || transition.Principal != record.Principal || transition.SourceID != record.SourceID ||
		transition.SourceGeneration != record.SourceGeneration || transition.ContentBytes != record.Bytes || transition.ContentFiles != record.Files ||
		transition.ReservedBytes == 0 || transition.ReservedFiles == 0 || transition.ExpiresAtUnix == 0 || transition.ContentFiles == 0 ||
		transition.ContentBytes > transition.ReservedBytes || transition.ContentFiles > transition.ReservedFiles ||
		!equalBytes(transition.ContentDigest, digest) || transition.NextRevision != transition.PriorRevision+1 {
		return errors.New("quarantine object has no valid durable commit receipt")
	}
	return nil
}

func acquisitionRequestsEqual(left, right CapabilityAcquisitionRequest) bool {
	return left.SchemaVersion == right.SchemaVersion && equalBytes(left.OwnerID, right.OwnerID) && equalBytes(left.AgentID, right.AgentID) &&
		equalBytes(left.LedgerID, right.LedgerID) && left.AcquisitionID == right.AcquisitionID && left.Phase == right.Phase &&
		left.Principal == right.Principal && left.SourceID == right.SourceID && left.SourceGeneration == right.SourceGeneration &&
		left.ReservedBytes == right.ReservedBytes && left.ReservedFiles == right.ReservedFiles && left.ExpiresAtUnix == right.ExpiresAtUnix &&
		equalBytes(left.ContentDigest, right.ContentDigest) && left.ContentBytes == right.ContentBytes && left.ContentFiles == right.ContentFiles &&
		left.PriorRevision == right.PriorRevision && left.NextRevision == right.NextRevision
}

func (l *QuarantineLedger) persistLocked() error {
	raw, err := json.Marshal(l.state)
	if err != nil {
		return err
	}
	return fileutil.WriteFileAtomic(filepath.Join(l.storageRoot, "quarantine-ledger.json"), append(raw, '\n'), 0o600)
}

func (l *QuarantineLedger) requirePinnedRootLocked() error {
	if l.rootHandle == nil || !l.rootHandle.matchesPath(l.root) || l.state.RootDevice != l.rootHandle.device || l.state.RootInode != l.rootHandle.inode {
		l.poisoned = true
		return errors.New("quarantine ledger root identity changed")
	}
	return nil
}

func boundedTreeUsage(root string) (uint64, uint32, error) {
	var bytesUsed uint64
	var files uint32
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		info, err := entry.Info()
		if err != nil || info.Mode()&os.ModeType != 0 && !info.IsDir() {
			return errors.New("quarantine contains unsupported filesystem object")
		}
		files++
		if files > QuarantineReservationFiles {
			return errors.New("quarantine file ceiling exceeded")
		}
		if info.Mode().IsRegular() {
			bytesUsed += uint64(info.Size())
			if bytesUsed > QuarantineReservationBytes {
				return errors.New("quarantine byte ceiling exceeded")
			}
		}
		return nil
	})
	return bytesUsed, files, err
}

func hashQuarantineSnapshot(snapshot quarantineSnapshot) ([]byte, error) {
	entries := make([]trusted.ContentManifestEntryV1, 0, len(snapshot.Entries))
	for _, item := range snapshot.Entries {
		entry := trusted.ContentManifestEntryV1{Path: filepath.ToSlash(item.Relative), Mode: uint32(item.Mode)}
		if item.Directory {
			entry.ObjectType = "directory"
		} else {
			entry.ObjectType = "regular"
			entry.Size = uint64(len(item.Data))
			digest := sha256.Sum256(item.Data)
			entry.ContentDigest = digest[:]
		}
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return trusted.ContentClosureRoot(entries)
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
