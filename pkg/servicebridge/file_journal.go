package servicebridge

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const filePurchaseJournalSchema = "tos.openfox.purchase-journal.v1"

type filePurchaseJournalDocument struct {
	Schema  string           `json:"schema"`
	Records []PurchaseRecord `json:"records"`
}

// FilePurchaseJournal is the production single-writer purchase state. Every
// transition is atomically replaced and fsynced before becoming visible in
// memory, preserving the funding lease across process death.
type FilePurchaseJournal struct {
	mu      sync.Mutex
	path    string
	records map[PurchaseKey]PurchaseRecord
}

// NewFilePurchaseJournal opens or creates the journal in an existing clean,
// absolute mode-0700 directory. Existing state must be a mode-0600 regular file
// and pass strict semantic validation.
func NewFilePurchaseJournal(directory string) (*FilePurchaseJournal, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, errors.New("servicebridge: purchase journal directory must be clean and absolute")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return nil, errors.New("servicebridge: purchase journal directory must be owner-private")
	}
	j := &FilePurchaseJournal{path: filepath.Join(directory, "purchases.json"), records: map[PurchaseKey]PurchaseRecord{}}
	if err := j.load(); err != nil {
		return nil, err
	}
	return j, nil
}

func (j *FilePurchaseJournal) load() error {
	info, err := os.Lstat(j.path)
	if errors.Is(err, os.ErrNotExist) {
		return j.persist(j.records)
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		return errors.New("servicebridge: purchase journal file must be owner-only")
	}
	raw, err := os.ReadFile(j.path)
	if err != nil || len(raw) == 0 || len(raw) > 16<<20 {
		return errors.New("servicebridge: read purchase journal")
	}
	var document filePurchaseJournalDocument
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&document) != nil || document.Schema != filePurchaseJournalSchema {
		return errors.New("servicebridge: invalid purchase journal")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("servicebridge: trailing purchase journal data")
	}
	for _, record := range document.Records {
		if !validPurchaseRecord(record) {
			return errors.New("servicebridge: invalid purchase journal record")
		}
		if _, exists := j.records[record.Key]; exists {
			return errors.New("servicebridge: duplicate purchase journal record")
		}
		j.records[record.Key] = record
	}
	return nil
}

func (j *FilePurchaseJournal) Begin(rec PurchaseRecord, now time.Time) (PurchaseRecord, error) {
	if rec.Key.QuoteCommitment == "" || rec.Key.EscrowAddress == "" || rec.AssetMaster == "" || rec.AtomicAmount == 0 ||
		now.IsZero() || now.UTC().Unix() <= 0 {
		return PurchaseRecord{}, ErrJournalPhase
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if existing, ok := j.records[rec.Key]; ok {
		if existing.AssetMaster != rec.AssetMaster || existing.AtomicAmount != rec.AtomicAmount {
			return PurchaseRecord{}, ErrJournalConflict
		}
		return existing, nil
	}
	rec.Phase = PhasePrepared
	rec.ClaimedUnix = now.UTC().Unix()
	updated := clonePurchaseRecords(j.records)
	updated[rec.Key] = rec
	if err := j.persist(updated); err != nil {
		return PurchaseRecord{}, err
	}
	j.records = updated
	return rec, nil
}

func (j *FilePurchaseJournal) AcquireFundingLease(key PurchaseKey) (bool, PurchaseRecord, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	record, ok := j.records[key]
	if !ok {
		return false, PurchaseRecord{}, ErrJournalMissing
	}
	if !CanAcquireFundingLease(record.Phase) {
		return false, record, nil
	}
	record.Phase = PhaseFundingLease
	updated := clonePurchaseRecords(j.records)
	updated[key] = record
	if err := j.persist(updated); err != nil {
		return false, PurchaseRecord{}, err
	}
	j.records = updated
	return true, record, nil
}

func (j *FilePurchaseJournal) Advance(key PurchaseKey, next Phase) error {
	if !next.valid() {
		return ErrJournalPhase
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	record, ok := j.records[key]
	if !ok {
		return ErrJournalMissing
	}
	if !CanAdvance(record.Phase, next) {
		return ErrJournalPhase
	}
	record.Phase = next
	updated := clonePurchaseRecords(j.records)
	updated[key] = record
	if err := j.persist(updated); err != nil {
		return err
	}
	j.records = updated
	return nil
}

func (j *FilePurchaseJournal) Get(key PurchaseKey) (PurchaseRecord, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	record, ok := j.records[key]
	return record, ok
}

func (j *FilePurchaseJournal) SpentInWindow(now time.Time, window time.Duration) uint64 {
	cutoff := now.Add(-window).Unix()
	j.mu.Lock()
	defer j.mu.Unlock()
	var total uint64
	for _, record := range j.records {
		if record.ClaimedUnix < cutoff {
			continue
		}
		if math.MaxUint64-total < record.AtomicAmount {
			return math.MaxUint64
		}
		total += record.AtomicAmount
	}
	return total
}

func (j *FilePurchaseJournal) persist(records map[PurchaseKey]PurchaseRecord) error {
	document := filePurchaseJournalDocument{Schema: filePurchaseJournalSchema,
		Records: make([]PurchaseRecord, 0, len(records))}
	for _, record := range records {
		document.Records = append(document.Records, record)
	}
	sort.Slice(document.Records, func(left, right int) bool {
		if document.Records[left].Key.QuoteCommitment == document.Records[right].Key.QuoteCommitment {
			return document.Records[left].Key.EscrowAddress < document.Records[right].Key.EscrowAddress
		}
		return document.Records[left].Key.QuoteCommitment < document.Records[right].Key.QuoteCommitment
	})
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	directory := filepath.Dir(j.path)
	temporary, err := os.CreateTemp(directory, ".purchase-journal-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, j.path); err != nil {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func validPurchaseRecord(record PurchaseRecord) bool {
	return record.Key.QuoteCommitment != "" && record.Key.EscrowAddress != "" && record.AssetMaster != "" &&
		record.AtomicAmount != 0 && record.ClaimedUnix > 0 && record.Phase.valid()
}

func clonePurchaseRecords(records map[PurchaseKey]PurchaseRecord) map[PurchaseKey]PurchaseRecord {
	result := make(map[PurchaseKey]PurchaseRecord, len(records))
	for key, record := range records {
		result[key] = record
	}
	return result
}

var _ PurchaseJournal = (*FilePurchaseJournal)(nil)
