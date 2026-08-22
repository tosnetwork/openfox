package opportunity

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/tosnetwork/openfox/pkg/fileutil"
)

const (
	journalSchema   = "tos.openfox.opportunity-journal.v1"
	journalFile     = "opportunities.json"
	maxJournalBytes = 16 << 20
)

type Phase string

const (
	PhaseDiscovered         Phase = "discovered"
	PhaseVerified           Phase = "finalized-verified"
	PhaseAssessed           Phase = "locally-assessed"
	PhaseQuoteRequested     Phase = "quote-requested"
	PhaseQuoteVerified      Phase = "quote-verified"
	PhasePolicyAuthorized   Phase = "policy-authorized"
	PhasePurchaseReferenced Phase = "purchase-referenced"
	PhasePurchaseResolved   Phase = "purchase-resolved"
	PhaseFailed             Phase = "terminal-failed"
)

type Record struct {
	IntentID       string             `json:"intent_id"`
	Phase          Phase              `json:"phase"`
	Hint           CandidateHint      `json:"hint"`
	Verified       *VerifiedCandidate `json:"verified,omitempty"`
	Assessment     *Assessment        `json:"assessment,omitempty"`
	Purchase       *PurchaseProgress  `json:"purchase,omitempty"`
	Failure        string             `json:"failure,omitempty"`
	DiscoveredUnix int64              `json:"discovered_unix"`
	UpdatedUnix    int64              `json:"updated_unix"`
}

type journalDocument struct {
	Schema  string   `json:"schema"`
	Records []Record `json:"records"`
}

type Journal struct {
	mu      sync.Mutex
	path    string
	records map[string]Record
	byKey   map[string]string
	random  io.Reader
}

func OpenJournal(directory string) (*Journal, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, errors.New("opportunity journal directory must be clean and absolute")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return nil, errors.New("opportunity journal directory must be owner-private")
	}
	j := &Journal{path: filepath.Join(directory, journalFile), records: map[string]Record{}, byKey: map[string]string{}, random: rand.Reader}
	if err := j.load(); err != nil {
		return nil, err
	}
	return j, nil
}

func (j *Journal) load() error {
	info, err := os.Lstat(j.path)
	if errors.Is(err, os.ErrNotExist) {
		return j.persist(j.records)
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > maxJournalBytes {
		return errors.New("opportunity journal file is not a bounded owner-only regular file")
	}
	raw, err := os.ReadFile(j.path)
	if err != nil {
		return errors.New("read opportunity journal")
	}
	var document journalDocument
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&document) != nil || document.Schema != journalSchema {
		return errors.New("invalid opportunity journal")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing opportunity journal data")
	}
	for _, record := range document.Records {
		if !validRecord(record) {
			return errors.New("invalid opportunity journal record")
		}
		key := keyString(record.Hint.Key)
		if _, duplicate := j.records[record.IntentID]; duplicate || j.byKey[key] != "" {
			return errors.New("duplicate opportunity journal record")
		}
		j.records[record.IntentID] = cloneRecord(record)
		j.byKey[key] = record.IntentID
	}
	return nil
}

func (j *Journal) Observe(hint CandidateHint, now time.Time) (Record, bool, error) {
	if j == nil || !validateHint(hint) || now.IsZero() || now.UTC().Unix() <= 0 {
		return Record{}, false, errors.New("invalid discovered opportunity")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	key := keyString(hint.Key)
	if intent := j.byKey[key]; intent != "" {
		existing := j.records[intent]
		return cloneRecord(existing), false, nil
	}
	var material [32]byte
	if _, err := io.ReadFull(j.random, material[:]); err != nil {
		return Record{}, false, errors.New("generate opportunity intent")
	}
	record := Record{IntentID: "opp_" + hex.EncodeToString(material[:]), Phase: PhaseDiscovered,
		Hint: cloneHint(hint), DiscoveredUnix: now.UTC().Unix(), UpdatedUnix: now.UTC().Unix()}
	updated := cloneRecords(j.records)
	updated[record.IntentID] = record
	if err := j.persist(updated); err != nil {
		return Record{}, false, err
	}
	j.records = updated
	j.byKey[key] = record.IntentID
	return cloneRecord(record), true, nil
}

func (j *Journal) MarkVerified(intent string, verified VerifiedCandidate, now time.Time) (Record, error) {
	return j.transition(intent, now, func(record *Record) error {
		if record.Phase != PhaseDiscovered || !validateVerified(verified) || verified.Key != record.Hint.Key {
			return errors.New("verified opportunity conflicts with discovered candidate")
		}
		owned := verified
		record.Verified = &owned
		record.Phase = PhaseVerified
		return nil
	})
}

func (j *Journal) MarkAssessed(intent string, assessment Assessment, now time.Time) (Record, error) {
	return j.transition(intent, now, func(record *Record) error {
		if record.Phase != PhaseVerified || assessment.AssessedAtUnix <= 0 || !boundedText(assessment.Reason, 1, 512) {
			return errors.New("invalid opportunity assessment transition")
		}
		owned := assessment
		record.Assessment = &owned
		record.Phase = PhaseAssessed
		return nil
	})
}

func (j *Journal) MarkFailed(intent, reason string, now time.Time) (Record, error) {
	return j.transition(intent, now, func(record *Record) error {
		if (record.Phase != PhaseDiscovered && record.Phase != PhaseAssessed && record.Phase != PhaseQuoteRequested &&
			record.Phase != PhaseQuoteVerified && record.Phase != PhasePolicyAuthorized) ||
			(record.Purchase != nil && record.Purchase.Key != nil) ||
			!boundedText(reason, 1, 512) {
			return errors.New("invalid opportunity failure transition")
		}
		record.Failure = reason
		record.Phase = PhaseFailed
		return nil
	})
}

func (j *Journal) MarkQuoteRequested(intent string, now time.Time) (Record, error) {
	return j.transition(intent, now, func(record *Record) error {
		if record.Phase != PhaseAssessed || record.Assessment == nil || !record.Assessment.Eligible || record.Purchase != nil {
			return errors.New("only an eligible assessed opportunity may request a Quote")
		}
		record.Phase = PhaseQuoteRequested
		return nil
	})
}

// MarkPurchaseProgress mirrors a coordinator-owned transition. It never
// advances the authoritative purchase journal and refuses a changed candidate
// or PurchaseKey.
func (j *Journal) MarkPurchaseProgress(intent string, progress PurchaseProgress, now time.Time) (Record, error) {
	return j.transition(intent, now, func(record *Record) error {
		if !validatePurchaseProgress(progress) || progress.IntentID != intent || record.Verified == nil ||
			progress.CandidateKey != record.Verified.Key || !validPurchaseTransition(record.Phase, progress.Phase) {
			return errors.New("invalid opportunity purchase projection")
		}
		if record.Purchase != nil && record.Purchase.Key != nil &&
			(progress.Key == nil || *record.Purchase.Key != *progress.Key) {
			return errors.New("opportunity purchase identity changed")
		}
		owned := clonePurchaseProgress(progress)
		record.Purchase = &owned
		record.Phase = progress.Phase
		return nil
	})
}

func (j *Journal) transition(intent string, now time.Time, apply func(*Record) error) (Record, error) {
	if j == nil || !regexpIntent(intent) || now.IsZero() || now.UTC().Unix() <= 0 {
		return Record{}, errors.New("invalid opportunity transition")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	record, found := j.records[intent]
	if !found {
		return Record{}, errors.New("opportunity intent does not exist")
	}
	if err := apply(&record); err != nil {
		return Record{}, err
	}
	record.UpdatedUnix = now.UTC().Unix()
	updated := cloneRecords(j.records)
	updated[intent] = record
	if err := j.persist(updated); err != nil {
		return Record{}, err
	}
	j.records = updated
	return cloneRecord(record), nil
}

func (j *Journal) List() []Record {
	if j == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	listed := make([]Record, 0, len(j.records))
	for _, record := range j.records {
		listed = append(listed, cloneRecord(record))
	}
	sort.Slice(listed, func(i, k int) bool {
		if listed[i].DiscoveredUnix != listed[k].DiscoveredUnix {
			return listed[i].DiscoveredUnix < listed[k].DiscoveredUnix
		}
		return listed[i].IntentID < listed[k].IntentID
	})
	return listed
}

func (j *Journal) persist(records map[string]Record) error {
	listed := make([]Record, 0, len(records))
	for _, record := range records {
		listed = append(listed, cloneRecord(record))
	}
	sort.Slice(listed, func(i, k int) bool { return listed[i].IntentID < listed[k].IntentID })
	raw, err := json.Marshal(journalDocument{Schema: journalSchema, Records: listed})
	if err != nil || len(raw) > maxJournalBytes {
		return errors.New("encode opportunity journal")
	}
	return fileutil.WriteFileAtomic(j.path, raw, 0o600)
}

func validRecord(record Record) bool {
	if !regexpIntent(record.IntentID) || !validateHint(record.Hint) || record.DiscoveredUnix <= 0 || record.UpdatedUnix < record.DiscoveredUnix {
		return false
	}
	switch record.Phase {
	case PhaseDiscovered:
		return record.Verified == nil && record.Assessment == nil && record.Purchase == nil && record.Failure == ""
	case PhaseVerified:
		return record.Verified != nil && validateVerified(*record.Verified) && record.Verified.Key == record.Hint.Key && record.Assessment == nil && record.Purchase == nil && record.Failure == ""
	case PhaseAssessed:
		return record.Verified != nil && validateVerified(*record.Verified) && record.Verified.Key == record.Hint.Key && record.Assessment != nil && record.Assessment.AssessedAtUnix > 0 && boundedText(record.Assessment.Reason, 1, 512) && record.Purchase == nil && record.Failure == ""
	case PhaseQuoteRequested:
		return validAssessedPurchaseBase(record) && record.Purchase == nil
	case PhaseQuoteVerified, PhasePolicyAuthorized, PhasePurchaseReferenced, PhasePurchaseResolved:
		return validAssessedPurchaseBase(record) && record.Purchase != nil && validatePurchaseProgress(*record.Purchase) &&
			record.Purchase.IntentID == record.IntentID && record.Purchase.CandidateKey == record.Verified.Key &&
			record.Purchase.Phase == record.Phase
	case PhaseFailed:
		return validFailedRecord(record)
	default:
		return false
	}
}

func validFailedRecord(record Record) bool {
	if !boundedText(record.Failure, 1, 512) {
		return false
	}
	if record.Purchase == nil {
		return true
	}
	return record.Purchase.Key == nil && validatePurchaseProgress(*record.Purchase) &&
		(record.Purchase.Phase == PhaseQuoteVerified || record.Purchase.Phase == PhasePolicyAuthorized)
}

func validAssessedPurchaseBase(record Record) bool {
	return record.Verified != nil && validateVerified(*record.Verified) && record.Verified.Key == record.Hint.Key &&
		record.Assessment != nil && record.Assessment.Eligible && record.Assessment.AssessedAtUnix > 0 &&
		boundedText(record.Assessment.Reason, 1, 512) && record.Failure == ""
}

func validPurchaseTransition(from, to Phase) bool {
	switch from {
	case PhaseQuoteRequested:
		return to == PhaseQuoteVerified
	case PhaseQuoteVerified:
		return to == PhasePolicyAuthorized
	case PhasePolicyAuthorized:
		return to == PhasePurchaseReferenced
	case PhasePurchaseReferenced:
		return to == PhasePurchaseReferenced || to == PhasePurchaseResolved
	default:
		return false
	}
}

func regexpIntent(value string) bool {
	return len(value) == 4+64 && value[:4] == "opp_" && digestPattern.MatchString("sha256:"+value[4:])
}

func keyString(key CandidateKey) string {
	return key.Network.ID + "\x00" + key.Network.GenesisRootHash + "\x00" + key.Network.GenesisFileHash + "\x00" +
		key.CapabilityID + "\x00" + key.Version + "\x00" + key.ManifestDigest + "\x00" + key.ProviderAgentID
}

func cloneHint(h CandidateHint) CandidateHint {
	h.GatewayIDs = append([]string(nil), h.GatewayIDs...)
	return h
}

func cloneRecord(record Record) Record {
	record.Hint = cloneHint(record.Hint)
	if record.Verified != nil {
		owned := *record.Verified
		record.Verified = &owned
	}
	if record.Assessment != nil {
		owned := *record.Assessment
		record.Assessment = &owned
	}
	if record.Purchase != nil {
		owned := clonePurchaseProgress(*record.Purchase)
		record.Purchase = &owned
	}
	return record
}

func clonePurchaseProgress(progress PurchaseProgress) PurchaseProgress {
	if progress.Key != nil {
		owned := *progress.Key
		progress.Key = &owned
	}
	return progress
}

func cloneRecords(records map[string]Record) map[string]Record {
	cloned := make(map[string]Record, len(records))
	for key, record := range records {
		cloned[key] = cloneRecord(record)
	}
	return cloned
}
