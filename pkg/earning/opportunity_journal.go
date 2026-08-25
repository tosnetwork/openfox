package earning

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tosnetwork/openfox/pkg/fileutil"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

type observedOpportunity struct {
	Intent       commerce.SignedAgentIntent `json:"intent"`
	IntentDigest string                     `json:"intent_digest"`
	CarrierID    string                     `json:"carrier_id"`
	Cursor       string                     `json:"cursor"`
	ObservedUnix uint64                     `json:"observed_unix"`
}

type opportunityCursor struct {
	CarrierID    string `json:"carrier_id"`
	Cursor       string `json:"cursor"`
	ObservedUnix uint64 `json:"observed_unix"`
}

type observedWithdrawal struct {
	Withdrawal       commerce.SignedAgentIntentWithdrawal `json:"withdrawal"`
	WithdrawalDigest string                               `json:"withdrawal_digest"`
	CarrierID        string                               `json:"carrier_id"`
	Cursor           string                               `json:"cursor"`
	ObservedUnix     uint64                               `json:"observed_unix"`
}

// OpportunityJournal commits exact verified input before advancing a
// source-local cursor. Model or evaluator failure therefore cannot lose an
// opportunity: recovery replays the immutable observation from this journal.
type OpportunityJournal struct {
	mu         sync.Mutex
	directory  string
	maxEntries uint32
	lock       *os.File
}

func OpenOpportunityJournal(directory string, maxEntries uint32) (*OpportunityJournal, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || maxEntries == 0 || maxEntries > 1_000_000 {
		return nil, errors.New("opportunity journal configuration is invalid")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return nil, errors.New("opportunity journal must be owner-private")
	}
	lock, err := acquireAuthorityLock(directory)
	if err != nil {
		return nil, err
	}
	return &OpportunityJournal{directory: directory, maxEntries: maxEntries, lock: lock}, nil
}

func (journal *OpportunityJournal) Close() error {
	if journal == nil || journal.lock == nil {
		return nil
	}
	err := releaseAuthorityLock(journal.lock)
	journal.lock = nil
	return err
}

func (journal *OpportunityJournal) Cursor(carrierID string) (string, error) {
	if journal == nil || carrierID == "" {
		return "", errors.New("opportunity cursor request is invalid")
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	raw, err := os.ReadFile(journal.cursorPath(carrierID))
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil || len(raw) > 4096 {
		return "", errors.New("opportunity cursor is unavailable")
	}
	var cursor opportunityCursor
	if json.Unmarshal(raw, &cursor) != nil || cursor.CarrierID != carrierID || !validSourceCursor(cursor.Cursor) {
		return "", errors.New("opportunity cursor is invalid")
	}
	return cursor.Cursor, nil
}

func (journal *OpportunityJournal) Record(result CarrierResult, digest string, observed time.Time) error {
	if journal == nil || journal.lock == nil || result.CarrierID == "" || !canonicalSHA256(digest) || !validSourceCursor(result.Cursor) || observed.IsZero() {
		return errors.New("opportunity observation is invalid")
	}
	computed, err := commerce.IntentBodyDigest(result.Intent.Body)
	if err != nil || computed != digest {
		return errors.New("opportunity observation digest mismatch")
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if current, readErr := journal.cursorLocked(result.CarrierID); readErr != nil {
		return readErr
	} else if current != "" && compareSourceCursor(result.Cursor, current) <= 0 {
		return nil
	}
	path := journal.observationPath(digest, result.CarrierID)
	observation := observedOpportunity{Intent: result.Intent, IntentDigest: digest, CarrierID: result.CarrierID,
		Cursor: result.Cursor, ObservedUnix: uint64(observed.UTC().Unix())}
	raw, err := json.Marshal(observation)
	if err != nil || len(raw) > 2<<20 {
		return errors.New("opportunity observation is oversized")
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		entries, countErr := filepath.Glob(filepath.Join(journal.directory, strings.Repeat("?", 64)+"-"+strings.Repeat("?", 64)+".json"))
		if countErr != nil || len(entries) >= int(journal.maxEntries) {
			return errors.New("opportunity journal capacity reached")
		}
		if err := writeOwnerExclusive(path, raw); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	cursorRaw, _ := json.Marshal(opportunityCursor{CarrierID: result.CarrierID, Cursor: result.Cursor, ObservedUnix: uint64(observed.UTC().Unix())})
	return fileutil.WriteFileAtomic(journal.cursorPath(result.CarrierID), cursorRaw, 0o600)
}

// RecordWithdrawal persists issuer-signed negative information before moving
// the source cursor. Once observed from any Carrier, the exact immutable
// revision remains suppressed even if another stale Carrier republishes it.
func (journal *OpportunityJournal) RecordWithdrawal(result CarrierResult, observed time.Time) error {
	if journal == nil || journal.lock == nil || result.Withdrawal == nil || result.CarrierID == "" ||
		!validSourceCursor(result.Cursor) || observed.IsZero() || !canonicalSHA256(result.Withdrawal.Body.IntentDigest) {
		return errors.New("opportunity withdrawal observation is invalid")
	}
	digest, err := commerce.IntentWithdrawalDigest(result.Withdrawal.Body)
	if err != nil {
		return err
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if current, readErr := journal.cursorLocked(result.CarrierID); readErr != nil {
		return readErr
	} else if current != "" && compareSourceCursor(result.Cursor, current) <= 0 {
		return nil
	}
	observation := observedWithdrawal{Withdrawal: *result.Withdrawal, WithdrawalDigest: digest, CarrierID: result.CarrierID,
		Cursor: result.Cursor, ObservedUnix: uint64(observed.UTC().Unix())}
	raw, err := json.Marshal(observation)
	if err != nil || len(raw) > 2<<20 {
		return errors.New("opportunity withdrawal observation is oversized")
	}
	path := journal.withdrawalPath(result.Withdrawal.Body.IntentDigest, result.CarrierID)
	if existing, readErr := os.ReadFile(path); readErr == nil {
		var prior observedWithdrawal
		if json.Unmarshal(existing, &prior) != nil || prior.WithdrawalDigest != digest || prior.CarrierID != result.CarrierID || prior.Cursor != result.Cursor {
			return errors.New("opportunity withdrawal observation conflicts")
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return readErr
	} else if err := writeOwnerExclusive(path, raw); err != nil {
		return err
	}
	cursorRaw, _ := json.Marshal(opportunityCursor{CarrierID: result.CarrierID, Cursor: result.Cursor, ObservedUnix: uint64(observed.UTC().Unix())})
	return fileutil.WriteFileAtomic(journal.cursorPath(result.CarrierID), cursorRaw, 0o600)
}

func (journal *OpportunityJournal) IsWithdrawn(intentDigest string) bool {
	if journal == nil || !canonicalSHA256(intentDigest) {
		return false
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	paths, err := filepath.Glob(filepath.Join(journal.directory, ".withdrawn-"+strings.TrimPrefix(intentDigest, "sha256:")+"-"+strings.Repeat("?", 64)+".json"))
	return err == nil && len(paths) > 0
}

func (journal *OpportunityJournal) Observations(carrierID string, limit uint32) ([]CarrierResult, error) {
	if journal == nil || carrierID == "" || limit == 0 || limit > 1000 {
		return nil, errors.New("opportunity replay request is invalid")
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	carrierDigest := sha256.Sum256([]byte(carrierID))
	paths, err := filepath.Glob(filepath.Join(journal.directory, strings.Repeat("?", 64)+"-"+hex.EncodeToString(carrierDigest[:])+".json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	if len(paths) > int(limit) {
		paths = paths[len(paths)-int(limit):]
	}
	results := make([]CarrierResult, 0, len(paths))
	for _, path := range paths {
		name := filepath.Base(path)
		digest := "sha256:" + name[:64]
		if _, markerErr := os.Lstat(journal.processedPath(digest, carrierID)); markerErr == nil {
			continue
		} else if !errors.Is(markerErr, os.ErrNotExist) {
			return nil, markerErr
		}
		raw, readErr := os.ReadFile(path)
		if readErr != nil || len(raw) > 2<<20 {
			return nil, errors.New("opportunity replay record is unavailable")
		}
		var observation observedOpportunity
		if json.Unmarshal(raw, &observation) != nil || observation.CarrierID != carrierID || !validSourceCursor(observation.Cursor) {
			return nil, errors.New("opportunity replay record is invalid")
		}
		computed, digestErr := commerce.IntentBodyDigest(observation.Intent.Body)
		if digestErr != nil || computed != observation.IntentDigest {
			return nil, errors.New("opportunity replay record digest is invalid")
		}
		results = append(results, CarrierResult{Intent: observation.Intent, Cursor: observation.Cursor, CarrierID: carrierID})
	}
	return results, nil
}

func (journal *OpportunityJournal) MarkProcessed(digest, carrierID string) error {
	if journal == nil || !canonicalSHA256(digest) || carrierID == "" {
		return errors.New("processed opportunity identity is invalid")
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	path := journal.processedPath(digest, carrierID)
	if err := writeOwnerExclusive(path, []byte("processed")); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return nil
}

func (journal *OpportunityJournal) cursorLocked(carrierID string) (string, error) {
	raw, err := os.ReadFile(journal.cursorPath(carrierID))
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	var cursor opportunityCursor
	if json.Unmarshal(raw, &cursor) != nil || cursor.CarrierID != carrierID || !validSourceCursor(cursor.Cursor) {
		return "", errors.New("opportunity cursor is invalid")
	}
	return cursor.Cursor, nil
}

func (journal *OpportunityJournal) cursorPath(carrierID string) string {
	digest := sha256.Sum256([]byte("tos.openfox.opportunity-cursor.v1\x00" + carrierID))
	return filepath.Join(journal.directory, ".source-"+hex.EncodeToString(digest[:])+".json")
}

func (journal *OpportunityJournal) observationPath(digest, carrierID string) string {
	carrierDigest := sha256.Sum256([]byte(carrierID))
	return filepath.Join(journal.directory, strings.TrimPrefix(digest, "sha256:")+"-"+hex.EncodeToString(carrierDigest[:])+".json")
}

func (journal *OpportunityJournal) processedPath(digest, carrierID string) string {
	carrierDigest := sha256.Sum256([]byte(carrierID))
	return filepath.Join(journal.directory, ".processed-"+strings.TrimPrefix(digest, "sha256:")+"-"+hex.EncodeToString(carrierDigest[:]))
}

func (journal *OpportunityJournal) withdrawalPath(intentDigest, carrierID string) string {
	carrierDigest := sha256.Sum256([]byte(carrierID))
	return filepath.Join(journal.directory, ".withdrawn-"+strings.TrimPrefix(intentDigest, "sha256:")+"-"+hex.EncodeToString(carrierDigest[:])+".json")
}

func validSourceCursor(cursor string) bool {
	if !strings.HasPrefix(cursor, "seq:") {
		return false
	}
	value, err := strconv.ParseUint(strings.TrimPrefix(cursor, "seq:"), 10, 64)
	return err == nil && value > 0 && cursor == "seq:"+strconv.FormatUint(value, 10)
}

func compareSourceCursor(left, right string) int {
	l, _ := strconv.ParseUint(strings.TrimPrefix(left, "seq:"), 10, 64)
	r, _ := strconv.ParseUint(strings.TrimPrefix(right, "seq:"), 10, 64)
	if l < r {
		return -1
	}
	if l > r {
		return 1
	}
	return 0
}
