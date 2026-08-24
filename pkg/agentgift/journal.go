package agentgift

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/tosnetwork/openfox/pkg/fileutil"
)

const journalSchema = "tos.openfox.agent-gift-journal.v1"
const journalFile = "agent-gifts.json"
const journalLockFile = ".agent-gifts.lock"
const maxJournalBytes = 32 << 20

type Record struct {
	IntentID                        string        `json:"intent_id"`
	Role                            Role          `json:"role"`
	State                           State         `json:"state"`
	PendingEffect                   PendingEffect `json:"pending_effect,omitempty"`
	Network                         string        `json:"network"`
	GlobalID                        int32         `json:"global_id"`
	SenderAgentID                   string        `json:"sender_agent_id"`
	RecipientAgentID                string        `json:"recipient_agent_id"`
	SenderAgentAccount              string        `json:"sender_agent_account"`
	AmountAtomic                    string        `json:"amount_atomic"`
	RequestedValidUntil             uint32        `json:"requested_valid_until"`
	ResponseNotAfter                uint32        `json:"response_not_after,omitempty"`
	DestinationAddress              string        `json:"destination_address,omitempty"`
	RequestDigest                   string        `json:"request_digest,omitempty"`
	ResponseDigest                  string        `json:"response_digest,omitempty"`
	OwnerAuthorizationDigest        string        `json:"owner_authorization_digest,omitempty"`
	UnsignedTransferDigest          string        `json:"unsigned_transfer_digest,omitempty"`
	OwnerWallet                     string        `json:"owner_wallet,omitempty"`
	ControllerKeyID                 string        `json:"controller_key_id,omitempty"`
	DeploymentID                    string        `json:"deployment_id,omitempty"`
	ControllerEpoch                 uint64        `json:"controller_epoch,omitempty"`
	FeeReserveAtomic                string        `json:"fee_reserve_atomic,omitempty"`
	CancellationAuthorizationDigest string        `json:"cancellation_authorization_digest,omitempty"`
	SignedGiftID                    string        `json:"signed_gift_id,omitempty"`
	ExactBOCDigest                  string        `json:"exact_boc_digest,omitempty"`
	Seqno                           uint32        `json:"seqno,omitempty"`
	ValidUntil                      uint32        `json:"valid_until,omitempty"`
	CanonicalRequest                []byte        `json:"canonical_request,omitempty"`
	CanonicalResponse               []byte        `json:"canonical_response,omitempty"`
	ExactSignedBOC                  []byte        `json:"exact_signed_boc,omitempty"`
	ExactCancellationBOC            []byte        `json:"exact_cancellation_boc,omitempty"`
	CanonicalOffer                  []byte        `json:"canonical_offer,omitempty"`
	CanonicalOfferDigest            string        `json:"canonical_offer_digest,omitempty"`
	RequestEventID                  string        `json:"request_event_id,omitempty"`
	ResponseEventID                 string        `json:"response_event_id,omitempty"`
	OfferEventID                    string        `json:"offer_event_id,omitempty"`
	BroadcastAttempts               uint32        `json:"broadcast_attempts,omitempty"`
	CancellationAttempts            uint32        `json:"cancellation_attempts,omitempty"`
	RetryNotBeforeUnix              int64         `json:"retry_not_before_unix,omitempty"`
	DisplayMessage                  string        `json:"display_message,omitempty"`
	CreatedAtUnix                   int64         `json:"created_at_unix"`
	UpdatedAtUnix                   int64         `json:"updated_at_unix"`
}
type document struct {
	Schema  string   `json:"schema"`
	Records []Record `json:"records"`
}
type Journal struct {
	mu      sync.Mutex
	path    string
	records map[string]Record
	lock    *os.File
}

func OpenJournal(directory string) (*Journal, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, errors.New("Agent Gift journal directory must be clean and absolute")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return nil, errors.New("Agent Gift journal directory must be owner-private")
	}
	lock, err := acquireJournalLock(directory)
	if err != nil {
		return nil, err
	}
	j := &Journal{path: filepath.Join(directory, journalFile), records: map[string]Record{}, lock: lock}
	if err := j.load(); err != nil {
		_ = j.Close()
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
		return errors.New("Agent Gift journal is not a bounded owner-only file")
	}
	raw, err := os.ReadFile(j.path)
	if err != nil {
		return errors.New("read Agent Gift journal")
	}
	var doc document
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&doc) != nil || doc.Schema != journalSchema {
		return errors.New("invalid Agent Gift journal")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing Agent Gift journal data")
	}
	if len(doc.Records) > maxGiftRecords {
		return errors.New("Agent Gift journal exceeds record capacity")
	}
	for _, record := range doc.Records {
		if err := validateRecord(record); err != nil {
			return err
		}
		if _, found := j.records[record.IntentID]; found {
			return errors.New("duplicate Agent Gift intent")
		}
		j.records[record.IntentID] = clone(record)
	}
	return nil
}

func (j *Journal) Create(record Record) (Record, error) {
	if j == nil {
		return Record{}, errors.New("nil Agent Gift journal")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.lock == nil {
		return Record{}, errors.New("Agent Gift journal is closed")
	}
	if _, found := j.records[record.IntentID]; found {
		return Record{}, errors.New("Agent Gift intent already exists")
	}
	if err := validateRecord(record); err != nil {
		return Record{}, err
	}
	updated := cloneMap(j.records)
	if len(updated) >= maxGiftRecords && !evictOldestTerminal(updated) {
		return Record{}, errors.New("Agent Gift journal capacity reached with no terminal record to evict")
	}
	updated[record.IntentID] = clone(record)
	if err := j.persist(updated); err != nil {
		return Record{}, err
	}
	j.records = updated
	return clone(record), nil
}

// Close releases the lifetime process lock. A second daemon cannot open the
// same journal until this Journal is closed or its process exits.
func (j *Journal) Close() error {
	if j == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.lock == nil {
		return nil
	}
	lock := j.lock
	j.lock = nil
	return releaseJournalLock(lock)
}

func evictOldestTerminal(records map[string]Record) bool {
	oldestID := ""
	var oldestUpdated int64
	for id, record := range records {
		if !terminalState(record.State) {
			continue
		}
		if oldestID == "" || record.UpdatedAtUnix < oldestUpdated || record.UpdatedAtUnix == oldestUpdated && id < oldestID {
			oldestID = id
			oldestUpdated = record.UpdatedAtUnix
		}
	}
	if oldestID == "" {
		return false
	}
	delete(records, oldestID)
	return true
}

func (j *Journal) Update(intent string, apply func(*Record) error) (Record, error) {
	if j == nil || apply == nil {
		return Record{}, errors.New("invalid Agent Gift update")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.lock == nil {
		return Record{}, errors.New("Agent Gift journal is closed")
	}
	record, found := j.records[intent]
	if !found {
		return Record{}, errors.New("Agent Gift intent not found")
	}
	before := clone(record)
	if err := apply(&record); err != nil {
		return Record{}, err
	}
	if record.IntentID != before.IntentID || record.Role != before.Role || record.CreatedAtUnix != before.CreatedAtUnix || record.UpdatedAtUnix < before.UpdatedAtUnix {
		return Record{}, errors.New("immutable Agent Gift journal identity changed")
	}
	if err := validateRecord(record); err != nil {
		return Record{}, err
	}
	updated := cloneMap(j.records)
	updated[intent] = clone(record)
	if err := j.persist(updated); err != nil {
		return Record{}, err
	}
	j.records = updated
	return clone(record), nil
}

func (j *Journal) Get(intent string) (Record, bool) {
	if j == nil {
		return Record{}, false
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.lock == nil {
		return Record{}, false
	}
	v, ok := j.records[intent]
	return clone(v), ok
}
func (j *Journal) List() []Record {
	if j == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.lock == nil {
		return nil
	}
	out := make([]Record, 0, len(j.records))
	for _, v := range j.records {
		out = append(out, clone(v))
	}
	sort.Slice(out, func(i, k int) bool { return out[i].IntentID < out[k].IntentID })
	return out
}
func (j *Journal) persist(records map[string]Record) error {
	list := make([]Record, 0, len(records))
	for _, v := range records {
		list = append(list, clone(v))
	}
	sort.Slice(list, func(i, k int) bool { return list[i].IntentID < list[k].IntentID })
	raw, err := json.Marshal(document{Schema: journalSchema, Records: list})
	if err != nil || len(raw) > maxJournalBytes {
		return errors.New("encode Agent Gift journal")
	}
	return fileutil.WriteFileAtomic(j.path, raw, 0o600)
}

func validateRecord(v Record) error {
	if len(v.IntentID) != 64 || v.CreatedAtUnix <= 0 || v.UpdatedAtUnix < v.CreatedAtUnix || (v.Role != RoleSender && v.Role != RoleRecipient) || v.State == "" || v.Network == "" || v.GlobalID == 0 || v.SenderAgentID == "" || v.RecipientAgentID == "" || v.SenderAgentID == v.RecipientAgentID || !validCanonicalAmount(v.AmountAtomic) || v.RequestedValidUntil == 0 || len(v.CanonicalRequest) > 64<<10 || len(v.CanonicalResponse) > 64<<10 || len(v.ExactSignedBOC) > 64<<10 || len(v.ExactCancellationBOC) > 64<<10 || len(v.CanonicalOffer) > 64<<10 || !terminalState(v.State) && len(v.CanonicalRequest) == 0 {
		return errors.New("invalid Agent Gift journal record")
	}
	for _, c := range v.IntentID {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return errors.New("invalid Agent Gift intent ID")
		}
	}
	if len(v.DisplayMessage) > 512 || !validRoleState(v.Role, v.State) {
		return errors.New("invalid Agent Gift role state")
	}
	if v.CanonicalOfferDigest != "" && !validSHA256Digest(v.CanonicalOfferDigest) {
		return errors.New("invalid canonical Gift offer digest")
	}
	return nil
}

func validSHA256Digest(value string) bool {
	if len(value) != len("sha256:")+64 || value[:len("sha256:")] != "sha256:" {
		return false
	}
	for _, c := range value[len("sha256:"):] {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func terminalState(state State) bool {
	return state == StateFinalizedPaid || state == StateExpiredUnpaid || state == StateInvalidatedUnpaid
}

func validRoleState(role Role, state State) bool {
	common := state == StateFinalizedPaid || state == StateExpiredUnpaid || state == StateInvalidatedUnpaid || state == StateFinalityUnknown || state == StateCurrentlyExecutable || state == StateCurrentlyUnexecutable || state == StateInsufficientFunds
	if role == RoleSender {
		return common || state == StateDraft || state == StateRecipientResolved || state == StateAddressRequested || state == StateAddressReceived || state == StateOwnerAuthorizationRequired || state == StateOwnerAuthorized || state == StateBOCSigned || state == StateOfferDelivered
	}
	return common || state == StateAddressRequestObserved || state == StateAddressResponseSent || state == StateSignedOfferObserved || state == StateVerified || state == StateBroadcastSubmitted
}
func clone(v Record) Record {
	v.CanonicalRequest = append([]byte(nil), v.CanonicalRequest...)
	v.CanonicalResponse = append([]byte(nil), v.CanonicalResponse...)
	v.ExactSignedBOC = append([]byte(nil), v.ExactSignedBOC...)
	v.ExactCancellationBOC = append([]byte(nil), v.ExactCancellationBOC...)
	v.CanonicalOffer = append([]byte(nil), v.CanonicalOffer...)
	return v
}
func cloneMap(values map[string]Record) map[string]Record {
	out := make(map[string]Record, len(values))
	for k, v := range values {
		out[k] = clone(v)
	}
	return out
}
