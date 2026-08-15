package atosbridge

import (
	"errors"
	"sync"
	"time"
)

// Phase is a durable purchase-journal phase. Only Prepared can acquire the
// single funding lease; a crash before FundingLease is recoverable, while a
// crash at or after FundingLease is read-only recovery that must resolve
// finalized state before any retry and can never trigger a second payment.
type Phase string

const (
	PhaseIntent       Phase = "intent"
	PhasePrepared     Phase = "prepared"
	PhaseFundingLease Phase = "funding_lease"
	PhaseFunded       Phase = "funded"
	PhaseExecution    Phase = "execution"
	PhaseReceipt      Phase = "receipt"
	PhaseRelease      Phase = "release"
	PhaseResolved     Phase = "resolved"
)

func (p Phase) valid() bool {
	switch p {
	case PhaseIntent, PhasePrepared, PhaseFundingLease, PhaseFunded,
		PhaseExecution, PhaseReceipt, PhaseRelease, PhaseResolved:
		return true
	}
	return false
}

// PurchaseKey is the durable slot key. It is the same (quote_commitment,
// escrow_address) pair the shared execution Gate uses; request/idempotency keys
// are retry aliases and never define the payment identity.
type PurchaseKey struct {
	QuoteCommitment string
	EscrowAddress   string
}

// PurchaseRecord is one atomic slot: it reserves budget and records the full
// intent in a single claim.
type PurchaseRecord struct {
	Key          PurchaseKey
	Phase        Phase
	AssetMaster  string
	AtomicAmount uint64
	ClaimedUnix  int64
}

var (
	ErrJournalConflict = errors.New("atosbridge: purchase slot already claimed by a different intent")
	ErrJournalMissing  = errors.New("atosbridge: purchase slot not found")
	ErrJournalPhase    = errors.New("atosbridge: invalid purchase phase transition")
)

// PurchaseJournal is the owner-private atomic journal with slot and budget
// claims. Implementations must be crash-safe and durable; InMemoryJournal is a
// test double, and the production implementation wraps the reviewed file-backed
// buyer budget journal.
type PurchaseJournal interface {
	// Begin atomically claims the slot at PhasePrepared (reserving budget) or
	// returns the existing record on an identical retry. A different asset or
	// amount for the same key is a conflict.
	Begin(rec PurchaseRecord, now time.Time) (PurchaseRecord, error)
	// AcquireFundingLease advances Prepared -> FundingLease exactly once. It
	// returns acquired=true for the single caller that crosses the transition and
	// false (already leased/funded/beyond) otherwise.
	AcquireFundingLease(key PurchaseKey) (acquired bool, current PurchaseRecord, err error)
	// Advance moves the record to next, rejecting illegal transitions.
	Advance(key PurchaseKey, next Phase) error
	// Get returns the current record.
	Get(key PurchaseKey) (PurchaseRecord, bool)
	// SpentInWindow sums AtomicAmount of all non-resolved-or-refunded records
	// claimed within [now-window, now], including unresolved reservations.
	SpentInWindow(now time.Time, window time.Duration) uint64
}

// InMemoryJournal is a mutex-guarded PurchaseJournal for tests and dry runs.
type InMemoryJournal struct {
	mu      sync.Mutex
	records map[PurchaseKey]PurchaseRecord
}

// NewInMemoryJournal returns an empty in-memory journal.
func NewInMemoryJournal() *InMemoryJournal {
	return &InMemoryJournal{records: map[PurchaseKey]PurchaseRecord{}}
}

func (j *InMemoryJournal) Begin(rec PurchaseRecord, now time.Time) (PurchaseRecord, error) {
	if rec.Key.QuoteCommitment == "" || rec.Key.EscrowAddress == "" || rec.AtomicAmount == 0 {
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
	rec.ClaimedUnix = now.Unix()
	j.records[rec.Key] = rec
	return rec, nil
}

func (j *InMemoryJournal) AcquireFundingLease(key PurchaseKey) (bool, PurchaseRecord, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	rec, ok := j.records[key]
	if !ok {
		return false, PurchaseRecord{}, ErrJournalMissing
	}
	if rec.Phase != PhasePrepared {
		return false, rec, nil
	}
	rec.Phase = PhaseFundingLease
	j.records[key] = rec
	return true, rec, nil
}

var phaseOrder = map[Phase]int{
	PhaseIntent: 0, PhasePrepared: 1, PhaseFundingLease: 2, PhaseFunded: 3,
	PhaseExecution: 4, PhaseReceipt: 5, PhaseRelease: 6, PhaseResolved: 7,
}

func (j *InMemoryJournal) Advance(key PurchaseKey, next Phase) error {
	if !next.valid() {
		return ErrJournalPhase
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	rec, ok := j.records[key]
	if !ok {
		return ErrJournalMissing
	}
	if phaseOrder[next] <= phaseOrder[rec.Phase] {
		return ErrJournalPhase
	}
	rec.Phase = next
	j.records[key] = rec
	return nil
}

func (j *InMemoryJournal) Get(key PurchaseKey) (PurchaseRecord, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	rec, ok := j.records[key]
	return rec, ok
}

func (j *InMemoryJournal) SpentInWindow(now time.Time, window time.Duration) uint64 {
	cutoff := now.Add(-window).Unix()
	var total uint64
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, rec := range j.records {
		if rec.ClaimedUnix < cutoff {
			continue
		}
		total += rec.AtomicAmount
	}
	return total
}
