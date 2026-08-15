package servicebridge

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

// Order is the strict forward position of a phase, or -1 if the phase is
// unknown. A purchase only ever advances forward; the journal never moves a
// purchase backward.
func (p Phase) Order() int {
	switch p {
	case PhaseIntent:
		return 0
	case PhasePrepared:
		return 1
	case PhaseFundingLease:
		return 2
	case PhaseFunded:
		return 3
	case PhaseExecution:
		return 4
	case PhaseReceipt:
		return 5
	case PhaseRelease:
		return 6
	case PhaseResolved:
		return 7
	}
	return -1
}

// CanAdvance reports whether a purchase may move from one phase to another. Only
// strictly-forward transitions between valid phases are legal, so a purchase
// never regresses or repeats a phase.
func CanAdvance(from, to Phase) bool {
	return from.valid() && to.valid() && to.Order() > from.Order()
}

// CanAcquireFundingLease reports whether the single funding lease may be taken
// from this phase. Only Prepared may cross into FundingLease, so a funded
// purchase is funded at most once.
func CanAcquireFundingLease(p Phase) bool {
	return p == PhasePrepared
}

// ResumeAction is the crash-recovery decision for a persisted purchase phase.
type ResumeAction string

const (
	// ResumeInvalid marks an unrecognised phase; recovery must not proceed.
	ResumeInvalid ResumeAction = "invalid"
	// ResumeMayFund means the purchase crashed before the funding lease and may
	// still fund.
	ResumeMayFund ResumeAction = "may_fund"
	// ResumeReconcileNeverRefund means the purchase crashed at or after the
	// funding lease: recovery is read-only, must resolve finalized state, and can
	// NEVER trigger a second payment.
	ResumeReconcileNeverRefund ResumeAction = "reconcile_never_refund"
	// ResumeComplete means the purchase already resolved.
	ResumeComplete ResumeAction = "complete"
)

// ResumeActionFor decides how to safely resume a purchase after process death.
// It is the single authority for the at-most-once payment invariant across
// crashes: before the funding lease the purchase may still fund; at or after the
// lease recovery is read-only and never re-pays; once resolved it is complete.
func ResumeActionFor(p Phase) ResumeAction {
	switch {
	case !p.valid():
		return ResumeInvalid
	case p.Order() < PhaseFundingLease.Order():
		return ResumeMayFund
	case p == PhaseResolved:
		return ResumeComplete
	default:
		return ResumeReconcileNeverRefund
	}
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
	ErrJournalConflict = errors.New("servicebridge: purchase slot already claimed by a different intent")
	ErrJournalMissing  = errors.New("servicebridge: purchase slot not found")
	ErrJournalPhase    = errors.New("servicebridge: invalid purchase phase transition")
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
	if !CanAcquireFundingLease(rec.Phase) {
		return false, rec, nil
	}
	rec.Phase = PhaseFundingLease
	j.records[key] = rec
	return true, rec, nil
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
	if !CanAdvance(rec.Phase, next) {
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
