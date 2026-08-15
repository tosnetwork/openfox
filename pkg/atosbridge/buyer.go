package atosbridge

import (
	"context"
	"errors"
	"time"
)

// TaskBuilder derives the exact task claim from a canonical Accepted Quote. The
// execution-ID/source-digest derivation is SDK-specific and injected so the core
// stays dependency-free.
type TaskBuilder func(aq AcceptedQuote) (Task, error)

// Buyer drives the ATOS buyer lifecycle under an owner spending policy. Every
// authority decision is re-derived from finalized TOS state; a Gateway or a
// transport acknowledgement is never treated as ownership or payment.
type Buyer struct {
	Policy    SpendingPolicy
	Resolver  NativeResolver
	Quotes    QuoteClient
	Journal   PurchaseJournal
	Signer    CustodySigner
	Transport TaskTransport
	Receipts  ReceiptVerifier
	Confirm   Confirmer // required only when Policy.ConfirmationMode == ConfirmManual
	Now       func() time.Time
}

var (
	ErrBuyerMisconfigured = errors.New("atosbridge: buyer is missing a required component")
	ErrFundingAmbiguous   = errors.New("atosbridge: escrow funding did not reach the exact quoted amount in finalized state")
	ErrManualNoConfirmer  = errors.New("atosbridge: manual policy has no confirmer")
)

func (b *Buyer) now() time.Time {
	if b.Now != nil {
		return b.Now().UTC()
	}
	return time.Now().UTC()
}

func (b *Buyer) ready() bool {
	return b.Resolver != nil && b.Quotes != nil && b.Journal != nil &&
		b.Signer != nil && b.Transport != nil && b.Receipts != nil
}

// Purchase runs the eight-step buyer flow and returns the finalized settlement.
// It dispatches the task on the given transport only after finalized funding,
// and never re-funds after the single funding lease.
func (b *Buyer) Purchase(ctx context.Context, ref CapabilityRef, transport Transport, buildTask TaskBuilder) (Settlement, error) {
	if !b.ready() || buildTask == nil {
		return Settlement{}, ErrBuyerMisconfigured
	}

	// Steps 1-2: candidate + finalized verification (owner/version/manifest/net/code).
	if err := b.Resolver.ResolveCapability(ctx, ref); err != nil {
		return Settlement{}, err
	}

	// Step 3: non-canonical Quote Proposal, complete preimage.
	proposal, err := b.Quotes.RequestQuote(ctx, ref)
	if err != nil {
		return Settlement{}, err
	}
	if proposal.Capability.CapabilityID != ref.CapabilityID {
		return Settlement{}, errors.New("atosbridge: quote proposal does not match the requested capability")
	}

	// Step 4: owner spending policy (asset/amount/expiry/allow-list/budget/mode).
	spent := b.Journal.SpentInWindow(b.now(), b.Policy.Window)
	authErr := (PolicyEngine{}).Authorize(b.Policy, proposal, spent, b.now())
	if errors.Is(authErr, ErrManualConfirmation) {
		if b.Confirm == nil {
			return Settlement{}, ErrManualNoConfirmer
		}
		if err := b.Confirm.Confirm(ctx, proposal); err != nil {
			return Settlement{}, err
		}
	} else if authErr != nil {
		return Settlement{}, authErr
	}

	// Step 5: canonical Accepted Quote + deterministic escrow StateInit.
	aq, err := b.Quotes.BuildAcceptedQuote(ctx, proposal)
	if err != nil {
		return Settlement{}, err
	}
	if aq.QuoteCommitment == "" || aq.EscrowAddress == "" {
		return Settlement{}, errors.New("atosbridge: accepted quote is missing its commitment or escrow address")
	}

	key := PurchaseKey{QuoteCommitment: aq.QuoteCommitment, EscrowAddress: aq.EscrowAddress}

	// Step 6: atomic slot+budget claim, single funding lease, exact finalized funding.
	if _, err := b.Journal.Begin(PurchaseRecord{
		Key: key, AssetMaster: proposal.Asset.Master, AtomicAmount: proposal.MaxAtomicAmount,
	}, b.now()); err != nil {
		return Settlement{}, err
	}

	acquired, rec, err := b.Journal.AcquireFundingLease(key)
	if err != nil {
		return Settlement{}, err
	}
	if acquired {
		// Only the lease holder may broadcast a funding message.
		if err := b.Signer.SignAndFundEscrow(ctx, aq); err != nil {
			// A broadcast error is ambiguous; recovery below re-resolves finalized
			// state and never re-funds because the phase is already FundingLease.
			return Settlement{}, err
		}
	} else if rec.Phase == PhaseFundingLease {
		// Crash/recovery: another attempt already leased and may have broadcast.
		// Fall through to read-only finalized resolution; do NOT re-fund.
	}

	// Payment == finalized escrow holds the exact quoted amount.
	escrow, err := b.Resolver.ResolveEscrow(ctx, aq.EscrowAddress)
	if err != nil {
		return Settlement{}, err
	}
	if !escrow.Found || escrow.FundedAtomic != proposal.MaxAtomicAmount {
		return Settlement{}, ErrFundingAmbiguous
	}
	if err := b.Journal.Advance(key, PhaseFunded); err != nil && !errors.Is(err, ErrJournalPhase) {
		return Settlement{}, err
	}

	// Step 7: dispatch the bound task only after finalized funding. The shared
	// execution Gate guarantees at-most-once across all transports.
	task, err := buildTask(aq)
	if err != nil {
		return Settlement{}, err
	}
	if task.QuoteCommitment != aq.QuoteCommitment || task.EscrowAddress != aq.EscrowAddress {
		return Settlement{}, errors.New("atosbridge: built task does not bind the accepted quote")
	}
	_ = b.Journal.Advance(key, PhaseExecution)
	if err := b.Transport.Dispatch(ctx, transport, task); err != nil {
		return Settlement{}, err
	}

	// Step 8: verify Receipt + settlement from finalized escrow and wallet state.
	settlement, err := b.Receipts.VerifySettlement(ctx, aq)
	if err != nil {
		return Settlement{}, err
	}
	_ = b.Journal.Advance(key, PhaseResolved)
	return settlement, nil
}
