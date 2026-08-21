package servicebridge

import (
	"context"
	"errors"
	"time"
)

// TaskBuilder derives the exact task claim from a canonical Accepted Quote. The
// execution-ID/source-digest derivation is SDK-specific and injected so the core
// stays dependency-free.
type TaskBuilder func(aq AcceptedQuote) (Task, error)

// Buyer drives the TOS Service Protocol buyer lifecycle under an owner spending policy. Every
// authority decision is re-derived from finalized TOS state; a Gateway or a
// transport acknowledgement is never treated as ownership or payment.
type Buyer struct {
	Policy   SpendingPolicy
	Resolver NativeResolver
	Quotes   QuoteClient
	Journal  PurchaseJournal
	Signer   CustodySigner
	// QuoteVerifier independently matches the funded Accepted Quote in finalized
	// state before every possible task dispatch, including crash recovery.
	QuoteVerifier FinalizedQuoteVerifier
	Transport     TaskTransport
	Receipts      ReceiptVerifier
	Confirm       Confirmer // required only when Policy.ConfirmationMode == ConfirmManual
	Now           func() time.Time
}

var (
	ErrBuyerMisconfigured = errors.New("servicebridge: buyer is missing a required component")
	ErrFundingAmbiguous   = errors.New("servicebridge: escrow funding did not reach the exact quoted amount in finalized state")
	ErrManualNoConfirmer  = errors.New("servicebridge: manual policy has no confirmer")
	ErrSettlementPending  = errors.New("servicebridge: finalized settlement is not terminal yet")
)

func (b *Buyer) now() time.Time {
	if b.Now != nil {
		return b.Now().UTC()
	}
	return time.Now().UTC()
}

func (b *Buyer) ready() bool {
	return b.Resolver != nil && b.Quotes != nil && b.Journal != nil &&
		b.Signer != nil && b.QuoteVerifier != nil && b.Transport != nil && b.Receipts != nil
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
		return Settlement{}, errors.New("servicebridge: quote proposal does not match the requested capability")
	}

	// Step 4: derive the canonical Accepted Quote and deterministic escrow
	// identity. This is read-only and gives policy retries their durable slot key.
	aq, err := b.Quotes.BuildAcceptedQuote(ctx, proposal)
	if err != nil {
		return Settlement{}, err
	}
	if aq.QuoteCommitment == "" || aq.EscrowAddress == "" {
		return Settlement{}, errors.New("servicebridge: accepted quote is missing its commitment or escrow address")
	}

	key := PurchaseKey{QuoteCommitment: aq.QuoteCommitment, EscrowAddress: aq.EscrowAddress}

	// Step 5: owner spending policy (asset/amount/expiry/allow-list/budget/mode).
	// An identical staged/recovery slot already reserves its amount; subtract it
	// before applying the proposed amount again so a retry is not double-counted.
	now := b.now()
	spent := b.Journal.SpentInWindow(now, b.Policy.Window)
	if existing, ok := b.Journal.Get(key); ok && existing.ClaimedUnix >= now.Add(-b.Policy.Window).Unix() &&
		existing.AtomicAmount <= spent {
		spent -= existing.AtomicAmount
	}
	authErr := (PolicyEngine{}).Authorize(b.Policy, proposal, spent, now)
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

	// Step 6: atomic slot+budget claim, single funding lease, exact finalized funding.
	if _, err := b.Journal.Begin(PurchaseRecord{
		Key: key, AssetMaster: proposal.Asset.Master, AtomicAmount: proposal.MaxAtomicAmount,
	}, now); err != nil {
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
	expectedTerms, err := PurchaseTermsForProposal(aq.Proposal)
	if err != nil {
		return Settlement{}, err
	}
	if err := b.QuoteVerifier.VerifyAcceptedQuote(
		ctx, aq.QuoteCommitment, aq.EscrowAddress, expectedTerms,
	); err != nil {
		return Settlement{}, err
	}
	current, ok := b.Journal.Get(key)
	if !ok {
		return Settlement{}, ErrJournalMissing
	}
	if current.Phase.Order() < PhaseFunded.Order() {
		if err := b.Journal.Advance(key, PhaseFunded); err != nil {
			return Settlement{}, err
		}
		current, _ = b.Journal.Get(key)
	}

	// Step 7: dispatch the bound task only after finalized funding. The shared
	// execution Gate guarantees at-most-once across all transports.
	if current.Phase.Order() < PhaseExecution.Order() {
		task, err := buildTask(aq)
		if err != nil {
			return Settlement{}, err
		}
		if task.QuoteCommitment != aq.QuoteCommitment || task.EscrowAddress != aq.EscrowAddress {
			return Settlement{}, errors.New("servicebridge: built task does not bind the accepted quote")
		}
		if err := b.Transport.Dispatch(ctx, transport, task); err != nil {
			return Settlement{}, err
		}
		if err := b.Journal.Advance(key, PhaseExecution); err != nil {
			return Settlement{}, err
		}
	}

	// Step 8: verify Receipt + settlement from finalized escrow and wallet state.
	settlement, err := b.Receipts.VerifySettlement(ctx, aq)
	if err != nil {
		return Settlement{}, err
	}
	if settlement.Released == settlement.Refunded {
		return Settlement{}, ErrSettlementPending
	}
	if err := b.Journal.Advance(key, PhaseResolved); err != nil && !errors.Is(err, ErrJournalPhase) {
		return Settlement{}, err
	}
	return settlement, nil
}
