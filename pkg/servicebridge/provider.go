package servicebridge

import (
	"context"
	"errors"
)

// Provider drives the TOS Service Protocol provider side after the shared Native execution Gate
// has admitted a task. The Gate (in the A2A/MCP/Agent Packet receiver) is the
// at-most-once authority; this orchestrator executes the admitted task, builds
// and signs the canonical Receipt, submits release, and reconciles credit from
// finalized state. It cannot change the manifest, price, signer, or Receipt
// after acceptance.
type Provider struct {
	Resolver NativeResolver
	Executor ExecutionAdapter
	Receipts ReceiptVerifier
	Signer   CustodySigner
}

var (
	ErrProviderMisconfigured = errors.New("servicebridge: provider is missing a required component")
	ErrEscrowNotFunded       = errors.New("servicebridge: admitted task escrow is not funded to the accepted quote")
	ErrOutcomeMismatch       = errors.New("servicebridge: execution outcome does not bind the admitted task")
)

func (p *Provider) ready() bool {
	return p.Resolver != nil && p.Executor != nil && p.Receipts != nil && p.Signer != nil
}

// HandleAdmittedTask runs steps 3-6 of the provider flow for a task the Gate has
// already admitted against finalized state: it re-confirms the funded escrow,
// executes inside the bounded executor, builds and signs the canonical Receipt,
// submits release, and reconciles provider credit from finalized wallet state.
// A failed execution produces no successful Receipt; timeout refund follows the
// escrow state machine and is not initiated here.
func (p *Provider) HandleAdmittedTask(ctx context.Context, aq AcceptedQuote, task Task) (Receipt, Settlement, error) {
	if !p.ready() {
		return Receipt{}, Settlement{}, ErrProviderMisconfigured
	}
	if task.QuoteCommitment != aq.QuoteCommitment || task.EscrowAddress != aq.EscrowAddress {
		return Receipt{}, Settlement{}, ErrOutcomeMismatch
	}

	// Step 3: accept only tasks bound to a funded escrow (defense in depth; the
	// Gate already checked this, re-derived here from finalized state).
	escrow, err := p.Resolver.ResolveEscrow(ctx, aq.EscrowAddress)
	if err != nil {
		return Receipt{}, Settlement{}, err
	}
	if !escrow.Found || escrow.FundedAtomic != aq.Proposal.MaxAtomicAmount {
		return Receipt{}, Settlement{}, ErrEscrowNotFunded
	}

	// Step 4: execute inside the bounded executor and content-addressed store.
	outcome, err := p.Executor.Execute(ctx, task)
	if err != nil {
		return Receipt{}, Settlement{}, err
	}
	if outcome.QuoteCommitment != aq.QuoteCommitment || outcome.ExecutionID != task.ExecutionID {
		return Receipt{}, Settlement{}, ErrOutcomeMismatch
	}

	// Step 5: build the canonical Receipt, sign the settlement intent, submit release.
	receipt, err := p.Receipts.BuildReceipt(ctx, aq, outcome)
	if err != nil {
		return Receipt{}, Settlement{}, err
	}
	if receipt.Commitment == "" || receipt.QuoteCommitment != aq.QuoteCommitment {
		return Receipt{}, Settlement{}, errors.New("servicebridge: built receipt does not bind the accepted quote")
	}
	if _, signErr := p.Signer.SignSettlementIntent(ctx, receipt.Commitment); signErr != nil {
		return Receipt{}, Settlement{}, signErr
	}

	// Step 6: reconcile provider stablecoin credit from finalized wallet state.
	settlement, err := p.Receipts.VerifySettlement(ctx, aq)
	if err != nil {
		return receipt, Settlement{}, err
	}
	return receipt, settlement, nil
}
