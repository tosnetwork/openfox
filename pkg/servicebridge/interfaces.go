package servicebridge

import "context"

// NativeResolver reads finalized Agent/Capability/escrow/wallet state from
// strict-majority TOS RPC. It is the ONLY source of canonical authority in the
// bridge; every candidate is re-resolved here before spending.
type NativeResolver interface {
	// ResolveCapability returns the finalized Capability and verifies it exactly
	// matches the requested owner Agent, version, manifest digest, network, and
	// registry code hash. A mismatch, tombstone, or revocation is an error.
	ResolveCapability(ctx context.Context, ref CapabilityRef) error
	// ResolveEscrow returns the finalized escrow state at the current checkpoint.
	ResolveEscrow(ctx context.Context, address string) (EscrowState, error)
}

// QuoteClient exchanges a non-canonical Quote Proposal and builds the canonical
// Accepted Quote plus its deterministic escrow StateInit.
type QuoteClient interface {
	RequestQuote(ctx context.Context, ref CapabilityRef) (QuoteProposal, error)
	BuildAcceptedQuote(ctx context.Context, proposal QuoteProposal) (AcceptedQuote, error)
}

// CustodySigner is the tosctl or hardware-backed signing boundary. It never
// exposes raw key material to the bridge.
type CustodySigner interface {
	// SignAndFundEscrow deploys/funds the escrow with the exact quoted amount
	// through the custody boundary. It returns after broadcasting the same signed
	// bytes it validated; the caller must treat the result as ambiguous until the
	// exact funded amount is finalized.
	SignAndFundEscrow(ctx context.Context, aq AcceptedQuote) error
	// SignSettlementIntent signs only the displayed settlement-intent hash for a
	// provider release; used by the provider flow.
	SignSettlementIntent(ctx context.Context, settlementIntentHash string) ([]byte, error)
}

// TaskTransport dispatches the bound task over one transport. All transports
// converge on the shared execution Gate, so a funded purchase admits at most
// one runner execution regardless of which transports are used.
type TaskTransport interface {
	Dispatch(ctx context.Context, t Transport, task Task) error
}

// ExecutionAdapter runs a manifest-bound task inside the OpenFox bounded
// executor (provider side) and returns a content-addressed Outcome.
type ExecutionAdapter interface {
	Execute(ctx context.Context, task Task) (Outcome, error)
}

// ReceiptVerifier builds a canonical Receipt from an Outcome (provider side) and
// verifies a Receipt + settlement from finalized state (buyer side).
type ReceiptVerifier interface {
	BuildReceipt(ctx context.Context, aq AcceptedQuote, outcome Outcome) (Receipt, error)
	VerifySettlement(ctx context.Context, aq AcceptedQuote) (Settlement, error)
}

// Confirmer is invoked when the owner spending policy requires manual approval
// before a spend. It returns nil to approve.
type Confirmer interface {
	Confirm(ctx context.Context, proposal QuoteProposal) error
}
