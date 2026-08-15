package nativeimpl

import (
	"context"
	"errors"
	"math/big"

	"github.com/tosnetwork/openfox/pkg/atosbridge"
	"github.com/tosnetwork/tos-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-protocol/pkg/toschain"
)

// finalizedEscrowReader is the one finalized read the buyer trusts. A
// *toschain.EscrowResolver satisfies it; keeping it an interface lets the
// status→bridge mapping be unit-tested without a live node.
type finalizedEscrowReader interface {
	ResolveFinalized(ctx context.Context, escrowAddress string) (*toschain.FinalizedEscrowV1, bool, error)
}

// EscrowSettlementReader derives BOTH the buyer's funding view and the buyer's
// settlement view from a single finalized escrow read. Funding and settlement
// are two projections of the same authoritative EscrowStateV1, so they can never
// disagree: there is one read, one status, one truth. The gateway, the relay,
// and any transport acknowledgement carry no authority here.
type EscrowSettlementReader struct {
	reader finalizedEscrowReader
}

// NewEscrowSettlementReader wraps a finalized escrow resolver.
func NewEscrowSettlementReader(reader finalizedEscrowReader) (*EscrowSettlementReader, error) {
	if reader == nil {
		return nil, errors.New("nativeimpl: escrow settlement reader needs a finalized escrow resolver")
	}
	return &EscrowSettlementReader{reader: reader}, nil
}

// ResolveEscrow maps the finalized escrow into the bridge's funding view. A
// not-found escrow is reported as not found (never as funded), and any amount
// that is negative or does not fit an atomic uint64 fails closed rather than
// wrapping.
func (r *EscrowSettlementReader) ResolveEscrow(ctx context.Context, escrowAddress string) (atosbridge.EscrowState, error) {
	resolved, found, err := r.reader.ResolveFinalized(ctx, escrowAddress)
	if err != nil {
		return atosbridge.EscrowState{}, err
	}
	if !found || resolved == nil || resolved.State == nil {
		return atosbridge.EscrowState{Address: escrowAddress, Found: false, AwaitingFunding: true}, nil
	}
	state := resolved.State
	funded, err := atomicUint64(state.FundedAtomicAmount)
	if err != nil {
		return atosbridge.EscrowState{}, err
	}
	settled, err := atomicUint64(state.SettledAtomicAmount)
	if err != nil {
		return atosbridge.EscrowState{}, err
	}
	return atosbridge.EscrowState{
		Address:         escrowAddress,
		Found:           true,
		FundedAtomic:    funded,
		SettledAtomic:   settled,
		ReceiptCommit:   state.ReceiptCommitment,
		AwaitingFunding: state.Status == nativecore.EscrowStatusAwaitingFunding,
		Checkpoint:      checkpointOf(resolved),
	}, nil
}

// VerifySettlement maps the finalized escrow into the bridge's settlement view.
// Release and refund are mutually exclusive terminal outcomes read from the same
// status the escrow decoder already validated (ReleasePending requires
// settled==funded and a bound Receipt; RefundPending requires settled==0). The
// buyer's own wallet balance is a separate stablecoin read and is left zero here.
func (r *EscrowSettlementReader) VerifySettlement(ctx context.Context, aq atosbridge.AcceptedQuote) (atosbridge.Settlement, error) {
	if aq.EscrowAddress == "" {
		return atosbridge.Settlement{}, errors.New("nativeimpl: accepted quote has no escrow address to settle")
	}
	resolved, found, err := r.reader.ResolveFinalized(ctx, aq.EscrowAddress)
	if err != nil {
		return atosbridge.Settlement{}, err
	}
	if !found || resolved == nil || resolved.State == nil {
		return atosbridge.Settlement{}, nil // not yet observable; neither released nor refunded
	}
	state := resolved.State
	settled, err := atomicUint64(state.SettledAtomicAmount)
	if err != nil {
		return atosbridge.Settlement{}, err
	}
	released := state.Status == nativecore.EscrowStatusReleasePending
	credit := uint64(0)
	if released {
		credit = settled
	}
	return atosbridge.Settlement{
		Released:             released,
		Refunded:             state.Status == nativecore.EscrowStatusRefundPending,
		ProviderCreditAtomic: credit,
		Checkpoint:           checkpointOf(resolved),
	}, nil
}

func checkpointOf(resolved *toschain.FinalizedEscrowV1) uint64 {
	if resolved == nil || resolved.Reference == nil {
		return 0
	}
	return resolved.Reference.FinalizedCheckpoint
}

// atomicUint64 parses a decimal atomic-amount string, rejecting empty, negative,
// non-numeric, or over-uint64 values so a malformed amount can never wrap into a
// small balance that would be mistaken for exact funding.
func atomicUint64(value string) (uint64, error) {
	if value == "" {
		return 0, nil
	}
	amount, ok := new(big.Int).SetString(value, 10)
	if !ok || amount.Sign() < 0 || !amount.IsUint64() {
		return 0, errors.New("nativeimpl: escrow amount is not a canonical atomic uint64")
	}
	return amount.Uint64(), nil
}
