package nativeimpl

import (
	"context"
	"errors"
	"testing"

	"github.com/tosnetwork/openfox/pkg/servicebridge"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
)

type fakeFinalized struct {
	state *nativecore.EscrowStateV1
	found bool
	cp    uint64
	err   error
}

func (f fakeFinalized) ResolveFinalized(context.Context, string) (*toschain.FinalizedEscrowV1, bool, error) {
	if f.err != nil {
		return nil, false, f.err
	}
	if !f.found {
		return nil, false, nil
	}
	return &toschain.FinalizedEscrowV1{
		State:     f.state,
		Reference: &nativev1.ChainReference{FinalizedCheckpoint: f.cp},
	}, true, nil
}

func newReader(t *testing.T, f fakeFinalized) *EscrowSettlementReader {
	t.Helper()
	r, err := NewEscrowSettlementReader(f)
	if err != nil {
		t.Fatalf("new reader: %v", err)
	}
	return r
}

func TestResolveEscrowFundedView(t *testing.T) {
	r := newReader(t, fakeFinalized{found: true, cp: 42, state: &nativecore.EscrowStateV1{
		Status: nativecore.EscrowStatusFunded, FundedAtomicAmount: "25000000", SettledAtomicAmount: "0",
	}})
	got, err := r.ResolveEscrow(context.Background(), "0:"+hex64)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !got.Found || got.FundedAtomic != 25000000 || got.SettledAtomic != 0 || got.AwaitingFunding || got.Checkpoint != 42 {
		t.Fatalf("funded view wrong: %+v", got)
	}
}

func TestResolveEscrowNotFoundIsNeverFunded(t *testing.T) {
	r := newReader(t, fakeFinalized{found: false})
	got, err := r.ResolveEscrow(context.Background(), "0:"+hex64)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got.Found || got.FundedAtomic != 0 || !got.AwaitingFunding {
		t.Fatalf("missing escrow must read as unfunded/awaiting: %+v", got)
	}
}

func TestResolveEscrowRejectsOverflowAmount(t *testing.T) {
	r := newReader(t, fakeFinalized{found: true, state: &nativecore.EscrowStateV1{
		Status: nativecore.EscrowStatusFunded, FundedAtomicAmount: "18446744073709551616", // 2^64
	}})
	if _, err := r.ResolveEscrow(context.Background(), "0:"+hex64); err == nil {
		t.Fatalf("amount over uint64 must fail closed, not wrap")
	}
}

func TestVerifySettlementReleased(t *testing.T) {
	r := newReader(t, fakeFinalized{found: true, cp: 7, state: &nativecore.EscrowStateV1{
		Status: nativecore.EscrowStatusReleasePending, FundedAtomicAmount: "25000000",
		SettledAtomicAmount: "25000000", ReceiptCommitment: "tvm-cell-sha256:" + hex64,
	}})
	s, err := r.VerifySettlement(context.Background(), servicebridge.AcceptedQuote{EscrowAddress: "0:" + hex64})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !s.Released || s.Refunded || s.ProviderCreditAtomic != 25000000 || s.Checkpoint != 7 {
		t.Fatalf("release view wrong: %+v", s)
	}
}

func TestVerifySettlementRefundedCreditsNothing(t *testing.T) {
	r := newReader(t, fakeFinalized{found: true, state: &nativecore.EscrowStateV1{
		Status: nativecore.EscrowStatusRefundPending, FundedAtomicAmount: "25000000", SettledAtomicAmount: "0",
	}})
	s, err := r.VerifySettlement(context.Background(), servicebridge.AcceptedQuote{EscrowAddress: "0:" + hex64})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if s.Released || !s.Refunded || s.ProviderCreditAtomic != 0 {
		t.Fatalf("refund must credit the provider nothing: %+v", s)
	}
}

func TestVerifySettlementPendingIsNeitherReleasedNorRefunded(t *testing.T) {
	r := newReader(t, fakeFinalized{found: true, state: &nativecore.EscrowStateV1{
		Status: nativecore.EscrowStatusFunded, FundedAtomicAmount: "25000000", SettledAtomicAmount: "0",
	}})
	s, err := r.VerifySettlement(context.Background(), servicebridge.AcceptedQuote{EscrowAddress: "0:" + hex64})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if s.Released || s.Refunded {
		t.Fatalf("funded-but-unsettled escrow is not a settlement: %+v", s)
	}
}

func TestVerifySettlementRequiresEscrowAddress(t *testing.T) {
	r := newReader(t, fakeFinalized{found: true, state: &nativecore.EscrowStateV1{Status: nativecore.EscrowStatusFunded}})
	if _, err := r.VerifySettlement(context.Background(), servicebridge.AcceptedQuote{}); err == nil {
		t.Fatalf("settlement without an escrow address must fail closed")
	}
}

func TestReaderPropagatesReadError(t *testing.T) {
	r := newReader(t, fakeFinalized{err: errors.New("node unreachable")})
	if _, err := r.ResolveEscrow(context.Background(), "0:"+hex64); err == nil {
		t.Fatalf("read error must propagate (never a silent unfunded)")
	}
}
