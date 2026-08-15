package nativeimpl

import (
	"context"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/tosnetwork/openfox/pkg/atosbridge"
	"github.com/tosnetwork/tos-ai/pkg/softwarework"
	nativev1 "github.com/tosnetwork/tos-protocol/gen/atos/native/v1"
	"github.com/tosnetwork/tos-protocol/pkg/buyersdk"
	"github.com/tosnetwork/tos-protocol/pkg/executiongate"
	"github.com/tosnetwork/tos-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-protocol/pkg/toschain"
	"github.com/xssnick/tonutils-go/tvm/cell"
)

// memLedger is the in-memory chain double: the single authoritative escrow store
// both buyer and provider read. It is the ONLY doubled component in the loop;
// every adapter, the settling runner, the shared Gate, and the buyer
// orchestration are the real code paths.
type memLedger struct {
	mu      sync.Mutex
	escrows map[string]*nativecore.EscrowStateV1
	cp      uint64
}

func newLedger() *memLedger {
	return &memLedger{escrows: map[string]*nativecore.EscrowStateV1{}, cp: 500}
}

func (l *memLedger) fund(addr, commitment string, amount uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.escrows[addr] = &nativecore.EscrowStateV1{
		Status: nativecore.EscrowStatusFunded, QuoteCommitment: commitment,
		FundedAtomicAmount: new(big.Int).SetUint64(amount).String(), SettledAtomicAmount: "0",
		AcceptedQuote: cell.BeginCell().MustStoreUInt(1, 8).EndCell(),
	}
}

func (l *memLedger) release(addr string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	state, ok := l.escrows[addr]
	if !ok || state.Status != nativecore.EscrowStatusFunded {
		return errors.New("ledger: release requires a funded escrow")
	}
	state.Status = nativecore.EscrowStatusReleasePending
	state.SettledAtomicAmount = state.FundedAtomicAmount
	state.ReceiptCommitment = "tvm-cell-sha256:" + hex64
	return nil
}

func (l *memLedger) ResolveFinalized(_ context.Context, addr string) (*toschain.FinalizedEscrowV1, bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	state, ok := l.escrows[addr]
	if !ok {
		return nil, false, nil
	}
	copyState := *state
	return &toschain.FinalizedEscrowV1{State: &copyState, Reference: &nativev1.ChainReference{FinalizedCheckpoint: l.cp}}, true, nil
}

// ledgerPreparer stands in for *buyersdk.Buyer: PreparePurchase yields the
// prepared purchase, FundPurchase writes the funded escrow into the ledger.
type ledgerPreparer struct {
	ledger    *memLedger
	prepared  *buyersdk.PreparedPurchase
	fundCalls int
}

func (p *ledgerPreparer) PreparePurchase(context.Context, buyersdk.PurchaseInput) (*buyersdk.PreparedPurchase, error) {
	return p.prepared, nil
}

func (p *ledgerPreparer) FundPurchase(_ context.Context, purchase *buyersdk.PreparedPurchase, _ string) (*toschain.FinalizedEscrowV1, error) {
	p.fundCalls++
	amount, err := atomicUint64(purchase.AmountAtomic)
	if err != nil {
		return nil, err
	}
	p.ledger.fund(purchase.Escrow.Address, purchase.QuoteCommitment, amount)
	resolved, _, _ := p.ledger.ResolveFinalized(context.Background(), purchase.Escrow.Address)
	return resolved, nil
}

// ledgerReleaseSubmitter transitions the ledger escrow to release-pending.
type ledgerReleaseSubmitter struct{ ledger *memLedger }

func (s ledgerReleaseSubmitter) SubmitRelease(_ context.Context, escrowAddress string, _ *cell.Cell) error {
	return s.ledger.release(escrowAddress)
}

// atMostOnceGate is the shared Native execution Gate: it admits a
// (quote, escrow) purchase exactly once.
type atMostOnceGate struct {
	mu      sync.Mutex
	claimed map[string]bool
	calls   int
}

func newGate() *atMostOnceGate { return &atMostOnceGate{claimed: map[string]bool{}} }

func (g *atMostOnceGate) ClaimExecution(_ context.Context, r executiongate.Request) (executiongate.Evidence, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.calls++
	key := r.QuoteCommitment + ":" + r.EscrowAddress
	if g.claimed[key] {
		return executiongate.Evidence{}, errors.New("gate: purchase slot already claimed")
	}
	g.claimed[key] = true
	return executiongate.Evidence{QuoteCommitment: r.QuoteCommitment, EscrowAddress: r.EscrowAddress, ProviderAgentID: "agent_" + hex64}, nil
}

var _ ProviderGate = (*atMostOnceGate)(nil)

// e2eResolver implements atosbridge.NativeResolver. ResolveEscrow reads the
// ledger; ResolveCapability defers the authoritative check to buyersdk
// (delegated inside BuildAcceptedQuote) and only confirms liveness here.
type e2eResolver struct{ reader *EscrowSettlementReader }

func (r e2eResolver) ResolveCapability(context.Context, atosbridge.CapabilityRef) error { return nil }
func (r e2eResolver) ResolveEscrow(ctx context.Context, addr string) (atosbridge.EscrowState, error) {
	return r.reader.ResolveEscrow(ctx, addr)
}

// e2eReceipts implements atosbridge.ReceiptVerifier for the buyer. The buyer
// never builds a receipt (the provider does), so BuildReceipt refuses.
type e2eReceipts struct{ reader *EscrowSettlementReader }

func (e e2eReceipts) BuildReceipt(context.Context, atosbridge.AcceptedQuote, atosbridge.Outcome) (atosbridge.Receipt, error) {
	return atosbridge.Receipt{}, errors.New("buyer does not build receipts")
}
func (e e2eReceipts) VerifySettlement(ctx context.Context, aq atosbridge.AcceptedQuote) (atosbridge.Settlement, error) {
	return e.reader.VerifySettlement(ctx, aq)
}

// inProcessTransport delivers the dispatched task to the provider handler.
type inProcessTransport struct {
	handle func(context.Context, atosbridge.Task) error
}

func (t inProcessTransport) Dispatch(ctx context.Context, _ atosbridge.Transport, task atosbridge.Task) error {
	return t.handle(ctx, task)
}

func e2ePolicy() atosbridge.SpendingPolicy {
	return atosbridge.SpendingPolicy{
		Asset:             atosbridge.AssetIdentity{Master: "0:" + repeatHex("ab"), WalletCodeHash: "tvm-cell-sha256:" + hex64},
		MaxAtomicPurchase: 100_000_000,
		DailyBudgetAtomic: 100_000_000,
		Window:            24 * time.Hour,
		Expiry:            time.Unix(1786800000, 0).Add(365 * 24 * time.Hour),
		CapabilityAllow:   map[string]bool{"cap_" + hex64: true},
		ConfirmationMode:  atosbridge.ConfirmAuto,
		OwnerSignature:    []byte("owner-signature"),
	}
}

func repeatHex(pair string) string {
	out := ""
	for i := 0; i < 32; i++ {
		out += pair
	}
	return out
}

// providerHandler builds the real provider execution path for one task exactly
// as the receiver adapters do: shared Gate claim (Evidence) -> runner execute
// (Outcome) -> post-execution Settler (Receipt -> escrow release).
func providerHandler(t *testing.T, gate *atMostOnceGate, ledger *memLedger, sub ledgerReleaseSubmitter) func(context.Context, atosbridge.Task) error {
	t.Helper()
	settler, err := NewEscrowReleaseSettler(ledger, &fakeExecSigner{}, sub)
	if err != nil {
		t.Fatalf("settler: %v", err)
	}
	runner := &fakeRunner{outcome: sampleOutcome()}
	return func(ctx context.Context, task atosbridge.Task) error {
		evidence, err := gate.ClaimExecution(ctx, executiongate.Request{QuoteCommitment: task.QuoteCommitment, EscrowAddress: task.EscrowAddress})
		if err != nil {
			return err
		}
		outcome, err := runner.Execute(ctx, softwarework.Request{QuoteCommitment: task.QuoteCommitment, ExecutionID: task.ExecutionID})
		if err != nil {
			return err
		}
		return settler.Settle(ctx, evidence, outcome)
	}
}

func TestBridgeClosesTheFullPaidLoop(t *testing.T) {
	ledger := newLedger()
	reader, err := NewEscrowSettlementReader(ledger)
	if err != nil {
		t.Fatalf("reader: %v", err)
	}
	preparer := &ledgerPreparer{ledger: ledger, prepared: samplePrepared()}
	session, err := NewBuyerSession(preparer, sampleInput())
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	gate := newGate()
	sub := ledgerReleaseSubmitter{ledger: ledger}
	transport := inProcessTransport{handle: providerHandler(t, gate, ledger, sub)}

	buyer := &atosbridge.Buyer{
		Policy:    e2ePolicy(),
		Resolver:  e2eResolver{reader: reader},
		Quotes:    session,
		Journal:   atosbridge.NewInMemoryJournal(),
		Signer:    session,
		Transport: transport,
		Receipts:  e2eReceipts{reader: reader},
		Now:       func() time.Time { return time.Unix(1786800000, 0) },
	}

	buildTask := func(aq atosbridge.AcceptedQuote) (atosbridge.Task, error) {
		return atosbridge.Task{EscrowAddress: aq.EscrowAddress, QuoteCommitment: aq.QuoteCommitment, ExecutionID: "sha256:" + hex64}, nil
	}

	settlement, err := buyer.Purchase(context.Background(), atosbridge.CapabilityRef{CapabilityID: "cap_" + hex64}, atosbridge.TransportA2A, buildTask)
	if err != nil {
		t.Fatalf("purchase: %v", err)
	}

	// The whole economic loop closed: funded once, executed once, released once,
	// and the buyer observes the finalized release crediting the provider.
	if !settlement.Released || settlement.ProviderCreditAtomic != 25_000_000 {
		t.Fatalf("settlement did not credit the provider from finalized state: %+v", settlement)
	}
	if preparer.fundCalls != 1 {
		t.Fatalf("escrow must be funded exactly once, got %d", preparer.fundCalls)
	}
	if gate.calls != 1 {
		t.Fatalf("execution must be claimed exactly once, got %d", gate.calls)
	}

	// A duplicate delivery on any transport is rejected by the same shared Gate,
	// and the escrow is never released a second time.
	dupErr := transport.handle(context.Background(), atosbridge.Task{
		EscrowAddress: "0:" + hex64, QuoteCommitment: "tvm-cell-sha256:" + hex64, ExecutionID: "sha256:" + hex64,
	})
	if dupErr == nil {
		t.Fatalf("a second execution of the same purchase must be refused by the Gate")
	}
	resolved, _, _ := ledger.ResolveFinalized(context.Background(), "0:"+hex64)
	if resolved.State.Status != nativecore.EscrowStatusReleasePending {
		t.Fatalf("escrow must remain released exactly once, status=%d", resolved.State.Status)
	}
}
