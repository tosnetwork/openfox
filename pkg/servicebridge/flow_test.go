package servicebridge

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/openfox/pkg/actionauth"
)

// ---- fakes -------------------------------------------------------------------

type fakeResolver struct {
	capErr  error
	escrow  EscrowState
	escErr  error
	capHits int
}

func (f *fakeResolver) ResolveCapability(context.Context, CapabilityRef) error {
	f.capHits++
	return f.capErr
}
func (f *fakeResolver) ResolveEscrow(context.Context, string) (EscrowState, error) {
	return f.escrow, f.escErr
}

type fakeQuotes struct {
	proposal QuoteProposal
	aq       AcceptedQuote
}

func (f *fakeQuotes) RequestQuote(context.Context, CapabilityRef) (QuoteProposal, error) {
	return f.proposal, nil
}
func (f *fakeQuotes) BuildAcceptedQuote(context.Context, QuoteProposal) (AcceptedQuote, error) {
	return f.aq, nil
}

type fakeSigner struct {
	fundCalls   int
	fundErr     error
	intentCalls int
}

func (f *fakeSigner) SignAndFundEscrow(context.Context, AcceptedQuote) error {
	f.fundCalls++
	return f.fundErr
}
func (f *fakeSigner) SignSettlementIntent(context.Context, string) ([]byte, error) {
	f.intentCalls++
	return []byte("sig"), nil
}

type fakeTransport struct {
	dispatched []Transport
}

type fakeQuoteVerifier struct {
	calls         int
	escrowAddress string
	err           error
	terms         actionauth.PurchaseTerms
}

func (f *fakeQuoteVerifier) VerifyAcceptedQuote(
	_ context.Context,
	_ string,
	escrowAddress string,
	terms actionauth.PurchaseTerms,
) error {
	f.calls++
	f.escrowAddress = escrowAddress
	f.terms = terms
	return f.err
}

func (f *fakeTransport) Dispatch(_ context.Context, tr Transport, _ Task) error {
	f.dispatched = append(f.dispatched, tr)
	return nil
}

type fakeExec struct{ outcome Outcome }

func (f *fakeExec) Execute(context.Context, Task) (Outcome, error) { return f.outcome, nil }

type fakeReceipts struct {
	receipt    Receipt
	settlement Settlement
}

func (f *fakeReceipts) BuildReceipt(context.Context, AcceptedQuote, Outcome) (Receipt, error) {
	return f.receipt, nil
}
func (f *fakeReceipts) VerifySettlement(context.Context, AcceptedQuote) (Settlement, error) {
	return f.settlement, nil
}

type fakeConfirmer struct{ err error }

func (f *fakeConfirmer) Confirm(context.Context, QuoteProposal) error { return f.err }

// ---- fixtures ----------------------------------------------------------------

const qc = "tvm-cell-sha256:qc"
const esc = "EQescrow"

func happyBuyer() (*Buyer, *fakeResolver, *fakeSigner, *fakeTransport) {
	prop := baseProposal()
	digest := "sha256:" + strings.Repeat("a", 64)
	prop.Capability = CapabilityRef{AgentID: "agent_" + strings.Repeat("1", 64), CapabilityID: "cap_sw",
		Version: "1", ManifestDigest: digest, CapabilityClass: "compute.inference"}
	prop.Asset.Network = Network{ID: "tos-local", GenesisRootHash: strings.Repeat("2", 64),
		GenesisFileHash: strings.Repeat("3", 64)}
	prop.Asset.MasterCodeHash = "tvm-cell-sha256:" + strings.Repeat("4", 64)
	prop.TransportBindingDigest = digest
	prop.EscrowTermsDigest = digest
	prop.DisputeTerms = digest
	prop.Expiry = time.Unix(2_000_000_000, 0)
	res := &fakeResolver{escrow: EscrowState{Address: esc, Found: true, FundedAtomic: prop.MaxAtomicAmount}}
	sig := &fakeSigner{}
	tr := &fakeTransport{}
	policy := basePolicy()
	policy.Asset = prop.Asset
	b := &Buyer{
		Policy:        policy,
		Resolver:      res,
		Quotes:        &fakeQuotes{proposal: prop, aq: AcceptedQuote{Proposal: prop, QuoteCommitment: qc, EscrowAddress: esc}},
		Journal:       NewInMemoryJournal(),
		Signer:        sig,
		QuoteVerifier: &fakeQuoteVerifier{},
		Transport:     tr,
		Receipts:      &fakeReceipts{settlement: Settlement{Released: true, ProviderCreditAtomic: prop.MaxAtomicAmount}},
		Now:           func() time.Time { return time.Unix(1_700_000_000, 0) },
	}
	return b, res, sig, tr
}

func buildTask(aq AcceptedQuote) (Task, error) {
	return Task{EscrowAddress: aq.EscrowAddress, QuoteCommitment: aq.QuoteCommitment, ExecutionID: "sha256:x"}, nil
}

func ref() CapabilityRef { return CapabilityRef{CapabilityID: "cap_sw"} }

// ---- buyer tests -------------------------------------------------------------

func TestBuyerHappyPath(t *testing.T) {
	b, res, sig, tr := happyBuyer()
	s, err := b.Purchase(context.Background(), ref(), TransportA2A, buildTask)
	if err != nil {
		t.Fatalf("purchase: %v", err)
	}
	if !s.Released {
		t.Fatalf("want released settlement")
	}
	if sig.fundCalls != 1 {
		t.Fatalf("want exactly one funding, got %d", sig.fundCalls)
	}
	if res.capHits != 1 {
		t.Fatalf("capability must be re-resolved from finalized state once, got %d", res.capHits)
	}
	if len(tr.dispatched) != 1 || tr.dispatched[0] != TransportA2A {
		t.Fatalf("want one A2A dispatch, got %v", tr.dispatched)
	}
	verifier := b.QuoteVerifier.(*fakeQuoteVerifier)
	if verifier.calls != 1 || verifier.escrowAddress != esc || verifier.terms.PriceAtomic != "25000000" {
		t.Fatalf("finalized Quote verification = %+v", verifier)
	}
	rec, _ := b.Journal.Get(PurchaseKey{QuoteCommitment: qc, EscrowAddress: esc})
	if rec.Phase != PhaseResolved {
		t.Fatalf("journal must end resolved, got %s", rec.Phase)
	}
}

func TestBuyerAtMostOnceFundingAcrossRetries(t *testing.T) {
	b, _, sig, tr := happyBuyer()
	for i := 0; i < 3; i++ {
		if _, err := b.Purchase(context.Background(), ref(), TransportMCP, buildTask); err != nil {
			t.Fatalf("retry %d: %v", i, err)
		}
	}
	if sig.fundCalls != 1 {
		t.Fatalf("three retries must fund exactly once, got %d", sig.fundCalls)
	}
	if len(tr.dispatched) != 1 {
		t.Fatalf("resolved retries must not re-dispatch, got %d", len(tr.dispatched))
	}
}

func TestBuyerSettlementRecoveryDoesNotRedispatch(t *testing.T) {
	b, _, _, transport := happyBuyer()
	receipts := b.Receipts.(*fakeReceipts)
	receipts.settlement = Settlement{}
	if _, err := b.Purchase(context.Background(), ref(), TransportAgentPacket, buildTask); !errors.Is(err, ErrSettlementPending) {
		t.Fatalf("pending settlement = %v", err)
	}
	if len(transport.dispatched) != 1 {
		t.Fatalf("initial dispatches = %d", len(transport.dispatched))
	}
	receipts.settlement = Settlement{Released: true, ProviderCreditAtomic: baseProposal().MaxAtomicAmount}
	if _, err := b.Purchase(context.Background(), ref(), TransportAgentPacket, buildTask); err != nil {
		t.Fatal(err)
	}
	if len(transport.dispatched) != 1 {
		t.Fatalf("settlement recovery re-dispatched %d times", len(transport.dispatched))
	}
}

func TestBuyerStagedFundingReservationIsNotDoubleCounted(t *testing.T) {
	b, _, signer, _ := happyBuyer()
	b.Policy.DailyBudgetAtomic = b.Policy.MaxAtomicPurchase
	key := PurchaseKey{QuoteCommitment: qc, EscrowAddress: esc}
	if _, err := b.Journal.Begin(PurchaseRecord{Key: key, AssetMaster: b.Policy.Asset.Master,
		AtomicAmount: b.Policy.MaxAtomicPurchase}, b.now()); err != nil {
		t.Fatal(err)
	}
	if acquired, _, err := b.Journal.AcquireFundingLease(key); err != nil || !acquired {
		t.Fatalf("lease = %t, %v", acquired, err)
	}
	if err := b.Journal.Advance(key, PhaseFunded); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Purchase(context.Background(), ref(), TransportA2A, buildTask); err != nil {
		t.Fatal(err)
	}
	if signer.fundCalls != 0 {
		t.Fatalf("staged funded retry called custody %d times", signer.fundCalls)
	}
}

func TestBuyerFundingAmbiguousFailsClosed(t *testing.T) {
	b, res, _, _ := happyBuyer()
	res.escrow.FundedAtomic = 24_999_999 // not the exact quoted amount
	if _, err := b.Purchase(context.Background(), ref(), TransportA2A, buildTask); !errors.Is(err, ErrFundingAmbiguous) {
		t.Fatalf("want ErrFundingAmbiguous, got %v", err)
	}
}

func TestBuyerRechecksFinalizedQuoteAfterFundingRecovery(t *testing.T) {
	b, _, sig, tr := happyBuyer()
	verifier := b.QuoteVerifier.(*fakeQuoteVerifier)
	verifier.err = errors.New("quote is not finalized yet")
	if _, err := b.Purchase(context.Background(), ref(), TransportA2A, buildTask); err == nil {
		t.Fatal("unverified Quote reached task dispatch")
	}
	if sig.fundCalls != 1 || verifier.calls != 1 || len(tr.dispatched) != 0 {
		t.Fatalf("first attempt: funds=%d verifies=%d dispatches=%d", sig.fundCalls, verifier.calls, len(tr.dispatched))
	}
	verifier.err = nil
	if _, err := b.Purchase(context.Background(), ref(), TransportA2A, buildTask); err != nil {
		t.Fatalf("recovery: %v", err)
	}
	if sig.fundCalls != 1 || verifier.calls != 2 || len(tr.dispatched) != 1 {
		t.Fatalf("recovery: funds=%d verifies=%d dispatches=%d", sig.fundCalls, verifier.calls, len(tr.dispatched))
	}
}

func TestBuyerPolicyRejectionBlocksSpend(t *testing.T) {
	b, _, sig, _ := happyBuyer()
	b.Policy.CapabilityAllow = map[string]bool{"cap_other": true} // cap_sw not allowed
	if _, err := b.Purchase(context.Background(), ref(), TransportA2A, buildTask); !errors.Is(err, ErrCapabilityNotAllowed) {
		t.Fatalf("want ErrCapabilityNotAllowed, got %v", err)
	}
	if sig.fundCalls != 0 {
		t.Fatalf("policy rejection must not fund, got %d", sig.fundCalls)
	}
}

func TestBuyerCapabilityResolutionFailsClosed(t *testing.T) {
	b, res, sig, _ := happyBuyer()
	res.capErr = errors.New("revoked")
	if _, err := b.Purchase(context.Background(), ref(), TransportA2A, buildTask); err == nil {
		t.Fatalf("must fail closed when capability does not resolve")
	}
	if sig.fundCalls != 0 {
		t.Fatalf("must not fund on unresolved capability, got %d", sig.fundCalls)
	}
}

func TestBuyerManualConfirmation(t *testing.T) {
	b, _, sig, _ := happyBuyer()
	b.Policy.ConfirmationMode = ConfirmManual

	// No confirmer -> refuse.
	if _, err := b.Purchase(context.Background(), ref(), TransportA2A, buildTask); !errors.Is(err, ErrManualNoConfirmer) {
		t.Fatalf("want ErrManualNoConfirmer, got %v", err)
	}
	if sig.fundCalls != 0 {
		t.Fatalf("must not fund without confirmation, got %d", sig.fundCalls)
	}

	// Rejecting confirmer -> blocked.
	b.Confirm = &fakeConfirmer{err: errors.New("declined")}
	if _, err := b.Purchase(context.Background(), ref(), TransportA2A, buildTask); err == nil {
		t.Fatalf("declined confirmation must block")
	}

	// Approving confirmer -> proceeds and funds once.
	b.Confirm = &fakeConfirmer{}
	if _, err := b.Purchase(context.Background(), ref(), TransportA2A, buildTask); err != nil {
		t.Fatalf("approved confirmation: %v", err)
	}
	if sig.fundCalls != 1 {
		t.Fatalf("approved manual purchase must fund once, got %d", sig.fundCalls)
	}
}

// ---- provider tests ----------------------------------------------------------

func happyProvider() (*Provider, AcceptedQuote, Task) {
	prop := baseProposal()
	aq := AcceptedQuote{Proposal: prop, QuoteCommitment: qc, EscrowAddress: esc}
	task := Task{EscrowAddress: esc, QuoteCommitment: qc, ExecutionID: "sha256:x"}
	p := &Provider{
		Resolver: &fakeResolver{escrow: EscrowState{Address: esc, Found: true, FundedAtomic: prop.MaxAtomicAmount}},
		Executor: &fakeExec{outcome: Outcome{ExecutionID: "sha256:x", QuoteCommitment: qc, ArtifactDigest: "sha256:a"}},
		Receipts: &fakeReceipts{receipt: Receipt{Commitment: "tvm-cell-sha256:r", QuoteCommitment: qc}, settlement: Settlement{Released: true}},
		Signer:   &fakeSigner{},
	}
	return p, aq, task
}

func TestProviderHappyPath(t *testing.T) {
	p, aq, task := happyProvider()
	rec, s, err := p.HandleAdmittedTask(context.Background(), aq, task)
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	if rec.Commitment == "" || !s.Released {
		t.Fatalf("want bound receipt + released settlement, got %+v / %+v", rec, s)
	}
	if p.Signer.(*fakeSigner).intentCalls != 1 {
		t.Fatalf("provider must sign the settlement intent once")
	}
}

func TestProviderRejectsUnfundedEscrow(t *testing.T) {
	p, aq, task := happyProvider()
	p.Resolver.(*fakeResolver).escrow.FundedAtomic = 0
	if _, _, err := p.HandleAdmittedTask(context.Background(), aq, task); !errors.Is(err, ErrEscrowNotFunded) {
		t.Fatalf("want ErrEscrowNotFunded, got %v", err)
	}
}

func TestProviderRejectsUnboundTask(t *testing.T) {
	p, aq, task := happyProvider()
	task.QuoteCommitment = "tvm-cell-sha256:other"
	if _, _, err := p.HandleAdmittedTask(context.Background(), aq, task); !errors.Is(err, ErrOutcomeMismatch) {
		t.Fatalf("want ErrOutcomeMismatch, got %v", err)
	}
}
