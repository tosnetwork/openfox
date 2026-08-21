package nativeimpl

import (
	"context"
	"errors"
	"testing"

	"github.com/tosnetwork/openfox/pkg/actionauth"
	"github.com/tosnetwork/openfox/pkg/servicebridge"
)

type fakeCapValidator struct {
	calls int
	gotID string
	err   error
}

func (f *fakeCapValidator) ValidateCapability(_ context.Context, capabilityID, _, _, _ string) error {
	f.calls++
	f.gotID = capabilityID
	return f.err
}

type fakeTaskTransport struct{}

type allowActionAuthorizer struct{}

func (allowActionAuthorizer) Authorize(context.Context, actionauth.Action) error { return nil }

type allowQuoteVerifier struct{}

func (allowQuoteVerifier) VerifyAcceptedQuote(
	context.Context,
	string,
	actionauth.PurchaseTerms,
) error {
	return nil
}

func (fakeTaskTransport) Dispatch(context.Context, servicebridge.Transport, servicebridge.Task) error {
	return nil
}

func testEscrowReader(t *testing.T) *EscrowSettlementReader {
	t.Helper()
	r, err := NewEscrowSettlementReader(fundedEscrow(1, "tvm-cell-sha256:"+hex64, "25000000", true))
	if err != nil {
		t.Fatalf("reader: %v", err)
	}
	return r
}

func TestNativeBuyerResolverDelegatesCapability(t *testing.T) {
	cap := &fakeCapValidator{}
	resolver, err := NewNativeBuyerResolver(cap, testEscrowReader(t))
	if err != nil {
		t.Fatalf("resolver: %v", err)
	}
	ref := servicebridge.CapabilityRef{
		CapabilityID:   "cap_" + hex64,
		AgentID:        "agent_" + hex64,
		Version:        "1.0.0",
		ManifestDigest: "sha256:" + hex64,
	}
	if err := resolver.ResolveCapability(context.Background(), ref); err != nil {
		t.Fatalf("resolve capability: %v", err)
	}
	if cap.calls != 1 || cap.gotID != ref.CapabilityID {
		t.Fatalf("capability validation must delegate to the single authority: %+v", cap)
	}

	state, err := resolver.ResolveEscrow(context.Background(), "0:"+hex64)
	if err != nil || !state.Found || state.FundedAtomic != 25000000 {
		t.Fatalf("escrow view wrong: %+v err=%v", state, err)
	}
}

func TestNativeBuyerResolverPropagatesCapabilityRejection(t *testing.T) {
	cap := &fakeCapValidator{err: errors.New("capability revoked")}
	resolver, _ := NewNativeBuyerResolver(cap, testEscrowReader(t))
	if err := resolver.ResolveCapability(
		context.Background(),
		servicebridge.CapabilityRef{CapabilityID: "cap_x"},
	); err == nil {
		t.Fatalf("a rejected capability must fail closed")
	}
}

func TestBuyerReceiptVerifierNeverBuildsReceipts(t *testing.T) {
	v, err := NewBuyerReceiptVerifier(testEscrowReader(t))
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	if _, err := v.BuildReceipt(
		context.Background(),
		servicebridge.AcceptedQuote{},
		servicebridge.Outcome{},
	); err == nil {
		t.Fatalf("the buyer must never build a receipt")
	}
	s, err := v.VerifySettlement(context.Background(), servicebridge.AcceptedQuote{EscrowAddress: "0:" + hex64})
	if err != nil {
		t.Fatalf("verify settlement: %v", err)
	}
	_ = s // funded-but-unsettled: neither released nor refunded, covered in escrow_read_test
}

func TestNewNativeBuyerAssembles(t *testing.T) {
	session, err := NewBuyerSession(&fakePreparer{prepared: samplePrepared()}, sampleInput())
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	buyer, err := NewNativeBuyer(NativeBuyerConfig{
		Policy:        e2ePolicy(),
		Escrow:        testEscrowReader(t),
		Capability:    &fakeCapValidator{},
		Session:       session,
		Transport:     fakeTaskTransport{},
		Journal:       servicebridge.NewInMemoryJournal(),
		Authorizer:    allowActionAuthorizer{},
		QuoteVerifier: allowQuoteVerifier{},
		MandateID:     "mdt_" + hex64,
	})
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	if buyer.Resolver == nil || buyer.Quotes == nil || buyer.Signer == nil || buyer.Receipts == nil ||
		buyer.Transport == nil {
		t.Fatalf("assembled buyer is missing a component: %+v", buyer)
	}
	if _, ok := buyer.Signer.(servicebridge.AuthorizedCustodySigner); !ok {
		t.Fatalf("native buyer exposed custody without Messenger authority: %T", buyer.Signer)
	}
}

func TestNewNativeBuyerRejectsIncompleteConfig(t *testing.T) {
	if _, err := NewNativeBuyer(NativeBuyerConfig{}); err == nil {
		t.Fatalf("an empty native buyer config must fail closed")
	}
}

func TestNewNativeBuyerCannotOmitMessengerAuthority(t *testing.T) {
	session, err := NewBuyerSession(&fakePreparer{prepared: samplePrepared()}, sampleInput())
	if err != nil {
		t.Fatal(err)
	}
	base := NativeBuyerConfig{
		Policy: e2ePolicy(), Escrow: testEscrowReader(t), Capability: &fakeCapValidator{},
		Session: session, Transport: fakeTaskTransport{}, Journal: servicebridge.NewInMemoryJournal(),
		Authorizer: allowActionAuthorizer{}, MandateID: "mdt_" + hex64,
		QuoteVerifier: allowQuoteVerifier{},
	}
	withoutAuthorizer := base
	withoutAuthorizer.Authorizer = nil
	if _, err := NewNativeBuyer(withoutAuthorizer); err == nil {
		t.Fatal("native buyer accepted no Messenger authorizer")
	}
	withoutMandate := base
	withoutMandate.MandateID = ""
	if _, err := NewNativeBuyer(withoutMandate); err == nil {
		t.Fatal("native buyer accepted no mandate")
	}
	withoutVerifier := base
	withoutVerifier.QuoteVerifier = nil
	if _, err := NewNativeBuyer(withoutVerifier); err == nil {
		t.Fatal("native buyer accepted no finalized Quote verifier")
	}
}
