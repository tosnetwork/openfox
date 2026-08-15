package nativeimpl

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/tosnetwork/openfox/pkg/atosbridge"
	nativev1 "github.com/tosnetwork/tos-protocol/gen/atos/native/v1"
	"github.com/tosnetwork/tos-protocol/pkg/buyersdk"
	"github.com/tosnetwork/tos-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-protocol/pkg/toschain"
)

type fakePreparer struct {
	prepared  *buyersdk.PreparedPurchase
	prepErr   error
	fundErr   error
	prepCalls int
	fundKeys  []string
}

func (f *fakePreparer) PreparePurchase(context.Context, buyersdk.PurchaseInput) (*buyersdk.PreparedPurchase, error) {
	f.prepCalls++
	if f.prepErr != nil {
		return nil, f.prepErr
	}
	return f.prepared, nil
}

func (f *fakePreparer) FundPurchase(_ context.Context, _ *buyersdk.PreparedPurchase, key string) (*toschain.FinalizedEscrowV1, error) {
	f.fundKeys = append(f.fundKeys, key)
	if f.fundErr != nil {
		return nil, f.fundErr
	}
	return &toschain.FinalizedEscrowV1{}, nil
}

func sampleInput() buyersdk.PurchaseInput {
	return buyersdk.PurchaseInput{
		Proposal: &nativev1.QuoteProposalV1{
			CapabilityId:         "cap_" + hex64,
			ProviderAgentId:      "agent_" + hex64,
			CapabilityVersion:    "1.0.0",
			ManifestDigest:       "sha256:" + hex64,
			ExpiresAtUnixSeconds: 1786800000,
			MaximumPrice: &nativev1.MoneyV1{
				AtomicAmount: "25000000",
				Asset: &nativev1.TOSAssetIdentityV1{
					Master:         &nativev1.TOSContractIdentityV1{Workchain: 0, AccountId: bytes.Repeat([]byte{0xAB}, 32)},
					WalletCodeHash: "tvm-cell-sha256:" + hex64,
				},
			},
		},
		ExecutionSignerEd25519: bytes.Repeat([]byte{0x01}, 32),
	}
}

func samplePrepared() *buyersdk.PreparedPurchase {
	return &buyersdk.PreparedPurchase{
		QuoteCommitment: "tvm-cell-sha256:" + hex64,
		Escrow:          nativecore.EscrowIdentityV1{Address: "0:" + hex64, StateInitBOC: "b5ee9c72..."},
		AmountAtomic:    "25000000",
	}
}

func TestBuyerSessionDelegatesPrepareAndFund(t *testing.T) {
	fp := &fakePreparer{prepared: samplePrepared()}
	session, err := NewBuyerSession(fp, sampleInput())
	if err != nil {
		t.Fatalf("new session: %v", err)
	}

	ref := atosbridge.CapabilityRef{CapabilityID: "cap_" + hex64}
	prop, err := session.RequestQuote(context.Background(), ref)
	if err != nil {
		t.Fatalf("request quote: %v", err)
	}
	if prop.MaxAtomicAmount != 25000000 || prop.Asset.Master != "0:"+strings.Repeat("ab", 32) ||
		prop.Capability.CapabilityID != ref.CapabilityID || prop.Capability.Version != "1.0.0" {
		t.Fatalf("proposal not mapped from negotiated input: %+v", prop)
	}

	aq, err := session.BuildAcceptedQuote(context.Background(), prop)
	if err != nil {
		t.Fatalf("build accepted quote: %v", err)
	}
	if fp.prepCalls != 1 || aq.QuoteCommitment != "tvm-cell-sha256:"+hex64 || aq.EscrowAddress != "0:"+hex64 {
		t.Fatalf("accepted quote not delegated to buyersdk: calls=%d aq=%+v", fp.prepCalls, aq)
	}

	if err := session.SignAndFundEscrow(context.Background(), aq); err != nil {
		t.Fatalf("fund: %v", err)
	}
	if len(fp.fundKeys) != 1 || fp.fundKeys[0] != aq.QuoteCommitment+":"+aq.EscrowAddress {
		t.Fatalf("funding must delegate with the stable purchase key, got %v", fp.fundKeys)
	}
}

func TestBuyerSessionRefusesMismatchedCapability(t *testing.T) {
	session, _ := NewBuyerSession(&fakePreparer{prepared: samplePrepared()}, sampleInput())
	if _, err := session.RequestQuote(context.Background(), atosbridge.CapabilityRef{CapabilityID: "cap_other"}); err == nil {
		t.Fatalf("a proposal for a different capability must be refused")
	}
}

func TestBuyerSessionFundRequiresPreparedPurchase(t *testing.T) {
	fp := &fakePreparer{prepared: samplePrepared()}
	session, _ := NewBuyerSession(fp, sampleInput())
	aq := atosbridge.AcceptedQuote{QuoteCommitment: "tvm-cell-sha256:" + hex64, EscrowAddress: "0:" + hex64}
	if err := session.SignAndFundEscrow(context.Background(), aq); err == nil {
		t.Fatalf("funding without a prepared purchase must fail closed")
	}
	if len(fp.fundKeys) != 0 {
		t.Fatalf("nothing may be funded before BuildAcceptedQuote prepared it")
	}
}

func TestBuyerSessionPrepareErrorNotStashed(t *testing.T) {
	fp := &fakePreparer{prepErr: errors.New("capability revoked in finalized state")}
	session, _ := NewBuyerSession(fp, sampleInput())
	prop, _ := session.RequestQuote(context.Background(), atosbridge.CapabilityRef{CapabilityID: "cap_" + hex64})
	if _, err := session.BuildAcceptedQuote(context.Background(), prop); err == nil {
		t.Fatalf("a rejected preparation must surface the buyersdk error")
	}
	if err := session.SignAndFundEscrow(context.Background(), atosbridge.AcceptedQuote{QuoteCommitment: "tvm-cell-sha256:" + hex64, EscrowAddress: "0:" + hex64}); err == nil {
		t.Fatalf("a failed preparation must leave nothing fundable")
	}
}

func TestBuyerSessionNeverSignsSettlement(t *testing.T) {
	session, _ := NewBuyerSession(&fakePreparer{prepared: samplePrepared()}, sampleInput())
	if _, err := session.SignSettlementIntent(context.Background(), "hash"); err == nil {
		t.Fatalf("the buyer must never sign a settlement intent")
	}
}
