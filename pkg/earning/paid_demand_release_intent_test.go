package earning

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/buyersdk"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

type releaseAuthorizerFake struct{}

func (releaseAuthorizerFake) AuthorizeCustodyEffect(_ context.Context,
	request buyersdk.CustodyEffectRequest) (commerce.CustodyEffectAuthorization, error) {
	return commerce.CustodyEffectAuthorization{ActionKind: request.ActionKind, StableActionID: "release-action"}, nil
}

type releaseSenderFake struct{ body []byte }

func (sender *releaseSenderFake) PrepareWalletAction(_ context.Context,
	intent buyersdk.WalletActionIntent) (*buyersdk.PreparedWalletAction, error) {
	body, err := base64.StdEncoding.DecodeString(intent.BodyBOCBase64)
	if err != nil {
		return nil, err
	}
	sender.body = body
	return &buyersdk.PreparedWalletAction{Intent: intent}, nil
}

func (*releaseSenderFake) BroadcastWalletAction(context.Context, *buyersdk.PreparedWalletAction) error {
	return nil
}

// The provider must sign the escrow v2 settlement intent for the configured
// network: the contract rebuilds that exact intent, including the network's
// global id, before it checks the signature.
func TestPaidDemandReleaseSignsTheEscrowV2IntentForTheConfiguredNetwork(t *testing.T) {
	executionKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x51}, ed25519.SeedSize))
	sender := &releaseSenderFake{}
	const globalID int32 = -217
	service := PaidDemandProviderSettlement{Engine: &Engine{OwnerID: "owner:test", AgentID: "agent:test",
		Now: func() time.Time { return time.Unix(1_800_000_000, 0) }},
		Network:      &nativev1.NetworkDomain{NetworkId: "tos:test"},
		ExecutionKey: executionKey, ActionSender: sender, Authorizer: releaseAuthorizerFake{},
		NetworkGlobalID: globalID, ActionNanoTOS: 100_000_000}
	escrow := nativecore.EscrowIdentityV2{Address: "0:" + strings.Repeat("b0", 32)}
	state := &nativecore.EscrowStateV2{QuoteCommitment: "tvm-cell-sha256:" + strings.Repeat("c1", 32),
		ProviderAddress: "0:" + strings.Repeat("9e", 32), ExecutionDeadline: 1_800_000_500}
	quote := cell.BeginCell().MustStoreUInt(0x51, 8).EndCell()
	receipt := cell.BeginCell().MustStoreUInt(0x52, 8).EndCell()
	payment := commerce.AgreementObligation{ObligationID: "pay",
		Amount: &commerce.AgreementAmount{AmountAtomic: "25000000"}}
	if err := service.submitRelease(context.Background(), EngagementRecord{AgreementDigest: "sha256:" + strings.Repeat("a1", 32)},
		payment, escrow, state, quote, receipt, "tvm-cell-sha256:"+strings.Repeat("d2", 32)); err != nil {
		t.Fatal(err)
	}
	body, err := cell.FromBOC(sender.body)
	if err != nil {
		t.Fatal(err)
	}
	s := body.MustBeginParse()
	if op := s.MustLoadUInt(32); op != nativecore.EscrowReleaseOpcode {
		t.Fatalf("release opcode %x", op)
	}
	queryID := s.MustLoadUInt(64)
	signature := s.MustLoadSlice(512)
	if !bytes.Equal(s.MustLoadRef().MustToCell().Hash(), receipt.Hash()) {
		t.Fatal("release body carries another Receipt")
	}
	public, ok := executionKey.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("invalid key")
	}
	for _, network := range []int32{globalID, globalID + 1} {
		intent, err := nativecore.BuildEscrowSettlementIntentV2(network, escrow.Address, quote, receipt,
			big.NewInt(25_000_000), queryID)
		if err != nil {
			t.Fatal(err)
		}
		if verified := ed25519.Verify(public, intent.Hash(), signature); verified != (network == globalID) {
			t.Fatalf("signature over the intent for global id %d verified=%v", network, verified)
		}
	}
}
