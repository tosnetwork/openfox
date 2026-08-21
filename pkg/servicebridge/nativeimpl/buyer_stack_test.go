package nativeimpl

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/openfox/pkg/servicebridge"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/buyersdk"
	"github.com/xssnick/tonutils-go/tvm/cell"
)

type stackFundingSender struct{}

func (stackFundingSender) PrepareStablecoinFunding(
	context.Context,
	buyersdk.FundingIntent,
) (*buyersdk.PreparedFunding, error) {
	return nil, nil
}

func (stackFundingSender) BroadcastStablecoinFunding(
	context.Context,
	*buyersdk.PreparedFunding,
) error {
	return nil
}

func testChainBuyerStackConfig(t *testing.T) ChainBuyerStackConfig {
	t.Helper()
	state := t.TempDir()
	if err := os.Chmod(state, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(state, "budget"), 0o700); err != nil {
		t.Fatal(err)
	}
	registryCode := cell.BeginCell().MustStoreUInt(0xdeadbeef, 32).EndCell()
	escrowCode := cell.BeginCell().MustStoreUInt(0xeeeeeeee, 32).EndCell()
	walletCode := cell.BeginCell().MustStoreUInt(0xaaaaaaaa, 32).EndCell()
	return ChainBuyerStackConfig{
		StateDir: state,
		Network: &nativev1.NetworkDomain{NetworkId: "tos-local",
			GenesisRootHash: "sha256:" + strings.Repeat("1", 64),
			GenesisFileHash: "sha256:" + strings.Repeat("2", 64)},
		Endpoints:        []string{"http://127.0.0.1:19001", "http://127.0.0.1:19002", "http://127.0.0.1:19003"},
		RegistryCodeBOC:  base64.StdEncoding.EncodeToString(registryCode.ToBOC()),
		RegistryCodeHash: "tvm-cell-sha256:" + hex.EncodeToString(registryCode.Hash()),
		EscrowCodeHash:   "tvm-cell-sha256:" + hex.EncodeToString(escrowCode.Hash()),
		BuyerAddress:     "0:" + strings.Repeat("3", 64),
		BuyerAgentID:     "agent_" + strings.Repeat("4", 64),
		EscrowCode:       escrowCode,
		AssetWalletCode:  walletCode,
		FundingSender:    stackFundingSender{},
		BudgetLimits: buyersdk.BudgetLimits{Window: 24 * time.Hour, MaxPurchases: 4,
			MaxPerPurchaseAtomic: "100", MaxTotalAtomic: "300"},
		PollInterval: 10 * time.Millisecond, FinalityTimeout: time.Second,
	}
}

func TestNewChainBuyerStackAssemblesOneAuthorityGraph(t *testing.T) {
	stack, err := NewChainBuyerStack(testChainBuyerStackConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	if stack.SDK == nil || stack.Capability != stack.SDK || stack.Escrow == nil {
		t.Fatalf("stack = %+v", stack)
	}
}

func TestNewChainBuyerStackRejectsNonQuorumShapeAndPublicBudgetState(t *testing.T) {
	wrongQuorum := testChainBuyerStackConfig(t)
	wrongQuorum.Endpoints = append(wrongQuorum.Endpoints, "http://127.0.0.1:19004")
	if _, err := NewChainBuyerStack(wrongQuorum); err == nil {
		t.Fatal("buyer stack accepted a non-frozen endpoint shape")
	}

	publicBudget := testChainBuyerStackConfig(t)
	if err := os.Chmod(filepath.Join(publicBudget.StateDir, "budget"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := NewChainBuyerStack(publicBudget); err == nil {
		t.Fatal("buyer stack accepted a non-private budget journal")
	}
}

func TestNewChainNativeBuyerConnectsReviewedStack(t *testing.T) {
	stack, err := NewChainBuyerStack(testChainBuyerStackConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	buyer, err := NewChainNativeBuyer(ChainNativeBuyerConfig{
		Stack: stack, Input: sampleInput(), Policy: e2ePolicy(),
		Transport: fakeTaskTransport{}, Journal: servicebridge.NewInMemoryJournal(),
		Authorizer: allowActionAuthorizer{}, QuoteVerifier: allowQuoteVerifier{},
		MandateID: "mdt_" + strings.Repeat("5", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	if buyer == nil || buyer.QuoteVerifier == nil {
		t.Fatalf("buyer = %+v", buyer)
	}
}

func TestNewChainNativeBuyerRequiresReviewedStack(t *testing.T) {
	if _, err := NewChainNativeBuyer(ChainNativeBuyerConfig{}); err == nil {
		t.Fatal("chain-native buyer accepted a missing stack")
	}
}
