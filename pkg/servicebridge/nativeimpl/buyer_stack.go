package nativeimpl

import (
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"strings"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/buyersdk"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
	"github.com/tosnetwork/tosutils-go/tvm/cell"

	"github.com/tosnetwork/openfox/pkg/actionauth"
	"github.com/tosnetwork/openfox/pkg/servicebridge"
)

// ChainBuyerStackConfig is the reviewed, route-independent production buyer
// assembly. Directories already exist and are owner-private; this constructor
// never creates custody or policy state on the caller's behalf.
type ChainBuyerStackConfig struct {
	StateDir         string
	Network          *nativev1.NetworkDomain
	Endpoints        []string
	RegistryCodeBOC  string
	RegistryCodeHash string
	EscrowCodeHash   string
	BuyerAddress     string
	BuyerAgentID     string
	EscrowCode       *cell.Cell
	AssetWalletCode  *cell.Cell
	FundingSender    buyersdk.FundingSender
	EscrowDeployer   EscrowDeployer
	BudgetLimits     buyersdk.BudgetLimits
	PollInterval     time.Duration
	FinalityTimeout  time.Duration
}

// ChainBuyerStack exposes the single concrete finalized authority graph used by
// the OpenFox buyer. SDK and Capability are the same buyersdk instance; Escrow
// backs both funding reconciliation and servicebridge settlement reads.
type ChainBuyerStack struct {
	SDK              *buyersdk.Buyer
	Capability       CapabilityValidator
	Escrow           *EscrowSettlementReader
	Deployer         EscrowDeployer
	Journal          servicebridge.PurchaseJournal
	Network          servicebridge.Network
	RegistryCodeHash string
}

// EscrowDeployer preserves the owner-review boundary between custody signing
// and one-way submission of the deterministic escrow deployment message.
type EscrowDeployer interface {
	PrepareEscrowDeployment(context.Context, *buyersdk.PreparedPurchase) (*buyersdk.PreparedEscrowDeployment, error)
	BroadcastEscrowDeployment(context.Context, *buyersdk.PreparedEscrowDeployment) error
}

// ChainNativeBuyerConfig supplies the per-purchase OpenFox components around a
// reviewed chain stack. Input remains one negotiation, while the stack's
// checkpoints and budget journal persist across purchases.
type ChainNativeBuyerConfig struct {
	Stack          *ChainBuyerStack
	Input          buyersdk.PurchaseInput
	Policy         servicebridge.SpendingPolicy
	OwnerPublicKey ed25519.PublicKey
	Transport      servicebridge.TaskTransport
	Confirm        servicebridge.Confirmer
	Authorizer     actionauth.Authorizer
	QuoteVerifier  servicebridge.FinalizedQuoteVerifier
	MandateID      string
}

// NewChainNativeBuyer connects the concrete finalized chain stack to the
// mandatory Messenger-authorized OpenFox buyer lifecycle for one negotiation.
func NewChainNativeBuyer(c ChainNativeBuyerConfig) (*servicebridge.Buyer, error) {
	if c.Stack == nil || c.Stack.SDK == nil || c.Stack.Capability == nil || c.Stack.Escrow == nil ||
		c.Stack.Deployer == nil || c.Stack.Journal == nil {
		return nil, errors.New("nativeimpl: chain-native buyer needs an assembled chain stack")
	}
	if err := servicebridge.VerifySpendingPolicySignature(c.Policy, c.OwnerPublicKey); err != nil {
		return nil, err
	}
	policy := c.Policy
	policy.OwnerSignature = append([]byte(nil), c.Policy.OwnerSignature...)
	policy.CapabilityAllow = make(map[string]bool, len(c.Policy.CapabilityAllow))
	for capability, allowed := range c.Policy.CapabilityAllow {
		policy.CapabilityAllow[capability] = allowed
	}
	session, err := NewBuyerSession(c.Stack.SDK, c.Input)
	if err != nil {
		return nil, err
	}
	return NewNativeBuyer(NativeBuyerConfig{
		Policy: policy, Escrow: c.Stack.Escrow, Capability: c.Stack.Capability,
		Session: session, Transport: c.Transport, Journal: c.Stack.Journal, Confirm: c.Confirm,
		Authorizer: c.Authorizer, QuoteVerifier: c.QuoteVerifier, MandateID: c.MandateID,
	})
}

// NewChainBuyerStack assembles the production Native buyer dependencies over
// exactly three RPC authorities with a strict 2-of-3 quorum. Network reads are
// lazy, so construction validates configuration and durable stores without
// claiming that any endpoint or chain object is live.
func NewChainBuyerStack(c ChainBuyerStackConfig) (*ChainBuyerStack, error) {
	if !filepath.IsAbs(c.StateDir) || filepath.Clean(c.StateDir) != c.StateDir ||
		c.Network == nil || len(c.Endpoints) != 3 || c.RegistryCodeBOC == "" ||
		c.RegistryCodeHash == "" || c.EscrowCodeHash == "" || c.BuyerAddress == "" ||
		c.BuyerAgentID == "" || c.EscrowCode == nil || c.AssetWalletCode == nil || c.FundingSender == nil ||
		c.EscrowDeployer == nil {
		return nil, errors.New("nativeimpl: chain buyer stack configuration is incomplete")
	}
	chain, err := toschain.New(toschain.Config{Network: c.Network.GetNetworkId(), Endpoints: c.Endpoints, Quorum: 2})
	if err != nil {
		return nil, err
	}
	locator, err := nativecore.NewLocator(c.Network, 0, c.RegistryCodeBOC, c.RegistryCodeHash)
	if err != nil {
		return nil, err
	}
	nativeResolver, err := toschain.NewSimplifiedNativeResolver(
		chain, locator, filepath.Join(c.StateDir, "native.checkpoint"))
	if err != nil {
		return nil, err
	}
	nativeClient, err := toschain.NewDirectNativeClient(nativeResolver)
	if err != nil {
		return nil, err
	}
	assetResolver, err := toschain.NewStablecoinResolver(
		chain, c.Network, filepath.Join(c.StateDir, "stablecoin.checkpoint"))
	if err != nil {
		return nil, err
	}
	escrowResolver, err := toschain.NewEscrowResolver(
		chain, c.Network, c.EscrowCodeHash, filepath.Join(c.StateDir, "escrow.checkpoint"))
	if err != nil {
		return nil, err
	}
	journal, err := buyersdk.NewFileBudgetJournal(filepath.Join(c.StateDir, "budget"))
	if err != nil {
		return nil, err
	}
	sdk, err := buyersdk.New(buyersdk.Config{
		NativeClient: nativeClient, AssetResolver: assetResolver, EscrowResolver: escrowResolver,
		FundingSender: c.FundingSender, BudgetJournal: journal, BudgetLimits: c.BudgetLimits,
		Network: c.Network, RegistryCodeHash: c.RegistryCodeHash, BuyerAddress: c.BuyerAddress,
		EscrowCode: c.EscrowCode, AssetWalletCode: c.AssetWalletCode, CallerID: c.BuyerAgentID,
		PollInterval: c.PollInterval, FinalityTimeout: c.FinalityTimeout,
	})
	if err != nil {
		return nil, err
	}
	escrow, err := NewEscrowSettlementReader(escrowResolver)
	if err != nil {
		return nil, err
	}
	purchaseJournal, err := servicebridge.NewFilePurchaseJournal(filepath.Join(c.StateDir, "purchases"))
	if err != nil {
		return nil, err
	}
	return &ChainBuyerStack{
		SDK: sdk, Capability: sdk, Escrow: escrow,
		Deployer: c.EscrowDeployer, Journal: purchaseJournal,
		Network: servicebridge.Network{
			ID:              c.Network.GetNetworkId(),
			GenesisRootHash: strings.TrimPrefix(c.Network.GetGenesisRootHash(), "sha256:"),
			GenesisFileHash: strings.TrimPrefix(c.Network.GetGenesisFileHash(), "sha256:"),
		},
		RegistryCodeHash: c.RegistryCodeHash,
	}, nil
}
