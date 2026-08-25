package earning

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/tosnetwork/openfox/pkg/config"
	openfoxearning "github.com/tosnetwork/openfox/pkg/earning"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/buyersdk"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/paiddemand"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

type paidDemandRuntime struct {
	Buyer            *buyersdk.PaidDemandBuyer
	Network          *nativev1.NetworkDomain
	EscrowResolver   *toschain.EscrowResolver
	NativeResolver   *toschain.SimplifiedNativeResolver
	AssetResolver    *toschain.StablecoinResolver
	OfferAuthorities openfoxearning.PinnedProviderOfferAuthorities
	EvidenceVerifier paiddemand.NativeEvidenceVerifier
	ProviderSigner   openfoxearning.ProviderOfferSigner
	PublicTerms      paiddemand.PublicTermsV1
	Negotiations     *openfoxearning.PaidDemandNegotiationStore
	ExecutionKey     ed25519.PrivateKey
	EscrowCode       *cell.Cell
	AssetWalletCode  *cell.Cell
	ActionSender     *buyersdk.TOSCTLWalletActionSender
	ProviderSender   *buyersdk.TOSCTLWalletActionSender
}

func openPaidDemandRuntime(settings config.EarningSettings, engine *openfoxearning.Engine,
	identityKey ed25519.PrivateKey, fence openfoxearning.WriterFenceProvider) (*paidDemandRuntime, error) {
	if engine == nil || engine.Authority == nil || fence == nil || !settings.TOSEscrow.Enabled {
		return nil, errors.New("Paid Demand runtime is disabled or incomplete")
	}
	configured := settings.TOSEscrow
	network := &nativev1.NetworkDomain{NetworkId: configured.NetworkID,
		GenesisRootHash: configured.GenesisRootHash, GenesisFileHash: configured.GenesisFileHash}
	chainAdapter, err := toschain.New(toschain.Config{Network: configured.NetworkID,
		Endpoints: append([]string(nil), configured.RPCEndpoints...), Quorum: int(configured.Quorum),
		QueryTimeout:     time.Duration(configured.QueryTimeoutMillis) * time.Millisecond,
		MaxResponseBytes: int64(configured.MaximumResponseBytes),
		ReadinessMaxAge:  time.Duration(configured.ReadinessMaximumAgeSeconds) * time.Second})
	if err != nil {
		return nil, err
	}
	checkpointDirectory := filepath.Join(settings.StateDir, "tos-escrow-checkpoints")
	if err := os.MkdirAll(checkpointDirectory, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(checkpointDirectory, 0o700); err != nil {
		return nil, err
	}
	registryRaw, registryCode, err := readPinnedCell(configured.RegistryCodeBOCFile, configured.RegistryCodeHash)
	if err != nil {
		return nil, fmt.Errorf("load pinned Native Registry code: %w", err)
	}
	locator, err := nativecore.NewLocator(network, -1, base64.StdEncoding.EncodeToString(registryRaw), configured.RegistryCodeHash)
	if err != nil || registryCode == nil {
		return nil, errors.New("construct pinned Native Registry locator")
	}
	nativeResolver, err := toschain.NewSimplifiedNativeResolver(chainAdapter, locator,
		filepath.Join(checkpointDirectory, "native.checkpoint"))
	if err != nil {
		return nil, err
	}
	nativeClient, err := toschain.NewDirectNativeClient(nativeResolver)
	if err != nil {
		return nil, err
	}
	assetResolver, err := toschain.NewStablecoinResolver(chainAdapter, network,
		filepath.Join(checkpointDirectory, "stablecoin.checkpoint"))
	if err != nil {
		return nil, err
	}
	escrowCodeRaw, escrowCode, err := readPinnedCell(configured.EscrowCodeBOCFile, configured.EscrowCodeHash)
	if err != nil || len(escrowCodeRaw) == 0 {
		return nil, fmt.Errorf("load pinned Paid Demand escrow code: %w", err)
	}
	escrowResolver, err := toschain.NewEscrowResolver(chainAdapter, network, configured.EscrowCodeHash,
		filepath.Join(checkpointDirectory, "paid-demand-escrow.checkpoint"))
	if err != nil {
		return nil, err
	}
	_, assetWalletCode, err := readPinnedCell(configured.AssetWalletCodeBOCFile, configured.AssetWalletCodeHash)
	if err != nil {
		return nil, fmt.Errorf("load pinned stablecoin wallet code: %w", err)
	}
	authorities, localPolicy, err := providerOfferAuthorities(configured.ProviderAuthorities, settings.AgentID)
	if err != nil {
		return nil, err
	}
	if len(identityKey) != ed25519.PrivateKeySize || !identityKey.Public().(ed25519.PublicKey).Equal(localPolicy.PublicKey) {
		return nil, errors.New("local Agent identity key differs from its Provider Offer authority pin")
	}
	executionKey, err := loadOrCreateNamedKey(filepath.Join(settings.StateDir, "identity"), "paid-demand-execution-ed25519.key")
	if err != nil {
		return nil, err
	}
	publicTerms := paiddemand.PublicTermsV1{SchemaVersion: 1, ProviderWallet: configured.ProviderWallet,
		AssetMasterAddress: configured.AssetMasterAddress, AssetMasterCodeHash: configured.AssetMasterCodeHash,
		AssetWalletCodeHash: configured.AssetWalletCodeHash, AssetDecimals: configured.AssetDecimals,
		CapabilityID: configured.CapabilityID, CapabilityVersion: configured.CapabilityVersion,
		ExecutionSignerEd25519: append([]byte(nil), executionKey.Public().(ed25519.PublicKey)...),
		TransportBinding: nativecore.TransportBindingV1{SecurityMode: configured.TransportSecurityMode,
			MaxRequestBytes: configured.TransportMaximumBytes, BaseURL: configured.TransportBaseURL},
		ExecutionProfileURI: paiddemand.ExecutionManifestProfileV1, FundingWindowSeconds: configured.FundingWindowSeconds,
		ExecutionWindowSeconds: configured.ExecutionWindowSeconds, RefundDelaySeconds: configured.RefundDelaySeconds}
	if _, err := paiddemand.CanonicalPublicTerms(publicTerms); err != nil {
		return nil, err
	}
	negotiations, err := openfoxearning.OpenPaidDemandNegotiationStore(filepath.Join(settings.StateDir, "paid-demand-negotiations"))
	if err != nil {
		return nil, err
	}
	deployer, err := buyersdk.NewTOSCTLPaidDemandEscrowDeployer(buyersdk.TOSCTLPaidDemandEscrowDeployerConfig{
		BinaryPath: configured.Executable, ConfigPath: configured.ConfigPath, WalletName: configured.DeploymentWallet,
		RelayerAddress: configured.RelayerAddress, AttachedNanoTOS: configured.DeploymentNanoTOS, VaultURL: configured.VaultURL})
	if err != nil {
		return nil, err
	}
	actionSender, err := buyersdk.NewTOSCTLWalletActionSender(buyersdk.TOSCTLWalletActionSenderConfig{
		BinaryPath: configured.Executable, ConfigPath: configured.ConfigPath, WalletName: configured.ActionWallet,
		FeeReserveNanoTOS: configured.FeeReserveNanoTOS, VaultURL: configured.VaultURL,
		JournalDirectory: configured.CustodyJournalDirectory})
	if err != nil {
		return nil, err
	}
	providerSender, err := buyersdk.NewTOSCTLWalletActionSender(buyersdk.TOSCTLWalletActionSenderConfig{
		BinaryPath: configured.Executable, ConfigPath: configured.ConfigPath, WalletName: configured.ProviderActionWallet,
		FeeReserveNanoTOS: configured.FeeReserveNanoTOS, VaultURL: configured.VaultURL,
		JournalDirectory: filepath.Join(configured.CustodyJournalDirectory, "provider")})
	if err != nil {
		return nil, err
	}
	offerResolver := openfoxearning.PinnedProviderOfferAuthorities{Policies: authorities}
	buyer, err := buyersdk.NewPaidDemandBuyer(buyersdk.PaidDemandBuyerConfig{NativeClient: nativeClient,
		AssetResolver: assetResolver, Network: network, RegistryCodeHash: configured.RegistryCodeHash,
		BuyerAddress: configured.BuyerAddress, AssetWalletCode: assetWalletCode,
		BudgetLimits: buyersdk.BudgetLimits{Window: time.Duration(configured.BudgetWindowSeconds) * time.Second,
			MaxPurchases: configured.MaximumPurchases, MaxPerPurchaseAtomic: configured.MaximumPerPurchaseAtomic,
			MaxTotalAtomic: configured.MaximumTotalAtomic}, EscrowResolver: escrowResolver,
		ProviderOfferResolver: offerResolver, EscrowCode: escrowCode, Deployer: deployer, ActionSender: actionSender,
		EffectAuthorizer: openfoxearning.PaidDemandCustodyAuthorizer{Engine: engine, FenceSource: fence, PolicyRevision: 1},
		OwnerID:          settings.OwnerID, AgentID: settings.AgentID, CallerID: settings.AgentID, NetworkGlobalID: configured.NetworkGlobalID,
		ActionNanoTOS: configured.ActionNanoTOS, PollInterval: time.Duration(configured.PollIntervalMillis) * time.Millisecond,
		FinalityTimeout: time.Duration(configured.FinalityTimeoutSeconds) * time.Second})
	if err != nil {
		return nil, err
	}
	evidence := paiddemand.NativeEvidenceVerifier{ProviderOffers: offerResolver,
		BuyerAccepts: paiddemand.QuorumBuyerAcceptVerifier{Resolver: escrowResolver, Network: network,
			ProviderOffers: offerResolver, Timeout: time.Duration(configured.QueryTimeoutMillis) * time.Millisecond}}
	return &paidDemandRuntime{Buyer: buyer, Network: network, EscrowResolver: escrowResolver, NativeResolver: nativeResolver,
		AssetResolver:    assetResolver,
		OfferAuthorities: offerResolver,
		EvidenceVerifier: evidence, ProviderSigner: openfoxearning.PolicyProviderOfferSigner{Policy: localPolicy,
			Key: identityKey, TTL: time.Hour}, PublicTerms: publicTerms, Negotiations: negotiations,
		ExecutionKey: executionKey, EscrowCode: escrowCode, AssetWalletCode: assetWalletCode,
		ActionSender: actionSender, ProviderSender: providerSender}, nil
}

func readPinnedCell(path, expectedHash string) ([]byte, *cell.Cell, error) {
	raw, err := readBoundedRegular(path, 4<<20, false)
	if err != nil {
		return nil, nil, err
	}
	root, err := cell.FromBOC(raw)
	if err != nil {
		return nil, nil, err
	}
	if expectedHash != "" && expectedHash != "tvm-cell-sha256:"+hex.EncodeToString(root.Hash()) {
		return nil, nil, errors.New("pinned TVM code hash mismatch")
	}
	return raw, root, nil
}

func providerOfferAuthorities(configured []config.EarningProviderOfferAuthoritySettings,
	localAgentID string) (map[string]openfoxearning.ProviderOfferAuthorityPolicy, openfoxearning.ProviderOfferAuthorityPolicy, error) {
	result := make(map[string]openfoxearning.ProviderOfferAuthorityPolicy, len(configured))
	var local openfoxearning.ProviderOfferAuthorityPolicy
	for _, item := range configured {
		key, err := decodeEd25519PublicKey(item.PublicKey)
		if err != nil {
			return nil, local, err
		}
		policy := openfoxearning.ProviderOfferAuthorityPolicy{AgentID: item.AgentID, PublicKey: key,
			AgentGeneration: item.AgentGeneration, ControllerPolicyDigest: item.ControllerPolicyDigest,
			DelegationDigest: item.DelegationDigest, ScopeBoundsDigest: item.ScopeBoundsDigest,
			OwnerMandateDigest:               item.OwnerMandateDigest,
			IssuanceAuthorityReferenceDigest: item.IssuanceAuthorityReferenceDigest}
		result[item.AgentID] = policy
		if item.AgentID == localAgentID {
			local = policy
		}
	}
	if local.AgentID == "" {
		return nil, local, errors.New("local Provider Offer authority is not pinned")
	}
	return result, local, nil
}

var _ commerce.PaidDemandNativeEvidenceVerifier = paiddemand.NativeEvidenceVerifier{}

// Keep the read path explicit: opening the runtime is also a bounded readiness
// check before an autonomous buyer can reserve capital.
func (runtime *paidDemandRuntime) CheckReady(ctx context.Context) error {
	if runtime == nil || runtime.EscrowResolver == nil || ctx == nil {
		return errors.New("Paid Demand runtime is unavailable")
	}
	return nil
}
