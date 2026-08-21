package nativeimpl

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/buyersdk"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

type chainBuyerConfigDocument struct {
	Schema                   string                  `json:"schema"`
	StateDir                 string                  `json:"state_dir"`
	Network                  *nativev1.NetworkDomain `json:"network"`
	Endpoints                []string                `json:"endpoints"`
	RegistryCodeBOCPath      string                  `json:"registry_code_boc_path"`
	RegistryCodeHash         string                  `json:"registry_code_hash"`
	EscrowCodeBOCPath        string                  `json:"escrow_code_boc_path"`
	EscrowCodeHash           string                  `json:"escrow_code_hash"`
	AssetWalletCodeBOCPath   string                  `json:"asset_wallet_code_boc_path"`
	BuyerAddress             string                  `json:"buyer_address"`
	BuyerAgentID             string                  `json:"buyer_agent_id"`
	Budget                   chainBuyerBudget        `json:"budget"`
	PollIntervalMilliseconds uint64                  `json:"poll_interval_milliseconds"`
	FinalityTimeoutSeconds   uint64                  `json:"finality_timeout_seconds"`
	TOSCTL                   chainBuyerTOSCTL        `json:"tosctl"`
}

type chainBuyerBudget struct {
	WindowSeconds        uint64 `json:"window_seconds"`
	MaxPurchases         uint64 `json:"max_purchases"`
	MaxPerPurchaseAtomic string `json:"max_per_purchase_atomic"`
	MaxTotalAtomic       string `json:"max_total_atomic"`
}

type chainBuyerTOSCTL struct {
	BinaryPath                string `json:"binary_path"`
	ConfigPath                string `json:"config_path"`
	WalletName                string `json:"wallet_name"`
	DeploymentAttachedNanoTOS uint64 `json:"deployment_attached_nanotos"`
	FundingAttachedNanoTOS    uint64 `json:"funding_attached_nanotos"`
	FundingForwardNanoTOS     uint64 `json:"funding_forward_nanotos"`
	TimeoutSeconds            uint64 `json:"timeout_seconds"`
}

// LoadChainBuyerStack reads one owner-private production config and assembles
// its reviewed code and tosctl custody adapters. It performs no network read,
// deployment, payment, or dispatch.
func LoadChainBuyerStack(path string) (*ChainBuyerStack, error) {
	if !secureConfigFile(path) {
		return nil, errors.New("nativeimpl: chain buyer config must be an owner-private absolute regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 || len(raw) > 1<<20 {
		return nil, errors.New("nativeimpl: read chain buyer config")
	}
	var document chainBuyerConfigDocument
	if err := decodeStrictJSON(raw, &document); err != nil || document.Schema != "tos.openfox.chain-buyer-config.v1" ||
		document.Network == nil || document.Budget.WindowSeconds == 0 || document.Budget.MaxPurchases == 0 ||
		document.Budget.WindowSeconds > 366*24*60*60 || document.PollIntervalMilliseconds < 10 ||
		document.PollIntervalMilliseconds > 60_000 || document.FinalityTimeoutSeconds == 0 ||
		document.FinalityTimeoutSeconds > 3600 || document.FinalityTimeoutSeconds*1000 <= document.PollIntervalMilliseconds ||
		document.TOSCTL.TimeoutSeconds == 0 || document.TOSCTL.TimeoutSeconds > 300 {
		return nil, errors.New("nativeimpl: invalid chain buyer config")
	}
	registryCode, registryBOC, err := readReviewedCode(document.RegistryCodeBOCPath)
	if err != nil || cellHashDigest(registryCode) != document.RegistryCodeHash {
		return nil, errors.New("nativeimpl: Registry code does not match reviewed hash")
	}
	escrowCode, _, err := readReviewedCode(document.EscrowCodeBOCPath)
	if err != nil || cellHashDigest(escrowCode) != document.EscrowCodeHash {
		return nil, errors.New("nativeimpl: escrow code does not match reviewed hash")
	}
	walletCode, _, err := readReviewedCode(document.AssetWalletCodeBOCPath)
	if err != nil {
		return nil, errors.New("nativeimpl: read reviewed asset-wallet code")
	}
	timeout := time.Duration(document.TOSCTL.TimeoutSeconds) * time.Second
	funding, err := buyersdk.NewTOSCTLFundingSender(buyersdk.TOSCTLFundingSenderConfig{
		BinaryPath: document.TOSCTL.BinaryPath, ConfigPath: document.TOSCTL.ConfigPath,
		WalletName: document.TOSCTL.WalletName, AttachedNanoTOS: document.TOSCTL.FundingAttachedNanoTOS,
		ForwardNanoTOS: document.TOSCTL.FundingForwardNanoTOS, Timeout: timeout,
	})
	if err != nil {
		return nil, err
	}
	deployer, err := buyersdk.NewTOSCTLEscrowDeployer(buyersdk.TOSCTLEscrowDeployerConfig{
		BinaryPath: document.TOSCTL.BinaryPath, ConfigPath: document.TOSCTL.ConfigPath,
		WalletName: document.TOSCTL.WalletName, BuyerAddress: document.BuyerAddress,
		AttachedNanoTOS: document.TOSCTL.DeploymentAttachedNanoTOS, Timeout: timeout,
	})
	if err != nil {
		return nil, err
	}
	return NewChainBuyerStack(ChainBuyerStackConfig{
		StateDir: document.StateDir, Network: document.Network, Endpoints: document.Endpoints,
		RegistryCodeBOC: registryBOC, RegistryCodeHash: document.RegistryCodeHash,
		EscrowCodeHash: document.EscrowCodeHash, BuyerAddress: document.BuyerAddress,
		BuyerAgentID: document.BuyerAgentID, EscrowCode: escrowCode, AssetWalletCode: walletCode,
		FundingSender: funding, EscrowDeployer: deployer, BudgetLimits: buyersdk.BudgetLimits{
			Window:       time.Duration(document.Budget.WindowSeconds) * time.Second,
			MaxPurchases: document.Budget.MaxPurchases, MaxPerPurchaseAtomic: document.Budget.MaxPerPurchaseAtomic,
			MaxTotalAtomic: document.Budget.MaxTotalAtomic,
		}, PollInterval: time.Duration(document.PollIntervalMilliseconds) * time.Millisecond,
		FinalityTimeout: time.Duration(document.FinalityTimeoutSeconds) * time.Second,
	})
}

func readReviewedCode(path string) (*cell.Cell, string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, "", errors.New("reviewed code path must be clean and absolute")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return nil, "", errors.New("reviewed code must be a non-writable regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 || len(raw) > 2<<20 {
		return nil, "", errors.New("read reviewed code")
	}
	encoded := strings.Join(strings.Fields(string(raw)), "")
	boc, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(boc) == 0 || base64.StdEncoding.EncodeToString(boc) != encoded {
		return nil, "", errors.New("reviewed code is not canonical Base64")
	}
	code, err := cell.FromBOC(boc)
	if err != nil {
		return nil, "", errors.New("reviewed code is not a cell BOC")
	}
	return code, encoded, nil
}
