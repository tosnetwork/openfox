package config

import (
	"strings"
	"testing"

	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
)

func validTOSEscrowEarningSettings() EarningSettings {
	digest := func(value string) string { return "sha256:" + strings.Repeat(value, 64) }
	cell := func(value string) string { return "tvm-cell-sha256:" + strings.Repeat(value, 64) }
	raw := func(value string) string { return "0:" + strings.Repeat(value, 64) }
	return EarningSettings{Enabled: true, Mode: "policy-gated", StateDir: "/var/lib/openfox/earning",
		OwnerID: "owner:test", AgentID: "agent:test", AuthorityID: "authority:test", MandateDigest: digest("3"),
		MessengerSocket: "/run/openfox/messenger.sock", MinimumIndependentCarriers: 2,
		TrustedIntentIssuerKeys: map[string]string{"agent:test": "ed25519:" + strings.Repeat("4", 64)},
		Carriers: []EarningCarrierSettings{
			{ID: "a", Endpoint: "https://carrier-a.example/v1/intents", ReadToken: NewSecureString("read-a")},
			{ID: "b", Endpoint: "https://carrier-b.example/v1/intents", ReadToken: NewSecureString("read-b")},
		},
		Gates:              EarningGateSettings{Contact: true, Agreement: true, TOSEscrow: true},
		Policy:             EarningPolicySettings{MinimumExpectedProfitAtomic: "0", MaximumLossAtomic: "0", MaximumOutgoingPaymentAtomic: "0"},
		SettlementAdapters: []string{"tos.escrow.paid-demand.v1"},
		TOSEscrow: EarningTOSEscrowSettings{Enabled: true, NetworkID: "tos:testnet",
			GenesisRootHash: digest("1"), GenesisFileHash: digest("2"),
			RPCEndpoints: []string{"https://rpc-a.example", "https://rpc-b.example", "https://rpc-c.example"},
			Quorum:       2, QueryTimeoutMillis: 5000, MaximumResponseBytes: 4 << 20, ReadinessMaximumAgeSeconds: 120,
			RegistryCodeBOCFile: "/etc/openfox/registry.boc", RegistryCodeHash: cell("4"),
			EscrowCodeBOCFile: "/etc/openfox/escrow.boc", EscrowCodeHash: nativecore.EscrowV2CodeHash,
			AssetWalletCodeBOCFile: "/etc/openfox/wallet.boc", AssetMasterAddress: raw("5"),
			AssetMasterCodeHash: cell("6"), AssetWalletCodeHash: cell("7"), AssetDecimals: 6,
			CapabilityID: "cap:test", CapabilityVersion: "1.0.0", TransportSecurityMode: 1,
			TransportMaximumBytes: 1 << 20, TransportBaseURL: "https://provider.example",
			FundingWindowSeconds: 600, ExecutionWindowSeconds: 3600, RefundDelaySeconds: 3600,
			BuyerAddress: raw("8"), ProviderWallet: raw("9"), Executable: "/opt/tos/bin/tosctl",
			ConfigPath: "/etc/tos/tosctl.json", ActionWallet: "buyer", ProviderActionWallet: "provider",
			DeploymentWallet: "deployer", RelayerAddress: raw("a"), CustodyJournalDirectory: "/var/lib/openfox/custody",
			CustodyQuorumConfigPaths: []string{"/etc/tos/rpc-b.json", "/etc/tos/rpc-c.json"},
			NetworkGlobalID:          -3, DeploymentNanoTOS: 100_000_000, ActionNanoTOS: 100_000_000,
			FeeReserveNanoTOS: 10_000_000, MaximumPurchases: 10, MaximumPerPurchaseAtomic: "100",
			MaximumTotalAtomic: "1000", BudgetWindowSeconds: 3600, PollIntervalMillis: 1000, FinalityTimeoutSeconds: 300,
			ProviderAuthorities: []EarningProviderOfferAuthoritySettings{{AgentID: "agent:test",
				PublicKey: "ed25519:" + strings.Repeat("b", 64), AgentGeneration: 1, ControllerPolicyDigest: digest("c"),
				DelegationDigest: digest("d"), ScopeBoundsDigest: digest("e"), OwnerMandateDigest: digest("f"),
				IssuanceAuthorityReferenceDigest: digest("0")}}}}
}

// Paid Demand settles only through the released escrow v2 contract: a
// well-formed hash of any other code is refused.
func TestPaidDemandRequiresTheReleasedEscrowCode(t *testing.T) {
	settings := validTOSEscrowEarningSettings()
	if err := settings.Validate(); err != nil {
		t.Fatalf("positive control: valid Paid Demand settings refused: %v", err)
	}
	for _, codeHash := range []string{"tvm-cell-sha256:" + strings.Repeat("1", 64),
		strings.ToUpper(nativecore.EscrowV2CodeHash), ""} {
		settings.TOSEscrow.EscrowCodeHash = codeHash
		err := settings.Validate()
		if err == nil || !strings.Contains(err.Error(), "escrow code") {
			t.Fatalf("escrow code %q: %v", codeHash, err)
		}
	}
}
