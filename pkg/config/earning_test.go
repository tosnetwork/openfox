package config

import (
	"strings"
	"testing"
)

func TestEarningDefaultsAndSideEffectsFailClosed(t *testing.T) {
	settings := DefaultConfig().Earning
	if err := settings.Validate(); err != nil {
		t.Fatal(err)
	}
	if settings.Enabled || !settings.ObserveOnly || settings.MinimumIndependentCarriers != 2 {
		t.Fatalf("unsafe defaults: %+v", settings)
	}
	settings.Gates.Contact = true
	if err := settings.Validate(); err == nil {
		t.Fatal("disabled configuration enabled contact")
	}
}

func TestEnabledEarningRequiresIndependentSecureCarriers(t *testing.T) {
	settings := EarningSettings{Enabled: true, StateDir: "/tmp/openfox-earning", OwnerID: "owner", AgentID: "agent", AuthorityID: "authority",
		MessengerSocket: "/tmp/openfox-messenger.sock",
		MandateDigest:   "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", MinimumIndependentCarriers: 2,
		TrustedIntentIssuerKeys: map[string]string{"agent:issuer": "ed25519:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		Gates:                   EarningGateSettings{Contact: true}, Policy: EarningPolicySettings{MinimumExpectedProfitAtomic: "1", MaximumLossAtomic: "10", MaximumOutgoingPaymentAtomic: "0"},
		Carriers: []EarningCarrierSettings{{ID: "a", Endpoint: "http://127.0.0.1:8081/v1/intents", ReadToken: NewSecureString("one")},
			{ID: "b", Endpoint: "http://localhost:8082/v1/intents", ReadToken: NewSecureString("two")}}}
	if err := settings.Validate(); err != nil {
		t.Fatal(err)
	}
	settings.Carriers = settings.Carriers[:1]
	if err := settings.Validate(); err == nil {
		t.Fatal("single Carrier enabled autonomous contact")
	}
}

func TestSharedEarningAuthorityRequiresCompleteMTLSIdentity(t *testing.T) {
	settings := EarningSettings{Enabled: true, Mode: "observe", ObserveOnly: true, StateDir: "/tmp/openfox-earning",
		OwnerID: "owner", AgentID: "agent", AuthorityID: "authority",
		MandateDigest:           "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		TrustedIntentIssuerKeys: map[string]string{"agent:issuer": "ed25519:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		Policy:                  EarningPolicySettings{MinimumExpectedProfitAtomic: "1", MaximumLossAtomic: "10"},
		Authority: EarningAuthoritySettings{Mode: "shared", Endpoint: "https://authority.example/v1/economic-authority",
			ServerName: "authority.example", CAFile: "/etc/openfox/authority-ca.pem", ClientCertFile: "/etc/openfox/client.pem",
			ClientKeyFile: "/etc/openfox/client.key", AuthorityPublicKey: "ed25519:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			InstanceID: "worker-a", TimeoutMillis: 5000}}
	if err := settings.Validate(); err != nil {
		t.Fatal(err)
	}
	settings.Authority.ClientKeyFile = "relative.key"
	if err := settings.Validate(); err == nil {
		t.Fatal("shared Authority accepted a relative client key path")
	}
}

func TestEarningCapabilityOfferIsOwnerBounded(t *testing.T) {
	settings := EarningSettings{Enabled: true, Mode: "observe", ObserveOnly: true, StateDir: "/tmp/openfox-earning",
		OwnerID: "owner", AgentID: "agent", AuthorityID: "authority",
		MandateDigest:           "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		TrustedIntentIssuerKeys: map[string]string{"agent": "ed25519:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		Policy:                  EarningPolicySettings{MinimumExpectedProfitAtomic: "1", MaximumLossAtomic: "10"},
		SettlementAdapters:      []string{"tos.payment.direct.v1"}}
	settings.Capabilities = []EarningCapabilitySettings{{Namespace: "tos.skill", Identifier: "review", Version: "1.0.0",
		EvidenceDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Offer: &EarningCapabilityOfferSettings{AssetNamespace: "tos.asset", AssetIdentifier: "native", Unit: "nanotos",
			MinimumRevenueAtomic: "100", MaximumRevenueAtomic: "200", MaximumUnitCostAtomic: "50",
			SettlementAdapterURI: "tos.payment.direct.v1", TaxonomyPrefixes: []string{"tos.taxonomy.v1/service/review"},
			RequiredKeywords: []string{"review"}, MinimumTTLSeconds: 60, MaximumTTLSeconds: 3600}}}
	if err := settings.Validate(); err != nil {
		t.Fatal(err)
	}
	settings.Capabilities[0].Offer.MaximumRevenueAtomic = "0200"
	if err := settings.Validate(); err == nil {
		t.Fatal("non-canonical owner offer amount was accepted")
	}
}

func TestAgentRelayDefaultsOffAndClientTrustIsComplete(t *testing.T) {
	settings := validAgentRelayEarningSettings("client")
	if err := settings.Validate(); err != nil {
		t.Fatal(err)
	}
	settings.AgentRelay.ProviderProvenance.CertificateSPKIDigest = ""
	if err := settings.Validate(); err == nil {
		t.Fatal("relay client accepted provenance without the owner SPKI pin")
	}
	settings = validAgentRelayEarningSettings("client")
	settings.AgentRelay.ClientRouteJournalDirectory = settings.AgentRelay.ClientAttemptJournalDirectory
	if err := settings.Validate(); err == nil {
		t.Fatal("relay client accepted one lock domain for attempt and owner route journals")
	}
	settings = DefaultConfig().Earning
	settings.AgentRelay.OfferIntentFile = "/etc/openfox/relay-offer.json"
	if err := settings.Validate(); err == nil {
		t.Fatal("disabled earning retained an active relay profile source")
	}
}

func TestAgentRelayAssuranceLevelIsExplicitAndIndependentFromMode(t *testing.T) {
	for _, assurance := range []string{"trusted-local", "authorized-single-provider", "autonomous-decentralized"} {
		settings := validAgentRelayEarningSettings("client")
		settings.AgentRelay.AssuranceLevel = assurance
		if err := settings.Validate(); err != nil {
			t.Fatalf("valid assurance %q was coupled to relay_exact mode: %v", assurance, err)
		}
	}
	settings := validAgentRelayEarningSettings("client")
	settings.AgentRelay.AssuranceLevel = ""
	if err := settings.Validate(); err == nil {
		t.Fatal("enabled Agent relay accepted an implicit assurance level")
	}
	settings.AgentRelay.AssuranceLevel = "production"
	if err := settings.Validate(); err == nil {
		t.Fatal("enabled Agent relay accepted an unknown assurance level")
	}
}

func TestAgentRelayProviderAdmissionAndNetworkPinsFailClosed(t *testing.T) {
	settings := validAgentRelayEarningSettings("provider")
	if err := settings.Validate(); err != nil {
		t.Fatal(err)
	}
	settings.AgentRelay.AdmissionLimits.MaximumActiveExecutions = 513
	if err := settings.Validate(); err == nil {
		t.Fatal("relay provider accepted an active-work limit beyond the protected durable bound")
	}
	settings = validAgentRelayEarningSettings("provider")
	settings.AgentRelay.TOS.RPCEndpoints[1] = settings.AgentRelay.TOS.RPCEndpoints[0]
	if err := settings.Validate(); err == nil {
		t.Fatal("relay provider accepted a duplicated RPC failure domain")
	}
}

func TestAgentRelayObservedSponsorshipBindsExactCustodyNetworkAndHistory(t *testing.T) {
	settings := validAgentRelayEarningSettings("provider")
	enableAgentRelayObservedSponsorship(&settings)
	settings.TOSPayment.MaximumTransactions = 10_000
	if err := settings.Validate(); err != nil {
		t.Fatalf("maximum supported corroboration history was rejected: %v", err)
	}
	settings.TOSPayment.MaximumTransactions = 10_001
	if err := settings.Validate(); err == nil {
		t.Fatal("corroboration history beyond the tosctl protocol bound was accepted")
	}
	settings = validAgentRelayEarningSettings("provider")
	enableAgentRelayObservedSponsorship(&settings)
	settings.TOSPayment.Network.ZeroStateRootHash = "sha256:" + strings.Repeat("f", 64)
	if err := settings.Validate(); err == nil {
		t.Fatal("sponsorship custody on another zero-state domain was accepted")
	}
	settings = validAgentRelayEarningSettings("provider")
	enableAgentRelayObservedSponsorship(&settings)
	settings.AgentRelay.AssuranceLevel = "autonomous-decentralized"
	if err := settings.Validate(); err == nil {
		t.Fatal("nonterminal RPC corroboration was upgraded to autonomous assurance")
	}
	settings = validAgentRelayEarningSettings("provider")
	enableAgentRelayObservedSponsorship(&settings)
	settings.AgentRelay.OwnerPolicy.FinalityProfiles[0].ProfileURI = "tos.finality.test.v1"
	if err := settings.Validate(); err == nil {
		t.Fatal("observed-only Agreement omitted its explicit client-corroborated terminal predicate")
	}
}

func enableAgentRelayObservedSponsorship(settings *EarningSettings) {
	digest := func(value string) string { return "sha256:" + strings.Repeat(value, 64) }
	settings.Gates.DirectPayment = true
	settings.SettlementAdapters = []string{"tos.payment.direct.v1"}
	settings.AgentRelay.OwnerPolicy.Modes = []string{"sponsor_only"}
	settings.AgentRelay.SponsorshipReleaseEvidenceClass = "observed_unproven"
	settings.AgentRelay.SponsorshipReleaseProfileURI = "agreement-payment-rpc-corroboration.v1"
	settings.AgentRelay.SponsorshipReleaseProfileDigest = digest("e")
	settings.AgentRelay.OwnerPolicy.FinalityProfiles[0].ProfileURI =
		"tos.sponsorship.client-corroborated-terminal.v1"
	settings.AgentRelay.OwnerPolicy.FinalityProfiles[0].TerminalEvidenceClass = "client_corroborated"
	settings.AgentRelay.OwnerPolicy.FinalityProfiles[0].MinimumConfirmationDepth = 1
	network := settings.AgentRelay.TOS.Network
	settings.TOSPayment = EarningTOSPaymentSettings{Enabled: true, Network: network,
		Executable: "/usr/bin/tosctl", ConfigPath: "/etc/tos/rpc-a.json", Wallet: "provider",
		SourceAccount: "0:" + strings.Repeat("1", 64), NetworkGlobalID: network.GlobalID,
		FeeReserveNanoTOS: 1, QuorumConfigPaths: []string{"/etc/tos/rpc-b.json", "/etc/tos/rpc-c.json"},
		EvidenceDirectory: "/var/lib/openfox/evidence", MaximumTransactions: 1000}
}

func validAgentRelayEarningSettings(role string) EarningSettings {
	digest := func(value string) string { return "sha256:" + strings.Repeat(value, 64) }
	network := EarningAgentRelayNetworkSettings{NetworkID: "tos:testnet", GlobalID: -3,
		ZeroStateRootHash: digest("1"), ZeroStateFileHash: digest("2"), WorkchainID: 0}
	settings := EarningSettings{Enabled: true, Mode: "policy-gated", StateDir: "/var/lib/openfox/earning",
		OwnerID: "owner:test", AgentID: "agent:test", AuthorityID: "authority:test",
		MessengerSocket: "/run/openfox/messenger.sock", MandateDigest: digest("3"), MinimumIndependentCarriers: 2,
		TrustedIntentIssuerKeys: map[string]string{"agent:test": "ed25519:" + strings.Repeat("4", 64)},
		Gates:                   EarningGateSettings{Contact: true, Agreement: true, Execution: true, AgentRelay: true},
		Policy:                  EarningPolicySettings{MinimumExpectedProfitAtomic: "0", MaximumLossAtomic: "0", MaximumOutgoingPaymentAtomic: "0"},
		Carriers: []EarningCarrierSettings{
			{ID: "a", Endpoint: "https://carrier-a.example/v1/intents", ReadToken: NewSecureString("read-a")},
			{ID: "b", Endpoint: "https://carrier-b.example/v1/intents", ReadToken: NewSecureString("read-b")},
		},
		AgentRelay: EarningAgentRelaySettings{Enabled: true, Role: role, AssuranceLevel: "authorized-single-provider",
			OfferIntentFile: "/etc/openfox/relay-offer.json", HTTPTimeoutMillis: 5000, MaximumHTTPBytes: 1 << 20,
			TOS: EarningAgentRelayTOSSettings{Network: network,
				RPCEndpoints: []string{"https://rpc-a.example", "https://rpc-b.example", "https://rpc-c.example"},
				Quorum:       2, QueryTimeoutMillis: 5000, MaximumResponseBytes: 4 << 20, ReadinessMaximumAgeSeconds: 120}}}
	if role == "client" || role == "both" {
		settings.AgentRelay.ClientAttemptJournalDirectory = "/var/lib/openfox/relay-attempts"
		settings.AgentRelay.ClientRouteJournalDirectory = "/var/lib/openfox/relay-routes"
		settings.AgentRelay.ClientTerminalAccountingDirectory = "/var/lib/openfox/relay-terminal-accounting"
		settings.AgentRelay.ClientTLS = EarningAgentRelayClientTLSSettings{CAFile: "/etc/openfox/relay-ca.pem",
			ClientCertFile: "/etc/openfox/relay-client.pem", ClientKeyFile: "/etc/openfox/relay-client.key"}
		settings.AgentRelay.ProviderProvenance = EarningAgentRelayProvenanceSettings{ProviderAgentID: "agent:provider",
			IntentDigest: digest("5"), ProfileDigest: digest("6"), OperatorDomain: "operator:one",
			FailureDomain: "failure:one", EndpointOrigin: "https://relay.example",
			CertificateSPKIDigest: digest("7"), ImplementationEvidenceHash: digest("8")}
	}
	settings.AgentRelay.OwnerPolicy = EarningAgentRelayOwnerPolicySettings{NetworkDomains: []EarningAgentRelayNetworkSettings{network},
		Modes: []string{"relay_exact"}, MaximumSignedBytes: 64 << 10,
		TransactionProfiles: []EarningAgentRelayTransactionSettings{{ProfileURI: "tos.transaction.test.v1",
			ProfileDigest: digest("9"), MaximumSignedBytes: 64 << 10, InspectableSourceSequence: true,
			InspectableTransactionExpiry: true}},
		FinalityProfiles: []EarningAgentRelayFinalitySettings{{ProfileURI: "tos.finality.test.v1",
			ProfileDigest: digest("a"), TerminalEvidenceClass: "validator_finality",
			MinimumConfirmationDepth: 2, MinimumObservers: 3,
			MinimumOperatorDomains: 2, ReorgWindowSeconds: 10, MaximumResolutionSeconds: 120}},
		MaximumServiceFees: []EarningAgentRelayAssetAmountSettings{{Asset: EarningAgentRelayAssetSettings{
			AssetNamespace: "tos.asset", AssetIdentifier: "native", Unit: "nanotos"}, AmountAtomic: "1000"}}}
	if role == "provider" || role == "both" {
		settings.AgentRelay.ProviderJournalDirectory = "/var/lib/openfox/relay-provider"
		settings.AgentRelay.ProviderTLS = EarningAgentRelayProviderTLSSettings{Listen: "0.0.0.0:9443",
			ServerCertFile: "/etc/openfox/relay-server.pem", ServerKeyFile: "/etc/openfox/relay-server.key",
			ClientCAFile: "/etc/openfox/relay-client-ca.pem"}
		settings.AgentRelay.TerminalRetentionSeconds = 30 * 86400
		settings.AgentRelay.MaximumProtectedRecords = 128
		settings.AgentRelay.QuoteLifetimeSeconds = 60
		settings.AgentRelay.RelayFee = EarningAgentRelayAssetAmountSettings{Asset: EarningAgentRelayAssetSettings{
			AssetNamespace: "tos.asset", AssetIdentifier: "native", Unit: "nanotos"}, AmountAtomic: "3"}
		settings.AgentRelay.SponsorshipFee = EarningAgentRelayAssetAmountSettings{Asset: settings.AgentRelay.RelayFee.Asset,
			AmountAtomic: "2"}
		settings.AgentRelay.AdmissionLimits = EarningAgentRelayAdmissionSettings{MaximumQuoteReservations: 256,
			MaximumActiveExecutions: 128, MaximumActivePerRequester: 8, MaximumQuoteRequestsPerWindow: 4096,
			MaximumQuoteRequestsPerRequesterWindow: 256, QuoteRequestWindowSeconds: 60}
	}
	return settings
}
