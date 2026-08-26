package earning

import (
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/tosnetwork/openfox/cmd/openfox/internal"
	"github.com/tosnetwork/openfox/pkg/config"
	openfoxearning "github.com/tosnetwork/openfox/pkg/earning"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
)

func relayCommand() *cobra.Command {
	command := &cobra.Command{Use: "relay", Short: "Validate explicitly enabled Agent relay runtime routes", Args: cobra.NoArgs}
	command.AddCommand(relayClientCheckCommand(), relayProviderCheckCommand())
	return command
}

func relayClientCheckCommand() *cobra.Command {
	return &cobra.Command{Use: "client-check", Short: "Construct and close the configured mTLS relay client route", Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			settings, err := loadEnabledRelaySettings("client")
			if err != nil {
				return err
			}
			adapter, err := configuredRelayTOSAdapter(settings.AgentRelay.TOS)
			if err != nil {
				return err
			}
			if err := adapter.VerifyPinnedRelayGenesis(command.Context(),
				configuredRelayNetwork(settings.AgentRelay.TOS.Network)); err != nil {
				return err
			}
			authorities, err := openfoxearning.ParsePinnedIntentAuthorities(settings.TrustedIntentIssuerKeys)
			if err != nil {
				return err
			}
			var intent commerce.SignedAgentIntent
			if err := decodeBoundedJSONFile(settings.AgentRelay.OfferIntentFile, 2<<20, &intent); err != nil {
				return err
			}
			verified, err := openfoxearning.VerifyDiscoveredRelayServiceProfile(intent, authorities,
				configuredRelayOwnerPolicy(settings.AgentRelay.OwnerPolicy), time.Now().UTC())
			if err != nil {
				return err
			}
			if !relayProfileContainsNetwork(verified.Profile(), configuredRelayNetwork(settings.AgentRelay.TOS.Network)) {
				return errors.New("verified relay profile does not contain the owner-pinned TOS RPC network")
			}
			relayAuthorities, err := openfoxearning.BindPinnedRelayAuthorities(authorities,
				verified.Profile().NetworkDomains)
			if err != nil {
				return err
			}
			certificate, roots, err := loadTLSIdentity(settings.AgentRelay.ClientTLS.ClientCertFile,
				settings.AgentRelay.ClientTLS.ClientKeyFile, settings.AgentRelay.ClientTLS.CAFile, false)
			if err != nil {
				return err
			}
			routeJournal, err := openfoxearning.OpenDurableRelayRouteJournal(settings.AgentRelay.ClientRouteJournalDirectory)
			if err != nil {
				return err
			}
			defer routeJournal.Close()
			terminalAccounting, err := openfoxearning.OpenDurableRelayTerminalAccountingJournal(
				settings.AgentRelay.ClientTerminalAccountingDirectory)
			if err != nil {
				return err
			}
			defer terminalAccounting.Close()
			runtime, err := openfoxearning.OpenRelayClientHTTPRuntime(openfoxearning.RelayClientHTTPRuntimeConfig{
				Enabled: true, AssuranceLevel: agentrelay.AssuranceLevel(settings.AgentRelay.AssuranceLevel),
				VerifiedProfile: verified, AgentResolver: relayAuthorities,
				RequesterAgentID:        settings.AgentID,
				TLSConfig:               &tls.Config{Certificates: []tls.Certificate{certificate}, RootCAs: roots},
				ProviderProvenance:      configuredRelayProvenance(settings.AgentRelay.ProviderProvenance),
				AttemptJournalDirectory: settings.AgentRelay.ClientAttemptJournalDirectory,
				Timeout:                 time.Duration(settings.AgentRelay.HTTPTimeoutMillis) * time.Millisecond,
				MaximumResponseBytes:    int64(settings.AgentRelay.MaximumHTTPBytes),
			})
			if err != nil {
				return err
			}
			defer runtime.Close()
			transportModes := relayModeNames(runtime.TransportModes)
			_, err = fmt.Fprintf(command.OutOrStdout(),
				"transport_ready=true role=client assurance=%s transport_modes=%s sponsorship_release_class=%s sponsorship_release_profile=%s@%s rpc_quorum=%d auth=mutual-tls provenance=owner-spki-pinned journals=durable execution_readiness=use-capability-planner\n",
				settings.AgentRelay.AssuranceLevel, transportModes,
				settings.AgentRelay.SponsorshipReleaseEvidenceClass,
				settings.AgentRelay.SponsorshipReleaseProfileURI,
				settings.AgentRelay.SponsorshipReleaseProfileDigest,
				settings.AgentRelay.TOS.Quorum)
			return err
		}}
}

func relayProviderCheckCommand() *cobra.Command {
	return &cobra.Command{Use: "provider-check", Short: "Validate the selected relay provider assurance and owner bounds", Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			settings, err := loadEnabledRelaySettings("provider")
			if err != nil {
				return err
			}
			adapter, err := configuredRelayTOSAdapter(settings.AgentRelay.TOS)
			if err != nil {
				return err
			}
			if err := adapter.VerifyPinnedRelayGenesis(command.Context(),
				configuredRelayNetwork(settings.AgentRelay.TOS.Network)); err != nil {
				return err
			}
			if _, _, err := loadTLSIdentity(settings.AgentRelay.ProviderTLS.ServerCertFile,
				settings.AgentRelay.ProviderTLS.ServerKeyFile, settings.AgentRelay.ProviderTLS.ClientCAFile, true); err != nil {
				return err
			}
			profile, offerIntentDigest, err := loadConfiguredProviderRelayProfile(settings)
			if err != nil {
				return err
			}
			relayFee := configuredRelayAmount(settings.AgentRelay.RelayFee)
			sponsorshipFee := configuredRelayAmount(settings.AgentRelay.SponsorshipFee)
			if _, err := openfoxearning.NewBoundedRelayQuotePolicy(offerIntentDigest, relayFee, sponsorshipFee,
				time.Duration(settings.AgentRelay.QuoteLifetimeSeconds)*time.Second); err != nil ||
				!relayProfileSupportsConfiguredPricing(profile, settings.AgentRelay.OwnerPolicy.Modes, relayFee.Asset) {
				return errors.New("bounded relay QuotePolicy conflicts with the signed provider profile")
			}
			assurance := agentrelay.AssuranceLevel(settings.AgentRelay.AssuranceLevel)
			if !relayProfileSupportsAssurance(profile, assurance) {
				return errors.New("signed provider profile does not support the owner-selected assurance level")
			}
			_, _ = fmt.Fprintf(command.OutOrStdout(),
				"configuration_ready=true role=provider assurance=%s configured_modes=%s sponsorship_release_class=%s sponsorship_release_profile=%s@%s quote_policy=owner-fixed rpc_quorum=%d runtime_readiness=checked-at-open\n",
				assurance, strings.Join(settings.AgentRelay.OwnerPolicy.Modes, ","),
				settings.AgentRelay.SponsorshipReleaseEvidenceClass,
				settings.AgentRelay.SponsorshipReleaseProfileURI,
				settings.AgentRelay.SponsorshipReleaseProfileDigest,
				settings.AgentRelay.TOS.Quorum)
			return nil
		}}
}

func configuredRelaySponsorshipReleasePolicy(settings config.EarningAgentRelaySettings) openfoxearning.RelaySponsorshipReleasePolicy {
	return openfoxearning.RelaySponsorshipReleasePolicy{
		EvidenceClass: agentrelay.SponsorshipReleaseEvidenceClass(settings.SponsorshipReleaseEvidenceClass),
		ProfileURI:    settings.SponsorshipReleaseProfileURI, ProfileDigest: settings.SponsorshipReleaseProfileDigest,
	}
}

func loadEnabledRelaySettings(role string) (config.EarningSettings, error) {
	cfg, err := internal.LoadConfig()
	if err != nil {
		return config.EarningSettings{}, err
	}
	if err := cfg.Earning.Validate(); err != nil {
		return config.EarningSettings{}, err
	}
	relay := cfg.Earning.AgentRelay
	if !relay.Enabled || !cfg.Earning.Gates.AgentRelay {
		return config.EarningSettings{}, errors.New("Agent relay owner gate is disabled")
	}
	if role == "client" && relay.Role != "client" && relay.Role != "both" ||
		role == "provider" && relay.Role != "provider" && relay.Role != "both" {
		return config.EarningSettings{}, errors.New("configured Agent relay role does not permit this command")
	}
	return cfg.Earning, nil
}

func configuredRelayTOSAdapter(settings config.EarningAgentRelayTOSSettings) (*toschain.Adapter, error) {
	network := configuredRelayNetwork(settings.Network)
	return toschain.New(toschain.Config{Network: network.NetworkID,
		PinnedNetworkDomain: &toschain.PinnedNetworkDomain{NetworkID: network.NetworkID, GlobalID: network.GlobalID,
			ZeroStateRootHash: network.ZeroStateRootHash, ZeroStateFileHash: network.ZeroStateFileHash,
			WorkchainID: network.WorkchainID},
		Endpoints: append([]string(nil), settings.RPCEndpoints...), Quorum: int(settings.Quorum),
		QueryTimeout:     time.Duration(settings.QueryTimeoutMillis) * time.Millisecond,
		MaxResponseBytes: int64(settings.MaximumResponseBytes),
		ReadinessMaxAge:  time.Duration(settings.ReadinessMaximumAgeSeconds) * time.Second})
}

func configuredRelayNetwork(value config.EarningAgentRelayNetworkSettings) agentrelay.NetworkDomain {
	return agentrelay.NetworkDomain{NetworkID: value.NetworkID, GlobalID: value.GlobalID,
		ZeroStateRootHash: value.ZeroStateRootHash, ZeroStateFileHash: value.ZeroStateFileHash,
		WorkchainID: value.WorkchainID}
}

func configuredRelayOwnerPolicy(value config.EarningAgentRelayOwnerPolicySettings) openfoxearning.RelayOwnerPolicy {
	policy := openfoxearning.RelayOwnerPolicy{MaximumSignedBytes: value.MaximumSignedBytes}
	for _, network := range value.NetworkDomains {
		policy.NetworkDomains = append(policy.NetworkDomains, configuredRelayNetwork(network))
	}
	for _, mode := range value.Modes {
		policy.Modes = append(policy.Modes, agentrelay.Mode(mode))
	}
	for _, profile := range value.TransactionProfiles {
		policy.TransactionProfiles = append(policy.TransactionProfiles, agentrelay.TransactionProfile{
			ProfileURI: profile.ProfileURI, ProfileDigest: profile.ProfileDigest,
			MaximumSignedBytes: profile.MaximumSignedBytes, InspectableSourceSequence: profile.InspectableSourceSequence,
			InspectableTransactionExpiry: profile.InspectableTransactionExpiry})
	}
	for _, profile := range value.FinalityProfiles {
		policy.FinalityProfiles = append(policy.FinalityProfiles, agentrelay.FinalityProfile{
			ProfileURI: profile.ProfileURI, ProfileDigest: profile.ProfileDigest,
			TerminalEvidenceClass:    agentrelay.TerminalEvidenceClass(profile.TerminalEvidenceClass),
			MinimumConfirmationDepth: profile.MinimumConfirmationDepth, MinimumObservers: profile.MinimumObservers,
			MinimumOperatorDomains: profile.MinimumOperatorDomains, ReorgWindowSeconds: profile.ReorgWindowSeconds,
			MaximumResolutionSeconds: profile.MaximumResolutionSeconds})
	}
	for _, amount := range value.MaximumServiceFees {
		policy.MaximumServiceFees = append(policy.MaximumServiceFees, agentrelay.AssetAmount{
			Asset: agentrelay.AssetIdentity{AssetNamespace: amount.Asset.AssetNamespace,
				AssetIdentifier: amount.Asset.AssetIdentifier, Unit: amount.Asset.Unit}, AmountAtomic: amount.AmountAtomic})
	}
	return policy
}

func configuredRelayProvenance(value config.EarningAgentRelayProvenanceSettings) openfoxearning.RelayProviderProvenance {
	return openfoxearning.RelayProviderProvenance{ProviderAgentID: value.ProviderAgentID,
		IntentDigest: value.IntentDigest, ProfileDigest: value.ProfileDigest, OperatorDomain: value.OperatorDomain,
		FailureDomain: value.FailureDomain, EndpointOrigin: value.EndpointOrigin,
		CertificatePinDigest: value.CertificateSPKIDigest, ImplementationEvidenceHash: value.ImplementationEvidenceHash}
}

func relayProfileContainsNetwork(profile agentrelay.RelayServiceProfile, network agentrelay.NetworkDomain) bool {
	for _, value := range profile.NetworkDomains {
		if value == network {
			return true
		}
	}
	return false
}

func loadConfiguredProviderRelayProfile(settings config.EarningSettings) (agentrelay.RelayServiceProfile, string, error) {
	var intent commerce.SignedAgentIntent
	if err := decodeBoundedJSONFile(settings.AgentRelay.OfferIntentFile, 2<<20, &intent); err != nil {
		return agentrelay.RelayServiceProfile{}, "", err
	}
	authorities, err := openfoxearning.ParsePinnedIntentAuthorities(settings.TrustedIntentIssuerKeys)
	verified, verifyErr := openfoxearning.VerifyDiscoveredRelayServiceProfile(intent, authorities,
		configuredRelayOwnerPolicy(settings.AgentRelay.OwnerPolicy), time.Now().UTC())
	if err != nil || verifyErr != nil {
		return agentrelay.RelayServiceProfile{}, "", errors.New("relay provider OFFER Intent is not owner-authorized")
	}
	profile := verified.Profile()
	if agentrelay.ValidateRelayServiceProfile(profile, time.Now().UTC()) != nil || profile.ProviderAgentID != settings.AgentID ||
		profile.ProviderAgentID != intent.Body.IssuerAgentID || !relayProfileContainsNetwork(profile,
		configuredRelayNetwork(settings.AgentRelay.TOS.Network)) {
		return agentrelay.RelayServiceProfile{}, "", errors.New("relay provider profile is invalid or outside the pinned TOS network")
	}
	return profile, verified.IntentDigest(), nil
}

func configuredRelayAmount(value config.EarningAgentRelayAssetAmountSettings) agentrelay.AssetAmount {
	return agentrelay.AssetAmount{Asset: agentrelay.AssetIdentity{AssetNamespace: value.Asset.AssetNamespace,
		AssetIdentifier: value.Asset.AssetIdentifier, Unit: value.Asset.Unit}, AmountAtomic: value.AmountAtomic}
}

func relayProfileSupportsConfiguredPricing(profile agentrelay.RelayServiceProfile, ownerModes []string,
	asset agentrelay.AssetIdentity) bool {
	feeAsset := false
	for _, candidate := range profile.FeeAssets {
		feeAsset = feeAsset || candidate == asset
	}
	if !feeAsset {
		return false
	}
	for _, configured := range ownerModes {
		found := false
		for _, mode := range profile.SupportedModes {
			found = found || mode == agentrelay.Mode(configured)
		}
		if !found {
			return false
		}
	}
	return true
}

func relayProfileSupportsAssurance(profile agentrelay.RelayServiceProfile,
	wanted agentrelay.AssuranceLevel) bool {
	for _, supported := range profile.SupportedAssuranceLevels {
		if supported == wanted {
			return true
		}
	}
	return false
}

func relayModeNames(modes []agentrelay.Mode) string {
	names := make([]string, 0, len(modes))
	for _, mode := range modes {
		names = append(names, string(mode))
	}
	return strings.Join(names, ",")
}
