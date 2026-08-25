package config

import (
	"errors"
	"math/big"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var (
	earningDigestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	earningEd25519KeyPattern = regexp.MustCompile(`^ed25519:[0-9a-f]{64}$`)
	earningCellDigestPattern = regexp.MustCompile(`^tvm-cell-sha256:[0-9a-f]{64}$`)
	earningRawWC0Pattern     = regexp.MustCompile(`^0:[0-9a-f]{64}$`)
)

func (settings EarningSettings) Validate() error {
	mode := settings.EffectiveMode()
	if mode != "off" && mode != "observe" && mode != "contact" && mode != "trusted" && mode != "policy-gated" && mode != "approval-required" {
		return errors.New("earning runtime mode is unknown")
	}
	minimumCarriers := settings.MinimumIndependentCarriers
	if minimumCarriers == 0 {
		minimumCarriers = 2
	}
	if minimumCarriers > 32 {
		return errors.New("earning minimum independent Carrier count must not exceed 32")
	}
	if !canonicalEconomicInteger(settings.Policy.MinimumExpectedProfitAtomic) || !canonicalEconomicInteger(settings.Policy.MaximumLossAtomic) ||
		settings.Policy.MaximumOutgoingPaymentAtomic != "" && !canonicalEconomicInteger(settings.Policy.MaximumOutgoingPaymentAtomic) ||
		settings.Policy.MinimumROIPPM > 1_000_000 || settings.Policy.MinimumPaymentProbabilityPPM > 1_000_000 ||
		settings.Policy.MinimumCompletionProbabilityPPM > 1_000_000 {
		return errors.New("earning economic policy is invalid")
	}
	anyGate := settings.Gates.Publication || settings.Gates.Contact || settings.Gates.Agreement || settings.Gates.Execution ||
		settings.Gates.DirectPayment || settings.Gates.ExternalSettlement || settings.Gates.TOSEscrow
	if !settings.Enabled {
		if anyGate || mode != "off" {
			return errors.New("disabled earning configuration cannot enable side-effect gates")
		}
		return nil
	}
	if mode == "off" {
		return errors.New("enabled earning configuration cannot use off mode")
	}
	if mode == "observe" && (anyGate || !settings.ObserveOnly) {
		return errors.New("observe mode requires observe_only and no side-effect gates")
	}
	if mode != "observe" && settings.ObserveOnly {
		return errors.New("side-effect earning modes cannot set observe_only")
	}
	if mode == "contact" && (settings.Gates.Agreement || settings.Gates.Execution || settings.Gates.DirectPayment ||
		settings.Gates.ExternalSettlement || settings.Gates.TOSEscrow) {
		return errors.New("contact mode cannot enable Agreement, execution, or settlement")
	}
	if mode == "trusted" && (settings.Gates.DirectPayment || settings.Gates.ExternalSettlement || settings.Gates.TOSEscrow) {
		return errors.New("trusted mode cannot enable value-transfer gates")
	}
	if mode == "approval-required" && anyGate {
		return errors.New("approval-required mode prepares proposals but cannot enable automatic side effects")
	}
	interval := settings.IntervalSeconds
	if interval == 0 {
		interval = 300
	}
	timeout := settings.CycleTimeoutSeconds
	if timeout == 0 {
		timeout = 60
	}
	if interval < 5 || interval > 86400 || timeout == 0 || timeout > interval || settings.JitterSeconds > interval {
		return errors.New("earning autonomous loop timing is invalid or unbounded")
	}
	if !filepath.IsAbs(settings.StateDir) || filepath.Clean(settings.StateDir) != settings.StateDir || settings.OwnerID == "" || settings.AgentID == "" ||
		settings.AuthorityID == "" || !earningDigestPattern.MatchString(settings.MandateDigest) {
		return errors.New("enabled earning configuration requires absolute state, owner, Agent, authority, and mandate identities")
	}
	authorityMode := settings.Authority.Mode
	if authorityMode == "" {
		authorityMode = "personal"
	}
	if authorityMode != "personal" && authorityMode != "shared" {
		return errors.New("earning authority mode must be personal or shared")
	}
	if authorityMode == "shared" {
		parsed, err := url.Parse(settings.Authority.Endpoint)
		if err != nil || parsed == nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
			parsed.Path != "/v1/economic-authority" || parsed.RawQuery != "" || parsed.Fragment != "" ||
			settings.Authority.ServerName == "" || settings.Authority.InstanceID == "" ||
			!earningEd25519KeyPattern.MatchString(settings.Authority.AuthorityPublicKey) ||
			settings.Authority.TimeoutMillis < 1000 || settings.Authority.TimeoutMillis > 60000 {
			return errors.New("shared earning authority endpoint, identity, key, and timeout are invalid")
		}
		for _, path := range []string{settings.Authority.CAFile, settings.Authority.ClientCertFile, settings.Authority.ClientKeyFile} {
			if !filepath.IsAbs(path) || filepath.Clean(path) != path {
				return errors.New("shared earning authority TLS paths must be canonical and absolute")
			}
		}
	} else if settings.Authority.Endpoint != "" || settings.Authority.ServerName != "" || settings.Authority.CAFile != "" ||
		settings.Authority.ClientCertFile != "" || settings.Authority.ClientKeyFile != "" || settings.Authority.AuthorityPublicKey != "" ||
		settings.Authority.InstanceID != "" || settings.Authority.TimeoutMillis != 0 {
		return errors.New("personal earning authority cannot configure shared authority fields")
	}
	if settings.Gates.Contact && uint32(len(settings.Carriers)) < minimumCarriers {
		return errors.New("autonomous contact requires the configured independent Carrier minimum")
	}
	if settings.Gates.Contact && (!filepath.IsAbs(settings.MessengerSocket) || filepath.Clean(settings.MessengerSocket) != settings.MessengerSocket) {
		return errors.New("autonomous contact requires an absolute Messenger authority socket")
	}
	if len(settings.TrustedIntentIssuerKeys) == 0 {
		return errors.New("enabled earning requires at least one trusted Intent issuer key")
	}
	seen := map[string]bool{}
	for _, carrier := range settings.Carriers {
		kind := carrier.Kind
		if kind == "" {
			kind = "http"
		}
		if carrier.ID == "" || seen[carrier.ID] || kind != "http" && kind != "directory" {
			return errors.New("earning Carrier configuration is invalid or duplicated")
		}
		if kind == "http" {
			parsed, err := url.Parse(carrier.Endpoint)
			if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "/v1/intents" ||
				carrier.ReadToken == nil || carrier.ReadToken.String() == "" || carrier.Directory != "" {
				return errors.New("earning HTTP Carrier configuration is invalid")
			}
			if parsed.Scheme != "https" && !(parsed.Scheme == "http" && earningLoopback(parsed.Hostname())) {
				return errors.New("earning Carrier requires HTTPS outside loopback development")
			}
			if settings.Gates.Publication && (carrier.RelayToken == nil || carrier.RelayToken.String() == "") {
				return errors.New("enabled earning publication requires a relay token for every HTTP Carrier")
			}
		} else if carrier.Endpoint != "" || carrier.ReadToken != nil || carrier.RelayToken != nil || !filepath.IsAbs(carrier.Directory) || filepath.Clean(carrier.Directory) != carrier.Directory {
			return errors.New("earning directory Carrier configuration is invalid")
		}
		seen[carrier.ID] = true
	}
	if !sort.StringsAreSorted(settings.SettlementAdapters) {
		return errors.New("earning settlement Adapters must be sorted")
	}
	capabilityKeys := make([]string, 0, len(settings.Capabilities))
	for _, capability := range settings.Capabilities {
		if capability.Namespace == "" || capability.Identifier == "" || capability.Version == "" || !earningDigestPattern.MatchString(capability.EvidenceDigest) {
			return errors.New("earning capability configuration is invalid")
		}
		if capability.Offer != nil {
			offer := capability.Offer
			minimum, minimumOK := new(big.Int).SetString(offer.MinimumRevenueAtomic, 10)
			maximum, maximumOK := new(big.Int).SetString(offer.MaximumRevenueAtomic, 10)
			cost, costOK := new(big.Int).SetString(offer.MaximumUnitCostAtomic, 10)
			if offer.AssetNamespace == "" || offer.AssetIdentifier == "" || offer.Unit == "" ||
				!canonicalEconomicInteger(offer.MinimumRevenueAtomic) || !canonicalEconomicInteger(offer.MaximumRevenueAtomic) ||
				!canonicalEconomicInteger(offer.MaximumUnitCostAtomic) || !minimumOK || !maximumOK || !costOK ||
				minimum.Cmp(maximum) > 0 || cost.Cmp(maximum) > 0 ||
				!containsSortedConfig(settings.SettlementAdapters, offer.SettlementAdapterURI) ||
				len(offer.TaxonomyPrefixes) == 0 || len(offer.TaxonomyPrefixes) > 16 || !sort.StringsAreSorted(offer.TaxonomyPrefixes) ||
				len(offer.RequiredKeywords) > 32 || !sort.StringsAreSorted(offer.RequiredKeywords) ||
				offer.MinimumTTLSeconds < 60 || offer.MaximumTTLSeconds < offer.MinimumTTLSeconds || offer.MaximumTTLSeconds > 90*86400 {
				return errors.New("earning capability offer policy is invalid or unbounded")
			}
			for index, prefix := range offer.TaxonomyPrefixes {
				if prefix == "" || index > 0 && offer.TaxonomyPrefixes[index-1] == prefix {
					return errors.New("earning capability offer taxonomy is invalid or duplicated")
				}
			}
			for index, keyword := range offer.RequiredKeywords {
				if keyword == "" || index > 0 && offer.RequiredKeywords[index-1] == keyword {
					return errors.New("earning capability offer keywords are invalid or duplicated")
				}
			}
		}
		capabilityKeys = append(capabilityKeys, capability.Namespace+"\x00"+capability.Identifier+"\x00"+capability.Version)
	}
	if !sort.StringsAreSorted(capabilityKeys) {
		return errors.New("earning capabilities must be sorted")
	}
	for agentID, publicKey := range settings.TrustedIntentIssuerKeys {
		if agentID == "" || !earningEd25519KeyPattern.MatchString(publicKey) {
			return errors.New("earning trusted Intent issuer key is invalid")
		}
	}
	if len(settings.Retrieval.AllowedOrigins) > 64 || !sort.StringsAreSorted(settings.Retrieval.AllowedOrigins) {
		return errors.New("earning retrieval origins are invalid or unsorted")
	}
	acquisition := settings.Acquisition
	if acquisition.ShortlistSize > 1000 || acquisition.MaximumPerIssuer > 1000 || acquisition.MaximumPerSource > 1000 ||
		acquisition.MaximumPerTaxonomy > 1000 || acquisition.MaximumPerValueBand > 1000 || acquisition.ExplorationPercent > 50 {
		return errors.New("earning acquisition shortlist policy is invalid or unbounded")
	}
	for index, origin := range settings.Retrieval.AllowedOrigins {
		parsed, err := url.Parse(origin)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" ||
			index > 0 && settings.Retrieval.AllowedOrigins[index-1] == origin {
			return errors.New("earning retrieval origin must be a unique canonical HTTPS origin")
		}
	}
	if len(settings.Retrieval.AllowedOrigins) > 0 && (settings.Retrieval.MaximumRedirects > 3 || settings.Retrieval.MaximumConnections == 0 ||
		settings.Retrieval.MaximumConnections > 16 || settings.Retrieval.MaximumResponseHeaderBytes == 0 || settings.Retrieval.MaximumResponseHeaderBytes > 256<<10 ||
		settings.Retrieval.MaximumCompressedBytes == 0 || settings.Retrieval.MaximumDecodedBytes < settings.Retrieval.MaximumCompressedBytes ||
		settings.Retrieval.MaximumDecodedBytes > 64<<20 || settings.Retrieval.TimeoutMillis < 100 || settings.Retrieval.TimeoutMillis > 60_000) {
		return errors.New("earning retrieval policy is invalid or unbounded")
	}
	private := settings.PrivateHandoff
	if private.Enabled {
		if !settings.Gates.Contact || !settings.Gates.Agreement || !settings.Gates.Execution || private.IngressProfileURI == "" ||
			private.IngressInstanceID == "" || !earningDigestPattern.MatchString(private.PurposeDigest) ||
			!earningDigestPattern.MatchString(private.RetentionPolicyDigest) || private.MaximumPlaintextBytes == 0 ||
			private.MaximumPlaintextBytes > 1<<30 || private.MaximumFiles == 0 || private.MaximumFiles > 10000 ||
			private.ChallengeTTLSeconds < 60 || private.ChallengeTTLSeconds > 86400 ||
			private.RetentionTTLSeconds < private.ChallengeTTLSeconds || private.RetentionTTLSeconds > 90*86400 ||
			len(private.AcceptedMediaTypes) == 0 || len(private.AcceptedMediaTypes) > 64 || !sort.StringsAreSorted(private.AcceptedMediaTypes) {
			return errors.New("earning private handoff policy is invalid or unbounded")
		}
		if private.IngressListen == "" && (len(private.Inputs) == 0 || len(private.Uploaders) == 0) ||
			(len(private.Inputs) == 0) != (len(private.Uploaders) == 0) {
			return errors.New("earning private handoff must configure a receiver ingress, or paired sender inputs and uploaders")
		}
		for index, mediaType := range private.AcceptedMediaTypes {
			if mediaType == "" || index > 0 && private.AcceptedMediaTypes[index-1] == mediaType {
				return errors.New("earning private handoff media types are invalid or duplicated")
			}
		}
		if private.IngressListen != "" {
			host, _, err := net.SplitHostPort(private.IngressListen)
			if err != nil {
				return errors.New("earning private ingress listen address is invalid")
			}
			loopback := earningLoopback(host)
			if !loopback && (private.IngressTLSCertFile == "" || private.IngressTLSKeyFile == "") {
				return errors.New("earning private ingress requires TLS outside loopback")
			}
			for _, path := range []string{private.IngressTLSCertFile, private.IngressTLSKeyFile} {
				if path != "" && (!filepath.IsAbs(path) || filepath.Clean(path) != path) {
					return errors.New("earning private ingress TLS paths must be canonical and absolute")
				}
			}
			if (private.IngressTLSCertFile == "") != (private.IngressTLSKeyFile == "") {
				return errors.New("earning private ingress certificate and key must be configured together")
			}
		}
		priorInput := ""
		for _, input := range private.Inputs {
			if input.ObligationID == "" || input.ObligationID <= priorInput || !filepath.IsAbs(input.Path) || filepath.Clean(input.Path) != input.Path ||
				input.CanonicalPath == "" || input.MediaType == "" || input.MaximumBytes == 0 || input.MaximumBytes > 1<<30 ||
				input.MaximumExpandedBytes < input.MaximumBytes || input.MaximumExpandedBytes > 4<<30 {
				return errors.New("earning private input sources are invalid or unsorted")
			}
			priorInput = input.ObligationID
		}
		priorUploader := ""
		for _, uploader := range private.Uploaders {
			parsed, err := url.Parse(uploader.Endpoint)
			if uploader.IngressInstanceID == "" || uploader.IngressInstanceID <= priorUploader || err != nil || parsed == nil ||
				parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path == "" || parsed.Path == "/" ||
				uploader.MaximumCiphertext == 0 || uploader.MaximumCiphertext > 1<<30 {
				return errors.New("earning private uploaders are invalid or unsorted")
			}
			if parsed.Scheme != "https" && !(uploader.AllowLoopbackHTTP && parsed.Scheme == "http" && earningLoopback(parsed.Hostname())) {
				return errors.New("earning private uploader requires HTTPS outside explicit loopback testing")
			}
			if uploader.CAFile != "" && (!filepath.IsAbs(uploader.CAFile) || filepath.Clean(uploader.CAFile) != uploader.CAFile) {
				return errors.New("earning private uploader CA path must be canonical and absolute")
			}
			priorUploader = uploader.IngressInstanceID
		}
	} else if private.IngressProfileURI != "" || private.IngressInstanceID != "" || private.IngressListen != "" ||
		len(private.Inputs) != 0 || len(private.Uploaders) != 0 {
		return errors.New("disabled private handoff cannot retain active endpoints or sources")
	}
	external := settings.ExternalSettlement
	if settings.Gates.ExternalSettlement != external.Enabled {
		return errors.New("external settlement gate and Adapter enablement must match")
	}
	if external.Enabled {
		parsed, err := url.Parse(external.Endpoint)
		if !settings.Gates.ExternalSettlement || external.AdapterURI == "" || external.SystemID == "" ||
			!earningDigestPattern.MatchString(external.AdapterProfileDigest) || parsed == nil || err != nil || parsed.Scheme != "https" ||
			parsed.Host == "" || parsed.User != nil || parsed.Path != "/v1/agreement-payments" || parsed.RawQuery != "" || parsed.Fragment != "" ||
			external.ServerName == "" || external.AttestorID == "" || !earningEd25519KeyPattern.MatchString(external.AttestorPublicKey) ||
			external.TimeoutMillis < 1000 || external.TimeoutMillis > 60000 {
			return errors.New("earning external settlement Adapter is invalid")
		}
		for _, path := range []string{external.CAFile, external.ClientCertFile, external.ClientKeyFile} {
			if !filepath.IsAbs(path) || filepath.Clean(path) != path {
				return errors.New("earning external settlement mTLS paths must be canonical and absolute")
			}
		}
		if !containsSortedConfig(settings.SettlementAdapters, external.AdapterURI) {
			return errors.New("external settlement Adapter is not in the supported Adapter inventory")
		}
	} else if external.AdapterURI != "" || external.SystemID != "" || external.AdapterProfileDigest != "" ||
		external.Endpoint != "" || external.AttestorID != "" || external.AttestorPublicKey != "" {
		return errors.New("disabled external settlement cannot retain an active Adapter")
	}
	if settings.Gates.Execution && !settings.Gates.Agreement ||
		(settings.Gates.DirectPayment || settings.Gates.ExternalSettlement || settings.Gates.TOSEscrow) && !settings.Gates.Agreement {
		return errors.New("execution and settlement gates require the Agreement gate")
	}
	if settings.Gates.Agreement && !settings.Gates.Contact {
		return errors.New("Agreement automation requires authenticated contact transport")
	}
	if settings.Gates.DirectPayment {
		payment := settings.TOSPayment
		if !payment.Enabled || !filepath.IsAbs(payment.Executable) || !filepath.IsAbs(payment.ConfigPath) ||
			!filepath.IsAbs(payment.EvidenceDirectory) || payment.Wallet == "" || payment.SourceAccount == "" || payment.NetworkGlobalID == 0 ||
			payment.FeeReserveNanoTOS == 0 || len(payment.QuorumConfigPaths) < 2 || payment.MaximumTransactions > 100000 ||
			payment.ResolveAttempts > 1000 || payment.ResolveIntervalMS > 60000 {
			return errors.New("direct payment gate requires bounded TOS custody configuration")
		}
		seenPaths := map[string]bool{filepath.Clean(payment.ConfigPath): true}
		for _, path := range payment.QuorumConfigPaths {
			clean := filepath.Clean(path)
			if !filepath.IsAbs(path) || seenPaths[clean] {
				return errors.New("TOS custody quorum paths must be distinct and absolute")
			}
			seenPaths[clean] = true
		}
		if !containsSortedConfig(settings.SettlementAdapters, "tos.payment.direct.v1") {
			return errors.New("direct payment gate requires the TOS direct-payment Adapter")
		}
	} else if settings.TOSPayment.Enabled {
		return errors.New("TOS payment Adapter cannot run while the direct-payment gate is closed")
	}
	escrow := settings.TOSEscrow
	if settings.Gates.TOSEscrow != escrow.Enabled {
		return errors.New("TOS escrow gate and Paid Demand Adapter enablement must match")
	}
	if escrow.Enabled {
		if escrow.NetworkID == "" || !earningDigestPattern.MatchString(escrow.GenesisRootHash) ||
			!earningDigestPattern.MatchString(escrow.GenesisFileHash) || len(escrow.RPCEndpoints) < 3 || len(escrow.RPCEndpoints) > 8 ||
			escrow.Quorum <= uint32(len(escrow.RPCEndpoints))/2 || escrow.Quorum > uint32(len(escrow.RPCEndpoints)) ||
			escrow.QueryTimeoutMillis < 100 || escrow.QueryTimeoutMillis > 30_000 || escrow.MaximumResponseBytes == 0 ||
			escrow.MaximumResponseBytes > 16<<20 || escrow.ReadinessMaximumAgeSeconds == 0 || escrow.ReadinessMaximumAgeSeconds > 3600 ||
			!earningCellDigestPattern.MatchString(escrow.RegistryCodeHash) || !earningCellDigestPattern.MatchString(escrow.EscrowCodeHash) ||
			!earningRawWC0Pattern.MatchString(escrow.AssetMasterAddress) || !earningCellDigestPattern.MatchString(escrow.AssetMasterCodeHash) ||
			!earningCellDigestPattern.MatchString(escrow.AssetWalletCodeHash) || escrow.AssetDecimals == 0 || escrow.AssetDecimals > 18 ||
			escrow.CapabilityID == "" || len(escrow.CapabilityID) > 256 || escrow.CapabilityVersion == "" || len(escrow.CapabilityVersion) > 64 ||
			escrow.TransportMaximumBytes == 0 || escrow.TransportMaximumBytes > 16<<20 ||
			escrow.FundingWindowSeconds < 60 || escrow.FundingWindowSeconds > 7*86400 ||
			escrow.ExecutionWindowSeconds < 60 || escrow.ExecutionWindowSeconds > 30*86400 ||
			escrow.RefundDelaySeconds < 60 || escrow.RefundDelaySeconds > 90*86400 ||
			!earningRawWC0Pattern.MatchString(escrow.BuyerAddress) || !earningRawWC0Pattern.MatchString(escrow.ProviderWallet) ||
			!earningRawWC0Pattern.MatchString(escrow.RelayerAddress) || escrow.ActionWallet == "" ||
			escrow.ProviderActionWallet == "" || escrow.DeploymentWallet == "" ||
			escrow.NetworkGlobalID == 0 || escrow.DeploymentNanoTOS == 0 || escrow.DeploymentNanoTOS > 1_000_000_000 ||
			escrow.ActionNanoTOS == 0 || escrow.ActionNanoTOS > 1_000_000_000 || escrow.FeeReserveNanoTOS == 0 ||
			escrow.FeeReserveNanoTOS > 1_000_000_000 || escrow.MaximumPurchases == 0 ||
			!canonicalEconomicInteger(escrow.MaximumPerPurchaseAtomic) || !canonicalEconomicInteger(escrow.MaximumTotalAtomic) ||
			escrow.BudgetWindowSeconds < 60 || escrow.BudgetWindowSeconds > 90*86400 ||
			escrow.PollIntervalMillis < 10 || escrow.PollIntervalMillis > 60_000 ||
			escrow.FinalityTimeoutSeconds == 0 || escrow.FinalityTimeoutSeconds > 3600 ||
			uint64(escrow.PollIntervalMillis) >= uint64(escrow.FinalityTimeoutSeconds)*1000 {
			return errors.New("Paid Demand TOS escrow policy is incomplete or unbounded")
		}
		for _, path := range []string{escrow.RegistryCodeBOCFile, escrow.EscrowCodeBOCFile, escrow.AssetWalletCodeBOCFile,
			escrow.Executable, escrow.ConfigPath, escrow.CustodyJournalDirectory} {
			if !filepath.IsAbs(path) || filepath.Clean(path) != path {
				return errors.New("Paid Demand code, custody, and journal paths must be canonical and absolute")
			}
		}
		transportURL, err := url.Parse(escrow.TransportBaseURL)
		if err != nil || transportURL == nil || transportURL.Host == "" || transportURL.User != nil || transportURL.Path != "" ||
			transportURL.RawQuery != "" || transportURL.Fragment != "" ||
			(escrow.TransportSecurityMode == 0 && (transportURL.Scheme != "http" || !earningLoopback(transportURL.Hostname()))) ||
			(escrow.TransportSecurityMode == 1 && transportURL.Scheme != "https") || escrow.TransportSecurityMode > 1 {
			return errors.New("Paid Demand transport binding is invalid")
		}
		seenEndpoints := map[string]bool{}
		for _, endpoint := range escrow.RPCEndpoints {
			parsed, err := url.Parse(endpoint)
			if err != nil || parsed == nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
				(parsed.Scheme != "https" && !(parsed.Scheme == "http" && earningLoopback(parsed.Hostname()))) || seenEndpoints[endpoint] {
				return errors.New("Paid Demand RPC endpoints must be distinct HTTPS or loopback HTTP URLs")
			}
			seenEndpoints[endpoint] = true
		}
		if !containsSortedConfig(settings.SettlementAdapters, "tos.escrow.paid-demand.v1") {
			return errors.New("Paid Demand gate requires its settlement Adapter in Inventory")
		}
		if len(escrow.ProviderAuthorities) == 0 || len(escrow.ProviderAuthorities) > 1024 {
			return errors.New("Paid Demand requires bounded pinned Provider authorities")
		}
		priorAgent := ""
		localFound := false
		for _, authority := range escrow.ProviderAuthorities {
			if authority.AgentID == "" || authority.AgentID <= priorAgent || !earningEd25519KeyPattern.MatchString(authority.PublicKey) ||
				authority.AgentGeneration == 0 || !earningDigestPattern.MatchString(authority.ControllerPolicyDigest) ||
				!earningDigestPattern.MatchString(authority.DelegationDigest) || !earningDigestPattern.MatchString(authority.ScopeBoundsDigest) ||
				!earningDigestPattern.MatchString(authority.OwnerMandateDigest) ||
				!earningDigestPattern.MatchString(authority.IssuanceAuthorityReferenceDigest) {
				return errors.New("Paid Demand Provider authority pins are invalid or unsorted")
			}
			localFound = localFound || authority.AgentID == settings.AgentID
			priorAgent = authority.AgentID
		}
		if !localFound {
			return errors.New("Paid Demand Provider mode requires the local Agent authority context")
		}
	} else if escrow.NetworkID != "" || len(escrow.RPCEndpoints) != 0 || escrow.Executable != "" ||
		len(escrow.ProviderAuthorities) != 0 {
		return errors.New("disabled Paid Demand Adapter cannot retain active chain or authority configuration")
	}
	if settings.Gates.Publication {
		publication := settings.Publication
		if publication.NetworkID == "" || publication.MinimumTTLSeconds < 60 || publication.MaximumTTLSeconds < publication.MinimumTTLSeconds ||
			publication.MaximumTTLSeconds > 90*86400 || publication.MinimumMarginPPM > 10_000_000 || publication.MaximumPriceChangePPM > 10_000_000 ||
			publication.MaximumActive == 0 || publication.MaximumActive > 1000 || publication.MaximumRevisionsPerObject == 0 ||
			publication.MaximumRevisionsPerObject > 1000 || publication.MaximumPublicationsPerPeriod == 0 ||
			publication.MaximumPublicationsPerPeriod > 10000 || publication.PeriodSeconds < 60 || publication.PeriodSeconds > 90*86400 ||
			len(publication.AllowedAudiences) == 0 || len(publication.AllowedAudiences) > 16 {
			return errors.New("earning publication policy is invalid or unbounded")
		}
		for index, audience := range publication.AllowedAudiences {
			if audience == "" || index > 0 && publication.AllowedAudiences[index-1] >= audience {
				return errors.New("publication audiences must be sorted and unique")
			}
		}
		if len(publication.SettlementParameters) > 16 {
			return errors.New("publication settlement parameter set is unbounded")
		}
		for adapter, parameters := range publication.SettlementParameters {
			if !containsSortedConfig(settings.SettlementAdapters, adapter) || len(parameters) == 0 || len(parameters) > 4096 {
				return errors.New("publication settlement parameters are invalid or unsupported")
			}
		}
	}
	return nil
}

func containsSortedConfig(values []string, value string) bool {
	index := sort.SearchStrings(values, value)
	return index < len(values) && values[index] == value
}

func (settings EarningSettings) EffectiveMode() string {
	if settings.Mode != "" {
		return settings.Mode
	}
	if !settings.Enabled {
		return "off"
	}
	if settings.ObserveOnly {
		return "observe"
	}
	return "policy-gated"
}

func canonicalEconomicInteger(value string) bool {
	if value == "0" {
		return true
	}
	if len(value) == 0 || len(value) > 78 || value[0] == '0' {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func earningLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
