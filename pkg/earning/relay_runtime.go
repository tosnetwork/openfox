package earning

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"sort"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
)

// RelayClientHTTPRuntimeConfig contains only owner-controlled runtime inputs.
// The verified profile itself must still come from a signed discovered OFFER.
type RelayClientHTTPRuntimeConfig struct {
	Enabled                 bool
	AssuranceLevel          agentrelay.AssuranceLevel
	VerifiedProfile         VerifiedRelayServiceProfile
	AgentResolver           agentrelay.AgentKeyResolver
	TLSConfig               *tls.Config
	ProviderProvenance      RelayProviderProvenance
	RequesterAgentID        string
	AttemptJournalDirectory string
	Timeout                 time.Duration
	MaximumResponseBytes    int64
}

// RelayClientHTTPRuntime owns one provider-scoped attempt journal and its
// authenticated route. An owner-wide DurableRelayRouteJournal remains a
// separate object because it coordinates at least two independent providers.
type RelayClientHTTPRuntime struct {
	Transport      *RelayHTTPClient
	AttemptJournal *DurableRelayJournal
	// TransportModes are the signed-profile modes reachable over this one
	// authenticated route. They deliberately are not RelayCapabilities and do
	// not carry a Ready bit: execution readiness is produced only by
	// EnableRelayClient after Agreement, admission, finality, and (for
	// decentralized assurance) route dependencies have been constructed.
	TransportModes []agentrelay.Mode
}

func OpenRelayClientHTTPRuntime(settings RelayClientHTTPRuntimeConfig) (*RelayClientHTTPRuntime, error) {
	if !settings.Enabled {
		return nil, errors.New("Agent relay client is disabled by owner configuration")
	}
	if !validRelayAssuranceLevel(settings.AssuranceLevel) ||
		!relayProfileSupportsAssurance(settings.VerifiedProfile.Profile(), settings.AssuranceLevel) {
		return nil, errors.New("Agent relay client selected an unsupported assurance level")
	}
	if !completeRelayClientTLSConfig(settings.TLSConfig) || settings.AttemptJournalDirectory == "" ||
		!boundedRelayTrustDomain(settings.RequesterAgentID) {
		return nil, errors.New("Agent relay client requires a complete mutual-TLS identity and durable attempt journal")
	}
	journal, err := OpenDurableRelayJournal(settings.AttemptJournalDirectory)
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (*RelayClientHTTPRuntime, error) {
		_ = journal.Close()
		return nil, cause
	}
	client, err := NewRelayHTTPClient(settings.VerifiedProfile, settings.AgentResolver, RelayHTTPClientConfig{
		TLSConfig: settings.TLSConfig, Timeout: settings.Timeout, MaximumResponseBytes: settings.MaximumResponseBytes,
		ProviderProvenance: &settings.ProviderProvenance, RequesterAgentID: settings.RequesterAgentID,
	})
	if err != nil {
		return fail(err)
	}
	transportModes := make([]agentrelay.Mode, 0, len(settings.VerifiedProfile.Profile().SupportedModes))
	for _, mode := range settings.VerifiedProfile.Profile().SupportedModes {
		if containsRelayMode(settings.VerifiedProfile.policy.Modes, mode) {
			transportModes = append(transportModes, mode)
		}
	}
	return &RelayClientHTTPRuntime{Transport: client, AttemptJournal: journal, TransportModes: transportModes}, nil
}

func (runtime *RelayClientHTTPRuntime) Close() error {
	if runtime == nil {
		return nil
	}
	if runtime.Transport != nil && runtime.Transport.client != nil {
		if transport, ok := runtime.Transport.client.Transport.(*http.Transport); ok {
			transport.CloseIdleConnections()
		}
	}
	if runtime.AttemptJournal != nil {
		return runtime.AttemptJournal.Close()
	}
	return nil
}

type RelayProviderHTTPRuntimeConfig struct {
	Enabled        bool
	AssuranceLevel agentrelay.AssuranceLevel
	// SponsorshipReleasePolicy is zero for relay_exact-only runtimes and is the
	// exact owner-enabled evidence descriptor for every sponsorship mode.
	SponsorshipReleasePolicy RelaySponsorshipReleasePolicy
	// EnabledModes is the owner-selected subset of the signed profile. Missing
	// mode dependencies disable only that pair, never unrelated modes.
	EnabledModes     []agentrelay.Mode
	JournalDirectory string
	TLSCertificate   tls.Certificate
	ClientCAs        *x509.CertPool
	// ClientAgentBySPKI is an owner-controlled sha256(SPKI) -> requester
	// AgentID map. Trusting the issuing CA alone would let another tenant query
	// or resolve this Agent's commercial actions.
	ClientAgentBySPKI       map[string]string
	AdmissionLimits         agentrelay.AdmissionLimits
	TerminalRetention       time.Duration
	MaximumProtectedRecords uint32
	MaximumHTTPBytes        int64
}

// RelayProviderHTTPRuntime is a fully authenticated route, but it does not
// open a socket. The caller retains explicit control over the listen address
// and serves Server only through TLSConfig (normally with tls.Listen).
type RelayProviderHTTPRuntime struct {
	Service   *agentrelay.ProviderService
	Journal   *DurableRelayJournal
	Handler   *RelayProviderHTTPHandler
	Server    *http.Server
	TLSConfig *tls.Config
	// Capabilities are the exact mode/assurance pairs enabled by the concrete
	// service dependencies used by this runtime.
	Capabilities RelayCapabilityReport
}

// OpenRelayProviderHTTPRuntime enables the selected assurance directly when
// its concrete dependencies are present. It does not require a separate
// "production acceptance" bit, and it never reports a higher assurance than
// the signed profile and runtime evidence actually support.
func OpenRelayProviderHTTPRuntime(service *agentrelay.ProviderService,
	settings RelayProviderHTTPRuntimeConfig) (*RelayProviderHTTPRuntime, error) {
	if !settings.Enabled {
		return nil, errors.New("Agent relay provider is disabled by owner configuration")
	}
	if service == nil || service.Journal != nil || settings.JournalDirectory == "" ||
		!validRelayEnabledModes(settings.EnabledModes, service.Profile.SupportedModes) ||
		len(settings.TLSCertificate.Certificate) == 0 || settings.ClientCAs == nil || len(settings.ClientCAs.Subjects()) == 0 ||
		!relayOwnerAdmissionWithinProfile(settings.AdmissionLimits, service.Profile.AdmissionLimits) {
		return nil, errors.New("Agent relay provider dependencies, mTLS, or owner admission limits are incomplete")
	}
	journal, err := OpenDurableRelayJournalWithOptions(settings.JournalDirectory, DurableRelayJournalOptions{
		TerminalRetention: settings.TerminalRetention, AdmissionLimits: &settings.AdmissionLimits,
		MaximumProtectedRecords: settings.MaximumProtectedRecords,
	})
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (*RelayProviderHTTPRuntime, error) {
		_ = journal.Close()
		return nil, cause
	}
	configured := *service
	if configured.Journal != nil {
		return fail(errors.New("Agent relay provider runtime requires exclusive ownership of its durable journal"))
	}
	configured.Journal = journal
	if relayModesContainSponsorship(settings.EnabledModes) {
		observationVerifier, observationOK := configured.Sponsorship.(agentrelay.SponsorshipCreditObservationVerifier)
		if !observationOK {
			return fail(errors.New("Agent relay sponsorship processor does not verify its own release observations"))
		}
		// The object that executes the sponsorship is authoritative for the
		// exact frozen observation verifier. Never retain a caller-supplied A
		// while side effects run through B.
		configured.SponsorshipObservationVerifier = observationVerifier
		renderer, rendererOK := configured.EvidenceSource.(RelayTerminalEvidenceRenderer)
		if existing, ok := configured.EvidenceSource.(*CompositeRelayFinalityEvidenceSource); ok && existing != nil {
			renderer = existing.terminalRenderer()
			rendererOK = renderer != nil
		}
		sponsorship, sponsorshipOK := configured.Sponsorship.(relayProviderSponsorshipEvidence)
		if rendererOK && sponsorshipOK {
			composite, compositeErr := NewCompositeRelayFinalityEvidenceSource(renderer, sponsorship)
			if compositeErr != nil {
				return fail(compositeErr)
			}
			configured.EvidenceSource = composite
		}
	}
	capabilities := planRelayProviderCapabilitiesForModes(&configured, settings.AssuranceLevel, settings.EnabledModes,
		settings.SponsorshipReleasePolicy)
	if !capabilities.Ready() {
		missing := make([]string, 0)
		for _, capability := range capabilities.Capabilities {
			missing = append(missing, capability.Missing...)
		}
		return fail(errors.New("Agent relay provider concrete mode/assurance dependencies are incomplete: " +
			joinRelayMissing(compactRelayMissingSorted(missing))))
	}
	authenticator, err := NewRelayMTLSAgentAuthenticator(settings.ClientAgentBySPKI)
	if err != nil {
		return fail(err)
	}
	handler, err := NewRelayProviderHTTPHandler(&configured, authenticator,
		settings.MaximumHTTPBytes, settings.AssuranceLevel, settings.EnabledModes,
		settings.SponsorshipReleasePolicy)
	if err != nil {
		return fail(err)
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{settings.TLSCertificate},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: settings.ClientCAs, SessionTicketsDisabled: true,
		Renegotiation: tls.RenegotiateNever}
	server := &http.Server{Handler: handler, TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 32 << 10}
	return &RelayProviderHTTPRuntime{Service: &configured, Journal: journal, Handler: handler,
		Server: server, TLSConfig: tlsConfig, Capabilities: capabilities}, nil
}

func relayModesContainSponsorship(modes []agentrelay.Mode) bool {
	for _, mode := range modes {
		if mode == agentrelay.ModeSponsorOnly || mode == agentrelay.ModeSponsorAndRelay {
			return true
		}
	}
	return false
}

func (runtime *RelayProviderHTTPRuntime) Close() error {
	if runtime == nil || runtime.Journal == nil {
		return nil
	}
	return runtime.Journal.Close()
}

func completeRelayClientTLSConfig(settings *tls.Config) bool {
	if settings == nil || settings.InsecureSkipVerify || settings.ServerName != "" || settings.RootCAs == nil ||
		len(settings.RootCAs.Subjects()) == 0 || len(settings.Certificates) != 1 {
		return false
	}
	certificate := settings.Certificates[0]
	return len(certificate.Certificate) > 0 && certificate.PrivateKey != nil
}

func relayOwnerAdmissionWithinProfile(owner, profile agentrelay.AdmissionLimits) bool {
	return owner.MaximumQuoteReservations > 0 && owner.MaximumQuoteReservations <= profile.MaximumQuoteReservations &&
		owner.MaximumActiveExecutions > 0 && owner.MaximumActiveExecutions <= profile.MaximumActiveExecutions &&
		owner.MaximumActivePerRequester > 0 && owner.MaximumActivePerRequester <= profile.MaximumActivePerRequester &&
		owner.MaximumQuoteRequestsPerWindow > 0 && owner.MaximumQuoteRequestsPerWindow <= profile.MaximumQuoteRequestsPerWindow &&
		owner.MaximumQuoteRequestsPerRequesterWindow > 0 &&
		owner.MaximumQuoteRequestsPerRequesterWindow <= profile.MaximumQuoteRequestsPerRequesterWindow &&
		owner.QuoteRequestWindowSeconds == profile.QuoteRequestWindowSeconds
}

func compactRelayMissingSorted(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	sort.Strings(values)
	return compactRelayMissing(values)
}

func validRelayEnabledModes(enabled, supported []agentrelay.Mode) bool {
	if len(enabled) == 0 || len(enabled) > len(supported) {
		return false
	}
	previous := agentrelay.Mode("")
	for _, mode := range enabled {
		if mode <= previous || !relayProfileSupportsMode(agentrelay.RelayServiceProfile{SupportedModes: supported}, mode) {
			return false
		}
		previous = mode
	}
	return true
}
