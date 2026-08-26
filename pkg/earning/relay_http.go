package earning

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	foxutils "github.com/tosnetwork/openfox/pkg/utils"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

const (
	defaultRelayHTTPBytes       = 1 << 20
	minimumRelayHTTPBytes       = 64 << 10
	maximumRelayHTTPConcurrency = 64
)

var (
	ErrRelaySubmissionAmbiguous = errors.New("relay submission outcome is ambiguous")
	ErrRelayRemoteUnknown       = errors.New("relay provider has no matching action")
)

type RelayTransport interface {
	Quote(context.Context, agentrelay.SignedRelayQuoteRequest) (agentrelay.SignedProviderRelayQuote, error)
	Submit(context.Context, agentrelay.RelayExecutionRequest, commerce.AgentAgreement) (agentrelay.SignedRelayResolution, error)
	Resolve(context.Context, agentrelay.ResolveCall, agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayResolution, error)
	Evidence(context.Context, agentrelay.EvidenceCall, agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayFinalityEvidence, error)
}

// relayAuthenticatedResolveTransport is deliberately package-private: an
// arbitrary integration cannot opt itself into query-based failover with a
// public boolean. Production support is sealed to the mTLS HTTP transport;
// package tests use an explicit controlled fake.
type relayAuthenticatedResolveTransport interface {
	resolveForFailover(context.Context, agentrelay.ResolveCall, agentrelay.RelayExecutionRequest,
		RelayProviderProvenance, string) (agentrelay.SignedRelayResolution, string, bool, error)
}

// relayAuthorizedProviderTransport is sealed to this package so a generic
// RelayTransport supplied by an integration cannot be mislabeled as an
// authenticated Provider route by the capability planner.
type relayAuthorizedProviderTransport interface {
	relayProviderTransportAuthorized() bool
}

var errRelayResolveAuthenticationRejected = errors.New("relay Provider rejected Resolve authentication")

type RelayHTTPClientConfig struct {
	TLSConfig            *tls.Config
	Timeout              time.Duration
	MaximumResponseBytes int64
	// PrivateHostWhitelist is an explicit owner-controlled development or
	// private-deployment exception. A discovered provider cannot populate it.
	PrivateHostWhitelist []string
	// Resolver is owner-controlled and primarily supports split-horizon/private
	// deployments and deterministic tests. Its answers still pass the same
	// private/restricted-address and whitelist checks at every dial.
	Resolver            *net.Resolver
	AuthenticateRequest func(*http.Request) error
	// ProviderProvenance is owner-attested. When present, its canonical origin
	// and leaf SPKI pin are enforced by the transport; profile self-assertions
	// cannot populate this field.
	ProviderProvenance *RelayProviderProvenance
	// RequesterAgentID is the owner-pinned identity represented by the one mTLS
	// client certificate used by this route.
	RequesterAgentID string
	Now              func() time.Time
}

// RelayHTTPClient accepts endpoints only from a verified signed profile. Its
// transport has no environment proxy, refuses redirects and compression, and
// enforces TLS 1.3 even when optional mTLS credentials are supplied.
type RelayHTTPClient struct {
	verified             VerifiedRelayServiceProfile
	profile              agentrelay.RelayServiceProfile
	resolver             agentrelay.AgentKeyResolver
	client               *http.Client
	maximum              int64
	auth                 func(*http.Request) error
	now                  func() time.Time
	provenance           *RelayProviderProvenance
	authenticatedResolve bool
	requesterAgentID     string
}

func (client *RelayHTTPClient) relayProviderTransportAuthorized() bool {
	return client != nil && client.authenticatedResolve
}

func NewRelayHTTPClient(verified VerifiedRelayServiceProfile, resolver agentrelay.AgentKeyResolver,
	settings RelayHTTPClientConfig) (*RelayHTTPClient, error) {
	profile := verified.Profile()
	if len(verified.canonicalProfile) == 0 || resolver == nil || settings.Timeout < time.Second || settings.Timeout > time.Minute {
		return nil, errors.New("relay HTTP client configuration is incomplete")
	}
	maximum := settings.MaximumResponseBytes
	if maximum == 0 {
		maximum = defaultRelayHTTPBytes
	}
	if maximum < minimumRelayHTTPBytes || maximum > codec.MaxCanonicalBytes {
		return nil, errors.New("relay HTTP response bound is invalid")
	}
	privateWhitelist, err := foxutils.NewPrivateHostWhitelist(settings.PrivateHostWhitelist)
	if err != nil {
		return nil, errors.New("relay HTTP private-host policy is invalid")
	}
	for _, endpoint := range []string{profile.Endpoints.QuoteURL, profile.Endpoints.SubmitURL,
		profile.Endpoints.ResolveURL, profile.Endpoints.EvidenceURL} {
		if err := foxutils.ValidateSafeHTTPURL(endpoint, privateWhitelist, nil); err != nil {
			return nil, errors.New("verified relay endpoint is private, local, or otherwise unsafe")
		}
	}
	var provenance *RelayProviderProvenance
	if settings.ProviderProvenance != nil {
		profileDigest, digestErr := agentrelay.RelayServiceProfileDigest(profile)
		origin, originErr := relayProfileEndpointOrigin(profile.Endpoints)
		candidate := *settings.ProviderProvenance
		if digestErr != nil || originErr != nil || !validRelayProvenance(candidate) ||
			candidate.ProviderAgentID != profile.ProviderAgentID || candidate.IntentDigest != verified.IntentDigest() ||
			candidate.ProfileDigest != profileDigest || candidate.EndpointOrigin != origin {
			return nil, errors.New("relay HTTP provenance does not bind the exact verified profile and origin")
		}
		provenance = &candidate
	}
	tlsConfig := &tls.Config{}
	if settings.TLSConfig != nil {
		if settings.TLSConfig.InsecureSkipVerify || settings.TLSConfig.ServerName != "" {
			return nil, errors.New("relay HTTP client cannot disable or redirect endpoint-host TLS verification")
		}
		tlsConfig = settings.TLSConfig.Clone()
	}
	tlsConfig.MinVersion = tls.VersionTLS13
	tlsConfig.Renegotiation = tls.RenegotiateNever
	if provenance != nil {
		priorVerifyConnection := tlsConfig.VerifyConnection
		expectedSPKI := provenance.CertificatePinDigest
		tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
			if priorVerifyConnection != nil {
				if err := priorVerifyConnection(state); err != nil {
					return err
				}
			}
			if len(state.PeerCertificates) == 0 {
				return errors.New("relay TLS peer certificate is unavailable")
			}
			digest := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
			if "sha256:"+hex.EncodeToString(digest[:]) != expectedSPKI {
				return errors.New("relay TLS peer SPKI differs from owner provenance")
			}
			return nil
		}
	}
	dialer := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{Proxy: nil, DisableCompression: true, ForceAttemptHTTP2: true,
		DialContext:     foxutils.NewSafeDialContextWithResolver(dialer, privateWhitelist, nil, settings.Resolver),
		TLSClientConfig: tlsConfig, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: settings.Timeout,
		MaxResponseHeaderBytes: 32 << 10, MaxIdleConns: 16, MaxIdleConnsPerHost: 4,
		MaxConnsPerHost: 8, IdleConnTimeout: 30 * time.Second}
	client := &http.Client{Transport: transport, Timeout: settings.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("relay HTTP redirects are forbidden") }}
	now := settings.Now
	if now == nil {
		now = time.Now
	}
	authenticatedResolve := provenance != nil && completeRelayClientTLSConfig(tlsConfig) &&
		boundedRelayTrustDomain(settings.RequesterAgentID)
	return &RelayHTTPClient{verified: verified, profile: profile, resolver: resolver, client: client,
		maximum: maximum, auth: settings.AuthenticateRequest, now: now, provenance: provenance,
		authenticatedResolve: authenticatedResolve, requesterAgentID: settings.RequesterAgentID}, nil
}

func (client *RelayHTTPClient) resolveForFailover(ctx context.Context, call agentrelay.ResolveCall,
	expected agentrelay.RelayExecutionRequest, provider RelayProviderProvenance,
	authenticatedPrincipal string) (agentrelay.SignedRelayResolution, string, bool, error) {
	if client == nil || !client.authenticatedResolve || client.provenance == nil ||
		client.requesterAgentID != authenticatedPrincipal || !sameRelayProvenance(*client.provenance, provider) {
		return agentrelay.SignedRelayResolution{}, "", false,
			errors.New("relay failover Resolve identity is not owner-pinned")
	}
	bindingDigest, err := relayTransportAuthenticationDigest(provider, authenticatedPrincipal)
	_, executionErr := agentrelay.RelayExecutionRequestDigest(expected)
	if err != nil || ctx == nil || agentrelay.ValidateResolveCall(call) != nil || executionErr != nil ||
		call.StableActionID != expected.AuthorizedAction.StableActionID ||
		call.ExactRequestDigest != expected.AuthorizedAction.ExactRequestDigest {
		return agentrelay.SignedRelayResolution{}, "", false,
			errors.New("relay failover Resolve request is invalid")
	}
	var result agentrelay.ResolveResult
	dispatched := false
	callErr := client.callObserved(ctx, client.profile.Endpoints.ResolveURL, agentrelay.ResolveCallContentType,
		agentrelay.ResolveResultContentType, call, &result, false, &dispatched)
	if callErr != nil {
		return agentrelay.SignedRelayResolution{}, bindingDigest, dispatched, callErr
	}
	if err := client.verifyResolution(result.Resolution, expected); err != nil {
		return agentrelay.SignedRelayResolution{}, bindingDigest, dispatched, err
	}
	return result.Resolution, bindingDigest, dispatched, nil
}

func (client *RelayHTTPClient) Quote(ctx context.Context,
	request agentrelay.SignedRelayQuoteRequest) (agentrelay.SignedProviderRelayQuote, error) {
	if client == nil || ctx == nil || client.verified.authorizeQuoteRequest(request, client.now().UTC()) != nil {
		return agentrelay.SignedProviderRelayQuote{}, errors.New("relay quote call is invalid")
	}
	var result agentrelay.QuoteResult
	if err := client.call(ctx, client.profile.Endpoints.QuoteURL, agentrelay.QuoteCallContentType,
		agentrelay.QuoteResultContentType, agentrelay.QuoteCall{Request: request}, &result, false); err != nil {
		return agentrelay.SignedProviderRelayQuote{}, err
	}
	if err := agentrelay.VerifyProviderRelayQuote(result.Quote, request, client.profile, client.resolver, client.now().UTC()); err != nil ||
		result.Quote.Body.OfferIntentDigest != client.verified.IntentDigest() {
		return agentrelay.SignedProviderRelayQuote{}, errors.New("relay provider returned an invalid quote")
	}
	return result.Quote, nil
}

func (client *RelayHTTPClient) Submit(ctx context.Context, request agentrelay.RelayExecutionRequest,
	agreement commerce.AgentAgreement) (agentrelay.SignedRelayResolution, error) {
	if client == nil || ctx == nil || client.verified.authorizeQuoteRequest(request.QuoteRequest, client.now().UTC()) != nil {
		return agentrelay.SignedRelayResolution{}, errors.New("relay submission is invalid")
	}
	transactionDigest, err := agentrelay.SignedTransactionDigest(request.SignedTransactionBytes)
	if err != nil || transactionDigest != request.QuoteRequest.Body.SignedTransactionDigest ||
		uint32(len(request.SignedTransactionBytes)) != request.QuoteRequest.Body.SignedTransactionSize {
		return agentrelay.SignedRelayResolution{}, errors.New("relay submission changes the selected exact transaction")
	}
	if _, err := agentrelay.RelayExecutionRequestDigest(request); err != nil {
		return agentrelay.SignedRelayResolution{}, err
	}
	var result agentrelay.SubmitResult
	if err := client.call(ctx, client.profile.Endpoints.SubmitURL, agentrelay.SubmitCallContentType,
		agentrelay.SubmitResultContentType, agentrelay.SubmitCall{Request: request, Agreement: agreement}, &result, true); err != nil {
		return agentrelay.SignedRelayResolution{}, err
	}
	if err := client.verifyResolution(result.Resolution, request); err != nil {
		return agentrelay.SignedRelayResolution{}, fmt.Errorf("%w: invalid signed response", ErrRelaySubmissionAmbiguous)
	}
	return result.Resolution, nil
}

func (client *RelayHTTPClient) Resolve(ctx context.Context, call agentrelay.ResolveCall,
	expected agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayResolution, error) {
	_, digestErr := agentrelay.RelayExecutionRequestDigest(expected)
	if client == nil || ctx == nil || agentrelay.ValidateResolveCall(call) != nil || digestErr != nil {
		return agentrelay.SignedRelayResolution{}, errors.New("relay resolution call is invalid")
	}
	var result agentrelay.ResolveResult
	if err := client.call(ctx, client.profile.Endpoints.ResolveURL, agentrelay.ResolveCallContentType,
		agentrelay.ResolveResultContentType, call, &result, false); err != nil {
		return agentrelay.SignedRelayResolution{}, err
	}
	if err := client.verifyResolution(result.Resolution, expected); err != nil {
		return agentrelay.SignedRelayResolution{}, err
	}
	return result.Resolution, nil
}

func (client *RelayHTTPClient) Evidence(ctx context.Context, call agentrelay.EvidenceCall,
	expected agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayFinalityEvidence, error) {
	if client == nil || ctx == nil || agentrelay.ValidateEvidenceCall(call) != nil {
		return agentrelay.SignedRelayFinalityEvidence{}, errors.New("relay evidence call is invalid")
	}
	executionDigest, err := agentrelay.RelayExecutionRequestDigest(expected)
	if err != nil || call.StableActionID != expected.AuthorizedAction.StableActionID ||
		call.ExactRequestDigest != expected.AuthorizedAction.ExactRequestDigest {
		return agentrelay.SignedRelayFinalityEvidence{}, errors.New("relay evidence call conflicts with the expected execution")
	}
	var result agentrelay.EvidenceResult
	if err := client.call(ctx, client.profile.Endpoints.EvidenceURL, agentrelay.EvidenceCallContentType,
		agentrelay.EvidenceResultContentType, call, &result, false); err != nil {
		return agentrelay.SignedRelayFinalityEvidence{}, err
	}
	if err := agentrelay.VerifyRelayFinalityEvidence(result.Evidence, client.resolver, client.now().UTC()); err != nil {
		return agentrelay.SignedRelayFinalityEvidence{}, errors.New("relay finality evidence signature is invalid")
	}
	body, quoted := result.Evidence.Body, expected.QuoteRequest.Body
	if body.ProviderAgentID != client.profile.ProviderAgentID || body.Network != quoted.Network ||
		body.AssuranceLevel != quoted.AssuranceLevel ||
		body.StableActionID != call.StableActionID || body.ExactRequestDigest != call.ExactRequestDigest ||
		body.RelayExecutionDigest != executionDigest || body.SignedTransactionDigest != quoted.SignedTransactionDigest ||
		body.SignedTransactionCellHash != quoted.SignedTransactionCellHash || body.SourceAccount != quoted.SourceAccount ||
		body.SourceSequence != quoted.SourceSequence ||
		!equalRelayFinalityProfile(body.RelayFinalityProfile, expected.ProviderQuote.Body.RelayFinalityProfile) ||
		!equalRelayFinalityProfile(body.SponsorshipTerminalProfile,
			expected.ProviderQuote.Body.SponsorshipTerminalProfile) {
		return agentrelay.SignedRelayFinalityEvidence{}, errors.New("relay finality evidence conflicts with the frozen execution")
	}
	return result.Evidence, nil
}

func (client *RelayHTTPClient) verifyResolution(signed agentrelay.SignedRelayResolution,
	expected agentrelay.RelayExecutionRequest) error {
	now := client.now().UTC()
	body := signed.Body
	if agentrelay.VerifyRelayResolutionForExecution(signed, expected, client.resolver, now) != nil ||
		body.ProviderAgentID != client.profile.ProviderAgentID ||
		body.ObservedAtUnix > uint64(now.Add(5*time.Minute).Unix()) || uint64(now.Unix()) >= body.ExpiresAtUnix {
		return errors.New("relay resolution conflicts with the frozen execution")
	}
	return nil
}

func (client *RelayHTTPClient) call(ctx context.Context, endpoint, requestType, responseType string,
	input, output any, ambiguous bool) error {
	return client.callObserved(ctx, endpoint, requestType, responseType, input, output, ambiguous, nil)
}

func (client *RelayHTTPClient) callObserved(ctx context.Context, endpoint, requestType, responseType string,
	input, output any, ambiguous bool, dispatched *bool) error {
	if dispatched != nil {
		*dispatched = false
	}
	raw, err := codec.Marshal(input)
	if err != nil || int64(len(raw)) > client.maximum {
		return errors.New("relay HTTP request is invalid or oversized")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", requestType)
	request.Header.Set("Accept", responseType)
	request.Header.Set("Cache-Control", "no-store")
	if client.auth != nil {
		if err := client.auth(request); err != nil {
			return errors.New("relay HTTP request authentication failed")
		}
	}
	if dispatched != nil {
		// This point is after canonical request construction and any owner auth
		// callback, immediately before the sealed, provenance-pinned mTLS
		// RoundTripper takes ownership of the attempt.
		*dispatched = true
	}
	response, err := client.client.Do(request)
	if err != nil {
		return relayCallError(err, ambiguous)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != responseType ||
		response.Header.Get("Content-Encoding") != "" {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		if dispatched != nil && (response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden) {
			return errRelayResolveAuthenticationRejected
		}
		if !ambiguous && response.StatusCode == http.StatusNotFound {
			return ErrRelayRemoteUnknown
		}
		return relayCallError(fmt.Errorf("relay HTTP endpoint rejected the call with status %d", response.StatusCode), ambiguous)
	}
	raw, err = io.ReadAll(io.LimitReader(response.Body, client.maximum+1))
	if err != nil || len(raw) == 0 || int64(len(raw)) > client.maximum || codec.Unmarshal(raw, output) != nil {
		return relayCallError(errors.New("relay HTTP response is invalid or oversized"), ambiguous)
	}
	return nil
}

func relayCallError(err error, ambiguous bool) error {
	if ambiguous {
		return fmt.Errorf("%w: %v", ErrRelaySubmissionAmbiguous, err)
	}
	return err
}

type RelayHTTPPrincipal struct {
	RequesterAgentID      string
	CertificateSPKIDigest string
}

type RelayHTTPRequestAuthenticator func(*http.Request) (RelayHTTPPrincipal, error)

// RequireRelayMTLSClient is the default authentication hook for resolve and
// evidence endpoints. The TLS server must already have verified its configured
// ClientCAs; this hook rejects requests that did not complete that handshake.
func RequireRelayMTLSClient(request *http.Request) (RelayHTTPPrincipal, error) {
	if request == nil || request.TLS == nil || len(request.TLS.VerifiedChains) == 0 || len(request.TLS.PeerCertificates) == 0 {
		return RelayHTTPPrincipal{}, errors.New("verified relay client certificate is required")
	}
	digest := sha256.Sum256(request.TLS.PeerCertificates[0].RawSubjectPublicKeyInfo)
	return RelayHTTPPrincipal{CertificateSPKIDigest: "sha256:" + hex.EncodeToString(digest[:])}, nil
}

// NewRelayMTLSAgentAuthenticator converts an owner-controlled certificate
// SPKI allowlist into a typed requester identity. CA membership alone is not
// commercial authorization: each certificate must map to exactly one Agent.
func NewRelayMTLSAgentAuthenticator(agentBySPKI map[string]string) (RelayHTTPRequestAuthenticator, error) {
	frozen := make(map[string]string, len(agentBySPKI))
	for digest, agentID := range agentBySPKI {
		if !canonicalSHA256(digest) || agentID == "" || len(agentID) > 256 || strings.ContainsAny(agentID, "\x00\r\n") {
			return nil, errors.New("relay mTLS Agent binding is invalid")
		}
		frozen[digest] = agentID
	}
	if len(frozen) == 0 {
		return nil, errors.New("relay mTLS Agent binding is empty")
	}
	return func(request *http.Request) (RelayHTTPPrincipal, error) {
		principal, err := RequireRelayMTLSClient(request)
		if err != nil {
			return RelayHTTPPrincipal{}, err
		}
		agentID, found := frozen[principal.CertificateSPKIDigest]
		if !found {
			return RelayHTTPPrincipal{}, errors.New("relay client certificate is not bound to an Agent")
		}
		principal.RequesterAgentID = agentID
		return principal, nil
	}, nil
}

type RelayProviderHTTPHandler struct {
	service                  *agentrelay.ProviderService
	authenticate             RelayHTTPRequestAuthenticator
	maximum                  int64
	assurance                agentrelay.AssuranceLevel
	enabledModes             map[agentrelay.Mode]bool
	sponsorshipReleasePolicy RelaySponsorshipReleasePolicy
	routes                   map[string]relayHTTPRoute
	concurrency              chan struct{}
	principalRate            *relayPrincipalRateLimiter
}

type relayPrincipalRateWindow struct {
	startedAt time.Time
	requests  uint32
}

type relayPrincipalRateLimiter struct {
	mu       sync.Mutex
	entries  map[string]relayPrincipalRateWindow
	maximum  uint32
	window   time.Duration
	maxAgent int
}

func (limiter *relayPrincipalRateLimiter) allow(agentID string, now time.Time) bool {
	if limiter == nil || agentID == "" || limiter.maximum == 0 || limiter.window <= 0 || limiter.maxAgent <= 0 {
		return false
	}
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	for key, entry := range limiter.entries {
		if !now.Before(entry.startedAt.Add(limiter.window)) {
			delete(limiter.entries, key)
		}
	}
	entry, found := limiter.entries[agentID]
	if !found {
		if len(limiter.entries) >= limiter.maxAgent {
			return false
		}
		entry.startedAt = now
	}
	if entry.requests >= limiter.maximum {
		return false
	}
	entry.requests++
	limiter.entries[agentID] = entry
	return true
}

type relayHTTPRoute struct {
	host      string
	operation string
}

func NewRelayProviderHTTPHandler(service *agentrelay.ProviderService,
	authenticate RelayHTTPRequestAuthenticator, maximumBytes int64, assurance agentrelay.AssuranceLevel,
	enabledModes []agentrelay.Mode, selectedPolicy ...RelaySponsorshipReleasePolicy) (*RelayProviderHTTPHandler, error) {
	if service == nil || authenticate == nil {
		return nil, errors.New("relay provider service is unavailable")
	}
	if maximumBytes == 0 {
		maximumBytes = defaultRelayHTTPBytes
	}
	if maximumBytes < minimumRelayHTTPBytes || maximumBytes > codec.MaxCanonicalBytes || service.ActionBinder == nil ||
		agentrelay.ValidateRelayServiceProfile(service.Profile, relayServiceNow(service)) != nil ||
		!relayProfileSupportsAssurance(service.Profile, assurance) ||
		!validRelayEnabledModes(enabledModes, service.Profile.SupportedModes) {
		return nil, errors.New("relay provider HTTP bounds or profile are invalid")
	}
	modeSet := make(map[agentrelay.Mode]bool, len(enabledModes))
	for _, mode := range enabledModes {
		modeSet[mode] = true
	}
	policy := RelaySponsorshipReleasePolicy{}
	if len(selectedPolicy) > 1 {
		return nil, errors.New("relay provider accepts one owner sponsorship release policy")
	}
	if len(selectedPolicy) == 1 {
		policy = selectedPolicy[0]
	}
	for _, mode := range enabledModes {
		if mode != agentrelay.ModeRelayExact && !validRelaySponsorshipReleasePolicy(assurance, policy) {
			return nil, errors.New("relay provider sponsorship release policy is invalid")
		}
	}
	routes := make(map[string]relayHTTPRoute, 4)
	for operation, endpoint := range map[string]string{"quote": service.Profile.Endpoints.QuoteURL,
		"submit": service.Profile.Endpoints.SubmitURL, "resolve": service.Profile.Endpoints.ResolveURL,
		"evidence": service.Profile.Endpoints.EvidenceURL} {
		parsed, err := url.Parse(endpoint)
		if err != nil || parsed == nil || parsed.Path == "" || routes[parsed.Path].operation != "" {
			return nil, errors.New("relay provider HTTP endpoint paths must be valid and distinct")
		}
		routes[parsed.Path] = relayHTTPRoute{host: parsed.Host, operation: operation}
	}
	limits := service.Profile.AdmissionLimits
	return &RelayProviderHTTPHandler{service: service, authenticate: authenticate, maximum: maximumBytes,
		assurance: assurance, enabledModes: modeSet, sponsorshipReleasePolicy: policy,
		routes: routes, concurrency: make(chan struct{}, maximumRelayHTTPConcurrency),
		principalRate: &relayPrincipalRateLimiter{entries: make(map[string]relayPrincipalRateWindow),
			maximum: limits.MaximumQuoteRequestsPerRequesterWindow,
			window:  time.Duration(limits.QuoteRequestWindowSeconds) * time.Second, maxAgent: 4096}}, nil
}

func (handler *RelayProviderHTTPHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	route, found := handler.routes[request.URL.Path]
	if !found || request.Method != http.MethodPost || request.URL.RawQuery != "" || !strings.EqualFold(request.Host, route.host) {
		http.Error(response, "relay endpoint not found", http.StatusNotFound)
		return
	}
	select {
	case handler.concurrency <- struct{}{}:
		defer func() { <-handler.concurrency }()
	default:
		http.Error(response, "relay provider is at bounded concurrency", http.StatusServiceUnavailable)
		return
	}
	principal, err := handler.authenticate(request)
	if err != nil || principal.RequesterAgentID == "" {
		http.Error(response, "relay client authentication required", http.StatusUnauthorized)
		return
	}
	if !handler.principalRate.allow(principal.RequesterAgentID, relayServiceNow(handler.service)) {
		http.Error(response, "relay requester rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	expectedRequest, expectedResponse := relayHTTPContentTypes(route.operation)
	if request.Header.Get("Content-Type") != expectedRequest || request.Header.Get("Accept") != expectedResponse ||
		request.Header.Get("Content-Encoding") != "" || request.ContentLength > handler.maximum {
		http.Error(response, "invalid relay media type or request bound", http.StatusUnsupportedMediaType)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(request.Body, handler.maximum+1))
	if err != nil || len(raw) == 0 || int64(len(raw)) > handler.maximum {
		http.Error(response, "invalid relay request", http.StatusBadRequest)
		return
	}
	var output any
	switch route.operation {
	case "quote":
		var call agentrelay.QuoteCall
		if codec.Unmarshal(raw, &call) != nil || call.Request.Body.RequesterAgentID != principal.RequesterAgentID ||
			call.Request.Body.AssuranceLevel != handler.assurance || !handler.enabledModes[call.Request.Body.Mode] ||
			!relayRequestUsesSponsorshipReleasePolicy(call.Request.Body, handler.sponsorshipReleasePolicy) {
			http.Error(response, "invalid relay request", http.StatusBadRequest)
			return
		}
		quote, callErr := handler.service.Quote(request.Context(), call.Request)
		if callErr != nil {
			http.Error(response, "relay quote refused", http.StatusUnprocessableEntity)
			return
		}
		output = agentrelay.QuoteResult{Quote: quote}
	case "submit":
		var call agentrelay.SubmitCall
		if codec.Unmarshal(raw, &call) != nil ||
			call.Request.QuoteRequest.Body.RequesterAgentID != principal.RequesterAgentID ||
			call.Request.AdmissionReceipt.Body.AuthenticatedPrincipal != principal.RequesterAgentID ||
			call.Request.QuoteRequest.Body.AssuranceLevel != handler.assurance ||
			!handler.enabledModes[call.Request.QuoteRequest.Body.Mode] ||
			!relayRequestUsesSponsorshipReleasePolicy(call.Request.QuoteRequest.Body,
				handler.sponsorshipReleasePolicy) {
			http.Error(response, "invalid relay request", http.StatusBadRequest)
			return
		}
		record, callErr := handler.service.Submit(request.Context(), call.Request, call.Agreement)
		if callErr != nil {
			http.Error(response, "relay submission unresolved", relayProviderStatus(callErr))
			return
		}
		signed, signErr := handler.service.SignedResolution(record)
		if signErr != nil {
			http.Error(response, "relay resolution unavailable", http.StatusServiceUnavailable)
			return
		}
		output = agentrelay.SubmitResult{Resolution: signed}
	case "resolve":
		var call agentrelay.ResolveCall
		if codec.Unmarshal(raw, &call) != nil || agentrelay.ValidateResolveCall(call) != nil {
			http.Error(response, "invalid relay request", http.StatusBadRequest)
			return
		}
		if !relayRecordBelongsToRequester(handler.service, call.StableActionID, call.ExactRequestDigest,
			principal.RequesterAgentID) {
			http.Error(response, "relay resolution unavailable", http.StatusNotFound)
			return
		}
		record, callErr := handler.service.Resolve(request.Context(), call.StableActionID, call.ExactRequestDigest)
		if callErr != nil {
			http.Error(response, "relay resolution unavailable", relayProviderStatus(callErr))
			return
		}
		signed, signErr := handler.service.SignedResolution(record)
		if signErr != nil {
			http.Error(response, "relay resolution unavailable", http.StatusServiceUnavailable)
			return
		}
		output = agentrelay.ResolveResult{Resolution: signed}
	case "evidence":
		var call agentrelay.EvidenceCall
		if codec.Unmarshal(raw, &call) != nil || agentrelay.ValidateEvidenceCall(call) != nil {
			http.Error(response, "invalid relay request", http.StatusBadRequest)
			return
		}
		if !relayRecordBelongsToRequester(handler.service, call.StableActionID, call.ExactRequestDigest,
			principal.RequesterAgentID) {
			http.Error(response, "relay evidence unavailable", http.StatusNotFound)
			return
		}
		evidence, callErr := handler.service.Evidence(request.Context(), call.StableActionID, call.ExactRequestDigest)
		if callErr != nil {
			http.Error(response, "relay evidence unavailable", relayProviderStatus(callErr))
			return
		}
		output = agentrelay.EvidenceResult{Evidence: evidence}
	default:
		http.Error(response, "relay endpoint not found", http.StatusNotFound)
		return
	}
	encoded, err := codec.Marshal(output)
	if err != nil || int64(len(encoded)) > handler.maximum {
		http.Error(response, "relay response unavailable", http.StatusServiceUnavailable)
		return
	}
	response.Header().Set("Content-Type", expectedResponse)
	response.Header().Set("Content-Length", fmt.Sprintf("%d", len(encoded)))
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(encoded)
}

func relayRequestUsesSponsorshipReleasePolicy(body agentrelay.RelayQuoteRequestBody,
	selected RelaySponsorshipReleasePolicy) bool {
	actual := relaySponsorshipReleasePolicyFromRequest(body)
	if body.Mode == agentrelay.ModeRelayExact {
		return actual == (RelaySponsorshipReleasePolicy{})
	}
	return actual == selected && validRelaySponsorshipReleasePolicy(body.AssuranceLevel, selected)
}

func relayRecordBelongsToRequester(service *agentrelay.ProviderService, stableActionID, exactRequestDigest,
	requesterAgentID string) bool {
	if service == nil || service.Journal == nil || requesterAgentID == "" {
		return false
	}
	record, err := service.Journal.Resolve(stableActionID, exactRequestDigest)
	return err == nil && record.ExecutionRequest().QuoteRequest.Body.RequesterAgentID == requesterAgentID
}

func relayHTTPContentTypes(operation string) (string, string) {
	switch operation {
	case "quote":
		return agentrelay.QuoteCallContentType, agentrelay.QuoteResultContentType
	case "submit":
		return agentrelay.SubmitCallContentType, agentrelay.SubmitResultContentType
	case "resolve":
		return agentrelay.ResolveCallContentType, agentrelay.ResolveResultContentType
	case "evidence":
		return agentrelay.EvidenceCallContentType, agentrelay.EvidenceResultContentType
	default:
		return "", ""
	}
}

func relayProviderStatus(err error) int {
	switch {
	case errors.Is(err, ErrRelayRetired):
		return http.StatusGone
	case errors.Is(err, agentrelay.ErrRelayUnknown):
		return http.StatusNotFound
	case errors.Is(err, agentrelay.ErrRelayConflict), errors.Is(err, agentrelay.ErrRelayStaleWriter),
		errors.Is(err, agentrelay.ErrRelayInvalidState):
		return http.StatusConflict
	default:
		return http.StatusServiceUnavailable
	}
}

func relayServiceNow(service *agentrelay.ProviderService) time.Time {
	if service.Now != nil {
		return service.Now().UTC()
	}
	return time.Now().UTC()
}

var _ RelayTransport = (*RelayHTTPClient)(nil)
var _ http.Handler = (*RelayProviderHTTPHandler)(nil)
