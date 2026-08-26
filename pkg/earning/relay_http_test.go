package earning

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
	"golang.org/x/net/dns/dnsmessage"
)

func TestRelayHTTPClientAndHandlerRecoverAmbiguousSubmitExactlyOnce(t *testing.T) {
	server := httptest.NewUnstartedServer(nil)
	origin := relayTestPublicOrigin(t, server)
	fixture := newRelayTestFixture(t, "agent:provider", nil, origin)
	directory := filepath.Join(t.TempDir(), "provider-journal")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenDurableRelayJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	broadcaster := &relayTestBroadcaster{result: agentrelay.BroadcastResult{Status: agentrelay.BroadcastAccepted,
		TransactionReference: "tx:exact"}}
	service := fixture.service(journal, broadcaster)
	handler, err := NewRelayProviderHTTPHandler(service, func(request *http.Request) (RelayHTTPPrincipal, error) {
		if request.Header.Get("X-Relay-Client") != "agent:client" {
			return RelayHTTPPrincipal{}, errors.New("unauthenticated")
		}
		return RelayHTTPPrincipal{RequesterAgentID: "agent:client", CertificateSPKIDigest: relayTestDigest("a")}, nil
	}, defaultRelayHTTPBytes, agentrelay.AssuranceAutonomousDecentralized, service.Profile.SupportedModes)
	if err != nil {
		t.Fatal(err)
	}
	var loseFirstSubmit atomic.Bool
	loseFirstSubmit.Store(true)
	server.Config.Handler = http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/submit" && loseFirstSubmit.CompareAndSwap(true, false) {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusOK {
				t.Fatalf("provider did not execute ambiguous submit: status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			http.Error(response, "response lost after provider execution", http.StatusServiceUnavailable)
			return
		}
		handler.ServeHTTP(response, request)
	})
	server.StartTLS()
	defer server.Close()

	client := relayTestHTTPClient(t, fixture, server, func(request *http.Request) error {
		request.Header.Set("X-Relay-Client", "agent:client")
		return nil
	})
	coordinator := relayTestCoordinator(t, fixture, client)
	attempt, err := coordinator.Prepare(t.Context(), fixture.prepared)
	if err != nil {
		t.Fatal(err)
	}
	submitWire, err := codec.Marshal(agentrelay.SubmitCall{Request: attempt.Execution, Agreement: attempt.Agreement})
	var decodedSubmit agentrelay.SubmitCall
	if err != nil || codec.Unmarshal(submitWire, &decodedSubmit) != nil ||
		decodedSubmit.Request.QuoteRequest.Body.RequesterAgentID != "agent:client" {
		t.Fatal("typed SubmitCall did not round-trip before transport")
	}
	result, err := coordinator.Submit(t.Context(), attempt)
	if err != nil || result.Resolution.Body.State != commerce.ActionAccepted || broadcaster.submits != 1 {
		t.Fatalf("ambiguous submit recovery: state=%s submits=%d err=%v", result.Resolution.Body.State, broadcaster.submits, err)
	}
	if len(broadcaster.payloads) != 1 || !bytes.Equal(broadcaster.payloads[0], fixture.prepared.ExactSignedBOC) {
		t.Fatal("provider did not broadcast the exact locally prepared BOC")
	}
	if _, err := coordinator.Submit(t.Context(), attempt); err != nil || broadcaster.submits != 1 {
		t.Fatalf("exact retry wrote again instead of querying: submits=%d err=%v", broadcaster.submits, err)
	}

	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenDurableRelayJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	service.Journal = reopened
	if _, err := coordinator.Submit(t.Context(), attempt); err != nil || broadcaster.submits != 1 {
		t.Fatalf("restart recovery rebroadcast exact bytes prematurely: submits=%d err=%v", broadcaster.submits, err)
	}
}

func TestRelayProviderHandlerRequiresAuthAndCanonicalBoundedCBOR(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	service := fixture.service(agentrelay.NewMemoryJournal(), &relayTestBroadcaster{})
	if _, err := NewRelayProviderHTTPHandler(service, nil, defaultRelayHTTPBytes,
		agentrelay.AssuranceAutonomousDecentralized, service.Profile.SupportedModes); err == nil {
		t.Fatal("provider handler admitted unauthenticated quote and submit endpoints")
	}
	handler, err := NewRelayProviderHTTPHandler(service, func(request *http.Request) (RelayHTTPPrincipal, error) {
		if request.Header.Get("X-Relay-Client") != "authorized" {
			return RelayHTTPPrincipal{}, errors.New("unauthenticated")
		}
		agentID := request.Header.Get("X-Relay-Agent")
		if agentID == "" {
			agentID = "agent:client"
		}
		return RelayHTTPPrincipal{RequesterAgentID: agentID, CertificateSPKIDigest: relayTestDigest("a")}, nil
	}, defaultRelayHTTPBytes, agentrelay.AssuranceAutonomousDecentralized, service.Profile.SupportedModes)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := agentrelay.SignRelayQuoteRequest(fixture.prepared.QuoteBody, fixture.clientKey)
	if err != nil {
		t.Fatal(err)
	}
	valid, _ := codec.Marshal(agentrelay.QuoteCall{Request: signed})

	request := httptest.NewRequest(http.MethodPost, fixture.profile.Endpoints.QuoteURL, bytes.NewReader(valid))
	request.Header.Set("Content-Type", agentrelay.QuoteCallContentType)
	request.Header.Set("Accept", agentrelay.QuoteResultContentType)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated quote status=%d", response.Code)
	}
	for index := 0; index < cap(handler.concurrency); index++ {
		handler.concurrency <- struct{}{}
	}
	request = httptest.NewRequest(http.MethodPost, fixture.profile.Endpoints.QuoteURL, bytes.NewReader(valid))
	request.Header.Set("X-Relay-Client", "authorized")
	request.Header.Set("Content-Type", agentrelay.QuoteCallContentType)
	request.Header.Set("Accept", agentrelay.QuoteResultContentType)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	for index := 0; index < cap(handler.concurrency); index++ {
		<-handler.concurrency
	}
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("bounded provider concurrency gate status=%d", response.Code)
	}

	unknown, _ := codec.Marshal(map[string]any{"request": signed, "unknown": true})
	request = httptest.NewRequest(http.MethodPost, fixture.profile.Endpoints.QuoteURL, bytes.NewReader(unknown))
	request.Header.Set("X-Relay-Client", "authorized")
	request.Header.Set("Content-Type", agentrelay.QuoteCallContentType)
	request.Header.Set("Accept", agentrelay.QuoteResultContentType)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || bytes.Contains(response.Body.Bytes(), fixture.prepared.ExactSignedBOC) {
		t.Fatalf("unknown CBOR field was accepted or raw BOC leaked: status=%d", response.Code)
	}

	trailing := append(append([]byte(nil), valid...), 0)
	request = httptest.NewRequest(http.MethodPost, fixture.profile.Endpoints.QuoteURL, bytes.NewReader(trailing))
	request.Header.Set("X-Relay-Client", "authorized")
	request.Header.Set("Content-Type", agentrelay.QuoteCallContentType)
	request.Header.Set("Accept", agentrelay.QuoteResultContentType)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("trailing CBOR was accepted: status=%d", response.Code)
	}

	request = httptest.NewRequest(http.MethodPost, fixture.profile.Endpoints.QuoteURL, bytes.NewReader(valid))
	request.Header.Set("X-Relay-Client", "authorized")
	request.Header.Set("Content-Type", agentrelay.QuoteCallContentType+"; charset=binary")
	request.Header.Set("Accept", agentrelay.QuoteResultContentType)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("parameterized content type was accepted: status=%d", response.Code)
	}

	otherBody := fixture.prepared.QuoteBody
	otherBody.RequesterAgentID = "agent:other"
	other, err := agentrelay.SignRelayQuoteRequest(otherBody, fixture.clientKey)
	if err != nil {
		t.Fatal(err)
	}
	otherRaw, _ := codec.Marshal(agentrelay.QuoteCall{Request: other})
	request = httptest.NewRequest(http.MethodPost, fixture.profile.Endpoints.QuoteURL, bytes.NewReader(otherRaw))
	request.Header.Set("X-Relay-Client", "authorized")
	request.Header.Set("Content-Type", agentrelay.QuoteCallContentType)
	request.Header.Set("Accept", agentrelay.QuoteResultContentType)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("certificate principal submitted another requester's quote: status=%d", response.Code)
	}

	downgradedBody := fixture.prepared.QuoteBody
	downgradedBody.AssuranceLevel = agentrelay.AssuranceAuthorizedSingleProvider
	downgraded, err := agentrelay.SignRelayQuoteRequest(downgradedBody, fixture.clientKey)
	if err != nil {
		t.Fatal(err)
	}
	downgradedRaw, _ := codec.Marshal(agentrelay.QuoteCall{Request: downgraded})
	request = httptest.NewRequest(http.MethodPost, fixture.profile.Endpoints.QuoteURL, bytes.NewReader(downgradedRaw))
	request.Header.Set("X-Relay-Client", "authorized")
	request.Header.Set("Content-Type", agentrelay.QuoteCallContentType)
	request.Header.Set("Accept", agentrelay.QuoteResultContentType)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("runtime assurance downgrade reached the provider service: status=%d", response.Code)
	}
}

func TestRelayProviderHandlerBindsAdmissionToAuthenticatedPrincipal(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	service := fixture.service(agentrelay.NewMemoryJournal(), &relayTestBroadcaster{})
	handler, err := NewRelayProviderHTTPHandler(service, func(*http.Request) (RelayHTTPPrincipal, error) {
		return RelayHTTPPrincipal{RequesterAgentID: "agent:client", CertificateSPKIDigest: relayTestDigest("a")}, nil
	}, defaultRelayHTTPBytes, agentrelay.AssuranceAutonomousDecentralized, service.Profile.SupportedModes)
	if err != nil {
		t.Fatal(err)
	}
	attempt := fixture.attempt(t)
	mutatedBody := attempt.Execution.AdmissionReceipt.Body
	mutatedBody.AuthenticatedPrincipal = "principal:different-session"
	attempt.Execution.AdmissionReceipt, err = agentrelay.SignRelaySideEffectAdmissionReceipt(mutatedBody,
		fixture.authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := codec.Marshal(agentrelay.SubmitCall{Request: attempt.Execution, Agreement: attempt.Agreement})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, fixture.profile.Endpoints.SubmitURL, bytes.NewReader(raw))
	request.Header.Set("Content-Type", agentrelay.SubmitCallContentType)
	request.Header.Set("Accept", agentrelay.SubmitResultContentType)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("receipt for another authenticated principal reached provider admission: status=%d", response.Code)
	}
}

func TestRelayProviderHandlerRejectsRequesterSelectedSponsorshipReleaseProfile(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	fixture.enableClientCorroboratedTerminalProfile()
	fixture.prepared.QuoteBody.AssuranceLevel = agentrelay.AssuranceAuthorizedSingleProvider
	fixture.prepared.QuoteBody.SponsorshipReleaseEvidenceClass = agentrelay.SponsorshipReleaseObservedUnproven
	fixture.prepared.QuoteBody.SponsorshipReleaseProfileURI = agentrelay.RPCCorroborationEvidenceProfileURI
	fixture.prepared.QuoteBody.SponsorshipReleaseProfileDigest = relayTestDigest("6")
	fixture.enableSponsorship(t, agentrelay.ModeSponsorOnly)
	service := fixture.service(agentrelay.NewMemoryJournal(), nil)
	selected := relaySponsorshipReleasePolicyFromRequest(fixture.prepared.QuoteBody)
	handler, err := NewRelayProviderHTTPHandler(service, func(*http.Request) (RelayHTTPPrincipal, error) {
		return RelayHTTPPrincipal{RequesterAgentID: "agent:client",
			CertificateSPKIDigest: relayTestDigest("a")}, nil
	}, defaultRelayHTTPBytes, agentrelay.AssuranceAuthorizedSingleProvider,
		[]agentrelay.Mode{agentrelay.ModeSponsorOnly}, selected)
	if err != nil {
		t.Fatal(err)
	}
	post := func(body agentrelay.RelayQuoteRequestBody) int {
		t.Helper()
		signed, signErr := agentrelay.SignRelayQuoteRequest(body, fixture.clientKey)
		if signErr != nil {
			t.Fatal(signErr)
		}
		raw, _ := codec.Marshal(agentrelay.QuoteCall{Request: signed})
		request := httptest.NewRequest(http.MethodPost, fixture.profile.Endpoints.QuoteURL, bytes.NewReader(raw))
		request.Header.Set("Content-Type", agentrelay.QuoteCallContentType)
		request.Header.Set("Accept", agentrelay.QuoteResultContentType)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response.Code
	}
	if status := post(fixture.prepared.QuoteBody); status != http.StatusOK {
		t.Fatalf("owner-pinned sponsorship release profile was rejected: status=%d", status)
	}
	alternate := fixture.prepared.QuoteBody
	alternate.SponsorshipReleaseProfileDigest = relayTestDigest("7")
	if status := post(alternate); status != http.StatusBadRequest {
		t.Fatalf("requester-selected sponsorship release profile reached QuotePolicy: status=%d", status)
	}
}

func TestRelayPrincipalRateLimiterIsBoundedPerAgent(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	limiter := &relayPrincipalRateLimiter{entries: make(map[string]relayPrincipalRateWindow),
		maximum: 2, window: time.Minute, maxAgent: 1}
	if !limiter.allow("agent:one", now) || !limiter.allow("agent:one", now) || limiter.allow("agent:one", now) {
		t.Fatal("per-Agent request window was not enforced")
	}
	if limiter.allow("agent:two", now) {
		t.Fatal("bounded principal table admitted unbounded Agent identities")
	}
	if !limiter.allow("agent:two", now.Add(time.Minute)) {
		t.Fatal("expired principal window was not safely reclaimed")
	}
}

type relayContextBlockingBody struct {
	ctx     context.Context
	started chan<- struct{}
	once    sync.Once
}

func (body *relayContextBlockingBody) Read([]byte) (int, error) {
	body.once.Do(func() { body.started <- struct{}{} })
	<-body.ctx.Done()
	return 0, body.ctx.Err()
}

func (*relayContextBlockingBody) Close() error { return nil }

func TestRelayProviderPrincipalFairnessAndCancellationRelease(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	service := fixture.service(agentrelay.NewMemoryJournal(), &relayTestBroadcaster{})
	handler, err := NewRelayProviderHTTPHandler(service, func(request *http.Request) (RelayHTTPPrincipal, error) {
		agentID := request.Header.Get("X-Relay-Agent")
		if agentID == "" {
			return RelayHTTPPrincipal{}, errors.New("missing Agent identity")
		}
		return RelayHTTPPrincipal{RequesterAgentID: agentID,
			CertificateSPKIDigest: relayTestDigest("a")}, nil
	}, defaultRelayHTTPBytes, agentrelay.AssuranceAutonomousDecentralized, service.Profile.SupportedModes)
	if err != nil {
		t.Fatal(err)
	}

	blockedContext, cancel := context.WithCancel(t.Context())
	started := make(chan struct{}, maximumRelayHTTPConcurrencyPerPrincipal)
	done := make(chan struct{}, maximumRelayHTTPConcurrencyPerPrincipal)
	for index := 0; index < maximumRelayHTTPConcurrencyPerPrincipal; index++ {
		request := httptest.NewRequest(http.MethodPost, fixture.profile.Endpoints.ResolveURL,
			&relayContextBlockingBody{ctx: blockedContext, started: started}).WithContext(blockedContext)
		request.Header.Set("X-Relay-Agent", "agent:slow")
		request.Header.Set("Content-Type", agentrelay.ResolveCallContentType)
		request.Header.Set("Accept", agentrelay.ResolveResultContentType)
		go func() {
			handler.ServeHTTP(httptest.NewRecorder(), request)
			done <- struct{}{}
		}()
	}
	for index := 0; index < maximumRelayHTTPConcurrencyPerPrincipal; index++ {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("slow authenticated request did not occupy its principal slot")
		}
	}

	// The same principal has reached its local ceiling without consuming the
	// provider-wide reserve required for an unrelated Agent.
	extra := httptest.NewRequest(http.MethodPost, fixture.profile.Endpoints.ResolveURL, bytes.NewReader([]byte{0xa0}))
	extra.Header.Set("X-Relay-Agent", "agent:slow")
	extra.Header.Set("Content-Type", agentrelay.ResolveCallContentType)
	extra.Header.Set("Accept", agentrelay.ResolveResultContentType)
	extraResponse := httptest.NewRecorder()
	handler.ServeHTTP(extraResponse, extra)
	if extraResponse.Code != http.StatusServiceUnavailable {
		t.Fatalf("principal concurrency ceiling was not enforced: status=%d", extraResponse.Code)
	}

	signed, err := agentrelay.SignRelayQuoteRequest(fixture.prepared.QuoteBody, fixture.clientKey)
	if err != nil {
		t.Fatal(err)
	}
	quoteRaw, err := codec.Marshal(agentrelay.QuoteCall{Request: signed})
	if err != nil {
		t.Fatal(err)
	}
	quote := httptest.NewRequest(http.MethodPost, fixture.profile.Endpoints.QuoteURL, bytes.NewReader(quoteRaw))
	quote.Header.Set("X-Relay-Agent", "agent:client")
	quote.Header.Set("Content-Type", agentrelay.QuoteCallContentType)
	quote.Header.Set("Accept", agentrelay.QuoteResultContentType)
	quoteResponse := httptest.NewRecorder()
	handler.ServeHTTP(quoteResponse, quote)
	if quoteResponse.Code != http.StatusOK {
		t.Fatalf("slow principal starved an unrelated Agent: status=%d body=%s",
			quoteResponse.Code, quoteResponse.Body.String())
	}

	cancel()
	for index := 0; index < maximumRelayHTTPConcurrencyPerPrincipal; index++ {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("cancelled request did not release its principal slot")
		}
	}
	released := httptest.NewRequest(http.MethodPost, fixture.profile.Endpoints.ResolveURL, bytes.NewReader([]byte{0xa0}))
	released.Header.Set("X-Relay-Agent", "agent:slow")
	released.Header.Set("Content-Type", agentrelay.ResolveCallContentType)
	released.Header.Set("Accept", agentrelay.ResolveResultContentType)
	releasedResponse := httptest.NewRecorder()
	handler.ServeHTTP(releasedResponse, released)
	if releasedResponse.Code == http.StatusServiceUnavailable {
		t.Fatal("cancelled request leaked its per-principal concurrency reservation")
	}
}

func TestRelayHTTPClientRejectsPrivateEndpointsAndReboundDial(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	for _, origin := range []string{"https://127.0.0.1:8443", "https://10.0.0.7:8443", "https://169.254.169.254"} {
		profile := fixture.profile
		profile.Endpoints = agentrelay.ServiceEndpoints{QuoteURL: origin + "/quote", SubmitURL: origin + "/submit",
			ResolveURL: origin + "/resolve", EvidenceURL: origin + "/evidence"}
		canonical, err := codec.Marshal(profile)
		if err != nil {
			t.Fatal(err)
		}
		verified := fixture.verified
		verified.canonicalProfile = canonical
		if _, err := NewRelayHTTPClient(verified, fixture.resolver,
			RelayHTTPClientConfig{Timeout: 5 * time.Second, Now: func() time.Time { return fixture.now }}); err == nil {
			t.Fatalf("private discovered endpoint %q was accepted without owner whitelist", origin)
		}
	}
	if _, err := NewRelayHTTPClient(fixture.verified, fixture.resolver, RelayHTTPClientConfig{
		Timeout: 5 * time.Second, TLSConfig: &tls.Config{ServerName: "attacker.example"},
		Now: func() time.Time { return fixture.now }}); err == nil {
		t.Fatal("owner TLS config redirected certificate verification away from the signed endpoint host")
	}
	client, err := NewRelayHTTPClient(fixture.verified, fixture.resolver,
		RelayHTTPClientConfig{Timeout: 5 * time.Second, Now: func() time.Time { return fixture.now }})
	if err != nil {
		t.Fatal(err)
	}
	transport := client.client.Transport.(*http.Transport)
	if transport.Proxy != nil || transport.DialContext == nil || transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatal("relay transport lost no-proxy, safe-dial, or TLS 1.3 hardening")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if connection, err := transport.DialContext(t.Context(), "tcp", listener.Addr().String()); err == nil {
		connection.Close()
		t.Fatal("safe relay dial accepted a direct private address")
	}
	dnsAddress, closeDNS := relayPrivateDNSResponder(t)
	defer closeDNS()
	priorResolver := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", dnsAddress)
	}}
	defer func() { net.DefaultResolver = priorResolver }()
	if connection, err := transport.DialContext(t.Context(), "tcp", "rebind.example:443"); err == nil {
		connection.Close()
		t.Fatal("safe relay dial accepted a hostname after DNS rebound to loopback")
	}
}

func TestRelayHTTPClientRejectsRedirectWrongMediaAndUnknownResponse(t *testing.T) {
	server := httptest.NewUnstartedServer(nil)
	origin := relayTestPublicOrigin(t, server)
	fixture := newRelayTestFixture(t, "agent:provider", nil, origin)
	var mode atomic.Int32
	var redirectTarget atomic.Int32
	server.Config.Handler = http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch mode.Load() {
		case 0:
			http.Redirect(response, request, origin+"/target", http.StatusFound)
		case 1:
			response.Header().Set("Content-Type", agentrelay.QuoteResultContentType+"; charset=binary")
			_, _ = response.Write([]byte{0xa0})
		case 2:
			response.Header().Set("Content-Type", agentrelay.QuoteResultContentType)
			raw, _ := codec.Marshal(map[string]any{"quote": agentrelay.SignedProviderRelayQuote{}, "unknown": true})
			_, _ = response.Write(raw)
		default:
			redirectTarget.Add(1)
		}
	})
	server.StartTLS()
	defer server.Close()
	client := relayTestHTTPClient(t, fixture, server, nil)
	signed, err := agentrelay.SignRelayQuoteRequest(fixture.prepared.QuoteBody, fixture.clientKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Quote(t.Context(), signed); err == nil || redirectTarget.Load() != 0 {
		t.Fatal("relay client followed a discovered endpoint redirect")
	}
	certificate, err := x509.ParseCertificate(server.Certificate().Raw)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	wrongProvenance := relayHTTPTestProvenance(t, fixture, certificate)
	wrongProvenance.CertificatePinDigest = relayTestDigest("f")
	wrongPinClient, err := NewRelayHTTPClient(fixture.verified, fixture.resolver, RelayHTTPClientConfig{
		TLSConfig: &tls.Config{RootCAs: roots}, Timeout: 5 * time.Second,
		PrivateHostWhitelist: []string{"127.0.0.0/8", "::1/128"}, ProviderProvenance: wrongProvenance,
		Now: func() time.Time { return fixture.now }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongPinClient.Quote(t.Context(), signed); err == nil {
		t.Fatal("relay client accepted a TLS peer outside the owner-attested SPKI pin")
	}
	mode.Store(1)
	if _, err := client.Quote(t.Context(), signed); err == nil {
		t.Fatal("relay client accepted a parameterized response media type")
	}
	mode.Store(2)
	if _, err := client.Quote(t.Context(), signed); err == nil {
		t.Fatal("relay client accepted an unknown response field")
	}
}

func TestRelayHTTPFailoverResolveDoesNotClaimPreDispatchOrRejectedAuthentication(t *testing.T) {
	server := httptest.NewUnstartedServer(nil)
	origin := relayTestPublicOrigin(t, server)
	fixture := newRelayTestFixture(t, "agent:provider", nil, origin)
	var requests atomic.Int32
	server.Config.Handler = http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		http.Error(response, "authentication rejected", http.StatusUnauthorized)
	})
	server.StartTLS()
	defer server.Close()
	attempt := fixture.attempt(t)
	call := agentrelay.ResolveCall{StableActionID: attempt.Execution.AuthorizedAction.StableActionID,
		ExactRequestDigest: attempt.Execution.AuthorizedAction.ExactRequestDigest}
	preflight := relayTestHTTPClient(t, fixture, server, func(*http.Request) error {
		return errors.New("owner credential broker refused the request")
	})
	if _, _, dispatched, err := preflight.resolveForFailover(t.Context(), call, attempt.Execution,
		*preflight.provenance, "agent:client"); err == nil || dispatched || requests.Load() != 0 {
		t.Fatalf("pre-dispatch authentication failure became a query gate: dispatched=%v requests=%d err=%v",
			dispatched, requests.Load(), err)
	}
	rejected := relayTestHTTPClient(t, fixture, server, nil)
	if _, _, dispatched, err := rejected.resolveForFailover(t.Context(), call, attempt.Execution,
		*rejected.provenance, "agent:client"); !errors.Is(err, errRelayResolveAuthenticationRejected) ||
		!dispatched || requests.Load() != 1 {
		t.Fatalf("Provider auth rejection was not distinguished from unavailable: dispatched=%v requests=%d err=%v",
			dispatched, requests.Load(), err)
	}
}

func relayTestHTTPClient(t *testing.T, fixture *relayTestFixture, server *httptest.Server,
	auth func(*http.Request) error) *RelayHTTPClient {
	t.Helper()
	certificate, err := x509.ParseCertificate(server.Certificate().Raw)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	clientCA, clientCAKey, _ := issueTestCertificate(t, nil, nil, "relay-test-client-ca", true, nil, fixture.now)
	_, _, clientCertificate := issueTestCertificate(t, clientCA, clientCAKey, "relay-test-client", false,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, fixture.now)
	dnsAddress, closeDNS := relayPrivateDNSResponder(t)
	t.Cleanup(closeDNS)
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", dnsAddress)
	}}
	client, err := NewRelayHTTPClient(fixture.verified, fixture.resolver, RelayHTTPClientConfig{
		TLSConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{clientCertificate}},
		Timeout:   5 * time.Second, MaximumResponseBytes: defaultRelayHTTPBytes,
		PrivateHostWhitelist: []string{"127.0.0.0/8", "::1/128"}, AuthenticateRequest: auth,
		Resolver:           resolver,
		ProviderProvenance: relayHTTPTestProvenance(t, fixture, certificate),
		RequesterAgentID:   "agent:client",
		Now:                func() time.Time { return fixture.now }})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func relayTestPublicOrigin(t *testing.T, server *httptest.Server) string {
	t.Helper()
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return "https://example.com:" + port
}

func relayHTTPTestProvenance(t *testing.T, fixture *relayTestFixture,
	certificate *x509.Certificate) *RelayProviderProvenance {
	t.Helper()
	profileDigest, err := agentrelay.RelayServiceProfileDigest(fixture.profile)
	origin, originErr := relayProfileEndpointOrigin(fixture.profile.Endpoints)
	if err != nil || originErr != nil {
		t.Fatal(errors.Join(err, originErr))
	}
	spki := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	return &RelayProviderProvenance{ProviderAgentID: fixture.profile.ProviderAgentID,
		IntentDigest: fixture.verified.IntentDigest(), ProfileDigest: profileDigest,
		OperatorDomain: "operator:test", FailureDomain: "failure:test", EndpointOrigin: origin,
		CertificatePinDigest:       "sha256:" + hex.EncodeToString(spki[:]),
		ImplementationEvidenceHash: relayTestDigest("a")}
}

func relayTestCoordinator(t *testing.T, fixture *relayTestFixture, transport RelayTransport) RelayCoordinator {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "client-relay-journal")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenDurableRelayJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	return RelayCoordinator{VerifiedProfile: fixture.verified, Transport: transport, RequesterKey: fixture.clientKey,
		AgentResolver: fixture.resolver, FenceResolver: fixture.resolver, Inspector: fixture.inspector,
		ActionBinder: fixture.binder, AgreementVerifier: commerce.AgentSignatureEvidenceVerifier{Resolver: fixture.resolver},
		AgreementAuthorizer: fixture.agreementAuthorizer(t), SideEffectAdmission: fixture.admission,
		AttemptJournal:              journal,
		FinalityVerifier:            relayTestFinalityVerifier{dualAbsence: true, portable: true},
		SponsorshipEvidenceVerifier: relayTestSponsorshipEvidenceVerifier{},
		SponsorshipReleasePolicy:    relaySponsorshipReleasePolicyFromRequest(fixture.prepared.QuoteBody),
		Now:                         func() time.Time { return fixture.now }}
}

type relayTestSponsorshipEvidenceVerifier struct{}

func (relayTestSponsorshipEvidenceVerifier) SupportsRelaySponsorshipTransactionEvidence(
	agentrelay.AssuranceLevel, RelaySponsorshipReleasePolicy, agentrelay.FinalityProfile) bool {
	return true
}

func (relayTestSponsorshipEvidenceVerifier) VerifySponsorshipTransactionEvidence(context.Context,
	agentrelay.RelaySponsorshipTransactionEvidence, agentrelay.RelaySponsorshipEvidenceContext,
	agentrelay.FinalityProfile) error {
	return nil
}

func (relayTestSponsorshipEvidenceVerifier) FreezeRelaySponsorshipClientEvidenceSnapshot(_ context.Context,
	body agentrelay.RelayQuoteRequestBody) (RelaySponsorshipEvidenceSnapshot, error) {
	selected := body.SelectedSponsorshipReleaseProfile()
	return RelaySponsorshipEvidenceSnapshot{SchemaVersion: 1, EvidenceClass: string(selected.EvidenceClass),
		ProfileURI: selected.ProfileURI, ProfileDigest: selected.ProfileDigest, MaximumTransactions: 1000,
		SnapshotPath: "/owner/client-relay-corroboration/manifest.json", SnapshotIdentity: relayTestDigest("e")}, nil
}

func (relayTestSponsorshipEvidenceVerifier) ValidateRelaySponsorshipClientEvidenceSnapshot(
	selected agentrelay.SponsorshipReleaseProfile, snapshot RelaySponsorshipEvidenceSnapshot) error {
	if !validClientRelaySponsorshipSnapshot(selected, snapshot) {
		return errors.New("invalid fixture client sponsorship snapshot")
	}
	return nil
}

func (verifier relayTestSponsorshipEvidenceVerifier) VerifySponsorshipTransactionEvidenceFromSnapshot(ctx context.Context,
	evidence agentrelay.RelaySponsorshipTransactionEvidence, expected agentrelay.RelaySponsorshipEvidenceContext,
	profile agentrelay.FinalityProfile, snapshot RelaySponsorshipEvidenceSnapshot) error {
	if snapshot.SnapshotIdentity != relayTestDigest("e") {
		return errors.New("fixture client sponsorship snapshot changed")
	}
	return verifier.VerifySponsorshipTransactionEvidence(ctx, evidence, expected, profile)
}

func (relayTestSponsorshipEvidenceVerifier) HasIndependentPortableSponsorshipProofs() bool {
	return true
}

func relayPrivateDNSResponder(t *testing.T) (string, func()) {
	t.Helper()
	connection, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 1500)
		for {
			count, peer, readErr := connection.ReadFrom(buffer)
			if readErr != nil {
				return
			}
			var parser dnsmessage.Parser
			header, parseErr := parser.Start(buffer[:count])
			if parseErr != nil {
				continue
			}
			question, parseErr := parser.Question()
			if parseErr != nil {
				continue
			}
			builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: header.ID, Response: true,
				RecursionDesired: header.RecursionDesired, RecursionAvailable: true})
			_ = builder.StartQuestions()
			_ = builder.Question(question)
			_ = builder.StartAnswers()
			if question.Type == dnsmessage.TypeA {
				_ = builder.AResource(dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA,
					Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}})
			}
			response, finishErr := builder.Finish()
			if finishErr == nil {
				_, _ = connection.WriteTo(response, peer)
			}
		}
	}()
	return connection.LocalAddr().String(), func() {
		_ = connection.Close()
		<-done
	}
}
