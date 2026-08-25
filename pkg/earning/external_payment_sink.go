package earning

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

type ExternalPaymentAttestorPins map[string]struct {
	AdapterURI string
	PublicKey  ed25519.PublicKey
}

func (pins ExternalPaymentAttestorPins) AuthorizeExternalPaymentAttestor(id, adapter string,
	key ed25519.PublicKey, _ time.Time) error {
	pin, found := pins[id]
	if !found || pin.AdapterURI != adapter || !pin.PublicKey.Equal(key) {
		return errors.New("external payment attestor is not owner-pinned")
	}
	return nil
}

type externalPaymentRPC struct {
	Operation string                           `json:"operation"`
	Action    *commerce.AuthorizedAction       `json:"authorized_action,omitempty"`
	Fence     *commerce.WriterFence            `json:"writer_fence,omitempty"`
	Fields    []commerce.SemanticFieldValue    `json:"semantic_fields,omitempty"`
	Request   commerce.AgreementPaymentRequest `json:"payment_request"`
}

type externalPaymentRPCResult struct {
	Attestation commerce.SignedExternalPaymentAttestation `json:"attestation"`
}

// ExternalAttestedPaymentSink delegates one exact payment request to an
// owner-configured mTLS adapter. The adapter response is useful only when an
// independently pinned attestor signs the exact request/action identity.
type ExternalAttestedPaymentSink struct {
	Endpoint   string
	AdapterURI string
	Client     *http.Client
	Resolver   commerce.ExternalPaymentAttestorResolver
	Now        func() time.Time
}

func NewExternalPaymentHTTPClient(certificate tls.Certificate, roots *x509.CertPool,
	serverName string, timeout time.Duration) (*http.Client, error) {
	if len(certificate.Certificate) == 0 || roots == nil || serverName == "" || timeout < time.Second || timeout > time.Minute {
		return nil, errors.New("external settlement mTLS configuration is incomplete")
	}
	transport := &http.Transport{Proxy: nil, DisableCompression: true, ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate},
			RootCAs: roots, ServerName: serverName, SessionTicketsDisabled: true}, TLSHandshakeTimeout: 5 * time.Second,
		ResponseHeaderTimeout: timeout}
	return &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("external settlement redirects are forbidden")
	}}, nil
}

func NewExternalAttestedPaymentSink(endpoint, adapterURI string, client *http.Client,
	resolver commerce.ExternalPaymentAttestorResolver) (*ExternalAttestedPaymentSink, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed == nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.Path != "/v1/agreement-payments" || parsed.RawQuery != "" || parsed.Fragment != "" ||
		adapterURI == "" || client == nil || resolver == nil {
		return nil, errors.New("external attested payment Adapter configuration is invalid")
	}
	return &ExternalAttestedPaymentSink{Endpoint: parsed.String(), AdapterURI: adapterURI, Client: client, Resolver: resolver, Now: time.Now}, nil
}

func (sink *ExternalAttestedPaymentSink) SubmitPayment(ctx context.Context, action commerce.AuthorizedAction,
	fence commerce.WriterFence, fields map[string]commerce.SemanticValue, _ []byte,
	request commerce.AgreementPaymentRequest) (commerce.AgreementPaymentEvidence, error) {
	if request.SchemaVersion != 2 || request.SemanticActionKind != "settlement.external" ||
		request.SettlementAdapterURI != sink.AdapterURI || action.ActionKind != "settlement.external" ||
		action.StableActionID != request.StableActionID {
		return commerce.AgreementPaymentEvidence{}, errors.New("external settlement request selects another Adapter or action")
	}
	wireFields, err := commerce.ExportSemanticFields(action.ActionKind, fields)
	if err != nil {
		return commerce.AgreementPaymentEvidence{}, err
	}
	return sink.call(ctx, externalPaymentRPC{Operation: "submit", Action: &action, Fence: &fence, Fields: wireFields, Request: request})
}

func (sink *ExternalAttestedPaymentSink) ResolvePayment(ctx context.Context,
	request commerce.AgreementPaymentRequest) (commerce.AgreementPaymentEvidence, error) {
	if request.SchemaVersion != 2 || request.SemanticActionKind != "settlement.external" ||
		request.SettlementAdapterURI != sink.AdapterURI {
		return commerce.AgreementPaymentEvidence{}, errors.New("external settlement query selects another Adapter")
	}
	return sink.call(ctx, externalPaymentRPC{Operation: "resolve", Request: request})
}

func (sink *ExternalAttestedPaymentSink) VerifyPaymentEvidence(request commerce.AgreementPaymentRequest,
	evidence commerce.AgreementPaymentEvidence, now time.Time) error {
	return (commerce.ExternalPaymentEvidenceVerifier{Resolver: sink.Resolver}).VerifyPaymentEvidence(request, evidence, now)
}

func (sink *ExternalAttestedPaymentSink) call(ctx context.Context, body externalPaymentRPC) (commerce.AgreementPaymentEvidence, error) {
	if sink == nil || sink.Client == nil || ctx == nil {
		return commerce.AgreementPaymentEvidence{}, errors.New("external payment Adapter is unavailable")
	}
	raw, err := json.Marshal(body)
	if err != nil || len(raw) > 2<<20 {
		return commerce.AgreementPaymentEvidence{}, errors.New("external payment request is oversized")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, sink.Endpoint, bytes.NewReader(raw))
	if err != nil {
		return commerce.AgreementPaymentEvidence{}, err
	}
	request.Header.Set("Content-Type", "application/vnd.tos.agreement-payment-adapter.v1+json")
	request.Header.Set("Accept", "application/vnd.tos.external-payment-attestation.v1+json")
	response, err := sink.Client.Do(request)
	if err != nil {
		return commerce.AgreementPaymentEvidence{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/vnd.tos.external-payment-attestation.v1+json" {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return commerce.AgreementPaymentEvidence{}, errors.New("external payment Adapter did not return final evidence")
	}
	limited := io.LimitReader(response.Body, (2<<20)+1)
	var result externalPaymentRPCResult
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || requireJSONEOF(decoder) != nil {
		return commerce.AgreementPaymentEvidence{}, errors.New("external payment Adapter response is invalid")
	}
	now := time.Now().UTC()
	if sink.Now != nil {
		now = sink.Now().UTC()
	}
	return commerce.ExternalPaymentEvidence(body.Request, result.Attestation, sink.Resolver, now)
}

var _ AgreementPaymentSink = (*ExternalAttestedPaymentSink)(nil)
var _ commerce.PaymentEvidenceVerifier = (*ExternalAttestedPaymentSink)(nil)
