package earning

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

const maxPrivateIngressControlBytes = 2 << 20

type privateIngressUploadRequest struct {
	Challenge     commerce.SignedPrivateHandoffChallenge     `json:"challenge"`
	Authorization commerce.SignedPrivateHandoffAuthorization `json:"authorization"`
	Ciphertext    []byte                                     `json:"ciphertext"`
}

type privateIngressUploadResponse struct {
	Acknowledgement commerce.SignedPrivateHandoffAcknowledgement `json:"acknowledgement"`
}

// HTTPPrivateContentUploader maps one owner-selected ingress instance to one
// exact URL. The remote challenge can select only the instance identifier; it
// cannot inject a URL, proxy, credential or redirect target.
type HTTPPrivateContentUploader struct {
	IngressInstanceID string
	Endpoint          string
	Client            *http.Client
	MaximumCiphertext uint64
}

func NewHTTPPrivateContentUploader(instanceID, endpoint string, roots *x509.CertPool,
	maximumCiphertext uint64, allowLoopbackHTTP bool) (*HTTPPrivateContentUploader, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || instanceID == "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil ||
		parsed.Path == "" || parsed.Path == "/" || maximumCiphertext == 0 || maximumCiphertext > 1<<30 {
		return nil, errors.New("private ingress endpoint configuration is invalid")
	}
	if parsed.Scheme != "https" {
		host := strings.ToLower(parsed.Hostname())
		if !allowLoopbackHTTP || parsed.Scheme != "http" || host != "localhost" && net.ParseIP(host) == nil ||
			(host != "localhost" && !net.ParseIP(host).IsLoopback()) {
			return nil, errors.New("private ingress requires HTTPS except for explicitly enabled loopback tests")
		}
	}
	transport := &http.Transport{Proxy: nil, DisableCompression: true, ForceAttemptHTTP2: true,
		DialContext:     (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, ServerName: parsed.Hostname(), RootCAs: roots}}
	client := &http.Client{Transport: transport, Timeout: 2 * time.Minute,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &HTTPPrivateContentUploader{IngressInstanceID: instanceID, Endpoint: parsed.String(), Client: client,
		MaximumCiphertext: maximumCiphertext}, nil
}

func (uploader *HTTPPrivateContentUploader) Upload(ctx context.Context, challenge commerce.SignedPrivateHandoffChallenge,
	authorization commerce.SignedPrivateHandoffAuthorization, ciphertext []byte) (commerce.SignedPrivateHandoffAcknowledgement, error) {
	if uploader == nil || uploader.Client == nil || challenge.Body.IngressInstanceID != uploader.IngressInstanceID ||
		uint64(len(ciphertext)) == 0 || uint64(len(ciphertext)) > uploader.MaximumCiphertext ||
		uint64(len(ciphertext)) > challenge.Body.MaximumCiphertextBytes {
		return commerce.SignedPrivateHandoffAcknowledgement{}, errors.New("private upload does not match the owner-selected ingress")
	}
	body, err := json.Marshal(privateIngressUploadRequest{Challenge: challenge, Authorization: authorization,
		Ciphertext: append([]byte(nil), ciphertext...)})
	if err != nil || len(body) > maxPrivateIngressControlBytes+len(ciphertext)*2 {
		return commerce.SignedPrivateHandoffAcknowledgement{}, errors.New("private upload envelope exceeds its bound")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, uploader.Endpoint, bytes.NewReader(body))
	if err != nil {
		return commerce.SignedPrivateHandoffAcknowledgement{}, err
	}
	request.Header.Set("Content-Type", "application/vnd.tos.private-handoff-upload.v1+json")
	request.Header.Set("Accept", "application/vnd.tos.private-handoff-acknowledgement.v1+json")
	response, err := uploader.Client.Do(request)
	if err != nil {
		return commerce.SignedPrivateHandoffAcknowledgement{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/vnd.tos.private-handoff-acknowledgement.v1+json" {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return commerce.SignedPrivateHandoffAcknowledgement{}, fmt.Errorf("private ingress returned HTTP %d", response.StatusCode)
	}
	var result privateIngressUploadResponse
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxPrivateIngressControlBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return commerce.SignedPrivateHandoffAcknowledgement{}, err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return commerce.SignedPrivateHandoffAcknowledgement{}, err
	}
	return result.Acknowledgement, nil
}

type PrivateHandoffAcceptFunc func(context.Context, commerce.SignedPrivateHandoffChallenge,
	commerce.SignedPrivateHandoffAuthorization, []byte) (commerce.SignedPrivateHandoffAcknowledgement, error)

// PrivateIngressHTTPHandler accepts only an exact challenge issued by this
// ingress instance and a sender-signed authorization. It has no bearer-token
// path. Concurrency and conflicting-byte behavior are enforced by the durable
// immutable ingress store behind Accept.
type PrivateIngressHTTPHandler struct {
	IngressInstanceID string
	MaximumBodyBytes  int64
	Accept            PrivateHandoffAcceptFunc
}

func (handler PrivateIngressHTTPHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || request.Header.Get("Content-Type") != "application/vnd.tos.private-handoff-upload.v1+json" ||
		handler.IngressInstanceID == "" || handler.Accept == nil {
		http.Error(response, "invalid private ingress request", http.StatusBadRequest)
		return
	}
	limit := handler.MaximumBodyBytes
	if limit <= 0 || limit > 2<<30 {
		limit = 64 << 20
	}
	request.Body = http.MaxBytesReader(response, request.Body, limit)
	defer request.Body.Close()
	var input privateIngressUploadRequest
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil || requireJSONEOF(decoder) != nil ||
		input.Challenge.Body.IngressInstanceID != handler.IngressInstanceID || len(input.Ciphertext) == 0 ||
		uint64(len(input.Ciphertext)) > input.Challenge.Body.MaximumCiphertextBytes {
		http.Error(response, "invalid private ingress envelope", http.StatusBadRequest)
		return
	}
	acknowledgement, err := handler.Accept(request.Context(), input.Challenge, input.Authorization, input.Ciphertext)
	if err != nil {
		http.Error(response, "private ingress rejected the upload", http.StatusConflict)
		return
	}
	response.Header().Set("Content-Type", "application/vnd.tos.private-handoff-acknowledgement.v1+json")
	response.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(response).Encode(privateIngressUploadResponse{Acknowledgement: acknowledgement})
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("JSON contains trailing data")
	}
	return nil
}
