package earning

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

// HTTPPublicationSink is a purpose-limited Carrier publisher. It obtains and
// solves the Carrier-selected admission challenge, then submits the exact
// Authority-signed action. Redirects are disabled so a Carrier cannot move the
// relay credential to another origin.
type HTTPPublicationSink struct {
	carrierID string
	endpoint  *url.URL
	token     string
	client    *http.Client
}

func NewHTTPPublicationSink(carrierID, endpoint, relayToken string, timeout time.Duration) (*HTTPPublicationSink, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed == nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "/v1/intents" ||
		carrierID == "" || strings.TrimSpace(relayToken) == "" || timeout <= 0 || timeout > time.Minute {
		return nil, errors.New("HTTP Intent publication configuration is invalid")
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && loopbackHost(parsed.Hostname())) {
		return nil, errors.New("HTTP Intent publication requires HTTPS outside loopback development")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &HTTPPublicationSink{carrierID: carrierID, endpoint: parsed, token: strings.TrimSpace(relayToken),
		client: &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("Intent Carrier redirects are disabled")
		}}}, nil
}

func (sink *HTTPPublicationSink) PublishIntent(ctx context.Context, action commerce.AuthorizedAction, fence commerce.WriterFence,
	fields map[string]commerce.SemanticValue, canonical []byte, intent commerce.SignedAgentIntent) (commerce.ActionResolution, error) {
	if sink == nil || ctx == nil || action.ActionKind != "publication.publish" || intent.Body.IssuerAgentID != action.AgentID {
		return commerce.ActionResolution{}, errors.New("HTTP Intent publication request is invalid")
	}
	derived, _, err := commerce.DeriveStableActionID(action.ActionKind, fields)
	requestDigest, digestErr := commerce.ExactRequestDigest(canonical)
	encodedIntent, encodeErr := codec.Marshal(intent)
	if err != nil || digestErr != nil || encodeErr != nil || derived != action.StableActionID || requestDigest != action.ExactRequestDigest || !bytes.Equal(encodedIntent, canonical) {
		return commerce.ActionResolution{}, errors.New("HTTP Intent publication identity or canonical request mismatch")
	}
	challengeURL := *sink.endpoint
	challengeURL.Path += "/admission-challenge"
	query := challengeURL.Query()
	query.Set("actor_id", action.AgentID)
	query.Set("audience", intent.Body.Audience)
	query.Set("declared_bytes", strconv.Itoa(len(canonical)))
	query.Set("operation_kind", "publication.publish")
	challengeURL.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, challengeURL.String(), nil)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	sink.authorize(request)
	response, err := sink.client.Do(request)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	challengeRaw, err := readBoundedResponse(response, http.StatusCreated, 128<<10)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	var challenge commerce.SignedOperationAdmissionChallenge
	if err := decodeStrictJSON(challengeRaw, &challenge); err != nil || challenge.Body.CarrierID != sink.carrierID {
		return commerce.ActionResolution{}, errors.New("Carrier returned an invalid admission challenge")
	}
	proof, err := commerce.SolveOperationAdmission(challenge, 1<<25)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	publicationRaw, err := json.Marshal(struct {
		Intent    commerce.SignedAgentIntent       `json:"intent"`
		Admission commerce.OperationAdmissionProof `json:"admission"`
		Action    commerce.AuthorizedAction        `json:"authorized_action"`
		Fence     commerce.WriterFence             `json:"writer_fence"`
	}{intent, proof, action, fence})
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	request, err = http.NewRequestWithContext(ctx, http.MethodPost, sink.endpoint.String(), bytes.NewReader(publicationRaw))
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	sink.authorize(request)
	request.Header.Set("Content-Type", "application/json")
	response, err = sink.client.Do(request)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	raw, err := readBoundedResponse(response, http.StatusCreated, 3<<20)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	var result struct {
		Result     json.RawMessage           `json:"result"`
		Resolution commerce.ActionResolution `json:"action_resolution"`
	}
	if err := decodeStrictJSON(raw, &result); err != nil || len(result.Result) == 0 || commerce.ValidateActionResolution(result.Resolution) != nil ||
		result.Resolution.StableActionID != action.StableActionID || result.Resolution.ExactRequestDigest != action.ExactRequestDigest {
		return commerce.ActionResolution{}, errors.New("Carrier returned an invalid publication resolution")
	}
	return result.Resolution, nil
}

func (sink *HTTPPublicationSink) WithdrawIntent(ctx context.Context, action commerce.AuthorizedAction,
	fence commerce.WriterFence, fields map[string]commerce.SemanticValue, canonical []byte,
	withdrawal commerce.SignedAgentIntentWithdrawal) (commerce.ActionResolution, error) {
	if sink == nil || ctx == nil || action.ActionKind != "publication.withdraw" || withdrawal.Body.IssuerAgentID != action.AgentID {
		return commerce.ActionResolution{}, errors.New("HTTP Intent withdrawal request is invalid")
	}
	derived, _, err := commerce.DeriveStableActionID(action.ActionKind, fields)
	requestDigest, digestErr := commerce.ExactRequestDigest(canonical)
	encoded, encodeErr := codec.Marshal(withdrawal)
	if err != nil || digestErr != nil || encodeErr != nil || derived != action.StableActionID || requestDigest != action.ExactRequestDigest || !bytes.Equal(encoded, canonical) {
		return commerce.ActionResolution{}, errors.New("HTTP Intent withdrawal identity or canonical request mismatch")
	}
	challengeURL := *sink.endpoint
	challengeURL.Path += "/admission-challenge"
	query := challengeURL.Query()
	query.Set("actor_id", action.AgentID)
	query.Set("audience", withdrawal.Body.Audience)
	query.Set("declared_bytes", strconv.Itoa(len(canonical)))
	query.Set("operation_kind", "publication.withdraw")
	challengeURL.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, challengeURL.String(), nil)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	sink.authorize(request)
	response, err := sink.client.Do(request)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	challengeRaw, err := readBoundedResponse(response, http.StatusCreated, 128<<10)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	var challenge commerce.SignedOperationAdmissionChallenge
	if err := decodeStrictJSON(challengeRaw, &challenge); err != nil || challenge.Body.CarrierID != sink.carrierID ||
		challenge.Body.OperationKind != "publication.withdraw" {
		return commerce.ActionResolution{}, errors.New("Carrier returned an invalid withdrawal admission challenge")
	}
	proof, err := commerce.SolveOperationAdmission(challenge, 1<<25)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	rawRequest, err := json.Marshal(struct {
		Withdrawal commerce.SignedAgentIntentWithdrawal `json:"withdrawal"`
		Admission  commerce.OperationAdmissionProof     `json:"admission"`
		Action     commerce.AuthorizedAction            `json:"authorized_action"`
		Fence      commerce.WriterFence                 `json:"writer_fence"`
	}{withdrawal, proof, action, fence})
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	endpoint := *sink.endpoint
	endpoint.Path += "/withdrawals"
	request, err = http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(rawRequest))
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	sink.authorize(request)
	request.Header.Set("Content-Type", "application/json")
	response, err = sink.client.Do(request)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	raw, err := readBoundedResponse(response, http.StatusCreated, 128<<10)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	var result struct {
		Resolution commerce.ActionResolution `json:"action_resolution"`
	}
	if err := decodeStrictJSON(raw, &result); err != nil || commerce.ValidateActionResolution(result.Resolution) != nil ||
		result.Resolution.StableActionID != action.StableActionID || result.Resolution.ExactRequestDigest != action.ExactRequestDigest {
		return commerce.ActionResolution{}, errors.New("Carrier returned an invalid withdrawal resolution")
	}
	return result.Resolution, nil
}

func (sink *HTTPPublicationSink) ResolveAction(ctx context.Context, actionID, requestDigest string) (commerce.ActionResolution, error) {
	if sink == nil || ctx == nil || !canonicalSHA256(actionID) || !canonicalSHA256(requestDigest) {
		return commerce.ActionResolution{}, errors.New("HTTP publication action query is invalid")
	}
	endpoint := *sink.endpoint
	endpoint.Path = "/v1/intent-actions/" + strings.TrimPrefix(actionID, "sha256:")
	query := endpoint.Query()
	query.Set("request_digest", requestDigest)
	endpoint.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	sink.authorize(request)
	response, err := sink.client.Do(request)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	raw, err := readBoundedResponse(response, http.StatusOK, 128<<10)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	var resolution commerce.ActionResolution
	if err := decodeStrictJSON(raw, &resolution); err != nil || commerce.ValidateActionResolution(resolution) != nil ||
		resolution.StableActionID != actionID || resolution.ExactRequestDigest != requestDigest {
		return commerce.ActionResolution{}, errors.New("Carrier returned an invalid action resolution")
	}
	return resolution, nil
}

func (sink *HTTPPublicationSink) authorize(request *http.Request) {
	request.Header.Set("Authorization", "Bearer "+sink.token)
	request.Header.Set("Accept", "application/json")
}

func readBoundedResponse(response *http.Response, expectedStatus, limit int) ([]byte, error) {
	if response == nil {
		return nil, errors.New("Carrier response is unavailable")
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, int64(limit)+1))
	if err != nil || response.StatusCode != expectedStatus || len(raw) == 0 || len(raw) > limit {
		return nil, errors.New("Carrier response is invalid, failed, or oversized")
	}
	return raw, nil
}

func decodeStrictJSON(raw []byte, output any) error {
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	return ensureJSONEOF(decoder)
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, composite := token.(json.Delim)
		if !composite {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("JSON object key is invalid")
				}
				if _, duplicate := seen[key]; duplicate {
					return errors.New("JSON object contains a duplicate key")
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim('}') {
				return errors.New("JSON object is not closed")
			}
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim(']') {
				return errors.New("JSON array is not closed")
			}
		default:
			return errors.New("JSON contains an unexpected delimiter")
		}
		return nil
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON contains trailing data")
		}
		return err
	}
	return nil
}
