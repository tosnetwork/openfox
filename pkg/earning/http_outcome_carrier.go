package earning

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type HTTPOutcomeCarrier struct {
	carrierID  string
	endpoint   *url.URL
	readToken  string
	relayToken string
	carrierKey ed25519.PublicKey
	client     *http.Client
}

func NewHTTPOutcomeCarrier(carrierID, endpoint, readToken, relayToken, receiptPublicKey string, timeout time.Duration) (*HTTPOutcomeCarrier, error) {
	parsed, err := url.Parse(endpoint)
	carrierKey, keyErr := decodeOutcomeCarrierKey(receiptPublicKey)
	if err != nil || parsed == nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "/v1/operations" ||
		keyErr != nil || carrierID == "" || strings.TrimSpace(readToken) == "" || strings.TrimSpace(relayToken) == "" || timeout <= 0 || timeout > time.Minute {
		return nil, errors.New("HTTP outcome Carrier configuration is invalid")
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && loopbackHost(parsed.Hostname())) {
		return nil, errors.New("HTTP outcome Carrier requires HTTPS outside loopback development")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Carrier credentials are origin credentials. Environment proxies must not
	// receive them, redirects cannot change their origin, and compressed
	// responses cannot bypass the retained-byte budget.
	transport.Proxy = nil
	transport.DisableCompression = true
	transport.MaxConnsPerHost = 8
	transport.MaxIdleConnsPerHost = 4
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13}
	return &HTTPOutcomeCarrier{carrierID: carrierID, endpoint: parsed, readToken: strings.TrimSpace(readToken), relayToken: strings.TrimSpace(relayToken), carrierKey: carrierKey,
		client: &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("outcome Carrier redirects are disabled")
		}}}, nil
}

func (carrier *HTTPOutcomeCarrier) ID() string {
	if carrier == nil {
		return ""
	}
	return carrier.carrierID
}

func (carrier *HTTPOutcomeCarrier) PublishOperation(ctx context.Context, action commerce.AuthorizedAction,
	fence commerce.WriterFence, operation commerce.OperationCarrierRequestV1) (commerce.ActionResolution, error) {
	if carrier == nil || ctx == nil || action.ActionKind != "operation.publish" || operation.CarrierID != carrier.carrierID || operation.OperationID == "" {
		return commerce.ActionResolution{}, errors.New("HTTP outcome publication is invalid")
	}
	canonical, err := codec.Marshal(operation)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	fields, err := commerce.OperationPublishSemanticFieldsV1(action.OwnerID, action.AgentID, operation)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	stable, _, err := commerce.DeriveStableActionID("operation.publish", fields)
	requestDigest, digestErr := commerce.ExactRequestDigest(canonical)
	if err != nil || digestErr != nil || stable != action.StableActionID || requestDigest != action.ExactRequestDigest {
		return commerce.ActionResolution{}, errors.New("HTTP outcome publication identity mismatch")
	}
	var envelope commerce.AgentOperationEnvelopeV1
	if codec.Unmarshal(operation.OperationEnvelope, &envelope) != nil || envelope.Body.ActorAgentID != action.AgentID {
		return commerce.ActionResolution{}, errors.New("HTTP outcome publisher mismatch")
	}
	challengeURL := *carrier.endpoint
	challengeURL.Path += "/admission-challenge"
	query := challengeURL.Query()
	query.Set("actor_id", action.AgentID)
	query.Set("audience", envelope.Body.AudienceDescriptor)
	query.Set("declared_bytes", strconv.Itoa(len(canonical)))
	challengeURL.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, challengeURL.String(), nil)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	carrier.authorize(request, true)
	response, err := carrier.client.Do(request)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	raw, err := readBoundedResponse(response, http.StatusCreated, 128<<10)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	var challenge commerce.SignedOperationAdmissionChallenge
	if decodeStrictJSON(raw, &challenge) != nil || challenge.Body.CarrierID != carrier.carrierID || challenge.Body.OperationKind != "operation.publish" {
		return commerce.ActionResolution{}, errors.New("outcome Carrier returned an invalid admission challenge")
	}
	proof, err := commerce.SolveOperationAdmission(challenge, 1<<25)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	carrierKey, err := decodeOutcomeCarrierKey(challenge.PublicKey)
	resourceDigest, resourceErr := commerce.AdmissionResourceVectorDigest("operation.publish", uint64(len(canonical)),
		map[string]uint64{"index_entries": 1, "retained_bytes": uint64(len(canonical))})
	if err != nil || resourceErr != nil || !bytes.Equal(carrierKey, carrier.carrierKey) || commerce.VerifyOperationAdmission(proof, carrierKey, action.AgentID,
		"operation.publish", envelope.Body.AudienceDescriptor, uint64(len(canonical)), resourceDigest, time.Now().UTC()) != nil {
		return commerce.ActionResolution{}, errors.New("outcome Carrier admission challenge is not authentic or exact")
	}
	input, err := json.Marshal(struct {
		Submission commerce.OperationCarrierSubmissionV1 `json:"submission"`
		Admission  commerce.OperationAdmissionProof      `json:"admission"`
	}{
		commerce.OperationCarrierSubmissionV1{Request: operation, AuthorizedAction: action, WriterFence: fence}, proof})
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	request, err = http.NewRequestWithContext(ctx, http.MethodPost, carrier.endpoint.String(), bytes.NewReader(input))
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	carrier.authorize(request, true)
	request.Header.Set("Content-Type", "application/json")
	response, err = carrier.client.Do(request)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	raw, err = readBoundedResponse(response, http.StatusCreated, 3<<20)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	var output struct {
		Result     OutcomeCarrierResult      `json:"result"`
		Resolution commerce.ActionResolution `json:"action_resolution"`
	}
	if decodeStrictJSON(raw, &output) != nil || validateHTTPOutcomeResult(output.Result, carrier.carrierID, carrier.carrierKey) != nil ||
		commerce.ValidateActionResolution(output.Resolution) != nil || output.Resolution.StableActionID != action.StableActionID || output.Resolution.ExactRequestDigest != action.ExactRequestDigest || output.Result.Request.OperationEnvelopeDigest != operation.OperationEnvelopeDigest ||
		output.Result.CarrierPublicKey != challenge.PublicKey || commerce.VerifyOperationSubmissionReceiptV1(output.Result.Receipt, carrierKey) != nil ||
		output.Result.Receipt.StableActionID != action.StableActionID || output.Result.Receipt.ExactRequestDigest != action.ExactRequestDigest ||
		output.Result.Receipt.SinkID != carrier.carrierID || output.Result.Receipt.SinkReference != operation.OperationEnvelopeDigest {
		return commerce.ActionResolution{}, errors.New("outcome Carrier returned an invalid publication result")
	}
	return output.Resolution, nil
}

func (carrier *HTTPOutcomeCarrier) ResolveAction(ctx context.Context, actionID, requestDigest string) (commerce.ActionResolution, error) {
	if carrier == nil || ctx == nil || !canonicalSHA256(actionID) || !canonicalSHA256(requestDigest) {
		return commerce.ActionResolution{}, errors.New("outcome action query is invalid")
	}
	endpoint := *carrier.endpoint
	endpoint.Path = "/v1/operation-actions/" + strings.TrimPrefix(actionID, "sha256:")
	query := endpoint.Query()
	query.Set("request_digest", requestDigest)
	endpoint.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	carrier.authorize(request, true)
	response, err := carrier.client.Do(request)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	raw, err := readBoundedResponse(response, http.StatusOK, 128<<10)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	var resolution commerce.ActionResolution
	if decodeStrictJSON(raw, &resolution) != nil || commerce.ValidateActionResolution(resolution) != nil || resolution.StableActionID != actionID || resolution.ExactRequestDigest != requestDigest {
		return commerce.ActionResolution{}, errors.New("outcome Carrier returned an invalid action resolution")
	}
	return resolution, nil
}

func (carrier *HTTPOutcomeCarrier) SearchOutcomes(ctx context.Context, query OutcomeCarrierQuery) (OutcomeCarrierPage, error) {
	if carrier == nil || ctx == nil || query.Limit == 0 || query.Limit > 1000 || query.Wait < 0 || query.Wait > 25*time.Second {
		return OutcomeCarrierPage{}, errors.New("outcome Carrier query is invalid")
	}
	endpoint := *carrier.endpoint
	if query.Wait > 0 {
		endpoint.Path += "/subscribe"
	}
	values := endpoint.Query()
	values.Set("limit", strconv.FormatUint(uint64(query.Limit), 10))
	if query.Cursor != "" {
		values.Set("cursor", query.Cursor)
	}
	if query.SubjectProfileURI != "" {
		values.Set("subject_profile_uri", query.SubjectProfileURI)
	}
	if query.SubjectID != "" {
		values.Set("subject_id", query.SubjectID)
	}
	if query.ActorAgentID != "" {
		values.Set("actor_agent_id", query.ActorAgentID)
	}
	for _, kind := range query.EventKinds {
		values.Add("event_kind", string(kind))
	}
	for _, profile := range query.AssertionProfileURIs {
		values.Add("assertion_profile_uri", profile)
	}
	if query.Wait > 0 {
		values.Set("wait_seconds", strconv.FormatUint(uint64(query.Wait/time.Second), 10))
	}
	endpoint.RawQuery = values.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return OutcomeCarrierPage{}, err
	}
	carrier.authorize(request, false)
	response, err := carrier.client.Do(request)
	if err != nil {
		return OutcomeCarrierPage{}, err
	}
	raw, err := readBoundedResponse(response, http.StatusOK, 4<<20)
	if err != nil {
		return OutcomeCarrierPage{}, err
	}
	var page OutcomeCarrierPage
	if decodeStrictJSON(raw, &page) != nil || page.CarrierID != carrier.carrierID || len(page.Results) > int(query.Limit) {
		return OutcomeCarrierPage{}, errors.New("outcome Carrier returned an invalid page")
	}
	for _, result := range page.Results {
		if validateHTTPOutcomeResult(result, carrier.carrierID, carrier.carrierKey) != nil {
			return OutcomeCarrierPage{}, errors.New("outcome Carrier returned invalid retained bytes")
		}
	}
	return page, nil
}

func validateHTTPOutcomeResult(result OutcomeCarrierResult, carrierID string, expectedKey ed25519.PublicKey) error {
	key, keyErr := decodeOutcomeCarrierKey(result.CarrierPublicKey)
	if keyErr != nil || !bytes.Equal(key, expectedKey) || validateOperationCarrierRequestForCurrentDependency(result.Request) != nil ||
		result.Request.CarrierID != carrierID || result.Provenance != "carrier-retained-unverified-assertion" ||
		result.ActorAgentID == "" || result.StoredAtUnix == 0 || result.CarrierSequence == 0 ||
		commerce.VerifyOperationSubmissionReceiptV1(result.Receipt, key) != nil || result.Receipt.State != commerce.ActionTerminal ||
		result.Receipt.SinkID != carrierID || result.Receipt.SinkReference != result.Request.OperationEnvelopeDigest {
		return errors.New("HTTP outcome result is invalid")
	}
	var envelope commerce.AgentOperationEnvelopeV1
	var body commerce.OperationOutcomeEventBodyV1
	if codec.Unmarshal(result.Request.OperationEnvelope, &envelope) != nil || envelope.Body.ActorAgentID != result.ActorAgentID ||
		codec.Unmarshal(result.Request.EventPayload, &body) != nil || !reflect.DeepEqual(body, result.EventBody) {
		return errors.New("HTTP outcome result derived fields do not bind retained bytes")
	}
	artifactDigest, err := codec.Digest("tos.operation-outcome.artifact-bundle.v1", result.Request.Artifacts)
	if err != nil || artifactDigest != result.Receipt.EvidenceDigest {
		return errors.New("HTTP outcome result receipt does not bind retained artifacts")
	}
	return nil
}

func decodeOutcomeCarrierKey(value string) (ed25519.PublicKey, error) {
	if !strings.HasPrefix(value, "ed25519:") {
		return nil, errors.New("Carrier key encoding is invalid")
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(value, "ed25519:"))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("Carrier key encoding is invalid")
	}
	return ed25519.PublicKey(raw), nil
}

func (carrier *HTTPOutcomeCarrier) authorize(request *http.Request, write bool) {
	token := carrier.readToken
	if write {
		token = carrier.relayToken
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/json")
}
