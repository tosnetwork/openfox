package earning

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

const maxCarrierResponseBytes = 8 << 20

type HTTPCarrier struct {
	id       string
	endpoint *url.URL
	token    string
	client   *http.Client
}

func NewHTTPCarrier(carrierID, endpoint, readToken string, timeout time.Duration) (*HTTPCarrier, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed == nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "/v1/intents" ||
		carrierID == "" || strings.TrimSpace(readToken) == "" || timeout <= 0 || timeout > time.Minute {
		return nil, errors.New("HTTP Intent Carrier configuration is invalid")
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && loopbackHost(parsed.Hostname())) {
		return nil, errors.New("HTTP Intent Carrier requires HTTPS outside loopback development")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	client := &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("Intent Carrier redirects are disabled")
	}}
	return &HTTPCarrier{id: carrierID, endpoint: parsed, token: strings.TrimSpace(readToken), client: client}, nil
}

func (carrier *HTTPCarrier) ID() string {
	if carrier == nil {
		return ""
	}
	return carrier.id
}

func (carrier *HTTPCarrier) Search(ctx context.Context, query IntentQuery) ([]CarrierResult, error) {
	return carrier.search(ctx, query, 0, false)
}

func (carrier *HTTPCarrier) Subscribe(ctx context.Context, query IntentQuery, wait time.Duration) ([]CarrierResult, error) {
	if wait < 0 || wait > 25*time.Second {
		return nil, errors.New("HTTP Intent Carrier subscription wait is invalid")
	}
	return carrier.search(ctx, query, wait, true)
}

func (carrier *HTTPCarrier) search(ctx context.Context, query IntentQuery, wait time.Duration, subscribe bool) ([]CarrierResult, error) {
	if carrier == nil || ctx == nil || query.MaximumResults == 0 || query.MaximumResults > 1000 {
		return nil, errors.New("HTTP Intent Carrier query is invalid")
	}
	endpoint := *carrier.endpoint
	if subscribe {
		endpoint.Path += "/subscribe"
	}
	values := endpoint.Query()
	values.Set("limit", strconv.FormatUint(uint64(query.MaximumResults), 10))
	if subscribe {
		values.Set("wait_seconds", strconv.FormatUint(uint64(wait/time.Second), 10))
	}
	if query.Cursor != "" {
		values.Set("cursor", query.Cursor)
	}
	if query.TaxonomyPrefix != "" {
		values.Set("taxonomy_prefix", query.TaxonomyPrefix)
	}
	for _, mode := range query.Modes {
		values.Add("mode", string(mode))
	}
	for _, class := range query.SubjectClasses {
		values.Add("subject_class", string(class))
	}
	for _, keyword := range query.Keywords {
		values.Add("keyword", keyword)
	}
	endpoint.RawQuery = values.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+carrier.token)
	request.Header.Set("Accept", "application/json")
	response, err := carrier.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.CopyN(io.Discard, response.Body, 4096)
		return nil, errors.New("HTTP Intent Carrier search failed")
	}
	limited := io.LimitReader(response.Body, maxCarrierResponseBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil || len(raw) == 0 || len(raw) > maxCarrierResponseBytes {
		return nil, errors.New("HTTP Intent Carrier response is invalid or oversized")
	}
	var page struct {
		CarrierID string `json:"carrier_id"`
		Results   []struct {
			Intent             commerce.SignedAgentIntent `json:"intent"`
			IntentDigest       string                     `json:"intent_digest"`
			AuthorizationLevel string                     `json:"authorization_level"`
			StoredAtUnix       uint64                     `json:"stored_at_unix"`
			CarrierSequence    uint64                     `json:"carrier_sequence"`
		} `json:"results"`
		Operations []struct {
			Kind            string `json:"kind"`
			CarrierSequence uint64 `json:"carrier_sequence"`
			Intent          *struct {
				Intent             commerce.SignedAgentIntent `json:"intent"`
				IntentDigest       string                     `json:"intent_digest"`
				AuthorizationLevel string                     `json:"authorization_level"`
				StoredAtUnix       uint64                     `json:"stored_at_unix"`
				CarrierSequence    uint64                     `json:"carrier_sequence"`
			} `json:"intent,omitempty"`
			Withdrawal *struct {
				Withdrawal       commerce.SignedAgentIntentWithdrawal `json:"withdrawal"`
				WithdrawalDigest string                               `json:"withdrawal_digest"`
				StoredAtUnix     uint64                               `json:"stored_at_unix"`
				CarrierSequence  uint64                               `json:"carrier_sequence"`
			} `json:"withdrawal,omitempty"`
		} `json:"operations"`
		Next string `json:"next_cursor"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&page) != nil || page.CarrierID != carrier.id || len(page.Results) > int(query.MaximumResults) || len(page.Operations) > int(query.MaximumResults) {
		return nil, errors.New("HTTP Intent Carrier response conflicts with configured identity or bounds")
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, err
	}
	results := make([]CarrierResult, 0, len(page.Results)+len(page.Operations))
	if len(page.Operations) > 0 {
		for _, operation := range page.Operations {
			cursor := "seq:" + strconv.FormatUint(operation.CarrierSequence, 10)
			switch {
			case operation.Kind == "intent" && operation.Intent != nil && operation.Withdrawal == nil:
				item := operation.Intent
				digest, digestErr := commerce.IntentBodyDigest(item.Intent.Body)
				if digestErr != nil || digest != item.IntentDigest || item.StoredAtUnix == 0 || item.CarrierSequence != operation.CarrierSequence || item.AuthorizationLevel == "" {
					return nil, errors.New("HTTP Intent Carrier returned a malformed Intent operation")
				}
				results = append(results, CarrierResult{Intent: item.Intent, Cursor: cursor, CarrierID: carrier.id})
			case operation.Kind == "withdrawal" && operation.Withdrawal != nil && operation.Intent == nil:
				item := operation.Withdrawal
				digest, digestErr := commerce.IntentWithdrawalDigest(item.Withdrawal.Body)
				if digestErr != nil || digest != item.WithdrawalDigest || item.StoredAtUnix == 0 || item.CarrierSequence != operation.CarrierSequence {
					return nil, errors.New("HTTP Intent Carrier returned a malformed withdrawal operation")
				}
				withdrawal := item.Withdrawal
				results = append(results, CarrierResult{Withdrawal: &withdrawal, Cursor: cursor, CarrierID: carrier.id})
			default:
				return nil, errors.New("HTTP Intent Carrier returned an unknown or ambiguous operation")
			}
		}
	} else {
		for _, item := range page.Results {
			digest, digestErr := commerce.IntentBodyDigest(item.Intent.Body)
			if digestErr != nil || digest != item.IntentDigest || item.StoredAtUnix == 0 || item.CarrierSequence == 0 || item.AuthorizationLevel == "" {
				return nil, errors.New("HTTP Intent Carrier returned a malformed result")
			}
			results = append(results, CarrierResult{Intent: item.Intent, Cursor: "seq:" + strconv.FormatUint(item.CarrierSequence, 10), CarrierID: carrier.id})
		}
	}
	if len(results) > 0 && page.Next != "" && page.Next != results[len(results)-1].Cursor {
		return nil, errors.New("HTTP Intent Carrier returned an inconsistent cursor")
	}
	for index := 1; index < len(results); index++ {
		if compareSourceCursor(results[index].Cursor, results[index-1].Cursor) <= 0 {
			return nil, errors.New("HTTP Intent Carrier returned non-monotonic or duplicate operations")
		}
	}
	return results, nil
}

func (carrier *HTTPCarrier) Resolve(ctx context.Context, digest string) (CarrierResult, error) {
	if carrier == nil || ctx == nil || !canonicalSHA256(digest) {
		return CarrierResult{}, errors.New("HTTP Intent resolution request is invalid")
	}
	endpoint := *carrier.endpoint
	endpoint.Path += "/" + strings.TrimPrefix(digest, "sha256:")
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return CarrierResult{}, err
	}
	request.Header.Set("Authorization", "Bearer "+carrier.token)
	request.Header.Set("Accept", "application/json")
	response, err := carrier.client.Do(request)
	if err != nil {
		return CarrierResult{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.CopyN(io.Discard, response.Body, 4096)
		return CarrierResult{}, errors.New("HTTP Intent Carrier resolution failed")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, (2<<20)+1))
	if err != nil || len(raw) == 0 || len(raw) > 2<<20 {
		return CarrierResult{}, errors.New("HTTP Intent resolution is invalid or oversized")
	}
	var result struct {
		Intent             commerce.SignedAgentIntent `json:"intent"`
		IntentDigest       string                     `json:"intent_digest"`
		AuthorizationLevel string                     `json:"authorization_level"`
		StoredAtUnix       uint64                     `json:"stored_at_unix"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || ensureJSONEOF(decoder) != nil || result.IntentDigest != digest || result.StoredAtUnix == 0 || result.AuthorizationLevel == "" {
		return CarrierResult{}, errors.New("HTTP Intent resolution conflicts with requested digest")
	}
	computed, err := commerce.IntentBodyDigest(result.Intent.Body)
	if err != nil || computed != digest {
		return CarrierResult{}, errors.New("HTTP Intent resolution body digest is invalid")
	}
	return CarrierResult{Intent: result.Intent, Cursor: digest, CarrierID: carrier.id}, nil
}

func canonicalSHA256(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("HTTP Intent Carrier response has trailing JSON")
	}
	return nil
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
