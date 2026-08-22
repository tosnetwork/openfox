package opportunity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	wireSchema       = "tos.openfox.opportunity-coordinator.v1"
	searchPath       = "/v1/opportunities/search"
	verifyPath       = "/v1/opportunities/verify"
	purchasePath     = "/v1/opportunities/purchase/advance"
	maxRequestBytes  = 1 << 20
	maxResponseBytes = 8 << 20
)

type wireRequest struct {
	Schema   string           `json:"schema"`
	Search   *SearchRequest   `json:"search,omitempty"`
	Hint     *CandidateHint   `json:"hint,omitempty"`
	Purchase *PurchaseRequest `json:"purchase,omitempty"`
}

type wireResponse struct {
	Schema   string             `json:"schema"`
	OK       bool               `json:"ok"`
	Code     string             `json:"code,omitempty"`
	Detail   string             `json:"detail,omitempty"`
	Hints    []CandidateHint    `json:"hints,omitempty"`
	Verified *VerifiedCandidate `json:"verified,omitempty"`
	Progress *PurchaseProgress  `json:"purchase_progress,omitempty"`
}

type UnixClient struct {
	socket string
	client *http.Client
}

func NewUnixClient(socket string, timeout time.Duration) (*UnixClient, error) {
	if !filepath.IsAbs(socket) || filepath.Clean(socket) != socket || timeout < time.Second || timeout > time.Minute {
		return nil, errors.New("invalid opportunity coordinator client configuration")
	}
	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{Proxy: nil, DisableCompression: true, MaxIdleConns: 2, MaxIdleConnsPerHost: 2,
		IdleConnTimeout: 30 * time.Second, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socket)
		}}
	return &UnixClient{socket: socket, client: &http.Client{Transport: transport, Timeout: timeout}}, nil
}

func (c *UnixClient) Search(ctx context.Context, request SearchRequest) ([]CandidateHint, error) {
	if !validSearchRequest(request, time.Now()) {
		return nil, errors.New("invalid opportunity search request")
	}
	response, err := c.call(ctx, searchPath, wireRequest{Schema: wireSchema, Search: &request})
	if err != nil {
		return nil, err
	}
	if response.Verified != nil || response.Progress != nil || len(response.Hints) > int(request.MaxCandidates) || len(response.Hints) > int(request.PageSize) {
		return nil, errors.New("invalid opportunity search response")
	}
	for _, hint := range response.Hints {
		if !validateHint(hint) {
			return nil, errors.New("invalid opportunity hint from coordinator")
		}
	}
	return append([]CandidateHint(nil), response.Hints...), nil
}

func (c *UnixClient) Verify(ctx context.Context, hint CandidateHint) (VerifiedCandidate, error) {
	if !validateHint(hint) {
		return VerifiedCandidate{}, errors.New("invalid opportunity verification request")
	}
	response, err := c.call(ctx, verifyPath, wireRequest{Schema: wireSchema, Hint: &hint})
	if err != nil {
		return VerifiedCandidate{}, err
	}
	if response.Verified == nil || response.Progress != nil || len(response.Hints) != 0 || !validateVerified(*response.Verified) || response.Verified.Key != hint.Key {
		return VerifiedCandidate{}, errors.New("invalid verified opportunity response")
	}
	return *response.Verified, nil
}

func (c *UnixClient) AdvancePurchase(ctx context.Context, request PurchaseRequest) (PurchaseProgress, error) {
	if !validatePurchaseRequest(request) {
		return PurchaseProgress{}, errors.New("invalid opportunity purchase request")
	}
	response, err := c.call(ctx, purchasePath, wireRequest{Schema: wireSchema, Purchase: &request})
	if err != nil {
		return PurchaseProgress{}, err
	}
	if response.Progress == nil || response.Verified != nil || len(response.Hints) != 0 ||
		!validatePurchaseProgress(*response.Progress) || response.Progress.IntentID != request.IntentID ||
		response.Progress.CandidateKey != request.Candidate.Key || !validPurchaseTransition(request.Current, response.Progress.Phase) {
		return PurchaseProgress{}, errors.New("invalid opportunity purchase response")
	}
	if request.Key != nil && (response.Progress.Key == nil || *response.Progress.Key != *request.Key) {
		return PurchaseProgress{}, errors.New("opportunity purchase identity changed")
	}
	return clonePurchaseProgress(*response.Progress), nil
}

func (c *UnixClient) call(ctx context.Context, path string, value wireRequest) (wireResponse, error) {
	if c == nil || c.client == nil || ctx == nil {
		return wireResponse{}, errors.New("opportunity coordinator client is incomplete")
	}
	raw, err := json.Marshal(value)
	if err != nil || len(raw) == 0 || len(raw) > maxRequestBytes {
		return wireResponse{}, errors.New("encode opportunity coordinator request")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix"+path, bytes.NewReader(raw))
	if err != nil {
		return wireResponse{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		return wireResponse{}, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil || len(body) == 0 || len(body) > maxResponseBytes || response.Header.Get("Content-Type") != "application/json" {
		return wireResponse{}, errors.New("invalid opportunity coordinator HTTP response")
	}
	var decoded wireResponse
	if decodeStrict(body, &decoded) != nil || decoded.Schema != wireSchema {
		return wireResponse{}, errors.New("invalid opportunity coordinator response")
	}
	if response.StatusCode != http.StatusOK || !decoded.OK {
		if decoded.Code == "candidate-rejected" && boundedText(decoded.Detail, 1, 400) {
			return wireResponse{}, &Rejection{Reason: decoded.Detail}
		}
		if decoded.Code == "purchase-rejected" && boundedText(decoded.Detail, 1, 400) {
			return wireResponse{}, &PurchaseRejection{Reason: decoded.Detail}
		}
		return wireResponse{}, fmt.Errorf("opportunity coordinator failed: %s", decoded.Code)
	}
	if decoded.Code != "" || decoded.Detail != "" {
		return wireResponse{}, errors.New("successful opportunity response carries failure fields")
	}
	return decoded, nil
}

func NewHandler(coordinator Coordinator) (http.Handler, error) {
	return NewHandlerWithPurchaseRunner(coordinator, nil)
}

func NewHandlerWithPurchaseRunner(coordinator Coordinator, purchases PurchaseRunner) (http.Handler, error) {
	if coordinator == nil {
		return nil, errors.New("opportunity coordinator handler needs an implementation")
	}
	mux := http.NewServeMux()
	mux.HandleFunc(searchPath, func(writer http.ResponseWriter, request *http.Request) {
		serveCoordinator(coordinator, true, writer, request)
	})
	mux.HandleFunc(verifyPath, func(writer http.ResponseWriter, request *http.Request) {
		serveCoordinator(coordinator, false, writer, request)
	})
	if purchases != nil {
		mux.HandleFunc(purchasePath, func(writer http.ResponseWriter, request *http.Request) {
			servePurchase(purchases, writer, request)
		})
	}
	return mux, nil
}

func serveCoordinator(coordinator Coordinator, search bool, writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || request.URL.RawQuery != "" || request.Header.Get("Content-Type") != "application/json" {
		writeWire(writer, http.StatusBadRequest, wireResponse{Schema: wireSchema, Code: "invalid-request", Detail: "invalid request envelope"})
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maxRequestBytes)
	raw, err := io.ReadAll(request.Body)
	if err != nil {
		writeWire(writer, http.StatusBadRequest, wireResponse{Schema: wireSchema, Code: "invalid-request", Detail: "invalid request body"})
		return
	}
	var value wireRequest
	if decodeStrict(raw, &value) != nil || value.Schema != wireSchema || value.Purchase != nil || (value.Search == nil) == (value.Hint == nil) {
		writeWire(writer, http.StatusBadRequest, wireResponse{Schema: wireSchema, Code: "invalid-request", Detail: "invalid request body"})
		return
	}
	if search {
		if value.Hint != nil || !validSearchRequest(*value.Search, time.Now()) {
			writeWire(writer, http.StatusBadRequest, wireResponse{Schema: wireSchema, Code: "invalid-request", Detail: "invalid search"})
			return
		}
		hints, err := coordinator.Search(request.Context(), *value.Search)
		if err != nil || len(hints) > int(value.Search.MaxCandidates) || len(hints) > int(value.Search.PageSize) {
			writeWire(writer, http.StatusServiceUnavailable, wireFailure(err))
			return
		}
		for _, hint := range hints {
			if !validateHint(hint) {
				writeWire(writer, http.StatusServiceUnavailable, wireFailure(errors.New("coordinator produced invalid hint")))
				return
			}
		}
		writeWire(writer, http.StatusOK, wireResponse{Schema: wireSchema, OK: true, Hints: hints})
		return
	}
	if value.Search != nil || !validateHint(*value.Hint) {
		writeWire(writer, http.StatusBadRequest, wireResponse{Schema: wireSchema, Code: "invalid-request", Detail: "invalid candidate"})
		return
	}
	verified, err := coordinator.Verify(request.Context(), *value.Hint)
	if err != nil {
		status := http.StatusServiceUnavailable
		if errors.Is(err, ErrCoordinatorRejected) {
			status = http.StatusUnprocessableEntity
		}
		writeWire(writer, status, wireFailure(err))
		return
	}
	if !validateVerified(verified) || verified.Key != value.Hint.Key {
		writeWire(writer, http.StatusServiceUnavailable, wireFailure(errors.New("coordinator produced invalid verified candidate")))
		return
	}
	writeWire(writer, http.StatusOK, wireResponse{Schema: wireSchema, OK: true, Verified: &verified})
}

func servePurchase(purchases PurchaseRunner, writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || request.URL.RawQuery != "" || request.Header.Get("Content-Type") != "application/json" {
		writeWire(writer, http.StatusBadRequest, wireResponse{Schema: wireSchema, Code: "invalid-request", Detail: "invalid request envelope"})
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maxRequestBytes)
	raw, err := io.ReadAll(request.Body)
	if err != nil {
		writeWire(writer, http.StatusBadRequest, wireResponse{Schema: wireSchema, Code: "invalid-request", Detail: "invalid request body"})
		return
	}
	var value wireRequest
	if decodeStrict(raw, &value) != nil || value.Schema != wireSchema || value.Search != nil || value.Hint != nil ||
		value.Purchase == nil || !validatePurchaseRequest(*value.Purchase) {
		writeWire(writer, http.StatusBadRequest, wireResponse{Schema: wireSchema, Code: "invalid-request", Detail: "invalid purchase"})
		return
	}
	progress, err := purchases.AdvancePurchase(request.Context(), *value.Purchase)
	if err != nil {
		status := http.StatusServiceUnavailable
		if errors.Is(err, ErrPurchaseRejected) {
			status = http.StatusUnprocessableEntity
		}
		writeWire(writer, status, wireFailure(err))
		return
	}
	if !validatePurchaseProgress(progress) || progress.IntentID != value.Purchase.IntentID ||
		progress.CandidateKey != value.Purchase.Candidate.Key || !validPurchaseTransition(value.Purchase.Current, progress.Phase) ||
		(value.Purchase.Key != nil && (progress.Key == nil || *progress.Key != *value.Purchase.Key)) {
		writeWire(writer, http.StatusServiceUnavailable, wireFailure(errors.New("purchase runner produced invalid progress")))
		return
	}
	writeWire(writer, http.StatusOK, wireResponse{Schema: wireSchema, OK: true, Progress: &progress})
}

func wireFailure(err error) wireResponse {
	if errors.Is(err, ErrPurchaseRejected) {
		detail := "purchase rejected before funding"
		var rejection *PurchaseRejection
		if errors.As(err, &rejection) && boundedText(rejection.Reason, 1, 400) {
			detail = rejection.Reason
		}
		return wireResponse{Schema: wireSchema, Code: "purchase-rejected", Detail: detail}
	}
	if errors.Is(err, ErrCoordinatorRejected) {
		detail := "candidate failed finalized verification"
		var rejection *Rejection
		if errors.As(err, &rejection) && boundedText(rejection.Reason, 1, 400) {
			detail = rejection.Reason
		}
		return wireResponse{Schema: wireSchema, Code: "candidate-rejected", Detail: detail}
	}
	return wireResponse{Schema: wireSchema, Code: "temporarily-unavailable", Detail: "coordinator unavailable"}
}

func validatePurchaseRequest(request PurchaseRequest) bool {
	if !regexpIntent(request.IntentID) || !validateVerified(request.Candidate) {
		return false
	}
	switch request.Current {
	case PhaseQuoteRequested, PhaseQuoteVerified, PhasePolicyAuthorized:
		return request.Key == nil
	case PhasePurchaseReferenced:
		return request.Key != nil && validatePurchaseKey(*request.Key)
	default:
		return false
	}
}

func writeWire(writer http.ResponseWriter, status int, response wireResponse) {
	response.OK = status == http.StatusOK
	raw, _ := json.Marshal(response)
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = writer.Write(raw)
}

func validSearchRequest(request SearchRequest, now time.Time) bool {
	return requestPattern.MatchString(request.RequestID) && boundedText(request.Query, 1, 256) && request.PageSize > 0 &&
		request.PageSize <= 100 && request.MaxCandidates > 0 && request.MaxCandidates <= 1000 &&
		request.MaxCandidates >= request.PageSize && request.DeadlineUnixMS > now.UnixMilli() &&
		request.DeadlineUnixMS <= now.Add(time.Minute).UnixMilli()
}

func decodeStrict(raw []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

type UnixServer struct {
	server   *http.Server
	listener net.Listener
	path     string
	once     sync.Once
}

func ListenUnix(path string, handler http.Handler) (*UnixServer, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || handler == nil {
		return nil, errors.New("invalid opportunity coordinator listener")
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || parent.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("opportunity coordinator socket directory must be owner-private")
	}
	if info, statErr := os.Lstat(path); statErr == nil {
		if info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("opportunity coordinator path is occupied")
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return nil, statErr
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, err
	}
	return &UnixServer{server: &http.Server{Handler: handler, ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout: time.Minute, WriteTimeout: time.Minute, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10},
		listener: listener, path: path}, nil
}

func (s *UnixServer) Serve() error {
	if s == nil || s.server == nil || s.listener == nil {
		return errors.New("invalid opportunity coordinator server")
	}
	return s.server.Serve(s.listener)
}

func (s *UnixServer) Shutdown(ctx context.Context) error {
	if s == nil || ctx == nil {
		return errors.New("invalid opportunity coordinator shutdown")
	}
	var combined error
	s.once.Do(func() {
		combined = s.server.Shutdown(ctx)
		if err := s.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			combined = errors.Join(combined, err)
		}
		if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			combined = errors.Join(combined, err)
		}
	})
	return combined
}
