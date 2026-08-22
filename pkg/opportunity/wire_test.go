package opportunity

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUnixCoordinatorCarriesHintsAndIndependentVerification(t *testing.T) {
	hint, verified := testCandidate()
	coordinator := &fakeCoordinator{hints: []CandidateHint{hint}, verified: verified}
	handler, err := NewHandler(coordinator)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(t.TempDir(), "run")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(directory, "opportunity.sock")
	server, err := ListenUnix(socket, handler)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve() }()
	t.Cleanup(func() {
		shutdown, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
		if serveErr := <-done; serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			t.Errorf("serve: %v", serveErr)
		}
	})
	client, err := NewUnixClient(socket, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	request := SearchRequest{RequestID: "opp-request_" + strings.Repeat("a", 64), Query: "test",
		PageSize: 10, MaxCandidates: 10, DeadlineUnixMS: time.Now().Add(time.Minute).UnixMilli()}
	hints, err := client.Search(context.Background(), request)
	if err != nil || len(hints) != 1 || hints[0].Key != hint.Key {
		t.Fatalf("search: %+v err=%v", hints, err)
	}
	got, err := client.Verify(context.Background(), hints[0])
	if err != nil || got.Key != verified.Key || got.FinalizedCheckpoint != verified.FinalizedCheckpoint {
		t.Fatalf("verify: %+v err=%v", got, err)
	}
	if info, err := os.Lstat(socket); err != nil || info.Mode().Perm() != 0o600 || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("socket permissions: info=%v err=%v", info, err)
	}
}

func TestUnixCoordinatorPreservesTerminalRejectionClass(t *testing.T) {
	hint, _ := testCandidate()
	coordinator := &fakeCoordinator{verifyErr: &Rejection{Reason: "manifest substitution"}}
	handler, _ := NewHandler(coordinator)
	directory := filepath.Join(t.TempDir(), "run")
	_ = os.Mkdir(directory, 0o700)
	server, _ := ListenUnix(filepath.Join(directory, "opportunity.sock"), handler)
	done := make(chan error, 1)
	go func() { done <- server.Serve() }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		<-done
	}()
	client, _ := NewUnixClient(filepath.Join(directory, "opportunity.sock"), 5*time.Second)
	if _, err := client.Verify(context.Background(), hint); !errors.Is(err, ErrCoordinatorRejected) {
		t.Fatalf("rejection class lost over wire: %v", err)
	}
}

func TestCoordinatorWireRejectsUnknownFields(t *testing.T) {
	coordinator := &fakeCoordinator{}
	handler, _ := NewHandler(coordinator)
	request, _ := http.NewRequest(http.MethodPost, searchPath,
		strings.NewReader(`{"schema":"tos.openfox.opportunity-coordinator.v1","search":{},"route":"model"}`))
	request.Header.Set("Content-Type", "application/json")
	response := &responseRecorder{header: http.Header{}}
	handler.ServeHTTP(response, request)
	if response.status != http.StatusBadRequest || coordinator.searchCalls != 0 {
		t.Fatalf("unknown authority reached coordinator: status=%d calls=%d", response.status, coordinator.searchCalls)
	}
}

type responseRecorder struct {
	header http.Header
	status int
}

func (r *responseRecorder) Header() http.Header    { return r.header }
func (r *responseRecorder) WriteHeader(status int) { r.status = status }
func (r *responseRecorder) Write(value []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return len(value), nil
}
