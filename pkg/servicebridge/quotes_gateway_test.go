package servicebridge

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/gen/tos/service/v1/tosservicev1connect"
	"github.com/tosnetwork/ai/protocol/pkg/nativeclient"
)

// recordingDiscovery is an in-process gateway discovery service that keeps
// the RequestQuoteProposal request it received.
type recordingDiscovery struct {
	tosservicev1connect.UnimplementedCapabilityDiscoveryServiceHandler

	mu       sync.Mutex
	received *nativev1.RequestQuoteProposalRequest
}

func (r *recordingDiscovery) RequestQuoteProposal(
	_ context.Context,
	request *connect.Request[nativev1.RequestQuoteProposalRequest],
) (*connect.Response[nativev1.RequestQuoteProposalResponse], error) {
	r.mu.Lock()
	r.received = request.Msg
	r.mu.Unlock()
	return connect.NewResponse(&nativev1.RequestQuoteProposalResponse{
		Package: &nativev1.QuoteProposalPackageV1{},
	}), nil
}

func (r *recordingDiscovery) last() *nativev1.RequestQuoteProposalRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.received
}

func newRecordingGateway(t *testing.T) (*recordingDiscovery, *nativeclient.Client) {
	t.Helper()
	discovery := &recordingDiscovery{}
	mux := http.NewServeMux()
	path, handler := tosservicev1connect.NewCapabilityDiscoveryServiceHandler(discovery)
	mux.Handle(path, handler)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	client, err := nativeclient.New(nativeclient.Config{
		BaseURL: server.URL, BearerToken: "test-token", Insecure: true,
	})
	if err != nil {
		t.Fatalf("native client: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return discovery, client
}

// A gateway refuses a discovery request whose context carries no future
// deadline, or one more than 15 minutes ahead. This drives the real Quote
// path end to end and checks the request the gateway actually receives.
func TestGatewayQuotesSendsABoundedFutureDeadline(t *testing.T) {
	discovery, client := newRecordingGateway(t)
	source := GatewayQuotes{Client: client, CallerID: "buyer-test"}
	before := time.Now()
	pkg, err := source.Quote(context.Background(), &nativev1.RequestQuoteProposalRequest{
		CapabilityId: "capability-1", CapabilityVersion: "1",
	})
	if err != nil {
		t.Fatalf("Quote: %v", err)
	}
	if pkg == nil {
		t.Fatal("Quote returned no package")
	}
	received := discovery.last()
	if received == nil || received.GetContext() == nil {
		t.Fatal("the gateway received no request context")
	}
	deadline := time.UnixMilli(received.GetContext().GetDeadlineUnixMillis())
	if !deadline.After(before) {
		t.Fatalf("received deadline %v is not in the future (sent at %v); a gateway refuses it as expired",
			received.GetContext().GetDeadlineUnixMillis(), before.UnixMilli())
	}
	if deadline.Sub(before) > 15*time.Minute {
		t.Fatalf("received deadline is %v ahead; a gateway refuses more than 15 minutes", deadline.Sub(before))
	}
	if got := received.GetContext().GetCallerId(); got != "buyer-test" {
		t.Fatalf("caller id %q, want buyer-test", got)
	}
	if got := received.GetContext().GetRequestId(); got != "capability-1/1" {
		t.Fatalf("request id %q, want capability-1/1", got)
	}
}

// A caller deadline sooner than the default bound is the one the gateway
// receives.
func TestGatewayQuotesSendsTheCallersSoonerDeadline(t *testing.T) {
	discovery, client := newRecordingGateway(t)
	source := GatewayQuotes{Client: client, CallerID: "buyer-test"}
	sooner := time.Now().Add(20 * time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), sooner)
	defer cancel()
	if _, err := source.Quote(ctx, &nativev1.RequestQuoteProposalRequest{
		CapabilityId: "capability-1", CapabilityVersion: "1",
	}); err != nil {
		t.Fatalf("Quote: %v", err)
	}
	received := discovery.last()
	if received == nil || received.GetContext() == nil {
		t.Fatal("the gateway received no request context")
	}
	if got := received.GetContext().GetDeadlineUnixMillis(); got != sooner.UnixMilli() {
		t.Fatalf("received deadline %d, want the caller's sooner deadline %d", got, sooner.UnixMilli())
	}
}
