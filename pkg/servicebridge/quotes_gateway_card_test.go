package servicebridge

import (
	"context"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/gen/tos/service/v1/tosservicev1connect"
	"github.com/tosnetwork/ai/protocol/pkg/buyersdk"
	"github.com/tosnetwork/ai/protocol/pkg/nativeclient"
)

// cardDiscovery is an in-process gateway discovery service that answers
// every Quote request with one package and one provider key card.
type cardDiscovery struct {
	tosservicev1connect.UnimplementedCapabilityDiscoveryServiceHandler

	mu   sync.Mutex
	pkg  *nativev1.QuoteProposalPackageV1
	card []byte
}

func (c *cardDiscovery) RequestQuoteProposal(
	_ context.Context,
	_ *connect.Request[nativev1.RequestQuoteProposalRequest],
) (*connect.Response[nativev1.RequestQuoteProposalResponse], error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return connect.NewResponse(&nativev1.RequestQuoteProposalResponse{
		Package: c.pkg, ProviderKeyCardPacketJson: c.card,
	}), nil
}

func newCardGateway(t *testing.T, pkg *nativev1.QuoteProposalPackageV1, card []byte) *nativeclient.Client {
	t.Helper()
	mux := http.NewServeMux()
	path, handler := tosservicev1connect.NewCapabilityDiscoveryServiceHandler(&cardDiscovery{pkg: pkg, card: card})
	mux.Handle(path, handler)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	client, err := nativeclient.New(nativeclient.Config{BaseURL: server.URL, BearerToken: "test-token", Insecure: true})
	if err != nil {
		t.Fatalf("native client: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// relayQuotePackage is a package for the relay tests' Capability whose
// proposal names provider. GatewayQuotes does not validate packages; the
// buyer does, after the Quote.
func relayQuotePackage(provider string) *nativev1.QuoteProposalPackageV1 {
	return &nativev1.QuoteProposalPackageV1{Proposal: &nativev1.QuoteProposalV1{
		CapabilityId: relayCapability, CapabilityVersion: "1.0.0", ProviderAgentId: provider,
	}}
}

func relayQuoteRequest() *nativev1.RequestQuoteProposalRequest {
	return &nativev1.RequestQuoteProposalRequest{CapabilityId: relayCapability, CapabilityVersion: "1.0.0"}
}

// A first purchase quoted by a gateway reaches a provider that receives only
// through a relay: the card served next to the Quote is verified, learned,
// and the task is sealed to it.
func TestAVerifiedQuoteCarriedCardIsLearnedAndUsedForSealing(t *testing.T) {
	clock := newRelayClock()
	agents := relayAgents()
	relay := startFakeRelay(t, clock)
	buyer := newRelayTestNode(t, clock, testBuyer, agents, relay)
	seller := newRelayTestNode(t, clock, testSeller, agents, relay)
	routes := RoutedTransport{Relay: buyer.carrier.Transport}
	if routes.Route(testSeller) != RouteNone {
		t.Fatal("the buyer could already reach the provider; the test exercises nothing")
	}
	var reports []string
	source := GatewayQuotes{
		Client: newCardGateway(t, relayQuotePackage(testSeller), seller.card()), CallerID: "buyer-test",
		Cards: buyer.cards, Report: func(stage string, err error) { reports = append(reports, stage+": "+err.Error()) },
	}
	pkg, err := source.Quote(context.Background(), relayQuoteRequest())
	if err != nil || pkg.GetProposal().GetProviderAgentId() != testSeller {
		t.Fatalf("Quote: %v", err)
	}
	if len(reports) != 0 {
		t.Fatalf("the verified card was reported as discarded: %v", reports)
	}
	if routes.Route(testSeller) != RouteRelay {
		t.Fatal("the verified Quote-carried card was not learned")
	}
	if _, err = buyer.courier.Deliver(context.Background(), relayEnvelopeTo(testSeller), markedBody(10)); err != nil {
		t.Fatalf("the task could not be sealed to the learned card: %v", err)
	}
	seller.pollAll()
	if len(seller.pending()) != 1 {
		t.Fatal("the provider did not receive the task sealed to its Quote-carried card")
	}
}

// The red control of the verification: every card here has the shape of a
// key card, and only its verification against finalized state (the signing
// controller, the validity window, the Capability's finalized owner) keeps
// it out. Learning a card without that verification fails this test.
func TestAQuoteCarriedCardThatDoesNotVerifyIsIgnored(t *testing.T) {
	cases := map[string]func(t *testing.T, clock *relayClock, agents *switchableAgents, relay *fakeRelay) (string, []byte){
		"a card of another Agent than the proposal's provider": func(t *testing.T, clock *relayClock,
			agents *switchableAgents, relay *fakeRelay) (string, []byte) {
			return testSeller, newRelayTestNode(t, clock, relayThird, agents, relay).card()
		},
		"a card of an Agent that is not the Capability's finalized owner": func(t *testing.T, clock *relayClock,
			agents *switchableAgents, relay *fakeRelay) (string, []byte) {
			// The proposal and the card agree; finalized state names
			// another owner.
			return relayThird, newRelayTestNode(t, clock, relayThird, agents, relay).card()
		},
		"a stale card": func(t *testing.T, clock *relayClock, agents *switchableAgents, relay *fakeRelay) (string, []byte) {
			card := newRelayTestNode(t, clock, testSeller, agents, relay).card()
			clock.Advance(RelayKeyLifetime + time.Hour)
			return testSeller, card
		},
		"a card whose signing controller left the Agent's finalized policy": func(t *testing.T, clock *relayClock,
			agents *switchableAgents, relay *fakeRelay) (string, []byte) {
			card := newRelayTestNode(t, clock, testSeller, agents, relay).card()
			agents.revoke(testSeller)
			return testSeller, card
		},
		"a malformed card": func(*testing.T, *relayClock, *switchableAgents, *fakeRelay) (string, []byte) {
			return testSeller, []byte(`{"not":"a packet"}`)
		},
		"an oversized card": func(*testing.T, *relayClock, *switchableAgents, *fakeRelay) (string, []byte) {
			return testSeller, []byte(strings.Repeat(" ", maxCardJSON+1))
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			clock := newRelayClock()
			agents := relayAgents()
			relay := startFakeRelay(t, clock)
			buyer := newRelayTestNode(t, clock, testBuyer, agents, relay)
			provider, card := build(t, clock, agents, relay)
			var reports []string
			source := GatewayQuotes{
				Client: newCardGateway(t, relayQuotePackage(provider), card), CallerID: "buyer-test",
				Cards: buyer.cards, Report: func(stage string, err error) {
					reports = append(reports, stage+": "+err.Error())
				},
			}
			pkg, err := source.Quote(context.Background(), relayQuoteRequest())
			if err != nil || pkg == nil {
				t.Fatalf("a discarded card invalidated the Quote: %v", err)
			}
			for _, agent := range []string{testSeller, relayThird} {
				if buyer.cards.Has(agent) {
					t.Fatalf("the card was learned for %s", agent)
				}
			}
			if len(reports) != 1 || !strings.HasPrefix(reports[0], "buyer.quote_card: ") {
				t.Fatalf("the discarded card was not reported once: %v", reports)
			}
		})
	}
}

// Without a card the buyer could seal to, a gateway-quoted purchase from a
// provider that is neither a direct peer nor reachable through a Messenger
// is refused before anything is prepared or paid.
func TestABuyerWithoutARouteToTheProviderRefusesToPay(t *testing.T) {
	f, offer, _ := publishedOffer(t)
	world := f.world()
	now := func() time.Time { return time.Unix(loadWorld(f.worldPath).Clock, 0) }
	// The gateway serves the real package with a card that does not verify.
	pkg, err := offerQuotes(f, offer).Quote(context.Background(), offerRequest(offer))
	if err != nil {
		t.Fatal(err)
	}
	clock := newRelayClock()
	relayNode := newRelayTestNode(t, clock, testBuyer, relayAgents(), startFakeRelay(t, clock))
	var reports []string
	manifests := &MemoryManifests{}
	quotes := &PackageQuotes{manifests: manifests, next: GatewayQuotes{
		Client: newCardGateway(t, pkg, []byte(`{"not":"a packet"}`)), CallerID: "buyer-test",
		Cards: relayNode.cards, Report: func(stage string, err error) { reports = append(reports, stage) },
	}}
	if err = ensurePrivateDirectory(filepath.Join(f.root, "calls")); err != nil {
		t.Fatal(err)
	}
	journal, err := buyersdk.OpenServiceActorJournal(filepath.Join(f.root, "calls"), now())
	if err != nil {
		t.Fatal(err)
	}
	sender := &recordingSender{}
	sdk, err := buyersdk.NewServiceActorBuyer(buyersdk.ServiceActorBuyerConfig{
		Reader: offerSessions{path: f.worldPath}, Manifests: manifests, Network: world.network(),
		ActorCodeHash: fakeCodeHashActor, BuyerWallet: testWallet, Sender: sender, Journal: journal,
		Limits: buyersdk.ServiceActorLimits{
			Window: time.Hour, MaxCalls: 4, MaxPerCallNanoTOS: big.NewInt(2_000_000_000),
			MaxWindowNanoTOS: big.NewInt(10_000_000_000),
		},
		Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	// The relays are the only route: no direct peer, no Messenger.
	courier, err := OpenCourier(filepath.Join(f.root, "outbox"), testSigner(t, testBuyer),
		RoutedTransport{Relay: relayNode.carrier.Transport})
	if err != nil {
		t.Fatal(err)
	}
	disclosed := 0
	buyer, err := NewBuyer(BuyerConfig{
		AgentID: testBuyer, Wallet: testWallet, Network: world.network(), Buyer: sdk, Quotes: quotes,
		Policy: SpendingPolicy{
			MaxCommittedPerPurchase: big.NewInt(2_000_000_000), MaxCommittedInWindow: big.NewInt(10_000_000_000),
			Window: time.Hour, MaxOpenPurchases: 4, RefundReserve: big.NewInt(300_000_000),
			AllowedProviders: map[string]bool{offer.ProviderAgentID: true},
		},
		Disclose: func(Costs) { disclosed++ },
		Courier:  courier, Lifecycle: idleLifecycle{}, Directory: filepath.Join(f.root, "purchases"), Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = buyer.Buy(context.Background(), offer.CapabilityID, offer.Version, []byte("a source archive"))
	if !errors.Is(err, ErrProviderUnreachable) {
		t.Fatalf("a purchase with no route to the provider was not refused for it: %v", err)
	}
	if len(reports) != 1 {
		t.Fatalf("the discarded card was not reported: %v", reports)
	}
	if len(sender.calls) != 0 || disclosed != 0 {
		t.Fatalf("the refused purchase went on: %d calls, %d disclosures", len(sender.calls), disclosed)
	}
	records, err := buyer.Purchases()
	if err != nil || len(records) != 0 {
		t.Fatalf("the refused purchase left records: %d, %v", len(records), err)
	}
	if calls, listErr := journal.Records(); listErr != nil || len(calls) != 0 {
		t.Fatalf("the refused purchase was prepared: %d calls, %v", len(calls), listErr)
	}
}
