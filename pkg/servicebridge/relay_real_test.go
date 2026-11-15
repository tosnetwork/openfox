package servicebridge

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketrelay"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
)

// startRealRelay runs the reference relay server with an in-memory store
// on loopback, on the test's clock.
func startRealRelay(t *testing.T, clock *relayClock) string {
	t.Helper()
	store, err := agentpacketrelay.NewMemoryStore(agentpacketrelay.DefaultLimits(4096, 64<<20))
	if err != nil {
		t.Fatal(err)
	}
	server, err := agentpacketrelay.NewServer(agentpacketrelay.ServerConfig{Store: store, Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	listener := httptest.NewServer(server)
	t.Cleanup(listener.Close)
	return listener.URL
}

// realRelays returns two reference relays as fake-relay handles for the
// node helper, which needs only their URLs.
func realRelays(t *testing.T, clock *relayClock) (*fakeRelay, *fakeRelay) {
	a, b := &fakeRelay{URL: startRealRelay(t, clock)}, &fakeRelay{URL: startRealRelay(t, clock)}
	if a.URL > b.URL {
		a, b = b, a
	}
	return a, b
}

func listed(t *testing.T, relay, agent string) []agentpacketrelay.MailboxEntry {
	t.Helper()
	client, err := agentpacketrelay.NewClient(agentpacketrelay.ClientConfig{BaseURL: relay})
	if err != nil {
		t.Fatal(err)
	}
	mailbox, err := client.List(context.Background(), agent)
	if err != nil {
		t.Fatal(err)
	}
	return mailbox.Envelopes
}

func TestARelayedSaleMessageCrossesTheReferenceRelayServer(t *testing.T) {
	clock := newRelayClock()
	agents := relayAgents()
	relayA, relayB := realRelays(t, clock)
	seller := newRelayTestNode(t, clock, testSeller, agents, relayA)
	buyer := newRelayTestNode(t, clock, testBuyer, agents, relayA, relayB)
	seller.learn(buyer)
	body := markedBody(MaxChunkData + 300)
	if _, err := seller.courier.Deliver(context.Background(), relayEnvelopeTo(testBuyer), body); err != nil {
		t.Fatal(err)
	}
	if err := seller.carrier.Transport.Redeposit(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(listed(t, relayA.URL, testBuyer)) != 2 || len(listed(t, relayB.URL, testBuyer)) != 2 {
		t.Fatal("the envelopes are not held at both relays")
	}
	buyer.pollAll()
	if pending := buyer.pending(); len(pending) != 1 || !bytes.Equal(pending[0].Body, body) {
		t.Fatalf("pending = %d", len(pending))
	}
	if len(listed(t, relayA.URL, testBuyer)) != 0 || len(listed(t, relayB.URL, testBuyer)) != 0 {
		t.Fatal("the envelopes were not acknowledged at both relays")
	}
	// A resend of an acknowledged envelope is a durable acceptance (410).
	journal, err := filepath.Glob(filepath.Join(seller.dir, relayStateDir, relayOutboxDir, "*.json"))
	if err != nil || len(journal) == 0 {
		t.Fatalf("no journaled envelope: %v", err)
	}
	record, found, err := seller.carrier.Transport.load(journal[0])
	if err != nil || !found {
		t.Fatalf("journal record: %v", err)
	}
	envelope, err := base64.StdEncoding.DecodeString(record.EnvelopeBase64)
	if err != nil {
		t.Fatal(err)
	}
	client, err := agentpacketrelay.NewClient(agentpacketrelay.ClientConfig{BaseURL: relayA.URL})
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := client.Deposit(context.Background(), envelope)
	if err != nil || outcome.Result != agentpacketrelay.DepositAcknowledged || !outcome.Accepted() {
		t.Fatalf("a resend after acknowledgement: %v %v", outcome.Result, err)
	}
}

func TestTheReferenceRelayRaceOfAJunkCopyDoesNotSuppressTheGenuineEnvelope(t *testing.T) {
	clock := newRelayClock()
	agents := relayAgents()
	relayA, relayB := realRelays(t, clock)
	seller := newRelayTestNode(t, clock, testSeller, agents, relayA)
	buyer := newRelayTestNode(t, clock, testBuyer, agents, relayA, relayB)
	seller.learn(buyer)
	body := markedBody(50)
	if _, err := seller.courier.Deliver(context.Background(), relayEnvelopeTo(testBuyer), body); err != nil {
		t.Fatal(err)
	}
	// An observer lists relay A, takes the public id, and deposits junk
	// under it at relay B first.
	entries := listed(t, relayA.URL, testBuyer)
	if len(entries) != 1 {
		t.Fatalf("relay A lists %d envelopes", len(entries))
	}
	genuine := downloadFrom(t, relayA.URL, testBuyer, entries[0].EnvelopeID)
	junk := append([]byte(nil), genuine...)
	junk[len(junk)-1] ^= 0xff
	observer, err := agentpacketrelay.NewClient(agentpacketrelay.ClientConfig{BaseURL: relayB.URL})
	if err != nil {
		t.Fatal(err)
	}
	if outcome, depositErr := observer.Deposit(context.Background(), junk); depositErr != nil || !outcome.Accepted() {
		t.Fatalf("the junk deposit: %v %v", outcome.Result, depositErr)
	}
	if err = seller.carrier.Transport.Redeposit(context.Background()); err != nil {
		t.Fatal(err)
	}
	views, err := ReadRelayOutbox(filepath.Join(seller.dir, relayStateDir, relayOutboxDir))
	if err != nil || len(views) != 1 || len(views[0].Conflicts) != 1 || views[0].Conflicts[0] != relayB.URL {
		t.Fatalf("the relay answering 409 was not abandoned: %+v %v", views, err)
	}
	buyer.pollOne(relayB)
	buyer.pollOne(relayA)
	if pending := buyer.pending(); len(pending) != 1 || !bytes.Equal(pending[0].Body, body) {
		t.Fatalf("the genuine envelope was suppressed: %d", len(pending))
	}
	buyer.pollOne(relayB)
	if len(listed(t, relayA.URL, testBuyer)) != 0 || len(listed(t, relayB.URL, testBuyer)) != 0 {
		t.Fatal("the settled id was not acknowledged at both relays")
	}
}

func downloadFrom(t *testing.T, relay, agent string, id [32]byte) []byte {
	t.Helper()
	client, err := agentpacketrelay.NewClient(agentpacketrelay.ClientConfig{BaseURL: relay})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := client.Download(context.Background(), agent, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := agentpacketseal.ParseEnvelope(raw); err != nil {
		t.Fatal(err)
	}
	return raw
}
