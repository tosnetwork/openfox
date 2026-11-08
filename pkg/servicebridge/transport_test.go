package servicebridge

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentpacket"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44/mldsa44test"
)

// packetKeys stands in for the ML-DSA-44 helper; it is not ML-DSA-44.
var packetKeys = &mldsa44test.Fake{}

type recordingTransport struct {
	mutex   sync.Mutex
	sent    []OutboundPacket
	failAll bool
}

func (r *recordingTransport) Send(_ context.Context, packet OutboundPacket) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.sent = append(r.sent, packet)
	if r.failAll {
		return errors.New("connection lost: outcome unknown")
	}
	return nil
}

func (r *recordingTransport) packets() []OutboundPacket {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return append([]OutboundPacket(nil), r.sent...)
}

func testSigner(t *testing.T, agent string) *PacketSigner {
	t.Helper()
	signer, err := NewPacketSigner(packetKeys, agent, packetKeys.KeyID(agent), agent)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func testEnvelope() Envelope {
	return Envelope{
		RecipientAgentID: testBuyer, CapabilityID: "cap_" + strings.Repeat("33", 32),
		QuoteCommitment: "tvm-cell-sha256:" + strings.Repeat("aa", 32), Kind: FrameResult, ActorAccount: testActor,
		RequestID: 3, RequestHash: testRequest,
	}
}

func TestCourierRetriesAnAmbiguousSendWithTheSameBytesKeyAndExpiry(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "outbox")
	transport := &recordingTransport{failAll: true}
	courier, err := OpenCourier(directory, testSigner(t, testSeller), transport)
	if err != nil {
		t.Fatal(err)
	}
	body := fill(MaxChunkData+10, 4)
	if _, err = courier.Deliver(context.Background(), testEnvelope(), body); err == nil {
		t.Fatal("an ambiguous send was reported accepted")
	}
	first := transport.packets()
	if len(first) != 1 {
		t.Fatalf("sent %d packets before the failure", len(first))
	}
	// A restart: a new courier over the same directory and a working carrier.
	working := &recordingTransport{}
	restarted, err := OpenCourier(directory, testSigner(t, testSeller), working)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Resume(context.Background()); err != nil {
		t.Fatal(err)
	}
	resent := working.packets()
	if len(resent) != 2 || !bytes.Equal(resent[0].JSON, first[0].JSON) ||
		resent[0].IdempotencyKey != first[0].IdempotencyKey ||
		resent[0].ExpiresAtUnix != first[0].ExpiresAtUnix {
		t.Fatalf("the retry changed the packet identity: %d packets", len(resent))
	}
	if err := restarted.Resume(context.Background()); err != nil || len(working.packets()) != 2 {
		t.Fatalf("an accepted packet was sent again: %d %v", len(working.packets()), err)
	}
}

func TestCourierRedeliversInAFreshGenerationAndRetiresAnExpiredOne(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "outbox")
	transport := &recordingTransport{failAll: true}
	courier, err := OpenCourier(directory, testSigner(t, testSeller), transport)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(2_000_000_000, 0)
	courier.now = func() time.Time { return now }
	envelope := testEnvelope()
	if _, err := courier.Deliver(context.Background(), envelope, fill(100, 1)); err == nil {
		t.Fatal("ambiguous send accepted")
	}
	// The journaled attempt expires before the carrier comes back.
	now = now.Add(PacketLifetime + time.Second)
	transport.failAll = false
	if err := courier.Resume(context.Background()); !errors.Is(err, ErrGenerationExpired) {
		t.Fatalf("an expired attempt was retried: %v", err)
	}
	before := len(transport.packets())
	if err := courier.Resume(context.Background()); err != nil || len(transport.packets()) != before {
		t.Fatalf("a retired generation was retried: %v", err)
	}
	if _, err := courier.Deliver(context.Background(), envelope, fill(100, 1)); err != nil {
		t.Fatal(err)
	}
	sent := transport.packets()
	last, previous := sent[len(sent)-1], sent[0]
	if bytes.Equal(last.JSON, previous.JSON) || last.IdempotencyKey == previous.IdempotencyKey {
		t.Fatal("a fresh generation reused the old packet")
	}
	if generations, err := courier.Generations(envelope); err != nil || generations != 2 {
		t.Fatalf("generations = %d %v", generations, err)
	}
	envelope.NotAfterUnix = uint64(now.Unix())
	if _, err := courier.Deliver(context.Background(), envelope, fill(100, 1)); err == nil {
		t.Fatal("a message past its deadline was delivered")
	}
}

func TestEveryFramePacketFitsTheMessengerDirectApplicationBound(t *testing.T) {
	transport := &recordingTransport{}
	courier, err := OpenCourier(filepath.Join(t.TempDir(), "outbox"), testSigner(t, testSeller), transport)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := courier.Deliver(context.Background(), testEnvelope(), fill(maxResultMessageBytes, 2)); err != nil {
		t.Fatal(err)
	}
	for _, packet := range transport.packets() {
		if len(packet.JSON) > 96<<10 {
			t.Fatalf("a %d-byte packet exceeds the direct application bound", len(packet.JSON))
		}
	}
}

type agentMap map[string]*nativev1.AgentStateV1

func (m agentMap) ResolveAgent(id string) (*nativev1.AgentStateV1, bool, error) {
	state, ok := m[id]
	return state, ok, nil
}

func agentState(id string) *nativev1.AgentStateV1 {
	return &nativev1.AgentStateV1{AgentId: id, Policy: &nativev1.ControllerPolicyV1{
		Threshold: 1, RecoveryThreshold: 1,
		Controllers: []*nativev1.ControllerV1{{
			KeyId: packetKeys.KeyID(id), Mldsa44PublicKey: packetKeys.PublicKey(id),
			Weight: 1, PurposeMask: 15, Recovery: true,
		}},
	}}
}

func TestReceiverStoresVerifiedFramesAndRefusesEverythingElse(t *testing.T) {
	transport := &recordingTransport{}
	courier, err := OpenCourier(filepath.Join(t.TempDir(), "outbox"), testSigner(t, testSeller), transport)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = courier.Deliver(context.Background(), testEnvelope(), fill(MaxChunkData+3, 8)); err != nil {
		t.Fatal(err)
	}
	inbox, _ := openTestInbox(t, 4, 8)
	var notified []InboxStatus
	receiver := &Receiver{
		LocalAgentID: testBuyer,
		Resolver:     agentMap{testBuyer: agentState(testBuyer), testSeller: agentState(testSeller)},
		Verifier:     packetKeys,
		Inbox:        inbox,
		Notify:       func(status InboxStatus, _ Message) { notified = append(notified, status) },
	}
	post := func(body []byte) int {
		recorder := httptest.NewRecorder()
		receiver.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/agent-packet", bytes.NewReader(body)))
		return recorder.Code
	}
	packets := transport.packets()
	tampered := bytes.Replace(packets[0].JSON, []byte(`"sequence":`), []byte(`"sequence":1`), 1)
	foreignCourier, err := OpenCourier(
		filepath.Join(t.TempDir(), "outbox2"),
		testSigner(t, testSeller),
		&recordingTransport{},
	)
	if err != nil {
		t.Fatal(err)
	}
	other := testEnvelope()
	other.RecipientAgentID = "agent_" + strings.Repeat("c3", 32)
	if _, err = foreignCourier.Deliver(context.Background(), other, fill(10, 1)); err != nil {
		t.Fatal(err)
	}
	unknownSender := testSigner(t, "agent_"+strings.Repeat("d4", 32))
	stranger, err := unknownSender.sign(context.Background(), testBuyer, testEnvelope().CapabilityID, "", fill(10, 1))
	if err != nil {
		t.Fatal(err)
	}
	strangerJSON, err := agentpacket.EncodeJSON(stranger)
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{
		"tampered signature preimage": tampered,
		"another recipient":           foreignCourier.mustFirstPacket(t),
		"sender not finalized":        strangerJSON,
		"not JSON":                    []byte("{"),
	} {
		if code := post(body); code == http.StatusAccepted {
			t.Errorf("%s: accepted", name)
		}
	}
	// A finalized, live Agent other than this node is still not this node.
	elsewhere := *receiver
	third := "agent_" + strings.Repeat("e5", 32)
	elsewhere.LocalAgentID = third
	elsewhere.Resolver = agentMap{
		testBuyer:  agentState(testBuyer),
		testSeller: agentState(testSeller),
		third:      agentState(third),
	}
	recorder := httptest.NewRecorder()
	elsewhere.ServeHTTP(
		recorder,
		httptest.NewRequest(http.MethodPost, "/v1/agent-packet", bytes.NewReader(packets[1].JSON)),
	)
	if recorder.Code == http.StatusAccepted {
		t.Error("a packet for another live Agent was accepted")
	}
	if code := post(packets[1].JSON); code != http.StatusAccepted {
		t.Fatalf("a verified frame was refused: %d", code)
	}
	if code := post(packets[0].JSON); code != http.StatusAccepted {
		t.Fatalf("a verified frame was refused: %d", code)
	}
	if len(notified) != 1 || notified[0] != InboxComplete {
		t.Fatalf("notifications = %v", notified)
	}
	pending, err := inbox.Pending()
	if err != nil || len(pending) != 1 || pending[0].SenderAgentID != testSeller {
		t.Fatalf("pending = %+v %v", pending, err)
	}
}

func (c *Courier) mustFirstPacket(t *testing.T) []byte {
	t.Helper()
	transport, ok := c.transport.(*recordingTransport)
	if !ok || len(transport.packets()) == 0 {
		t.Fatal("no packet recorded")
	}
	return transport.packets()[0].JSON
}
