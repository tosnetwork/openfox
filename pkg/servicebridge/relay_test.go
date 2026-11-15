package servicebridge

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
)

// ownersMap stands in for the Capabilities' finalized owners.
type ownersMap map[string]string

func (o ownersMap) CapabilityOwner(_ context.Context, capabilityID string) (string, error) {
	owner, ok := o[capabilityID]
	if !ok {
		return "", fmt.Errorf("%w: no such Capability", ErrCardRefused)
	}
	return owner, nil
}

// switchableAgents resolves from a map that a test edits, and can be made
// to fail as an unavailable chain would.
type switchableAgents struct {
	mutex  sync.Mutex
	agents agentMap
	down   bool
}

func (s *switchableAgents) ResolveAgent(id string) (*nativev1.AgentStateV1, bool, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.down {
		return nil, false, errors.New("finalized state is unavailable")
	}
	state, ok := s.agents[id]
	return state, ok, nil
}

func (s *switchableAgents) set(down bool) {
	s.mutex.Lock()
	s.down = down
	s.mutex.Unlock()
}

func (s *switchableAgents) revoke(id string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	state := agentState(id)
	state.Policy.Controllers[0].KeyId = packetKeys.KeyID("agent_" + strings.Repeat("99", 32))
	state.Policy.Controllers[0].Mldsa44PublicKey = packetKeys.PublicKey("agent_" + strings.Repeat("99", 32))
	s.agents[id] = state
}

const relayCapability = "cap_" + "33333333333333333333333333333333333333333333333333333333333333aa"

var (
	relayStranger = "agent_" + strings.Repeat("d4", 32)
	relayThird    = "agent_" + strings.Repeat("e5", 32)
)

func relayAgents() *switchableAgents {
	return &switchableAgents{agents: agentMap{
		testBuyer: agentState(testBuyer), testSeller: agentState(testSeller), relayThird: agentState(relayThird),
	}}
}

type relayTestNode struct {
	t        *testing.T
	agent    string
	dir      string
	clock    *relayClock
	agents   *switchableAgents
	inbox    *Inbox
	receiver *Receiver
	cards    *PeerCards
	carrier  *RelayCarrier
	courier  *Courier
	relays   []*fakeRelay
	mutex    sync.Mutex
	reports  []string
	notified []InboxStatus
}

func newRelayTestNode(t *testing.T, clock *relayClock, agent string, agents *switchableAgents,
	relays ...*fakeRelay,
) *relayTestNode {
	t.Helper()
	return openRelayTestNode(t, t.TempDir(), clock, agent, agents, relays...)
}

func openRelayTestNode(t *testing.T, dir string, clock *relayClock, agent string, agents *switchableAgents,
	relays ...*fakeRelay,
) *relayTestNode {
	t.Helper()
	node := &relayTestNode{t: t, agent: agent, dir: dir, clock: clock, agents: agents, relays: relays}
	inbox, err := OpenInbox(filepath.Join(dir, "inbox"), 4, 8)
	if err != nil {
		t.Fatal(err)
	}
	node.inbox = inbox
	node.receiver = &Receiver{
		LocalAgentID: agent, Resolver: agents, Verifier: packetKeys, Inbox: inbox, Now: clock.Now,
		Notify: func(status InboxStatus, _ Message) {
			node.mutex.Lock()
			node.notified = append(node.notified, status)
			node.mutex.Unlock()
		},
	}
	if err = ensurePrivateDirectory(filepath.Join(dir, relayStateDir)); err != nil {
		t.Fatal(err)
	}
	node.cards, err = OpenPeerCards(filepath.Join(dir, relayStateDir, relayPeersDir), packetKeys, agents,
		ownersMap{relayCapability: testSeller}, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	node.cards.AllowLoopbackRelays(true)
	urls := make([]string, 0, len(relays))
	for _, relay := range relays {
		urls = append(urls, relay.URL)
	}
	signer := testSigner(t, agent)
	signer.now = clock.Now
	node.carrier, err = OpenRelayCarrier(RelayCarrierConfig{
		StateDir: dir, AgentID: agent, Relays: urls, Signer: signer, Cards: node.cards, Receiver: node.receiver,
		Now: clock.Now, Report: func(stage string, err error) {
			node.mutex.Lock()
			node.reports = append(node.reports, stage+": "+err.Error())
			node.mutex.Unlock()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	node.courier, err = OpenCourier(
		filepath.Join(dir, "outbox"),
		signer,
		RoutedTransport{Relay: node.carrier.Transport},
	)
	if err != nil {
		t.Fatal(err)
	}
	node.courier.now = clock.Now
	return node
}

// card is the node's current own card packet JSON.
func (n *relayTestNode) card() []byte {
	n.t.Helper()
	key, err := n.carrier.Keys.Current(context.Background(), 0)
	if err != nil {
		n.t.Fatal(err)
	}
	return key.CardJSON
}

// learn makes n know peer's current card, as a task or an offer would.
func (n *relayTestNode) learn(peer *relayTestNode) {
	n.t.Helper()
	if err := n.cards.Learn(context.Background(), peer.card(), peer.agent, ""); err != nil {
		n.t.Fatal(err)
	}
}

func (n *relayTestNode) pollAll() {
	for _, relay := range n.relays {
		n.carrier.Inbound.Poll(context.Background(), relay.URL)
	}
}

func (n *relayTestNode) pollOne(relay *fakeRelay) {
	n.carrier.Inbound.Poll(context.Background(), relay.URL)
}

func (n *relayTestNode) pending() []Message {
	n.t.Helper()
	messages, err := n.inbox.Pending()
	if err != nil {
		n.t.Fatal(err)
	}
	return messages
}

func (n *relayTestNode) reportText() string {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	return strings.Join(n.reports, "\n")
}

func relayEnvelopeTo(recipient string) Envelope {
	envelope := testEnvelope()
	envelope.RecipientAgentID = recipient
	return envelope
}

// plaintextMarker is in every test message body, so its absence from the
// relays' bytes shows they never held the packet in clear.
const plaintextMarker = "relay-plaintext-marker-1f7c"

func markedBody(size int) []byte {
	body := bytes.Repeat([]byte{'x'}, size)
	copy(body, plaintextMarker)
	return body
}

func onlyEnvelopeID(t *testing.T, relay *fakeRelay, agent string) [32]byte {
	t.Helper()
	relay.mutex.Lock()
	defer relay.mutex.Unlock()
	if len(relay.boxes[agent]) != 1 {
		t.Fatalf("relay holds %d envelopes, want 1", len(relay.boxes[agent]))
	}
	for id := range relay.boxes[agent] {
		return id
	}
	return [32]byte{}
}

func TestARelayedMessageIsSealedDeliveredStoredAndAcknowledgedAtEveryRelay(t *testing.T) {
	clock := newRelayClock()
	agents := relayAgents()
	relayA, relayB := twoRelays(t, clock)
	seller := newRelayTestNode(t, clock, testSeller, agents, relayA)
	buyer := newRelayTestNode(t, clock, testBuyer, agents, relayA, relayB)
	seller.learn(buyer)

	body := markedBody(MaxChunkData + 100)
	if _, err := seller.courier.Deliver(context.Background(), relayEnvelopeTo(testBuyer), body); err != nil {
		t.Fatal(err)
	}
	// Send returns at the first acceptance; the other relay is the
	// background loop's.
	if relayA.count(testBuyer) != 2 || relayB.count(testBuyer) != 0 {
		t.Fatalf("after send: A holds %d, B holds %d", relayA.count(testBuyer), relayB.count(testBuyer))
	}
	if err := seller.carrier.Transport.Redeposit(context.Background()); err != nil {
		t.Fatal(err)
	}
	if relayB.count(testBuyer) != 2 {
		t.Fatalf("the redundancy loop left B with %d envelopes", relayB.count(testBuyer))
	}
	if bytes.Contains(relayA.allBytes(), []byte(plaintextMarker)) ||
		bytes.Contains(relayB.allBytes(), []byte(plaintextMarker)) {
		t.Fatal("a relay holds the packet in clear")
	}
	buyer.pollAll()
	pending := buyer.pending()
	if len(pending) != 1 || pending[0].SenderAgentID != testSeller || !bytes.Equal(pending[0].Body, body) {
		t.Fatalf("pending = %d messages", len(pending))
	}
	if relayA.count(testBuyer) != 0 || relayB.count(testBuyer) != 0 {
		t.Fatalf("not acknowledged everywhere: A %d, B %d", relayA.count(testBuyer), relayB.count(testBuyer))
	}
	buyer.mutex.Lock()
	notified := append([]InboxStatus(nil), buyer.notified...)
	buyer.mutex.Unlock()
	if len(notified) != 1 || notified[0] != InboxComplete {
		t.Fatalf("notifications = %v", notified)
	}
	views, err := ReadRelayOutbox(filepath.Join(seller.dir, relayStateDir, relayOutboxDir))
	if err != nil || len(views) != 2 || len(views[0].Pending) != 0 || len(views[0].Accepted) != 2 {
		t.Fatalf("outbox = %+v %v", views, err)
	}
}

func TestACardOfAnotherAgentThanTheCapabilitysFinalizedOwnerIsRefused(t *testing.T) {
	clock := newRelayClock()
	agents := relayAgents()
	relay := startFakeRelay(t, clock)
	buyer := newRelayTestNode(t, clock, testBuyer, agents, relay)
	seller := newRelayTestNode(t, clock, testSeller, agents, relay)
	third := newRelayTestNode(t, clock, relayThird, agents, relay)
	// A valid card of a live Agent that does not own the Capability.
	err := buyer.cards.Learn(context.Background(), third.card(), relayThird, relayCapability)
	if !errors.Is(err, ErrCardRefused) || buyer.cards.Has(relayThird) {
		t.Fatalf("a card of another Agent than the finalized owner was taken: %v", err)
	}
	// A card that claims the owner's Agent but carries another's packet.
	if err := buyer.cards.Learn(context.Background(), third.card(), testSeller, relayCapability); err == nil {
		t.Fatal("a card was taken for an Agent that did not sign it")
	}
	if err := buyer.cards.Learn(context.Background(), seller.card(), testSeller, relayCapability); err != nil {
		t.Fatalf("the finalized owner's card was refused: %v", err)
	}
	// Ownership is read again at a later verification: a Capability whose
	// owner changed stops the card.
	buyer.cards.owners = ownersMap{relayCapability: relayThird}
	clock.Advance(RelayCardReverify + time.Second)
	if _, err := buyer.cards.Current(context.Background(), testSeller); !errors.Is(err, ErrNoPacketRoute) {
		t.Fatalf("a card no longer bound to the finalized owner was used: %v", err)
	}
}

func TestAnOfferFileSwapOfAnotherValidCardOfTheOwnerIsSealedToByPreference(t *testing.T) {
	clock := newRelayClock()
	agents := relayAgents()
	relayA, relayB := twoRelays(t, clock)
	buyer := newRelayTestNode(t, clock, testBuyer, agents, relayA)
	oldSeller := newRelayTestNode(t, clock, testSeller, agents, relayA)
	older := oldSeller.card()
	clock.Advance(time.Hour)
	// The same Agent with a newer key at another relay.
	newSeller := newRelayTestNode(t, clock, testSeller, agents, relayB)
	newer := newSeller.card()
	if err := buyer.cards.Learn(context.Background(), newer, testSeller, relayCapability); err != nil {
		t.Fatal(err)
	}
	// A stale offer file hands over the older, still valid card: it is
	// taken (it is the owner's, validly signed) but the newer one is used.
	if err := buyer.cards.Learn(context.Background(), older, testSeller, relayCapability); err != nil {
		t.Fatalf("a valid older card of the owner was refused: %v", err)
	}
	current, err := buyer.cards.Current(context.Background(), testSeller)
	if err != nil || !bytes.Equal(current.JSON, newer) {
		t.Fatalf("sealed to the older card: %v", err)
	}
	// Holding only the older card, the buyer seals to it: the protocol
	// accepts a stale but valid card until it expires.
	alone := newRelayTestNode(t, clock, testBuyer, agents, relayA)
	if err := alone.cards.Learn(context.Background(), older, testSeller, relayCapability); err != nil {
		t.Fatal(err)
	}
	if current, err := alone.cards.Current(context.Background(), testSeller); err != nil ||
		!bytes.Equal(current.JSON, older) {
		t.Fatalf("the only valid card was not used: %v", err)
	}
	if _, err := alone.courier.Deliver(context.Background(), relayEnvelopeTo(testSeller), markedBody(10)); err != nil {
		t.Fatal(err)
	}
	oldSeller.pollAll()
	if len(oldSeller.pending()) != 1 {
		t.Fatal("the envelope sealed to the older card was not opened by its key")
	}
}

func TestARevokedCardIsNotSealedToOnceItsVerificationIsStale(t *testing.T) {
	clock := newRelayClock()
	agents := relayAgents()
	relay := startFakeRelay(t, clock)
	seller := newRelayTestNode(t, clock, testSeller, agents, relay)
	buyer := newRelayTestNode(t, clock, testBuyer, agents, relay)
	seller.learn(buyer)
	if _, err := seller.cards.Current(context.Background(), testBuyer); err != nil {
		t.Fatal(err)
	}
	// The buyer's signing controller leaves its finalized policy.
	agents.revoke(testBuyer)
	clock.Advance(RelayCardReverify + time.Second)
	if _, err := seller.courier.Deliver(context.Background(), relayEnvelopeTo(testBuyer), markedBody(10)); !errors.Is(
		err,
		ErrNoPacketRoute,
	) {
		t.Fatalf("a revoked card was sealed to: %v", err)
	}
	if seller.cards.Has(testBuyer) {
		t.Fatal("the revoked card is still held")
	}
}

func TestAJunkCopyUnderThePublicIDAtAnotherRelayDoesNotSuppressTheGenuineEnvelope(t *testing.T) {
	clock := newRelayClock()
	agents := relayAgents()
	relayA, relayB := twoRelays(t, clock)
	seller := newRelayTestNode(t, clock, testSeller, agents, relayA)
	buyer := newRelayTestNode(t, clock, testBuyer, agents, relayA, relayB)
	seller.learn(buyer)
	body := markedBody(40)
	if _, err := seller.courier.Deliver(context.Background(), relayEnvelopeTo(testBuyer), body); err != nil {
		t.Fatal(err)
	}
	// An observer of relay A reads the id and deposits junk under it at B
	// before the background deposit reaches B.
	id := onlyEnvelopeID(t, relayA, testBuyer)
	junk := relayA.stored(testBuyer, id)
	junk[len(junk)-1] ^= 0xff
	relayB.put(testBuyer, id, junk)
	if err := seller.carrier.Transport.Redeposit(context.Background()); err != nil {
		t.Fatal(err)
	}
	views, err := ReadRelayOutbox(filepath.Join(seller.dir, relayStateDir, relayOutboxDir))
	if err != nil || len(views) != 1 || len(views[0].Conflicts) != 1 || views[0].Conflicts[0] != relayB.URL ||
		len(views[0].Pending) != 0 {
		t.Fatalf("the 409 relay was not abandoned for the envelope: %+v %v", views, err)
	}
	// The redundancy loop terminated: nothing more is sent to B.
	deposits := len(relayB.depositLog())
	if err := seller.carrier.Transport.Redeposit(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(relayB.depositLog()) != deposits {
		t.Fatal("the envelope is deposited again at the relay that answered 409")
	}
	// The recipient polls B first: the junk does not open, and the genuine
	// copy at A is still opened in the same cycle.
	buyer.pollOne(relayB)
	buyer.pollOne(relayA)
	if pending := buyer.pending(); len(pending) != 1 || !bytes.Equal(pending[0].Body, body) {
		t.Fatalf("the genuine envelope was suppressed: %d messages", len(pending))
	}
	// The settled id is acknowledged at B too, which removes the junk.
	buyer.pollOne(relayB)
	if relayA.count(testBuyer) != 0 || relayB.count(testBuyer) != 0 {
		t.Fatalf("A %d, B %d envelopes left", relayA.count(testBuyer), relayB.count(testBuyer))
	}
}

func TestAConflictAtEveryRelayResealsUnderAFreshIDAndTheRetrySucceeds(t *testing.T) {
	clock := newRelayClock()
	agents := relayAgents()
	relayA, relayB := twoRelays(t, clock)
	seller := newRelayTestNode(t, clock, testSeller, agents, relayA)
	buyer := newRelayTestNode(t, clock, testBuyer, agents, relayA, relayB)
	seller.learn(buyer)
	relayA.conflictAll, relayB.conflictAll = true, true
	if _, err := seller.courier.Deliver(context.Background(), relayEnvelopeTo(testBuyer), markedBody(40)); !errors.Is(
		err,
		ErrRelayResealed,
	) {
		t.Fatalf("send over two conflicting relays: %v", err)
	}
	first := relayA.depositLog()[0].raw
	views, err := ReadRelayOutbox(filepath.Join(seller.dir, relayStateDir, relayOutboxDir))
	if err != nil || len(views) != 1 || views[0].Seals != 2 || len(views[0].Conflicts) != 0 {
		t.Fatalf("no fresh seal journaled: %+v %v", views, err)
	}
	header, _ := agentpacketseal.ParseEnvelope(first)
	if views[0].EnvelopeID == hex.EncodeToString(header.EnvelopeID[:]) {
		t.Fatal("the reseal kept the conflicting envelope id")
	}
	// Each retry over relays that keep conflicting reseals once and fails;
	// it never loops inside a send.
	for range 3 {
		if err := seller.courier.Resume(context.Background()); !errors.Is(err, ErrRelayResealed) {
			t.Fatalf("resume: %v", err)
		}
	}
	relayA.conflictAll, relayB.conflictAll = false, false
	if err := seller.courier.Resume(context.Background()); err != nil {
		t.Fatalf("the retry with the fresh envelope failed: %v", err)
	}
	buyer.pollAll()
	if len(buyer.pending()) != 1 {
		t.Fatal("the resealed packet was not delivered")
	}
}

func TestAnAmbiguousDepositIsRetriedAfterARestartWithIdenticalBytes(t *testing.T) {
	clock := newRelayClock()
	agents := relayAgents()
	relay := startFakeRelay(t, clock)
	dir := t.TempDir()
	seller := openRelayTestNode(t, dir, clock, testSeller, agents, relay)
	buyer := newRelayTestNode(t, clock, testBuyer, agents, relay)
	seller.learn(buyer)
	relay.storeThenFail = true
	if _, err := seller.courier.Deliver(context.Background(), relayEnvelopeTo(testBuyer), markedBody(40)); err == nil {
		t.Fatal("an ambiguous deposit was reported delivered")
	}
	// A restart over the same state: new transport, journal and cards from
	// disk.
	restarted := openRelayTestNode(t, dir, clock, testSeller, agents, relay)
	if err := restarted.courier.Resume(context.Background()); err != nil {
		t.Fatalf("resume: %v", err)
	}
	log := relay.depositLog()
	if len(log) != 2 || !bytes.Equal(log[0].raw, log[1].raw) || log[1].status != 200 {
		t.Fatalf("the retry did not resend the journaled bytes: %d deposits", len(log))
	}
	buyer.pollAll()
	if len(buyer.pending()) != 1 {
		t.Fatal("the packet was not delivered")
	}
}

func TestEveryRelayFailingFailsTheSendAndTheJournalKeepsOneEnvelope(t *testing.T) {
	clock := newRelayClock()
	agents := relayAgents()
	relay := startFakeRelay(t, clock)
	seller := newRelayTestNode(t, clock, testSeller, agents, relay)
	buyer := newRelayTestNode(t, clock, testBuyer, agents, relay)
	seller.learn(buyer)
	relay.failDeposits = 2
	if _, err := seller.courier.Deliver(context.Background(), relayEnvelopeTo(testBuyer), markedBody(40)); !errors.Is(
		err,
		ErrRelayUndelivered,
	) {
		t.Fatalf("send to a failing relay: %v", err)
	}
	if err := seller.courier.Resume(context.Background()); !errors.Is(err, ErrRelayUndelivered) {
		t.Fatalf("resume: %v", err)
	}
	if err := seller.courier.Resume(context.Background()); err != nil {
		t.Fatal(err)
	}
	log := relay.depositLog()
	if len(log) != 3 || !bytes.Equal(log[0].raw, log[2].raw) || log[2].status != 201 {
		t.Fatalf("deposits = %d", len(log))
	}
}

func TestARelayedEnvelopeIsAcknowledgedOnlyAfterTheDurableInboxWrite(t *testing.T) {
	clock := newRelayClock()
	agents := relayAgents()
	relay := startFakeRelay(t, clock)
	seller := newRelayTestNode(t, clock, testSeller, agents, relay)
	buyerAgents := relayAgents()
	buyer := newRelayTestNode(t, clock, testBuyer, buyerAgents, relay)
	seller.learn(buyer)
	if _, err := seller.courier.Deliver(context.Background(), relayEnvelopeTo(testBuyer), markedBody(40)); err != nil {
		t.Fatal(err)
	}
	// Finalized state is unavailable: the packet cannot be verified now.
	buyerAgents.set(true)
	buyer.pollAll()
	if relay.count(testBuyer) != 1 || len(buyer.pending()) != 0 {
		t.Fatal("an unverified packet was acknowledged or stored")
	}
	buyerAgents.set(false)
	// The inbox cannot be written: still not acknowledged.
	inboxDir := filepath.Join(buyer.dir, "inbox")
	if err := os.Chmod(inboxDir, 0o500); err != nil {
		t.Fatal(err)
	}
	buyer.pollAll()
	if err := os.Chmod(inboxDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if relay.count(testBuyer) != 1 {
		t.Fatal("an envelope was acknowledged although its frame was not stored")
	}
	buyer.pollAll()
	if relay.count(testBuyer) != 0 || len(buyer.pending()) != 1 {
		t.Fatalf("not delivered once storable: relay %d", relay.count(testBuyer))
	}
}

func TestARecipientRestartBetweenInboxWriteAndAckRedeliversAndDeduplicates(t *testing.T) {
	clock := newRelayClock()
	agents := relayAgents()
	relay := startFakeRelay(t, clock)
	seller := newRelayTestNode(t, clock, testSeller, agents, relay)
	dir := t.TempDir()
	buyer := openRelayTestNode(t, dir, clock, testBuyer, agents, relay)
	seller.learn(buyer)
	if _, err := seller.courier.Deliver(context.Background(), relayEnvelopeTo(testBuyer), markedBody(40)); err != nil {
		t.Fatal(err)
	}
	// The relay loses the acknowledgement (or the node died before it).
	relay.replay = true
	buyer.pollAll()
	restarted := openRelayTestNode(t, dir, clock, testBuyer, agents, relay)
	restarted.pollAll()
	if pending := restarted.pending(); len(pending) != 1 {
		t.Fatalf("a redelivered envelope made %d messages", len(pending))
	}
	restarted.mutex.Lock()
	notified := append([]InboxStatus(nil), restarted.notified...)
	restarted.mutex.Unlock()
	if len(notified) != 1 || notified[0] == InboxPartial {
		t.Fatalf("the redelivery was not handed to the service once: %v", notified)
	}
}

// sealTo seals packet JSON to node's current key and stores it at relay.
func sealTo(t *testing.T, relay *fakeRelay, node *relayTestNode, packetJSON []byte) [32]byte {
	t.Helper()
	held := node.carrier.Keys.Held()
	card, err := decodeOwnCard(node.agent, held[0].CardJSON)
	if err != nil {
		t.Fatal(err)
	}
	var secret [32]byte
	if _, err = rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}
	raw, err := agentpacketseal.Seal(agentpacketseal.RecipientKey{
		AgentID: node.agent, KeyID: card.KeyID, PublicKey: card.PublicKey,
	}, secret, packetJSON, uint64(node.clock.Now().Add(time.Hour).Unix()))
	if err != nil {
		t.Fatal(err)
	}
	id := agentpacketseal.AckHash(secret)
	relay.put(node.agent, id, raw)
	return id
}

func framePacket(t *testing.T, signer, recipient string) []byte {
	t.Helper()
	frames, err := SplitMessage(FrameResult, testActor, 3, testRequest, markedBody(30))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := EncodeFrame(frames[0])
	if err != nil {
		t.Fatal(err)
	}
	packet, err := testSigner(t, signer).sign(context.Background(), recipient, testEnvelope().CapabilityID, "", payload)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := agentpacket.EncodeJSON(packet)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestTamperedForeignAndUnauthorizedEnvelopesAreRefusedAsSpecified(t *testing.T) {
	clock := newRelayClock()
	agents := relayAgents()
	relay := startFakeRelay(t, clock)
	buyer := newRelayTestNode(t, clock, testBuyer, agents, relay)
	buyer.card()

	// Sealed to the buyer's key, but signed by an Agent that is not
	// finalized: it opens, is refused, and is acknowledged.
	unauthorized := sealTo(t, relay, buyer, framePacket(t, relayStranger, testBuyer))
	// Sealed to the buyer's key, but the packet names another recipient.
	foreign := sealTo(t, relay, buyer, framePacket(t, testSeller, relayThird))
	// A genuine envelope whose ciphertext was altered: it does not open,
	// is not acknowledged, and is not downloaded again.
	tampered := sealTo(t, relay, buyer, framePacket(t, testSeller, testBuyer))
	raw := relay.stored(testBuyer, tampered)
	raw[agentpacketseal.EnvelopeHeaderSize+agentpacketseal.EncapsulatedKeySize+3] ^= 1
	relay.put(testBuyer, tampered, raw)
	// A header byte altered: the AEAD binding refuses it.
	header := sealTo(t, relay, buyer, framePacket(t, testSeller, testBuyer))
	raw = relay.stored(testBuyer, header)
	raw[agentpacketseal.EnvelopeHeaderSize-5] ^= 1
	relay.put(testBuyer, header, raw)

	buyer.pollAll()
	if len(buyer.pending()) != 0 {
		t.Fatal("a refused packet reached the inbox")
	}
	for name, id := range map[string][32]byte{"unauthorized signer": unauthorized, "another recipient": foreign} {
		if relay.stored(testBuyer, id) != nil {
			t.Errorf("%s: an opened but refused packet was not acknowledged", name)
		}
	}
	for name, id := range map[string][32]byte{"tampered ciphertext": tampered, "tampered header": header} {
		if relay.stored(testBuyer, id) == nil {
			t.Errorf("%s: an envelope that does not open was deleted", name)
		}
	}
	if !strings.Contains(buyer.reportText(), "refused and acknowledged") {
		t.Fatal("the refusal was not reported")
	}
	downloads := len(relay.depositLog())
	buyer.pollAll()
	if !buyer.carrier.Inbound.remembered(relayMemoryKey(relay.URL, tampered)) {
		t.Fatal("the envelope that did not open is not remembered")
	}
	if len(relay.depositLog()) != downloads || len(buyer.pending()) != 0 {
		t.Fatal("a second poll changed what the first decided")
	}
}

func TestAnEnvelopeForAKeyNotHeldIsLeftToExpireWithoutADownload(t *testing.T) {
	clock := newRelayClock()
	agents := relayAgents()
	relay := startFakeRelay(t, clock)
	buyer := newRelayTestNode(t, clock, testBuyer, agents, relay)
	other := newRelayTestNode(t, clock, testBuyer, agents, relay)
	// Sealed to a key of the same Agent this node never held.
	other.card()
	id := sealTo(t, relay, other, framePacket(t, testSeller, testBuyer))
	buyer.card()
	buyer.pollAll()
	buyer.pollAll()
	if relay.stored(testBuyer, id) == nil || len(buyer.pending()) != 0 {
		t.Fatal("an envelope for a key not held was taken or deleted")
	}
	if !buyer.carrier.Inbound.remembered(relayMemoryKey(relay.URL, id)) {
		t.Fatal("the unknown-key envelope is not remembered")
	}
}

func TestKeysRotateAheadOfExpiryAndAreDestroyedAfterTheirRetention(t *testing.T) {
	clock := newRelayClock()
	agents := relayAgents()
	relay := startFakeRelay(t, clock)
	seller := newRelayTestNode(t, clock, testSeller, agents, relay)
	buyer := newRelayTestNode(t, clock, testBuyer, agents, relay)
	first, err := buyer.carrier.Keys.Current(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if first.NotAfterUnix-first.NotBeforeUnix != uint64(RelayKeyLifetime/time.Second) {
		t.Fatalf("card lifetime %d s", first.NotAfterUnix-first.NotBeforeUnix)
	}
	seller.learn(buyer)
	clock.Advance(RelayKeyLifetime - RelaySuccessorLead - time.Hour)
	if issued, maintainErr := buyer.carrier.Keys.Maintain(context.Background()); maintainErr != nil || issued {
		t.Fatalf("a successor was issued early: %v %v", issued, maintainErr)
	}
	clock.Advance(2 * time.Hour)
	if issued, maintainErr := buyer.carrier.Keys.Maintain(context.Background()); maintainErr != nil || !issued {
		t.Fatalf("no successor inside the lead: %v %v", issued, maintainErr)
	}
	second, err := buyer.carrier.Keys.Current(context.Background(), 0)
	if err != nil || second.KeyID == first.KeyID || len(buyer.carrier.Keys.Held()) != 2 {
		t.Fatalf("successor = %v held %d", err, len(buyer.carrier.Keys.Held()))
	}
	// The seller still holds only the first card and seals to it; the
	// buyer opens it with the old key although a successor is current.
	if _, err := seller.courier.Deliver(context.Background(), relayEnvelopeTo(testBuyer), markedBody(20)); err != nil {
		t.Fatal(err)
	}
	buyer.pollAll()
	if len(buyer.pending()) != 1 {
		t.Fatal("an envelope sealed to the previous card was not opened")
	}
	// Past the first card's expiry the seller cannot seal to it any more,
	// but the buyer still opens what was sealed to it.
	clock.Advance(RelaySuccessorLead)
	late := sealToKey(t, relay, testBuyer, first, framePacket(t, testSeller, testBuyer), clock)
	buyer.pollAll()
	if relay.stored(testBuyer, late) != nil || len(buyer.pending()) != 2 {
		t.Fatal("an envelope to an expired but retained key was not opened")
	}
	if _, err := seller.courier.Deliver(context.Background(), Envelope{
		RecipientAgentID: testBuyer, CapabilityID: testEnvelope().CapabilityID, Kind: FrameResult,
		ActorAccount: testActor, RequestID: 9, RequestHash: testRequest,
	}, markedBody(20)); !errors.Is(err, ErrNoPacketRoute) {
		t.Fatalf("an expired card was sealed to: %v", err)
	}
	firstFile := filepath.Join(buyer.dir, relayStateDir, relayKeysDir, hex.EncodeToString(first.KeyID[:])+".json")
	clock.Advance(RelayKeyRetention - time.Hour - time.Minute)
	if _, err := buyer.carrier.Keys.Maintain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(firstFile); err != nil {
		t.Fatal("the key was destroyed before its retention ended")
	}
	clock.Advance(2 * time.Minute)
	if _, err := buyer.carrier.Keys.Maintain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(firstFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the key outlived its retention")
	}
	if _, held := buyer.carrier.Keys.private(first.KeyID); held {
		t.Fatal("the destroyed key is still usable")
	}
	// An envelope to the destroyed key is left to expire.
	id := sealToKey(t, relay, testBuyer, first, framePacket(t, relayThird, testBuyer), clock)
	buyer.pollAll()
	if relay.stored(testBuyer, id) == nil || len(buyer.pending()) != 2 {
		t.Fatal("an envelope to a destroyed key was opened or deleted")
	}
}

func sealToKey(t *testing.T, relay *fakeRelay, agent string, key OwnRelayKey, packetJSON []byte,
	clock *relayClock,
) [32]byte {
	t.Helper()
	card, err := decodeOwnCard(agent, key.CardJSON)
	if err != nil {
		t.Fatal(err)
	}
	var secret [32]byte
	if _, err = rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}
	raw, err := agentpacketseal.Seal(agentpacketseal.RecipientKey{
		AgentID: agent, KeyID: card.KeyID,
		PublicKey: card.PublicKey,
	}, secret, packetJSON, uint64(clock.Now().Add(time.Hour).Unix()))
	if err != nil {
		t.Fatal(err)
	}
	id := agentpacketseal.AckHash(secret)
	relay.put(agent, id, raw)
	return id
}

func TestAKeyFileThatDisagreesWithItselfIsRefusedAtOpen(t *testing.T) {
	clock := newRelayClock()
	agents := relayAgents()
	relay := startFakeRelay(t, clock)
	dir := t.TempDir()
	node := openRelayTestNode(t, dir, clock, testBuyer, agents, relay)
	node.card()
	keysDir := filepath.Join(dir, relayStateDir, relayKeysDir)
	entries, err := os.ReadDir(keysDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("key files = %d %v", len(entries), err)
	}
	path := filepath.Join(keysDir, entries[0].Name())
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the key file is not owner-only: %v", info.Mode())
	}
	var record relayKeyRecord
	if err := readJSON(path, 64<<10, &record); err != nil {
		t.Fatal(err)
	}
	seed, _ := agentpacketseal.GenerateSeed()
	record.SeedBase64 = base64.StdEncoding.EncodeToString(seed)
	encoded, _ := json.Marshal(record)
	if err := replaceSynced(path, encoded); err != nil {
		t.Fatal(err)
	}
	signer := testSigner(t, testBuyer)
	if _, err := OpenRelayKeys(keysDir, testBuyer, []string{relay.URL}, signer, clock.Now); err == nil {
		t.Fatal("a key file whose seed does not match its key id was loaded")
	}
}

func TestNoPrivateKeyOrPlaintextReachesReportsStatusOrRelays(t *testing.T) {
	clock := newRelayClock()
	agents := relayAgents()
	relay := startFakeRelay(t, clock)
	seller := newRelayTestNode(t, clock, testSeller, agents, relay)
	buyer := newRelayTestNode(t, clock, testBuyer, agents, relay)
	seller.learn(buyer)
	if _, err := seller.courier.Deliver(context.Background(), relayEnvelopeTo(testBuyer), markedBody(60)); err != nil {
		t.Fatal(err)
	}
	// A refused packet and a failing relay make the node report.
	sealTo(t, relay, buyer, framePacket(t, relayStranger, testBuyer))
	buyer.pollAll()
	relay.listFails = true
	buyer.pollAll()
	if err := buyer.carrier.WriteStatus(); err != nil {
		t.Fatal(err)
	}
	if err := seller.carrier.WriteStatus(); err != nil {
		t.Fatal(err)
	}
	var secrets [][]byte
	for _, node := range []*relayTestNode{buyer, seller} {
		keysDir := filepath.Join(node.dir, relayStateDir, relayKeysDir)
		entries, err := os.ReadDir(keysDir)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			var record relayKeyRecord
			if err := readJSON(filepath.Join(keysDir, entry.Name()), 64<<10, &record); err != nil {
				t.Fatal(err)
			}
			seed, _ := base64.StdEncoding.DecodeString(record.SeedBase64)
			secrets = append(secrets, []byte(record.SeedBase64), []byte(hex.EncodeToString(seed)), seed)
		}
	}
	if len(secrets) == 0 {
		t.Fatal("no key was found to look for")
	}
	var evidence []byte
	for _, node := range []*relayTestNode{buyer, seller} {
		evidence = append(evidence, node.reportText()...)
		status, err := os.ReadFile(filepath.Join(node.dir, relayStateDir, relayStatusFile))
		if err != nil {
			t.Fatal(err)
		}
		evidence = append(evidence, status...)
		report, err := ReadRelayDelivery(node.dir, nil)
		if err != nil {
			t.Fatal(err)
		}
		encoded, _ := json.Marshal(report)
		evidence = append(evidence, encoded...)
		outbox, err := os.ReadDir(filepath.Join(node.dir, relayStateDir, relayOutboxDir))
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range outbox {
			raw, err := os.ReadFile(filepath.Join(node.dir, relayStateDir, relayOutboxDir, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			decoded := raw
			var record relayOutboxRecord
			if json.Unmarshal(raw, &record) == nil {
				envelope, _ := base64.StdEncoding.DecodeString(record.EnvelopeBase64)
				decoded = append(decoded, envelope...)
			}
			evidence = append(evidence, decoded...)
		}
	}
	evidence = append(evidence, relay.allBytes()...)
	if !strings.Contains(buyer.reportText(), "relay.receive") {
		t.Fatal("the instrument is silent: no report was produced")
	}
	for _, secret := range secrets {
		if bytes.Contains(evidence, secret) {
			t.Fatal("a private key reached a report, the status, the journal or a relay")
		}
	}
	if bytes.Contains(evidence, []byte(plaintextMarker)) {
		t.Fatal("packet plaintext reached a report, the status, the journal or a relay")
	}
}

func TestTheRelayPollerBacksOffAndHonoursRetryAfter(t *testing.T) {
	clock := newRelayClock()
	agents := relayAgents()
	relay := startFakeRelay(t, clock)
	buyer := newRelayTestNode(t, clock, testBuyer, agents, relay)
	buyer.card()
	buyer.carrier.Inbound.Due(context.Background())
	states := buyer.carrier.Inbound.States()
	if len(states) != 1 || states[0].ConsecutiveFailures != 0 {
		t.Fatalf("states = %+v", states)
	}
	gap := time.Unix(states[0].NextPollUnix, 0).Sub(clock.Now())
	if gap < RelayPollInterval-time.Second || gap > RelayPollInterval+RelayPollInterval/5+time.Second {
		t.Fatalf("poll interval %s", gap)
	}
	relay.listFails = true
	var last time.Duration
	for range 8 {
		buyer.pollAll()
		state := buyer.carrier.Inbound.States()[0]
		last = time.Unix(state.NextPollUnix, 0).Sub(clock.Now())
	}
	if last < RelayPollMaxBackoff-time.Second || last > RelayPollMaxBackoff+RelayPollMaxBackoff/5+time.Second {
		t.Fatalf("backoff after repeated failures %s", last)
	}
	state := buyer.carrier.Inbound.States()[0]
	if state.ConsecutiveFailures != 8 || state.LastError != relayErrList {
		t.Fatalf("state = %+v", state)
	}
}

func TestACardTakenByBuyIsUsedByTheRunningServeOfTheSameNode(t *testing.T) {
	clock := newRelayClock()
	agents := relayAgents()
	relay := startFakeRelay(t, clock)
	dir := t.TempDir()
	serving := openRelayTestNode(t, dir, clock, testBuyer, agents, relay)
	seller := newRelayTestNode(t, clock, testSeller, agents, relay)
	// `buy --offer` runs as its own process over the same state directory.
	buying, err := OpenPeerCards(filepath.Join(dir, relayStateDir, relayPeersDir), packetKeys, agents,
		ownersMap{relayCapability: testSeller}, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	buying.AllowLoopbackRelays(true)
	if err = buying.Learn(context.Background(), seller.card(), testSeller, relayCapability); err != nil {
		t.Fatal(err)
	}
	if _, err = serving.courier.Deliver(context.Background(), relayEnvelopeTo(testSeller), markedBody(10)); err != nil {
		t.Fatalf("the running node did not see the card the other process took: %v", err)
	}
	seller.pollAll()
	if len(seller.pending()) != 1 {
		t.Fatal("the packet was not delivered")
	}
}
