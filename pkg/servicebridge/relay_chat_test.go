package servicebridge

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketrelay"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
)

// The Messenger daemon is not run here: it reads finalized state only
// through a chain RPC client, which these tests have no chain for. The
// stand-in below speaks the daemon's half of the carrier boundary over real
// carrierapi sockets with the real relayframe codecs and Ed25519 delivery
// acks, and makes the daemon's admission decision from an allow-list. The
// daemon's own checks (admission, evidence, sessions, ratchets) are outside
// this suite.

// chatMessengerText marks every copy's ciphertext, so its absence from the
// relays' bytes shows they never held a frame in clear.
const chatMessengerText = "chat-relay-plaintext-marker-77d1"

type standInPeer struct {
	endpoint string
	device   string
	public   ed25519.PublicKey
}

// standInDaemon is the Messenger daemon's carrier half for one Agent.
type standInDaemon struct {
	t        *testing.T
	agent    string
	endpoint string
	device   string
	key      ed25519.PrivateKey
	evidence []byte
	cardPath string
	clock    *relayClock
	carrier  *carrierapi.Client
	mutex    sync.Mutex
	admitted map[string]bool
	peers    map[string]standInPeer
	// accepted counts the copies applied, by Event id; a second arrival is a
	// duplicate and never applied again.
	accepted  map[string]int
	delivered map[string]bool
	calls     int
	// retryNext answers retry to that many deliveries.
	retryNext int
}

func standInIDs(agent string) (endpoint, device string) {
	sum := sha256.Sum256([]byte("endpoint\x00" + agent))
	endpoint = "mep_" + hex.EncodeToString(sum[:])
	sum = sha256.Sum256([]byte("device\x00" + agent))
	return endpoint, "dev_" + hex.EncodeToString(sum[:])
}

func newStandInDaemon(t *testing.T, agent string, clock *relayClock) *standInDaemon {
	t.Helper()
	seed := sha256.Sum256([]byte("endpoint-key\x00" + agent))
	endpoint, device := standInIDs(agent)
	evidence, err := relayframe.EncodeEvidence(relayframe.Evidence{
		Delegation: []byte(`{"delegation":"` + agent + `"}`), Policy: []byte(`{"policy":1}`),
		Descriptor: []byte(`{"descriptor":"` + endpoint + `"}`), BundleSet: []byte(`{"bundles":["` + device + `"]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	return &standInDaemon{
		t: t, agent: agent, endpoint: endpoint, device: device, key: ed25519.NewKeyFromSeed(seed[:]),
		evidence: evidence, clock: clock, admitted: map[string]bool{}, peers: map[string]standInPeer{},
		accepted: map[string]int{}, delivered: map[string]bool{},
	}
}

func (d *standInDaemon) card() []byte {
	d.t.Helper()
	card, err := os.ReadFile(d.cardPath)
	if err != nil {
		d.t.Fatal(err)
	}
	return card
}

func (d *standInDaemon) callCount() int {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	return d.calls
}

func (d *standInDaemon) acceptedCount(event string) int {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	return d.accepted[event]
}

func (d *standInDaemon) isDelivered(event string) bool {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	return d.delivered[event]
}

func (d *standInDaemon) frame(kind uint8, part []byte) []byte {
	d.t.Helper()
	frame, err := relayframe.Encode(relayframe.Frame{
		Kind: kind, PartIndex: 0, PartCount: 1, Card: d.card(),
		Evidence: d.evidence, Part: part,
	})
	if err != nil {
		d.t.Fatal(err)
	}
	return frame
}

func chatEventID(label string) string {
	sum := sha256.Sum256([]byte("event\x00" + label))
	return "evt_" + hex.EncodeToString(sum[:])
}

// copyFrame is the kind-1 frame of one copy of event to peer.
func (d *standInDaemon) copyFrame(peer, event string) []byte {
	d.t.Helper()
	d.mutex.Lock()
	info, ok := d.peers[peer]
	d.mutex.Unlock()
	if !ok {
		info.endpoint, info.device = standInIDs(peer)
	}
	sum := sha256.Sum256([]byte("session\x00" + d.agent + peer))
	conversation := sha256.Sum256([]byte("conversation\x00" + d.agent + peer))
	object, err := relayframe.EncodeCopy(relayframe.Copy{
		EventID: event, SessionID: "ses_" + hex.EncodeToString(sum[:]), RecipientEndpointID: info.endpoint,
		RecipientDeviceID: info.device, ConversationID: "conv_" + hex.EncodeToString(conversation[:]),
		Ciphertext:    []byte(chatMessengerText + strings.Repeat("c", 64)),
		ExpiresAtUnix: uint64(d.clock.Now().Add(7 * 24 * time.Hour).Unix()),
	})
	if err != nil {
		d.t.Fatal(err)
	}
	return d.frame(relayframe.KindCopy, object)
}

func chatCopyKey(t *testing.T, event string, generation uint32) string {
	t.Helper()
	key, err := relayframe.CopyIdempotencyKey("dly_"+event, generation)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// carry asks the node's carrier socket to deposit generation of event.
func (d *standInDaemon) carry(peer, event string, generation uint32) carrierapi.Response {
	d.t.Helper()
	withdraw := ""
	if generation > 1 {
		withdraw = chatCopyKey(d.t, event, generation-1)
	}
	response, err := d.carrier.Carry(context.Background(), peer, chatCopyKey(d.t, event, generation), withdraw,
		uint64(d.clock.Now().Add(7*24*time.Hour).Unix()), d.copyFrame(peer, event))
	if err != nil {
		d.t.Fatal(err)
	}
	return response
}

// Carry implements carrierapi.Handler: the daemon does not serve it.
func (d *standInDaemon) Carry(context.Context, carrierapi.Request, []byte) carrierapi.Response {
	return carrierapi.NotServed()
}

// Deliver applies a copy or evidence frame as the daemon's admission would:
// an allow-listed sender is admitted, every other sender is refused with a
// signed rejection.
func (d *standInDaemon) Deliver(_ context.Context, sender string, raw []byte) carrierapi.Response {
	d.mutex.Lock()
	d.calls++
	if d.retryNext > 0 {
		d.retryNext--
		d.mutex.Unlock()
		return carrierapi.Retry()
	}
	admitted := d.admitted[sender]
	d.mutex.Unlock()
	frame, err := relayframe.Decode(raw)
	if err != nil {
		return carrierapi.Refusal(carrierapi.CodeFrameMalformed)
	}
	if frame.Kind == relayframe.KindEvidence {
		if !admitted {
			return carrierapi.Response{Result: carrierapi.ResultIgnored}
		}
		return carrierapi.Response{Result: carrierapi.ResultAdmitted}
	}
	value, err := relayframe.DecodeCopy(frame.Part)
	if err != nil || value.RecipientDeviceID != d.device || value.RecipientEndpointID != d.endpoint {
		return carrierapi.Refusal(carrierapi.CodeNotAccepted)
	}
	outcome, code := relayframe.OutcomeAccepted, fault.Code("")
	d.mutex.Lock()
	switch {
	case !admitted:
		outcome, code = relayframe.OutcomeRejected, fault.CodeRejected
	case d.accepted[value.EventID] > 0:
		outcome = relayframe.OutcomeDuplicate
	default:
		d.accepted[value.EventID]++
	}
	d.mutex.Unlock()
	digest := sha256.Sum256(value.Ciphertext)
	ack, err := relayframe.SignAck(relayframe.Ack{
		EventID: value.EventID, SessionID: value.SessionID, RecipientEndpointID: d.endpoint,
		RecipientDeviceID: d.device, CiphertextDigest: "sha256:" + hex.EncodeToString(digest[:]),
		Outcome: outcome, Code: code, AcceptedAtUnix: uint64(d.clock.Now().Unix()),
	}, d.key)
	if err != nil {
		return carrierapi.Retry()
	}
	object, err := relayframe.EncodeAck(ack)
	if err != nil {
		return carrierapi.Retry()
	}
	return carrierapi.Response{
		Result: carrierapi.ResultAck, AckOutcome: outcome,
		AckFrameBase64: base64.StdEncoding.EncodeToString(d.frame(relayframe.KindDeliveryAck, object)),
	}
}

// DeliveryAck settles a copy on an ack signed by the peer's Endpoint.
func (d *standInDaemon) DeliveryAck(_ context.Context, sender string, raw []byte) carrierapi.Response {
	d.mutex.Lock()
	d.calls++
	peer, known := d.peers[sender]
	d.mutex.Unlock()
	frame, err := relayframe.Decode(raw)
	if err != nil || frame.Kind != relayframe.KindDeliveryAck {
		return carrierapi.Refusal(carrierapi.CodeFrameMalformed)
	}
	ack, err := relayframe.DecodeAck(frame.Part)
	if err != nil {
		return carrierapi.Refusal(carrierapi.CodeFrameMalformed)
	}
	if !known || ack.RecipientEndpointID != peer.endpoint || relayframe.VerifyAck(ack, peer.public) != nil {
		return carrierapi.Refusal(carrierapi.CodeSenderMismatch)
	}
	if ack.Outcome == relayframe.OutcomeRejected {
		return carrierapi.Response{Result: carrierapi.ResultApplied}
	}
	d.mutex.Lock()
	defer d.mutex.Unlock()
	if d.delivered[ack.EventID] {
		return carrierapi.Response{Result: carrierapi.ResultIgnored}
	}
	d.delivered[ack.EventID] = true
	return carrierapi.Response{Result: carrierapi.ResultApplied}
}

// countingAgents counts finalized Agent reads, so a test can show a refusal
// happened before any verification.
type countingAgents struct {
	next  agentpacket.AgentResolver
	mutex sync.Mutex
	reads int
}

func (c *countingAgents) ResolveAgent(id string) (*nativev1.AgentStateV1, bool, error) {
	c.mutex.Lock()
	c.reads++
	c.mutex.Unlock()
	return c.next.ResolveAgent(id)
}

func (c *countingAgents) count() int {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.reads
}

func (c *countingAgents) reset() {
	c.mutex.Lock()
	c.reads = 0
	c.mutex.Unlock()
}

// chatTestNode is one OpenFox node with a chat lane, its stand-in daemon and
// both carrier sockets.
type chatTestNode struct {
	t        *testing.T
	agent    string
	dir      string
	clock    *relayClock
	agents   *countingAgents
	inbox    *Inbox
	carrier  *RelayCarrier
	chat     *ChatCarrier
	daemon   *standInDaemon
	relays   []string
	mutex    sync.Mutex
	reports  []string
	sockets  string
	stopping context.CancelFunc
}

func newChatTestNode(t *testing.T, clock *relayClock, agent string, agents *switchableAgents,
	relays ...string,
) *chatTestNode {
	t.Helper()
	return openChatTestNode(t, t.TempDir(), clock, agent, agents, relays...)
}

func openChatTestNode(t *testing.T, dir string, clock *relayClock, agent string, agents *switchableAgents,
	relays ...string,
) *chatTestNode {
	t.Helper()
	sockets, err := os.MkdirTemp("", "chat")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(sockets, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockets) })
	return openChatTestNodeIn(t, dir, sockets, clock, agent, agents, relays...)
}

// openChatTestNodeIn opens a node whose sockets live in a given private
// directory, which the caller cleans up.
func openChatTestNodeIn(t *testing.T, dir, sockets string, clock *relayClock, agent string,
	agents *switchableAgents, relays ...string,
) *chatTestNode {
	t.Helper()
	var err error
	node := &chatTestNode{
		t: t, agent: agent, dir: dir, clock: clock, agents: &countingAgents{next: agents},
		relays: relays, sockets: sockets,
	}
	node.inbox, err = OpenInbox(filepath.Join(dir, "inbox"), 4, 8)
	if err != nil {
		t.Fatal(err)
	}
	receiver := &Receiver{
		LocalAgentID: agent, Resolver: node.agents, Verifier: packetKeys, Inbox: node.inbox,
		Now: clock.Now,
	}
	if err = ensurePrivateDirectory(filepath.Join(dir, relayStateDir)); err != nil {
		t.Fatal(err)
	}
	railCards, err := OpenPeerCards(filepath.Join(dir, relayStateDir, relayPeersDir), packetKeys, node.agents,
		ownersMap{}, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	railCards.AllowLoopbackRelays(true)
	node.daemon = newStandInDaemon(t, agent, clock)
	node.daemon.cardPath = filepath.Join(dir, relayStateDir, "chat-card.json")
	ctx, cancel := context.WithCancel(context.Background())
	node.stopping = cancel
	t.Cleanup(cancel)
	daemonSocket := filepath.Join(sockets, "d.sock")
	listener, err := carrierapi.Listen(daemonSocket)
	if err != nil {
		t.Fatal(err)
	}
	server, err := carrierapi.NewServer(node.daemon, 0)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(ctx, listener) }()
	t.Cleanup(func() { _ = listener.Close() })
	client, err := carrierapi.NewClient(daemonSocket, 0)
	if err != nil {
		t.Fatal(err)
	}
	signer := testSigner(t, agent)
	signer.now = clock.Now
	node.carrier, err = OpenRelayCarrier(RelayCarrierConfig{
		StateDir: dir, AgentID: agent, Relays: relays, Signer: signer, Cards: railCards, Receiver: receiver,
		Now: clock.Now, Report: func(stage string, err error) {
			node.mutex.Lock()
			node.reports = append(node.reports, stage+": "+err.Error())
			node.mutex.Unlock()
		},
		Chat: &chatLaneConfig{Relays: relays, CardPath: node.daemon.cardPath, Signer: signer, Daemon: client},
	})
	if err != nil {
		t.Fatal(err)
	}
	node.chat = node.carrier.Chat
	if _, err = node.chat.Republish(context.Background()); err != nil {
		t.Fatal(err)
	}
	carrierSocket := filepath.Join(sockets, "c.sock")
	serve, err := node.chat.ListenCarrier(carrierSocket)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = serve(ctx) }()
	node.daemon.carrier, err = carrierapi.NewClient(carrierSocket, 0)
	if err != nil {
		t.Fatal(err)
	}
	return node
}

func (n *chatTestNode) reportText() string {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	return strings.Join(n.reports, "\n")
}

func (n *chatTestNode) pollAll() {
	for _, relay := range n.relays {
		n.carrier.Inbound.Poll(context.Background(), relay)
	}
}

func (n *chatTestNode) redeposit() {
	n.t.Helper()
	if err := n.chat.Transport.Redeposit(context.Background()); err != nil {
		n.t.Fatal(err)
	}
}

// contactOf is node's contact file, as `chat contact export` writes it.
func (n *chatTestNode) contactOf() []byte {
	n.t.Helper()
	contact, err := relayframe.EncodeContactJSON(relayframe.Contact{
		AgentID: n.agent, Evidence: n.daemon.evidence, Card: n.daemon.card(),
	})
	if err != nil {
		n.t.Fatal(err)
	}
	wrapped, err := json.Marshal(chatContactFile{Schema: ChatContactSchema, RelayContact: contact})
	if err != nil {
		n.t.Fatal(err)
	}
	return wrapped
}

// importContact makes n hold peer's chat card from its contact file, as the
// owner's import does; the daemon is told of the peer's Endpoint.
func (n *chatTestNode) importContact(peer *chatTestNode) {
	n.t.Helper()
	if _, err := importChatContact(context.Background(), n.chat.Cards, filepath.Join(n.dir, "contacts"), n.agent,
		peer.contactOf()); err != nil {
		n.t.Fatal(err)
	}
	n.knowEndpoint(peer)
}

// knowEndpoint tells n's daemon the peer's Endpoint and device, as its
// committed evidence would, without admitting the peer.
func (n *chatTestNode) knowEndpoint(peer *chatTestNode) {
	n.daemon.mutex.Lock()
	n.daemon.peers[peer.agent] = standInPeer{
		endpoint: peer.daemon.endpoint, device: peer.daemon.device,
		public: peer.daemon.key.Public().(ed25519.PublicKey),
	}
	n.daemon.mutex.Unlock()
}

// admit makes n's daemon admit sender, as an allow-listed contact or a used
// invite would.
func (n *chatTestNode) admit(sender *chatTestNode) {
	n.knowEndpoint(sender)
	n.daemon.mutex.Lock()
	n.daemon.admitted[sender.agent] = true
	n.daemon.mutex.Unlock()
}

func listedAt(t *testing.T, relay, agent string) []agentpacketrelay.MailboxEntry {
	t.Helper()
	return listed(t, relay, agent)
}

// startClosableRelay runs a reference relay that a test can take down.
func startClosableRelay(t *testing.T, clock *relayClock) *httptest.Server {
	t.Helper()
	return startConfiguredRelay(t, clock, agentpacketrelay.RateLimit{})
}

// startConfiguredRelay runs a reference relay with a deposit rate; a zero
// rate takes the relay's default. Every node of a test deposits from one
// loopback address, so a test that fills the in-flight cap from two nodes
// needs more than the default burst of one address.
func startConfiguredRelay(t *testing.T, clock *relayClock, deposit agentpacketrelay.RateLimit) *httptest.Server {
	t.Helper()
	store, err := agentpacketrelay.NewMemoryStore(agentpacketrelay.DefaultLimits(4096, 64<<20))
	if err != nil {
		t.Fatal(err)
	}
	config := agentpacketrelay.ServerConfig{Store: store, Now: clock.Now, DepositRate: deposit}
	if deposit != (agentpacketrelay.RateLimit{}) {
		config.ReadRate = agentpacketrelay.RateLimit{PerMinute: 60000, Burst: 10000}
	}
	server, err := agentpacketrelay.NewServer(config)
	if err != nil {
		t.Fatal(err)
	}
	listener := httptest.NewServer(server)
	t.Cleanup(listener.Close)
	return listener
}

func requireResult(t *testing.T, response carrierapi.Response, result carrierapi.Result, code carrierapi.Code) {
	t.Helper()
	if response.Result != result || response.Code != code {
		t.Fatalf("carrier answered %s %s, want %s %s", response.Result, response.Code, result, code)
	}
}

// chatPair is A and B, each with a chat lane on the same relays: B admits A
// and holds nothing of A's; A imported B's contact file.
func chatPair(t *testing.T, clock *relayClock, relays ...string) (*chatTestNode, *chatTestNode) {
	t.Helper()
	agents := relayAgents()
	a := newChatTestNode(t, clock, testSeller, agents, relays...)
	b := newChatTestNode(t, clock, testBuyer, agents, relays...)
	a.importContact(b)
	a.admit(b)
	b.admit(a)
	return a, b
}

func TestChatCrossesARealRelayAndIsDeliveredOnlyOnAVerifiedAck(t *testing.T) {
	clock := newRelayClock()
	relayA, relayB := startRealRelay(t, clock), startRealRelay(t, clock)
	a, b := chatPair(t, clock, relayA, relayB)
	if b.chat.Cards.Has(a.agent) {
		t.Fatal("B holds A's card before any contact")
	}
	event := chatEventID("hello")
	requireResult(t, a.daemon.carry(b.agent, event, 1), carrierapi.ResultCarried, "")
	a.redeposit()
	if len(listedAt(t, relayA, b.agent)) != 1 || len(listedAt(t, relayB, b.agent)) != 1 {
		t.Fatal("the copy is not held at both relays of B's chat card")
	}
	b.pollAll()
	if b.daemon.acceptedCount(event) != 1 {
		t.Fatalf("B applied the copy %d times", b.daemon.acceptedCount(event))
	}
	// B learned A's card in band, from the frame its daemon admitted.
	if !b.chat.Cards.Has(a.agent) {
		t.Fatalf("B did not learn A's card in band: %s", b.reportText())
	}
	if len(listedAt(t, relayA, b.agent)) != 0 || len(listedAt(t, relayB, b.agent)) != 0 {
		t.Fatal("B did not relay-acknowledge the copy at both relays")
	}
	if a.daemon.isDelivered(event) {
		t.Fatal("the copy counts as delivered before A received the signed ack")
	}
	a.pollAll()
	if !a.daemon.isDelivered(event) {
		t.Fatalf("A did not apply B's delivery ack: %s", a.reportText())
	}
	// B answers over the relay too: its daemon carries a reply to A.
	reply := chatEventID("reply")
	requireResult(t, b.daemon.carry(a.agent, reply, 1), carrierapi.ResultCarried, "")
	a.pollAll()
	b.pollAll()
	if a.daemon.acceptedCount(reply) != 1 || !b.daemon.isDelivered(reply) {
		t.Fatal("the reply was not delivered and acknowledged")
	}
	for _, relay := range []string{relayA, relayB} {
		if len(listedAt(t, relay, a.agent)) != 0 || len(listedAt(t, relay, b.agent)) != 0 {
			t.Fatal("an envelope is left at a relay after the conversation")
		}
	}
	// Every journaled envelope is exactly 1,373 + F + 4*ceil(B/3) bytes for a
	// bucket-sized frame and F inside the fixed-field range.
	for _, node := range []*chatTestNode{a, b} {
		checkChatEnvelopeSizes(t, node)
	}
}

func checkChatEnvelopeSizes(t *testing.T, node *chatTestNode) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(node.dir, relayStateDir, relayChatOutboxDir))
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, entry := range entries {
		if !relayOutboxFilePattern.MatchString(entry.Name()) {
			continue
		}
		var record relayOutboxRecord
		if err := readJSON(filepath.Join(node.dir, relayStateDir, relayChatOutboxDir, entry.Name()), 1<<20,
			&record); err != nil {
			t.Fatal(err)
		}
		packetJSON, _ := base64.StdEncoding.DecodeString(record.PacketBase64)
		envelope, _ := base64.StdEncoding.DecodeString(record.EnvelopeBase64)
		packet, err := agentpacket.DecodeJSON(packetJSON)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = relayframe.Decode(packet.Payload); err != nil {
			t.Fatalf("a journaled frame is not a canonical bucket-sized frame: %v", err)
		}
		fixed := len(packetJSON) - len(base64.StdEncoding.EncodeToString(packet.Payload))
		want, err := relayframe.EnvelopeSize(len(packet.Payload), fixed)
		if err != nil {
			// The test signer's signatures are not ML-DSA-44 sized; the formula
			// is checked against this packet's own fixed fields instead.
			want = relayframe.SealOverheadBytes + fixed + 4*((len(packet.Payload)+2)/3)
		}
		if len(envelope) != want {
			t.Fatalf("envelope of %d bytes, the formula gives %d", len(envelope), want)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no journaled chat envelope was checked")
	}
}

func TestARefusedStrangersInBandCardIsNeverStored(t *testing.T) {
	clock := newRelayClock()
	relay := startRealRelay(t, clock)
	agents := relayAgents()
	stranger := newChatTestNode(t, clock, relayThird, agents, relay)
	b := newChatTestNode(t, clock, testBuyer, agents, relay)
	// The stranger holds B's card (anyone may fetch a contact file); B's
	// daemon has not admitted the stranger.
	stranger.importContact(b)
	b.knowEndpoint(stranger)
	event := chatEventID("spam")
	requireResult(t, stranger.daemon.carry(b.agent, event, 1), carrierapi.ResultCarried, "")
	b.pollAll()
	if b.daemon.callCount() != 1 {
		t.Fatalf("B's daemon was asked %d times", b.daemon.callCount())
	}
	if b.chat.Cards.Has(stranger.agent) {
		t.Fatal("B stored the card of a stranger its daemon refused")
	}
	if len(b.chat.Cards.List()) != 0 {
		t.Fatal("B's chat card store is not empty")
	}
	if len(listedAt(t, relay, b.agent)) != 0 {
		t.Fatal("the refused copy was not relay-acknowledged")
	}
	if len(listedAt(t, relay, stranger.agent)) != 0 {
		t.Fatal("B sent an ack to a stranger whose card it must not hold")
	}
	// An evidence request of the stranger is ignored the same way.
	request := stranger.daemon.frame(relayframe.KindEvidence, []byte{relayframe.EvidenceRequest})
	key, err := relayframe.EvidenceRequestKey(b.agent, 1)
	if err != nil {
		t.Fatal(err)
	}
	response, err := stranger.daemon.carrier.Carry(context.Background(), b.agent, key, "",
		uint64(clock.Now().Add(time.Hour).Unix()), request)
	if err != nil {
		t.Fatal(err)
	}
	requireResult(t, response, carrierapi.ResultCarried, "")
	b.pollAll()
	if b.chat.Cards.Has(stranger.agent) || len(listedAt(t, relay, b.agent)) != 0 {
		t.Fatal("a stranger's evidence frame left its card stored or its envelope unacknowledged")
	}
	// Once B's daemon admits the sender, the same in-band card is kept.
	b.admit(stranger)
	requireResult(t, stranger.daemon.carry(b.agent, chatEventID("admitted"), 1), carrierapi.ResultCarried, "")
	b.pollAll()
	if !b.chat.Cards.Has(stranger.agent) {
		t.Fatalf("B did not keep the card of a sender its daemon admitted: %s", b.reportText())
	}
}

// chatFramePacket is a signed chat packet to recipient carrying a relay frame.
func chatFramePacket(t *testing.T, sender *chatTestNode, recipient string) []byte {
	t.Helper()
	frame := sender.daemon.copyFrame(recipient, chatEventID("wrong-key"))
	packet, err := testSigner(t, sender.agent).sign(context.Background(), recipient, chatCapability, "", frame)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := agentpacket.EncodeJSON(packet)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestPurposeIsEnforcedAtTheKeyBeforeAnySideEffect(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	agents := relayAgents()
	a := newChatTestNode(t, clock, testSeller, agents, relay.URL)
	b := newChatTestNode(t, clock, testBuyer, agents, relay.URL)
	b.admit(a)
	chatKey, err := b.chat.Keys.Current(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	railKey, err := b.carrier.Keys.Current(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if chatKey.KeyID == railKey.KeyID || bytes.Equal(chatKey.CardJSON, railKey.CardJSON) {
		t.Fatal("the chat key and the rail key are one key")
	}
	// A rail packet sealed to B's chat key.
	sealToKey(t, relay, b.agent, chatKey, framePacket(t, a.agent, b.agent), clock)
	// A chat frame sealed to B's rail key.
	sealToKey(t, relay, b.agent, railKey, chatFramePacket(t, a, b.agent), clock)
	b.agents.reset()
	b.pollAll()
	if relay.count(b.agent) != 0 {
		t.Fatal("a wrong-purpose envelope was not relay-acknowledged")
	}
	if reads := b.agents.count(); reads != 0 {
		t.Fatalf("finalized state was read %d times for wrong-purpose packets", reads)
	}
	if b.daemon.callCount() != 0 {
		t.Fatal("a rail packet reached the Messenger daemon")
	}
	if pending, err := b.inbox.Pending(); err != nil || len(pending) != 0 {
		t.Fatalf("a chat frame reached the rail inbox: %d, %v", len(pending), err)
	}
	if len(b.chat.Cards.List()) != 0 {
		t.Fatal("a wrong-purpose packet left a card stored")
	}
	// The right purposes still pass: a chat frame under the chat key reaches
	// the daemon.
	sealToKey(t, relay, b.agent, chatKey, chatFramePacket(t, a, b.agent), clock)
	b.pollAll()
	if b.daemon.callCount() != 1 {
		t.Fatalf("a chat frame under the chat key was not handed to the daemon: %s", b.reportText())
	}
}

func TestAChatKeyFileIsRefusedAsARailKeyAndTheReverse(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	node := newChatTestNode(t, clock, testSeller, relayAgents(), relay.URL)
	chatKey := node.chat.Keys.Held()[0]
	name := hex.EncodeToString(chatKey.KeyID[:]) + ".json"
	raw, err := os.ReadFile(filepath.Join(node.dir, relayStateDir, relayChatKeysDir, name))
	if err != nil {
		t.Fatal(err)
	}
	railDir := filepath.Join(t.TempDir(), "keys")
	if err := ensurePrivateDirectory(railDir); err != nil {
		t.Fatal(err)
	}
	if err := writeSynced(filepath.Join(railDir, name), raw); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRelayKeys(railDir, node.agent, []string{relay.URL}, testSigner(t, node.agent),
		clock.Now); err == nil {
		t.Fatal("a chat key file was loaded as a rail key")
	}
	if _, err := OpenChatRelayKeys(railDir, node.agent, []string{relay.URL}, testSigner(t, node.agent),
		clock.Now); err != nil {
		t.Fatalf("the chat key file does not load as a chat key: %v", err)
	}
}

func TestGenerationNIsWithdrawnOnceGenerationNPlusOneIsAccepted(t *testing.T) {
	clock := newRelayClock()
	relayA, relayB := startRealRelay(t, clock), startRealRelay(t, clock)
	a, b := chatPair(t, clock, relayA, relayB)
	event := chatEventID("offline")
	requireResult(t, a.daemon.carry(b.agent, event, 1), carrierapi.ResultCarried, "")
	a.redeposit()
	first := listedAt(t, relayA, b.agent)
	if len(first) != 1 || len(listedAt(t, relayB, b.agent)) != 1 {
		t.Fatal("generation 1 is not held at both relays")
	}
	// B stays offline past the re-deposit interval; generation 2 replaces 1.
	clock.Advance(20 * time.Hour)
	requireResult(t, a.daemon.carry(b.agent, event, 2), carrierapi.ResultCarried, "")
	a.redeposit()
	for _, relay := range []string{relayA, relayB} {
		entries := listedAt(t, relay, b.agent)
		if len(entries) != 1 || entries[0].EnvelopeID == first[0].EnvelopeID {
			t.Fatalf("relay %s lists %d envelopes; generation 1 was not withdrawn", relay, len(entries))
		}
	}
	// Generation 1's key is never deposited again, even if asked.
	requireResult(t, a.daemon.carry(b.agent, event, 1), carrierapi.ResultRefused, carrierapi.CodeInvalidRequest)
	b.pollAll()
	if b.daemon.acceptedCount(event) != 1 {
		t.Fatalf("B applied the message %d times", b.daemon.acceptedCount(event))
	}
	a.pollAll()
	if !a.daemon.isDelivered(event) {
		t.Fatalf("generation 2 was not acknowledged: %s", a.reportText())
	}
	// A third generation after B acknowledged is answered duplicate and
	// never applied again.
	requireResult(t, a.daemon.carry(b.agent, event, 3), carrierapi.ResultCarried, "")
	b.pollAll()
	if b.daemon.acceptedCount(event) != 1 {
		t.Fatal("a later generation was applied again")
	}
}

func TestThePeerCapCountsStoredAcksAndFreesOnceThePeerAcknowledged(t *testing.T) {
	clock := newRelayClock()
	relay := startConfiguredRelay(t, clock, agentpacketrelay.RateLimit{PerMinute: 6000, Burst: 1000}).URL
	a, b := chatPair(t, clock, relay)
	b.importContact(a)
	for index := range ChatPeerEnvelopeCap {
		requireResult(t, a.daemon.carry(b.agent, chatEventID(fmt.Sprint("m", index)), 1), carrierapi.ResultCarried, "")
	}
	// A's own copies to B fill the cap while B is offline.
	requireResult(t, a.daemon.carry(b.agent, chatEventID("over"), 1), carrierapi.ResultRefused,
		carrierapi.CodePeerCap)
	// B receives all of them and answers one ack each, which A does not
	// fetch: B's stored acks now fill B's cap towards A.
	b.pollAll()
	if len(listedAt(t, relay, a.agent)) != ChatPeerEnvelopeCap {
		t.Fatalf("A's mailbox lists %d acks: %s", len(listedAt(t, relay, a.agent)), b.reportText())
	}
	requireResult(t, b.daemon.carry(a.agent, chatEventID("b-over"), 1), carrierapi.ResultRefused,
		carrierapi.CodePeerCap)
	// B relay-acknowledged A's copies: A's count drops once it reads B's
	// mailbox listing, and A may carry again.
	requireResult(t, a.daemon.carry(b.agent, chatEventID("over"), 1), carrierapi.ResultCarried, "")
	// A fetches and acknowledges the acks: B may carry again.
	a.pollAll()
	requireResult(t, b.daemon.carry(a.agent, chatEventID("b-over"), 1), carrierapi.ResultCarried, "")
}

func TestCarryRefusesWithoutAPeerCardAndInvalidRequests(t *testing.T) {
	clock := newRelayClock()
	relay := startRealRelay(t, clock)
	a, b := chatPair(t, clock, relay)
	ctx := context.Background()
	expires := uint64(clock.Now().Add(time.Hour).Unix())
	frame := a.daemon.copyFrame(relayThird, chatEventID("x"))
	key := chatCopyKey(t, chatEventID("x"), 1)
	response, err := a.daemon.carrier.Carry(ctx, relayThird, key, "", expires, frame)
	if err != nil {
		t.Fatal(err)
	}
	requireResult(t, response, carrierapi.ResultRefused, carrierapi.CodeNoPeerCard)
	cases := []struct {
		name      string
		recipient string
		expires   uint64
		frame     []byte
		code      carrierapi.Code
	}{
		{"self", a.agent, expires, frame, carrierapi.CodeInvalidRequest},
		{"expired", b.agent, uint64(clock.Now().Add(-time.Second).Unix()), frame, carrierapi.CodeInvalidRequest},
		{
			"ack kind",
			b.agent,
			expires,
			a.daemon.frame(relayframe.KindDeliveryAck, []byte{1}),
			carrierapi.CodeKindNotCarried,
		},
		{
			"another card",
			b.agent,
			expires,
			b.daemon.copyFrame(a.agent, chatEventID("y")),
			carrierapi.CodeFrameMalformed,
		},
		{"not a frame", b.agent, expires, bytes.Repeat([]byte{7}, 1024), carrierapi.CodeFrameMalformed},
	}
	for _, test := range cases {
		answer, carryErr := a.daemon.carrier.Carry(ctx, test.recipient, key, "", test.expires, test.frame)
		if carryErr != nil {
			t.Fatalf("%s: %v", test.name, carryErr)
		}
		if answer.Result != carrierapi.ResultRefused || answer.Code != test.code {
			t.Fatalf("%s: answered %s %s, want %s", test.name, answer.Result, answer.Code, test.code)
		}
	}
	if len(listedAt(t, relay, b.agent)) != 0 || len(listedAt(t, relay, relayThird)) != 0 {
		t.Fatal("a refused carry deposited something")
	}
	// A key journaled for B is not carried to another peer, and a withdrawal
	// never names another peer's envelope.
	requireResult(t, a.daemon.carry(b.agent, chatEventID("x"), 1), carrierapi.ResultCarried, "")
	a.importContact(newChatTestNode(t, clock, relayThird, relayAgents(), relay))
	response, err = a.daemon.carrier.Carry(ctx, relayThird, key, "", expires, frame)
	if err != nil {
		t.Fatal(err)
	}
	requireResult(t, response, carrierapi.ResultRefused, carrierapi.CodeInvalidRequest)
	response, err = a.daemon.carrier.Carry(ctx, relayThird, chatCopyKey(t, chatEventID("x"), 2), key, expires,
		frame)
	if err != nil {
		t.Fatal(err)
	}
	requireResult(t, response, carrierapi.ResultRefused, carrierapi.CodeInvalidRequest)
}

func TestWithRelayOneDownTheSecondRelayCarriesTheConversation(t *testing.T) {
	clock := newRelayClock()
	one, two := startClosableRelay(t, clock), startClosableRelay(t, clock)
	a, b := chatPair(t, clock, one.URL, two.URL)
	one.Close()
	event := chatEventID("outage")
	requireResult(t, a.daemon.carry(b.agent, event, 1), carrierapi.ResultCarried, "")
	b.pollAll()
	a.pollAll()
	if b.daemon.acceptedCount(event) != 1 || !a.daemon.isDelivered(event) {
		t.Fatalf("the conversation did not cross relay two: %s / %s", a.reportText(), b.reportText())
	}
}

func TestAPreDepositedJunkIDAtOneRelayIsAbandonedThereAndTheOtherDelivers(t *testing.T) {
	clock := newRelayClock()
	race, honest := startFakeRelay(t, clock), startFakeRelay(t, clock)
	race.mutex.Lock()
	race.conflictAll = true
	race.mutex.Unlock()
	a, b := chatPair(t, clock, race.URL, honest.URL)
	event := chatEventID("race")
	requireResult(t, a.daemon.carry(b.agent, event, 1), carrierapi.ResultCarried, "")
	a.redeposit()
	views, err := ReadRelayOutbox(filepath.Join(a.dir, relayStateDir, relayChatOutboxDir))
	if err != nil || len(views) != 1 {
		t.Fatalf("chat outbox: %d, %v", len(views), err)
	}
	if len(views[0].Conflicts) != 1 || views[0].Conflicts[0] != race.URL || len(views[0].Pending) != 0 {
		t.Fatalf("the 409 relay was not abandoned for this envelope: %+v", views[0])
	}
	b.pollAll()
	a.pollAll()
	if b.daemon.acceptedCount(event) != 1 || !a.daemon.isDelivered(event) {
		t.Fatal("the honest relay did not deliver the copy")
	}
}

func TestACrashBetweenDepositAndJournalRetriesTheSameEnvelope(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	a, b := chatPair(t, clock, relay.URL)
	event := chatEventID("ambiguous")
	// The relay stores the envelope and the answer is lost.
	relay.mutex.Lock()
	relay.storeThenFail = true
	relay.mutex.Unlock()
	requireResult(t, a.daemon.carry(b.agent, event, 1), carrierapi.ResultRetry, "")
	if relay.count(b.agent) != 1 {
		t.Fatal("the ambiguous deposit did not store the envelope")
	}
	stored := onlyEnvelopeID(t, relay, b.agent)
	// The daemon retries the same key: the journaled envelope is sent again,
	// byte for byte, and the relay recognizes it.
	requireResult(t, a.daemon.carry(b.agent, event, 1), carrierapi.ResultCarried, "")
	if relay.count(b.agent) != 1 || onlyEnvelopeID(t, relay, b.agent) != stored {
		t.Fatal("the retry deposited another envelope")
	}
	// The daemon dies after carried but before recording it: the same key is
	// answered carried with no new deposit.
	deposits := len(relay.depositLog())
	requireResult(t, a.daemon.carry(b.agent, event, 1), carrierapi.ResultCarried, "")
	if len(relay.depositLog()) != deposits {
		t.Fatal("a retry of an accepted key deposited again")
	}
	// A restarted carrier over the same state answers the same.
	restarted := openChatTestNode(t, a.dir, clock, a.agent, relayAgents(), relay.URL)
	requireResult(t, restarted.daemon.carry(b.agent, event, 1), carrierapi.ResultCarried, "")
	if len(relay.depositLog()) != deposits {
		t.Fatal("a restarted carrier deposited an accepted key again")
	}
	b.pollAll()
	if b.daemon.acceptedCount(event) != 1 {
		t.Fatal("the copy was not applied exactly once")
	}
}

func TestARecipientThatDiesBeforeTheRelayAckIsAnsweredDuplicateWithTheSameAck(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	a, b := chatPair(t, clock, relay.URL)
	event := chatEventID("restart")
	requireResult(t, a.daemon.carry(b.agent, event, 1), carrierapi.ResultCarried, "")
	// B's daemon applied it, but B's relay ack fails: the envelope stays.
	relay.mutex.Lock()
	relay.ackFails = 1
	relay.mutex.Unlock()
	b.pollAll()
	if b.daemon.acceptedCount(event) != 1 || relay.count(b.agent) != 1 {
		t.Fatal("the setup did not leave the applied copy listed")
	}
	// B restarts and polls again: the copy is answered duplicate, the ack
	// envelope journaled the first time is reused, and the copy is acked.
	restarted := openChatTestNode(t, b.dir, clock, b.agent, relayAgents(), relay.URL)
	restarted.admit(a)
	restarted.daemon.mutex.Lock()
	restarted.daemon.accepted[event] = 1
	restarted.daemon.mutex.Unlock()
	restarted.pollAll()
	if relay.count(b.agent) != 0 {
		t.Fatal("the redelivered copy was not relay-acknowledged")
	}
	if relay.count(a.agent) != 1 {
		t.Fatalf("A's mailbox lists %d acks, want the one journaled ack", relay.count(a.agent))
	}
	a.pollAll()
	if !a.daemon.isDelivered(event) {
		t.Fatal("A did not settle the copy")
	}
}

func TestADaemonRetryLeavesTheEnvelopeListed(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	a, b := chatPair(t, clock, relay.URL)
	b.daemon.retryNext = 1
	event := chatEventID("retry")
	requireResult(t, a.daemon.carry(b.agent, event, 1), carrierapi.ResultCarried, "")
	b.pollAll()
	if relay.count(b.agent) != 1 || b.daemon.acceptedCount(event) != 0 {
		t.Fatal("a retry answer did not leave the envelope listed")
	}
	b.pollAll()
	if relay.count(b.agent) != 0 || b.daemon.acceptedCount(event) != 1 {
		t.Fatal("the next poll did not deliver the copy")
	}
}

func TestWithdrawIsJournaledIdempotentAndFinal(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	a, b := chatPair(t, clock, relay.URL)
	key := chatCopyKey(t, chatEventID("w"), 1)
	if found, err := a.chat.Transport.Withdraw(key); err != nil || found {
		t.Fatalf("withdrawing an unknown key: %v, %v", found, err)
	}
	if _, err := a.chat.Transport.Withdraw("idem_nope"); err == nil {
		t.Fatal("an invalid key was accepted")
	}
	requireResult(t, a.daemon.carry(b.agent, chatEventID("w"), 1), carrierapi.ResultCarried, "")
	for range 2 {
		if found, err := a.chat.Transport.Withdraw(key); err != nil || !found {
			t.Fatalf("withdraw: %v, %v", found, err)
		}
	}
	a.redeposit()
	if relay.count(b.agent) != 0 {
		t.Fatal("the withdrawn envelope is still held")
	}
	packet, found, err := a.chat.Transport.journaled(key)
	if err != nil || !found {
		t.Fatal(err)
	}
	if err := a.chat.Transport.Send(context.Background(), packet); !errors.Is(err, ErrRelayWithdrawn) {
		t.Fatalf("a withdrawn key was sent again: %v", err)
	}
}

func TestChatContactImportVerifiesBeforeWritingAnything(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	agents := relayAgents()
	a := newChatTestNode(t, clock, testSeller, agents, relay.URL)
	b := newChatTestNode(t, clock, testBuyer, agents, relay.URL)
	contacts := filepath.Join(a.dir, "contacts")
	ctx := context.Background()
	if _, err := importChatContact(ctx, a.chat.Cards, contacts, a.agent, a.contactOf()); err == nil {
		t.Fatal("a node imported its own contact")
	}
	// B's evidence with A's card: the card is not of the contact's Agent.
	forged, err := relayframe.EncodeContactJSON(relayframe.Contact{
		AgentID: b.agent, Evidence: b.daemon.evidence, Card: a.daemon.card(),
	})
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := json.Marshal(chatContactFile{Schema: ChatContactSchema, RelayContact: forged})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := importChatContact(ctx, a.chat.Cards, contacts, a.agent, wrapped); err == nil {
		t.Fatal("a contact whose card is another Agent's was imported")
	}
	// A revoked signer: the card no longer verifies against finalized state.
	agents.revoke(b.agent)
	if _, err := importChatContact(ctx, a.chat.Cards, contacts, a.agent, b.contactOf()); err == nil {
		t.Fatal("a card that does not verify was imported")
	}
	for _, raw := range [][]byte{
		nil, []byte(`{}`), []byte(`{"schema":"x","relay_contact":{}}`),
		append(b.contactOf(), ' ', '{', '}'),
	} {
		if _, err := importChatContact(ctx, a.chat.Cards, contacts, a.agent, raw); err == nil {
			t.Fatalf("a malformed contact file was imported: %q", raw)
		}
	}
	if _, err := os.Stat(contacts); !errors.Is(err, os.ErrNotExist) || len(a.chat.Cards.List()) != 0 {
		t.Fatal("a refused import wrote something")
	}
}

func TestChatConfigurationIsValidatedAgainstTheNode(t *testing.T) {
	base := NodeConfig{
		RelayURLs: []string{"https://relay.example"}, ReceiverSocket: "/state/rail.sock",
		Chat: &ChatConfig{
			CarrierSocket: "/state/chat.sock", MessengerCarrierSocket: "/run/m/carrier.sock",
			CardPath: "/state/relay/chat-card.json",
		},
	}
	if err := validateChatConfig(base); err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*NodeConfig){
		"messenger transport": func(c *NodeConfig) { c.MessengerSocket = "/run/m/local.sock" },
		"no rail relays":      func(c *NodeConfig) { c.RelayURLs = nil },
		"same sockets":        func(c *NodeConfig) { c.Chat.MessengerCarrierSocket = c.Chat.CarrierSocket },
		"receiver socket":     func(c *NodeConfig) { c.Chat.CarrierSocket = c.ReceiverSocket },
		"relative card":       func(c *NodeConfig) { c.Chat.CardPath = "chat-card.json" },
		"empty carrier":       func(c *NodeConfig) { c.Chat.CarrierSocket = "" },
		"bad chat relay":      func(c *NodeConfig) { c.Chat.RelayURLs = []string{"http://relay.example"} },
		"long socket":         func(c *NodeConfig) { c.Chat.CarrierSocket = "/" + strings.Repeat("s", 120) },
		"relative contacts":   func(c *NodeConfig) { c.Chat.ContactDir = "contacts" },
	}
	for name, mutate := range mutations {
		config := base
		chat := *base.Chat
		config.Chat = &chat
		mutate(&config)
		if err := validateChatConfig(config); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	_, err := OpenNode(context.Background(), NodeConfig{
		StateDir: t.TempDir(), RelayURLs: base.RelayURLs, MessengerSocket: "/run/m/local.sock",
		Chat: base.Chat,
	}, NodeOptions{})
	if err == nil || !strings.Contains(err.Error(), "exclude each other") {
		t.Fatalf("a node combining chat carriage with the Messenger transport was not refused for it: %v", err)
	}
}

func TestTheChatCardIsPublishedOnlyWhenItChangesAndWithinTheFrameBound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "card", "chat-card.json")
	card := []byte(`{"card":1}`)
	if err := publishChatCard(path, card); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = publishChatCard(path, card); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("an unchanged card was written again")
	}
	if err = publishChatCard(path, bytes.Repeat([]byte{'x'}, relayframe.MaxCardBytes+1)); err == nil {
		t.Fatal("a card above the frame's card bound was published")
	}
	for _, bad := range []string{"", "relative/card.json"} {
		if publishChatCard(bad, card) == nil {
			t.Fatalf("published to %q", bad)
		}
	}
	if publishChatCard(path, nil) == nil {
		t.Fatal("an empty card was published")
	}
	if got, readErr := os.ReadFile(path); readErr != nil || !bytes.Equal(got, card) {
		t.Fatal("a refused publication changed the card")
	}
}

func TestTheRailPacketBoundStaysWhileChatTakesTheSealedPacketBound(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	node := newChatTestNode(t, clock, testSeller, relayAgents(), relay.URL)
	if node.carrier.Transport.maxPacket != maxPacketJSON {
		t.Fatalf("the rail bound is %d", node.carrier.Transport.maxPacket)
	}
	if node.chat.Transport.maxPacket != agentpacketseal.MaxPacketJSONBytes {
		t.Fatalf("the chat bound is %d", node.chat.Transport.maxPacket)
	}
	big := OutboundPacket{
		RecipientAgentID: testBuyer, JSON: bytes.Repeat([]byte{'x'}, maxPacketJSON+1),
		IdempotencyKey: "idem_" + strings.Repeat("ab", 32), ExpiresAtUnix: uint64(clock.Now().Add(time.Hour).Unix()),
	}
	if err := node.carrier.Transport.Send(context.Background(), big); !errors.Is(err, ErrRelayPacketTooLarge) {
		t.Fatalf("the rail sent a packet over its bound: %v", err)
	}
	if err := node.chat.Transport.Send(context.Background(), big); errors.Is(err, ErrRelayPacketTooLarge) {
		t.Fatal("chat refused a packet inside the sealed packet bound")
	}
	big.JSON = bytes.Repeat([]byte{'x'}, agentpacketseal.MaxPacketJSONBytes+1)
	if err := node.chat.Transport.Send(context.Background(), big); !errors.Is(err, ErrRelayPacketTooLarge) {
		t.Fatalf("chat sent a packet over the sealed bound: %v", err)
	}
}

func TestNoChatPlaintextReachesTheRelays(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	relay.mutex.Lock()
	relay.replay = true
	relay.mutex.Unlock()
	a, b := chatPair(t, clock, relay.URL)
	requireResult(t, a.daemon.carry(b.agent, chatEventID("secret"), 1), carrierapi.ResultCarried, "")
	b.pollAll()
	all := relay.allBytes()
	for _, marker := range []string{
		chatMessengerText, a.daemon.endpoint, b.daemon.endpoint, b.daemon.device,
		chatEventID("secret"),
	} {
		if bytes.Contains(all, []byte(marker)) {
			t.Fatalf("a relay holds %q in clear", marker)
		}
	}
	if len(all) == 0 {
		t.Fatal("the control found nothing stored at all")
	}
}

func TestTheChatFrameDomainIsTheRelayFrameSeparator(t *testing.T) {
	evidence, err := relayframe.EncodeEvidence(relayframe.Evidence{
		Delegation: []byte{1}, Policy: []byte{2},
		Descriptor: []byte{3}, BundleSet: []byte{4},
	})
	if err != nil {
		t.Fatal(err)
	}
	frame, err := relayframe.Encode(relayframe.Frame{
		Kind: relayframe.KindEvidence, PartIndex: 0, PartCount: 1,
		Card: []byte{5}, Evidence: evidence, Part: []byte{relayframe.EvidenceRequest},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(frame, []byte(chatFrameDomain)) {
		t.Fatal("chatFrameDomain is not the separator relay frames start with")
	}
	if isRailPayload(frame) {
		t.Fatal("a relay frame passes as a rail frame")
	}
}

func TestChatContactExportCarriesTheCurrentCardAndStatusShowsIt(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	node := newChatTestNode(t, clock, testSeller, relayAgents(), relay.URL)
	export := filepath.Join(t.TempDir(), "export")
	if err := ensurePrivateDirectory(export); err != nil {
		t.Fatal(err)
	}
	config := NodeConfig{
		AgentID: node.agent, StateDir: node.dir, RelayURLs: []string{relay.URL},
		ReceiverSocket: filepath.Join(node.dir, "rail.sock"),
		Chat: &ChatConfig{
			CarrierSocket:          filepath.Join(node.sockets, "c.sock"),
			MessengerCarrierSocket: filepath.Join(node.sockets, "d.sock"), CardPath: node.daemon.cardPath,
			EvidenceExportDir: export,
		},
	}
	configPath := filepath.Join(t.TempDir(), "rail.json")
	if err := writeNodeConfig(configPath, config); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "contact.json")
	if _, err := ChatContactExport(configPath, out, clock.Now()); err == nil {
		t.Fatal("an export without the daemon's relay contact succeeded")
	}
	// The daemon exported a contact with a stale card; the export replaces it
	// with the card handed out now.
	stale, err := relayframe.EncodeContactJSON(relayframe.Contact{
		AgentID: node.agent, Evidence: node.daemon.evidence, Card: []byte(`{"stale":true}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = writeSynced(filepath.Join(export, "relay-contact.json"), stale); err != nil {
		t.Fatal(err)
	}
	wrapped, err := ChatContactExport(configPath, out, clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	contact, _, err := decodeChatContact(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if contact.AgentID != node.agent || !bytes.Equal(contact.Card, node.daemon.card()) ||
		!bytes.Equal(contact.Evidence, node.daemon.evidence) {
		t.Fatal("the exported contact does not carry the current card and the daemon's evidence")
	}
	status, err := ReadChatStatus(configPath, clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !status.CardPublished || status.CurrentKey == nil || status.CurrentKeyProblem != "" {
		t.Fatalf("status: %+v", status)
	}
	// A card path that does not hold the current card stops the export.
	if err := replaceSynced(node.daemon.cardPath, []byte(`{"other":1}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := ChatContactExport(configPath, out, clock.Now()); err == nil {
		t.Fatal("an export with a stale published card succeeded")
	}
}
