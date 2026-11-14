package servicebridge

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// directNode is one node's transport and receiver: a real receiver behind
// the real Agent Packet Unix server, a durable inbox, and a courier whose
// transport is the configured direct route.
type directNode struct {
	agent    string
	socket   string
	inbox    *Inbox
	courier  *Courier
	complete chan Message
}

func startDirectNode(t *testing.T, root, agent string, peers map[string]string) *directNode {
	t.Helper()
	directory := filepath.Join(root, agent[len(agent)-4:])
	if err := ensurePrivateDirectory(directory); err != nil {
		t.Fatal(err)
	}
	node := &directNode{
		agent:    agent,
		socket:   filepath.Join(directory, "rail-receiver.sock"),
		complete: make(chan Message, 8),
	}
	var err error
	if node.inbox, err = OpenInbox(
		filepath.Join(directory, "inbox"),
		DefaultMaxAssembliesPerSender,
		DefaultMaxAssemblies,
	); err != nil {
		t.Fatal(err)
	}
	receiver := &Receiver{
		LocalAgentID: agent, Verifier: packetKeys, Inbox: node.inbox,
		Resolver: agentMap{testBuyer: agentState(testBuyer), testSeller: agentState(testSeller)},
		Notify: func(status InboxStatus, message Message) {
			if status == InboxComplete {
				node.complete <- message
			}
		},
	}
	server, err := OpenAgentPacketUnixServer(node.socket, receiver)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	})
	transport, err := openPacketTransport(NodeConfig{AgentID: agent, DirectPeers: peers})
	if err != nil {
		t.Fatal(err)
	}
	if node.courier, err = OpenCourier(
		filepath.Join(directory, "outbox"),
		testSigner(t, agent),
		transport,
	); err != nil {
		t.Fatal(err)
	}
	return node
}

func socketRoot(t *testing.T) string {
	t.Helper()
	// A short path: a Unix socket address holds about a hundred bytes.
	root, err := os.MkdirTemp("", "of-direct-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	return root
}

func awaitMessage(t *testing.T, node *directNode) Message {
	t.Helper()
	select {
	case message := <-node.complete:
		return message
	case <-time.After(20 * time.Second):
		t.Fatal("no complete message arrived")
		return Message{}
	}
}

// Two nodes exchange a task and its result over their real receiver
// sockets: every packet is posted, verified against the sender's Agent
// state, stored durably and answered 202 before the courier marks it sent.
func TestTwoNodesExchangeATaskAndAResultOverTheirReceiverSockets(t *testing.T) {
	root := socketRoot(t)
	buyerSocket := filepath.Join(root, testBuyer[len(testBuyer)-4:], "rail-receiver.sock")
	sellerSocket := filepath.Join(root, testSeller[len(testSeller)-4:], "rail-receiver.sock")
	buyer := startDirectNode(t, root, testBuyer, map[string]string{testSeller: sellerSocket})
	seller := startDirectNode(t, root, testSeller, map[string]string{testBuyer: buyerSocket})

	task := fill(3*MaxChunkData+11, 4)
	envelope := Envelope{
		RecipientAgentID: testSeller, CapabilityID: "cap_" + strings.Repeat("33", 32),
		QuoteCommitment: "tvm-cell-sha256:" + strings.Repeat("aa", 32), Kind: FrameTask, ActorAccount: testActor,
		RequestID: 9, RequestHash: testRequest,
	}
	if _, err := buyer.courier.Deliver(context.Background(), envelope, task); err != nil {
		t.Fatalf("the task was not delivered: %v", err)
	}
	received := awaitMessage(t, seller)
	if received.SenderAgentID != testBuyer || received.Kind != FrameTask || received.RequestID != 9 ||
		!bytes.Equal(received.Body, task) {
		t.Fatalf("the seller received another task: %s kind %d, %d bytes", received.SenderAgentID, received.Kind,
			len(received.Body))
	}
	pending, err := seller.inbox.Pending()
	if err != nil || len(pending) != 1 || !bytes.Equal(pending[0].Body, task) {
		t.Fatalf("the task is not in the seller's durable inbox: %d %v", len(pending), err)
	}

	result := fill(2*MaxChunkData+5, 6)
	envelope.RecipientAgentID, envelope.Kind = testBuyer, FrameResult
	if _, err = seller.courier.Deliver(context.Background(), envelope, result); err != nil {
		t.Fatalf("the result was not delivered: %v", err)
	}
	back := awaitMessage(t, buyer)
	if back.SenderAgentID != testSeller || back.Kind != FrameResult || !bytes.Equal(back.Body, result) {
		t.Fatalf("the buyer received another result: %s kind %d", back.SenderAgentID, back.Kind)
	}
	// Nothing is left to retry on either side.
	if err = buyer.courier.Resume(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = seller.courier.Resume(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// A failed direct send leaves the packets journaled exactly as a failed
// Messenger send does, and Resume delivers them once the peer serves.
func TestADirectSendThatFailsIsRetriedByResume(t *testing.T) {
	root := socketRoot(t)
	sellerSocket := filepath.Join(root, testSeller[len(testSeller)-4:], "rail-receiver.sock")
	buyer := startDirectNode(t, root, testBuyer, map[string]string{testSeller: sellerSocket})
	envelope := testEnvelope()
	envelope.RecipientAgentID, envelope.Kind = testSeller, FrameTask
	body := fill(MaxChunkData+3, 2)
	_, err := buyer.courier.Deliver(context.Background(), envelope, body)
	if !errors.Is(err, ErrDirectSocketInvalid) {
		t.Fatalf("a send to a peer that is not serving: %v", err)
	}
	seller := startDirectNode(t, root, testSeller, map[string]string{testBuyer: filepath.Join(root, "buyer.sock")})
	if err = buyer.courier.Resume(context.Background()); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if received := awaitMessage(t, seller); !bytes.Equal(received.Body, body) {
		t.Fatal("the retried task differs")
	}
}

func directPacket(t *testing.T, recipient string, size int) OutboundPacket {
	t.Helper()
	transport := &recordingTransport{}
	courier, err := OpenCourier(filepath.Join(t.TempDir(), "outbox"), testSigner(t, testBuyer), transport)
	if err != nil {
		t.Fatal(err)
	}
	envelope := testEnvelope()
	envelope.RecipientAgentID, envelope.Kind = recipient, FrameTask
	if _, err = courier.Deliver(context.Background(), envelope, fill(size, 3)); err != nil {
		t.Fatal(err)
	}
	return transport.packets()[0]
}

func TestTheDirectTransportRefusesWhatItCannotDeliverSafely(t *testing.T) {
	root := socketRoot(t)
	sellerSocket := filepath.Join(root, testSeller[len(testSeller)-4:], "rail-receiver.sock")
	seller := startDirectNode(t, root, testSeller, map[string]string{testBuyer: filepath.Join(root, "buyer.sock")})
	packet := directPacket(t, testSeller, 100)
	ctx := context.Background()

	if err := (RoutedTransport{}).Send(ctx, packet); !errors.Is(err, ErrNoPacketRoute) {
		t.Fatalf("a packet without a route: %v", err)
	}
	// A recipient that is not a direct peer goes to the Messenger when one
	// is configured, and nowhere else.
	fallback := &recordingTransport{}
	routed := RoutedTransport{
		Direct:   DirectTransport{Peers: map[string]string{testSeller: sellerSocket}},
		Fallback: fallback,
	}
	other := directPacket(t, "agent_"+strings.Repeat("c3", 32), 100)
	if err := routed.Send(ctx, other); err != nil || len(fallback.packets()) != 1 {
		t.Fatalf("an unlisted recipient did not go to the fallback: %v", err)
	}
	if err := routed.Send(ctx, packet); err != nil || len(fallback.packets()) != 1 {
		t.Fatalf("a direct peer's packet went to the fallback: %v", err)
	}
	awaitMessage(t, seller)

	link := filepath.Join(root, "link.sock")
	if err := os.Symlink(sellerSocket, link); err != nil {
		t.Fatal(err)
	}
	regular := filepath.Join(root, "regular")
	writeFixtureFile(t, regular, []byte("not a socket"), 0o600)
	for name, path := range map[string]string{
		"a symbolic link to a socket": link, "a regular file": regular, "a missing socket": filepath.Join(root, "absent.sock"),
		"a relative path": "rail-receiver.sock", "a directory": root,
	} {
		direct := DirectTransport{Peers: map[string]string{testSeller: path}}
		if err := direct.Send(ctx, packet); !errors.Is(err, ErrDirectSocketInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	direct := DirectTransport{Peers: map[string]string{testSeller: sellerSocket}}
	oversize := packet
	oversize.JSON = bytes.Repeat([]byte("x"), maxPacketJSON+1)
	if err := direct.Send(ctx, oversize); !errors.Is(err, ErrDirectPacketTooLarge) {
		t.Fatalf("an oversize packet: %v", err)
	}
	// The receiver refuses a packet it cannot verify; that is not a
	// delivery, and its answer is not repeated.
	tampered := packet
	tampered.JSON = bytes.Replace(packet.JSON, []byte(`"sequence":`), []byte(`"sequence":1`), 1)
	err := direct.Send(ctx, tampered)
	if !errors.Is(err, ErrDirectRefused) || strings.Contains(err.Error(), "refused\n") {
		t.Fatalf("a packet the receiver refused: %v", err)
	}
	pending, pendingErr := seller.inbox.Pending()
	if pendingErr != nil || len(pending) != 1 {
		t.Fatalf("the refused packet reached the inbox: %d %v", len(pending), pendingErr)
	}
}

// A socket that answers anything but 202, or redirects, is not a delivery.
func TestOnlyA202FromTheReceiverIsADelivery(t *testing.T) {
	root := socketRoot(t)
	packet := directPacket(t, testSeller, 100)
	serve := func(name string, handler http.HandlerFunc) string {
		path := filepath.Join(root, name+".sock")
		listener, err := net.Listen("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		server := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second}
		go func() { _ = server.Serve(listener) }()
		t.Cleanup(func() { _ = server.Close() })
		return path
	}
	var redirected atomic.Int32
	cases := map[string]http.HandlerFunc{
		"200": func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) },
		"204": func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) },
		"422": func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "secret detail", http.StatusUnprocessableEntity)
		},
		"500 with a long body": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write(bytes.Repeat([]byte("z"), 1<<20))
		},
		// The redirect points back at this socket's accepting path: a
		// client that followed it would be answered 202.
		"redirect": func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/accept" {
				redirected.Add(1)
				w.WriteHeader(http.StatusAccepted)
				return
			}
			http.Redirect(w, r, "http://rail-receiver/accept", http.StatusTemporaryRedirect)
		},
	}
	for name, handler := range cases {
		path := serve(strings.ReplaceAll(name, " ", "-"), handler)
		err := DirectTransport{Peers: map[string]string{testSeller: path}}.Send(context.Background(), packet)
		if !errors.Is(err, ErrDirectRefused) {
			t.Errorf("%s was taken as a delivery or another failure: %v", name, err)
		}
		if err != nil && strings.Contains(err.Error(), "secret detail") {
			t.Errorf("%s: the receiver's answer was repeated", name)
		}
	}
	if redirected.Load() != 0 {
		t.Fatal("a redirect was followed")
	}
	slow := serve("slow", func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(3 * time.Second)
		w.WriteHeader(http.StatusAccepted)
	})
	started := time.Now()
	err := DirectTransport{Peers: map[string]string{testSeller: slow}, Timeout: 300 * time.Millisecond}.
		Send(context.Background(), packet)
	if !errors.Is(err, ErrDirectUnreachable) || time.Since(started) > 2*time.Second {
		t.Fatalf("a receiver that does not answer in time: %v after %s", err, time.Since(started))
	}
	accepting := serve("accepting", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/agent-packet" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	})
	if err = (DirectTransport{Peers: map[string]string{testSeller: accepting}}).Send(
		context.Background(),
		packet,
	); err != nil {
		t.Fatalf("a 202 on POST /v1/agent-packet: %v", err)
	}
}

func TestTheNodeTransportFailsClosedWithoutARoute(t *testing.T) {
	socket := "/run/openfox/peer/rail-receiver.sock"
	cases := map[string]NodeConfig{
		"neither messenger nor peers": {AgentID: testBuyer},
		"a peer named by a bad id":    {AgentID: testBuyer, DirectPeers: map[string]string{"agent_zz": socket}},
		"a relative peer socket":      {AgentID: testBuyer, DirectPeers: map[string]string{testSeller: "peer.sock"}},
		"an unclean peer socket": {
			AgentID:     testBuyer,
			DirectPeers: map[string]string{testSeller: "/run/../peer.sock"},
		},
		"a peer socket path too long": {
			AgentID:     testBuyer,
			DirectPeers: map[string]string{testSeller: "/" + strings.Repeat("a", 120)},
		},
		"its own Agent as a peer":     {AgentID: testBuyer, DirectPeers: map[string]string{testBuyer: socket}},
		"a relative messenger socket": {AgentID: testBuyer, MessengerSocket: "messenger.sock"},
	}
	for name, config := range cases {
		if _, err := openPacketTransport(config); err == nil {
			t.Errorf("%s: a transport was opened", name)
		}
	}
	tooMany := map[string]string{}
	for index := 0; index <= maxDirectPeers; index++ {
		tooMany["agent_"+strings.Repeat("0", 62)+string("0123456789abcdef"[index/16])+string("0123456789abcdef"[index%16])] = socket
	}
	if _, err := openPacketTransport(NodeConfig{AgentID: testBuyer, DirectPeers: tooMany}); err == nil {
		t.Error("more direct peers than the bound were accepted")
	}
	transport, err := openPacketTransport(
		NodeConfig{AgentID: testBuyer, DirectPeers: map[string]string{testSeller: socket}},
	)
	if err != nil {
		t.Fatal(err)
	}
	routed := transport.(RoutedTransport)
	if routed.Route(testSeller) != RouteDirect || routed.Route("agent_"+strings.Repeat("c3", 32)) != RouteNone {
		t.Fatalf("routes without a Messenger: %s %s", routed.Route(testSeller), routed.Route("x"))
	}
	withMessenger, err := openPacketTransport(NodeConfig{
		AgentID: testBuyer, MessengerSocket: "/run/openfox/messenger.sock",
		DirectPeers: map[string]string{testSeller: socket},
	})
	if err != nil {
		t.Fatal(err)
	}
	routed = withMessenger.(RoutedTransport)
	if routed.Route(testSeller) != RouteDirect || routed.Route("agent_"+strings.Repeat("c3", 32)) != RouteMessenger {
		t.Fatal("routes with a Messenger")
	}
}
