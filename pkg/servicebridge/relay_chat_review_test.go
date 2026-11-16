package servicebridge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
)

func setFailDeposits(relay *fakeRelay, count int) {
	relay.mutex.Lock()
	relay.failDeposits = count
	relay.mutex.Unlock()
}

func chatJournalRecord(t *testing.T, node *chatTestNode, key string) relayOutboxRecord {
	t.Helper()
	var record relayOutboxRecord
	if err := readJSON(node.chat.Transport.recordPath(key), 1<<20, &record); err != nil {
		t.Fatal(err)
	}
	return record
}

func TestAnExpiredPacketNoRelayAcceptedIsSignedAgainUnderTheSameKey(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	a, b := chatPair(t, clock, relay.URL)
	event := chatEventID("expired")
	key := chatCopyKey(t, event, 1)
	// Every deposit fails: the packet is journaled, no relay accepts it.
	setFailDeposits(relay, 1<<20)
	requireResult(t, a.daemon.carry(b.agent, event, 1), carrierapi.ResultRetry, "")
	before := chatJournalRecord(t, a, key)
	// The journaled packet outlives its lifetime before any relay takes it.
	clock.Advance(PacketLifetime + time.Minute)
	setFailDeposits(relay, 0)
	requireResult(t, a.daemon.carry(b.agent, event, 1), carrierapi.ResultCarried, "")
	after := chatJournalRecord(t, a, key)
	if after.PacketBase64 == before.PacketBase64 || after.EnvelopeID == before.EnvelopeID {
		t.Fatal("the expired packet was not replaced by a freshly signed one")
	}
	if after.PacketExpiresAtUnix <= uint64(clock.Now().Unix()) || relay.count(b.agent) != 1 {
		t.Fatal("the fresh packet is not deliverable or not deposited")
	}
	b.pollAll()
	if b.daemon.acceptedCount(event) != 1 {
		t.Fatalf("B applied the copy %d times: %s", b.daemon.acceptedCount(event), b.reportText())
	}
	// An evidence request under one generation key advances the same way.
	requestKey, err := relayframe.EvidenceRequestKey(b.agent, 1)
	if err != nil {
		t.Fatal(err)
	}
	request := a.daemon.frame(relayframe.KindEvidence, []byte{relayframe.EvidenceRequest})
	setFailDeposits(relay, 1<<20)
	carry := func() carrierapi.Response {
		response, carryErr := a.daemon.carrier.Carry(context.Background(), b.agent, requestKey, "",
			uint64(clock.Now().Add(24*time.Hour).Unix()), request)
		if carryErr != nil {
			t.Fatal(carryErr)
		}
		return response
	}
	requireResult(t, carry(), carrierapi.ResultRetry, "")
	clock.Advance(PacketLifetime + time.Minute)
	setFailDeposits(relay, 0)
	requireResult(t, carry(), carrierapi.ResultCarried, "")
}

func TestAnEnvelopeStillDueAtARelayIsNeverTakenForGone(t *testing.T) {
	clock := newRelayClock()
	one, two := startFakeRelay(t, clock), startFakeRelay(t, clock)
	if one.URL > two.URL {
		one, two = two, one
	}
	a, b := chatPair(t, clock, one.URL, two.URL)
	requireResult(t, a.daemon.carry(b.agent, chatEventID("due"), 1), carrierapi.ResultCarried, "")
	if one.count(b.agent) != 1 || two.count(b.agent) != 0 {
		t.Fatal("setup: the copy is not held at the first relay only")
	}
	ctx := context.Background()
	live := func() int {
		stored, err := a.chat.Transport.storedFor(b.agent)
		if err != nil {
			t.Fatal(err)
		}
		a.chat.refreshGone(ctx, b.agent, stored)
		return a.chat.liveCount(stored)
	}
	// B acknowledges at the first relay before the second deposit lands: no
	// relay lists the envelope, but the second deposit is still due.
	b.carrier.Inbound.Poll(ctx, one.URL)
	if one.count(b.agent) != 0 {
		t.Fatal("setup: B did not acknowledge at the first relay")
	}
	if got := live(); got != 1 {
		t.Fatalf("an envelope with a deposit still due counts %d", got)
	}
	a.redeposit()
	if two.count(b.agent) != 1 {
		t.Fatal("setup: the second deposit did not land")
	}
	if got := live(); got != 1 {
		t.Fatalf("an envelope stored at the second relay counts %d", got)
	}
	b.carrier.Inbound.Poll(ctx, two.URL)
	if got := live(); got != 0 {
		t.Fatalf("an envelope no relay holds and none is due to counts %d", got)
	}
}

func TestTheHeldChatCardIsThePublishedOneWhenAFreshInitHoldsTwoKeys(t *testing.T) {
	clock := newRelayClock()
	relays := []string{"http://127.0.0.1:9"}
	ctx := context.Background()
	for round := range 16 {
		dir := t.TempDir()
		if err := ensurePrivateDirectory(filepath.Join(dir, relayStateDir)); err != nil {
			t.Fatal(err)
		}
		signer := testCardSigner(t, testSeller)
		signer.packet.now = clock.Now
		keys, err := OpenChatRelayKeys(filepath.Join(dir, relayStateDir, relayChatKeysDir), testSeller, relays,
			signer, clock.Now)
		if err != nil {
			t.Fatal(err)
		}
		// What chat init does: maintenance issues a seven-day key, then the
		// handed-out thirty-day card is issued in the same second.
		if _, err = keys.Maintain(ctx); err != nil {
			t.Fatal(err)
		}
		card, err := keys.Current(ctx, offerCardCover(uint64(clock.Now().Unix())))
		if err != nil {
			t.Fatal(err)
		}
		if len(keys.Held()) != 2 {
			t.Fatalf("setup: %d keys held", len(keys.Held()))
		}
		cardPath := filepath.Join(dir, relayStateDir, "chat-card.json")
		if err = publishChatCard(cardPath, card.CardJSON); err != nil {
			t.Fatal(err)
		}
		config := NodeConfig{
			AgentID: testSeller, StateDir: dir, RelayURLs: relays,
			CardKeyID: packetKeys.KeyID(testCardController(testSeller)), Chat: &ChatConfig{CardPath: cardPath},
		}
		held, published, err := heldChatCard(config, clock.Now())
		if err != nil {
			t.Fatal(err)
		}
		if !published || held.KeyID != card.KeyID {
			t.Fatalf("round %d: the held card is not the published one", round)
		}
	}
}

// sealedChatFrame seals a signed packet from sender with payload to the
// recipient's chat key at a fake relay.
func sealedChatFrame(t *testing.T, relay *fakeRelay, sender, recipient *chatTestNode, capability string,
	payload []byte,
) {
	t.Helper()
	packet, err := testSigner(t, sender.agent).sign(context.Background(), recipient.agent, capability, "", payload)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := agentpacket.EncodeJSON(packet)
	if err != nil {
		t.Fatal(err)
	}
	key, err := recipient.chat.Keys.Current(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	sealToKey(t, relay, recipient.agent, key, encoded, recipient.clock)
}

func TestAStrangersAckFrameIsRefusedAndTheCardItCarriesIsNotStored(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	agents := relayAgents()
	stranger := newChatTestNode(t, clock, relayThird, agents, relay.URL)
	b := newChatTestNode(t, clock, testBuyer, agents, relay.URL)
	digest := sha256.Sum256([]byte("ciphertext"))
	ack, err := relayframe.SignAck(relayframe.Ack{
		EventID: chatEventID("forged"), SessionID: "ses_" + hex.EncodeToString(digest[:]),
		RecipientEndpointID: stranger.daemon.endpoint, RecipientDeviceID: stranger.daemon.device,
		CiphertextDigest: "sha256:" + hex.EncodeToString(digest[:]), Outcome: relayframe.OutcomeAccepted,
		AcceptedAtUnix: uint64(clock.Now().Unix()),
	}, stranger.daemon.key)
	if err != nil {
		t.Fatal(err)
	}
	object, err := relayframe.EncodeAck(ack)
	if err != nil {
		t.Fatal(err)
	}
	sealedChatFrame(t, relay, stranger, b, chatCapability, stranger.daemon.frame(relayframe.KindDeliveryAck, object))
	b.pollAll()
	if b.daemon.callCount() != 1 {
		t.Fatalf("B's daemon was asked %d times", b.daemon.callCount())
	}
	if b.chat.Cards.Has(stranger.agent) || len(b.chat.Cards.List()) != 0 {
		t.Fatal("the card of a stranger's refused ack frame was stored")
	}
	if relay.count(b.agent) != 0 {
		t.Fatal("the refused ack frame was not relay-acknowledged")
	}
}

func TestAFailedListingAtTheCapCountsItsEnvelopesAsHeld(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	a, b := chatPair(t, clock, relay.URL)
	for index := range ChatPeerEnvelopeCap {
		requireResult(t, a.daemon.carry(b.agent, chatEventID("cap"+string(rune('a'+index))), 1),
			carrierapi.ResultCarried, "")
	}
	b.pollAll()
	if relay.count(b.agent) != 0 {
		t.Fatal("setup: B did not acknowledge every copy")
	}
	relay.mutex.Lock()
	relay.listFails = true
	relay.mutex.Unlock()
	requireResult(t, a.daemon.carry(b.agent, chatEventID("over"), 1), carrierapi.ResultRefused,
		carrierapi.CodePeerCap)
	relay.mutex.Lock()
	relay.listFails = false
	relay.mutex.Unlock()
	requireResult(t, a.daemon.carry(b.agent, chatEventID("over"), 1), carrierapi.ResultCarried, "")
}

func TestAChatKeyPacketWithANonZeroCapabilityIsRefusedBeforeAnyRead(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	agents := relayAgents()
	a := newChatTestNode(t, clock, testSeller, agents, relay.URL)
	b := newChatTestNode(t, clock, testBuyer, agents, relay.URL)
	b.admit(a)
	sealedChatFrame(t, relay, a, b, testEnvelope().CapabilityID, a.daemon.copyFrame(b.agent, chatEventID("cap")))
	b.agents.reset()
	b.pollAll()
	if reads := b.agents.count(); reads != 0 {
		t.Fatalf("finalized state was read %d times for a packet with a real Capability", reads)
	}
	if b.daemon.callCount() != 0 || relay.count(b.agent) != 0 || len(b.chat.Cards.List()) != 0 {
		t.Fatal("a packet with a real Capability reached the daemon, stayed listed or left a card")
	}
}

// Crash between deposit and journal write, with a real process death.
const (
	chatCrashDirEnv     = "SERVICEBRIDGE_CHAT_CRASH_DIR"
	chatCrashSocketsEnv = "SERVICEBRIDGE_CHAT_CRASH_SOCKETS"
	chatCrashRelayEnv   = "SERVICEBRIDGE_CHAT_CRASH_RELAY"
	chatCrashEvent      = "crash"
)

// The child half: carry one copy and die the moment a relay accepted it,
// before the acceptance is journaled.
func TestChatCarryCrashChild(t *testing.T) {
	dir := os.Getenv(chatCrashDirEnv)
	if dir == "" {
		t.Skip("runs only as the child of TestAKilledCarrierReusesItsJournaledEnvelopeAfterRestart")
	}
	clock := newRelayClock()
	node := openChatTestNodeIn(t, dir, os.Getenv(chatCrashSocketsEnv), clock, testSeller, relayAgents(),
		os.Getenv(chatCrashRelayEnv))
	node.chat.Transport.afterDeposit = func() { _ = syscall.Kill(os.Getpid(), syscall.SIGKILL) }
	event := chatEventID(chatCrashEvent)
	response := node.chat.Carry(context.Background(), carrierapi.Request{
		RecipientAgentID: testBuyer, IdempotencyKey: chatCopyKey(t, event, 1),
		ExpiresAtUnix: uint64(clock.Now().Add(7 * 24 * time.Hour).Unix()),
	}, node.daemon.copyFrame(testBuyer, event))
	t.Fatalf("the carrier was not killed after the deposit: %s %s", response.Result, response.Code)
}

func TestAKilledCarrierReusesItsJournaledEnvelopeAfterRestart(t *testing.T) {
	if os.Getenv(chatCrashDirEnv) != "" {
		t.Skip("the child does not recurse")
	}
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	agents := relayAgents()
	aDir := t.TempDir()
	a := openChatTestNode(t, aDir, clock, testSeller, agents, relay.URL)
	b := newChatTestNode(t, clock, testBuyer, agents, relay.URL)
	a.importContact(b)
	a.admit(b)
	b.admit(a)
	sockets, err := os.MkdirTemp("", "crash")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockets) })
	if err = os.Chmod(sockets, 0o700); err != nil {
		t.Fatal(err)
	}
	child := exec.Command(os.Args[0], "-test.run=^TestChatCarryCrashChild$", "-test.count=1")
	child.Env = append(os.Environ(), chatCrashDirEnv+"="+aDir, chatCrashSocketsEnv+"="+sockets,
		chatCrashRelayEnv+"="+relay.URL)
	output, runErr := child.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(runErr, &exit) {
		t.Fatalf("the child was not killed: %v\n%s", runErr, output)
	}
	status, ok := exit.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatalf("the child did not die by SIGKILL: %v\n%s", runErr, output)
	}
	event := chatEventID(chatCrashEvent)
	key := chatCopyKey(t, event, 1)
	if relay.count(b.agent) != 1 {
		t.Fatalf("the relay holds %d envelopes after the crash", relay.count(b.agent))
	}
	stored := onlyEnvelopeID(t, relay, b.agent)
	record := chatJournalRecord(t, a, key)
	if len(record.Accepted) != 0 {
		t.Fatal("the acceptance was journaled: the child died too late")
	}
	// The restarted carrier, with nothing in memory, retries the key: the
	// journaled envelope is deposited again byte for byte and the relay
	// recognizes it.
	deposits := len(relay.depositLog())
	restarted := openChatTestNode(t, aDir, clock, testSeller, agents, relay.URL)
	requireResult(t, restarted.daemon.carry(b.agent, event, 1), carrierapi.ResultCarried, "")
	log := relay.depositLog()
	if relay.count(b.agent) != 1 || onlyEnvelopeID(t, relay, b.agent) != stored || len(log) != deposits+1 ||
		log[len(log)-1].status != 200 {
		t.Fatal("the restarted carrier did not resend the journaled envelope")
	}
	if accepted := chatJournalRecord(t, restarted, key).Accepted; len(accepted) != 1 {
		t.Fatal("the retry did not journal the acceptance")
	}
	b.pollAll()
	if b.daemon.acceptedCount(event) != 1 {
		t.Fatal("the copy was not applied exactly once")
	}
}

func TestTheCarrierTimeoutIsBoundedLikeTheDaemons(t *testing.T) {
	base := NodeConfig{
		RelayURLs: []string{"https://relay.example"}, ReceiverSocket: "/state/rail.sock",
		Chat: &ChatConfig{
			CarrierSocket: "/state/chat.sock", MessengerCarrierSocket: "/run/m/carrier.sock",
			CardPath: "/state/relay/chat-card.json",
		},
	}
	for seconds, valid := range map[uint64]bool{0: true, 1: true, 300: true, 301: false, 1 << 40: false} {
		config := base
		chat := *base.Chat
		chat.TimeoutSeconds = seconds
		config.Chat = &chat
		if err := validateChatConfig(config); (err == nil) != valid {
			t.Fatalf("timeout_seconds %d: %v", seconds, err)
		}
	}
	if timeout, err := (ChatConfig{}).timeout(); err != nil || timeout != 30*time.Second {
		t.Fatalf("the default timeout is %s", timeout)
	}
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	dir := t.TempDir()
	if err := ensurePrivateDirectory(filepath.Join(dir, relayStateDir)); err != nil {
		t.Fatal(err)
	}
	daemon, err := carrierapi.NewClient(filepath.Join(dir, "absent.sock"), 0)
	if err != nil {
		t.Fatal(err)
	}
	open := func(timeout time.Duration) error {
		_, openErr := openChatCarrier(filepath.Join(dir, relayStateDir), testSeller, chatLaneConfig{
			Relays: []string{relay.URL}, CardPath: filepath.Join(dir, "card.json"), Signer: testSigner(t, testSeller),
			CardSigner: testCardSigner(t, testSeller), Daemon: daemon, Timeout: timeout,
		}, packetKeys, relayAgents(), newRelayPool(nil), clock.Now, nil)
		return openErr
	}
	for _, timeout := range []time.Duration{time.Millisecond, 301 * time.Second} {
		if open(timeout) == nil {
			t.Fatalf("a carrier timeout of %s was accepted", timeout)
		}
	}
	if err = open(300 * time.Second); err != nil {
		t.Fatalf("the largest carrier timeout was refused: %v", err)
	}
}

func TestARemovedContactIsNoLongerSealedToAndAnUnknownOneIsRefused(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	a, b := chatPair(t, clock, relay.URL)
	cards := filepath.Join(a.dir, relayStateDir, relayChatPeersDir)
	contacts := filepath.Join(a.dir, "contacts")
	contactFile := filepath.Join(contacts, b.agent[len("agent_"):]+".json")
	if _, err := os.Stat(contactFile); err != nil {
		t.Fatalf("setup: the import wrote no contact file: %v", err)
	}
	for _, bad := range []string{"", "agent_xyz", a.agent, relayStranger} {
		if _, err := removeChatContact(cards, contacts, a.agent, bad); err == nil {
			t.Fatalf("removing %q was accepted", bad)
		}
	}
	removed, err := removeChatContact(cards, contacts, a.agent, b.agent)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed.RemovedCards) != 1 || removed.ContactFile != contactFile {
		t.Fatalf("removed %+v", removed)
	}
	if _, err = os.Stat(contactFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the contact file is still there")
	}
	// The running carrier no longer holds the card.
	if a.chat.Cards.Has(b.agent) {
		t.Fatal("the running carrier still holds the removed card")
	}
	requireResult(t, a.daemon.carry(b.agent, chatEventID("after-remove"), 1), carrierapi.ResultRefused,
		carrierapi.CodeNoPeerCard)
	if _, err = removeChatContact(cards, contacts, a.agent, b.agent); err == nil {
		t.Fatal("removing an unknown contact was accepted")
	}
}
