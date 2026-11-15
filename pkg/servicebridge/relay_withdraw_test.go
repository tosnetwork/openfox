package servicebridge

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
)

// replacementController is the packet controller switchableAgents.revoke
// puts in the Agent's finalized policy.
var replacementController = "agent_" + strings.Repeat("99", 32)

// issueCardUnder makes the node sign its key cards with controller and
// issues a card under it, as an owner does after replacing a revoked
// packet controller.
func (n *relayTestNode) issueCardUnder(controller string) OwnRelayKey {
	n.t.Helper()
	signer, err := NewPacketSigner(packetKeys, controller, packetKeys.KeyID(controller), n.agent)
	if err != nil {
		n.t.Fatal(err)
	}
	signer.now = n.clock.Now
	n.carrier.Keys.mutex.Lock()
	n.carrier.Keys.signer = signer
	n.carrier.Keys.mutex.Unlock()
	// A cover past every held card's long floor issues a new card.
	cover := uint64(n.clock.Now().Add(20 * 24 * time.Hour).Unix())
	key, err := n.carrier.Keys.Current(context.Background(), cover)
	if err != nil {
		n.t.Fatal(err)
	}
	return key
}

func (n *relayTestNode) journal() []relayOutboxRecord {
	n.t.Helper()
	directory := filepath.Join(n.dir, relayStateDir, relayOutboxDir)
	entries, err := os.ReadDir(directory)
	if err != nil {
		n.t.Fatal(err)
	}
	reader := &RelayTransport{directory: directory}
	var out []relayOutboxRecord
	for _, entry := range entries {
		if !relayOutboxFilePattern.MatchString(entry.Name()) {
			continue
		}
		record, found, err := reader.load(filepath.Join(directory, entry.Name()))
		if err != nil || !found {
			n.t.Fatalf("journal record %s: %v", entry.Name(), err)
		}
		out = append(out, record)
	}
	return out
}

func (n *relayTestNode) redeposit() {
	n.t.Helper()
	if err := n.carrier.Transport.Redeposit(context.Background()); err != nil {
		n.t.Fatal(err)
	}
}

func envelopeID(t *testing.T, text string) [32]byte {
	t.Helper()
	var id [32]byte
	if err := decodeHex32(text, &id); err != nil {
		t.Fatal(err)
	}
	return id
}

// revokeAndReplace revokes the buyer's packet controller, has the buyer
// issue a card under its replacement and the seller learn it, and lets the
// seller's verification of the old card go stale.
func revokeAndReplace(clock *relayClock, agents *switchableAgents, seller, buyer *relayTestNode) OwnRelayKey {
	agents.revoke(testBuyer)
	key := buyer.issueCardUnder(replacementController)
	seller.learnCard(key.CardJSON)
	clock.Advance(RelayCardReverify + time.Second)
	return key
}

func TestAnEnvelopeSealedToARevokedCardIsWithdrawnAndThePacketResealedToTheNewCard(t *testing.T) {
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
	seller.redeposit()
	before := seller.journal()
	if len(before) != 1 || len(before[0].Accepted) != 2 || before[0].AckSecret == "" {
		t.Fatalf("journal before revocation: %+v", before)
	}
	old, oldSecret := envelopeID(t, before[0].EnvelopeID), before[0].AckSecret
	if !relayA.holds(testBuyer, old) || !relayB.holds(testBuyer, old) {
		t.Fatal("the envelope is not held at both relays")
	}
	fresh := revokeAndReplace(clock, agents, seller, buyer)
	seller.redeposit()

	// The sender withdrew the old envelope at both relays with its secret.
	for _, relay := range []*fakeRelay{relayA, relayB} {
		if relay.holds(testBuyer, old) {
			t.Fatalf("relay %s still holds the envelope sealed to the revoked card", relay.URL)
		}
		presented := false
		for _, secret := range relay.ackBodies {
			presented = presented || hex.EncodeToString(secret) == oldSecret
		}
		if !presented {
			t.Fatal("the old envelope was not withdrawn by its sender")
		}
	}
	after := seller.journal()
	if len(after) != 1 || after[0].KeyID != agentpacketseal.KeyIDText(fresh.KeyID) || len(after[0].Withdrawals) != 0 ||
		len(after[0].Accepted) != 2 || after[0].AckSecret == oldSecret || after[0].EnvelopeID == before[0].EnvelopeID {
		t.Fatalf("journal after revocation: %+v", after)
	}
	raw, err := os.ReadFile(filepath.Join(seller.dir, relayStateDir, relayOutboxDir, strings.TrimPrefix(
		after[0].IdempotencyKey, "idem_")+".json"))
	if err != nil || bytes.Contains(raw, []byte(oldSecret)) {
		t.Fatalf("the withdrawn envelope's secret is still kept: %v", err)
	}
	// The packet is delivered under the new card.
	buyer.pollAll()
	if pending := buyer.pending(); len(pending) != 1 || !bytes.Equal(pending[0].Body, body) {
		t.Fatalf("pending = %d", len(pending))
	}
	// Neither secret reaches the status, the delivery report or a report.
	if err = seller.carrier.WriteStatus(); err != nil {
		t.Fatal(err)
	}
	status, err := os.ReadFile(filepath.Join(seller.dir, relayStateDir, relayStatusFile))
	if err != nil {
		t.Fatal(err)
	}
	report, err := ReadRelayDelivery(seller.dir, nil)
	if err != nil || len(report.Outbox) != 1 {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	evidence := append(append(append([]byte{}, status...), encoded...), seller.reportText()...)
	if !bytes.Contains(evidence, []byte(after[0].EnvelopeID)) {
		t.Fatal("the instrument is silent: the status does not name the envelope")
	}
	for _, secret := range []string{oldSecret, after[0].AckSecret} {
		decoded, _ := hex.DecodeString(secret)
		if bytes.Contains(evidence, []byte(secret)) || bytes.Contains(evidence, decoded) {
			t.Fatal("an acknowledgement secret reached the status or a report")
		}
	}
}

func TestAnEnvelopeSealedToAValidCardIsNeverWithdrawn(t *testing.T) {
	clock := newRelayClock()
	agents := relayAgents()
	relayA, relayB := twoRelays(t, clock)
	seller := newRelayTestNode(t, clock, testSeller, agents, relayA)
	buyer := newRelayTestNode(t, clock, testBuyer, agents, relayA, relayB)
	seller.learn(buyer)
	if _, err := seller.courier.Deliver(context.Background(), relayEnvelopeTo(testBuyer), markedBody(40)); err != nil {
		t.Fatal(err)
	}
	// A newer card of the same controller is learned: the old one stays
	// valid, and is not withdrawn for being superseded.
	seller.learnCard(buyer.issueCardUnder(testBuyer).CardJSON)
	for range 3 {
		clock.Advance(RelayCardReverify + time.Second)
		seller.redeposit()
	}
	id := envelopeID(t, seller.journal()[0].EnvelopeID)
	for _, relay := range []*fakeRelay{relayA, relayB} {
		if requests, _ := relay.ackCounts(); requests != 0 || !relay.holds(testBuyer, id) {
			t.Fatalf("an envelope sealed to a valid card was withdrawn: %d requests", requests)
		}
	}
	if seller.journal()[0].Stopped {
		t.Fatal("the envelope was stopped")
	}
}

func TestAnEnvelopeSealedToACardThatOnlyExpiredIsLeftForTheRecipient(t *testing.T) {
	clock := newRelayClock()
	agents := relayAgents()
	relay := startFakeRelay(t, clock)
	seller := newRelayTestNode(t, clock, testSeller, agents, relay)
	buyer := newRelayTestNode(t, clock, testBuyer, agents, relay)
	seller.learn(buyer)
	clock.Advance(RelayKeyLifetime - 2*time.Hour)
	if _, err := seller.courier.Deliver(context.Background(), relayEnvelopeTo(testBuyer), markedBody(40)); err != nil {
		t.Fatal(err)
	}
	clock.Advance(3 * time.Hour)
	seller.redeposit()
	seller.redeposit()
	if requests, _ := relay.ackCounts(); requests != 0 {
		t.Fatalf("an envelope sealed to an expired, unrevoked card was withdrawn: %d requests", requests)
	}
	// The recipient keeps its key past the card's expiry and opens it.
	buyer.pollAll()
	if len(buyer.pending()) != 1 {
		t.Fatal("the envelope was not delivered")
	}
}

// The restart cases: a pass whose withdrawals fail leaves them in the
// journal, and a node reopened from that journal finishes them; a 404 at a
// relay that never stored the envelope ends the attempt there.
func TestWithdrawalsLeftByAFailedPassAreFinishedAfterARestart(t *testing.T) {
	clock := newRelayClock()
	agents := relayAgents()
	relayA, relayB := twoRelays(t, clock)
	seller := newRelayTestNode(t, clock, testSeller, agents, relayA)
	buyer := newRelayTestNode(t, clock, testBuyer, agents, relayA, relayB)
	seller.learn(buyer)
	relayB.failDeposits = 1000
	if _, err := seller.courier.Deliver(context.Background(), relayEnvelopeTo(testBuyer), markedBody(40)); err != nil {
		t.Fatal(err)
	}
	old := envelopeID(t, seller.journal()[0].EnvelopeID)
	revokeAndReplace(clock, agents, seller, buyer)
	relayA.ackFails = 1000
	seller.redeposit()
	record := seller.journal()[0]
	if len(record.Withdrawals) != 1 || strings.Join(record.Withdrawals[0].Relays, " ") != relayA.URL ||
		!relayA.holds(testBuyer, old) {
		t.Fatalf("after a failing pass: %+v", record.Withdrawals)
	}
	if _, requests := relayB.ackCounts(); requests != 0 {
		t.Fatal("relay B deleted an envelope it never held")
	}
	relayA.ackFails, relayB.failDeposits = 0, 0
	restarted := openRelayTestNode(t, seller.dir, clock, testSeller, agents, relayA)
	restarted.redeposit()
	if relayA.holds(testBuyer, old) || len(restarted.journal()[0].Withdrawals) != 0 {
		t.Fatal("the restarted node did not finish the withdrawal")
	}
	requestsA, _ := relayA.ackCounts()
	requestsB, _ := relayB.ackCounts()
	restarted.redeposit()
	if a, _ := relayA.ackCounts(); a != requestsA {
		t.Fatal("a finished withdrawal was requested again")
	}
	if b, _ := relayB.ackCounts(); b != requestsB {
		t.Fatal("a finished withdrawal was requested again")
	}
	buyer.pollAll()
	if len(buyer.pending()) != 1 {
		t.Fatal("the resealed packet was not delivered")
	}
}

func TestWithdrawalsAreBoundedPerPass(t *testing.T) {
	clock := newRelayClock()
	agents := relayAgents()
	relayA, relayB := twoRelays(t, clock)
	seller := newRelayTestNode(t, clock, testSeller, agents, relayA)
	buyer := newRelayTestNode(t, clock, testBuyer, agents, relayA, relayB)
	seller.learn(buyer)
	const packets = 10
	for index := range packets {
		envelope := relayEnvelopeTo(testBuyer)
		envelope.RequestID = uint64(100 + index)
		if _, err := seller.courier.Deliver(context.Background(), envelope, markedBody(40)); err != nil {
			t.Fatal(err)
		}
	}
	seller.redeposit()
	revokeAndReplace(clock, agents, seller, buyer)
	requests := func() int {
		a, _ := relayA.ackCounts()
		b, _ := relayB.ackCounts()
		return a + b
	}
	seller.redeposit()
	if got := requests(); got != relayWithdrawPerPass {
		t.Fatalf("one pass made %d withdrawal requests, want the bound %d", got, relayWithdrawPerPass)
	}
	seller.redeposit()
	if got := requests(); got != 2*packets {
		t.Fatalf("withdrawal requests = %d, want %d", got, 2*packets)
	}
}

const (
	relayKillChildEnv = "OPENFOX_RELAY_WITHDRAW_KILL_CHILD"
	relayKillDirEnv   = "OPENFOX_RELAY_WITHDRAW_DIR"
	relayKillURLEnv   = "OPENFOX_RELAY_WITHDRAW_RELAY"
	relayKillClockEnv = "OPENFOX_RELAY_WITHDRAW_CLOCK"
)

// The seller process is killed right after it journaled the withdrawal and
// the replacement, before any withdrawal or deposit request; the node
// reopened from that journal withdraws, deposits and delivers.
func TestAKillAfterTheWithdrawalIsJournaledResumesFromTheJournal(t *testing.T) {
	if os.Getenv(relayKillChildEnv) == "1" {
		relayKillChild(t)
		return
	}
	clock := newRelayClock()
	agents := relayAgents()
	relay := startFakeRelay(t, clock)
	dir := t.TempDir()
	seller := openRelayTestNode(t, dir, clock, testSeller, agents, relay)
	buyer := newRelayTestNode(t, clock, testBuyer, agents, relay)
	seller.learn(buyer)
	if _, err := seller.courier.Deliver(context.Background(), relayEnvelopeTo(testBuyer), markedBody(40)); err != nil {
		t.Fatal(err)
	}
	old := envelopeID(t, seller.journal()[0].EnvelopeID)
	revokeAndReplace(clock, agents, seller, buyer)
	command := exec.Command(os.Args[0], "-test.run=^TestAKillAfterTheWithdrawalIsJournaledResumesFromTheJournal$")
	command.Env = append(os.Environ(), relayKillChildEnv+"=1", relayKillDirEnv+"="+dir, relayKillURLEnv+"="+relay.URL,
		relayKillClockEnv+"="+strconv.FormatInt(clock.Now().Unix(), 10))
	output, err := command.CombinedOutput()
	var exit *exec.ExitError
	if !asExitError(err, &exit) || exit.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatalf("the child was not killed: %v\n%s", err, output)
	}
	record := seller.journal()[0]
	if len(record.Withdrawals) != 1 || !record.sealed() || len(record.Accepted) != 0 || !record.Background {
		t.Fatalf("the journal at the kill: %+v", record)
	}
	if requests, _ := relay.ackCounts(); requests != 0 || !relay.holds(testBuyer, old) {
		t.Fatal("a request was made before the kill")
	}
	restarted := openRelayTestNode(t, dir, clock, testSeller, agents, relay)
	restarted.redeposit()
	if relay.holds(testBuyer, old) || len(restarted.journal()[0].Withdrawals) != 0 {
		t.Fatal("the restarted node did not withdraw the envelope")
	}
	buyer.pollAll()
	if len(buyer.pending()) != 1 {
		t.Fatal("the resealed packet was not delivered")
	}
}

func asExitError(err error, target **exec.ExitError) bool {
	exit, ok := err.(*exec.ExitError)
	if ok {
		*target = exit
	}
	return ok
}

func relayKillChild(t *testing.T) {
	unix, err := strconv.ParseInt(os.Getenv(relayKillClockEnv), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	clock := &relayClock{now: time.Unix(unix, 0)}
	agents := relayAgents()
	agents.revoke(testBuyer)
	relay := &fakeRelay{URL: os.Getenv(relayKillURLEnv)}
	seller := openRelayTestNode(t, os.Getenv(relayKillDirEnv), clock, testSeller, agents, relay)
	seller.carrier.Transport.afterJournal = func() {
		if err := syscall.Kill(os.Getpid(), syscall.SIGKILL); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Minute)
	}
	seller.redeposit()
	t.Fatal("the pass finished without journaling a withdrawal")
}

// A replacement that every relay of its card answers 409 for is sealed
// again under a fresh secret by the background pass, as the courier does
// for its own sends; otherwise the packet, whose original was withdrawn and
// which the courier counts as sent, would be lost.
func TestAReplacementEveryRelayRefusesWithAConflictIsSealedAgainAndDelivered(t *testing.T) {
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
	seller.redeposit()
	revokeAndReplace(clock, agents, seller, buyer)
	// The replacement is captured once it is journaled, before its first
	// deposit, and both relays answer 409 to its id for the rest of the
	// test, so only a fresh seal can deliver the packet.
	var replacement relayOutboxRecord
	seller.carrier.Transport.afterJournal = func() {
		if replacement.EnvelopeID != "" {
			return
		}
		replacement = seller.journal()[0]
		id := envelopeID(t, replacement.EnvelopeID)
		for _, relay := range []*fakeRelay{relayA, relayB} {
			relay.mutex.Lock()
			relay.conflictIDs = map[[32]byte]bool{id: true}
			relay.mutex.Unlock()
		}
	}
	seller.redeposit()
	if replacement.EnvelopeID == "" || !replacement.sealed() {
		t.Fatal("no replacement was journaled")
	}
	record := seller.journal()[0]
	conflicted := 0
	for _, relay := range []*fakeRelay{relayA, relayB} {
		for _, deposit := range relay.depositLog() {
			if deposit.status == 409 {
				conflicted++
			}
		}
	}
	if conflicted != 2 || !record.sealed() || record.EnvelopeID == replacement.EnvelopeID ||
		record.Seals != replacement.Seals+1 || len(record.Conflicts) != 0 || len(record.Accepted) != 0 ||
		!record.Background {
		t.Fatalf("after every relay refused the replacement %s: %d conflicts, journal %+v",
			replacement.EnvelopeID, conflicted, record)
	}
	resealed := record.EnvelopeID
	// Bounded: the fresh seal waits for the deposit backoff, so a relay
	// that refuses every id does not make each pass seal again.
	depositsBefore := len(relayA.depositLog()) + len(relayB.depositLog())
	seller.redeposit()
	if again := seller.journal()[0]; again.EnvelopeID != resealed || again.Seals != record.Seals ||
		len(relayA.depositLog())+len(relayB.depositLog()) != depositsBefore {
		t.Fatalf("a pass inside the backoff deposited or sealed again: %+v", again)
	}
	clock.Advance(relayRedepositFirst + time.Second)
	seller.redeposit()
	after := seller.journal()[0]
	if after.EnvelopeID != resealed || len(after.Accepted) != 2 {
		t.Fatalf("the fresh seal was not deposited: %+v", after)
	}
	buyer.pollAll()
	if pending := buyer.pending(); len(pending) != 1 || !bytes.Equal(pending[0].Body, body) {
		t.Fatalf("pending = %d", len(pending))
	}
}

// Consecutive rounds in which every relay answers 409 back off as failures
// do, doubling up to the cap, so a relay refusing every id costs a seal per
// growing backoff period rather than one every first step.
func TestConsecutiveAllConflictRoundsBackOff(t *testing.T) {
	clock := newRelayClock()
	agents := relayAgents()
	relayA, relayB := twoRelays(t, clock)
	seller := newRelayTestNode(t, clock, testSeller, agents, relayA)
	buyer := newRelayTestNode(t, clock, testBuyer, agents, relayA, relayB)
	seller.learn(buyer)
	if _, err := seller.courier.Deliver(context.Background(), relayEnvelopeTo(testBuyer), markedBody(40)); err != nil {
		t.Fatal(err)
	}
	seller.redeposit()
	revokeAndReplace(clock, agents, seller, buyer)
	for _, relay := range []*fakeRelay{relayA, relayB} {
		relay.mutex.Lock()
		relay.conflictAll = true
		relay.mutex.Unlock()
	}
	deposits := func() int { return len(relayA.depositLog()) + len(relayB.depositLog()) }
	seller.redeposit()
	seals := seller.journal()[0].Seals
	// After the n-th refused round the next deposit waits
	// relayRedepositFirst * 2^(n-1), capped at relayRedepositMax.
	wait := relayRedepositFirst
	for round := range 6 {
		before := deposits()
		clock.Advance(wait - time.Second)
		seller.redeposit()
		if deposits() != before || seller.journal()[0].Seals != seals {
			t.Fatalf("round %d: a deposit or seal %s into a %s backoff", round, wait-time.Second, wait)
		}
		clock.Advance(2 * time.Second)
		seller.redeposit()
		if deposits() != before+2 || seller.journal()[0].Seals != seals+1 {
			t.Fatalf("round %d: no deposit and seal once the %s backoff passed", round, wait)
		}
		seals++
		wait *= 2
		if wait > relayRedepositMax {
			wait = relayRedepositMax
		}
	}
}

// unavailableVerifier answers as a tosctl that cannot be run.
type unavailableVerifier struct{}

func (unavailableVerifier) Verify(context.Context, mldsa44.Use, []byte, []byte, []byte) error {
	return mldsa44.ErrUnavailable
}

// While finalized state cannot answer whether the card stands, nothing is
// withdrawn and nothing is sent: an outage is never taken for a revocation.
func TestAFinalizedStateOutageNeverWithdrawsOrSends(t *testing.T) {
	// The verifier is consulted only for a card whose signing controller
	// is still in the finalized policy: a revoked one is refused before any
	// signature check, so that case keeps the card standing.
	revoked := map[string]bool{"resolver failure": true, "verifier unavailable": false, "canceled context": true}
	for name, outage := range map[string]func(*switchableAgents, *relayTestNode) context.Context{
		"resolver failure": func(agents *switchableAgents, _ *relayTestNode) context.Context {
			agents.set(true)
			return context.Background()
		},
		"verifier unavailable": func(_ *switchableAgents, seller *relayTestNode) context.Context {
			seller.cards.mutex.Lock()
			seller.cards.verifier = unavailableVerifier{}
			seller.cards.mutex.Unlock()
			return context.Background()
		},
		"canceled context": func(*switchableAgents, *relayTestNode) context.Context {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx
		},
	} {
		t.Run(name, func(t *testing.T) {
			clock := newRelayClock()
			agents := relayAgents()
			relay := startFakeRelay(t, clock)
			seller := newRelayTestNode(t, clock, testSeller, agents, relay)
			buyer := newRelayTestNode(t, clock, testBuyer, agents, relay)
			seller.learn(buyer)
			if _, err := seller.courier.Deliver(context.Background(), relayEnvelopeTo(testBuyer),
				markedBody(40)); err != nil {
				t.Fatal(err)
			}
			before := seller.journal()[0]
			if revoked[name] {
				revokeAndReplace(clock, agents, seller, buyer)
			} else {
				clock.Advance(RelayCardReverify + time.Second)
			}
			deposits := len(relay.depositLog())
			ctx := outage(agents, seller)
			for range 2 {
				_ = seller.carrier.Transport.Redeposit(ctx)
				clock.Advance(relayRedepositMax)
			}
			after := seller.journal()[0]
			if requests, _ := relay.ackCounts(); requests != 0 || len(relay.depositLog()) != deposits {
				t.Fatalf("a request was sent during the outage: %d acks, %d deposits", requests,
					len(relay.depositLog())-deposits)
			}
			if len(after.Withdrawals) != 0 || after.EnvelopeID != before.EnvelopeID || after.Stopped {
				t.Fatalf("the outage changed the journal: %+v", after)
			}
		})
	}
}

// A relay that answered 404 to a withdrawal does not hold the envelope; it
// is never asked again, however long the other relays' withdrawals retry.
func TestARelayThatAnswered404IsNeverAskedAgain(t *testing.T) {
	clock := newRelayClock()
	agents := relayAgents()
	relayA, relayB := twoRelays(t, clock)
	seller := newRelayTestNode(t, clock, testSeller, agents, relayA)
	buyer := newRelayTestNode(t, clock, testBuyer, agents, relayA, relayB)
	seller.learn(buyer)
	relayB.failDeposits = 1000
	if _, err := seller.courier.Deliver(context.Background(), relayEnvelopeTo(testBuyer), markedBody(40)); err != nil {
		t.Fatal(err)
	}
	revokeAndReplace(clock, agents, seller, buyer)
	relayA.mutex.Lock()
	relayA.ackFails = 1000
	relayA.mutex.Unlock()
	seller.redeposit()
	first, _ := relayB.ackCounts()
	if first != 1 {
		t.Fatalf("relay B was asked %d times in the first pass", first)
	}
	for range 5 {
		clock.Advance(relayRedepositMax + time.Second)
		seller.redeposit()
	}
	if again, _ := relayB.ackCounts(); again != first {
		t.Fatalf("relay B, which answered 404, was asked %d more times", again-first)
	}
	if requests, _ := relayA.ackCounts(); requests < 3 {
		t.Fatalf("the failing relay was not retried after the backoff: %d requests", requests)
	}
}
