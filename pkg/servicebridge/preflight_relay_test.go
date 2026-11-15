package servicebridge

import (
	"context"
	"path/filepath"
	"testing"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
)

// relayPreflight is a ready provider with relays, its own key issued and
// one held peer card.
func relayPreflight(t *testing.T, issueKey bool) (*pfFixture, *fakeRelay) {
	t.Helper()
	f := newPreflightFixture(t)
	clock := &relayClock{now: pfChainNow}
	relay := startFakeRelay(t, clock)
	f.config.RelayURLs = []string{relay.URL}
	f.chain.agent = &nativev1.NativeStateV1{Network: testNetwork, State: &nativev1.NativeStateV1_Agent{
		Agent: agentState(testSeller),
	}}
	f.env.PacketVerifier = func(NodeConfig) (mldsa44.Verifier, error) { return packetKeys, nil }
	if issueKey {
		root := filepath.Join(f.config.StateDir, relayStateDir)
		if err := ensurePrivateDirectory(root); err != nil {
			t.Fatal(err)
		}
		signer := testSigner(t, testSeller)
		signer.now = clock.Now
		keys, err := OpenRelayKeys(filepath.Join(root, relayKeysDir), testSeller, f.config.RelayURLs, signer, clock.Now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = keys.Current(context.Background(), 0); err != nil {
			t.Fatal(err)
		}
		// A buyer card learned while the buyer was live; the preflight's
		// checkpoint no longer has that Agent.
		cards, err := OpenPeerCards(filepath.Join(root, relayPeersDir), packetKeys, relayAgents(), ownersMap{},
			clock.Now)
		if err != nil {
			t.Fatal(err)
		}
		cards.AllowLoopbackRelays(true)
		buyer := newRelayTestNode(t, clock, testBuyer, relayAgents(), relay)
		if err = cards.Learn(context.Background(), buyer.card(), testBuyer, ""); err != nil {
			t.Fatal(err)
		}
	}
	return f, relay
}

func TestPreflightChecksTheRelaysTheOwnKeyCardAndThePeerCards(t *testing.T) {
	f, _ := relayPreflight(t, true)
	report, checks := f.run(t)
	for id, want := range map[string]string{
		"relay.config": CheckPass, "relay.reachable": CheckPass, "relay.key": CheckPass, "relay.card": CheckPass,
		"relay.peers": CheckWarn, "transport.peers": CheckPass,
	} {
		if checks[id].Status != want {
			t.Errorf("%s: %s (%s), want %s", id, checks[id].Status, checks[id].Message, want)
		}
	}
	if !report.OK {
		t.Fatalf("a ready relay node failed: %+v", report.Checks)
	}
	// The own card stops verifying once its signing controller leaves the
	// finalized policy.
	revoked := agentState(testSeller)
	revoked.Policy.Controllers[0].KeyId = packetKeys.KeyID(testBuyer)
	revoked.Policy.Controllers[0].Mldsa44PublicKey = packetKeys.PublicKey(testBuyer)
	f.chain.agent = &nativev1.NativeStateV1{Network: testNetwork, State: &nativev1.NativeStateV1_Agent{Agent: revoked}}
	if _, checks = f.run(t); checks["relay.card"].Status != CheckFail {
		t.Fatalf("a revoked own card: %+v", checks["relay.card"])
	}
}

func TestPreflightFailsARelayNodeWithoutAKeyOrWithAPlaintextRelay(t *testing.T) {
	f, relay := relayPreflight(t, false)
	_, checks := f.run(t)
	if checks["relay.key"].Status != CheckFail || checks["relay.card"].Status != CheckUnknown {
		t.Fatalf("no own key: %+v %+v", checks["relay.key"], checks["relay.card"])
	}
	relay.listFails = true
	if _, checks = f.run(t); checks["relay.reachable"].Status != CheckFail {
		t.Fatalf("an unlistable relay: %+v", checks["relay.reachable"])
	}
	f.config.RelayURLs = []string{"http://relay.example"}
	if _, checks = f.run(t); checks["relay.config"].Status != CheckFail {
		t.Fatalf("a plaintext relay outside loopback: %+v", checks["relay.config"])
	}
}
