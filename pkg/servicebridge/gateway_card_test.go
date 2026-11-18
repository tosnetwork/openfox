package servicebridge

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// currentGatewayCard is the long card the node's maintenance pass hands to
// the card publishing hook.
func currentGatewayCard(t *testing.T, node *relayTestNode) OwnRelayKey {
	t.Helper()
	key, err := node.carrier.Keys.Current(context.Background(), offerCardCover(uint64(node.clock.Now().Unix())))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// requireGatewayReadable applies the gateway's own acceptance of the card
// file: a regular, non-symlink file of 1 to 16,384 bytes, mode 0600, owned
// by this user, holding exactly want.
func requireGatewayReadable(t *testing.T, path string, want []byte) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > maxCardJSON {
		t.Fatalf("the card file is not an owner-only bounded regular file: %v, %d bytes", info.Mode(), info.Size())
	}
	if owned, ownerErr := ownedByCurrentUser(info); ownerErr != nil || !owned {
		t.Fatalf("the card file is not owned by this user: %v", ownerErr)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("the card file holds %d bytes other than the exact signed card packet (%d bytes)", len(got), len(want))
	}
}

func gatewayCardNode(agent, path string, carrier *RelayCarrier) *Node {
	return &Node{
		Config: NodeConfig{AgentID: agent, RelayURLs: []string{"https://relay.example"},
			Provider: &ProviderNode{GatewayCardFile: path}},
		Relay: carrier,
	}
}

func TestTheGatewayCardFileHoldsTheExactSignedCardOwnerOnly(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	provider := newRelayTestNode(t, clock, testSeller, relayAgents(), relay)
	key := currentGatewayCard(t, provider)
	// The directory does not exist yet: it is created owner-only.
	path := filepath.Join(t.TempDir(), "gateway", "provider-card.json")
	if err := publishGatewayCard(path, testSeller, key.CardJSON, clock.Now()); err != nil {
		t.Fatal(err)
	}
	requireGatewayReadable(t, path, key.CardJSON)
	info, err := os.Lstat(filepath.Dir(path))
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("the card directory is not owner-only: %v", err)
	}
	if err = checkGatewayCard(testSeller, key.CardJSON, clock.Now()); err != nil {
		t.Fatalf("the published card is not one the gateway serves now: %v", err)
	}
	// An unchanged card is not rewritten.
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = publishGatewayCard(path, testSeller, key.CardJSON, clock.Now()); err != nil {
		t.Fatal(err)
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("an unchanged card was rewritten")
	}
	// A file the gateway would refuse (wrong mode) is replaced even when it
	// holds the card.
	if err = os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err = publishGatewayCard(path, testSeller, key.CardJSON, clock.Now()); err != nil {
		t.Fatal(err)
	}
	requireGatewayReadable(t, path, key.CardJSON)
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatalf("the card directory holds more than the card: %d entries", len(entries))
	}
}

// The red control of republishing: the node's maintenance pass must replace
// the gateway card file when it issues a successor. Removing the gateway
// call from the node's card publishing hook makes this test fail.
func TestTheGatewayCardFileIsReplacedWhenTheCardRotates(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	provider := newRelayTestNode(t, clock, testSeller, relayAgents(), relay)
	path := filepath.Join(t.TempDir(), "provider-card.json")
	node := gatewayCardNode(testSeller, path, provider.carrier)
	node.registerCardPublishing()
	if err := provider.carrier.Maintain(context.Background()); err != nil {
		t.Fatal(err)
	}
	first := currentGatewayCard(t, provider)
	requireGatewayReadable(t, path, first.CardJSON)
	// Past the reuse floor of the long card a successor is issued.
	clock.Advance(relayLongCoverFloor + time.Hour)
	if err := provider.carrier.Maintain(context.Background()); err != nil {
		t.Fatal(err)
	}
	second := currentGatewayCard(t, provider)
	if second.KeyID == first.KeyID || bytes.Equal(second.CardJSON, first.CardJSON) {
		t.Fatal("no successor card was issued; the test exercised nothing")
	}
	requireGatewayReadable(t, path, second.CardJSON)
	if err := checkGatewayCard(testSeller, second.CardJSON, clock.Now()); err != nil {
		t.Fatalf("the republished card is not valid now: %v", err)
	}
}

func TestTheOfferAndGatewayCardFilesAreRepublishedIndependently(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	provider := newRelayTestNode(t, clock, testSeller, relayAgents(), relay)
	dir := t.TempDir()
	path := filepath.Join(dir, "provider-card.json")
	node := gatewayCardNode(testSeller, path, provider.carrier)
	// An offer file that cannot be written (its manifest is missing) does
	// not keep the gateway card from being written.
	node.Config.Provider.OfferFile = filepath.Join(dir, "offer.json")
	node.Config.Provider.ManifestFile = filepath.Join(dir, "missing.cbor")
	node.registerCardPublishing()
	if err := provider.carrier.Maintain(context.Background()); err == nil {
		t.Fatal("the failing offer file was not reported")
	}
	requireGatewayReadable(t, path, currentGatewayCard(t, provider).CardJSON)
}

func TestAStaleOrForeignCardIsNeverWrittenToTheGatewayCardFile(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	provider := newRelayTestNode(t, clock, testSeller, relayAgents(), relay)
	key := currentGatewayCard(t, provider)
	card, err := decodeOwnCard(testSeller, key.CardJSON)
	if err != nil {
		t.Fatal(err)
	}
	expiry := time.Unix(int64(card.NotAfterUnix), 0)
	start := time.Unix(int64(card.NotBeforeUnix), 0)
	other := newRelayTestNode(t, clock, testBuyer, relayAgents(), relay)
	cases := map[string]struct {
		agent string
		card  []byte
		now   time.Time
	}{
		"expired":             {testSeller, key.CardJSON, expiry},
		"long expired":        {testSeller, key.CardJSON, expiry.Add(24 * time.Hour)},
		"not yet valid":       {testSeller, key.CardJSON, start.Add(-time.Second)},
		"another Agent's":     {testSeller, other.card(), clock.Now()},
		"empty":               {testSeller, []byte{}, clock.Now()},
		"oversized":           {testSeller, bytes.Repeat([]byte(" "), maxCardJSON+1), clock.Now()},
		"not a packet":        {testSeller, []byte(`{"schema":"x"}`), clock.Now()},
		"with trailing bytes": {testSeller, append(append([]byte(nil), key.CardJSON...), []byte("garbage")...), clock.Now()},
		"clock not set":       {testSeller, key.CardJSON, time.Unix(0, 0)},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			// No file yet: none is created.
			missing := filepath.Join(dir, "absent", "card.json")
			if err := publishGatewayCard(missing, c.agent, c.card, c.now); !errors.Is(err, errGatewayCardRefused) {
				t.Fatalf("published: %v", err)
			}
			if _, err := os.Lstat(filepath.Dir(missing)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("a refused card created the card directory")
			}
			// A current card is in place: it is left exactly as it was.
			path := filepath.Join(dir, "card.json")
			if err := publishGatewayCard(path, testSeller, key.CardJSON, clock.Now()); err != nil {
				t.Fatal(err)
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := publishGatewayCard(path, c.agent, c.card, c.now); !errors.Is(err, errGatewayCardRefused) {
				t.Fatalf("published: %v", err)
			}
			after, err := os.Lstat(path)
			if err != nil || !os.SameFile(before, after) {
				t.Fatal("a refused card replaced the card file")
			}
			requireGatewayReadable(t, path, key.CardJSON)
		})
	}
	// The node's hook refuses its own card once the card has expired.
	path := filepath.Join(t.TempDir(), "card.json")
	node := gatewayCardNode(testSeller, path, provider.carrier)
	clock.Advance(expiry.Sub(clock.Now()))
	if err := node.republishGatewayCard(key); !errors.Is(err, errGatewayCardRefused) {
		t.Fatalf("an expired card was published: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("an expired card was written")
	}
}

func TestAGatewayCardFileNeedsACleanPathAndRelays(t *testing.T) {
	relays := []string{"https://relay.example"}
	for name, c := range map[string]struct {
		path   string
		relays []string
	}{
		"relative":  {"gateway/card.json", relays},
		"unclean":   {"/srv/gateway/../card.json", relays},
		"no relays": {"/srv/gateway/card.json", nil},
	} {
		if err := (&ProviderNode{GatewayCardFile: c.path}).checkGatewayCardConfig(c.relays); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	if err := (&ProviderNode{GatewayCardFile: "/srv/gateway/card.json"}).checkGatewayCardConfig(relays); err != nil {
		t.Fatal(err)
	}
	if err := (&ProviderNode{}).checkGatewayCardConfig(nil); err != nil {
		t.Fatal(err)
	}
	if err := publishGatewayCard("card.json", testSeller, []byte("{}"), time.Now()); err == nil {
		t.Fatal("a relative card file path was accepted")
	}
}

const (
	gatewayCrashPathEnv  = "SERVICEBRIDGE_GATEWAY_CARD_PATH"
	gatewayCrashCardEnv  = "SERVICEBRIDGE_GATEWAY_CARD_SOURCE"
	gatewayCrashReadyEnv = "SERVICEBRIDGE_GATEWAY_CARD_READY"
)

// The child half: publish a card and stop between writing the temporary
// file and renaming it, until the parent kills the process.
func TestGatewayCardCrashChild(t *testing.T) {
	path := os.Getenv(gatewayCrashPathEnv)
	if path == "" {
		t.Skip("runs only as the child of TestACrashBetweenWriteAndRenameLeavesThePreviousCard")
	}
	card, err := os.ReadFile(os.Getenv(gatewayCrashCardEnv))
	if err != nil {
		t.Fatal(err)
	}
	gatewayCardCommitHook = func(string) {
		if err := os.WriteFile(os.Getenv(gatewayCrashReadyEnv), []byte("ready"), 0o600); err != nil {
			t.Error(err)
			return
		}
		time.Sleep(time.Hour)
	}
	if err := publishGatewayCard(path, testSeller, card, time.Now()); err != nil {
		t.Fatal(err)
	}
	t.Fatal("the child was not killed before the rename")
}

// A process killed after writing the new card and before renaming it leaves
// the previous card in place, whole; the next publish replaces it and clears
// the temporary file the crash left once it is old enough to be a crash's.
func TestACrashBetweenWriteAndRenameLeavesThePreviousCard(t *testing.T) {
	if os.Getenv(gatewayCrashPathEnv) != "" {
		t.Skip("the child does not recurse")
	}
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	// Two key stores of one Agent give two cards valid now.
	previous := currentGatewayCard(t, newRelayTestNode(t, clock, testSeller, relayAgents(), relay))
	next := currentGatewayCard(t, newRelayTestNode(t, clock, testSeller, relayAgents(), relay))
	if bytes.Equal(previous.CardJSON, next.CardJSON) {
		t.Fatal("the two cards are the same")
	}
	dir := t.TempDir()
	cardDir := filepath.Join(dir, "gateway")
	path := filepath.Join(cardDir, "card.json")
	if err := publishGatewayCard(path, testSeller, previous.CardJSON, time.Now()); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(dir, "next.json")
	if err := os.WriteFile(source, next.CardJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	ready := filepath.Join(dir, "ready")
	child := exec.Command(os.Args[0], "-test.run=^TestGatewayCardCrashChild$", "-test.count=1")
	child.Env = append(os.Environ(), gatewayCrashPathEnv+"="+path, gatewayCrashCardEnv+"="+source,
		gatewayCrashReadyEnv+"="+ready)
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		if _, err := os.Lstat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = child.Process.Kill()
			_ = child.Wait()
			t.Fatal("the child never reached the rename")
		}
		time.Sleep(time.Millisecond)
	}
	if err := child.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait()
	requireGatewayReadable(t, path, previous.CardJSON)
	// The crash left the complete new card in a temporary file the gateway
	// never reads.
	entries, err := os.ReadDir(cardDir)
	if err != nil {
		t.Fatal(err)
	}
	var leftovers []string
	for _, entry := range entries {
		if entry.Name() == "card.json" {
			continue
		}
		if !strings.HasPrefix(entry.Name(), gatewayCardTemporaryPrefix(path)) {
			t.Fatalf("the crash left %s, which is not a temporary card file", entry.Name())
		}
		leftovers = append(leftovers, filepath.Join(cardDir, entry.Name()))
	}
	if len(leftovers) != 1 {
		t.Fatalf("the crash left %d temporary files, want 1", len(leftovers))
	}
	// Once old enough to be a crash's, the next publish removes it.
	old := time.Now().Add(-2 * gatewayCardTemporaryLeft)
	if err = os.Chtimes(leftovers[0], old, old); err != nil {
		t.Fatal(err)
	}
	if err = publishGatewayCard(path, testSeller, next.CardJSON, time.Now()); err != nil {
		t.Fatal(err)
	}
	requireGatewayReadable(t, path, next.CardJSON)
	if entries, err = os.ReadDir(cardDir); err != nil || len(entries) != 1 {
		t.Fatalf("the temporary file the crash left was not removed: %d entries", len(entries))
	}
}
