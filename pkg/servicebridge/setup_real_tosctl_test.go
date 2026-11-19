package servicebridge

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44/mldsa44test"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
)

// TestSetupCommandsRequireAndUseTheRealPinnedTOSCTL runs every setup
// command that needs no chain against the real helper named by
// TOS_SERVICE_TOSCTL and TOS_SERVICE_TOSCTL_SHA256: controller creation in
// a temporary vault, the identity domain, the Service Actor address and the
// wallet listing. It fails, rather than skips, without the helper: these
// are the answers whose exact shape and failure phrases the fake stands in
// for everywhere else.
func TestSetupCommandsRequireAndUseTheRealPinnedTOSCTL(t *testing.T) {
	binary, pin := os.Getenv(mldsa44test.BinaryEnvironment), os.Getenv(mldsa44test.SHA256Environment)
	if binary == "" || pin == "" {
		t.Fatalf("set %s and %s to the pinned tosctl helper", mldsa44test.BinaryEnvironment,
			mldsa44test.SHA256Environment)
	}
	directory, err := os.MkdirTemp("", "openfox-setup-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if chmodErr := os.Chmod(directory, 0o700); chmodErr != nil {
		t.Fatal(chmodErr)
	}
	master := make([]byte, 32)
	if _, randErr := rand.Read(master); randErr != nil {
		t.Fatal(randErr)
	}
	vault := "file://" + filepath.Join(directory, "vault.json") + "?master_key=" + hex.EncodeToString(master)
	config := TOSCTLConfig{Binary: binary, SHA256: pin, ConfigPath: filepath.Join(directory, "tosctl-config.json")}
	direct := func(args ...string) []byte {
		command := exec.Command(binary, args...)
		command.Env, command.Dir = []string{"VAULT_URL=" + vault}, "/"
		output, runErr := command.Output()
		if runErr != nil {
			t.Fatalf("tosctl %s failed: %v", strings.Join(args[:2], " "), runErr)
		}
		return output
	}
	direct("config", "generate", "--output="+config.ConfigPath)
	// A global configuration with the two genesis anchors tosctl reads.
	root, file := strings.Repeat("\x11", 32), strings.Repeat("\x22", 32)
	global := filepath.Join(directory, "global.config.json")
	writeFixtureFile(t, global, []byte(`{"validator":{"zero_state":{"root_hash":"`+
		base64.StdEncoding.EncodeToString([]byte(root))+`","file_hash":"`+
		base64.StdEncoding.EncodeToString([]byte(file))+`"}}}`), 0o600)

	wrong := config
	wrong.SHA256 = strings.Repeat("0", 64)
	if _, pinErr := NewSealedTOSCTL(wrong, vault); pinErr == nil {
		t.Fatal("a helper with another SHA-256 was accepted")
	}
	runner, err := NewSealedTOSCTL(config, vault)
	if err != nil {
		t.Fatal(err)
	}
	ops := tosctlOps{runner: runner, globalConfig: global, networkLabel: "tos:global-id:7"}
	ctx := context.Background()
	leaks := func(err error) bool {
		return strings.Contains(err.Error(), hex.EncodeToString(master)) || strings.Contains(err.Error(), directory)
	}

	// Controllers: absent is told from every other failure by the real
	// phrase, creation never replaces, and without --yes nothing is made.
	_, err = ops.controller(ctx, "service-attestor")
	if tosctlFailure(err) != TOSCTLFailureNotFound || leaks(err) {
		t.Fatalf("an absent controller is not classified as not found: %v", err)
	}
	world := filepath.Join(directory, "unused-world.json")
	run := &setupRun{ctx: ctx, env: fakeEnv(world, nil), stateDir: directory}
	if _, err = run.ensureController(
		ops,
		"controller.attestor",
		"service-attestor",
	); !errors.Is(
		err,
		ErrConfirmationRequired,
	) {
		t.Fatalf("without --yes: %v", err)
	}
	if _, err = ops.controller(ctx, "service-attestor"); tosctlFailure(err) != TOSCTLFailureNotFound {
		t.Fatal("a controller was created without --yes")
	}
	run.yes = true
	created, err := run.ensureController(ops, "controller.attestor", "service-attestor")
	if err != nil {
		t.Fatalf("the real helper did not create the controller: %v", err)
	}
	again, err := run.ensureController(ops, "controller.attestor", "service-attestor")
	if err != nil || again.KeyID != created.KeyID || !strings.HasPrefix(created.Text(), "mldsa44:") {
		t.Fatalf("the controller changed on a second run: %v", err)
	}
	if _, err = ops.newController(
		ctx,
		"service-attestor",
	); tosctlFailure(err) != TOSCTLFailureAlreadyExists ||
		leaks(err) {
		t.Fatalf("creating an existing controller is not refused as existing: %v", err)
	}
	probed, err := ProbeControllerKeyID(ctx, config, vault, "service-attestor")
	if err != nil || probed != created.KeyID {
		t.Fatalf("the preflight probe resolves another key: %v", err)
	}

	// The domain: the release registry code hashes to the code hash the
	// helper signs for, and the genesis anchors are the configuration's.
	domain, err := ops.domain(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if domain.GenesisRootHash != "sha256:"+hex.EncodeToString([]byte(root)) ||
		domain.GenesisFileHash != "sha256:"+hex.EncodeToString([]byte(file)) {
		t.Fatalf("domain = %+v", domain)
	}
	code, err := os.ReadFile(filepath.Join("testdata", "native-registry-code.boc.base64"))
	if err != nil {
		t.Fatal(err)
	}
	network := &nativev1.NetworkDomain{
		NetworkId: ops.networkLabel, GenesisRootHash: domain.GenesisRootHash, GenesisFileHash: domain.GenesisFileHash,
	}
	if _, err = nativecore.NewLocator(
		network,
		0,
		strings.Join(strings.Fields(string(code)), ""),
		domain.CodeHash,
	); err != nil {
		t.Fatalf("the release registry code does not hash to the helper's code hash %s: %v", domain.CodeHash, err)
	}
	missing := ops
	missing.globalConfig = filepath.Join(directory, "absent.json")
	if _, err = missing.domain(ctx); err == nil || leaks(err) {
		t.Fatalf("a missing global configuration: %v", err)
	}

	// The actor address: deterministic, raw, and bound to every term and to
	// the attestor key.
	terms := ActorTerms{
		PriceNano: 100_000_001, StorageFeeNano: 200_000_000, CleanupBountyNano: 100_000_000, ResponseSLA: 3600,
		RefundClaimWindow: 3600,
	}
	owner := "0:" + strings.Repeat("11", 32)
	actor, err := ops.actorAddress(ctx, owner, terms, created, false)
	if err != nil {
		t.Fatalf("the real helper did not derive the actor address: %v", err)
	}
	same, _ := ops.actorAddress(ctx, owner, terms, created, false)
	dearer := terms
	dearer.PriceNano++
	other, _ := ops.actorAddress(ctx, owner, dearer, created, false)
	if actor != same || actor == other || !rawAddressPattern.MatchString(actor) {
		t.Fatalf("actor addresses: %s %s %s", actor, same, other)
	}

	// The wallet listing: the address tosctl derives, in raw form; the
	// chain state is unknown because no chain is reachable.
	if _, err = ops.wallet(ctx, "provider"); !errors.Is(err, errWalletMissing) {
		t.Fatalf("a wallet that is not configured: %v", err)
	}
	printed := regexp.MustCompile(`0:[0-9a-f]{64}`).Find(direct("wallet", "create", "--config", config.ConfigPath,
		"-n", "provider", "-v", "V3R2", "-w", "0"))
	wallet, err := ops.wallet(ctx, "provider")
	if err != nil {
		t.Fatalf("the real helper's wallet listing did not decode: %v", err)
	}
	if wallet.Address != string(printed) || wallet.StateKnown {
		t.Fatalf("wallet = %+v, tosctl printed %s", wallet, printed)
	}
	if fundErr := requireFundedWallet(
		wallet,
		1,
		"the test",
	); fundErr == nil ||
		!strings.Contains(fundErr.Error(), wallet.Address) {
		t.Fatalf("a wallet of unknown state was taken as funded: %v", fundErr)
	}
}
