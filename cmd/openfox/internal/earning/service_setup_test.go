package earning

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/openfox/pkg/servicebridge"
)

// runService executes one `service` subcommand and returns what it printed
// and its error.
func runService(args ...string) (stdout, stderr string, err error) {
	command := serviceCommand()
	var out, diagnostics bytes.Buffer
	command.SetOut(&out)
	command.SetErr(&diagnostics)
	command.SetArgs(args)
	err = command.Execute()
	return out.String(), diagnostics.String(), err
}

func TestTheServiceCommandOffersTheFrontDoorCommands(t *testing.T) {
	names := map[string]bool{}
	for _, child := range serviceCommand().Commands() {
		names[child.Name()] = true
		if child.Args == nil {
			t.Errorf("%s takes positional arguments", child.Name())
		}
	}
	for _, name := range []string{"init", "offer", "withdraw", "buy", "serve", "status", "preflight", "purchases"} {
		if !names[name] {
			t.Errorf("no %s command", name)
		}
	}
	if _, _, err := runService("init", "positional"); err == nil {
		t.Fatal("init took a positional argument")
	}
}

func TestBuyTakesExactlyOneQuoteSource(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source.tar")
	if err := os.WriteFile(source, []byte("archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := runService("buy", "--rail-config", filepath.Join(root, "rail.json"), "--source", source,
		"--offer", filepath.Join(root, "offer.json"), "--quote-package", filepath.Join(root, "quote.json"))
	if err == nil || !strings.Contains(err.Error(), "exactly one Quote source") {
		t.Fatalf("two Quote sources were accepted: %v", err)
	}
	// An offer file that does not decode stops the purchase before the
	// node is opened.
	offer := filepath.Join(root, "offer.json")
	if err = os.WriteFile(offer, []byte(`{"schema":"tos.openfox.rail-offer.v1","extra":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err = runService(
		"buy",
		"--rail-config",
		filepath.Join(root, "absent.json"),
		"--source",
		source,
		"--offer",
		offer,
	)
	if err == nil || !strings.Contains(err.Error(), "offer file") {
		t.Fatalf("a malformed offer file: %v", err)
	}
	// A flag may only agree with the offer file.
	manifest, digest, _, err := servicebridge.BuildManifest(servicebridge.ManifestInput{
		ProviderAgentID: "agent_" + strings.Repeat("ab", 32), Actor: "0:" + strings.Repeat("77", 32),
		ActorCodeHash: "tvm-cell-sha256:" + strings.Repeat("88", 32), Attestor: "mldsa44:" + strings.Repeat("99", 32),
		Version: "1.0.0", RetentionSeconds: 86400,
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := servicebridge.EncodeOfferFile(servicebridge.Offer{
		CapabilityID: "cap_" + strings.Repeat("33", 32), Version: "1.0.0",
		ProviderAgentID: "agent_" + strings.Repeat("ab", 32), ManifestDigest: digest, ManifestCBOR: manifest,
	}, time.Unix(1_900_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(offer, encoded, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, flags := range [][]string{
		{"--capability-id", "cap_" + strings.Repeat("44", 32)}, {"--version", "2.0.0"},
	} {
		args := append([]string{
			"buy", "--rail-config", filepath.Join(root, "absent.json"), "--source", source,
			"--offer", offer,
		}, flags...)
		if _, _, err = runService(
			args...); err == nil ||
			!strings.Contains(err.Error(), "differs from the offer file") {
			t.Fatalf("%v disagreeing with the offer file: %v", flags, err)
		}
	}
	// Agreeing flags pass that check and stop only at the absent
	// configuration.
	_, _, err = runService(
		"buy",
		"--rail-config",
		filepath.Join(root, "absent.json"),
		"--source",
		source,
		"--offer",
		offer,
		"--capability-id",
		"cap_"+strings.Repeat("33", 32),
	)
	if err == nil || !strings.Contains(err.Error(), "rail configuration") {
		t.Fatalf("an agreeing flag: %v", err)
	}
}

func TestWithdrawTakesExactlyOneOfAmountAndAll(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.json")
	for name, args := range map[string][]string{
		"neither": {"withdraw", "--rail-config", path},
		"both":    {"withdraw", "--rail-config", path, "--amount", "1", "--all"},
	} {
		if _, _, err := runService(
			args...); err == nil ||
			!strings.Contains(err.Error(), "exactly one of --amount and --all") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, _, err := runService(
		"withdraw",
		"--rail-config",
		path,
		"--amount",
		"0",
		"--yes",
	); err != servicebridge.ErrWithdrawZero {
		t.Fatalf("a zero withdrawal: %v", err)
	}
	for _, amount := range []string{"-1", "1e9", "0.0000000001", "abc"} {
		if _, _, err := runService("withdraw", "--rail-config", path, "--amount", amount, "--yes"); err == nil ||
			!strings.Contains(err.Error(), "--amount") {
			t.Errorf("amount %q: %v", amount, err)
		}
	}
	// --acknowledge closes an earlier withdrawal; it is never combined
	// with a new one, and --note belongs to it alone.
	for name, args := range map[string][]string{
		"with an amount": {"withdraw", "--rail-config", path, "--acknowledge", "7", "--amount", "1"},
		"with all":       {"withdraw", "--rail-config", path, "--acknowledge", "7", "--all"},
	} {
		if _, _, err := runService(args...); err == nil ||
			!strings.Contains(err.Error(), "neither --amount nor --all") {
			t.Errorf("--acknowledge %s: %v", name, err)
		}
	}
	if _, _, err := runService("withdraw", "--rail-config", path, "--all", "--note", "x"); err == nil ||
		!strings.Contains(err.Error(), "--note belongs to --acknowledge") {
		t.Errorf("--note without --acknowledge: %v", err)
	}
	if _, _, err := runService("withdraw", "--rail-config", path, "--acknowledge", "0", "--note", "x"); err == nil ||
		!strings.Contains(err.Error(), "query id") {
		t.Errorf("--acknowledge 0: %v", err)
	}
	// An acknowledgement reaches the configuration, not a withdrawal.
	if _, _, err := runService("withdraw", "--rail-config", path, "--acknowledge", "7", "--note", "x"); err == nil ||
		strings.Contains(err.Error(), "exactly one of") {
		t.Errorf("--acknowledge was taken for a withdrawal: %v", err)
	}
	// A well-formed request reaches the configuration, and prints a report
	// even though it fails.
	stdout, _, err := runService("withdraw", "--rail-config", path, "--amount", "1.5")
	var report servicebridge.WithdrawResult
	if err == nil || json.Unmarshal([]byte(stdout), &report) != nil ||
		report.Schema != servicebridge.WithdrawResultSchema ||
		report.Confirmed {
		t.Fatalf("report %q, error %v", stdout, err)
	}
}

func TestInitAndOfferRefuseMalformedFlagsBeforeDoingAnything(t *testing.T) {
	root := t.TempDir()
	base := []string{
		"init", "--rail-config", filepath.Join(root, "rail.json"), "--state-dir", filepath.Join(root, "state"),
		"--rpc", "http://127.0.0.1:1", "--rpc", "http://127.0.0.1:2", "--rpc", "http://127.0.0.1:3",
		"--global-config", filepath.Join(root, "global.json"), "--network-label", "tos:global-id:7",
		"--tosctl", filepath.Join(root, "tosctl"), "--tosctl-config", filepath.Join(root, "tosctl.json"),
		"--wallet", "provider", "--registry-code-boc", filepath.Join(root, "registry.boc"),
		"--actor-code-hash", "tvm-cell-sha256:" + strings.Repeat("88", 32),
	}
	for name, extra := range map[string][]string{
		"a direct peer without a socket":  {"--direct-peer", "agent_" + strings.Repeat("ab", 32)},
		"a direct peer named twice":       {"--direct-peer", "agent_x=/a", "--direct-peer", "agent_x=/b"},
		"buyer limits without a provider": {"--messenger-socket", "/run/m.sock", "--max-per-purchase", "3"},
		"a malformed buyer amount":        {"--messenger-socket", "/run/m.sock", "--allow-provider", "agent_" + strings.Repeat("ab", 32), "--max-per-purchase", "1e3"},
		"no transport at all":             {},
		"a direct peer with a bad Agent":  {"--direct-peer", "agent_zz=/run/peer.sock"},
		"a relative direct peer socket":   {"--direct-peer", "agent_" + strings.Repeat("ab", 32) + "=peer.sock"},
		"a malformed tosctl pin":          {"--messenger-socket", "/run/m.sock", "--tosctl-sha256", "abc"},
		"a messenger socket not absolute": {"--messenger-socket", "m.sock"},
		"a provider that is not an Agent": {"--messenger-socket", "/run/m.sock", "--allow-provider", "someone"},
		"a missing tosctl binary to pin":  {"--messenger-socket", "/run/m.sock"},
	} {
		if _, _, err := runService(append(append([]string(nil), base...), extra...)...); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if _, statErr := os.Stat(filepath.Join(root, "rail.json")); statErr == nil {
			t.Fatalf("%s: a configuration was written", name)
		}
	}
	if _, _, err := runService("init"); err == nil || !strings.Contains(err.Error(), "required flag") {
		t.Fatalf("init without its inputs: %v", err)
	}
	offer := []string{
		"offer", "--rail-config", filepath.Join(root, "rail.json"), "--storage-fee", "0.2", "--cleanup-bounty", "0.1",
		"--response-sla", "3600", "--refund-claim-window", "3600", "--executor", "/usr/bin/executor",
		"--containerd-socket", "/run/containerd.sock",
	}
	for _, price := range []string{"-0.1", "1e2", "0.1234567891", "free"} {
		if _, _, err := runService(append(append([]string(nil), offer...), "--price", price)...); err == nil ||
			!strings.Contains(err.Error(), "--price") {
			t.Errorf("price %q: %v", price, err)
		}
	}
	if _, _, err := runService(offer...); err == nil || !strings.Contains(err.Error(), "required flag") {
		t.Fatalf("offer without a price: %v", err)
	}
}

func TestPurchasesOfABuyerThatBoughtNothingIsAnEmptyList(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state")
	if err := os.MkdirAll(filepath.Join(state, "purchases"), 0o700); err != nil {
		t.Fatal(err)
	}
	encoded, err := servicebridge.EncodeNodeConfig(servicebridge.NodeConfig{
		StateDir: state, Buyer: &servicebridge.BuyerNode{},
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "rail.json")
	if err = os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, _, err := runService("purchases", "--rail-config", path)
	if err != nil {
		t.Fatal(err)
	}
	var listed []servicebridge.PurchaseRecord
	if err = json.Unmarshal([]byte(stdout), &listed); err != nil || listed == nil || len(listed) != 0 {
		t.Fatalf("no purchases printed %q, not an empty list (%v)", stdout, err)
	}
}
