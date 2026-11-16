package servicebridge

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
)

func mustFail(t *testing.T, err error, target error, fragments ...string) {
	t.Helper()
	if err == nil {
		t.Fatal("the command succeeded")
	}
	if target != nil && !errors.Is(err, target) {
		t.Fatalf("error %q is not %q", err, target)
	}
	for _, fragment := range fragments {
		if !strings.Contains(err.Error(), fragment) {
			t.Fatalf("error %q does not say %q", err, fragment)
		}
	}
}

func TestInitRegistersTheAgentAndWritesAConfigurationThatLoadsStrictly(t *testing.T) {
	f := newSetupFixture(t)
	result := f.mustInit(t)
	world := f.world()
	// Two controllers are created: the packet controller and the
	// card-signing controller.
	if world.count("agent native-registry new-controller") != 2 || world.count("wallet send") != 1 ||
		world.count("agent native-registry register-agent") != 1 {
		t.Fatalf("calls = %+v", world.Calls)
	}
	if _, registered := world.Agents[result.AgentID]; !registered || !agentIDPattern.MatchString(result.AgentID) {
		t.Fatalf("Agent %q is not in finalized state", result.AgentID)
	}
	if result.TOSCTLPin != PinTrustOnFirstUse || !strings.Contains(result.TOSCTLPinNote, "trust on first use") {
		t.Fatalf("an unpinned tosctl was not reported as trust on first use: %+v", result)
	}
	config, err := LoadNodeConfig(f.init.RailConfigPath)
	if err != nil {
		t.Fatalf("the written configuration does not load strictly: %v", err)
	}
	info, err := os.Stat(f.init.RailConfigPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the configuration is not owner-only: %v %v", info, err)
	}
	want := NodeConfig{
		Network: NetworkConfig{
			NetworkID: fakeNetworkLabel, GenesisRootHash: "sha256:" + strings.Repeat("11", 32),
			GenesisFileHash: "sha256:" + strings.Repeat("22", 32),
		},
		GlobalConfigFile: f.init.GlobalConfigFile, RPCEndpoints: fakeEndpoints,
		RegistryCodeBOC: f.init.RegistryCodeBOC, RegistryCodeHash: "tvm-cell-sha256:" + world.CodeHash,
		ActorCodeHash: fakeCodeHashActor, StateDir: f.init.StateDir, AgentID: result.AgentID,
		PacketController: "openfox-packet", PacketKeyID: fakeKey("openfox-packet").Text(),
		CardController: "openfox-packet-card", CardKeyID: fakeKey("openfox-packet-card").Text(),
		TOSCTL: TOSCTLConfig{
			Binary: f.init.TOSCTLBinary, SHA256: result.TOSCTLSHA256, ConfigPath: f.init.TOSCTLConfigPath,
			VaultURLEnv: pfVaultEnvName,
		},
		WalletName: fakeWalletName, WalletAddress: fakeWalletAddress, MessengerSocket: f.init.MessengerSocket,
		ReceiverSocket: filepath.Join(f.init.StateDir, "rail-receiver.sock"),
	}
	if !reflect.DeepEqual(config, want) {
		t.Fatalf("configuration\n got %+v\nwant %+v", config, want)
	}
	// The registration went to the address the Agent id derives, with the
	// exact value previewed.
	send := world.last("wallet send")
	if fakeArgument(send.Args, "--to") != result.AgentAddress ||
		fakeArgument(
			send.Args,
			"--amount-nanotos",
		) != "2000000000" || fakeArgument(send.Args, "--from") != fakeWalletName {
		t.Fatalf("send = %v", send.Args)
	}
	for _, line := range *f.reports {
		if strings.Contains(line, pfSecretVault) || strings.Contains(line, "secret-token") {
			t.Fatalf("a report line leaks custody or an endpoint token: %s", line)
		}
	}
	// A second run changes nothing on chain and in the vault.
	again := f.mustInit(t)
	after := f.world()
	if after.sends() != 1 || after.count("agent native-registry new-controller") != 2 ||
		after.count("agent native-registry register-agent") != 1 || again.AgentID != result.AgentID {
		t.Fatalf("a re-run was not idempotent: %+v", after.Calls)
	}
	if again.TOSCTLPin != PinKept {
		t.Fatalf("pin on re-run = %s", again.TOSCTLPin)
	}
}

func TestInitWithoutYesCreatesSignsAndSendsNothing(t *testing.T) {
	f := newSetupFixture(t)
	f.init.Yes = false
	result, err := RunInit(context.Background(), f.init, f.env())
	mustFail(t, err, ErrConfirmationRequired)
	world := f.world()
	for _, label := range []string{
		"agent native-registry new-controller", "agent native-registry register-agent", "wallet send",
	} {
		if world.count(label) != 0 {
			t.Fatalf("%s ran without --yes", label)
		}
	}
	if result.Confirmed || len(world.Controllers) != 0 {
		t.Fatalf("result = %+v controllers = %v", result, world.Controllers)
	}
	if _, statErr := os.Stat(f.init.RailConfigPath); statErr == nil {
		t.Fatal("a configuration was written for an Agent that does not exist")
	}
	// With the controller present the plan still stops before signing.
	f.change(func(w *fakeWorld) { w.Controllers["openfox-packet"] = true })
	_, err = RunInit(context.Background(), f.init, f.env())
	mustFail(t, err, ErrConfirmationRequired)
	if world = f.world(); world.count("agent native-registry register-agent") != 0 || world.sends() != 0 {
		t.Fatalf("signed or sent without --yes: %+v", world.Calls)
	}
}

func TestInitStopsWithWhatToFundWhenTheWalletCannotPay(t *testing.T) {
	cases := map[string]struct {
		change    func(*fakeWorld)
		fragments []string
	}{
		"missing": {func(w *fakeWorld) { w.WalletMissing = true }, []string{"tosctl wallet create -n provider"}},
		"inactive": {
			func(w *fakeWorld) { w.WalletState = "uninit" },
			[]string{fakeWalletAddress, "2.050000000 TOS", "wallet activate"},
		},
		"unfunded": {
			func(w *fakeWorld) { w.WalletBalance = "2.0499" },
			[]string{fakeWalletAddress, "2.050000000 TOS"},
		},
		"chain down": {func(w *fakeWorld) { w.WalletState = "" }, []string{fakeWalletAddress, "chain_rpc"}},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			f := newSetupFixture(t)
			f.change(test.change)
			_, err := RunInit(context.Background(), f.init, f.env())
			mustFail(t, err, nil, test.fragments...)
			if world := f.world(); world.sends() != 0 || world.count("agent native-registry register-agent") != 0 {
				t.Fatalf("signed or sent from a wallet that cannot pay: %+v", world.Calls)
			}
		})
	}
	// Exactly the needed balance is enough.
	f := newSetupFixture(t)
	f.change(func(w *fakeWorld) { w.WalletBalance = "2.05" })
	f.mustInit(t)
}

func TestInitPinsTOSCTLAndRefusesAnotherBinary(t *testing.T) {
	f := newSetupFixture(t)
	f.init.TOSCTLSHA256 = strings.Repeat("0", 64)
	_, err := RunInit(context.Background(), f.init, f.env())
	mustFail(t, err, nil, "not the --tosctl-sha256 given")
	if len(f.world().Calls) != 0 {
		t.Fatal("tosctl was run although it does not have the SHA-256 given")
	}
	actual, err := HashTOSCTL(f.init.TOSCTLBinary)
	if err != nil {
		t.Fatal(err)
	}
	f.init.TOSCTLSHA256 = actual
	if result := f.mustInit(t); result.TOSCTLPin != PinGivenByOwner || result.TOSCTLSHA256 != actual {
		t.Fatalf("pin = %+v", result)
	}
	// The binary is replaced after it was pinned.
	f.init.TOSCTLSHA256 = ""
	calls := len(f.world().Calls)
	writeFixtureFile(t, f.init.TOSCTLBinary, []byte("another tosctl"), 0o700)
	_, err = RunInit(context.Background(), f.init, f.env())
	mustFail(t, err, nil, "changed since it was pinned", actual)
	if len(f.world().Calls) != calls {
		t.Fatal("a replaced tosctl was run")
	}
	replaced, _ := HashTOSCTL(f.init.TOSCTLBinary)
	f.init.TOSCTLSHA256 = replaced
	if result := f.mustInit(t); result.TOSCTLSHA256 != replaced {
		t.Fatalf("the owner's explicit new pin was not taken: %+v", result)
	}
}

func TestInitCrossChecksTheDomainAgainstTheCodeFileAndTheEndpoints(t *testing.T) {
	cases := map[string]struct {
		prepare  func(*setupFixture)
		fragment string
	}{
		"registry code file is other code": {func(f *setupFixture) {
			f.change(func(w *fakeWorld) { w.CodeHash = strings.Repeat("77", 32) })
		}, "does not hold the Native Registry code"},
		"label hash differs": {func(f *setupFixture) {
			f.change(func(w *fakeWorld) { w.LabelMismatch = true })
		}, "does not answer for the network label"},
		"an endpoint serves another genesis": {func(f *setupFixture) {
			f.change(func(w *fakeWorld) { w.GenesisFail[fakeEndpoints[1]] = "wrong" })
		}, "RPC endpoints serve the genesis"},
		"no quorum reachable": {func(f *setupFixture) {
			f.change(
				func(w *fakeWorld) { w.GenesisFail[fakeEndpoints[0]], w.GenesisFail[fakeEndpoints[2]] = "down", "down" },
			)
		}, "1 of 3 RPC endpoints"},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			f := newSetupFixture(t)
			test.prepare(f)
			_, err := RunInit(context.Background(), f.init, f.env())
			mustFail(t, err, nil, test.fragment)
			if strings.Contains(err.Error(), "secret-token") {
				t.Fatalf("the error leaks an endpoint token: %v", err)
			}
			world := f.world()
			if world.sends() != 0 || world.count("agent native-registry new-controller") != 0 {
				t.Fatalf("acted on an unverified domain: %+v", world.Calls)
			}
		})
	}
	// One unreachable endpoint with a quorum that matches is not a refusal.
	f := newSetupFixture(t)
	f.change(func(w *fakeWorld) { w.GenesisFail[fakeEndpoints[2]] = "down" })
	f.mustInit(t)
}

func TestInitRefusesARegistrationBuiltForAnotherAddress(t *testing.T) {
	f := newSetupFixture(t)
	f.script("agent native-registry register-agent", fakeWrongTarget)
	_, err := RunInit(context.Background(), f.init, f.env())
	mustFail(t, err, nil, "another address", "nothing was sent")
	if f.world().sends() != 0 {
		t.Fatal("a registration for an underived address was sent")
	}
}

func TestInitRefusesAChangedIdentityInputOnlyAfterTheRegistrationWasSent(t *testing.T) {
	// Before anything was sent the owner may still change their mind.
	f := newSetupFixture(t)
	f.script("agent native-registry register-agent", fakeWrongTarget)
	if _, err := RunInit(context.Background(), f.init, f.env()); err == nil {
		t.Fatal("setup of the unsent state failed to fail")
	}
	f.init.PacketController = "other-packet"
	first := f.mustInit(t)
	// After it was sent, another controller would be another Agent.
	f.init.PacketController = "third-packet"
	f.change(func(w *fakeWorld) { w.Controllers["third-packet"] = true })
	sends := f.world().sends()
	_, err := RunInit(context.Background(), f.init, f.env())
	mustFail(t, err, ErrSetupInputChanged, "packet_controller", first.AgentID)
	world := f.world()
	if world.sends() != sends || len(world.Agents) != 1 {
		t.Fatalf("a second Agent was registered: %v", world.Agents)
	}
	// The same holds when the journal is gone but the configuration names
	// the Agent: it is adopted, not replaced.
	g := newSetupFixture(t)
	adopted := g.mustInit(t)
	if err := os.Remove(setupJournalPath(g.init.StateDir)); err != nil {
		t.Fatal(err)
	}
	again := g.mustInit(t)
	if world := g.world(); again.AgentID != adopted.AgentID || world.sends() != 1 || len(world.Agents) != 1 {
		t.Fatalf("a lost journal led to a second Agent: %v", world.Agents)
	}
}

// The registration nonce is durable before the registration is built: a
// process killed while tosctl builds it comes back and builds the same
// Agent.
func TestInitKilledWhileBuildingRebuildsTheSameAgent(t *testing.T) {
	f := newSetupFixture(t)
	f.script("agent native-registry register-agent", fakeKillBefore)
	f.runKilled(t, "init", f.init)
	first := f.world().last("agent native-registry register-agent")
	journal := f.journal(t)
	if journal.Init == nil || journal.Init.AgentNonce == "" ||
		journal.Init.AgentNonce != fakeArgument(first.Args, "--nonce") {
		t.Fatalf("the nonce handed to tosctl was not durable first: %+v", journal.Init)
	}
	result := f.mustInit(t)
	world := f.world()
	second := world.last("agent native-registry register-agent")
	if fakeArgument(second.Args, "--nonce") != journal.Init.AgentNonce || world.count("wallet send") != 1 ||
		len(world.Agents) != 1 || world.Agents[result.AgentID] == "" {
		t.Fatalf("the restart did not rebuild the same Agent: %v", world.Agents)
	}
}

func TestInitNeverResendsARegistrationWhoseOutcomeIsUnknown(t *testing.T) {
	t.Run("killed after the message landed", func(t *testing.T) {
		f := newSetupFixture(t)
		f.script("wallet send", fakeKillAfter)
		f.runKilled(t, "init", f.init)
		if step := f.journal(t).Init.Agent; step.State != stepSending || step.Attempts != 1 {
			t.Fatalf("the journal does not say a message may be in flight: %+v", step)
		}
		result := f.mustInit(t)
		if world := f.world(); world.count("wallet send") != 1 || world.Agents[result.AgentID] == "" {
			t.Fatalf("a landed registration was sent again: %d sends", world.count("wallet send"))
		}
		if f.journal(t).Init.Agent.State != stepFinalized {
			t.Fatal("the step was not resolved from finalized state")
		}
	})
	t.Run("killed before the message had any effect", func(t *testing.T) {
		f := newSetupFixture(t)
		f.script("wallet send", fakeKillBefore)
		f.runKilled(t, "init", f.init)
		// Inside the inclusion window the outcome is unknown: wait, never
		// send.
		_, err := RunInit(context.Background(), f.init, f.env())
		mustFail(t, err, ErrOutcomeUnknown, "nothing was re-sent")
		if world := f.world(); world.count("wallet send") != 1 || len(world.Agents) != 0 {
			t.Fatalf("an unknown outcome was answered by sending: %d sends", world.count("wallet send"))
		}
		// Past the window on finalized chain time the first message cannot
		// land any more; the same Agent is registered, once.
		nonce := f.journal(t).Init.AgentNonce
		f.change(func(w *fakeWorld) { w.Clock += int64(sendResolutionWindow.Seconds()) })
		result := f.mustInit(t)
		world := f.world()
		if world.count("wallet send") != 2 || len(world.Agents) != 1 || f.journal(t).Init.AgentNonce != nonce ||
			world.Agents[result.AgentID] == "" {
			t.Fatalf("after the window: sends %d agents %v", world.count("wallet send"), world.Agents)
		}
	})
	t.Run("the send fails but the message landed", func(t *testing.T) {
		f := newSetupFixture(t)
		f.script("wallet send", fakeLandedError)
		result := f.mustInit(t)
		if world := f.world(); world.count("wallet send") != 1 || world.Agents[result.AgentID] == "" {
			t.Fatalf("sends = %d", world.count("wallet send"))
		}
	})
	t.Run("the send fails and nothing lands", func(t *testing.T) {
		f := newSetupFixture(t)
		f.script("wallet send", fakeLost)
		_, err := RunInit(context.Background(), f.init, f.env())
		mustFail(t, err, ErrOutcomeUnknown)
		if step := f.journal(t).Init.Agent; step.State != stepSending {
			t.Fatalf("an unknown outcome was recorded as %q", step.State)
		}
		_, err = RunInit(context.Background(), f.init, f.env())
		mustFail(t, err, ErrOutcomeUnknown)
		if f.world().count("wallet send") != 1 {
			t.Fatal("the unknown outcome was answered by sending again")
		}
		if _, statErr := os.Stat(f.init.RailConfigPath); statErr == nil {
			t.Fatal("a configuration was written for an Agent that is not finalized")
		}
	})
	t.Run("tosctl refuses before broadcasting", func(t *testing.T) {
		f := newSetupFixture(t)
		f.script("wallet send", fakeRefuseBalance)
		_, err := RunInit(context.Background(), f.init, f.env())
		mustFail(t, err, nil, string(TOSCTLFailureBalance))
		if step := f.journal(t).Init.Agent; step.State != stepPending {
			t.Fatalf("a refused send is recorded as in flight: %+v", step)
		}
		// Nothing is in flight, so the next run sends without waiting.
		f.mustInit(t)
		if f.world().count("wallet send") != 2 {
			t.Fatal("the refused send was not retried")
		}
	})
}

// fakePolicyJSON is a stored policy of the fake world.
func fakePolicyJSON(t *testing.T, threshold uint32, controllers ...agentPolicyController) string {
	t.Helper()
	encoded, err := json.Marshal(agentPolicyFile{
		Threshold: threshold, RecoveryThreshold: threshold, RecoveryTimelock: agentRecoveryTimelock,
		Controllers: controllers,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func fakeController(name string, weight uint32, purposes uint16) agentPolicyController {
	return agentPolicyController{
		PublicKey: hex.EncodeToString(fakeKey(name).PublicKey), Weight: weight, Purposes: purposes,
	}
}

func TestInitRefusesAnAgentWhoseFinalizedPolicyLacksThePacketKey(t *testing.T) {
	f := newSetupFixture(t)
	first := f.mustInit(t)
	f.change(func(w *fakeWorld) {
		w.Agents[first.AgentID] = fakePolicyJSON(t, 2, fakeController("another", 2, 15),
			fakeController(first.CardController, 1, cardControllerPurposes))
	})
	_, err := RunInit(context.Background(), f.init, f.env())
	mustFail(t, err, nil, "does not hold packet key")
}

func TestInitRegistersTheCardControllerWithoutAuthorityBesideThePacketController(t *testing.T) {
	f := newSetupFixture(t)
	result := f.mustInit(t)
	if result.CardController != f.init.PacketController+"-card" || result.CardKeyID == "" ||
		result.CardKeyID == result.PacketKeyID {
		t.Fatalf("card controller %q (%s), packet %s", result.CardController, result.CardKeyID, result.PacketKeyID)
	}
	config, err := LoadNodeConfig(f.init.RailConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if config.CardController != result.CardController || config.CardKeyID != result.CardKeyID {
		t.Fatalf("the configuration names card controller %q (%s)", config.CardController, config.CardKeyID)
	}
	world := f.world()
	policy, err := fakeFinalizedPolicy(world.Agents[result.AgentID])
	if err != nil {
		t.Fatal(err)
	}
	// The registry's own rules accept the policy: valid controllers, every
	// purpose and recovery reachable, consent met by the signers.
	if err = nativecore.VerifyRegistrationConsent(policy); err != nil {
		t.Fatalf("the registry refuses the registered policy: %v", err)
	}
	agent := &nativev1.AgentStateV1{AgentId: result.AgentID, Policy: policy}
	if err = checkCardController(agent, result.CardKeyID, result.PacketKeyID); err != nil {
		t.Fatalf("the registered card controller is refused: %v", err)
	}
	// The packet controller alone still meets every threshold.
	var packetWeight uint32
	for _, controller := range policy.GetControllers() {
		if controller.GetKeyId() == result.PacketKeyID {
			packetWeight = controller.GetWeight()
		}
	}
	if packetWeight < policy.GetThreshold() || packetWeight < policy.GetRecoveryThreshold() {
		t.Fatalf("the packet controller (weight %d) no longer meets threshold %d / recovery %d", packetWeight,
			policy.GetThreshold(), policy.GetRecoveryThreshold())
	}
	var signers []string
	for _, call := range world.Calls {
		if call.Label == "agent native-registry register-agent" {
			signers = fakeArguments(call.Args, "--signer")
		}
	}
	if len(signers) != 2 || signers[0] != f.init.PacketController || signers[1] != result.CardController {
		t.Fatalf("the registration was signed by %v", signers)
	}
}

func TestInitRefusesAnAgentWhoseCardControllerIsMissingOrHoldsAuthority(t *testing.T) {
	cases := map[string]func(packet, card string) string{
		"card controller missing": func(packet, _ string) string {
			return fakePolicyJSON(t, 2, fakeController(packet, 2, 15))
		},
		"card controller meets the threshold": func(packet, card string) string {
			return fakePolicyJSON(t, 2, fakeController(packet, 2, 15), fakeController(card, 2, 2))
		},
		"card controller holds recovery": func(packet, card string) string {
			return fakePolicyJSON(t, 2, fakeController(packet, 2, 15), fakeController(card, 1, 4))
		},
	}
	for name, policy := range cases {
		t.Run(name, func(t *testing.T) {
			f := newSetupFixture(t)
			first := f.mustInit(t)
			f.change(func(w *fakeWorld) {
				w.Agents[first.AgentID] = policy(f.init.PacketController, first.CardController)
			})
			_, err := RunInit(context.Background(), f.init, f.env())
			mustFail(t, err, nil, "card-signing controller is not usable")
		})
	}
}

func TestInitRefusesACardControllerThatIsThePacketController(t *testing.T) {
	f := newSetupFixture(t)
	f.init.CardController = f.init.PacketController
	if _, err := RunInit(context.Background(), f.init, f.env()); err == nil ||
		!strings.Contains(err.Error(), "another controller than the packet controller") {
		t.Fatalf("accepted the packet controller as card controller: %v", err)
	}
	if len(f.world().Calls) != 0 {
		t.Fatal("tosctl was run on invalid input")
	}
}

func TestInitValidatesItsInputsBeforeTouchingAnything(t *testing.T) {
	cases := map[string]func(*InitInput){
		"relative state dir":   func(in *InitInput) { in.StateDir = "state" },
		"bad actor code hash":  func(in *InitInput) { in.ActorCodeHash = "sha256:" + strings.Repeat("88", 32) },
		"bad wallet name":      func(in *InitInput) { in.WalletName = "--yes" },
		"bad network label":    func(in *InitInput) { in.NetworkLabel = "--config" },
		"bad direct peer":      func(in *InitInput) { in.DirectPeers = map[string]string{"agent_x": "/tmp/s"} },
		"relative peer socket": func(in *InitInput) { in.DirectPeers = map[string]string{testBuyer: "peer.sock"} },
		"unbounded buyer": func(in *InitInput) {
			in.Buyer = &BuyerNode{Policy: PolicyConfig{MaxCommittedPerPurchase: "1", MaxCommittedInWindow: "1"}}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newSetupFixture(t)
			mutate(&f.init)
			if _, err := RunInit(context.Background(), f.init, f.env()); err == nil {
				t.Fatal("accepted")
			}
			if len(f.world().Calls) != 0 {
				t.Fatal("tosctl was run on invalid input")
			}
		})
	}
}

func TestInitKeepsTheSectionsItDoesNotOwnAndWritesABuyerSection(t *testing.T) {
	f := newSetupFixture(t)
	f.init.DirectPeers = map[string]string{testBuyer: "/run/peer/rail-receiver.sock"}
	f.init.Buyer = &BuyerNode{Policy: PolicyConfig{
		MaxCommittedPerPurchase: "2000000000", MaxCommittedInWindow: "10000000000", WindowSeconds: 86400,
		MaxOpenPurchases: 4, RefundReserve: "300000000", AllowedProviders: []string{testSeller},
	}}
	f.mustInit(t)
	f.mustOffer(t)
	// A re-run that restates neither the buyer nor the transport keeps
	// both, and the provider section offer wrote.
	f.init.Buyer, f.init.DirectPeers, f.init.MessengerSocket = nil, nil, ""
	f.mustInit(t)
	config, err := LoadNodeConfig(f.init.RailConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if config.Provider == nil || config.Buyer == nil || config.Buyer.Policy.AllowedProviders[0] != testSeller ||
		config.DirectPeers[testBuyer] == "" || config.MessengerSocket == "" {
		t.Fatalf("a re-run dropped a section: %+v", config)
	}
}

// Two nodes that reach each other directly each need the other's Agent id,
// which only that node's init produces. So the first init names no
// transport: it establishes the node, says what is missing, and the node
// does not start until a second run adds the peer, without a second Agent.
func TestInitWithoutATransportEstablishesTheNodeWhichCannotStartUntilOneIsAdded(t *testing.T) {
	f := newSetupFixture(t)
	f.init.MessengerSocket = ""
	first := f.mustInit(t)
	missing := false
	for _, step := range first.Steps {
		missing = missing || (step.ID == "transport" && step.Status == SetupMissing)
	}
	if !missing || len(first.NextSteps) == 0 || !strings.Contains(first.NextSteps[0], "--direct-peer") {
		t.Fatalf("the report does not say a transport is missing: %+v", first)
	}
	config, err := LoadNodeConfig(f.init.RailConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if config.MessengerSocket != "" || len(config.DirectPeers) != 0 || config.AgentID != first.AgentID {
		t.Fatalf("configuration = %+v", config)
	}
	if _, err = openPacketTransport(config, nil); err == nil {
		t.Fatal("a node without a transport opened one")
	}
	f.init.DirectPeers = map[string]string{testBuyer: "/run/peer/rail-receiver.sock"}
	second := f.mustInit(t)
	for _, step := range second.Steps {
		if step.ID == "transport" {
			t.Fatalf("a transport is still reported missing: %+v", step)
		}
	}
	config, err = LoadNodeConfig(f.init.RailConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if config.DirectPeers[testBuyer] != "/run/peer/rail-receiver.sock" || second.AgentID != first.AgentID ||
		f.world().count("wallet send") != 1 {
		t.Fatalf("adding the peer changed the Agent or sent again: %+v", config)
	}
	if _, err = openPacketTransport(config, nil); err != nil {
		t.Fatalf("the node with a direct peer has no transport: %v", err)
	}
}
