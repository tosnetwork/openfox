package servicebridge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/serviceactor"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
)

// The preflight fixture's chain values are synthetic shapes checked by the
// protocol's own decoders and verifiers, not contract-produced vectors.
var (
	pfCapability   = "cap_" + strings.Repeat("33", 32)
	pfActor        = "0:" + strings.Repeat("77", 32)
	pfCodeHash     = "tvm-cell-sha256:" + strings.Repeat("88", 32)
	pfAttestorKey  = bytes.Repeat([]byte{0x5a}, mldsa44.PublicKeySize)
	pfAttestorID   = func() [32]byte { id, _ := mldsa44.KeyID(pfAttestorKey); return id }()
	pfPacketID     = [32]byte{0x61}
	pfChainNow     = time.Unix(1_900_000_000, 0)
	pfEndpoints    = []string{"http://127.0.0.1:18001/token-a", "http://127.0.0.1:18002", "http://127.0.0.1:18003"}
	pfSecretVault  = "file:///vault.json?master_key=" + strings.Repeat("5e", 32)
	pfVaultEnvName = "OPENFOX_TEST_VAULT_URL"
)

type pfChain struct {
	genesis    map[string]error
	beginErr   error
	chainTime  time.Time
	capability *nativev1.NativeStateV1
	agent      *nativev1.NativeStateV1
	registry   error
	actor      *toschain.ActorAccount
	actorErr   error
}

func (c *pfChain) Endpoints() []string { return append([]string(nil), pfEndpoints...) }

func (c *pfChain) CheckEndpointGenesis(_ context.Context, endpoint string) error {
	return c.genesis[endpoint]
}

func (c *pfChain) BeginPreflight(context.Context) (serviceactor.Session, error) {
	if c.beginErr != nil {
		return nil, c.beginErr
	}
	return c, nil
}

func (c *pfChain) Checkpoint() uint64   { return 77 }
func (c *pfChain) ChainTime() time.Time { return c.chainTime }

func (c *pfChain) ResolveRegistry(_ context.Context, id string) (*nativev1.NativeStateV1, bool, error) {
	if c.registry != nil {
		return nil, false, c.registry
	}
	var state *nativev1.NativeStateV1
	switch {
	case c.capability != nil && id == c.capability.GetCapability().GetCapabilityId():
		state = c.capability
	case c.agent != nil && id == c.agent.GetAgent().GetAgentId():
		state = c.agent
	default:
		return nil, false, nil
	}
	state.Reference = &nativev1.ChainReference{FinalizedCheckpoint: 77}
	return state, true, nil
}

func (c *pfChain) ReadActor(_ context.Context, actor string) (*toschain.ActorAccount, bool, error) {
	if c.actorErr != nil {
		return nil, false, c.actorErr
	}
	if c.actor == nil || actor != c.actor.Address {
		return nil, false, nil
	}
	return c.actor, true, nil
}

type pfFixture struct {
	configPath string
	config     NodeConfig
	chain      *pfChain
	env        PreflightEnv
	probes     map[string][32]byte
	probeErr   error
	free       uint64
	euid       int
	vault      string
}

func pfWritePinned(t *testing.T, directory, name string, content []byte) (string, string) {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, content, 0o700); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	return path, hex.EncodeToString(sum[:])
}

// newPreflightFixture returns a provider node every check passes on.
func newPreflightFixture(t *testing.T) *pfFixture {
	t.Helper()
	root := t.TempDir()
	state := filepath.Join(root, "state")
	if err := ensurePrivateDirectory(state); err != nil {
		t.Fatal(err)
	}
	tosctl, tosctlSum := pfWritePinned(t, root, "tosctl", []byte("#!/bin/sh\nexit 1\n"))
	executor, executorSum := pfWritePinned(t, root, "executor", []byte("#!/bin/sh\nexit 2\n"))
	tosctlConfig := filepath.Join(root, "tosctl-config.json")
	if err := os.WriteFile(tosctlConfig, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	socketDir, err := os.MkdirTemp("", "pf")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socket := filepath.Join(socketDir, "c.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if chmodErr := os.Chmod(socket, 0o660); chmodErr != nil {
		t.Fatal(chmodErr)
	}
	attestor := mldsa44.KeyIDText(pfAttestorID)
	manifestCBOR, digest, _, err := BuildManifest(ManifestInput{
		ProviderAgentID: testSeller, Actor: pfActor,
		ActorCodeHash: pfCodeHash, Attestor: attestor, Version: "1.0.0", RetentionSeconds: 86400,
	})
	if err != nil {
		t.Fatal(err)
	}
	manifestFile := filepath.Join(root, "manifest.cbor")
	if writeErr := os.WriteFile(manifestFile, manifestCBOR, 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	registryBOC := filepath.Join(root, "registry.boc")
	if writeErr := os.WriteFile(registryBOC, []byte("te6cc"), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	config := NodeConfig{
		Network: NetworkConfig{
			NetworkID: testNetwork.GetNetworkId(), GenesisRootHash: testNetwork.GetGenesisRootHash(),
			GenesisFileHash: testNetwork.GetGenesisFileHash(),
		},
		RPCEndpoints: pfEndpoints, RegistryCodeBOC: registryBOC,
		RegistryCodeHash: "tvm-cell-sha256:" + strings.Repeat("66", 32), ActorCodeHash: pfCodeHash, StateDir: state,
		AgentID: testSeller, PacketController: "packet", PacketKeyID: mldsa44.KeyIDText(pfPacketID),
		TOSCTL: TOSCTLConfig{
			Binary:      tosctl,
			SHA256:      tosctlSum,
			ConfigPath:  tosctlConfig,
			VaultURLEnv: pfVaultEnvName,
		},
		WalletName: "provider", WalletAddress: testWallet,
		MessengerSocket: filepath.Join(root, "m.sock"), ReceiverSocket: filepath.Join(root, "r.sock"),
		Provider: &ProviderNode{
			CapabilityID: pfCapability, Version: "1.0.0", ManifestFile: manifestFile,
			AttestorController: "service-attestor", RespondBudgetSecond: 120, ExecutorBinary: executor,
			ExecutorSHA256: executorSum, ContainerdSocket: socket, FIFODir: filepath.Join(root, "fifo"),
		},
	}
	metadata, err := nativecore.ServiceActorMetadataHash(nativecore.ServiceActorMetadataInputV1{
		Network:      testNetwork,
		CapabilityID: pfCapability, ProviderAgentID: testSeller, CapabilityVersion: "1.0.0", ManifestDigest: digest,
	})
	if err != nil {
		t.Fatal(err)
	}
	owner, err := nativecore.StandardAddress("0:" + strings.Repeat("11", 32))
	if err != nil {
		t.Fatal(err)
	}
	policy := nativecore.ServiceActorPolicyV1{
		PolicyVersion: 2, PricePerCall: big.NewInt(300_000_000),
		StorageFee: big.NewInt(200_000_000), CleanupBounty: big.NewInt(100_000_000), ResponseSLA: 3600,
		RefundClaimWindow: 3600, OpenAccess: true, MetadataHash: metadata,
		ProofSchemeHash: nativecore.ServiceActorSoftwareWorkProofScheme, HasAttestor: true,
		AttestorKeyID: pfAttestorID, AttestorKey: pfAttestorKey,
	}
	chain := &pfChain{
		genesis: map[string]error{}, chainTime: pfChainNow.Add(-4 * time.Second),
		capability: &nativev1.NativeStateV1{Network: testNetwork, State: &nativev1.NativeStateV1_Capability{
			Capability: &nativev1.CapabilityStateV1{
				CapabilityId: pfCapability, OwnerAgentId: testSeller,
				Versions: []*nativev1.CapabilityVersionV1{{Version: "1.0.0", ManifestDigest: digest}},
			},
		}},
		agent: &nativev1.NativeStateV1{Network: testNetwork, State: &nativev1.NativeStateV1_Agent{
			Agent: &nativev1.AgentStateV1{AgentId: testSeller},
		}},
		actor: &toschain.ActorAccount{
			Address: pfActor, CodeHash: pfCodeHash, BalanceNano: 3_000_000_000,
			Data: &nativecore.ServiceActorDataV1{Owner: owner, Active: true, Policy: policy},
		},
	}
	f := &pfFixture{
		config: config, chain: chain, free: 4 << 30, euid: 1000, vault: pfSecretVault,
		probes: map[string][32]byte{"service-attestor": pfAttestorID, "packet": pfPacketID},
	}
	f.configPath = filepath.Join(root, "rail.json")
	f.env = PreflightEnv{
		Now: func() time.Time { return pfChainNow },
		OpenChain: func(NodeConfig, string) (PreflightChain, error) {
			return f.chain, nil
		},
		ProbeController: func(_ context.Context, _ NodeConfig, controller string) ([32]byte, error) {
			if f.probeErr != nil {
				return [32]byte{}, f.probeErr
			}
			id, ok := f.probes[controller]
			if !ok {
				return [32]byte{}, errors.New("no such controller")
			}
			return id, nil
		},
		FreeBytes: func(string) (uint64, error) { return f.free, nil },
		Euid:      func() int { return f.euid },
		Getenv: func(name string) string {
			if name == pfVaultEnvName {
				return f.vault
			}
			return ""
		},
	}
	return f
}

func (f *pfFixture) run(t *testing.T) (*PreflightReport, map[string]PreflightCheck) {
	t.Helper()
	raw, err := json.Marshal(f.config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.configPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	report := RunPreflight(context.Background(), f.configPath, f.env)
	checks := map[string]PreflightCheck{}
	for _, check := range report.Checks {
		if _, duplicate := checks[check.ID]; duplicate {
			t.Fatalf("check %s reported twice", check.ID)
		}
		checks[check.ID] = check
	}
	return report, checks
}

var allPreflightChecks = []string{
	"config.parse", "config.provider", "state_dir.private", "state_dir.disk_free", "admission.pause",
	"process.user", "tosctl.pin", "tosctl.config", "tosctl.vault_env", "executor.pin", "containerd.socket",
	"manifest.local", "rpc.endpoints", "rpc.independence", "chain.open", "rpc.genesis", "chain.finalized",
	"clock.skew", "chain.registry", "chain.capability", "chain.actor", "chain.attestor", "chain.admission",
	"signer.attestor", "signer.packet", "signer.wallet",
}

func TestPreflightPassesEveryCheckOnAReadyProvider(t *testing.T) {
	f := newPreflightFixture(t)
	report, checks := f.run(t)
	if !report.OK || report.Schema != PreflightSchema || report.Version != PreflightVersion || report.AdmissionPaused {
		t.Fatalf("a ready provider failed: %+v", report)
	}
	for _, id := range allPreflightChecks {
		check, ok := checks[id]
		if !ok {
			t.Fatalf("check %s is missing", id)
		}
		want := CheckPass
		if id == "rpc.independence" || id == "signer.wallet" {
			want = CheckUnknown
		}
		if check.Status != want || check.Message == "" {
			t.Fatalf("check %s: %s (%s), want %s", id, check.Status, check.Message, want)
		}
	}
	if len(checks) != len(allPreflightChecks) {
		t.Fatalf("%d checks reported, want %d", len(checks), len(allPreflightChecks))
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{pfSecretVault, strings.Repeat("5e", 32), "token-a"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("the report prints %q", secret)
		}
	}
}

func TestEachPreflightCheckFailsWithAnActionableMessage(t *testing.T) {
	cases := []struct {
		id     string
		status string
		break_ func(t *testing.T, f *pfFixture)
	}{
		{"config.provider", CheckFail, func(_ *testing.T, f *pfFixture) { f.config.Provider.CapabilityID = "cap_x" }},
		{"state_dir.private", CheckFail, func(t *testing.T, f *pfFixture) {
			if err := os.Chmod(f.config.StateDir, 0o750); err != nil {
				t.Fatal(err)
			}
		}},
		{"state_dir.private", CheckFail, func(t *testing.T, f *pfFixture) {
			link := f.config.StateDir + "-link"
			if err := os.Symlink(f.config.StateDir, link); err != nil {
				t.Fatal(err)
			}
			f.config.StateDir = link
		}},
		{"state_dir.private", CheckFail, func(_ *testing.T, f *pfFixture) { f.config.StateDir += "-missing" }},
		{"state_dir.disk_free", CheckFail, func(_ *testing.T, f *pfFixture) { f.free = MinStateDirFreeBytes - 1 }},
		{"admission.pause", CheckWarn, func(t *testing.T, f *pfFixture) {
			if _, _, err := PauseAdmission(f.config.StateDir, "", pfChainNow); err != nil {
				t.Fatal(err)
			}
		}},
		{"process.user", CheckWarn, func(_ *testing.T, f *pfFixture) { f.euid = 0 }},
		{
			"tosctl.pin",
			CheckFail,
			func(_ *testing.T, f *pfFixture) { f.config.TOSCTL.SHA256 = strings.Repeat("0", 64) },
		},
		{"tosctl.config", CheckFail, func(t *testing.T, f *pfFixture) {
			if err := os.Chmod(f.config.TOSCTL.ConfigPath, 0o604); err != nil {
				t.Fatal(err)
			}
		}},
		{"tosctl.vault_env", CheckFail, func(_ *testing.T, f *pfFixture) { f.vault = "" }},
		{"executor.pin", CheckFail, func(_ *testing.T, f *pfFixture) {
			f.config.Provider.ExecutorSHA256 = strings.Repeat("0", 64)
		}},
		{"containerd.socket", CheckFail, func(t *testing.T, f *pfFixture) {
			if err := os.Chmod(f.config.Provider.ContainerdSocket, 0o666); err != nil {
				t.Fatal(err)
			}
		}},
		{"containerd.socket", CheckFail, func(_ *testing.T, f *pfFixture) {
			f.config.Provider.ContainerdSocket = f.config.Provider.ManifestFile
		}},
		{"manifest.local", CheckFail, func(_ *testing.T, f *pfFixture) {
			f.config.ActorCodeHash = "tvm-cell-sha256:" + strings.Repeat("89", 32)
		}},
		{"rpc.endpoints", CheckFail, func(_ *testing.T, f *pfFixture) { f.config.Quorum = 1 }},
		{"rpc.endpoints", CheckFail, func(_ *testing.T, f *pfFixture) { f.config.RPCEndpoints = pfEndpoints[:2] }},
		{"rpc.genesis", CheckFail, func(_ *testing.T, f *pfFixture) {
			f.chain.genesis[pfEndpoints[1]] = nativecore.NewProtocolError(
				nativecore.ErrWrongNetwork,
				"genesis root",
				nil,
			)
		}},
		{"rpc.genesis", CheckWarn, func(_ *testing.T, f *pfFixture) {
			// Transport errors quote the URL, whose path may carry a token.
			f.chain.genesis[pfEndpoints[0]] = errors.New("post " + pfEndpoints[0] + ": connection refused")
		}},
		{"rpc.genesis", CheckFail, func(_ *testing.T, f *pfFixture) {
			f.chain.genesis[pfEndpoints[1]] = errors.New("connection refused")
			f.chain.genesis[pfEndpoints[2]] = errors.New("connection refused")
		}},
		{"chain.finalized", CheckFail, func(_ *testing.T, f *pfFixture) { f.chain.beginErr = errors.New("no quorum") }},
		{"clock.skew", CheckWarn, func(_ *testing.T, f *pfFixture) {
			f.chain.chainTime = pfChainNow.Add(-ClockSkewWarning - time.Second)
		}},
		{"chain.registry", CheckFail, func(_ *testing.T, f *pfFixture) {
			f.chain.registry = errors.New("Native account code hash mismatch")
		}},
		{"chain.capability", CheckFail, func(_ *testing.T, f *pfFixture) { f.chain.capability = nil }},
		{"chain.capability", CheckFail, func(_ *testing.T, f *pfFixture) {
			f.chain.capability.GetCapability().Versions[0].ManifestDigest = "sha256:" + strings.Repeat("01", 32)
		}},
		{"chain.capability", CheckFail, func(_ *testing.T, f *pfFixture) {
			f.chain.capability.GetCapability().OwnerAgentId = testBuyer
		}},
		{"chain.capability", CheckFail, func(_ *testing.T, f *pfFixture) {
			f.chain.capability.GetCapability().Versions[0].Revoked = true
		}},
		{"chain.actor", CheckFail, func(_ *testing.T, f *pfFixture) { f.chain.actor = nil }},
		{"chain.actor", CheckFail, func(_ *testing.T, f *pfFixture) { f.chain.actor.Data.Active = false }},
		{"chain.actor", CheckFail, func(_ *testing.T, f *pfFixture) {
			f.chain.actorErr = errors.New("Native account code hash mismatch")
		}},
		{"chain.attestor", CheckFail, func(_ *testing.T, f *pfFixture) {
			f.chain.actor.Data.Policy.HasAttestor = false
			f.chain.actor.Data.Policy.AttestorKeyID = [32]byte{}
			f.chain.actor.Data.Policy.AttestorKey = nil
		}},
		{"chain.attestor", CheckFail, func(_ *testing.T, f *pfFixture) {
			f.chain.actor.Data.Policy.AttestorKeyID = [32]byte{0x01}
		}},
		{"chain.admission", CheckFail, func(_ *testing.T, f *pfFixture) {
			f.chain.actor.Data.Policy.MetadataHash = [32]byte{0x02}
		}},
		{"chain.admission", CheckFail, func(_ *testing.T, f *pfFixture) { f.chain.agent = nil }},
		{"signer.attestor", CheckFail, func(_ *testing.T, f *pfFixture) { f.probes["service-attestor"] = [32]byte{3} }},
		{"signer.attestor", CheckFail, func(_ *testing.T, f *pfFixture) { f.probeErr = errors.New("vault locked") }},
		{"signer.packet", CheckFail, func(_ *testing.T, f *pfFixture) { delete(f.probes, "packet") }},
		{"signer.packet", CheckFail, func(_ *testing.T, f *pfFixture) { f.probes["packet"] = [32]byte{4} }},
	}
	for _, test := range cases {
		t.Run(test.id, func(t *testing.T) {
			f := newPreflightFixture(t)
			test.break_(t, f)
			report, checks := f.run(t)
			check, ok := checks[test.id]
			if !ok {
				t.Fatalf("check %s is missing", test.id)
			}
			if check.Status != test.status || check.Message == "" {
				t.Fatalf("check %s: %s (%s), want %s", test.id, check.Status, check.Message, test.status)
			}
			if report.OK != (test.status != CheckFail) {
				t.Fatalf("report ok = %v with %s %s", report.OK, test.id, check.Status)
			}
			if strings.Contains(check.Message, "token-a") || strings.Contains(check.Message, pfSecretVault) {
				t.Fatalf("the message prints a secret: %s", check.Message)
			}
		})
	}
}

func TestPreflightNamesAnAttestorLessActorAsRefused(t *testing.T) {
	f := newPreflightFixture(t)
	f.chain.actor.Data.Policy.HasAttestor = false
	f.chain.actor.Data.Policy.AttestorKeyID = [32]byte{}
	f.chain.actor.Data.Policy.AttestorKey = nil
	report, checks := f.run(t)
	check := checks["chain.attestor"]
	if report.OK || check.Status != CheckFail || !strings.Contains(check.Message, "no attestor") {
		t.Fatalf("an attestor-less actor was not named as refused: %+v", check)
	}
}

func TestPreflightRefusesAConfigurationThatIsNotStrictOrOwnerOnly(t *testing.T) {
	f := newPreflightFixture(t)
	if _, checks := f.run(t); checks["config.parse"].Status != CheckPass {
		t.Fatal("the fixture configuration did not parse")
	}
	if err := os.WriteFile(f.configPath, []byte(`{"unknown_field":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	report := RunPreflight(context.Background(), f.configPath, f.env)
	if report.OK || len(report.Checks) != 1 || report.Checks[0].ID != "config.parse" ||
		report.Checks[0].Status != CheckFail {
		t.Fatalf("an unknown field was accepted: %+v", report)
	}
	if err := os.Chmod(f.configPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if report := RunPreflight(context.Background(), f.configPath, f.env); report.OK {
		t.Fatal("a world-readable configuration was accepted")
	}
}

func TestPreflightWritesNothingIntoTheStateDirectory(t *testing.T) {
	f := newPreflightFixture(t)
	opened := ""
	f.env.OpenChain = func(_ NodeConfig, checkpointDir string) (PreflightChain, error) {
		opened = checkpointDir
		return f.chain, nil
	}
	if report, _ := f.run(t); !report.OK {
		t.Fatalf("the fixture failed: %+v", report)
	}
	entries, err := os.ReadDir(f.config.StateDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("preflight wrote into state_dir: %v %v", entries, err)
	}
	if opened == "" || strings.HasPrefix(opened, f.config.StateDir) {
		t.Fatalf("the checkpoint fences were placed in %q", opened)
	}
	if _, err := os.Stat(opened); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the scratch directory was left behind: %v", err)
	}
}
