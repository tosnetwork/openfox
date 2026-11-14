package servicebridge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

// The fake world stands in for tosctl and the chain in the setup tests. It
// lives in a file, so a helper process that is killed mid-step and the test
// that restarts the command see the same chain and the same record of what
// tosctl was asked to do. Its addresses and ids are shapes the protocol's
// own decoders accept, not contract-produced vectors.

// Behaviors a scripted tosctl call can take. The kill behaviors end the
// process with SIGKILL and are used only in a helper process.
const (
	fakeOK            = ""
	fakeKillBefore    = "kill-before"    // die before the message has any effect
	fakeKillAfter     = "kill-after"     // the message lands, then die before answering
	fakeLost          = "lost"           // fail without effect, cause unknown to the caller
	fakeLandedError   = "landed-error"   // the message lands, the call still fails
	fakeRefuseBalance = "refuse-balance" // tosctl refuses before broadcasting
	fakeWrongTarget   = "wrong-target"   // a builder answers for another address
	fakeFailedTx      = "failed-tx"      // the message is included and its transaction fails
)

const (
	fakeCodeHashActor = "tvm-cell-sha256:8888888888888888888888888888888888888888888888888888888888888888"
	fakeWalletAddress = "0:2121212121212121212121212121212121212121212121212121212121212121"
	fakeWalletName    = "provider"
	fakeNetworkLabel  = "tos:global-id:7"
)

var fakeEndpoints = []string{"http://127.0.0.1:19001/secret-token", "http://127.0.0.1:19002", "http://127.0.0.1:19003"}

type fakeCall struct {
	Label string   `json:"label"`
	Args  []string `json:"args"`
}

type fakeCapability struct {
	Owner   string `json:"owner"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
}

type fakeActor struct {
	Address     string     `json:"address"`
	Owner       string     `json:"owner"`
	Attestor    string     `json:"attestor"`
	Terms       ActorTerms `json:"terms"`
	Metadata    string     `json:"metadata"`
	Proof       string     `json:"proof"`
	Revenue     uint64     `json:"revenue"`
	LastLT      uint64     `json:"last_lt"`
	CodeHash    string     `json:"code_hash"`
	PolicyCount uint32     `json:"policy_count"`
}

type fakeWorld struct {
	path          string
	GenesisRoot   string                       `json:"genesis_root"`
	GenesisFile   string                       `json:"genesis_file"`
	CodeHash      string                       `json:"code_hash"`
	Controllers   map[string]bool              `json:"controllers"`
	WalletState   string                       `json:"wallet_state"`
	WalletBalance string                       `json:"wallet_balance"`
	WalletMissing bool                         `json:"wallet_missing"`
	Agents        map[string]string            `json:"agents"`
	Capabilities  map[string]fakeCapability    `json:"capabilities"`
	Actor         *fakeActor                   `json:"actor"`
	History       []toschain.ActorTransaction  `json:"history"`
	Clock         int64                        `json:"clock"`
	Checkpoint    uint64                       `json:"checkpoint"`
	Calls         []fakeCall                   `json:"calls"`
	Script        map[string][]string          `json:"script"`
	GenesisFail   map[string]string            `json:"genesis_fail"`
	LabelMismatch bool                         `json:"label_mismatch"`
	RandomCounter uint64                       `json:"random_counter"`
	Registrations map[string]map[string]string `json:"registrations"`
}

func loadWorld(path string) *fakeWorld {
	raw, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	world := &fakeWorld{}
	if err := json.Unmarshal(raw, world); err != nil {
		panic(err)
	}
	world.path = path
	return world
}

func (w *fakeWorld) save() {
	raw, err := json.Marshal(w)
	if err != nil {
		panic(err)
	}
	// The world must survive a SIGKILL right after a message "landed".
	if err := replaceSynced(w.path, raw); err != nil {
		panic(err)
	}
}

func updateWorld(path string, change func(*fakeWorld)) *fakeWorld {
	world := loadWorld(path)
	change(world)
	world.save()
	return world
}

func (w *fakeWorld) count(label string) int {
	total := 0
	for _, call := range w.Calls {
		if call.Label == label {
			total++
		}
	}
	return total
}

func (w *fakeWorld) sends() int {
	return w.count("wallet send") + w.count("agent service deploy") + w.count("agent service send update-policy") +
		w.count("agent service send withdraw-revenue")
}

func (w *fakeWorld) last(label string) fakeCall {
	for index := len(w.Calls) - 1; index >= 0; index-- {
		if w.Calls[index].Label == label {
			return w.Calls[index]
		}
	}
	return fakeCall{}
}

func fakeArgument(args []string, name string) string {
	for index, value := range args {
		if value == name && index+1 < len(args) {
			return args[index+1]
		}
	}
	return ""
}

func fakePublicKey(name string) []byte {
	seed := sha256.Sum256([]byte("fake controller " + name))
	return bytes.Repeat(seed[:1], mldsa44.PublicKeySize)
}

func fakeKey(name string) ControllerKey {
	public := fakePublicKey(name)
	id, err := mldsa44.KeyID(public)
	if err != nil {
		panic(err)
	}
	return ControllerKey{Name: name, KeyID: id, PublicKey: public}
}

// fakeRegistryCode is a small code cell standing in for the registry code.
func fakeRegistryCode() (bocText, codeHash string) {
	code := cell.BeginCell().MustStoreUInt(0x4e52, 16).MustStoreUInt(0xc0de, 16).EndCell()
	return base64.StdEncoding.EncodeToString(code.ToBOC()), hex.EncodeToString(code.Hash())
}

func (w *fakeWorld) network() *nativev1.NetworkDomain {
	return &nativev1.NetworkDomain{
		NetworkId: fakeNetworkLabel, GenesisRootHash: "sha256:" + w.GenesisRoot,
		GenesisFileHash: "sha256:" + w.GenesisFile,
	}
}

func (w *fakeWorld) locator() *nativecore.Locator {
	boc, hash := fakeRegistryCode()
	locator, err := nativecore.NewLocator(w.network(), 0, boc, "tvm-cell-sha256:"+hash)
	if err != nil {
		panic(err)
	}
	return locator
}

func fakeActorAddress(owner string, terms []string, attestorPublicKey string) string {
	sum := sha256.Sum256([]byte(owner + "|" + strings.Join(terms, "|") + "|" + attestorPublicKey))
	return "0:" + hex.EncodeToString(sum[:])
}

func fakeTerms(args []string) ActorTerms {
	amount := func(name string) uint64 {
		value, err := ParseTOSAmount(fakeArgument(args, name))
		if err != nil {
			panic(fmt.Sprintf("the fake tosctl was handed a malformed %s: %v", name, err))
		}
		return value
	}
	seconds := func(name string) uint32 {
		value, err := strconv.ParseUint(fakeArgument(args, name), 10, 32)
		if err != nil {
			panic(err)
		}
		return uint32(value)
	}
	return ActorTerms{
		PriceNano: amount("--price-per-call"), StorageFeeNano: amount("--storage-fee"),
		CleanupBountyNano: amount("--cleanup-bounty"), ResponseSLA: seconds("--response-sla"),
		RefundClaimWindow: seconds("--refund-claim-window"),
	}
}

func fakeTermArgs(args []string) []string {
	out := make([]string, 0, 5)
	for _, name := range []string{
		"--price-per-call", "--storage-fee", "--cleanup-bounty", "--response-sla", "--refund-claim-window",
	} {
		out = append(out, fakeArgument(args, name))
	}
	return out
}

// fakeRunner is the scripted tosctl.
type fakeRunner struct{ path string }

func die() {
	_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
	select {}
}

var errFakeUnknown = &TOSCTLError{Label: "fake", Status: "exit status 1"}

func (f fakeRunner) Run(_ context.Context, call TOSCTLCall) ([]byte, error) {
	var behavior string
	world := updateWorld(f.path, func(w *fakeWorld) {
		w.Calls = append(w.Calls, fakeCall{Label: call.Label, Args: call.Args})
		if queue := w.Script[call.Label]; len(queue) > 0 {
			behavior, w.Script[call.Label] = queue[0], queue[1:]
		}
	})
	answer := func(value any) ([]byte, error) {
		raw, err := json.Marshal(value)
		return raw, err
	}
	// send applies a message's effect under the scripted behavior.
	send := func(effect func(*fakeWorld)) error {
		switch behavior {
		case fakeKillBefore:
			die()
		case fakeLost:
			return errFakeUnknown
		case fakeRefuseBalance:
			return &TOSCTLError{Label: call.Label, Status: "exit status 1", Reason: TOSCTLFailureBalance}
		}
		updateWorld(f.path, effect)
		switch behavior {
		case fakeKillAfter:
			die()
		case fakeLandedError:
			return errFakeUnknown
		}
		return nil
	}
	switch call.Label {
	case "agent native-registry controller", "agent native-registry new-controller":
		name := fakeArgument(call.Args, "--name")
		exists := world.Controllers[name]
		if strings.HasSuffix(call.Label, "new-controller") {
			if exists {
				return nil, &TOSCTLError{Label: call.Label, Status: "exit status 1", Reason: TOSCTLFailureAlreadyExists}
			}
			updateWorld(f.path, func(w *fakeWorld) { w.Controllers[name] = true })
		} else if !exists {
			return nil, &TOSCTLError{Label: call.Label, Status: "exit status 1", Reason: TOSCTLFailureNotFound}
		}
		key := fakeKey(name)
		return answer(controllerAnswer{
			Name: name, Suite: "ML-DSA-44", KeyID: hex.EncodeToString(key.KeyID[:]),
			PublicKey: hex.EncodeToString(key.PublicKey),
		})
	case "wallet ls":
		if world.WalletMissing {
			return []byte("[]"), nil
		}
		// tosctl lists the user-friendly form; the raw form is accepted too.
		entry := map[string]any{"name": fakeWalletName, "address": fakeWalletAddress, "wallet_type": "V3R2", "seqno": 1}
		entry["state"], entry["balance"] = world.WalletState, world.WalletBalance
		if world.WalletState == "" {
			entry["state"], entry["balance"], entry["wallet_type"], entry["seqno"] = nil, nil, nil, nil
		}
		return answer([]any{entry})
	case "agent native-registry domain":
		label := fakeArgument(call.Args, "--network-label")
		hash := sha256.Sum256([]byte(label))
		if world.LabelMismatch {
			hash = sha256.Sum256([]byte("another label"))
		}
		return answer(map[string]string{
			"network_label": label, "genesis_root": world.GenesisRoot, "genesis_file": world.GenesisFile,
			"network_hash": hex.EncodeToString(hash[:]), "code_hash": world.CodeHash,
		})
	case "agent native-registry register-agent":
		if behavior == fakeKillBefore {
			die()
		}
		nonce, signer := fakeArgument(call.Args, "--nonce"), fakeArgument(call.Args, "--signer")
		policy, err := os.ReadFile(fakeArgument(call.Args, "--policy"))
		if err != nil {
			return nil, errFakeUnknown
		}
		id := sha256.Sum256(append([]byte(nonce), policy...))
		agentID := "agent_" + hex.EncodeToString(id[:])
		if _, exists := world.Agents[agentID]; exists {
			return nil, &TOSCTLError{Label: call.Label, Status: "exit status 1", Reason: TOSCTLFailureOccupied}
		}
		located, err := world.locator().Locate(agentID)
		if err != nil {
			return nil, err
		}
		destination := located.Address
		if behavior == fakeWrongTarget {
			destination = "0:" + strings.Repeat("ee", 32)
		}
		body, _ := json.Marshal(map[string]string{"kind": "agent", "id": agentID, "key_id": fakeKey(signer).Text()})
		return answer(map[string]any{
			"kind": "register-agent", "object_id": hex.EncodeToString(id[:]), "destination": destination,
			"final_target": destination, "action_hash": strings.Repeat("ab", 32), "generation": 1, "sequence": 1,
			"state_init_boc": base64.StdEncoding.EncodeToString([]byte("state-init")),
			"body_boc":       base64.StdEncoding.EncodeToString(body),
		})
	case "agent native-registry action":
		if behavior == fakeKillBefore {
			die()
		}
		if behavior == fakeLost {
			return nil, errFakeUnknown
		}
		agentAddress, version := fakeArgument(call.Args, "--agent"), fakeArgument(call.Args, "--version")
		digest := "sha256:" + fakeArgument(call.Args, "--manifest")
		objectNonce, _ := hex.DecodeString(fakeArgument(call.Args, "--object-nonce"))
		owner := ""
		for agentID := range world.Agents {
			if located, err := world.locator().Locate(agentID); err == nil && located.Address == agentAddress {
				owner = agentID
			}
		}
		if owner == "" {
			return nil, errFakeUnknown
		}
		capabilityID, err := nativecore.DeriveCapabilityID(world.network(), objectNonce, owner,
			&nativev1.CapabilityVersionV1{Version: version, ManifestDigest: digest})
		if err != nil {
			return nil, err
		}
		located, err := world.locator().Locate(capabilityID)
		if err != nil {
			return nil, err
		}
		target := located.Address
		if behavior == fakeWrongTarget {
			target = "0:" + strings.Repeat("ee", 32)
		}
		body, _ := json.Marshal(map[string]string{
			"kind": "capability", "id": capabilityID, "owner": owner, "version": version, "digest": digest,
		})
		return answer(map[string]any{
			"kind": "register-capability", "kind_code": 6, "target_id": strings.TrimPrefix(capabilityID, "cap_"),
			"destination": agentAddress, "final_target": target, "action_hash": strings.Repeat("cd", 32),
			"generation": 1, "sequence": 2, "predecessor": strings.Repeat("00", 32), "chain_time": world.Clock,
			"body_boc": base64.StdEncoding.EncodeToString(body),
		})
	case "wallet send":
		raw, err := base64.StdEncoding.DecodeString(fakeArgument(call.Args, "--body-boc"))
		if err != nil {
			return nil, errFakeUnknown
		}
		var body map[string]string
		if err := json.Unmarshal(raw, &body); err != nil {
			return nil, errFakeUnknown
		}
		return nil, send(func(w *fakeWorld) {
			switch body["kind"] {
			case "agent":
				w.Agents[body["id"]] = body["key_id"]
			case "capability":
				w.Capabilities[body["id"]] = fakeCapability{
					Owner: body["owner"], Version: body["version"], Digest: body["digest"],
				}
			}
		})
	case "agent service build-state":
		return answer(map[string]string{"address": fakeActorAddress(fakeArgument(call.Args, "--owner"),
			fakeTermArgs(call.Args), fakeArgument(call.Args, "--attestor-pubkey"))})
	case "agent service deploy":
		owner := fakeArgument(call.Args, "--owner")
		attestor := fakeArgument(call.Args, "--attestor-controller")
		address := fakeActorAddress(owner, fakeTermArgs(call.Args), hex.EncodeToString(fakePublicKey(attestor)))
		if behavior == fakeWrongTarget {
			address = "0:" + strings.Repeat("ee", 32)
		}
		if err := send(func(w *fakeWorld) {
			w.Actor = &fakeActor{
				Address: address, Owner: owner, Attestor: attestor, Terms: fakeTerms(call.Args),
				Metadata: zeroHash64, Proof: zeroHash64, LastLT: 10, CodeHash: fakeCodeHashActor, PolicyCount: 1,
			}
		}); err != nil {
			return nil, err
		}
		line, _ := json.Marshal(map[string]string{
			"name": fakeArgument(call.Args, "--name"), "address": address, "status": "submitted", "owner": owner,
		})
		return append([]byte("Transfer summary:\n  From: provider\nOK sent\n"), append(line, '\n')...), nil
	case "agent service send update-policy":
		return nil, send(func(w *fakeWorld) {
			if w.Actor == nil || w.Actor.Address != fakeArgument(call.Args, "--address") {
				return
			}
			w.Actor.Terms, w.Actor.PolicyCount = fakeTerms(call.Args), w.Actor.PolicyCount+1
			w.Actor.Metadata = fakeArgument(call.Args, "--metadata-hash")
			w.Actor.Proof = fakeArgument(call.Args, "--proof-scheme-hash")
			w.Actor.LastLT++
		})
	case "agent service send withdraw-revenue":
		amount, err := ParseTOSAmount(fakeArgument(call.Args, "--withdraw-amount"))
		if err != nil {
			panic(err)
		}
		queryID, _ := strconv.ParseUint(fakeArgument(call.Args, "--query-id"), 10, 64)
		failed := behavior == fakeFailedTx
		if failed {
			behavior = fakeOK
		}
		return nil, send(func(w *fakeWorld) {
			w.Actor.LastLT++
			transaction := toschain.ActorTransaction{
				LT: w.Actor.LastLT, Hash: fmt.Sprintf("%064x", w.Actor.LastLT), Sender: fakeWalletAddress,
			}
			if failed || amount > w.Actor.Revenue {
				body := cell.BeginCell().MustStoreUInt(nativecore.ServiceActorWithdrawOpcode, 32).
					MustStoreUInt(queryID, 64).MustStoreBigCoins(new(big.Int).SetUint64(amount)).EndCell()
				transaction.Kind, transaction.ExitCode = toschain.ActorTxFailed, 77
				transaction.BodyBOC = base64.StdEncoding.EncodeToString(body.ToBOC())
			} else {
				w.Actor.Revenue -= amount
				transaction.Kind, transaction.Opcode = toschain.ActorTxOwner, nativecore.ServiceActorWithdrawOpcode
				transaction.QueryID = queryID
				transaction.Payouts = []toschain.ActorPayout{
					{Destination: fakeWalletAddress, AmountNano: strconv.FormatUint(amount, 10)},
					{Destination: fakeWalletAddress, AmountNano: "190000000"},
				}
			}
			w.History = append([]toschain.ActorTransaction{transaction}, w.History...)
		})
	}
	panic("the fake tosctl was asked for an unexpected command: " + call.Label)
}

// fakeChain reads the fake world as finalized state.
type fakeChain struct{ path string }

func (c fakeChain) Endpoints() []string { return append([]string(nil), fakeEndpoints...) }

func (c fakeChain) CheckEndpointGenesis(_ context.Context, endpoint string) error {
	switch loadWorld(c.path).GenesisFail[endpoint] {
	case "":
		return nil
	case "wrong":
		return &nativecore.ProtocolError{Code: nativecore.ErrWrongNetwork, Message: "another genesis at " + endpoint}
	default:
		return errors.New("connection refused to " + endpoint)
	}
}

func (c fakeChain) BeginRail(context.Context) (RailSession, error) {
	return fakeSession{world: updateWorld(c.path, func(w *fakeWorld) { w.Checkpoint++ })}, nil
}

type fakeSession struct{ world *fakeWorld }

func (s fakeSession) Checkpoint() uint64   { return s.world.Checkpoint }
func (s fakeSession) ChainTime() time.Time { return time.Unix(s.world.Clock, 0) }

func (s fakeSession) ResolveRegistry(_ context.Context, id string) (*nativev1.NativeStateV1, bool, error) {
	reference := &nativev1.ChainReference{
		FinalizedCheckpoint: s.world.Checkpoint, ContractCodeHash: "tvm-cell-sha256:" + s.world.CodeHash,
	}
	if keyID, ok := s.world.Agents[id]; ok {
		return &nativev1.NativeStateV1{
			Network: s.world.network(), Reference: reference,
			State: &nativev1.NativeStateV1_Agent{Agent: &nativev1.AgentStateV1{
				AgentId: id, Policy: &nativev1.ControllerPolicyV1{
					Threshold:         1,
					RecoveryThreshold: 1,
					Controllers:       []*nativev1.ControllerV1{{KeyId: keyID, Weight: 1}},
				},
			}},
		}, true, nil
	}
	if capability, ok := s.world.Capabilities[id]; ok {
		return &nativev1.NativeStateV1{
			Network: s.world.network(), Reference: reference,
			State: &nativev1.NativeStateV1_Capability{Capability: &nativev1.CapabilityStateV1{
				CapabilityId: id, OwnerAgentId: capability.Owner, Versions: []*nativev1.CapabilityVersionV1{
					{Version: capability.Version, ManifestDigest: capability.Digest},
				},
			}},
		}, true, nil
	}
	return nil, false, nil
}

func hash32(text string) [32]byte {
	var out [32]byte
	raw, err := hex.DecodeString(text)
	if err != nil || len(raw) != 32 {
		panic("the fake world holds a malformed hash")
	}
	copy(out[:], raw)
	return out
}

func (s fakeSession) ReadActor(_ context.Context, actor string) (*toschain.ActorAccount, bool, error) {
	state := s.world.Actor
	if state == nil || state.Address != actor {
		return nil, false, nil
	}
	owner, err := nativecore.StandardAddress(state.Owner)
	if err != nil {
		return nil, false, err
	}
	attestor := fakeKey(state.Attestor)
	return &toschain.ActorAccount{
		Address: actor, CodeHash: state.CodeHash, BalanceNano: 3_000_000_000,
		LastTransaction: toschain.ActorTxID{LT: state.LastLT, Hash: fmt.Sprintf("%064x", state.LastLT)},
		Data: &nativecore.ServiceActorDataV1{
			Owner: owner, Active: true,
			Policy: nativecore.ServiceActorPolicyV1{
				PolicyVersion: state.PolicyCount, PricePerCall: new(big.Int).SetUint64(state.Terms.PriceNano),
				StorageFee:    new(big.Int).SetUint64(state.Terms.StorageFeeNano),
				CleanupBounty: new(big.Int).SetUint64(state.Terms.CleanupBountyNano),
				ResponseSLA:   state.Terms.ResponseSLA, RefundClaimWindow: state.Terms.RefundClaimWindow,
				OpenAccess: true, MetadataHash: hash32(state.Metadata), ProofSchemeHash: hash32(state.Proof),
				HasAttestor: true, AttestorKeyID: attestor.KeyID, AttestorKey: attestor.PublicKey,
			},
			Accounting: nativecore.ServiceActorAccountingV1{
				WithdrawableRevenue: new(big.Int).SetUint64(state.Revenue), LockedStorageFees: big.NewInt(0),
				PendingLiability: big.NewInt(0), RefundableLiability: big.NewInt(0),
			},
		},
	}, true, nil
}

func (s fakeSession) History(_ context.Context, _ string, anchor *toschain.ActorTxID) (*toschain.ActorHistory, error) {
	history := &toschain.ActorHistory{Result: toschain.HistoryComplete}
	if anchor != nil {
		history.Result = toschain.HistoryAnchorReached
	}
	for _, transaction := range s.world.History {
		if anchor == nil || transaction.LT > anchor.LT {
			history.Transactions = append(history.Transactions, transaction)
		}
	}
	return history, nil
}

// setupFixture is one node directory with its fake world.
type setupFixture struct {
	root      string
	worldPath string
	init      InitInput
	offer     OfferInput
	reports   *[]string
}

func (f *setupFixture) world() *fakeWorld { return loadWorld(f.worldPath) }

func (f *setupFixture) change(change func(*fakeWorld)) { updateWorld(f.worldPath, change) }

func (f *setupFixture) script(label string, behaviors ...string) {
	f.change(func(w *fakeWorld) { w.Script[label] = append(w.Script[label], behaviors...) })
}

// fakeEnv builds the effects from the world file alone, so a helper
// process and the test build the same environment.
func fakeEnv(worldPath string, reports *[]string) SetupEnv {
	return SetupEnv{
		Now: func() time.Time { return time.Unix(loadWorld(worldPath).Clock, 0) },
		// Waiting advances the one clock that is both local and chain time.
		Sleep: func(_ context.Context, wait time.Duration) error {
			updateWorld(worldPath, func(w *fakeWorld) { w.Clock += int64(wait / time.Second) })
			return nil
		},
		Getenv: func(name string) string {
			if name == pfVaultEnvName {
				return pfSecretVault
			}
			return ""
		},
		Random: func(value []byte) error {
			world := updateWorld(worldPath, func(w *fakeWorld) { w.RandomCounter++ })
			sum := sha256.Sum256([]byte(fmt.Sprintf("fake random %d", world.RandomCounter)))
			copy(value, sum[:])
			return nil
		},
		Runner:    func(TOSCTLConfig, string) (TOSCTLRunner, error) { return fakeRunner{path: worldPath}, nil },
		OpenChain: func(NodeConfig) (RailChain, error) { return fakeChain{path: worldPath}, nil },
		Report: func(line string) {
			if reports != nil {
				*reports = append(*reports, line)
			}
		},
		WaitBudget: 30 * time.Second, PollInterval: 3 * time.Second,
	}
}

func (f *setupFixture) env() SetupEnv { return fakeEnv(f.worldPath, f.reports) }

func writeFixtureFile(t *testing.T, path string, content []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatal(err)
	}
}

func newSetupFixture(t *testing.T) *setupFixture {
	t.Helper()
	root, err := os.MkdirTemp("", "of-setup-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	state := filepath.Join(root, "state")
	if mkdirErr := os.Mkdir(state, 0o700); mkdirErr != nil {
		t.Fatal(mkdirErr)
	}
	boc, codeHash := fakeRegistryCode()
	writeFixtureFile(t, filepath.Join(root, "registry.boc"), []byte(boc+"\n"), 0o600)
	writeFixtureFile(t, filepath.Join(root, "tosctl"), []byte("the pinned tosctl bytes"), 0o700)
	writeFixtureFile(t, filepath.Join(root, "executor"), []byte("the pinned executor bytes"), 0o700)
	writeFixtureFile(t, filepath.Join(root, "tosctl-config.json"), []byte("{}"), 0o600)
	writeFixtureFile(t, filepath.Join(root, "global.config.json"), []byte("{}"), 0o600)
	fixture := &setupFixture{root: root, worldPath: filepath.Join(root, "world.json"), reports: &[]string{}}
	world := &fakeWorld{
		path: fixture.worldPath, GenesisRoot: strings.Repeat("11", 32), GenesisFile: strings.Repeat("22", 32),
		CodeHash: codeHash, Controllers: map[string]bool{}, WalletState: "active", WalletBalance: "100",
		Agents: map[string]string{}, Capabilities: map[string]fakeCapability{}, Clock: 1_900_000_000,
		Script: map[string][]string{}, GenesisFail: map[string]string{},
	}
	world.save()
	fixture.init = InitInput{
		RailConfigPath: filepath.Join(root, "rail.json"), StateDir: state, RPCEndpoints: fakeEndpoints,
		GlobalConfigFile: filepath.Join(root, "global.config.json"), NetworkLabel: fakeNetworkLabel,
		TOSCTLBinary: filepath.Join(root, "tosctl"), TOSCTLConfigPath: filepath.Join(root, "tosctl-config.json"),
		VaultURLEnv: pfVaultEnvName, WalletName: fakeWalletName, PacketController: "openfox-packet",
		RegistryCodeBOC: filepath.Join(root, "registry.boc"), ActorCodeHash: fakeCodeHashActor,
		MessengerSocket: filepath.Join(root, "messenger.sock"), Yes: true,
	}
	fixture.offer = OfferInput{
		RailConfigPath: fixture.init.RailConfigPath,
		Terms: ActorTerms{
			PriceNano: 300_000_000, StorageFeeNano: 250_000_000, CleanupBountyNano: 100_000_000, ResponseSLA: 3600,
			RefundClaimWindow: 7200,
		},
		ExecutorBinary: filepath.Join(root, "executor"), ContainerdSocket: filepath.Join(root, "containerd.sock"),
		Yes: true,
	}
	return fixture
}

func (f *setupFixture) mustInit(t *testing.T) *InitResult {
	t.Helper()
	result, err := RunInit(context.Background(), f.init, f.env())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	return result
}

func (f *setupFixture) mustOffer(t *testing.T) *OfferResult {
	t.Helper()
	result, err := RunOffer(context.Background(), f.offer, f.env())
	if err != nil {
		t.Fatalf("offer: %v", err)
	}
	return result
}

func (f *setupFixture) journal(t *testing.T) *SetupJournal {
	t.Helper()
	journal, err := loadSetupJournal(f.init.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	return journal
}

// The helper process: it runs one setup command against the fake world of
// a directory and is expected to be killed by the scripted behavior.
const (
	crashHelperDir     = "OPENFOX_SETUP_CRASH_DIR"
	crashHelperCommand = "OPENFOX_SETUP_CRASH_COMMAND"
)

func TestHelperProcessForSetupCrashTests(t *testing.T) {
	directory := os.Getenv(crashHelperDir)
	if directory == "" {
		return
	}
	raw, err := os.ReadFile(filepath.Join(directory, "input.json"))
	if err != nil {
		t.Fatal(err)
	}
	env := fakeEnv(filepath.Join(directory, "world.json"), nil)
	switch os.Getenv(crashHelperCommand) {
	case "init":
		var in InitInput
		if err = json.Unmarshal(raw, &in); err == nil {
			_, err = RunInit(context.Background(), in, env)
		}
	case "offer":
		var in OfferInput
		if err = json.Unmarshal(raw, &in); err == nil {
			_, err = RunOffer(context.Background(), in, env)
		}
	case "withdraw":
		var in WithdrawInput
		if err = json.Unmarshal(raw, &in); err == nil {
			_, err = RunWithdraw(context.Background(), in, env)
		}
	default:
		t.Fatal("no helper command")
	}
	// Reaching here means the process was not killed.
	fmt.Fprintf(os.Stderr, "helper finished without being killed: %v\n", err)
	os.Exit(3)
}

// runKilled runs a command in a helper process and requires that the
// process really died by SIGKILL, so the restart that follows starts from
// exactly what was durable at that instant.
func (f *setupFixture) runKilled(t *testing.T, command string, input any) {
	t.Helper()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, filepath.Join(f.root, "input.json"), raw, 0o600)
	helper := exec.Command(os.Args[0], "-test.run=^TestHelperProcessForSetupCrashTests$")
	helper.Env = append(os.Environ(), crashHelperDir+"="+f.root, crashHelperCommand+"="+command)
	output, err := helper.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("the helper was not killed: %v\n%s", err, output)
	}
	status, ok := exit.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatalf("the helper did not die by SIGKILL: %v\n%s", err, output)
	}
}

func (f *setupFixture) withdrawTx(w *fakeWorld, queryID uint64, sender, amount string) toschain.ActorTransaction {
	return toschain.ActorTransaction{
		LT: w.Actor.LastLT + 5, Hash: strings.Repeat("ef", 32), Sender: sender, Kind: toschain.ActorTxOwner,
		Opcode: nativecore.ServiceActorWithdrawOpcode, QueryID: queryID,
		Payouts: []toschain.ActorPayout{{Destination: fakeWalletAddress, AmountNano: amount}},
	}
}

// hookedEnv is the fixture's environment with a runner that changes the
// world right after one tosctl command succeeded.
func hookedEnv(f *setupFixture, label string, change func(*fakeWorld)) SetupEnv {
	env := f.env()
	env.Runner = func(TOSCTLConfig, string) (TOSCTLRunner, error) {
		return hookedRunner{inner: fakeRunner{path: f.worldPath}, label: label, change: change}, nil
	}
	return env
}

type hookedRunner struct {
	inner  fakeRunner
	label  string
	change func(*fakeWorld)
}

func (h hookedRunner) Run(ctx context.Context, call TOSCTLCall) ([]byte, error) {
	output, err := h.inner.Run(ctx, call)
	if err == nil && call.Label == h.label {
		updateWorld(h.inner.path, h.change)
	}
	return output, err
}
