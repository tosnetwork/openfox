package servicebridge

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
)

// InitInput is what the owner chooses for a rail node. Everything else in
// the rail configuration is derived and verified.
type InitInput struct {
	RailConfigPath string   `json:"rail_config_path"`
	StateDir       string   `json:"state_dir"`
	RPCEndpoints   []string `json:"rpc_endpoints"`
	Quorum         int      `json:"quorum"`
	// GlobalConfigFile and NetworkLabel name the chain: the identity domain
	// is derived from them by tosctl and cross-checked against the
	// endpoints and the registry code file.
	GlobalConfigFile string `json:"global_config_file"`
	NetworkLabel     string `json:"network_label"`
	TOSCTLBinary     string `json:"tosctl_binary"`
	// TOSCTLSHA256 pins tosctl; empty pins the binary found (trust on first
	// use).
	TOSCTLSHA256     string            `json:"tosctl_sha256"`
	TOSCTLConfigPath string            `json:"tosctl_config_path"`
	VaultURLEnv      string            `json:"vault_url_env"`
	WalletName       string            `json:"wallet_name"`
	PacketController string            `json:"packet_controller"`
	RegistryCodeBOC  string            `json:"registry_code_boc"`
	ActorCodeHash    string            `json:"actor_code_hash"`
	MessengerSocket  string            `json:"messenger_socket"`
	ReceiverSocket   string            `json:"receiver_socket"`
	DirectPeers      map[string]string `json:"direct_peers"`
	// RelayURLs are the Agent Packet Relay base URLs the node publishes in
	// its encryption key card and polls (1 to 4).
	RelayURLs []string `json:"relay_urls"`
	// RelayCAFile is a PEM file of one or more certificate authorities
	// this node's own https relays are verified against instead of the
	// system trust store. It is copied into the owner-only state.
	RelayCAFile string `json:"relay_ca_file"`
	// RelaySystemRoots drops a pinned CA file: the relays are verified
	// against the system trust store again.
	RelaySystemRoots bool `json:"relay_system_roots"`
	// Buyer, when set, becomes the buyer section.
	Buyer *BuyerNode `json:"buyer"`
	// Yes confirms the previewed actions.
	Yes bool `json:"yes"`
}

// InitIdentity holds the inputs that determine the Agent's identity.
type InitIdentity struct {
	NetworkID        string `json:"network_id"`
	GenesisRootHash  string `json:"genesis_root_hash"`
	GenesisFileHash  string `json:"genesis_file_hash"`
	RegistryCodeHash string `json:"registry_code_hash"`
	PacketController string `json:"packet_controller"`
	PacketKeyID      string `json:"packet_key_id"`
}

// InitJournal is the durable state of `init`.
type InitJournal struct {
	Identity     InitIdentity `json:"identity"`
	TOSCTLSHA256 string       `json:"tosctl_sha256"`
	// AgentNonce is stored before the registration is built.
	AgentNonce   string                 `json:"agent_nonce,omitempty"`
	Registration *SignedRegistryMessage `json:"registration,omitempty"`
	AgentID      string                 `json:"agent_id,omitempty"`
	AgentAddress string                 `json:"agent_address,omitempty"`
	Agent        ChainStep              `json:"agent"`
}

// How the tosctl pin was established.
const (
	PinTrustOnFirstUse = "trust_on_first_use"
	PinGivenByOwner    = "given_by_owner"
	PinKept            = "kept_from_earlier_run"
)

// InitResult is the report of `init`.
type InitResult struct {
	Schema           string        `json:"schema"`
	Confirmed        bool          `json:"confirmed"`
	RailConfig       string        `json:"rail_config"`
	StateDir         string        `json:"state_dir"`
	Network          NetworkConfig `json:"network"`
	RegistryCodeHash string        `json:"registry_code_hash"`
	TOSCTLSHA256     string        `json:"tosctl_sha256"`
	TOSCTLPin        string        `json:"tosctl_pin"`
	TOSCTLPinNote    string        `json:"tosctl_pin_note"`
	WalletName       string        `json:"wallet_name"`
	WalletAddress    string        `json:"wallet_address,omitempty"`
	PacketController string        `json:"packet_controller"`
	PacketKeyID      string        `json:"packet_key_id,omitempty"`
	AgentID          string        `json:"agent_id,omitempty"`
	AgentAddress     string        `json:"agent_address,omitempty"`
	AttachedNanoTOS  string        `json:"registration_attached_nanotos"`
	Steps            []SetupStep   `json:"steps"`
	NextSteps        []string      `json:"next_steps,omitempty"`
}

// InitResultSchema names the init report.
const InitResultSchema = "tos.openfox.rail-init.v1"

const maxDirectPeers = 64

// maxUnixSocketPath is the longest path a Unix socket address holds.
const maxUnixSocketPath = 103

func cleanAbsolute(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path
}

func validateDirectPeers(peers map[string]string) error {
	if len(peers) > maxDirectPeers {
		return fmt.Errorf("servicebridge: at most %d direct peers may be configured", maxDirectPeers)
	}
	for agent, socket := range peers {
		if !agentIDPattern.MatchString(agent) {
			return errors.New("servicebridge: a direct peer is not named by an Agent id (agent_<64 hex>)")
		}
		if !cleanAbsolute(socket) || len(socket) > maxUnixSocketPath {
			return fmt.Errorf("servicebridge: the direct peer socket of %s must be an absolute clean path of at "+
				"most %d bytes", agent, maxUnixSocketPath)
		}
	}
	return nil
}

func (in InitInput) validate() error {
	var problems []string
	for name, path := range map[string]string{
		"the rail configuration path": in.RailConfigPath, "the state directory": in.StateDir,
		"the chain global configuration": in.GlobalConfigFile, "the tosctl binary": in.TOSCTLBinary,
		"the tosctl configuration": in.TOSCTLConfigPath, "the registry code file": in.RegistryCodeBOC,
		"the receiver socket": in.ReceiverSocket,
	} {
		if !cleanAbsolute(path) {
			problems = append(problems, name+" must be an absolute clean path")
		}
	}
	if in.MessengerSocket != "" && !cleanAbsolute(in.MessengerSocket) {
		problems = append(problems, "the messenger socket must be an absolute clean path")
	}
	if len(in.ReceiverSocket) > maxUnixSocketPath {
		problems = append(problems, fmt.Sprintf("the receiver socket path exceeds %d bytes", maxUnixSocketPath))
	}
	if in.NetworkLabel == "" || len(in.NetworkLabel) > 64 || strings.ContainsAny(in.NetworkLabel, " \t\r\n\x00") ||
		strings.HasPrefix(in.NetworkLabel, "-") {
		problems = append(problems, "the network label must be 1 to 64 printable bytes")
	}
	if !walletNamePattern.MatchString(in.WalletName) {
		problems = append(problems, "the wallet name is not a valid tosctl wallet name")
	}
	if !walletNamePattern.MatchString(in.PacketController) {
		problems = append(problems, "the packet controller name is not a valid controller name")
	}
	if in.TOSCTLSHA256 != "" && !hex64Pattern.MatchString(in.TOSCTLSHA256) {
		problems = append(problems, "--tosctl-sha256 must be 64 lowercase hex digits")
	}
	if _, err := digestBytes32(in.ActorCodeHash, "tvm-cell-sha256:"); err != nil {
		problems = append(problems, "the actor code hash must be tvm-cell-sha256:<64 hex>")
	}
	if in.VaultURLEnv != "" && !envNamePattern.MatchString(in.VaultURLEnv) {
		problems = append(problems, "the vault URL environment variable name is invalid")
	}
	if err := validateDirectPeers(in.DirectPeers); err != nil {
		problems = append(problems, strings.TrimPrefix(err.Error(), "servicebridge: "))
	}
	if len(in.RelayURLs) > 0 {
		if _, err := canonicalRelayURLs(in.RelayURLs); err != nil {
			problems = append(problems, strings.TrimPrefix(err.Error(), "servicebridge: "))
		}
	}
	if in.RelayCAFile != "" && !cleanAbsolute(in.RelayCAFile) {
		problems = append(problems, "--relay-ca-file must be an absolute clean path")
	}
	if in.RelayCAFile != "" && in.RelaySystemRoots {
		problems = append(problems, "--relay-ca-file and --relay-system-roots exclude each other")
	}
	if in.Buyer != nil {
		if _, err := in.Buyer.Policy.parse(); err != nil {
			problems = append(problems, strings.TrimPrefix(err.Error(), "servicebridge: "))
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return errors.New("servicebridge: init: " + strings.Join(problems, "; "))
	}
	return nil
}

// agentPolicyFile is the policy tosctl registers the Agent with: one
// controller that alone meets both thresholds and carries every purpose.
type agentPolicyFile struct {
	Threshold         uint32                  `json:"threshold"`
	RecoveryThreshold uint32                  `json:"recovery_threshold"`
	RecoveryTimelock  uint64                  `json:"recovery_timelock"`
	Controllers       []agentPolicyController `json:"controllers"`
}

type agentPolicyController struct {
	PublicKey string `json:"public_key"`
	Weight    uint32 `json:"weight"`
	Purposes  uint16 `json:"purposes"`
}

const agentRecoveryTimelock = 3600

func writeAgentPolicy(stateDir string, controller ControllerKey) (string, error) {
	encoded, err := json.Marshal(agentPolicyFile{
		Threshold: 1, RecoveryThreshold: 1, RecoveryTimelock: agentRecoveryTimelock,
		Controllers: []agentPolicyController{{
			PublicKey: hex.EncodeToString(controller.PublicKey), Weight: 1, Purposes: 15,
		}},
	})
	if err != nil {
		return "", errors.New("servicebridge: encode the Agent policy")
	}
	path := filepath.Join(stateDir, setupDirectory, "agent-policy.json")
	return path, replaceSynced(path, encoded)
}

// pinTOSCTL decides the tosctl pin. A binary that differs from an earlier
// pin is refused unless the owner states the new digest.
func pinTOSCTL(in InitInput, earlier string) (pin, how string, err error) {
	actual, err := HashTOSCTL(in.TOSCTLBinary)
	if err != nil {
		return "", "", err
	}
	switch {
	case in.TOSCTLSHA256 != "":
		if actual != in.TOSCTLSHA256 {
			return "", "", fmt.Errorf("servicebridge: the tosctl binary hashes to %s, not the --tosctl-sha256 given",
				actual)
		}
		return actual, PinGivenByOwner, nil
	case earlier != "" && earlier != actual:
		return "", "", fmt.Errorf("servicebridge: the tosctl binary changed since it was pinned (pinned %s, now %s); "+
			"if you replaced it, pass --tosctl-sha256 %s to accept it", earlier, actual, actual)
	case earlier != "":
		return actual, PinKept, nil
	default:
		return actual, PinTrustOnFirstUse, nil
	}
}

func pinNote(how string) string { return pinNoteFor(how, "--tosctl-sha256") }

// pinNoteFor words a pin for the flag that states the binary's digest.
func pinNoteFor(how, flag string) string {
	switch how {
	case PinGivenByOwner:
		return "the binary matches the SHA-256 given with " + flag
	case PinKept:
		return "the binary matches the SHA-256 pinned by an earlier run"
	default:
		return "trust on first use: this SHA-256 was computed from the binary found, not checked against " +
			"anything; compare it with the digest of the release you meant to install, or pass " + flag
	}
}

// ensureController returns the named controller, creating it when the vault
// holds none. tosctl stores a new controller only if the name is free, so
// an existing key is never replaced.
func (r *setupRun) ensureController(ops tosctlOps, id, name string) (ControllerKey, error) {
	key, err := ops.controller(r.ctx, name)
	if err == nil {
		r.notef(id, SetupAlready, "controller %q exists in the vault with key id %s", name, key.Text())
		return key, nil
	}
	if tosctlFailure(err) != TOSCTLFailureNotFound {
		return ControllerKey{}, fmt.Errorf("servicebridge: controller %q could not be read from the vault (check the "+
			"vault URL environment variable and the tosctl configuration): %w", name, err)
	}
	if !r.yes {
		r.notef(id, SetupPlanned, "controller %q is not in the vault and will be created", name)
		return ControllerKey{}, ErrConfirmationRequired
	}
	key, err = ops.newController(r.ctx, name)
	if err != nil {
		return ControllerKey{}, fmt.Errorf("servicebridge: create controller %q: %w", name, err)
	}
	// What was created is read back, so the key used is the key stored.
	stored, err := ops.controller(r.ctx, name)
	if err != nil || stored.KeyID != key.KeyID {
		return ControllerKey{}, fmt.Errorf("servicebridge: controller %q does not read back as created", name)
	}
	r.notef(id, SetupDone, "created controller %q in the vault with key id %s", name, key.Text())
	return key, nil
}

// requireFundedWallet stops with what to fund when the wallet cannot pay
// neededNano.
func requireFundedWallet(wallet WalletView, neededNano uint64, purpose string) error {
	needed := FormatTOSAmount(neededNano)
	switch {
	case !wallet.StateKnown:
		return fmt.Errorf("servicebridge: tosctl could not read the chain state of wallet %q (%s); check chain_rpc "+
			"in the tosctl configuration. %s needs at least %s TOS in it", wallet.Name, wallet.Address, purpose, needed)
	case wallet.State != "active":
		return fmt.Errorf("servicebridge: wallet %q (%s) is %s, not an active account: send at least %s TOS to that "+
			"address, then run `tosctl wallet activate -n %s`, and run this command again", wallet.Name,
			wallet.Address, wallet.State, needed, wallet.Name)
	case wallet.BalanceNano < neededNano:
		return fmt.Errorf("servicebridge: wallet %q (%s) holds about %s TOS; %s needs at least %s TOS: fund that "+
			"address and run this command again", wallet.Name, wallet.Address, FormatTOSAmount(wallet.BalanceNano),
			purpose, needed)
	default:
		return requireExpiringWallet(wallet)
	}
}

// agentEffect reports whether the Agent is registered in finalized state
// under a policy that holds the packet controller.
func agentEffect(ctx context.Context, agentID, packetKeyID string) effectFunc {
	return func(session RailSession) (bool, error) {
		state, found, err := session.ResolveRegistry(ctx, agentID)
		if err != nil {
			return false, fmt.Errorf("servicebridge: read Agent %s: %w", agentID, err)
		}
		if !found {
			return false, nil
		}
		agent := state.GetAgent()
		if agent == nil || agent.GetAgentId() != agentID {
			return false, fmt.Errorf("servicebridge: the registry object at %s is not that Agent", agentID)
		}
		if agent.GetTombstoned() {
			return false, fmt.Errorf("servicebridge: Agent %s is revoked", agentID)
		}
		for _, controller := range agent.GetPolicy().GetControllers() {
			if controller.GetKeyId() == packetKeyID {
				return true, nil
			}
		}
		return false, fmt.Errorf("servicebridge: Agent %s is registered but its policy does not hold packet key %s",
			agentID, packetKeyID)
	}
}

func identityDifference(a, b InitIdentity) string {
	left, right := reflect.ValueOf(a), reflect.ValueOf(b)
	for index := 0; index < left.NumField(); index++ {
		if left.Field(index).String() != right.Field(index).String() {
			return left.Type().Field(index).Tag.Get("json")
		}
	}
	return ""
}

// writeNodeConfig writes the rail configuration owner-only and requires it
// to read back, strictly, as exactly what was written.
func writeNodeConfig(path string, config NodeConfig) error {
	encoded, err := EncodeNodeConfig(config)
	if err != nil {
		return errors.New("servicebridge: encode the rail configuration")
	}
	if mkdirErr := os.MkdirAll(filepath.Dir(path), 0o700); mkdirErr != nil {
		return errors.New("servicebridge: create the rail configuration directory")
	}
	if info, statErr := os.Lstat(path); statErr == nil && !info.Mode().IsRegular() {
		return errors.New("servicebridge: the rail configuration path is not a regular file")
	}
	if writeErr := replaceSynced(path, append(encoded, '\n')); writeErr != nil {
		return writeErr
	}
	loaded, err := LoadNodeConfig(path)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(normalizeConfig(loaded), normalizeConfig(config)) {
		return errors.New("servicebridge: the rail configuration does not read back as written")
	}
	return nil
}

// normalizeConfig makes empty and absent collections compare equal.
func normalizeConfig(config NodeConfig) NodeConfig {
	if len(config.DirectPeers) == 0 {
		config.DirectPeers = nil
	}
	if len(config.RPCEndpoints) == 0 {
		config.RPCEndpoints = nil
	}
	if len(config.RelayURLs) == 0 {
		config.RelayURLs = nil
	}
	if config.Buyer != nil {
		buyer := *config.Buyer
		if len(buyer.Policy.AllowedProviders) == 0 {
			buyer.Policy.AllowedProviders = nil
		}
		config.Buyer = &buyer
	}
	return config
}

// RunInit establishes a rail node's identity and writes its configuration.
// It is idempotent: a re-run reads finalized state first and resumes.
func RunInit(ctx context.Context, in InitInput, env SetupEnv) (*InitResult, error) {
	env.fill()
	if ctx == nil {
		return nil, errors.New("servicebridge: no context")
	}
	result := &InitResult{
		Schema: InitResultSchema, RailConfig: in.RailConfigPath, StateDir: in.StateDir, WalletName: in.WalletName,
		PacketController: in.PacketController, AttachedNanoTOS: fmt.Sprint(RegistryMessageValueNano),
		Steps: []SetupStep{},
	}
	// One run at a time per state directory, from before the configuration
	// and the journal are read: two runs that both read "no Agent yet"
	// would draw two nonces and register two Agents.
	if !cleanAbsolute(in.StateDir) {
		return result, errors.New("servicebridge: init: the state directory must be an absolute clean path")
	}
	release, lockErr := lockSetup(in.StateDir)
	if lockErr != nil {
		return result, lockErr
	}
	defer release()
	// An existing configuration keeps the sections init does not own, and
	// the transport a re-run does not restate.
	var existing *NodeConfig
	if loaded, err := LoadNodeConfig(in.RailConfigPath); err == nil {
		existing = &loaded
		if in.MessengerSocket == "" && len(in.DirectPeers) == 0 && len(in.RelayURLs) == 0 {
			in.MessengerSocket, in.DirectPeers, in.RelayURLs = loaded.MessengerSocket, loaded.DirectPeers,
				loaded.RelayURLs
		}
		if in.ReceiverSocket == "" && loaded.StateDir == in.StateDir {
			in.ReceiverSocket = loaded.ReceiverSocket
		}
	} else if _, statErr := os.Lstat(in.RailConfigPath); statErr == nil {
		return result, fmt.Errorf("servicebridge: the existing rail configuration cannot be read, and init will not "+
			"replace a file it cannot read: %w", err)
	}
	if in.ReceiverSocket == "" && cleanAbsolute(in.StateDir) {
		in.ReceiverSocket = filepath.Join(in.StateDir, "rail-receiver.sock")
	}
	if err := in.validate(); err != nil {
		return result, err
	}
	var relays []string
	if len(in.RelayURLs) > 0 {
		canonical, err := canonicalRelayURLs(in.RelayURLs)
		if err != nil {
			return result, err
		}
		relays = canonical
	}
	relayPin, err := chooseRelayCA(in, existing, relays, env.Now())
	if err != nil {
		return result, err
	}
	journal, err := loadSetupJournal(in.StateDir)
	if err != nil {
		return result, err
	}
	run := &setupRun{
		ctx: ctx, env: env, stateDir: in.StateDir, journal: journal, yes: in.Yes,
		endpoints: append([]string(nil), in.RPCEndpoints...),
	}
	defer func() { result.Steps = run.steps }()

	earlierPin := ""
	if journal.Init != nil {
		earlierPin = journal.Init.TOSCTLSHA256
	} else if existing != nil {
		earlierPin = existing.TOSCTL.SHA256
	}
	pin, how, err := pinTOSCTL(in, earlierPin)
	if err != nil {
		return result, err
	}
	result.TOSCTLSHA256, result.TOSCTLPin, result.TOSCTLPinNote = pin, how, pinNote(how)
	run.notef("tosctl.pin", SetupDone, "tosctl is pinned to SHA-256 %s (%s)", pin, pinNote(how))
	tosctl := TOSCTLConfig{
		Binary: in.TOSCTLBinary, SHA256: pin, ConfigPath: in.TOSCTLConfigPath, VaultURLEnv: in.VaultURLEnv,
	}
	if in.VaultURLEnv != "" && env.Getenv(in.VaultURLEnv) == "" {
		return result, fmt.Errorf("servicebridge: the environment variable %s that carries the vault URL is not set",
			in.VaultURLEnv)
	}
	runner, err := env.Runner(tosctl, env.vaultURL(tosctl))
	if err != nil {
		return result, err
	}
	ops := tosctlOps{runner: runner, globalConfig: in.GlobalConfigFile, networkLabel: in.NetworkLabel}

	// The identity domain: tosctl derives it from the global configuration;
	// the registry code file must hash to the code tosctl embeds, and the
	// endpoints must serve that genesis.
	domain, err := ops.domain(ctx)
	if err != nil {
		return result, fmt.Errorf("servicebridge: derive the identity domain: %w", err)
	}
	config := NodeConfig{
		Network: NetworkConfig{
			NetworkID: in.NetworkLabel, GenesisRootHash: domain.GenesisRootHash,
			GenesisFileHash: domain.GenesisFileHash,
		},
		GlobalConfigFile: in.GlobalConfigFile, RPCEndpoints: in.RPCEndpoints, Quorum: in.Quorum,
		RegistryCodeBOC: in.RegistryCodeBOC, RegistryCodeHash: domain.CodeHash, ActorCodeHash: in.ActorCodeHash,
		StateDir: in.StateDir, PacketController: in.PacketController, TOSCTL: tosctl, WalletName: in.WalletName,
		MessengerSocket: in.MessengerSocket, DirectPeers: in.DirectPeers, RelayURLs: relays,
		ReceiverSocket: in.ReceiverSocket, Buyer: in.Buyer,
	}
	if existing != nil {
		config.Provider, config.MaxAssemblies = existing.Provider, existing.MaxAssemblies
		if config.Buyer == nil {
			config.Buyer = existing.Buyer
		}
	}
	result.Network, result.RegistryCodeHash = config.Network, domain.CodeHash
	code, err := os.ReadFile(in.RegistryCodeBOC)
	if err != nil || len(code) == 0 || len(code) > 1<<20 {
		return result, errors.New("servicebridge: the registry code file cannot be read")
	}
	locator, err := nativecore.NewLocator(networkOf(config), 0, strings.Join(strings.Fields(string(code)), ""),
		domain.CodeHash)
	if err != nil {
		return result, fmt.Errorf("servicebridge: the registry code file does not hold the Native Registry code "+
			"this tosctl release signs for (%s): %w", domain.CodeHash, err)
	}
	run.chain, err = env.OpenChain(config)
	if err != nil {
		return result, fmt.Errorf("servicebridge: open the finalized reader: %s",
			redactEndpoints(err.Error(), run.endpoints))
	}
	if err = checkEndpointGenesis(ctx, run.chain, config); err != nil {
		return result, err
	}
	run.notef("network.domain", SetupDone, "network %q with genesis root %s and file %s, registry code %s; the "+
		"registry code file and the RPC endpoints agree", in.NetworkLabel, domain.GenesisRootHash,
		domain.GenesisFileHash, domain.CodeHash)

	wallet, err := ops.wallet(ctx, in.WalletName)
	if errors.Is(err, errWalletMissing) {
		return result, fmt.Errorf("servicebridge: wallet %q is not in the tosctl configuration; create it with "+
			"`tosctl wallet create -n %s -v V3R2 -w 0`, fund the address it prints, activate it with `tosctl wallet "+
			"activate -n %s`, and run this command again", in.WalletName, in.WalletName, in.WalletName)
	}
	if err != nil {
		return result, err
	}
	config.WalletAddress, result.WalletAddress = wallet.Address, wallet.Address
	run.wallet = &wallet
	run.notef("wallet.address", SetupDone, "wallet %q is %s", wallet.Name, wallet.Address)

	packet, err := run.ensureController(ops, "controller.packet", in.PacketController)
	if errors.Is(err, ErrConfirmationRequired) {
		run.notef("agent.register", SetupPlanned, "an Agent registration will be signed with controller %q and sent "+
			"from wallet %q (%s) attaching %s TOS", in.PacketController, wallet.Name, wallet.Address,
			FormatTOSAmount(RegistryMessageValueNano))
		return result, err
	}
	if err != nil {
		return result, err
	}
	config.PacketKeyID, result.PacketKeyID = packet.Text(), packet.Text()

	identity := InitIdentity{
		NetworkID: in.NetworkLabel, GenesisRootHash: domain.GenesisRootHash, GenesisFileHash: domain.GenesisFileHash,
		RegistryCodeHash: domain.CodeHash, PacketController: in.PacketController, PacketKeyID: packet.Text(),
	}
	switch {
	case journal.Init == nil:
		journal.Init = &InitJournal{Identity: identity}
		// A configuration that already names an Agent is adopted, never
		// answered with a second registration.
		if existing != nil && existing.AgentID != "" {
			journal.Init.AgentID = existing.AgentID
		}
	case journal.Init.Identity != identity:
		field := identityDifference(journal.Init.Identity, identity)
		if journal.Init.Agent.sent() || journal.Init.AgentID != "" {
			return result, fmt.Errorf("%w: %s differs from the value Agent %s was registered with; init will not "+
				"register a second Agent. Restore the earlier value, or start a new node with another state "+
				"directory and rail configuration", ErrSetupInputChanged, field, journal.Init.AgentID)
		}
		journal.Init = &InitJournal{Identity: identity}
	}
	state := journal.Init
	state.TOSCTLSHA256 = pin
	if err = run.save(); err != nil {
		return result, err
	}

	if state.AgentID == "" {
		if !in.Yes {
			run.notef("agent.register", SetupPlanned, "an Agent registration will be signed with controller %q and "+
				"sent from wallet %q (%s) attaching %s TOS", in.PacketController, wallet.Name, wallet.Address,
				FormatTOSAmount(RegistryMessageValueNano))
			return result, ErrConfirmationRequired
		}
		needed, addErr := checkedAdd(RegistryMessageValueNano, walletFeeMarginNano)
		if addErr != nil {
			return result, addErr
		}
		if err = requireFundedWallet(wallet, needed, "registering the Agent"); err != nil {
			return result, err
		}
		// The nonce is durable before the registration is built, so a
		// re-run after a crash builds the same Agent.
		if state.AgentNonce == "" {
			if state.AgentNonce, err = env.nonce(); err != nil {
				return result, err
			}
			if err = run.save(); err != nil {
				return result, err
			}
		}
		policyPath, policyErr := writeAgentPolicy(in.StateDir, packet)
		if policyErr != nil {
			return result, policyErr
		}
		env.reportf("agent.register: signing an Agent registration with controller %q (%s) for network %q",
			in.PacketController, packet.Text(), in.NetworkLabel)
		message, buildErr := ops.registerAgent(ctx, policyPath, state.AgentNonce, in.PacketController)
		if buildErr != nil {
			return result, fmt.Errorf("servicebridge: build the Agent registration: %w", buildErr)
		}
		agentID := "agent_" + message.ObjectID
		located, locateErr := locator.Locate(agentID)
		if locateErr != nil || located.Address != message.Destination {
			return result, errors.New("servicebridge: tosctl built a registration for another address than the one " +
				"the Agent id derives under the configured network and registry code; nothing was sent")
		}
		state.Registration, state.AgentID, state.AgentAddress = &message, agentID, message.Destination
		if err = run.save(); err != nil {
			return result, err
		}
	}
	result.AgentID = state.AgentID
	if state.AgentAddress == "" {
		located, locateErr := locator.Locate(state.AgentID)
		if locateErr != nil {
			return result, locateErr
		}
		state.AgentAddress = located.Address
	}
	result.AgentAddress = state.AgentAddress
	effect := agentEffect(ctx, state.AgentID, packet.Text())
	err = run.runStep("agent.register", "the registration of Agent "+state.AgentID, &state.Agent, effect,
		func() error {
			if state.Registration == nil {
				return notSent(fmt.Errorf("servicebridge: Agent %s is named by the rail configuration but is not "+
					"in finalized state, and this state directory holds no registration for it", state.AgentID))
			}
			needed, addErr := checkedAdd(RegistryMessageValueNano, walletFeeMarginNano)
			if addErr != nil {
				return notSent(addErr)
			}
			if fundErr := requireFundedWallet(wallet, needed, "registering the Agent"); fundErr != nil {
				return notSent(fundErr)
			}
			env.reportf("agent.register: sending the registration of %s to %s from wallet %q (%s), attaching %s TOS",
				state.AgentID, state.AgentAddress, wallet.Name, wallet.Address,
				FormatTOSAmount(RegistryMessageValueNano))
			return ops.walletSend(ctx, in.WalletName, RegistryMessageValueNano, *state.Registration)
		})
	if err != nil {
		return result, err
	}
	config.AgentID = state.AgentID
	if relayPin.data != nil {
		if config.RelayCAFile, err = installRelayCA(in.StateDir, relayPin.data); err != nil {
			return result, err
		}
	} else {
		config.RelayCAFile = relayPin.path
	}
	config.RelayCASHA256 = relayPin.sha256
	if relayPin.sha256 != "" {
		run.notef("relay.trust", SetupDone, "this node's https relays are verified against the %d pinned certificate "+
			"authorities in %s (SHA-256 %s) only, not the system trust store; relays only a peer's card names "+
			"use the system trust store", relayPin.certificates, config.RelayCAFile, relayPin.sha256)
	}
	if err = writeNodeConfig(in.RailConfigPath, config); err != nil {
		return result, err
	}
	// Only now that the configuration names the new pin (or none) is an
	// earlier pinned file unused.
	if err = removeStaleRelayCAs(in.StateDir, config.RelayCAFile); err != nil {
		return result, err
	}
	run.notef("config.write", SetupDone, "wrote the rail configuration %s (0600); it reads back strictly",
		in.RailConfigPath)
	result.Confirmed = true
	result.NextSteps = []string{
		"provider: openfox earning service offer --rail-config " + in.RailConfigPath + " --price <TOS> ...",
		"buyer: openfox earning service buy --rail-config " + in.RailConfigPath + " --offer <file> --source <archive>",
	}
	// Two nodes that reach each other directly each need the other's Agent
	// id, which exists only after that node's own init. A node may therefore
	// be established without a transport; it cannot serve or buy until one
	// is added.
	if config.MessengerSocket == "" && len(config.DirectPeers) == 0 && len(config.RelayURLs) == 0 {
		run.notef("transport", SetupMissing, "no packet transport is configured: serve and buy refuse to start "+
			"until this command is run again with --direct-peer, --relay-url or --messenger-socket")
		result.NextSteps = append([]string{
			"add a packet transport: run init again with --direct-peer agent_<hex>=<socket> (the peer's Agent id " +
				"and receiver socket), --relay-url <https URL> or --messenger-socket <socket>",
		}, result.NextSteps...)
	}
	return result, nil
}
