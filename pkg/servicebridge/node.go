package servicebridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/tosnetwork/ai/execution/pkg/railgate"
	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/buyersdk"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
	"github.com/tosnetwork/ai/protocol/pkg/nativeclient"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/quoteprovider"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
	"github.com/tosnetwork/tos-messenger/pkg/localapi"
)

// NodeConfig is the owner-private configuration of one OpenFox rail node.
// It names custody (tosctl, the vault) but holds no key material: the vault
// URL is read from the environment variable VaultURLEnv.
type NodeConfig struct {
	Network NetworkConfig `json:"network"`
	// GlobalConfigFile is the chain global configuration tosctl derives the
	// Native Registry identity domain from; `init` records it for `offer`.
	GlobalConfigFile string       `json:"chain_global_config_file,omitempty"`
	RPCEndpoints     []string     `json:"rpc_endpoints"`
	Quorum           int          `json:"quorum"`
	RegistryCodeBOC  string       `json:"registry_code_boc_file"`
	RegistryCodeHash string       `json:"registry_code_hash"`
	ActorCodeHash    string       `json:"actor_code_hash"`
	StateDir         string       `json:"state_dir"`
	AgentID          string       `json:"agent_id"`
	PacketController string       `json:"packet_controller"`
	PacketKeyID      string       `json:"packet_key_id"`
	TOSCTL           TOSCTLConfig `json:"tosctl"`
	WalletName       string       `json:"wallet_name"`
	WalletAddress    string       `json:"wallet_address"`
	// MessengerSocket is the local Messenger daemon. It may be empty only
	// when DirectPeers is not: then every packet needs a direct route.
	MessengerSocket string `json:"messenger_socket,omitempty"`
	// DirectPeers maps a recipient Agent id to the receiver Unix socket of
	// its node on this host. A packet to a listed Agent is posted to that
	// socket instead of going through the Messenger.
	DirectPeers map[string]string `json:"direct_peers,omitempty"`
	// RelayURLs are the Agent Packet Relay base URLs this node publishes in
	// its encryption key card and polls. With them a packet to a peer whose
	// verified card is known is sealed to that card and deposited at the
	// peer's relays.
	RelayURLs      []string        `json:"relay_urls,omitempty"`
	ReceiverSocket string          `json:"receiver_socket"`
	Provider       *ProviderNode   `json:"provider,omitempty"`
	Buyer          *BuyerNode      `json:"buyer,omitempty"`
	MaxAssemblies  *AssemblyBounds `json:"max_assemblies,omitempty"`
}

// NetworkConfig is the network domain.
type NetworkConfig struct {
	NetworkID       string `json:"network_id"`
	GenesisRootHash string `json:"genesis_root_hash"`
	GenesisFileHash string `json:"genesis_file_hash"`
}

// TOSCTLConfig pins tosctl.
type TOSCTLConfig struct {
	Binary      string `json:"binary"`
	SHA256      string `json:"sha256"`
	ConfigPath  string `json:"config_path"`
	VaultURLEnv string `json:"vault_url_env"`
}

// AssemblyBounds bounds the inbox.
type AssemblyBounds struct {
	PerSender int `json:"per_sender"`
	Total     int `json:"total"`
}

// ProviderNode configures the selling side. Exactly one executor is
// configured: ExecutorSocket, or ExecutorBinary with its pin, runtime socket
// and FIFO directory.
type ProviderNode struct {
	CapabilityID        string `json:"capability_id"`
	Version             string `json:"version"`
	ManifestFile        string `json:"manifest_file"`
	AttestorController  string `json:"attestor_controller"`
	RespondBudgetSecond int    `json:"respond_budget_seconds"`
	// ExecutorSocket is the Unix socket of the root-run executor service.
	// With it the node needs no container runtime privilege and runs as an
	// ordinary user.
	ExecutorSocket string `json:"executor_socket,omitempty"`
	// ExecutorBinary is the executor the node runs as its own child, for an
	// operator who runs the node and the container runtime as one user.
	ExecutorBinary   string `json:"executor_binary,omitempty"`
	ExecutorSHA256   string `json:"executor_sha256,omitempty"`
	ContainerdSocket string `json:"containerd_socket,omitempty"`
	FIFODir          string `json:"fifo_dir,omitempty"`
	// OfferFile is the offer file `offer` wrote. With relays configured the
	// node rewrites it when it issues a successor key card.
	OfferFile string `json:"offer_file,omitempty"`
}

// Executor modes of a provider node.
const (
	ExecutorModeSocket     = "socket"
	ExecutorModeSubprocess = "subprocess"
)

// ExecutorMode says which executor the section configures. Naming both, or
// neither, is refused: the node never picks one for the owner.
func (p *ProviderNode) ExecutorMode() (string, error) {
	if p == nil {
		return "", errors.New("servicebridge: the rail configuration has no provider section")
	}
	socket := p.ExecutorSocket != ""
	subprocess := p.ExecutorBinary != "" || p.ExecutorSHA256 != "" || p.ContainerdSocket != "" || p.FIFODir != ""
	switch {
	case socket && subprocess:
		return "", errors.New("servicebridge: provider.executor_socket is set together with executor_binary, " +
			"executor_sha256, containerd_socket or fifo_dir; configure exactly one executor")
	case socket:
		if !cleanAbsolute(p.ExecutorSocket) {
			return "", errors.New("servicebridge: provider.executor_socket must be an absolute clean path")
		}
		return ExecutorModeSocket, nil
	case subprocess:
		return ExecutorModeSubprocess, nil
	default:
		return "", errors.New("servicebridge: the provider section names no executor; set provider.executor_socket, " +
			"or executor_binary with executor_sha256, containerd_socket and fifo_dir")
	}
}

// BuyerNode configures the buying side.
type BuyerNode struct {
	GatewayURL       string       `json:"gateway_url,omitempty"`
	GatewayTokenFile string       `json:"gateway_token_file,omitempty"`
	GatewayCAFile    string       `json:"gateway_ca_file,omitempty"`
	CallerID         string       `json:"caller_id,omitempty"`
	Policy           PolicyConfig `json:"policy"`
}

// PolicyConfig is the owner spending policy in nanoTOS.
type PolicyConfig struct {
	MaxCommittedPerPurchase string   `json:"max_committed_per_purchase_nanotos"`
	MaxCommittedInWindow    string   `json:"max_committed_in_window_nanotos"`
	WindowSeconds           int64    `json:"window_seconds"`
	MaxOpenPurchases        int      `json:"max_open_purchases"`
	ConfirmAbove            string   `json:"confirm_above_nanotos,omitempty"`
	RefundReserve           string   `json:"refund_reserve_nanotos"`
	AllowedProviders        []string `json:"allowed_providers"`
}

// LoadNodeConfig strictly reads an owner-only configuration file.
func LoadNodeConfig(path string) (NodeConfig, error) {
	var config NodeConfig
	if !filepath.IsAbs(path) {
		return config, errors.New("servicebridge: the rail configuration path must be absolute")
	}
	if err := readJSON(path, 1<<20, &config); err != nil {
		return config, fmt.Errorf("servicebridge: rail configuration: %w", err)
	}
	return config, nil
}

// NodeOptions adjusts an assembled node. Runner and Artifacts replace the
// subprocess executor, for a host without the container runtime;
// ExecutorService replaces the client of the configured executor socket.
type NodeOptions struct {
	Runner          WorkRunner
	Artifacts       ArtifactSource
	ExecutorService ExecutorService
	// RelayDial replaces the relay HTTP client, for tests.
	RelayDial relayDialer
	Report    func(stage string, err error)
	Now       func() time.Time
}

// Node is one assembled rail node.
type Node struct {
	Config    NodeConfig
	Network   *nativev1.NetworkDomain
	Reader    *toschain.ServiceActorReader
	Helper    *mldsa44.Tosctl
	Inbox     *Inbox
	Courier   *Courier
	Receiver  *Receiver
	Provider  *Provider
	Buyer     *Buyer
	Service   *Service
	Manifests *MemoryManifests
	// Relay is the Agent Packet Relay carrier, nil without relay_urls.
	Relay *RelayCarrier
	// Cards holds the verified key cards of peers, nil without relay_urls.
	Cards   *PeerCards
	closers []io.Closer
}

// Close releases the node's resources.
func (n *Node) Close() error {
	var failures []error
	for index := len(n.closers) - 1; index >= 0; index-- {
		if err := n.closers[index].Close(); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

// MemoryManifests serves manifest bytes by digest. Bytes are untrusted:
// every consumer checks them against the finalized digest.
type MemoryManifests struct {
	mutex  sync.Mutex
	values map[string][]byte
}

// Put adds manifest bytes under their claimed digest.
func (m *MemoryManifests) Put(digest string, value []byte) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if m.values == nil {
		m.values = map[string][]byte{}
	}
	m.values[digest] = append([]byte(nil), value...)
}

// Manifest implements serviceactor.ManifestSource.
func (m *MemoryManifests) Manifest(_ context.Context, digest string) ([]byte, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	value, ok := m.values[digest]
	if !ok {
		return nil, errors.New("servicebridge: manifest not known")
	}
	return append([]byte(nil), value...), nil
}

type railReader struct{ reader *toschain.ServiceActorReader }

func (r railReader) BeginSession(ctx context.Context) (railgate.Session, error) {
	return r.reader.Begin(ctx)
}

func parseNano(value, name string, allowEmpty bool) (*big.Int, error) {
	if value == "" && allowEmpty {
		return nil, nil
	}
	parsed, ok := new(big.Int).SetString(value, 10)
	if !ok || parsed.Sign() < 0 || parsed.String() != value {
		return nil, fmt.Errorf("servicebridge: %s must be a canonical nanoTOS integer", name)
	}
	return parsed, nil
}

// effectiveQuorum is the configured quorum, or a strict majority of the
// endpoints when none is configured.
func effectiveQuorum(config NodeConfig) int {
	if config.Quorum == 0 {
		return len(config.RPCEndpoints)/2 + 1
	}
	return config.Quorum
}

// newChainAdapter validates the endpoint set and quorum without contacting
// any endpoint.
func newChainAdapter(config NodeConfig) (*toschain.Adapter, error) {
	return toschain.New(toschain.Config{
		Network: config.Network.NetworkID, Endpoints: config.RPCEndpoints, Quorum: effectiveQuorum(config),
	})
}

// openServiceActorReader assembles the finalized Service Actor reader whose
// monotonic checkpoint fences live in checkpointDir.
func openServiceActorReader(
	config NodeConfig,
	network *nativev1.NetworkDomain,
	checkpointDir string,
) (*toschain.ServiceActorReader, error) {
	chain, err := newChainAdapter(config)
	if err != nil {
		return nil, err
	}
	code, err := os.ReadFile(config.RegistryCodeBOC)
	if err != nil || len(code) == 0 || len(code) > 1<<20 {
		return nil, errors.New("servicebridge: read the Native Registry code BOC")
	}
	locator, err := nativecore.NewLocator(
		network,
		0,
		strings.Join(strings.Fields(string(code)), ""),
		config.RegistryCodeHash,
	)
	if err != nil {
		return nil, err
	}
	registry, err := toschain.NewSimplifiedNativeResolver(
		chain,
		locator,
		filepath.Join(checkpointDir, "registry.checkpoint"),
	)
	if err != nil {
		return nil, err
	}
	return toschain.NewServiceActorReader(toschain.ServiceActorReaderConfig{
		Chain:          chain,
		Network:        network,
		ActorCodeHash:  config.ActorCodeHash,
		Registry:       registry,
		CheckpointPath: filepath.Join(checkpointDir, "service-actor.checkpoint"),
	})
}

func newMessengerClient(socket string) (*localapi.Client, error) {
	return localapi.NewClient(socket, 30*time.Second)
}

// OpenNode validates the configuration and assembles the node.
func OpenNode(ctx context.Context, config NodeConfig, options NodeOptions) (*Node, error) {
	if config.Provider == nil && config.Buyer == nil {
		return nil, errors.New("servicebridge: the rail node needs a provider or a buyer section")
	}
	if !filepath.IsAbs(config.StateDir) || filepath.Clean(config.StateDir) != config.StateDir {
		return nil, errors.New("servicebridge: state_dir must be absolute and clean")
	}
	if err := ensurePrivateDirectory(config.StateDir); err != nil {
		return nil, err
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	node := &Node{Config: config, Manifests: &MemoryManifests{}}
	fail := func(err error) (*Node, error) { return nil, errors.Join(err, node.Close()) }
	var err error
	node.Network = &nativev1.NetworkDomain{
		NetworkId: config.Network.NetworkID, GenesisRootHash: config.Network.GenesisRootHash,
		GenesisFileHash: config.Network.GenesisFileHash,
	}
	node.Reader, err = openServiceActorReader(config, node.Network, config.StateDir)
	if err != nil {
		return fail(err)
	}
	vaultURL := ""
	if config.TOSCTL.VaultURLEnv != "" {
		vaultURL = os.Getenv(config.TOSCTL.VaultURLEnv)
	}
	node.Helper, err = mldsa44.NewTosctl(mldsa44.TosctlConfig{
		Binary: config.TOSCTL.Binary, SHA256: config.TOSCTL.SHA256,
		ConfigPath: config.TOSCTL.ConfigPath, VaultURL: vaultURL,
	})
	if err != nil {
		return fail(err)
	}
	signer, err := NewPacketSigner(node.Helper, config.PacketController, config.PacketKeyID, config.AgentID)
	if err != nil {
		return fail(err)
	}
	agents := FinalizedAgents{Sessions: ChainSessions{Reader: node.Reader}}
	node.Receiver = &Receiver{LocalAgentID: config.AgentID, Resolver: agents, Verifier: node.Helper, Now: options.Now}
	if len(config.RelayURLs) > 0 {
		if err = node.openRelay(signer, agents, options); err != nil {
			return fail(err)
		}
	}
	var relay *RelayTransport
	if node.Relay != nil {
		relay = node.Relay.Transport
	}
	transport, err := openPacketTransport(config, relay)
	if err != nil {
		return fail(err)
	}
	node.Courier, err = OpenCourier(filepath.Join(config.StateDir, "outbox"), signer, transport)
	if err != nil {
		return fail(err)
	}
	bounds := AssemblyBounds{PerSender: DefaultMaxAssembliesPerSender, Total: DefaultMaxAssemblies}
	if config.MaxAssemblies != nil {
		bounds = *config.MaxAssemblies
	}
	node.Inbox, err = OpenInbox(filepath.Join(config.StateDir, "inbox"), bounds.PerSender, bounds.Total)
	if err != nil {
		return fail(err)
	}
	lifecycle, err := NewTOSCTLLifecycle(TOSCTLLifecycleConfig{
		BinaryPath: config.TOSCTL.Binary, BinarySHA256: config.TOSCTL.SHA256,
		ConfigPath: config.TOSCTL.ConfigPath, VaultURL: vaultURL, WalletName: config.WalletName,
	})
	if err != nil {
		return fail(err)
	}
	if config.Provider != nil {
		if err = node.openProvider(ctx, options, lifecycle); err != nil {
			return fail(err)
		}
	}
	if config.Buyer != nil {
		if err = node.openBuyer(options, lifecycle, vaultURL); err != nil {
			return fail(err)
		}
	}
	node.Service, err = NewService(node.Inbox, node.Provider, node.Buyer, options.Report)
	if err != nil {
		return fail(err)
	}
	node.Receiver.Inbox, node.Receiver.Notify = node.Inbox, node.Service.Notify
	if node.Relay != nil && config.Provider != nil && config.Provider.OfferFile != "" {
		node.Relay.SetRotationHook(node.republishOffer)
	}
	return node, nil
}

// openRelay opens the relay carrier and the peer card directory. The
// receiver it feeds is completed once the inbox is open.
func (n *Node) openRelay(signer *PacketSigner, agents FinalizedAgents, options NodeOptions) error {
	root := filepath.Join(n.Config.StateDir, relayStateDir)
	if err := ensurePrivateDirectory(root); err != nil {
		return err
	}
	cards, err := OpenPeerCards(filepath.Join(root, relayPeersDir), n.Helper, agents,
		FinalizedCapabilityOwners{Sessions: ChainSessions{Reader: n.Reader}}, options.Now)
	if err != nil {
		return err
	}
	report := options.Report
	if report == nil {
		report = func(string, error) {}
	}
	carrier, err := OpenRelayCarrier(RelayCarrierConfig{
		StateDir: n.Config.StateDir, AgentID: n.Config.AgentID, Relays: n.Config.RelayURLs, Signer: signer,
		Cards: cards, Receiver: n.Receiver, Dial: options.RelayDial, Now: options.Now, Report: report,
	})
	if err != nil {
		return err
	}
	n.Relay, n.Cards = carrier, cards
	return nil
}

// republishOffer rewrites the provider's offer file with a new own card.
func (n *Node) republishOffer(_ context.Context, key OwnRelayKey) error {
	provider := n.Config.Provider
	manifestCBOR, err := os.ReadFile(provider.ManifestFile)
	if err != nil || len(manifestCBOR) == 0 || len(manifestCBOR) > 1<<20 {
		return errors.New("servicebridge: read the provider manifest")
	}
	manifest, err := nativecore.DecodeCanonicalSoftwareWorkManifestCBOR(manifestCBOR)
	if err != nil {
		return err
	}
	_, digest, err := nativecore.CanonicalSoftwareWorkManifest(manifest)
	if err != nil {
		return err
	}
	return writeOfferFile(provider.OfferFile, Offer{
		CapabilityID: provider.CapabilityID, Version: provider.Version, ProviderAgentID: n.Config.AgentID,
		ManifestDigest: digest, ManifestCBOR: manifestCBOR, KeyCard: key.CardJSON,
	}, time.Now())
}

func (n *Node) openProvider(ctx context.Context, options NodeOptions, lifecycle LifecycleSender) error {
	config := n.Config.Provider
	manifestCBOR, err := os.ReadFile(config.ManifestFile)
	if err != nil || len(manifestCBOR) == 0 || len(manifestCBOR) > 1<<20 {
		return errors.New("servicebridge: read the provider manifest")
	}
	manifest, err := nativecore.DecodeCanonicalSoftwareWorkManifestCBOR(manifestCBOR)
	if err != nil {
		return err
	}
	canonical, digest, err := nativecore.CanonicalSoftwareWorkManifest(manifest)
	if err != nil || !bytes.Equal(canonical, manifestCBOR) {
		return errors.New("servicebridge: the provider manifest is not canonical")
	}
	n.Manifests.Put(digest, manifestCBOR)
	respond := time.Duration(config.RespondBudgetSecond) * time.Second
	verifier, err := railgate.NewVerifier(railgate.VerifierConfig{
		Reader:          railReader{reader: n.Reader},
		Manifests:       n.Manifests,
		Network:         n.Network,
		ActorCodeHash:   n.Config.ActorCodeHash,
		ProviderAgentID: n.Config.AgentID,
		CapabilityID:    config.CapabilityID,
		Version:         config.Version,
		ExecutionBudget: time.Duration(manifest.Limits.WallClockMillis) * time.Millisecond,
		RespondBudget:   respond,
	})
	if err != nil {
		return err
	}
	gate, err := railgate.OpenGate(verifier, filepath.Join(n.Config.StateDir, "slots"))
	if err != nil {
		return err
	}
	n.closers = append(n.closers, gate)
	// The verifier reserves its default when none is configured; the
	// provider stops waiting for an outcome by the same budget.
	providerRespond := respond
	if providerRespond == 0 {
		providerRespond = railgate.DefaultRespondBudget
	}
	var runner WorkRunner
	var service ServiceRunner
	var store ArtifactSource
	mode, err := config.ExecutorMode()
	switch {
	case options.Runner != nil:
		runner, store = options.Runner, options.Artifacts
	case err != nil:
		return err
	case mode == ExecutorModeSocket:
		socket, socketErr := NewSocketRunner(SocketRunnerConfig{
			SocketPath:      config.ExecutorSocket,
			StateDir:        filepath.Join(n.Config.StateDir, "executor-service"),
			ManifestDigest:  digest,
			ToolchainDigest: manifest.ToolchainDigest,
			Limits:          manifest.Limits,
			Client:          options.ExecutorService,
		})
		if socketErr != nil {
			return socketErr
		}
		service, store = socket, socket
	default:
		subprocess, subprocessErr := NewSubprocessRunner(SubprocessRunnerConfig{
			BinaryPath:       config.ExecutorBinary,
			BinarySHA256:     config.ExecutorSHA256,
			ContainerdSocket: config.ContainerdSocket,
			FIFODir:          config.FIFODir,
			StateDir: filepath.Join(
				n.Config.StateDir,
				"executor",
			),
			ManifestDigest: digest,
			OutputBytes:    manifest.Limits.OutputBytes,
		})
		if subprocessErr != nil {
			return subprocessErr
		}
		runner, store = subprocess, subprocess
	}
	if (runner == nil && service == nil) || store == nil {
		return errors.New("servicebridge: the provider has no executor")
	}
	n.Provider, err = NewProvider(ProviderConfig{
		AgentID:            n.Config.AgentID,
		CapabilityID:       config.CapabilityID,
		Version:            config.Version,
		Network:            n.Network,
		Gate:               gate,
		Runner:             runner,
		Service:            service,
		RespondBudget:      providerRespond,
		Store:              store,
		Lifecycle:          lifecycle,
		AttestorController: config.AttestorController,
		Courier:            n.Courier,
		Cards:              n.Cards,
		History:            railReader{reader: n.Reader},
		Directory:          filepath.Join(n.Config.StateDir, "provider"),
		StateDir:           n.Config.StateDir,
		Now:                options.Now,
	})
	return err
}

func (n *Node) openBuyer(options NodeOptions, lifecycle LifecycleSender, vaultURL string) error {
	config := n.Config.Buyer
	policy, err := config.Policy.parse()
	if err != nil {
		return err
	}
	journalDir := filepath.Join(n.Config.StateDir, "calls")
	if err = ensurePrivateDirectory(journalDir); err != nil {
		return err
	}
	journal, err := buyersdk.OpenServiceActorJournal(journalDir, options.Now())
	if err != nil {
		return err
	}
	sender, err := buyersdk.NewTOSCTLServiceActorSender(buyersdk.TOSCTLServiceActorSenderConfig{
		BinaryPath:   n.Config.TOSCTL.Binary,
		BinarySHA256: n.Config.TOSCTL.SHA256, ConfigPath: n.Config.TOSCTL.ConfigPath, WalletName: n.Config.WalletName,
		VaultURL: vaultURL, Endpoints: n.Reader,
	})
	if err != nil {
		return err
	}
	buyer, err := buyersdk.NewServiceActorBuyer(buyersdk.ServiceActorBuyerConfig{
		Reader:        buyersdk.BuyerReaderFromChain(n.Reader),
		Manifests:     n.Manifests,
		Network:       n.Network,
		ActorCodeHash: n.Config.ActorCodeHash,
		BuyerWallet:   n.Config.WalletAddress,
		Sender:        sender,
		Journal:       journal,
		Limits: buyersdk.ServiceActorLimits{
			Window: policy.Window, MaxCalls: policy.MaxOpenPurchases,
			MaxPerCallNanoTOS: policy.MaxCommittedPerPurchase, MaxWindowNanoTOS: policy.MaxCommittedInWindow,
		},
		Now: options.Now,
	})
	if err != nil {
		return err
	}
	var quotes QuoteSource = &PackageQuotes{manifests: n.Manifests}
	if config.GatewayURL != "" {
		token := ""
		if config.GatewayTokenFile != "" {
			raw, rawErr := readPrivateFile(config.GatewayTokenFile, 4096)
			if rawErr != nil {
				return rawErr
			}
			token = strings.TrimSpace(string(raw))
		}
		client, clientErr := nativeclient.New(nativeclient.Config{
			BaseURL: config.GatewayURL, BearerToken: token, CAFile: config.GatewayCAFile,
			Timeout: 30 * time.Second,
		})
		if clientErr != nil {
			return clientErr
		}
		quotes = &PackageQuotes{manifests: n.Manifests, next: GatewayQuotes{Client: client, CallerID: config.CallerID}}
	}
	n.Buyer, err = NewBuyer(BuyerConfig{
		AgentID:   n.Config.AgentID,
		Wallet:    n.Config.WalletAddress,
		Network:   n.Network,
		Buyer:     buyer,
		Quotes:    quotes,
		Policy:    policy,
		Courier:   n.Courier,
		RelayKeys: n.relayKeys(),
		Lifecycle: lifecycle,
		Directory: filepath.Join(n.Config.StateDir, "purchases"),
		Manifests: n.Manifests,
		Now:       options.Now,
	})
	return err
}

func (p PolicyConfig) parse() (SpendingPolicy, error) {
	perPurchase, err := parseNano(p.MaxCommittedPerPurchase, "max_committed_per_purchase_nanotos", false)
	if err != nil {
		return SpendingPolicy{}, err
	}
	window, err := parseNano(p.MaxCommittedInWindow, "max_committed_in_window_nanotos", false)
	if err != nil {
		return SpendingPolicy{}, err
	}
	confirm, err := parseNano(p.ConfirmAbove, "confirm_above_nanotos", true)
	if err != nil {
		return SpendingPolicy{}, err
	}
	reserve, err := parseNano(p.RefundReserve, "refund_reserve_nanotos", false)
	if err != nil {
		return SpendingPolicy{}, err
	}
	allowed := map[string]bool{}
	for _, provider := range p.AllowedProviders {
		if !agentIDPattern.MatchString(provider) {
			return SpendingPolicy{}, errors.New("servicebridge: allowed_providers holds an invalid Agent id")
		}
		allowed[provider] = true
	}
	policy := SpendingPolicy{
		MaxCommittedPerPurchase: perPurchase,
		MaxCommittedInWindow:    window,
		Window: time.Duration(
			p.WindowSeconds,
		) * time.Second,
		MaxOpenPurchases: p.MaxOpenPurchases,
		ConfirmAbove:     confirm,
		AllowedProviders: allowed,
		RefundReserve:    reserve,
	}
	return policy, policy.Validate()
}

// PackageQuotes takes the Quote from next (a gateway) or from a package the
// owner set, and makes its manifest bytes available to discovery, which
// checks them against the finalized digest.
type PackageQuotes struct {
	manifests *MemoryManifests
	next      QuoteSource
	mutex     sync.Mutex
	fixed     *nativev1.QuoteProposalPackageV1
	source    QuoteSource
}

// UseSource makes the next Quote come from source instead of the gateway.
func (q *PackageQuotes) UseSource(source QuoteSource) {
	q.mutex.Lock()
	defer q.mutex.Unlock()
	q.source = source
}

// UsePackage makes the next Quote the given package.
func (q *PackageQuotes) UsePackage(value *nativev1.QuoteProposalPackageV1) {
	q.mutex.Lock()
	defer q.mutex.Unlock()
	q.fixed = value
}

// Quote implements QuoteSource.
func (q *PackageQuotes) Quote(
	ctx context.Context,
	request *nativev1.RequestQuoteProposalRequest,
) (*nativev1.QuoteProposalPackageV1, error) {
	q.mutex.Lock()
	fixed, chosen := q.fixed, q.source
	q.mutex.Unlock()
	var source QuoteSource = FixedQuote{Package: fixed}
	switch {
	case fixed != nil && chosen != nil:
		return nil, errors.New("servicebridge: more than one Quote source was chosen")
	case chosen != nil:
		source = chosen
	case fixed == nil:
		if q.next == nil {
			return nil, errors.New("servicebridge: no gateway, offer or Quote package is configured")
		}
		source = q.next
	}
	pkg, err := source.Quote(ctx, request)
	if err != nil {
		return nil, err
	}
	if pkg.GetProposal() != nil && len(pkg.GetCanonicalManifestCbor()) > 0 {
		q.manifests.Put(pkg.GetProposal().GetManifestDigest(), pkg.GetCanonicalManifestCbor())
	}
	return pkg, nil
}

// BuyerQuotes returns the buyer's package quote source.
func (n *Node) BuyerQuotes() (*PackageQuotes, bool) {
	if n == nil || n.Buyer == nil {
		return nil, false
	}
	quotes, ok := n.Buyer.config.Quotes.(*PackageQuotes)
	return quotes, ok
}

// UseOffer makes the buyer build its next Quote locally from an offer file
// and finalized state.
func (n *Node) UseOffer(offer Offer, now func() time.Time) error {
	quotes, ok := n.BuyerQuotes()
	if !ok || n.Reader == nil {
		return errors.New("servicebridge: the buyer cannot take an offer file")
	}
	quotes.UseSource(OfferQuotes{
		Sessions: quoteprovider.FromChain(n.Reader), Network: n.Network,
		RegistryCodeHash: n.Config.RegistryCodeHash, Offer: offer, Cards: n.Cards, Now: now,
	})
	return nil
}

func (n *Node) relayKeys() *RelayKeys {
	if n.Relay == nil {
		return nil
	}
	return n.Relay.Keys
}

// EncodeNodeConfig renders a configuration for an owner to edit.
func EncodeNodeConfig(config NodeConfig) ([]byte, error) {
	return json.MarshalIndent(config, "", "  ")
}

// ReadProviderRecords lists a provider's requests from its state directory
// without taking the worker's ownership, so it runs beside `serve`.
func ReadProviderRecords(stateDir string) ([]ProviderRecord, error) {
	if !filepath.IsAbs(stateDir) || filepath.Clean(stateDir) != stateDir {
		return nil, errors.New("servicebridge: state_dir must be clean and absolute")
	}
	directory := filepath.Join(stateDir, "provider")
	if err := checkPrivateDirectory(stateDir); err != nil {
		return nil, err
	}
	if err := checkPrivateDirectory(directory); err != nil {
		return nil, err
	}
	provider := &Provider{config: ProviderConfig{Directory: directory, Now: time.Now}}
	return provider.Records()
}

// ReadPurchases lists a buyer's purchases from its state directory without
// taking the worker's ownership.
func ReadPurchases(stateDir string) ([]PurchaseRecord, error) {
	if !filepath.IsAbs(stateDir) || filepath.Clean(stateDir) != stateDir {
		return nil, errors.New("servicebridge: state_dir must be clean and absolute")
	}
	directory := filepath.Join(stateDir, "purchases")
	if err := checkPrivateDirectory(stateDir); err != nil {
		return nil, err
	}
	if err := checkPrivateDirectory(directory); err != nil {
		return nil, err
	}
	buyer := &Buyer{config: BuyerConfig{Directory: directory, Now: time.Now}}
	return buyer.Purchases()
}
