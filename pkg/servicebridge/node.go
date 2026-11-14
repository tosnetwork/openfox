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

	"github.com/tosnetwork/tos-ai/pkg/railgate"
	"github.com/tosnetwork/tos-messenger/pkg/localapi"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/buyersdk"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativeclient"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
)

// NodeConfig is the owner-private configuration of one OpenFox rail node.
// It names custody (tosctl, the vault) but holds no key material: the vault
// URL is read from the environment variable VaultURLEnv.
type NodeConfig struct {
	Network          NetworkConfig   `json:"network"`
	RPCEndpoints     []string        `json:"rpc_endpoints"`
	Quorum           int             `json:"quorum"`
	RegistryCodeBOC  string          `json:"registry_code_boc_file"`
	RegistryCodeHash string          `json:"registry_code_hash"`
	ActorCodeHash    string          `json:"actor_code_hash"`
	StateDir         string          `json:"state_dir"`
	AgentID          string          `json:"agent_id"`
	PacketController string          `json:"packet_controller"`
	PacketKeyID      string          `json:"packet_key_id"`
	TOSCTL           TOSCTLConfig    `json:"tosctl"`
	WalletName       string          `json:"wallet_name"`
	WalletAddress    string          `json:"wallet_address"`
	MessengerSocket  string          `json:"messenger_socket"`
	ReceiverSocket   string          `json:"receiver_socket"`
	Provider         *ProviderNode   `json:"provider,omitempty"`
	Buyer            *BuyerNode      `json:"buyer,omitempty"`
	MaxAssemblies    *AssemblyBounds `json:"max_assemblies,omitempty"`
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

// ProviderNode configures the selling side.
type ProviderNode struct {
	CapabilityID        string `json:"capability_id"`
	Version             string `json:"version"`
	ManifestFile        string `json:"manifest_file"`
	AttestorController  string `json:"attestor_controller"`
	RespondBudgetSecond int    `json:"respond_budget_seconds"`
	ExecutorBinary      string `json:"executor_binary"`
	ExecutorSHA256      string `json:"executor_sha256"`
	ContainerdSocket    string `json:"containerd_socket"`
	FIFODir             string `json:"fifo_dir"`
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
// subprocess executor, for a host without the container runtime.
type NodeOptions struct {
	Runner    WorkRunner
	Artifacts ArtifactSource
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
	closers   []io.Closer
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
	client, err := localapi.NewClient(config.MessengerSocket, 30*time.Second)
	if err != nil {
		return fail(err)
	}
	node.Courier, err = OpenCourier(
		filepath.Join(config.StateDir, "outbox"),
		signer,
		MessengerTransport{Client: client},
	)
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
	node.Receiver = &Receiver{
		LocalAgentID: config.AgentID, Resolver: FinalizedAgents{Sessions: ChainSessions{Reader: node.Reader}},
		Verifier: node.Helper, Inbox: node.Inbox, Notify: node.Service.Notify, Now: options.Now,
	}
	return node, nil
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
	var runner WorkRunner
	var store ArtifactSource
	if options.Runner != nil {
		runner, store = options.Runner, options.Artifacts
	} else {
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
	if runner == nil || store == nil {
		return errors.New("servicebridge: the provider has no executor")
	}
	n.Provider, err = NewProvider(ProviderConfig{
		AgentID:            n.Config.AgentID,
		CapabilityID:       config.CapabilityID,
		Version:            config.Version,
		Network:            n.Network,
		Gate:               gate,
		Runner:             runner,
		Store:              store,
		Lifecycle:          lifecycle,
		AttestorController: config.AttestorController,
		Courier:            n.Courier,
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
		Lifecycle: lifecycle,
		Directory: filepath.Join(n.Config.StateDir, "purchases"),
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
	fixed := q.fixed
	q.mutex.Unlock()
	var source QuoteSource = FixedQuote{Package: fixed}
	if fixed == nil {
		if q.next == nil {
			return nil, errors.New("servicebridge: no gateway or Quote package is configured")
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
