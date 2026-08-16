// Command tos-service-provider runs the chain-backed OpenFox provider with one
// finalized execution gate shared by A2A, MCP, and Agent Packet transports.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	nativeimpl "github.com/tosnetwork/openfox/pkg/servicebridge/nativeimpl"
	"github.com/tosnetwork/tos-ai/pkg/a2aadapter"
	"github.com/tosnetwork/tos-ai/pkg/adapterhttp"
	"github.com/tosnetwork/tos-ai/pkg/artifacthttp"
	"github.com/tosnetwork/tos-ai/pkg/artifactstore"
	"github.com/tosnetwork/tos-ai/pkg/executor"
	"github.com/tosnetwork/tos-ai/pkg/executor/containerdbackend"
	"github.com/tosnetwork/tos-ai/pkg/mcpadapter"
	"github.com/tosnetwork/tos-ai/pkg/softwarework"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentpacket"
	"github.com/tosnetwork/tos-service-protocol/pkg/executiongate"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
)

const (
	manifestDigest  = "sha256:e4db0138ca2a4d5ad8f3c7ec458304927344e341ae610ee0a682b9cc5b00594e"
	toolchainDigest = "sha256:9624bca74096f810c5b24e489521dde124fadcfa1808581648b38bdc1ba1b105"
	imageReference  = "docker.io/tosnetwork/software-work-go:1.26.5@" + toolchainDigest
)

type endpointsFlag []string

func (f *endpointsFlag) String() string { return strings.Join(*f, ",") }
func (f *endpointsFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

type options struct {
	stateDir, socket, fifoDir                            string
	networkID, genesisRoot, genesisFile                  string
	registryBOC, registryHash, escrowHash                string
	providerAgent, providerAddress                       string
	transportDigest, signerAuthorization, signerSeedPath string
	executionSignerWallet, executionSignerPublicKey      string
	tosctlBinary, tosctlConfig, tosctlWallet             string
	certificate, privateKey, bearerPath                  string
	a2aAddress, mcpAddress, packetAddress, artifactAddr  string
	artifactOrigin                                       string
	endpoints                                            endpointsFlag
}

func main() {
	configured := parseFlags()
	if err := run(configured); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func parseFlags() options {
	var value options
	flag.StringVar(&value.stateDir, "state-dir", "", "private provider state directory")
	flag.StringVar(&value.socket, "containerd-socket", "", "private containerd socket")
	flag.StringVar(&value.fifoDir, "fifo-dir", "", "private containerd FIFO directory")
	flag.StringVar(&value.networkID, "network-id", "", "TOS network ID")
	flag.StringVar(&value.genesisRoot, "genesis-root", "", "sha256 genesis root hash")
	flag.StringVar(&value.genesisFile, "genesis-file", "", "sha256 genesis file hash")
	flag.Var(&value.endpoints, "endpoint", "quorum JSON-RPC endpoint; repeat exactly three times")
	flag.StringVar(&value.registryBOC, "registry-code-boc", "", "path to frozen Registry code BOC base64")
	flag.StringVar(&value.registryHash, "registry-code-hash", "", "Registry TVM cell digest")
	flag.StringVar(&value.escrowHash, "escrow-code-hash", "", "escrow TVM cell digest")
	flag.StringVar(&value.providerAgent, "provider-agent-id", "", "provider Native Agent ID")
	flag.StringVar(&value.providerAddress, "provider-address", "", "provider raw wallet address")
	flag.StringVar(&value.transportDigest, "transport-digest", "", "transport binding SHA-256 digest")
	flag.StringVar(&value.signerAuthorization, "signer-authorization", "", "execution signer authorization SHA-256 digest")
	flag.StringVar(&value.signerSeedPath, "execution-signer-seed", "", "private raw 32-byte Ed25519 seed")
	flag.StringVar(&value.executionSignerWallet, "execution-signer-wallet", "", "tosctl wallet holding the execution signer")
	flag.StringVar(&value.executionSignerPublicKey, "execution-signer-public-key", "", "expected execution signer Ed25519 public key hex")
	flag.StringVar(&value.tosctlBinary, "tosctl", "", "tosctl executable")
	flag.StringVar(&value.tosctlConfig, "tosctl-config", "", "private tosctl configuration")
	flag.StringVar(&value.tosctlWallet, "tosctl-wallet", "provider", "tosctl provider wallet name")
	flag.StringVar(&value.certificate, "tls-cert", "", "TLS certificate PEM")
	flag.StringVar(&value.privateKey, "tls-key", "", "TLS private key PEM")
	flag.StringVar(&value.bearerPath, "bearer-token-file", "", "private transport bearer token file")
	flag.StringVar(&value.a2aAddress, "a2a-address", "127.0.0.1:8443", "A2A listen address")
	flag.StringVar(&value.mcpAddress, "mcp-address", "127.0.0.1:8444", "MCP listen address")
	flag.StringVar(&value.packetAddress, "agent-packet-address", "127.0.0.1:8445", "Agent Packet listen address")
	flag.StringVar(&value.artifactAddr, "artifact-address", "127.0.0.1:8446", "artifact listen address")
	flag.StringVar(&value.artifactOrigin, "artifact-origin", "https://127.0.0.1:8446", "buyer-visible artifact HTTPS origin")
	flag.Parse()
	return value
}

func run(value options) error {
	if len(value.endpoints) != 3 || value.stateDir == "" || value.socket == "" || value.fifoDir == "" ||
		value.networkID == "" || value.genesisRoot == "" || value.genesisFile == "" || value.registryBOC == "" ||
		value.registryHash == "" || value.escrowHash == "" || value.providerAgent == "" || value.providerAddress == "" ||
		value.transportDigest == "" || value.signerAuthorization == "" ||
		value.tosctlBinary == "" || value.tosctlConfig == "" || value.tosctlWallet == "" ||
		value.certificate == "" || value.privateKey == "" || value.bearerPath == "" {
		return errors.New("provider configuration is incomplete")
	}
	seedSigner := value.signerSeedPath != "" && value.executionSignerWallet == "" && value.executionSignerPublicKey == ""
	tosctlSigner := value.signerSeedPath == "" && value.executionSignerWallet != "" && value.executionSignerPublicKey != ""
	if !seedSigner && !tosctlSigner {
		return errors.New("configure exactly one execution signer custody mode")
	}
	if err := requirePrivateDirectory(value.stateDir); err != nil {
		return err
	}
	bearer, err := readPrivateBearer(value.bearerPath)
	if err != nil {
		return err
	}
	network := &nativev1.NetworkDomain{NetworkId: value.networkID, GenesisRootHash: value.genesisRoot, GenesisFileHash: value.genesisFile}
	registryBOC, err := readBase64File(value.registryBOC, 1<<20)
	if err != nil {
		return err
	}
	chain, err := toschain.New(toschain.Config{Network: value.networkID, Endpoints: value.endpoints, Quorum: 2})
	if err != nil {
		return err
	}
	registryLocator, err := nativecore.NewLocator(network, 0, registryBOC, value.registryHash)
	if err != nil {
		return err
	}
	nativeResolver, err := toschain.NewSimplifiedNativeResolver(chain, registryLocator, filepath.Join(value.stateDir, "native.checkpoint"))
	if err != nil {
		return err
	}
	escrowResolver, err := toschain.NewEscrowResolver(chain, network, value.escrowHash, filepath.Join(value.stateDir, "escrow.checkpoint"))
	if err != nil {
		return err
	}
	gate, err := executiongate.New(executiongate.Config{
		Directory: filepath.Join(value.stateDir, "gate"), EscrowResolver: escrowResolver, NativeResolver: nativeResolver,
		Network: network, RegistryCodeHash: value.registryHash, ProviderAgentID: value.providerAgent,
		ProviderAddress: value.providerAddress, ManifestDigest: manifestDigest, TransportDigest: value.transportDigest,
		ExecutionSignerAuthorization: value.signerAuthorization, Timeout: 30 * time.Second,
	})
	if err != nil {
		return err
	}

	limits := executor.Limits{CPUMillis: 120_000, MemoryBytes: 1 << 30, DiskBytes: 2 << 30,
		PIDs: 64, ExecutionTime: 180 * time.Second, OutputBytes: 16 << 20}
	backend, err := containerdbackend.Open(context.Background(), containerdbackend.Config{
		SocketPath: value.socket, Namespace: "tos-service-paid-work", Snapshotter: "overlayfs", Runtime: "io.containerd.runc.v2",
		FIFODir: value.fifoDir, MaxActive: 4, PolicyLimits: limits, ImageReference: imageReference,
		ImageDigest: toolchainDigest, ImagePlatform: "linux/amd64",
	})
	if err != nil {
		return err
	}
	defer backend.Close()
	bound, err := executor.NewPolicyExecutor(executor.Policy{AllowedImages: map[string]struct{}{toolchainDigest: {}},
		MaxAllowedImages: 1, MaxEnvironment: 8, MaxArguments: 8, MaxAllowedHosts: 0, MaxStringBytes: 4096,
		MaxInputBytes: 16 << 20, Ceiling: limits, RequireReadOnlyRoot: true}, backend)
	if err != nil {
		return err
	}
	store, err := artifactstore.Open(filepath.Join(value.stateDir, "artifacts"), 64<<20)
	if err != nil {
		return err
	}
	journal, err := softwarework.OpenJournal(filepath.Join(value.stateDir, "journal"))
	if err != nil {
		return err
	}
	defer journal.Close()
	runner, err := softwarework.NewRunner(bound, store, journal, softwarework.Contract{
		ManifestDigest: manifestDigest, ToolchainDigest: toolchainDigest, SandboxDigest: manifestDigest,
		Executable: "/usr/local/bin/go", Arguments: []string{"test", "./...", "-count=1"}, WorkingDirectory: "/workspace/source",
		Limits: limits, UserID: 65532, GroupID: 65532,
	})
	if err != nil {
		return err
	}
	artifactLocator, err := artifacthttp.OpenPersistent(
		store, value.artifactOrigin, filepath.Join(value.stateDir, "artifact-publications.json"),
	)
	if err != nil {
		return err
	}
	var signer nativeimpl.ExecutionSigner
	if seedSigner {
		seed, seedErr := readPrivateSeed(value.signerSeedPath)
		if seedErr != nil {
			return seedErr
		}
		signer, err = nativeimpl.NewEd25519ExecutionSigner(ed25519.NewKeyFromSeed(seed))
		for index := range seed {
			seed[index] = 0
		}
	} else {
		public, decodeErr := hex.DecodeString(value.executionSignerPublicKey)
		if decodeErr != nil || len(public) != ed25519.PublicKeySize {
			return errors.New("execution signer public key must be 32-byte lowercase hex")
		}
		signer, err = nativeimpl.NewTOSCTLExecutionSigner(nativeimpl.TOSCTLExecutionSignerConfig{
			BinaryPath: value.tosctlBinary, ConfigPath: value.tosctlConfig, WalletName: value.executionSignerWallet,
			ExpectedPublicKey: ed25519.PublicKey(public), Timeout: time.Minute,
		})
	}
	if err != nil {
		return err
	}
	release, err := nativeimpl.NewTOSCTLReleaseSubmitter(nativeimpl.TOSCTLReleaseSubmitterConfig{
		BinaryPath: value.tosctlBinary, ConfigPath: value.tosctlConfig, WalletName: value.tosctlWallet,
		ProviderAddress: value.providerAddress, Timeout: 3 * time.Minute,
	})
	if err != nil {
		return err
	}
	receivers, err := nativeimpl.NewNativeProviderReceivers(nativeimpl.NativeProviderConfig{
		Escrow: escrowResolver, Gate: gate, Runner: runner, Locator: artifactLocator, Signer: signer, Release: release,
	})
	if err != nil {
		return err
	}

	serverConfig := func(address string) adapterhttp.ServerConfig {
		return adapterhttp.ServerConfig{Address: address, CertificateFile: value.certificate, PrivateKeyFile: value.privateKey,
			Boundary:    adapterhttp.BoundaryConfig{BearerToken: bearer, MaxRequestBytes: 16 << 20, MaxConcurrent: 8},
			ReadTimeout: 4 * time.Minute}
	}
	a2aServer, err := a2aadapter.NewPublicServer(receivers.A2A, serverConfig(value.a2aAddress))
	if err != nil {
		return err
	}
	mcpServer, err := mcpadapter.NewPublicServer(receivers.MCP, serverConfig(value.mcpAddress))
	if err != nil {
		return err
	}
	packetHandler := agentpacket.Handler(chainAgentResolver{resolver: nativeResolver}, &agentpacket.ReplayGuard{}, receivers.AgentPacket)
	packetServer, err := adapterhttp.NewServer(packetHandler, serverConfig(value.packetAddress))
	if err != nil {
		return err
	}
	artifactServer, err := adapterhttp.NewServer(artifactLocator.Handler(), serverConfig(value.artifactAddr))
	if err != nil {
		return err
	}
	servers := []*http.Server{a2aServer, mcpServer, packetServer, artifactServer}
	errChannel := make(chan error, len(servers))
	for _, server := range servers {
		go func(server *http.Server) {
			err := adapterhttp.ListenAndServe(server)
			if !errors.Is(err, http.ErrServerClosed) {
				errChannel <- err
			}
		}(server)
	}
	fmt.Printf("READY a2a=%s mcp=%s agent_packet=%s artifact=%s\n", value.a2aAddress, value.mcpAddress, value.packetAddress, value.artifactAddr)
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)
	select {
	case received := <-shutdown:
		fmt.Printf("SHUTDOWN signal=%s\n", received)
	case serverErr := <-errChannel:
		return serverErr
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var combined error
	for _, server := range servers {
		combined = errors.Join(combined, server.Shutdown(ctx))
	}
	return combined
}

type chainAgentResolver struct {
	resolver *toschain.SimplifiedNativeResolver
}

func (r chainAgentResolver) ResolveAgent(id string) (*nativev1.AgentStateV1, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	state, found, _, err := r.resolver.ResolveFinalizedState(ctx, id, "")
	if err != nil || !found || state == nil {
		return nil, found, err
	}
	agent := state.GetAgent()
	return agent, agent != nil, nil
}

func readBase64File(path string, maximum int64) (string, error) {
	value, err := os.ReadFile(path)
	if err != nil || len(value) == 0 || int64(len(value)) > maximum {
		return "", errors.New("read bounded Registry code BOC")
	}
	compact := strings.Join(strings.Fields(string(value)), "")
	if _, err := base64.StdEncoding.DecodeString(compact); err != nil {
		return "", errors.New("Registry code BOC is not base64")
	}
	return compact, nil
}

func readPrivateSeed(path string) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("execution signer seed path must be canonical and absolute")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		return nil, errors.New("execution signer seed must be a private regular file")
	}
	value, err := os.ReadFile(path)
	if err != nil || len(value) != ed25519.SeedSize {
		return nil, errors.New("execution signer seed must contain exactly 32 bytes")
	}
	return value, nil
}

func readPrivateBearer(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", errors.New("bearer token file path must be canonical and absolute")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		return "", errors.New("bearer token must be a private regular file")
	}
	value, err := os.ReadFile(path)
	if err != nil || len(value) == 0 || len(value) > 4096 {
		return "", errors.New("read bounded bearer token")
	}
	token := strings.TrimSpace(string(value))
	if len(token) < 32 || len(token) > 4096 || strings.ContainsAny(token, " \t\r\n") {
		return "", errors.New("bearer token must be one non-whitespace value of at least 32 bytes")
	}
	return token, nil
}

func requirePrivateDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("provider state directory must be canonical and absolute")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errors.New("provider state directory must be private")
	}
	return nil
}
