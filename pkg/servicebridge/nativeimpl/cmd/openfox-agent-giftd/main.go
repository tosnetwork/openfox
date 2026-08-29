// Command openfox-agent-giftd assembles the production Agent Gift runtime.
// The model and owner runtime receive separate private Unix sockets; all
// messaging, custody, chain reads, broadcast, and owner confirmation remain
// outside the model process.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	openfoxgift "github.com/tosnetwork/openfox/pkg/agentgift"
	nativeimpl "github.com/tosnetwork/openfox/pkg/servicebridge/nativeimpl"
	"github.com/tosnetwork/tos-messenger/pkg/localapi"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/chainactionpublisher"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativeclient"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
)

const configSchema = "tos.openfox.agent-giftd-config.v1"

type config struct {
	Schema                 string                                   `json:"schema"`
	LocalAgentID           string                                   `json:"local_agent_id"`
	Network                *nativev1.NetworkDomain                  `json:"network"`
	GlobalID               int32                                    `json:"global_id"`
	ChainEndpoints         []string                                 `json:"chain_endpoints"`
	ChainQuorum            int                                      `json:"chain_quorum"`
	NativeGateway          nativeGatewayConfig                      `json:"native_gateway"`
	TOSCTLCustody          nativeimpl.TOSCTLGiftCustodyConfig       `json:"tosctl_custody"`
	Publisher              chainactionpublisher.TosctlBackendConfig `json:"publisher"`
	MessengerSocket        string                                   `json:"messenger_socket"`
	JournalDirectory       string                                   `json:"journal_directory"`
	ModelSocket            string                                   `json:"model_socket"`
	RuntimeSocket          string                                   `json:"runtime_socket"`
	RecipientAddress       string                                   `json:"recipient_address"`
	FeeReserveAtomic       uint64                                   `json:"fee_reserve_atomic"`
	MinimumInclusionMargin uint32                                   `json:"minimum_inclusion_margin_seconds"`
	ResponseLifetimeSecs   uint32                                   `json:"response_lifetime_seconds"`
}

type nativeGatewayConfig struct {
	BaseURL        string `json:"base_url"`
	BearerToken    string `json:"bearer_token"`
	Insecure       bool   `json:"insecure"`
	ServerName     string `json:"server_name,omitempty"`
	CAFile         string `json:"ca_file,omitempty"`
	ClientCertFile string `json:"client_cert_file,omitempty"`
	ClientKeyFile  string `json:"client_key_file,omitempty"`
}

func main() {
	path := flag.String("config", "", "absolute owner-private Agent Gift daemon configuration")
	flag.Parse()
	if flag.NArg() != 0 || *path == "" {
		fmt.Fprintln(os.Stderr, "openfox-agent-giftd: --config is required")
		os.Exit(2)
	}
	if err := run(*path); err != nil {
		fmt.Fprintln(os.Stderr, "openfox-agent-giftd:", err)
		os.Exit(1)
	}
}

func run(path string) error {
	value, err := loadConfig(path)
	if err != nil {
		return err
	}
	chain, err := toschain.New(toschain.Config{Network: value.Network.NetworkId, Endpoints: value.ChainEndpoints, Quorum: value.ChainQuorum})
	if err != nil {
		return err
	}
	reader, err := toschain.NewAgentGiftReader(chain, value.Network)
	if err != nil {
		return err
	}
	finalized, err := nativeimpl.NewAgentGiftChainAdapter(reader)
	if err != nil {
		return err
	}
	gateway, err := nativeclient.New(nativeclient.Config{BaseURL: value.NativeGateway.BaseURL, BearerToken: value.NativeGateway.BearerToken, Insecure: value.NativeGateway.Insecure, ServerName: value.NativeGateway.ServerName, CAFile: value.NativeGateway.CAFile, ClientCertFile: value.NativeGateway.ClientCertFile, ClientKeyFile: value.NativeGateway.ClientKeyFile})
	if err != nil {
		return err
	}
	defer gateway.Close()
	recipientAuthority, err := nativeimpl.NewAgentGiftDNSRecipientAuthority(gateway, value.Network, "openfox-agent-giftd")
	if err != nil {
		return err
	}
	resolver, err := nativeimpl.NewAgentGiftResolver(finalized, recipientAuthority)
	if err != nil {
		return err
	}
	protocol, err := nativeimpl.NewAgentGiftProtocol(finalized, value.FeeReserveAtomic, value.MinimumInclusionMargin)
	if err != nil {
		return err
	}
	value.TOSCTLCustody.FeeReserveAtomic = value.FeeReserveAtomic
	value.TOSCTLCustody.MinimumInclusionMargin = value.MinimumInclusionMargin
	custody, err := nativeimpl.NewTOSCTLGiftCustody(value.TOSCTLCustody, finalized)
	if err != nil {
		return err
	}
	messengerClient, err := localapi.NewClient(value.MessengerSocket, localapi.DefaultClientTimeout)
	if err != nil {
		return err
	}
	messenger, err := nativeimpl.NewAgentGiftMessenger(messengerClient, 24*time.Hour)
	if err != nil {
		return err
	}
	publisher, err := chainactionpublisher.NewTosctlBackend(value.Publisher)
	if err != nil {
		return err
	}
	broadcaster, err := nativeimpl.NewAgentGiftBroadcaster(publisher)
	if err != nil {
		return err
	}
	addresses, err := nativeimpl.NewStaticAgentGiftAddressAuthority(value.RecipientAddress)
	if err != nil {
		return err
	}
	owner, err := nativeimpl.NewAgentGiftOwnerAuthorizer(nativeimpl.NewTTYAgentGiftOwnerConfirmer())
	if err != nil {
		return err
	}
	journal, err := openfoxgift.OpenJournal(value.JournalDirectory)
	if err != nil {
		return err
	}
	defer journal.Close()
	service, err := openfoxgift.NewService(journal, protocol, resolver, messenger, custody, broadcaster, addresses, owner)
	if err != nil {
		return err
	}
	modelServer, err := openfoxgift.NewLocalServer(service, openfoxgift.LocalPrincipalModel, value.Network.NetworkId, value.GlobalID, value.LocalAgentID)
	if err != nil {
		return err
	}
	runtimeServer, err := openfoxgift.NewLocalServer(service, openfoxgift.LocalPrincipalRuntime, value.Network.NetworkId, value.GlobalID, value.LocalAgentID)
	if err != nil {
		return err
	}
	modelListener, err := openfoxgift.ListenLocalUnix(value.ModelSocket)
	if err != nil {
		return err
	}
	defer modelListener.Close()
	runtimeListener, err := openfoxgift.ListenLocalUnix(value.RuntimeSocket)
	if err != nil {
		return err
	}
	defer runtimeListener.Close()
	runtime, err := nativeimpl.NewAgentGiftRuntime(service, messengerClient, nativeimpl.AgentGiftRuntimeConfig{LocalAgentID: value.LocalAgentID, Network: value.Network.NetworkId, GlobalID: value.GlobalID, ResponseLifetime: time.Duration(value.ResponseLifetimeSecs) * time.Second})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return runGiftComponents(ctx, stop,
		func(ctx context.Context) error { return modelServer.Serve(ctx, modelListener) },
		func(ctx context.Context) error { return runtimeServer.Serve(ctx, runtimeListener) },
		func(ctx context.Context) error { return runtime.Run(ctx) },
	)
}

func runGiftComponents(ctx context.Context, cancel context.CancelFunc, runners ...func(context.Context) error) error {
	if ctx == nil || cancel == nil || len(runners) == 0 {
		return errors.New("invalid Agent Gift component group")
	}
	for _, runner := range runners {
		if runner == nil {
			cancel()
			return errors.New("invalid Agent Gift component runner")
		}
	}
	errorsCh := make(chan error, len(runners))
	for _, runner := range runners {
		go func(run func(context.Context) error) { errorsCh <- run(ctx) }(runner)
	}
	results := make([]error, 0, len(runners))
	results = append(results, <-errorsCh)
	cancel()
	for len(results) < len(runners) {
		results = append(results, <-errorsCh)
	}
	return errors.Join(results...)
}

func loadConfig(path string) (config, error) {
	var value config
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return value, errors.New("configuration path must be clean and absolute")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > 2<<20 {
		return value, errors.New("configuration must be a bounded owner-private regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return value, errors.New("configuration owner mismatch")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return value, errors.New("read Agent Gift daemon configuration")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return value, errors.New("decode Agent Gift daemon configuration")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return value, errors.New("trailing Agent Gift daemon configuration")
	}
	if value.Schema != configSchema || value.Network == nil || value.Network.NetworkId == "" || value.Network.GenesisRootHash == "" || value.Network.GenesisFileHash == "" || value.GlobalID == 0 || value.LocalAgentID == "" || len(value.ChainEndpoints) < 3 || value.ChainQuorum <= len(value.ChainEndpoints)/2 || value.NativeGateway.BaseURL == "" || value.NativeGateway.BearerToken == "" || value.TOSCTLCustody.BinaryPath == "" || value.TOSCTLCustody.ConfigPath == "" || value.TOSCTLCustody.VaultURL == "" || value.TOSCTLCustody.WalletName == "" || value.TOSCTLCustody.OwnerWallet == "" || value.TOSCTLCustody.ControllerKeyID == "" || len(value.TOSCTLCustody.QuorumConfigPaths) < 2 || value.Publisher.Network != value.Network.NetworkId || value.Publisher.GenesisRootHash != value.Network.GenesisRootHash || value.Publisher.GenesisFileHash != value.Network.GenesisFileHash || value.Publisher.Binary != value.TOSCTLCustody.BinaryPath || value.Publisher.ConfigPath != value.TOSCTLCustody.ConfigPath || value.Publisher.VaultURL != value.TOSCTLCustody.VaultURL || value.Publisher.RPCURL == "" || value.Publisher.WalletName == "" || value.Publisher.Payer != value.TOSCTLCustody.OwnerWallet || value.TOSCTLCustody.FeeReserveAtomic != 0 && value.TOSCTLCustody.FeeReserveAtomic != value.FeeReserveAtomic || value.TOSCTLCustody.MinimumInclusionMargin != 0 && value.TOSCTLCustody.MinimumInclusionMargin != value.MinimumInclusionMargin || value.MessengerSocket == "" || value.JournalDirectory == "" || value.ModelSocket == "" || value.RuntimeSocket == "" || value.ModelSocket == value.RuntimeSocket || value.RecipientAddress == "" || value.FeeReserveAtomic == 0 || value.MinimumInclusionMargin == 0 || value.ResponseLifetimeSecs < 60 || value.ResponseLifetimeSecs > 86400 {
		return value, errors.New("incomplete Agent Gift daemon configuration")
	}
	return value, nil
}
