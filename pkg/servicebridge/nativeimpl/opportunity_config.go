package nativeimpl

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/buyersdk"
	"github.com/tosnetwork/tos-service-protocol/pkg/gatewayfederation"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativeclient"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"

	"github.com/tosnetwork/openfox/pkg/messengerauth"
	"github.com/tosnetwork/openfox/pkg/servicebridge"
)

const opportunityCoordinatorConfigSchema = "tos.openfox.opportunity-coordinator-config.v1"

type opportunityCoordinatorDocument struct {
	Schema                       string                     `json:"schema"`
	StateDir                     string                     `json:"state_dir"`
	SocketPath                   string                     `json:"socket_path"`
	Network                      *nativev1.NetworkDomain    `json:"network"`
	ChainEndpoints               []string                   `json:"chain_endpoints"`
	ChainQuorum                  int                        `json:"chain_quorum"`
	RegistryCodeBOCPath          string                     `json:"registry_code_boc_path"`
	RegistryCodeHash             string                     `json:"registry_code_hash"`
	CallerID                     string                     `json:"caller_id"`
	RequestTimeoutSeconds        uint64                     `json:"request_timeout_seconds"`
	MaxResults                   int                        `json:"max_results"`
	CredentialQuotaEnforced      bool                       `json:"credential_quota_enforced"`
	CheckpointCacheMaxAgeSeconds uint64                     `json:"checkpoint_cache_max_age_seconds,omitempty"`
	Gateways                     []opportunityGatewayConfig `json:"gateways"`
	Purchase                     *opportunityPurchaseConfig `json:"purchase,omitempty"`
}

type opportunityPurchaseConfig struct {
	StateDir                    string `json:"state_dir"`
	ChainBuyerConfig            string `json:"chain_buyer_config"`
	SpendingPolicy              string `json:"spending_policy"`
	MessengerSocket             string `json:"messenger_socket"`
	MandateID                   string `json:"mandate_id"`
	CapabilityClass             string `json:"capability_class"`
	BuyerAddress                string `json:"buyer_address"`
	ExecutionSignerPublicKeyHex string `json:"execution_signer_public_key_hex"`
	Transport                   string `json:"transport"`
	SourceArchive               string `json:"source_archive"`
	SourceDigest                string `json:"source_digest"`
	InputDigest                 string `json:"input_digest"`
	ProviderCA                  string `json:"provider_ca,omitempty"`
	ProviderBearerToken         string `json:"provider_bearer_token"`
	SenderAgentID               string `json:"sender_agent_id,omitempty"`
	AgentSigningSeed            string `json:"agent_signing_seed,omitempty"`
	RequestTimeoutSeconds       uint64 `json:"request_timeout_seconds"`
}

type opportunityGatewayConfig struct {
	ID               string `json:"id"`
	BaseURL          string `json:"base_url"`
	BearerTokenFile  string `json:"bearer_token_file"`
	InsecureLoopback bool   `json:"insecure_loopback,omitempty"`
	ServerName       string `json:"server_name,omitempty"`
	CAFile           string `json:"ca_file,omitempty"`
	ClientCertFile   string `json:"client_cert_file,omitempty"`
	ClientKeyFile    string `json:"client_key_file,omitempty"`
}

type OpportunityCoordinatorResources struct {
	Coordinator *OpportunityCoordinator
	Purchases   *PurchaseCoordinator
	SocketPath  string
}

func LoadOpportunityCoordinator(path string) (*OpportunityCoordinatorResources, error) {
	if !secureConfigFile(path) {
		return nil, errors.New("nativeimpl: opportunity coordinator config must be an owner-private absolute regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 || len(raw) > 1<<20 {
		return nil, errors.New("nativeimpl: read opportunity coordinator config")
	}
	var document opportunityCoordinatorDocument
	if decodeStrictJSON(raw, &document) != nil || document.Schema != opportunityCoordinatorConfigSchema ||
		document.Network == nil || !ownerDirectory(document.StateDir) || !cleanSocket(document.SocketPath) ||
		len(document.ChainEndpoints) < 3 || len(document.ChainEndpoints) > 8 ||
		document.ChainQuorum <= len(document.ChainEndpoints)/2 || document.ChainQuorum > len(document.ChainEndpoints) ||
		document.CallerID == "" || len(document.CallerID) > 128 || document.RequestTimeoutSeconds == 0 ||
		document.RequestTimeoutSeconds > 60 || document.MaxResults <= 0 || document.MaxResults > 3200 ||
		len(document.Gateways) < 2 || len(document.Gateways) > 8 ||
		(!document.CredentialQuotaEnforced && document.CheckpointCacheMaxAgeSeconds == 0) ||
		document.CheckpointCacheMaxAgeSeconds > 24*60*60 {
		return nil, errors.New("nativeimpl: invalid opportunity coordinator config")
	}
	registryCode, registryBOC, err := readReviewedCode(document.RegistryCodeBOCPath)
	if err != nil || cellHashDigest(registryCode) != document.RegistryCodeHash {
		return nil, errors.New("nativeimpl: opportunity Registry code does not match reviewed hash")
	}
	chain, err := toschain.New(toschain.Config{Network: document.Network.NetworkId,
		Endpoints: document.ChainEndpoints, Quorum: document.ChainQuorum})
	if err != nil {
		return nil, err
	}
	locator, err := nativecore.NewLocator(document.Network, 0, registryBOC, document.RegistryCodeHash)
	if err != nil {
		return nil, err
	}
	resolver, err := toschain.NewSimplifiedNativeResolver(chain, locator, filepath.Join(document.StateDir, "native.checkpoint"))
	if err != nil {
		return nil, err
	}
	direct, err := toschain.NewDirectNativeClient(resolver)
	if err != nil {
		return nil, err
	}
	timeout := time.Duration(document.RequestTimeoutSeconds) * time.Second
	verifier, err := buyersdk.NewCapabilityVerifier(buyersdk.CapabilityVerifierConfig{NativeClient: direct,
		Network: document.Network, RegistryCodeHash: document.RegistryCodeHash, CallerID: document.CallerID, Timeout: timeout})
	if err != nil {
		return nil, err
	}
	gateways, err := assembleOpportunityGateways(document.Gateways, timeout)
	if err != nil {
		return nil, err
	}
	federation, err := gatewayfederation.New(gatewayfederation.Config{Network: document.Network,
		RegistryCodeHash: document.RegistryCodeHash, PerGatewayTimeout: timeout,
		MaxGateways: len(gateways), MaxResults: document.MaxResults})
	if err != nil {
		return nil, err
	}
	coordinator, err := NewOpportunityCoordinator(OpportunityCoordinatorConfig{Federation: federation,
		Gateways: gateways, Verifier: verifier, Network: document.Network,
		RegistryCodeHash: document.RegistryCodeHash, CallerID: document.CallerID})
	if err != nil {
		return nil, err
	}
	var purchases *PurchaseCoordinator
	if document.Purchase != nil {
		purchases, err = assembleOpportunityPurchase(*document.Purchase, document.Network, gateways)
		if err != nil {
			return nil, err
		}
	}
	return &OpportunityCoordinatorResources{Coordinator: coordinator, Purchases: purchases, SocketPath: document.SocketPath}, nil
}

func assembleOpportunityPurchase(config opportunityPurchaseConfig, network *nativev1.NetworkDomain,
	gateways []gatewayfederation.Gateway) (*PurchaseCoordinator, error) {
	if !ownerDirectory(config.StateDir) || config.MandateID == "" || config.CapabilityClass == "" ||
		config.RequestTimeoutSeconds == 0 || config.RequestTimeoutSeconds > 60 {
		return nil, errors.New("nativeimpl: invalid policy-gated opportunity configuration")
	}
	stack, err := LoadChainBuyerStack(config.ChainBuyerConfig)
	if err != nil {
		return nil, err
	}
	policy, owner, err := LoadSignedSpendingPolicy(config.SpendingPolicy)
	if err != nil {
		return nil, err
	}
	messenger, err := messengerauth.NewClient(config.MessengerSocket, time.Duration(config.RequestTimeoutSeconds)*time.Second)
	if err != nil {
		return nil, err
	}
	executionSigner, err := hex.DecodeString(config.ExecutionSignerPublicKeyHex)
	if err != nil || len(executionSigner) != ed25519.PublicKeySize || config.ExecutionSignerPublicKeyHex != strings.ToLower(config.ExecutionSignerPublicKeyHex) {
		return nil, errors.New("nativeimpl: invalid autonomous execution signer public key")
	}
	planner, err := NewStaticDispatchPlanner(StaticDispatchPlannerConfig{Transport: servicebridge.Transport(config.Transport),
		SourceArchivePath: config.SourceArchive, SourceDigest: config.SourceDigest, InputDigest: config.InputDigest,
		CAFile: config.ProviderCA, BearerTokenFile: config.ProviderBearerToken, SenderAgentID: config.SenderAgentID,
		AgentSigningSeed: config.AgentSigningSeed, RequestTimeout: 30 * time.Minute})
	if err != nil {
		return nil, err
	}
	quoteGateways := make([]NamedQuoteGateway, 0, len(gateways))
	for _, gateway := range gateways {
		client, ok := gateway.Client.(QuoteGateway)
		if !ok {
			return nil, errors.New("nativeimpl: configured Gateway cannot request Quote Proposals")
		}
		quoteGateways = append(quoteGateways, NamedQuoteGateway{ID: gateway.ID, Client: client})
	}
	backend, err := NewChainOpportunityPurchaseBackend(ChainOpportunityPurchaseBackendConfig{StateDir: config.StateDir,
		Stack: stack, Network: network, Gateways: quoteGateways, Policy: policy, OwnerPublicKey: owner,
		BuyerAddress: config.BuyerAddress, Messenger: messenger, MandateID: config.MandateID,
		CapabilityClass: config.CapabilityClass, ExecutionSigner: ed25519.PublicKey(executionSigner), Planner: planner,
		QuoteTimeout: time.Duration(config.RequestTimeoutSeconds) * time.Second})
	if err != nil {
		return nil, err
	}
	return OpenPurchaseCoordinator(config.StateDir, backend)
}

func assembleOpportunityGateways(configs []opportunityGatewayConfig, timeout time.Duration) ([]gatewayfederation.Gateway, error) {
	gateways := make([]gatewayfederation.Gateway, 0, len(configs))
	seenURL := map[string]struct{}{}
	previous := ""
	for _, config := range configs {
		if config.ID == "" || len(config.ID) > 128 || config.ID <= previous {
			return nil, errors.New("nativeimpl: opportunity gateways must be sorted and unique")
		}
		previous = config.ID
		parsed, err := url.Parse(config.BaseURL)
		if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" ||
			(parsed.Scheme != "https" && parsed.Scheme != "http") ||
			(parsed.Scheme == "http" && (!config.InsecureLoopback || !isLoopback(parsed.Hostname()))) {
			return nil, errors.New("nativeimpl: invalid opportunity Gateway URL")
		}
		if _, duplicate := seenURL[config.BaseURL]; duplicate {
			return nil, errors.New("nativeimpl: duplicate opportunity Gateway URL")
		}
		seenURL[config.BaseURL] = struct{}{}
		token, err := readPrivateText(config.BearerTokenFile, 16<<10)
		if err != nil {
			return nil, errors.New("nativeimpl: read opportunity Gateway credential")
		}
		client, err := nativeclient.New(nativeclient.Config{BaseURL: config.BaseURL, BearerToken: token, Timeout: timeout,
			MaxMessageBytes: 16 << 20, Insecure: config.InsecureLoopback, ServerName: config.ServerName,
			CAFile: config.CAFile, ClientCertFile: config.ClientCertFile, ClientKeyFile: config.ClientKeyFile})
		if err != nil {
			return nil, err
		}
		gateways = append(gateways, gatewayfederation.Gateway{ID: config.ID, Client: client})
	}
	sort.Slice(gateways, func(i, j int) bool { return gateways[i].ID < gateways[j].ID })
	return gateways, nil
}

func readPrivateText(path string, max int64) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", errors.New("private input path must be clean and absolute")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > max {
		return "", errors.New("private input must be a bounded owner-only regular file")
	}
	raw, err := os.ReadFile(path)
	value := strings.TrimSpace(string(raw))
	if err != nil || value == "" || strings.ContainsAny(value, "\x00\r\n\t ") {
		return "", errors.New("private input is invalid")
	}
	return value, nil
}

func ownerDirectory(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	info, err := os.Lstat(path)
	return err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm() == 0o700
}

func cleanSocket(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && ownerDirectory(filepath.Dir(path))
}

func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
