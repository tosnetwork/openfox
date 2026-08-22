package nativeimpl

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2aclient"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/tosnetwork/tos-service-protocol/pkg/buyersdk"

	"github.com/tosnetwork/openfox/pkg/servicebridge"
)

type StaticDispatchPlannerConfig struct {
	Transport         servicebridge.Transport
	SourceArchivePath string
	SourceDigest      string
	InputDigest       string
	CAFile            string
	BearerTokenFile   string
	SenderAgentID     string
	AgentSigningSeed  string
	RequestTimeout    time.Duration
}

// StaticDispatchPlanner binds autonomous work to an operator-reviewed source
// archive and input digest. The model cannot change the transport, endpoint,
// source, execution ID, credentials, or provider identity.
type StaticDispatchPlanner struct {
	config StaticDispatchPlannerConfig
	source []byte
}

func NewStaticDispatchPlanner(config StaticDispatchPlannerConfig) (*StaticDispatchPlanner, error) {
	if config.Transport != servicebridge.TransportA2A && config.Transport != servicebridge.TransportMCP &&
		config.Transport != servicebridge.TransportAgentPacket {
		return nil, errors.New("nativeimpl: unsupported autonomous task transport")
	}
	if !hexDigest(config.SourceDigest, "sha256:") || !hexDigest(config.InputDigest, "sha256:") {
		return nil, errors.New("nativeimpl: autonomous task digests are invalid")
	}
	source, err := readReviewedBytes(config.SourceArchivePath, 64<<20)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(source)
	if config.SourceDigest != "sha256:"+hex.EncodeToString(digest[:]) {
		return nil, errors.New("nativeimpl: autonomous source archive digest mismatch")
	}
	if config.RequestTimeout == 0 {
		config.RequestTimeout = 10 * time.Minute
	}
	if config.RequestTimeout < time.Second || config.RequestTimeout > 30*time.Minute {
		return nil, errors.New("nativeimpl: autonomous dispatch timeout is invalid")
	}
	if config.Transport == servicebridge.TransportAgentPacket {
		if config.SenderAgentID == "" || !secureConfigFile(config.AgentSigningSeed) {
			return nil, errors.New("nativeimpl: Agent Packet dispatch requires a sender and private signing seed")
		}
	}
	return &StaticDispatchPlanner{config: config, source: append([]byte(nil), source...)}, nil
}

func (p *StaticDispatchPlanner) Plan(ctx context.Context, purchase *buyersdk.PreparedPurchase) (DispatchPlan, error) {
	if p == nil || ctx == nil || purchase == nil || purchase.Proposal == nil {
		return DispatchPlan{}, errors.New("nativeimpl: invalid autonomous dispatch plan request")
	}
	input, err := PurchaseInputFromPreparedPurchase(purchase)
	if err != nil || input.TransportBinding.BaseURL == "" ||
		(input.TransportBinding.MaxRequestBytes > 0 && uint64(len(p.source)) > uint64(input.TransportBinding.MaxRequestBytes)) {
		return DispatchPlan{}, errors.New("nativeimpl: task conflicts with Quote transport binding")
	}
	client, err := NewPinnedProviderHTTPClient(input.TransportBinding.BaseURL, p.config.CAFile, p.config.BearerTokenFile, p.config.RequestTimeout)
	if err != nil {
		return DispatchPlan{}, err
	}
	var sender servicebridge.TaskTransport
	var closeFn func() error
	switch p.config.Transport {
	case servicebridge.TransportA2A:
		wire := a2aclient.NewJSONRPCTransport(input.TransportBinding.BaseURL, client)
		sender, err = NewA2ATaskTransport(wire)
		closeFn = func() error { wire.Destroy(); client.CloseIdleConnections(); return nil }
	case servicebridge.TransportMCP:
		mcpClient := mcp.NewClient(&mcp.Implementation{Name: "tos-openfox-autonomous-buyer", Version: "1.0.0"}, nil)
		var session *mcp.ClientSession
		session, err = mcpClient.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: input.TransportBinding.BaseURL,
			HTTPClient: client, DisableStandaloneSSE: true, MaxRetries: -1}, nil)
		if err == nil {
			sender, err = NewMCPTaskTransport(session)
			closeFn = func() error { client.CloseIdleConnections(); return session.Close() }
		}
	case servicebridge.TransportAgentPacket:
		var seed []byte
		seed, err = readPrivateBytes(p.config.AgentSigningSeed, ed25519.SeedSize)
		if err == nil && len(seed) != ed25519.SeedSize {
			err = errors.New("nativeimpl: invalid Agent Packet signing seed")
		}
		if err == nil {
			key := ed25519.NewKeyFromSeed(seed)
			for index := range seed {
				seed[index] = 0
			}
			sender, err = NewAgentPacketTaskTransport(AgentPacketTransportConfig{SenderAgentID: p.config.SenderAgentID,
				RecipientAgentID: purchase.Proposal.GetProviderAgentId(), CapabilityID: purchase.Proposal.GetCapabilityId(),
				SigningKey: key, Endpoint: input.TransportBinding.BaseURL, Client: client})
			closeFn = func() error { client.CloseIdleConnections(); return nil }
		}
	}
	if err != nil {
		client.CloseIdleConnections()
		return DispatchPlan{}, err
	}
	executionHash := sha256.Sum256([]byte("tos.openfox.autonomous-execution.v1\x00" + purchase.QuoteCommitment + "\x00" +
		p.config.InputDigest + "\x00" + p.config.SourceDigest))
	executionID := "exec_" + hex.EncodeToString(executionHash[:])
	source := append([]byte(nil), p.source...)
	build := func(accepted servicebridge.AcceptedQuote) (servicebridge.Task, error) {
		if accepted.QuoteCommitment != purchase.QuoteCommitment || accepted.EscrowAddress != purchase.Escrow.Address {
			return servicebridge.Task{}, errors.New("nativeimpl: autonomous task conflicts with Accepted Quote")
		}
		return servicebridge.Task{EscrowAddress: accepted.EscrowAddress, QuoteCommitment: accepted.QuoteCommitment,
			ExecutionID: executionID, InputDigest: p.config.InputDigest, SourceDigest: p.config.SourceDigest,
			SourceArchive: append([]byte(nil), source...)}, nil
	}
	return DispatchPlan{Transport: p.config.Transport, Sender: sender, BuildTask: build, Close: closeFn}, nil
}

func NewPinnedProviderHTTPClient(endpoint, caPath, tokenPath string, timeout time.Duration) (*http.Client, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		(parsed.Scheme != "https" && parsed.Scheme != "http") {
		return nil, errors.New("nativeimpl: invalid provider endpoint")
	}
	if parsed.Scheme == "http" && !isLoopback(strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")) {
		return nil, errors.New("nativeimpl: plaintext provider endpoint must be loopback")
	}
	token, err := readPrivateBytes(tokenPath, 16<<10)
	if err != nil {
		return nil, errors.New("nativeimpl: read provider bearer token")
	}
	credential := strings.TrimSpace(string(token))
	if len(credential) < 32 || strings.ContainsAny(credential, " \t\r\n") {
		return nil, errors.New("nativeimpl: provider bearer token is invalid")
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: timeout}).DialContext,
		TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout, DisableCompression: true}
	if parsed.Scheme == "https" {
		ca, err := readReviewedBytes(caPath, 1<<20)
		if err != nil {
			return nil, err
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(ca) {
			return nil, errors.New("nativeimpl: parse provider CA")
		}
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}
	}
	return &http.Client{Transport: providerBearerTransport{token: credential, base: transport}, Timeout: timeout}, nil
}

type providerBearerTransport struct {
	token string
	base  http.RoundTripper
}

func (t providerBearerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	owned := request.Clone(request.Context())
	owned.Header = request.Header.Clone()
	owned.Header.Set("Authorization", "Bearer "+t.token)
	return t.base.RoundTrip(owned)
}

func readPrivateBytes(path string, maximum int64) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("nativeimpl: private input path must be clean and absolute")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 ||
		info.Size() <= 0 || info.Size() > maximum {
		return nil, errors.New("nativeimpl: private input must be a bounded owner-only regular file")
	}
	return os.ReadFile(path)
}

func readReviewedBytes(path string, maximum int64) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("nativeimpl: reviewed input path must be clean and absolute")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 ||
		info.Size() <= 0 || info.Size() > maximum {
		return nil, errors.New("nativeimpl: reviewed input must be a bounded non-writable regular file")
	}
	return os.ReadFile(path)
}

var _ DispatchPlanner = (*StaticDispatchPlanner)(nil)
