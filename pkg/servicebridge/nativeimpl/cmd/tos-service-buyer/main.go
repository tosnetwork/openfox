// Command tos-service-buyer dispatches an already-funded local test task to the
// real provider over A2A or MCP. Quote construction and funding deliberately
// stay outside this command so a transport can never be mistaken for payment.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2aclient"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/tosnetwork/openfox/pkg/servicebridge"
	nativeimpl "github.com/tosnetwork/openfox/pkg/servicebridge/nativeimpl"
)

type fundedTask struct {
	Schema          string `json:"schema"`
	EscrowAddress   string `json:"escrow_address"`
	QuoteCommitment string `json:"quote_commitment"`
	ExecutionID     string `json:"execution_id"`
	InputDigest     string `json:"input_digest"`
	SourceDigest    string `json:"source_digest"`
	SourceArchive   string `json:"source_archive"`
}

type bearerRoundTripper struct {
	base  http.RoundTripper
	token string
}

func (t bearerRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	clone.Header.Set("Authorization", "Bearer "+t.token)
	return t.base.RoundTrip(clone)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	var transportName, endpoint, taskPath, caPath, tokenPath, evidencePath string
	var senderAgent, recipientAgent, capabilityID, signingSeedPath string
	flag.StringVar(&transportName, "transport", "", "a2a, mcp, or agent_packet")
	flag.StringVar(&endpoint, "endpoint", "", "provider HTTPS endpoint")
	flag.StringVar(&taskPath, "task", "", "funded task JSON")
	flag.StringVar(&caPath, "ca", "", "private local CA certificate PEM")
	flag.StringVar(&tokenPath, "bearer-token-file", "", "private bearer token file")
	flag.StringVar(&evidencePath, "evidence", "", "output dispatch evidence JSON")
	flag.StringVar(&senderAgent, "sender-agent-id", "", "live sender Native Agent ID")
	flag.StringVar(&recipientAgent, "recipient-agent-id", "", "provider Native Agent ID")
	flag.StringVar(&capabilityID, "capability-id", "", "target Native Capability ID")
	flag.StringVar(&signingSeedPath, "agent-signing-seed", "", "raw 32-byte Agent Packet signing seed")
	flag.Parse()
	if endpoint == "" || taskPath == "" || caPath == "" || tokenPath == "" || evidencePath == "" {
		return errors.New("buyer configuration is incomplete")
	}

	var document fundedTask
	encoded, err := os.ReadFile(taskPath)
	if err != nil || json.Unmarshal(encoded, &document) != nil || document.Schema != "tos.service.local-funded-task.v1" {
		return errors.New("read funded task")
	}
	archive, err := os.ReadFile(document.SourceArchive)
	if err != nil || len(archive) == 0 {
		return errors.New("read source archive")
	}
	hash := sha256.Sum256(archive)
	if "sha256:"+hex.EncodeToString(hash[:]) != document.SourceDigest {
		return errors.New("source archive digest mismatch")
	}
	task := servicebridge.Task{EscrowAddress: document.EscrowAddress, QuoteCommitment: document.QuoteCommitment,
		ExecutionID: document.ExecutionID, InputDigest: document.InputDigest, SourceDigest: document.SourceDigest,
		SourceArchive: archive}

	ca, err := os.ReadFile(caPath)
	if err != nil {
		return errors.New("read local CA")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return errors.New("parse local CA")
	}
	token, err := os.ReadFile(tokenPath)
	if err != nil || len(strings.TrimSpace(string(token))) < 32 {
		return errors.New("read bearer token")
	}
	client := &http.Client{Transport: bearerRoundTripper{token: strings.TrimSpace(string(token)), base: &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}}}}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	var dispatch servicebridge.TaskTransport
	var closeSession func() error
	switch transportName {
	case "a2a":
		wire := a2aclient.NewJSONRPCTransport(endpoint, client)
		defer wire.Destroy()
		dispatch, err = nativeimpl.NewA2ATaskTransport(wire)
	case "mcp":
		mcpClient := mcp.NewClient(&mcp.Implementation{Name: "tos-service-local-buyer", Version: "1.0.0"}, nil)
		var session *mcp.ClientSession
		session, err = mcpClient.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: endpoint, HTTPClient: client,
			DisableStandaloneSSE: true, MaxRetries: -1}, nil)
		if err == nil {
			dispatch, err = nativeimpl.NewMCPTaskTransport(session)
			closeSession = session.Close
		}
	case "agent_packet":
		seed, readErr := os.ReadFile(signingSeedPath)
		if readErr != nil || len(seed) != ed25519.SeedSize {
			return errors.New("read Agent Packet signing seed")
		}
		dispatch, err = nativeimpl.NewAgentPacketTaskTransport(nativeimpl.AgentPacketTransportConfig{
			SenderAgentID: senderAgent, RecipientAgentID: recipientAgent, CapabilityID: capabilityID,
			SigningKey: ed25519.NewKeyFromSeed(seed), Endpoint: endpoint, Client: client,
		})
		for index := range seed {
			seed[index] = 0
		}
	default:
		return errors.New("transport must be a2a, mcp, or agent_packet")
	}
	if err != nil {
		return err
	}
	if closeSession != nil {
		defer closeSession()
	}
	transport := servicebridge.Transport(transportName)
	if err := dispatch.Dispatch(ctx, transport, task); err != nil {
		return err
	}

	evidence := struct {
		Schema          string `json:"schema"`
		Verdict         string `json:"verdict"`
		Transport       string `json:"transport"`
		EscrowAddress   string `json:"escrow_address"`
		QuoteCommitment string `json:"quote_commitment"`
		ExecutionID     string `json:"execution_id"`
		SourceDigest    string `json:"source_digest"`
		CompletedAtUnix int64  `json:"completed_at_unix"`
	}{"tos.service.local-provider-dispatch.v1", "PASS_REAL_PROVIDER_DISPATCH", transportName,
		document.EscrowAddress, document.QuoteCommitment, document.ExecutionID, document.SourceDigest, time.Now().Unix()}
	body, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(evidencePath, append(body, '\n'), 0o600); err != nil {
		return err
	}
	fmt.Printf("PASS real provider dispatch transport=%s evidence=%s\n", transportName, evidencePath)
	return nil
}
