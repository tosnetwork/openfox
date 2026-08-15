package nativeimpl

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/tosnetwork/openfox/pkg/atosbridge"
	"github.com/tosnetwork/tos-ai/pkg/agentpacketadapter"
	"github.com/tosnetwork/tos-protocol/pkg/agentpacket"
)

// packetPoster delivers a signed packet to the provider endpoint. agentpacket.Post
// is the production poster; injecting it makes dispatch unit-testable without a
// live receiver.
type packetPoster func(context.Context, *http.Client, string, agentpacket.Packet) error

// AgentPacketTaskTransport dispatches a purchase-bound Task to a provider as a
// signed Agent Packet. The packet is a transport envelope only: the provider's
// adapter still claims the purchase through the finalized Gate before running
// it, and the escrow release is confirmed by the buyer's own finalized read.
type AgentPacketTaskTransport struct {
	sender, recipient, capabilityID string
	key                             ed25519.PrivateKey
	endpoint                        string
	client                          *http.Client
	sequence                        func() uint64
	now                             func() time.Time
	post                            packetPoster
}

// AgentPacketTransportConfig configures the buyer's Agent Packet dispatch.
type AgentPacketTransportConfig struct {
	SenderAgentID    string
	RecipientAgentID string
	CapabilityID     string
	SigningKey       ed25519.PrivateKey
	Endpoint         string
	Client           *http.Client
}

// NewAgentPacketTaskTransport validates the configuration and returns a transport.
func NewAgentPacketTaskTransport(c AgentPacketTransportConfig) (*AgentPacketTaskTransport, error) {
	if c.SenderAgentID == "" || c.RecipientAgentID == "" || c.SenderAgentID == c.RecipientAgentID ||
		c.CapabilityID == "" || len(c.SigningKey) != ed25519.PrivateKeySize || c.Client == nil || !validPacketEndpoint(c.Endpoint) {
		return nil, errors.New("nativeimpl: invalid Agent Packet transport configuration")
	}
	var counter uint64
	return &AgentPacketTaskTransport{
		sender: c.SenderAgentID, recipient: c.RecipientAgentID, capabilityID: c.CapabilityID,
		key: append(ed25519.PrivateKey(nil), c.SigningKey...), endpoint: c.Endpoint, client: c.Client,
		sequence: func() uint64 { return atomic.AddUint64(&counter, 1) },
		now:      func() time.Time { return time.Now().UTC() },
		post:     agentpacket.Post,
	}, nil
}

// Dispatch delivers the bound Task as a signed Agent Packet. It handles only
// TransportAgentPacket and fails closed on any other transport or an
// insufficiently bound task before signing or sending anything.
func (t *AgentPacketTaskTransport) Dispatch(ctx context.Context, transport atosbridge.Transport, task atosbridge.Task) error {
	if transport != atosbridge.TransportAgentPacket {
		return errors.New("nativeimpl: Agent Packet transport was asked to dispatch a non-packet transport")
	}
	if task.EscrowAddress == "" || task.QuoteCommitment == "" || task.ExecutionID == "" ||
		task.InputDigest == "" || len(task.SourceArchive) == 0 {
		return errors.New("nativeimpl: Agent Packet dispatch needs a fully bound task (escrow, quote, execution, input, source)")
	}
	sourceHash := sha256.Sum256(task.SourceArchive)
	payload, err := json.Marshal(agentPacketWorkPayload{
		Schema:              agentpacketadapter.PayloadSchema,
		EscrowAddress:       task.EscrowAddress,
		QuoteCommitment:     task.QuoteCommitment,
		ExecutionID:         task.ExecutionID,
		InputDigest:         task.InputDigest,
		SourceDigest:        "sha256:" + hex.EncodeToString(sourceHash[:]),
		SourceArchiveBase64: base64.StdEncoding.EncodeToString(task.SourceArchive),
	})
	if err != nil {
		return err
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return errors.New("nativeimpl: could not generate a packet nonce")
	}
	packet := agentpacket.Packet{
		SenderAgentID: t.sender, RecipientAgentID: t.recipient, CapabilityID: t.capabilityID,
		QuoteCommitment: task.QuoteCommitment, Sequence: t.sequence(), Nonce: nonce,
		Payload: payload, CreatedAtUnix: uint64(t.now().Unix()),
	}
	signed, err := agentpacket.Sign(packet, t.key)
	if err != nil {
		return err
	}
	return t.post(ctx, t.client, t.endpoint, signed)
}

var _ atosbridge.TaskTransport = (*AgentPacketTaskTransport)(nil)

// agentPacketWorkPayload mirrors the agentpacketadapter work payload wire shape.
type agentPacketWorkPayload struct {
	Schema              string `json:"schema"`
	EscrowAddress       string `json:"escrow_address"`
	QuoteCommitment     string `json:"quote_commitment"`
	ExecutionID         string `json:"execution_id"`
	InputDigest         string `json:"input_digest"`
	SourceDigest        string `json:"source_digest"`
	SourceArchiveBase64 string `json:"source_archive_base64"`
}

func validPacketEndpoint(endpoint string) bool {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed == nil || parsed.User != nil || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	if parsed.Scheme == "https" {
		return true
	}
	return parsed.Scheme == "http" && (parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "localhost" || parsed.Hostname() == "::1")
}
