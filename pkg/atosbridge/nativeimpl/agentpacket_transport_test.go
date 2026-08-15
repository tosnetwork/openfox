package nativeimpl

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/tosnetwork/openfox/pkg/atosbridge"
	"github.com/tosnetwork/tos-ai/pkg/agentpacketadapter"
	"github.com/tosnetwork/tos-protocol/pkg/agentpacket"
)

func newPacketTransport(t *testing.T) (*AgentPacketTaskTransport, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	transport, err := NewAgentPacketTaskTransport(AgentPacketTransportConfig{
		SenderAgentID:    "agent_" + hex64,
		RecipientAgentID: "agent_" + repeatHex("bb"),
		CapabilityID:     "cap_" + hex64,
		SigningKey:       priv,
		Endpoint:         "https://provider.example/packets",
		Client:           &http.Client{},
	})
	if err != nil {
		t.Fatalf("new transport: %v", err)
	}
	return transport, pub
}

func TestAgentPacketTransportSignsAndPosts(t *testing.T) {
	transport, pub := newPacketTransport(t)
	var sent agentpacket.Packet
	posted := false
	transport.post = func(_ context.Context, _ *http.Client, endpoint string, packet agentpacket.Packet) error {
		posted, sent = true, packet
		if endpoint != "https://provider.example/packets" {
			t.Fatalf("wrong endpoint: %s", endpoint)
		}
		return nil
	}

	if err := transport.Dispatch(context.Background(), atosbridge.TransportAgentPacket, sampleTask()); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if !posted {
		t.Fatalf("a packet must have been posted")
	}
	if sent.SenderAgentID != "agent_"+hex64 || sent.RecipientAgentID != "agent_"+repeatHex("bb") ||
		sent.CapabilityID != "cap_"+hex64 || sent.QuoteCommitment != "tvm-cell-sha256:"+hex64 {
		t.Fatalf("packet not bound to the purchase: %+v", sent)
	}
	if len(sent.Signature) != ed25519.SignatureSize || string(sent.SenderPublicKey) != string(pub) {
		t.Fatalf("packet must be signed by the buyer key")
	}
	var payload agentPacketWorkPayload
	if err := json.Unmarshal(sent.Payload, &payload); err != nil {
		t.Fatalf("payload decode: %v", err)
	}
	if payload.Schema != agentpacketadapter.PayloadSchema || payload.EscrowAddress != "0:"+hex64 ||
		payload.QuoteCommitment != "tvm-cell-sha256:"+hex64 || payload.SourceArchiveBase64 == "" {
		t.Fatalf("work payload not bound to the task: %+v", payload)
	}
}

func TestAgentPacketTransportRejectsWrongTransport(t *testing.T) {
	transport, _ := newPacketTransport(t)
	transport.post = func(context.Context, *http.Client, string, agentpacket.Packet) error {
		t.Fatalf("nothing may be posted for the wrong transport")
		return nil
	}
	if err := transport.Dispatch(context.Background(), atosbridge.TransportMCP, sampleTask()); err == nil {
		t.Fatalf("an MCP dispatch must not be sent as an Agent Packet")
	}
}

func TestAgentPacketTransportRejectsUnboundTask(t *testing.T) {
	transport, _ := newPacketTransport(t)
	transport.post = func(context.Context, *http.Client, string, agentpacket.Packet) error {
		t.Fatalf("nothing may be posted for an unbound task")
		return nil
	}
	task := sampleTask()
	task.InputDigest = "" // missing the committed input binding
	if err := transport.Dispatch(context.Background(), atosbridge.TransportAgentPacket, task); err == nil {
		t.Fatalf("a task missing its input digest must fail closed")
	}
}

func TestAgentPacketTransportPropagatesPostError(t *testing.T) {
	transport, _ := newPacketTransport(t)
	transport.post = func(context.Context, *http.Client, string, agentpacket.Packet) error {
		return errors.New("receiver rejected packet")
	}
	if err := transport.Dispatch(context.Background(), atosbridge.TransportAgentPacket, sampleTask()); err == nil {
		t.Fatalf("a post error must propagate")
	}
}

func TestNewAgentPacketTransportRejectsBadConfig(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := NewAgentPacketTaskTransport(AgentPacketTransportConfig{
		SenderAgentID: "agent_" + hex64, RecipientAgentID: "agent_" + hex64, // sender == recipient
		CapabilityID: "cap_" + hex64, SigningKey: priv, Endpoint: "https://p.example/x", Client: &http.Client{},
	}); err == nil {
		t.Fatalf("sender and recipient must differ")
	}
	if _, err := NewAgentPacketTaskTransport(AgentPacketTransportConfig{
		SenderAgentID: "agent_" + hex64, RecipientAgentID: "agent_" + repeatHex("bb"),
		CapabilityID: "cap_" + hex64, SigningKey: priv, Endpoint: "http://provider.example/x", Client: &http.Client{},
	}); err == nil {
		t.Fatalf("a non-loopback plain-HTTP endpoint must be rejected")
	}
}
