// Package actionauth defines OpenFox's narrow side-effect authorization seam.
// Policy stays outside this package: today the implementation is the TOS
// Messenger runtime socket, and a future transport can replace that client
// without changing tool call sites.
package actionauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
)

const (
	MaxProvenance             = 32
	MaxPhysicalArgumentsBytes = 8 << 10
)

type Effect string

const (
	EffectNone          Effect = "none"
	EffectLocalRead     Effect = "local-read"
	EffectLocalWrite    Effect = "local-write"
	EffectMessage       Effect = "message"
	EffectToolCall      Effect = "tool-call"
	EffectPhysicalIO    Effect = "physical-io"
	EffectSpend         Effect = "spend"
	EffectKeyUse        Effect = "key-use"
	EffectConfiguration Effect = "configuration"
)

func (e Effect) Known() bool {
	switch e {
	case EffectNone, EffectLocalRead, EffectLocalWrite, EffectMessage,
		EffectToolCall, EffectPhysicalIO, EffectSpend, EffectKeyUse, EffectConfiguration:
		return true
	default:
		return false
	}
}

type Origin struct {
	AgentID        string `json:"agent_id"`
	EndpointID     string `json:"messaging_endpoint_id"`
	DeviceID       string `json:"device_id"`
	EventID        string `json:"event_id"`
	ConversationID string `json:"conversation_id"`
	Kind           string `json:"event_kind"`
	ReceivedAtUnix uint64 `json:"received_at_unix"`
}

type AssetIdentity struct {
	NetworkID       string `json:"network_id"`
	GenesisRootHash string `json:"genesis_root_hash"`
	GenesisFileHash string `json:"genesis_file_hash"`
	Workchain       int32  `json:"workchain"`
	AccountID       string `json:"master_account_id"`
	MasterCodeHash  string `json:"master_code_hash"`
	WalletCodeHash  string `json:"wallet_code_hash"`
	Decimals        uint32 `json:"decimals"`
}

// PurchaseTerms is the complete canonical quote surface committed by a spend
// approval. No display ticker or floating-point amount is accepted here.
type PurchaseTerms struct {
	CapabilityID           string        `json:"capability_id"`
	CapabilityVersion      string        `json:"capability_version"`
	CapabilityClass        string        `json:"capability_class"`
	ProviderAgentID        string        `json:"provider_agent_id"`
	ManifestDigest         string        `json:"manifest_digest"`
	TransportBindingDigest string        `json:"transport_binding_digest"`
	Asset                  AssetIdentity `json:"asset"`
	PriceAtomic            string        `json:"price_atomic"`
	EscrowTermsDigest      string        `json:"escrow_terms_digest"`
	DisputePolicyDigest    string        `json:"dispute_policy_digest"`
	NotAfterUnix           uint64        `json:"not_after_unix"`
}

type Action struct {
	Effect         Effect             `json:"effect"`
	Summary        string             `json:"summary"`
	IdempotencyKey string             `json:"idempotency_key,omitempty"`
	DerivedFrom    []Origin           `json:"derived_from,omitempty"`
	MandateID      string             `json:"mandate_id,omitempty"`
	Terms          *PurchaseTerms     `json:"terms,omitempty"`
	Physical       *PhysicalOperation `json:"physical,omitempty"`
}

// PhysicalOperation identifies the separately configured local Capability
// and exact hardware invocation for which Messenger must obtain a one-shot
// owner decision. The digest is over encoding/json's canonical map encoding;
// raw device arguments do not cross the policy socket.
type PhysicalOperation struct {
	CapabilityID    string `json:"capability_id"`
	Tool            string `json:"tool"`
	Operation       string `json:"operation"`
	ArgumentsDigest string `json:"arguments_digest"`
	ArgumentsJSON   string `json:"arguments_json"`
}

var (
	physicalCapabilityPattern = regexp.MustCompile(`^cap_[0-9a-f]{64}$`)
	physicalNamePattern       = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	physicalDigestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

func (p PhysicalOperation) Valid() bool {
	if !physicalCapabilityPattern.MatchString(p.CapabilityID) ||
		!physicalNamePattern.MatchString(p.Tool) || !physicalNamePattern.MatchString(p.Operation) ||
		!physicalDigestPattern.MatchString(p.ArgumentsDigest) || len(p.ArgumentsJSON) == 0 ||
		len(p.ArgumentsJSON) > MaxPhysicalArgumentsBytes {
		return false
	}
	var arguments map[string]any
	if err := json.Unmarshal([]byte(p.ArgumentsJSON), &arguments); err != nil {
		return false
	}
	canonical, err := json.Marshal(arguments)
	if err != nil || string(canonical) != p.ArgumentsJSON || arguments["action"] != p.Operation {
		return false
	}
	digest := sha256.Sum256(canonical)
	return p.ArgumentsDigest == "sha256:"+hex.EncodeToString(digest[:])
}

type Authorizer interface {
	Authorize(ctx context.Context, action Action) error
}

type AuthorizerFunc func(context.Context, Action) error

func (f AuthorizerFunc) Authorize(ctx context.Context, action Action) error { return f(ctx, action) }

type Invocation struct {
	IdempotencyKey string
	Summary        string
	DerivedFrom    []Origin
	// LineageComplete is asserted only by runtime context accounting. The
	// zero value fails closed when enforcement is enabled.
	LineageComplete bool
}

type invocationKey struct{}

func WithInvocation(ctx context.Context, invocation Invocation) context.Context {
	copyOf := invocation
	copyOf.DerivedFrom = append([]Origin(nil), invocation.DerivedFrom...)
	return context.WithValue(ctx, invocationKey{}, copyOf)
}

func InvocationFrom(ctx context.Context) (Invocation, bool) {
	invocation, ok := ctx.Value(invocationKey{}).(Invocation)
	invocation.DerivedFrom = append([]Origin(nil), invocation.DerivedFrom...)
	return invocation, ok
}

// ToolInvocationKey derives the retry-stable key committed by Messenger. The
// model never supplies it. JSON object keys are ordered by encoding/json, so
// an exact retry of one provider tool call reproduces the same key.
func ToolInvocationKey(
	agentID, sessionKey, inboundMessageID, toolCallID, toolName string,
	args map[string]any,
) (string, error) {
	if toolCallID == "" || toolName == "" {
		return "", errors.New("tool invocation needs a call ID and tool name")
	}
	preimage, err := json.Marshal(struct {
		Domain           string         `json:"domain"`
		AgentID          string         `json:"agent_id"`
		SessionKey       string         `json:"session_key"`
		InboundMessageID string         `json:"inbound_message_id"`
		ToolCallID       string         `json:"tool_call_id"`
		ToolName         string         `json:"tool_name"`
		Arguments        map[string]any `json:"arguments"`
	}{
		Domain: "openfox.tos-messenger.tool-invocation.v1", AgentID: agentID,
		SessionKey: sessionKey, InboundMessageID: inboundMessageID,
		ToolCallID: toolCallID, ToolName: toolName, Arguments: args,
	})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(preimage)
	return "idem_" + hex.EncodeToString(digest[:]), nil
}
