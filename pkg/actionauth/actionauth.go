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
	EffectKeyUse        Effect = "key-use"
	EffectConfiguration Effect = "configuration"
)

func (e Effect) Known() bool {
	switch e {
	case EffectNone, EffectLocalRead, EffectLocalWrite, EffectMessage,
		EffectToolCall, EffectPhysicalIO, EffectKeyUse, EffectConfiguration:
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

// Action is one proposed side effect. It carries no spending terms or
// mandate: spending is not authorised through this seam, and Messenger
// refuses a spend effect, purchase terms and mandate references.
type Action struct {
	Effect         Effect             `json:"effect"`
	Summary        string             `json:"summary"`
	IdempotencyKey string             `json:"idempotency_key,omitempty"`
	DerivedFrom    []Origin           `json:"derived_from,omitempty"`
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
