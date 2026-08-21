package protocoltypes

import (
	"time"

	"github.com/tosnetwork/openfox/pkg/actionauth"
)

type ToolCall struct {
	ID               string         `json:"id"`
	Type             string         `json:"type,omitempty"`
	Function         *FunctionCall  `json:"function,omitempty"`
	Name             string         `json:"-"`
	Arguments        map[string]any `json:"-"`
	ThoughtSignature string         `json:"-"` // Internal use only
	ExtraContent     *ExtraContent  `json:"extra_content,omitempty"`
}

type ExtraContent struct {
	Google                  *GoogleExtra `json:"google,omitempty"`
	ToolFeedbackExplanation string       `json:"tool_feedback_explanation,omitempty"`
}

type GoogleExtra struct {
	ThoughtSignature string `json:"thought_signature,omitempty"`
}

type FunctionCall struct {
	Name             string `json:"name"`
	Arguments        string `json:"arguments"`
	ThoughtSignature string `json:"thought_signature,omitempty"`
}

type LLMResponse struct {
	Content          string            `json:"content"`
	ReasoningContent string            `json:"reasoning_content,omitempty"`
	ToolCalls        []ToolCall        `json:"tool_calls,omitempty"`
	FinishReason     string            `json:"finish_reason"`
	Usage            *UsageInfo        `json:"usage,omitempty"`
	Reasoning        string            `json:"reasoning"`
	ReasoningDetails []ReasoningDetail `json:"reasoning_details"`
}

type StreamChunk struct {
	Content          string
	ReasoningContent string
}

type ReasoningDetail struct {
	Format string `json:"format"`
	Index  int    `json:"index"`
	Type   string `json:"type"`
	Text   string `json:"text"`
}

type UsageInfo struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// CacheControl marks a content block for LLM-side prefix caching.
// Currently only "ephemeral" is supported (used by Anthropic).
type CacheControl struct {
	Type string `json:"type"` // "ephemeral"
}

// ContentBlock represents a structured segment of a system message.
// Adapters that understand SystemParts can use these blocks to set
// per-block cache control (e.g. Anthropic's cache_control: ephemeral).
type ContentBlock struct {
	Type         string        `json:"type"` // "text"
	Text         string        `json:"text"`
	CacheControl *CacheControl `json:"cache_control,omitempty"`

	// Prompt metadata is internal to the agent runtime. It records which
	// structured prompt segment produced this block without changing provider
	// JSON.
	PromptLayer  string `json:"-"`
	PromptSlot   string `json:"-"`
	PromptSource string `json:"-"`
}

type Attachment struct {
	Type        string `json:"type,omitempty"`
	Ref         string `json:"ref,omitempty"`
	URL         string `json:"url,omitempty"`
	Filename    string `json:"filename,omitempty"`
	ContentType string `json:"content_type,omitempty"`
}

type Message struct {
	Role             string         `json:"role"`
	Content          string         `json:"content"`
	ModelName        string         `json:"model_name,omitempty"`
	CreatedAt        *time.Time     `json:"created_at,omitempty"`
	Media            []string       `json:"media,omitempty"`
	Attachments      []Attachment   `json:"attachments,omitempty"`
	ReasoningContent string         `json:"reasoning_content,omitempty"`
	SystemParts      []ContentBlock `json:"system_parts,omitempty"` // structured system blocks for cache-aware adapters
	ToolCalls        []ToolCall     `json:"tool_calls,omitempty"`
	ToolCallID       string         `json:"tool_call_id,omitempty"`

	// ActionOrigins and ActionProvenanceState are runtime-owned metadata. They
	// are persisted with session history but provider adapters intentionally do
	// not serialize them onto model APIs. A model therefore cannot add or remove
	// its own authority lineage.
	ActionOrigins         []actionauth.Origin `json:"action_origins,omitempty"`
	ActionProvenanceState string              `json:"action_provenance_state,omitempty"`
	// SourceEventID/SourceRoomID and moderation fields are also runtime-owned.
	// Hidden content is replaced before it reaches a provider; the storage layer
	// retains the immutable original so an authorized restore can undo the
	// presentation overlay without exposing it in this projected Message.
	SourceEventID            string `json:"source_event_id,omitempty"`
	SourceRoomID             string `json:"source_room_id,omitempty"`
	RoomModerationAction     string `json:"room_moderation_action,omitempty"`
	RoomModerationRevision   uint64 `json:"room_moderation_revision,omitempty"`
	RoomModerationDecisionID string `json:"room_moderation_decision_id,omitempty"`
	ModerationSynthetic      bool   `json:"moderation_synthetic,omitempty"`

	// Prompt metadata is internal to the agent runtime. It records where a
	// message or system part came from without changing provider/session JSON.
	PromptLayer  string `json:"-"`
	PromptSlot   string `json:"-"`
	PromptSource string `json:"-"`
}

// RoomModerationDecision is the durable, model-invisible presentation state
// for one authenticated Messenger Event.
type RoomModerationDecision struct {
	RoomID           string `json:"room_id"`
	TargetEventID    string `json:"target_event_id"`
	DecisionEventID  string `json:"decision_event_id"`
	DecisionRevision uint64 `json:"decision_revision"`
	Action           string `json:"action"`
	Reason           string `json:"reason,omitempty"`
}

type ToolDefinition struct {
	Type     string                 `json:"type"`
	Function ToolFunctionDefinition `json:"function"`

	// Prompt metadata is internal to the agent runtime. Tool definitions are
	// model-visible capability prompts even though providers send them outside
	// the system message.
	PromptLayer  string `json:"-"`
	PromptSlot   string `json:"-"`
	PromptSource string `json:"-"`
}

type ToolFunctionDefinition struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}
