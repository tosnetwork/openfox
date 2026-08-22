package memory

import (
	"context"

	"github.com/tosnetwork/openfox/pkg/providers"
)

// MessageStore defines the atomic message-history operations of persistent
// session storage. There is no separate Save() call.
type MessageStore interface {
	// AddMessage appends a simple text message to a session.
	AddMessage(ctx context.Context, sessionKey, role, content string) error

	// AddFullMessage appends a complete message (with tool calls, etc.) to a session.
	AddFullMessage(ctx context.Context, sessionKey string, msg providers.Message) error

	// ApplyAuthenticatedInbound atomically deduplicates and appends one
	// authenticated input by its source Event ID.
	ApplyAuthenticatedInbound(
		ctx context.Context,
		sessionKey, eventID string,
		msg providers.Message,
	) (bool, error)

	// GetHistory returns all messages for a session in insertion order.
	// Returns an empty slice (not nil) if the session does not exist.
	GetHistory(ctx context.Context, sessionKey string) ([]providers.Message, error)

	// TruncateHistory removes all but the last keepLast messages from a session.
	// If keepLast <= 0, all messages are removed.
	TruncateHistory(ctx context.Context, sessionKey string, keepLast int) error

	// SetHistory replaces all messages in a session with the provided history.
	SetHistory(ctx context.Context, sessionKey string, history []providers.Message) error

	// ApplyRoomModeration durably advances one target's presentation decision.
	ApplyRoomModeration(ctx context.Context, sessionKey string, decision providers.RoomModerationDecision) (bool, error)
}

// SummaryStore defines the atomic summary operations of persistent session
// storage.
type SummaryStore interface {
	// GetSummary returns the conversation summary for a session.
	// Returns an empty string if no summary exists.
	GetSummary(ctx context.Context, sessionKey string) (string, error)

	// SetSummary updates the conversation summary for a session.
	SetSummary(ctx context.Context, sessionKey, summary string) error
}

// StoreMaintenance defines lifecycle and compaction operations for persistent
// session storage.
type StoreMaintenance interface {
	// Compact reclaims storage by physically removing logically truncated
	// data. Backends that do not accumulate dead data may return nil.
	Compact(ctx context.Context, sessionKey string) error

	// ListSessions returns all known session keys.
	ListSessions() []string

	// Close releases any resources held by the store.
	Close() error
}

// Store is the compatibility aggregate used by callers that require the full
// persistent session capability set.
type Store interface {
	MessageStore
	SummaryStore
	StoreMaintenance
}
