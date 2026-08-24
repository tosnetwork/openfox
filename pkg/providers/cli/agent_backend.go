package cliprovider

import "context"

// AgentBackend is the lifecycle boundary for a local full-agent runtime. It is
// intentionally distinct from a stateless HTTP inference provider.
type AgentBackend interface {
	Start(ctx context.Context) error
	Health(ctx context.Context) error
	RunTurn(ctx context.Context, req AgentTurnRequest) (*AgentTurnResult, error)
	Capabilities() AgentBackendCapabilities
	Close()
}

type AgentTurnRequest struct {
	Prompt string
	Model  string
}

type AgentTurnResult struct {
	Content  string
	ThreadID string
	TurnID   string
}

type AgentBackendCapabilities struct {
	PersistentProcess bool
	ResumableThreads  bool
	StreamingEvents   bool
	NativeTools       bool
	Sandbox           string
}
