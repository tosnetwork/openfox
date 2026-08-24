package providers

import (
	"context"

	cliprovider "github.com/tosnetwork/openfox/pkg/providers/cli"
)

func WithAgentBackendPrincipal(ctx context.Context, channel, senderID string) context.Context {
	return cliprovider.WithAgentBackendPrincipal(ctx, channel, senderID)
}

func WithInternalAgentBackendPrincipal(ctx context.Context) context.Context {
	return cliprovider.WithInternalAgentBackendPrincipal(ctx)
}

type (
	AgentBackend             = cliprovider.AgentBackend
	AgentBackendCapabilities = cliprovider.AgentBackendCapabilities
	AgentTurnRequest         = cliprovider.AgentTurnRequest
	AgentTurnResult          = cliprovider.AgentTurnResult
	RuntimeOptions           = cliprovider.RuntimeOptions
	ClaudeCliProvider        = cliprovider.ClaudeCliProvider
	CodexCliProvider         = cliprovider.CodexCliProvider
	CodexAppServerProvider   = cliprovider.CodexAppServerProvider
	GitHubCopilotProvider    = cliprovider.GitHubCopilotProvider
)

const CodexHomeEnvVar = cliprovider.CodexHomeEnvVar

func NewClaudeCliProvider(workspace string) *ClaudeCliProvider {
	return cliprovider.NewClaudeCliProvider(workspace)
}

func NewClaudeCliProviderWithOptions(options RuntimeOptions) *ClaudeCliProvider {
	return cliprovider.NewClaudeCliProviderWithOptions(options)
}

func NewCodexCliProvider(workspace string) *CodexCliProvider {
	return cliprovider.NewCodexCliProvider(workspace)
}

func NewCodexCliProviderWithOptions(options RuntimeOptions) *CodexCliProvider {
	return cliprovider.NewCodexCliProviderWithOptions(options)
}

func NewCodexAppServerProvider(options RuntimeOptions) *CodexAppServerProvider {
	return cliprovider.NewCodexAppServerProvider(options)
}

func NewGitHubCopilotProvider(uri string, connectMode string, model string) (*GitHubCopilotProvider, error) {
	return cliprovider.NewGitHubCopilotProvider(uri, connectMode, model)
}

func NormalizeToolCall(tc ToolCall) ToolCall {
	return cliprovider.NormalizeToolCall(tc)
}
