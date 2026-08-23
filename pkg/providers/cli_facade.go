package providers

import (
	"time"

	cliprovider "github.com/tosnetwork/openfox/pkg/providers/cli"
)

type (
	AgentBackend             = cliprovider.AgentBackend
	AgentBackendCapabilities = cliprovider.AgentBackendCapabilities
	AgentTurnRequest         = cliprovider.AgentTurnRequest
	AgentTurnResult          = cliprovider.AgentTurnResult
	RuntimeOptions           = cliprovider.RuntimeOptions
	ClaudeCliProvider        = cliprovider.ClaudeCliProvider
	CodexCliProvider         = cliprovider.CodexCliProvider
	CodexAppServerProvider   = cliprovider.CodexAppServerProvider
	CodexCliAuth             = cliprovider.CodexCliAuth
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

func ReadCodexCliCredentials() (accessToken, accountID string, expiresAt time.Time, err error) {
	return cliprovider.ReadCodexCliCredentials()
}

func CreateCodexCliTokenSource() func() (string, string, error) {
	return cliprovider.CreateCodexCliTokenSource()
}

func NormalizeToolCall(tc ToolCall) ToolCall {
	return cliprovider.NormalizeToolCall(tc)
}
