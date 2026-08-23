package cliprovider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
)

// ClaudeCliProvider implements LLMProvider using the claude CLI as a subprocess.
type ClaudeCliProvider struct {
	command   string
	workspace string
	options   RuntimeOptions
	sem       chan struct{}
	initMu    sync.Mutex
}

// NewClaudeCliProvider creates a new Claude CLI provider.
func NewClaudeCliProvider(workspace string) *ClaudeCliProvider {
	return NewClaudeCliProviderWithOptions(RuntimeOptions{Workspace: workspace})
}

// NewClaudeCliProviderWithOptions creates a hardened Claude Code provider.
func NewClaudeCliProviderWithOptions(options RuntimeOptions) *ClaudeCliProvider {
	options = options.normalized()
	return &ClaudeCliProvider{
		command:   "claude",
		workspace: options.Workspace,
		options:   options,
		sem:       make(chan struct{}, options.MaxConcurrentCalls),
	}
}

// Chat implements LLMProvider.Chat by executing the claude CLI.
func (p *ClaudeCliProvider) Chat(
	ctx context.Context, messages []Message, tools []ToolDefinition, model string, _ map[string]any,
) (*LLMResponse, error) {
	options, sem := p.runtime()
	if err := options.validate(); err != nil {
		return nil, err
	}
	if err := options.authorizePrincipal(ctx); err != nil {
		return nil, err
	}
	ctx, cancel := options.boundedContext(ctx)
	defer cancel()
	if options.AllowNativeTools {
		return nil, fmt.Errorf("claude-cli native tools are disabled: route tools through the OpenFox authorization loop")
	}
	if _, err := options.canonicalWorkspace(); err != nil {
		return nil, err
	}
	select {
	case sem <- struct{}{}:
		defer func() { <-sem }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	// A local-personal subscription must not be silently replaced by an API
	// key, LLM gateway, Bedrock, Vertex, or Foundry environment override.
	claudeEnv := removeEnvironmentPrefixes(os.Environ(), "ANTHROPIC_", "CLAUDE_")
	claudeEnv = replaceEnvironmentValue(claudeEnv, "DISABLE_AUTOUPDATER", "1")
	if options.SubscriptionUse == "local-personal" {
		if err := verifyClaudePersonalSubscription(ctx, p.command, claudeEnv, options.MaxOutputBytes); err != nil {
			return nil, err
		}
	}
	// Claude Code subscription auth does not support --bare. Use an empty,
	// short-lived cwd so repository CLAUDE.md files and project settings cannot
	// silently become a second instruction channel. OpenFox tools retain the
	// actual workspace authorization boundary.
	sterileDir, err := os.MkdirTemp("", "openfox-claude-backend-")
	if err != nil {
		return nil, fmt.Errorf("create sterile claude-cli workspace: %w", err)
	}
	defer os.RemoveAll(sterileDir)

	systemPrompt := p.buildSystemPrompt(messages, tools)
	prompt := p.messagesToPrompt(messages)

	args := []string{
		"-p", "--output-format", "json",
		"--safe-mode",
		"--tools", "",
		"--permission-mode", "plan",
		"--setting-sources", "",
		"--no-session-persistence",
		"--no-chrome",
	}
	if systemPrompt != "" {
		args = append(args, "--system-prompt", systemPrompt)
	}
	if model != "" && model != "claude-code" {
		args = append(args, "--model", model)
	}
	args = append(args, "-") // read from stdin

	cmd := exec.CommandContext(ctx, p.command, args...)
	cmd.Dir = sterileDir
	cmd.Env = claudeEnv
	configureCommandCancellation(cmd)
	stdout, stderr, err := runCommandBounded(ctx, cmd, []byte(prompt), options.MaxOutputBytes)
	if errors.Is(err, ErrOutputLimit) {
		return nil, err
	}
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		stderrStr := strings.TrimSpace(stderr)
		stdoutStr := strings.TrimSpace(stdout)
		switch {
		case stderrStr != "" && stdoutStr != "":
			return nil, fmt.Errorf("claude cli error: %w\nstderr: %s\nstdout: %s", err, stderrStr, stdoutStr)
		case stderrStr != "":
			return nil, fmt.Errorf("claude cli error: %s", stderrStr)
		case stdoutStr != "":
			return nil, fmt.Errorf("claude cli error: %w\noutput: %s", err, stdoutStr)
		default:
			return nil, fmt.Errorf("claude cli error: %w", err)
		}
	}

	return p.parseClaudeCliResponse(stdout)
}

func verifyClaudePersonalSubscription(
	ctx context.Context, command string, environment []string, maxOutputBytes int,
) error {
	cmd := exec.CommandContext(ctx, command, "auth", "status", "--json")
	cmd.Env = environment
	configureCommandCancellation(cmd)
	stdout, stderr, err := runCommandBounded(ctx, cmd, nil, min(maxOutputBytes, 64*1024))
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if strings.TrimSpace(stderr) != "" {
			return fmt.Errorf("check Claude Code subscription authentication: %s", strings.TrimSpace(stderr))
		}
		return fmt.Errorf("check Claude Code subscription authentication: %w", err)
	}
	var status struct {
		LoggedIn         bool   `json:"loggedIn"`
		AuthMethod       string `json:"authMethod"`
		APIProvider      string `json:"apiProvider"`
		SubscriptionType string `json:"subscriptionType"`
	}
	if err := json.Unmarshal([]byte(stdout), &status); err != nil {
		return fmt.Errorf("decode Claude Code authentication status: %w", err)
	}
	subscriptionType := strings.ToLower(strings.TrimSpace(status.SubscriptionType))
	if !status.LoggedIn || status.AuthMethod != "claude.ai" || status.APIProvider != "firstParty" ||
		(subscriptionType != "pro" && subscriptionType != "max") {
		return fmt.Errorf("local-personal Claude backend requires an authenticated Claude.ai Pro or Max subscription")
	}
	return nil
}

func (p *ClaudeCliProvider) runtime() (RuntimeOptions, chan struct{}) {
	p.initMu.Lock()
	defer p.initMu.Unlock()
	options := p.options
	if options.Workspace == "" {
		options.Workspace = p.workspace
	}
	options = options.normalized()
	p.options = options
	if p.sem == nil {
		p.sem = make(chan struct{}, options.MaxConcurrentCalls)
	}
	return options, p.sem
}

// GetDefaultModel returns the default model identifier.
func (p *ClaudeCliProvider) GetDefaultModel() string {
	return "claude-code"
}

// messagesToPrompt converts messages to a CLI-compatible prompt string.
func (p *ClaudeCliProvider) messagesToPrompt(messages []Message) string {
	var parts []string

	for _, msg := range messages {
		switch msg.Role {
		case "system":
			// handled via --system-prompt flag
		case "user":
			parts = append(parts, "User: "+msg.Content)
		case "assistant":
			parts = append(parts, "Assistant: "+msg.Content)
		case "tool":
			parts = append(parts, fmt.Sprintf("[Tool Result for %s]: %s", msg.ToolCallID, msg.Content))
		}
	}

	// Simplify single user message
	if len(parts) == 1 && strings.HasPrefix(parts[0], "User: ") {
		return strings.TrimPrefix(parts[0], "User: ")
	}

	return strings.Join(parts, "\n")
}

// buildSystemPrompt combines system messages and tool definitions.
func (p *ClaudeCliProvider) buildSystemPrompt(messages []Message, tools []ToolDefinition) string {
	var parts []string

	for _, msg := range messages {
		if msg.Role == "system" {
			parts = append(parts, msg.Content)
		}
	}

	if len(tools) > 0 {
		parts = append(parts, buildCLIToolsPrompt(tools))
	}

	return strings.Join(parts, "\n\n")
}

// parseClaudeCliResponse parses the JSON output from the claude CLI.
func (p *ClaudeCliProvider) parseClaudeCliResponse(output string) (*LLMResponse, error) {
	var resp claudeCliJSONResponse
	if err := json.Unmarshal([]byte(output), &resp); err != nil {
		return nil, fmt.Errorf("failed to parse claude cli response: %w", err)
	}

	if resp.IsError {
		return nil, fmt.Errorf("claude cli returned error: %s", resp.Result)
	}

	toolCalls := p.extractToolCalls(resp.Result)

	finishReason := "stop"
	content := resp.Result
	if len(toolCalls) > 0 {
		finishReason = "tool_calls"
		content = p.stripToolCallsJSON(resp.Result)
	}

	var usage *UsageInfo
	if resp.Usage.InputTokens > 0 || resp.Usage.OutputTokens > 0 {
		usage = &UsageInfo{
			PromptTokens:     resp.Usage.InputTokens + resp.Usage.CacheCreationInputTokens + resp.Usage.CacheReadInputTokens,
			CompletionTokens: resp.Usage.OutputTokens,
			TotalTokens:      resp.Usage.InputTokens + resp.Usage.CacheCreationInputTokens + resp.Usage.CacheReadInputTokens + resp.Usage.OutputTokens,
		}
	}

	return &LLMResponse{
		Content:      strings.TrimSpace(content),
		ToolCalls:    toolCalls,
		FinishReason: finishReason,
		Usage:        usage,
	}, nil
}

// extractToolCalls delegates to the shared extractToolCallsFromText function.
func (p *ClaudeCliProvider) extractToolCalls(text string) []ToolCall {
	return extractToolCallsFromText(text)
}

// stripToolCallsJSON delegates to the shared stripToolCallsFromText function.
func (p *ClaudeCliProvider) stripToolCallsJSON(text string) string {
	return stripToolCallsFromText(text)
}

// findMatchingBrace finds the index after the closing brace matching the opening brace at pos.
func findMatchingBrace(text string, pos int) int {
	depth := 0
	for i := pos; i < len(text); i++ {
		if text[i] == '{' {
			depth++
		} else if text[i] == '}' {
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}
	return pos
}

// claudeCliJSONResponse represents the JSON output from the claude CLI.
// Matches the real claude CLI v2.x output format.
type claudeCliJSONResponse struct {
	Type         string             `json:"type"`
	Subtype      string             `json:"subtype"`
	IsError      bool               `json:"is_error"`
	Result       string             `json:"result"`
	SessionID    string             `json:"session_id"`
	TotalCostUSD float64            `json:"total_cost_usd"`
	DurationMS   int                `json:"duration_ms"`
	DurationAPI  int                `json:"duration_api_ms"`
	NumTurns     int                `json:"num_turns"`
	Usage        claudeCliUsageInfo `json:"usage"`
}

// claudeCliUsageInfo represents token usage from the claude CLI response.
type claudeCliUsageInfo struct {
	InputTokens              int `json:"input_tokens"`
	OutputTokens             int `json:"output_tokens"`
	CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
	CacheReadInputTokens     int `json:"cache_read_input_tokens"`
}
