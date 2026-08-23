package cliprovider

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
)

// CodexCliProvider implements LLMProvider by wrapping the codex CLI as a subprocess.
type CodexCliProvider struct {
	command   string
	workspace string
	options   RuntimeOptions
	sem       chan struct{}
	initMu    sync.Mutex
}

// NewCodexCliProvider creates a new Codex CLI provider.
func NewCodexCliProvider(workspace string) *CodexCliProvider {
	return NewCodexCliProviderWithOptions(RuntimeOptions{Workspace: workspace})
}

// NewCodexCliProviderWithOptions creates a hardened one-shot Codex provider.
func NewCodexCliProviderWithOptions(options RuntimeOptions) *CodexCliProvider {
	options = options.normalized()
	return &CodexCliProvider{
		command:   "codex",
		workspace: options.Workspace,
		options:   options,
		sem:       make(chan struct{}, options.MaxConcurrentCalls),
	}
}

// Chat implements LLMProvider.Chat by executing the codex CLI in non-interactive mode.
func (p *CodexCliProvider) Chat(
	ctx context.Context, messages []Message, tools []ToolDefinition, model string, _ map[string]any,
) (*LLMResponse, error) {
	if p.command == "" {
		return nil, fmt.Errorf("codex command not configured")
	}
	options, sem := p.runtime()
	if err := options.validate(); err != nil {
		return nil, err
	}
	if err := options.authorizePrincipal(ctx); err != nil {
		return nil, err
	}
	ctx, cancel := options.boundedContext(ctx)
	defer cancel()
	if _, err := options.canonicalWorkspace(); err != nil {
		return nil, err
	}
	select {
	case sem <- struct{}{}:
		defer func() { <-sem }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	sterileDir, err := os.MkdirTemp("", "openfox-codex-cli-backend-")
	if err != nil {
		return nil, fmt.Errorf("create sterile codex-cli workspace: %w", err)
	}
	defer os.RemoveAll(sterileDir)

	prompt := p.buildPrompt(messages, tools)

	args := []string{
		"exec",
		"--strict-config",
		"--json",
		"--sandbox", options.Sandbox,
		"--skip-git-repo-check",
		"--ephemeral",
		"--ignore-user-config",
		"--ignore-rules",
		"--color", "never",
		"-c", `forced_login_method="chatgpt"`,
		"-c", `allow_login_shell=false`,
		"-c", `shell_environment_policy.inherit="none"`,
		"-c", `shell_environment_policy.ignore_default_excludes=false`,
		"-c", `shell_environment_policy.experimental_use_profile=false`,
	}
	if !options.AllowNativeTools {
		for _, feature := range disabledCodexNativeFeatures() {
			args = append(args, "--disable", feature)
		}
		args = append(args, "-c", `web_search="disabled"`)
	}
	if model != "" && model != "codex-cli" {
		args = append(args, "-m", model)
	}
	args = append(args, "-C", sterileDir)
	args = append(args, "-") // read prompt from stdin

	cmd := exec.CommandContext(ctx, p.command, args...)
	cmd.Dir = sterileDir
	if err := configureSterileCodexHome(cmd, sterileDir); err != nil {
		return nil, err
	}
	configureCommandCancellation(cmd)
	stdout, stderr, err := runCommandBounded(ctx, cmd, []byte(prompt), options.MaxOutputBytes)
	if errors.Is(err, ErrOutputLimit) {
		return nil, err
	}

	// Parse JSONL from stdout even if exit code is non-zero,
	// because codex writes diagnostic noise to stderr (e.g. rollout errors)
	// but still produces valid JSONL output.
	if stdout != "" {
		resp, parseErr := p.parseJSONLEvents(stdout)
		if parseErr == nil && resp != nil && (resp.Content != "" || len(resp.ToolCalls) > 0) {
			return resp, nil
		}
	}

	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if stderr != "" {
			return nil, fmt.Errorf("codex cli error: %s", strings.TrimSpace(stderr))
		}
		return nil, fmt.Errorf("codex cli error: %w", err)
	}

	return p.parseJSONLEvents(stdout)
}

func (p *CodexCliProvider) runtime() (RuntimeOptions, chan struct{}) {
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
func (p *CodexCliProvider) GetDefaultModel() string {
	return "codex-cli"
}

// buildPrompt converts messages to a prompt string for the Codex CLI.
// System messages are prepended as instructions since Codex CLI has no --system-prompt flag.
func (p *CodexCliProvider) buildPrompt(messages []Message, tools []ToolDefinition) string {
	var systemParts []string
	var conversationParts []string

	for _, msg := range messages {
		switch msg.Role {
		case "system":
			systemParts = append(systemParts, msg.Content)
		case "user":
			conversationParts = append(conversationParts, msg.Content)
		case "assistant":
			conversationParts = append(conversationParts, "Assistant: "+msg.Content)
		case "tool":
			conversationParts = append(conversationParts,
				fmt.Sprintf("[Tool Result for %s]: %s", msg.ToolCallID, msg.Content))
		}
	}

	var sb strings.Builder

	if len(systemParts) > 0 {
		sb.WriteString("## System Instructions\n\n")
		sb.WriteString(strings.Join(systemParts, "\n\n"))
		sb.WriteString("\n\n## Task\n\n")
	}

	if len(tools) > 0 {
		sb.WriteString(buildCLIToolsPrompt(tools))
		sb.WriteString("\n\n")
	}

	// Simplify single user message (no prefix)
	if len(conversationParts) == 1 && len(systemParts) == 0 && len(tools) == 0 {
		return conversationParts[0]
	}

	sb.WriteString(strings.Join(conversationParts, "\n"))
	return sb.String()
}

// codexEvent represents a single JSONL event from `codex exec --json`.
type codexEvent struct {
	Type     string          `json:"type"`
	ThreadID string          `json:"thread_id,omitempty"`
	Message  string          `json:"message,omitempty"`
	Item     *codexEventItem `json:"item,omitempty"`
	Usage    *codexUsage     `json:"usage,omitempty"`
	Error    *codexEventErr  `json:"error,omitempty"`
}

type codexEventItem struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Text     string `json:"text,omitempty"`
	Message  string `json:"message,omitempty"`
	Command  string `json:"command,omitempty"`
	Status   string `json:"status,omitempty"`
	ExitCode *int   `json:"exit_code,omitempty"`
	Output   string `json:"output,omitempty"`
}

type codexUsage struct {
	InputTokens       int `json:"input_tokens"`
	CachedInputTokens int `json:"cached_input_tokens"`
	OutputTokens      int `json:"output_tokens"`
}

type codexEventErr struct {
	Message string `json:"message"`
}

// parseJSONLEvents processes the JSONL output from codex exec --json.
func (p *CodexCliProvider) parseJSONLEvents(output string) (*LLMResponse, error) {
	var contentParts []string
	var usage *UsageInfo
	var lastError string
	turnCompleted := false

	scanner := bufio.NewScanner(strings.NewReader(output))
	scanner.Buffer(make([]byte, 64*1024), p.options.normalized().MaxOutputBytes)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var event codexEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			return nil, fmt.Errorf("decode codex cli event: %w", err)
		}

		switch event.Type {
		case "thread.started", "turn.started":
		case "item.started", "item.updated", "item.completed":
			if err := validateCodexExecItem(event.Item); err != nil {
				return nil, err
			}
			if event.Type == "item.completed" && event.Item.Type == "agent_message" && event.Item.Text != "" {
				contentParts = append(contentParts, event.Item.Text)
			}
		case "turn.completed":
			turnCompleted = true
			if event.Usage != nil {
				promptTokens := event.Usage.InputTokens + event.Usage.CachedInputTokens
				usage = &UsageInfo{
					PromptTokens:     promptTokens,
					CompletionTokens: event.Usage.OutputTokens,
					TotalTokens:      promptTokens + event.Usage.OutputTokens,
				}
			}
		case "error":
			lastError = event.Message
		case "turn.failed":
			if event.Error != nil {
				lastError = event.Error.Message
			}
		default:
			return nil, fmt.Errorf("codex cli emitted unsupported event %q", event.Type)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan codex cli events: %w", err)
	}

	if lastError != "" {
		return nil, fmt.Errorf("codex cli: %s", lastError)
	}
	if !turnCompleted {
		return nil, fmt.Errorf("codex cli stream ended without a completed turn")
	}

	content := strings.Join(contentParts, "\n")

	// Extract tool calls from response text (same pattern as ClaudeCliProvider)
	toolCalls := extractToolCallsFromText(content)

	finishReason := "stop"
	if len(toolCalls) > 0 {
		finishReason = "tool_calls"
		content = stripToolCallsFromText(content)
	}

	return &LLMResponse{
		Content:      strings.TrimSpace(content),
		ToolCalls:    toolCalls,
		FinishReason: finishReason,
		Usage:        usage,
	}, nil
}

func validateCodexExecItem(item *codexEventItem) error {
	if item == nil {
		return fmt.Errorf("codex cli emitted an item event without an item")
	}
	switch item.Type {
	case "agent_message", "reasoning", "todo_list":
		return nil
	case "error":
		// Current Codex versions surface this explicit fail-closed state as a
		// non-fatal error item when the code-mode host feature is disabled.
		if strings.HasPrefix(
			strings.TrimSpace(item.Message),
			"Code Mode is unavailable because code-mode host is disabled. Code mode will fail closed",
		) {
			return nil
		}
		return fmt.Errorf("codex cli reported item error: %s", strings.TrimSpace(item.Message))
	default:
		return fmt.Errorf("codex cli attempted prohibited native item %q", item.Type)
	}
}
