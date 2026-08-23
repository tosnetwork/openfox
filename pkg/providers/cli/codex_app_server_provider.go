package cliprovider

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/tosnetwork/openfox/pkg/isolation"
)

// CodexAppServerProvider keeps one official local Codex app-server process and
// maps OpenFox LLM turns onto isolated ephemeral Codex threads. It implements
// AgentBackend as well as the compatibility LLMProvider surface.
type CodexAppServerProvider struct {
	command string
	options RuntimeOptions
	sem     chan struct{}

	turnMu sync.Mutex
	procMu sync.Mutex
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	events chan appServerMessage
	done   chan error
	stop   chan struct{}
	nextID int64
	stderr *boundedCollector
	// sterileDir prevents repository instructions from becoming a hidden
	// instruction channel in provider-as-LLM mode.
	sterileDir string
}

type appServerMessage struct {
	ID     json.RawMessage `json:"id,omitempty"`
	Method string          `json:"method,omitempty"`
	Params json.RawMessage `json:"params,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func NewCodexAppServerProvider(options RuntimeOptions) *CodexAppServerProvider {
	options = options.normalized()
	return &CodexAppServerProvider{
		command: "codex",
		options: options,
		sem:     make(chan struct{}, options.MaxConcurrentCalls),
	}
}

func (p *CodexAppServerProvider) GetDefaultModel() string { return "codex-cli" }

func (p *CodexAppServerProvider) Capabilities() AgentBackendCapabilities {
	return AgentBackendCapabilities{
		PersistentProcess: true,
		ResumableThreads:  false, // compatibility Chat calls use ephemeral threads
		StreamingEvents:   true,
		NativeTools:       p.options.AllowNativeTools,
		Sandbox:           p.options.Sandbox,
	}
}

func (p *CodexAppServerProvider) Chat(
	ctx context.Context, messages []Message, tools []ToolDefinition, model string, _ map[string]any,
) (*LLMResponse, error) {
	prompt := buildCodexPrompt(messages, tools)
	result, err := p.RunTurn(ctx, AgentTurnRequest{Prompt: prompt, Model: model})
	if err != nil {
		return nil, err
	}
	toolCalls := extractToolCallsFromText(result.Content)
	content := result.Content
	finishReason := "stop"
	if len(toolCalls) > 0 {
		finishReason = "tool_calls"
		content = stripToolCallsFromText(content)
	}
	return &LLMResponse{
		Content:      strings.TrimSpace(content),
		ToolCalls:    toolCalls,
		FinishReason: finishReason,
	}, nil
}

func (p *CodexAppServerProvider) Start(ctx context.Context) error {
	ctx, cancel := p.options.boundedContext(ctx)
	defer cancel()
	p.procMu.Lock()
	defer p.procMu.Unlock()
	return p.startLocked(ctx)
}

func (p *CodexAppServerProvider) startLocked(ctx context.Context) error {
	if p.cmd != nil {
		return nil
	}
	if err := p.options.validate(); err != nil {
		return err
	}
	if _, err := p.options.canonicalWorkspace(); err != nil {
		return err
	}

	args := []string{"app-server", "--listen", "stdio://"}
	if !p.options.AllowNativeTools {
		for _, feature := range disabledCodexNativeFeatures() {
			args = append(args, "--disable", feature)
		}
		args = append(args, "-c", `web_search="disabled"`)
	}
	sterileDir, err := os.MkdirTemp("", "openfox-codex-backend-")
	if err != nil {
		return fmt.Errorf("create sterile codex app-server workspace: %w", err)
	}
	p.sterileDir = sterileDir
	defer func() {
		if p.cmd == nil && p.sterileDir != "" {
			_ = os.RemoveAll(p.sterileDir)
			p.sterileDir = ""
		}
	}()
	cmd := exec.Command(p.command, args...)
	cmd.Dir = sterileDir
	if err := configureSterileCodexHome(cmd, sterileDir); err != nil {
		return err
	}
	configureProcessGroup(cmd)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("codex app-server stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("codex app-server stdout: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("codex app-server stderr: %w", err)
	}
	if err := isolation.Start(cmd); err != nil {
		return fmt.Errorf("start codex app-server: %w", err)
	}
	if err := attachProcessTree(cmd); err != nil {
		_ = cmd.Process.Kill()
		return fmt.Errorf("attach codex app-server process tree: %w", err)
	}

	p.cmd = cmd
	p.stdin = stdin
	events := make(chan appServerMessage, 1)
	done := make(chan error, 1)
	stop := make(chan struct{})
	p.events = events
	p.done = done
	p.stop = stop
	p.stderr = newBoundedCollector(min(64*1024, p.options.MaxOutputBytes))
	go func() { _, _ = io.Copy(p.stderr, stderr) }()
	go p.readLoop(stdout, cmd, events, done, stop)

	p.nextID++
	initID := p.nextID
	if err := p.sendLocked(map[string]any{
		"id":     initID,
		"method": "initialize",
		"params": map[string]any{
			"clientInfo": map[string]string{
				"name":    "openfox",
				"title":   "OpenFox",
				"version": "1",
			},
			"capabilities": map[string]any{
				"optOutNotificationMethods": []string{
					"item/agentMessage/delta",
					"item/reasoning/textDelta",
					"item/reasoning/summaryTextDelta",
					"item/commandExecution/outputDelta",
					"item/fileChange/outputDelta",
				},
			},
		},
	}); err != nil {
		p.stopLocked()
		return err
	}
	if _, err := p.waitForResponseLocked(ctx, initID, nil); err != nil {
		p.stopLocked()
		return fmt.Errorf("initialize codex app-server: %w", err)
	}
	if err := p.sendLocked(map[string]any{"method": "initialized", "params": map[string]any{}}); err != nil {
		p.stopLocked()
		return err
	}
	if err := p.healthLocked(ctx); err != nil {
		p.stopLocked()
		return err
	}
	return nil
}

func (p *CodexAppServerProvider) Health(ctx context.Context) error {
	ctx, cancel := p.options.boundedContext(ctx)
	defer cancel()
	p.turnMu.Lock()
	defer p.turnMu.Unlock()
	if err := p.Start(ctx); err != nil {
		return err
	}
	p.procMu.Lock()
	defer p.procMu.Unlock()
	return p.healthLocked(ctx)
}

func (p *CodexAppServerProvider) healthLocked(ctx context.Context) error {
	p.nextID++
	id := p.nextID
	if err := p.sendLocked(map[string]any{
		"id": id, "method": "account/read", "params": map[string]any{"refreshToken": false},
	}); err != nil {
		return fmt.Errorf("codex account/read: %w", err)
	}
	response, err := p.waitForResponseLocked(ctx, id, nil)
	if err != nil {
		return fmt.Errorf("codex account/read: %w", err)
	}
	var payload struct {
		Account            json.RawMessage `json:"account"`
		RequiresOpenAIAuth bool            `json:"requiresOpenaiAuth"`
	}
	if err := json.Unmarshal(response.Result, &payload); err != nil {
		return fmt.Errorf("decode codex account/read response: %w", err)
	}
	accountMissing := len(payload.Account) == 0 || string(payload.Account) == "null"
	if payload.RequiresOpenAIAuth && accountMissing {
		return fmt.Errorf("codex CLI is not authenticated; log in with the official Codex CLI")
	}
	if p.options.SubscriptionUse == "local-personal" && !accountMissing {
		var account struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(payload.Account, &account); err != nil {
			return fmt.Errorf("decode codex account: %w", err)
		}
		if account.Type != "chatgpt" {
			return fmt.Errorf("local-personal Codex backend requires a ChatGPT account")
		}
	}
	return nil
}

func (p *CodexAppServerProvider) RunTurn(ctx context.Context, req AgentTurnRequest) (*AgentTurnResult, error) {
	if err := p.options.validate(); err != nil {
		return nil, err
	}
	if err := p.options.authorizePrincipal(ctx); err != nil {
		return nil, err
	}
	ctx, cancel := p.options.boundedContext(ctx)
	defer cancel()
	select {
	case p.sem <- struct{}{}:
		defer func() { <-p.sem }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// The stdio protocol is ordered. Serialize turns so responses and
	// notifications cannot be attributed to the wrong OpenFox request.
	p.turnMu.Lock()
	defer p.turnMu.Unlock()

	if err := p.Start(ctx); err != nil {
		return nil, err
	}
	if _, err := p.options.canonicalWorkspace(); err != nil {
		return nil, err
	}

	p.procMu.Lock()
	defer p.procMu.Unlock()
	if p.cmd == nil {
		return nil, fmt.Errorf("codex app-server is not running")
	}
	workspace := p.sterileDir
	if workspace == "" {
		return nil, fmt.Errorf("codex app-server sterile workspace is unavailable")
	}

	p.nextID++
	threadReqID := p.nextID
	threadParams := map[string]any{
		"approvalPolicy": p.options.ApprovalPolicy,
		"cwd":            workspace,
		"ephemeral":      true,
		"sandbox":        p.options.Sandbox,
		"config":         secureCodexThreadConfig(p.options.AllowNativeTools),
	}
	if req.Model != "" && req.Model != "codex-cli" {
		threadParams["model"] = req.Model
	}
	if err := p.sendLocked(map[string]any{
		"id": threadReqID, "method": "thread/start", "params": threadParams,
	}); err != nil {
		p.stopLocked()
		return nil, err
	}
	threadResp, err := p.waitForResponseLocked(ctx, threadReqID, nil)
	if err != nil {
		p.stopLocked()
		return nil, fmt.Errorf("codex thread/start: %w", err)
	}
	threadID, err := parseThreadID(threadResp.Result)
	if err != nil {
		return nil, err
	}

	p.nextID++
	turnReqID := p.nextID
	if err := p.sendLocked(map[string]any{
		"id":     turnReqID,
		"method": "turn/start",
		"params": map[string]any{
			"threadId":       threadID,
			"input":          []map[string]any{{"type": "text", "text": req.Prompt}},
			"approvalPolicy": p.options.ApprovalPolicy,
		},
	}); err != nil {
		p.stopLocked()
		return nil, err
	}
	var pending []appServerMessage
	turnResp, err := p.waitForResponseLocked(ctx, turnReqID, func(msg appServerMessage) {
		pending = append(pending, msg)
	})
	if err != nil {
		p.stopLocked()
		return nil, fmt.Errorf("codex turn/start: %w", err)
	}
	turnID := parseTurnID(turnResp.Result)

	var content string
	retained := 0
	if p.stderr != nil {
		retained = p.stderr.Len()
	}
	handleMessage := func(msg appServerMessage) (*AgentTurnResult, bool, error) {
		retained += len(msg.Params) + len(msg.Result)
		if retained > p.options.MaxOutputBytes {
			return nil, false, ErrOutputLimit
		}
		if len(msg.ID) > 0 && msg.Method != "" {
			if err := p.rejectServerRequestLocked(msg); err != nil {
				return nil, false, err
			}
			return nil, false, nil
		}
		switch msg.Method {
		case "item/completed":
			if text := parseCompletedAgentMessage(msg.Params, threadID, turnID); text != "" {
				content = text
			}
		case "turn/completed":
			status, completedTurnID, turnErr := parseTurnCompleted(msg.Params, threadID)
			if status == "" && completedTurnID == "" {
				return nil, false, nil
			}
			if completedTurnID != "" {
				turnID = completedTurnID
			}
			if turnErr != "" || status == "failed" {
				if turnErr == "" {
					turnErr = status
				}
				return nil, false, fmt.Errorf("codex turn failed: %s", turnErr)
			}
			return &AgentTurnResult{Content: content, ThreadID: threadID, TurnID: turnID}, true, nil
		}
		return nil, false, nil
	}
	for _, msg := range pending {
		if result, complete, err := handleMessage(msg); err != nil {
			p.stopLocked()
			return nil, err
		} else if complete {
			return result, nil
		}
	}
	for {
		msg, err := p.nextMessageLocked(ctx)
		if err != nil {
			p.stopLocked()
			return nil, err
		}
		if result, complete, err := handleMessage(msg); err != nil {
			p.stopLocked()
			return nil, err
		} else if complete {
			return result, nil
		}
	}
}

func (p *CodexAppServerProvider) Close() {
	p.turnMu.Lock()
	defer p.turnMu.Unlock()
	p.procMu.Lock()
	defer p.procMu.Unlock()
	p.stopLocked()
}

func (p *CodexAppServerProvider) stopLocked() {
	if p.stop != nil {
		close(p.stop)
		p.stop = nil
	}
	if p.stdin != nil {
		_ = p.stdin.Close()
	}
	if p.cmd != nil && p.cmd.Process != nil {
		_ = killProcessTree(p.cmd)
	}
	p.cmd = nil
	p.stdin = nil
	p.events = nil
	p.done = nil
	if p.sterileDir != "" {
		_ = os.RemoveAll(p.sterileDir)
		p.sterileDir = ""
	}
}

func (p *CodexAppServerProvider) readLoop(
	stdout io.Reader, cmd *exec.Cmd, events chan<- appServerMessage, done chan<- error, stop <-chan struct{},
) {
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), p.options.MaxOutputBytes)
	for scanner.Scan() {
		var msg appServerMessage
		if err := json.Unmarshal(scanner.Bytes(), &msg); err != nil {
			_ = killProcessTree(cmd)
			_ = cmd.Wait()
			done <- fmt.Errorf("decode codex app-server message: %w", err)
			return
		}
		if err := validateAppServerMessage(msg); err != nil {
			_ = killProcessTree(cmd)
			_ = cmd.Wait()
			done <- err
			return
		}
		select {
		case events <- msg:
		case <-stop:
			_ = cmd.Wait()
			return
		}
	}
	err := scanner.Err()
	if waitErr := cmd.Wait(); err == nil {
		err = waitErr
	}
	done <- err
}

func validateAppServerMessage(msg appServerMessage) error {
	for _, prefix := range []string{"mcpServer/", "plugin/", "hook/"} {
		if strings.HasPrefix(msg.Method, prefix) {
			return fmt.Errorf("codex app-server attempted prohibited native integration %q", msg.Method)
		}
	}
	if msg.Method != "item/completed" {
		return nil
	}
	var payload struct {
		Item struct {
			Type string `json:"type"`
		} `json:"item"`
	}
	if err := json.Unmarshal(msg.Params, &payload); err != nil {
		return fmt.Errorf("decode codex completed item: %w", err)
	}
	switch payload.Item.Type {
	case "", "agentMessage", "reasoning":
		return nil
	default:
		return fmt.Errorf("codex app-server attempted prohibited native item %q", payload.Item.Type)
	}
}

func (p *CodexAppServerProvider) sendLocked(value any) error {
	if p.stdin == nil {
		return fmt.Errorf("codex app-server stdin is closed")
	}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = p.stdin.Write(data)
	return err
}

func (p *CodexAppServerProvider) nextMessageLocked(ctx context.Context) (appServerMessage, error) {
	events := p.events
	done := p.done
	select {
	case msg := <-events:
		return msg, nil
	case err := <-done:
		if err == nil {
			err = io.EOF
		}
		stderr := ""
		if p.stderr != nil {
			stderr = strings.TrimSpace(p.stderr.String())
		}
		if stderr != "" {
			return appServerMessage{}, fmt.Errorf("codex app-server stopped: %w: %s", err, stderr)
		}
		return appServerMessage{}, fmt.Errorf("codex app-server stopped: %w", err)
	case <-ctx.Done():
		return appServerMessage{}, ctx.Err()
	}
}

func (p *CodexAppServerProvider) waitForResponseLocked(
	ctx context.Context, id int64, onNotification func(appServerMessage),
) (appServerMessage, error) {
	want := strconv.FormatInt(id, 10)
	retained := 0
	for {
		msg, err := p.nextMessageLocked(ctx)
		if err != nil {
			return appServerMessage{}, err
		}
		retained += len(msg.ID) + len(msg.Method) + len(msg.Params) + len(msg.Result)
		if retained > p.options.MaxOutputBytes {
			return appServerMessage{}, ErrOutputLimit
		}
		if len(msg.ID) > 0 && msg.Method != "" {
			if err := p.rejectServerRequestLocked(msg); err != nil {
				return appServerMessage{}, err
			}
			continue
		}
		if strings.TrimSpace(string(msg.ID)) == want {
			if msg.Error != nil {
				return appServerMessage{}, fmt.Errorf("rpc %d: %s", msg.Error.Code, msg.Error.Message)
			}
			return msg, nil
		}
		if onNotification != nil {
			onNotification(msg)
		}
	}
}

func (p *CodexAppServerProvider) rejectServerRequestLocked(msg appServerMessage) error {
	var id any
	if err := json.Unmarshal(msg.ID, &id); err != nil {
		return err
	}
	return p.sendLocked(map[string]any{
		"id": id,
		"error": map[string]any{
			"code":    -32000,
			"message": "OpenFox denies backend-initiated approvals and input requests",
		},
	})
}

func disabledCodexNativeFeatures() []string {
	return []string{
		"shell_tool", "unified_exec", "js_repl", "browser_use", "computer_use",
		"apps", "plugins", "multi_agent", "code_mode", "code_mode_host", "hooks",
		"image_generation", "skill_mcp_dependency_install",
	}
}

func secureCodexThreadConfig(allowNativeTools bool) map[string]any {
	if allowNativeTools {
		return map[string]any{}
	}
	features := make(map[string]bool)
	for _, feature := range disabledCodexNativeFeatures() {
		features[feature] = false
	}
	return map[string]any{"features": features, "web_search": "disabled"}
}

func buildCodexPrompt(messages []Message, tools []ToolDefinition) string {
	p := &CodexCliProvider{}
	return p.buildPrompt(messages, tools)
}

func parseThreadID(raw json.RawMessage) (string, error) {
	var payload struct {
		Thread struct {
			ID string `json:"id"`
		} `json:"thread"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", fmt.Errorf("decode codex thread/start response: %w", err)
	}
	if payload.Thread.ID == "" {
		return "", fmt.Errorf("codex thread/start response omitted thread id")
	}
	return payload.Thread.ID, nil
}

func parseTurnID(raw json.RawMessage) string {
	var payload struct {
		Turn struct {
			ID string `json:"id"`
		} `json:"turn"`
	}
	_ = json.Unmarshal(raw, &payload)
	return payload.Turn.ID
}

func parseCompletedAgentMessage(raw json.RawMessage, threadID, turnID string) string {
	var payload struct {
		ThreadID string `json:"threadId"`
		TurnID   string `json:"turnId"`
		Item     struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"item"`
	}
	if json.Unmarshal(raw, &payload) != nil || payload.ThreadID != threadID ||
		(turnID != "" && payload.TurnID != turnID) || payload.Item.Type != "agentMessage" {
		return ""
	}
	return payload.Item.Text
}

func parseTurnCompleted(raw json.RawMessage, threadID string) (status, turnID, message string) {
	var payload struct {
		ThreadID string `json:"threadId"`
		Turn     struct {
			ID     string `json:"id"`
			Status string `json:"status"`
			Error  *struct {
				Message string `json:"message"`
			} `json:"error"`
		} `json:"turn"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil || payload.ThreadID != threadID {
		return "", "", ""
	}
	if payload.Turn.Error != nil {
		message = payload.Turn.Error.Message
	}
	return payload.Turn.Status, payload.Turn.ID, message
}

var _ AgentBackend = (*CodexAppServerProvider)(nil)
var _ LLMProvider = (*CodexAppServerProvider)(nil)
