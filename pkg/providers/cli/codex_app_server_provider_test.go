package cliprovider

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func createMockCodexAppServer(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("mock app-server scripts are not supported on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "codex")
	script := `#!/bin/sh
read -r initialize
echo '{"id":1,"result":{"userAgent":"mock"}}'
read -r initialized
read -r account_read
echo '{"id":2,"result":{"account":{"type":"chatgpt","email":"owner@example.test"},"requiresOpenaiAuth":true}}'
read -r thread_start
echo '{"id":3,"result":{"thread":{"id":"thread-openfox"}}}'
read -r turn_start
echo '{"method":"item/completed","params":{"threadId":"thread-openfox","turnId":"turn-openfox","item":{"type":"agentMessage","text":"secure app-server response"}}}'
echo '{"id":4,"result":{"turn":{"id":"turn-openfox"}}}'
echo '{"method":"turn/completed","params":{"threadId":"some-other-thread","turn":{"id":"wrong","status":"completed"}}}'
echo '{"method":"turn/completed","params":{"threadId":"thread-openfox","turn":{"id":"turn-openfox","status":"completed"}}}'
while read -r ignored; do :; done
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCodexAppServerProvider_RunTurn(t *testing.T) {
	p := NewCodexAppServerProvider(RuntimeOptions{
		Workspace: t.TempDir(), SubscriptionUse: "local-personal",
		OwnerChannel: "test", OwnerSenderID: "owner",
	})
	p.command = createMockCodexAppServer(t)
	t.Cleanup(p.Close)

	ctx := WithAgentBackendPrincipal(context.Background(), "test", "owner")
	result, err := p.RunTurn(ctx, AgentTurnRequest{Prompt: "hello"})
	if err != nil {
		t.Fatalf("RunTurn() error = %v", err)
	}
	if result.Content != "secure app-server response" {
		t.Errorf("Content = %q", result.Content)
	}
	if result.ThreadID != "thread-openfox" || result.TurnID != "turn-openfox" {
		t.Errorf("IDs = %q/%q", result.ThreadID, result.TurnID)
	}
}

func TestCodexAppServerProvider_RejectsUnsafePolicy(t *testing.T) {
	p := NewCodexAppServerProvider(RuntimeOptions{
		Workspace:      t.TempDir(),
		Sandbox:        "danger-full-access",
		ApprovalPolicy: "never",
	})
	_, err := p.RunTurn(context.Background(), AgentTurnRequest{Prompt: "hello"})
	if err == nil || !strings.Contains(err.Error(), "unsafe agent backend sandbox") {
		t.Fatalf("RunTurn() error = %v, want unsafe sandbox rejection", err)
	}
}

func TestCodexAppServerProvider_StartRejectsUnauthenticatedCLI(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mock app-server scripts are not supported on Windows")
	}
	dir := t.TempDir()
	command := filepath.Join(dir, "codex")
	script := `#!/bin/sh
read -r initialize
echo '{"id":1,"result":{"userAgent":"mock"}}'
read -r initialized
read -r account_read
echo '{"id":2,"result":{"account":null,"requiresOpenaiAuth":true}}'
while read -r ignored; do :; done
`
	if err := os.WriteFile(command, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	p := NewCodexAppServerProvider(RuntimeOptions{Workspace: t.TempDir()})
	p.command = command
	t.Cleanup(p.Close)

	err := p.Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), "not authenticated") {
		t.Fatalf("Start() error = %v, want authentication rejection", err)
	}
}

func TestCodexAppServerCapabilitiesDefaultToNoNativeTools(t *testing.T) {
	p := NewCodexAppServerProvider(RuntimeOptions{Workspace: t.TempDir()})
	caps := p.Capabilities()
	if !caps.PersistentProcess || !caps.StreamingEvents || caps.NativeTools {
		t.Fatalf("Capabilities() = %+v", caps)
	}
	if caps.Sandbox != "read-only" {
		t.Errorf("Sandbox = %q, want read-only", caps.Sandbox)
	}
}

func TestValidateAppServerMessageRejectsNativeIntegration(t *testing.T) {
	for _, msg := range []appServerMessage{
		{Method: "mcpServer/startupStatus/updated"},
		{Method: "item/completed", Params: []byte(`{"item":{"type":"commandExecution"}}`)},
	} {
		if err := validateAppServerMessage(msg); err == nil {
			t.Fatalf("validateAppServerMessage(%q) accepted native integration", msg.Method)
		}
	}
}
