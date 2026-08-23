package cliprovider

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestCodexAppServerProvider_Integration(t *testing.T) {
	if os.Getenv("OPENFOX_CODEX_APP_SERVER_INTEGRATION") != "1" {
		t.Skip("set OPENFOX_CODEX_APP_SERVER_INTEGRATION=1 to use the authenticated local Codex CLI")
	}
	p := NewCodexAppServerProvider(RuntimeOptions{
		Workspace:          t.TempDir(),
		SubscriptionUse:    "local-personal",
		OwnerChannel:       "integration",
		OwnerSenderID:      "owner",
		MaxConcurrentCalls: 1,
		MaxOutputBytes:     1024 * 1024,
		Timeout:            2 * time.Minute,
	})
	t.Cleanup(p.Close)

	ctx := WithAgentBackendPrincipal(context.Background(), "integration", "owner")
	result, err := p.RunTurn(ctx, AgentTurnRequest{
		Prompt: "Do not use any tool. Reply with exactly OPENFOX_APP_SERVER_OK.",
	})
	if err != nil {
		t.Fatalf("RunTurn() error = %v", err)
	}
	if strings.TrimSpace(result.Content) != "OPENFOX_APP_SERVER_OK" {
		t.Fatalf("RunTurn() content = %q", result.Content)
	}
}
