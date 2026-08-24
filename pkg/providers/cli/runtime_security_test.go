package cliprovider

import (
	"context"
	"errors"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func TestRunCommandBoundedRejectsOversizedOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell test is not supported on Windows")
	}
	cmd := exec.CommandContext(context.Background(), "sh", "-c", "yes x | head -c 8192")
	stdout, _, err := runCommandBounded(context.Background(), cmd, nil, 4096)
	if !errors.Is(err, ErrOutputLimit) {
		t.Fatalf("error = %v, want ErrOutputLimit", err)
	}
	if len(stdout) != 4096 {
		t.Fatalf("retained stdout = %d bytes, want 4096", len(stdout))
	}
}

func TestRunCommandBoundedSharesBudgetAcrossStreams(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell test is not supported on Windows")
	}
	cmd := exec.CommandContext(
		context.Background(),
		"sh",
		"-c",
		"head -c 3072 /dev/zero | tr '\\0' o; head -c 3072 /dev/zero | tr '\\0' e >&2",
	)
	stdout, stderr, err := runCommandBounded(context.Background(), cmd, nil, 4096)
	if !errors.Is(err, ErrOutputLimit) {
		t.Fatalf("error = %v, want ErrOutputLimit", err)
	}
	if got := len(stdout) + len(stderr); got != 4096 {
		t.Fatalf("total retained output = %d, want 4096", got)
	}
	if strings.Contains(stdout+stderr, "unexpected") {
		t.Fatal("unreachable")
	}
}

func TestRuntimeOptionsAuthorizeOnlyConfiguredOwner(t *testing.T) {
	options := RuntimeOptions{
		SubscriptionUse: "local-personal",
		OwnerChannel:    "telegram",
		OwnerSenderID:   "42",
	}
	if err := options.authorizePrincipal(context.Background()); err == nil {
		t.Fatal("missing trusted principal was accepted")
	}
	owner := WithAgentBackendPrincipal(context.Background(), "telegram", "42")
	if err := options.authorizePrincipal(owner); err != nil {
		t.Fatalf("configured owner rejected: %v", err)
	}
	other := WithAgentBackendPrincipal(context.Background(), "telegram", "7")
	if err := options.authorizePrincipal(other); err == nil {
		t.Fatal("different sender was accepted")
	}
	if err := options.authorizePrincipal(WithInternalAgentBackendPrincipal(context.Background())); err == nil {
		t.Fatal("internal automation was accepted without allow_internal")
	}
	options.AllowInternal = true
	if err := options.authorizePrincipal(WithInternalAgentBackendPrincipal(context.Background())); err != nil {
		t.Fatalf("explicitly allowed internal automation rejected: %v", err)
	}
}

func TestRuntimeOptionsRequireCanonicalWorkspace(t *testing.T) {
	options := RuntimeOptions{Workspace: ""}.normalized()
	if _, err := options.canonicalWorkspace(); err == nil {
		t.Fatal("canonicalWorkspace() accepted an empty workspace")
	}
}

func TestRemoveEnvironmentPrefixes(t *testing.T) {
	environment := removeEnvironmentPrefixes([]string{
		"PATH=/bin", "ANTHROPIC_API_KEY=secret", "anthropic_auth_token=secret",
		"CLAUDE_CODE_USE_BEDROCK=1", "CLAUDE_CONFIG_DIR=/tmp/hostile", "HTTPS_PROXY=https://proxy.test",
	}, "ANTHROPIC_", "CLAUDE_")
	joined := strings.Join(environment, "\n")
	if strings.Contains(strings.ToUpper(joined), "ANTHROPIC_") ||
		strings.Contains(strings.ToUpper(joined), "CLAUDE_") {
		t.Fatalf("credential override remained in environment: %q", joined)
	}
	if !strings.Contains(joined, "PATH=/bin") || !strings.Contains(joined, "HTTPS_PROXY=https://proxy.test") {
		t.Fatalf("required process environment was removed: %q", joined)
	}
}
