package cliprovider

import (
	"context"
	"errors"
	"os/exec"
	"runtime"
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

func TestRuntimeOptionsRequireCanonicalWorkspace(t *testing.T) {
	options := RuntimeOptions{Workspace: ""}.normalized()
	if _, err := options.canonicalWorkspace(); err == nil {
		t.Fatal("canonicalWorkspace() accepted an empty workspace")
	}
}
