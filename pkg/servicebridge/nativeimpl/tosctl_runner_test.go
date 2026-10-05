package nativeimpl

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func secureFiles(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	binary := filepath.Join(dir, "tosctl")
	config := filepath.Join(dir, "config.json")
	if err := os.WriteFile(binary, []byte("#!/bin/true\n"), 0o700); err != nil {
		t.Fatalf("write binary: %v", err)
	}
	if err := os.WriteFile(config, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	// Defend against umask leaving unexpected bits.
	if err := os.Chmod(binary, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(config, 0o600); err != nil {
		t.Fatal(err)
	}
	return binary, config
}

func TestPinnedReleaseRunnerRejectsExecutableSubstitutionAndPinsConfig(t *testing.T) {
	binary, config := secureFiles(t)
	if err := os.WriteFile(config, []byte(`{"network":"original"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	runner, err := newPinnedReleaseRunner(binary, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, []byte(`{"network":"substituted"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if string(runner.config) != `{"network":"original"}` {
		t.Fatal("release runner did not pin configuration bytes")
	}
	if err := os.WriteFile(binary, []byte("#!/bin/false\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := runner.run(context.Background(), binary, "wallet", "ls"); err == nil ||
		!strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("substituted executable was not rejected: %v", err)
	}
}
