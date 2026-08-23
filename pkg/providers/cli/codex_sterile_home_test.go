package cliprovider

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestConfigureSterileCodexHomeCopiesOnlyAuthentication(t *testing.T) {
	sourceHome := t.TempDir()
	if err := os.WriteFile(filepath.Join(sourceHome, "auth.json"), []byte(`{"auth":"opaque"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceHome, "config.toml"), []byte(`[mcp_servers.evil]`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(CodexHomeEnvVar, sourceHome)
	runtimeDir := t.TempDir()
	cmd := exec.Command("codex")
	cmd.Env = append(os.Environ(),
		"OPENAI_API_KEY=untrusted", "AZURE_OPENAI_API_KEY=untrusted", "CODEX_API_KEY=untrusted",
	)
	if err := configureSterileCodexHome(cmd, runtimeDir); err != nil {
		t.Fatal(err)
	}
	sterileHome := filepath.Join(runtimeDir, "codex-home")
	data, err := os.ReadFile(filepath.Join(sterileHome, "auth.json"))
	if err != nil || string(data) != `{"auth":"opaque"}` {
		t.Fatalf("sterile auth = %q, %v", data, err)
	}
	if _, err := os.Stat(filepath.Join(sterileHome, "config.toml")); !os.IsNotExist(err) {
		t.Fatalf("user config leaked into sterile home: %v", err)
	}
	for _, item := range cmd.Env {
		upper := strings.ToUpper(item)
		if strings.HasPrefix(upper, "OPENAI_") || strings.HasPrefix(upper, "AZURE_OPENAI_") ||
			strings.HasPrefix(upper, "CODEX_API_KEY=") {
			t.Fatalf("credential override leaked into Codex environment: %q", item)
		}
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(sterileHome, "auth.json"))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("sterile auth permissions = %v", info.Mode().Perm())
		}
	}
}

func TestReplaceEnvironmentValueRemovesCaseVariants(t *testing.T) {
	environment := replaceEnvironmentValue([]string{
		"PATH=/bin", "codex_home=/tmp/untrusted", "CODEX_HOME=/tmp/old",
	}, "CODEX_HOME", "/tmp/sterile")
	joined := strings.Join(environment, "\n")
	if strings.Count(strings.ToUpper(joined), "CODEX_HOME=") != 1 ||
		!strings.Contains(joined, "CODEX_HOME=/tmp/sterile") {
		t.Fatalf("environment replacement was not case-insensitive: %q", joined)
	}
}
