package cliprovider

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
