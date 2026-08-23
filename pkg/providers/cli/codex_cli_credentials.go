package cliprovider

import (
	"fmt"
	"os"
	"path/filepath"
)

// CodexHomeEnvVar is the environment variable that overrides the Codex CLI
// home directory when resolving the codex auth.json credentials file.
// Default: ~/.codex
const CodexHomeEnvVar = "CODEX_HOME"

func resolveCodexAuthPath() (string, error) {
	codexHome := os.Getenv(CodexHomeEnvVar)
	if codexHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("getting home dir: %w", err)
		}
		codexHome = filepath.Join(home, ".codex")
	}
	return filepath.Join(codexHome, "auth.json"), nil
}
