package cliprovider

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const maxCodexAuthFileBytes = 1024 * 1024

// configureSterileCodexHome gives app-server an empty configuration root while
// copying only the opaque authentication file. User config.toml, MCP servers,
// plugins, hooks, skills, and session state are deliberately not inherited.
func configureSterileCodexHome(cmd *exec.Cmd, runtimeDir string) error {
	if cmd == nil {
		return fmt.Errorf("codex command is nil")
	}
	codexHome := filepath.Join(runtimeDir, "codex-home")
	if err := os.Mkdir(codexHome, 0o700); err != nil {
		return fmt.Errorf("create sterile CODEX_HOME: %w", err)
	}

	authPath, err := resolveCodexAuthPath()
	if err != nil {
		return err
	}
	if err := copyCodexAuthFile(authPath, filepath.Join(codexHome, "auth.json")); err != nil {
		return err
	}
	cmd.Env = replaceEnvironmentValue(cmd.Environ(), CodexHomeEnvVar, codexHome)
	return nil
}

func copyCodexAuthFile(source, destination string) error {
	sourceFile, err := os.Open(source)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open Codex authentication file: %w", err)
	}
	defer sourceFile.Close()
	info, err := sourceFile.Stat()
	if err != nil {
		return fmt.Errorf("stat Codex authentication file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > maxCodexAuthFileBytes {
		return fmt.Errorf("Codex authentication file must be regular and at most %d bytes", maxCodexAuthFileBytes)
	}
	destinationFile, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create sterile Codex authentication file: %w", err)
	}
	written, copyErr := io.Copy(destinationFile, io.LimitReader(sourceFile, maxCodexAuthFileBytes+1))
	closeErr := destinationFile.Close()
	if copyErr != nil {
		return fmt.Errorf("copy Codex authentication file: %w", copyErr)
	}
	if written > maxCodexAuthFileBytes {
		return fmt.Errorf("Codex authentication file exceeds %d bytes", maxCodexAuthFileBytes)
	}
	if closeErr != nil {
		return fmt.Errorf("close sterile Codex authentication file: %w", closeErr)
	}
	return nil
}

func replaceEnvironmentValue(environment []string, key, value string) []string {
	prefix := key + "="
	result := make([]string, 0, len(environment)+1)
	for _, item := range environment {
		if !strings.HasPrefix(item, prefix) {
			result = append(result, item)
		}
	}
	return append(result, prefix+value)
}
