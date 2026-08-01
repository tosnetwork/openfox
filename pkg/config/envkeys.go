// OpenFox - Ultra-lightweight personal AI agent
// License: MIT
//
// Copyright (c) 2026 OpenFox contributors

package config

import (
	"os"
	"path/filepath"

	"github.com/tosnetwork/openfox/pkg"
)

// Runtime environment variable keys for the openfox process.
// These control the location of files and binaries at runtime and are read
// directly via os.Getenv / os.LookupEnv. All openfox-specific keys use the
// OPENFOX_ prefix. Reference these constants instead of inline string
// literals to keep all supported knobs visible in one place and to prevent
// typos.
const (
	// EnvHome overrides the base directory for all openfox data
	// (config, workspace, skills, auth store, …).
	// Default: ~/.openfox
	EnvHome = "OPENFOX_HOME"

	// EnvConfig overrides the full path to the JSON config file.
	// Default: $OPENFOX_HOME/config.json
	EnvConfig = "OPENFOX_CONFIG"

	// EnvBuiltinSkills overrides the directory from which built-in
	// skills are loaded.
	// Default: <cwd>/skills
	EnvBuiltinSkills = "OPENFOX_BUILTIN_SKILLS"

	// EnvBinary overrides the path to the openfox executable.
	// Used by the web launcher when spawning the gateway subprocess.
	// Default: resolved from the same directory as the current executable.
	EnvBinary = "OPENFOX_BINARY"

	// EnvGatewayHost overrides the host address for the gateway server.
	// Default: "localhost"
	EnvGatewayHost = "OPENFOX_GATEWAY_HOST"
)

func GetHome() string {
	homePath, _ := os.UserHomeDir()
	if openfoxHome := os.Getenv(EnvHome); openfoxHome != "" {
		homePath = openfoxHome
	} else if homePath != "" {
		homePath = filepath.Join(homePath, pkg.DefaultOpenFoxHome)
	}
	if homePath == "" {
		homePath = "."
	}
	return homePath
}
