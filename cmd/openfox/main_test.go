package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tosnetwork/openfox/cmd/openfox/internal"
	"github.com/tosnetwork/openfox/pkg/config"
)

func TestNewOpenfoxCommand(t *testing.T) {
	cmd := NewOpenfoxCommand()

	require.NotNil(t, cmd)

	short := fmt.Sprintf("%s OpenFox — personal AI assistant", internal.Logo)
	longHas := strings.Contains(cmd.Long, config.FormatVersion())

	assert.Equal(t, "openfox", cmd.Use)
	assert.Equal(t, short, cmd.Short)
	assert.True(t, longHas)

	assert.True(t, cmd.HasSubCommands())
	assert.True(t, cmd.HasAvailableSubCommands())

	assert.True(t, cmd.PersistentFlags().Lookup("no-color") != nil)

	assert.Nil(t, cmd.Run)
	assert.Nil(t, cmd.RunE)

	assert.NotNil(t, cmd.PersistentPreRun)
	assert.Nil(t, cmd.PersistentPostRun)

	allowedCommands := []string{
		"agent",
		"auth",
		"capability",
		"config",
		"cron",
		"earning",
		"gateway",
		"mcp",
		"migrate",
		"model",
		"onboard",
		"skills",
		"status",
		"update",
		"version",
	}

	subcommands := cmd.Commands()
	assert.Len(t, subcommands, len(allowedCommands))

	for _, subcmd := range subcommands {
		found := slices.Contains(allowedCommands, subcmd.Name())
		assert.True(t, found, "unexpected subcommand %q", subcmd.Name())

		assert.False(t, subcmd.Hidden)
	}
}

// TestMain lets a test run the real main() in a child process.
func TestMain(m *testing.M) {
	if os.Getenv("OPENFOX_TEST_RUN_MAIN") == "1" {
		os.Args = []string{"openfox", "version"}
		main()
		return
	}
	os.Exit(m.Run())
}

func TestStandardOutputThatIsNotATerminalCarriesNoBanner(t *testing.T) {
	executable, err := os.Executable()
	require.NoError(t, err)
	child := exec.Command(executable)
	child.Env = append(os.Environ(), "OPENFOX_TEST_RUN_MAIN=1", "TZ=UTC")
	var stdout, stderr bytes.Buffer
	child.Stdout, child.Stderr = &stdout, &stderr
	require.NoError(t, child.Run())
	require.NotEmpty(t, stdout.String(), "the command printed nothing, so the check below proves nothing")
	assert.NotContains(t, stdout.String(), "██", "a piped standard output starts with the banner")
	assert.NotContains(t, stdout.String(), "\x1b[", "a piped standard output carries terminal escapes")
	assert.NotContains(t, stdout.String(), "TZ environment", "a diagnostic went to standard output")
	assert.Contains(t, stderr.String(), "TZ environment")

	assert.Equal(t, "", startupBanner(false, false))
	assert.Equal(t, "", startupBanner(false, true))
	assert.Equal(t, banner, startupBanner(true, false))
	assert.Equal(t, plainBanner, startupBanner(true, true))
}
