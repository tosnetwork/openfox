package version

import (
	"github.com/spf13/cobra"

	"github.com/tosnetwork/openfox/cmd/openfox/internal"
	"github.com/tosnetwork/openfox/cmd/openfox/internal/cliui"
	"github.com/tosnetwork/openfox/pkg/config"
)

func NewVersionCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "version",
		Aliases: []string{"v"},
		Short:   "Show version information",
		Run: func(_ *cobra.Command, _ []string) {
			printVersion()
		},
	}

	return cmd
}

func printVersion() {
	build, goVer := config.FormatBuildInfo()
	cliui.PrintVersion(internal.Logo, "openfox "+config.FormatVersion(), build, goVer)
}
