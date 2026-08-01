package onboard

import (
	"github.com/spf13/cobra"

	openfox "github.com/tosnetwork/openfox"
)

var embeddedFiles = openfox.OnboardWorkspace

func NewOnboardCommand() *cobra.Command {
	var encrypt bool

	cmd := &cobra.Command{
		Use:     "onboard",
		Aliases: []string{"o"},
		Short:   "Initialize openfox configuration and workspace",
		// Run without subcommands → original onboard flow
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) == 0 {
				onboard(encrypt)
			} else {
				_ = cmd.Help()
			}
		},
	}

	cmd.Flags().BoolVar(&encrypt, "enc", false,
		"Enable credential encryption (generates SSH key and prompts for passphrase)")

	return cmd
}
