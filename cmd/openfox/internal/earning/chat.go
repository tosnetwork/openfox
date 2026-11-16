package earning

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/tosnetwork/openfox/pkg/servicebridge"
)

// chatCommand is the OpenFox half of Messenger relay carriage: the chat key
// and card, contact files and the chat lane's state. `service serve` runs
// the carriage itself.
func chatCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "chat",
		Short: "Carry private Messenger chat between Agents over the packet relays",
		Args:  cobra.NoArgs,
	}
	contact := &cobra.Command{Use: "contact", Short: "Export or import a chat contact file", Args: cobra.NoArgs}
	contact.AddCommand(chatContactExportCommand(), chatContactImportCommand())
	command.AddCommand(chatCardCommand("init", "Issue the chat key and card and publish the card to the Messenger "+
		"daemon's card path"), chatCardCommand("republish", "Rotate the chat keys and republish the current chat "+
		"card"), chatStatusCommand(), contact)
	return command
}

func chatCardCommand(name, short string) *cobra.Command {
	var path string
	command := &cobra.Command{
		Use: name, Short: short, Args: cobra.NoArgs, SilenceUsage: true,
		RunE: func(command *cobra.Command, _ []string) error {
			result, err := servicebridge.ChatRepublish(command.Context(), path, setupEnv(command))
			if err != nil {
				return err
			}
			return printJSON(command.OutOrStdout(), result)
		},
	}
	railConfigFlag(command, &path)
	return command
}

func chatStatusCommand() *cobra.Command {
	var path string
	command := &cobra.Command{
		Use: "status", Short: "Show the chat key, the held chat cards of peers and the chat journal",
		Args: cobra.NoArgs, SilenceUsage: true,
		RunE: func(command *cobra.Command, _ []string) error {
			report, err := servicebridge.ReadChatStatus(path, time.Now())
			if err != nil {
				return err
			}
			return printJSON(command.OutOrStdout(), report)
		},
	}
	railConfigFlag(command, &path)
	return command
}

func chatContactExportCommand() *cobra.Command {
	var path, out string
	command := &cobra.Command{
		Use: "export", Short: "Write this node's contact file (relay identity evidence and chat card)",
		Args: cobra.NoArgs, SilenceUsage: true,
		RunE: func(command *cobra.Command, _ []string) error {
			if _, err := servicebridge.ChatContactExport(path, out, time.Now()); err != nil {
				return err
			}
			return printJSON(command.OutOrStdout(), map[string]string{
				"contact_file": out,
				"schema":       servicebridge.ChatContactSchema,
			})
		},
	}
	railConfigFlag(command, &path)
	command.Flags().StringVar(&out, "out", "", "where to write the contact file")
	_ = command.MarkFlagRequired("out")
	return command
}

func chatContactImportCommand() *cobra.Command {
	var path, file string
	command := &cobra.Command{
		Use: "import", Short: "Verify and import a peer's contact file (admits that peer)",
		Args: cobra.NoArgs, SilenceUsage: true,
		RunE: func(command *cobra.Command, _ []string) error {
			imported, err := servicebridge.ChatContactImport(command.Context(), path, file, time.Now)
			if err != nil {
				return err
			}
			return printJSON(command.OutOrStdout(), imported)
		},
	}
	railConfigFlag(command, &path)
	command.Flags().StringVar(&file, "file", "", "the peer's contact file")
	_ = command.MarkFlagRequired("file")
	return command
}
