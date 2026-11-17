package earning

import (
	"errors"
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
	contact := &cobra.Command{
		Use: "contact", Short: "Export, import or remove a chat contact", Args: cobra.NoArgs,
	}
	contact.AddCommand(chatContactExportCommand(), chatContactImportCommand(), chatContactRemoveCommand())
	command.AddCommand(chatCardCommand("init", "Issue the chat key and card and publish the card to the Messenger "+
		"daemon's card path"), chatCardCommand("republish", "Rotate the chat keys and republish the current chat "+
		"card"), chatStatusCommand(), contact, chatRoomCommand(), chatInviteCommand(), chatOwnerCommand())
	return command
}

// chatOwnerLong explains the owner ceremony every room and invite decision
// takes.
const chatOwnerLong = "Prepares an owner decision for the Messenger daemon's owner socket (chat.owner_socket) " +
	"and writes it to --out, a new owner-only file. The owner signs it away from the Agent runtime, for example " +
	"with `tos-messenger-owner sign -key FILE -decision DECISION -out SIGNED`, and submits it with `openfox chat " +
	"owner submit --decision SIGNED` within two minutes. openfox never reads the owner's key."

func chatRoomCommand() *cobra.Command {
	command := &cobra.Command{
		Use: "room", Short: "Manage private Messenger rooms through the daemon's owner socket", Args: cobra.NoArgs,
	}
	command.AddCommand(
		chatRoomDecisionCommand(
			servicebridge.ChatRoomCreate,
			"Found a private room with this node as its authority",
			"",
		),
		chatRoomDecisionCommand(servicebridge.ChatRoomAdd, "Add an Agent to a room this node is the authority of",
			"agent"),
		chatRoomDecisionCommand(servicebridge.ChatRoomRemove, "Remove a member from a room this node is the "+
			"authority of", "agent"),
		chatRoomDecisionCommand(servicebridge.ChatRoomJoin, "Join a room an authority invited this node to",
			"authority"),
		chatRoomListCommand(),
	)
	return command
}

// chatRoomDecisionCommand prepares one room membership decision; agentFlag
// names the flag of the Agent it takes, if any.
func chatRoomDecisionCommand(op servicebridge.ChatRoomOp, short, agentFlag string) *cobra.Command {
	var path, room, agent, out string
	command := &cobra.Command{
		Use: string(op), Short: short, Long: short + ". " + chatOwnerLong, Args: cobra.NoArgs, SilenceUsage: true,
		RunE: func(command *cobra.Command, _ []string) error {
			prepared, err := servicebridge.ChatRoomPrepare(command.Context(), path, op, room, agent, out)
			if err != nil {
				return err
			}
			return printJSON(command.OutOrStdout(), prepared)
		},
	}
	railConfigFlag(command, &path)
	command.Flags().StringVar(&room, "room", "", "the room id (room_<64 hex>)")
	_ = command.MarkFlagRequired("room")
	if agentFlag != "" {
		usage := "the member Agent id"
		if agentFlag == "authority" {
			usage = "the inviting authority's Agent id"
		}
		command.Flags().StringVar(&agent, agentFlag, "", usage)
		_ = command.MarkFlagRequired(agentFlag)
	}
	command.Flags().StringVar(&out, "out", "", "the new owner-only file the prepared decision is written to")
	_ = command.MarkFlagRequired("out")
	return command
}

func chatRoomListCommand() *cobra.Command {
	var path string
	command := &cobra.Command{
		Use: "list", Short: "List the daemon's private rooms and pending room invites", Args: cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(command *cobra.Command, _ []string) error {
			rooms, err := servicebridge.ChatRoomList(command.Context(), path)
			if err != nil {
				return err
			}
			return printJSON(command.OutOrStdout(), rooms)
		},
	}
	railConfigFlag(command, &path)
	return command
}

func chatInviteCommand() *cobra.Command {
	command := &cobra.Command{
		Use: "invite", Short: "Present invites other Agents' owners issued to this node", Args: cobra.NoArgs,
	}
	var path, recipient, tokenFile, out string
	var expiresAt uint64
	present := &cobra.Command{
		Use:   "present",
		Short: "Prepare the decision that makes every delivery to an Agent carry its owner's invite",
		Long: "Prepare the invites.present decision: every delivery to the recipient Agent then carries the " +
			"invite its owner issued, sealed, until one is accepted. The invite_ token is a bearer: it is read " +
			"from an owner-only (0600) file, never from the command line. " + chatOwnerLong,
		Args: cobra.NoArgs, SilenceUsage: true,
		RunE: func(command *cobra.Command, _ []string) error {
			prepared, err := servicebridge.ChatInvitePresent(command.Context(), path, recipient,
				servicebridge.ChatInvite{TokenFile: tokenFile, ExpiresAtUnix: expiresAt}, out, time.Now())
			if err != nil {
				return err
			}
			return printJSON(command.OutOrStdout(), prepared)
		},
	}
	railConfigFlag(present, &path)
	present.Flags().StringVar(&recipient, "recipient", "", "the Agent whose owner issued the invite")
	present.Flags().StringVar(&tokenFile, "token-file", "", "owner-only (0600) file holding the invite_ token")
	present.Flags().Uint64Var(&expiresAt, "expires-at", 0, "the invite's absolute Unix expiry")
	present.Flags().StringVar(&out, "out", "", "the new owner-only file the prepared decision is written to")
	for _, name := range []string{"recipient", "token-file", "expires-at", "out"} {
		_ = present.MarkFlagRequired(name)
	}
	command.AddCommand(present)
	return command
}

func chatOwnerCommand() *cobra.Command {
	command := &cobra.Command{
		Use: "owner", Short: "Submit signed owner decisions to the daemon's owner socket", Args: cobra.NoArgs,
	}
	var path, decision string
	submit := &cobra.Command{
		Use:   "submit",
		Short: "Submit a signed room or invite decision",
		Long: "Submit a decision `chat room` or `chat invite` prepared, once the owner signed it. The daemon " +
			"verifies the owner's signature and spends the decision's single-use challenge.",
		Args: cobra.NoArgs, SilenceUsage: true,
		RunE: func(command *cobra.Command, _ []string) error {
			submitted, err := servicebridge.ChatOwnerSubmit(command.Context(), path, decision)
			if err != nil {
				return err
			}
			return printJSON(command.OutOrStdout(), submitted)
		},
	}
	railConfigFlag(submit, &path)
	submit.Flags().StringVar(&decision, "decision", "", "the signed decision file")
	_ = submit.MarkFlagRequired("decision")
	command.AddCommand(submit)
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

func chatContactRemoveCommand() *cobra.Command {
	var path string
	command := &cobra.Command{
		Use:   "remove <agent>",
		Short: "Remove a contact's stored chat card and the contact file its import wrote",
		Long: "Remove a contact's stored chat cards and the contact file its import wrote. This stops only this " +
			"node from sealing to the peer: no copy is carried to it and no delivery ack goes back to it. It does " +
			"not remove the peer's committed relay evidence in the Messenger daemon, which still treats the peer " +
			"as admitted and accepts its copies. To stop receiving from the peer, change the daemon's admission " +
			"policy.",
		Args: cobra.ExactArgs(1), SilenceUsage: true,
		RunE: func(command *cobra.Command, args []string) error {
			removed, err := servicebridge.ChatContactRemove(path, args[0])
			if err != nil {
				return err
			}
			return printJSON(command.OutOrStdout(), removed)
		},
	}
	railConfigFlag(command, &path)
	return command
}

func chatContactImportCommand() *cobra.Command {
	var path, file, invite, inviteOut string
	var inviteExpiresAt uint64
	command := &cobra.Command{
		Use: "import", Short: "Verify and import a peer's contact file (admits that peer)",
		Long: "Verify and import a peer's contact file (admits that peer). With --invite, the invite the peer's " +
			"owner issued to this node is presented with it: its invites.present decision is prepared into " +
			"--invite-out for the owner to sign and submit (`openfox chat owner submit`).",
		Args: cobra.NoArgs, SilenceUsage: true,
		RunE: func(command *cobra.Command, _ []string) error {
			var imported *servicebridge.ChatContactImported
			var err error
			if invite == "" {
				if inviteExpiresAt != 0 || inviteOut != "" {
					return errors.New("--invite-expires-at and --invite-out need --invite")
				}
				imported, err = servicebridge.ChatContactImport(command.Context(), path, file, time.Now)
			} else {
				imported, err = servicebridge.ChatContactImportWithInvite(command.Context(), path, file,
					servicebridge.ChatInvite{TokenFile: invite, ExpiresAtUnix: inviteExpiresAt}, inviteOut, time.Now)
			}
			if err != nil {
				return err
			}
			return printJSON(command.OutOrStdout(), imported)
		},
	}
	railConfigFlag(command, &path)
	command.Flags().StringVar(&file, "file", "", "the peer's contact file")
	_ = command.MarkFlagRequired("file")
	command.Flags().StringVar(&invite, "invite", "", "owner-only (0600) file holding the invite_ token the peer's "+
		"owner issued to this node")
	command.Flags().Uint64Var(&inviteExpiresAt, "invite-expires-at", 0, "the invite's absolute Unix expiry")
	command.Flags().StringVar(&inviteOut, "invite-out", "", "the new owner-only file the invite decision is "+
		"written to")
	command.MarkFlagsRequiredTogether("invite", "invite-expires-at", "invite-out")
	return command
}
