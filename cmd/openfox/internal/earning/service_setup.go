package earning

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/tosnetwork/openfox/pkg/servicebridge"
)

// setupEnv reports previews and progress on stderr; stdout carries only
// the JSON result.
func setupEnv(command *cobra.Command) servicebridge.SetupEnv {
	stderr := command.ErrOrStderr()
	return servicebridge.SetupEnv{Report: func(line string) { fmt.Fprintln(stderr, line) }}
}

// finishSetup prints the report and keeps the command's error, so a run
// that stopped still shows what it did and what it planned.
func finishSetup(command *cobra.Command, report any, err error) error {
	if printErr := printJSON(command.OutOrStdout(), report); printErr != nil {
		return errors.Join(err, printErr)
	}
	return err
}

func parseDirectPeers(values []string) (map[string]string, error) {
	peers := map[string]string{}
	for _, value := range values {
		agent, socket, found := strings.Cut(value, "=")
		if !found || agent == "" || socket == "" {
			return nil, errors.New("--direct-peer takes agent_<hex>=<absolute socket path>")
		}
		if _, duplicate := peers[agent]; duplicate {
			return nil, errors.New("--direct-peer names an Agent twice")
		}
		peers[agent] = socket
	}
	return peers, nil
}

func tosFlag(name, value string, allowEmpty bool) (uint64, error) {
	if value == "" && allowEmpty {
		return 0, nil
	}
	amount, err := servicebridge.ParseTOSAmount(value)
	if err != nil {
		return 0, fmt.Errorf("--%s: %w", name, err)
	}
	return amount, nil
}

func serviceInitCommand() *cobra.Command {
	var in servicebridge.InitInput
	var directPeers, allowProviders []string
	var perPurchase, inWindow, refundReserve, confirmAbove string
	var windowSeconds int64
	var maxOpen int
	var gatewayURL, gatewayToken, gatewayCA, callerID string
	var chat servicebridge.ChatConfig
	command := &cobra.Command{
		Use:   "init",
		Short: "Establish this node's Agent identity and write its rail configuration",
		Long: "Pin tosctl, resolve the owner wallet, create the packet controller if the vault has none, register " +
			"the node's Agent in the Native Registry and write the complete rail configuration. The network " +
			"domain and the registry code hash are derived by tosctl from the chain global configuration and " +
			"cross-checked against the registry code file and the RPC endpoints. OpenFox holds no key: every " +
			"signature and send is made by the pinned tosctl. Without --yes nothing is created, signed or sent " +
			"and the plan is printed. Re-running is safe: finalized state is read first and an interrupted run " +
			"resumes.",
		Args: cobra.NoArgs, SilenceUsage: true,
		RunE: func(command *cobra.Command, _ []string) error {
			peers, err := parseDirectPeers(directPeers)
			if err != nil {
				return err
			}
			in.DirectPeers = peers
			if len(allowProviders) > 0 {
				buyer := &servicebridge.BuyerNode{
					GatewayURL:       gatewayURL,
					GatewayTokenFile: gatewayToken,
					GatewayCAFile:    gatewayCA,
					CallerID:         callerID,
					Policy: servicebridge.PolicyConfig{
						WindowSeconds: windowSeconds, MaxOpenPurchases: maxOpen, AllowedProviders: allowProviders,
					},
				}
				for _, amount := range []struct {
					name, value string
					target      *string
					optional    bool
				}{
					{"max-per-purchase", perPurchase, &buyer.Policy.MaxCommittedPerPurchase, false},
					{"max-in-window", inWindow, &buyer.Policy.MaxCommittedInWindow, false},
					{"refund-reserve", refundReserve, &buyer.Policy.RefundReserve, false},
					{"confirm-above", confirmAbove, &buyer.Policy.ConfirmAbove, true},
				} {
					if amount.value == "" && amount.optional {
						continue
					}
					nano, amountErr := tosFlag(amount.name, amount.value, false)
					if amountErr != nil {
						return amountErr
					}
					*amount.target = fmt.Sprint(nano)
				}
				in.Buyer = buyer
			} else if command.Flags().Changed("gateway-url") || command.Flags().Changed("max-per-purchase") ||
				command.Flags().Changed("max-in-window") || command.Flags().Changed("confirm-above") {
				return errors.New("a buyer section needs at least one --allow-provider: the spending policy is an " +
					"allow-list")
			}
			if chat.MessengerCarrierSocket != "" {
				in.Chat = &chat
			} else if len(chat.RelayURLs) > 0 || chat.CarrierSocket != "" || chat.CardPath != "" ||
				chat.EvidenceExportDir != "" || chat.ContactDir != "" || chat.TimeoutSeconds != 0 {
				return errors.New("the chat section needs --messenger-carrier-socket")
			}
			result, err := servicebridge.RunInit(command.Context(), in, setupEnv(command))
			if result == nil {
				return err
			}
			return finishSetup(command, result, err)
		},
	}
	flags := command.Flags()
	flags.StringVar(&in.RailConfigPath, "rail-config", "", "where to write the owner-private rail configuration")
	flags.StringVar(&in.StateDir, "state-dir", "", "the node's owner-private state directory")
	flags.StringArrayVar(&in.RPCEndpoints, "rpc", nil, "chain RPC endpoint (repeat: 3 to 8 distinct endpoints)")
	flags.IntVar(&in.Quorum, "quorum", 0, "endpoint quorum (default: a strict majority)")
	flags.StringVar(&in.GlobalConfigFile, "global-config", "", "chain global configuration file (JSON)")
	flags.StringVar(&in.NetworkLabel, "network-label", "", "network label of the identity domain (tos:global-id:<n>)")
	flags.StringVar(&in.TOSCTLBinary, "tosctl", "", "tosctl binary")
	flags.StringVar(&in.TOSCTLSHA256, "tosctl-sha256", "", "SHA-256 the tosctl binary must have (default: pin the "+
		"binary found, trust on first use)")
	flags.StringVar(&in.TOSCTLConfigPath, "tosctl-config", "", "tosctl configuration file")
	flags.StringVar(&in.VaultURLEnv, "vault-url-env", "VAULT_URL", "environment variable that carries the vault "+
		"URL (its value is never printed or stored)")
	flags.StringVar(&in.WalletName, "wallet", "", "tosctl wallet that owns and funds this node")
	flags.StringVar(&in.PacketController, "packet-controller", "openfox-packet", "vault controller that signs "+
		"Agent Packets and controls the Agent (created if absent)")
	flags.StringVar(&in.CardController, "card-controller", "", "vault controller that signs the chat key cards "+
		"and nothing else, registered in the Agent's policy without authority of its own (created if absent; "+
		"default: the packet controller name with -card)")
	flags.StringVar(&in.RegistryCodeBOC, "registry-code-boc", "", "Native Registry code BOC file (base64)")
	flags.StringVar(&in.ActorCodeHash, "actor-code-hash", "", "pinned Service Actor release code hash "+
		"(tvm-cell-sha256:<hex>)")
	flags.StringVar(&in.MessengerSocket, "messenger-socket", "", "local Messenger daemon socket")
	flags.StringVar(&in.ReceiverSocket, "receiver-socket", "", "this node's Agent Packet receiver socket (default: "+
		"<state-dir>/rail-receiver.sock)")
	flags.StringArrayVar(&directPeers, "direct-peer", nil, "agent_<hex>=<socket>: deliver that Agent's packets to "+
		"its receiver socket on this host instead of the Messenger (repeatable; same host and user only)")
	flags.StringArrayVar(&in.RelayURLs, "relay-url", nil, "Agent Packet Relay base URL this node publishes in its "+
		"encryption key card and polls (repeatable, at most 4; https, or http only to a loopback host): packets "+
		"to peers whose verified card is known are sealed end to end and deposited at the peer's relays")
	flags.StringVar(&in.RelayCAFile, "relay-ca-file", "", "PEM file of one or more certificate authorities this "+
		"node's own https relays are verified against instead of the system trust store (copied into the "+
		"owner-only state; kept by a re-run that names neither this nor --relay-system-roots)")
	flags.BoolVar(&in.RelaySystemRoots, "relay-system-roots", false, "drop a pinned --relay-ca-file: verify this "+
		"node's relays against the system trust store again")
	flags.StringArrayVar(&allowProviders, "allow-provider", nil, "provider Agent this node may buy from "+
		"(repeatable; adds the buyer section)")
	flags.StringVar(&perPurchase, "max-per-purchase", "2", "buyer: most TOS one purchase may commit")
	flags.StringVar(&inWindow, "max-in-window", "10", "buyer: most TOS committed within the window")
	flags.Int64Var(&windowSeconds, "window-seconds", 86400, "buyer: spending window")
	flags.IntVar(&maxOpen, "max-open-purchases", 4, "buyer: most purchases open at once")
	flags.StringVar(&refundReserve, "refund-reserve", "0.3", "buyer: TOS kept for the refund transactions")
	flags.StringVar(&confirmAbove, "confirm-above", "", "buyer: TOS above which a purchase needs --yes")
	flags.StringVar(&gatewayURL, "gateway-url", "", "buyer: gateway that serves Quotes (optional with --offer)")
	flags.StringVar(&gatewayToken, "gateway-token-file", "", "buyer: gateway bearer token file")
	flags.StringVar(&gatewayCA, "gateway-ca-file", "", "buyer: gateway CA file")
	flags.StringVar(&callerID, "caller-id", "", "buyer: caller id sent to the gateway")
	flags.StringVar(&chat.MessengerCarrierSocket, "messenger-carrier-socket", "", "chat: the Messenger daemon's "+
		"carrier socket (its relay_carriage.listen_socket_path); adds the chat carriage section")
	flags.StringArrayVar(&chat.RelayURLs, "chat-relay-url", nil, "chat: relay base URL the chat card names and "+
		"the node polls for chat (repeatable, at most 4; default: the --relay-url list)")
	flags.StringVar(&chat.CarrierSocket, "chat-carrier-socket", "", "chat: socket this node serves carrier.carry "+
		"on, the daemon's relay_carriage.carry_socket_path (default: <state-dir>/chat-carrier.sock)")
	flags.StringVar(&chat.CardPath, "chat-card-path", "", "chat: where the current chat card is republished, "+
		"the daemon's relay_carriage.card_path (default: <state-dir>/relay/chat-card.json)")
	flags.StringVar(&chat.EvidenceExportDir, "messenger-evidence-dir", "", "chat: the daemon's "+
		"relay_carriage.evidence_export_dir, read by chat contact export")
	flags.StringVar(&chat.ContactDir, "messenger-contact-dir", "", "chat: the daemon's discovery.contact_dir, "+
		"written by chat contact import")
	flags.Uint64Var(&chat.TimeoutSeconds, "chat-timeout-seconds", 0, "chat: bound of one carrier operation, "+
		"1 to 300; set it to the daemon's relay_carriage.timeout_seconds (default 30)")
	flags.BoolVar(&in.Yes, "yes", false, "create the controller, sign and send as previewed")
	for _, name := range []string{
		"rail-config", "state-dir", "rpc", "global-config", "network-label", "tosctl", "tosctl-config", "wallet",
		"registry-code-boc", "actor-code-hash",
	} {
		_ = command.MarkFlagRequired(name)
	}
	return command
}

func serviceOfferCommand() *cobra.Command {
	var in servicebridge.OfferInput
	var price, storageFee, cleanupBounty, deployFunding string
	var responseSLA, refundWindow uint32
	command := &cobra.Command{
		Use:   "offer",
		Short: "Publish this provider's offer: Service Actor, manifest, Capability and policy",
		Long: "Create the attestor controller if the vault has none, deploy the Service Actor with it, build the " +
			"manifest, register the Capability, set the actor's policy to the Capability version, verify the " +
			"result with the preflight's own chain checks, fill the provider section of the rail configuration " +
			"and write an offer file for buyers. Every bound the contract enforces is checked before anything " +
			"is sent. Without --yes nothing is created, signed or sent and the preview is printed. Each step " +
			"reads finalized state first, so a re-run after an interruption resumes and never sends a message " +
			"whose outcome is unknown.",
		Args: cobra.NoArgs, SilenceUsage: true,
		RunE: func(command *cobra.Command, _ []string) error {
			var err error
			if in.Terms.PriceNano, err = tosFlag("price", price, false); err != nil {
				return err
			}
			if in.Terms.StorageFeeNano, err = tosFlag("storage-fee", storageFee, false); err != nil {
				return err
			}
			if in.Terms.CleanupBountyNano, err = tosFlag("cleanup-bounty", cleanupBounty, false); err != nil {
				return err
			}
			if in.DeployFundingNano, err = tosFlag("deploy-funding", deployFunding, true); err != nil {
				return err
			}
			in.Terms.ResponseSLA, in.Terms.RefundClaimWindow = responseSLA, refundWindow
			result, err := servicebridge.RunOffer(command.Context(), in, setupEnv(command))
			if result == nil {
				return err
			}
			return finishSetup(command, result, err)
		},
	}
	railConfigFlag(command, &in.RailConfigPath)
	flags := command.Flags()
	flags.StringVar(&price, "price", "", "price per call, in TOS")
	flags.StringVar(&storageFee, "storage-fee", "", "non-refundable storage fee per call, in TOS (at least 0.1 "+
		"plus the cleanup bounty)")
	flags.StringVar(&cleanupBounty, "cleanup-bounty", "", "bounty for sweeping an expired request, in TOS (0.1 to 1)")
	flags.Uint32Var(&responseSLA, "response-sla", 0, "seconds a call has to be responded to (3600 to 2592000)")
	flags.Uint32Var(&refundWindow, "refund-claim-window", 0, "seconds a refund stays claimable (3600 to 2592000)")
	flags.StringVar(&in.Version, "version", servicebridge.DefaultOfferVersion, "Capability version")
	flags.StringVar(&in.AttestorController, "attestor-controller", servicebridge.DefaultAttestorController,
		"vault controller that attests responses (created if absent)")
	flags.StringVar(&in.ExecutorSocket, "executor-socket", "", "socket of the root-run executor service (default "+
		servicebridge.DefaultExecutorSocket+" unless --executor is given)")
	flags.StringVar(&in.ExecutorBinary, "executor", "", "software-work executor binary to run as this user instead "+
		"of the executor service (needs --containerd-socket)")
	flags.StringVar(&in.ExecutorSHA256, "executor-sha256", "", "SHA-256 the executor must have (default: pin the "+
		"binary found, trust on first use)")
	flags.StringVar(&in.ContainerdSocket, "containerd-socket", "", "private container runtime socket")
	flags.StringVar(&in.FIFODir, "fifo-dir", "", "executor FIFO directory (default: <state_dir>/fifo)")
	flags.IntVar(&in.RespondBudgetSeconds, "respond-budget-seconds", servicebridge.DefaultRespondBudget,
		"time kept for responding after execution")
	flags.Uint64Var(&in.RetentionSeconds, "retention-seconds", servicebridge.DefaultRetentionSeconds,
		"how long results are redelivered")
	flags.StringVar(&deployFunding, "deploy-funding", "", "TOS sent with the deployment (default and minimum 1.2: "+
		"the actor's 1 TOS reserve plus a fee margin)")
	flags.StringVar(&in.OfferPath, "offer-out", "", "where to write the offer file (default: "+
		"<state_dir>/setup/offer.json)")
	flags.BoolVar(&in.Yes, "yes", false, "create the controller, sign and send as previewed")
	for _, name := range []string{
		"price", "storage-fee", "cleanup-bounty", "response-sla", "refund-claim-window",
	} {
		_ = command.MarkFlagRequired(name)
	}
	return command
}

func serviceWithdrawCommand() *cobra.Command {
	var in servicebridge.WithdrawInput
	var amount, note string
	var acknowledge uint64
	command := &cobra.Command{
		Use:   "withdraw",
		Short: "Withdraw the actor's credited revenue to the owner wallet",
		Long: "Read the actor's credited revenue at a finalized checkpoint, preview the amount, the destination " +
			"(the owner wallet, where the contract pays a withdrawal) and the value attached for fees, and with " +
			"--yes send withdraw_revenue through the pinned tosctl. The withdrawal is recorded before it is " +
			"sent and resolved from the finalized transaction that carries its query id. Zero and more than " +
			"the credit are refused. A finalized withdrawal is the actor paying out; the wallet's own credit " +
			"is not verified and is reported as such.",
		Args: cobra.NoArgs, SilenceUsage: true,
		RunE: func(command *cobra.Command, _ []string) error {
			if command.Flags().Changed("acknowledge") {
				if in.All || command.Flags().Changed("amount") {
					return errors.New("--acknowledge closes an earlier withdrawal; it takes neither --amount nor --all")
				}
				result, err := servicebridge.RunWithdrawAcknowledge(command.Context(), servicebridge.AcknowledgeInput{
					RailConfigPath: in.RailConfigPath, QueryID: acknowledge, Note: note, Yes: in.Yes,
				}, setupEnv(command))
				return finishSetup(command, result, err)
			}
			if command.Flags().Changed("note") {
				return errors.New("--note belongs to --acknowledge")
			}
			if in.All == command.Flags().Changed("amount") {
				return errors.New("give exactly one of --amount and --all")
			}
			if !in.All {
				nano, err := tosFlag("amount", amount, false)
				if err != nil {
					return err
				}
				if nano == 0 {
					return servicebridge.ErrWithdrawZero
				}
				in.AmountNano = nano
			}
			result, err := servicebridge.RunWithdraw(command.Context(), in, setupEnv(command))
			return finishSetup(command, result, err)
		},
	}
	railConfigFlag(command, &in.RailConfigPath)
	command.Flags().StringVar(&amount, "amount", "", "amount to withdraw, in TOS")
	command.Flags().BoolVar(&in.All, "all", false, "withdraw all credited revenue")
	command.Flags().Uint64Var(&acknowledge, "acknowledge", 0, "query id of an earlier withdrawal that finalized "+
		"state cannot decide and whose inclusion window has passed: close its record so it no longer blocks "+
		"withdrawals (moves no funds, sends nothing, never automatic)")
	command.Flags().StringVar(&note, "note", "", "with --acknowledge: what you checked, stored with the record")
	command.Flags().BoolVar(&in.Yes, "yes", false, "send the withdrawal, or record the acknowledgement, as previewed")
	return command
}
