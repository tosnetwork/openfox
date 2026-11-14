package earning

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/tosnetwork/openfox/pkg/servicebridge"
)

// serviceCommand is paid software work on the Service Actor rail: a provider
// publishes a Service Actor Capability and serves it, a buyer starts from a
// published Capability, takes a Quote and calls.
func serviceCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "service",
		Short: "Sell or buy software work on the Service Actor rail",
		Args:  cobra.NoArgs,
	}
	command.AddCommand(serviceManifestCommand(), serviceMetadataCommand(), serviceServeCommand(), serviceBuyCommand(),
		servicePurchasesCommand(), serviceStatusCommand(), servicePreflightCommand(), servicePauseCommand(),
		serviceResumeCommand())
	return command
}

func railConfigFlag(command *cobra.Command, path *string) {
	command.Flags().StringVar(path, "rail-config", "", "owner-private rail node configuration (JSON)")
	_ = command.MarkFlagRequired("rail-config")
}

func printJSON(out io.Writer, value any) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func serviceManifestCommand() *cobra.Command {
	var provider, actor, codeHash, attestor, version, out string
	var retention uint64
	command := &cobra.Command{
		Use: "manifest", Short: "Build the canonical manifest of a Service Actor Capability (no chain effect)",
		Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
			encoded, digest, _, err := servicebridge.BuildManifest(servicebridge.ManifestInput{
				ProviderAgentID: provider, Actor: actor,
				ActorCodeHash: codeHash, Attestor: attestor, Version: version, RetentionSeconds: retention,
			})
			if err != nil {
				return err
			}
			if !filepath.IsAbs(out) {
				return errors.New("--out-dir must be absolute")
			}
			path := filepath.Join(out, strings.TrimPrefix(digest, "sha256:")+".cbor")
			if err := os.WriteFile(path, encoded, 0o600); err != nil {
				return err
			}
			return printJSON(
				command.OutOrStdout(),
				map[string]any{"manifest_digest": digest, "path": path, "next_steps": []string{
					"tosctl agent service deploy ... --attestor-controller <attestor> (if the actor is not deployed yet)",
					"tosctl agent native-registry action --kind register-capability --manifest " + strings.TrimPrefix(
						digest,
						"sha256:",
					) + " ...",
					"openfox earning service metadata --capability-id <cap_...> --manifest-digest " + digest + " ...",
					"tosctl agent service send --operation update-policy --metadata-hash <NSM1> ...",
				}},
			)
		},
	}
	command.Flags().StringVar(&provider, "provider-agent", "", "provider Agent id (agent_<hex>)")
	command.Flags().StringVar(&actor, "actor", "", "Service Actor address (0:<hex>)")
	command.Flags().
		StringVar(&codeHash, "code-hash", "", "pinned Service Actor release code hash (tvm-cell-sha256:<hex>)")
	command.Flags().StringVar(&attestor, "attestor", "", "attestor controller key id (mldsa44:<hex>)")
	command.Flags().StringVar(&version, "version", "1.0.0", "Capability version")
	command.Flags().Uint64Var(&retention, "retention-seconds", 86400, "how long results are redelivered")
	command.Flags().StringVar(&out, "out-dir", "", "directory for the manifest file")
	return command
}

func serviceMetadataCommand() *cobra.Command {
	var networkID, root, file, capability, provider, version, digest string
	command := &cobra.Command{
		Use: "metadata", Short: "Print the NSM1 metadata hash the actor policy must carry", Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			hash, err := servicebridge.MetadataHash(&nativev1.NetworkDomain{
				NetworkId: networkID, GenesisRootHash: root,
				GenesisFileHash: file,
			}, capability, provider, version, digest)
			if err != nil {
				return err
			}
			return printJSON(command.OutOrStdout(), map[string]string{"metadata_hash": hash})
		},
	}
	command.Flags().StringVar(&networkID, "network-id", "", "network id")
	command.Flags().StringVar(&root, "genesis-root-hash", "", "genesis root hash")
	command.Flags().StringVar(&file, "genesis-file-hash", "", "genesis file hash")
	command.Flags().StringVar(&capability, "capability-id", "", "registered Capability id")
	command.Flags().StringVar(&provider, "provider-agent", "", "provider Agent id")
	command.Flags().StringVar(&version, "version", "1.0.0", "Capability version")
	command.Flags().StringVar(&digest, "manifest-digest", "", "manifest digest")
	return command
}

func openRailNode(ctx context.Context, path string, command *cobra.Command) (*servicebridge.Node, error) {
	config, err := servicebridge.LoadNodeConfig(path)
	if err != nil {
		return nil, err
	}
	stderr := command.ErrOrStderr()
	return servicebridge.OpenNode(ctx, config, servicebridge.NodeOptions{Report: func(stage string, err error) {
		fmt.Fprintf(stderr, "%s: %s: %v\n", time.Now().UTC().Format(time.RFC3339), stage, err)
	}})
}

func serviceServeCommand() *cobra.Command {
	var path string
	command := &cobra.Command{
		Use: "serve", Short: "Receive rail packets and run the provider and buyer duties", Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			ctx, stop := signal.NotifyContext(command.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			node, err := openRailNode(ctx, path, command)
			if err != nil {
				return err
			}
			defer node.Close()
			server, err := servicebridge.OpenAgentPacketUnixServer(node.Config.ReceiverSocket, node.Receiver)
			if err != nil {
				return err
			}
			served := make(chan error, 1)
			go func() { served <- server.Serve() }()
			runErr := node.Service.Run(ctx, 5*time.Second)
			shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			shutdownErr := server.Shutdown(shutdown)
			if serveErr := <-served; serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				return serveErr
			}
			if errors.Is(runErr, context.Canceled) {
				runErr = nil
			}
			return errors.Join(runErr, shutdownErr)
		},
	}
	railConfigFlag(command, &path)
	return command
}

func serviceBuyCommand() *cobra.Command {
	var path, capability, version, source, packagePath string
	var yes bool
	command := &cobra.Command{
		Use: "buy", Short: "Buy software work from a published Service Actor Capability", Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if !filepath.IsAbs(source) {
				return errors.New("--source must be an absolute path")
			}
			archive, err := os.ReadFile(source)
			if err != nil {
				return err
			}
			if len(archive) == 0 || len(archive) > servicebridge.MaxInlineInputBytes {
				return servicebridge.ErrInputTooLarge
			}
			node, err := openRailNode(command.Context(), path, command)
			if err != nil {
				return err
			}
			defer node.Close()
			if node.Buyer == nil {
				return errors.New("the rail configuration has no buyer section")
			}
			if packagePath != "" {
				raw, rawErr := os.ReadFile(packagePath)
				if rawErr != nil {
					return rawErr
				}
				value := &nativev1.QuoteProposalPackageV1{}
				if rawErr := protojson.Unmarshal(raw, value); rawErr != nil {
					return fmt.Errorf("--quote-package: %w", rawErr)
				}
				quotes, ok := node.BuyerQuotes()
				if !ok {
					return errors.New("the buyer cannot take a Quote package")
				}
				quotes.UsePackage(value)
			}
			node.Buyer.SetDisclosure(func(costs servicebridge.Costs) {
				fmt.Fprintln(command.ErrOrStderr(), costs.Disclosure())
			})
			node.Buyer.SetConfirmer(func(_ context.Context, _ servicebridge.Costs) error {
				if yes {
					return nil
				}
				fmt.Fprint(command.ErrOrStderr(), "Confirm this purchase [y/N]: ")
				answer, _ := bufio.NewReader(command.InOrStdin()).ReadString('\n')
				if strings.TrimSpace(strings.ToLower(answer)) != "y" {
					return errors.New("the owner declined the purchase")
				}
				return nil
			})
			record, err := node.Buyer.Buy(command.Context(), capability, version, archive)
			if printErr := printJSON(command.OutOrStdout(), record); printErr != nil {
				return errors.Join(err, printErr)
			}
			return err
		},
	}
	railConfigFlag(command, &path)
	command.Flags().StringVar(&capability, "capability-id", "", "published Capability id (cap_<hex>)")
	command.Flags().StringVar(&version, "version", "1.0.0", "Capability version")
	command.Flags().StringVar(&source, "source", "", "source archive (at most 1 MiB)")
	command.Flags().
		StringVar(&packagePath, "quote-package", "", "a Quote package obtained out of band (protojson), instead of the gateway")
	command.Flags().BoolVar(&yes, "yes", false, "confirm a purchase the policy routes to the owner")
	return command
}

func servicePurchasesCommand() *cobra.Command {
	var path string
	command := &cobra.Command{
		Use: "purchases", Short: "List purchases with phase, status, required action and costs", Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			config, err := servicebridge.LoadNodeConfig(path)
			if err != nil {
				return err
			}
			if config.Buyer == nil {
				return errors.New("the rail configuration has no buyer section")
			}
			records, err := servicebridge.ReadPurchases(config.StateDir)
			if err != nil {
				return err
			}
			return printJSON(command.OutOrStdout(), records)
		},
	}
	railConfigFlag(command, &path)
	return command
}

func serviceStatusCommand() *cobra.Command {
	var path string
	var offline, recordsOnly bool
	command := &cobra.Command{
		Use: "status", Short: "Show admission, the actor's credited revenue and each request's operator state",
		Long: "Show whether new admissions are paused, the actor's finalized accounting (credited revenue is a " +
			"contract balance, not wallet receipt) and one operator state per request: admitted, executing, " +
			"result_available, responded, refunded, swept or outcome_unknown. Without --offline it reads one " +
			"finalized checkpoint; a failed read is reported, and states it would have decided stay outcome_unknown.",
		Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			config, err := servicebridge.LoadNodeConfig(path)
			if err != nil {
				return err
			}
			if config.Provider == nil {
				return errors.New("the rail configuration has no provider section")
			}
			var chain servicebridge.StatusChain
			if !offline {
				chain, err = servicebridge.OpenStatusChain(config)
				if err != nil {
					// The local view is still worth printing; the failure is
					// reported in actor.error and chain-decided states stay
					// unknown.
					chain = servicebridge.UnavailableStatusChain(fmt.Errorf("open the finalized reader: %w", err))
				}
			}
			status, err := servicebridge.ReadProviderStatus(command.Context(), config, chain, time.Now())
			if err != nil {
				return err
			}
			if recordsOnly {
				return printJSON(command.OutOrStdout(), status.Requests)
			}
			return printJSON(command.OutOrStdout(), status)
		},
	}
	railConfigFlag(command, &path)
	command.Flags().BoolVar(&offline, "offline", false, "do not read finalized chain facts")
	command.Flags().
		BoolVar(&recordsOnly, "records", false, "print only the request list (the earlier array shape, with added fields)")
	return command
}

// errPreflightFailed makes a failed preflight exit non-zero after its report
// was printed.
var errPreflightFailed = errors.New("preflight: at least one required check failed")

func servicePreflightCommand() *cobra.Command {
	var path string
	command := &cobra.Command{
		Use:   "preflight",
		Short: "Check that this provider node is ready to admit paid work (no chain effect, signs nothing)",
		Long: "Print a machine-readable readiness report and exit non-zero if any check fails. It reads the " +
			"configuration, local files and finalized chain state; it sends nothing, signs nothing, never connects " +
			"to the container runtime socket and writes nothing into state_dir.",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: false,
		RunE: func(command *cobra.Command, _ []string) error {
			if path == "" {
				return errors.New("--rail-config is required")
			}
			report := servicebridge.RunPreflight(command.Context(), path, servicebridge.PreflightEnv{})
			if err := printJSON(command.OutOrStdout(), report); err != nil {
				return err
			}
			if !report.OK {
				return errPreflightFailed
			}
			return nil
		},
	}
	command.Flags().StringVar(&path, "rail-config", "", "owner-private rail node configuration (JSON)")
	command.Flags().StringVar(&path, "config", "", "alias of --rail-config")
	return command
}

func servicePauseCommand() *cobra.Command {
	var path, reason string
	command := &cobra.Command{
		Use:   "pause",
		Short: "Stop admitting new requests; admitted work still executes, responds and delivers",
		Long: "Write an owner-only marker in state_dir that a running `serve` checks before each admission. " +
			"Work already admitted is unaffected. A task that arrives while paused is held, not refused; it is " +
			"admitted after `resume` if its request is still admissible, and otherwise the buyer's refund path " +
			"applies. Pausing never touches funds; to stop new calls on chain, change the actor's policy with the " +
			"owner wallet.",
		Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			config, err := servicebridge.LoadNodeConfig(path)
			if err != nil {
				return err
			}
			if config.Provider == nil {
				return errors.New("the rail configuration has no provider section")
			}
			pause, already, err := servicebridge.PauseAdmission(config.StateDir, reason, time.Now())
			if err != nil {
				return err
			}
			return printJSON(command.OutOrStdout(), map[string]any{
				"paused": true, "already_paused": already, "paused_unix": pause.PausedUnix, "reason": pause.Reason,
			})
		},
	}
	railConfigFlag(command, &path)
	command.Flags().StringVar(&reason, "reason", "", "one-line note shown in status (at most 256 bytes)")
	return command
}

func serviceResumeCommand() *cobra.Command {
	var path string
	command := &cobra.Command{
		Use: "resume", Short: "Admit new requests again", Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			config, err := servicebridge.LoadNodeConfig(path)
			if err != nil {
				return err
			}
			if config.Provider == nil {
				return errors.New("the rail configuration has no provider section")
			}
			wasPaused, err := servicebridge.ResumeAdmission(config.StateDir)
			if err != nil {
				return err
			}
			return printJSON(command.OutOrStdout(), map[string]any{"paused": false, "was_paused": wasPaused})
		},
	}
	railConfigFlag(command, &path)
	return command
}
