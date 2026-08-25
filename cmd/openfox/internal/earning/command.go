package earning

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"github.com/tosnetwork/tos-ai/pkg/commercegate"
	"github.com/tosnetwork/tos-messenger/pkg/localapi"

	"github.com/tosnetwork/openfox/cmd/openfox/internal"
	"github.com/tosnetwork/openfox/pkg/config"
	openfoxearning "github.com/tosnetwork/openfox/pkg/earning"
	"github.com/tosnetwork/openfox/pkg/providers"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/paiddemand"
)

func NewCommand() *cobra.Command {
	command := &cobra.Command{Use: "earning", Short: "Inspect autonomous earning safety state", Args: cobra.NoArgs}
	command.AddCommand(statusCommand(), registryCommand(), scoutCommand(), runCommand(), intentCommand(), reconcileCommand(), operationsCommand(), authorityCommand(), modeCommand("pause", openfoxearning.OperationalPaused),
		modeCommand("drain", openfoxearning.OperationalDraining), modeCommand("resume", openfoxearning.OperationalRunning))
	return command
}

func intentCommand() *cobra.Command {
	command := &cobra.Command{Use: "intent", Short: "Publish, revise, inspect, or withdraw owner-authorized Intents", Args: cobra.NoArgs}
	command.AddCommand(intentPublishCommand(false), intentPublishCommand(true), intentWithdrawCommand(), intentListCommand())
	return command
}

func intentPublishCommand(revise bool) *cobra.Command {
	var path string
	name := "publish"
	if revise {
		name = "revise"
	}
	command := &cobra.Command{Use: name, Short: name + " one bounded signed Intent across configured Carriers", Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			runtime, err := openPublicationRuntime(command.Context())
			if err != nil {
				return err
			}
			defer runtime.Close()
			var draft openfoxearning.PublicationDraft
			if err := decodeBoundedJSONFile(path, 2<<20, &draft); err != nil {
				return err
			}
			var record openfoxearning.PublicationRecord
			if revise {
				record, err = runtime.Manager.Revise(command.Context(), draft, runtime.CarrierIDs, 1, runtime.Fence)
			} else {
				record, err = runtime.Manager.Publish(command.Context(), draft, runtime.CarrierIDs, 1, runtime.Fence)
			}
			if err != nil {
				return err
			}
			return json.NewEncoder(command.OutOrStdout()).Encode(record)
		}}
	command.Flags().StringVar(&path, "file", "", "JSON PublicationDraft file")
	_ = command.MarkFlagRequired("file")
	return command
}

func intentWithdrawCommand() *cobra.Command {
	var objectID, reason string
	command := &cobra.Command{Use: "withdraw", Short: "Publish an issuer-signed withdrawal to every prior Carrier", Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			runtime, err := openPublicationRuntime(command.Context())
			if err != nil {
				return err
			}
			defer runtime.Close()
			record, err := runtime.Manager.Withdraw(command.Context(), objectID, reason, 1, runtime.Fence)
			if err != nil {
				return err
			}
			return json.NewEncoder(command.OutOrStdout()).Encode(record)
		}}
	command.Flags().StringVar(&objectID, "object-id", "", "stable Intent object ID")
	command.Flags().StringVar(&reason, "reason", "", "bounded withdrawal reason code")
	_ = command.MarkFlagRequired("object-id")
	_ = command.MarkFlagRequired("reason")
	return command
}

func intentListCommand() *cobra.Command {
	return &cobra.Command{Use: "list", Short: "List the durable local Intent publication journal", Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			cfg, err := internal.LoadConfig()
			if err != nil {
				return err
			}
			records, err := openfoxearning.ReadPublicationRecords(filepath.Join(cfg.Earning.StateDir, "publications"))
			if err != nil {
				return err
			}
			return json.NewEncoder(command.OutOrStdout()).Encode(records)
		}}
}

type publicationRuntime struct {
	Manager        *openfoxearning.PublicationManager
	Authority      openfoxearning.EconomicAuthority
	CloseAuthority func()
	DirectorySinks []*openfoxearning.DirectoryPublicationSink
	CarrierIDs     []string
	Fence          commerce.WriterFence
}

func (runtime *publicationRuntime) Close() {
	if runtime == nil {
		return
	}
	if runtime.Manager != nil {
		_ = runtime.Manager.Close()
	}
	for _, sink := range runtime.DirectorySinks {
		_ = sink.Close()
	}
	if runtime.CloseAuthority != nil {
		runtime.CloseAuthority()
	}
}

func openPublicationRuntime(ctx context.Context) (*publicationRuntime, error) {
	cfg, err := internal.LoadConfig()
	if err != nil {
		return nil, err
	}
	if err := cfg.Earning.Validate(); err != nil {
		return nil, err
	}
	if !cfg.Earning.Gates.Publication {
		return nil, errors.New("Intent publication gate is disabled")
	}
	authority, closeAuthority, err := openConfiguredAuthority(cfg.Earning, true)
	if err != nil {
		return nil, err
	}
	runtime := &publicationRuntime{Authority: authority, CloseAuthority: closeAuthority}
	fail := func(cause error) (*publicationRuntime, error) { runtime.Close(); return nil, cause }
	identityDir := filepath.Join(cfg.Earning.StateDir, "identity")
	if err := os.MkdirAll(identityDir, 0o700); err != nil {
		return fail(err)
	}
	_ = os.Chmod(identityDir, 0o700)
	identityKey, err := loadOrCreateNamedKey(identityDir, "agent-ed25519.key")
	if err != nil {
		return fail(err)
	}
	authorities, err := openfoxearning.ParsePinnedIntentAuthorities(cfg.Earning.TrustedIntentIssuerKeys)
	if err != nil {
		return fail(err)
	}
	identityPublic := identityKey.Public().(ed25519.PublicKey)
	if pinned, found := authorities[cfg.Earning.AgentID]; found && !pinned.Equal(identityPublic) {
		return fail(errors.New("local Agent identity key differs from configured authority"))
	}
	authorities[cfg.Earning.AgentID] = identityPublic
	operations, err := configuredOperations()
	if err != nil {
		return fail(err)
	}
	engine := &openfoxearning.Engine{OwnerID: cfg.Earning.OwnerID, AgentID: cfg.Earning.AgentID, MandateDigest: cfg.Earning.MandateDigest,
		Gates: configuredFeatureGates(cfg.Earning), Authority: authority, Collector: openfoxearning.Collector{Authority: authorities},
		PublicationSinks: map[string]openfoxearning.PublicationSink{}, Operations: operations}
	for _, carrier := range cfg.Earning.Carriers {
		kind := carrier.Kind
		if kind == "" {
			kind = "http"
		}
		if kind == "directory" {
			sink, openErr := openfoxearning.OpenDirectoryPublicationSink(carrier.Directory, carrier.ID, authority)
			if openErr != nil {
				return fail(openErr)
			}
			runtime.DirectorySinks = append(runtime.DirectorySinks, sink)
			engine.PublicationSinks[carrier.ID] = sink
			engine.Collector.Carriers = append(engine.Collector.Carriers,
				openfoxearning.DirectoryCarrier{CarrierID: carrier.ID, Directory: carrier.Directory})
		} else {
			sink, openErr := openfoxearning.NewHTTPPublicationSink(carrier.ID, carrier.Endpoint, carrier.RelayToken.String(), 30*time.Second)
			if openErr != nil {
				return fail(openErr)
			}
			engine.PublicationSinks[carrier.ID] = sink
			reader, openErr := openfoxearning.NewHTTPCarrier(carrier.ID, carrier.Endpoint, carrier.ReadToken.String(), 30*time.Second)
			if openErr != nil {
				return fail(openErr)
			}
			engine.Collector.Carriers = append(engine.Collector.Carriers, reader)
		}
		runtime.CarrierIDs = append(runtime.CarrierIDs, carrier.ID)
	}
	sort.Strings(runtime.CarrierIDs)
	fence, err := authority.AcquireWriter(ctx, authorityInstanceID(cfg.Earning, "earning-publication"), configuredWriterScopes(cfg.Earning), time.Hour)
	if err != nil {
		return fail(err)
	}
	runtime.Fence = fence
	publication := cfg.Earning.Publication
	manager, err := openfoxearning.OpenPublicationManager(filepath.Join(cfg.Earning.StateDir, "publications"), engine,
		openfoxearning.InventorySourceFunc(func(context.Context) (openfoxearning.InventorySnapshot, error) {
			return configuredInventory(cfg.Earning, authority, time.Now().UTC()), nil
		}),
		identityKey, openfoxearning.PublicationPolicy{MinimumTTL: time.Duration(publication.MinimumTTLSeconds) * time.Second,
			MaximumTTL: time.Duration(publication.MaximumTTLSeconds) * time.Second, MinimumMarginPPM: publication.MinimumMarginPPM,
			MaximumPriceChangePPM: publication.MaximumPriceChangePPM, MaximumActive: publication.MaximumActive,
			MaximumRevisionsPerObject: publication.MaximumRevisionsPerObject, MaximumPublicationsPerPeriod: publication.MaximumPublicationsPerPeriod,
			Period: time.Duration(publication.PeriodSeconds) * time.Second, AllowedAudiences: append([]string(nil), publication.AllowedAudiences...), AllowDemand: publication.AllowDemand})
	if err != nil {
		return fail(err)
	}
	runtime.Manager = manager
	return runtime, nil
}

func decodeBoundedJSONFile(path string, maximum int64, target any) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("input path must be canonical and absolute")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maximum {
		return errors.New("input is not a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("input has trailing JSON")
	}
	return nil
}

func reconcileCommand() *cobra.Command {
	var apply bool
	command := &cobra.Command{Use: "reconcile", Short: "Inspect or safely apply deterministic earning-ledger repairs", Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			cfg, err := internal.LoadConfig()
			if err != nil {
				return err
			}
			if err := cfg.Earning.Validate(); err != nil {
				return err
			}
			authority, closeAuthority, err := openConfiguredAuthority(cfg.Earning, false)
			if err != nil {
				return err
			}
			defer closeAuthority()
			operations, err := configuredOperations()
			if err != nil {
				return err
			}
			engine := &openfoxearning.Engine{OwnerID: cfg.Earning.OwnerID, AgentID: cfg.Earning.AgentID,
				MandateDigest: cfg.Earning.MandateDigest, Authority: authority, Operations: operations}
			var report openfoxearning.ReconciliationReport
			if apply {
				fence, acquireErr := authority.AcquireWriter(command.Context(), authorityInstanceID(cfg.Earning, "earning-reconciler"), []string{"portfolio.release"}, 10*time.Minute)
				if acquireErr != nil {
					return acquireErr
				}
				report, err = engine.ReconcileApply(command.Context(), 1, fence)
			} else {
				report, err = engine.ReconcileDryRun()
			}
			if err != nil {
				return err
			}
			encoder := json.NewEncoder(command.OutOrStdout())
			encoder.SetIndent("", "  ")
			return encoder.Encode(report)
		}}
	command.Flags().BoolVar(&apply, "apply", false, "apply only deterministic writer-fenced repairs; default is dry-run")
	return command
}

func operationsCommand() *cobra.Command {
	return &cobra.Command{Use: "operations", Short: "Show durable pause and drain controls", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		controller, err := configuredOperations()
		if err != nil {
			return err
		}
		revision, scopes, audit := controller.Snapshot()
		if len(audit) > 100 {
			audit = audit[len(audit)-100:]
		}
		encoder := json.NewEncoder(command.OutOrStdout())
		encoder.SetIndent("", "  ")
		return encoder.Encode(struct {
			Revision uint64                                     `json:"revision"`
			Scopes   []openfoxearning.OperationalScopeStateView `json:"scopes"`
			Audit    []openfoxearning.OperationalAuditRecord    `json:"recent_audit"`
		}{revision, scopes, audit})
	}}
}

func modeCommand(name string, mode openfoxearning.OperationalMode) *cobra.Command {
	var scope, reason string
	command := &cobra.Command{Use: name, Short: name + " an autonomous earning scope", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		controller, err := configuredOperations()
		if err != nil {
			return err
		}
		current, err := user.Current()
		if err != nil || current.Uid == "" {
			return errors.New("cannot authenticate local operator identity")
		}
		record, err := controller.SetMode("local-uid:"+current.Uid, scope, mode, reason)
		if err != nil {
			return err
		}
		return json.NewEncoder(command.OutOrStdout()).Encode(record)
	}}
	command.Flags().StringVar(&scope, "scope", "*", "scope name or * for all scopes")
	command.Flags().StringVar(&reason, "reason", "", "required audit reason")
	_ = command.MarkFlagRequired("reason")
	return command
}

func configuredOperations() (*openfoxearning.OperationalController, error) {
	cfg, err := internal.LoadConfig()
	if err != nil {
		return nil, err
	}
	if !filepath.IsAbs(cfg.Earning.StateDir) || filepath.Clean(cfg.Earning.StateDir) != cfg.Earning.StateDir {
		return nil, errors.New("earning state directory is not configured")
	}
	directory := filepath.Join(cfg.Earning.StateDir, "operations")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return nil, err
	}
	return openfoxearning.OpenOperationalController(directory)
}

func scoutCommand() *cobra.Command {
	var modes, classes, keywords []string
	var taxonomy string
	var limit uint32
	command := &cobra.Command{Use: "scout", Short: "Find and economically assess signed Intents without side effects", Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			cfg, err := internal.LoadConfig()
			if err != nil {
				return err
			}
			if !cfg.Earning.Enabled {
				return errors.New("autonomous earning is disabled")
			}
			if err := cfg.Earning.Validate(); err != nil {
				return err
			}
			authorities, err := openfoxearning.ParsePinnedIntentAuthorities(cfg.Earning.TrustedIntentIssuerKeys)
			if err != nil {
				return err
			}
			carriers := make([]openfoxearning.Carrier, 0, len(cfg.Earning.Carriers))
			for _, configured := range cfg.Earning.Carriers {
				kind := configured.Kind
				if kind == "" {
					kind = "http"
				}
				if kind == "directory" {
					carriers = append(carriers, openfoxearning.DirectoryCarrier{CarrierID: configured.ID, Directory: configured.Directory})
					continue
				}
				carrier, err := openfoxearning.NewHTTPCarrier(configured.ID, configured.Endpoint, configured.ReadToken.String(), 15*time.Second)
				if err != nil {
					return err
				}
				carriers = append(carriers, carrier)
			}
			llm, model, err := providers.CreateProvider(cfg)
			if err != nil {
				return err
			}
			if closeable, ok := llm.(providers.StatefulProvider); ok {
				defer closeable.Close()
			}
			now := time.Now().UTC()
			capabilities := make([]openfoxearning.Capability, 0, len(cfg.Earning.Capabilities))
			for _, capability := range cfg.Earning.Capabilities {
				capabilities = append(capabilities, openfoxearning.Capability{Namespace: capability.Namespace, Identifier: capability.Identifier,
					Version: capability.Version, State: openfoxearning.CapabilityReady, Authority: cfg.Earning.OwnerID,
					EvidenceDigest: capability.EvidenceDigest, RevocationGeneration: 1, ExpiresAtUnix: uint64(now.Add(2 * time.Minute).Unix())})
			}
			adapters := append([]string(nil), cfg.Earning.SettlementAdapters...)
			sort.Strings(adapters)
			inventory := openfoxearning.InventorySnapshot{OwnerID: cfg.Earning.OwnerID, AgentID: cfg.Earning.AgentID,
				CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(2 * time.Minute).Unix()), SourceGeneration: 1,
				PortfolioRevision: 1, PolicyRevision: 1, ConsistencyToken: fmt.Sprintf("startup:%d", now.UnixNano()), Capabilities: capabilities,
				Available: openfoxearning.ResourceCapacity{CPUUnits: cfg.Earning.Resources.CPUUnits, MemoryBytes: cfg.Earning.Resources.MemoryBytes,
					StorageBytes: cfg.Earning.Resources.StorageBytes, ModelTokens: cfg.Earning.Resources.ModelTokens,
					APIAtomicBudget: cfg.Earning.Resources.APIAtomicBudget, Concurrency: cfg.Earning.Resources.Concurrency},
				SupportedSettlementAdapters: adapters}
			query := openfoxearning.IntentQuery{TaxonomyPrefix: taxonomy, Keywords: keywords, MaximumResults: limit}
			for _, value := range modes {
				query.Modes = append(query.Modes, commerce.IntentMode(strings.ToUpper(value)))
			}
			for _, value := range classes {
				query.SubjectClasses = append(query.SubjectClasses, commerce.SubjectClass(strings.ToUpper(value)))
			}
			collector := openfoxearning.Collector{Carriers: carriers, Authority: authorities,
				Inventory: openfoxearning.CurrentInventory{SnapshotValue: inventory},
				Estimator: openfoxearning.LLMEconomicEstimator{Provider: llm, Model: model, Now: func() time.Time { return now }},
				Policy: openfoxearning.EconomicPolicy{MinimumExpectedProfitAtomic: cfg.Earning.Policy.MinimumExpectedProfitAtomic,
					MinimumROIPPM: cfg.Earning.Policy.MinimumROIPPM, MaximumLossAtomic: cfg.Earning.Policy.MaximumLossAtomic,
					MinimumPaymentProbabilityPPM:    cfg.Earning.Policy.MinimumPaymentProbabilityPPM,
					MinimumCompletionProbabilityPPM: cfg.Earning.Policy.MinimumCompletionProbabilityPPM}, Content: configuredContentResolver(cfg.Earning),
				Shortlist: configuredShortlist(cfg.Earning), Now: func() time.Time { return now }}
			assessments, err := collector.Collect(context.Background(), query)
			if err != nil {
				return err
			}
			encoder := json.NewEncoder(command.OutOrStdout())
			encoder.SetIndent("", "  ")
			return encoder.Encode(assessments)
		}}
	command.Flags().StringSliceVar(&modes, "mode", nil, "Intent mode filter (repeatable)")
	command.Flags().StringSliceVar(&classes, "subject-class", nil, "subject class filter (repeatable)")
	command.Flags().StringSliceVar(&keywords, "keyword", nil, "exact normalized keyword filter (repeatable)")
	command.Flags().StringVar(&taxonomy, "taxonomy-prefix", "", "taxonomy prefix filter")
	command.Flags().Uint32Var(&limit, "limit", 100, "maximum candidates per Carrier")
	return command
}

func runCommand() *cobra.Command {
	var once bool
	var keywords []string
	var taxonomy string
	var limit uint32
	command := &cobra.Command{Use: "run", Short: "Run the durable autonomous opportunity worker", Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			cfg, err := internal.LoadConfig()
			if err != nil {
				return err
			}
			if err := cfg.Earning.Validate(); err != nil {
				return err
			}
			if !cfg.Earning.Enabled || cfg.Earning.EffectiveMode() == "off" {
				return errors.New("autonomous earning is off")
			}
			authorities, err := openfoxearning.ParsePinnedIntentAuthorities(cfg.Earning.TrustedIntentIssuerKeys)
			if err != nil {
				return err
			}
			var identityKey ed25519.PrivateKey
			if cfg.Earning.Gates.Agreement || cfg.Earning.Gates.Publication {
				identityDir := filepath.Join(cfg.Earning.StateDir, "identity")
				if err := os.MkdirAll(identityDir, 0o700); err != nil {
					return err
				}
				_ = os.Chmod(identityDir, 0o700)
				identityKey, err = loadOrCreateNamedKey(identityDir, "agent-ed25519.key")
				if err != nil {
					return err
				}
				identityPublic := identityKey.Public().(ed25519.PublicKey)
				if configured, found := authorities[cfg.Earning.AgentID]; found && !configured.Equal(identityPublic) {
					return errors.New("local Agent identity key differs from its configured finalized authority")
				}
				authorities[cfg.Earning.AgentID] = identityPublic
			}
			carriers, err := configuredCarriers(cfg.Earning)
			if err != nil {
				return err
			}
			llm, model, err := providers.CreateProvider(cfg)
			if err != nil {
				return err
			}
			if closeable, ok := llm.(providers.StatefulProvider); ok {
				defer closeable.Close()
			}
			journalDir := filepath.Join(cfg.Earning.StateDir, "opportunities")
			if err := os.MkdirAll(journalDir, 0o700); err != nil {
				return err
			}
			_ = os.Chmod(journalDir, 0o700)
			journal, err := openfoxearning.OpenOpportunityJournal(journalDir, 100_000)
			if err != nil {
				return err
			}
			defer journal.Close()
			operations, err := configuredOperations()
			if err != nil {
				return err
			}
			var authority openfoxearning.EconomicAuthority
			collector := openfoxearning.Collector{Carriers: carriers, Authority: authorities,
				Inventory: openfoxearning.InventorySourceFunc(func(context.Context) (openfoxearning.InventorySnapshot, error) {
					return configuredInventory(cfg.Earning, authority, time.Now().UTC()), nil
				}),
				Estimator: openfoxearning.LLMEconomicEstimator{Provider: llm, Model: model},
				Policy: openfoxearning.EconomicPolicy{MinimumExpectedProfitAtomic: cfg.Earning.Policy.MinimumExpectedProfitAtomic,
					MinimumROIPPM: cfg.Earning.Policy.MinimumROIPPM, MaximumLossAtomic: cfg.Earning.Policy.MaximumLossAtomic,
					MinimumPaymentProbabilityPPM:    cfg.Earning.Policy.MinimumPaymentProbabilityPPM,
					MinimumCompletionProbabilityPPM: cfg.Earning.Policy.MinimumCompletionProbabilityPPM}, Content: configuredContentResolver(cfg.Earning),
				Shortlist: configuredShortlist(cfg.Earning), Journal: journal}
			var handler openfoxearning.CandidateHandler = openfoxearning.CandidateHandlerFunc(func(_ context.Context, assessment openfoxearning.CandidateAssessment) error {
				encoder := json.NewEncoder(command.OutOrStdout())
				return encoder.Encode(assessment)
			})
			var agreementAutonomy *openfoxearning.AgreementAutonomy
			var paidDemandAutonomy *openfoxearning.PaidDemandBuyerAutonomy
			var engagementAutonomy *openfoxearning.EngagementAutonomy
			var publicationAutonomy *openfoxearning.PublicationAutonomy
			var privateHandoffAutonomy *openfoxearning.PrivateHandoffAutonomy
			var paidDemand *paidDemandRuntime
			var contactHandler *openfoxearning.ContactCandidateHandler
			if cfg.Earning.Gates.Contact || cfg.Earning.Gates.Publication {
				var closeAuthority func()
				authority, closeAuthority, err = openConfiguredAuthority(cfg.Earning, true)
				if err != nil {
					return err
				}
				defer closeAuthority()
				var messenger *localapi.Client
				if cfg.Earning.Gates.Contact {
					messenger, err = localapi.NewClient(cfg.Earning.MessengerSocket, 15*time.Second)
					if err != nil {
						return err
					}
				}
				engine := &openfoxearning.Engine{OwnerID: cfg.Earning.OwnerID, AgentID: cfg.Earning.AgentID, MandateDigest: cfg.Earning.MandateDigest,
					MinimumIndependentCarriers: int(cfg.Earning.MinimumIndependentCarriers), Gates: configuredFeatureGates(cfg.Earning),
					Collector: collector, Authority: authority, Operations: operations, PublicationSinks: map[string]openfoxearning.PublicationSink{}}
				if messenger != nil {
					engine.Sink = &openfoxearning.MessengerSink{Client: messenger}
				}
				var fenceMu sync.Mutex
				var fence commerce.WriterFence
				fenceSource := func(ctx context.Context) (commerce.WriterFence, error) {
					fenceMu.Lock()
					defer fenceMu.Unlock()
					if fence.Body.ExpiresAtUnix > uint64(time.Now().UTC().Add(5*time.Minute).Unix()) {
						return fence, nil
					}
					acquired, err := authority.AcquireWriter(ctx, authorityInstanceID(cfg.Earning, "earning-worker"), configuredWriterScopes(cfg.Earning), time.Hour)
					if err == nil {
						fence = acquired
					}
					return acquired, err
				}
				if cfg.Earning.Gates.Contact {
					contactHandler = &openfoxearning.ContactCandidateHandler{Engine: engine, Drafter: openfoxearning.LLMContactDrafter{Provider: llm, Model: model},
						Fence: fenceSource, PaymentDestination: []byte(cfg.Earning.TOSPayment.SourceAccount)}
					handler = contactHandler
				}
				if cfg.Earning.Gates.Agreement {
					verifier := openfoxearning.AgreementEvidenceRouter{AgentAuthority: authorities,
						Profiles: map[string]openfoxearning.ExternalAgreementEvidenceVerifier{}}
					if cfg.Earning.Gates.TOSEscrow {
						paidDemand, err = openPaidDemandRuntime(cfg.Earning, engine, identityKey, fenceSource)
						if err != nil {
							return err
						}
						verifier.Profiles[commerce.EvidenceProfilePaidDemandQuote] = commerce.PaidDemandQuoteEvidenceVerifier{
							Native: paidDemand.EvidenceVerifier}
						if contactHandler != nil {
							contactHandler.SupplyProfiles = map[string]openfoxearning.SupplyAgreementProfileCompiler{
								"tos.escrow.paid-demand.v1": openfoxearning.PaidDemandSupplyAgreementCompiler{
									Network: paidDemand.Network, BuyerWallet: cfg.Earning.TOSEscrow.BuyerAddress,
									Store: paidDemand.Negotiations}}
						}
					}
					agreementPolicy := openfoxearning.BoundedAgreementAdmissionPolicy{
						LocalAgentID: cfg.Earning.AgentID, MaximumOutgoingPaymentAtomic: effectiveOutgoingPayment(cfg.Earning.Policy.MaximumOutgoingPaymentAtomic),
						AllowedEvidenceProfiles: configuredAgreementEvidenceProfiles(cfg.Earning)}
					agreementAutonomy = &openfoxearning.AgreementAutonomy{Coordinator: openfoxearning.AgreementCoordinator{
						Inbox: openfoxearning.AgreementInbox{Client: messenger}, Authority: authority, Verifier: verifier},
						Engine: engine, Inventory: collector.Inventory, Policy: agreementPolicy,
						IdentityKey: identityKey, Verifier: verifier, Fence: fenceSource}
					if paidDemand != nil {
						funding := openfoxearning.PaidDemandFundingPrerequisite{Resolver: paidDemand.EscrowResolver,
							Network: paidDemand.Network, ProviderOffers: paidDemand.OfferAuthorities}
						prerequisite := openfoxearning.AdapterPrerequisitePolicy{LocalAgentID: cfg.Earning.AgentID,
							PrepaidAdapters: []string{paiddemand.SettlementAdapterURI}, Funding: funding}
						buyerService := openfoxearning.PaidDemandBuyerService{Engine: engine, Runtime: paidDemand.Buyer,
							Verifier: verifier, PolicyRevision: 1}
						paidDemandAutonomy = &openfoxearning.PaidDemandBuyerAutonomy{Engine: engine, Inventory: collector.Inventory,
							Policy: agreementPolicy, Store: paidDemand.Negotiations, Preparer: paidDemand.Buyer, Buyer: buyerService,
							Network: paidDemand.Network, PublicTerms: paidDemand.PublicTerms, Prerequisite: prerequisite, Fence: fenceSource}
					}
				}
				if cfg.Earning.PrivateHandoff.Enabled {
					privateRuntime, privateErr := openPrivateHandoffRuntime(cfg.Earning, engine, messenger, identityKey, authorities, fenceSource)
					if privateErr != nil {
						return privateErr
					}
					defer privateRuntime.Close()
					privateHandoffAutonomy = privateRuntime.Autonomy
				}
				if cfg.Earning.Gates.Execution || cfg.Earning.Gates.DirectPayment || cfg.Earning.Gates.ExternalSettlement {
					var gate *commercegate.Gate
					if cfg.Earning.Gates.Execution {
						var gateErr error
						gate, gateErr = commercegate.Open(filepath.Join(cfg.Earning.StateDir, "execution-gate"), authority)
						if gateErr != nil {
							return gateErr
						}
						defer gate.Close()
					}
					postpaid := make([]string, 0, 1)
					for _, adapter := range cfg.Earning.SettlementAdapters {
						if adapter == "tos.payment.direct.v1" || cfg.Earning.ExternalSettlement.Enabled && adapter == cfg.Earning.ExternalSettlement.AdapterURI {
							postpaid = append(postpaid, adapter)
						}
					}
					prerequisite := openfoxearning.AdapterPrerequisitePolicy{LocalAgentID: cfg.Earning.AgentID, PostpaidAdapters: postpaid}
					if paidDemand != nil {
						prerequisite.PrepaidAdapters = []string{"tos.escrow.paid-demand.v1"}
						prerequisite.Funding = openfoxearning.PaidDemandFundingPrerequisite{Resolver: paidDemand.EscrowResolver,
							Network: paidDemand.Network, ProviderOffers: paidDemand.OfferAuthorities}
					}
					outputDirectory := filepath.Join(cfg.Earning.StateDir, "deliverables")
					engagementAutonomy = &openfoxearning.EngagementAutonomy{Engine: engine, Inventory: collector.Inventory,
						Planner:      openfoxearning.BoundedEngagementPlanner{OwnerID: cfg.Earning.OwnerID, AgentID: cfg.Earning.AgentID, ComputeUnitsPerExecution: 1},
						Prerequisite: prerequisite, Gate: gate, Fence: fenceSource,
						Scheduler: &openfoxearning.SchedulerService{Authority: authority, OwnerID: cfg.Earning.OwnerID,
							AgentID: cfg.Earning.AgentID, MandateDigest: cfg.Earning.MandateDigest}}
					if paidDemand != nil {
						engagementAutonomy.Native = openfoxearning.PaidDemandNativeGate{
							Directory: filepath.Join(cfg.Earning.StateDir, "paid-demand-native-gate"), Store: paidDemand.Negotiations,
							PublicTerms: paidDemand.PublicTerms, Network: paidDemand.Network, EscrowResolver: paidDemand.EscrowResolver,
							NativeResolver: paidDemand.NativeResolver, RegistryCodeHash: cfg.Earning.TOSEscrow.RegistryCodeHash,
							EscrowCode: paidDemand.EscrowCode, AssetWalletCode: paidDemand.AssetWalletCode,
							OfferAuthorities: paidDemand.OfferAuthorities}
						engagementAutonomy.Receivables = openfoxearning.PaidDemandProviderSettlement{
							Engine: engine, Store: paidDemand.Negotiations, Network: paidDemand.Network,
							PublicTerms: paidDemand.PublicTerms, EscrowResolver: paidDemand.EscrowResolver,
							AssetResolver: paidDemand.AssetResolver, OfferAuthorities: paidDemand.OfferAuthorities,
							EscrowCode: paidDemand.EscrowCode, AssetWalletCode: paidDemand.AssetWalletCode,
							ExecutionKey: paidDemand.ExecutionKey, ActionSender: paidDemand.ProviderSender,
							Authorizer:      openfoxearning.PaidDemandCustodyAuthorizer{Engine: engine, FenceSource: fenceSource, PolicyRevision: 1},
							NetworkGlobalID: cfg.Earning.TOSEscrow.NetworkGlobalID,
							ActionNanoTOS:   cfg.Earning.TOSEscrow.ActionNanoTOS,
							PollInterval:    time.Duration(cfg.Earning.TOSEscrow.PollIntervalMillis) * time.Millisecond,
							FinalityTimeout: time.Duration(cfg.Earning.TOSEscrow.FinalityTimeoutSeconds) * time.Second}
					}
					paymentBuilder := openfoxearning.DirectPaymentRequestBuilder{OwnerID: cfg.Earning.OwnerID,
						AgentID: cfg.Earning.AgentID, ExternalAdapters: map[string]openfoxearning.ExternalAdapterIdentity{}}
					if cfg.Earning.Gates.Execution {
						workspace := cfg.WorkspacePath()
						if err := os.MkdirAll(workspace, 0o700); err != nil {
							return err
						}
						learningCapability := ""
						if len(cfg.Earning.Capabilities) == 1 {
							learningCapability = cfg.Earning.Capabilities[0].Identifier
						}
						learning, learningErr := openfoxearning.NewEvolutionExecutionLearningRecorder(
							cfg.Evolution, workspace, cfg.Earning.AgentID, llm, model, learningCapability)
						if learningErr != nil {
							return learningErr
						}
						engagementAutonomy.Runners = openfoxearning.AgreementRunnerFactoryFunc(func(record openfoxearning.EngagementRecord) (openfoxearning.AgreementRunner, error) {
							return openfoxearning.LLMTaskRunner{Provider: llm, Model: model, Agreement: record.Agreement.Body,
								OutputDirectory: outputDirectory, SkillWorkspace: workspace, Learning: learning}, nil
						})
						engagementAutonomy.Delivery = openfoxearning.MessengerDeliverySink{Messenger: &openfoxearning.MessengerSink{Client: messenger}}
					}
					if cfg.Earning.Gates.DirectPayment {
						payment := cfg.Earning.TOSPayment
						interval := time.Duration(payment.ResolveIntervalMS) * time.Millisecond
						if interval == 0 {
							interval = time.Second
						}
						sink := &openfoxearning.TOSCTLPaymentSink{Authority: authority, Executable: payment.Executable, ConfigPath: payment.ConfigPath,
							Wallet: payment.Wallet, SourceAccount: payment.SourceAccount, NetworkGlobalID: payment.NetworkGlobalID,
							FeeReserveNanoTOS: payment.FeeReserveNanoTOS, QuorumConfigPaths: append([]string(nil), payment.QuorumConfigPaths...),
							MaximumTransactions: payment.MaximumTransactions, VaultURL: payment.VaultURL, EvidenceDirectory: payment.EvidenceDirectory,
							ResolveAttempts: payment.ResolveAttempts, ResolveInterval: interval}
						engagementAutonomy.Payment = &openfoxearning.PaymentService{Engine: engine, Sink: sink, Verifier: sink}
					}
					if cfg.Earning.Gates.ExternalSettlement {
						external := cfg.Earning.ExternalSettlement
						certificate, roots, tlsErr := loadTLSIdentity(external.ClientCertFile, external.ClientKeyFile, external.CAFile, false)
						if tlsErr != nil {
							return tlsErr
						}
						httpClient, clientErr := openfoxearning.NewExternalPaymentHTTPClient(certificate, roots, external.ServerName,
							time.Duration(external.TimeoutMillis)*time.Millisecond)
						if clientErr != nil {
							return clientErr
						}
						defer httpClient.CloseIdleConnections()
						attestorKey, keyErr := decodeEd25519PublicKey(external.AttestorPublicKey)
						if keyErr != nil {
							return keyErr
						}
						pins := openfoxearning.ExternalPaymentAttestorPins{external.AttestorID: {
							AdapterURI: external.AdapterURI, PublicKey: attestorKey}}
						sink, sinkErr := openfoxearning.NewExternalAttestedPaymentSink(external.Endpoint, external.AdapterURI, httpClient, pins)
						if sinkErr != nil {
							return sinkErr
						}
						if engagementAutonomy.Payments == nil {
							engagementAutonomy.Payments = map[string]*openfoxearning.PaymentService{}
						}
						engagementAutonomy.Payments[external.AdapterURI] = &openfoxearning.PaymentService{Engine: engine, Sink: sink,
							Verifier: sink, ExternalSettlement: true}
						paymentBuilder.ExternalAdapters[external.AdapterURI] = openfoxearning.ExternalAdapterIdentity{
							SystemID: external.SystemID, AdapterProfileDigest: external.AdapterProfileDigest}
					}
					engagementAutonomy.PaymentBuilder = paymentBuilder
				}
				if cfg.Earning.Gates.Publication {
					for _, carrier := range cfg.Earning.Carriers {
						kind := carrier.Kind
						if kind == "" {
							kind = "http"
						}
						if kind == "directory" {
							sink, openErr := openfoxearning.OpenDirectoryPublicationSink(carrier.Directory, carrier.ID, authority)
							if openErr != nil {
								return openErr
							}
							defer sink.Close()
							engine.PublicationSinks[carrier.ID] = sink
						} else {
							sink, openErr := openfoxearning.NewHTTPPublicationSink(carrier.ID, carrier.Endpoint, carrier.RelayToken.String(), 30*time.Second)
							if openErr != nil {
								return openErr
							}
							engine.PublicationSinks[carrier.ID] = sink
						}
					}
					publication := cfg.Earning.Publication
					manager, openErr := openfoxearning.OpenPublicationManager(filepath.Join(cfg.Earning.StateDir, "publications"), engine, collector.Inventory,
						identityKey, openfoxearning.PublicationPolicy{MinimumTTL: time.Duration(publication.MinimumTTLSeconds) * time.Second,
							MaximumTTL: time.Duration(publication.MaximumTTLSeconds) * time.Second, MinimumMarginPPM: publication.MinimumMarginPPM,
							MaximumPriceChangePPM: publication.MaximumPriceChangePPM, MaximumActive: publication.MaximumActive,
							MaximumRevisionsPerObject: publication.MaximumRevisionsPerObject, MaximumPublicationsPerPeriod: publication.MaximumPublicationsPerPeriod,
							Period: time.Duration(publication.PeriodSeconds) * time.Second, AllowedAudiences: append([]string(nil), publication.AllowedAudiences...), AllowDemand: publication.AllowDemand})
					if openErr != nil {
						return openErr
					}
					defer manager.Close()
					settlementParameters := configuredSettlementParameters(publication.SettlementParameters)
					if paidDemand != nil {
						canonicalTerms, termsErr := paiddemand.CanonicalPublicTerms(paidDemand.PublicTerms)
						if termsErr != nil {
							return termsErr
						}
						settlementParameters[paiddemand.SettlementAdapterURI] = canonicalTerms
					}
					manager.Drafter = openfoxearning.LLMSupplyDrafter{Provider: llm, Model: model, NetworkID: publication.NetworkID,
						AgentID: cfg.Earning.AgentID, Audience: publication.AllowedAudiences[0],
						SettlementParameters: settlementParameters, OfferPolicies: configuredSupplyOfferPolicies(cfg.Earning)}
					if agreementAutonomy != nil {
						negotiator := openfoxearning.DemandApplicationNegotiator{Publications: manager,
							Engine: engine, Inventory: collector.Inventory, Fence: fenceSource,
							Compiler: openfoxearning.DemandAgreementCompiler{LocalAgentID: cfg.Earning.AgentID,
								MaximumTTL: time.Duration(publication.MaximumTTLSeconds) * time.Second}}
						if paidDemand != nil {
							providerService := &openfoxearning.PaidDemandProviderService{Engine: engine,
								Signer: paidDemand.ProviderSigner, OfferResolver: paidDemand.OfferAuthorities,
								Evidence: agreementAutonomy.Verifier, PolicyRevision: 1}
							funding := openfoxearning.PaidDemandFundingPrerequisite{Resolver: paidDemand.EscrowResolver,
								Network: paidDemand.Network, ProviderOffers: paidDemand.OfferAuthorities}
							negotiator.Profiles = map[string]openfoxearning.DemandApplicationProfileHandler{
								paiddemand.SettlementAdapterURI: openfoxearning.PaidDemandApplicationHandler{
									Engine: engine, Provider: providerService, Network: paidDemand.Network,
									Store: paidDemand.Negotiations, Prerequisite: openfoxearning.AdapterPrerequisitePolicy{
										LocalAgentID: cfg.Earning.AgentID, PrepaidAdapters: []string{paiddemand.SettlementAdapterURI},
										Funding: funding}, ComputeUnits: 1}}
						}
						agreementAutonomy.Coordinator.ApplicationHandler = negotiator
					}
					carrierIDs := make([]string, 0, len(cfg.Earning.Carriers))
					for _, carrier := range cfg.Earning.Carriers {
						carrierIDs = append(carrierIDs, carrier.ID)
					}
					sort.Strings(carrierIDs)
					publicationAutonomy = &openfoxearning.PublicationAutonomy{Manager: manager, CarrierIDs: carrierIDs, Fence: fenceSource}
				}
			}
			interval := time.Duration(cfg.Earning.IntervalSeconds) * time.Second
			if interval == 0 {
				interval = 5 * time.Minute
			}
			timeout := time.Duration(cfg.Earning.CycleTimeoutSeconds) * time.Second
			if timeout == 0 {
				timeout = time.Minute
			}
			service := &openfoxearning.AutonomousService{Collector: collector, Handler: handler, Operations: operations,
				Agreements: agreementAutonomy, PaidDemand: paidDemandAutonomy, PrivateHandoffs: privateHandoffAutonomy,
				Engagements: engagementAutonomy, Publications: publicationAutonomy,
				Config: openfoxearning.AutonomousServiceConfig{Query: openfoxearning.IntentQuery{TaxonomyPrefix: taxonomy, Keywords: keywords, MaximumResults: limit},
					Interval: interval, MaxJitter: time.Duration(cfg.Earning.JitterSeconds) * time.Second, CycleTimeout: timeout}}
			if once {
				return service.RunCycle(command.Context())
			}
			return service.Run(command.Context())
		}}
	command.Flags().BoolVar(&once, "once", false, "run exactly one acquisition cycle")
	command.Flags().StringSliceVar(&keywords, "keyword", nil, "exact normalized keyword filter")
	command.Flags().StringVar(&taxonomy, "taxonomy-prefix", "", "taxonomy prefix filter")
	command.Flags().Uint32Var(&limit, "limit", 100, "maximum candidates per Carrier")
	return command
}

func configuredShortlist(settings config.EarningSettings) openfoxearning.ShortlistPolicy {
	return openfoxearning.ShortlistPolicy{Size: settings.Acquisition.ShortlistSize,
		MaximumPerIssuer: settings.Acquisition.MaximumPerIssuer, MaximumPerSource: settings.Acquisition.MaximumPerSource,
		MaximumPerTaxonomy: settings.Acquisition.MaximumPerTaxonomy, MaximumPerValueBand: settings.Acquisition.MaximumPerValueBand,
		ExplorationPercent: settings.Acquisition.ExplorationPercent}
}

func configuredFeatureGates(settings config.EarningSettings) openfoxearning.FeatureGates {
	return openfoxearning.FeatureGates{ObserveOnly: settings.ObserveOnly, Publication: settings.Gates.Publication,
		Contact: settings.Gates.Contact, Agreement: settings.Gates.Agreement, Execution: settings.Gates.Execution,
		DirectPayment: settings.Gates.DirectPayment, ExternalSettlement: settings.Gates.ExternalSettlement, TOSEscrow: settings.Gates.TOSEscrow}
}

func effectiveOutgoingPayment(value string) string {
	if value == "" {
		return "0"
	}
	return value
}

func configuredAgreementEvidenceProfiles(settings config.EarningSettings) []string {
	if settings.Gates.TOSEscrow {
		return []string{commerce.EvidenceProfilePaidDemandQuote}
	}
	return nil
}

func configuredWriterScopes(settings config.EarningSettings) []string {
	scopes := []string{"authority.instance"}
	if settings.Gates.Contact {
		scopes = append(scopes, "messenger.contact")
	}
	if settings.Gates.Agreement {
		scopes = append(scopes, "agreement.authorize", "agreement.propose")
	}
	if settings.Gates.Publication {
		scopes = append(scopes, "publication.publish", "publication.withdraw")
	}
	if settings.Gates.Execution {
		scopes = append(scopes, "billing.materialize", "billing.resolve", "content.delete", "content.upload", "delivery.release", "execution.prepare", "execution.start", "executor.effect", "portfolio.release", "portfolio.reserve", "reconcile.apply", "schedule.dependency.transition", "schedule.entry.transition")
	}
	if settings.Gates.DirectPayment {
		scopes = append(scopes, "billing.resolve", "payment.direct")
	}
	if settings.Gates.ExternalSettlement {
		scopes = append(scopes, "billing.resolve", "settlement.external")
	}
	if settings.Gates.TOSEscrow {
		scopes = append(scopes, "agreement.authorize", "escrow.transition", "portfolio.reserve", "provider.offer")
	}
	sort.Strings(scopes)
	write := 0
	for _, scope := range scopes {
		if write == 0 || scopes[write-1] != scope {
			scopes[write] = scope
			write++
		}
	}
	return scopes[:write]
}

func configuredSettlementParameters(input map[string]string) map[string][]byte {
	result := make(map[string][]byte, len(input))
	for adapter, parameters := range input {
		result[adapter] = []byte(parameters)
	}
	return result
}

func configuredSupplyOfferPolicies(settings config.EarningSettings) []openfoxearning.SupplyOfferPolicy {
	policies := make([]openfoxearning.SupplyOfferPolicy, 0, len(settings.Capabilities))
	for _, capability := range settings.Capabilities {
		if capability.Offer == nil {
			continue
		}
		offer := capability.Offer
		policies = append(policies, openfoxearning.SupplyOfferPolicy{
			CapabilityNamespace: capability.Namespace, CapabilityIdentifier: capability.Identifier,
			AssetNamespace: offer.AssetNamespace, AssetIdentifier: offer.AssetIdentifier, Unit: offer.Unit,
			MinimumRevenueAtomic: offer.MinimumRevenueAtomic, MaximumRevenueAtomic: offer.MaximumRevenueAtomic,
			MaximumUnitCostAtomic: offer.MaximumUnitCostAtomic, SettlementAdapterURI: offer.SettlementAdapterURI,
			TaxonomyPrefixes:  append([]string(nil), offer.TaxonomyPrefixes...),
			RequiredKeywords:  append([]string(nil), offer.RequiredKeywords...),
			MinimumTTLSeconds: offer.MinimumTTLSeconds, MaximumTTLSeconds: offer.MaximumTTLSeconds})
	}
	return policies
}

func configuredCarriers(settings config.EarningSettings) ([]openfoxearning.Carrier, error) {
	carriers := make([]openfoxearning.Carrier, 0, len(settings.Carriers))
	for _, configured := range settings.Carriers {
		kind := configured.Kind
		if kind == "" {
			kind = "http"
		}
		if kind == "directory" {
			carriers = append(carriers, openfoxearning.DirectoryCarrier{CarrierID: configured.ID, Directory: configured.Directory})
			continue
		}
		carrier, err := openfoxearning.NewHTTPCarrier(configured.ID, configured.Endpoint, configured.ReadToken.String(), 30*time.Second)
		if err != nil {
			return nil, err
		}
		carriers = append(carriers, carrier)
	}
	return carriers, nil
}

func configuredContentResolver(settings config.EarningSettings) openfoxearning.IntentContentResolver {
	if len(settings.Retrieval.AllowedOrigins) == 0 {
		return nil
	}
	return openfoxearning.SecureIntentContentResolver{Retriever: commerce.SecureContentRetriever{Policy: commerce.ContentRetrievalPolicy{
		SchemaVersion: 1, AllowedOrigins: append([]string(nil), settings.Retrieval.AllowedOrigins...),
		MaxRedirects: settings.Retrieval.MaximumRedirects, MaxConnections: settings.Retrieval.MaximumConnections,
		MaxResponseHeaderBytes: settings.Retrieval.MaximumResponseHeaderBytes, MaxCompressedBytes: settings.Retrieval.MaximumCompressedBytes,
		MaxDecodedBytes: settings.Retrieval.MaximumDecodedBytes, TimeoutMillis: settings.Retrieval.TimeoutMillis}}}
}

func configuredInventory(settings config.EarningSettings, authority openfoxearning.EconomicAuthority, now time.Time) openfoxearning.InventorySnapshot {
	capabilities := make([]openfoxearning.Capability, 0, len(settings.Capabilities))
	for _, capability := range settings.Capabilities {
		capabilities = append(capabilities, openfoxearning.Capability{Namespace: capability.Namespace, Identifier: capability.Identifier,
			Version: capability.Version, State: openfoxearning.CapabilityReady, Authority: settings.OwnerID, EvidenceDigest: capability.EvidenceDigest,
			RevocationGeneration: 1, ExpiresAtUnix: uint64(now.Add(10 * time.Minute).Unix())})
	}
	available := openfoxearning.ResourceCapacity{CPUUnits: settings.Resources.CPUUnits, MemoryBytes: settings.Resources.MemoryBytes,
		StorageBytes: settings.Resources.StorageBytes, ModelTokens: settings.Resources.ModelTokens, APIAtomicBudget: settings.Resources.APIAtomicBudget,
		Concurrency: settings.Resources.Concurrency}
	portfolioRevision := uint64(1)
	if authority != nil {
		revision, _, reservations := authority.Snapshot()
		portfolioRevision = revision
		for _, reservation := range reservations {
			if reservation.Released {
				continue
			}
			if reservation.ComputeUnits >= available.CPUUnits {
				available.CPUUnits = 0
			} else {
				available.CPUUnits -= reservation.ComputeUnits
			}
			if reservation.SpendAtomic >= available.APIAtomicBudget {
				available.APIAtomicBudget = 0
			} else {
				available.APIAtomicBudget -= reservation.SpendAtomic
			}
		}
	}
	return openfoxearning.InventorySnapshot{OwnerID: settings.OwnerID, AgentID: settings.AgentID, CreatedAtUnix: uint64(now.Unix()),
		ExpiresAtUnix: uint64(now.Add(10 * time.Minute).Unix()), SourceGeneration: 1, PortfolioRevision: portfolioRevision, PolicyRevision: 1,
		ConsistencyToken: fmt.Sprintf("runtime:%d", now.UnixNano()), Capabilities: capabilities,
		Available: available, SupportedSettlementAdapters: append([]string(nil), settings.SettlementAdapters...)}
}

func loadOrCreateAuthorityKey(directory string) (ed25519.PrivateKey, error) {
	return loadOrCreateNamedKey(directory, "authority-ed25519.key")
}

func loadOrCreateNamedKey(directory, name string) (ed25519.PrivateKey, error) {
	if name == "" || filepath.Base(name) != name {
		return nil, errors.New("private key name is invalid")
	}
	path := filepath.Join(directory, name)
	if info, err := os.Lstat(path); err == nil {
		return readAuthorityKey(path, info)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	if _, err = file.Write(key); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return key, nil
}

func loadAuthorityKey(directory string) (ed25519.PrivateKey, error) {
	path := filepath.Join(directory, "authority-ed25519.key")
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("economic authority has not been initialized")
		}
		return nil, err
	}
	return readAuthorityKey(path, info)
}

func readAuthorityKey(path string, info os.FileInfo) (ed25519.PrivateKey, error) {
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() != ed25519.PrivateKeySize {
		return nil, errors.New("economic authority key file is invalid")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ed25519.PrivateKey(raw), nil
}

func statusCommand() *cobra.Command {
	return &cobra.Command{Use: "status", Short: "Show fail-closed earning gates without secrets", Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			cfg, err := internal.LoadConfig()
			if err != nil {
				return err
			}
			validation := "valid"
			if err := cfg.Earning.Validate(); err != nil {
				validation = err.Error()
			}
			carrierIDs := make([]string, 0, len(cfg.Earning.Carriers))
			for _, carrier := range cfg.Earning.Carriers {
				carrierIDs = append(carrierIDs, carrier.ID)
			}
			output := struct {
				Enabled                    bool     `json:"enabled"`
				Mode                       string   `json:"mode"`
				ObserveOnly                bool     `json:"observe_only"`
				Validation                 string   `json:"validation"`
				MinimumIndependentCarriers uint32   `json:"minimum_independent_carriers"`
				CarrierIDs                 []string `json:"carrier_ids"`
				Gates                      any      `json:"gates"`
			}{cfg.Earning.Enabled, cfg.Earning.EffectiveMode(), cfg.Earning.ObserveOnly, validation, cfg.Earning.MinimumIndependentCarriers, carrierIDs, cfg.Earning.Gates}
			encoder := json.NewEncoder(command.OutOrStdout())
			encoder.SetIndent("", "  ")
			return encoder.Encode(output)
		}}
}

func registryCommand() *cobra.Command {
	return &cobra.Command{Use: "action-registry", Short: "Print the released semantic side-effect registry", Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			encoder := json.NewEncoder(command.OutOrStdout())
			encoder.SetIndent("", "  ")
			if err := encoder.Encode(commerce.SemanticActionRegistry()); err != nil {
				return fmt.Errorf("encode action registry: %w", err)
			}
			return nil
		}}
}
