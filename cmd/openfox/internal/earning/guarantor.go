package earning

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"time"

	"github.com/spf13/cobra"
	guarantor "github.com/tosnetwork/ai/protocol/pkg/agentguarantor"

	"github.com/tosnetwork/openfox/cmd/openfox/internal"
	"github.com/tosnetwork/openfox/pkg/config"
	openfoxearning "github.com/tosnetwork/openfox/pkg/earning"
)

type guarantorStatusReport struct {
	Enabled             bool              `json:"enabled"`
	Role                string            `json:"role"`
	ProfileID           string            `json:"profile_id"`
	ProfileRevision     uint64            `json:"profile_revision"`
	ProfileDigest       string            `json:"profile_digest"`
	ProviderAgentID     string            `json:"provider_agent_id"`
	AssuranceLevels     []string          `json:"assurance_levels"`
	JournalRevision     uint64            `json:"journal_revision"`
	OfferCounts         map[string]uint64 `json:"offer_counts"`
	CoverageCounts      map[string]uint64 `json:"coverage_counts"`
	ClaimCounts         map[string]uint64 `json:"claim_counts"`
	PaidAtomicByAsset   map[string]string `json:"paid_atomic_by_asset"`
	SideEffectsReady    bool              `json:"side_effects_ready"`
	BlockedCapabilities []string          `json:"blocked_capabilities"`
	// ActionPlans are the actions coordinator calls prepared and have not
	// committed a receipt for, one per head. Each holds its head until its
	// request is repeated or the plan is abandoned.
	ActionPlans []guarantorActionPlanStatus `json:"action_plans"`
}

// guarantorActionPlanStatus is what status shows of one stored action plan:
// the head it holds and the action it prepared, without its request.
type guarantorActionPlanStatus struct {
	Kind               string `json:"kind"`
	ScopeID            string `json:"scope_id"`
	SubjectID          string `json:"subject_id,omitempty"`
	ActionKind         string `json:"action_kind"`
	StableActionID     string `json:"stable_action_id"`
	ExactRequestDigest string `json:"exact_request_digest"`
	WriterGeneration   uint64 `json:"writer_generation"`
	PreparedAtUnix     uint64 `json:"prepared_at_unix"`
}

// guarantorActionPlanStatuses lists stored action plans for status, in the
// order given. The list is empty, never absent, when there is none.
func guarantorActionPlanStatuses(plans []openfoxearning.GuarantorActionPlan) []guarantorActionPlanStatus {
	statuses := make([]guarantorActionPlanStatus, 0, len(plans))
	for _, plan := range plans {
		statuses = append(statuses, guarantorActionPlanStatus{
			Kind: plan.Kind, ScopeID: plan.ScopeID, SubjectID: plan.SubjectID, ActionKind: plan.Action.ActionKind,
			StableActionID: plan.Action.StableActionID, ExactRequestDigest: plan.Action.ExactRequestDigest,
			WriterGeneration: plan.Action.WriterGeneration, PreparedAtUnix: plan.PreparedAtUnix,
		})
	}
	return statuses
}

func guarantorCommand() *cobra.Command {
	command := &cobra.Command{Use: "guarantor", Short: "Inspect the owner-gated Agent Guarantor runtime", Args: cobra.NoArgs}
	command.AddCommand(guarantorStatusCommand(), guarantorVerifyEvidenceCommand(), guarantorAbandonPlanCommand())
	return command
}

// validateGuarantorCLIAssembly prevents a generic earning worker from looking
// healthy while silently omitting an enabled Guarantor Provider. The Provider
// requires owner-supplied underwriting, historical authority, Decision
// Authority, and payment dependencies which must be assembled explicitly via
// earning.NewGuarantorProviderRuntime; they must never be inferred from model
// output, Intent content, or weak CLI defaults.
func validateGuarantorCLIAssembly(settings config.EarningSettings) error {
	if settings.AgentGuarantor.Enabled || settings.Gates.AgentGuarantor {
		return errors.New("Agent Guarantor side effects require an explicitly assembled NewGuarantorProviderRuntime; the generic earning CLI does not install authority dependencies")
	}
	return nil
}

func guarantorStatusCommand() *cobra.Command {
	return &cobra.Command{Use: "status", Short: "Verify the configured unsecured Guarantor profile and durable journal", Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			cfg, err := internal.LoadConfig()
			if err != nil {
				return err
			}
			if err := cfg.Earning.Validate(); err != nil {
				return err
			}
			settings := cfg.Earning.AgentGuarantor
			if !settings.Enabled || !cfg.Earning.Gates.AgentGuarantor {
				return errors.New("Agent Guarantor owner gate is disabled")
			}
			var artifact guarantor.GuarantorServiceProfileArtifactV1
			if err := decodeBoundedJSONFile(settings.ProfileArtifactFile, 1<<20, &artifact); err != nil {
				return err
			}
			now := time.Now().UTC()
			authorities, err := openfoxearning.ParsePinnedIntentAuthorities(cfg.Earning.TrustedIntentIssuerKeys)
			if err != nil {
				return err
			}
			profile, err := guarantor.ResolveServiceProfileArtifactV1(artifact, authorities, now)
			if err != nil {
				return err
			}
			profileDigest := artifact.SelectedServiceProfileDigest
			if profile.ProviderAgentID != cfg.Earning.AgentID {
				return errors.New("configured Guarantor profile belongs to another Agent")
			}
			report := guarantorStatusReport{
				Enabled:           true,
				Role:              settings.Role,
				ProfileID:         profile.ProfileID,
				ProfileRevision:   profile.Revision,
				ProfileDigest:     profileDigest,
				ProviderAgentID:   profile.ProviderAgentID,
				AssuranceLevels:   append([]string(nil), settings.AssuranceLevels...),
				OfferCounts:       map[string]uint64{},
				CoverageCounts:    map[string]uint64{},
				ClaimCounts:       map[string]uint64{},
				PaidAtomicByAsset: map[string]string{},
				SideEffectsReady:  false,
				BlockedCapabilities: []string{
					"configured-provider-coordinator",
					"collateral-attested",
					"independently-enforceable",
				},
			}
			if err := summarizeGuarantorJournal(settings.JournalDirectory, cfg.Earning.OwnerID, cfg.Earning.AgentID,
				&report); err != nil {
				return err
			}
			encoder := json.NewEncoder(command.OutOrStdout())
			encoder.SetIndent("", "  ")
			return encoder.Encode(report)
		}}
}

// inspectGuarantorJournal opens the journal for a command that only reads it.
// Nothing in the journal directory is created, rewritten or removed; what a
// crash left behind is swept by the Provider when it opens its journal.
func inspectGuarantorJournal(directory, ownerID, agentID string) (*openfoxearning.GuarantorJournal, error) {
	if info, err := os.Lstat(directory); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("Agent Guarantor journal directory is unavailable")
	}
	return openfoxearning.OpenGuarantorJournalReadOnly(directory, ownerID, agentID)
}

// summarizeGuarantorJournal fills the journal part of a status report from a
// journal opened read-only.
func summarizeGuarantorJournal(directory, ownerID, agentID string, report *guarantorStatusReport) (err error) {
	journal, err := inspectGuarantorJournal(directory, ownerID, agentID)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, journal.Close()) }()
	revision, offers, coverages, err := journal.Snapshot()
	if err != nil {
		return fmt.Errorf("Agent Guarantor journal could not be read: %w", err)
	}
	report.JournalRevision = revision
	plans, err := journal.ActionPlans()
	if err != nil {
		return fmt.Errorf("Agent Guarantor journal action plans could not be read: %w", err)
	}
	report.ActionPlans = guarantorActionPlanStatuses(plans)
	for _, offer := range offers {
		report.OfferCounts[string(offer.Record.Status)]++
	}
	for _, coverage := range coverages {
		report.CoverageCounts[string(coverage.Record.CoverageStatus)]++
		for _, claim := range coverage.Claims {
			report.ClaimCounts[string(claim.ClaimStatus)]++
		}
		asset := coverage.Terms.CoverageAsset.AssetNamespace + ":" + coverage.Terms.CoverageAsset.AssetIdentifier + ":" + coverage.Terms.CoverageAsset.Unit
		paid, ok := new(big.Int).SetString(coverage.PaidAtomic, 10)
		if !ok || paid.Sign() < 0 {
			return errors.New("Agent Guarantor journal contains a noncanonical paid amount")
		}
		prior := new(big.Int)
		if recorded, counted := report.PaidAtomicByAsset[asset]; counted {
			if _, ok := prior.SetString(recorded, 10); !ok {
				return errors.New("Agent Guarantor paid total is not a number")
			}
		}
		report.PaidAtomicByAsset[asset] = prior.Add(prior, paid).String()
	}
	return nil
}

// guarantorEvidenceVerification is what verify-evidence prints after every
// stored receipt passed.
type guarantorEvidenceVerification struct {
	Verified        bool   `json:"verified"`
	JournalRevision uint64 `json:"journal_revision"`
	Receipts        uint64 `json:"receipts"`
	Bytes           uint64 `json:"bytes"`
}

func guarantorVerifyEvidenceCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "verify-evidence",
		Short: "Read and hash every receipt the Guarantor journal stores; changes nothing and fails on the first bad receipt",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			cfg, err := internal.LoadConfig()
			if err != nil {
				return err
			}
			if err := cfg.Earning.Validate(); err != nil {
				return err
			}
			return verifyGuarantorJournalEvidence(cfg.Earning.AgentGuarantor.JournalDirectory, cfg.Earning.OwnerID,
				cfg.Earning.AgentID, command.OutOrStdout())
		},
	}
}

// verifyGuarantorJournalEvidence opens the journal read-only, checks every
// stored receipt file against the length and hash the journal records, and
// writes the totals. Any failure is returned, so the command exits non-zero:
// a journal that does not open, a receipt that is missing, of another length
// or of another hash, or a journal that cannot be closed. Nothing is printed
// as verified unless every receipt passed.
func verifyGuarantorJournalEvidence(directory, ownerID, agentID string, output io.Writer) (err error) {
	if directory == "" {
		return errors.New("Agent Guarantor journal directory is not configured")
	}
	journal, err := inspectGuarantorJournal(directory, ownerID, agentID)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, journal.Close()) }()
	revision, _, _, err := journal.Snapshot()
	if err != nil {
		return fmt.Errorf("Agent Guarantor journal could not be read: %w", err)
	}
	report, err := journal.VerifyStoredEvidence()
	if err != nil {
		return fmt.Errorf("Agent Guarantor stored evidence failed its integrity check after %d intact receipts: %w",
			report.Receipts, err)
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(guarantorEvidenceVerification{
		Verified: true, JournalRevision: revision,
		Receipts: report.Receipts, Bytes: report.Bytes,
	})
}

// guarantorPlanAbandonment is what abandon-plan prints: the plan of the head,
// the state its action has at the authority, and whether the plan was given
// up. Without --apply nothing is changed and Applied is false.
type guarantorPlanAbandonment struct {
	Applied        bool                      `json:"applied"`
	ActionPlan     guarantorActionPlanStatus `json:"action_plan"`
	AuthorityState string                    `json:"authority_state"`
}

// guarantorPlanAbandonmentLease is the writer lease the command takes to
// abandon a plan. It only has to outlast the rejection and the discard.
const guarantorPlanAbandonmentLease = 10 * time.Minute

func guarantorAbandonPlanCommand() *cobra.Command {
	var kind, scopeID, subjectID string
	var apply bool
	command := &cobra.Command{
		Use: "abandon-plan",
		Short: "Show the prepared action plan of one head, or with --apply give it up: the authority rejects " +
			"its action, then the journal discards the plan",
		Long: "A prepared action plan holds its head until its request is repeated. abandon-plan shows the plan " +
			"and its action's state at the authority, and changes nothing. With --apply it takes the writer, " +
			"which fences out a running Provider, has the authority reject the prepared action and then discards " +
			"the plan. The rejection is final: the same request cannot be admitted again for that head. A plan " +
			"whose action is terminal is refused; repeat its request to commit its receipt instead.",
		Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			cfg, err := internal.LoadConfig()
			if err != nil {
				return err
			}
			if err = cfg.Earning.Validate(); err != nil {
				return err
			}
			if !cfg.Earning.AgentGuarantor.Enabled || !cfg.Earning.Gates.AgentGuarantor {
				return errors.New("Agent Guarantor owner gate is disabled")
			}
			authority, closeAuthority, err := openConfiguredAuthority(cfg.Earning, false)
			if err != nil {
				return err
			}
			defer closeAuthority()
			return abandonGuarantorActionPlan(command, cfg.Earning.AgentGuarantor.JournalDirectory,
				cfg.Earning.OwnerID, cfg.Earning.AgentID, authority,
				authorityInstanceID(cfg.Earning, "guarantor-plan-abandonment"), kind, scopeID, subjectID, apply)
		},
	}
	command.Flags().StringVar(&kind, "kind", "", "action plan kind, as status lists it")
	command.Flags().StringVar(&scopeID, "scope", "", "action plan scope ID, as status lists it")
	command.Flags().StringVar(&subjectID, "subject", "", "action plan subject ID, as status lists it, if any")
	command.Flags().BoolVar(&apply, "apply", false, "reject the prepared action and discard the plan; default shows it only")
	_ = command.MarkFlagRequired("kind")
	_ = command.MarkFlagRequired("scope")
	return command
}

// abandonGuarantorActionPlan shows the action plan of one head with its
// action's authority state, or with apply abandons it under a writer fence it
// takes from authority. It fails when the journal holds no plan for the head,
// when the authority cannot be asked, and, with apply, whenever the journal
// refuses the abandonment, which leaves the plan as it was.
func abandonGuarantorActionPlan(command *cobra.Command, directory, ownerID, agentID string,
	authority openfoxearning.EconomicAuthority, instanceID, kind, scopeID, subjectID string, apply bool,
) (err error) {
	if directory == "" {
		return errors.New("Agent Guarantor journal directory is not configured")
	}
	// The plan is looked up read-only, so a head without one changes nothing.
	plan, found, err := inspectGuarantorActionPlan(directory, ownerID, agentID, kind, scopeID, subjectID)
	if err != nil {
		return err
	}
	if !found {
		return errors.New("Agent Guarantor journal holds no action plan for that head")
	}
	if authority == nil {
		return errors.New("Agent Guarantor action authority is unavailable")
	}
	report := guarantorPlanAbandonment{ActionPlan: guarantorActionPlanStatuses(
		[]openfoxearning.GuarantorActionPlan{plan})[0]}
	if !apply {
		report.AuthorityState = string(authority.Resolve(plan.Action.StableActionID,
			plan.Action.ExactRequestDigest).State)
	} else {
		journal, openErr := openfoxearning.OpenGuarantorJournal(directory, ownerID, agentID)
		if openErr != nil {
			return openErr
		}
		defer func() { err = errors.Join(err, journal.Close()) }()
		fence, acquireErr := authority.AcquireWriter(command.Context(), instanceID, []string{plan.Action.ActionKind},
			guarantorPlanAbandonmentLease)
		if acquireErr != nil {
			return acquireErr
		}
		abandoned, resolution, abandonErr := journal.AbandonPreparedActionPlan(kind, scopeID, subjectID, authority,
			fence, authority.AuthorityNow())
		if abandonErr != nil {
			return abandonErr
		}
		report.ActionPlan = guarantorActionPlanStatuses([]openfoxearning.GuarantorActionPlan{abandoned})[0]
		report.Applied, report.AuthorityState = true, string(resolution.State)
	}
	encoder := json.NewEncoder(command.OutOrStdout())
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

// inspectGuarantorActionPlan reads the action plan of one head from a journal
// opened read-only.
func inspectGuarantorActionPlan(directory, ownerID, agentID, kind, scopeID, subjectID string,
) (plan openfoxearning.GuarantorActionPlan, found bool, err error) {
	journal, err := inspectGuarantorJournal(directory, ownerID, agentID)
	if err != nil {
		return openfoxearning.GuarantorActionPlan{}, false, err
	}
	defer func() { err = errors.Join(err, journal.Close()) }()
	plan, found, err = journal.ActionPlan(kind, scopeID, subjectID)
	if err != nil {
		return openfoxearning.GuarantorActionPlan{}, false,
			fmt.Errorf("Agent Guarantor journal action plans could not be read: %w", err)
	}
	return plan, found, nil
}
