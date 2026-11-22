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
}

func guarantorCommand() *cobra.Command {
	command := &cobra.Command{Use: "guarantor", Short: "Inspect the owner-gated Agent Guarantor runtime", Args: cobra.NoArgs}
	command.AddCommand(guarantorStatusCommand(), guarantorVerifyEvidenceCommand())
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
