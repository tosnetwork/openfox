package earning

import (
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/tosnetwork/openfox/cmd/openfox/internal"
	"github.com/tosnetwork/openfox/pkg/config"
	openfoxearning "github.com/tosnetwork/openfox/pkg/earning"
	guarantor "github.com/tosnetwork/tos-service-protocol/pkg/agentguarantor"
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
	command.AddCommand(guarantorStatusCommand())
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
			if info, err := os.Lstat(settings.JournalDirectory); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return errors.New("Agent Guarantor journal directory is unavailable")
			}
			journal, err := openfoxearning.OpenGuarantorJournal(settings.JournalDirectory, cfg.Earning.OwnerID, cfg.Earning.AgentID)
			if err != nil {
				return err
			}
			defer journal.Close()
			revision, offers, coverages := journal.Snapshot()
			report := guarantorStatusReport{Enabled: true, Role: settings.Role, ProfileID: profile.ProfileID,
				ProfileRevision: profile.Revision, ProfileDigest: profileDigest, ProviderAgentID: profile.ProviderAgentID,
				AssuranceLevels: append([]string(nil), settings.AssuranceLevels...), JournalRevision: revision,
				OfferCounts: map[string]uint64{}, CoverageCounts: map[string]uint64{}, ClaimCounts: map[string]uint64{},
				PaidAtomicByAsset: map[string]string{}, SideEffectsReady: false,
				BlockedCapabilities: []string{"configured-provider-coordinator", "collateral-attested", "independently-enforceable"}}
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
				prior, _ := new(big.Int).SetString(report.PaidAtomicByAsset[asset], 10)
				if prior == nil {
					prior = new(big.Int)
				}
				report.PaidAtomicByAsset[asset] = prior.Add(prior, paid).String()
			}
			encoder := json.NewEncoder(command.OutOrStdout())
			encoder.SetIndent("", "  ")
			return encoder.Encode(report)
		}}
}
