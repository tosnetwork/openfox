package earning

import (
	"context"
	"errors"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
)

// RelayTerminalEvidenceRenderer is deliberately weaker than an independent
// evidence source. It may render an already validated terminal journal record,
// but it cannot by itself advertise sponsorship production or verification.
type RelayTerminalEvidenceRenderer interface {
	agentrelay.FinalityEvidenceSource
	SupportsRelayEvidenceRendering(agentrelay.RelayEvidenceCapability) bool
}

type relayProviderSponsorshipEvidence interface {
	RelaySponsorshipEvidenceCapabilities() RelaySponsorshipEvidenceCapabilities
	RelaySponsorshipTerminalProfileCapability
	RelaySponsorshipProviderAbsenceCapability
	RelaySponsorshipProviderTransactionAbsenceCapability
}

// CompositeRelayFinalityEvidenceSource conjuncts the TOS terminal renderer
// with the concrete, snapshot-bound sponsorship producer. This is the only
// stock Provider object allowed to advertise lower-assurance sponsorship;
// neither half is sufficient alone.
type CompositeRelayFinalityEvidenceSource struct {
	renderer    RelayTerminalEvidenceRenderer
	direct      agentrelay.IndependentFinalityEvidenceSource
	sponsorship relayProviderSponsorshipEvidence
}

func NewCompositeRelayFinalityEvidenceSource(renderer RelayTerminalEvidenceRenderer,
	sponsorship relayProviderSponsorshipEvidence) (*CompositeRelayFinalityEvidenceSource, error) {
	if renderer == nil || sponsorship == nil {
		return nil, errors.New("composite relay evidence source requires renderer and sponsorship producer")
	}
	direct, _ := renderer.(agentrelay.IndependentFinalityEvidenceSource)
	return &CompositeRelayFinalityEvidenceSource{renderer: renderer, direct: direct,
		sponsorship: sponsorship}, nil
}

func (source *CompositeRelayFinalityEvidenceSource) SupportsRelayEvidenceCapability(
	capability agentrelay.RelayEvidenceCapability) bool {
	if source == nil || source.renderer == nil {
		return false
	}
	if capability.Mode == agentrelay.ModeRelayExact {
		return source.direct != nil && source.direct.SupportsRelayEvidenceCapability(capability)
	}
	if source.sponsorship == nil || capability.AssuranceLevel == agentrelay.AssuranceAutonomousDecentralized ||
		(capability.Mode != agentrelay.ModeSponsorOnly && capability.Mode != agentrelay.ModeSponsorAndRelay) ||
		!source.renderer.SupportsRelayEvidenceRendering(capability) ||
		capability.SponsorshipTerminalProfile == nil {
		return false
	}
	policy := RelaySponsorshipReleasePolicy{EvidenceClass: capability.SponsorshipReleaseProfile.EvidenceClass,
		ProfileURI:    capability.SponsorshipReleaseProfile.ProfileURI,
		ProfileDigest: capability.SponsorshipReleaseProfile.ProfileDigest}
	available := source.sponsorship.RelaySponsorshipEvidenceCapabilities()
	if !available.TerminalEvidence ||
		!supportsRelaySponsorshipReleasePolicy(available.SupportedReleasePolicies, policy) ||
		!source.sponsorship.SupportsRelaySponsorshipTerminalFinalityProfile(
			*capability.SponsorshipTerminalProfile, nil) ||
		!source.sponsorship.SupportsRelaySponsorshipComponentAbsenceEvidence(capability) {
		return false
	}
	if capability.Mode == agentrelay.ModeSponsorAndRelay &&
		(!source.sponsorship.SupportsRelayDualAbsenceEvidence(capability) ||
			!source.sponsorship.SupportsRelayTransactionComponentAbsenceEvidence(capability)) {
		return false
	}
	return true
}

func (source *CompositeRelayFinalityEvidenceSource) SupportsRelayDualAbsenceEvidence(
	capability agentrelay.RelayEvidenceCapability) bool {
	return capability.Mode == agentrelay.ModeSponsorAndRelay &&
		source.SupportsRelayEvidenceCapability(capability) &&
		source.sponsorship.SupportsRelayDualAbsenceEvidence(capability)
}

func (source *CompositeRelayFinalityEvidenceSource) SupportsRelaySponsorshipComponentAbsenceEvidence(
	capability agentrelay.RelayEvidenceCapability) bool {
	return capability.Mode != agentrelay.ModeRelayExact &&
		source.SupportsRelayEvidenceCapability(capability) &&
		source.sponsorship.SupportsRelaySponsorshipComponentAbsenceEvidence(capability)
}

func (source *CompositeRelayFinalityEvidenceSource) SupportsRelayTransactionComponentAbsenceEvidence(
	capability agentrelay.RelayEvidenceCapability) bool {
	return capability.Mode == agentrelay.ModeSponsorAndRelay &&
		source.SupportsRelayEvidenceCapability(capability) &&
		source.sponsorship.SupportsRelayTransactionComponentAbsenceEvidence(capability)
}

func (source *CompositeRelayFinalityEvidenceSource) Evidence(ctx context.Context,
	record agentrelay.Record) (agentrelay.RelayFinalityEvidenceBody, error) {
	if source == nil || source.renderer == nil {
		return agentrelay.RelayFinalityEvidenceBody{}, errors.New("composite relay evidence renderer is unavailable")
	}
	capability, err := relayEvidenceCapabilityForExecution(record.ExecutionRequest())
	if err != nil || !source.SupportsRelayEvidenceCapability(capability) {
		return agentrelay.RelayFinalityEvidenceBody{}, errors.New("terminal record is outside the exact composite evidence capability")
	}
	return source.renderer.Evidence(ctx, record)
}

func (source *CompositeRelayFinalityEvidenceSource) HasRetrievableIndependentProofs() bool {
	return source != nil && source.direct != nil && source.direct.HasRetrievableIndependentProofs()
}

func (source *CompositeRelayFinalityEvidenceSource) HasRollbackResistantCheckpoint() bool {
	return source != nil && source.direct != nil && source.direct.HasRollbackResistantCheckpoint()
}

func (source *CompositeRelayFinalityEvidenceSource) HasRollbackResistantTerminalCommitment() bool {
	return source != nil && source.direct != nil && source.direct.HasRollbackResistantTerminalCommitment()
}

func (source *CompositeRelayFinalityEvidenceSource) terminalRenderer() RelayTerminalEvidenceRenderer {
	if source == nil {
		return nil
	}
	return source.renderer
}

var _ agentrelay.IndependentFinalityEvidenceSource = (*CompositeRelayFinalityEvidenceSource)(nil)
