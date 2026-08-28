package earning

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
)

const RelayClientCorroboratedTerminalProfileURI = agentrelay.ClientCorroboratedTerminalProfileURI
const relayV1UnderlyingActionKind = "payment.direct"

// RelayCapability identifies one independently enabled service-mode and
// assurance-level pair. A service mode says what may happen; the assurance
// level says which trust and recovery dependencies must be present. Neither
// dimension implies the other.
type RelayCapability struct {
	Mode           agentrelay.Mode
	AssuranceLevel agentrelay.AssuranceLevel
	Ready          bool
	// FailoverEnabled is true only for the exact-BOC decentralized route.
	// Sponsorship modes can still use decentralized quote selection, but V1
	// never creates a successor after a possibly executed top-up.
	FailoverEnabled bool
	Missing         []string
}

// RelayCapabilityReport is an evidence-based readiness result. Missing is
// deliberately machine-readable and stable so operators do not have to infer
// readiness from a generic "production accepted" flag.
type RelayCapabilityReport struct {
	Capabilities []RelayCapability
}

// RelaySponsorshipAssuranceCapability is implemented only by a sponsorship
// processor whose custody/evidence path can satisfy the selected assurance.
// A non-nil SponsorshipProcessor is intentionally insufficient: it may be
// able to submit a top-up while being unable to prove the exact
// AgreementPaymentRequestV3 credit at the requested assurance.
type RelaySponsorshipEvidenceCapabilities struct {
	SupportedReleasePolicies    []RelaySponsorshipReleasePolicy
	FreshBalanceSequenceRecheck bool
	// TerminalEvidence reports a concrete terminal-evidence resolver. For
	// observed_unproven it means an explicit
	// client-corroborated terminal predicate, not validator finality.
	// observed_unproven alone is never a complete sponsorship capability.
	TerminalEvidence         bool
	PortableFinalityEvidence bool
}

// RelaySponsorshipReleasePolicy is copied into every signed sponsorship
// request, Provider quote and Agreement binding. Readiness binds an exact
// profile URI and digest; a class-only boolean cannot authorize an arbitrary
// Provider-selected evidence model.
type RelaySponsorshipReleasePolicy struct {
	EvidenceClass agentrelay.SponsorshipReleaseEvidenceClass
	ProfileURI    string
	ProfileDigest string
}

type RelaySponsorshipAssuranceCapability interface {
	RelaySponsorshipEvidenceCapabilities() RelaySponsorshipEvidenceCapabilities
}

// RelaySponsorshipTerminalProfileCapability prevents a resolver that can only
// prove one concrete finality profile (for example confirmation depth one)
// from making a profile-agnostic readiness claim.
type RelaySponsorshipTerminalProfileCapability interface {
	// A nil snapshot checks the current owner configuration before a new Quote
	// is signed. A non-nil snapshot checks immutable per-action recovery state
	// and must not consult mutable current configuration.
	SupportsRelaySponsorshipTerminalFinalityProfile(agentrelay.FinalityProfile,
		*RelaySponsorshipEvidenceSnapshot) bool
}

// RelaySponsorshipClientEvidenceCapability is a concrete client-side proof
// capability. A non-nil verifier is insufficient when it only recognizes
// provider-local cached proof bytes that are absent from the signed wire
// evidence.
type RelaySponsorshipClientEvidenceCapability interface {
	SupportsRelaySponsorshipTransactionEvidence(agentrelay.AssuranceLevel,
		RelaySponsorshipReleasePolicy, agentrelay.FinalityProfile) bool
}

// RelaySponsorshipProviderAbsenceCapability is the provider-side producer for
// the exact typed dual-absence proof. The general FinalityEvidenceSource can
// transport an already terminal record, but it cannot substitute for this
// pre-terminal resolver.
type RelaySponsorshipProviderAbsenceCapability interface {
	SupportsRelaySponsorshipComponentAbsenceEvidence(agentrelay.RelayEvidenceCapability) bool
	SupportsRelayDualAbsenceEvidence(agentrelay.RelayEvidenceCapability) bool
}

type RelaySponsorshipProviderTransactionAbsenceCapability interface {
	SupportsRelayTransactionComponentAbsenceEvidence(agentrelay.RelayEvidenceCapability) bool
}

// RelaySponsorshipClientSnapshotVerifier freezes the requester-owned RPC
// configuration before Quote/admission and verifies terminal evidence through
// that immutable snapshot. Provider snapshot identities are intentionally not
// compared: each side freezes different credential/config bytes, while both
// must reproduce the same signed release descriptor and failure domains.
type RelaySponsorshipClientSnapshotVerifier interface {
	RelaySponsorshipClientEvidenceCapability
	FreezeRelaySponsorshipClientEvidenceSnapshot(context.Context,
		agentrelay.RelayQuoteRequestBody) (RelaySponsorshipEvidenceSnapshot, error)
	ValidateRelaySponsorshipClientEvidenceSnapshot(agentrelay.SponsorshipReleaseProfile,
		RelaySponsorshipEvidenceSnapshot) error
	VerifySponsorshipTransactionEvidenceFromSnapshot(context.Context,
		agentrelay.RelaySponsorshipTransactionEvidence, agentrelay.RelaySponsorshipEvidenceContext,
		agentrelay.FinalityProfile, RelaySponsorshipEvidenceSnapshot) error
}

// RelayAutonomousAdmissionAssurance is a capability of the concrete
// side-effect admission authority, not a deployment label. Autonomous mode
// requires one linearizable high-water that cannot be rolled back to mint a
// second generation or admission sequence.
type RelayAutonomousAdmissionAssurance interface {
	HasLinearizableRelayAdmission() bool
	HasRollbackResistantRelayAdmissionHighWater() bool
}

// RelayAutonomousRouteAssurance is required for every autonomous route. A
// rollback can fork the route head, provider-fee exposure, attempt lineage, or
// submit_started boundary even when the exact transaction BOC is immutable.
// The shipped local file journal deliberately reports false.
type RelayAutonomousRouteAssurance interface {
	HasRollbackResistantRelayRouteHighWater() bool
}

// RelayAutonomousProviderJournalAssurance is implemented only by a Provider
// journal whose quote reservation, stage consumption, sponsorship attempt,
// exposure and terminal high-waters share a linearizable rollback-resistant
// admission domain. A local file or memory journal is not this capability.
type RelayAutonomousProviderJournalAssurance interface {
	HasLinearizableRelayProviderJournal() bool
	HasRollbackResistantRelayProviderJournalHighWater() bool
}

func (report RelayCapabilityReport) ReadyModes() []agentrelay.Mode {
	modes := make([]agentrelay.Mode, 0, len(report.Capabilities))
	for _, capability := range report.Capabilities {
		if capability.Ready {
			modes = append(modes, capability.Mode)
		}
	}
	return modes
}

func (report RelayCapabilityReport) Ready() bool {
	return len(report.Capabilities) > 0 && len(report.ReadyModes()) == len(report.Capabilities)
}

func validRelayAssuranceLevel(level agentrelay.AssuranceLevel) bool {
	return level == agentrelay.AssuranceTrustedLocal ||
		level == agentrelay.AssuranceAuthorizedSingleProvider ||
		level == agentrelay.AssuranceAutonomousDecentralized
}

func relayProfileSupportsAssurance(profile agentrelay.RelayServiceProfile,
	level agentrelay.AssuranceLevel) bool {
	for _, supported := range profile.SupportedAssuranceLevels {
		if supported == level {
			return true
		}
	}
	return false
}

func relayProfileSupportsMode(profile agentrelay.RelayServiceProfile, mode agentrelay.Mode) bool {
	for _, supported := range profile.SupportedModes {
		if supported == mode {
			return true
		}
	}
	return false
}

// relayProfileEvidenceCapabilitiesSupported proves that every exact terminal
// tuple selectable from the signed profile and (when present) the local owner
// policy is implemented by the concrete source/verifier. V1 deliberately
// probes only payment.direct: an empty action kind is never a wildcard, and a
// future action kind must add an explicit capability entry before readiness
// can be claimed.
func relayProfileEvidenceCapabilitiesSupported(profile agentrelay.RelayServiceProfile,
	ownerPolicy *RelayOwnerPolicy, level agentrelay.AssuranceLevel, mode agentrelay.Mode,
	sponsorshipPolicy RelaySponsorshipReleasePolicy,
	supports func(agentrelay.RelayEvidenceCapability) bool) bool {
	if supports == nil || !validRelayAssuranceLevel(level) || !knownRelayMode(mode) {
		return false
	}
	networks := make([]agentrelay.NetworkDomain, 0, len(profile.NetworkDomains))
	for _, network := range profile.NetworkDomains {
		if ownerPolicy == nil || containsRelayNetwork(ownerPolicy.NetworkDomains, network) {
			networks = append(networks, network)
		}
	}
	transactions := make([]agentrelay.TransactionProfile, 0, len(profile.TransactionProfiles))
	for _, transaction := range profile.TransactionProfiles {
		if ownerPolicy == nil || containsRelayTransactionProfile(ownerPolicy.TransactionProfiles, transaction) {
			transactions = append(transactions, transaction)
		}
	}
	relayProfiles := make([]agentrelay.FinalityProfile, 0, len(profile.FinalityProfiles))
	sponsorshipProfiles := make([]agentrelay.FinalityProfile, 0, len(profile.FinalityProfiles))
	for _, finality := range profile.FinalityProfiles {
		if ownerPolicy != nil && !containsRelayFinalityProfile(ownerPolicy.FinalityProfiles, finality) {
			continue
		}
		if mode != agentrelay.ModeSponsorOnly &&
			(finality.TerminalEvidenceClass == agentrelay.RelayTerminalValidatorFinality ||
				finality.TerminalEvidenceClass == agentrelay.RelayTerminalProviderCorroborated &&
					level != agentrelay.AssuranceAutonomousDecentralized) {
			relayProfiles = append(relayProfiles, finality)
		}
		if mode != agentrelay.ModeRelayExact {
			switch sponsorshipPolicy.EvidenceClass {
			case agentrelay.SponsorshipReleaseValidatorFinality:
				if finality.TerminalEvidenceClass == agentrelay.SponsorshipTerminalValidatorFinality &&
					finality.ProfileURI == sponsorshipPolicy.ProfileURI &&
					finality.ProfileDigest == sponsorshipPolicy.ProfileDigest {
					sponsorshipProfiles = append(sponsorshipProfiles, finality)
				}
			case agentrelay.SponsorshipReleaseObservedUnproven:
				if level != agentrelay.AssuranceAutonomousDecentralized &&
					finality.TerminalEvidenceClass == agentrelay.SponsorshipTerminalClientCorroborated &&
					finality.ProfileURI == agentrelay.ClientCorroboratedTerminalProfileURI {
					sponsorshipProfiles = append(sponsorshipProfiles, finality)
				}
			}
		}
	}
	if len(networks) == 0 || len(transactions) == 0 ||
		mode != agentrelay.ModeSponsorOnly && len(relayProfiles) == 0 ||
		mode != agentrelay.ModeRelayExact && len(sponsorshipProfiles) == 0 {
		return false
	}
	if mode == agentrelay.ModeSponsorOnly {
		relayProfiles = append(relayProfiles, agentrelay.FinalityProfile{})
	}
	if mode == agentrelay.ModeRelayExact {
		sponsorshipProfiles = append(sponsorshipProfiles, agentrelay.FinalityProfile{})
	}
	for _, network := range networks {
		for _, transaction := range transactions {
			for _, relayProfile := range relayProfiles {
				for _, sponsorshipProfile := range sponsorshipProfiles {
					capability := agentrelay.RelayEvidenceCapability{Mode: mode, AssuranceLevel: level,
						Network: network, TransactionProfileURI: transaction.ProfileURI,
						TransactionProfileDigest: transaction.ProfileDigest,
						UnderlyingActionKind:     relayV1UnderlyingActionKind}
					if mode != agentrelay.ModeSponsorOnly {
						selected := relayProfile
						capability.RelayTerminalEvidenceClass = selected.TerminalEvidenceClass
						capability.RelayFinalityProfile = &selected
					}
					if mode != agentrelay.ModeRelayExact {
						selected := sponsorshipProfile
						capability.SponsorshipTerminalEvidenceClass = selected.TerminalEvidenceClass
						capability.SponsorshipReleaseProfile = agentrelay.SponsorshipReleaseProfile{
							EvidenceClass: sponsorshipPolicy.EvidenceClass, ProfileURI: sponsorshipPolicy.ProfileURI,
							ProfileDigest: sponsorshipPolicy.ProfileDigest}
						capability.SponsorshipTerminalProfile = &selected
						if level != agentrelay.AssuranceAutonomousDecentralized {
							capability.AbsenceProofProfileURI = agentrelay.RelayAbsenceTOSRPCProofProfileURI
							capability.AbsenceProofProfileDigest, _ = agentrelay.RelayAbsenceTOSRPCProofProfileDigest()
						}
					}
					if !supports(capability) {
						return false
					}
				}
			}
		}
	}
	return true
}

func relayEvidenceCapabilityForQuoteBody(profile agentrelay.RelayServiceProfile,
	body agentrelay.RelayQuoteRequestBody) (agentrelay.RelayEvidenceCapability, error) {
	capability := agentrelay.RelayEvidenceCapability{Mode: body.Mode, AssuranceLevel: body.AssuranceLevel,
		Network: body.Network, TransactionProfileURI: body.TransactionProfileURI,
		TransactionProfileDigest: body.TransactionProfileDigest, UnderlyingActionKind: body.UnderlyingActionKind,
		RelayTerminalEvidenceClass:       body.RelayTerminalEvidenceClass,
		SponsorshipTerminalEvidenceClass: body.SponsorshipTerminalEvidenceClass,
		SponsorshipReleaseProfile:        body.SelectedSponsorshipReleaseProfile()}
	if body.Mode != agentrelay.ModeSponsorOnly {
		selected, found := relayFinalityProfile(profile.FinalityProfiles,
			body.RelayFinalityProfileURI, body.RelayFinalityProfileDigest)
		if !found || selected.TerminalEvidenceClass != body.RelayTerminalEvidenceClass {
			return agentrelay.RelayEvidenceCapability{}, errors.New("relay terminal profile is unavailable")
		}
		capability.RelayFinalityProfile = &selected
	}
	if body.Mode != agentrelay.ModeRelayExact {
		selected, found := relayFinalityProfile(profile.FinalityProfiles,
			body.SponsorshipTerminalProfileURI, body.SponsorshipTerminalProfileDigest)
		if !found || selected.TerminalEvidenceClass != body.SponsorshipTerminalEvidenceClass {
			return agentrelay.RelayEvidenceCapability{}, errors.New("sponsorship terminal profile is unavailable")
		}
		capability.SponsorshipTerminalProfile = &selected
		if body.AssuranceLevel != agentrelay.AssuranceAutonomousDecentralized {
			capability.AbsenceProofProfileURI = agentrelay.RelayAbsenceTOSRPCProofProfileURI
			capability.AbsenceProofProfileDigest, _ = agentrelay.RelayAbsenceTOSRPCProofProfileDigest()
		}
	}
	return capability, nil
}

func relayEvidenceCapabilityForExecution(execution agentrelay.RelayExecutionRequest) (agentrelay.RelayEvidenceCapability, error) {
	capability, err := relayEvidenceCapabilityForQuoteBody(agentrelay.RelayServiceProfile{
		FinalityProfiles: relayExecutionFinalityProfiles(execution)}, execution.QuoteRequest.Body)
	if err != nil {
		return agentrelay.RelayEvidenceCapability{}, err
	}
	if !equalRelayFinalityProfile(capability.RelayFinalityProfile,
		execution.ProviderQuote.Body.RelayFinalityProfile) ||
		!equalRelayFinalityProfile(capability.SponsorshipTerminalProfile,
			execution.ProviderQuote.Body.SponsorshipTerminalProfile) {
		return agentrelay.RelayEvidenceCapability{}, errors.New("provider quote changes a selected terminal profile")
	}
	return capability, nil
}

func relayExecutionFinalityProfiles(execution agentrelay.RelayExecutionRequest) []agentrelay.FinalityProfile {
	profiles := make([]agentrelay.FinalityProfile, 0, 2)
	if execution.ProviderQuote.Body.RelayFinalityProfile != nil {
		profiles = append(profiles, *execution.ProviderQuote.Body.RelayFinalityProfile)
	}
	if execution.ProviderQuote.Body.SponsorshipTerminalProfile != nil &&
		(execution.ProviderQuote.Body.RelayFinalityProfile == nil ||
			*execution.ProviderQuote.Body.SponsorshipTerminalProfile != *execution.ProviderQuote.Body.RelayFinalityProfile) {
		profiles = append(profiles, *execution.ProviderQuote.Body.SponsorshipTerminalProfile)
	}
	return profiles
}

func equalRelayFinalityProfile(left, right *agentrelay.FinalityProfile) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

// PlanRelayProviderCapabilities checks concrete runtime objects, not an
// environment label or an external acceptance campaign. trusted-local and
// authorized-single-provider accept a locally verifiable FinalityEvidenceSource;
// autonomous-decentralized additionally requires portable independent proofs
// and rollback-resistant checkpoint and terminal commitments.
func PlanRelayProviderCapabilities(service *agentrelay.ProviderService,
	level agentrelay.AssuranceLevel) RelayCapabilityReport {
	if service == nil {
		return planRelayProviderCapabilitiesForModes(service, level, nil, RelaySponsorshipReleasePolicy{})
	}
	return planRelayProviderCapabilitiesForModes(service, level, service.Profile.SupportedModes,
		RelaySponsorshipReleasePolicy{})
}

// PlanRelayProviderCapabilitiesWithSponsorshipPolicy plans the concrete
// owner-selected descriptor. The policy is ignored by relay_exact pairs and
// mandatory for sponsorship pairs.
func PlanRelayProviderCapabilitiesWithSponsorshipPolicy(service *agentrelay.ProviderService,
	level agentrelay.AssuranceLevel, policy RelaySponsorshipReleasePolicy) RelayCapabilityReport {
	if service == nil {
		return planRelayProviderCapabilitiesForModes(service, level, nil, policy)
	}
	return planRelayProviderCapabilitiesForModes(service, level, service.Profile.SupportedModes, policy)
}

func planRelayProviderCapabilitiesForModes(service *agentrelay.ProviderService,
	level agentrelay.AssuranceLevel, modes []agentrelay.Mode,
	sponsorshipPolicy RelaySponsorshipReleasePolicy) RelayCapabilityReport {
	if service == nil {
		return RelayCapabilityReport{Capabilities: []RelayCapability{{AssuranceLevel: level,
			Missing: []string{"provider-service"}}}}
	}
	report := RelayCapabilityReport{Capabilities: make([]RelayCapability, 0, len(modes))}
	for _, mode := range modes {
		missing := relayProviderCapabilityMissing(service, level, mode, sponsorshipPolicy)
		report.Capabilities = append(report.Capabilities, RelayCapability{Mode: mode, AssuranceLevel: level,
			Ready: len(missing) == 0, FailoverEnabled: relayCapabilityFailover(level, mode), Missing: missing})
	}
	if len(report.Capabilities) == 0 {
		report.Capabilities = append(report.Capabilities, RelayCapability{AssuranceLevel: level,
			Missing: []string{"signed-profile-mode"}})
	}
	return report
}

func relayProviderCapabilityMissing(service *agentrelay.ProviderService, level agentrelay.AssuranceLevel,
	mode agentrelay.Mode, sponsorshipPolicy RelaySponsorshipReleasePolicy) []string {
	missing := make([]string, 0, 16)
	add := func(condition bool, name string) {
		if condition {
			missing = append(missing, name)
		}
	}
	add(!validRelayAssuranceLevel(level), "known-assurance-level")
	add(!relayProfileSupportsAssurance(service.Profile, level), "signed-profile-assurance")
	add(!relayProfileSupportsMode(service.Profile, mode), "signed-profile-mode")
	add(len(service.SigningKey) != ed25519.PrivateKeySize, "provider-signing-key")
	add(service.AgentResolver == nil, "agent-key-resolver")
	add(service.FenceResolver == nil, "writer-fence-resolver")
	add(service.Inspector == nil, "transaction-inspector")
	add(service.ActionBinder == nil, "action-transaction-binding")
	add(service.AgreementVerifier == nil, "agreement-verifier")
	add(service.QuotePolicy == nil, "quote-policy")
	add(service.Journal == nil, "provider-journal")
	add(service.EvidenceSource == nil, "finality-evidence")
	exactEvidence, exactEvidenceOK := service.EvidenceSource.(agentrelay.IndependentFinalityEvidenceSource)
	add(!exactEvidenceOK || !relayProfileEvidenceCapabilitiesSupported(service.Profile, nil, level, mode,
		sponsorshipPolicy, exactEvidence.SupportsRelayEvidenceCapability), "exact-finality-evidence-capability")
	add(mode == agentrelay.ModeSponsorAndRelay && (!exactEvidenceOK ||
		!relayProfileEvidenceCapabilitiesSupported(service.Profile, nil, level, mode, sponsorshipPolicy,
			exactEvidence.SupportsRelayDualAbsenceEvidence)), "dual-absence-finality-evidence")
	add(mode != agentrelay.ModeRelayExact && (!exactEvidenceOK ||
		!relayProfileEvidenceCapabilitiesSupported(service.Profile, nil, level, mode, sponsorshipPolicy,
			exactEvidence.SupportsRelaySponsorshipComponentAbsenceEvidence)),
		"sponsorship-component-absence-finality-evidence")
	add(mode == agentrelay.ModeSponsorAndRelay && (!exactEvidenceOK ||
		!relayProfileEvidenceCapabilitiesSupported(service.Profile, nil, level, mode, sponsorshipPolicy,
			exactEvidence.SupportsRelayTransactionComponentAbsenceEvidence)),
		"transaction-component-absence-finality-evidence")
	switch mode {
	case agentrelay.ModeRelayExact:
		add(service.Broadcaster == nil, "exact-transaction-broadcaster")
	case agentrelay.ModeSponsorOnly:
		add(!relayProfileSupportsSponsorshipReleasePolicy(service.Profile, level, sponsorshipPolicy),
			"owner-sponsorship-release-policy")
		add(service.Sponsorship == nil, "sponsorship-custody")
		qualified, ok := service.Sponsorship.(RelaySponsorshipAssuranceCapability)
		addRelayProviderSponsorshipEvidenceMissing(&missing, level, sponsorshipPolicy,
			service.Profile.FinalityProfiles, qualified, ok)
		absence, absenceOK := service.Sponsorship.(RelaySponsorshipProviderAbsenceCapability)
		add(!absenceOK || !relayProfileEvidenceCapabilitiesSupported(service.Profile, nil, level, mode,
			sponsorshipPolicy, absence.SupportsRelaySponsorshipComponentAbsenceEvidence),
			"sponsorship-component-absence-resolver")
		add(sponsorshipPolicy.EvidenceClass == agentrelay.SponsorshipReleaseObservedUnproven &&
			service.SponsorshipObservationVerifier == nil, "sponsorship-observation-verifier")
	case agentrelay.ModeSponsorAndRelay:
		add(!relayProfileSupportsSponsorshipReleasePolicy(service.Profile, level, sponsorshipPolicy),
			"owner-sponsorship-release-policy")
		add(service.Sponsorship == nil, "sponsorship-custody")
		qualified, ok := service.Sponsorship.(RelaySponsorshipAssuranceCapability)
		addRelayProviderSponsorshipEvidenceMissing(&missing, level, sponsorshipPolicy,
			service.Profile.FinalityProfiles, qualified, ok)
		absence, absenceOK := service.Sponsorship.(RelaySponsorshipProviderAbsenceCapability)
		add(!absenceOK || !relayProfileEvidenceCapabilitiesSupported(service.Profile, nil, level, mode,
			sponsorshipPolicy, absence.SupportsRelaySponsorshipComponentAbsenceEvidence),
			"sponsorship-component-absence-resolver")
		add(!absenceOK || !relayProfileEvidenceCapabilitiesSupported(service.Profile, nil, level, mode,
			sponsorshipPolicy, absence.SupportsRelayDualAbsenceEvidence),
			"sponsorship-dual-absence-resolver")
		transactionAbsence, transactionAbsenceOK := service.Sponsorship.(RelaySponsorshipProviderTransactionAbsenceCapability)
		add(!transactionAbsenceOK || !relayProfileEvidenceCapabilitiesSupported(service.Profile, nil, level, mode,
			sponsorshipPolicy, transactionAbsence.SupportsRelayTransactionComponentAbsenceEvidence),
			"transaction-component-absence-resolver")
		_, dualAggregatorOK := service.Sponsorship.(agentrelay.CombinedRelayDualAbsenceResolver)
		add(!dualAggregatorOK, "sponsorship-dual-absence-aggregator")
		_, transactionResolverOK := service.Sponsorship.(agentrelay.CombinedRelayTransactionAbsenceResolver)
		add(!transactionResolverOK, "sponsorship-transaction-absence-resolver")
		add(sponsorshipPolicy.EvidenceClass == agentrelay.SponsorshipReleaseObservedUnproven &&
			service.SponsorshipObservationVerifier == nil, "sponsorship-observation-verifier")
		add(service.Broadcaster == nil, "exact-transaction-broadcaster")
	default:
		add(true, "known-service-mode")
	}
	if level == agentrelay.AssuranceAutonomousDecentralized {
		journal, ok := service.Journal.(RelayAutonomousProviderJournalAssurance)
		add(!ok || !journal.HasLinearizableRelayProviderJournal() ||
			!journal.HasRollbackResistantRelayProviderJournalHighWater(),
			"rollback-resistant-provider-journal")
		add(!exactEvidenceOK, "portable-finality-evidence")
		if exactEvidenceOK {
			add(!exactEvidence.HasRetrievableIndependentProofs(), "retrievable-independent-proofs")
			add(!exactEvidence.HasRollbackResistantCheckpoint(), "rollback-resistant-checkpoint")
			add(!exactEvidence.HasRollbackResistantTerminalCommitment(), "rollback-resistant-terminal-commitment")
		}
	}
	return compactRelayMissingSorted(missing)
}

func addRelayProviderSponsorshipEvidenceMissing(missing *[]string, level agentrelay.AssuranceLevel,
	policy RelaySponsorshipReleasePolicy, finalityProfiles []agentrelay.FinalityProfile,
	provider RelaySponsorshipAssuranceCapability, ok bool) {
	capabilities := RelaySponsorshipEvidenceCapabilities{}
	if ok {
		capabilities = provider.RelaySponsorshipEvidenceCapabilities()
	}
	if !validRelaySponsorshipReleasePolicy(level, policy) {
		*missing = append(*missing, "owner-sponsorship-release-policy")
		return
	}
	if !supportsRelaySponsorshipReleasePolicy(capabilities.SupportedReleasePolicies, policy) {
		*missing = append(*missing, "selected-sponsorship-release-profile")
	}
	if !capabilities.TerminalEvidence {
		*missing = append(*missing, "terminal-sponsorship-evidence")
	}
	profileCapability, profileOK := any(provider).(RelaySponsorshipTerminalProfileCapability)
	supportedProfile, selectedProfiles := profileOK, 0
	if profileOK {
		for _, profile := range finalityProfiles {
			selected := policy.EvidenceClass == agentrelay.SponsorshipReleaseValidatorFinality &&
				profile.TerminalEvidenceClass == agentrelay.SponsorshipTerminalValidatorFinality &&
				profile.ProfileURI == policy.ProfileURI && profile.ProfileDigest == policy.ProfileDigest ||
				policy.EvidenceClass == agentrelay.SponsorshipReleaseObservedUnproven &&
					profile.TerminalEvidenceClass == agentrelay.SponsorshipTerminalClientCorroborated &&
					profile.ProfileURI == RelayClientCorroboratedTerminalProfileURI
			if !selected {
				continue
			}
			selectedProfiles++
			supportedProfile = supportedProfile &&
				profileCapability.SupportsRelaySponsorshipTerminalFinalityProfile(profile, nil)
		}
	}
	if !supportedProfile || selectedProfiles == 0 {
		*missing = append(*missing, "terminal-sponsorship-profile")
	}
	if level == agentrelay.AssuranceAutonomousDecentralized {
		if !capabilities.PortableFinalityEvidence {
			*missing = append(*missing, "portable-sponsorship-finality-evidence")
		}
		return
	}
	if policy.EvidenceClass == agentrelay.SponsorshipReleaseObservedUnproven &&
		!capabilities.FreshBalanceSequenceRecheck {
		*missing = append(*missing, "fresh-sponsorship-balance-sequence-recheck")
	}
}

// RelayClientCapabilityDependencies are the already constructed safe runtime
// seams. The capability planner never turns booleans into authority: every
// ready result is based on the concrete coordinator that will execute it.
type RelayClientCapabilityDependencies struct {
	SingleProvider *RelayCoordinator
	// TerminalAccounting is a separate durable accounting/portfolio sink.
	// Route artifacts remain unacknowledged and non-evictable until this sink
	// returns an idempotent content-digested receipt and monotonic revision.
	TerminalAccounting RelayTerminalAccountingHandoffStore
	// SingleProviderRouteJournal is the owner-wide first-dispatch fence for
	// lower-assurance sponsorship. The provider-scoped AttemptJournal cannot
	// distinguish a crash before the socket write from a lost response after a
	// top-up, so sponsorship is never enabled without this second durable gate.
	SingleProviderRouteJournal *DurableRelayRouteJournal
	SingleProviderProvenance   RelayProviderProvenance
	SponsorshipReleasePolicy   RelaySponsorshipReleasePolicy
	Decentralized              *DecentralizedRelayCoordinator
	// DecentralizedProvenance is the current owner-authorized snapshot used to
	// make readiness deterministic. The runtime provenance verifier must return
	// the same exact records during Prepare; a non-nil verifier alone is not
	// evidence that Providers occupy independent operator/failure domains.
	DecentralizedProvenance []RelayProviderProvenance
}

func PlanRelayClientCapability(level agentrelay.AssuranceLevel, mode agentrelay.Mode,
	dependencies RelayClientCapabilityDependencies) RelayCapability {
	capability := RelayCapability{Mode: mode, AssuranceLevel: level}
	if !validRelayAssuranceLevel(level) {
		capability.Missing = []string{"known-assurance-level"}
		return capability
	}
	if mode != agentrelay.ModeRelayExact && mode != agentrelay.ModeSponsorOnly && mode != agentrelay.ModeSponsorAndRelay {
		capability.Missing = []string{"known-service-mode"}
		return capability
	}
	if level == agentrelay.AssuranceAutonomousDecentralized {
		capability.Missing = decentralizedRelayCapabilityMissing(dependencies.Decentralized,
			dependencies.DecentralizedProvenance, level, mode)
	} else {
		capability.Missing = relayCoordinatorCapabilityMissing(dependencies.SingleProvider, level, mode)
		if dependencies.SingleProviderRouteJournal == nil {
			capability.Missing = append(capability.Missing, "single-provider-owner-route-journal")
		}
		if !relayProvenanceMatchesCoordinator(dependencies.SingleProviderProvenance,
			dependencies.SingleProvider) {
			capability.Missing = append(capability.Missing, "single-provider-owner-provenance")
		}
		sort.Strings(capability.Missing)
		capability.Missing = compactRelayMissing(capability.Missing)
	}
	if dependencies.TerminalAccounting == nil {
		capability.Missing = append(capability.Missing, "durable-terminal-accounting-handoff")
	}
	if level == agentrelay.AssuranceAutonomousDecentralized {
		assurance, ok := dependencies.TerminalAccounting.(interface {
			HasRollbackResistantRelayTerminalAccountingHighWater() bool
		})
		if !ok || !assurance.HasRollbackResistantRelayTerminalAccountingHighWater() {
			capability.Missing = append(capability.Missing, "rollback-resistant-terminal-accounting-handoff")
		}
	}
	if mode == agentrelay.ModeSponsorOnly || mode == agentrelay.ModeSponsorAndRelay {
		if !validRelaySponsorshipReleasePolicy(level, dependencies.SponsorshipReleasePolicy) ||
			!relayClientCoordinatorsUseSponsorshipPolicy(level, dependencies,
				dependencies.SponsorshipReleasePolicy) {
			capability.Missing = append(capability.Missing, "owner-sponsorship-release-policy")
			sort.Strings(capability.Missing)
			capability.Missing = compactRelayMissing(capability.Missing)
		}
	}
	sort.Strings(capability.Missing)
	capability.Missing = compactRelayMissing(capability.Missing)
	capability.Ready = len(capability.Missing) == 0
	capability.FailoverEnabled = capability.Ready && relayCapabilityFailover(level, mode)
	return capability
}

func relayClientCoordinatorsUseSponsorshipPolicy(level agentrelay.AssuranceLevel,
	dependencies RelayClientCapabilityDependencies, wanted RelaySponsorshipReleasePolicy) bool {
	if level != agentrelay.AssuranceAutonomousDecentralized {
		return dependencies.SingleProvider != nil &&
			dependencies.SingleProvider.SponsorshipReleasePolicy == wanted
	}
	if dependencies.Decentralized == nil || len(dependencies.Decentralized.Providers) < 2 {
		return false
	}
	for _, coordinator := range dependencies.Decentralized.Providers {
		if coordinator == nil || coordinator.SponsorshipReleasePolicy != wanted {
			return false
		}
	}
	return true
}

func relayCapabilityFailover(level agentrelay.AssuranceLevel, mode agentrelay.Mode) bool {
	return level == agentrelay.AssuranceAutonomousDecentralized && mode == agentrelay.ModeRelayExact
}

func relayCoordinatorCapabilityMissing(coordinator *RelayCoordinator, level agentrelay.AssuranceLevel,
	mode agentrelay.Mode) []string {
	if coordinator == nil {
		return []string{"single-provider-coordinator"}
	}
	missing := make([]string, 0, 14)
	add := func(condition bool, name string) {
		if condition {
			missing = append(missing, name)
		}
	}
	profile := coordinator.VerifiedProfile.Profile()
	add(!relayProfileSupportsAssurance(profile, level), "signed-profile-assurance")
	add(!relayProfileSupportsMode(profile, mode), "signed-profile-mode")
	add(coordinator.Transport == nil, "authenticated-provider-transport")
	if level != agentrelay.AssuranceTrustedLocal {
		authorized, ok := coordinator.Transport.(relayAuthorizedProviderTransport)
		add(!ok || !authorized.relayProviderTransportAuthorized(), "authenticated-provider-transport")
	}
	add(len(coordinator.RequesterKey) != ed25519.PrivateKeySize, "requester-signing-key")
	add(coordinator.AgentResolver == nil, "agent-key-resolver")
	add(coordinator.FenceResolver == nil, "writer-fence-resolver")
	add(coordinator.Inspector == nil, "transaction-inspector")
	add(coordinator.ActionBinder == nil, "action-transaction-binding")
	add(coordinator.AgreementVerifier == nil, "agreement-verifier")
	add(coordinator.AgreementAuthorizer == nil, "agreement-authorizer")
	add(coordinator.SideEffectAdmission == nil, "side-effect-admission")
	if level == agentrelay.AssuranceAutonomousDecentralized {
		admission, ok := coordinator.SideEffectAdmission.(RelayAutonomousAdmissionAssurance)
		add(!ok || !admission.HasLinearizableRelayAdmission() ||
			!admission.HasRollbackResistantRelayAdmissionHighWater(),
			"rollback-resistant-side-effect-admission")
	}
	add(coordinator.FinalityVerifier == nil, "finality-verifier")
	if coordinator.FinalityVerifier != nil {
		_, snapshotOK := coordinator.FinalityVerifier.(RelayClientFinalitySnapshotVerifier)
		add(!snapshotOK, "client-finality-frozen-snapshot-verifier")
		ownerPolicy := coordinator.VerifiedProfile.policy
		add(!relayProfileEvidenceCapabilitiesSupported(profile, &ownerPolicy, level, mode,
			coordinator.SponsorshipReleasePolicy,
			coordinator.FinalityVerifier.SupportsRelayEvidenceCapability),
			"exact-client-finality-capability")
		add(mode == agentrelay.ModeSponsorAndRelay &&
			!relayProfileEvidenceCapabilitiesSupported(profile, &ownerPolicy, level, mode,
				coordinator.SponsorshipReleasePolicy,
				coordinator.FinalityVerifier.SupportsRelayDualAbsenceEvidence),
			"client-dual-absence-finality-evidence")
		add(mode != agentrelay.ModeRelayExact &&
			!relayProfileEvidenceCapabilitiesSupported(profile, &ownerPolicy, level, mode,
				coordinator.SponsorshipReleasePolicy,
				coordinator.FinalityVerifier.SupportsRelaySponsorshipComponentAbsenceEvidence),
			"client-sponsorship-component-absence-finality-evidence")
		add(mode == agentrelay.ModeSponsorAndRelay &&
			!relayProfileEvidenceCapabilitiesSupported(profile, &ownerPolicy, level, mode,
				coordinator.SponsorshipReleasePolicy,
				coordinator.FinalityVerifier.SupportsRelayTransactionComponentAbsenceEvidence),
			"client-transaction-component-absence-finality-evidence")
		if relayPairRequiresPortableFinality(profile, &ownerPolicy, level, mode,
			coordinator.SponsorshipReleasePolicy) {
			portable, ok := coordinator.FinalityVerifier.(agentrelay.PortableRelayFinalityEvidenceVerifier)
			add(!ok || !portable.HasIndependentPortableRelayFinalityProofs(),
				"portable-client-finality-verifier")
		}
	}
	if mode == agentrelay.ModeSponsorOnly || mode == agentrelay.ModeSponsorAndRelay {
		policy := coordinator.SponsorshipReleasePolicy
		add(!relayProfileSupportsSponsorshipReleasePolicy(profile, level, policy),
			"owner-sponsorship-release-policy")
		add(coordinator.SponsorshipEvidenceVerifier == nil,
			"sponsorship-transaction-evidence-verifier")
		clientProofs, proofOK := coordinator.SponsorshipEvidenceVerifier.(RelaySponsorshipClientEvidenceCapability)
		supportedProof, selectedProfiles := proofOK, 0
		if proofOK {
			for _, finality := range profile.FinalityProfiles {
				selected := policy.EvidenceClass == agentrelay.SponsorshipReleaseValidatorFinality &&
					finality.TerminalEvidenceClass == agentrelay.SponsorshipTerminalValidatorFinality &&
					finality.ProfileURI == policy.ProfileURI && finality.ProfileDigest == policy.ProfileDigest ||
					policy.EvidenceClass == agentrelay.SponsorshipReleaseObservedUnproven &&
						finality.TerminalEvidenceClass == agentrelay.SponsorshipTerminalClientCorroborated &&
						finality.ProfileURI == RelayClientCorroboratedTerminalProfileURI
				if !selected {
					continue
				}
				selectedProfiles++
				supportedProof = supportedProof &&
					clientProofs.SupportsRelaySponsorshipTransactionEvidence(level, policy, finality)
			}
		}
		add(!supportedProof || selectedProfiles == 0, "client-sponsorship-evidence-profile")
		if policy.EvidenceClass == agentrelay.SponsorshipReleaseObservedUnproven {
			_, snapshotOK := coordinator.SponsorshipEvidenceVerifier.(RelaySponsorshipClientSnapshotVerifier)
			add(!snapshotOK, "client-sponsorship-frozen-snapshot-verifier")
		}
		if policy.EvidenceClass == agentrelay.SponsorshipReleaseValidatorFinality {
			portable, ok := coordinator.SponsorshipEvidenceVerifier.(agentrelay.PortableSponsorshipTransactionEvidenceVerifier)
			if level == agentrelay.AssuranceAutonomousDecentralized {
				add(!ok || !portable.HasIndependentPortableSponsorshipProofs(), "portable-sponsorship-evidence-verifier")
			}
		}
	}
	add(coordinator.AttemptJournal == nil, "durable-attempt-journal")
	sort.Strings(missing)
	return missing
}

func relayPairRequiresPortableFinality(profile agentrelay.RelayServiceProfile, ownerPolicy *RelayOwnerPolicy,
	level agentrelay.AssuranceLevel, mode agentrelay.Mode, sponsorshipPolicy RelaySponsorshipReleasePolicy) bool {
	if level == agentrelay.AssuranceAutonomousDecentralized ||
		mode != agentrelay.ModeRelayExact && sponsorshipPolicy.EvidenceClass == agentrelay.SponsorshipReleaseValidatorFinality {
		return true
	}
	if mode == agentrelay.ModeSponsorOnly {
		return false
	}
	for _, finality := range profile.FinalityProfiles {
		if ownerPolicy != nil && !containsRelayFinalityProfile(ownerPolicy.FinalityProfiles, finality) {
			continue
		}
		if finality.TerminalEvidenceClass == agentrelay.RelayTerminalValidatorFinality {
			return true
		}
	}
	return false
}

func validRelaySponsorshipReleasePolicy(level agentrelay.AssuranceLevel,
	policy RelaySponsorshipReleasePolicy) bool {
	if policy.ProfileURI == "" || !canonicalSHA256(policy.ProfileDigest) {
		return false
	}
	switch policy.EvidenceClass {
	case agentrelay.SponsorshipReleaseValidatorFinality:
		return true
	case agentrelay.SponsorshipReleaseObservedUnproven:
		return level != agentrelay.AssuranceAutonomousDecentralized &&
			policy.ProfileURI == agentrelay.RPCCorroborationEvidenceProfileURI
	default:
		return false
	}
}

func relayProfileSupportsSponsorshipReleasePolicy(profile agentrelay.RelayServiceProfile,
	level agentrelay.AssuranceLevel, policy RelaySponsorshipReleasePolicy) bool {
	if !validRelaySponsorshipReleasePolicy(level, policy) {
		return false
	}
	if policy.EvidenceClass == agentrelay.SponsorshipReleaseObservedUnproven {
		return true
	}
	for _, finality := range profile.FinalityProfiles {
		if finality.ProfileURI == policy.ProfileURI && finality.ProfileDigest == policy.ProfileDigest {
			return true
		}
	}
	return false
}

func supportsRelaySponsorshipReleasePolicy(supported []RelaySponsorshipReleasePolicy,
	wanted RelaySponsorshipReleasePolicy) bool {
	for _, candidate := range supported {
		if candidate == wanted {
			return true
		}
	}
	return false
}

func decentralizedRelayCapabilityMissing(orchestrator *DecentralizedRelayCoordinator,
	pinned []RelayProviderProvenance, level agentrelay.AssuranceLevel, mode agentrelay.Mode) []string {
	if orchestrator == nil {
		return []string{"decentralized-coordinator"}
	}
	missing := make([]string, 0, 8)
	add := func(condition bool, name string) {
		if condition {
			missing = append(missing, name)
		}
	}
	add(orchestrator.Selector == nil, "owner-provider-selector")
	add(orchestrator.ProvenanceVerifier == nil, "provider-provenance-verifier")
	add(orchestrator.AgentResolver == nil, "historical-agent-key-resolver")
	add(orchestrator.RouteJournal == nil, "durable-route-journal")
	if level == agentrelay.AssuranceAutonomousDecentralized {
		routes, ok := any(orchestrator.RouteJournal).(RelayAutonomousRouteAssurance)
		add(!ok || !routes.HasRollbackResistantRelayRouteHighWater(),
			"rollback-resistant-route-journal")
	}
	add(orchestrator.MaximumRouteAttempts == 0 || orchestrator.MaximumRouteAttempts > agentrelay.MaxRelayRouteAttempts,
		"bounded-route-attempts")
	add(len(orchestrator.Providers) < 2, "two-independent-providers")
	sortedPinned := append([]RelayProviderProvenance(nil), pinned...)
	sort.Slice(sortedPinned, func(left, right int) bool {
		return relayProvenanceKey(sortedPinned[left]) < relayProvenanceKey(sortedPinned[right])
	})
	add(!validIndependentRelayProvenance(sortedPinned), "independent-provider-provenance")
	providerIDs, intentDigests := map[string]bool{}, map[string]bool{}
	for _, coordinator := range orchestrator.Providers {
		if childMissing := relayCoordinatorCapabilityMissing(coordinator, level, mode); len(childMissing) != 0 {
			missing = append(missing, childMissing...)
			continue
		}
		providerID := coordinator.VerifiedProfile.Profile().ProviderAgentID
		intentDigest := coordinator.VerifiedProfile.IntentDigest()
		if providerIDs[providerID] || intentDigests[intentDigest] {
			add(true, "two-independent-providers")
		}
		profile := coordinator.VerifiedProfile.Profile()
		profileDigest, digestErr := agentrelay.RelayServiceProfileDigest(profile)
		origin, originErr := relayProfileEndpointOrigin(profile.Endpoints)
		matched := false
		for _, provenance := range sortedPinned {
			matched = matched || digestErr == nil && originErr == nil &&
				provenance.ProviderAgentID == providerID && provenance.IntentDigest == intentDigest &&
				provenance.ProfileDigest == profileDigest && provenance.EndpointOrigin == origin
		}
		add(!matched, "independent-provider-provenance")
		providerIDs[providerID], intentDigests[intentDigest] = true, true
	}
	sort.Strings(missing)
	missing = compactRelayMissing(missing)
	return missing
}

func compactRelayMissing(values []string) []string {
	if len(values) < 2 {
		return values
	}
	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}

// EnabledRelayClient is the operational gate produced by a successful
// capability plan. Callers cannot use it to claim a higher level: the signed
// request must select the exact enabled pair before any quote is sent.
type EnabledRelayClient struct {
	capability         RelayCapability
	single             *RelayCoordinator
	singleRoute        *DurableRelayRouteJournal
	singleProvenance   RelayProviderProvenance
	decentralized      *DecentralizedRelayCoordinator
	pinnedProvenance   []RelayProviderProvenance
	terminalAccounting RelayTerminalAccountingHandoffStore
}

type EnabledRelayPlan struct {
	Single                *RelayAttempt
	SingleRouteGeneration uint64
	SinglePrepared        *PreparedRelayTransaction
	Decentralized         *DecentralizedRelayPlan
}

func EnableRelayClient(level agentrelay.AssuranceLevel, mode agentrelay.Mode,
	dependencies RelayClientCapabilityDependencies) (*EnabledRelayClient, error) {
	capability := PlanRelayClientCapability(level, mode, dependencies)
	if !capability.Ready {
		return nil, errors.New("relay capability dependencies are incomplete: " + joinRelayMissing(capability.Missing))
	}
	if mode == agentrelay.ModeSponsorOnly || mode == agentrelay.ModeSponsorAndRelay {
		if level == agentrelay.AssuranceAutonomousDecentralized {
			for _, coordinator := range dependencies.Decentralized.Providers {
				coordinator.SponsorshipEffectRegistry = dependencies.Decentralized.RouteJournal
			}
		} else {
			dependencies.SingleProvider.SponsorshipEffectRegistry = dependencies.SingleProviderRouteJournal
		}
	}
	return &EnabledRelayClient{capability: capability, single: dependencies.SingleProvider,
		singleRoute:        dependencies.SingleProviderRouteJournal,
		singleProvenance:   dependencies.SingleProviderProvenance,
		decentralized:      dependencies.Decentralized,
		terminalAccounting: dependencies.TerminalAccounting,
		pinnedProvenance:   append([]RelayProviderProvenance(nil), dependencies.DecentralizedProvenance...)}, nil
}

func (client *EnabledRelayClient) Capability() RelayCapability {
	if client == nil {
		return RelayCapability{}
	}
	result := client.capability
	result.Missing = append([]string(nil), result.Missing...)
	return result
}

func (client *EnabledRelayClient) Prepare(ctx context.Context,
	prepared PreparedRelayTransaction) (*EnabledRelayPlan, error) {
	if client == nil || !client.capability.Ready || prepared.QuoteBody.Mode != client.capability.Mode ||
		prepared.QuoteBody.AssuranceLevel != client.capability.AssuranceLevel {
		return nil, errors.New("signed relay request does not select the enabled capability")
	}
	if client.capability.AssuranceLevel == agentrelay.AssuranceAutonomousDecentralized {
		plan, err := client.decentralized.Prepare(ctx, prepared)
		if err != nil {
			return nil, err
		}
		sortedActual := append([]RelayProviderProvenance(nil), plan.provenance...)
		sort.Slice(sortedActual, func(left, right int) bool {
			return relayProvenanceKey(sortedActual[left]) < relayProvenanceKey(sortedActual[right])
		})
		if !validIndependentRelayProvenance(sortedActual) {
			return nil, errors.New("decentralized relay lost its independent Provider provenance")
		}
		for _, actual := range sortedActual {
			if !containsRelayProvenance(client.pinnedProvenance, actual) {
				return nil, errors.New("decentralized relay Provider provenance changed after capability enablement")
			}
		}
		return &EnabledRelayPlan{Decentralized: plan}, nil
	}
	if existing, resolveErr := client.singleRoute.Resolve(prepared.UnderlyingAction.StableActionID,
		prepared.UnderlyingAction.ExactRequestDigest); resolveErr == nil {
		current, found := existing.Current()
		if !found || !sameRelayProvenance(current.Provider, client.singleProvenance) ||
			!attemptMatchesPrepared(current.Attempt, prepared) {
			return nil, errors.New("single-provider sponsorship route conflicts with the prepared action")
		}
		frozen, err := clonePreparedRelayTransaction(prepared)
		if err != nil {
			return nil, err
		}
		attempt := cloneRelayAttempt(current.Attempt)
		return &EnabledRelayPlan{Single: &attempt, SingleRouteGeneration: current.Generation,
			SinglePrepared: &frozen}, nil
	} else if !errors.Is(resolveErr, agentrelay.ErrRelayUnknown) {
		return nil, resolveErr
	}
	attempt, err := client.single.Prepare(ctx, prepared)
	if err != nil {
		return nil, err
	}
	plan := &EnabledRelayPlan{Single: &attempt}
	route, _, err := client.singleRoute.BindSingle(prepared, client.singleProvenance,
		attempt, client.single.now())
	if err != nil {
		return nil, err
	}
	current, found := route.Current()
	if !found || !sameRelayProvenance(current.Provider, client.singleProvenance) ||
		!attemptMatchesPrepared(current.Attempt, prepared) {
		return nil, errors.New("single-provider sponsorship route binding changed the exact attempt")
	}
	frozen, err := clonePreparedRelayTransaction(prepared)
	if err != nil {
		return nil, err
	}
	attempt = cloneRelayAttempt(current.Attempt)
	plan.Single, plan.SingleRouteGeneration, plan.SinglePrepared = &attempt, current.Generation, &frozen
	return plan, nil
}

func (client *EnabledRelayClient) Submit(ctx context.Context,
	plan *EnabledRelayPlan) (RelayExecutionResult, error) {
	if client == nil || plan == nil || !client.capability.Ready {
		return RelayExecutionResult{}, errors.New("relay capability is not enabled")
	}
	if client.capability.AssuranceLevel == agentrelay.AssuranceAutonomousDecentralized {
		if plan.Decentralized == nil || plan.Single != nil {
			return RelayExecutionResult{}, errors.New("relay plan does not belong to the decentralized capability")
		}
		body := plan.Decentralized.Attempt.Execution.QuoteRequest.Body
		if body.Mode != client.capability.Mode || body.AssuranceLevel != client.capability.AssuranceLevel {
			return RelayExecutionResult{}, errors.New("relay plan changes the enabled capability")
		}
		result, err := client.decentralized.Submit(ctx, plan.Decentralized)
		if err != nil || result.Resolution.Body.State != commerce.ActionTerminal {
			return result, err
		}
		if err := client.commitTerminalAccountingHandoff(ctx, plan, result); err != nil {
			return RelayExecutionResult{}, err
		}
		return result, nil
	}
	if plan.Single == nil || plan.Decentralized != nil {
		return RelayExecutionResult{}, errors.New("relay plan does not belong to the single-provider capability")
	}
	body := plan.Single.Execution.QuoteRequest.Body
	if body.Mode != client.capability.Mode || body.AssuranceLevel != client.capability.AssuranceLevel {
		return RelayExecutionResult{}, errors.New("relay plan changes the enabled capability")
	}
	result, err := client.submitSingleProviderRoute(ctx, plan)
	if err != nil || result.Resolution.Body.State != commerce.ActionTerminal {
		return result, err
	}
	if err := client.commitTerminalAccountingHandoff(ctx, plan, result); err != nil {
		return RelayExecutionResult{}, err
	}
	return result, nil
}

func (client *EnabledRelayClient) commitTerminalAccountingHandoff(ctx context.Context,
	plan *EnabledRelayPlan, result RelayExecutionResult) error {
	if client == nil || plan == nil || client.terminalAccounting == nil || result.Evidence == nil {
		return errors.New("terminal relay route has no durable accounting handoff sink")
	}
	var journal RelayRouteJournal
	var attempt RelayAttempt
	var now time.Time
	if plan.Decentralized != nil {
		if client.decentralized == nil || client.decentralized.RouteJournal == nil {
			return errors.New("terminal decentralized relay has no route journal")
		}
		journal, attempt = client.decentralized.RouteJournal, plan.Decentralized.Attempt
		if plan.Decentralized.selected < 0 || plan.Decentralized.selected >= len(plan.Decentralized.candidates) ||
			plan.Decentralized.candidates[plan.Decentralized.selected].Coordinator == nil {
			return errors.New("terminal decentralized relay has no selected route clock")
		}
		now = plan.Decentralized.candidates[plan.Decentralized.selected].Coordinator.now()
	} else if plan.Single != nil {
		journal, attempt = client.singleRoute, *plan.Single
		if client.single == nil {
			return errors.New("terminal single-provider relay has no route clock")
		}
		now = client.single.now()
	} else {
		return errors.New("terminal accounting handoff has no relay plan")
	}
	record, err := journal.Resolve(attempt.Execution.AuthorizedAction.StableActionID,
		attempt.Execution.AuthorizedAction.ExactRequestDigest)
	if err != nil {
		return errors.New("resolve terminal route for accounting handoff: " + err.Error())
	}
	terminalHop, found := record.Current()
	if !found {
		return errors.New("terminal route for accounting handoff has no current hop")
	}
	// A decentralized plan may be recovered from its original attempt while the
	// route journal has already advanced. Accounting must consume the exact
	// terminal hop from that journal; otherwise hop A's Agreement/Provider
	// identities could be paired with hop B's terminal result after takeover.
	attempt = terminalHop.Attempt
	reference, err := RelayTerminalHandoffReferenceForRecord(record)
	if err != nil {
		return errors.New("derive terminal accounting handoff reference: " + err.Error())
	}
	receipt, err := client.terminalAccounting.CommitRelayTerminalHandoff(ctx, reference,
		attempt, result, now)
	if err != nil {
		return errors.New("commit terminal relay accounting handoff: " + err.Error())
	}
	if receipt.RecordedAtUnix == 0 || receipt.RecordedAtUnix > uint64(^uint64(0)>>1) {
		return errors.New("terminal relay accounting receipt has invalid time")
	}
	acknowledgedAt := time.Unix(int64(receipt.RecordedAtUnix), 0).UTC()
	if err := journal.AcknowledgeTerminalHandoff(RelayTerminalHandoffAcknowledgement{Reference: reference,
		AccountingReceiptDigest: receipt.ReceiptDigest, AccountingRevision: receipt.Revision,
		AcknowledgedAt: acknowledgedAt}); err != nil {
		return errors.New("acknowledge terminal relay accounting handoff: " + err.Error())
	}
	return nil
}

func (client *EnabledRelayClient) submitSingleProviderRoute(ctx context.Context,
	plan *EnabledRelayPlan) (RelayExecutionResult, error) {
	if client.singleRoute == nil || plan.SinglePrepared == nil || plan.SingleRouteGeneration == 0 ||
		!attemptMatchesPrepared(*plan.Single, *plan.SinglePrepared) {
		return RelayExecutionResult{}, errors.New("single-provider relay has no durable first-dispatch route")
	}
	executionDigest, err := agentrelay.RelayExecutionRequestDigest(plan.Single.Execution)
	if err != nil {
		return RelayExecutionResult{}, err
	}
	route, err := client.singleRoute.Resolve(plan.SinglePrepared.UnderlyingAction.StableActionID,
		plan.SinglePrepared.UnderlyingAction.ExactRequestDigest)
	if err != nil {
		return RelayExecutionResult{}, err
	}
	current, found := route.Current()
	if !found || current.Generation != plan.SingleRouteGeneration || current.RelayExecutionDigest != executionDigest ||
		!sameRelayProvenance(current.Provider, client.singleProvenance) ||
		!reflect.DeepEqual(current.Attempt, *plan.Single) {
		return RelayExecutionResult{}, errors.New("single-provider sponsorship plan differs from its durable route")
	}
	if current.TerminalResolution != nil && current.TerminalFinalityEvidence != nil {
		stored := RelayExecutionResult{Resolution: *current.TerminalResolution,
			Evidence: current.TerminalFinalityEvidence}
		if client.single.verifyHistoricalTerminalResolution(plan.Single.Execution, stored.Resolution) != nil ||
			client.single.verifyIndependentFinality(ctx, *plan.Single, *stored.Evidence) != nil ||
			stored.Resolution.Body.TerminalOutcome != stored.Evidence.Body.Outcome ||
			!relayResolutionReferenceMatchesEvidence(stored.Resolution.Body, stored.Evidence.Body) {
			return RelayExecutionResult{}, errors.New("durable single-provider relay result failed verification")
		}
		return stored, nil
	}
	wasStarted := current.SubmitStarted
	if _, err := client.singleRoute.MarkSubmitStarted(route.StableActionID, route.ExactRequestDigest,
		current.Generation, executionDigest, client.single.now()); err != nil {
		return RelayExecutionResult{}, err
	}
	if !wasStarted {
		allowFreshSponsorship := plan.Single.Execution.QuoteRequest.Body.Mode != agentrelay.ModeRelayExact
		result, submitErr := client.single.submit(ctx, *plan.Single, allowFreshSponsorship)
		return client.recordSingleProviderResult(plan, executionDigest, result, submitErr)
	}
	// Once first dispatch was durably marked, a restart or timeout can only
	// query the exact Provider identity. Remote unknown/404 is not absence of a
	// top-up and can never authorize another Submit.
	call := agentrelay.ResolveCall{StableActionID: route.StableActionID,
		ExactRequestDigest: route.ExactRequestDigest}
	resolution, resolveErr := client.single.Transport.Resolve(ctx, call, plan.Single.Execution)
	if resolveErr != nil {
		if plan.Single.Execution.QuoteRequest.Body.Mode == agentrelay.ModeRelayExact &&
			errors.Is(resolveErr, ErrRelayRemoteUnknown) {
			// The owner route already froze the exact signed BOC and Provider.
			// A Provider 404 after crash-before-socket cannot distinguish "never
			// received" from lost state, but rebroadcasting the same immutable
			// transaction is idempotent at the chain identity. This exception is
			// forbidden for every sponsorship mode.
			result, submitErr := client.single.Submit(ctx, *plan.Single)
			return client.recordSingleProviderResult(plan, executionDigest, result, submitErr)
		}
		return RelayExecutionResult{}, fmt.Errorf("%w: single-provider relay remains unresolved",
			ErrRelaySubmissionAmbiguous)
	}
	if err := client.single.verifyResolution(plan.Single.Execution, resolution); err != nil {
		return RelayExecutionResult{}, err
	}
	if resolution.Body.State == commerce.ActionPrepared {
		// The authenticated Provider durably admitted the exact action but has
		// not crossed its own sponsorship boundary. Resuming that same record is
		// safe; RelayCoordinator queries it again before any custody call.
		result, submitErr := client.single.Submit(ctx, *plan.Single)
		return client.recordSingleProviderResult(plan, executionDigest, result, submitErr)
	}
	record, err := client.single.AttemptJournal.Resolve(route.StableActionID, route.ExactRequestDigest)
	if err != nil {
		return RelayExecutionResult{}, errors.New("resolved sponsorship has no durable local attempt")
	}
	result, acceptErr := client.single.acceptResolution(ctx, *plan.Single, record, resolution)
	return client.recordSingleProviderResult(plan, executionDigest, result, acceptErr)
}

func (client *EnabledRelayClient) recordSingleProviderResult(plan *EnabledRelayPlan, executionDigest string,
	result RelayExecutionResult, resultErr error) (RelayExecutionResult, error) {
	if resultErr != nil || result.Resolution.Body.State != commerce.ActionTerminal {
		return result, resultErr
	}
	if result.Evidence == nil {
		return RelayExecutionResult{}, errors.New("terminal single-provider relay has no finality evidence")
	}
	if _, err := client.singleRoute.RecordTerminal(plan.Single.Execution.AuthorizedAction.StableActionID,
		plan.Single.Execution.AuthorizedAction.ExactRequestDigest, plan.SingleRouteGeneration,
		executionDigest, result, client.single.now()); err != nil {
		return RelayExecutionResult{}, errors.New("persist terminal single-provider relay: " + err.Error())
	}
	return result, nil
}

func relayProvenanceMatchesCoordinator(provenance RelayProviderProvenance,
	coordinator *RelayCoordinator) bool {
	if coordinator == nil || !validRelayProvenance(provenance) {
		return false
	}
	profile := coordinator.VerifiedProfile.Profile()
	profileDigest, digestErr := agentrelay.RelayServiceProfileDigest(profile)
	origin, originErr := relayProfileEndpointOrigin(profile.Endpoints)
	return digestErr == nil && originErr == nil && provenance.ProviderAgentID == profile.ProviderAgentID &&
		provenance.IntentDigest == coordinator.VerifiedProfile.IntentDigest() &&
		provenance.ProfileDigest == profileDigest && provenance.EndpointOrigin == origin
}

func joinRelayMissing(values []string) string {
	result := ""
	for index, value := range values {
		if index != 0 {
			result += ","
		}
		result += value
	}
	return result
}
