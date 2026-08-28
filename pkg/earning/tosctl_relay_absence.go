package earning

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

const (
	tosctlRelaySponsorshipDualAbsenceSchema                  = "tosctl.agent-account.agreement-payment-sponsorship-dual-absence.v1"
	tosctlRelaySponsorshipComponentAbsenceSchema             = "tosctl.agent-account.agreement-payment-sponsorship-component-absence.v1"
	tosctlRelayTransactionComponentAbsenceSchema             = "tosctl.agent-account.relay-transaction-component-absence.v1"
	tosctlRelaySponsorshipDualAbsenceVerificationSchema      = "tosctl.agent-account.agreement-payment-sponsorship-dual-absence-proof-verification.v1"
	tosctlRelaySponsorshipComponentAbsenceVerificationSchema = "tosctl.agent-account.agreement-payment-sponsorship-component-absence-proof-verification.v1"
	tosctlRelayTransactionComponentAbsenceVerificationSchema = "tosctl.agent-account.relay-transaction-component-absence-proof-verification.v1"
	tosctlRelaySponsorshipAbsenceCapabilitySchema            = "tosctl.agent-account.agreement-payment-sponsorship-dual-absence-capability.v1"
	tosctlRelayAbsenceDigestMethod                           = "TOS-PROTOCOL-CBOR/rfc8949-core-deterministic"
)

type tosctlRelayAbsenceHeader struct {
	Schema string `json:"schema"`
	State  string `json:"state"`
}

type tosctlRelayAbsenceUnknown struct {
	Schema                        string `json:"schema"`
	State                         string `json:"state"`
	Category                      string `json:"category"`
	Reason                        string `json:"reason"`
	RelayExecutionRequestDigest   string `json:"relay_execution_request_digest"`
	RelayStableActionID           string `json:"relay_stable_action_id"`
	RelayExactRequestDigest       string `json:"relay_exact_request_digest"`
	SponsorshipStableActionID     string `json:"sponsorship_stable_action_id"`
	SponsorshipExactRequestDigest string `json:"sponsorship_exact_request_digest"`
	ChainSideEffect               bool   `json:"chain_side_effect"`
	CustodySideEffect             bool   `json:"custody_side_effect"`
}

type tosctlRelayAbsenceTerminal struct {
	Schema                                  string                                        `json:"schema"`
	State                                   string                                        `json:"state"`
	Outcome                                 string                                        `json:"outcome"`
	TerminalEvidenceClass                   agentrelay.TerminalEvidenceClass              `json:"terminal_evidence_class"`
	ValidatorAuthenticatedPortableProof     bool                                          `json:"validator_authenticated_portable_proof"`
	NetworkDomain                           agentrelay.NetworkDomain                      `json:"network_domain"`
	NetworkDigest                           string                                        `json:"network_digest"`
	AgreementPaymentRequestDigest           string                                        `json:"agreement_payment_request_digest"`
	SponsorshipStableActionID               string                                        `json:"sponsorship_stable_action_id"`
	SponsorshipExactRequestDigest           string                                        `json:"sponsorship_exact_request_digest"`
	SponsorshipValidUntilUnix               uint64                                        `json:"sponsorship_valid_until_unix"`
	RelayStableActionID                     string                                        `json:"relay_stable_action_id"`
	RelayExactRequestDigest                 string                                        `json:"relay_exact_request_digest"`
	RelayExecutionRequestDigest             string                                        `json:"relay_execution_request_digest"`
	SignedTopUpTransactionDigest            string                                        `json:"signed_top_up_transaction_digest"`
	SignedTopUpTransactionCellHash          string                                        `json:"signed_top_up_transaction_cell_hash"`
	SignedTransactionDigest                 string                                        `json:"signed_transaction_digest"`
	SignedTransactionCellHash               string                                        `json:"signed_transaction_cell_hash"`
	TransactionValidUntilUnix               uint64                                        `json:"transaction_valid_until_unix"`
	SponsorshipTerminalProfile              agentrelay.FinalityProfile                    `json:"sponsorship_terminal_profile"`
	RelayFinalityProfile                    *agentrelay.FinalityProfile                   `json:"relay_finality_profile"`
	ProviderSnapshotIdentity                string                                        `json:"provider_snapshot_identity"`
	EvidenceProfileURI                      string                                        `json:"evidence_profile_uri"`
	EvidenceProfileDigest                   string                                        `json:"evidence_profile_digest"`
	SponsorshipAbsenceObservations          []agentrelay.RelayAbsenceObservationReference `json:"sponsorship_absence_observations"`
	TransactionAbsenceObservations          []agentrelay.RelayAbsenceObservationReference `json:"transaction_absence_observations"`
	EvidenceSetDigest                       string                                        `json:"evidence_set_digest"`
	ProofBundleDigestAlgorithm              string                                        `json:"proof_bundle_digest_algorithm"`
	ProofBundleDigestDomain                 string                                        `json:"proof_bundle_digest_domain"`
	ProofBundleDigest                       string                                        `json:"proof_bundle_digest"`
	PredecessorSponsorshipProofBundleDigest string                                        `json:"predecessor_sponsorship_proof_bundle_digest,omitempty"`
	ProofBundleCBOR                         []byte                                        `json:"proof_bundle_cbor"`
	ProofBundle                             agentrelay.RelayAbsenceProofBundleV1          `json:"proof_bundle"`
	ProofPayload                            json.RawMessage                               `json:"proof_payload"`
	ProducedAtUnix                          uint64                                        `json:"produced_at_unix"`
	CustodyState                            string                                        `json:"custody_state"`
	ChainSideEffect                         bool                                          `json:"chain_side_effect"`
	CustodySideEffect                       bool                                          `json:"custody_side_effect"`
}

type tosctlRelayTransactionAbsenceTerminal struct {
	Schema                              string                                        `json:"schema"`
	State                               string                                        `json:"state"`
	ComponentOutcome                    string                                        `json:"component_outcome"`
	TerminalEvidenceClass               agentrelay.TerminalEvidenceClass              `json:"terminal_evidence_class"`
	ValidatorAuthenticatedPortableProof bool                                          `json:"validator_authenticated_portable_proof"`
	NetworkDomain                       agentrelay.NetworkDomain                      `json:"network_domain"`
	NetworkDigest                       string                                        `json:"network_digest"`
	AgreementPaymentRequestDigest       string                                        `json:"agreement_payment_request_digest"`
	SponsorshipStableActionID           string                                        `json:"sponsorship_stable_action_id"`
	SponsorshipExactRequestDigest       string                                        `json:"sponsorship_exact_request_digest"`
	RelayStableActionID                 string                                        `json:"relay_stable_action_id"`
	RelayExactRequestDigest             string                                        `json:"relay_exact_request_digest"`
	RelayExecutionRequestDigest         string                                        `json:"relay_execution_request_digest"`
	SignedTransactionDigest             string                                        `json:"signed_transaction_digest"`
	SignedTransactionCellHash           string                                        `json:"signed_transaction_cell_hash"`
	TransactionValidUntilUnix           uint64                                        `json:"transaction_valid_until_unix"`
	ProviderSnapshotIdentity            string                                        `json:"provider_snapshot_identity"`
	TransactionAbsenceObservations      []agentrelay.RelayAbsenceObservationReference `json:"transaction_absence_observations"`
	EvidenceSetDigest                   string                                        `json:"evidence_set_digest"`
	ProofBundleDigestAlgorithm          string                                        `json:"proof_bundle_digest_algorithm"`
	ProofBundleDigestDomain             string                                        `json:"proof_bundle_digest_domain"`
	ProofBundleDigest                   string                                        `json:"proof_bundle_digest"`
	ProofBundleCBOR                     []byte                                        `json:"proof_bundle_cbor"`
	ProofBundle                         agentrelay.RelayAbsenceProofBundleV1          `json:"proof_bundle"`
	ProofPayload                        json.RawMessage                               `json:"proof_payload"`
	ProducedAtUnix                      uint64                                        `json:"produced_at_unix"`
	ChainSideEffect                     bool                                          `json:"chain_side_effect"`
	CustodySideEffect                   bool                                          `json:"custody_side_effect"`
}

// tosctlRelayAbsencePayload is the exact adapter payload inside the generic
// protocol wrapper. Interface-valued raw observations are retained and the
// whole struct is re-encoded byte-for-byte, so an added/unknown field cannot
// be silently discarded by the Go boundary.
type tosctlRelayAbsencePayload struct {
	Schema                          string                                        `json:"schema"`
	ProofScope                      agentrelay.RelayAbsenceProofScope             `json:"proof_scope"`
	ProviderSnapshotIdentity        string                                        `json:"provider_snapshot_identity"`
	EvidenceProfileURI              string                                        `json:"evidence_profile_uri"`
	EvidenceProfileDigest           string                                        `json:"evidence_profile_digest"`
	EvidenceProfile                 tosctlRelaySponsorshipEvidenceProfile         `json:"evidence_profile"`
	NetworkDomain                   agentrelay.NetworkDomain                      `json:"network_domain"`
	NetworkDigest                   string                                        `json:"network_digest"`
	AgreementPaymentRequest         commerce.AgreementPaymentRequest              `json:"agreement_payment_request"`
	AgreementPaymentRequestDigest   string                                        `json:"agreement_payment_request_digest"`
	SponsorshipStableActionID       string                                        `json:"sponsorship_stable_action_id"`
	SponsorshipExactRequestDigest   string                                        `json:"sponsorship_exact_request_digest"`
	SponsorshipValidUntilUnix       uint64                                        `json:"sponsorship_valid_until_unix"`
	SignedTopUpTransactionBOC       []byte                                        `json:"signed_top_up_transaction_boc"`
	SignedTopUpTransactionDigest    string                                        `json:"signed_top_up_transaction_digest"`
	SignedTopUpTransactionCellHash  string                                        `json:"signed_top_up_transaction_cell_hash"`
	ProviderSponsorSourceAccount    string                                        `json:"provider_sponsor_source_account"`
	ProviderSponsorSourceSequence   uint64                                        `json:"provider_sponsor_source_sequence"`
	RelayExecutionRequestDigest     string                                        `json:"relay_execution_request_digest"`
	RelayStableActionID             string                                        `json:"relay_stable_action_id"`
	RelayExactRequestDigest         string                                        `json:"relay_exact_request_digest"`
	ProviderAgentID                 string                                        `json:"provider_agent_id"`
	Mode                            agentrelay.Mode                               `json:"mode"`
	AssuranceLevel                  agentrelay.AssuranceLevel                     `json:"assurance_level"`
	SignedTransactionDigest         string                                        `json:"signed_transaction_digest"`
	SignedTransactionCellHash       string                                        `json:"signed_transaction_cell_hash"`
	SignedTransactionSourceAccount  string                                        `json:"signed_transaction_source_account"`
	SignedTransactionSourceSequence uint64                                        `json:"signed_transaction_source_sequence"`
	TransactionValidUntilUnix       uint64                                        `json:"transaction_valid_until_unix"`
	SponsorshipTerminalProfile      agentrelay.FinalityProfile                    `json:"sponsorship_terminal_profile"`
	RelayFinalityProfile            *agentrelay.FinalityProfile                   `json:"relay_finality_profile"`
	Outcome                         string                                        `json:"outcome"`
	SponsorshipObservations         []map[string]any                              `json:"sponsorship_observations"`
	TransactionObservations         []map[string]any                              `json:"transaction_observations"`
	SponsorshipAbsenceObservations  []agentrelay.RelayAbsenceObservationReference `json:"sponsorship_absence_observations"`
	TransactionAbsenceObservations  []agentrelay.RelayAbsenceObservationReference `json:"transaction_absence_observations"`
	EvidenceSetDigest               string                                        `json:"evidence_set_digest"`
	ProducedAtUnix                  uint64                                        `json:"produced_at_unix"`
}

type tosctlRelayAbsenceCapability struct {
	Schema                              string                                     `json:"schema"`
	State                               string                                     `json:"state"`
	Role                                string                                     `json:"role"`
	Mode                                agentrelay.Mode                            `json:"mode"`
	AssuranceLevel                      agentrelay.AssuranceLevel                  `json:"assurance_level"`
	NetworkDomain                       agentrelay.NetworkDomain                   `json:"network_domain"`
	NetworkDigest                       string                                     `json:"network_digest"`
	UnderlyingActionKind                string                                     `json:"underlying_action_kind"`
	TransactionProfileURI               string                                     `json:"transaction_profile_uri"`
	TransactionProfileDigest            string                                     `json:"transaction_profile_digest"`
	SponsorshipReleaseEvidenceClass     agentrelay.SponsorshipReleaseEvidenceClass `json:"sponsorship_release_evidence_class"`
	SponsorshipReleaseProfileURI        string                                     `json:"sponsorship_release_profile_uri"`
	SponsorshipReleaseProfileDigest     string                                     `json:"sponsorship_release_profile_digest"`
	SponsorshipTerminalEvidenceClass    agentrelay.TerminalEvidenceClass           `json:"sponsorship_terminal_evidence_class"`
	SponsorshipTerminalProfile          agentrelay.FinalityProfile                 `json:"sponsorship_terminal_profile"`
	RelayTerminalEvidenceClass          agentrelay.TerminalEvidenceClass           `json:"relay_terminal_evidence_class"`
	RelayFinalityProfile                *agentrelay.FinalityProfile                `json:"relay_finality_profile"`
	SnapshotIdentity                    string                                     `json:"snapshot_identity"`
	SnapshotMembers                     uint32                                     `json:"snapshot_members"`
	SnapshotThreshold                   uint32                                     `json:"snapshot_threshold"`
	AbsenceProofProfileURI              string                                     `json:"absence_proof_profile_uri"`
	AbsenceProofProfileDigest           string                                     `json:"absence_proof_profile_digest"`
	DualAbsence                         bool                                       `json:"dual_absence"`
	SponsorshipComponentAbsence         bool                                       `json:"sponsorship_component_absence"`
	TransactionComponentAbsence         bool                                       `json:"transaction_component_absence"`
	AllReachableComponentOutcomes       bool                                       `json:"all_reachable_component_outcomes"`
	ProducerSupported                   bool                                       `json:"producer_supported"`
	IndependentVerifierSupported        bool                                       `json:"independent_verifier_supported"`
	ValidatorAuthenticatedPortableProof bool                                       `json:"validator_authenticated_portable_proof"`
	AutonomousDecentralizedSupported    bool                                       `json:"autonomous_decentralized_supported"`
	SideEffect                          bool                                       `json:"side_effect"`
}

type tosctlRelayAbsenceVerification struct {
	Schema                                 string                                        `json:"schema"`
	State                                  string                                        `json:"state"`
	Outcome                                string                                        `json:"outcome"`
	TerminalEvidenceClass                  agentrelay.TerminalEvidenceClass              `json:"terminal_evidence_class"`
	ValidatorAuthenticatedPortableProof    bool                                          `json:"validator_authenticated_portable_proof"`
	NetworkDomain                          agentrelay.NetworkDomain                      `json:"network_domain"`
	NetworkDigest                          string                                        `json:"network_digest"`
	AgreementPaymentRequestDigest          string                                        `json:"agreement_payment_request_digest"`
	SponsorshipStableActionID              string                                        `json:"sponsorship_stable_action_id"`
	SponsorshipExactRequestDigest          string                                        `json:"sponsorship_exact_request_digest"`
	RelayStableActionID                    string                                        `json:"relay_stable_action_id"`
	RelayExactRequestDigest                string                                        `json:"relay_exact_request_digest"`
	RelayExecutionRequestDigest            string                                        `json:"relay_execution_request_digest"`
	ProviderSnapshotIdentity               string                                        `json:"provider_snapshot_identity"`
	ClientSnapshotIdentity                 string                                        `json:"client_snapshot_identity"`
	ProviderEvidenceSetDigest              string                                        `json:"provider_evidence_set_digest"`
	ClientEvidenceSetDigest                string                                        `json:"client_evidence_set_digest"`
	ProviderSponsorshipAbsenceObservations []agentrelay.RelayAbsenceObservationReference `json:"provider_sponsorship_absence_observations"`
	ProviderTransactionAbsenceObservations []agentrelay.RelayAbsenceObservationReference `json:"provider_transaction_absence_observations"`
	SponsorshipAbsenceObservations         []agentrelay.RelayAbsenceObservationReference `json:"sponsorship_absence_observations"`
	TransactionAbsenceObservations         []agentrelay.RelayAbsenceObservationReference `json:"transaction_absence_observations"`
	ProofBundleDigestAlgorithm             string                                        `json:"proof_bundle_digest_algorithm"`
	ProofBundleDigestDomain                string                                        `json:"proof_bundle_digest_domain"`
	ProofBundleDigest                      string                                        `json:"proof_bundle_digest"`
	VerifiedAtUnix                         uint64                                        `json:"verified_at_unix"`
	ChainSideEffect                        bool                                          `json:"chain_side_effect"`
	CustodySideEffect                      bool                                          `json:"custody_side_effect"`
}

func (sink *TOSCTLPaymentSink) relayAbsenceSnapshot(
	frozen *RelaySponsorshipEvidenceSnapshot, role string) (RelaySponsorshipEvidenceSnapshot, error) {
	if frozen != nil {
		profile := agentrelay.SponsorshipReleaseProfile{EvidenceClass: agentrelay.SponsorshipReleaseEvidenceClass(frozen.EvidenceClass),
			ProfileURI: frozen.ProfileURI, ProfileDigest: frozen.ProfileDigest}
		var validateErr error
		if role == "verifier" {
			validateErr = sink.ValidateRelaySponsorshipClientEvidenceSnapshot(profile, *frozen)
		} else {
			validateErr = sink.ValidateRelaySponsorshipEvidenceSnapshot(profile, *frozen)
		}
		if validateErr != nil {
			return RelaySponsorshipEvidenceSnapshot{}, errors.New("relay absence snapshot is invalid")
		}
		return *cloneRelaySponsorshipEvidenceSnapshot(frozen), nil
	}
	snapshot, err := sink.ensureCurrentRelaySponsorshipSnapshot()
	if err != nil {
		return RelaySponsorshipEvidenceSnapshot{}, err
	}
	if role == "producer" {
		if !validFrozenRelayCustodyLocator(snapshot.custodyWallet) ||
			!validFrozenRelayCustodyLocator(snapshot.providerSource) {
			return RelaySponsorshipEvidenceSnapshot{}, errors.New("relay absence producer has no frozen custody identity")
		}
		return snapshot.frozenProvider(), nil
	}
	return snapshot.frozenClient(), nil
}

func (sink *TOSCTLPaymentSink) supportsRelayAbsenceCapability(capability agentrelay.RelayEvidenceCapability,
	frozen *RelaySponsorshipEvidenceSnapshot, role string) bool {
	if sink == nil || (role != "producer" && role != "verifier") ||
		capability.AssuranceLevel == agentrelay.AssuranceAutonomousDecentralized ||
		(capability.Mode != agentrelay.ModeSponsorOnly && capability.Mode != agentrelay.ModeSponsorAndRelay) ||
		capability.UnderlyingActionKind != relayV1UnderlyingActionKind ||
		capability.SponsorshipReleaseProfile.EvidenceClass != agentrelay.SponsorshipReleaseObservedUnproven ||
		capability.SponsorshipTerminalProfile == nil ||
		capability.SponsorshipTerminalEvidenceClass != agentrelay.SponsorshipTerminalClientCorroborated ||
		capability.AbsenceProofProfileURI != agentrelay.RelayAbsenceTOSRPCProofProfileURI {
		return false
	}
	stockAbsenceDigest, stockAbsenceErr := agentrelay.RelayAbsenceTOSRPCProofProfileDigest()
	if stockAbsenceErr != nil || capability.AbsenceProofProfileDigest != stockAbsenceDigest {
		return false
	}
	snapshot, err := sink.relayAbsenceSnapshot(frozen, role)
	if err != nil || snapshot.ProfileURI != capability.SponsorshipReleaseProfile.ProfileURI ||
		snapshot.ProfileDigest != capability.SponsorshipReleaseProfile.ProfileDigest {
		return false
	}
	sponsorshipPath, _, sponsorshipCleanup, err := sink.writePrivateCanonicalCBOR(
		".relay-absence-sponsorship-profile-*.cbor", *capability.SponsorshipTerminalProfile)
	if err != nil {
		return false
	}
	defer sponsorshipCleanup()
	args := []string{"agent", "account", "economic-payment-sponsorship-dual-absence-capability",
		"--mode", string(capability.Mode), "--assurance-level", string(capability.AssuranceLevel),
		"--underlying-action-kind", capability.UnderlyingActionKind,
		"--transaction-profile-uri", capability.TransactionProfileURI,
		"--transaction-profile-digest", capability.TransactionProfileDigest,
		"--sponsorship-release-evidence-class", string(capability.SponsorshipReleaseProfile.EvidenceClass),
		"--sponsorship-release-profile-uri", capability.SponsorshipReleaseProfile.ProfileURI,
		"--sponsorship-release-profile-digest", capability.SponsorshipReleaseProfile.ProfileDigest,
		"--sponsorship-terminal-evidence-class", string(capability.SponsorshipTerminalEvidenceClass),
		"--sponsorship-terminal-profile-cbor", sponsorshipPath,
		"--corroboration-snapshot", snapshot.SnapshotPath,
		"--corroboration-snapshot-identity", snapshot.SnapshotIdentity, "--role", role}
	var relayCleanup func()
	if capability.Mode == agentrelay.ModeSponsorAndRelay {
		if capability.RelayFinalityProfile == nil ||
			capability.RelayTerminalEvidenceClass != agentrelay.RelayTerminalProviderCorroborated {
			return false
		}
		relayPath, _, cleanup, writeErr := sink.writePrivateCanonicalCBOR(
			".relay-absence-relay-profile-*.cbor", *capability.RelayFinalityProfile)
		if writeErr != nil {
			return false
		}
		relayCleanup = cleanup
		defer relayCleanup()
		args = append(args, "--relay-terminal-evidence-class", string(capability.RelayTerminalEvidenceClass),
			"--relay-finality-profile-cbor", relayPath)
	}
	ctx, cancel := context.WithTimeout(context.Background(), tosctlSponsorshipPreflightTimeout)
	defer cancel()
	raw, err := sink.run(ctx, args)
	if err != nil {
		return false
	}
	var header tosctlRelayAbsenceHeader
	if json.Unmarshal(raw, &header) != nil || header.Schema != tosctlRelaySponsorshipAbsenceCapabilitySchema ||
		header.State != "ready" {
		return false
	}
	var result tosctlRelayAbsenceCapability
	profileDigest, profileErr := agentrelay.RelayAbsenceTOSRPCProofProfileDigest()
	networkDigest, networkErr := agentrelay.NetworkDomainDigest(capability.Network)
	if decodeStrictJSON(raw, &result) != nil || profileErr != nil || networkErr != nil ||
		result.Role != role || result.Mode != capability.Mode || result.AssuranceLevel != capability.AssuranceLevel ||
		result.NetworkDomain != capability.Network || result.NetworkDigest != networkDigest ||
		result.UnderlyingActionKind != capability.UnderlyingActionKind ||
		result.TransactionProfileURI != capability.TransactionProfileURI ||
		result.TransactionProfileDigest != capability.TransactionProfileDigest ||
		result.SponsorshipReleaseEvidenceClass != capability.SponsorshipReleaseProfile.EvidenceClass ||
		result.SponsorshipReleaseProfileURI != capability.SponsorshipReleaseProfile.ProfileURI ||
		result.SponsorshipReleaseProfileDigest != capability.SponsorshipReleaseProfile.ProfileDigest ||
		result.SponsorshipTerminalEvidenceClass != capability.SponsorshipTerminalEvidenceClass ||
		result.SponsorshipTerminalProfile != *capability.SponsorshipTerminalProfile ||
		result.RelayTerminalEvidenceClass != capability.RelayTerminalEvidenceClass ||
		!reflect.DeepEqual(result.RelayFinalityProfile, capability.RelayFinalityProfile) ||
		result.SnapshotIdentity != snapshot.SnapshotIdentity || result.SnapshotMembers < 3 ||
		result.SnapshotThreshold < result.SnapshotMembers/2+1 ||
		result.AbsenceProofProfileURI != capability.AbsenceProofProfileURI ||
		result.AbsenceProofProfileDigest != capability.AbsenceProofProfileDigest ||
		result.AbsenceProofProfileDigest != profileDigest || !result.SponsorshipComponentAbsence ||
		result.DualAbsence != (capability.Mode == agentrelay.ModeSponsorAndRelay) ||
		result.TransactionComponentAbsence != (capability.Mode == agentrelay.ModeSponsorAndRelay) ||
		!result.AllReachableComponentOutcomes || !result.ProducerSupported ||
		!result.IndependentVerifierSupported || result.ValidatorAuthenticatedPortableProof ||
		result.AutonomousDecentralizedSupported || result.SideEffect {
		return false
	}
	return true
}

func (sink *TOSCTLPaymentSink) SupportsRelaySponsorshipComponentAbsenceEvidence(
	capability agentrelay.RelayEvidenceCapability, frozen *RelaySponsorshipEvidenceSnapshot) bool {
	return sink.supportsRelayAbsenceCapability(capability, frozen, "producer")
}

func (sink *TOSCTLPaymentSink) SupportsRelayDualAbsenceEvidence(
	capability agentrelay.RelayEvidenceCapability, frozen *RelaySponsorshipEvidenceSnapshot) bool {
	if capability.Mode != agentrelay.ModeSponsorAndRelay {
		return false
	}
	return sink.supportsRelayAbsenceCapability(capability, frozen, "producer")
}

func (sink *TOSCTLPaymentSink) SupportsRelayTransactionComponentAbsenceEvidence(
	capability agentrelay.RelayEvidenceCapability, frozen *RelaySponsorshipEvidenceSnapshot) bool {
	return capability.Mode == agentrelay.ModeSponsorAndRelay &&
		sink.supportsRelayAbsenceCapability(capability, frozen, "producer")
}

// ResolveRelayTransactionAbsence is the query-only S+/R- producer. It consumes
// the retained PaymentRequestV3 and immutable Provider snapshot but never a
// wallet/stable-action submit flag, so it cannot create a replacement top-up.
func (sink *TOSCTLPaymentSink) ResolveRelayTransactionAbsence(ctx context.Context,
	execution agentrelay.RelayExecutionRequest, payment commerce.AgreementPaymentRequest,
	frozen RelaySponsorshipEvidenceSnapshot,
	relayOutcome agentrelay.TerminalOutcome) (RelaySponsorshipAbsenceResult, error) {
	if sink == nil || ctx == nil || payment.SchemaVersion != 3 ||
		execution.QuoteRequest.Body.Mode != agentrelay.ModeSponsorAndRelay ||
		!safeRelayTerminalAbsenceOutcome(relayOutcome) {
		return RelaySponsorshipAbsenceResult{}, errors.New("relay transaction-component absence lacks exact recovery state")
	}
	capability, err := relayEvidenceCapabilityForExecution(execution)
	if err != nil || !sink.SupportsRelayTransactionComponentAbsenceEvidence(capability, &frozen) {
		return RelaySponsorshipAbsenceResult{}, errors.New("relay transaction-component absence is not ready for the frozen capability")
	}
	paymentPath, _, paymentCleanup, err := sink.writePrivateCanonicalCBOR(
		".relay-transaction-absence-payment-*.cbor", payment)
	if err != nil {
		return RelaySponsorshipAbsenceResult{}, err
	}
	defer paymentCleanup()
	executionPath, _, executionCleanup, err := sink.writePrivateCanonicalCBOR(
		".relay-transaction-absence-execution-*.cbor", execution)
	if err != nil {
		return RelaySponsorshipAbsenceResult{}, err
	}
	defer executionCleanup()
	sponsorshipPath, _, sponsorshipCleanup, err := sink.writePrivateCanonicalCBOR(
		".relay-transaction-absence-sponsorship-profile-*.cbor", *execution.ProviderQuote.Body.SponsorshipTerminalProfile)
	if err != nil {
		return RelaySponsorshipAbsenceResult{}, err
	}
	defer sponsorshipCleanup()
	if execution.ProviderQuote.Body.RelayFinalityProfile == nil {
		return RelaySponsorshipAbsenceResult{}, errors.New("relay transaction-component absence has no signed relay profile")
	}
	relayPath, _, relayCleanup, err := sink.writePrivateCanonicalCBOR(
		".relay-transaction-absence-relay-profile-*.cbor", *execution.ProviderQuote.Body.RelayFinalityProfile)
	if err != nil {
		return RelaySponsorshipAbsenceResult{}, err
	}
	defer relayCleanup()
	raw, err := sink.run(ctx, []string{"agent", "account", "economic-payment-relay-transaction-component-absence",
		"--agreement-payment-request-cbor", paymentPath,
		"--relay-execution-request-cbor", executionPath,
		"--sponsorship-terminal-profile-cbor", sponsorshipPath,
		"--relay-finality-profile-cbor", relayPath,
		"--corroboration-snapshot", frozen.SnapshotPath,
		"--corroboration-snapshot-identity", frozen.SnapshotIdentity,
		"--sponsorship-release-profile-digest", frozen.ProfileDigest})
	if err != nil {
		return RelaySponsorshipAbsenceResult{}, err
	}
	var header tosctlRelayAbsenceHeader
	if json.Unmarshal(raw, &header) != nil || header.Schema != tosctlRelayTransactionComponentAbsenceSchema {
		return RelaySponsorshipAbsenceResult{}, errors.New("decode tosctl transaction-component absence envelope")
	}
	if header.State == "unknown" {
		var unknown tosctlRelayAbsenceUnknown
		executionDigest, _ := agentrelay.RelayExecutionRequestDigest(execution)
		if decodeStrictJSON(raw, &unknown) != nil ||
			(unknown.Category != "not_mature" && unknown.Category != "temporarily_unavailable") ||
			unknown.Reason == "" || len(unknown.Reason) > 1024 || unknown.ChainSideEffect || unknown.CustodySideEffect ||
			unknown.RelayExecutionRequestDigest != executionDigest ||
			unknown.RelayStableActionID != execution.AuthorizedAction.StableActionID ||
			unknown.RelayExactRequestDigest != execution.AuthorizedAction.ExactRequestDigest ||
			unknown.SponsorshipStableActionID != payment.StableActionID {
			return RelaySponsorshipAbsenceResult{}, errors.New("invalid tosctl transaction-component unknown outcome")
		}
		return RelaySponsorshipAbsenceResult{}, ErrRelaySponsorshipAbsenceUnresolved
	}
	if header.State != "corroborated_transaction_absent" {
		return RelaySponsorshipAbsenceResult{}, errors.New("unsupported tosctl transaction-component absence outcome")
	}
	result, err := sink.decodeRelayTransactionAbsence(execution, payment, frozen, raw)
	if err != nil || !sameRelayAbsenceConclusion(result.Outcome, relayOutcome) {
		if err != nil {
			return RelaySponsorshipAbsenceResult{}, err
		}
		return RelaySponsorshipAbsenceResult{}, errors.New("tosctl transaction-component absence changed the chain resolver conclusion")
	}
	return result, nil
}

func (sink *TOSCTLPaymentSink) ResolveRelaySponsorshipAbsence(ctx context.Context,
	execution agentrelay.RelayExecutionRequest, payment commerce.AgreementPaymentRequest,
	frozen *RelaySponsorshipEvidenceSnapshot) (RelaySponsorshipAbsenceResult, error) {
	if sink == nil || ctx == nil || frozen == nil || payment.SchemaVersion != 3 ||
		execution.QuoteRequest.Body.Mode == agentrelay.ModeRelayExact {
		return RelaySponsorshipAbsenceResult{}, errors.New("relay sponsorship absence query lacks exact recovery state")
	}
	capability, err := relayEvidenceCapabilityForExecution(execution)
	if err != nil || !sink.supportsRelayAbsenceCapability(capability, frozen, "producer") {
		return RelaySponsorshipAbsenceResult{}, errors.New("relay sponsorship absence query is not ready for the frozen capability")
	}
	paymentPath, _, paymentCleanup, err := sink.writePrivateCanonicalCBOR(
		".relay-absence-payment-*.cbor", payment)
	if err != nil {
		return RelaySponsorshipAbsenceResult{}, err
	}
	defer paymentCleanup()
	executionPath, _, executionCleanup, err := sink.writePrivateCanonicalCBOR(
		".relay-absence-execution-*.cbor", execution)
	if err != nil {
		return RelaySponsorshipAbsenceResult{}, err
	}
	defer executionCleanup()
	sponsorshipPath, _, sponsorshipCleanup, err := sink.writePrivateCanonicalCBOR(
		".relay-absence-sponsorship-profile-*.cbor", *execution.ProviderQuote.Body.SponsorshipTerminalProfile)
	if err != nil {
		return RelaySponsorshipAbsenceResult{}, err
	}
	defer sponsorshipCleanup()
	configPath, err := sink.relaySponsorshipSnapshotPrimaryConfig(*frozen)
	if err != nil {
		return RelaySponsorshipAbsenceResult{}, err
	}
	args := []string{"agent", "account", "economic-payment-sponsorship-component-absence",
		"--wallet", frozen.CustodyWallet, "--stable-action-id", payment.StableActionID,
		"--agreement-payment-request-cbor", paymentPath,
		"--relay-execution-request-cbor", executionPath,
		"--sponsorship-terminal-profile-cbor", sponsorshipPath,
		"--corroboration-snapshot", frozen.SnapshotPath,
		"--corroboration-snapshot-identity", frozen.SnapshotIdentity,
		"--sponsorship-release-profile-digest", frozen.ProfileDigest, "-c", configPath}
	if execution.ProviderQuote.Body.RelayFinalityProfile != nil {
		relayPath, _, cleanup, writeErr := sink.writePrivateCanonicalCBOR(
			".relay-absence-relay-profile-*.cbor", *execution.ProviderQuote.Body.RelayFinalityProfile)
		if writeErr != nil {
			return RelaySponsorshipAbsenceResult{}, writeErr
		}
		defer cleanup()
		args = append(args, "--relay-finality-profile-cbor", relayPath)
	}
	raw, err := sink.run(ctx, args)
	if err != nil {
		return RelaySponsorshipAbsenceResult{}, err
	}
	var header tosctlRelayAbsenceHeader
	if json.Unmarshal(raw, &header) != nil || header.Schema != tosctlRelaySponsorshipComponentAbsenceSchema {
		return RelaySponsorshipAbsenceResult{}, errors.New("decode tosctl sponsorship-component absence envelope")
	}
	if header.State == "unknown" {
		var unknown tosctlRelayAbsenceUnknown
		executionDigest, _ := agentrelay.RelayExecutionRequestDigest(execution)
		if decodeStrictJSON(raw, &unknown) != nil ||
			(unknown.Category != "not_mature" && unknown.Category != "temporarily_unavailable") ||
			unknown.Reason == "" || len(unknown.Reason) > 1024 || unknown.ChainSideEffect || unknown.CustodySideEffect ||
			unknown.RelayExecutionRequestDigest != executionDigest ||
			unknown.RelayStableActionID != execution.AuthorizedAction.StableActionID ||
			unknown.RelayExactRequestDigest != execution.AuthorizedAction.ExactRequestDigest ||
			unknown.SponsorshipStableActionID != payment.StableActionID {
			return RelaySponsorshipAbsenceResult{}, errors.New("invalid tosctl sponsorship-component unknown outcome")
		}
		return RelaySponsorshipAbsenceResult{}, ErrRelaySponsorshipAbsenceUnresolved
	}
	if header.State != "corroborated_sponsorship_absent" {
		return RelaySponsorshipAbsenceResult{}, errors.New("unsupported tosctl sponsorship-component absence outcome")
	}
	return sink.decodeRelaySponsorshipAbsence(execution, payment, *frozen, raw)
}

func (sink *TOSCTLPaymentSink) ResolveRelaySponsorshipDualAbsence(ctx context.Context,
	execution agentrelay.RelayExecutionRequest, payment commerce.AgreementPaymentRequest,
	frozen RelaySponsorshipEvidenceSnapshot,
	existingSponsorship []agentrelay.RelayAbsenceObservationReference,
	existingBundleDigest string, existingBundle []byte) (RelaySponsorshipAbsenceResult, error) {
	if sink == nil || ctx == nil || payment.SchemaVersion != 3 ||
		execution.QuoteRequest.Body.Mode != agentrelay.ModeSponsorAndRelay {
		return RelaySponsorshipAbsenceResult{}, errors.New("relay dual-absence aggregation lacks exact recovery state")
	}
	computedPriorDigest, err := agentrelay.RelayAbsenceProofBundleDigest(existingBundle)
	var prior agentrelay.RelayAbsenceProofBundleV1
	var priorPayload tosctlRelayAbsencePayload
	if err != nil || computedPriorDigest != existingBundleDigest || codec.Unmarshal(existingBundle, &prior) != nil ||
		prior.ProofScope != agentrelay.RelayAbsenceProofSponsorshipOnly ||
		!reflect.DeepEqual(prior.SponsorshipAbsenceObservations, existingSponsorship) ||
		len(prior.TransactionAbsenceObservations) != 0 || codec.Unmarshal(prior.ProofPayload, &priorPayload) != nil {
		return RelaySponsorshipAbsenceResult{}, errors.New("relay dual-absence aggregation has an invalid protected predecessor")
	}
	capability, err := relayEvidenceCapabilityForExecution(execution)
	if err != nil || !sink.SupportsRelayDualAbsenceEvidence(capability, &frozen) {
		return RelaySponsorshipAbsenceResult{}, errors.New("relay dual-absence aggregation is not ready for the frozen capability")
	}
	paymentPath, _, paymentCleanup, err := sink.writePrivateCanonicalCBOR(
		".relay-dual-absence-payment-*.cbor", payment)
	if err != nil {
		return RelaySponsorshipAbsenceResult{}, err
	}
	defer paymentCleanup()
	executionPath, _, executionCleanup, err := sink.writePrivateCanonicalCBOR(
		".relay-dual-absence-execution-*.cbor", execution)
	if err != nil {
		return RelaySponsorshipAbsenceResult{}, err
	}
	defer executionCleanup()
	sponsorshipPath, _, sponsorshipCleanup, err := sink.writePrivateCanonicalCBOR(
		".relay-dual-absence-sponsorship-profile-*.cbor", *execution.ProviderQuote.Body.SponsorshipTerminalProfile)
	if err != nil {
		return RelaySponsorshipAbsenceResult{}, err
	}
	defer sponsorshipCleanup()
	if execution.ProviderQuote.Body.RelayFinalityProfile == nil {
		return RelaySponsorshipAbsenceResult{}, errors.New("relay dual-absence aggregation has no signed relay profile")
	}
	relayPath, _, relayCleanup, err := sink.writePrivateCanonicalCBOR(
		".relay-dual-absence-relay-profile-*.cbor", *execution.ProviderQuote.Body.RelayFinalityProfile)
	if err != nil {
		return RelaySponsorshipAbsenceResult{}, err
	}
	defer relayCleanup()
	priorPath, priorCleanup, err := sink.writePrivateBytes(
		".relay-dual-absence-predecessor-*.cbor", existingBundle)
	if err != nil {
		return RelaySponsorshipAbsenceResult{}, err
	}
	defer priorCleanup()
	configPath, err := sink.relaySponsorshipSnapshotPrimaryConfig(frozen)
	if err != nil {
		return RelaySponsorshipAbsenceResult{}, err
	}
	args := []string{"agent", "account", "economic-payment-sponsorship-dual-absence",
		"--wallet", frozen.CustodyWallet, "--stable-action-id", payment.StableActionID,
		"--agreement-payment-request-cbor", paymentPath,
		"--relay-execution-request-cbor", executionPath,
		"--sponsorship-terminal-profile-cbor", sponsorshipPath,
		"--relay-finality-profile-cbor", relayPath,
		"--corroboration-snapshot", frozen.SnapshotPath,
		"--corroboration-snapshot-identity", frozen.SnapshotIdentity,
		"--sponsorship-release-profile-digest", frozen.ProfileDigest,
		"--existing-sponsorship-proof-bundle-cbor", priorPath, "-c", configPath}
	raw, err := sink.run(ctx, args)
	if err != nil {
		return RelaySponsorshipAbsenceResult{}, err
	}
	var header tosctlRelayAbsenceHeader
	if json.Unmarshal(raw, &header) != nil || header.Schema != tosctlRelaySponsorshipDualAbsenceSchema {
		return RelaySponsorshipAbsenceResult{}, errors.New("decode tosctl dual-absence aggregation envelope")
	}
	if header.State == "unknown" {
		var unknown tosctlRelayAbsenceUnknown
		executionDigest, _ := agentrelay.RelayExecutionRequestDigest(execution)
		if decodeStrictJSON(raw, &unknown) != nil ||
			(unknown.Category != "not_mature" && unknown.Category != "temporarily_unavailable") ||
			unknown.Reason == "" || len(unknown.Reason) > 1024 || unknown.ChainSideEffect || unknown.CustodySideEffect ||
			unknown.RelayExecutionRequestDigest != executionDigest ||
			unknown.RelayStableActionID != execution.AuthorizedAction.StableActionID ||
			unknown.RelayExactRequestDigest != execution.AuthorizedAction.ExactRequestDigest ||
			unknown.SponsorshipStableActionID != payment.StableActionID {
			return RelaySponsorshipAbsenceResult{}, errors.New("invalid tosctl dual-absence unknown outcome")
		}
		return RelaySponsorshipAbsenceResult{}, ErrRelaySponsorshipAbsenceUnresolved
	}
	if header.State != "corroborated_absent" {
		return RelaySponsorshipAbsenceResult{}, errors.New("unsupported tosctl dual-absence aggregation outcome")
	}
	return sink.decodeRelaySponsorshipDualAbsence(execution, payment, frozen, priorPayload,
		existingSponsorship, existingBundleDigest, raw)
}

func (sink *TOSCTLPaymentSink) decodeRelaySponsorshipAbsence(execution agentrelay.RelayExecutionRequest,
	payment commerce.AgreementPaymentRequest, frozen RelaySponsorshipEvidenceSnapshot,
	raw []byte) (RelaySponsorshipAbsenceResult, error) {
	var result tosctlRelayAbsenceTerminal
	if decodeStrictJSON(raw, &result) != nil {
		return RelaySponsorshipAbsenceResult{}, errors.New("decode strict tosctl sponsorship-component absence")
	}
	var wrapper agentrelay.RelayAbsenceProofBundleV1
	if codec.Unmarshal(result.ProofBundleCBOR, &wrapper) != nil || !reflect.DeepEqual(wrapper, result.ProofBundle) {
		return RelaySponsorshipAbsenceResult{}, errors.New("tosctl absence JSON and canonical wrapper differ")
	}
	bundleDigest, bundleErr := agentrelay.RelayAbsenceProofBundleDigest(result.ProofBundleCBOR)
	var payload tosctlRelayAbsencePayload
	if codec.Unmarshal(wrapper.ProofPayload, &payload) != nil {
		return RelaySponsorshipAbsenceResult{}, errors.New("decode exact tosctl absence payload")
	}
	reencoded, reencodeErr := codec.Marshal(payload)
	paymentDigest, paymentErr := commerce.AgreementPaymentRequestDigest(payment)
	canonical, _, materialErr := commerce.PaymentAuthorizationMaterial(payment)
	paymentExactDigest, exactErr := commerce.ExactRequestDigest(canonical)
	executionDigest, executionErr := agentrelay.RelayExecutionRequestDigest(execution)
	networkDigest, networkErr := agentrelay.NetworkDomainDigest(execution.QuoteRequest.Body.Network)
	evidenceSet, evidenceSetErr := relayAbsenceReferenceSetDigest(result.SponsorshipAbsenceObservations,
		result.TransactionAbsenceObservations)
	now := sink.sponsorshipNow()
	if bundleErr != nil || reencodeErr != nil || !bytes.Equal(reencoded, wrapper.ProofPayload) ||
		paymentErr != nil || materialErr != nil || exactErr != nil || executionErr != nil || networkErr != nil ||
		evidenceSetErr != nil || result.Schema != tosctlRelaySponsorshipComponentAbsenceSchema ||
		result.State != "corroborated_sponsorship_absent" ||
		result.Outcome != "corroborated_sponsorship_absent_component" ||
		result.TerminalEvidenceClass != agentrelay.SponsorshipTerminalClientCorroborated ||
		result.ValidatorAuthenticatedPortableProof || result.NetworkDomain != execution.QuoteRequest.Body.Network ||
		result.NetworkDigest != networkDigest || result.AgreementPaymentRequestDigest != paymentDigest ||
		result.SponsorshipStableActionID != payment.StableActionID ||
		result.SponsorshipExactRequestDigest != paymentExactDigest ||
		result.SponsorshipValidUntilUnix != payment.ExpiresAtUnix ||
		result.RelayStableActionID != execution.AuthorizedAction.StableActionID ||
		result.RelayExactRequestDigest != execution.AuthorizedAction.ExactRequestDigest ||
		result.RelayExecutionRequestDigest != executionDigest ||
		result.SignedTransactionDigest != execution.QuoteRequest.Body.SignedTransactionDigest ||
		result.SignedTransactionCellHash != execution.QuoteRequest.Body.SignedTransactionCellHash ||
		result.TransactionValidUntilUnix != execution.QuoteRequest.Body.TransactionValidUntilUnix ||
		execution.ProviderQuote.Body.SponsorshipTerminalProfile == nil ||
		result.SponsorshipTerminalProfile != *execution.ProviderQuote.Body.SponsorshipTerminalProfile ||
		!reflect.DeepEqual(result.RelayFinalityProfile, execution.ProviderQuote.Body.RelayFinalityProfile) ||
		result.ProviderSnapshotIdentity != frozen.SnapshotIdentity ||
		result.EvidenceProfileURI != frozen.ProfileURI || result.EvidenceProfileDigest != frozen.ProfileDigest ||
		result.EvidenceSetDigest != evidenceSet || result.ProofBundleDigestAlgorithm != tosctlRelayAbsenceDigestMethod ||
		result.ProofBundleDigestDomain != agentrelay.RelayAbsenceProofBundleDomainV1 ||
		result.ProofBundleDigest != bundleDigest || wrapper.ProofScope != agentrelay.RelayAbsenceProofSponsorshipOnly ||
		!reflect.DeepEqual(wrapper.SponsorshipAbsenceObservations, result.SponsorshipAbsenceObservations) ||
		!relayAbsenceReferencesUseObservationProfile(result.SponsorshipAbsenceObservations,
			frozen.ProfileURI, frozen.ProfileDigest) ||
		len(wrapper.TransactionAbsenceObservations) != 0 || len(result.TransactionAbsenceObservations) != 0 ||
		result.ProducedAtUnix == 0 || result.ProducedAtUnix > uint64(now.Add(5*time.Minute).Unix()) ||
		result.CustodyState != "resolved" || result.ChainSideEffect || !result.CustodySideEffect ||
		payload.ProofScope != agentrelay.RelayAbsenceProofSponsorshipOnly ||
		payload.ProviderSnapshotIdentity != frozen.SnapshotIdentity || payload.NetworkDomain != result.NetworkDomain ||
		payload.NetworkDigest != result.NetworkDigest || !reflect.DeepEqual(payload.AgreementPaymentRequest, payment) ||
		payload.AgreementPaymentRequestDigest != paymentDigest || payload.SponsorshipStableActionID != payment.StableActionID ||
		payload.SponsorshipExactRequestDigest != paymentExactDigest || payload.RelayExecutionRequestDigest != executionDigest ||
		payload.RelayStableActionID != execution.AuthorizedAction.StableActionID ||
		payload.RelayExactRequestDigest != execution.AuthorizedAction.ExactRequestDigest ||
		payload.ProviderAgentID != execution.ProviderQuote.Body.ProviderAgentID ||
		payload.Mode != execution.QuoteRequest.Body.Mode || payload.AssuranceLevel != execution.QuoteRequest.Body.AssuranceLevel ||
		!reflect.DeepEqual(payload.SponsorshipAbsenceObservations, result.SponsorshipAbsenceObservations) ||
		len(payload.TransactionAbsenceObservations) != 0 || payload.EvidenceSetDigest != evidenceSet {
		return RelaySponsorshipAbsenceResult{}, errors.New("tosctl sponsorship-component absence changes exact execution or proof profile")
	}
	return RelaySponsorshipAbsenceResult{Outcome: agentrelay.OutcomeCorroboratedExpired,
		SponsorshipAbsenceObservations: append([]agentrelay.RelayAbsenceObservationReference(nil),
			result.SponsorshipAbsenceObservations...), ProofBundleDigest: bundleDigest,
		ProofBundle: append([]byte(nil), result.ProofBundleCBOR...)}, nil
}

func (sink *TOSCTLPaymentSink) decodeRelayTransactionAbsence(execution agentrelay.RelayExecutionRequest,
	payment commerce.AgreementPaymentRequest, frozen RelaySponsorshipEvidenceSnapshot,
	raw []byte) (RelaySponsorshipAbsenceResult, error) {
	var result tosctlRelayTransactionAbsenceTerminal
	if decodeStrictJSON(raw, &result) != nil {
		return RelaySponsorshipAbsenceResult{}, errors.New("decode strict tosctl transaction-component absence")
	}
	var wrapper agentrelay.RelayAbsenceProofBundleV1
	if codec.Unmarshal(result.ProofBundleCBOR, &wrapper) != nil || !reflect.DeepEqual(wrapper, result.ProofBundle) {
		return RelaySponsorshipAbsenceResult{}, errors.New("tosctl transaction absence JSON and canonical wrapper differ")
	}
	bundleDigest, bundleErr := agentrelay.RelayAbsenceProofBundleDigest(result.ProofBundleCBOR)
	var payload, jsonPayload tosctlRelayAbsencePayload
	if codec.Unmarshal(wrapper.ProofPayload, &payload) != nil ||
		decodeStrictJSON(result.ProofPayload, &jsonPayload) != nil || !reflect.DeepEqual(payload, jsonPayload) {
		return RelaySponsorshipAbsenceResult{}, errors.New("decode exact tosctl transaction absence payload")
	}
	reencoded, reencodeErr := codec.Marshal(payload)
	paymentDigest, paymentErr := commerce.AgreementPaymentRequestDigest(payment)
	canonical, _, materialErr := commerce.PaymentAuthorizationMaterial(payment)
	paymentExactDigest, exactErr := commerce.ExactRequestDigest(canonical)
	executionDigest, executionErr := agentrelay.RelayExecutionRequestDigest(execution)
	networkDigest, networkErr := agentrelay.NetworkDomainDigest(execution.QuoteRequest.Body.Network)
	evidenceSet, evidenceSetErr := relayAbsenceReferenceSetDigest(nil, result.TransactionAbsenceObservations)
	outcome, outcomeOK := relayTransactionComponentOutcome(result.ComponentOutcome)
	now := sink.sponsorshipNow()
	if bundleErr != nil || reencodeErr != nil || !bytes.Equal(reencoded, wrapper.ProofPayload) ||
		paymentErr != nil || materialErr != nil || exactErr != nil || executionErr != nil || networkErr != nil ||
		evidenceSetErr != nil || !outcomeOK || result.Schema != tosctlRelayTransactionComponentAbsenceSchema ||
		result.State != "corroborated_transaction_absent" ||
		result.TerminalEvidenceClass != agentrelay.RelayTerminalProviderCorroborated ||
		result.ValidatorAuthenticatedPortableProof || result.NetworkDomain != execution.QuoteRequest.Body.Network ||
		result.NetworkDigest != networkDigest || result.AgreementPaymentRequestDigest != paymentDigest ||
		result.SponsorshipStableActionID != payment.StableActionID ||
		result.SponsorshipExactRequestDigest != paymentExactDigest ||
		result.RelayStableActionID != execution.AuthorizedAction.StableActionID ||
		result.RelayExactRequestDigest != execution.AuthorizedAction.ExactRequestDigest ||
		result.RelayExecutionRequestDigest != executionDigest ||
		result.SignedTransactionDigest != execution.QuoteRequest.Body.SignedTransactionDigest ||
		result.SignedTransactionCellHash != execution.QuoteRequest.Body.SignedTransactionCellHash ||
		result.TransactionValidUntilUnix != execution.QuoteRequest.Body.TransactionValidUntilUnix ||
		result.ProviderSnapshotIdentity != frozen.SnapshotIdentity || result.EvidenceSetDigest != evidenceSet ||
		result.ProofBundleDigestAlgorithm != tosctlRelayAbsenceDigestMethod ||
		result.ProofBundleDigestDomain != agentrelay.RelayAbsenceProofBundleDomainV1 ||
		result.ProofBundleDigest != bundleDigest || wrapper.ProofScope != agentrelay.RelayAbsenceProofTransactionOnly ||
		len(wrapper.SponsorshipAbsenceObservations) != 0 ||
		!reflect.DeepEqual(wrapper.TransactionAbsenceObservations, result.TransactionAbsenceObservations) ||
		!relayAbsenceReferencesUseObservationProfile(result.TransactionAbsenceObservations,
			frozen.ProfileURI, frozen.ProfileDigest) ||
		!relayTransactionAbsenceReferencesMatch(execution, outcome, result.TransactionAbsenceObservations) ||
		result.ProducedAtUnix == 0 || result.ProducedAtUnix > uint64(now.Add(5*time.Minute).Unix()) ||
		result.ChainSideEffect || result.CustodySideEffect ||
		payload.ProofScope != agentrelay.RelayAbsenceProofTransactionOnly ||
		payload.ProviderSnapshotIdentity != frozen.SnapshotIdentity || payload.NetworkDomain != result.NetworkDomain ||
		payload.NetworkDigest != result.NetworkDigest || !reflect.DeepEqual(payload.AgreementPaymentRequest, payment) ||
		payload.AgreementPaymentRequestDigest != paymentDigest || payload.SponsorshipStableActionID != payment.StableActionID ||
		payload.SponsorshipExactRequestDigest != paymentExactDigest || payload.RelayExecutionRequestDigest != executionDigest ||
		payload.RelayStableActionID != execution.AuthorizedAction.StableActionID ||
		payload.RelayExactRequestDigest != execution.AuthorizedAction.ExactRequestDigest ||
		payload.ProviderAgentID != execution.ProviderQuote.Body.ProviderAgentID ||
		payload.Mode != execution.QuoteRequest.Body.Mode || payload.AssuranceLevel != execution.QuoteRequest.Body.AssuranceLevel ||
		len(payload.SponsorshipAbsenceObservations) != 0 ||
		!reflect.DeepEqual(payload.TransactionAbsenceObservations, result.TransactionAbsenceObservations) ||
		payload.EvidenceSetDigest != evidenceSet {
		return RelaySponsorshipAbsenceResult{}, errors.New("tosctl transaction-component absence changes exact execution or proof profile")
	}
	return RelaySponsorshipAbsenceResult{Outcome: outcome,
		TransactionAbsenceObservations: append([]agentrelay.RelayAbsenceObservationReference(nil),
			result.TransactionAbsenceObservations...), ProofBundleDigest: bundleDigest,
		ProofBundle: append([]byte(nil), result.ProofBundleCBOR...)}, nil
}

func relayTransactionComponentOutcome(value string) (agentrelay.TerminalOutcome, bool) {
	switch value {
	case "corroborated_transaction_expired":
		return agentrelay.OutcomeCorroboratedExpired, true
	case "corroborated_transaction_absent":
		return agentrelay.OutcomeCorroboratedAbsent, true
	case "corroborated_transaction_invalidated":
		return agentrelay.OutcomeCorroboratedInvalidated, true
	default:
		return "", false
	}
}

func relayTransactionAbsenceReferencesMatch(execution agentrelay.RelayExecutionRequest,
	outcome agentrelay.TerminalOutcome, references []agentrelay.RelayAbsenceObservationReference) bool {
	if len(references) == 0 || execution.ProviderQuote.Body.RelayFinalityProfile == nil {
		return false
	}
	executionDigest, err := agentrelay.RelayExecutionRequestDigest(execution)
	networkDigest, networkErr := agentrelay.NetworkDomainDigest(execution.QuoteRequest.Body.Network)
	if err != nil || networkErr != nil {
		return false
	}
	profile := *execution.ProviderQuote.Body.RelayFinalityProfile
	for _, reference := range references {
		if reference.ObservationKind != agentrelay.AbsenceObservationClientTransaction ||
			reference.ProviderAgentID != execution.ProviderQuote.Body.ProviderAgentID ||
			reference.NetworkDigest != networkDigest ||
			reference.RelayStableActionID != execution.AuthorizedAction.StableActionID ||
			reference.RelayExactRequestDigest != execution.AuthorizedAction.ExactRequestDigest ||
			reference.RelayExecutionDigest != executionDigest ||
			reference.SignedTransactionDigest != execution.QuoteRequest.Body.SignedTransactionDigest ||
			reference.SignedTransactionCellHash != execution.QuoteRequest.Body.SignedTransactionCellHash ||
			reference.TerminalProfileURI != profile.ProfileURI ||
			reference.TerminalProfileDigest != profile.ProfileDigest ||
			reference.TerminalEvidenceClass != profile.TerminalEvidenceClass ||
			!relayAbsenceReferenceConclusionMatchesOutcome(reference.Conclusion, outcome) {
			return false
		}
	}
	return true
}

func relayAbsenceReferenceConclusionMatchesOutcome(conclusion agentrelay.RelayAbsenceConclusion,
	outcome agentrelay.TerminalOutcome) bool {
	switch conclusion {
	case agentrelay.AbsenceConclusionExpiredWithoutInclusion:
		return outcome == agentrelay.OutcomeFinalizedExpired || outcome == agentrelay.OutcomeCorroboratedExpired
	case agentrelay.AbsenceConclusionAbsent:
		return outcome == agentrelay.OutcomeFinalizedAbsent || outcome == agentrelay.OutcomeCorroboratedAbsent
	case agentrelay.AbsenceConclusionInvalidated:
		return outcome == agentrelay.OutcomeFinalizedInvalidated || outcome == agentrelay.OutcomeCorroboratedInvalidated
	default:
		return false
	}
}

func (sink *TOSCTLPaymentSink) decodeRelaySponsorshipDualAbsence(execution agentrelay.RelayExecutionRequest,
	payment commerce.AgreementPaymentRequest, frozen RelaySponsorshipEvidenceSnapshot,
	priorPayload tosctlRelayAbsencePayload, existingSponsorship []agentrelay.RelayAbsenceObservationReference,
	existingBundleDigest string, raw []byte) (RelaySponsorshipAbsenceResult, error) {
	var result tosctlRelayAbsenceTerminal
	if decodeStrictJSON(raw, &result) != nil {
		return RelaySponsorshipAbsenceResult{}, errors.New("decode strict tosctl dual-absence aggregation")
	}
	var wrapper agentrelay.RelayAbsenceProofBundleV1
	if codec.Unmarshal(result.ProofBundleCBOR, &wrapper) != nil || !reflect.DeepEqual(wrapper, result.ProofBundle) {
		return RelaySponsorshipAbsenceResult{}, errors.New("tosctl dual-absence JSON and canonical wrapper differ")
	}
	bundleDigest, bundleErr := agentrelay.RelayAbsenceProofBundleDigest(result.ProofBundleCBOR)
	var payload, jsonPayload tosctlRelayAbsencePayload
	if codec.Unmarshal(wrapper.ProofPayload, &payload) != nil ||
		decodeStrictJSON(result.ProofPayload, &jsonPayload) != nil || !reflect.DeepEqual(payload, jsonPayload) {
		return RelaySponsorshipAbsenceResult{}, errors.New("decode exact tosctl dual-absence payload")
	}
	reencoded, reencodeErr := codec.Marshal(payload)
	paymentDigest, paymentErr := commerce.AgreementPaymentRequestDigest(payment)
	canonical, _, materialErr := commerce.PaymentAuthorizationMaterial(payment)
	paymentExactDigest, exactErr := commerce.ExactRequestDigest(canonical)
	executionDigest, executionErr := agentrelay.RelayExecutionRequestDigest(execution)
	networkDigest, networkErr := agentrelay.NetworkDomainDigest(execution.QuoteRequest.Body.Network)
	evidenceSet, evidenceSetErr := relayAbsenceReferenceSetDigest(result.SponsorshipAbsenceObservations,
		result.TransactionAbsenceObservations)
	outcome, outcomeOK := relayCorroboratedAbsenceOutcome(result.Outcome)
	now := sink.sponsorshipNow()
	if bundleErr != nil || reencodeErr != nil || !bytes.Equal(reencoded, wrapper.ProofPayload) ||
		paymentErr != nil || materialErr != nil || exactErr != nil || executionErr != nil || networkErr != nil ||
		evidenceSetErr != nil || !outcomeOK || result.Schema != tosctlRelaySponsorshipDualAbsenceSchema ||
		result.State != "corroborated_absent" ||
		result.TerminalEvidenceClass != agentrelay.SponsorshipTerminalClientCorroborated ||
		result.ValidatorAuthenticatedPortableProof || result.NetworkDomain != execution.QuoteRequest.Body.Network ||
		result.NetworkDigest != networkDigest || result.AgreementPaymentRequestDigest != paymentDigest ||
		result.SponsorshipStableActionID != payment.StableActionID ||
		result.SponsorshipExactRequestDigest != paymentExactDigest ||
		result.SponsorshipValidUntilUnix != payment.ExpiresAtUnix ||
		result.RelayStableActionID != execution.AuthorizedAction.StableActionID ||
		result.RelayExactRequestDigest != execution.AuthorizedAction.ExactRequestDigest ||
		result.RelayExecutionRequestDigest != executionDigest ||
		result.SignedTransactionDigest != execution.QuoteRequest.Body.SignedTransactionDigest ||
		result.SignedTransactionCellHash != execution.QuoteRequest.Body.SignedTransactionCellHash ||
		result.TransactionValidUntilUnix != execution.QuoteRequest.Body.TransactionValidUntilUnix ||
		execution.ProviderQuote.Body.SponsorshipTerminalProfile == nil ||
		result.SponsorshipTerminalProfile != *execution.ProviderQuote.Body.SponsorshipTerminalProfile ||
		!reflect.DeepEqual(result.RelayFinalityProfile, execution.ProviderQuote.Body.RelayFinalityProfile) ||
		result.ProviderSnapshotIdentity != frozen.SnapshotIdentity ||
		result.EvidenceProfileURI != frozen.ProfileURI || result.EvidenceProfileDigest != frozen.ProfileDigest ||
		result.PredecessorSponsorshipProofBundleDigest != existingBundleDigest ||
		result.EvidenceSetDigest != evidenceSet || result.ProofBundleDigestAlgorithm != tosctlRelayAbsenceDigestMethod ||
		result.ProofBundleDigestDomain != agentrelay.RelayAbsenceProofBundleDomainV1 ||
		result.ProofBundleDigest != bundleDigest || wrapper.ProofScope != agentrelay.RelayAbsenceProofDual ||
		!reflect.DeepEqual(wrapper.SponsorshipAbsenceObservations, result.SponsorshipAbsenceObservations) ||
		!reflect.DeepEqual(wrapper.TransactionAbsenceObservations, result.TransactionAbsenceObservations) ||
		!reflect.DeepEqual(result.SponsorshipAbsenceObservations, existingSponsorship) ||
		len(result.TransactionAbsenceObservations) == 0 ||
		!relayAbsenceReferencesUseObservationProfile(result.SponsorshipAbsenceObservations,
			frozen.ProfileURI, frozen.ProfileDigest) ||
		!relayAbsenceReferencesUseObservationProfile(result.TransactionAbsenceObservations,
			frozen.ProfileURI, frozen.ProfileDigest) ||
		result.ProducedAtUnix == 0 || result.ProducedAtUnix > uint64(now.Add(5*time.Minute).Unix()) ||
		result.CustodyState != "resolved_sponsorship_component" || result.ChainSideEffect || result.CustodySideEffect ||
		payload.ProofScope != agentrelay.RelayAbsenceProofDual ||
		payload.ProviderSnapshotIdentity != frozen.SnapshotIdentity || payload.NetworkDomain != result.NetworkDomain ||
		payload.NetworkDigest != result.NetworkDigest || !reflect.DeepEqual(payload.AgreementPaymentRequest, payment) ||
		payload.AgreementPaymentRequestDigest != paymentDigest || payload.SponsorshipStableActionID != payment.StableActionID ||
		payload.SponsorshipExactRequestDigest != paymentExactDigest || payload.RelayExecutionRequestDigest != executionDigest ||
		payload.RelayStableActionID != execution.AuthorizedAction.StableActionID ||
		payload.RelayExactRequestDigest != execution.AuthorizedAction.ExactRequestDigest ||
		payload.ProviderAgentID != execution.ProviderQuote.Body.ProviderAgentID ||
		payload.Mode != execution.QuoteRequest.Body.Mode || payload.AssuranceLevel != execution.QuoteRequest.Body.AssuranceLevel ||
		payload.Outcome != result.Outcome ||
		!reflect.DeepEqual(payload.SponsorshipAbsenceObservations, existingSponsorship) ||
		!reflect.DeepEqual(payload.TransactionAbsenceObservations, result.TransactionAbsenceObservations) ||
		payload.EvidenceSetDigest != evidenceSet ||
		!sameRelaySponsorshipAbsencePredecessor(priorPayload, payload) {
		return RelaySponsorshipAbsenceResult{}, errors.New("tosctl dual-absence aggregation changes an exact predecessor or proof profile")
	}
	return RelaySponsorshipAbsenceResult{Outcome: outcome,
		SponsorshipAbsenceObservations: append([]agentrelay.RelayAbsenceObservationReference(nil),
			result.SponsorshipAbsenceObservations...),
		TransactionAbsenceObservations: append([]agentrelay.RelayAbsenceObservationReference(nil),
			result.TransactionAbsenceObservations...),
		ProofBundleDigest: bundleDigest, ProofBundle: append([]byte(nil), result.ProofBundleCBOR...)}, nil
}

func sameRelaySponsorshipAbsencePredecessor(prior, dual tosctlRelayAbsencePayload) bool {
	return reflect.DeepEqual(prior.AgreementPaymentRequest, dual.AgreementPaymentRequest) &&
		prior.AgreementPaymentRequestDigest == dual.AgreementPaymentRequestDigest &&
		prior.SponsorshipStableActionID == dual.SponsorshipStableActionID &&
		prior.SponsorshipExactRequestDigest == dual.SponsorshipExactRequestDigest &&
		prior.SponsorshipValidUntilUnix == dual.SponsorshipValidUntilUnix &&
		bytes.Equal(prior.SignedTopUpTransactionBOC, dual.SignedTopUpTransactionBOC) &&
		prior.SignedTopUpTransactionDigest == dual.SignedTopUpTransactionDigest &&
		prior.SignedTopUpTransactionCellHash == dual.SignedTopUpTransactionCellHash &&
		prior.ProviderSponsorSourceAccount == dual.ProviderSponsorSourceAccount &&
		prior.ProviderSponsorSourceSequence == dual.ProviderSponsorSourceSequence &&
		reflect.DeepEqual(prior.SponsorshipObservations, dual.SponsorshipObservations) &&
		reflect.DeepEqual(prior.SponsorshipAbsenceObservations, dual.SponsorshipAbsenceObservations)
}

func relayCorroboratedAbsenceOutcome(value string) (agentrelay.TerminalOutcome, bool) {
	switch value {
	case string(agentrelay.OutcomeCorroboratedExpired):
		return agentrelay.OutcomeCorroboratedExpired, true
	case string(agentrelay.OutcomeCorroboratedAbsent):
		return agentrelay.OutcomeCorroboratedAbsent, true
	case string(agentrelay.OutcomeCorroboratedInvalidated):
		return agentrelay.OutcomeCorroboratedInvalidated, true
	default:
		return "", false
	}
}

func relayAbsenceReferencesUseObservationProfile(references []agentrelay.RelayAbsenceObservationReference,
	profileURI, profileDigest string) bool {
	if len(references) == 0 || profileURI == "" || profileDigest == "" {
		return false
	}
	for _, reference := range references {
		if reference.ObservationEvidenceProfileURI != profileURI ||
			reference.ObservationEvidenceProfileDigest != profileDigest {
			return false
		}
	}
	return true
}

func relayAbsenceReferenceSetDigest(sponsorship,
	transaction []agentrelay.RelayAbsenceObservationReference) (string, error) {
	digests := make([]string, 0, len(sponsorship)+len(transaction))
	for _, reference := range append(append([]agentrelay.RelayAbsenceObservationReference(nil), sponsorship...), transaction...) {
		digest, err := agentrelay.RelayAbsenceObservationReferenceDigest(reference)
		if err != nil {
			return "", err
		}
		digests = append(digests, digest)
	}
	sort.Strings(digests)
	return agentrelay.RelayEvidenceSetDigest(digests)
}

// TOSCTLRelayFinalityVerifier composes the client-owned TOS relay component
// verifier with the tosctl sponsorship/absence verifier. The two independently
// frozen snapshots are encoded in one protected route snapshot; Provider and
// requester snapshot identities may differ, but their public descriptor and
// signed evidence tuple must be identical.
type TOSCTLRelayFinalityVerifier struct {
	RelayComponent RelayClientFinalitySnapshotVerifier
	Sponsorship    *TOSCTLPaymentSink
}

type tosctlRelayClientFinalitySnapshot struct {
	SchemaVersion       uint16                             `json:"schema_version"`
	Capability          agentrelay.RelayEvidenceCapability `json:"capability"`
	RelayComponent      []byte                             `json:"relay_component_snapshot,omitempty"`
	SponsorshipEvidence *RelaySponsorshipEvidenceSnapshot  `json:"sponsorship_evidence_snapshot"`
}

func (verifier *TOSCTLRelayFinalityVerifier) SupportsRelayEvidenceCapability(
	capability agentrelay.RelayEvidenceCapability) bool {
	if verifier == nil || verifier.Sponsorship == nil ||
		!verifier.Sponsorship.supportsRelayAbsenceCapability(capability, nil, "verifier") {
		return false
	}
	if capability.Mode == agentrelay.ModeSponsorOnly {
		return true
	}
	return verifier.RelayComponent != nil && verifier.RelayComponent.SupportsRelayEvidenceCapability(capability)
}

func (verifier *TOSCTLRelayFinalityVerifier) SupportsRelayDualAbsenceEvidence(
	capability agentrelay.RelayEvidenceCapability) bool {
	return capability.Mode == agentrelay.ModeSponsorAndRelay && verifier.SupportsRelayEvidenceCapability(capability)
}

func (verifier *TOSCTLRelayFinalityVerifier) SupportsRelaySponsorshipComponentAbsenceEvidence(
	capability agentrelay.RelayEvidenceCapability) bool {
	return verifier.SupportsRelayEvidenceCapability(capability)
}

func (verifier *TOSCTLRelayFinalityVerifier) SupportsRelayTransactionComponentAbsenceEvidence(
	capability agentrelay.RelayEvidenceCapability) bool {
	return capability.Mode == agentrelay.ModeSponsorAndRelay && verifier.SupportsRelayEvidenceCapability(capability)
}

func (verifier *TOSCTLRelayFinalityVerifier) HasIndependentPortableRelayFinalityProofs() bool {
	return false
}

func (verifier *TOSCTLRelayFinalityVerifier) FreezeRelayFinalityEvidenceSnapshot(ctx context.Context,
	capability agentrelay.RelayEvidenceCapability) ([]byte, error) {
	if !verifier.SupportsRelayEvidenceCapability(capability) {
		return nil, errors.New("tosctl relay verifier does not support the exact current capability")
	}
	request := relayQuoteBodyForEvidenceCapability(capability)
	sponsorship, err := verifier.Sponsorship.FreezeRelaySponsorshipClientEvidenceSnapshot(ctx, request)
	if err != nil {
		return nil, err
	}
	var relaySnapshot []byte
	if capability.Mode == agentrelay.ModeSponsorAndRelay {
		relaySnapshot, err = verifier.RelayComponent.FreezeRelayFinalityEvidenceSnapshot(ctx, capability)
		if err != nil {
			return nil, err
		}
	}
	return codec.Marshal(tosctlRelayClientFinalitySnapshot{SchemaVersion: 1, Capability: capability,
		RelayComponent: relaySnapshot, SponsorshipEvidence: &sponsorship})
}

func relayQuoteBodyForEvidenceCapability(capability agentrelay.RelayEvidenceCapability) agentrelay.RelayQuoteRequestBody {
	body := agentrelay.RelayQuoteRequestBody{Mode: capability.Mode, AssuranceLevel: capability.AssuranceLevel,
		Network: capability.Network, TransactionProfileURI: capability.TransactionProfileURI,
		TransactionProfileDigest: capability.TransactionProfileDigest, UnderlyingActionKind: capability.UnderlyingActionKind,
		RelayTerminalEvidenceClass:       capability.RelayTerminalEvidenceClass,
		SponsorshipTerminalEvidenceClass: capability.SponsorshipTerminalEvidenceClass,
		SponsorshipReleaseEvidenceClass:  capability.SponsorshipReleaseProfile.EvidenceClass,
		SponsorshipReleaseProfileURI:     capability.SponsorshipReleaseProfile.ProfileURI,
		SponsorshipReleaseProfileDigest:  capability.SponsorshipReleaseProfile.ProfileDigest}
	if capability.RelayFinalityProfile != nil {
		body.RelayFinalityProfileURI = capability.RelayFinalityProfile.ProfileURI
		body.RelayFinalityProfileDigest = capability.RelayFinalityProfile.ProfileDigest
	}
	if capability.SponsorshipTerminalProfile != nil {
		body.SponsorshipTerminalProfileURI = capability.SponsorshipTerminalProfile.ProfileURI
		body.SponsorshipTerminalProfileDigest = capability.SponsorshipTerminalProfile.ProfileDigest
	}
	return body
}

func (verifier *TOSCTLRelayFinalityVerifier) decodeSnapshot(capability agentrelay.RelayEvidenceCapability,
	raw []byte) (tosctlRelayClientFinalitySnapshot, error) {
	var frozen tosctlRelayClientFinalitySnapshot
	if verifier == nil || verifier.Sponsorship == nil || len(raw) == 0 || codec.Unmarshal(raw, &frozen) != nil ||
		frozen.SchemaVersion != 1 || !reflect.DeepEqual(frozen.Capability, capability) || frozen.SponsorshipEvidence == nil ||
		verifier.Sponsorship.ValidateRelaySponsorshipClientEvidenceSnapshot(
			capability.SponsorshipReleaseProfile, *frozen.SponsorshipEvidence) != nil {
		return frozen, errors.New("tosctl relay client snapshot is invalid")
	}
	reencoded, err := codec.Marshal(frozen)
	if err != nil || !bytes.Equal(reencoded, raw) {
		return frozen, errors.New("tosctl relay client snapshot is not exact canonical CBOR")
	}
	if capability.Mode == agentrelay.ModeSponsorAndRelay {
		if verifier.RelayComponent == nil || len(frozen.RelayComponent) == 0 ||
			verifier.RelayComponent.ValidateRelayFinalityEvidenceSnapshot(capability, frozen.RelayComponent) != nil {
			return frozen, errors.New("tosctl relay component snapshot is invalid")
		}
	} else if len(frozen.RelayComponent) != 0 {
		return frozen, errors.New("sponsor-only snapshot carries a relay component")
	}
	return frozen, nil
}

func (verifier *TOSCTLRelayFinalityVerifier) ValidateRelayFinalityEvidenceSnapshot(
	capability agentrelay.RelayEvidenceCapability, raw []byte) error {
	_, err := verifier.decodeSnapshot(capability, raw)
	return err
}

func (verifier *TOSCTLRelayFinalityVerifier) VerifyRelayFinality(ctx context.Context,
	execution agentrelay.RelayExecutionRequest, evidence agentrelay.SignedRelayFinalityEvidence) error {
	capability, err := relayEvidenceCapabilityForExecution(execution)
	if err != nil {
		return err
	}
	raw, err := verifier.FreezeRelayFinalityEvidenceSnapshot(ctx, capability)
	if err != nil {
		return err
	}
	return verifier.VerifyRelayFinalityFromSnapshot(ctx, execution, evidence, raw)
}

func (verifier *TOSCTLRelayFinalityVerifier) VerifyRelayFinalityFromSnapshot(ctx context.Context,
	execution agentrelay.RelayExecutionRequest, evidence agentrelay.SignedRelayFinalityEvidence,
	raw []byte) error {
	capability, err := relayEvidenceCapabilityForExecution(execution)
	if err != nil {
		return err
	}
	frozen, err := verifier.decodeSnapshot(capability, raw)
	if err != nil {
		return err
	}
	if capability.Mode == agentrelay.ModeSponsorAndRelay {
		if relayEvidenceHasTerminalRelayComponent(evidence.Body) {
			if err := verifier.RelayComponent.VerifyRelayFinalityFromSnapshot(ctx, execution, evidence,
				frozen.RelayComponent); err != nil {
				return err
			}
		} else if !relayEvidenceMaySkipTerminalRelayVerification(capability, evidence.Body) {
			return errors.New("combined relay evidence omitted its independently verified relay component")
		}
	}
	if len(evidence.Body.SponsorshipAbsenceObservations) == 0 &&
		len(evidence.Body.TransactionAbsenceObservations) == 0 {
		return nil
	}
	return verifier.Sponsorship.verifyRelayAbsenceProofFromSnapshot(ctx, execution, evidence,
		*frozen.SponsorshipEvidence)
}

func relayEvidenceMaySkipTerminalRelayVerification(capability agentrelay.RelayEvidenceCapability,
	body agentrelay.RelayFinalityEvidenceBody) bool {
	return capability.AssuranceLevel != agentrelay.AssuranceAutonomousDecentralized &&
		relayEvidenceIsPreSubmitSponsorshipOnly(body)
}

// A lower-assurance combined sponsorship-only result may be terminal before any client BOC
// was submitted (for example, a fresh balance/sequence recheck rejected the
// relay after the exact top-up terminalized). There is then no relay chain
// effect for the relay verifier to query. Every body that carries even one
// relay-positive or relay-negative claim must still cross the frozen base
// verifier; this exception is deliberately exact rather than outcome-only.
// Autonomous decentralized execution does not use this absence-free shortcut:
// without portable non-submission evidence it remains unresolved.
func relayEvidenceIsPreSubmitSponsorshipOnly(body agentrelay.RelayFinalityEvidenceBody) bool {
	return (body.Outcome == agentrelay.OutcomeFinalizedSponsorshipOnly ||
		body.Outcome == agentrelay.OutcomeCorroboratedSponsorshipOnly) &&
		body.SponsorshipTransferReference != "" && body.SponsorshipTransactionEvidence != nil &&
		!relayEvidenceHasTerminalRelayComponent(body) &&
		len(body.SponsorshipAbsenceObservations) == 0 && len(body.TransactionAbsenceObservations) == 0 &&
		body.AbsenceProofBundleDigest == "" && len(body.AbsenceProofBundle) == 0
}

func relayEvidenceHasTerminalRelayComponent(body agentrelay.RelayFinalityEvidenceBody) bool {
	return body.SubmittedTransactionHash != "" || body.SourceExecutionReference != "" ||
		len(body.DestinationCreditReferences) != 0 || body.RelayTerminalEvidenceClass != "" ||
		relayPortableProofAuthenticated(body.RelayValidatorAuthenticatedPortableProof) ||
		body.RelayFinalizedCheckpointID != "" ||
		body.RelayFinalizedCheckpointSequence != 0 || body.RelayFinalizedCheckpointUnix != 0 ||
		body.RelayConfirmationDepth != 0 ||
		len(body.RelayObservationDigests) != 0 || len(body.TransactionAbsenceObservations) != 0
}

// relayPortableProofAuthenticated is a one-release compatibility bridge. The
// reviewed relay V1 dependency used a bool; the presence-hardened protocol uses
// *bool so explicit false and absence are distinct on the wire. Accept both Go
// representations while the protocol and OpenFox feature branches are landed
// in dependency order.
func relayPortableProofAuthenticated(value any) bool {
	reflected := reflect.ValueOf(value)
	if !reflected.IsValid() {
		return false
	}
	if reflected.Kind() == reflect.Pointer {
		return !reflected.IsNil() && reflected.Elem().Kind() == reflect.Bool && reflected.Elem().Bool()
	}
	return reflected.Kind() == reflect.Bool && reflected.Bool()
}

func (sink *TOSCTLPaymentSink) verifyRelayAbsenceProofFromSnapshot(ctx context.Context,
	execution agentrelay.RelayExecutionRequest, evidence agentrelay.SignedRelayFinalityEvidence,
	frozen RelaySponsorshipEvidenceSnapshot) error {
	body := evidence.Body
	if sink == nil || ctx == nil || len(body.AbsenceProofBundle) == 0 ||
		sink.ValidateRelaySponsorshipClientEvidenceSnapshot(
			execution.QuoteRequest.Body.SelectedSponsorshipReleaseProfile(), frozen) != nil {
		return errors.New("client absence proof lost its frozen sponsorship snapshot")
	}
	var wrapper agentrelay.RelayAbsenceProofBundleV1
	if codec.Unmarshal(body.AbsenceProofBundle, &wrapper) != nil {
		return errors.New("client sponsorship verifier received an unsupported absence scope")
	}
	var payload tosctlRelayAbsencePayload
	if codec.Unmarshal(wrapper.ProofPayload, &payload) != nil {
		return errors.New("client absence proof payload cannot be decoded")
	}
	paymentPath, _, paymentCleanup, err := sink.writePrivateCanonicalCBOR(
		".relay-client-absence-payment-*.cbor", payload.AgreementPaymentRequest)
	if err != nil {
		return err
	}
	defer paymentCleanup()
	executionPath, _, executionCleanup, err := sink.writePrivateCanonicalCBOR(
		".relay-client-absence-execution-*.cbor", execution)
	if err != nil {
		return err
	}
	defer executionCleanup()
	sponsorshipPath, _, sponsorshipCleanup, err := sink.writePrivateCanonicalCBOR(
		".relay-client-absence-sponsorship-profile-*.cbor", *execution.ProviderQuote.Body.SponsorshipTerminalProfile)
	if err != nil {
		return err
	}
	defer sponsorshipCleanup()
	proofPath, proofCleanup, err := sink.writePrivateBytes(
		".relay-client-absence-proof-*.cbor", body.AbsenceProofBundle)
	if err != nil {
		return err
	}
	defer proofCleanup()
	command := "economic-payment-sponsorship-component-absence-proof-verify"
	expectedSchema := tosctlRelaySponsorshipComponentAbsenceVerificationSchema
	expectedState := "corroborated_sponsorship_absent_verified"
	expectedClass := agentrelay.SponsorshipTerminalClientCorroborated
	if wrapper.ProofScope == agentrelay.RelayAbsenceProofDual {
		command = "economic-payment-sponsorship-dual-absence-proof-verify"
		expectedSchema = tosctlRelaySponsorshipDualAbsenceVerificationSchema
		expectedState = "corroborated_absent_verified"
	} else if wrapper.ProofScope == agentrelay.RelayAbsenceProofTransactionOnly {
		command = "economic-payment-relay-transaction-component-absence-proof-verify"
		expectedSchema = tosctlRelayTransactionComponentAbsenceVerificationSchema
		expectedState = "corroborated_transaction_absent_verified"
		if execution.ProviderQuote.Body.RelayFinalityProfile == nil {
			return errors.New("client transaction-component proof has no signed relay profile")
		}
		expectedClass = execution.ProviderQuote.Body.RelayFinalityProfile.TerminalEvidenceClass
	}
	args := []string{"agent", "account", command, "--proof-bundle-cbor", proofPath,
		"--agreement-payment-request-cbor", paymentPath, "--relay-execution-request-cbor", executionPath,
		"--sponsorship-terminal-profile-cbor", sponsorshipPath,
		"--corroboration-snapshot", frozen.SnapshotPath,
		"--corroboration-snapshot-identity", frozen.SnapshotIdentity,
		"--sponsorship-release-profile-digest", frozen.ProfileDigest}
	if execution.ProviderQuote.Body.RelayFinalityProfile != nil {
		relayPath, _, cleanup, writeErr := sink.writePrivateCanonicalCBOR(
			".relay-client-absence-relay-profile-*.cbor", *execution.ProviderQuote.Body.RelayFinalityProfile)
		if writeErr != nil {
			return writeErr
		}
		defer cleanup()
		args = append(args, "--relay-finality-profile-cbor", relayPath)
	}
	resultRaw, err := sink.run(ctx, args)
	if err != nil {
		return err
	}
	var header tosctlRelayAbsenceHeader
	if json.Unmarshal(resultRaw, &header) != nil || header.Schema != expectedSchema {
		return errors.New("decode tosctl client absence verification envelope")
	}
	if header.State == "unknown" {
		return errors.New("client-owned absence quorum has not reached a terminal result")
	}
	var result tosctlRelayAbsenceVerification
	bundleDigest, bundleErr := agentrelay.RelayAbsenceProofBundleDigest(body.AbsenceProofBundle)
	executionDigest, executionErr := agentrelay.RelayExecutionRequestDigest(execution)
	networkDigest, networkErr := agentrelay.NetworkDomainDigest(execution.QuoteRequest.Body.Network)
	paymentDigest, paymentErr := commerce.AgreementPaymentRequestDigest(payload.AgreementPaymentRequest)
	now := sink.sponsorshipNow()
	if decodeStrictJSON(resultRaw, &result) != nil || bundleErr != nil || executionErr != nil ||
		networkErr != nil || paymentErr != nil || result.State != expectedState ||
		result.TerminalEvidenceClass != expectedClass ||
		result.ValidatorAuthenticatedPortableProof || result.NetworkDomain != execution.QuoteRequest.Body.Network ||
		result.NetworkDigest != networkDigest || result.AgreementPaymentRequestDigest != paymentDigest ||
		result.SponsorshipStableActionID != payload.SponsorshipStableActionID ||
		result.SponsorshipExactRequestDigest != payload.SponsorshipExactRequestDigest ||
		result.RelayStableActionID != execution.AuthorizedAction.StableActionID ||
		result.RelayExactRequestDigest != execution.AuthorizedAction.ExactRequestDigest ||
		result.RelayExecutionRequestDigest != executionDigest || result.ProviderSnapshotIdentity != payload.ProviderSnapshotIdentity ||
		result.ClientSnapshotIdentity != frozen.SnapshotIdentity ||
		result.ProviderEvidenceSetDigest != payload.EvidenceSetDigest ||
		!reflect.DeepEqual(result.ProviderSponsorshipAbsenceObservations, body.SponsorshipAbsenceObservations) ||
		!reflect.DeepEqual(result.ProviderTransactionAbsenceObservations, body.TransactionAbsenceObservations) ||
		len(body.SponsorshipAbsenceObservations) != 0 &&
			!relayAbsenceReferencesUseObservationProfile(result.SponsorshipAbsenceObservations,
				frozen.ProfileURI, frozen.ProfileDigest) ||
		len(body.TransactionAbsenceObservations) != 0 &&
			!relayAbsenceReferencesUseObservationProfile(result.TransactionAbsenceObservations,
				frozen.ProfileURI, frozen.ProfileDigest) ||
		result.ProofBundleDigestAlgorithm != tosctlRelayAbsenceDigestMethod ||
		result.ProofBundleDigestDomain != agentrelay.RelayAbsenceProofBundleDomainV1 ||
		result.ProofBundleDigest != bundleDigest || result.VerifiedAtUnix == 0 ||
		result.VerifiedAtUnix > uint64(now.Add(5*time.Minute).Unix()) || result.ChainSideEffect || result.CustodySideEffect {
		return errors.New("tosctl client absence verification changes exact signed evidence")
	}
	return nil
}

var _ RelaySponsorshipAbsenceResolver = (*TOSCTLPaymentSink)(nil)
var _ RelaySponsorshipAbsenceCapability = (*TOSCTLPaymentSink)(nil)
var _ RelaySponsorshipDualAbsenceAggregator = (*TOSCTLPaymentSink)(nil)
var _ RelayClientFinalitySnapshotVerifier = (*TOSCTLRelayFinalityVerifier)(nil)

func (value tosctlRelayAbsencePayload) String() string {
	return fmt.Sprintf("%s/%s", value.Schema, value.ProofScope)
}
