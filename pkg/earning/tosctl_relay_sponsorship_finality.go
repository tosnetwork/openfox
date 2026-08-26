package earning

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

const (
	tosctlRelaySponsorshipFinalitySchema          = "tosctl.agent-account.agreement-payment-sponsorship-corroborated-terminal.v1"
	tosctlRelaySponsorshipProofSchema             = "tosctl.agent-account.agreement-payment-sponsorship-proof-bundle.v1"
	tosctlRelaySponsorshipProofDomain             = "tos.agent-relay-sponsorship-proof-bundle.v1"
	tosctlRelaySponsorshipDigestMethod            = "TOS-PROTOCOL-CBOR/rfc8949-core-deterministic"
	tosctlRelaySponsorshipAssuranceScope          = "owner-selected-rpc-corroborated-terminal"
	verifiedSponsorshipTransactionTTL             = 5 * time.Minute
	tosctlRelaySponsorshipProofVerificationSchema = "tosctl.agent-account.agreement-payment-sponsorship-proof-verification.v1"
	tosctlRelaySponsorshipClientAssuranceScope    = "client-owned-rpc-corroborated-terminal-verification"
)

type tosctlRelaySponsorshipProofBundle struct {
	Schema                               string                                      `json:"schema"`
	AgreementPaymentRequest              commerce.AgreementPaymentRequest            `json:"agreement_payment_request"`
	AgreementPaymentRequestDigest        string                                      `json:"agreement_payment_request_digest"`
	SponsorshipStableActionID            string                                      `json:"sponsorship_stable_action_id"`
	SponsorshipExactRequestDigest        string                                      `json:"sponsorship_exact_request_digest"`
	ProviderSponsorSourceAccount         string                                      `json:"provider_sponsor_source_account"`
	ProviderSponsorSourceSequence        uint64                                      `json:"provider_sponsor_source_sequence"`
	ProviderSponsorValidUntilUnix        uint64                                      `json:"provider_sponsor_valid_until_unix"`
	DestinationSourceAccount             string                                      `json:"destination_source_account"`
	SignedTopUpTransactionDigest         string                                      `json:"signed_top_up_transaction_digest"`
	SignedTopUpTransactionCellHash       string                                      `json:"signed_top_up_transaction_cell_hash"`
	SignedTopUpTransactionBOC            []byte                                      `json:"signed_top_up_transaction_boc"`
	SponsorshipPaymentCommitmentCellHash string                                      `json:"sponsorship_payment_commitment_cell_hash"`
	NetworkDigest                        string                                      `json:"network_digest"`
	NetworkDomain                        agentrelay.NetworkDomain                    `json:"network_domain"`
	FinalityProfile                      agentrelay.FinalityProfile                  `json:"finality_profile"`
	FinalityProfileCBORDigest            string                                      `json:"finality_profile_cbor_digest"`
	SponsorshipReleaseProfileURI         string                                      `json:"sponsorship_release_profile_uri"`
	SponsorshipReleaseProfileDigest      string                                      `json:"sponsorship_release_profile_digest"`
	SponsorshipReleaseProfile            tosctlRelaySponsorshipEvidenceProfile       `json:"sponsorship_release_profile"`
	CorroborationSnapshotIdentity        string                                      `json:"corroboration_snapshot_identity"`
	ConfirmationDepth                    uint32                                      `json:"confirmation_depth"`
	TerminalEvidenceClass                agentrelay.SponsorshipTerminalEvidenceClass `json:"terminal_evidence_class"`
	ValidatorAuthenticatedPortableProof  bool                                        `json:"validator_authenticated_portable_proof"`
	Quorum                               tosctlQuorum                                `json:"quorum"`
	ObservationDigests                   []string                                    `json:"observation_digests"`
	Observations                         []tosctlPaymentObservation                  `json:"observations"`
	Failures                             []string                                    `json:"failures"`
	FinalizedCheckpointID                string                                      `json:"finalized_checkpoint_id"`
	FinalizedCheckpointSequence          uint64                                      `json:"finalized_checkpoint_sequence"`
	FinalizedCheckpointUnix              uint64                                      `json:"finalized_checkpoint_unix"`
}

type tosctlRelaySponsorshipFinality struct {
	Schema                               string                                         `json:"schema"`
	StableActionID                       string                                         `json:"stable_action_id"`
	AgreementPaymentRequestDigest        string                                         `json:"agreement_payment_request_digest"`
	SponsorshipExactRequestDigest        string                                         `json:"sponsorship_exact_request_digest"`
	NetworkDomain                        agentrelay.NetworkDomain                       `json:"network_domain"`
	NetworkDigest                        string                                         `json:"network_digest"`
	FinalityProfileURI                   string                                         `json:"finality_profile_uri"`
	FinalityProfileDigest                string                                         `json:"finality_profile_digest"`
	FinalityProfile                      agentrelay.FinalityProfile                     `json:"finality_profile"`
	FinalityProfileCBORDigest            string                                         `json:"finality_profile_cbor_digest"`
	SponsorshipReleaseProfileURI         string                                         `json:"sponsorship_release_profile_uri"`
	SponsorshipReleaseProfileDigest      string                                         `json:"sponsorship_release_profile_digest"`
	SponsorshipReleaseProfile            tosctlRelaySponsorshipEvidenceProfile          `json:"sponsorship_release_profile"`
	CorroborationSnapshot                string                                         `json:"corroboration_snapshot"`
	CorroborationSnapshotIdentity        string                                         `json:"corroboration_snapshot_identity"`
	ProviderSnapshotIdentity             string                                         `json:"provider_snapshot_identity"`
	OperatorProvenance                   []string                                       `json:"operator_provenance"`
	ProofBundleDigestAlgorithm           string                                         `json:"proof_bundle_digest_algorithm"`
	ProofBundleDigestDomain              string                                         `json:"proof_bundle_digest_domain"`
	ProofBundleDigest                    string                                         `json:"proof_bundle_digest"`
	ProofBundle                          json.RawMessage                                `json:"proof_bundle"`
	ProofBundleCBOR                      []byte                                         `json:"proof_bundle_cbor"`
	SponsorshipPaymentCommitmentCellHash string                                         `json:"sponsorship_payment_commitment_cell_hash"`
	Quorum                               tosctlQuorum                                   `json:"quorum"`
	Evidence                             tosctlPaymentObservation                       `json:"evidence"`
	Observations                         []tosctlPaymentObservation                     `json:"observations"`
	Failures                             []string                                       `json:"failures"`
	SponsorshipTransactionEvidence       agentrelay.RelaySponsorshipTransactionEvidence `json:"sponsorship_transaction_evidence"`
	ObservedAtUnix                       uint64                                         `json:"observed_at_unix"`
	State                                string                                         `json:"state"`
	CustodyState                         string                                         `json:"custody_state"`
	ChainSideEffect                      bool                                           `json:"chain_side_effect"`
	CustodySideEffect                    bool                                           `json:"custody_side_effect"`
	TerminalEvidenceClass                agentrelay.SponsorshipTerminalEvidenceClass    `json:"terminal_evidence_class"`
	AssuranceScope                       string                                         `json:"assurance_scope"`
	ValidatorAuthenticatedPortableProof  bool                                           `json:"validator_authenticated_portable_proof"`
}

type tosctlRelaySponsorshipTerminalHeader struct {
	Schema string `json:"schema"`
	State  string `json:"state"`
}

type tosctlRelaySponsorshipTerminalUnknown struct {
	Schema                        string `json:"schema"`
	State                         string `json:"state"`
	Category                      string `json:"category"`
	Reason                        string `json:"reason"`
	StableActionID                string `json:"stable_action_id"`
	AgreementPaymentRequestDigest string `json:"agreement_payment_request_digest"`
	SponsorshipExactRequestDigest string `json:"sponsorship_exact_request_digest"`
	CustodyState                  string `json:"custody_state"`
	ChainSideEffect               bool   `json:"chain_side_effect"`
	CustodySideEffect             bool   `json:"custody_side_effect"`
}

type tosctlRelaySponsorshipProofVerificationUnknown struct {
	Schema                        string `json:"schema"`
	State                         string `json:"state"`
	Category                      string `json:"category"`
	Reason                        string `json:"reason"`
	ProofBundleDigest             string `json:"proof_bundle_digest"`
	AgreementPaymentRequestDigest string `json:"agreement_payment_request_digest"`
	SponsorshipStableActionID     string `json:"sponsorship_stable_action_id"`
	SponsorshipExactRequestDigest string `json:"sponsorship_exact_request_digest"`
	ChainSideEffect               bool   `json:"chain_side_effect"`
	CustodySideEffect             bool   `json:"custody_side_effect"`
}

type tosctlRelaySponsorshipProofVerification struct {
	Schema                               string                                      `json:"schema"`
	ProofBundleDigestAlgorithm           string                                      `json:"proof_bundle_digest_algorithm"`
	ProofBundleDigestDomain              string                                      `json:"proof_bundle_digest_domain"`
	ProofBundleDigest                    string                                      `json:"proof_bundle_digest"`
	AgreementPaymentRequestDigest        string                                      `json:"agreement_payment_request_digest"`
	SponsorshipStableActionID            string                                      `json:"sponsorship_stable_action_id"`
	SponsorshipExactRequestDigest        string                                      `json:"sponsorship_exact_request_digest"`
	NetworkDigest                        string                                      `json:"network_digest"`
	FinalityProfileDigest                string                                      `json:"finality_profile_digest"`
	FinalityProfileCBORDigest            string                                      `json:"finality_profile_cbor_digest"`
	SponsorshipReleaseProfileURI         string                                      `json:"sponsorship_release_profile_uri"`
	SponsorshipReleaseProfileDigest      string                                      `json:"sponsorship_release_profile_digest"`
	ProviderSnapshotIdentity             string                                      `json:"provider_snapshot_identity"`
	ClientSnapshotIdentity               string                                      `json:"client_snapshot_identity"`
	ProviderSponsorSourceAccount         string                                      `json:"provider_sponsor_source_account"`
	ProviderSponsorControllerEpoch       uint64                                      `json:"provider_sponsor_controller_epoch"`
	ProviderSponsorSourceSequence        uint64                                      `json:"provider_sponsor_source_sequence"`
	ProviderSponsorValidUntilUnix        uint64                                      `json:"provider_sponsor_valid_until_unix"`
	SignedTopUpTransactionDigest         string                                      `json:"signed_top_up_transaction_digest"`
	SignedTopUpTransactionCellHash       string                                      `json:"signed_top_up_transaction_cell_hash"`
	SponsorshipPaymentCommitmentCellHash string                                      `json:"sponsorship_payment_commitment_cell_hash"`
	DestinationSourceAccount             string                                      `json:"destination_source_account"`
	AmountAtomic                         string                                      `json:"amount_atomic"`
	ConfirmationDepth                    uint32                                      `json:"confirmation_depth"`
	TerminalEvidenceClass                agentrelay.SponsorshipTerminalEvidenceClass `json:"terminal_evidence_class"`
	OperatorProvenance                   []string                                    `json:"operator_provenance"`
	Quorum                               tosctlQuorum                                `json:"quorum"`
	ObservationDigests                   []string                                    `json:"observation_digests"`
	Evidence                             tosctlPaymentObservation                    `json:"evidence"`
	Observations                         []tosctlPaymentObservation                  `json:"observations"`
	Failures                             []string                                    `json:"failures"`
	VerifiedAtUnix                       uint64                                      `json:"verified_at_unix"`
	State                                string                                      `json:"state"`
	AssuranceScope                       string                                      `json:"assurance_scope"`
	ValidatorAuthenticatedPortableProof  bool                                        `json:"validator_authenticated_portable_proof"`
	ChainSideEffect                      bool                                        `json:"chain_side_effect"`
	CustodySideEffect                    bool                                        `json:"custody_side_effect"`
}

func validateTOSCTLSponsorshipTerminalUnknown(outcome tosctlRelaySponsorshipTerminalUnknown,
	request commerce.AgreementPaymentRequest) error {
	paymentDigest, paymentErr := commerce.AgreementPaymentRequestDigest(request)
	canonical, _, materialErr := commerce.PaymentAuthorizationMaterial(request)
	exactDigest, exactErr := commerce.ExactRequestDigest(canonical)
	reasons := map[string]string{
		"not_found":               "exact submitted sponsorship transaction is not yet visible in bounded RPC history",
		"not_mature":              "quorum checkpoint has not crossed the selected chain-time reorg window",
		"temporarily_unavailable": "the frozen RPC quorum is temporarily insufficient for an exact terminal observation",
	}
	if paymentErr != nil || materialErr != nil || exactErr != nil ||
		outcome.Schema != tosctlRelaySponsorshipFinalitySchema || outcome.State != "unknown" ||
		reasons[outcome.Category] == "" || outcome.Reason != reasons[outcome.Category] ||
		outcome.StableActionID != request.StableActionID ||
		outcome.AgreementPaymentRequestDigest != paymentDigest ||
		outcome.SponsorshipExactRequestDigest != exactDigest || outcome.CustodyState != "broadcasting" ||
		outcome.ChainSideEffect || outcome.CustodySideEffect {
		return errors.New("tosctl sponsorship terminal unknown outcome changes the exact request")
	}
	return nil
}

func validateTOSCTLClientSponsorshipUnknown(outcome tosctlRelaySponsorshipProofVerificationUnknown,
	evidence agentrelay.RelaySponsorshipTransactionEvidence) error {
	reasons := map[string]string{
		"not_found":               "exact sponsorship transaction is not visible in the client-owned bounded RPC history",
		"not_mature":              "client quorum checkpoint has not crossed the selected chain-time reorg window",
		"temporarily_unavailable": "the client-owned RPC quorum is temporarily insufficient for exact verification",
	}
	if outcome.Schema != tosctlRelaySponsorshipProofVerificationSchema || outcome.State != "unknown" ||
		reasons[outcome.Category] == "" || outcome.Reason != reasons[outcome.Category] ||
		outcome.ProofBundleDigest != evidence.ProofBundleDigest ||
		outcome.AgreementPaymentRequestDigest != evidence.AgreementPaymentRequestDigest ||
		outcome.SponsorshipStableActionID != evidence.SponsorshipStableActionID ||
		outcome.SponsorshipExactRequestDigest != evidence.SponsorshipExactRequestDigest ||
		outcome.ChainSideEffect || outcome.CustodySideEffect {
		return errors.New("tosctl client sponsorship unknown outcome changes the exact evidence")
	}
	return nil
}

func (sink *TOSCTLPaymentSink) SupportsRelaySponsorshipTerminalFinalityProfile(
	profile agentrelay.FinalityProfile, frozen *RelaySponsorshipEvidenceSnapshot) bool {
	if sink == nil || profile.MinimumConfirmationDepth != 1 || profile.MinimumObservers == 0 ||
		profile.MinimumOperatorDomains == 0 || !validSHA256Digest(profile.ProfileDigest) ||
		profile.ProfileURI != RelayClientCorroboratedTerminalProfileURI {
		return false
	}
	var snapshot tosctlRelaySponsorshipSnapshot
	var err error
	if frozen == nil {
		configured := false
		for _, candidate := range sink.RelayTerminalFinalityProfiles {
			configured = configured || candidate == profile
		}
		if !configured {
			return false
		}
		snapshot, err = sink.ensureCurrentRelaySponsorshipSnapshot()
	} else {
		release := agentrelay.SponsorshipReleaseProfile{
			EvidenceClass: agentrelay.SponsorshipReleaseEvidenceClass(frozen.EvidenceClass),
			ProfileURI:    frozen.ProfileURI, ProfileDigest: frozen.ProfileDigest}
		validateErr := sink.ValidateRelaySponsorshipEvidenceSnapshot(release, *frozen)
		if frozen.CustodyWallet == "" && frozen.ProviderSourceAccount == "" {
			validateErr = sink.ValidateRelaySponsorshipClientEvidenceSnapshot(release, *frozen)
		}
		if validateErr != nil {
			return false
		}
		snapshot = relayTOSCTLSponsorshipSnapshot(release, *frozen)
	}
	if err != nil {
		return false
	}
	raw, err := readBoundedRegularFile(snapshot.manifestPath, 1<<20, true)
	var manifest tosctlRelaySponsorshipSnapshotManifest
	if err != nil || decodeStrictJSON(raw, &manifest) != nil {
		return false
	}
	members := len(manifest.EvidenceProfile.Members)
	return int(profile.MinimumObservers) <= members && int(profile.MinimumOperatorDomains) <= members
}

// ResolveRelaySponsorshipTerminalEvidence invokes the sponsorship-specific,
// chain-side-effect-free tosctl resolver. The command may atomically journal
// the exact quorum winner in local custody before stdout, but it never signs,
// prepares, broadcasts, or replaces a top-up and never uses the ordinary
// direct-payment resolver.
func (sink *TOSCTLPaymentSink) ResolveRelaySponsorshipTerminalEvidence(ctx context.Context,
	execution agentrelay.RelayExecutionRequest, request commerce.AgreementPaymentRequest,
	frozen *RelaySponsorshipEvidenceSnapshot) (agentrelay.SponsorshipResolution, error) {
	unknown := agentrelay.SponsorshipResolution{Status: agentrelay.SponsorshipResolutionUnknown}
	if sink == nil || ctx == nil || frozen == nil || request.SchemaVersion != 3 {
		return unknown, errors.New("terminal sponsorship query lacks its exact local context")
	}
	profile := execution.QuoteRequest.Body.SelectedSponsorshipReleaseProfile()
	if profile.EvidenceClass != agentrelay.SponsorshipReleaseObservedUnproven ||
		sink.ValidateRelaySponsorshipEvidenceSnapshot(profile, *frozen) != nil {
		return unknown, errors.New("terminal sponsorship query changes the signed release profile")
	}
	configPath, err := sink.relaySponsorshipSnapshotPrimaryConfig(*frozen)
	if err != nil {
		return unknown, err
	}
	if err := sink.verifyRelayNetworkDomainAt(ctx, execution.QuoteRequest.Body.Network, configPath); err != nil {
		return unknown, err
	}
	paymentPath, paymentCBORDigest, paymentCleanup, err := sink.writePrivateCanonicalCBOR(
		".relay-sponsorship-payment-*.cbor", request)
	if err != nil {
		return unknown, err
	}
	defer paymentCleanup()
	finality, err := relaySponsorshipTerminalProfile(execution)
	if err != nil {
		return unknown, err
	}
	finalityPath, finalityCBORDigest, finalityCleanup, err := sink.writePrivateCanonicalCBOR(
		".relay-sponsorship-finality-*.cbor", finality)
	if err != nil {
		return unknown, err
	}
	defer finalityCleanup()
	_ = paymentCBORDigest
	raw, err := sink.run(ctx, []string{"agent", "account", "economic-payment-sponsorship-corroborated-terminal",
		"--wallet", frozen.CustodyWallet, "--stable-action-id", request.StableActionID,
		"--agreement-payment-request-cbor", paymentPath, "--finality-profile-cbor", finalityPath,
		"--corroboration-snapshot", frozen.SnapshotPath,
		"--corroboration-snapshot-identity", frozen.SnapshotIdentity,
		"--sponsorship-release-profile-digest", frozen.ProfileDigest, "-c", configPath})
	if err != nil {
		return unknown, err
	}
	var header tosctlRelaySponsorshipTerminalHeader
	if err := json.Unmarshal(raw, &header); err != nil || header.Schema != tosctlRelaySponsorshipFinalitySchema {
		return agentrelay.SponsorshipResolution{}, errors.New("decode tosctl sponsorship terminal envelope")
	}
	if header.State == "unknown" {
		var outcome tosctlRelaySponsorshipTerminalUnknown
		if err := decodeStrictJSON(raw, &outcome); err != nil ||
			validateTOSCTLSponsorshipTerminalUnknown(outcome, request) != nil {
			return agentrelay.SponsorshipResolution{}, errors.New("invalid tosctl sponsorship terminal unknown outcome")
		}
		return unknown, nil
	}
	if header.State != "corroborated_terminal" {
		return agentrelay.SponsorshipResolution{}, errors.New("unsupported tosctl sponsorship terminal outcome")
	}
	evidence, err := sink.decodeRelaySponsorshipFinality(execution, request, *frozen,
		finalityCBORDigest, raw)
	if err != nil {
		return agentrelay.SponsorshipResolution{}, err
	}
	return agentrelay.SponsorshipResolution{Status: agentrelay.SponsorshipResolutionCorroboratedTerminal,
		TransferReference:   evidence.SubmittedTransactionHash,
		EvidenceRefs:        append([]string(nil), evidence.ObservationDigests...),
		TransactionEvidence: &evidence}, nil
}

func (sink *TOSCTLPaymentSink) decodeRelaySponsorshipFinality(execution agentrelay.RelayExecutionRequest,
	request commerce.AgreementPaymentRequest, frozen RelaySponsorshipEvidenceSnapshot,
	finalityCBORDigest string, raw []byte) (agentrelay.RelaySponsorshipTransactionEvidence, error) {
	var result tosctlRelaySponsorshipFinality
	if err := decodeStrictJSON(raw, &result); err != nil {
		return agentrelay.RelaySponsorshipTransactionEvidence{}, errors.New("decode strict tosctl sponsorship finality v1")
	}
	var proof tosctlRelaySponsorshipProofBundle
	if err := decodeStrictJSON(result.ProofBundle, &proof); err != nil {
		return agentrelay.RelaySponsorshipTransactionEvidence{}, errors.New("decode strict tosctl sponsorship proof bundle")
	}
	var cborProof tosctlRelaySponsorshipProofBundle
	if err := codec.Unmarshal(result.ProofBundleCBOR, &cborProof); err != nil || !reflect.DeepEqual(cborProof, proof) {
		return agentrelay.RelaySponsorshipTransactionEvidence{}, errors.New("tosctl sponsorship JSON and canonical-CBOR proof bundles differ")
	}
	paymentDigest, paymentErr := commerce.AgreementPaymentRequestDigest(request)
	canonical, _, materialErr := commerce.PaymentAuthorizationMaterial(request)
	exactDigest, exactErr := commerce.ExactRequestDigest(canonical)
	networkDigest, networkErr := agentrelay.NetworkDomainDigest(execution.QuoteRequest.Body.Network)
	finality, profileErr := relaySponsorshipTerminalProfile(execution)
	policy := relaySponsorshipReleasePolicyFromRequest(execution.QuoteRequest.Body)
	now := sink.sponsorshipNow()
	if paymentErr != nil || materialErr != nil || exactErr != nil || networkErr != nil || profileErr != nil ||
		result.Schema != tosctlRelaySponsorshipFinalitySchema || result.StableActionID != request.StableActionID ||
		result.AgreementPaymentRequestDigest != paymentDigest || result.SponsorshipExactRequestDigest != exactDigest ||
		result.NetworkDomain != execution.QuoteRequest.Body.Network || result.NetworkDigest != networkDigest ||
		result.FinalityProfileURI != finality.ProfileURI || result.FinalityProfileDigest != finality.ProfileDigest ||
		result.FinalityProfile != finality || result.FinalityProfileCBORDigest != finalityCBORDigest ||
		result.SponsorshipReleaseProfileURI != policy.ProfileURI ||
		result.SponsorshipReleaseProfileDigest != policy.ProfileDigest ||
		result.CorroborationSnapshot != frozen.SnapshotPath ||
		result.CorroborationSnapshotIdentity != frozen.SnapshotIdentity ||
		result.ProviderSnapshotIdentity != frozen.SnapshotIdentity ||
		result.ProofBundleDigestAlgorithm != tosctlRelaySponsorshipDigestMethod ||
		result.ProofBundleDigestDomain != tosctlRelaySponsorshipProofDomain ||
		result.State != "corroborated_terminal" || result.CustodyState != "resolved" || result.ChainSideEffect ||
		!result.CustodySideEffect || result.TerminalEvidenceClass != agentrelay.SponsorshipTerminalClientCorroborated ||
		result.AssuranceScope != tosctlRelaySponsorshipAssuranceScope || result.ValidatorAuthenticatedPortableProof ||
		result.ObservedAtUnix == 0 || result.ObservedAtUnix > uint64(now.Add(5*time.Minute).Unix()) {
		return agentrelay.RelaySponsorshipTransactionEvidence{}, errors.New("tosctl sponsorship terminal evidence conflicts with the exact request or profiles")
	}
	corroboration := tosctlRelaySponsorshipObserved{NetworkGlobalID: result.NetworkDomain.GlobalID,
		NetworkDomain: result.NetworkDomain, EvidenceProfileURI: result.SponsorshipReleaseProfileURI,
		EvidenceProfileDigest: result.SponsorshipReleaseProfileDigest,
		EvidenceProfile:       result.SponsorshipReleaseProfile, ObservationDigests: result.SponsorshipTransactionEvidence.ObservationDigests,
		Quorum: result.Quorum, Evidence: result.Evidence, Observations: result.Observations, Failures: result.Failures}
	if err := verifyTOSCTLSponsorshipCorroboration(corroboration, policy); err != nil {
		return agentrelay.RelaySponsorshipTransactionEvidence{}, err
	}
	operators := make([]string, 0, len(result.Observations))
	winner := result.Evidence.quorumKey()
	for _, observation := range result.Observations {
		if observation.quorumKey() == winner {
			operators = append(operators, observation.OperatorProvenance)
		}
	}
	sort.Strings(operators)
	if !equalStrings(operators, result.OperatorProvenance) || len(operators) < int(finality.MinimumOperatorDomains) ||
		len(result.SponsorshipTransactionEvidence.ObservationDigests) < int(finality.MinimumObservers) ||
		result.SponsorshipTransactionEvidence.ConfirmationDepth < finality.MinimumConfirmationDepth ||
		result.SponsorshipTransactionEvidence.ConfirmationDepth != 1 ||
		!relaySponsorshipWinnerMature(result.Evidence, finality) {
		return agentrelay.RelaySponsorshipTransactionEvidence{}, errors.New("tosctl sponsorship terminal evidence does not satisfy the signed profile")
	}
	expectedProof := tosctlRelaySponsorshipProofBundle{Schema: tosctlRelaySponsorshipProofSchema,
		AgreementPaymentRequest: request, AgreementPaymentRequestDigest: paymentDigest,
		SponsorshipStableActionID: request.StableActionID, SponsorshipExactRequestDigest: exactDigest,
		ProviderSponsorSourceAccount:         result.SponsorshipTransactionEvidence.ProviderSponsorSourceAccount,
		ProviderSponsorSourceSequence:        result.SponsorshipTransactionEvidence.ProviderSponsorSourceSequence,
		ProviderSponsorValidUntilUnix:        result.SponsorshipTransactionEvidence.ProviderSponsorValidUntilUnix,
		DestinationSourceAccount:             result.SponsorshipTransactionEvidence.DestinationSourceAccount,
		SignedTopUpTransactionDigest:         result.SponsorshipTransactionEvidence.SignedTopUpTransactionDigest,
		SignedTopUpTransactionCellHash:       result.SponsorshipTransactionEvidence.SignedTopUpTransactionCellHash,
		SponsorshipPaymentCommitmentCellHash: result.SponsorshipTransactionEvidence.SponsorshipPaymentCommitmentCellHash,
		SignedTopUpTransactionBOC:            append([]byte(nil), proof.SignedTopUpTransactionBOC...),
		NetworkDigest:                        networkDigest, NetworkDomain: result.NetworkDomain, FinalityProfile: finality,
		FinalityProfileCBORDigest:    finalityCBORDigest,
		SponsorshipReleaseProfileURI: policy.ProfileURI, SponsorshipReleaseProfileDigest: policy.ProfileDigest,
		SponsorshipReleaseProfile:     result.SponsorshipReleaseProfile,
		CorroborationSnapshotIdentity: frozen.SnapshotIdentity, ConfirmationDepth: 1,
		TerminalEvidenceClass:               agentrelay.SponsorshipTerminalClientCorroborated,
		ValidatorAuthenticatedPortableProof: false,
		Quorum:                              result.Quorum, ObservationDigests: append([]string(nil), result.SponsorshipTransactionEvidence.ObservationDigests...),
		Observations:                append([]tosctlPaymentObservation(nil), result.Observations...),
		Failures:                    append([]string(nil), result.Failures...),
		FinalizedCheckpointID:       result.SponsorshipTransactionEvidence.FinalizedCheckpointID,
		FinalizedCheckpointSequence: result.SponsorshipTransactionEvidence.FinalizedCheckpointSequence,
		FinalizedCheckpointUnix:     result.SponsorshipTransactionEvidence.FinalizedCheckpointUnix}
	if len(proof.SignedTopUpTransactionBOC) == 0 ||
		sha256Digest(proof.SignedTopUpTransactionBOC) != proof.SignedTopUpTransactionDigest ||
		!reflect.DeepEqual(proof, expectedProof) {
		return agentrelay.RelaySponsorshipTransactionEvidence{}, errors.New("tosctl sponsorship proof bundle changes its wrapper projection")
	}
	proofDigest, err := agentrelay.RelaySponsorshipProofBundleDigest(result.ProofBundleCBOR)
	if err != nil || proofDigest != result.ProofBundleDigest ||
		proofDigest != result.SponsorshipTransactionEvidence.ProofBundleDigest ||
		!reflect.DeepEqual(result.ProofBundleCBOR, result.SponsorshipTransactionEvidence.ProofBundle) {
		return agentrelay.RelaySponsorshipTransactionEvidence{}, errors.New("tosctl sponsorship proof bundle digest is not reproducible")
	}
	evidence := result.SponsorshipTransactionEvidence
	if evidence.SchemaVersion != 1 ||
		evidence.TerminalEvidenceClass != agentrelay.SponsorshipTerminalClientCorroborated ||
		evidence.ValidatorAuthenticatedPortableProof || evidence.NetworkDigest != networkDigest ||
		!reflect.DeepEqual(evidence.AgreementPaymentRequest, request) ||
		evidence.AgreementPaymentRequestDigest != paymentDigest || evidence.SponsorshipStableActionID != request.StableActionID ||
		evidence.SponsorshipExactRequestDigest != exactDigest ||
		evidence.ProviderSponsorSourceAccount != frozen.ProviderSourceAccount ||
		evidence.ProviderSponsorValidUntilUnix != request.ExpiresAtUnix ||
		!validSHA256Digest(evidence.SignedTopUpTransactionDigest) || !validTVMCellSHA256(evidence.SignedTopUpTransactionCellHash) ||
		!validTVMCellSHA256(evidence.SponsorshipPaymentCommitmentCellHash) ||
		evidence.SponsorshipPaymentCommitmentCellHash != result.SponsorshipPaymentCommitmentCellHash ||
		evidence.DestinationSourceAccount != string(request.Destination) ||
		execution.ProviderQuote.Body.ReservedSponsorship == nil ||
		evidence.Amount != *execution.ProviderQuote.Body.ReservedSponsorship ||
		evidence.SubmittedTransactionHash != result.Evidence.TransactionHash ||
		evidence.SourceExecutionReference != evidence.SubmittedTransactionHash ||
		len(evidence.DestinationCreditReferences) != 1 ||
		evidence.DestinationCreditReferences[0] != result.Evidence.DestinationCreditReference ||
		evidence.FinalizedCheckpointID != "masterchain:"+checkpointSuffix(result.Evidence) ||
		evidence.FinalizedCheckpointSequence != uint64(result.Evidence.ObservedMasterchainSeqno) ||
		evidence.FinalizedCheckpointUnix != result.Evidence.ObservedMasterchainGenUTime ||
		evidence.SponsorshipTerminalProfileDigest != finality.ProfileDigest || evidence.PortableProofLocator != "" ||
		evidence.ObservedAtUnix != result.ObservedAtUnix {
		return agentrelay.RelaySponsorshipTransactionEvidence{}, errors.New("tosctl sponsorship transaction evidence is not the exact finalized winner")
	}
	if _, err := agentrelay.RelaySponsorshipTransactionEvidenceDigest(evidence); err != nil {
		return agentrelay.RelaySponsorshipTransactionEvidence{}, err
	}
	digest, _ := agentrelay.RelaySponsorshipTransactionEvidenceDigest(evidence)
	sink.rememberVerifiedSponsorshipTransaction(digest, now.Add(verifiedSponsorshipTransactionTTL))
	return evidence, nil
}

func checkpointSuffix(observation tosctlPaymentObservation) string {
	return strings.Join([]string{
		strconv.FormatInt(int64(observation.ObservedMasterchainWorkchain), 10),
		strconv.FormatInt(observation.ObservedMasterchainShard, 10),
		strconv.FormatUint(uint64(observation.ObservedMasterchainSeqno), 10),
		observation.ObservedMasterchainRootHash,
		observation.ObservedMasterchainFileHash,
	}, ":")
}

func (sink *TOSCTLPaymentSink) SupportsRelaySponsorshipTransactionEvidence(level agentrelay.AssuranceLevel,
	release RelaySponsorshipReleasePolicy, profile agentrelay.FinalityProfile) bool {
	if sink == nil || level == agentrelay.AssuranceAutonomousDecentralized ||
		release != sink.RelaySponsorshipReleasePolicy ||
		release.EvidenceClass != agentrelay.SponsorshipReleaseObservedUnproven ||
		profile.ProfileURI != RelayClientCorroboratedTerminalProfileURI ||
		!sink.SupportsRelaySponsorshipTerminalFinalityProfile(profile, nil) {
		return false
	}
	_, err := sink.ensureCurrentRelaySponsorshipSnapshot()
	return err == nil
}

// VerifyRelaySponsorshipTransactionEvidenceFromSnapshot is the Provider-local
// terminal gate. ResolveRelaySponsorshipTerminalEvidence has already parsed
// and independently reconstructed the exact frozen-quorum output and cached
// only its content-addressed typed evidence digest. Revalidating the immutable
// snapshot here prevents current owner config rotation from changing recovery.
// The requester uses the separate, stronger RPC re-query method below.
func (sink *TOSCTLPaymentSink) VerifyRelaySponsorshipTransactionEvidenceFromSnapshot(ctx context.Context,
	evidence agentrelay.RelaySponsorshipTransactionEvidence, expected agentrelay.RelaySponsorshipEvidenceContext,
	profile agentrelay.FinalityProfile, frozen RelaySponsorshipEvidenceSnapshot) error {
	release := agentrelay.SponsorshipReleaseProfile{
		EvidenceClass: agentrelay.SponsorshipReleaseEvidenceClass(frozen.EvidenceClass),
		ProfileURI:    frozen.ProfileURI, ProfileDigest: frozen.ProfileDigest}
	if sink == nil || ctx == nil || sink.ValidateRelaySponsorshipEvidenceSnapshot(release, frozen) != nil ||
		!sink.SupportsRelaySponsorshipTerminalFinalityProfile(profile, &frozen) {
		return errors.New("provider sponsorship proof changes its frozen evidence snapshot")
	}
	policy := RelaySponsorshipReleasePolicy{EvidenceClass: release.EvidenceClass,
		ProfileURI: release.ProfileURI, ProfileDigest: release.ProfileDigest}
	return sink.verifySponsorshipTransactionEvidence(evidence, expected, profile, policy, false)
}

func (sink *TOSCTLPaymentSink) FreezeRelaySponsorshipClientEvidenceSnapshot(_ context.Context,
	request agentrelay.RelayQuoteRequestBody) (RelaySponsorshipEvidenceSnapshot, error) {
	selected := request.SelectedSponsorshipReleaseProfile()
	policy := RelaySponsorshipReleasePolicy{EvidenceClass: selected.EvidenceClass,
		ProfileURI: selected.ProfileURI, ProfileDigest: selected.ProfileDigest}
	if sink == nil || request.AssuranceLevel == agentrelay.AssuranceAutonomousDecentralized ||
		policy != sink.RelaySponsorshipReleasePolicy || sink.RelayNetworkDomain == nil ||
		request.Network != *sink.RelayNetworkDomain ||
		request.SponsorshipTerminalProfileURI != RelayClientCorroboratedTerminalProfileURI ||
		request.SponsorshipTerminalEvidenceClass != agentrelay.SponsorshipTerminalClientCorroborated {
		return RelaySponsorshipEvidenceSnapshot{}, errors.New("client sponsorship verifier is not bound to the signed quote predicate")
	}
	snapshot, err := sink.ensureCurrentRelaySponsorshipSnapshot()
	if err != nil {
		return RelaySponsorshipEvidenceSnapshot{}, err
	}
	return snapshot.frozenClient(), nil
}

func (sink *TOSCTLPaymentSink) ValidateRelaySponsorshipClientEvidenceSnapshot(
	profile agentrelay.SponsorshipReleaseProfile, frozen RelaySponsorshipEvidenceSnapshot) error {
	if sink == nil || frozen.SchemaVersion != 2 || frozen.EvidenceClass != string(profile.EvidenceClass) ||
		frozen.ProfileURI != profile.ProfileURI || frozen.ProfileDigest != profile.ProfileDigest ||
		frozen.CustodyWallet != "" || frozen.ProviderSourceAccount != "" || frozen.FeeReserveNanoTOS != 0 {
		return errors.New("frozen client corroboration snapshot changes the signed release profile")
	}
	return sink.validateRelaySponsorshipSnapshot(relayTOSCTLSponsorshipSnapshot(profile, frozen))
}

func (sink *TOSCTLPaymentSink) VerifySponsorshipTransactionEvidenceFromSnapshot(ctx context.Context,
	evidence agentrelay.RelaySponsorshipTransactionEvidence, expected agentrelay.RelaySponsorshipEvidenceContext,
	profile agentrelay.FinalityProfile, frozen RelaySponsorshipEvidenceSnapshot) error {
	release := agentrelay.SponsorshipReleaseProfile{
		EvidenceClass: agentrelay.SponsorshipReleaseEvidenceClass(frozen.EvidenceClass),
		ProfileURI:    frozen.ProfileURI, ProfileDigest: frozen.ProfileDigest}
	if sink == nil || ctx == nil || evidence.TerminalEvidenceClass != agentrelay.SponsorshipTerminalClientCorroborated ||
		evidence.ValidatorAuthenticatedPortableProof || profile.ProfileURI != RelayClientCorroboratedTerminalProfileURI ||
		len(evidence.DestinationCreditReferences) != 1 ||
		!sink.SupportsRelaySponsorshipTerminalFinalityProfile(profile, &frozen) ||
		sink.ValidateRelaySponsorshipClientEvidenceSnapshot(release, frozen) != nil ||
		agentrelay.VerifySponsorshipPaymentRequestForEvidence(evidence.AgreementPaymentRequest, evidence, expected) != nil {
		return errors.New("client sponsorship proof verifier context is incomplete")
	}
	proofDigest, err := agentrelay.RelaySponsorshipProofBundleDigest(evidence.ProofBundle)
	if err != nil || proofDigest != evidence.ProofBundleDigest {
		return errors.New("client sponsorship proof bundle digest is invalid")
	}
	paymentPath, _, paymentCleanup, err := sink.writePrivateCanonicalCBOR(
		".relay-client-sponsorship-payment-*.cbor", evidence.AgreementPaymentRequest)
	if err != nil {
		return err
	}
	defer paymentCleanup()
	finalityPath, finalityCBORDigest, finalityCleanup, err := sink.writePrivateCanonicalCBOR(
		".relay-client-sponsorship-finality-*.cbor", profile)
	if err != nil {
		return err
	}
	defer finalityCleanup()
	proofPath, proofCleanup, err := sink.writePrivateBytes(
		".relay-client-sponsorship-proof-*.cbor", evidence.ProofBundle)
	if err != nil {
		return err
	}
	defer proofCleanup()
	raw, err := sink.run(ctx, []string{"agent", "account", "economic-payment-sponsorship-proof-verify",
		"--proof-bundle-cbor", proofPath, "--agreement-payment-request-cbor", paymentPath,
		"--finality-profile-cbor", finalityPath, "--corroboration-snapshot", frozen.SnapshotPath,
		"--corroboration-snapshot-identity", frozen.SnapshotIdentity,
		"--sponsorship-release-profile-digest", frozen.ProfileDigest})
	if err != nil {
		return err
	}
	var header tosctlRelaySponsorshipTerminalHeader
	if json.Unmarshal(raw, &header) != nil || header.Schema != tosctlRelaySponsorshipProofVerificationSchema {
		return errors.New("decode tosctl client sponsorship proof envelope")
	}
	if header.State == "unknown" {
		var outcome tosctlRelaySponsorshipProofVerificationUnknown
		if decodeStrictJSON(raw, &outcome) != nil ||
			validateTOSCTLClientSponsorshipUnknown(outcome, evidence) != nil {
			return errors.New("invalid tosctl client sponsorship unknown outcome")
		}
		return errors.New("client-owned sponsorship quorum has not yet reproduced the terminal chain effect")
	}
	if header.State != "corroborated_terminal_verified" {
		return errors.New("unsupported tosctl client sponsorship proof outcome")
	}
	var result tosctlRelaySponsorshipProofVerification
	if err := decodeStrictJSON(raw, &result); err != nil {
		return errors.New("decode strict tosctl client sponsorship proof verification")
	}
	return sink.validateClientSponsorshipProofVerification(evidence, expected, profile, frozen,
		finalityCBORDigest, result)
}

func (sink *TOSCTLPaymentSink) validateClientSponsorshipProofVerification(
	evidence agentrelay.RelaySponsorshipTransactionEvidence, expected agentrelay.RelaySponsorshipEvidenceContext,
	profile agentrelay.FinalityProfile, frozen RelaySponsorshipEvidenceSnapshot, finalityCBORDigest string,
	result tosctlRelaySponsorshipProofVerification) error {
	var proof tosctlRelaySponsorshipProofBundle
	if err := codec.Unmarshal(evidence.ProofBundle, &proof); err != nil {
		return errors.New("client sponsorship proof attachment is not canonical CBOR")
	}
	raw, err := readBoundedRegularFile(frozen.SnapshotPath, 1<<20, true)
	var manifest tosctlRelaySponsorshipSnapshotManifest
	if err != nil || decodeStrictJSON(raw, &manifest) != nil {
		return errors.New("client sponsorship snapshot manifest is unreadable")
	}
	paymentDigest, paymentErr := commerce.AgreementPaymentRequestDigest(evidence.AgreementPaymentRequest)
	canonical, _, materialErr := commerce.PaymentAuthorizationMaterial(evidence.AgreementPaymentRequest)
	exactDigest, exactErr := commerce.ExactRequestDigest(canonical)
	networkDigest, networkErr := agentrelay.NetworkDomainDigest(manifest.NetworkDomain)
	policy := RelaySponsorshipReleasePolicy{
		EvidenceClass: agentrelay.SponsorshipReleaseEvidenceClass(frozen.EvidenceClass),
		ProfileURI:    frozen.ProfileURI, ProfileDigest: frozen.ProfileDigest}
	now := sink.sponsorshipNow()
	if paymentErr != nil || materialErr != nil || exactErr != nil || networkErr != nil ||
		result.Schema != tosctlRelaySponsorshipProofVerificationSchema ||
		result.ProofBundleDigestAlgorithm != tosctlRelaySponsorshipDigestMethod ||
		result.ProofBundleDigestDomain != tosctlRelaySponsorshipProofDomain ||
		result.ProofBundleDigest != evidence.ProofBundleDigest || result.AgreementPaymentRequestDigest != paymentDigest ||
		result.SponsorshipStableActionID != evidence.SponsorshipStableActionID ||
		result.SponsorshipExactRequestDigest != exactDigest || result.NetworkDigest != networkDigest ||
		result.FinalityProfileDigest != profile.ProfileDigest ||
		result.FinalityProfileCBORDigest != finalityCBORDigest ||
		result.SponsorshipReleaseProfileURI != policy.ProfileURI ||
		result.SponsorshipReleaseProfileDigest != policy.ProfileDigest ||
		result.ProviderSnapshotIdentity != proof.CorroborationSnapshotIdentity ||
		result.ClientSnapshotIdentity != frozen.SnapshotIdentity ||
		result.ProviderSponsorSourceAccount != evidence.ProviderSponsorSourceAccount ||
		result.ProviderSponsorSourceSequence != evidence.ProviderSponsorSourceSequence ||
		result.ProviderSponsorValidUntilUnix != evidence.ProviderSponsorValidUntilUnix ||
		result.SignedTopUpTransactionDigest != evidence.SignedTopUpTransactionDigest ||
		result.SignedTopUpTransactionCellHash != evidence.SignedTopUpTransactionCellHash ||
		result.SponsorshipPaymentCommitmentCellHash != evidence.SponsorshipPaymentCommitmentCellHash ||
		result.DestinationSourceAccount != evidence.DestinationSourceAccount ||
		result.AmountAtomic != evidence.Amount.AmountAtomic || result.ConfirmationDepth != evidence.ConfirmationDepth ||
		result.TerminalEvidenceClass != agentrelay.SponsorshipTerminalClientCorroborated ||
		result.State != "corroborated_terminal_verified" ||
		result.AssuranceScope != tosctlRelaySponsorshipClientAssuranceScope ||
		result.ValidatorAuthenticatedPortableProof || result.ChainSideEffect || result.CustodySideEffect ||
		result.VerifiedAtUnix == 0 || result.VerifiedAtUnix > uint64(now.Add(5*time.Minute).Unix()) ||
		agentrelay.VerifySponsorshipPaymentRequestForEvidence(evidence.AgreementPaymentRequest, evidence, expected) != nil {
		return errors.New("tosctl client sponsorship verification changes the signed terminal predicate")
	}
	providerCorroboration := tosctlRelaySponsorshipObserved{NetworkGlobalID: proof.NetworkDomain.GlobalID,
		NetworkDomain: proof.NetworkDomain, EvidenceProfileURI: proof.SponsorshipReleaseProfileURI,
		EvidenceProfileDigest: proof.SponsorshipReleaseProfileDigest,
		EvidenceProfile:       proof.SponsorshipReleaseProfile, ObservationDigests: proof.ObservationDigests,
		Quorum: proof.Quorum, Observations: proof.Observations, Failures: proof.Failures}
	providerWinnerFound := false
	for _, observation := range proof.Observations {
		if observation.TransactionHash == evidence.SubmittedTransactionHash &&
			observation.DestinationCreditReference == evidence.DestinationCreditReferences[0] &&
			"masterchain:"+checkpointSuffix(observation) == evidence.FinalizedCheckpointID {
			providerCorroboration.Evidence, providerWinnerFound = observation, true
			break
		}
	}
	if !providerWinnerFound || verifyTOSCTLSponsorshipCorroboration(providerCorroboration, policy) != nil ||
		proof.Schema != tosctlRelaySponsorshipProofSchema ||
		proof.TerminalEvidenceClass != agentrelay.SponsorshipTerminalClientCorroborated ||
		proof.ValidatorAuthenticatedPortableProof || proof.NetworkDomain != manifest.NetworkDomain ||
		proof.NetworkDigest != networkDigest || proof.FinalityProfile != profile ||
		proof.FinalityProfileCBORDigest != finalityCBORDigest ||
		proof.AgreementPaymentRequestDigest != paymentDigest ||
		proof.SponsorshipStableActionID != evidence.SponsorshipStableActionID ||
		proof.SponsorshipExactRequestDigest != evidence.SponsorshipExactRequestDigest ||
		proof.SponsorshipPaymentCommitmentCellHash != evidence.SponsorshipPaymentCommitmentCellHash ||
		!relaySponsorshipWinnerMature(providerCorroboration.Evidence, profile) {
		return errors.New("provider sponsorship proof bundle does not reproduce its signed chain effect")
	}
	clientCorroboration := tosctlRelaySponsorshipObserved{NetworkGlobalID: manifest.NetworkDomain.GlobalID,
		NetworkDomain: manifest.NetworkDomain, EvidenceProfileURI: manifest.EvidenceProfileURI,
		EvidenceProfileDigest: manifest.EvidenceProfileDigest, EvidenceProfile: manifest.EvidenceProfile,
		ObservationDigests: result.ObservationDigests, Quorum: result.Quorum, Evidence: result.Evidence,
		Observations: result.Observations, Failures: result.Failures}
	if verifyTOSCTLSponsorshipCorroboration(clientCorroboration, policy) != nil ||
		result.Evidence.TransactionHash != evidence.SubmittedTransactionHash ||
		len(evidence.DestinationCreditReferences) != 1 ||
		result.Evidence.DestinationCreditReference != evidence.DestinationCreditReferences[0] ||
		result.Evidence.DestinationCreditAtomic != evidence.Amount.AmountAtomic ||
		!sameTOSCTLSponsorshipChainEffect(providerCorroboration.Evidence, result.Evidence) ||
		!relaySponsorshipWinnerMature(result.Evidence, profile) {
		return errors.New("client-owned quorum did not reproduce the exact Provider sponsorship chain effect")
	}
	operators := make([]string, 0, len(result.Observations))
	winner := result.Evidence.quorumKey()
	for _, observation := range result.Observations {
		if observation.quorumKey() == winner {
			operators = append(operators, observation.OperatorProvenance)
		}
	}
	sort.Strings(operators)
	if !equalStrings(operators, result.OperatorProvenance) || len(operators) < int(profile.MinimumOperatorDomains) ||
		len(result.ObservationDigests) < int(profile.MinimumObservers) {
		return errors.New("client-owned quorum does not satisfy the signed terminal profile")
	}
	return nil
}

func sameTOSCTLSponsorshipChainEffect(left, right tosctlPaymentObservation) bool {
	left.ObservedMasterchainWorkchain, right.ObservedMasterchainWorkchain = 0, 0
	left.ObservedMasterchainShard, right.ObservedMasterchainShard = 0, 0
	left.ObservedMasterchainSeqno, right.ObservedMasterchainSeqno = 0, 0
	left.ObservedMasterchainRootHash, right.ObservedMasterchainRootHash = "", ""
	left.ObservedMasterchainFileHash, right.ObservedMasterchainFileHash = "", ""
	left.ObservedMasterchainGenUTime, right.ObservedMasterchainGenUTime = 0, 0
	left.Endpoint, right.Endpoint = "", ""
	left.OperatorProvenance, right.OperatorProvenance = "", ""
	left.FinalityProven, right.FinalityProven = false, false
	return reflect.DeepEqual(left, right)
}

func (sink *TOSCTLPaymentSink) supportsProviderLocalSponsorshipTransactionEvidence(
	release RelaySponsorshipReleasePolicy, profile agentrelay.FinalityProfile) bool {
	if sink == nil ||
		release != sink.RelaySponsorshipReleasePolicy ||
		release.EvidenceClass != agentrelay.SponsorshipReleaseObservedUnproven ||
		profile.MinimumConfirmationDepth != 1 {
		return false
	}
	for _, configured := range sink.RelayTerminalFinalityProfiles {
		if configured == profile {
			return true
		}
	}
	return false
}

func (sink *TOSCTLPaymentSink) VerifySponsorshipTransactionEvidence(_ context.Context,
	evidence agentrelay.RelaySponsorshipTransactionEvidence, expected agentrelay.RelaySponsorshipEvidenceContext,
	profile agentrelay.FinalityProfile) error {
	policy := sink.RelaySponsorshipReleasePolicy
	return sink.verifySponsorshipTransactionEvidence(evidence, expected, profile, policy, true)
}

func (sink *TOSCTLPaymentSink) verifySponsorshipTransactionEvidence(
	evidence agentrelay.RelaySponsorshipTransactionEvidence, expected agentrelay.RelaySponsorshipEvidenceContext,
	profile agentrelay.FinalityProfile, policy RelaySponsorshipReleasePolicy, requireCurrent bool) error {
	profileSupported := sink.supportsProviderLocalSponsorshipTransactionEvidence(policy, profile)
	if !requireCurrent {
		profileSupported = policy.EvidenceClass == agentrelay.SponsorshipReleaseObservedUnproven &&
			policy.ProfileURI == agentrelay.RPCCorroborationEvidenceProfileURI &&
			validSHA256Digest(policy.ProfileDigest) && profile.ProfileURI == RelayClientCorroboratedTerminalProfileURI &&
			profile.MinimumConfirmationDepth == 1 && profile.MinimumObservers > 0 && profile.MinimumOperatorDomains > 0
	}
	evidenceDigest, evidenceErr := agentrelay.RelaySponsorshipTransactionEvidenceDigest(evidence)
	if evidenceErr != nil || !sink.hasVerifiedSponsorshipTransaction(evidenceDigest) ||
		len(evidence.DestinationCreditReferences) != 1 ||
		!profileSupported ||
		evidence.SponsorshipTerminalProfileDigest != profile.ProfileDigest ||
		evidence.ConfirmationDepth < profile.MinimumConfirmationDepth ||
		len(evidence.ObservationDigests) < int(profile.MinimumObservers) ||
		agentrelay.VerifySponsorshipPaymentRequestForEvidence(evidence.AgreementPaymentRequest, evidence, expected) != nil {
		return errors.New("sponsorship transaction evidence changes the expected payment or finality profile")
	}
	proofDigest, err := agentrelay.RelaySponsorshipProofBundleDigest(evidence.ProofBundle)
	if err != nil || proofDigest != evidence.ProofBundleDigest {
		return errors.New("sponsorship proof attachment digest is invalid")
	}
	var proof tosctlRelaySponsorshipProofBundle
	if err := codec.Unmarshal(evidence.ProofBundle, &proof); err != nil {
		return errors.New("sponsorship proof attachment is not exact canonical CBOR")
	}
	finalityCBOR, err := codec.Marshal(profile)
	if err != nil || proof.Schema != tosctlRelaySponsorshipProofSchema ||
		!reflect.DeepEqual(proof.AgreementPaymentRequest, evidence.AgreementPaymentRequest) ||
		proof.AgreementPaymentRequestDigest != evidence.AgreementPaymentRequestDigest ||
		proof.SponsorshipStableActionID != evidence.SponsorshipStableActionID ||
		proof.SponsorshipExactRequestDigest != evidence.SponsorshipExactRequestDigest ||
		proof.ProviderSponsorSourceAccount != evidence.ProviderSponsorSourceAccount ||
		proof.ProviderSponsorSourceSequence != evidence.ProviderSponsorSourceSequence ||
		proof.ProviderSponsorValidUntilUnix != evidence.ProviderSponsorValidUntilUnix ||
		proof.DestinationSourceAccount != evidence.DestinationSourceAccount ||
		proof.SignedTopUpTransactionDigest != evidence.SignedTopUpTransactionDigest ||
		proof.SignedTopUpTransactionCellHash != evidence.SignedTopUpTransactionCellHash ||
		proof.SponsorshipPaymentCommitmentCellHash != evidence.SponsorshipPaymentCommitmentCellHash ||
		len(proof.SignedTopUpTransactionBOC) == 0 ||
		sha256Digest(proof.SignedTopUpTransactionBOC) != evidence.SignedTopUpTransactionDigest ||
		proof.NetworkDigest != evidence.NetworkDigest || proof.NetworkDomain.NetworkID != expected.NetworkID ||
		proof.NetworkDigest != expected.NetworkDomainDigest || proof.FinalityProfile != profile ||
		proof.FinalityProfileCBORDigest != sha256Digest(finalityCBOR) ||
		proof.SponsorshipReleaseProfileURI != policy.ProfileURI ||
		proof.SponsorshipReleaseProfileDigest != policy.ProfileDigest ||
		!validSHA256Digest(proof.CorroborationSnapshotIdentity) ||
		proof.ConfirmationDepth != evidence.ConfirmationDepth ||
		!equalStrings(proof.ObservationDigests, evidence.ObservationDigests) ||
		proof.FinalizedCheckpointID != evidence.FinalizedCheckpointID ||
		proof.FinalizedCheckpointSequence != evidence.FinalizedCheckpointSequence ||
		proof.FinalizedCheckpointUnix != evidence.FinalizedCheckpointUnix {
		return errors.New("sponsorship proof attachment changes the exact transaction evidence")
	}
	corroboration := tosctlRelaySponsorshipObserved{NetworkGlobalID: proof.NetworkDomain.GlobalID,
		NetworkDomain: proof.NetworkDomain, EvidenceProfileURI: proof.SponsorshipReleaseProfileURI,
		EvidenceProfileDigest: proof.SponsorshipReleaseProfileDigest,
		EvidenceProfile:       proof.SponsorshipReleaseProfile, ObservationDigests: proof.ObservationDigests,
		Quorum: proof.Quorum, Observations: proof.Observations, Failures: proof.Failures}
	// The proof declares the exact winner through its finalized checkpoint and
	// transaction references; select that observation before reconstructing the
	// strict-majority digest set.
	foundWinner := false
	for _, observation := range proof.Observations {
		checkpoint := "masterchain:" + checkpointSuffix(observation)
		if observation.TransactionHash == evidence.SubmittedTransactionHash &&
			observation.DestinationCreditReference == evidence.DestinationCreditReferences[0] &&
			checkpoint == evidence.FinalizedCheckpointID {
			corroboration.Evidence, foundWinner = observation, true
			break
		}
	}
	if !foundWinner || verifyTOSCTLSponsorshipCorroboration(corroboration, policy) != nil {
		return errors.New("sponsorship proof attachment has no reproducible owner-pinned quorum winner")
	}
	operators := map[string]bool{}
	for _, observation := range proof.Observations {
		if observation.quorumKey() == corroboration.Evidence.quorumKey() {
			operators[observation.OperatorProvenance] = true
		}
	}
	now := sink.sponsorshipNow()
	if len(operators) < int(profile.MinimumOperatorDomains) ||
		!relaySponsorshipWinnerMature(corroboration.Evidence, profile) ||
		evidence.ObservedAtUnix > uint64(now.Add(5*time.Minute).Unix()) ||
		evidence.PortableProofLocator != "" {
		return errors.New("sponsorship proof attachment does not satisfy the lower-assurance terminal predicate")
	}
	return nil
}

// relaySponsorshipWinnerMature deliberately uses chain-observed time from the
// exact quorum winner.  Host observed_at is only logging metadata and cannot
// prove that the signed reorg window elapsed.
func relaySponsorshipWinnerMature(winner tosctlPaymentObservation,
	profile agentrelay.FinalityProfile) bool {
	window := uint64(profile.ReorgWindowSeconds)
	economicEffectUnix := winner.TransactionUTime
	if winner.DestinationTransactionUTime > economicEffectUnix {
		economicEffectUnix = winner.DestinationTransactionUTime
	}
	return economicEffectUnix > 0 && winner.ObservedMasterchainGenUTime >= economicEffectUnix &&
		economicEffectUnix <= ^uint64(0)-window &&
		winner.ObservedMasterchainGenUTime >= economicEffectUnix+window
}

func (sink *TOSCTLPaymentSink) writePrivateCanonicalCBOR(pattern string, value any) (string, string, func(), error) {
	encoded, err := codec.Marshal(value)
	if err != nil {
		return "", "", func() {}, err
	}
	path, cleanup, err := sink.writePrivateBytes(pattern, encoded)
	if err != nil {
		return "", "", func() {}, err
	}
	return path, sha256Digest(encoded), cleanup, nil
}

func (sink *TOSCTLPaymentSink) writePrivateBytes(pattern string, encoded []byte) (string, func(), error) {
	if len(encoded) == 0 || len(encoded) > 128<<10 {
		return "", func() {}, errors.New("private sponsorship evidence has invalid size")
	}
	if err := os.MkdirAll(sink.EvidenceDirectory, 0o700); err != nil {
		return "", func() {}, err
	}
	info, err := os.Lstat(sink.EvidenceDirectory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return "", func() {}, errors.New("custody evidence directory must be private")
	}
	file, err := os.CreateTemp(filepath.Clean(sink.EvidenceDirectory), pattern)
	if err != nil {
		return "", func() {}, err
	}
	path := file.Name()
	cleanup := func() { _ = os.Remove(path) }
	if err := file.Chmod(0o600); err == nil {
		_, err = file.Write(encoded)
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		cleanup()
		return "", func() {}, err
	}
	return path, cleanup, nil
}

func (sink *TOSCTLPaymentSink) rememberVerifiedSponsorshipTransaction(digest string, expiresAt time.Time) {
	if sink == nil || !validSHA256Digest(digest) || expiresAt.IsZero() {
		return
	}
	now := uint64(sink.sponsorshipNow().Unix())
	sink.verifiedSponsorshipMu.Lock()
	defer sink.verifiedSponsorshipMu.Unlock()
	if sink.verifiedSponsorshipTransactions == nil {
		sink.verifiedSponsorshipTransactions = make(map[string]uint64)
	}
	for candidate, expiry := range sink.verifiedSponsorshipTransactions {
		if expiry <= now {
			delete(sink.verifiedSponsorshipTransactions, candidate)
		}
	}
	for len(sink.verifiedSponsorshipTransactions) >= maximumVerifiedSponsorshipObservationRefs {
		oldestDigest, oldestExpiry := "", ^uint64(0)
		for candidate, expiry := range sink.verifiedSponsorshipTransactions {
			if expiry < oldestExpiry || expiry == oldestExpiry && candidate < oldestDigest {
				oldestDigest, oldestExpiry = candidate, expiry
			}
		}
		delete(sink.verifiedSponsorshipTransactions, oldestDigest)
	}
	sink.verifiedSponsorshipTransactions[digest] = uint64(expiresAt.UTC().Unix())
}

func (sink *TOSCTLPaymentSink) hasVerifiedSponsorshipTransaction(digest string) bool {
	if sink == nil || !validSHA256Digest(digest) {
		return false
	}
	now := uint64(sink.sponsorshipNow().Unix())
	sink.verifiedSponsorshipMu.Lock()
	defer sink.verifiedSponsorshipMu.Unlock()
	expiry, ok := sink.verifiedSponsorshipTransactions[digest]
	if !ok || expiry <= now {
		delete(sink.verifiedSponsorshipTransactions, digest)
		return false
	}
	return true
}

func validTVMCellSHA256(value string) bool {
	const prefix = "tvm-cell-sha256:"
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+64 {
		return false
	}
	for _, character := range value[len(prefix):] {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}
