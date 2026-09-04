package earning

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

const (
	tosQuorumEvidenceProfile                  = "tos://settlement/native-agent-account-quorum/v1"
	maximumVerifiedSponsorshipObservationRefs = 512
	maximumTOSCTLCommandOutputBytes           = 1 << 20
	maximumConcurrentTOSCTLCommands           = 8
)

var errRelaySponsorshipTypedResolutionRequired = errors.New("relay sponsorship requires typed frozen-snapshot resolution")

// TOSCTLPaymentSink is the production boundary between OpenFox's Owner
// Economic Action Authority and tosctl custody. OpenFox never passes a private
// wallet key to the command. Custody receives one short-lived, exact,
// Agreement-bound proof and independently enforces its pinned authority key,
// writer-generation high-water mark, Agent Account limits, sequence and
// finalized-chain evidence.
type TOSCTLPaymentSink struct {
	Authority       EconomicAuthority
	Executable      string
	ConfigPath      string
	Wallet          string
	SourceAccount   string
	NetworkGlobalID int32
	// RelayNetworkDomain is required for every TOS custody authorization: the
	// custody boundary accepts only schema v2 proofs bound to the complete
	// zero-state and target workchain. RelayNetworkPreflight is additionally
	// required before funding a bearer-executable Agent relay sponsorship.
	RelayNetworkDomain    *agentrelay.NetworkDomain
	RelayNetworkPreflight func(context.Context, string, agentrelay.NetworkDomain) error
	// RelaySponsorshipReleasePolicy is owner configuration. When it selects the
	// observed profile, this sink may be explicitly wired as the typed
	// sponsorship resolver; ordinary payments never infer or enable it.
	RelaySponsorshipReleasePolicy RelaySponsorshipReleasePolicy
	// RelayTerminalFinalityProfiles is the exact owner-selected subset this
	// adapter may prove. The bundled tosctl RPC terminal adapter currently
	// supports confirmation depth one only.
	RelayTerminalFinalityProfiles   []agentrelay.FinalityProfile
	FeeReserveNanoTOS               uint64
	QuorumConfigPaths               []string
	MaximumTransactions             uint32
	VaultURL                        string
	EvidenceDirectory               string
	ResolveAttempts                 uint32
	ResolveInterval                 time.Duration
	Now                             func() time.Time
	Run                             func(context.Context, []string, []string) ([]byte, error)
	executableMu                    sync.Mutex
	executableIdentity              *tosctlExecutableIdentity
	executableSnapshot              *os.File
	executableLaunches              chan struct{}
	vaultCapabilityPinned           bool
	vaultCapabilityDigest           [sha256.Size]byte
	verifiedSponsorshipMu           sync.Mutex
	verifiedSponsorshipObservations map[string]uint64
	verifiedSponsorshipTransactions map[string]uint64
	sponsorshipSnapshotMu           sync.Mutex
}

func (sink *TOSCTLPaymentSink) verifyRelayNetworkDomain(ctx context.Context,
	expected agentrelay.NetworkDomain) error {
	if sink == nil || sink.RelayNetworkDomain == nil || *sink.RelayNetworkDomain != expected ||
		sink.NetworkGlobalID != expected.GlobalID {
		return errors.New("TOS custody relay network domain is not the current owner pin")
	}
	return sink.verifyRelayNetworkDomainAt(ctx, expected, sink.ConfigPath)
}

func (sink *TOSCTLPaymentSink) verifyRelayNetworkDomainAt(ctx context.Context,
	expected agentrelay.NetworkDomain, configPath string) error {
	if sink == nil || ctx == nil || sink.RelayNetworkPreflight == nil || !filepath.IsAbs(configPath) {
		return errors.New("TOS custody relay network domain is not completely pinned")
	}
	if _, err := agentrelay.NetworkDomainDigest(expected); err != nil {
		return errors.New("TOS custody relay network domain is invalid")
	}
	if err := sink.RelayNetworkPreflight(ctx, configPath, expected); err != nil {
		return fmt.Errorf("verify TOS custody relay network domain: %w", err)
	}
	return nil
}

func (sink *TOSCTLPaymentSink) custodyNetworkDomain(ctx context.Context,
	request commerce.AgreementPaymentRequest, configPath string) (commerce.CustodyNetworkDomain, error) {
	if sink == nil || sink.RelayNetworkDomain == nil || request.NetworkID != sink.RelayNetworkDomain.NetworkID ||
		sink.NetworkGlobalID != sink.RelayNetworkDomain.GlobalID {
		return commerce.CustodyNetworkDomain{}, errors.New("TOS custody payment has no exact pinned network domain")
	}
	return sink.custodyNetworkDomainAt(ctx, request, configPath, *sink.RelayNetworkDomain)
}

func (sink *TOSCTLPaymentSink) custodyNetworkDomainAt(ctx context.Context,
	request commerce.AgreementPaymentRequest, configPath string,
	domain agentrelay.NetworkDomain) (commerce.CustodyNetworkDomain, error) {
	if sink == nil || request.NetworkID != domain.NetworkID {
		return commerce.CustodyNetworkDomain{}, errors.New("TOS custody payment has no exact pinned network domain")
	}
	digest, err := agentrelay.NetworkDomainDigest(domain)
	if err != nil {
		return commerce.CustodyNetworkDomain{}, errors.New("TOS custody payment network domain is invalid")
	}
	switch request.SchemaVersion {
	case 3:
		if request.NetworkDomainDigest != digest {
			return commerce.CustodyNetworkDomain{}, errors.New("relay-eligible payment conflicts with the pinned network domain")
		}
		if err := sink.verifyRelayNetworkDomainAt(ctx, domain, configPath); err != nil {
			return commerce.CustodyNetworkDomain{}, err
		}
	default:
		return commerce.CustodyNetworkDomain{}, errors.New("native TOS custody requires a full owner-pinned network domain")
	}
	return commerce.CustodyNetworkDomain{NetworkID: domain.NetworkID, GlobalID: domain.GlobalID,
		ZeroStateRootHash: domain.ZeroStateRootHash, ZeroStateFileHash: domain.ZeroStateFileHash,
		WorkchainID: domain.WorkchainID}, nil
}

type tosctlPaymentPrepared struct {
	Schema                        string                   `json:"schema"`
	StableActionID                string                   `json:"stable_action_id"`
	AgreementBodyDigest           string                   `json:"agreement_body_digest"`
	ObligationInstanceID          string                   `json:"obligation_instance_id"`
	Account                       string                   `json:"account"`
	Target                        string                   `json:"target"`
	AmountNanoTOS                 uint64                   `json:"amount_nanotos"`
	ControllerEpoch               uint64                   `json:"controller_epoch"`
	Seqno                         uint32                   `json:"seqno"`
	NetworkGlobalID               int32                    `json:"network_global_id"`
	NetworkDomain                 agentrelay.NetworkDomain `json:"network_domain"`
	ValidUntil                    uint32                   `json:"valid_until"`
	ActionKind                    string                   `json:"action_kind"`
	SponsorshipCommitmentBodyHash *string                  `json:"sponsorship_commitment_body_hash"`
	ExactSignedBOC                string                   `json:"exact_signed_boc"`
	ExactSignedBOCDigest          string                   `json:"exact_signed_boc_digest"`
}

func validateTOSCTLPreparedPayment(prepared tosctlPaymentPrepared, request commerce.AgreementPaymentRequest,
	network commerce.CustodyNetworkDomain, sourceAccount string, amount, authorizedValidUntil uint64,
	sponsored bool) error {
	boc, bocErr := base64.StdEncoding.Strict().DecodeString(prepared.ExactSignedBOC)
	bocDigest := sha256.Sum256(boc)
	if prepared.Schema != "tosctl.agent-account.agreement-payment-prepared.v1" ||
		prepared.StableActionID != request.StableActionID || prepared.AgreementBodyDigest != request.AgreementBodyDigest ||
		prepared.ObligationInstanceID != request.ObligationInstanceID || prepared.Account != sourceAccount ||
		prepared.Target != string(request.Destination) || prepared.AmountNanoTOS != amount ||
		prepared.NetworkGlobalID != network.GlobalID || prepared.NetworkDomain.NetworkID != network.NetworkID ||
		prepared.NetworkDomain.GlobalID != network.GlobalID ||
		prepared.NetworkDomain.ZeroStateRootHash != network.ZeroStateRootHash ||
		prepared.NetworkDomain.ZeroStateFileHash != network.ZeroStateFileHash ||
		prepared.NetworkDomain.WorkchainID != network.WorkchainID ||
		authorizedValidUntil == 0 || authorizedValidUntil > request.ExpiresAtUnix ||
		authorizedValidUntil > uint64(^uint32(0)) || prepared.ValidUntil != uint32(authorizedValidUntil) ||
		prepared.ExactSignedBOC == "" || bocErr != nil || len(boc) == 0 ||
		prepared.ExactSignedBOCDigest != "sha256:"+hex.EncodeToString(bocDigest[:]) {
		return fmt.Errorf("tosctl returned an unrelated prepared payment: schema=%q action=%q agreement=%q obligation=%q account=%q target=%q amount=%d digest=%q",
			prepared.Schema, prepared.StableActionID, prepared.AgreementBodyDigest, prepared.ObligationInstanceID,
			prepared.Account, prepared.Target, prepared.AmountNanoTOS, prepared.ExactSignedBOCDigest)
	}
	if !sponsored {
		if prepared.ActionKind != "agent-native-send" || prepared.SponsorshipCommitmentBodyHash != nil {
			return errors.New("tosctl prepared an unexpected sponsored payment action")
		}
		return nil
	}
	if prepared.ActionKind != "agent-task-send" || prepared.SponsorshipCommitmentBodyHash == nil ||
		!canonicalSHA256("sha256:"+strings.TrimPrefix(*prepared.SponsorshipCommitmentBodyHash, "tvm-cell-sha256:")) ||
		!strings.HasPrefix(*prepared.SponsorshipCommitmentBodyHash, "tvm-cell-sha256:") {
		return errors.New("tosctl omitted the sponsorship payment commitment")
	}
	return nil
}

type tosctlPaymentBroadcast struct {
	Schema               string `json:"schema"`
	StableActionID       string `json:"stable_action_id"`
	Account              string `json:"account"`
	ExactSignedBOCDigest string `json:"exact_signed_boc_digest"`
	State                string `json:"state"`
}

type tosctlPaymentFinalized struct {
	Schema               string          `json:"schema"`
	StableActionID       string          `json:"stable_action_id"`
	AgreementBodyDigest  string          `json:"agreement_body_digest"`
	ObligationInstanceID string          `json:"obligation_instance_id"`
	SourceAccount        string          `json:"source_account"`
	Destination          string          `json:"destination"`
	AmountNanoTOS        uint64          `json:"amount_nanotos"`
	NetworkGlobalID      int32           `json:"network_global_id"`
	Quorum               tosctlQuorum    `json:"quorum"`
	Evidence             json.RawMessage `json:"evidence"`
	Observations         json.RawMessage `json:"observations"`
	Failures             []string        `json:"failures"`
	State                string          `json:"state"`
}

type tosctlQuorum struct {
	Members   uint32 `json:"members"`
	Threshold uint32 `json:"threshold"`
	Agreeing  uint32 `json:"agreeing"`
}

type tosctlPaymentObservation struct {
	Endpoint                        string `json:"endpoint"`
	LocatorIdentityDigest           string `json:"locator_identity_digest"`
	OperatorProvenance              string `json:"operator_provenance"`
	TransactionHash                 string `json:"transaction_hash"`
	TransactionLT                   uint64 `json:"transaction_lt"`
	TransactionUTime                uint64 `json:"transaction_utime"`
	TransactionBOCDigest            string `json:"transaction_boc_digest"`
	SourceOutboundMessageHash       string `json:"source_outbound_message_hash"`
	DestinationCreditReference      string `json:"destination_credit_reference"`
	DestinationTransactionHash      string `json:"destination_transaction_hash"`
	DestinationTransactionLT        uint64 `json:"destination_transaction_lt"`
	DestinationTransactionUTime     uint64 `json:"destination_transaction_utime"`
	DestinationTransactionBOCDigest string `json:"destination_transaction_boc_digest"`
	DestinationBlockWorkchain       int32  `json:"destination_block_workchain"`
	DestinationBlockShard           int64  `json:"destination_block_shard"`
	DestinationBlockSeqno           uint32 `json:"destination_block_seqno"`
	DestinationBlockRootHash        string `json:"destination_block_root_hash"`
	DestinationBlockFileHash        string `json:"destination_block_file_hash"`
	DestinationCreditAtomic         string `json:"destination_credit_atomic"`
	DestinationCreditFirst          bool   `json:"destination_credit_first"`
	DestinationTransactionAborted   bool   `json:"destination_transaction_aborted"`
	DestinationBouncePresent        bool   `json:"destination_bounce_present"`
	DestinationCreditObservedExact  bool   `json:"destination_credit_observed_exact"`
	BlockWorkchain                  int32  `json:"block_workchain"`
	BlockShard                      int64  `json:"block_shard"`
	BlockSeqno                      uint32 `json:"block_seqno"`
	BlockRootHash                   string `json:"block_root_hash"`
	BlockFileHash                   string `json:"block_file_hash"`
	NetworkGlobalID                 int32  `json:"network_global_id"`
	ZeroStateWorkchain              int32  `json:"zero_state_workchain"`
	ZeroStateShard                  int64  `json:"zero_state_shard"`
	ZeroStateSeqno                  uint32 `json:"zero_state_seqno"`
	ZeroStateRootHash               string `json:"zero_state_root_hash"`
	ZeroStateFileHash               string `json:"zero_state_file_hash"`
	ObservedMasterchainWorkchain    int32  `json:"observed_masterchain_workchain"`
	ObservedMasterchainShard        int64  `json:"observed_masterchain_shard"`
	ObservedMasterchainSeqno        uint32 `json:"observed_masterchain_seqno"`
	ObservedMasterchainRootHash     string `json:"observed_masterchain_root_hash"`
	ObservedMasterchainFileHash     string `json:"observed_masterchain_file_hash"`
	ObservedMasterchainGenUTime     uint64 `json:"observed_masterchain_gen_utime"`
	FinalityProven                  bool   `json:"finality_proven"`
}

type tosctlRelaySponsorshipEvidenceProfileMember struct {
	Endpoint              string `json:"endpoint"`
	LocatorIdentityDigest string `json:"locator_identity_digest"`
	OperatorProvenance    string `json:"operator_provenance"`
}

type tosctlRelaySponsorshipEvidenceProfile struct {
	ProfileURI                 string                                        `json:"profile_uri"`
	NetworkDomain              agentrelay.NetworkDomain                      `json:"network_domain"`
	Members                    []tosctlRelaySponsorshipEvidenceProfileMember `json:"members"`
	Threshold                  uint32                                        `json:"threshold"`
	MaximumHistoryTransactions uint32                                        `json:"maximum_history_transactions"`
	StrictMajority             bool                                          `json:"strict_majority"`
	ExactSubmittedMessage      bool                                          `json:"exact_submitted_message"`
	ExactDestinationCredit     bool                                          `json:"exact_destination_credit"`
	ValidatorFinalityProven    bool                                          `json:"validator_finality_proven"`
}

type tosctlRelaySponsorshipObserved struct {
	Schema                               string                                `json:"schema"`
	StableActionID                       string                                `json:"stable_action_id"`
	SponsorshipStableActionID            string                                `json:"sponsorship_stable_action_id"`
	SponsorshipExactRequestDigest        string                                `json:"sponsorship_exact_request_digest"`
	AgreementPaymentRequestDigest        string                                `json:"agreement_payment_request_digest"`
	AgreementBodyDigest                  string                                `json:"agreement_body_digest"`
	ObligationInstanceID                 string                                `json:"obligation_instance_id"`
	ProviderSponsorSourceAccount         string                                `json:"provider_sponsor_source_account"`
	ProviderSponsorSourceSequence        uint64                                `json:"provider_sponsor_source_sequence"`
	ProviderSponsorValidUntilUnix        uint64                                `json:"provider_sponsor_valid_until_unix"`
	SignedTopUpTransactionDigest         string                                `json:"signed_top_up_transaction_digest"`
	SignedTopUpTransactionCellHash       string                                `json:"signed_top_up_transaction_cell_hash"`
	SponsorshipPaymentCommitmentCellHash string                                `json:"sponsorship_payment_commitment_cell_hash"`
	DestinationSourceAccount             string                                `json:"destination_source_account"`
	Destination                          string                                `json:"destination"`
	AmountNanoTOS                        uint64                                `json:"amount_nanotos"`
	NetworkGlobalID                      int32                                 `json:"network_global_id"`
	NetworkDomain                        agentrelay.NetworkDomain              `json:"network_domain"`
	SubmittedTransactionHash             string                                `json:"submitted_transaction_hash"`
	SourceExecutionReference             string                                `json:"source_execution_reference"`
	DestinationCreditReferences          []string                              `json:"destination_credit_references"`
	EvidenceProfileURI                   string                                `json:"evidence_profile_uri"`
	EvidenceProfileDigest                string                                `json:"evidence_profile_digest"`
	EvidenceProfile                      tosctlRelaySponsorshipEvidenceProfile `json:"evidence_profile"`
	CorroborationSnapshot                string                                `json:"corroboration_snapshot"`
	CorroborationSnapshotIdentity        string                                `json:"corroboration_snapshot_identity"`
	ObservedCheckpointID                 string                                `json:"observed_checkpoint_id"`
	ObservedCheckpointSequence           uint64                                `json:"observed_checkpoint_sequence"`
	ObservedCheckpointUnix               uint64                                `json:"observed_checkpoint_unix"`
	ObservationDigests                   []string                              `json:"observation_digests"`
	ObservedAtUnix                       uint64                                `json:"observed_at_unix"`
	Quorum                               tosctlQuorum                          `json:"quorum"`
	Evidence                             tosctlPaymentObservation              `json:"evidence"`
	Observations                         []tosctlPaymentObservation            `json:"observations"`
	Failures                             []string                              `json:"failures"`
	Finality                             string                                `json:"finality"`
	State                                string                                `json:"state"`
	CustodyState                         string                                `json:"custody_state"`
	MissingProof                         string                                `json:"missing_proof"`
}

func (sink *TOSCTLPaymentSink) SubmitPayment(ctx context.Context, action commerce.AuthorizedAction,
	fence commerce.WriterFence, fields map[string]commerce.SemanticValue, canonicalRequest []byte,
	request commerce.AgreementPaymentRequest) (commerce.AgreementPaymentEvidence, error) {
	return sink.submitPayment(ctx, action, fence, fields, canonicalRequest, request, sink.ConfigPath, nil, nil)
}

// ResumePaymentBroadcast asks custody to submit only the signed BOC already
// journaled under this stable action. It intentionally shares the same exact
// broadcast-by-ID primitive as sponsorship recovery; no authorization,
// sequence allocation, prepare, or re-signing occurs here.
func (sink *TOSCTLPaymentSink) ResumePaymentBroadcast(ctx context.Context,
	request commerce.AgreementPaymentRequest, exactRequestDigest string) error {
	return sink.ResumeRelaySponsorshipBroadcast(ctx, request, exactRequestDigest, nil)
}

type tosctlFrozenCustodyIdentity struct {
	wallet        string
	sourceAccount string
	network       agentrelay.NetworkDomain
	feeReserve    uint64
}

func (sink *TOSCTLPaymentSink) SubmitRelaySponsorshipPayment(ctx context.Context,
	action commerce.AuthorizedAction, fence commerce.WriterFence,
	fields map[string]commerce.SemanticValue, canonicalRequest []byte,
	request commerce.AgreementPaymentRequest,
	binding SponsorshipCustodyBinding,
	finality agentrelay.FinalityProfile,
	releaseProfile agentrelay.SponsorshipReleaseProfile,
	frozen *RelaySponsorshipEvidenceSnapshot) (commerce.AgreementPaymentEvidence, error) {
	configPath := sink.ConfigPath
	var identity *tosctlFrozenCustodyIdentity
	if frozen != nil {
		if err := sink.ValidateRelaySponsorshipEvidenceSnapshot(releaseProfile, *frozen); err != nil {
			return commerce.AgreementPaymentEvidence{}, err
		}
		var err error
		configPath, err = sink.relaySponsorshipSnapshotPrimaryConfig(*frozen)
		if err != nil {
			return commerce.AgreementPaymentEvidence{}, err
		}
		frozenNetwork, err := sink.relaySponsorshipSnapshotNetwork(*frozen)
		if err != nil {
			return commerce.AgreementPaymentEvidence{}, err
		}
		identity = &tosctlFrozenCustodyIdentity{wallet: frozen.CustodyWallet,
			sourceAccount: frozen.ProviderSourceAccount, network: frozenNetwork,
			feeReserve: frozen.FeeReserveNanoTOS}
	}
	finalityCBOR, err := codec.Marshal(finality)
	if err != nil || !sink.SupportsRelaySponsorshipTerminalFinalityProfile(finality, frozen) {
		return commerce.AgreementPaymentEvidence{}, errors.New("selected sponsorship finality profile is unsupported")
	}
	paymentDigest, err := commerce.AgreementPaymentRequestDigest(request)
	snapshotID := zeroSHA256Digest()
	if frozen != nil {
		snapshotID = frozen.SnapshotIdentity
	}
	if err != nil || binding.PaymentRequestDigest != paymentDigest ||
		binding.FinalityProfileCBORDigest != sha256Digest(finalityCBOR) ||
		binding.ReleaseProfileDigest != releaseProfile.ProfileDigest ||
		binding.CorroborationSnapshotID != snapshotID {
		return commerce.AgreementPaymentEvidence{}, errors.New("relay sponsorship custody purpose changes its exact payment or evidence profile")
	}
	return sink.submitPayment(ctx, action, fence, fields, canonicalRequest, request, configPath, &binding, identity)
}

func (sink *TOSCTLPaymentSink) ResumeRelaySponsorshipBroadcast(ctx context.Context,
	request commerce.AgreementPaymentRequest, exactRequestDigest string,
	frozen *RelaySponsorshipEvidenceSnapshot) error {
	if err := sink.validate(); err != nil {
		return err
	}
	configPath := sink.ConfigPath
	wallet := sink.Wallet
	sourceAccount := sink.SourceAccount
	networkID := ""
	if sink.RelayNetworkDomain != nil {
		networkID = sink.RelayNetworkDomain.NetworkID
	}
	if frozen != nil {
		profile := agentrelay.SponsorshipReleaseProfile{
			EvidenceClass: agentrelay.SponsorshipReleaseEvidenceClass(frozen.EvidenceClass),
			ProfileURI:    frozen.ProfileURI, ProfileDigest: frozen.ProfileDigest,
		}
		if err := sink.ValidateRelaySponsorshipEvidenceSnapshot(profile, *frozen); err != nil {
			return err
		}
		var err error
		configPath, err = sink.relaySponsorshipSnapshotPrimaryConfig(*frozen)
		if err != nil {
			return err
		}
		frozenNetwork, networkErr := sink.relaySponsorshipSnapshotNetwork(*frozen)
		if networkErr != nil {
			return networkErr
		}
		networkID = frozenNetwork.NetworkID
		wallet = frozen.CustodyWallet
		sourceAccount = frozen.ProviderSourceAccount
	}
	canonical, fields, materialErr := commerce.PaymentAuthorizationMaterial(request)
	derivedStableActionID, _, stableErr := commerce.DeriveStableActionID(commerce.PaymentActionKind(request), fields)
	resolution := sink.Authority.Resolve(request.StableActionID, exactRequestDigest)
	if request.SchemaVersion != 3 || request.StableActionID == "" || !canonicalSHA256(exactRequestDigest) ||
		materialErr != nil || len(canonical) == 0 || stableErr != nil || derivedStableActionID != request.StableActionID ||
		resolution.State != commerce.ActionSubmitted || resolution.ExactRequestDigest != exactRequestDigest ||
		networkID == "" || request.NetworkID != networkID {
		return errors.New("submitted payment recovery lacks an exact authority boundary")
	}
	raw, err := sink.run(ctx, []string{"agent", "account", "economic-payment-broadcast",
		"--wallet", wallet, "--stable-action-id", request.StableActionID, "--yes", "-c", configPath})
	if err != nil {
		// This includes the expected already-Broadcasting response. The caller
		// immediately performs the bounded read-only corroboration query; an
		// unknown result remains ambiguous and cannot authorize another top-up.
		return err
	}
	var result tosctlPaymentBroadcast
	if err := decodeStrictJSON(raw, &result); err != nil ||
		result.Schema != "tosctl.agent-account.agreement-payment-broadcast.v1" ||
		result.StableActionID != request.StableActionID || result.Account != sourceAccount ||
		!canonicalSHA256(result.ExactSignedBOCDigest) || result.State != "broadcasting" {
		return errors.New("tosctl returned an unrelated resumed sponsorship broadcast")
	}
	return nil
}

func (sink *TOSCTLPaymentSink) submitPayment(ctx context.Context, action commerce.AuthorizedAction,
	fence commerce.WriterFence, fields map[string]commerce.SemanticValue, canonicalRequest []byte,
	request commerce.AgreementPaymentRequest, configPath string,
	sponsorshipBinding *SponsorshipCustodyBinding,
	frozenIdentity *tosctlFrozenCustodyIdentity) (commerce.AgreementPaymentEvidence, error) {
	if err := sink.validate(); err != nil {
		return commerce.AgreementPaymentEvidence{}, err
	}
	if request.NetworkID == "" || string(request.Destination) == "" || action.StableActionID != request.StableActionID {
		return commerce.AgreementPaymentEvidence{}, errors.New("TOS payment request is incomplete")
	}
	wallet, sourceAccount, feeReserve := sink.Wallet, sink.SourceAccount, sink.FeeReserveNanoTOS
	var networkDomain commerce.CustodyNetworkDomain
	var err error
	if frozenIdentity != nil {
		wallet, sourceAccount = frozenIdentity.wallet, frozenIdentity.sourceAccount
		feeReserve = frozenIdentity.feeReserve
		networkDomain, err = sink.custodyNetworkDomainAt(ctx, request, configPath, frozenIdentity.network)
	} else {
		networkDomain, err = sink.custodyNetworkDomain(ctx, request, configPath)
	}
	if err != nil {
		return commerce.AgreementPaymentEvidence{}, err
	}
	authorization, err := sink.Authority.AuthorizeCustodyPayment(action, fields, canonicalRequest, fence,
		request, sourceAccount, networkDomain, sponsorshipBinding)
	if err != nil {
		return commerce.AgreementPaymentEvidence{}, err
	}
	authorizationPath, cleanup, err := sink.writeAuthorization(authorization)
	if err != nil {
		return commerce.AgreementPaymentEvidence{}, err
	}
	defer cleanup()
	amount, err := strconv.ParseUint(request.Amount.AmountAtomic, 10, 64)
	if err != nil || amount == 0 {
		return commerce.AgreementPaymentEvidence{}, errors.New("TOS payment amount is invalid")
	}
	preparedRaw, err := sink.run(ctx, []string{"agent", "account", "economic-payment-prepare",
		"--wallet", wallet, "--target", string(request.Destination), "--amount-nanotos", strconv.FormatUint(amount, 10),
		"--fee-reserve-nanotos", strconv.FormatUint(feeReserve, 10), "--valid-until", strconv.FormatUint(authorization.ExpiresAtUnix, 10),
		"--authorization-file", authorizationPath, "--yes", "-c", configPath})
	if err != nil {
		return commerce.AgreementPaymentEvidence{}, fmt.Errorf("prepare Agreement payment: %w", err)
	}
	var prepared tosctlPaymentPrepared
	if err := decodeStrictJSON(preparedRaw, &prepared); err != nil {
		return commerce.AgreementPaymentEvidence{}, fmt.Errorf("decode tosctl prepared payment: %w", err)
	}
	if err := validateTOSCTLPreparedPayment(prepared, request, networkDomain, sourceAccount, amount,
		authorization.ExpiresAtUnix,
		sponsorshipBinding != nil); err != nil {
		return commerce.AgreementPaymentEvidence{}, err
	}
	// The exact custody authorization can only be issued while OpenFox's
	// authority record is PREPARED. Once tosctl has durably prepared the exact
	// signed BOC, move to SUBMITTED before the first broadcast socket write.
	// A crash after this point may resume/resubmit only this byte-identical BOC
	// from custody; it can never prepare, sign, or allocate a sequence for a
	// replacement top-up.
	if _, err := sink.Authority.Transition(action.StableActionID, action.ExactRequestDigest,
		commerce.ActionSubmitted, "", nil); err != nil {
		return commerce.AgreementPaymentEvidence{}, errors.New("establish durable custody submission boundary")
	}
	broadcastRaw, err := sink.run(ctx, []string{"agent", "account", "economic-payment-broadcast", "--wallet", wallet,
		"--stable-action-id", request.StableActionID, "--yes", "-c", configPath})
	if err != nil {
		// A transport error after submission is deliberately ambiguous. Resolve
		// the same stable action; never prepare or broadcast a replacement.
		if sponsorshipBinding != nil {
			return commerce.AgreementPaymentEvidence{}, errRelaySponsorshipTypedResolutionRequired
		}
		return sink.ResolvePayment(ctx, request)
	}
	var broadcast tosctlPaymentBroadcast
	if err := decodeStrictJSON(broadcastRaw, &broadcast); err != nil || broadcast.Schema != "tosctl.agent-account.agreement-payment-broadcast.v1" ||
		broadcast.StableActionID != request.StableActionID || broadcast.Account != sourceAccount ||
		broadcast.ExactSignedBOCDigest != prepared.ExactSignedBOCDigest || broadcast.State != "broadcasting" {
		return commerce.AgreementPaymentEvidence{}, errors.New("tosctl returned an unrelated broadcast result")
	}
	if sponsorshipBinding != nil {
		return commerce.AgreementPaymentEvidence{}, errRelaySponsorshipTypedResolutionRequired
	}
	return sink.ResolvePayment(ctx, request)
}

func (sink *TOSCTLPaymentSink) ManagesRelaySponsorshipSubmissionFence() bool {
	return sink != nil && sink.Authority != nil
}

func (sink *TOSCTLPaymentSink) ResolvePayment(ctx context.Context,
	request commerce.AgreementPaymentRequest) (commerce.AgreementPaymentEvidence, error) {
	if err := sink.validate(); err != nil {
		return commerce.AgreementPaymentEvidence{}, err
	}
	attempts := sink.ResolveAttempts
	if attempts == 0 {
		attempts = 30
	}
	interval := sink.ResolveInterval
	if interval <= 0 {
		interval = 2 * time.Second
	}
	args := []string{"agent", "account", "economic-payment-resolve", "--wallet", sink.Wallet,
		"--stable-action-id", request.StableActionID, "--max-transactions", strconv.FormatUint(uint64(sink.maximumTransactions()), 10),
		"--quorum-config"}
	args = append(args, sink.QuorumConfigPaths...)
	args = append(args, "-c", sink.ConfigPath)
	var lastErr error
	for attempt := uint32(0); attempt < attempts; attempt++ {
		raw, err := sink.run(ctx, args)
		if err == nil {
			return sink.evidence(request, raw)
		}
		lastErr = err
		if attempt+1 == attempts {
			break
		}
		select {
		case <-ctx.Done():
			return commerce.AgreementPaymentEvidence{}, ctx.Err()
		case <-time.After(interval):
		}
	}
	return commerce.AgreementPaymentEvidence{}, fmt.Errorf("resolve Agreement payment from TOS quorum: %w", lastErr)
}

// ResolveRelaySponsorshipEvidence translates only the strict tosctl v2 RPC
// corroboration artifact. It embeds the locally held canonical
// AgreementPaymentRequestV3; tosctl never gets to substitute that body. The
// result remains observed_unproven and cannot satisfy payment finality.
func (sink *TOSCTLPaymentSink) ResolveRelaySponsorshipEvidence(ctx context.Context,
	execution agentrelay.RelayExecutionRequest,
	request commerce.AgreementPaymentRequest) (agentrelay.SponsorshipResolution, error) {
	if err := sink.validate(); err != nil {
		return agentrelay.SponsorshipResolution{}, err
	}
	policy := relaySponsorshipReleasePolicyFromRequest(execution.QuoteRequest.Body)
	if policy.EvidenceClass != agentrelay.SponsorshipReleaseObservedUnproven ||
		!validRelaySponsorshipReleasePolicy(execution.QuoteRequest.Body.AssuranceLevel, policy) {
		return agentrelay.SponsorshipResolution{}, errors.New("tosctl RPC corroboration is not the signed owner release profile")
	}
	snapshot, err := sink.ensureCurrentRelaySponsorshipSnapshot()
	if err != nil {
		return agentrelay.SponsorshipResolution{}, err
	}
	return sink.resolveRelaySponsorshipEvidenceFromSnapshot(ctx, execution, request, snapshot)
}

func (sink *TOSCTLPaymentSink) resolveRelaySponsorshipEvidenceFromSnapshot(ctx context.Context,
	execution agentrelay.RelayExecutionRequest, request commerce.AgreementPaymentRequest,
	snapshot tosctlRelaySponsorshipSnapshot) (agentrelay.SponsorshipResolution, error) {
	policy := relaySponsorshipReleasePolicyFromRequest(execution.QuoteRequest.Body)
	if snapshot.policy != policy || sink.validateRelaySponsorshipSnapshot(snapshot) != nil {
		return agentrelay.SponsorshipResolution{}, errors.New("frozen tosctl corroboration snapshot conflicts with the signed release profile")
	}
	frozen := snapshot.frozenProvider()
	frozenNetwork, networkErr := sink.relaySponsorshipSnapshotNetwork(frozen)
	if request.SchemaVersion != 3 || networkErr != nil ||
		execution.QuoteRequest.Body.Network != frozenNetwork || request.NetworkID != frozenNetwork.NetworkID {
		return agentrelay.SponsorshipResolution{}, errors.New("tosctl sponsorship request lacks exact PaymentRequestV3 network binding")
	}
	configPath, err := sink.relaySponsorshipSnapshotPrimaryConfig(frozen)
	if err != nil {
		return agentrelay.SponsorshipResolution{}, err
	}
	args := []string{"agent", "account", "economic-payment-corroborate", "--wallet", snapshot.custodyWallet,
		"--stable-action-id", request.StableActionID,
		"--corroboration-snapshot", snapshot.manifestPath,
		"--corroboration-snapshot-identity", snapshot.identity,
		"--sponsorship-release-profile-digest", snapshot.policy.ProfileDigest, "-c", configPath}
	raw, err := sink.run(ctx, args)
	if err != nil {
		// A failed bounded query is unknown, never absence and never permission
		// to submit another top-up.
		return agentrelay.SponsorshipResolution{Status: agentrelay.SponsorshipResolutionUnknown}, nil
	}
	observation, err := sink.decodeRelaySponsorshipObservation(execution, request, raw,
		snapshot)
	if err != nil {
		return agentrelay.SponsorshipResolution{}, err
	}
	return agentrelay.SponsorshipResolution{Status: agentrelay.SponsorshipResolutionObservedUnproven,
		CreditObservation: &observation}, nil
}

func (sink *TOSCTLPaymentSink) VerifyRelaySponsorshipCreditObservation(_ context.Context,
	observation agentrelay.RelaySponsorshipCreditObservation, execution agentrelay.RelayExecutionRequest,
	request commerce.AgreementPaymentRequest) error {
	policy := relaySponsorshipReleasePolicyFromRequest(execution.QuoteRequest.Body)
	if sink == nil ||
		observation.EvidenceProfileURI != policy.ProfileURI || observation.EvidenceProfileDigest != policy.ProfileDigest {
		return errors.New("sponsorship observation differs from the owner-pinned profile")
	}
	digest, err := agentrelay.RelaySponsorshipCreditObservationDigest(observation)
	if err != nil {
		return err
	}
	if !sink.hasVerifiedSponsorshipObservation(digest) {
		return errors.New("sponsorship observation was not produced by the strict owner-pinned tosctl verifier")
	}
	projected := agentrelay.RelaySponsorshipTransactionEvidence{
		AgreementPaymentRequestDigest: observation.AgreementPaymentRequestDigest,
		SponsorshipStableActionID:     observation.SponsorshipStableActionID,
		SponsorshipExactRequestDigest: observation.SponsorshipExactRequestDigest,
		ProviderSponsorValidUntilUnix: observation.ProviderSponsorValidUntilUnix,
	}
	return validateRelaySponsorshipPaymentBinding(execution, request, projected)
}

func (sink *TOSCTLPaymentSink) VerifyRelaySponsorshipCreditObservationFromSnapshot(ctx context.Context,
	observation agentrelay.RelaySponsorshipCreditObservation, execution agentrelay.RelayExecutionRequest,
	request commerce.AgreementPaymentRequest, frozen RelaySponsorshipEvidenceSnapshot) error {
	release := agentrelay.SponsorshipReleaseProfile{
		EvidenceClass: agentrelay.SponsorshipReleaseEvidenceClass(frozen.EvidenceClass),
		ProfileURI:    frozen.ProfileURI, ProfileDigest: frozen.ProfileDigest}
	if sink == nil || sink.ValidateRelaySponsorshipEvidenceSnapshot(release, frozen) != nil ||
		release != execution.QuoteRequest.Body.SelectedSponsorshipReleaseProfile() ||
		observation.EvidenceProfileURI != frozen.ProfileURI ||
		observation.EvidenceProfileDigest != frozen.ProfileDigest {
		return errors.New("sponsorship observation changes its frozen evidence snapshot")
	}
	return sink.VerifyRelaySponsorshipCreditObservation(ctx, observation, execution, request)
}

// VerifySponsorshipCreditObservation is the provider-side protocol gate. A
// typed observation is accepted only when this process first reconstructed
// the complete frozen tosctl descriptor, strict-majority winner, and all
// framed Rust observation digests in ResolveRelaySponsorshipEvidence.
func (sink *TOSCTLPaymentSink) VerifySponsorshipCreditObservation(_ context.Context,
	observation agentrelay.RelaySponsorshipCreditObservation,
	profile agentrelay.SponsorshipReleaseProfile) error {
	policy := RelaySponsorshipReleasePolicy{EvidenceClass: profile.EvidenceClass,
		ProfileURI: profile.ProfileURI, ProfileDigest: profile.ProfileDigest}
	if sink == nil || observation.EvidenceProfileURI != policy.ProfileURI ||
		observation.EvidenceProfileDigest != policy.ProfileDigest {
		return errors.New("sponsorship observation differs from the selected release profile")
	}
	digest, err := agentrelay.RelaySponsorshipCreditObservationDigest(observation)
	if err != nil {
		return err
	}
	if !sink.hasVerifiedSponsorshipObservation(digest) {
		return errors.New("sponsorship observation lacks a reconstructed tosctl quorum artifact")
	}
	return nil
}

func (sink *TOSCTLPaymentSink) RelaySponsorshipEvidenceCapabilities() RelaySponsorshipEvidenceCapabilities {
	if sink == nil || sink.RelaySponsorshipReleasePolicy.EvidenceClass !=
		agentrelay.SponsorshipReleaseObservedUnproven ||
		!validRelaySponsorshipReleasePolicy(agentrelay.AssuranceAuthorizedSingleProvider,
			sink.RelaySponsorshipReleasePolicy) {
		return RelaySponsorshipEvidenceCapabilities{}
	}
	if _, err := sink.ensureCurrentRelaySponsorshipSnapshot(); err != nil {
		return RelaySponsorshipEvidenceCapabilities{}
	}
	terminal := false
	for _, profile := range sink.RelayTerminalFinalityProfiles {
		terminal = terminal || sink.SupportsRelaySponsorshipTerminalFinalityProfile(profile, nil)
	}
	if !terminal {
		return RelaySponsorshipEvidenceCapabilities{}
	}
	return RelaySponsorshipEvidenceCapabilities{SupportedReleasePolicies: []RelaySponsorshipReleasePolicy{
		sink.RelaySponsorshipReleasePolicy}, FreshBalanceSequenceRecheck: true,
		TerminalEvidence: true}
}

func (sink *TOSCTLPaymentSink) FreezeRelaySponsorshipEvidenceSnapshot(_ context.Context,
	execution agentrelay.RelayExecutionRequest) (RelaySponsorshipEvidenceSnapshot, error) {
	snapshot, err := sink.ensureCurrentRelaySponsorshipSnapshot()
	if err != nil || sink.RelayNetworkDomain == nil ||
		execution.QuoteRequest.Body.Network != *sink.RelayNetworkDomain ||
		snapshot.policy != relaySponsorshipReleasePolicyFromRequest(execution.QuoteRequest.Body) {
		return RelaySponsorshipEvidenceSnapshot{}, errors.New("current corroboration snapshot does not match the signed execution")
	}
	if !validFrozenRelayCustodyLocator(snapshot.custodyWallet) ||
		!validFrozenRelayCustodyLocator(snapshot.providerSource) || snapshot.feeReserveNanoTOS == 0 {
		return RelaySponsorshipEvidenceSnapshot{}, errors.New("current provider custody identity is not freezeable")
	}
	return snapshot.frozenProvider(), nil
}

func (sink *TOSCTLPaymentSink) ValidateRelaySponsorshipEvidenceSnapshot(
	profile agentrelay.SponsorshipReleaseProfile, frozen RelaySponsorshipEvidenceSnapshot) error {
	policy := RelaySponsorshipReleasePolicy{EvidenceClass: profile.EvidenceClass,
		ProfileURI: profile.ProfileURI, ProfileDigest: profile.ProfileDigest}
	if frozen.SchemaVersion != 2 || frozen.EvidenceClass != string(policy.EvidenceClass) ||
		frozen.ProfileURI != policy.ProfileURI || frozen.ProfileDigest != policy.ProfileDigest ||
		!validFrozenRelayCustodyLocator(frozen.CustodyWallet) ||
		!validFrozenRelayCustodyLocator(frozen.ProviderSourceAccount) || frozen.FeeReserveNanoTOS == 0 {
		return errors.New("frozen corroboration snapshot changes the signed release profile")
	}
	return sink.validateRelaySponsorshipSnapshot(relayTOSCTLSponsorshipSnapshot(profile, frozen))
}

func (sink *TOSCTLPaymentSink) ResolveRelaySponsorshipEvidenceFromSnapshot(ctx context.Context,
	execution agentrelay.RelayExecutionRequest, request commerce.AgreementPaymentRequest,
	frozen RelaySponsorshipEvidenceSnapshot) (agentrelay.SponsorshipResolution, error) {
	profile := execution.QuoteRequest.Body.SelectedSponsorshipReleaseProfile()
	if err := sink.ValidateRelaySponsorshipEvidenceSnapshot(profile, frozen); err != nil {
		return agentrelay.SponsorshipResolution{}, err
	}
	return sink.resolveRelaySponsorshipEvidenceFromSnapshot(ctx, execution, request,
		relayTOSCTLSponsorshipSnapshot(profile, frozen))
}

func (sink *TOSCTLPaymentSink) decodeRelaySponsorshipObservation(execution agentrelay.RelayExecutionRequest,
	request commerce.AgreementPaymentRequest, raw []byte,
	snapshot tosctlRelaySponsorshipSnapshot) (agentrelay.RelaySponsorshipCreditObservation, error) {
	var result tosctlRelaySponsorshipObserved
	if err := decodeStrictJSON(raw, &result); err != nil {
		return agentrelay.RelaySponsorshipCreditObservation{}, errors.New("decode strict tosctl sponsorship corroboration v2")
	}
	paymentDigest, digestErr := commerce.AgreementPaymentRequestDigest(request)
	canonical, _, materialErr := commerce.PaymentAuthorizationMaterial(request)
	exactDigest, exactErr := commerce.ExactRequestDigest(canonical)
	amount, amountErr := strconv.ParseUint(request.Amount.AmountAtomic, 10, 64)
	policy := relaySponsorshipReleasePolicyFromRequest(execution.QuoteRequest.Body)
	reserved := execution.ProviderQuote.Body.ReservedSponsorship
	frozenNetwork, networkErr := sink.relaySponsorshipSnapshotNetwork(snapshot.frozenProvider())
	now := time.Now().UTC()
	if sink.Now != nil {
		now = sink.Now().UTC()
	}
	if digestErr != nil || materialErr != nil || exactErr != nil || amountErr != nil || networkErr != nil || reserved == nil ||
		result.Schema != "tosctl.agent-account.agreement-payment-rpc-corroboration.v2" ||
		result.StableActionID != request.StableActionID || result.SponsorshipStableActionID != request.StableActionID ||
		result.SponsorshipExactRequestDigest != exactDigest || result.AgreementPaymentRequestDigest != paymentDigest ||
		result.AgreementBodyDigest != request.AgreementBodyDigest ||
		result.ObligationInstanceID != request.ObligationInstanceID ||
		result.ProviderSponsorSourceAccount != snapshot.providerSource ||
		result.ProviderSponsorValidUntilUnix != request.ExpiresAtUnix ||
		result.DestinationSourceAccount != string(request.Destination) ||
		result.Destination != string(request.Destination) || result.AmountNanoTOS != amount ||
		result.NetworkGlobalID != frozenNetwork.GlobalID ||
		result.NetworkDomain != frozenNetwork || result.NetworkDomain != execution.QuoteRequest.Body.Network ||
		result.EvidenceProfileURI != policy.ProfileURI || result.EvidenceProfileDigest != policy.ProfileDigest ||
		result.EvidenceProfile.ProfileURI != policy.ProfileURI ||
		result.EvidenceProfile.NetworkDomain != result.NetworkDomain ||
		result.EvidenceProfile.MaximumHistoryTransactions != snapshot.maximumTransactions ||
		result.CorroborationSnapshot != snapshot.manifestPath ||
		result.CorroborationSnapshotIdentity != snapshot.identity ||
		!result.EvidenceProfile.StrictMajority || !result.EvidenceProfile.ExactSubmittedMessage ||
		!result.EvidenceProfile.ExactDestinationCredit || result.EvidenceProfile.ValidatorFinalityProven ||
		result.Finality != "unproven" || result.State != "observed_unproven" ||
		result.CustodyState != "broadcasting" || result.MissingProof == "" ||
		result.ObservedAtUnix == 0 || result.ObservedAtUnix > uint64(now.Add(5*time.Minute).Unix()) ||
		result.ProviderSponsorValidUntilUnix <= uint64(now.Unix()) ||
		result.Quorum.Members < 3 || result.Quorum.Threshold < 2 ||
		result.Quorum.Agreeing < result.Quorum.Threshold {
		return agentrelay.RelaySponsorshipCreditObservation{}, errors.New("tosctl sponsorship corroboration conflicts with the exact payment or policy")
	}
	if reserved.AmountAtomic != request.Amount.AmountAtomic || reserved.Asset.AssetNamespace != request.Amount.AssetNamespace ||
		reserved.Asset.AssetIdentifier != request.Amount.AssetIdentifier || reserved.Asset.Unit != request.Amount.Unit {
		return agentrelay.RelaySponsorshipCreditObservation{}, errors.New("tosctl sponsorship amount differs from the signed quote")
	}
	if err := verifyTOSCTLSponsorshipCorroboration(result, policy); err != nil {
		return agentrelay.RelaySponsorshipCreditObservation{}, err
	}
	if result.Evidence.TransactionHash != result.SubmittedTransactionHash ||
		result.Evidence.NetworkGlobalID != result.NetworkGlobalID || result.Evidence.FinalityProven ||
		uint64(result.Evidence.ObservedMasterchainSeqno) != result.ObservedCheckpointSequence ||
		result.Evidence.ObservedMasterchainGenUTime != result.ObservedCheckpointUnix ||
		result.SourceExecutionReference != result.SubmittedTransactionHash ||
		len(result.DestinationCreditReferences) != 1 ||
		result.DestinationCreditReferences[0] != result.Evidence.DestinationCreditReference ||
		result.ObservedCheckpointID != fmt.Sprintf("masterchain:%d:%d:%d:%s:%s",
			result.Evidence.ObservedMasterchainWorkchain, result.Evidence.ObservedMasterchainShard,
			result.Evidence.ObservedMasterchainSeqno, result.Evidence.ObservedMasterchainRootHash,
			result.Evidence.ObservedMasterchainFileHash) {
		return agentrelay.RelaySponsorshipCreditObservation{}, errors.New("tosctl sponsorship winner differs from the bound checkpoint")
	}
	observation := agentrelay.RelaySponsorshipCreditObservation{SchemaVersion: 1,
		NetworkDigest: request.NetworkDomainDigest, AgreementPaymentRequest: request,
		AgreementPaymentRequestDigest: paymentDigest, SponsorshipStableActionID: request.StableActionID,
		ProviderSponsorSourceAccount:         result.ProviderSponsorSourceAccount,
		ProviderSponsorSourceSequence:        result.ProviderSponsorSourceSequence,
		ProviderSponsorValidUntilUnix:        result.ProviderSponsorValidUntilUnix,
		SignedTopUpTransactionDigest:         result.SignedTopUpTransactionDigest,
		SignedTopUpTransactionCellHash:       result.SignedTopUpTransactionCellHash,
		SponsorshipPaymentCommitmentCellHash: result.SponsorshipPaymentCommitmentCellHash,
		DestinationSourceAccount:             result.DestinationSourceAccount, Amount: *reserved,
		SubmittedTransactionHash:    result.SubmittedTransactionHash,
		SourceExecutionReference:    result.SourceExecutionReference,
		DestinationCreditReferences: append([]string(nil), result.DestinationCreditReferences...),
		EvidenceProfileURI:          result.EvidenceProfileURI, EvidenceProfileDigest: result.EvidenceProfileDigest,
		ObservedCheckpointID:       result.ObservedCheckpointID,
		ObservedCheckpointSequence: result.ObservedCheckpointSequence,
		ObservedCheckpointUnix:     result.ObservedCheckpointUnix,
		ObservationDigests:         append([]string(nil), result.ObservationDigests...), ObservedAtUnix: result.ObservedAtUnix}
	observation.SponsorshipExactRequestDigest = exactDigest
	digest, err := agentrelay.RelaySponsorshipCreditObservationDigest(observation)
	if err != nil {
		return agentrelay.RelaySponsorshipCreditObservation{}, errors.New("tosctl sponsorship corroboration does not form a canonical observation")
	}
	sink.rememberVerifiedSponsorshipObservation(digest, observation.ProviderSponsorValidUntilUnix)
	return observation, nil
}

func (sink *TOSCTLPaymentSink) evidence(request commerce.AgreementPaymentRequest, raw []byte) (commerce.AgreementPaymentEvidence, error) {
	var result tosctlPaymentFinalized
	if err := decodeStrictJSON(raw, &result); err != nil || result.Schema != "tosctl.agent-account.agreement-payment-finalized.v1" ||
		result.StableActionID != request.StableActionID || result.AgreementBodyDigest != request.AgreementBodyDigest ||
		result.ObligationInstanceID != request.ObligationInstanceID || result.SourceAccount != sink.SourceAccount ||
		result.Destination != string(request.Destination) || result.NetworkGlobalID != sink.NetworkGlobalID || result.State != "finalized" ||
		result.Quorum.Members < 3 || result.Quorum.Threshold < 2 || result.Quorum.Agreeing < result.Quorum.Threshold || len(result.Evidence) == 0 {
		return commerce.AgreementPaymentEvidence{}, errors.New("tosctl returned unrelated or insufficient finality evidence")
	}
	amount, err := strconv.ParseUint(request.Amount.AmountAtomic, 10, 64)
	if err != nil || result.AmountNanoTOS != amount {
		return commerce.AgreementPaymentEvidence{}, errors.New("tosctl finality evidence has the wrong amount")
	}
	requestDigest, err := commerce.AgreementPaymentRequestDigest(request)
	if err != nil {
		return commerce.AgreementPaymentEvidence{}, err
	}
	var observation tosctlPaymentObservation
	if err := decodeStrictJSON(result.Evidence, &observation); err != nil || observation.TransactionHash == "" || observation.BlockRootHash == "" || observation.TransactionUTime == 0 {
		return commerce.AgreementPaymentEvidence{}, errors.New("tosctl finality observation is incomplete")
	}
	return commerce.AgreementPaymentEvidence{PaymentRequestDigest: requestDigest, StableActionID: request.StableActionID,
		ExactTransferReference: observation.TransactionHash, AdapterEvidenceProfile: tosQuorumEvidenceProfile,
		ResolvedState: "finalized", ResolvedAtUnix: observation.TransactionUTime,
		FinalityReference: observation.BlockRootHash, Evidence: append([]byte(nil), raw...)}, nil
}

// VerifyPaymentEvidence independently re-parses the complete quorum artifact
// instead of trusting the evidence fields returned by SubmitPayment.
func (sink *TOSCTLPaymentSink) VerifyPaymentEvidence(request commerce.AgreementPaymentRequest,
	evidence commerce.AgreementPaymentEvidence, now time.Time) error {
	if evidence.ResolvedAtUnix > uint64(now.UTC().Unix()) {
		return errors.New("TOS payment evidence is from the future")
	}
	rebuilt, err := sink.evidence(request, evidence.Evidence)
	if err != nil || rebuilt.PaymentRequestDigest != evidence.PaymentRequestDigest || rebuilt.StableActionID != evidence.StableActionID ||
		rebuilt.ExactTransferReference != evidence.ExactTransferReference || rebuilt.AdapterEvidenceProfile != evidence.AdapterEvidenceProfile ||
		rebuilt.ResolvedState != evidence.ResolvedState || rebuilt.ResolvedAtUnix != evidence.ResolvedAtUnix || rebuilt.FinalityReference != evidence.FinalityReference {
		return errors.New("TOS payment evidence fields differ from the verified quorum artifact")
	}
	return nil
}

func (sink *TOSCTLPaymentSink) validate() error {
	if sink == nil || sink.Authority == nil || !filepath.IsAbs(sink.Executable) || !filepath.IsAbs(sink.ConfigPath) ||
		!filepath.IsAbs(sink.EvidenceDirectory) || sink.Wallet == "" || sink.SourceAccount == "" || sink.NetworkGlobalID == 0 ||
		sink.RelayNetworkDomain == nil || sink.RelayNetworkDomain.GlobalID != sink.NetworkGlobalID ||
		sink.FeeReserveNanoTOS == 0 || len(sink.QuorumConfigPaths) < 2 || sink.maximumTransactions() > 10_000 {
		return errors.New("TOS custody payment Adapter configuration is invalid")
	}
	if err := sink.freezeVaultCapability(); err != nil {
		return errors.New("TOS custody payment Adapter vault capability is invalid")
	}
	if _, err := agentrelay.NetworkDomainDigest(*sink.RelayNetworkDomain); err != nil {
		return errors.New("TOS custody payment Adapter network domain is invalid")
	}
	// Test and embedding callbacks are still output-bounded by run(), but only
	// the production subprocess path has an executable to enroll. Enrolling at
	// validation time makes replacement between authority admission and launch
	// detectable; the launch path reopens and snapshots the same identity.
	if sink.Run == nil {
		if err := sink.pinTOSCTLExecutable(); err != nil {
			return errors.New("TOS custody payment Adapter executable is untrusted")
		}
	}
	seen := map[string]bool{filepath.Clean(sink.ConfigPath): true}
	for _, path := range sink.QuorumConfigPaths {
		if !filepath.IsAbs(path) || seen[filepath.Clean(path)] {
			return errors.New("TOS custody quorum configs must be distinct absolute paths")
		}
		seen[filepath.Clean(path)] = true
	}
	return nil
}

func (sink *TOSCTLPaymentSink) maximumTransactions() uint32 {
	if sink.MaximumTransactions == 0 {
		return 1000
	}
	return sink.MaximumTransactions
}

func (sink *TOSCTLPaymentSink) sponsorshipNow() time.Time {
	if sink != nil && sink.Now != nil {
		return sink.Now().UTC()
	}
	return time.Now().UTC()
}

func (sink *TOSCTLPaymentSink) rememberVerifiedSponsorshipObservation(digest string, expiresAtUnix uint64) {
	if sink == nil || !validSHA256Digest(digest) || expiresAtUnix == 0 {
		return
	}
	now := uint64(sink.sponsorshipNow().Unix())
	sink.verifiedSponsorshipMu.Lock()
	defer sink.verifiedSponsorshipMu.Unlock()
	if sink.verifiedSponsorshipObservations == nil {
		sink.verifiedSponsorshipObservations = make(map[string]uint64)
	}
	for candidate, expiry := range sink.verifiedSponsorshipObservations {
		if expiry <= now {
			delete(sink.verifiedSponsorshipObservations, candidate)
		}
	}
	for len(sink.verifiedSponsorshipObservations) >= maximumVerifiedSponsorshipObservationRefs {
		oldestDigest, oldestExpiry := "", ^uint64(0)
		for candidate, expiry := range sink.verifiedSponsorshipObservations {
			if expiry < oldestExpiry || expiry == oldestExpiry && candidate < oldestDigest {
				oldestDigest, oldestExpiry = candidate, expiry
			}
		}
		delete(sink.verifiedSponsorshipObservations, oldestDigest)
	}
	sink.verifiedSponsorshipObservations[digest] = expiresAtUnix
}

func (sink *TOSCTLPaymentSink) hasVerifiedSponsorshipObservation(digest string) bool {
	if sink == nil || !validSHA256Digest(digest) {
		return false
	}
	now := uint64(sink.sponsorshipNow().Unix())
	sink.verifiedSponsorshipMu.Lock()
	defer sink.verifiedSponsorshipMu.Unlock()
	expiry, ok := sink.verifiedSponsorshipObservations[digest]
	if !ok || expiry <= now {
		delete(sink.verifiedSponsorshipObservations, digest)
		return false
	}
	return true
}

func (sink *TOSCTLPaymentSink) writeAuthorization(authorization commerce.CustodyActionAuthorization) (string, func(), error) {
	if err := os.MkdirAll(sink.EvidenceDirectory, 0o700); err != nil {
		return "", func() {}, err
	}
	info, err := os.Lstat(sink.EvidenceDirectory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return "", func() {}, errors.New("custody evidence directory must be private")
	}
	file, err := os.CreateTemp(sink.EvidenceDirectory, ".economic-authorization-*.json")
	if err != nil {
		return "", func() {}, err
	}
	path := file.Name()
	cleanup := func() { _ = os.Remove(path) }
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		cleanup()
		return "", func() {}, err
	}
	encoder := json.NewEncoder(file)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(authorization); err != nil {
		_ = file.Close()
		cleanup()
		return "", func() {}, err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		cleanup()
		return "", func() {}, err
	}
	if err := file.Close(); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return path, cleanup, nil
}

func (sink *TOSCTLPaymentSink) run(ctx context.Context, args []string) ([]byte, error) {
	if sink == nil || ctx == nil || sink.freezeVaultCapability() != nil {
		return nil, errors.New("tosctl command capability is invalid")
	}
	// Custody does not inherit loader, proxy, HOME, PATH, certificate, cloud or
	// wallet-selection variables from the long-running Agent. The explicit
	// vault capability is the only environment input accepted by this adapter.
	env := []string{}
	if sink.VaultURL != "" {
		env = append(env, "VAULT_URL="+sink.VaultURL)
	}
	if sink.Run != nil {
		output, err := sink.Run(ctx, append([]string(nil), args...), env)
		if err != nil {
			return nil, errors.New("tosctl command failed")
		}
		if len(output) > maximumTOSCTLCommandOutputBytes {
			return nil, errors.New("tosctl output exceeded its shared byte budget")
		}
		// Do not retain a callback-owned backing array whose capacity may be much
		// larger than the accepted response budget.
		return append([]byte(nil), output...), nil
	}
	return sink.runPinnedTOSCTL(ctx, args, env)
}

func (sink *TOSCTLPaymentSink) freezeVaultCapability() error {
	if sink == nil || len(sink.VaultURL) > 4096 || strings.ContainsAny(sink.VaultURL, "\x00\r\n") {
		return errors.New("invalid bounded tosctl vault capability")
	}
	digest := sha256.Sum256([]byte(sink.VaultURL))
	sink.executableMu.Lock()
	defer sink.executableMu.Unlock()
	if !sink.vaultCapabilityPinned {
		sink.vaultCapabilityPinned = true
		sink.vaultCapabilityDigest = digest
		return nil
	}
	if sink.vaultCapabilityDigest != digest {
		return errors.New("tosctl vault capability changed after enrollment")
	}
	return nil
}

// tosctlExecutableIdentity is compared on every launch. Device/inode prevent a
// rename substitution and the canonical SHA-256 digest detects in-place byte
// changes even when a file happens to retain its metadata.
type tosctlExecutableIdentity struct {
	device uint64
	inode  uint64
	size   int64
	digest [32]byte
}

// tosctlSharedOutput enforces one aggregate budget across stdout and stderr.
// Stderr is deliberately not retained: custody tools may include sensitive
// paths or backend details in diagnostics, and callers receive only bounded,
// stable error categories.
type tosctlSharedOutput struct {
	mu         sync.Mutex
	stdout     bytes.Buffer
	total      int
	exceeded   bool
	stderrSeen bool
	// A bounded prefix of what the adapter wrote to stderr. The custody path
	// deliberately discards adapter output from its result, but discarding it
	// from the failure message too leaves an operator with "tosctl command
	// failed" and no way to tell a misconfigured network pin from an expired
	// authorization. Bounded so a chatty or hostile adapter cannot grow the
	// error, and only ever read on the failure path.
	stderrPrefix []byte
}

// maximumTOSCTLDiagnosticBytes bounds the adapter stderr kept for diagnosis.
const maximumTOSCTLDiagnosticBytes = 512

func (output *tosctlSharedOutput) diagnostic() string {
	if output == nil {
		return ""
	}
	output.mu.Lock()
	defer output.mu.Unlock()
	return redactTOSCTLDiagnostic(strings.TrimSpace(string(output.stderrPrefix)))
}

// redactTOSCTLDiagnostic removes vault material from adapter output before it
// reaches an error string. The adapter is handed VAULT_URL, whose query carries
// the master key, so any adapter path that echoes its own configuration would
// copy that key into an error the caller is free to log. No tosctl failure
// observed today echoes it; this holds regardless of which paths the adapter
// grows later, which the caller cannot audit.
func redactTOSCTLDiagnostic(value string) string {
	const marker = "master_key="
	for searched := 0; ; {
		found := strings.Index(value[searched:], marker)
		if found < 0 {
			return value
		}
		secret := searched + found + len(marker)
		end := secret
		for end < len(value) && !strings.ContainsRune("&\"' \t\r\n", rune(value[end])) {
			end++
		}
		if end == secret {
			searched = secret
			continue
		}
		value = value[:secret] + "[redacted]" + value[end:]
		searched = secret + len("[redacted]")
	}
}

type tosctlOutputWriter struct {
	output *tosctlSharedOutput
	stderr bool
}

func (writer tosctlOutputWriter) Write(value []byte) (int, error) {
	if writer.output == nil {
		return 0, errors.New("tosctl output sink is unavailable")
	}
	writer.output.mu.Lock()
	defer writer.output.mu.Unlock()
	if writer.stderr {
		writer.output.stderrSeen = writer.output.stderrSeen || len(value) != 0
		if room := maximumTOSCTLDiagnosticBytes - len(writer.output.stderrPrefix); room > 0 {
			writer.output.stderrPrefix = append(writer.output.stderrPrefix, value[:min(room, len(value))]...)
		}
	}
	remaining := maximumTOSCTLCommandOutputBytes - writer.output.total
	if remaining <= 0 {
		writer.output.exceeded = true
		return 0, errors.New("tosctl output exceeded limit")
	}
	accepted := len(value)
	if accepted > remaining {
		accepted = remaining
		writer.output.exceeded = true
	}
	if !writer.stderr && accepted != 0 {
		_, _ = writer.output.stdout.Write(value[:accepted])
	}
	writer.output.total += accepted
	if accepted != len(value) {
		return accepted, errors.New("tosctl output exceeded limit")
	}
	return accepted, nil
}

func (output *tosctlSharedOutput) result() ([]byte, bool, bool) {
	if output == nil {
		return nil, false, false
	}
	output.mu.Lock()
	defer output.mu.Unlock()
	return append([]byte(nil), output.stdout.Bytes()...), output.stderrSeen, output.exceeded
}
