package prediction

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tosutils-go/address"
	"github.com/tosnetwork/tosutils-go/tvm/cell"

	"github.com/tosnetwork/openfox/pkg/fileutil"
)

const (
	relaySchemaVersion      = 1
	maximumRelayRecordBytes = 4 << 20
	maximumChainBOCBytes    = 2 << 20
)

var ErrPredictionEvidencePending = errors.New("prediction relay evidence is not final yet")

type RelayState string

const (
	RelaySigned                         RelayState = "signed"
	RelayBroadcasting                   RelayState = "broadcasting"
	RelaySourceFinalized                RelayState = "source_finalized"
	RelaySourceActionSkipped            RelayState = "source_action_skipped"
	RelayDestinationCommitted           RelayState = "destination_committed"
	RelayDestinationFailedBounceCreated RelayState = "destination_failed_bounce_created"
	RelayBounceCreditedAtAgent          RelayState = "bounce_credited_at_agent"
	RelayDestinationFailedNoBounce      RelayState = "destination_failed_no_bounce"
)

// PredictionRelayProfile freezes every identity used to interpret chain
// evidence. ObserverIDs are independent RPC/config identities, not URLs that
// may silently change ownership after an action has been signed.
type PredictionRelayProfile struct {
	NetworkDomainHash          string   `json:"network_domain_hash"`
	SourceAgentAccount         string   `json:"source_agent_account"`
	SourceAgentAccountCodeHash string   `json:"source_agent_account_code_hash"`
	MarketAddress              string   `json:"market_address"`
	MarketID                   string   `json:"market_id"`
	MarketCodeHash             string   `json:"market_code_hash"`
	MarketConfigHash           string   `json:"market_config_hash"`
	ObserverIDs                []string `json:"observer_ids"`
	QuorumThreshold            uint32   `json:"quorum_threshold"`
	MaximumOutstanding         uint32   `json:"maximum_outstanding"`
	MaximumSignedBOCBytes      uint32   `json:"maximum_signed_boc_bytes"`
	MinimumNoBounceMCBlocks    uint32   `json:"minimum_no_bounce_masterchain_blocks"`
}

type AccountCursor struct {
	AccountAddress      string `json:"account_address"`
	LastLogicalTime     uint64 `json:"last_logical_time"`
	LastTransactionHash string `json:"last_transaction_hash"`
}

type BlockIdentity struct {
	WorkchainID         int32  `json:"workchain_id"`
	Shard               int64  `json:"shard"`
	SequenceNumber      uint32 `json:"sequence_number"`
	RootHash            string `json:"root_hash"`
	FileHash            string `json:"file_hash"`
	MasterchainSequence uint32 `json:"masterchain_sequence_number"`
}

type QuorumFinality struct {
	NetworkDomainHash string   `json:"network_domain_hash"`
	FinalityViewID    string   `json:"finality_view_id"`
	ObserverIDs       []string `json:"observer_ids"`
	AgreeingIDs       []string `json:"agreeing_ids"`
	Threshold         uint32   `json:"threshold"`
	MasterchainSeqno  uint32   `json:"masterchain_seqno"`
}

type ExpectedContractCall struct {
	ActionKind             string `json:"action_kind"`
	StableActionID         string `json:"stable_action_id"`
	TargetAddress          string `json:"target_address"`
	ValueNanoTOS           uint64 `json:"value_nanotos"`
	BodyBOCBase64          string `json:"body_boc_base64"`
	BodyHash               string `json:"body_hash"`
	StateInitBOCBase64     string `json:"state_init_boc_base64,omitempty"`
	StateInitHash          string `json:"state_init_hash,omitempty"`
	Bounce                 bool   `json:"bounce"`
	ExtraFlags             uint64 `json:"extra_flags"`
	Opcode                 uint32 `json:"opcode"`
	SuccessPredicateDigest string `json:"success_predicate_digest"`
}

// ChainObservedMessage is reconstructed from a transaction BOC. Its hash is
// over ExactMessageBOC, including the chain-filled fee/time fields.
type ChainObservedMessage struct {
	MessageHash        string `json:"message_hash"`
	ExactMessageBOC    string `json:"exact_message_boc_base64"`
	SourceAddress      string `json:"source_address"`
	DestinationAddress string `json:"destination_address"`
	ValueNanoTOS       uint64 `json:"value_nanotos"`
	BodyBOCBase64      string `json:"body_boc_base64"`
	BodyHash           string `json:"body_hash"`
	StateInitBOCBase64 string `json:"state_init_boc_base64,omitempty"`
	StateInitHash      string `json:"state_init_hash,omitempty"`
	Bounce             bool   `json:"bounce"`
	Bounced            bool   `json:"bounced"`
	ExtraFlags         uint64 `json:"extra_flags"`
}

type SourceTransactionEvidence struct {
	SubmittedExternalMessageHash string                 `json:"submitted_external_message_hash"`
	TransactionHash              string                 `json:"transaction_hash"`
	TransactionBOCBase64         string                 `json:"transaction_boc_base64"`
	Block                        BlockIdentity          `json:"block"`
	Finality                     QuorumFinality         `json:"finality"`
	NextSourceCursor             AccountCursor          `json:"next_source_cursor"`
	OutboundMessages             []ChainObservedMessage `json:"outbound_messages"`
}

type BoundedAbsenceEvidence struct {
	ScanStartMasterchainSeqno uint32   `json:"scan_start_masterchain_seqno"`
	ScanEndMasterchainSeqno   uint32   `json:"scan_end_masterchain_seqno"`
	ObservationDigests        []string `json:"observation_digests"`
	EvidenceSetDigest         string   `json:"evidence_set_digest"`
}

type DestinationTransactionEvidence struct {
	InboundMessageHash         string                  `json:"inbound_message_hash"`
	TransactionHash            string                  `json:"transaction_hash"`
	TransactionBOCBase64       string                  `json:"transaction_boc_base64"`
	Block                      BlockIdentity           `json:"block"`
	Finality                   QuorumFinality          `json:"finality"`
	NextDestinationCursor      AccountCursor           `json:"next_destination_cursor"`
	Ordinary                   bool                    `json:"ordinary"`
	Aborted                    bool                    `json:"aborted"`
	ComputeSuccess             bool                    `json:"compute_success"`
	ActionSuccess              bool                    `json:"action_success"`
	OpcodeSuccess              bool                    `json:"opcode_success"`
	MarketCodeHash             string                  `json:"market_code_hash"`
	MarketConfigHash           string                  `json:"market_config_hash"`
	SuccessPredicateDigest     string                  `json:"success_predicate_digest"`
	BounceMessage              *ChainObservedMessage   `json:"bounce_message,omitempty"`
	RichBounceEnvelopeHash     string                  `json:"rich_bounce_envelope_hash,omitempty"`
	RichBounceOriginalBodyHash string                  `json:"rich_bounce_original_body_hash,omitempty"`
	NoBounceProof              *BoundedAbsenceEvidence `json:"no_bounce_proof,omitempty"`
}

type BounceCreditEvidence struct {
	InboundBounceMessageHash string         `json:"inbound_bounce_message_hash"`
	TransactionHash          string         `json:"transaction_hash"`
	TransactionBOCBase64     string         `json:"transaction_boc_base64"`
	Block                    BlockIdentity  `json:"block"`
	Finality                 QuorumFinality `json:"finality"`
	NextSourceCursor         AccountCursor  `json:"next_source_cursor"`
	CreditedValueNanoTOS     uint64         `json:"credited_value_nanotos"`
}

type PredictionRelayRecord struct {
	SchemaVersion                     uint16                          `json:"schema_version"`
	Revision                          uint64                          `json:"revision"`
	ActionID                          string                          `json:"action_id"`
	Profile                           PredictionRelayProfile          `json:"profile"`
	Expected                          ExpectedContractCall            `json:"expected"`
	ExactSignedBOCBase64              string                          `json:"exact_signed_boc_base64"`
	ExactSignedBOCDigest              string                          `json:"exact_signed_boc_digest"`
	SubmittedExternalMessageHash      string                          `json:"submitted_external_message_hash"`
	PreBroadcastSourceCursor          AccountCursor                   `json:"pre_broadcast_source_cursor"`
	PreBroadcastMasterchainCheckpoint BlockIdentity                   `json:"pre_broadcast_masterchain_checkpoint"`
	State                             RelayState                      `json:"state"`
	BroadcastAttempts                 uint32                          `json:"broadcast_attempts"`
	SourceEvidence                    *SourceTransactionEvidence      `json:"source_evidence,omitempty"`
	ActualOutbound                    *ChainObservedMessage           `json:"actual_outbound,omitempty"`
	DestinationEvidence               *DestinationTransactionEvidence `json:"destination_evidence,omitempty"`
	BounceCreditEvidence              *BounceCreditEvidence           `json:"bounce_credit_evidence,omitempty"`
}

type PredictionExactBroadcaster interface {
	BroadcastExactPredictionBOC(ctx context.Context, boc []byte) error
}

// PredictionRelayEvidenceVerifier must parse full transaction/message BOCs
// and validate the quorum's signed/canonical block proof. The journal repeats
// all structural and identity checks so an implementation cannot weaken the
// state machine by returning a convenient boolean.
type PredictionRelayEvidenceVerifier interface {
	VerifyPredictionSource(ctx context.Context, record PredictionRelayRecord, evidence SourceTransactionEvidence) error
	VerifyPredictionDestination(
		ctx context.Context,
		record PredictionRelayRecord,
		evidence DestinationTransactionEvidence,
	) error
	VerifyPredictionBounceCredit(ctx context.Context, record PredictionRelayRecord, evidence BounceCreditEvidence) error
}

type PredictionRelayJournal struct {
	mu        sync.Mutex
	directory string
	lock      *os.File
	profile   PredictionRelayProfile
	records   map[string]PredictionRelayRecord
	inFlight  map[string]bool
}

func OpenPredictionRelayJournal(directory string, profile PredictionRelayProfile) (*PredictionRelayJournal, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || validateRelayProfile(profile) != nil {
		return nil, errors.New("prediction relay journal configuration is invalid")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return nil, errors.New("prediction relay journal directory must be owner-private")
	}
	lock, err := acquireBookLock(directory)
	if err != nil {
		return nil, err
	}
	journal := &PredictionRelayJournal{
		directory: directory,
		lock:      lock,
		profile:   cloneRelayProfile(profile),
		records:   map[string]PredictionRelayRecord{},
		inFlight:  map[string]bool{},
	}
	if err := journal.load(); err != nil {
		_ = releaseBookLock(lock)
		return nil, err
	}
	return journal, nil
}

func (journal *PredictionRelayJournal) Close() error {
	if journal == nil {
		return nil
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.lock == nil {
		return nil
	}
	err := releaseBookLock(journal.lock)
	journal.lock = nil
	return err
}

// Profile returns the immutable relay trust domain selected when the journal
// was opened. Callers use it to reject a builder artifact before asking Owner
// authority to sign.
func (journal *PredictionRelayJournal) Profile() (PredictionRelayProfile, bool) {
	if journal == nil {
		return PredictionRelayProfile{}, false
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.lock == nil {
		return PredictionRelayProfile{}, false
	}
	return cloneRelayProfile(journal.profile), true
}

func (journal *PredictionRelayJournal) Prepare(actionID string, exactSignedBOC []byte, expected ExpectedContractCall,
	sourceCursor AccountCursor, masterchainCheckpoint BlockIdentity,
) (PredictionRelayRecord, error) {
	if journal == nil || !canonicalDigest(actionID, "sha256:") || len(exactSignedBOC) == 0 {
		return PredictionRelayRecord{}, errors.New("prediction relay preparation is invalid")
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.lock == nil {
		return PredictionRelayRecord{}, errors.New("prediction relay journal is closed")
	}
	messageHash, err := canonicalCellDigest(exactSignedBOC, int(journal.profile.MaximumSignedBOCBytes))
	exactDigest := sha256Digest(exactSignedBOC)
	if err != nil || validateExpectedCall(expected, journal.profile, actionID) != nil ||
		validateAccountCursor(sourceCursor, journal.profile.SourceAgentAccount) != nil ||
		validateCheckpoint(masterchainCheckpoint) != nil || masterchainCheckpoint.WorkchainID != -1 ||
		masterchainCheckpoint.SequenceNumber != masterchainCheckpoint.MasterchainSequence {
		return PredictionRelayRecord{}, errors.New("prediction relay preparation material is invalid")
	}
	if prior, ok := journal.records[actionID]; ok {
		if prior.ExactSignedBOCDigest != exactDigest ||
			prior.ExactSignedBOCBase64 != base64.StdEncoding.EncodeToString(exactSignedBOC) ||
			!reflect.DeepEqual(prior.Expected, expected) ||
			!reflect.DeepEqual(prior.PreBroadcastSourceCursor, sourceCursor) ||
			!reflect.DeepEqual(prior.PreBroadcastMasterchainCheckpoint, masterchainCheckpoint) {
			return PredictionRelayRecord{}, errors.New("prediction action ID conflicts with durable exact material")
		}
		return cloneRelayRecord(prior), nil
	}
	if uint32(len(journal.records)) >= journal.profile.MaximumOutstanding {
		return PredictionRelayRecord{}, errors.New("prediction relay journal capacity is exhausted before signing")
	}
	record := PredictionRelayRecord{
		SchemaVersion: relaySchemaVersion, Revision: 1, ActionID: actionID,
		Profile: cloneRelayProfile(journal.profile), Expected: expected,
		ExactSignedBOCBase64: base64.StdEncoding.EncodeToString(exactSignedBOC), ExactSignedBOCDigest: exactDigest,
		SubmittedExternalMessageHash: messageHash, PreBroadcastSourceCursor: sourceCursor,
		PreBroadcastMasterchainCheckpoint: masterchainCheckpoint, State: RelaySigned,
	}
	if err := journal.persist(record); err != nil {
		return PredictionRelayRecord{}, err
	}
	journal.records[actionID] = record
	return cloneRelayRecord(record), nil
}

// BeginOrResumeExactBroadcast closes the classic crash window by durably
// entering Broadcasting before the socket write. Broadcasting retries resend
// only the same bytes. Any source-final state is a hard no-broadcast boundary.
func (journal *PredictionRelayJournal) BeginOrResumeExactBroadcast(ctx context.Context, actionID string,
	broadcaster PredictionExactBroadcaster,
) (PredictionRelayRecord, error) {
	if journal == nil || ctx == nil || broadcaster == nil {
		return PredictionRelayRecord{}, errors.New("prediction broadcast is unavailable")
	}
	journal.mu.Lock()
	record, ok := journal.records[actionID]
	if !ok || journal.lock == nil || (record.State != RelaySigned && record.State != RelayBroadcasting) {
		journal.mu.Unlock()
		return PredictionRelayRecord{}, errors.New("exact prediction BOC is no longer broadcastable")
	}
	if journal.inFlight[actionID] || record.BroadcastAttempts == ^uint32(0) {
		journal.mu.Unlock()
		return PredictionRelayRecord{}, errors.New("exact prediction BOC already has an in-flight broadcast")
	}
	raw, err := base64.StdEncoding.DecodeString(record.ExactSignedBOCBase64)
	if err != nil {
		journal.mu.Unlock()
		return PredictionRelayRecord{}, errors.New("durable exact prediction BOC is unavailable")
	}
	record.Revision++
	record.State = RelayBroadcasting
	record.BroadcastAttempts++
	if err := journal.persist(record); err != nil {
		journal.mu.Unlock()
		return PredictionRelayRecord{}, err
	}
	journal.records[actionID] = record
	journal.inFlight[actionID] = true
	journal.mu.Unlock()
	broadcastErr := broadcaster.BroadcastExactPredictionBOC(ctx, append([]byte(nil), raw...))
	journal.mu.Lock()
	delete(journal.inFlight, actionID)
	journal.mu.Unlock()
	if broadcastErr != nil {
		return cloneRelayRecord(record), broadcastErr
	}
	return cloneRelayRecord(record), nil
}

func (journal *PredictionRelayJournal) ResolveSource(ctx context.Context, actionID string,
	evidence SourceTransactionEvidence, verifier PredictionRelayEvidenceVerifier,
) (PredictionRelayRecord, error) {
	if journal == nil || ctx == nil || verifier == nil {
		return PredictionRelayRecord{}, errors.New("prediction source resolver is unavailable")
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	record, ok := journal.records[actionID]
	if !ok || journal.lock == nil || record.State != RelayBroadcasting || journal.inFlight[actionID] {
		return PredictionRelayRecord{}, errors.New("prediction source is not awaiting finality")
	}
	if err := validateSourceEvidence(record, evidence); err != nil {
		return PredictionRelayRecord{}, err
	}
	if err := verifier.VerifyPredictionSource(
		ctx,
		cloneRelayRecord(record),
		cloneSourceEvidence(evidence),
	); err != nil {
		return PredictionRelayRecord{}, fmt.Errorf("verify prediction source proof: %w", err)
	}
	record.Revision++
	record.SourceEvidence = ptrSourceEvidence(evidence)
	if len(evidence.OutboundMessages) == 0 {
		record.State = RelaySourceActionSkipped
	} else {
		record.State = RelaySourceFinalized
		outbound := evidence.OutboundMessages[0]
		record.ActualOutbound = &outbound
	}
	if err := journal.persist(record); err != nil {
		return PredictionRelayRecord{}, err
	}
	journal.records[actionID] = record
	return cloneRelayRecord(record), nil
}

func (journal *PredictionRelayJournal) ResolveDestination(ctx context.Context, actionID string,
	evidence DestinationTransactionEvidence, verifier PredictionRelayEvidenceVerifier,
) (PredictionRelayRecord, error) {
	if journal == nil || ctx == nil || verifier == nil {
		return PredictionRelayRecord{}, errors.New("prediction destination resolver is unavailable")
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	record, ok := journal.records[actionID]
	if !ok || journal.lock == nil || record.State != RelaySourceFinalized || record.ActualOutbound == nil {
		return PredictionRelayRecord{}, errors.New("prediction destination is not awaiting finality")
	}
	if err := validateDestinationEvidence(record, evidence); err != nil {
		return PredictionRelayRecord{}, err
	}
	if err := verifier.VerifyPredictionDestination(
		ctx,
		cloneRelayRecord(record),
		cloneDestinationEvidence(evidence),
	); err != nil {
		return PredictionRelayRecord{}, fmt.Errorf("verify prediction destination proof: %w", err)
	}
	record.Revision++
	record.DestinationEvidence = ptrDestinationEvidence(evidence)
	success := evidence.Ordinary && !evidence.Aborted && evidence.ComputeSuccess && evidence.ActionSuccess &&
		evidence.OpcodeSuccess
	if success {
		record.State = RelayDestinationCommitted
	} else if evidence.BounceMessage != nil {
		record.State = RelayDestinationFailedBounceCreated
	} else {
		record.State = RelayDestinationFailedNoBounce
	}
	if err := journal.persist(record); err != nil {
		return PredictionRelayRecord{}, err
	}
	journal.records[actionID] = record
	return cloneRelayRecord(record), nil
}

func (journal *PredictionRelayJournal) ResolveBounceCredit(ctx context.Context, actionID string,
	evidence BounceCreditEvidence, verifier PredictionRelayEvidenceVerifier,
) (PredictionRelayRecord, error) {
	if journal == nil || ctx == nil || verifier == nil {
		return PredictionRelayRecord{}, errors.New("prediction bounce resolver is unavailable")
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	record, ok := journal.records[actionID]
	if !ok || journal.lock == nil || record.State != RelayDestinationFailedBounceCreated ||
		record.DestinationEvidence == nil || record.DestinationEvidence.BounceMessage == nil {
		return PredictionRelayRecord{}, errors.New("prediction bounce is not awaiting credit")
	}
	if err := validateBounceCreditEvidence(record, evidence); err != nil {
		return PredictionRelayRecord{}, err
	}
	if err := verifier.VerifyPredictionBounceCredit(
		ctx,
		cloneRelayRecord(record),
		cloneBounceCreditEvidence(evidence),
	); err != nil {
		return PredictionRelayRecord{}, fmt.Errorf("verify prediction bounce credit proof: %w", err)
	}
	record.Revision++
	record.BounceCreditEvidence = ptrBounceCreditEvidence(evidence)
	record.State = RelayBounceCreditedAtAgent
	if err := journal.persist(record); err != nil {
		return PredictionRelayRecord{}, err
	}
	journal.records[actionID] = record
	return cloneRelayRecord(record), nil
}

func (journal *PredictionRelayJournal) Get(actionID string) (PredictionRelayRecord, bool) {
	if journal == nil {
		return PredictionRelayRecord{}, false
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	record, ok := journal.records[actionID]
	return cloneRelayRecord(record), ok
}

type PredictionReservationDisposition struct {
	ReleaseMarketExposure  bool
	ReleaseSourceLiquidity bool
	RealizeSourceLoss      bool
}

func (record PredictionRelayRecord) ReservationDisposition() PredictionReservationDisposition {
	switch record.State {
	case RelaySourceActionSkipped, RelayDestinationCommitted, RelayBounceCreditedAtAgent:
		return PredictionReservationDisposition{ReleaseMarketExposure: true, ReleaseSourceLiquidity: true}
	case RelayDestinationFailedBounceCreated:
		return PredictionReservationDisposition{ReleaseMarketExposure: true}
	case RelayDestinationFailedNoBounce:
		return PredictionReservationDisposition{ReleaseMarketExposure: true, RealizeSourceLoss: true}
	default:
		return PredictionReservationDisposition{}
	}
}

func validateRelayProfile(profile PredictionRelayProfile) error {
	if !canonicalDigest(profile.NetworkDomainHash, "sha256:") || !validRawAddress(profile.SourceAgentAccount) ||
		!canonicalDigest(profile.SourceAgentAccountCodeHash, "tvm-cell-sha256:") ||
		!validRawAddress(profile.MarketAddress) || profile.SourceAgentAccount == profile.MarketAddress ||
		!canonicalDigest(profile.MarketID, "sha256:") ||
		!canonicalDigest(profile.MarketCodeHash, "tvm-cell-sha256:") ||
		!canonicalDigest(profile.MarketConfigHash, "tvm-cell-sha256:") || len(profile.ObserverIDs) < 3 ||
		profile.QuorumThreshold < 2 || profile.QuorumThreshold <= uint32(len(profile.ObserverIDs)/2) ||
		profile.QuorumThreshold > uint32(len(profile.ObserverIDs)) || profile.MaximumOutstanding == 0 ||
		profile.MaximumOutstanding > 100_000 || profile.MaximumSignedBOCBytes == 0 ||
		profile.MaximumSignedBOCBytes > 1<<20 || profile.MinimumNoBounceMCBlocks == 0 ||
		profile.MinimumNoBounceMCBlocks > 1_000_000 {
		return errors.New("invalid prediction relay profile")
	}
	if !sortedUniqueCanonicalDigests(profile.ObserverIDs, "sha256:") {
		return errors.New("prediction observer identities are not canonical")
	}
	return nil
}

func validateExpectedCall(call ExpectedContractCall, profile PredictionRelayProfile, actionID string) error {
	if !commerce.IsPredictionCustodyEffectKind(call.ActionKind) || call.StableActionID != actionID ||
		call.TargetAddress != profile.MarketAddress || call.ValueNanoTOS == 0 || !call.Bounce || call.ExtraFlags != 3 ||
		call.Opcode == 0 || !canonicalDigest(call.SuccessPredicateDigest, "sha256:") {
		return errors.New("prediction expected contract call is invalid")
	}
	body, err := decodeCanonicalCell(call.BodyBOCBase64, maximumChainBOCBytes)
	if err != nil || cellDigest(body) != call.BodyHash {
		return errors.New("prediction expected body is not canonical")
	}
	bodySlice, parseErr := body.BeginParse()
	opcode, opcodeErr := uint64(0), error(nil)
	if parseErr == nil {
		opcode, opcodeErr = bodySlice.LoadUInt(32)
	}
	if parseErr != nil || opcodeErr != nil || opcode != uint64(call.Opcode) {
		return errors.New("prediction expected opcode is not the body opcode")
	}
	wantedPredicate, predicateErr := contractCallSuccessPredicateDigest(call)
	if predicateErr != nil || call.SuccessPredicateDigest != wantedPredicate {
		return errors.New("prediction expected success predicate is not canonical")
	}
	if call.StateInitBOCBase64 == "" {
		if call.StateInitHash != "" {
			return errors.New("prediction expected StateInit hash has no bytes")
		}
	} else {
		stateInit, stateErr := decodeCanonicalCell(call.StateInitBOCBase64, maximumChainBOCBytes)
		if stateErr != nil || cellDigest(stateInit) != call.StateInitHash {
			return errors.New("prediction expected StateInit is not canonical")
		}
	}
	return nil
}

// NewExpectedContractCall freezes the exact Agent Account V2 outbound before
// it can enter the relay journal. The success predicate is derived rather than
// caller-selected, so a resolver cannot reinterpret a successful transaction
// under a weaker business action.
func NewExpectedContractCall(actionKind, stableActionID, target string, value uint64,
	bodyBOC []byte,
) (ExpectedContractCall, error) {
	root, err := cell.FromBOC(bodyBOC)
	if err != nil || root == nil || len(bodyBOC) == 0 || len(bodyBOC) > maximumChainBOCBytes ||
		!bytes.Equal(bodyBOC, root.ToBOCWithFlags(false)) {
		return ExpectedContractCall{}, errors.New("prediction operation body is not one canonical cell")
	}
	slice, err := root.BeginParse()
	if err != nil {
		return ExpectedContractCall{}, errors.New("prediction operation body cannot be parsed")
	}
	opcode, err := slice.LoadUInt(32)
	if err != nil || opcode == 0 {
		return ExpectedContractCall{}, errors.New("prediction operation body has no opcode")
	}
	call := ExpectedContractCall{
		ActionKind: actionKind, StableActionID: stableActionID, TargetAddress: target,
		ValueNanoTOS: value, BodyBOCBase64: base64.StdEncoding.EncodeToString(bodyBOC),
		BodyHash: cellDigest(root), Bounce: true, ExtraFlags: 3, Opcode: uint32(opcode),
	}
	call.SuccessPredicateDigest, err = contractCallSuccessPredicateDigest(call)
	if err != nil {
		return ExpectedContractCall{}, err
	}
	return call, nil
}

func contractCallSuccessPredicateDigest(call ExpectedContractCall) (string, error) {
	if !commerce.IsPredictionCustodyEffectKind(call.ActionKind) || !canonicalDigest(call.StableActionID, "sha256:") ||
		!validRawAddress(call.TargetAddress) || call.ValueNanoTOS == 0 ||
		!canonicalDigest(
			call.BodyHash,
			"tvm-cell-sha256:",
		) || call.Opcode == 0 || !call.Bounce || call.ExtraFlags != 3 ||
		call.StateInitBOCBase64 != "" || call.StateInitHash != "" {
		return "", errors.New("prediction contract-call success predicate is invalid")
	}
	preimage := fmt.Sprintf("TOS-PREDICTION-CALL-SUCCESS\x00%s\x00%s\x00%s\x00%d\x00%s\x00%d\x00%d",
		call.ActionKind, call.StableActionID, call.TargetAddress, call.ValueNanoTOS, call.BodyHash,
		call.ExtraFlags, call.Opcode)
	digest := sha256.Sum256([]byte(preimage))
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func validateSourceEvidence(record PredictionRelayRecord, evidence SourceTransactionEvidence) error {
	if evidence.SubmittedExternalMessageHash != record.SubmittedExternalMessageHash ||
		validateOpaqueBOC(evidence.TransactionBOCBase64, evidence.TransactionHash) != nil ||
		validateCheckpoint(
			evidence.Block,
		) != nil || evidence.Block.MasterchainSequence < record.PreBroadcastMasterchainCheckpoint.SequenceNumber ||
		validateQuorum(evidence.Finality, record.Profile, evidence.Block.MasterchainSequence) != nil ||
		validateAccountCursor(evidence.NextSourceCursor, record.Profile.SourceAgentAccount) != nil ||
		evidence.NextSourceCursor.LastLogicalTime < record.PreBroadcastSourceCursor.LastLogicalTime ||
		len(evidence.OutboundMessages) > 1 {
		return errors.New("prediction source evidence is inconsistent")
	}
	if len(evidence.OutboundMessages) == 1 &&
		validateObservedCall(evidence.OutboundMessages[0], record.Profile.SourceAgentAccount, record.Expected) != nil {
		return errors.New("source transaction did not contain the exact checked-bounceable call")
	}
	return nil
}

func validateObservedCall(message ChainObservedMessage, source string, expected ExpectedContractCall) error {
	if validateObservedMessage(message) != nil || message.SourceAddress != source ||
		message.DestinationAddress != expected.TargetAddress || message.ValueNanoTOS != expected.ValueNanoTOS ||
		message.BodyBOCBase64 != expected.BodyBOCBase64 || message.BodyHash != expected.BodyHash ||
		message.StateInitBOCBase64 != expected.StateInitBOCBase64 || message.StateInitHash != expected.StateInitHash ||
		!message.Bounce || message.Bounced || message.ExtraFlags != 3 {
		return errors.New("chain-observed outbound differs from the authorized call")
	}
	return nil
}

func validateDestinationEvidence(record PredictionRelayRecord, evidence DestinationTransactionEvidence) error {
	outbound := record.ActualOutbound
	if outbound == nil || evidence.InboundMessageHash != outbound.MessageHash ||
		validateOpaqueBOC(evidence.TransactionBOCBase64, evidence.TransactionHash) != nil ||
		validateCheckpoint(
			evidence.Block,
		) != nil || evidence.Block.MasterchainSequence < record.PreBroadcastMasterchainCheckpoint.SequenceNumber ||
		validateQuorum(evidence.Finality, record.Profile, evidence.Block.MasterchainSequence) != nil ||
		validateAccountCursor(evidence.NextDestinationCursor, record.Profile.MarketAddress) != nil ||
		evidence.MarketCodeHash != record.Profile.MarketCodeHash ||
		evidence.MarketConfigHash != record.Profile.MarketConfigHash ||
		!evidence.Ordinary {
		return errors.New("prediction destination evidence is inconsistent")
	}
	success := !evidence.Aborted && evidence.ComputeSuccess && evidence.ActionSuccess && evidence.OpcodeSuccess
	if success {
		if evidence.SuccessPredicateDigest != record.Expected.SuccessPredicateDigest || evidence.BounceMessage != nil ||
			evidence.NoBounceProof != nil || evidence.RichBounceEnvelopeHash != "" || evidence.RichBounceOriginalBodyHash != "" {
			return errors.New("prediction success evidence contains conflicting failure material")
		}
		return nil
	}
	if evidence.SuccessPredicateDigest != "" {
		return errors.New("prediction failure claims a success predicate")
	}
	if evidence.BounceMessage != nil {
		bounce := *evidence.BounceMessage
		if evidence.NoBounceProof != nil || validateObservedMessage(bounce) != nil || !bounce.Bounced ||
			bounce.Bounce ||
			bounce.SourceAddress != record.Profile.MarketAddress ||
			bounce.DestinationAddress != record.Profile.SourceAgentAccount ||
			bounce.ValueNanoTOS > outbound.ValueNanoTOS ||
			!canonicalDigest(evidence.RichBounceEnvelopeHash, "tvm-cell-sha256:") ||
			evidence.RichBounceEnvelopeHash != bounce.BodyHash ||
			evidence.RichBounceOriginalBodyHash != record.Expected.BodyHash {
			return errors.New("prediction failure has an invalid rich bounce")
		}
		return nil
	}
	if evidence.NoBounceProof == nil || evidence.RichBounceEnvelopeHash != "" ||
		evidence.RichBounceOriginalBodyHash != "" {
		return errors.New("prediction failure has neither an exact bounce nor bounded absence proof")
	}
	absence := evidence.NoBounceProof
	if absence.ScanStartMasterchainSeqno > evidence.Block.MasterchainSequence ||
		uint64(
			absence.ScanEndMasterchainSeqno,
		) < uint64(
			evidence.Block.MasterchainSequence,
		)+uint64(
			record.Profile.MinimumNoBounceMCBlocks,
		) ||
		absence.ScanEndMasterchainSeqno > evidence.Finality.MasterchainSeqno ||
		!sortedUniqueCanonicalDigests(absence.ObservationDigests, "sha256:") ||
		len(absence.ObservationDigests) < int(record.Profile.QuorumThreshold) ||
		!canonicalDigest(absence.EvidenceSetDigest, "sha256:") {
		return errors.New("prediction no-bounce proof is not bounded and final")
	}
	return nil
}

func validateBounceCreditEvidence(record PredictionRelayRecord, evidence BounceCreditEvidence) error {
	bounce := record.DestinationEvidence.BounceMessage
	if evidence.InboundBounceMessageHash != bounce.MessageHash ||
		evidence.CreditedValueNanoTOS != bounce.ValueNanoTOS ||
		validateOpaqueBOC(evidence.TransactionBOCBase64, evidence.TransactionHash) != nil ||
		validateCheckpoint(evidence.Block) != nil ||
		evidence.Block.MasterchainSequence < record.DestinationEvidence.Block.MasterchainSequence ||
		validateQuorum(evidence.Finality, record.Profile, evidence.Block.MasterchainSequence) != nil ||
		validateAccountCursor(evidence.NextSourceCursor, record.Profile.SourceAgentAccount) != nil ||
		evidence.NextSourceCursor.LastLogicalTime < record.SourceEvidence.NextSourceCursor.LastLogicalTime {
		return errors.New("prediction bounce credit evidence is inconsistent")
	}
	return nil
}

func validateObservedMessage(message ChainObservedMessage) error {
	root, err := decodeCanonicalCell(message.ExactMessageBOC, maximumChainBOCBytes)
	if err != nil || cellDigest(root) != message.MessageHash || !validRawAddress(message.SourceAddress) ||
		!validRawAddress(message.DestinationAddress) || message.ValueNanoTOS == 0 {
		return errors.New("chain-observed message is invalid")
	}
	body, bodyErr := decodeCanonicalCell(message.BodyBOCBase64, maximumChainBOCBytes)
	if bodyErr != nil || cellDigest(body) != message.BodyHash {
		return errors.New("chain-observed message body is invalid")
	}
	if message.StateInitBOCBase64 == "" {
		if message.StateInitHash != "" {
			return errors.New("chain-observed message StateInit hash has no bytes")
		}
	} else {
		state, stateErr := decodeCanonicalCell(message.StateInitBOCBase64, maximumChainBOCBytes)
		if stateErr != nil || cellDigest(state) != message.StateInitHash {
			return errors.New("chain-observed message StateInit is invalid")
		}
	}
	return nil
}

func validateQuorum(finality QuorumFinality, profile PredictionRelayProfile, minimumMC uint32) error {
	if finality.NetworkDomainHash != profile.NetworkDomainHash ||
		!canonicalDigest(finality.FinalityViewID, "sha256:") ||
		!reflect.DeepEqual(finality.ObserverIDs, profile.ObserverIDs) ||
		finality.Threshold != profile.QuorumThreshold ||
		finality.MasterchainSeqno < minimumMC ||
		!sortedUniqueCanonicalDigests(finality.AgreeingIDs, "sha256:") ||
		len(finality.AgreeingIDs) < int(profile.QuorumThreshold) {
		return errors.New("prediction evidence quorum is invalid")
	}
	allowed := make(map[string]struct{}, len(profile.ObserverIDs))
	for _, id := range profile.ObserverIDs {
		allowed[id] = struct{}{}
	}
	for _, id := range finality.AgreeingIDs {
		if _, ok := allowed[id]; !ok {
			return errors.New("prediction evidence has an unadmitted observer")
		}
	}
	return nil
}

func validateCheckpoint(block BlockIdentity) error {
	if !canonicalDigest(block.RootHash, "sha256:") || !canonicalDigest(block.FileHash, "sha256:") ||
		block.SequenceNumber == 0 || block.MasterchainSequence == 0 {
		return errors.New("invalid chain block identity")
	}
	return nil
}

func validateAccountCursor(cursor AccountCursor, account string) error {
	if cursor.AccountAddress != account || (cursor.LastLogicalTime == 0) != (cursor.LastTransactionHash == "") ||
		(cursor.LastTransactionHash != "" && !canonicalDigest(cursor.LastTransactionHash, "sha256:")) {
		return errors.New("invalid account transaction cursor")
	}
	return nil
}

func validateOpaqueBOC(encoded, digest string) error {
	root, err := decodeCanonicalCell(encoded, maximumChainBOCBytes)
	if err != nil || !canonicalDigest(digest, "sha256:") ||
		"sha256:"+hex.EncodeToString(root.Hash()) != digest {
		return errors.New("invalid exact chain BOC")
	}
	return nil
}

func (journal *PredictionRelayJournal) load() error {
	actions := filepath.Join(journal.directory, "actions")
	if err := os.MkdirAll(actions, 0o700); err != nil {
		return err
	}
	actionsInfo, err := os.Lstat(actions)
	if err != nil || !actionsInfo.IsDir() || actionsInfo.Mode()&os.ModeSymlink != 0 ||
		actionsInfo.Mode().Perm() != 0o700 {
		return errors.New("prediction relay actions directory is not owner-private")
	}
	return filepath.WalkDir(actions, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == actions {
			return nil
		}
		info, err := entry.Info()
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("prediction relay journal contains an unsafe entry")
		}
		if entry.IsDir() {
			relative, relativeErr := filepath.Rel(actions, path)
			parts := strings.Split(relative, string(filepath.Separator))
			if relativeErr != nil || len(parts) > 2 || !lowerHex(parts[len(parts)-1], 2) ||
				info.Mode().Perm() != 0o700 {
				return errors.New("prediction relay shard is not owner-private")
			}
			return nil
		}
		if filepath.Ext(path) != ".json" || info.Mode().Perm() != 0o600 || info.Size() > maximumRelayRecordBytes {
			return errors.New("prediction relay journal contains an invalid record file")
		}
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		var record PredictionRelayRecord
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&record) != nil || decoder.Decode(&struct{}{}) != io.EOF ||
			validateRelayRecord(record, journal.profile) != nil ||
			path != journal.recordPath(record.ActionID) {
			return errors.New("prediction relay journal record is corrupt")
		}
		if _, duplicate := journal.records[record.ActionID]; duplicate {
			return errors.New("duplicate prediction relay record")
		}
		journal.records[record.ActionID] = record
		if uint32(len(journal.records)) > journal.profile.MaximumOutstanding {
			return errors.New("prediction relay journal exceeds its configured bound")
		}
		return nil
	})
}

func validateRelayRecord(record PredictionRelayRecord, profile PredictionRelayProfile) error {
	if record.SchemaVersion != relaySchemaVersion || record.Revision == 0 ||
		!canonicalDigest(record.ActionID, "sha256:") ||
		!reflect.DeepEqual(record.Profile, profile) ||
		validateExpectedCall(record.Expected, profile, record.ActionID) != nil ||
		validateAccountCursor(record.PreBroadcastSourceCursor, profile.SourceAgentAccount) != nil ||
		validateCheckpoint(record.PreBroadcastMasterchainCheckpoint) != nil ||
		record.PreBroadcastMasterchainCheckpoint.WorkchainID != -1 ||
		record.PreBroadcastMasterchainCheckpoint.SequenceNumber !=
			record.PreBroadcastMasterchainCheckpoint.MasterchainSequence {
		return errors.New("invalid prediction relay record identity")
	}
	raw, err := decodeBase64Bounded(record.ExactSignedBOCBase64, int(profile.MaximumSignedBOCBytes))
	if err != nil {
		return err
	}
	messageHash, err := canonicalCellDigest(raw, int(profile.MaximumSignedBOCBytes))
	if err != nil || sha256Digest(raw) != record.ExactSignedBOCDigest ||
		record.SubmittedExternalMessageHash != messageHash {
		return errors.New("prediction relay exact BOC changed")
	}
	switch record.State {
	case RelaySigned:
		if record.BroadcastAttempts != 0 || record.SourceEvidence != nil || record.ActualOutbound != nil ||
			record.DestinationEvidence != nil ||
			record.BounceCreditEvidence != nil {
			return errors.New("signed relay record has future evidence")
		}
	case RelayBroadcasting:
		if record.BroadcastAttempts == 0 || record.SourceEvidence != nil || record.ActualOutbound != nil ||
			record.DestinationEvidence != nil ||
			record.BounceCreditEvidence != nil {
			return errors.New("broadcasting relay record has invalid evidence")
		}
	case RelaySourceActionSkipped:
		if record.SourceEvidence == nil || len(record.SourceEvidence.OutboundMessages) != 0 ||
			record.ActualOutbound != nil ||
			record.DestinationEvidence != nil ||
			record.BounceCreditEvidence != nil ||
			validateSourceEvidence(recordWithoutEvidence(record), *record.SourceEvidence) != nil {
			return errors.New("action-skipped relay record is invalid")
		}
	case RelaySourceFinalized,
		RelayDestinationCommitted,
		RelayDestinationFailedBounceCreated,
		RelayDestinationFailedNoBounce,
		RelayBounceCreditedAtAgent:
		if record.SourceEvidence == nil || record.ActualOutbound == nil ||
			len(record.SourceEvidence.OutboundMessages) != 1 ||
			validateSourceEvidence(recordWithoutEvidence(record), *record.SourceEvidence) != nil ||
			!reflect.DeepEqual(*record.ActualOutbound, record.SourceEvidence.OutboundMessages[0]) {
			return errors.New("source-final relay record is invalid")
		}
		if record.State == RelaySourceFinalized {
			if record.DestinationEvidence != nil || record.BounceCreditEvidence != nil {
				return errors.New("source-final relay record has future evidence")
			}
		} else if record.DestinationEvidence == nil ||
			validateDestinationEvidence(recordAtSourceFinal(record), *record.DestinationEvidence) != nil {
			return errors.New("destination-final relay record is invalid")
		} else if destinationState(*record.DestinationEvidence) != record.State &&
			record.State != RelayBounceCreditedAtAgent {
			return errors.New("destination evidence does not match relay state")
		} else if record.State == RelayBounceCreditedAtAgent &&
			destinationState(*record.DestinationEvidence) != RelayDestinationFailedBounceCreated {
			return errors.New("credited relay record has no bounce-created predecessor")
		} else if record.State == RelayBounceCreditedAtAgent {
			if record.BounceCreditEvidence == nil ||
				validateBounceCreditEvidence(recordAtBounceCreated(record), *record.BounceCreditEvidence) != nil {
				return errors.New("bounce-credit relay record is invalid")
			}
		} else if record.BounceCreditEvidence != nil {
			return errors.New("relay record has premature bounce credit")
		}
	default:
		return errors.New("unknown prediction relay state")
	}
	return nil
}

func destinationState(evidence DestinationTransactionEvidence) RelayState {
	if evidence.Ordinary && !evidence.Aborted && evidence.ComputeSuccess && evidence.ActionSuccess &&
		evidence.OpcodeSuccess {
		return RelayDestinationCommitted
	}
	if evidence.BounceMessage != nil {
		return RelayDestinationFailedBounceCreated
	}
	return RelayDestinationFailedNoBounce
}

func (journal *PredictionRelayJournal) persist(record PredictionRelayRecord) error {
	if validateRelayRecord(record, journal.profile) != nil {
		return errors.New("refuse to persist invalid prediction relay record")
	}
	raw, err := json.Marshal(record)
	if err != nil || len(raw) > maximumRelayRecordBytes {
		return errors.New("prediction relay record exceeds its durable bound")
	}
	path := journal.recordPath(record.ActionID)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if info, statErr := os.Lstat(filepath.Dir(path)); statErr != nil || !info.IsDir() ||
		info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o700 {
		return errors.New("prediction relay shard is unsafe")
	}
	return fileutil.WriteFileAtomic(path, raw, 0o600)
}

func (journal *PredictionRelayJournal) recordPath(actionID string) string {
	hexID := strings.TrimPrefix(actionID, "sha256:")
	if len(hexID) != 64 {
		return filepath.Join(journal.directory, "invalid")
	}
	return filepath.Join(journal.directory, "actions", hexID[:2], hexID[2:4], hexID+".json")
}

func validRawAddress(value string) bool {
	parsed, err := address.ParseRawAddr(value)
	return err == nil && parsed != nil && parsed.Type() == address.StdAddress && parsed.BitsLen() == 256 &&
		parsed.StringRaw() == value
}

func canonicalCellDigest(raw []byte, maximum int) (string, error) {
	if len(raw) == 0 || len(raw) > maximum {
		return "", errors.New("cell BOC exceeds bound")
	}
	root, err := cell.FromBOC(raw)
	if err != nil || root == nil || !bytes.Equal(raw, root.ToBOCWithFlags(false)) {
		return "", errors.New("cell BOC is not canonical")
	}
	return cellDigest(root), nil
}

func sha256Digest(raw []byte) string {
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func decodeCanonicalCell(encoded string, maximum int) (*cell.Cell, error) {
	raw, err := decodeBase64Bounded(encoded, maximum)
	if err != nil {
		return nil, err
	}
	root, cellErr := cell.FromBOC(raw)
	if cellErr != nil || root == nil || !bytes.Equal(raw, root.ToBOCWithFlags(false)) {
		return nil, errors.New("cell BOC is not canonical")
	}
	return root, nil
}

func decodeBase64Bounded(encoded string, maximum int) ([]byte, error) {
	if encoded == "" || len(encoded) > base64.StdEncoding.EncodedLen(maximum) {
		return nil, errors.New("encoded evidence exceeds bound")
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(raw) == 0 || len(raw) > maximum || base64.StdEncoding.EncodeToString(raw) != encoded {
		return nil, errors.New("evidence is not canonical base64")
	}
	return raw, nil
}

func cellDigest(value *cell.Cell) string {
	return "tvm-cell-sha256:" + hex.EncodeToString(value.Hash())
}

func sortedUniqueCanonicalDigests(values []string, prefix string) bool {
	if len(values) == 0 || !sort.StringsAreSorted(values) {
		return false
	}
	for index, value := range values {
		if !canonicalDigest(value, prefix) || (index > 0 && value == values[index-1]) {
			return false
		}
	}
	return true
}

func lowerHex(value string, length int) bool {
	if len(value) != length || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded)*2 == length
}

func cloneRelayProfile(value PredictionRelayProfile) PredictionRelayProfile {
	value.ObserverIDs = append([]string(nil), value.ObserverIDs...)
	return value
}

func cloneRelayRecord(value PredictionRelayRecord) PredictionRelayRecord {
	raw, _ := json.Marshal(value)
	var cloned PredictionRelayRecord
	_ = json.Unmarshal(raw, &cloned)
	return cloned
}

func cloneSourceEvidence(value SourceTransactionEvidence) SourceTransactionEvidence {
	return *ptrSourceEvidence(value)
}

func cloneDestinationEvidence(value DestinationTransactionEvidence) DestinationTransactionEvidence {
	return *ptrDestinationEvidence(value)
}

func cloneBounceCreditEvidence(value BounceCreditEvidence) BounceCreditEvidence {
	return *ptrBounceCreditEvidence(value)
}

func ptrSourceEvidence(value SourceTransactionEvidence) *SourceTransactionEvidence {
	raw, _ := json.Marshal(value)
	var cloned SourceTransactionEvidence
	_ = json.Unmarshal(raw, &cloned)
	return &cloned
}

func ptrDestinationEvidence(value DestinationTransactionEvidence) *DestinationTransactionEvidence {
	raw, _ := json.Marshal(value)
	var cloned DestinationTransactionEvidence
	_ = json.Unmarshal(raw, &cloned)
	return &cloned
}

func ptrBounceCreditEvidence(value BounceCreditEvidence) *BounceCreditEvidence {
	cloned := value
	cloned.Finality.ObserverIDs = append([]string(nil), value.Finality.ObserverIDs...)
	cloned.Finality.AgreeingIDs = append([]string(nil), value.Finality.AgreeingIDs...)
	return &cloned
}

func recordWithoutEvidence(value PredictionRelayRecord) PredictionRelayRecord {
	value.State = RelayBroadcasting
	value.SourceEvidence, value.ActualOutbound, value.DestinationEvidence, value.BounceCreditEvidence = nil, nil, nil, nil
	return value
}

func recordAtSourceFinal(value PredictionRelayRecord) PredictionRelayRecord {
	value.State = RelaySourceFinalized
	value.DestinationEvidence, value.BounceCreditEvidence = nil, nil
	return value
}

func recordAtBounceCreated(value PredictionRelayRecord) PredictionRelayRecord {
	value.State = RelayDestinationFailedBounceCreated
	value.BounceCreditEvidence = nil
	return value
}
