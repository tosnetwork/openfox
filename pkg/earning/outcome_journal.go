package earning

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tosnetwork/openfox/pkg/fileutil"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

const (
	outcomeJournalSchema         = "tos.openfox.operation-outcome-journal.v1"
	outcomeJournalScope          = "operation.journal.append"
	outcomeJournalHead           = "head.json"
	maxOutcomeJournalRecordBytes = 2 << 20
	maxOutcomeJournalResultBytes = 64 << 20
	maxOutcomeJournalRecords     = 1_000_000
)

type OutcomeJournalHead struct {
	Schema             string   `json:"schema"`
	OwnerID            string   `json:"owner_id"`
	AgentID            string   `json:"agent_id"`
	AuthorityID        string   `json:"authority_id"`
	OrderingDomain     string   `json:"ordering_domain"`
	CohortScopeDigest  string   `json:"cohort_scope_digest"`
	WriterGeneration   uint64   `json:"writer_generation"`
	LastSequence       uint64   `json:"last_sequence"`
	LastEnvelopeDigest string   `json:"last_envelope_digest"`
	LastRecordChecksum string   `json:"last_record_checksum"`
	PendingSequence    uint64   `json:"pending_sequence"`
	GapSequences       []uint64 `json:"gap_sequences"`
}

type OutcomeJournalRecord struct {
	Schema                     string                                             `json:"schema"`
	Epoch                      uint64                                             `json:"epoch"`
	Sequence                   uint64                                             `json:"sequence"`
	OperationID                string                                             `json:"operation_id"`
	EventContentID             string                                             `json:"event_content_id"`
	OperationEnvelopeDigest    string                                             `json:"operation_envelope_digest"`
	JournalAppendActionID      string                                             `json:"journal_append_action_id"`
	JournalAppendRequestDigest string                                             `json:"journal_append_request_digest,omitempty"`
	JournalAppendRequest       *commerce.OperationJournalAppendAdmissionRequestV1 `json:"journal_append_request,omitempty"`
	JournalAppendAction        *commerce.AuthorizedAction                         `json:"journal_append_action,omitempty"`
	JournalAppendWriterFence   *commerce.WriterFence                              `json:"journal_append_writer_fence,omitempty"`
	SourceAuthorizedAction     *commerce.AuthorizedAction                         `json:"source_authorized_action,omitempty"`
	SourceActionResolution     *commerce.ActionResolution                         `json:"source_action_resolution,omitempty"`
	PreviousRecordChecksum     string                                             `json:"previous_record_checksum"`
	Envelope                   commerce.AgentOperationEnvelopeV1                  `json:"envelope"`
	Payload                    []byte                                             `json:"payload"`
	Artifacts                  commerce.OperationOutcomeArtifactBundleV1          `json:"artifacts"`
	RecordChecksum             string                                             `json:"record_checksum"`
}

// OutcomeJournalSourceResolution retains the exact authority envelope and sink
// resolution whose digests are committed by an Action-resolution assertion.
// It is local-private journal material; public propagation still applies the
// event's explicit disclosure policy.
type OutcomeJournalSourceResolution struct {
	Action     commerce.AuthorizedAction
	Resolution commerce.ActionResolution
}

type OutcomeJournalAppendAdmission struct {
	Request commerce.OperationJournalAppendAdmissionRequestV1
	Action  commerce.AuthorizedAction
	Fence   commerce.WriterFence
}

type historicalOutcomeFenceResolver struct {
	authorityID string
	key         ed25519.PublicKey
}

type historicalOutcomeOperationSelfResolver struct{}

func (historicalOutcomeOperationSelfResolver) AuthorizeAgentOperationKey(string, commerce.ProfileRefV1, ed25519.PublicKey, time.Time, []byte) error {
	return nil
}

func (resolver historicalOutcomeFenceResolver) AuthorizeFenceKey(authorityID string, key ed25519.PublicKey, _ time.Time) error {
	if authorityID != resolver.authorityID || !bytes.Equal(key, resolver.key) {
		return errors.New("historical outcome authority key differs from the retained fence")
	}
	return nil
}

type OutcomeJournal struct {
	mu        sync.Mutex
	directory string
	root      *os.Root
	lock      *os.File
	head      OutcomeJournalHead
}

// OutcomeOrderingDomainV1 creates the authority-scoped journal identity. A
// different owner, Agent, authority, purpose or cohort cannot share a stream.
func OutcomeOrderingDomainV1(ownerID, agentID, authorityID, purpose, cohortScopeDigest string) (string, error) {
	if ownerID == "" || agentID == "" || authorityID == "" || purpose == "" || !canonicalSHA256(cohortScopeDigest) {
		return "", errors.New("outcome ordering domain inputs are invalid")
	}
	return codec.Digest("tos.openfox.operation-outcome-ordering-domain.v1", struct {
		OwnerID           string `json:"owner_id"`
		AgentID           string `json:"agent_id"`
		AuthorityID       string `json:"authority_id"`
		Purpose           string `json:"purpose"`
		CohortScopeDigest string `json:"cohort_scope_digest"`
	}{ownerID, agentID, authorityID, purpose, cohortScopeDigest})
}

func OpenOutcomeJournal(directory, ownerID, agentID, authorityID, purpose, cohortScopeDigest string,
	fence commerce.WriterFence, resolver commerce.CurrentWriterFenceResolver, now time.Time) (*OutcomeJournal, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || ownerID == "" || agentID == "" || authorityID == "" || now.IsZero() {
		return nil, errors.New("outcome journal configuration is invalid")
	}
	if fence.Body.OwnerID != ownerID || fence.Body.AgentID != agentID || fence.Body.AuthorityID != authorityID ||
		fence.Body.WriterGeneration == 0 || !containsString(fence.Body.Scope, outcomeJournalScope) {
		return nil, errors.New("outcome journal Writer Fence is out of scope")
	}
	if err := commerce.VerifyWriterFence(fence, resolver, now.UTC(), outcomeJournalScope); err != nil {
		return nil, err
	}
	if err := commerce.ConfirmCurrentWriterFence(fence, resolver, now.UTC()); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return nil, errors.New("outcome journal must be owner-private")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	lock, err := acquireAuthorityLockRoot(root)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	domain, err := OutcomeOrderingDomainV1(ownerID, agentID, authorityID, purpose, cohortScopeDigest)
	if err != nil {
		_ = releaseAuthorityLock(lock)
		_ = root.Close()
		return nil, err
	}
	journal := &OutcomeJournal{directory: directory, root: root, lock: lock, head: OutcomeJournalHead{Schema: outcomeJournalSchema,
		OwnerID: ownerID, AgentID: agentID, AuthorityID: authorityID, OrderingDomain: domain, CohortScopeDigest: cohortScopeDigest,
		WriterGeneration: fence.Body.WriterGeneration, GapSequences: []uint64{}}}
	if err := journal.recoverHead(fence.Body.WriterGeneration); err != nil {
		_ = releaseAuthorityLock(lock)
		_ = root.Close()
		return nil, err
	}
	return journal, nil
}

func (journal *OutcomeJournal) Close() error {
	if journal == nil || journal.lock == nil {
		return nil
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	err := releaseAuthorityLock(journal.lock)
	journal.lock = nil
	rootErr := journal.root.Close()
	journal.root = nil
	if err != nil {
		return err
	}
	return rootErr
}

func (journal *OutcomeJournal) Head() OutcomeJournalHead {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	clone := journal.head
	clone.GapSequences = make([]uint64, len(journal.head.GapSequences))
	copy(clone.GapSequences, journal.head.GapSequences)
	return clone
}

// Reserve makes a sequence permanently unique before any signing. A crash
// after this call converts the pending sequence into an explicit gap on open.
func (journal *OutcomeJournal) Reserve(fence commerce.WriterFence, resolver commerce.CurrentWriterFenceResolver, now time.Time) (uint64, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if err := journal.currentWriterLocked(fence, resolver, now); err != nil {
		return 0, err
	}
	if journal.head.PendingSequence != 0 {
		return 0, errors.New("outcome journal already has a pending sequence")
	}
	next := journal.head.LastSequence + 1
	if len(journal.head.GapSequences) > 0 && journal.head.GapSequences[len(journal.head.GapSequences)-1] >= next {
		next = journal.head.GapSequences[len(journal.head.GapSequences)-1] + 1
	}
	journal.head.PendingSequence = next
	if err := journal.persistHeadLocked(); err != nil {
		journal.head.PendingSequence = 0
		return 0, err
	}
	return next, nil
}

func (journal *OutcomeJournal) AbortReserved(sequence uint64) error {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.head.PendingSequence != sequence || sequence == 0 {
		return errors.New("outcome journal reservation does not match")
	}
	journal.head.GapSequences = append(journal.head.GapSequences, sequence)
	journal.head.PendingSequence = 0
	return journal.persistHeadLocked()
}

func (journal *OutcomeJournal) Commit(sequence uint64, envelope commerce.AgentOperationEnvelopeV1, payload []byte,
	artifacts commerce.OperationOutcomeArtifactBundleV1, resolver commerce.AgentOperationAuthorityResolver,
	now time.Time, appendAdmission *OutcomeJournalAppendAdmission, source *OutcomeJournalSourceResolution) (OutcomeJournalRecord, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.lock == nil || journal.head.PendingSequence != sequence || sequence == 0 || appendAdmission == nil {
		return OutcomeJournalRecord{}, errors.New("outcome journal commit has no exact reservation")
	}
	if envelope.Body.ActorAgentID != journal.head.AgentID || envelope.Body.OrderingDomain != journal.head.OrderingDomain ||
		envelope.Body.Epoch != journal.head.WriterGeneration || envelope.Body.Sequence != sequence {
		return OutcomeJournalRecord{}, errors.New("outcome operation ordering binding is invalid")
	}
	body, err := commerce.VerifyOperationOutcomeEnvelopeV1(envelope, payload, resolver, now.UTC())
	if err != nil {
		return OutcomeJournalRecord{}, err
	}
	if err := commerce.VerifyOperationOutcomeArtifactBundleV1(body, artifacts); err != nil {
		return OutcomeJournalRecord{}, err
	}
	envelopeDigest, err := commerce.AgentOperationEnvelopeDigestV1(envelope)
	if err != nil {
		return OutcomeJournalRecord{}, err
	}
	appendFields, err := commerce.OperationJournalAppendSemanticFieldsV1(journal.head.OwnerID, journal.head.AgentID,
		journal.head.OrderingDomain, journal.head.WriterGeneration, sequence, envelope.Body.ObjectID)
	if err != nil {
		return OutcomeJournalRecord{}, err
	}
	appendActionID, _, err := commerce.DeriveStableActionID("operation.journal.append", appendFields)
	if err != nil {
		return OutcomeJournalRecord{}, err
	}
	record := OutcomeJournalRecord{Schema: outcomeJournalSchema, Epoch: journal.head.WriterGeneration, Sequence: sequence,
		OperationID: envelope.Body.OperationID, EventContentID: envelope.Body.ObjectID, OperationEnvelopeDigest: envelopeDigest,
		JournalAppendActionID: appendActionID, PreviousRecordChecksum: journal.head.LastRecordChecksum,
		Envelope: envelope, Payload: append([]byte(nil), payload...), Artifacts: artifacts}
	if source != nil {
		actionCopy, resolutionCopy := source.Action, source.Resolution
		resolutionCopy.EvidenceRefs = append([]string(nil), source.Resolution.EvidenceRefs...)
		record.SourceAuthorizedAction = &actionCopy
		record.SourceActionResolution = &resolutionCopy
	}
	if err := validateOutcomeJournalSourceResolution(record); err != nil {
		return OutcomeJournalRecord{}, err
	}
	{
		gapDigest, digestErr := codec.Digest("tos.openfox.outcome-journal-gap-set.v1", journal.head.GapSequences)
		expectedRequest := commerce.OperationJournalAppendAdmissionRequestV1{OrderingDomain: journal.head.OrderingDomain,
			Epoch: journal.head.WriterGeneration, Sequence: sequence, EventContentID: envelope.Body.ObjectID,
			OperationEnvelopeDigest: envelopeDigest, GapSetDigest: gapDigest}
		requestBytes, requestErr := codec.Marshal(appendAdmission.Request)
		requestDigest, requestDigestErr := commerce.ExactRequestDigest(requestBytes)
		fenceDigest, fenceErr := commerce.WriterFenceDigest(appendAdmission.Fence)
		if digestErr != nil || requestErr != nil || requestDigestErr != nil || fenceErr != nil {
			return OutcomeJournalRecord{}, errors.New("outcome journal append admission cannot be canonicalized")
		}
		if appendAdmission.Request != expectedRequest {
			return OutcomeJournalRecord{}, errors.New("outcome journal append request does not bind the reserved head")
		}
		if appendAdmission.Action.ActionKind != outcomeJournalScope || appendAdmission.Action.StableActionID != appendActionID ||
			appendAdmission.Action.ExactRequestDigest != requestDigest || appendAdmission.Action.WriterFenceDigest != fenceDigest ||
			appendAdmission.Action.OwnerID != journal.head.OwnerID || appendAdmission.Action.AgentID != journal.head.AgentID {
			return OutcomeJournalRecord{}, errors.New("outcome journal append admission identity mismatch")
		}
		requestCopy, actionCopy, fenceCopy := appendAdmission.Request, appendAdmission.Action, appendAdmission.Fence
		record.JournalAppendRequestDigest = appendAdmission.Action.ExactRequestDigest
		record.JournalAppendRequest = &requestCopy
		record.JournalAppendAction = &actionCopy
		record.JournalAppendWriterFence = &fenceCopy
	}
	record.RecordChecksum, err = outcomeRecordChecksum(record)
	if err != nil {
		return OutcomeJournalRecord{}, err
	}
	raw, err := json.Marshal(record)
	if err != nil || len(raw) > maxOutcomeJournalRecordBytes {
		return OutcomeJournalRecord{}, errors.New("outcome journal record is oversized")
	}
	if err := writeOutcomeRootExclusive(journal.root, outcomeRecordName(record.Epoch, record.Sequence), raw); err != nil {
		return OutcomeJournalRecord{}, err
	}
	journal.head.LastSequence = sequence
	journal.head.LastEnvelopeDigest = envelopeDigest
	journal.head.LastRecordChecksum = record.RecordChecksum
	journal.head.PendingSequence = 0
	if err := journal.persistHeadLocked(); err != nil {
		return OutcomeJournalRecord{}, err
	}
	return record, nil
}

func (journal *OutcomeJournal) Records(limit uint32) ([]OutcomeJournalRecord, error) {
	if limit == 0 || limit > 10000 {
		return nil, errors.New("outcome journal record limit is invalid")
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	result := make([]OutcomeJournalRecord, 0, limit)
	retainedBytes := 0
	err := journal.scanOutcomeRecordsLocked(func(record OutcomeJournalRecord, rawBytes, index, total int) error {
		if index < total-int(limit) {
			return nil
		}
		if retainedBytes > maxOutcomeJournalResultBytes-rawBytes {
			return errors.New("outcome journal result exceeds the V1 byte bound; reduce the requested limit")
		}
		retainedBytes += rawBytes
		result = append(result, record)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// scanOutcomeRecordsLocked validates the complete retained chain while
// allowing callers to keep only a bounded projection. No caller may treat an
// unvalidated prefix as an authoritative denominator.
func (journal *OutcomeJournal) scanOutcomeRecordsLocked(visitor func(OutcomeJournalRecord, int, int, int) error) error {
	entries, err := readOutcomeRootDirectory(journal.root)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), "record-") && strings.HasSuffix(entry.Name(), ".json") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	if len(names) > maxOutcomeJournalRecords {
		return errors.New("outcome journal exceeds the V1 record-count bound")
	}
	previousChecksum := ""
	var previousSequence uint64
	for index, name := range names {
		raw, err := journal.root.ReadFile(name)
		if err != nil || len(raw) > maxOutcomeJournalRecordBytes {
			return errors.New("outcome journal record is unavailable")
		}
		var record OutcomeJournalRecord
		if decodeStrictJSON(raw, &record) != nil {
			return errors.New("outcome journal record is invalid")
		}
		checksum, err := outcomeRecordChecksum(record)
		if err != nil || checksum != record.RecordChecksum {
			return errors.New("outcome journal checksum mismatch")
		}
		fields, err := commerce.OperationJournalAppendSemanticFieldsV1(journal.head.OwnerID, journal.head.AgentID,
			journal.head.OrderingDomain, record.Epoch, record.Sequence, record.EventContentID)
		if err != nil {
			return errors.New("outcome journal append identity is invalid")
		}
		actionID, _, err := commerce.DeriveStableActionID("operation.journal.append", fields)
		if err != nil || actionID != record.JournalAppendActionID || record.PreviousRecordChecksum != previousChecksum ||
			record.Sequence <= previousSequence ||
			record.Envelope.Body.OperationID != record.OperationID ||
			record.Envelope.Body.ObjectID != record.EventContentID || record.Envelope.Body.Sequence != record.Sequence ||
			record.Envelope.Body.Epoch != record.Epoch {
			return errors.New("outcome journal record binding is invalid")
		}
		if err := journal.validateAppendAdmission(record, fields, actionID, journal.head.GapSequences); err != nil {
			return err
		}
		if containsUint64(journal.head.GapSequences, record.Sequence) {
			return errors.New("outcome journal marks a committed record as a gap")
		}
		for sequence := previousSequence + 1; sequence < record.Sequence; sequence++ {
			if !containsUint64(journal.head.GapSequences, sequence) {
				return errors.New("outcome journal record is missing without an explicit gap")
			}
		}
		var body commerce.OperationOutcomeEventBodyV1
		verifiedBody, envelopeErr := commerce.VerifyOperationOutcomeEnvelopeV1(record.Envelope, record.Payload,
			historicalOutcomeOperationSelfResolver{}, time.Unix(int64(record.Envelope.Body.CreatedAtUnix), 0).UTC())
		computedEnvelopeDigest, digestErr := commerce.AgentOperationEnvelopeDigestV1(record.Envelope)
		if codec.Unmarshal(record.Payload, &body) != nil || envelopeErr != nil || digestErr != nil ||
			computedEnvelopeDigest != record.OperationEnvelopeDigest || !reflect.DeepEqual(verifiedBody, body) ||
			commerce.VerifyOperationOutcomeArtifactBundleV1(body, record.Artifacts) != nil ||
			validateOutcomeJournalSourceResolution(record) != nil {
			return errors.New("outcome journal artifact binding is invalid")
		}
		if visitor != nil {
			if err := visitor(record, len(raw), index, len(names)); err != nil {
				return err
			}
		}
		previousChecksum = record.RecordChecksum
		previousSequence = record.Sequence
	}
	if previousSequence != journal.head.LastSequence || previousChecksum != journal.head.LastRecordChecksum {
		if previousSequence != 0 || journal.head.LastSequence != 0 {
			return errors.New("outcome journal record chain does not match its durable head")
		}
	}
	return nil
}

func validateOutcomeJournalSourceResolution(record OutcomeJournalRecord) error {
	if record.SourceAuthorizedAction == nil && record.SourceActionResolution == nil {
		return nil
	}
	if record.SourceAuthorizedAction == nil || record.SourceActionResolution == nil {
		return errors.New("outcome journal source resolution is incomplete")
	}
	action, resolution := *record.SourceAuthorizedAction, *record.SourceActionResolution
	actionDigest, actionErr := commerce.AuthorizedActionDigest(action)
	resolutionDigest, resolutionErr := codec.Digest("tos.action-resolution.v1", resolution)
	var assertion commerce.ActionResolutionReferencePayloadV1
	if actionErr != nil || resolutionErr != nil || commerce.ValidateActionResolution(resolution) != nil ||
		codec.Unmarshal(record.Artifacts.AssertionPayload, &assertion) != nil ||
		resolution.StableActionID != action.StableActionID || resolution.ExactRequestDigest != action.ExactRequestDigest ||
		assertion.StableActionID != action.StableActionID || assertion.ExactRequestDigest != action.ExactRequestDigest ||
		assertion.AuthorizedActionDigest != actionDigest || assertion.ActionResolutionDigest != resolutionDigest ||
		assertion.ResolutionState != resolution.State || assertion.ResolutionStateRevision != resolution.StateRevision {
		return errors.New("outcome journal source resolution binding is invalid")
	}
	return nil
}

func (journal *OutcomeJournal) validateAppendAdmission(record OutcomeJournalRecord, fields map[string]commerce.SemanticValue,
	actionID string, gapSequences []uint64) error {
	if record.JournalAppendRequest == nil || record.JournalAppendAction == nil || record.JournalAppendWriterFence == nil {
		return errors.New("outcome journal append admission is incomplete")
	}
	requestBytes, requestErr := codec.Marshal(*record.JournalAppendRequest)
	requestDigest, requestDigestErr := commerce.ExactRequestDigest(requestBytes)
	fenceDigest, fenceErr := commerce.WriterFenceDigest(*record.JournalAppendWriterFence)
	fenceKey, keyErr := decodeOutcomeJournalFenceKey(record.JournalAppendWriterFence.PublicKey)
	verificationTime := time.Unix(int64(record.JournalAppendWriterFence.Body.IssuedAtUnix), 0).UTC()
	authorityErr := commerce.VerifyAuthorizedActionAtAuthorityTime(*record.JournalAppendAction, fields, requestBytes,
		*record.JournalAppendWriterFence, historicalOutcomeFenceResolver{record.JournalAppendWriterFence.Body.AuthorityID, fenceKey}, verificationTime, verificationTime)
	gapsAtAppend := make([]uint64, 0, len(gapSequences))
	for _, sequence := range gapSequences {
		if sequence < record.Sequence {
			gapsAtAppend = append(gapsAtAppend, sequence)
		}
	}
	expectedGapDigest, gapDigestErr := codec.Digest("tos.openfox.outcome-journal-gap-set.v1", gapsAtAppend)
	if requestErr != nil || requestDigestErr != nil || fenceErr != nil || keyErr != nil || authorityErr != nil ||
		gapDigestErr != nil || record.JournalAppendRequest.GapSetDigest != expectedGapDigest ||
		record.JournalAppendRequest.OrderingDomain != journal.head.OrderingDomain ||
		record.JournalAppendRequest.Epoch != record.Epoch || record.JournalAppendRequest.Sequence != record.Sequence ||
		record.JournalAppendRequest.EventContentID != record.EventContentID ||
		record.JournalAppendRequest.OperationEnvelopeDigest != record.OperationEnvelopeDigest ||
		record.JournalAppendAction.ActionKind != outcomeJournalScope || record.JournalAppendAction.StableActionID != actionID ||
		record.JournalAppendAction.ExactRequestDigest != requestDigest || requestDigest != record.JournalAppendRequestDigest ||
		record.JournalAppendAction.WriterFenceDigest != fenceDigest || record.JournalAppendWriterFence.Body.WriterGeneration != record.Epoch ||
		record.JournalAppendWriterFence.Body.OwnerID != journal.head.OwnerID ||
		record.JournalAppendWriterFence.Body.AgentID != journal.head.AgentID ||
		record.JournalAppendWriterFence.Body.AuthorityID != journal.head.AuthorityID ||
		record.JournalAppendAction.OwnerID != journal.head.OwnerID || record.JournalAppendAction.AgentID != journal.head.AgentID ||
		record.JournalAppendAction.AuthorityID != journal.head.AuthorityID {
		return errors.New("outcome journal append admission binding is invalid")
	}
	return nil
}

func decodeOutcomeJournalFenceKey(encoded string) (ed25519.PublicKey, error) {
	if !strings.HasPrefix(encoded, "ed25519:") {
		return nil, errors.New("outcome journal fence key is invalid")
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(encoded, "ed25519:"))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("outcome journal fence key is invalid")
	}
	return ed25519.PublicKey(raw), nil
}

func (journal *OutcomeJournal) HasActionResolution(stableActionID string, revision uint64) (bool, error) {
	_, found, err := journal.ActionResolutionRecord(stableActionID, revision)
	return found, err
}

// ActionResolutionRecord returns the exact journal record for one immutable
// Action-resolution revision. It is also the crash-recovery anchor for the
// journal-append action that admitted that record.
func (journal *OutcomeJournal) ActionResolutionRecord(stableActionID string, revision uint64) (OutcomeJournalRecord, bool, error) {
	if !canonicalSHA256(stableActionID) || revision == 0 {
		return OutcomeJournalRecord{}, false, errors.New("outcome Action resolution identity is invalid")
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	var result OutcomeJournalRecord
	found := false
	err := journal.scanOutcomeRecordsLocked(func(record OutcomeJournalRecord, _, _, _ int) error {
		if record.Envelope.Body.PayloadProfile != commerce.OperationOutcomeProfileRefV1() {
			return nil
		}
		var body commerce.OperationOutcomeEventBodyV1
		var assertion commerce.ActionResolutionReferencePayloadV1
		if codec.Unmarshal(record.Payload, &body) == nil && body.AssertionProfileURI == commerce.OutcomeProfileActionResolutionReference &&
			codec.Unmarshal(record.Artifacts.AssertionPayload, &assertion) == nil && assertion.StableActionID == stableActionID &&
			assertion.ResolutionStateRevision == revision {
			if found && result.OperationEnvelopeDigest != record.OperationEnvelopeDigest {
				return errors.New("outcome journal contains duplicate Action-resolution identity")
			}
			result, found = record, true
		}
		return nil
	})
	if err != nil {
		return OutcomeJournalRecord{}, false, err
	}
	return result, found, nil
}

func (journal *OutcomeJournal) currentWriterLocked(fence commerce.WriterFence, resolver commerce.CurrentWriterFenceResolver, now time.Time) error {
	if journal.lock == nil || fence.Body.OwnerID != journal.head.OwnerID || fence.Body.AgentID != journal.head.AgentID ||
		fence.Body.AuthorityID != journal.head.AuthorityID || fence.Body.WriterGeneration != journal.head.WriterGeneration {
		return errors.New("stale writer cannot append an outcome")
	}
	if err := commerce.VerifyWriterFence(fence, resolver, now.UTC(), outcomeJournalScope); err != nil {
		return err
	}
	return commerce.ConfirmCurrentWriterFence(fence, resolver, now.UTC())
}

func (journal *OutcomeJournal) recoverHead(generation uint64) error {
	if _, err := journal.recoverPendingArchiveImportLocked(); err != nil {
		return err
	}
	raw, err := journal.root.ReadFile(outcomeJournalHead)
	if errors.Is(err, os.ErrNotExist) {
		return journal.persistHeadLocked()
	}
	if err != nil || len(raw) > 1<<20 {
		return errors.New("outcome journal head is unavailable")
	}
	var prior OutcomeJournalHead
	if decodeStrictJSON(raw, &prior) != nil || validateOutcomeJournalHead(prior) != nil || prior.Schema != outcomeJournalSchema || prior.OwnerID != journal.head.OwnerID ||
		prior.AgentID != journal.head.AgentID || prior.AuthorityID != journal.head.AuthorityID || prior.OrderingDomain != journal.head.OrderingDomain ||
		prior.CohortScopeDigest != journal.head.CohortScopeDigest || prior.WriterGeneration > generation {
		return errors.New("outcome journal head conflicts or rolled back")
	}
	journal.head = prior
	if journal.head.PendingSequence != 0 {
		recovered, recoverErr := journal.recoverPendingRecordLocked()
		if recoverErr != nil {
			return recoverErr
		}
		if !recovered {
			journal.head.GapSequences = append(journal.head.GapSequences, journal.head.PendingSequence)
		}
		journal.head.PendingSequence = 0
	}
	if journal.head.WriterGeneration < generation {
		journal.head.WriterGeneration = generation
	}
	if err := validateOutcomeJournalHead(journal.head); err != nil {
		return err
	}
	if err := journal.reconcileDurableRecordsLocked(); err != nil {
		return err
	}
	if err := journal.validateLatestCheckpointAgainstHeadLocked(); err != nil {
		return err
	}
	return journal.persistHeadLocked()
}

// recoverPendingRecordLocked closes the durable-record/head crash window. A
// record written and fsynced before the atomic head update is committed only
// when its complete signed Operation and append admission bind the pending
// sequence and prior head. Missing bytes become an explicit gap; corrupt or
// conflicting bytes stop recovery instead of being silently omitted.
func (journal *OutcomeJournal) recoverPendingRecordLocked() (bool, error) {
	sequence := journal.head.PendingSequence
	if sequence == 0 {
		return false, nil
	}
	raw, err := journal.root.ReadFile(outcomeRecordName(journal.head.WriterGeneration, sequence))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || len(raw) == 0 || len(raw) > maxOutcomeJournalRecordBytes {
		return false, errors.New("pending outcome journal record is unavailable")
	}
	var record OutcomeJournalRecord
	if decodeStrictJSON(raw, &record) != nil {
		return false, errors.New("pending outcome journal record is invalid")
	}
	checksum, checksumErr := outcomeRecordChecksum(record)
	fields, fieldsErr := commerce.OperationJournalAppendSemanticFieldsV1(journal.head.OwnerID, journal.head.AgentID,
		journal.head.OrderingDomain, record.Epoch, record.Sequence, record.EventContentID)
	actionID, _, actionErr := commerce.DeriveStableActionID(outcomeJournalScope, fields)
	var event commerce.OperationOutcomeEventBodyV1
	verified, envelopeErr := commerce.VerifyOperationOutcomeEnvelopeV1(record.Envelope, record.Payload,
		historicalOutcomeOperationSelfResolver{}, time.Unix(int64(record.Envelope.Body.CreatedAtUnix), 0).UTC())
	envelopeDigest, envelopeDigestErr := commerce.AgentOperationEnvelopeDigestV1(record.Envelope)
	if checksumErr != nil || checksum != record.RecordChecksum || record.PreviousRecordChecksum != journal.head.LastRecordChecksum ||
		record.Epoch != journal.head.WriterGeneration || record.Sequence != sequence || fieldsErr != nil || actionErr != nil ||
		actionID != record.JournalAppendActionID || journal.validateAppendAdmission(record, fields, actionID, journal.head.GapSequences) != nil ||
		codec.Unmarshal(record.Payload, &event) != nil || envelopeErr != nil || !reflect.DeepEqual(verified, event) ||
		envelopeDigestErr != nil || envelopeDigest != record.OperationEnvelopeDigest ||
		record.Envelope.Body.OrderingDomain != journal.head.OrderingDomain || record.Envelope.Body.Epoch != record.Epoch ||
		record.Envelope.Body.Sequence != record.Sequence || record.Envelope.Body.OperationID != record.OperationID ||
		record.Envelope.Body.ObjectID != record.EventContentID || commerce.VerifyOperationOutcomeArtifactBundleV1(event, record.Artifacts) != nil ||
		validateOutcomeJournalSourceResolution(record) != nil {
		return false, errors.New("pending outcome journal record does not bind its reserved head")
	}
	journal.head.LastSequence = record.Sequence
	journal.head.LastEnvelopeDigest = record.OperationEnvelopeDigest
	journal.head.LastRecordChecksum = record.RecordChecksum
	return true, nil
}

func validateOutcomeJournalHead(head OutcomeJournalHead) error {
	if head.Schema != outcomeJournalSchema || head.OwnerID == "" || head.AgentID == "" || head.AuthorityID == "" ||
		!canonicalSHA256(head.OrderingDomain) || !canonicalSHA256(head.CohortScopeDigest) || head.WriterGeneration == 0 ||
		(head.LastSequence == 0) != (head.LastEnvelopeDigest == "") || (head.LastSequence == 0) != (head.LastRecordChecksum == "") ||
		head.LastSequence != 0 && (!canonicalSHA256(head.LastEnvelopeDigest) || !canonicalSHA256(head.LastRecordChecksum)) {
		return errors.New("outcome journal head is invalid")
	}
	var prior uint64
	for _, sequence := range head.GapSequences {
		if sequence == 0 || sequence <= prior || sequence == head.PendingSequence {
			return errors.New("outcome journal gap set is not canonical")
		}
		prior = sequence
	}
	if head.PendingSequence != 0 && (head.PendingSequence <= head.LastSequence || prior >= head.PendingSequence) {
		return errors.New("outcome journal pending sequence is invalid")
	}
	return nil
}

func (journal *OutcomeJournal) persistHeadLocked() error {
	if err := validateOutcomeJournalHead(journal.head); err != nil {
		return err
	}
	raw, err := json.Marshal(journal.head)
	if err != nil {
		return err
	}
	return fileutil.WriteFileAtomicRoot(journal.root, outcomeJournalHead, raw, 0o600)
}

func (journal *OutcomeJournal) reconcileDurableRecordsLocked() error {
	entries, err := readOutcomeRootDirectory(journal.root)
	if err != nil {
		return err
	}
	var committedHeadFound bool
	type durableRecord struct {
		name   string
		record OutcomeJournalRecord
	}
	committedRecords := make([]durableRecord, 0)
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasPrefix(name, "record-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		raw, err := journal.root.ReadFile(name)
		if err != nil || len(raw) > maxOutcomeJournalRecordBytes {
			return errors.New("outcome journal contains an unreadable durable record")
		}
		var record OutcomeJournalRecord
		checksum := ""
		if decodeStrictJSON(raw, &record) == nil {
			checksum, _ = outcomeRecordChecksum(record)
		}
		committed := record.Schema == outcomeJournalSchema && checksum == record.RecordChecksum &&
			record.Sequence <= journal.head.LastSequence && outcomeRecordName(record.Epoch, record.Sequence) == name
		if record.Sequence == journal.head.LastSequence && record.OperationEnvelopeDigest == journal.head.LastEnvelopeDigest {
			committedHeadFound = committed
		}
		if committed {
			committedRecords = append(committedRecords, durableRecord{name: name, record: record})
			continue
		}
		if err := journal.root.Mkdir("quarantine", 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		if err := journal.root.Rename(name, filepath.Join("quarantine", name)); err != nil {
			return fmt.Errorf("quarantine uncommitted outcome record: %w", err)
		}
	}
	if journal.head.LastSequence != 0 && !committedHeadFound {
		return errors.New("outcome journal head is rolled back or lacks its durable record")
	}
	sort.Slice(committedRecords, func(i, j int) bool {
		if committedRecords[i].record.Epoch == committedRecords[j].record.Epoch {
			return committedRecords[i].record.Sequence < committedRecords[j].record.Sequence
		}
		return committedRecords[i].record.Epoch < committedRecords[j].record.Epoch
	})
	previousChecksum := ""
	var previousSequence uint64
	for _, durable := range committedRecords {
		record := durable.record
		if record.PreviousRecordChecksum != previousChecksum || record.Sequence <= previousSequence {
			return errors.New("outcome journal durable record chain is discontinuous")
		}
		for sequence := previousSequence + 1; sequence < record.Sequence; sequence++ {
			if !containsUint64(journal.head.GapSequences, sequence) {
				return errors.New("outcome journal durable record is missing without an explicit gap")
			}
		}
		previousChecksum, previousSequence = record.RecordChecksum, record.Sequence
	}
	if previousChecksum != journal.head.LastRecordChecksum {
		return errors.New("outcome journal durable chain head checksum conflicts")
	}
	return syncOutcomeRootDirectory(journal.root)
}

func containsUint64(values []uint64, target uint64) bool {
	index := sort.Search(len(values), func(index int) bool { return values[index] >= target })
	return index < len(values) && values[index] == target
}

func writeOutcomeRootExclusive(root *os.Root, name string, raw []byte) error {
	if root == nil || name == "" || filepath.IsAbs(name) || filepath.Clean(name) != name {
		return errors.New("outcome journal rooted write is invalid")
	}
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err = file.Write(raw); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return syncOutcomeRootDirectory(root)
}

func syncOutcomeRootDirectory(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return err
	}
	return directory.Close()
}

func readOutcomeRootDirectory(root *os.Root) ([]os.DirEntry, error) {
	directory, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil {
		return nil, readErr
	}
	return entries, closeErr
}

func outcomeRecordChecksum(record OutcomeJournalRecord) (string, error) {
	record.RecordChecksum = ""
	canonical, err := codec.Marshal(record)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(append([]byte("tos.openfox.outcome-journal-record.v1\x00"), canonical...))
	return "sha256:" + hex.EncodeToString(hash[:]), nil
}

func outcomeRecordName(epoch, sequence uint64) string {
	return fmt.Sprintf("record-%020d-%020d.json", epoch, sequence)
}
