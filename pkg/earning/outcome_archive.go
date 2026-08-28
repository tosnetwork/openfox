package earning

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"time"

	"github.com/tosnetwork/openfox/pkg/fileutil"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

const (
	MaxOutcomeArchiveRecordsV1 = 10_000
	MaxOutcomeArchiveBytesV1   = 64 << 20
	outcomeJournalImportIntent = "pending-import.json"
)

type OutcomeJournalArchiveV1 struct {
	Schema  string                 `json:"schema"`
	Head    OutcomeJournalHead     `json:"head"`
	Records []OutcomeJournalRecord `json:"records"`
}

// ExportArchive returns exact signed Operations and artifacts. It does not
// claim that the stream is complete beyond Head; callers pin a signed
// checkpoint digest separately when rollback resistance is required.
func (journal *OutcomeJournal) ExportArchive() (OutcomeJournalArchiveV1, error) {
	if journal == nil {
		return OutcomeJournalArchiveV1{}, errors.New("outcome journal is unavailable")
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	records := make([]OutcomeJournalRecord, 0)
	retainedBytes := 0
	if err := journal.scanOutcomeRecordsLocked(func(record OutcomeJournalRecord, rawBytes, _, total int) error {
		if total > MaxOutcomeArchiveRecordsV1 || retainedBytes > MaxOutcomeArchiveBytesV1-rawBytes {
			return errors.New("outcome archive exceeds the V1 bound")
		}
		retainedBytes += rawBytes
		records = append(records, record)
		return nil
	}); err != nil {
		return OutcomeJournalArchiveV1{}, err
	}
	head := journal.head
	head.GapSequences = append([]uint64(nil), journal.head.GapSequences...)
	if head.PendingSequence != 0 {
		return OutcomeJournalArchiveV1{}, errors.New("outcome archive cannot export a pending reservation")
	}
	if head.LastSequence != 0 && (len(records) == 0 || records[len(records)-1].Sequence != head.LastSequence ||
		records[len(records)-1].RecordChecksum != head.LastRecordChecksum) {
		return OutcomeJournalArchiveV1{}, errors.New("outcome archive exceeds the V1 bound or changed during export")
	}
	archive := OutcomeJournalArchiveV1{Schema: "tos.openfox.operation-outcome-archive.v1", Head: head, Records: records}
	if raw, marshalErr := json.Marshal(archive); marshalErr != nil || len(raw) > MaxOutcomeArchiveBytesV1 {
		return OutcomeJournalArchiveV1{}, errors.New("outcome archive exceeds the V1 byte bound")
	}
	return archive, nil
}

// ImportArchive installs an exact archive only into an empty journal with the
// same ordering domain. It never merges branches or chooses a winner. A
// conflicting/non-empty target is a separate explicit migration problem.
func (journal *OutcomeJournal) ImportArchive(archive OutcomeJournalArchiveV1,
	resolver commerce.AgentOperationAuthorityResolver, now time.Time) error {
	if journal == nil || resolver == nil || now.IsZero() || archive.Schema != "tos.openfox.operation-outcome-archive.v1" ||
		len(archive.Records) == 0 || len(archive.Records) > MaxOutcomeArchiveRecordsV1 {
		return errors.New("outcome archive import is invalid or unbounded")
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.lock == nil || journal.head.LastSequence != 0 || journal.head.PendingSequence != 0 ||
		archive.Head.OwnerID != journal.head.OwnerID || archive.Head.AgentID != journal.head.AgentID ||
		archive.Head.AuthorityID != journal.head.AuthorityID || archive.Head.OrderingDomain != journal.head.OrderingDomain ||
		archive.Head.CohortScopeDigest != journal.head.CohortScopeDigest || archive.Head.LastSequence == 0 {
		return errors.New("outcome archive cannot be imported into this journal")
	}
	if err := journal.validateArchiveRecordsLocked(archive, resolver); err != nil {
		return err
	}
	rawArchive, err := json.Marshal(archive)
	if err != nil || len(rawArchive) == 0 || len(rawArchive) > MaxOutcomeArchiveBytesV1 {
		return errors.New("outcome archive exceeds the V1 byte bound")
	}
	// The complete bounded archive is the crash-recovery intent. It is durable
	// before any materialized record, so startup can finish exactly this import
	// instead of treating a partial record set as a new local branch.
	if err := fileutil.WriteFileAtomicRoot(journal.root, outcomeJournalImportIntent, rawArchive, 0o600); err != nil {
		return err
	}
	if err := journal.materializeArchiveRecordsLocked(archive); err != nil {
		return err
	}
	return journal.promoteImportedArchiveLocked(archive)
}

func (journal *OutcomeJournal) validateArchiveRecordsLocked(archive OutcomeJournalArchiveV1,
	resolver commerce.AgentOperationAuthorityResolver) error {
	if archive.Schema != "tos.openfox.operation-outcome-archive.v1" || len(archive.Records) == 0 ||
		len(archive.Records) > MaxOutcomeArchiveRecordsV1 || validateOutcomeJournalHead(archive.Head) != nil ||
		archive.Head.OwnerID != journal.head.OwnerID || archive.Head.AgentID != journal.head.AgentID ||
		archive.Head.AuthorityID != journal.head.AuthorityID || archive.Head.OrderingDomain != journal.head.OrderingDomain ||
		archive.Head.CohortScopeDigest != journal.head.CohortScopeDigest {
		return errors.New("outcome archive identity or bounds are invalid")
	}
	previous := ""
	var sequence uint64
	totalBytes := 4096
	for _, record := range archive.Records {
		checksum, err := outcomeRecordChecksum(record)
		recordRaw, rawErr := json.Marshal(record)
		if err != nil || rawErr != nil || len(recordRaw) > maxOutcomeJournalRecordBytes || checksum != record.RecordChecksum ||
			record.PreviousRecordChecksum != previous || record.Sequence <= sequence {
			return errors.New("outcome archive record chain is invalid")
		}
		if totalBytes > MaxOutcomeArchiveBytesV1-len(recordRaw) {
			return errors.New("outcome archive exceeds the V1 byte bound")
		}
		totalBytes += len(recordRaw)
		for gap := sequence + 1; gap < record.Sequence; gap++ {
			if !containsUint64(archive.Head.GapSequences, gap) {
				return errors.New("outcome archive hides a sequence gap")
			}
		}
		fields, fieldsErr := commerce.OperationJournalAppendSemanticFieldsV1(journal.head.OwnerID, journal.head.AgentID,
			journal.head.OrderingDomain, record.Epoch, record.Sequence, record.EventContentID)
		actionID, _, actionErr := commerce.DeriveStableActionID(outcomeJournalScope, fields)
		if fieldsErr != nil || actionErr != nil || actionID != record.JournalAppendActionID ||
			journal.validateAppendAdmission(record, fields, actionID, archive.Head.GapSequences) != nil {
			return errors.New("outcome archive append admission is invalid")
		}
		var body commerce.OperationOutcomeEventBodyV1
		if codec.Unmarshal(record.Payload, &body) != nil || commerce.VerifyOperationOutcomeArtifactBundleV1(body, record.Artifacts) != nil ||
			validateOutcomeJournalSourceResolution(record) != nil {
			return errors.New("outcome archive artifact bundle is invalid")
		}
		verificationTime := time.Unix(int64(record.Envelope.Body.CreatedAtUnix), 0).UTC()
		verified, err := commerce.VerifyOperationOutcomeEnvelopeV1(record.Envelope, record.Payload, resolver, verificationTime)
		envelopeDigest, digestErr := commerce.AgentOperationEnvelopeDigestV1(record.Envelope)
		if err != nil || !reflect.DeepEqual(verified, body) || record.Envelope.Body.Sequence != record.Sequence || record.Envelope.Body.Epoch != record.Epoch ||
			record.Envelope.Body.OrderingDomain != journal.head.OrderingDomain || digestErr != nil || envelopeDigest != record.OperationEnvelopeDigest ||
			record.Envelope.Body.OperationID != record.OperationID || record.Envelope.Body.ObjectID != record.EventContentID {
			return errors.New("outcome archive Operation authority or ordering is invalid")
		}
		previous, sequence = checksum, record.Sequence
	}
	if sequence != archive.Head.LastSequence || previous != archive.Head.LastRecordChecksum ||
		archive.Records[len(archive.Records)-1].OperationEnvelopeDigest != archive.Head.LastEnvelopeDigest {
		return errors.New("outcome archive head does not commit its record chain")
	}
	return nil
}

func (journal *OutcomeJournal) materializeArchiveRecordsLocked(archive OutcomeJournalArchiveV1) error {
	for _, record := range archive.Records {
		raw, err := json.Marshal(record)
		if err != nil {
			return err
		}
		name := outcomeRecordName(record.Epoch, record.Sequence)
		if err := writeOutcomeRootExclusive(journal.root, name, raw); err != nil {
			if !errors.Is(err, os.ErrExist) {
				return err
			}
			existing, readErr := journal.root.ReadFile(name)
			if readErr != nil || !bytes.Equal(existing, raw) {
				return errors.New("outcome archive import encountered a fork")
			}
		}
	}
	return nil
}

func (journal *OutcomeJournal) promoteImportedArchiveLocked(archive OutcomeJournalArchiveV1) error {
	journal.head.LastSequence = archive.Head.LastSequence
	journal.head.LastEnvelopeDigest = archive.Head.LastEnvelopeDigest
	journal.head.LastRecordChecksum = archive.Head.LastRecordChecksum
	journal.head.GapSequences = append([]uint64(nil), archive.Head.GapSequences...)
	if err := journal.persistHeadLocked(); err != nil {
		return err
	}
	if err := journal.root.Remove(outcomeJournalImportIntent); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncOutcomeRootDirectory(journal.root)
}

// recoverPendingArchiveImportLocked completes an exact import whose durable
// intent survived a crash. The retained append-authority signatures anchor the
// materialized records; no source is silently selected or merged.
func (journal *OutcomeJournal) recoverPendingArchiveImportLocked() (bool, error) {
	raw, err := journal.root.ReadFile(outcomeJournalImportIntent)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || len(raw) == 0 || len(raw) > MaxOutcomeArchiveBytesV1 {
		return false, errors.New("pending outcome archive import is unavailable")
	}
	var archive OutcomeJournalArchiveV1
	if decodeStrictJSON(raw, &archive) != nil {
		return false, errors.New("pending outcome archive import is invalid")
	}
	if err := journal.validateArchiveRecordsLocked(archive, historicalOutcomeOperationSelfResolver{}); err != nil {
		return false, err
	}
	if err := journal.materializeArchiveRecordsLocked(archive); err != nil {
		return false, err
	}
	if err := journal.promoteImportedArchiveLocked(archive); err != nil {
		return false, err
	}
	return true, nil
}
