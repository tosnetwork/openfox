package earning

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

const (
	relayTerminalAccountingHighWaterSchema = "tos.openfox.agent-relay-terminal-accounting-high-water.v1"
	relayTerminalAccountingRecordSchema    = "tos.openfox.agent-relay-terminal-accounting-record.v1"
	relayTerminalAccountingReceiptDomain   = "tos.openfox.agent-relay-terminal-accounting-receipt.v1"
	relayTerminalAccountingHighWaterFile   = "agent-relay-terminal-accounting-high-water.json"
	relayTerminalAccountingRecordDirectory = ".agent-relay-terminal-accounting-records"
	maximumRelayTerminalAccountingBytes    = 128 << 10
	maximumRelayTerminalAccountingRecords  = 65536
	maximumRelayTerminalAccountingRegistry = 256 << 20
)

type RelayComponentFulfillment string

const (
	RelayComponentFulfilled     RelayComponentFulfillment = "fulfilled"
	RelayComponentUnfulfilled   RelayComponentFulfillment = "unfulfilled"
	RelayComponentNotApplicable RelayComponentFulfillment = "not_applicable"
)

type RelayFeeAccountingStatus string

const (
	RelayFeeDue    RelayFeeAccountingStatus = "due"
	RelayFeeNotDue RelayFeeAccountingStatus = "not_due"
)

type RelaySponsorshipFinancialDisposition string

const (
	RelaySponsorshipNotApplicable           RelaySponsorshipFinancialDisposition = "not_applicable"
	RelaySponsorshipNotIncurred             RelaySponsorshipFinancialDisposition = "not_incurred"
	RelaySponsorshipReimbursementUnresolved RelaySponsorshipFinancialDisposition = "provider_reimbursement_unresolved"
)

type RelayFeeObligationAccounting struct {
	ObligationID string                   `json:"obligation_id"`
	Kind         string                   `json:"kind"`
	Amount       agentrelay.AssetAmount   `json:"amount"`
	Status       RelayFeeAccountingStatus `json:"status"`
}

// RelayTerminalAccountingHandoffStore is an accounting/portfolio sink that is
// independent of the route journal. Commit must be idempotent across crashes
// and return the same receipt/revision for the same terminal reference.
type RelayTerminalAccountingHandoffStore interface {
	CommitRelayTerminalHandoff(context.Context, RelayTerminalHandoffReference,
		RelayAttempt, RelayExecutionResult, time.Time) (RelayTerminalAccountingReceipt, error)
}

type RelayTerminalAccountingReceipt struct {
	ReceiptDigest  string
	Revision       uint64
	RecordedAtUnix uint64
}

// RelayTerminalFinancialReport is the bounded, durable accounting projection
// exposed to portfolio/reporting code. It carries no BOC or proof bytes; the
// content-addressed route artifact remains the recovery authority until this
// record's receipt is acknowledged by the route journal.
type RelayTerminalFinancialReport struct {
	OwnerID                              string
	AgentID                              string
	StableActionID                       string
	ExactRequestDigest                   string
	RelayExecutionDigest                 string
	ProviderAgentID                      string
	RouteGeneration                      uint64
	Mode                                 agentrelay.Mode
	AssuranceLevel                       agentrelay.AssuranceLevel
	AgreementBodyDigest                  string
	RelayObligationID                    string
	SponsorshipObligationID              string
	FeeObligationIDs                     []string
	FeeAccounting                        []RelayFeeObligationAccounting
	ReservedSponsorship                  *agentrelay.AssetAmount
	RelayFulfillment                     RelayComponentFulfillment
	SponsorshipFulfillment               RelayComponentFulfillment
	ClientFeeReservationReleased         bool
	ClientSponsorshipReservationReleased bool
	ProviderSponsorshipDisposition       RelaySponsorshipFinancialDisposition
	TerminalOutcome                      agentrelay.TerminalOutcome
	ProtectedArtifactDigest              string
	TerminalResolutionDigest             string
	TerminalFinalityEvidenceDigest       string
	AccountingReceiptDigest              string
	AccountingRevision                   uint64
	RecordedAtUnix                       uint64
}

type relayTerminalAccountingHighWater struct {
	Schema       string `json:"schema"`
	OwnerID      string `json:"owner_id,omitempty"`
	AgentID      string `json:"agent_id,omitempty"`
	NextRevision uint64 `json:"next_revision"`
}

// relayTerminalAccountingRecord is deliberately a bounded economic
// projection, not a second copy of the potentially multi-megabyte proof. Its
// protected route artifact and exact finality-evidence digests remain the
// authoritative recovery references until this record is committed.
type relayTerminalAccountingRecord struct {
	Schema                               string                               `json:"schema"`
	OwnerID                              string                               `json:"owner_id"`
	AgentID                              string                               `json:"agent_id"`
	Reference                            RelayTerminalHandoffReference        `json:"terminal_handoff_reference"`
	RelayExecutionDigest                 string                               `json:"relay_execution_digest"`
	ProviderAgentID                      string                               `json:"provider_agent_id"`
	Mode                                 agentrelay.Mode                      `json:"mode"`
	AssuranceLevel                       agentrelay.AssuranceLevel            `json:"assurance_level"`
	AgreementBodyDigest                  string                               `json:"agreement_body_digest"`
	RelayObligationID                    string                               `json:"relay_obligation_id,omitempty"`
	SponsorshipObligationID              string                               `json:"sponsorship_obligation_id,omitempty"`
	FeeObligationIDs                     []string                             `json:"fee_obligation_ids"`
	FeeLines                             []agentrelay.FeeLine                 `json:"fee_lines"`
	FeeAccounting                        []RelayFeeObligationAccounting       `json:"fee_accounting"`
	ReservedSponsorship                  *agentrelay.AssetAmount              `json:"reserved_sponsorship,omitempty"`
	RelayFulfillment                     RelayComponentFulfillment            `json:"relay_fulfillment"`
	SponsorshipFulfillment               RelayComponentFulfillment            `json:"sponsorship_fulfillment"`
	ClientFeeReservationReleased         bool                                 `json:"client_fee_reservation_released"`
	ClientSponsorshipReservationReleased bool                                 `json:"client_sponsorship_reservation_released"`
	ProviderSponsorshipDisposition       RelaySponsorshipFinancialDisposition `json:"provider_sponsorship_disposition"`
	TerminalOutcome                      agentrelay.TerminalOutcome           `json:"terminal_outcome"`
	TerminalResolutionDigest             string                               `json:"terminal_resolution_digest"`
	TerminalFinalityEvidenceDigest       string                               `json:"terminal_finality_evidence_digest"`
	Revision                             uint64                               `json:"revision"`
	RecordedAtUnix                       uint64                               `json:"recorded_at_unix"`
	ReceiptDigest                        string                               `json:"receipt_digest"`
}

type relayTerminalAccountingReceiptPreimage struct {
	Schema                               string                               `json:"schema"`
	OwnerID                              string                               `json:"owner_id"`
	AgentID                              string                               `json:"agent_id"`
	Reference                            RelayTerminalHandoffReference        `json:"terminal_handoff_reference"`
	RelayExecutionDigest                 string                               `json:"relay_execution_digest"`
	ProviderAgentID                      string                               `json:"provider_agent_id"`
	Mode                                 agentrelay.Mode                      `json:"mode"`
	AssuranceLevel                       agentrelay.AssuranceLevel            `json:"assurance_level"`
	AgreementBodyDigest                  string                               `json:"agreement_body_digest"`
	RelayObligationID                    string                               `json:"relay_obligation_id,omitempty"`
	SponsorshipObligationID              string                               `json:"sponsorship_obligation_id,omitempty"`
	FeeObligationIDs                     []string                             `json:"fee_obligation_ids"`
	FeeLines                             []agentrelay.FeeLine                 `json:"fee_lines"`
	FeeAccounting                        []RelayFeeObligationAccounting       `json:"fee_accounting"`
	ReservedSponsorship                  *agentrelay.AssetAmount              `json:"reserved_sponsorship,omitempty"`
	RelayFulfillment                     RelayComponentFulfillment            `json:"relay_fulfillment"`
	SponsorshipFulfillment               RelayComponentFulfillment            `json:"sponsorship_fulfillment"`
	ClientFeeReservationReleased         bool                                 `json:"client_fee_reservation_released"`
	ClientSponsorshipReservationReleased bool                                 `json:"client_sponsorship_reservation_released"`
	ProviderSponsorshipDisposition       RelaySponsorshipFinancialDisposition `json:"provider_sponsorship_disposition"`
	TerminalOutcome                      agentrelay.TerminalOutcome           `json:"terminal_outcome"`
	TerminalResolutionDigest             string                               `json:"terminal_resolution_digest"`
	TerminalFinalityEvidenceDigest       string                               `json:"terminal_finality_evidence_digest"`
	Revision                             uint64                               `json:"revision"`
	RecordedAtUnix                       uint64                               `json:"recorded_at_unix"`
}

type DurableRelayTerminalAccountingJournal struct {
	mu                    sync.Mutex
	directory             string
	directoryHandle       *relayPinnedDirectory
	highWaterPath         string
	recordDirectory       string
	recordDirectoryHandle *relayPinnedDirectory
	lock                  *os.File
	domainLock            *localEconomicDomainLock
	ownerDomainLock       *localEconomicDomainLock
	ownerID               string
	agentID               string
	nextRevision          uint64
	recordCount           int
	recordBytes           int64
	// recordWrite is a narrow fault-injection seam for proving recovery from
	// an atomic write that committed before its caller observed an error. It is
	// nil in production; callers cannot access this unexported field.
	recordWrite func(string, []byte) error
}

func (*DurableRelayTerminalAccountingJournal) HasRollbackResistantRelayTerminalAccountingHighWater() bool {
	return false
}

func OpenDurableRelayTerminalAccountingJournal(directory string) (*DurableRelayTerminalAccountingJournal, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, errors.New("relay terminal accounting directory must be clean and absolute")
	}
	if err := validateRelayJournalDirectorySecurity(directory); err != nil {
		return nil, errors.New("relay terminal accounting directory must be owner-private and cannot be a symlink")
	}
	directoryHandle, err := openRelayPinnedDirectory(directory)
	if err != nil {
		return nil, err
	}
	domainLock, err := acquireLocalEconomicDomainLock("relay-terminal-accounting\x00" + directory)
	if err != nil {
		_ = directoryHandle.close()
		return nil, err
	}
	lock, err := acquireRelayJournalLockRoot(directoryHandle.root)
	if err != nil {
		_ = domainLock.Close()
		_ = directoryHandle.close()
		return nil, err
	}
	lockInfo, lockErr := lock.Stat()
	rootLockInfo, rootLockErr := directoryHandle.root.Lstat(relayJournalLockFile)
	if lockErr != nil || rootLockErr != nil || !os.SameFile(lockInfo, rootLockInfo) ||
		directoryHandle.ensureAttached() != nil {
		_ = releaseRelayJournalLock(lock)
		_ = domainLock.Close()
		_ = directoryHandle.close()
		return nil, errors.New("relay terminal accounting lock does not belong to retained directory")
	}
	recordDirectory := filepath.Join(directory, relayTerminalAccountingRecordDirectory)
	if err := directoryHandle.mkdir(relayTerminalAccountingRecordDirectory); err != nil {
		_ = releaseRelayJournalLock(lock)
		_ = domainLock.Close()
		_ = directoryHandle.close()
		return nil, errors.New("create relay terminal accounting registry")
	}
	recordDirectoryHandle, err := openRelayPinnedDirectory(recordDirectory)
	if err != nil || directoryHandle.ensureChild(relayTerminalAccountingRecordDirectory,
		recordDirectoryHandle) != nil {
		_ = releaseRelayJournalLock(lock)
		_ = domainLock.Close()
		if recordDirectoryHandle != nil {
			_ = recordDirectoryHandle.close()
		}
		_ = directoryHandle.close()
		return nil, errors.New("relay terminal accounting registry must be owner-private")
	}
	journal := &DurableRelayTerminalAccountingJournal{directory: directory,
		highWaterPath:   filepath.Join(directory, relayTerminalAccountingHighWaterFile),
		recordDirectory: recordDirectory, lock: lock, directoryHandle: directoryHandle,
		recordDirectoryHandle: recordDirectoryHandle, domainLock: domainLock}
	recordCount, recordBytes, err := countRelayPermanentRegistryPinned(recordDirectoryHandle, ".", ".json",
		maximumRelayTerminalAccountingRecords, maximumRelayTerminalAccountingBytes,
		maximumRelayTerminalAccountingRegistry)
	if err != nil {
		_ = recordDirectoryHandle.close()
		_ = directoryHandle.close()
		_ = releaseRelayJournalLock(lock)
		_ = domainLock.Close()
		return nil, errors.New("count relay terminal accounting registry")
	}
	journal.recordCount, journal.recordBytes = recordCount, recordBytes
	if err := journal.loadHighWater(); err != nil {
		journal.closeOwnerDomain()
		_ = recordDirectoryHandle.close()
		_ = directoryHandle.close()
		_ = releaseRelayJournalLock(lock)
		_ = domainLock.Close()
		return nil, err
	}
	return journal, nil
}

func (journal *DurableRelayTerminalAccountingJournal) Close() error {
	if journal == nil {
		return nil
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.lock == nil {
		return nil
	}
	lock := journal.lock
	journal.lock = nil
	err := releaseRelayJournalLock(lock)
	if ownerErr := journal.ownerDomainLock.Close(); err == nil && ownerErr != nil {
		err = ownerErr
	}
	journal.ownerDomainLock = nil
	if domainErr := journal.domainLock.Close(); err == nil && domainErr != nil {
		err = domainErr
	}
	journal.domainLock = nil
	if closeErr := journal.recordDirectoryHandle.close(); err == nil && closeErr != nil {
		err = closeErr
	}
	if closeErr := journal.directoryHandle.close(); err == nil && closeErr != nil {
		err = closeErr
	}
	journal.recordDirectoryHandle = nil
	journal.directoryHandle = nil
	return err
}

func (journal *DurableRelayTerminalAccountingJournal) bindOwnerDomain(ownerID, agentID string) error {
	if journal == nil || !boundedRelayTrustDomain(ownerID) || !boundedRelayTrustDomain(agentID) {
		return agentrelay.ErrRelayInvalidState
	}
	if journal.ownerID != "" || journal.agentID != "" {
		if journal.ownerID != ownerID || journal.agentID != agentID || journal.ownerDomainLock == nil ||
			journal.ownerDomainLock.connection == nil {
			return agentrelay.ErrRelayConflict
		}
		return nil
	}
	lock, err := acquireLocalEconomicDomainLock("relay-accounting-owner-agent\x00" + ownerID + "\x00" + agentID)
	if err != nil {
		return err
	}
	journal.ownerID, journal.agentID, journal.ownerDomainLock = ownerID, agentID, lock
	return nil
}

func (journal *DurableRelayTerminalAccountingJournal) closeOwnerDomain() {
	if journal == nil {
		return
	}
	_ = journal.ownerDomainLock.Close()
	journal.ownerDomainLock = nil
	journal.ownerID, journal.agentID = "", ""
}

func (journal *DurableRelayTerminalAccountingJournal) ensureStorageIdentity() error {
	if journal == nil || journal.lock == nil || journal.domainLock == nil || journal.domainLock.connection == nil ||
		journal.directoryHandle == nil || journal.recordDirectoryHandle == nil {
		return errors.New("relay terminal accounting storage identity is unavailable")
	}
	if err := journal.directoryHandle.ensureAttached(); err != nil {
		return err
	}
	if err := journal.recordDirectoryHandle.ensureAttached(); err != nil {
		return err
	}
	if err := journal.directoryHandle.ensureChild(relayTerminalAccountingRecordDirectory,
		journal.recordDirectoryHandle); err != nil {
		return err
	}
	lockInfo, lockErr := journal.lock.Stat()
	rootLockInfo, rootLockErr := journal.directoryHandle.root.Lstat(relayJournalLockFile)
	if lockErr != nil || rootLockErr != nil || !os.SameFile(lockInfo, rootLockInfo) {
		journal.directoryHandle.poison()
		return errors.New("relay terminal accounting process lock was replaced")
	}
	return nil
}

func (journal *DurableRelayTerminalAccountingJournal) rootedPath(path string) (*relayPinnedDirectory, string, error) {
	if journal == nil || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, "", agentrelay.ErrRelayInvalidState
	}
	for _, location := range []struct {
		path string
		root *relayPinnedDirectory
	}{{journal.recordDirectory, journal.recordDirectoryHandle}, {journal.directory, journal.directoryHandle}} {
		name, err := filepath.Rel(location.path, path)
		if location.root == nil || err != nil || name == ".." ||
			strings.HasPrefix(name, ".."+string(filepath.Separator)) || !filepath.IsLocal(name) {
			continue
		}
		return location.root, name, nil
	}
	return nil, "", errors.New("relay terminal accounting path escapes retained directory capabilities")
}

func (journal *DurableRelayTerminalAccountingJournal) openFile(path string) (*os.File, error) {
	if err := journal.ensureStorageIdentity(); err != nil {
		return nil, err
	}
	directory, name, err := journal.rootedPath(path)
	if err != nil {
		return nil, err
	}
	return directory.openFile(name)
}

func (journal *DurableRelayTerminalAccountingJournal) writeAtomic(path string, raw []byte) error {
	if err := journal.ensureStorageIdentity(); err != nil {
		return err
	}
	directory, name, err := journal.rootedPath(path)
	if err != nil {
		return err
	}
	if err := directory.writeAtomic(name, raw); err != nil {
		return err
	}
	return journal.ensureStorageIdentity()
}

func (journal *DurableRelayTerminalAccountingJournal) writeRecordAtomic(path string, raw []byte) error {
	if journal.recordWrite != nil {
		return journal.recordWrite(path, raw)
	}
	return journal.writeAtomic(path, raw)
}

func (journal *DurableRelayTerminalAccountingJournal) refreshRecordRegistryCounts() error {
	count, bytes, err := countRelayPermanentRegistryPinned(journal.recordDirectoryHandle, ".", ".json",
		maximumRelayTerminalAccountingRecords, maximumRelayTerminalAccountingBytes,
		maximumRelayTerminalAccountingRegistry)
	if err != nil {
		// A failed reconciliation must never make capacity appear available.
		journal.recordCount = maximumRelayTerminalAccountingRecords
		journal.recordBytes = maximumRelayTerminalAccountingRegistry
		return errors.New("reconcile relay terminal accounting registry")
	}
	journal.recordCount, journal.recordBytes = count, bytes
	return nil
}

func (journal *DurableRelayTerminalAccountingJournal) loadHighWater() error {
	file, err := journal.openFile(journal.highWaterPath)
	if errors.Is(err, os.ErrNotExist) {
		journal.nextRevision = 1
		return journal.persistHighWater(1)
	}
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !relayJournalFileInfoSecure(info) ||
		info.Size() <= 0 || info.Size() > maximumRelayTerminalAccountingBytes {
		return errors.New("relay terminal accounting high-water is invalid")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximumRelayTerminalAccountingBytes+1))
	var value relayTerminalAccountingHighWater
	if err != nil || decodeStrictJSON(raw, &value) != nil || value.Schema != relayTerminalAccountingHighWaterSchema ||
		value.NextRevision == 0 || (value.OwnerID == "") != (value.AgentID == "") || value.OwnerID != "" &&
		(!boundedRelayTrustDomain(value.OwnerID) || !boundedRelayTrustDomain(value.AgentID)) {
		return errors.New("relay terminal accounting high-water cannot be verified")
	}
	if value.OwnerID == "" && journal.recordCount != 0 {
		return errors.New("relay terminal accounting records lack their owner authority domain")
	}
	if value.OwnerID != "" {
		if err := journal.bindOwnerDomain(value.OwnerID, value.AgentID); err != nil {
			return errors.New("acquire relay terminal accounting owner authority domain")
		}
	}
	journal.nextRevision = value.NextRevision
	return nil
}

func (journal *DurableRelayTerminalAccountingJournal) persistHighWater(next uint64) error {
	if next == 0 {
		return agentrelay.ErrRelayInvalidState
	}
	raw, err := jsonMarshalBounded(relayTerminalAccountingHighWater{
		Schema: relayTerminalAccountingHighWaterSchema, OwnerID: journal.ownerID,
		AgentID: journal.agentID, NextRevision: next}, maximumRelayTerminalAccountingBytes)
	if err != nil {
		return err
	}
	return journal.writeAtomic(journal.highWaterPath, raw)
}

func jsonMarshalBounded(value any, maximum int) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) == 0 || len(raw) > maximum {
		return nil, errors.New("encode bounded relay terminal accounting value")
	}
	return raw, nil
}

func (journal *DurableRelayTerminalAccountingJournal) recordPath(stableActionID string,
	createShard bool) (string, error) {
	if journal == nil || !canonicalSHA256(stableActionID) || !filepath.IsAbs(journal.recordDirectory) {
		return "", agentrelay.ErrRelayInvalidState
	}
	hexDigest := strings.TrimPrefix(stableActionID, "sha256:")
	shard := filepath.Join(journal.recordDirectory, hexDigest[:2])
	if createShard {
		if err := journal.ensureStorageIdentity(); err != nil {
			return "", err
		}
		if err := journal.recordDirectoryHandle.mkdir(hexDigest[:2]); err != nil {
			return "", errors.New("create relay terminal accounting shard")
		}
	}
	return filepath.Join(shard, hexDigest+".json"), nil
}

func relayTerminalAccountingPreimage(record relayTerminalAccountingRecord) relayTerminalAccountingReceiptPreimage {
	return relayTerminalAccountingReceiptPreimage{Schema: record.Schema, OwnerID: record.OwnerID,
		AgentID: record.AgentID, Reference: record.Reference,
		RelayExecutionDigest: record.RelayExecutionDigest, ProviderAgentID: record.ProviderAgentID,
		Mode: record.Mode, AssuranceLevel: record.AssuranceLevel, AgreementBodyDigest: record.AgreementBodyDigest,
		RelayObligationID: record.RelayObligationID, SponsorshipObligationID: record.SponsorshipObligationID,
		FeeObligationIDs:    append([]string(nil), record.FeeObligationIDs...),
		FeeLines:            append([]agentrelay.FeeLine(nil), record.FeeLines...),
		FeeAccounting:       append([]RelayFeeObligationAccounting(nil), record.FeeAccounting...),
		ReservedSponsorship: cloneRelayAssetAmount(record.ReservedSponsorship),
		RelayFulfillment:    record.RelayFulfillment, SponsorshipFulfillment: record.SponsorshipFulfillment,
		ClientFeeReservationReleased:         record.ClientFeeReservationReleased,
		ClientSponsorshipReservationReleased: record.ClientSponsorshipReservationReleased,
		ProviderSponsorshipDisposition:       record.ProviderSponsorshipDisposition,
		TerminalOutcome:                      record.TerminalOutcome,
		TerminalResolutionDigest:             record.TerminalResolutionDigest,
		TerminalFinalityEvidenceDigest:       record.TerminalFinalityEvidenceDigest,
		Revision:                             record.Revision, RecordedAtUnix: record.RecordedAtUnix}
}

func cloneRelayAssetAmount(value *agentrelay.AssetAmount) *agentrelay.AssetAmount {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func relayTerminalComponentFulfillment(mode agentrelay.Mode, outcome agentrelay.TerminalOutcome) (
	RelayComponentFulfillment, RelayComponentFulfillment, error) {
	switch mode {
	case agentrelay.ModeRelayExact:
		switch outcome {
		case agentrelay.OutcomeFinalizedSuccess, agentrelay.OutcomeCorroboratedSuccess:
			return RelayComponentFulfilled, RelayComponentNotApplicable, nil
		case agentrelay.OutcomeFinalizedExpired, agentrelay.OutcomeFinalizedAbsent,
			agentrelay.OutcomeFinalizedInvalidated, agentrelay.OutcomeCorroboratedExpired,
			agentrelay.OutcomeCorroboratedAbsent, agentrelay.OutcomeCorroboratedInvalidated:
			return RelayComponentUnfulfilled, RelayComponentNotApplicable, nil
		}
	case agentrelay.ModeSponsorOnly:
		switch outcome {
		case agentrelay.OutcomeFinalizedSponsorshipOnly, agentrelay.OutcomeCorroboratedSponsorshipOnly:
			return RelayComponentNotApplicable, RelayComponentFulfilled, nil
		case agentrelay.OutcomeFinalizedExpired, agentrelay.OutcomeFinalizedAbsent,
			agentrelay.OutcomeFinalizedInvalidated, agentrelay.OutcomeCorroboratedExpired,
			agentrelay.OutcomeCorroboratedAbsent, agentrelay.OutcomeCorroboratedInvalidated:
			return RelayComponentNotApplicable, RelayComponentUnfulfilled, nil
		}
	case agentrelay.ModeSponsorAndRelay:
		switch outcome {
		case agentrelay.OutcomeFinalizedSuccess, agentrelay.OutcomeCorroboratedSuccess:
			return RelayComponentFulfilled, RelayComponentFulfilled, nil
		case agentrelay.OutcomeFinalizedSponsorshipOnly, agentrelay.OutcomeCorroboratedSponsorshipOnly:
			return RelayComponentUnfulfilled, RelayComponentFulfilled, nil
		case agentrelay.OutcomeFinalizedRelayOnly, agentrelay.OutcomeCorroboratedRelayOnly:
			return RelayComponentFulfilled, RelayComponentUnfulfilled, nil
		case agentrelay.OutcomeFinalizedExpired, agentrelay.OutcomeFinalizedAbsent,
			agentrelay.OutcomeFinalizedInvalidated, agentrelay.OutcomeCorroboratedExpired,
			agentrelay.OutcomeCorroboratedAbsent, agentrelay.OutcomeCorroboratedInvalidated:
			return RelayComponentUnfulfilled, RelayComponentUnfulfilled, nil
		}
	}
	return "", "", errors.New("relay terminal outcome has no deterministic component-fulfillment projection")
}

func relaySponsorshipFinancialDisposition(
	fulfillment RelayComponentFulfillment) (RelaySponsorshipFinancialDisposition, error) {
	switch fulfillment {
	case RelayComponentNotApplicable:
		return RelaySponsorshipNotApplicable, nil
	case RelayComponentUnfulfilled:
		return RelaySponsorshipNotIncurred, nil
	case RelayComponentFulfilled:
		// A successful top-up incurs Provider value exposure. Client route
		// terminality cannot pretend that reimbursement or an authorized write-off
		// has occurred; ProviderService.ReleaseSponsorshipExposure remains the
		// separate evidence-bound authority for that transition.
		return RelaySponsorshipReimbursementUnresolved, nil
	default:
		return "", errors.New("relay sponsorship fulfillment is unknown")
	}
}

func relayTerminalFeeAccountingForAttempt(attempt RelayAttempt, relayFulfillment,
	sponsorshipFulfillment RelayComponentFulfillment) ([]RelayFeeObligationAccounting, error) {
	execution := attempt.Execution
	if len(execution.FeeObligationIDs) != len(execution.ProviderQuote.Body.FeeLines) ||
		len(execution.FeeObligationIDs) == 0 {
		return nil, errors.New("relay fee obligation set is incomplete")
	}
	obligations := make(map[string]commerce.AgreementObligation, len(attempt.Agreement.Body.Obligations))
	for _, obligation := range attempt.Agreement.Body.Obligations {
		if _, duplicate := obligations[obligation.ObligationID]; duplicate {
			return nil, errors.New("relay Agreement has duplicate obligation identity")
		}
		obligations[obligation.ObligationID] = obligation
	}
	lines := make(map[string]agentrelay.FeeLine, len(execution.ProviderQuote.Body.FeeLines))
	for _, line := range execution.ProviderQuote.Body.FeeLines {
		if _, duplicate := lines[line.Kind]; duplicate {
			return nil, errors.New("relay Quote has duplicate fee kind")
		}
		lines[line.Kind] = line
	}
	result := make([]RelayFeeObligationAccounting, 0, len(execution.FeeObligationIDs))
	seenKinds := make(map[string]bool, len(lines))
	for _, obligationID := range execution.FeeObligationIDs {
		obligation, found := obligations[obligationID]
		line, quoted := lines[obligation.Kind]
		if !found || !quoted || seenKinds[obligation.Kind] || obligation.Amount == nil ||
			obligation.ObligorAgentID != execution.QuoteRequest.Body.RequesterAgentID ||
			obligation.BeneficiaryAgentID != execution.ProviderQuote.Body.ProviderAgentID ||
			obligation.Amount.AssetNamespace != line.Amount.Asset.AssetNamespace ||
			obligation.Amount.AssetIdentifier != line.Amount.Asset.AssetIdentifier ||
			obligation.Amount.Unit != line.Amount.Asset.Unit ||
			obligation.Amount.AmountAtomic != line.Amount.AmountAtomic || obligation.Amount.AmountDecimal != "" {
			return nil, errors.New("relay fee obligation cannot be mapped to its exact quoted fee")
		}
		status := RelayFeeNotDue
		switch obligation.Kind {
		case agentrelay.ObligationRelayFee:
			if relayFulfillment == RelayComponentFulfilled {
				status = RelayFeeDue
			}
		case agentrelay.ObligationSponsorshipFee:
			if sponsorshipFulfillment == RelayComponentFulfilled {
				status = RelayFeeDue
			}
		default:
			return nil, errors.New("relay accounting does not know this fee semantic")
		}
		seenKinds[obligation.Kind] = true
		result = append(result, RelayFeeObligationAccounting{ObligationID: obligationID,
			Kind: obligation.Kind, Amount: line.Amount, Status: status})
	}
	if len(seenKinds) != len(lines) {
		return nil, errors.New("relay accounting fee mapping omitted a quoted fee")
	}
	return result, nil
}

func validRelayTerminalAccountingRecord(record relayTerminalAccountingRecord) bool {
	if record.Schema != relayTerminalAccountingRecordSchema || !boundedRelayTrustDomain(record.OwnerID) ||
		!boundedRelayTrustDomain(record.AgentID) || !validRelayTerminalHandoffReference(record.Reference) ||
		!canonicalSHA256(record.RelayExecutionDigest) || !boundedRelayTrustDomain(record.ProviderAgentID) ||
		record.RelayExecutionDigest != record.Reference.RelayExecutionDigest ||
		record.ProviderAgentID != record.Reference.ProviderAgentID ||
		!validRelayAssuranceLevel(record.AssuranceLevel) || record.AgreementBodyDigest == "" ||
		!canonicalSHA256(record.AgreementBodyDigest) || !validDurableRelayOutcome(record.TerminalOutcome) ||
		!canonicalSHA256(record.TerminalResolutionDigest) ||
		record.TerminalResolutionDigest != record.Reference.TerminalResolutionDigest ||
		record.TerminalFinalityEvidenceDigest != record.Reference.TerminalEvidenceDigest ||
		record.Revision == 0 || record.RecordedAtUnix == 0 || !canonicalSHA256(record.ReceiptDigest) ||
		!record.ClientFeeReservationReleased ||
		record.ClientSponsorshipReservationReleased != (record.Mode != agentrelay.ModeRelayExact) ||
		len(record.FeeObligationIDs) == 0 || len(record.FeeObligationIDs) != len(record.FeeLines) ||
		len(record.FeeObligationIDs) != len(record.FeeAccounting) {
		return false
	}
	expectedRelay, expectedSponsorship, err := relayTerminalComponentFulfillment(record.Mode, record.TerminalOutcome)
	expectedSponsorshipDisposition, dispositionErr := relaySponsorshipFinancialDisposition(expectedSponsorship)
	if err != nil || record.RelayFulfillment != expectedRelay ||
		record.SponsorshipFulfillment != expectedSponsorship || dispositionErr != nil ||
		record.ProviderSponsorshipDisposition != expectedSponsorshipDisposition {
		return false
	}
	switch record.Mode {
	case agentrelay.ModeRelayExact:
		if record.RelayObligationID == "" || record.SponsorshipObligationID != "" || record.ReservedSponsorship != nil {
			return false
		}
	case agentrelay.ModeSponsorOnly:
		if record.RelayObligationID != "" || record.SponsorshipObligationID == "" || record.ReservedSponsorship == nil {
			return false
		}
	case agentrelay.ModeSponsorAndRelay:
		if record.RelayObligationID == "" || record.SponsorshipObligationID == "" || record.ReservedSponsorship == nil {
			return false
		}
	default:
		return false
	}
	for index, accounting := range record.FeeAccounting {
		if accounting.ObligationID != record.FeeObligationIDs[index] ||
			accounting.Kind != record.FeeLines[index].Kind || accounting.Amount != record.FeeLines[index].Amount ||
			accounting.Status != RelayFeeDue && accounting.Status != RelayFeeNotDue {
			return false
		}
		due := accounting.Kind == agentrelay.ObligationRelayFee && record.RelayFulfillment == RelayComponentFulfilled ||
			accounting.Kind == agentrelay.ObligationSponsorshipFee &&
				record.SponsorshipFulfillment == RelayComponentFulfilled
		if accounting.Kind != agentrelay.ObligationRelayFee && accounting.Kind != agentrelay.ObligationSponsorshipFee ||
			due != (accounting.Status == RelayFeeDue) {
			return false
		}
	}
	digest, err := codec.Digest(relayTerminalAccountingReceiptDomain, relayTerminalAccountingPreimage(record))
	return err == nil && digest == record.ReceiptDigest
}

func (journal *DurableRelayTerminalAccountingJournal) readRecord(stableActionID string) (
	relayTerminalAccountingRecord, bool, error) {
	path, err := journal.recordPath(stableActionID, false)
	if err != nil {
		return relayTerminalAccountingRecord{}, false, err
	}
	file, err := journal.openFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return relayTerminalAccountingRecord{}, false, nil
	}
	if err != nil {
		return relayTerminalAccountingRecord{}, false, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !relayJournalFileInfoSecure(info) ||
		info.Size() <= 0 || info.Size() > maximumRelayTerminalAccountingBytes {
		return relayTerminalAccountingRecord{}, false, errors.New("relay terminal accounting record is invalid")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximumRelayTerminalAccountingBytes+1))
	var record relayTerminalAccountingRecord
	if err != nil || decodeStrictJSON(raw, &record) != nil || record.Reference.StableActionID != stableActionID ||
		record.OwnerID != journal.ownerID || record.AgentID != journal.agentID ||
		!validRelayTerminalAccountingRecord(record) {
		return relayTerminalAccountingRecord{}, false, errors.New("relay terminal accounting record cannot be verified")
	}
	return record, true, nil
}

func relayTerminalFinancialReport(record relayTerminalAccountingRecord) RelayTerminalFinancialReport {
	return RelayTerminalFinancialReport{
		OwnerID:              record.OwnerID,
		AgentID:              record.AgentID,
		StableActionID:       record.Reference.StableActionID,
		ExactRequestDigest:   record.Reference.ExactRequestDigest,
		RelayExecutionDigest: record.RelayExecutionDigest,
		ProviderAgentID:      record.ProviderAgentID, RouteGeneration: record.Reference.RouteGeneration,
		Mode: record.Mode, AssuranceLevel: record.AssuranceLevel,
		AgreementBodyDigest: record.AgreementBodyDigest, RelayObligationID: record.RelayObligationID,
		SponsorshipObligationID: record.SponsorshipObligationID,
		FeeObligationIDs:        append([]string(nil), record.FeeObligationIDs...),
		FeeAccounting:           append([]RelayFeeObligationAccounting(nil), record.FeeAccounting...),
		ReservedSponsorship:     cloneRelayAssetAmount(record.ReservedSponsorship),
		RelayFulfillment:        record.RelayFulfillment, SponsorshipFulfillment: record.SponsorshipFulfillment,
		ClientFeeReservationReleased:         record.ClientFeeReservationReleased,
		ClientSponsorshipReservationReleased: record.ClientSponsorshipReservationReleased,
		ProviderSponsorshipDisposition:       record.ProviderSponsorshipDisposition,
		TerminalOutcome:                      record.TerminalOutcome,
		ProtectedArtifactDigest:              record.Reference.ProtectedArtifactDigest,
		TerminalResolutionDigest:             record.TerminalResolutionDigest,
		TerminalFinalityEvidenceDigest:       record.TerminalFinalityEvidenceDigest,
		AccountingReceiptDigest:              record.ReceiptDigest, AccountingRevision: record.Revision,
		RecordedAtUnix: record.RecordedAtUnix,
	}
}

func sameRelayAccountingAmount(amount *commerce.AgreementAmount, expected *agentrelay.AssetAmount) bool {
	if amount == nil || expected == nil {
		return amount == nil && expected == nil
	}
	return amount.AssetNamespace == expected.Asset.AssetNamespace &&
		amount.AssetIdentifier == expected.Asset.AssetIdentifier && amount.Unit == expected.Asset.Unit &&
		amount.AmountAtomic == expected.AmountAtomic && amount.AmountDecimal == ""
}

func sameRelayAccountingBoundObligation(obligation commerce.AgreementObligation,
	kind, obligor, beneficiary string, subject []byte) bool {
	return obligation.ObligationID != "" && obligation.Kind == kind &&
		obligation.ObligorAgentID == obligor && obligation.BeneficiaryAgentID == beneficiary &&
		obligation.SubjectContentType == agentrelay.AgreementBindingContentType &&
		bytes.Equal(obligation.Subject, subject)
}

func relayAccountingReservedObligationKind(kind string) bool {
	switch kind {
	case agentrelay.ObligationRelayDelivery, agentrelay.ObligationSponsorDelivery,
		agentrelay.ObligationRelayFee, agentrelay.ObligationSponsorshipFee:
		return true
	default:
		return false
	}
}

// relayTerminalServiceObligationsMatchAttempt repeats the protocol's exact
// service-obligation projection at the accounting boundary. The Agreement
// digest alone is not enough here: a caller must not be able to relabel an
// unrelated obligation as fulfilled (or due) while retaining the same route
// result identities.
func relayTerminalServiceObligationsMatchAttempt(attempt RelayAttempt) error {
	execution := attempt.Execution
	binding, err := agentrelay.CompileRelayAgreementBinding(execution.QuoteRequest, execution.ProviderQuote)
	if err != nil {
		return err
	}
	subject, err := agentrelay.RelayAgreementBindingBytes(binding)
	if err != nil {
		return err
	}
	if attempt.Agreement.Body.TermsContentType != agentrelay.AgreementBindingContentType ||
		!bytes.Equal(attempt.Agreement.Body.Terms, subject) {
		return errors.New("relay terminal accounting Agreement terms do not bind the exact quote pair")
	}
	obligations := make(map[string]commerce.AgreementObligation, len(attempt.Agreement.Body.Obligations))
	for _, obligation := range attempt.Agreement.Body.Obligations {
		if _, duplicate := obligations[obligation.ObligationID]; duplicate {
			return errors.New("relay terminal accounting Agreement has duplicate obligation identity")
		}
		obligations[obligation.ObligationID] = obligation
	}
	client := execution.QuoteRequest.Body.RequesterAgentID
	provider := execution.ProviderQuote.Body.ProviderAgentID
	expected := make(map[string]string, 2+len(execution.FeeObligationIDs))
	if execution.RelayObligationID != "" {
		obligation := obligations[execution.RelayObligationID]
		if !sameRelayAccountingBoundObligation(obligation, agentrelay.ObligationRelayDelivery,
			provider, client, subject) || obligation.Amount != nil {
			return errors.New("relay terminal accounting relay-delivery obligation conflicts")
		}
		expected[execution.RelayObligationID] = agentrelay.ObligationRelayDelivery
	}
	if execution.SponsorshipObligationID != "" {
		obligation := obligations[execution.SponsorshipObligationID]
		if !sameRelayAccountingBoundObligation(obligation, agentrelay.ObligationSponsorDelivery,
			provider, client, subject) ||
			!sameRelayAccountingAmount(obligation.Amount, execution.ProviderQuote.Body.ReservedSponsorship) ||
			obligation.SettlementAdapterURI != agentrelay.DirectPaymentAdapterURI {
			return errors.New("relay terminal accounting sponsorship obligation conflicts")
		}
		expected[execution.SponsorshipObligationID] = agentrelay.ObligationSponsorDelivery
	}
	lines := make(map[string]agentrelay.FeeLine, len(execution.ProviderQuote.Body.FeeLines))
	for _, line := range execution.ProviderQuote.Body.FeeLines {
		if _, duplicate := lines[line.Kind]; duplicate {
			return errors.New("relay terminal accounting Quote has duplicate fee kind")
		}
		lines[line.Kind] = line
	}
	seenKinds := make(map[string]bool, len(lines))
	for _, obligationID := range execution.FeeObligationIDs {
		obligation := obligations[obligationID]
		line, found := lines[obligation.Kind]
		if !found || seenKinds[obligation.Kind] ||
			!sameRelayAccountingBoundObligation(obligation, obligation.Kind, client, provider, subject) ||
			!sameRelayAccountingAmount(obligation.Amount, &line.Amount) {
			return errors.New("relay terminal accounting fee obligation conflicts")
		}
		seenKinds[obligation.Kind] = true
		expected[obligationID] = obligation.Kind
	}
	if len(seenKinds) != len(lines) {
		return errors.New("relay terminal accounting fee obligation set is incomplete")
	}
	for _, obligation := range attempt.Agreement.Body.Obligations {
		expectedKind, referenced := expected[obligation.ObligationID]
		reusesBinding := obligation.SubjectContentType == agentrelay.AgreementBindingContentType &&
			bytes.Equal(obligation.Subject, subject)
		if (relayAccountingReservedObligationKind(obligation.Kind) || reusesBinding) &&
			(!referenced || expectedKind != obligation.Kind) {
			return errors.New("relay terminal accounting Agreement has an unreferenced service obligation")
		}
	}
	return nil
}

// RelayTerminalFinancialReport returns the authoritative idempotent inbox
// entry used to acknowledge route-artifact handoff. A missing entry is not a
// zero-valued report and cannot release route recovery storage.
func (journal *DurableRelayTerminalAccountingJournal) RelayTerminalFinancialReport(
	stableActionID string) (RelayTerminalFinancialReport, bool, error) {
	if journal == nil || !canonicalSHA256(stableActionID) {
		return RelayTerminalFinancialReport{}, false, agentrelay.ErrRelayInvalidState
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.lock == nil {
		return RelayTerminalFinancialReport{}, false, errors.New("relay terminal accounting journal is closed")
	}
	if err := journal.ensureStorageIdentity(); err != nil {
		return RelayTerminalFinancialReport{}, false, err
	}
	record, found, err := journal.readRecord(stableActionID)
	if err != nil || !found {
		return RelayTerminalFinancialReport{}, found, err
	}
	return relayTerminalFinancialReport(record), true, nil
}

func relayTerminalAccountingRecordFor(reference RelayTerminalHandoffReference,
	attempt RelayAttempt, result RelayExecutionResult, revision uint64,
	at time.Time) (relayTerminalAccountingRecord, error) {
	execution := attempt.Execution
	executionDigest, executionErr := agentrelay.RelayExecutionRequestDigest(execution)
	resolutionDigest, resolutionErr := agentrelay.RelayResolutionDigest(result.Resolution.Body)
	if result.Evidence == nil {
		return relayTerminalAccountingRecord{}, agentrelay.ErrRelayInvalidState
	}
	evidenceDigest, evidenceErr := agentrelay.RelayFinalityEvidenceDigest(result.Evidence.Body)
	nowUnix := at.UTC().Unix()
	agreementDigest, agreementErr := commerce.AgreementBodyDigest(attempt.Agreement.Body)
	relayFulfillment, sponsorshipFulfillment, fulfillmentErr := relayTerminalComponentFulfillment(
		execution.QuoteRequest.Body.Mode, result.Evidence.Body.Outcome)
	sponsorshipDisposition, dispositionErr := relaySponsorshipFinancialDisposition(sponsorshipFulfillment)
	feeAccounting, feeErr := relayTerminalFeeAccountingForAttempt(attempt, relayFulfillment, sponsorshipFulfillment)
	serviceObligationErr := relayTerminalServiceObligationsMatchAttempt(attempt)
	quoted := execution.QuoteRequest.Body
	provider := execution.ProviderQuote.Body.ProviderAgentID
	resolution := result.Resolution.Body
	evidence := result.Evidence.Body
	if executionErr != nil || resolutionErr != nil || evidenceErr != nil || agreementErr != nil ||
		fulfillmentErr != nil || dispositionErr != nil || feeErr != nil || serviceObligationErr != nil ||
		nowUnix <= 0 || revision == 0 ||
		executionDigest != reference.RelayExecutionDigest || provider != reference.ProviderAgentID ||
		resolutionDigest != reference.TerminalResolutionDigest ||
		evidenceDigest != reference.TerminalEvidenceDigest ||
		agreementDigest != execution.AgreementBodyDigest ||
		execution.AuthorizedAction.StableActionID != reference.StableActionID ||
		execution.AuthorizedAction.ExactRequestDigest != reference.ExactRequestDigest ||
		quoted.ProviderAgentID != provider || quoted.StableActionID != reference.StableActionID ||
		quoted.ExactRequestDigest != reference.ExactRequestDigest ||
		resolution.State != commerce.ActionTerminal || resolution.ProviderAgentID != provider ||
		resolution.Network != quoted.Network || resolution.AssuranceLevel != quoted.AssuranceLevel ||
		resolution.StableActionID != reference.StableActionID ||
		resolution.ExactRequestDigest != reference.ExactRequestDigest ||
		resolution.RelayExecutionDigest != reference.RelayExecutionDigest ||
		evidence.ProviderAgentID != provider || evidence.Network != quoted.Network ||
		evidence.AssuranceLevel != quoted.AssuranceLevel || evidence.StableActionID != reference.StableActionID ||
		evidence.ExactRequestDigest != reference.ExactRequestDigest ||
		evidence.RelayExecutionDigest != reference.RelayExecutionDigest ||
		evidence.SignedTransactionDigest != quoted.SignedTransactionDigest ||
		evidence.SignedTransactionCellHash != quoted.SignedTransactionCellHash ||
		evidence.TransactionValidUntilUnix != quoted.TransactionValidUntilUnix ||
		evidence.SourceAccount != quoted.SourceAccount || evidence.SourceSequence != quoted.SourceSequence ||
		resolution.TerminalOutcome != evidence.Outcome || !relayResolutionReferenceMatchesEvidence(resolution, evidence) {
		return relayTerminalAccountingRecord{}, agentrelay.ErrRelayInvalidState
	}
	record := relayTerminalAccountingRecord{Schema: relayTerminalAccountingRecordSchema,
		OwnerID: execution.AuthorizedAction.OwnerID, AgentID: execution.AuthorizedAction.AgentID, Reference: reference,
		RelayExecutionDigest: executionDigest, ProviderAgentID: execution.ProviderQuote.Body.ProviderAgentID,
		Mode: execution.QuoteRequest.Body.Mode, AssuranceLevel: execution.QuoteRequest.Body.AssuranceLevel,
		AgreementBodyDigest:                  execution.AgreementBodyDigest,
		RelayObligationID:                    execution.RelayObligationID,
		SponsorshipObligationID:              execution.SponsorshipObligationID,
		FeeObligationIDs:                     append([]string(nil), execution.FeeObligationIDs...),
		FeeAccounting:                        feeAccounting,
		ReservedSponsorship:                  cloneRelayAssetAmount(execution.ProviderQuote.Body.ReservedSponsorship),
		RelayFulfillment:                     relayFulfillment,
		SponsorshipFulfillment:               sponsorshipFulfillment,
		ClientFeeReservationReleased:         true,
		ClientSponsorshipReservationReleased: execution.QuoteRequest.Body.Mode != agentrelay.ModeRelayExact,
		ProviderSponsorshipDisposition:       sponsorshipDisposition,
		TerminalOutcome:                      result.Evidence.Body.Outcome, TerminalResolutionDigest: resolutionDigest,
		TerminalFinalityEvidenceDigest: evidenceDigest, Revision: revision, RecordedAtUnix: uint64(nowUnix)}
	record.FeeLines = make([]agentrelay.FeeLine, len(feeAccounting))
	for index, item := range feeAccounting {
		record.FeeLines[index] = agentrelay.FeeLine{Kind: item.Kind, Amount: item.Amount}
	}
	receipt, err := codec.Digest(relayTerminalAccountingReceiptDomain, relayTerminalAccountingPreimage(record))
	if err != nil {
		return relayTerminalAccountingRecord{}, err
	}
	record.ReceiptDigest = receipt
	if !validRelayTerminalAccountingRecord(record) {
		return relayTerminalAccountingRecord{}, agentrelay.ErrRelayInvalidState
	}
	return record, nil
}

func (journal *DurableRelayTerminalAccountingJournal) CommitRelayTerminalHandoff(ctx context.Context,
	reference RelayTerminalHandoffReference, attempt RelayAttempt,
	result RelayExecutionResult, at time.Time) (RelayTerminalAccountingReceipt, error) {
	if journal == nil || ctx == nil || ctx.Err() != nil || !validRelayTerminalHandoffReference(reference) {
		return RelayTerminalAccountingReceipt{}, agentrelay.ErrRelayInvalidState
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.lock == nil {
		return RelayTerminalAccountingReceipt{}, errors.New("relay terminal accounting journal is closed")
	}
	if err := journal.ensureStorageIdentity(); err != nil {
		return RelayTerminalAccountingReceipt{}, err
	}
	if err := journal.bindOwnerDomain(attempt.Execution.AuthorizedAction.OwnerID,
		attempt.Execution.AuthorizedAction.AgentID); err != nil {
		return RelayTerminalAccountingReceipt{}, err
	}
	if prior, found, err := journal.readRecord(reference.StableActionID); err != nil {
		return RelayTerminalAccountingReceipt{}, err
	} else if found {
		// A prior atomic write may have committed before returning an error. Do
		// not let any existing-record path, including a conflicting replay,
		// preserve stale in-memory capacity counters.
		if err := journal.refreshRecordRegistryCounts(); err != nil {
			return RelayTerminalAccountingReceipt{}, err
		}
		candidate, candidateErr := relayTerminalAccountingRecordFor(reference, attempt, result,
			prior.Revision, time.Unix(int64(prior.RecordedAtUnix), 0).UTC())
		if candidateErr != nil || !reflect.DeepEqual(prior, candidate) {
			return RelayTerminalAccountingReceipt{}, agentrelay.ErrRelayConflict
		}
		return RelayTerminalAccountingReceipt{ReceiptDigest: prior.ReceiptDigest,
			Revision: prior.Revision, RecordedAtUnix: prior.RecordedAtUnix}, nil
	}
	revision := journal.nextRevision
	if revision == ^uint64(0) {
		return RelayTerminalAccountingReceipt{}, errors.New("relay terminal accounting revision is exhausted")
	}
	record, err := relayTerminalAccountingRecordFor(reference, attempt, result, revision, at)
	if err != nil {
		return RelayTerminalAccountingReceipt{}, err
	}
	raw, err := jsonMarshalBounded(record, maximumRelayTerminalAccountingBytes)
	if err != nil {
		return RelayTerminalAccountingReceipt{}, err
	}
	if journal.recordCount >= maximumRelayTerminalAccountingRecords ||
		journal.recordBytes > maximumRelayTerminalAccountingRegistry-int64(len(raw)) {
		return RelayTerminalAccountingReceipt{}, errors.New("relay terminal accounting registry capacity is exhausted")
	}
	// Reserve the monotonic revision before the record write. A crash may leave
	// a harmless gap, but can never reuse a receipt revision for another route.
	if err := journal.persistHighWater(revision + 1); err != nil {
		return RelayTerminalAccountingReceipt{}, err
	}
	journal.nextRevision = revision + 1
	path, err := journal.recordPath(reference.StableActionID, true)
	if err != nil {
		return RelayTerminalAccountingReceipt{}, err
	}
	if err := journal.writeRecordAtomic(path, raw); err != nil {
		// Atomic replacement can become durable before directory sync, close,
		// or a post-write identity check reports failure. Recount from the pinned
		// registry so both committed and uncommitted outcomes remain fail-closed.
		if reconcileErr := journal.refreshRecordRegistryCounts(); reconcileErr != nil {
			return RelayTerminalAccountingReceipt{}, errors.Join(err, reconcileErr)
		}
		return RelayTerminalAccountingReceipt{}, err
	}
	journal.recordCount++
	journal.recordBytes += int64(len(raw))
	return RelayTerminalAccountingReceipt{ReceiptDigest: record.ReceiptDigest,
		Revision: record.Revision, RecordedAtUnix: record.RecordedAtUnix}, nil
}
