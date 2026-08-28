package earning

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tosnetwork/openfox/pkg/fileutil"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
)

const (
	relayJournalSchema       = "tos.openfox.agent-relay-journal.v2"
	relayJournalFile         = "agent-relay-journal.json"
	relayJournalLockFile     = ".agent-relay-journal.lock"
	maximumRelayJournalBytes = 64 << 20
	maximumRelayRecords      = 512
	maximumRelayReservations = 2048
	maximumRelayTombstones   = 65536
	maximumRelayRateEvents   = 200000
	defaultRelayRetention    = 30 * 24 * time.Hour
	relayGlobalRateBucket    = "\x00provider-global"
)

// ErrRelayRetired means the exact action was compacted after its independently
// evidenced terminal state. Resolve deliberately does not synthesize a Record:
// callers must treat the stable ID as permanently consumed and use retained
// content-addressed evidence outside the execution journal for historical UI.
var ErrRelayRetired = errors.New("relay action is permanently retired")

type persistedRelayRecord struct {
	Snapshot                 agentrelay.RecordSnapshot        `json:"snapshot"`
	Request                  agentrelay.RelayExecutionRequest `json:"protected_exact_request"`
	SponsorshipRecoveryToken []byte                           `json:"protected_sponsorship_recovery_token,omitempty"`
}

type persistedRelayQuoteReservation struct {
	RequestDigest       string                              `json:"request_digest"`
	QuoteDigest         string                              `json:"quote_digest"`
	Quote               agentrelay.SignedProviderRelayQuote `json:"signed_quote"`
	ReservedSponsorship *agentrelay.AssetAmount             `json:"reserved_sponsorship,omitempty"`
	ExpiresAtUnix       uint64                              `json:"expires_at_unix"`
	Consumed            bool                                `json:"consumed"`
	ExposureReleased    bool                                `json:"exposure_released"`
	StableActionID      string                              `json:"stable_action_id,omitempty"`
	ExecutionDigest     string                              `json:"execution_digest,omitempty"`
	AdmissionLimits     agentrelay.AdmissionLimits          `json:"admission_limits"`
}

// persistedRelayTombstone is the compact, permanent non-reuse boundary. It
// contains no raw BOC, Agreement, authorization credential, or recovery token.
// A stable_action_id remains provider-wide forever: the exact retired request
// returns ErrRelayRetired and every different request returns ErrRelayConflict.
type persistedRelayTombstone struct {
	StableActionID                         string                                      `json:"stable_action_id"`
	ExactRequestDigest                     string                                      `json:"exact_request_digest"`
	RelayExecutionDigest                   string                                      `json:"relay_execution_digest"`
	AdmissionReceiptDigest                 string                                      `json:"admission_receipt_digest"`
	SignedTransactionDigest                string                                      `json:"signed_transaction_digest"`
	ProviderQuoteDigest                    string                                      `json:"provider_quote_digest"`
	QuoteRequestDigest                     string                                      `json:"quote_request_digest"`
	QuoteReservationKey                    string                                      `json:"quote_reservation_key"`
	Mode                                   agentrelay.Mode                             `json:"mode"`
	AssuranceLevel                         agentrelay.AssuranceLevel                   `json:"assurance_level,omitempty"`
	RelayFinalityProfileURI                string                                      `json:"relay_finality_profile_uri,omitempty"`
	RelayFinalityProfileDigest             string                                      `json:"relay_finality_profile_digest,omitempty"`
	RelayTerminalEvidenceClass             agentrelay.RelayTerminalEvidenceClass       `json:"relay_terminal_evidence_class,omitempty"`
	RelayValidatorAuthenticatedProof       bool                                        `json:"relay_validator_authenticated_portable_proof,omitempty"`
	SponsorshipTerminalProfileURI          string                                      `json:"sponsorship_terminal_profile_uri,omitempty"`
	SponsorshipTerminalProfileDigest       string                                      `json:"sponsorship_terminal_profile_digest,omitempty"`
	SponsorshipTerminalEvidenceClass       agentrelay.SponsorshipTerminalEvidenceClass `json:"sponsorship_terminal_evidence_class,omitempty"`
	SponsorshipValidatorAuthenticatedProof bool                                        `json:"sponsorship_validator_authenticated_portable_proof,omitempty"`
	TransactionReference                   string                                      `json:"transaction_reference,omitempty"`
	EvidenceRefs                           []string                                    `json:"evidence_refs"`
	TerminalOutcome                        agentrelay.TerminalOutcome                  `json:"terminal_outcome"`
	SponsorshipStableActionID              string                                      `json:"sponsorship_stable_action_id,omitempty"`
	SponsorshipExactRequestDigest          string                                      `json:"sponsorship_exact_request_digest,omitempty"`
	SponsorshipValidUntilUnix              uint64                                      `json:"sponsorship_valid_until_unix,omitempty"`
	SponsorshipTransferReference           string                                      `json:"sponsorship_transfer_reference,omitempty"`
	SponsorshipAbsenceObservationDigests   []string                                    `json:"sponsorship_absence_observation_digests,omitempty"`
	TransactionAbsenceObservationDigests   []string                                    `json:"transaction_absence_observation_digests,omitempty"`
	AbsenceProofBundleDigest               string                                      `json:"absence_proof_bundle_digest,omitempty"`
	ExposureReleaseEvidenceRefs            []string                                    `json:"exposure_release_evidence_refs,omitempty"`
	TerminalUpdatedAtUnix                  uint64                                      `json:"terminal_updated_at_unix"`
	RetiredAtUnix                          uint64                                      `json:"retired_at_unix"`
}

type relayJournalDocument struct {
	Schema            string                                    `json:"schema"`
	ProviderAgentID   string                                    `json:"provider_agent_id,omitempty"`
	Records           []persistedRelayRecord                    `json:"records"`
	Tombstones        []persistedRelayTombstone                 `json:"tombstones"`
	QuoteReservations map[string]persistedRelayQuoteReservation `json:"quote_reservations"`
	QuoteBindings     map[string]string                         `json:"quote_bindings"`
	WriterHighWater   map[string]uint64                         `json:"writer_high_water"`
	QuoteAdmissions   map[string][]uint64                       `json:"quote_admissions"`
}

// DurableRelayJournal is an owner-private implementation of
// agentrelay.Journal. Exact BOC bytes are held only in its 0600 protected
// journal and returned to ProviderService; status and error paths never format
// or log the request.
type DurableRelayJournal struct {
	mu                 sync.Mutex
	directory          string
	root               *os.Root
	path               string
	lock               *os.File
	domainLock         *localEconomicDomainLock
	providerDomainLock *localEconomicDomainLock
	boundProviderID    string
	poisoned           bool
	records            map[string]agentrelay.Record
	tombstones         map[string]persistedRelayTombstone
	providerAgentID    string
	quoteReservations  map[string]persistedRelayQuoteReservation
	quoteBindings      map[string]string
	writerHighWater    map[string]uint64
	quoteAdmissions    map[string][]uint64
	terminalRetention  time.Duration
	localAdmission     *agentrelay.AdmissionLimits
	maximumProtected   uint32
}

func (journal *DurableRelayJournal) HasLinearizableRelayProviderJournal() bool {
	if journal == nil {
		return false
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	return journal.boundProviderID != "" && journal.providerDomainLock != nil &&
		journal.ensureStorageIdentityLocked() == nil
}

// BindRelayProviderAuthority promotes this otherwise role-neutral attempt
// journal to the single local authoritative journal for providerAgentID. A
// client also journals a selected Provider's quote, so the role cannot be
// inferred safely from ReserveQuote or Admit inputs. Provider runtimes must
// bind explicitly before advertising linearizable admission.
func (journal *DurableRelayJournal) BindRelayProviderAuthority(providerAgentID string) error {
	if journal == nil || providerAgentID == "" {
		return errors.New("relay provider identity is unavailable")
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if err := journal.ensureStorageIdentityLocked(); err != nil {
		return err
	}
	if journal.boundProviderID != "" {
		if journal.boundProviderID != providerAgentID {
			return errors.New("relay journal is bound to a different provider authority")
		}
		return nil
	}
	if journal.providerAgentID != "" && journal.providerAgentID != providerAgentID {
		return errors.New("relay journal is scoped to a different provider")
	}
	lock, err := acquireLocalEconomicDomainLock("relay-provider\x00" + providerAgentID)
	if err != nil {
		return err
	}
	journal.providerDomainLock = lock
	journal.boundProviderID = providerAgentID
	return nil
}

// A locked owner-private file is durable and single-host linearizable but may
// be restored from an older filesystem snapshot. It cannot support the
// autonomous-decentralized assurance claim without an external monotonic
// storage implementation.
func (*DurableRelayJournal) HasRollbackResistantRelayProviderJournalHighWater() bool { return false }

func OpenDurableRelayJournal(directory string) (*DurableRelayJournal, error) {
	return OpenDurableRelayJournalWithOptions(directory, DurableRelayJournalOptions{})
}

type DurableRelayJournalOptions struct {
	// TerminalRetention controls how long exact protected execution material is
	// retained after terminal evidence. Zero selects the conservative 30-day
	// default. Compaction never removes a sponsorship with unreleased exposure.
	TerminalRetention time.Duration
	// AdmissionLimits is an optional provider-owner ceiling stricter than the
	// signed profile. The effective limit is the minimum of both at every
	// reservation; it can never widen provider-advertised availability.
	AdmissionLimits *agentrelay.AdmissionLimits
	// MaximumProtectedRecords bounds raw protected executions retained at once.
	// Zero selects the implementation maximum. Values may only make the local
	// disk admission policy stricter.
	MaximumProtectedRecords uint32
}

func OpenDurableRelayJournalWithOptions(directory string,
	options DurableRelayJournalOptions) (*DurableRelayJournal, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, errors.New("relay journal directory must be clean and absolute")
	}
	retention := options.TerminalRetention
	if retention == 0 {
		retention = defaultRelayRetention
	}
	if retention < time.Second || retention > 365*24*time.Hour {
		return nil, errors.New("relay terminal retention must be between one second and one year")
	}
	var localAdmission *agentrelay.AdmissionLimits
	if options.AdmissionLimits != nil {
		limits := *options.AdmissionLimits
		if !validRelayAdmissionLimits(limits) {
			return nil, errors.New("relay local admission limits are invalid")
		}
		localAdmission = &limits
	}
	maximumProtected := options.MaximumProtectedRecords
	if maximumProtected == 0 {
		maximumProtected = maximumRelayRecords
	}
	if maximumProtected == 0 || maximumProtected > maximumRelayRecords {
		return nil, errors.New("relay protected record bound is invalid")
	}
	if err := validateRelayJournalDirectorySecurity(directory); err != nil {
		return nil, errors.New("relay journal directory must be owner-private and cannot be a symlink")
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return nil, errors.New("stat relay journal directory")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, errors.New("open relay journal directory capability")
	}
	rootInfo, err := root.Stat(".")
	if err != nil || !os.SameFile(info, rootInfo) {
		_ = root.Close()
		return nil, errors.New("relay journal directory changed while opening")
	}
	domainLock, err := acquireLocalEconomicDomainLock("provider-relay-journal\x00" + directory)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	lock, err := acquireRelayJournalLockRoot(root)
	if err != nil {
		_ = domainLock.Close()
		_ = root.Close()
		return nil, err
	}
	pathInfo, pathErr := os.Lstat(directory)
	if pathErr != nil || !os.SameFile(rootInfo, pathInfo) {
		_ = releaseRelayJournalLock(lock)
		_ = domainLock.Close()
		_ = root.Close()
		return nil, errors.New("relay journal directory changed while locking")
	}
	journal := &DurableRelayJournal{directory: directory, root: root, path: filepath.Join(directory, relayJournalFile),
		lock: lock, domainLock: domainLock,
		records: map[string]agentrelay.Record{}, tombstones: map[string]persistedRelayTombstone{},
		quoteReservations: map[string]persistedRelayQuoteReservation{}, quoteBindings: map[string]string{},
		writerHighWater: map[string]uint64{}, quoteAdmissions: map[string][]uint64{},
		terminalRetention: retention, localAdmission: localAdmission, maximumProtected: maximumProtected}
	if err := journal.load(); err != nil {
		_ = releaseRelayJournalLock(lock)
		_ = domainLock.Close()
		_ = root.Close()
		return nil, err
	}
	return journal, nil
}

func (journal *DurableRelayJournal) Close() error {
	if journal == nil {
		return nil
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.lock == nil {
		return nil
	}
	lock, root, domainLock, providerDomainLock := journal.lock, journal.root, journal.domainLock, journal.providerDomainLock
	journal.lock = nil
	journal.root = nil
	journal.domainLock = nil
	journal.providerDomainLock = nil
	journal.boundProviderID = ""
	err := releaseRelayJournalLock(lock)
	if rootErr := root.Close(); err == nil && rootErr != nil {
		err = errors.New("close relay journal directory capability")
	}
	if domainErr := domainLock.Close(); err == nil && domainErr != nil {
		err = domainErr
	}
	if providerDomainErr := providerDomainLock.Close(); err == nil && providerDomainErr != nil {
		err = providerDomainErr
	}
	return err
}

// ensureStorageIdentityLocked makes pathname replacement a fail-closed
// condition while all file operations remain anchored to the retained root.
// The caller must hold journal.mu, or be OpenDurableRelayJournal before it is
// published to another goroutine.
func (journal *DurableRelayJournal) ensureStorageIdentityLocked() error {
	if journal == nil || journal.poisoned || journal.lock == nil || journal.domainLock == nil || journal.root == nil ||
		journal.boundProviderID != "" && journal.providerDomainLock == nil {
		return errors.New("relay journal storage identity is unavailable")
	}
	opened, err := journal.root.Stat(".")
	current, pathErr := os.Lstat(journal.directory)
	if err != nil || pathErr != nil || !current.IsDir() || current.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(opened, current) {
		journal.poisoned = true
		return errors.New("relay journal storage directory was replaced")
	}
	// A same-inode permission drift makes new effects unavailable, but is not
	// namespace detachment. Returning an error without poisoning lets an
	// operator repair the owner-only permissions and recover the old durable
	// state. Inode/path/reparse replacement above remains permanently poisoned.
	if validateRelayJournalDirectorySecurity(journal.directory) != nil {
		return errors.New("relay journal storage directory is not owner-private")
	}
	return nil
}

func (journal *DurableRelayJournal) ReserveQuote(profile agentrelay.RelayServiceProfile,
	request agentrelay.SignedRelayQuoteRequest, proposal agentrelay.SignedProviderRelayQuote,
	now time.Time) (agentrelay.SignedProviderRelayQuote, bool, error) {
	if journal == nil || now.IsZero() {
		return agentrelay.SignedProviderRelayQuote{}, false, errors.New("relay quote reservation is invalid")
	}
	requestDigest, err := agentrelay.RelayQuoteRequestDigest(request.Body)
	if err != nil {
		return agentrelay.SignedProviderRelayQuote{}, false, err
	}
	quoteDigest, err := agentrelay.ProviderRelayQuoteDigest(proposal.Body)
	if err != nil {
		return agentrelay.SignedProviderRelayQuote{}, false, err
	}
	profileDigest, err := agentrelay.RelayServiceProfileDigest(profile)
	if err != nil || request.Body.ProviderAgentID != profile.ProviderAgentID ||
		proposal.Body.ProviderAgentID != profile.ProviderAgentID || proposal.Body.QuoteRequestDigest != requestDigest ||
		proposal.Body.ServiceProfileDigest != profileDigest || proposal.Body.ExpiresAtUnix <= uint64(now.UTC().Unix()) ||
		(request.Body.RequestedSponsorship == nil) != (proposal.Body.ReservedSponsorship == nil) ||
		request.Body.RequestedSponsorship != nil && !sameRelayAssetAmount(*request.Body.RequestedSponsorship,
			*proposal.Body.ReservedSponsorship) {
		return agentrelay.SignedProviderRelayQuote{}, false, agentrelay.ErrRelayConflict
	}
	limits, err := effectiveRelayAdmissionLimits(profile.AdmissionLimits, journal.localAdmission)
	if err != nil {
		return agentrelay.SignedProviderRelayQuote{}, false, err
	}
	key := relayDurableQuoteReservationKey(profile.ProviderAgentID, requestDigest)
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.lock == nil {
		return agentrelay.SignedProviderRelayQuote{}, false, errors.New("relay journal is closed")
	}
	if err := journal.ensureStorageIdentityLocked(); err != nil {
		return agentrelay.SignedProviderRelayQuote{}, false, err
	}
	if journal.boundProviderID != "" && journal.boundProviderID != profile.ProviderAgentID {
		return agentrelay.SignedProviderRelayQuote{}, false, errors.New("relay journal is bound to a different provider authority")
	}
	if journal.providerAgentID != "" && journal.providerAgentID != profile.ProviderAgentID {
		return agentrelay.SignedProviderRelayQuote{}, false, errors.New("relay journal is scoped to a different provider")
	}
	providerAgentID := profile.ProviderAgentID
	nextRecords := cloneRelayRecords(journal.records)
	nextTombstones := cloneRelayTombstones(journal.tombstones)
	nextReservations := cloneRelayQuoteReservations(journal.quoteReservations)
	nextBindings := cloneRelayStrings(journal.quoteBindings)
	nextAdmissions := cloneRelayAdmissions(journal.quoteAdmissions)
	pruneAllRelayAdmissions(nextAdmissions, uint64(now.UTC().Unix()))
	if compactRelayTerminalRecords(nextRecords, nextTombstones, nextReservations, providerAgentID,
		journal.terminalRetention, uint64(now.UTC().Unix())) {
		if err := journal.persist(providerAgentID, nextRecords, nextTombstones, nextReservations, nextBindings,
			journal.writerHighWater, journal.quoteAdmissions); err != nil {
			return agentrelay.SignedProviderRelayQuote{}, false, err
		}
		journal.providerAgentID, journal.records, journal.tombstones, journal.quoteReservations =
			providerAgentID, nextRecords, nextTombstones, nextReservations
	}
	releaseExpiredRelayReservations(nextReservations, nextBindings, uint64(now.UTC().Unix()))
	if retiredRelayQuoteRequest(nextTombstones, requestDigest) {
		return agentrelay.SignedProviderRelayQuote{}, false, agentrelay.ErrRelayQuoteConsumed
	}
	if existing, found := nextReservations[key]; found {
		if existing.ExpiresAtUnix > uint64(now.UTC().Unix()) {
			return cloneRelaySignedQuote(existing.Quote), false, nil
		}
		return agentrelay.SignedProviderRelayQuote{}, false, agentrelay.ErrRelayQuoteConsumed
	}
	if bound, found := nextBindings[quoteDigest]; found && bound != key {
		return agentrelay.SignedProviderRelayQuote{}, false, agentrelay.ErrRelayConflict
	}
	if len(nextReservations) >= maximumRelayReservations ||
		activeRelayQuoteReservations(nextReservations) >= uint64(limits.MaximumQuoteReservations) {
		return agentrelay.SignedProviderRelayQuote{}, false, agentrelay.ErrRelayAdmissionLimit
	}
	if proposal.Body.ReservedSponsorship != nil && !canReserveRelayExposure(profile, nextReservations,
		*proposal.Body.ReservedSponsorship) {
		return agentrelay.SignedProviderRelayQuote{}, false, agentrelay.ErrRelayExposure
	}
	if !admitRelayQuoteRate(nextAdmissions, request.Body.RequesterAgentID, limits, uint64(now.UTC().Unix())) {
		return agentrelay.SignedProviderRelayQuote{}, false, agentrelay.ErrRelayAdmissionLimit
	}
	reservation := persistedRelayQuoteReservation{RequestDigest: requestDigest, QuoteDigest: quoteDigest,
		Quote: cloneRelaySignedQuote(proposal), ExpiresAtUnix: proposal.Body.ExpiresAtUnix, AdmissionLimits: limits}
	if proposal.Body.ReservedSponsorship != nil {
		amount := *proposal.Body.ReservedSponsorship
		reservation.ReservedSponsorship = &amount
	}
	nextReservations[key], nextBindings[quoteDigest] = reservation, key
	if err := journal.persist(providerAgentID, nextRecords, nextTombstones, nextReservations, nextBindings,
		journal.writerHighWater, nextAdmissions); err != nil {
		return agentrelay.SignedProviderRelayQuote{}, false, err
	}
	journal.providerAgentID, journal.records, journal.tombstones, journal.quoteReservations, journal.quoteBindings =
		providerAgentID, nextRecords, nextTombstones, nextReservations, nextBindings
	journal.quoteAdmissions = nextAdmissions
	return cloneRelaySignedQuote(proposal), true, nil
}

func (journal *DurableRelayJournal) Admit(request agentrelay.RelayExecutionRequest,
	now time.Time) (agentrelay.Record, bool, error) {
	if journal == nil || !validFrozenRelayRequest(request) || now.IsZero() {
		return agentrelay.Record{}, false, errors.New("relay journal admission is invalid")
	}
	prepared, err := agentrelay.NewPreparedRecord(request, now.UTC())
	if err != nil {
		return agentrelay.Record{}, false, err
	}
	requestDigest, err := agentrelay.RelayQuoteRequestDigest(request.QuoteRequest.Body)
	if err != nil {
		return agentrelay.Record{}, false, err
	}
	action := request.AuthorizedAction
	// Resolve is network-free, so stable_action_id is provider-wide.
	key := relayDurableRecordKey(action.StableActionID)
	reservationKey := relayDurableQuoteReservationKey(request.ProviderQuote.Body.ProviderAgentID, requestDigest)
	ownerKey := action.OwnerID + "\x00" + action.AgentID

	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.lock == nil {
		return agentrelay.Record{}, false, errors.New("relay journal is closed")
	}
	if err := journal.ensureStorageIdentityLocked(); err != nil {
		return agentrelay.Record{}, false, err
	}
	providerAgentID := request.ProviderQuote.Body.ProviderAgentID
	if journal.boundProviderID != "" && journal.boundProviderID != providerAgentID {
		return agentrelay.Record{}, false, errors.New("relay journal is bound to a different provider authority")
	}
	if journal.providerAgentID != "" && journal.providerAgentID != providerAgentID {
		return agentrelay.Record{}, false, errors.New("relay journal is scoped to a different provider")
	}
	currentGeneration := journal.writerHighWater[ownerKey]
	nextRecords := cloneRelayRecords(journal.records)
	nextTombstones := cloneRelayTombstones(journal.tombstones)
	nextReservations := cloneRelayQuoteReservations(journal.quoteReservations)
	nextBindings := cloneRelayStrings(journal.quoteBindings)
	nextWriters := cloneRelayUint64(journal.writerHighWater)
	compacted := compactRelayTerminalRecords(nextRecords, nextTombstones, nextReservations, providerAgentID,
		journal.terminalRetention, uint64(now.UTC().Unix()))
	highWaterChanged := action.WriterGeneration > currentGeneration
	if highWaterChanged {
		nextWriters[ownerKey] = action.WriterGeneration
	}
	persistMetadata := func() error {
		if !highWaterChanged && !compacted {
			return nil
		}
		if persistErr := journal.persist(providerAgentID, nextRecords, nextTombstones, nextReservations, nextBindings,
			nextWriters, journal.quoteAdmissions); persistErr != nil {
			return persistErr
		}
		journal.providerAgentID, journal.records, journal.tombstones, journal.quoteReservations,
			journal.quoteBindings, journal.writerHighWater = providerAgentID, nextRecords, nextTombstones,
			nextReservations, nextBindings, nextWriters
		return nil
	}
	if retired, found := nextTombstones[key]; found {
		if persistErr := persistMetadata(); persistErr != nil {
			return agentrelay.Record{}, false, persistErr
		}
		if retired.ExactRequestDigest != action.ExactRequestDigest ||
			retired.RelayExecutionDigest != prepared.RelayExecutionDigest ||
			retired.AdmissionReceiptDigest != prepared.AdmissionReceiptDigest ||
			retired.SignedTransactionDigest != request.QuoteRequest.Body.SignedTransactionDigest {
			return agentrelay.Record{}, false, agentrelay.ErrRelayConflict
		}
		return agentrelay.Record{}, false, ErrRelayRetired
	}
	if existing, found := nextRecords[key]; found {
		if existing.ExactRequestDigest != action.ExactRequestDigest || existing.RelayExecutionDigest != prepared.RelayExecutionDigest ||
			existing.AdmissionReceiptDigest != prepared.AdmissionReceiptDigest ||
			existing.SignedTransactionDigest != request.QuoteRequest.Body.SignedTransactionDigest {
			if persistErr := persistMetadata(); persistErr != nil {
				return agentrelay.Record{}, false, persistErr
			}
			return cloneRelayRecord(existing), false, agentrelay.ErrRelayConflict
		}
		if highWaterChanged || compacted {
			if err := journal.persist(providerAgentID, nextRecords, nextTombstones, nextReservations, nextBindings,
				nextWriters, journal.quoteAdmissions); err != nil {
				return agentrelay.Record{}, false, err
			}
			journal.providerAgentID, journal.records, journal.tombstones, journal.quoteReservations,
				journal.quoteBindings, journal.writerHighWater = providerAgentID, nextRecords, nextTombstones,
				nextReservations, nextBindings, nextWriters
		}
		return cloneRelayRecord(nextRecords[key]), false, nil
	}
	reservation, found := nextReservations[reservationKey]
	if !found {
		if persistErr := persistMetadata(); persistErr != nil {
			return agentrelay.Record{}, false, persistErr
		}
		return agentrelay.Record{}, false, agentrelay.ErrRelayQuoteUnreserved
	}
	if reservation.QuoteDigest != prepared.ProviderQuoteDigest || reservation.Quote.PublicKey != request.ProviderQuote.PublicKey ||
		reservation.Quote.Signature != request.ProviderQuote.Signature {
		if persistErr := persistMetadata(); persistErr != nil {
			return agentrelay.Record{}, false, persistErr
		}
		return agentrelay.Record{}, false, agentrelay.ErrRelayConflict
	}
	if reservation.ExpiresAtUnix <= uint64(now.UTC().Unix()) {
		if !reservation.Consumed {
			delete(nextReservations, reservationKey)
			if nextBindings[reservation.QuoteDigest] == reservationKey {
				delete(nextBindings, reservation.QuoteDigest)
			}
		}
		if err := journal.persist(providerAgentID, nextRecords, nextTombstones, nextReservations, nextBindings,
			nextWriters, journal.quoteAdmissions); err != nil {
			return agentrelay.Record{}, false, err
		}
		journal.providerAgentID, journal.records, journal.tombstones, journal.quoteReservations,
			journal.quoteBindings, journal.writerHighWater = providerAgentID, nextRecords, nextTombstones,
			nextReservations, nextBindings, nextWriters
		return agentrelay.Record{}, false, agentrelay.ErrRelayQuoteUnreserved
	}
	if reservation.Consumed {
		if persistErr := persistMetadata(); persistErr != nil {
			return agentrelay.Record{}, false, persistErr
		}
		return agentrelay.Record{}, false, agentrelay.ErrRelayQuoteConsumed
	}
	limits, limitsErr := relayExecutionAdmissionLimits(reservation.AdmissionLimits, journal.localAdmission)
	if limitsErr != nil {
		return agentrelay.Record{}, false, limitsErr
	}
	if len(nextRecords) >= int(journal.maximumProtected) ||
		activeRelayExecutions(nextRecords, "") >= uint64(limits.MaximumActiveExecutions) ||
		activeRelayExecutions(nextRecords, request.QuoteRequest.Body.RequesterAgentID) >=
			uint64(limits.MaximumActivePerRequester) {
		return agentrelay.Record{}, false, agentrelay.ErrRelayAdmissionLimit
	}
	nextRecords[key] = prepared
	reservation.Consumed, reservation.StableActionID, reservation.ExecutionDigest = true, action.StableActionID, prepared.RelayExecutionDigest
	nextReservations[reservationKey] = reservation
	if err := journal.persist(providerAgentID, nextRecords, nextTombstones, nextReservations, nextBindings,
		nextWriters, journal.quoteAdmissions); err != nil {
		return agentrelay.Record{}, false, err
	}
	journal.providerAgentID, journal.records, journal.tombstones, journal.quoteReservations,
		journal.quoteBindings, journal.writerHighWater = providerAgentID, nextRecords, nextTombstones,
		nextReservations, nextBindings, nextWriters
	return cloneRelayRecord(prepared), true, nil
}

func (journal *DurableRelayJournal) Resolve(stableActionID,
	exactRequestDigest string) (agentrelay.Record, error) {
	if journal == nil || !canonicalSHA256(stableActionID) || !canonicalSHA256(exactRequestDigest) {
		return agentrelay.Record{}, agentrelay.ErrRelayUnknown
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.lock == nil {
		return agentrelay.Record{}, errors.New("relay journal is closed")
	}
	if err := journal.ensureStorageIdentityLocked(); err != nil {
		return agentrelay.Record{}, err
	}
	record, found := journal.records[relayDurableRecordKey(stableActionID)]
	if !found {
		return agentrelay.Record{}, relayRetiredRecordError(journal.tombstones, stableActionID, exactRequestDigest)
	}
	if record.ExactRequestDigest != exactRequestDigest {
		return cloneRelayRecord(record), agentrelay.ErrRelayConflict
	}
	return cloneRelayRecord(record), nil
}

func (journal *DurableRelayJournal) BeginSponsorship(stableActionID, exactRequestDigest string,
	expectedRevision uint64, recovery agentrelay.SponsorshipRecoveryHandle, at time.Time) (agentrelay.Record, error) {
	recoveryToken := recovery.OpaqueToken
	if journal == nil || expectedRevision == 0 || !canonicalSHA256(stableActionID) ||
		!canonicalSHA256(exactRequestDigest) || !canonicalSHA256(recovery.StableActionID) ||
		!canonicalSHA256(recovery.ExactRequestDigest) || !canonicalSHA256(recovery.AgreementPaymentRequestDigest) ||
		recovery.ValidUntilUnix == 0 ||
		len(recoveryToken) == 0 || at.IsZero() {
		return agentrelay.Record{}, agentrelay.ErrRelayInvalidState
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.lock == nil {
		return agentrelay.Record{}, errors.New("relay journal is closed")
	}
	if err := journal.ensureStorageIdentityLocked(); err != nil {
		return agentrelay.Record{}, err
	}
	key := relayDurableRecordKey(stableActionID)
	record, found := journal.records[key]
	if !found {
		return agentrelay.Record{}, relayRetiredRecordError(journal.tombstones, stableActionID, exactRequestDigest)
	}
	if record.ExactRequestDigest != exactRequestDigest {
		return cloneRelayRecord(record), agentrelay.ErrRelayConflict
	}
	atUnix := at.UTC().Unix()
	sponsorshipProfile := record.ExecutionRequest().ProviderQuote.Body.SponsorshipTerminalProfile
	if sponsorshipProfile == nil {
		return cloneRelayRecord(record), agentrelay.ErrRelayInvalidState
	}
	recoveryBudget := uint64(agentrelay.MinimumRelayInclusionMarginSeconds) +
		uint64(sponsorshipProfile.MaximumResolutionSeconds)
	if record.State != commerce.ActionPrepared ||
		record.ExecutionRequest().QuoteRequest.Body.Mode == agentrelay.ModeRelayExact ||
		record.SponsorshipTransferReference != "" || atUnix < 0 ||
		recovery.ValidUntilUnix > record.ExecutionRequest().ExpiresAtUnix ||
		recovery.ValidUntilUnix <= uint64(atUnix) || recovery.ValidUntilUnix-uint64(atUnix) <= recoveryBudget {
		return cloneRelayRecord(record), agentrelay.ErrRelayInvalidState
	}
	if record.SponsorshipAttempted {
		if record.SponsorshipAgreementPaymentRequestDigest != recovery.AgreementPaymentRequestDigest ||
			record.SponsorshipStableActionID != recovery.StableActionID ||
			record.SponsorshipExactRequestDigest != recovery.ExactRequestDigest ||
			record.SponsorshipValidUntilUnix != recovery.ValidUntilUnix ||
			!bytes.Equal(record.SponsorshipRecoveryToken(), recoveryToken) {
			return cloneRelayRecord(record), agentrelay.ErrRelayConflict
		}
		return cloneRelayRecord(record), nil
	}
	if record.StateRevision != expectedRevision || atUnix <= 0 || uint64(atUnix) < record.UpdatedAtUnix {
		return cloneRelayRecord(record), agentrelay.ErrRelayInvalidState
	}
	snapshot := record.Snapshot()
	recoveryDigest, err := commerce.ExactRequestDigest(recoveryToken)
	if err != nil {
		return cloneRelayRecord(record), agentrelay.ErrRelayInvalidState
	}
	snapshot.SponsorshipAttempted = true
	snapshot.SponsorshipAgreementPaymentRequestDigest = recovery.AgreementPaymentRequestDigest
	snapshot.SponsorshipStableActionID = recovery.StableActionID
	snapshot.SponsorshipExactRequestDigest = recovery.ExactRequestDigest
	snapshot.SponsorshipValidUntilUnix = recovery.ValidUntilUnix
	snapshot.SponsorshipRecoveryTokenDigest = recoveryDigest
	snapshot.StateRevision++
	snapshot.UpdatedAtUnix = uint64(atUnix)
	updated, err := agentrelay.RestoreRecord(snapshot, record.ExecutionRequest(), recoveryToken)
	if err != nil {
		return cloneRelayRecord(record), agentrelay.ErrRelayInvalidState
	}
	nextRecords := cloneRelayRecords(journal.records)
	nextRecords[key] = updated
	if err := journal.persist(journal.providerAgentID, nextRecords, journal.tombstones, journal.quoteReservations,
		journal.quoteBindings, journal.writerHighWater, journal.quoteAdmissions); err != nil {
		return agentrelay.Record{}, err
	}
	journal.records = nextRecords
	return cloneRelayRecord(updated), nil
}

func (journal *DurableRelayJournal) RecordSponsorshipObservation(stableActionID, exactRequestDigest string,
	expectedRevision uint64, observation agentrelay.RelaySponsorshipCreditObservation,
	at time.Time) (agentrelay.Record, error) {
	observationDigest, observationErr := agentrelay.RelaySponsorshipCreditObservationDigest(observation)
	if journal == nil || expectedRevision == 0 || !canonicalSHA256(stableActionID) ||
		!canonicalSHA256(exactRequestDigest) || observationErr != nil || at.IsZero() {
		return agentrelay.Record{}, agentrelay.ErrRelayInvalidState
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.lock == nil {
		return agentrelay.Record{}, errors.New("relay journal is closed")
	}
	if err := journal.ensureStorageIdentityLocked(); err != nil {
		return agentrelay.Record{}, err
	}
	key := relayDurableRecordKey(stableActionID)
	record, found := journal.records[key]
	if !found {
		return agentrelay.Record{}, relayRetiredRecordError(journal.tombstones, stableActionID, exactRequestDigest)
	}
	if record.ExactRequestDigest != exactRequestDigest {
		return cloneRelayRecord(record), agentrelay.ErrRelayConflict
	}
	request := record.ExecutionRequest()
	if request.QuoteRequest.Body.Mode == agentrelay.ModeRelayExact ||
		request.QuoteRequest.Body.AssuranceLevel == agentrelay.AssuranceAutonomousDecentralized ||
		(record.State != commerce.ActionPrepared && record.State != commerce.ActionSubmitted &&
			record.State != commerce.ActionAccepted) || record.SponsorshipTransferReference != "" {
		return cloneRelayRecord(record), agentrelay.ErrRelayInvalidState
	}
	if record.SponsorshipCreditObservation != nil {
		existingDigest, err := agentrelay.RelaySponsorshipCreditObservationDigest(*record.SponsorshipCreditObservation)
		if err != nil || existingDigest != observationDigest {
			return cloneRelayRecord(record), agentrelay.ErrRelayConflict
		}
		return cloneRelayRecord(record), nil
	}
	atUnix := at.UTC().Unix()
	if !record.SponsorshipAttempted || !canonicalSHA256(record.SponsorshipStableActionID) ||
		!canonicalSHA256(record.SponsorshipExactRequestDigest) ||
		observation.AgreementPaymentRequestDigest != record.SponsorshipAgreementPaymentRequestDigest ||
		observation.SponsorshipStableActionID != record.SponsorshipStableActionID ||
		observation.SponsorshipExactRequestDigest != record.SponsorshipExactRequestDigest ||
		observation.ProviderSponsorValidUntilUnix != record.SponsorshipValidUntilUnix ||
		record.StateRevision != expectedRevision || atUnix <= 0 || uint64(atUnix) < record.UpdatedAtUnix {
		return cloneRelayRecord(record), agentrelay.ErrRelayInvalidState
	}
	snapshot := record.Snapshot()
	snapshot.SponsorshipCreditObservation = &observation
	snapshot.StateRevision++
	snapshot.UpdatedAtUnix = uint64(atUnix)
	updated, err := agentrelay.RestoreRecord(snapshot, request, record.SponsorshipRecoveryToken())
	if err != nil {
		return cloneRelayRecord(record), agentrelay.ErrRelayInvalidState
	}
	nextRecords := cloneRelayRecords(journal.records)
	nextRecords[key] = updated
	if err := journal.persist(journal.providerAgentID, nextRecords, journal.tombstones, journal.quoteReservations,
		journal.quoteBindings, journal.writerHighWater, journal.quoteAdmissions); err != nil {
		return agentrelay.Record{}, err
	}
	journal.records = nextRecords
	return cloneRelayRecord(updated), nil
}

func (journal *DurableRelayJournal) RecordSponsorship(stableActionID, exactRequestDigest string,
	expectedRevision uint64, evidence agentrelay.RelaySponsorshipTransactionEvidence,
	at time.Time) (agentrelay.Record, error) {
	evidenceDigest, evidenceErr := agentrelay.RelaySponsorshipTransactionEvidenceDigest(evidence)
	if journal == nil || expectedRevision == 0 || !canonicalSHA256(stableActionID) ||
		!canonicalSHA256(exactRequestDigest) || evidenceErr != nil || at.IsZero() {
		return agentrelay.Record{}, agentrelay.ErrRelayInvalidState
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.lock == nil {
		return agentrelay.Record{}, errors.New("relay journal is closed")
	}
	if err := journal.ensureStorageIdentityLocked(); err != nil {
		return agentrelay.Record{}, err
	}
	key := relayDurableRecordKey(stableActionID)
	record, found := journal.records[key]
	if !found {
		return agentrelay.Record{}, relayRetiredRecordError(journal.tombstones, stableActionID, exactRequestDigest)
	}
	if record.ExactRequestDigest != exactRequestDigest {
		return cloneRelayRecord(record), agentrelay.ErrRelayConflict
	}
	if (record.State != commerce.ActionPrepared && record.State != commerce.ActionSubmitted &&
		record.State != commerce.ActionAccepted) ||
		record.ExecutionRequest().QuoteRequest.Body.Mode == agentrelay.ModeRelayExact {
		return cloneRelayRecord(record), agentrelay.ErrRelayInvalidState
	}
	if record.SponsorshipTransactionEvidence != nil {
		existingDigest, err := agentrelay.RelaySponsorshipTransactionEvidenceDigest(*record.SponsorshipTransactionEvidence)
		if err != nil || existingDigest != evidenceDigest {
			return cloneRelayRecord(record), agentrelay.ErrRelayConflict
		}
		return cloneRelayRecord(record), nil
	}
	atUnix := at.UTC().Unix()
	if !record.SponsorshipAttempted ||
		evidence.AgreementPaymentRequestDigest != record.SponsorshipAgreementPaymentRequestDigest ||
		evidence.SponsorshipStableActionID != record.SponsorshipStableActionID ||
		evidence.SponsorshipExactRequestDigest != record.SponsorshipExactRequestDigest ||
		evidence.ProviderSponsorValidUntilUnix != record.SponsorshipValidUntilUnix ||
		record.SponsorshipCreditObservation != nil &&
			!relayObservedSponsorshipMatchesEvidence(*record.SponsorshipCreditObservation, evidence) ||
		record.StateRevision != expectedRevision || atUnix <= 0 ||
		uint64(atUnix) < record.UpdatedAtUnix {
		return cloneRelayRecord(record), agentrelay.ErrRelayInvalidState
	}
	snapshot := record.Snapshot()
	snapshot.SponsorshipTransferReference = evidence.SubmittedTransactionHash
	snapshot.SponsorshipTransactionEvidence = &evidence
	snapshot.SponsorshipCreditObservation = nil
	recoveryToken := record.SponsorshipRecoveryToken()
	if record.ExecutionRequest().QuoteRequest.Body.Mode != agentrelay.ModeSponsorAndRelay {
		snapshot.SponsorshipAttempted = false
		snapshot.SponsorshipRecoveryTokenDigest = ""
		recoveryToken = nil
	}
	snapshot.EvidenceRefs = append([]string(nil), evidence.ObservationDigests...)
	snapshot.StateRevision++
	snapshot.UpdatedAtUnix = uint64(atUnix)
	updated, err := agentrelay.RestoreRecord(snapshot, record.ExecutionRequest(), recoveryToken)
	if err != nil {
		return cloneRelayRecord(record), agentrelay.ErrRelayInvalidState
	}
	nextRecords := cloneRelayRecords(journal.records)
	nextRecords[key] = updated
	if err := journal.persist(journal.providerAgentID, nextRecords, journal.tombstones, journal.quoteReservations,
		journal.quoteBindings, journal.writerHighWater, journal.quoteAdmissions); err != nil {
		return agentrelay.Record{}, err
	}
	journal.records = nextRecords
	return cloneRelayRecord(updated), nil
}

func relayObservedSponsorshipMatchesEvidence(observation agentrelay.RelaySponsorshipCreditObservation,
	evidence agentrelay.RelaySponsorshipTransactionEvidence) bool {
	return observation.NetworkDigest == evidence.NetworkDigest &&
		reflect.DeepEqual(observation.AgreementPaymentRequest, evidence.AgreementPaymentRequest) &&
		observation.AgreementPaymentRequestDigest == evidence.AgreementPaymentRequestDigest &&
		observation.SponsorshipStableActionID == evidence.SponsorshipStableActionID &&
		observation.SponsorshipExactRequestDigest == evidence.SponsorshipExactRequestDigest &&
		observation.ProviderSponsorSourceAccount == evidence.ProviderSponsorSourceAccount &&
		observation.ProviderSponsorSourceSequence == evidence.ProviderSponsorSourceSequence &&
		observation.ProviderSponsorValidUntilUnix == evidence.ProviderSponsorValidUntilUnix &&
		observation.SignedTopUpTransactionDigest == evidence.SignedTopUpTransactionDigest &&
		observation.SignedTopUpTransactionCellHash == evidence.SignedTopUpTransactionCellHash &&
		observation.DestinationSourceAccount == evidence.DestinationSourceAccount &&
		observation.Amount == evidence.Amount &&
		observation.SubmittedTransactionHash == evidence.SubmittedTransactionHash &&
		observation.SourceExecutionReference == evidence.SourceExecutionReference &&
		reflect.DeepEqual(observation.DestinationCreditReferences, evidence.DestinationCreditReferences)
}

func (journal *DurableRelayJournal) RecordSponsorshipAbsence(stableActionID, exactRequestDigest string,
	expectedRevision uint64, outcome agentrelay.TerminalOutcome, sponsorshipObservations,
	transactionObservations []agentrelay.RelayAbsenceObservationReference, absenceProofBundleDigest string,
	absenceProofBundle []byte, at time.Time) (agentrelay.Record, error) {
	if journal == nil || expectedRevision == 0 || !canonicalSHA256(stableActionID) ||
		!canonicalSHA256(exactRequestDigest) || !validDurableSponsorshipAbsenceOutcome(outcome) || at.IsZero() {
		return agentrelay.Record{}, agentrelay.ErrRelayInvalidState
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.lock == nil {
		return agentrelay.Record{}, errors.New("relay journal is closed")
	}
	if err := journal.ensureStorageIdentityLocked(); err != nil {
		return agentrelay.Record{}, err
	}
	key := relayDurableRecordKey(stableActionID)
	record, found := journal.records[key]
	if !found {
		return agentrelay.Record{}, relayRetiredRecordError(journal.tombstones, stableActionID, exactRequestDigest)
	}
	if record.ExactRequestDigest != exactRequestDigest {
		return cloneRelayRecord(record), agentrelay.ErrRelayConflict
	}
	sponsorshipObservationDigests, sponsorshipErr := relayAbsenceReferenceDigests(sponsorshipObservations)
	transactionObservationDigests, transactionErr := relayAbsenceReferenceDigests(transactionObservations)
	merged := mergeRelayEvidenceRefs(sponsorshipObservationDigests, transactionObservationDigests)
	if sponsorshipErr != nil || transactionErr != nil ||
		len(merged) != len(sponsorshipObservationDigests)+len(transactionObservationDigests) ||
		!sortedRelayEvidenceRefs(merged) {
		return cloneRelayRecord(record), agentrelay.ErrRelayInvalidState
	}
	if len(record.SponsorshipAbsenceObservations)+len(record.TransactionAbsenceObservations) != 0 {
		exactReplay := record.TerminalOutcome == outcome &&
			equalRelayEvidenceRefs(record.SponsorshipAbsenceObservationDigests, sponsorshipObservationDigests) &&
			equalRelayEvidenceRefs(record.TransactionAbsenceObservationDigests, transactionObservationDigests) &&
			record.AbsenceProofBundleDigest == absenceProofBundleDigest &&
			bytes.Equal(record.AbsenceProofBundle, absenceProofBundle)
		if exactReplay {
			return cloneRelayRecord(record), nil
		}
	}
	atUnix := at.UTC().Unix()
	mode := record.ExecutionRequest().QuoteRequest.Body.Mode
	hasSponsorshipAbsence := len(sponsorshipObservations) != 0
	hasTransactionAbsence := len(transactionObservations) != 0
	promotingComponentToDual := mode == agentrelay.ModeSponsorAndRelay &&
		record.State != commerce.ActionTerminal && record.TerminalOutcome == "" &&
		len(record.SponsorshipAbsenceObservations) != 0 && len(record.TransactionAbsenceObservations) == 0 &&
		hasSponsorshipAbsence && hasTransactionAbsence &&
		equalRelayEvidenceRefs(record.SponsorshipAbsenceObservationDigests, sponsorshipObservationDigests) &&
		safeRelayTerminalAbsenceOutcome(outcome)
	if len(record.SponsorshipAbsenceObservations)+len(record.TransactionAbsenceObservations) != 0 &&
		!promotingComponentToDual {
		return cloneRelayRecord(record), agentrelay.ErrRelayConflict
	}
	validScope := mode == agentrelay.ModeSponsorOnly && hasSponsorshipAbsence && !hasTransactionAbsence &&
		record.SponsorshipTransferReference == "" && record.SponsorshipAttempted && safeRelayTerminalAbsenceOutcome(outcome) ||
		mode == agentrelay.ModeSponsorAndRelay && hasSponsorshipAbsence && hasTransactionAbsence &&
			record.SponsorshipTransferReference == "" && record.SponsorshipAttempted && safeRelayTerminalAbsenceOutcome(outcome) ||
		mode == agentrelay.ModeSponsorAndRelay && hasSponsorshipAbsence && !hasTransactionAbsence &&
			record.SponsorshipTransferReference == "" && record.SponsorshipAttempted && outcome == "" ||
		mode == agentrelay.ModeSponsorAndRelay && !hasSponsorshipAbsence && hasTransactionAbsence &&
			record.SponsorshipTransferReference != "" && record.SponsorshipAttempted &&
			record.SponsorshipTransactionEvidence != nil &&
			(outcome == agentrelay.OutcomeFinalizedSponsorshipOnly ||
				outcome == agentrelay.OutcomeCorroboratedSponsorshipOnly)
	validScope = validScope || promotingComponentToDual
	if (record.State != commerce.ActionPrepared && record.State != commerce.ActionSubmitted &&
		record.State != commerce.ActionAccepted) || !validScope ||
		!canonicalSHA256(record.SponsorshipStableActionID) || !canonicalSHA256(record.SponsorshipExactRequestDigest) ||
		record.StateRevision != expectedRevision || atUnix <= 0 || uint64(atUnix) < record.UpdatedAtUnix {
		return cloneRelayRecord(record), agentrelay.ErrRelayInvalidState
	}
	snapshot := record.Snapshot()
	if hasSponsorshipAbsence && record.SponsorshipCreditObservation != nil {
		observationDigest, err := agentrelay.RelaySponsorshipCreditObservationDigest(*record.SponsorshipCreditObservation)
		if err != nil {
			return cloneRelayRecord(record), agentrelay.ErrRelayInvalidState
		}
		snapshot.SupersededSponsorshipCreditObservationDigest = observationDigest
		snapshot.SponsorshipCreditObservation = nil
	}
	snapshot.SponsorshipAbsenceObservations = append([]agentrelay.RelayAbsenceObservationReference(nil),
		sponsorshipObservations...)
	snapshot.TransactionAbsenceObservations = append([]agentrelay.RelayAbsenceObservationReference(nil),
		transactionObservations...)
	snapshot.SponsorshipAbsenceObservationDigests = append([]string(nil), sponsorshipObservationDigests...)
	snapshot.TransactionAbsenceObservationDigests = append([]string(nil), transactionObservationDigests...)
	if promotingComponentToDual {
		snapshot.SupersededAbsenceProofBundleDigest = record.AbsenceProofBundleDigest
	}
	snapshot.AbsenceProofBundleDigest = absenceProofBundleDigest
	snapshot.AbsenceProofBundle = append([]byte(nil), absenceProofBundle...)
	terminal := mode == agentrelay.ModeSponsorOnly || hasTransactionAbsence
	recoveryToken := record.SponsorshipRecoveryToken()
	if terminal {
		snapshot.State = commerce.ActionTerminal
		snapshot.SponsorshipAttempted = false
		snapshot.SponsorshipRecoveryTokenDigest = ""
		recoveryToken = nil
	}
	snapshot.StateRevision++
	if terminal {
		snapshot.TransactionReference = record.SponsorshipTransferReference
	}
	snapshot.EvidenceRefs = mergeRelayEvidenceRefs(record.EvidenceRefs, merged)
	snapshot.TerminalOutcome = outcome
	snapshot.UpdatedAtUnix = uint64(atUnix)
	updated, err := agentrelay.RestoreRecord(snapshot, record.ExecutionRequest(), recoveryToken)
	if err != nil {
		return cloneRelayRecord(record), agentrelay.ErrRelayInvalidState
	}
	nextRecords := cloneRelayRecords(journal.records)
	nextReservations := cloneRelayQuoteReservations(journal.quoteReservations)
	nextRecords[key] = updated
	if terminal {
		// A terminal S+/R- record still has provider reimbursement exposure;
		// releaseRelayRecordExposure intentionally leaves that reservation live
		// until settlement/write-off evidence is recorded.
		releaseRelayRecordExposure(nextReservations, updated)
	}
	if err := journal.persist(journal.providerAgentID, nextRecords, journal.tombstones, nextReservations,
		journal.quoteBindings, journal.writerHighWater, journal.quoteAdmissions); err != nil {
		return agentrelay.Record{}, err
	}
	journal.records, journal.quoteReservations = nextRecords, nextReservations
	return cloneRelayRecord(updated), nil
}

func (journal *DurableRelayJournal) ReleaseSponsorshipExposure(stableActionID, exactRequestDigest string,
	expectedRevision uint64, settlementEvidenceRefs []string, at time.Time) (agentrelay.Record, error) {
	if journal == nil || expectedRevision == 0 || !canonicalSHA256(stableActionID) ||
		!canonicalSHA256(exactRequestDigest) || len(settlementEvidenceRefs) == 0 ||
		!sortedRelayEvidenceRefs(settlementEvidenceRefs) || at.IsZero() {
		return agentrelay.Record{}, agentrelay.ErrRelayInvalidState
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.lock == nil {
		return agentrelay.Record{}, errors.New("relay journal is closed")
	}
	if err := journal.ensureStorageIdentityLocked(); err != nil {
		return agentrelay.Record{}, err
	}
	key := relayDurableRecordKey(stableActionID)
	record, found := journal.records[key]
	if !found {
		return agentrelay.Record{}, relayRetiredRecordError(journal.tombstones, stableActionID, exactRequestDigest)
	}
	if record.ExactRequestDigest != exactRequestDigest {
		return cloneRelayRecord(record), agentrelay.ErrRelayConflict
	}
	if len(record.SponsorshipExposureReleaseEvidenceRefs) > 0 {
		if !reflect.DeepEqual(record.SponsorshipExposureReleaseEvidenceRefs, settlementEvidenceRefs) {
			return cloneRelayRecord(record), agentrelay.ErrRelayConflict
		}
		return cloneRelayRecord(record), nil
	}
	atUnix := at.UTC().Unix()
	if record.StateRevision != expectedRevision || record.State != commerce.ActionTerminal ||
		record.SponsorshipTransferReference == "" || atUnix <= 0 || uint64(atUnix) < record.UpdatedAtUnix {
		return cloneRelayRecord(record), agentrelay.ErrRelayInvalidState
	}
	snapshot := record.Snapshot()
	snapshot.SponsorshipExposureReleaseEvidenceRefs = append([]string(nil), settlementEvidenceRefs...)
	snapshot.SponsorshipExposureReleasedAtUnix = uint64(atUnix)
	snapshot.StateRevision++
	snapshot.UpdatedAtUnix = uint64(atUnix)
	updated, err := agentrelay.RestoreRecord(snapshot, record.ExecutionRequest())
	if err != nil {
		return cloneRelayRecord(record), agentrelay.ErrRelayInvalidState
	}
	nextRecords := cloneRelayRecords(journal.records)
	nextReservations := cloneRelayQuoteReservations(journal.quoteReservations)
	nextRecords[key] = updated
	if !releaseRelayRecordExposure(nextReservations, updated) {
		return cloneRelayRecord(record), agentrelay.ErrRelayInvalidState
	}
	if err := journal.persist(journal.providerAgentID, nextRecords, journal.tombstones, nextReservations,
		journal.quoteBindings, journal.writerHighWater, journal.quoteAdmissions); err != nil {
		return agentrelay.Record{}, err
	}
	journal.records, journal.quoteReservations = nextRecords, nextReservations
	return cloneRelayRecord(updated), nil
}

func (journal *DurableRelayJournal) Transition(stableActionID, exactRequestDigest string, expectedRevision uint64,
	target commerce.ActionResolutionState, transactionReference string, evidenceRefs []string,
	outcome agentrelay.TerminalOutcome, at time.Time) (agentrelay.Record, error) {
	if journal == nil || expectedRevision == 0 || len(transactionReference) > 1024 || !sortedRelayEvidenceRefs(evidenceRefs) || at.IsZero() {
		return agentrelay.Record{}, agentrelay.ErrRelayInvalidState
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.lock == nil {
		return agentrelay.Record{}, errors.New("relay journal is closed")
	}
	if err := journal.ensureStorageIdentityLocked(); err != nil {
		return agentrelay.Record{}, err
	}
	key := relayDurableRecordKey(stableActionID)
	record, found := journal.records[key]
	if !found {
		return agentrelay.Record{}, relayRetiredRecordError(journal.tombstones, stableActionID, exactRequestDigest)
	}
	if record.ExactRequestDigest != exactRequestDigest {
		return cloneRelayRecord(record), agentrelay.ErrRelayConflict
	}
	atUnix := at.UTC().Unix()
	if record.StateRevision != expectedRevision || !validDurableRelayTransition(record.State, target) ||
		atUnix <= 0 || uint64(atUnix) < record.UpdatedAtUnix {
		return cloneRelayRecord(record), agentrelay.ErrRelayInvalidState
	}
	if target == commerce.ActionTerminal {
		if !validDurableRelayOutcomeForRecord(record, outcome, transactionReference) || len(evidenceRefs) == 0 {
			return cloneRelayRecord(record), agentrelay.ErrRelayInvalidState
		}
	} else if outcome != "" {
		return cloneRelayRecord(record), agentrelay.ErrRelayInvalidState
	}
	snapshot := record.Snapshot()
	snapshot.State, snapshot.StateRevision = target, snapshot.StateRevision+1
	snapshot.TransactionReference = transactionReference
	snapshot.EvidenceRefs = append([]string(nil), evidenceRefs...)
	snapshot.TerminalOutcome = outcome
	recoveryToken := record.SponsorshipRecoveryToken()
	if target == commerce.ActionTerminal {
		snapshot.SponsorshipAttempted = false
		snapshot.SponsorshipRecoveryTokenDigest = ""
		recoveryToken = nil
	}
	snapshot.UpdatedAtUnix = uint64(atUnix)
	updated, err := agentrelay.RestoreRecord(snapshot, record.ExecutionRequest(), recoveryToken)
	if err != nil {
		return cloneRelayRecord(record), agentrelay.ErrRelayInvalidState
	}
	nextRecords := cloneRelayRecords(journal.records)
	nextReservations := cloneRelayQuoteReservations(journal.quoteReservations)
	nextRecords[key] = updated
	if target == commerce.ActionRejected || target == commerce.ActionConflict || target == commerce.ActionTerminal {
		releaseRelayRecordExposure(nextReservations, updated)
	}
	if err := journal.persist(journal.providerAgentID, nextRecords, journal.tombstones, nextReservations,
		journal.quoteBindings, journal.writerHighWater, journal.quoteAdmissions); err != nil {
		return agentrelay.Record{}, err
	}
	journal.records, journal.quoteReservations = nextRecords, nextReservations
	return cloneRelayRecord(updated), nil
}

func (journal *DurableRelayJournal) load() error {
	if err := journal.ensureStorageIdentityLocked(); err != nil {
		return err
	}
	file, err := openRelayJournalRootFile(journal.root, relayJournalFile)
	if errors.Is(err, os.ErrNotExist) {
		return journal.persist(journal.providerAgentID, journal.records, journal.tombstones, journal.quoteReservations,
			journal.quoteBindings, journal.writerHighWater, journal.quoteAdmissions)
	}
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Size() <= 0 || info.Size() > maximumRelayJournalBytes {
		return errors.New("relay journal is not a bounded owner-only regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximumRelayJournalBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maximumRelayJournalBytes {
		return errors.New("read bounded relay journal")
	}
	var document relayJournalDocument
	if decodeStrictJSON(raw, &document) != nil || document.Schema != relayJournalSchema || document.QuoteReservations == nil ||
		document.Tombstones == nil || document.QuoteBindings == nil || document.WriterHighWater == nil ||
		document.QuoteAdmissions == nil ||
		len(document.Records) > maximumRelayRecords || len(document.Tombstones) > maximumRelayTombstones ||
		len(document.QuoteReservations) > maximumRelayReservations ||
		(document.ProviderAgentID == "" && (len(document.Records) != 0 || len(document.Tombstones) != 0 ||
			len(document.QuoteReservations) != 0)) ||
		len(document.ProviderAgentID) > 256 {
		return errors.New("relay journal document is invalid")
	}
	records := make(map[string]agentrelay.Record, len(document.Records))
	tombstones := make(map[string]persistedRelayTombstone, len(document.Tombstones))
	reservations := cloneRelayQuoteReservations(document.QuoteReservations)
	expectedQuotes := make(map[string]string, len(reservations)+len(document.Tombstones))
	for key, reservation := range reservations {
		quoteDigest, quoteErr := agentrelay.ProviderRelayQuoteDigest(reservation.Quote.Body)
		if quoteErr != nil || quoteDigest != reservation.QuoteDigest || !canonicalSHA256(reservation.RequestDigest) ||
			reservation.Quote.Body.ProviderAgentID != document.ProviderAgentID ||
			reservation.Quote.Body.QuoteRequestDigest != reservation.RequestDigest || reservation.ExpiresAtUnix == 0 ||
			reservation.ExpiresAtUnix != reservation.Quote.Body.ExpiresAtUnix ||
			key != relayDurableQuoteReservationKey(document.ProviderAgentID, reservation.RequestDigest) ||
			(reservation.ReservedSponsorship == nil) != (reservation.Quote.Body.ReservedSponsorship == nil) ||
			reservation.ReservedSponsorship != nil && (!sameRelayAssetAmount(*reservation.ReservedSponsorship,
				*reservation.Quote.Body.ReservedSponsorship) || !canonicalRelayAtomic(reservation.ReservedSponsorship.AmountAtomic) ||
				reservation.ReservedSponsorship.AmountAtomic == "0") ||
			reservation.Consumed && (!canonicalSHA256(reservation.StableActionID) || !canonicalSHA256(reservation.ExecutionDigest)) ||
			!reservation.Consumed && (reservation.StableActionID != "" || reservation.ExecutionDigest != "" || reservation.ExposureReleased) ||
			reservation.ExposureReleased && (!reservation.Consumed || reservation.ReservedSponsorship == nil) ||
			!validRelayAdmissionLimits(reservation.AdmissionLimits) {
			return errors.New("relay journal quote reservation is invalid")
		}
		if prior, found := expectedQuotes[quoteDigest]; found && prior != key {
			return errors.New("relay journal reuses a provider quote")
		}
		expectedQuotes[quoteDigest] = key
	}
	for _, tombstone := range document.Tombstones {
		key := relayDurableRecordKey(tombstone.StableActionID)
		if !validRelayTombstone(document.ProviderAgentID, tombstone) {
			return errors.New("relay journal tombstone is invalid")
		}
		if _, found := tombstones[key]; found {
			return errors.New("relay journal contains a duplicate tombstone")
		}
		if _, found := records[key]; found {
			return errors.New("relay journal action is both active and retired")
		}
		if prior, found := expectedQuotes[tombstone.ProviderQuoteDigest]; found && prior != tombstone.QuoteReservationKey {
			return errors.New("relay journal reuses a retired provider quote")
		}
		expectedQuotes[tombstone.ProviderQuoteDigest] = tombstone.QuoteReservationKey
		tombstones[key] = cloneRelayTombstone(tombstone)
	}
	for _, persisted := range document.Records {
		record, restoreErr := agentrelay.RestoreRecord(persisted.Snapshot, persisted.Request,
			persisted.SponsorshipRecoveryToken)
		if restoreErr != nil || !validFrozenRelayRequest(record.ExecutionRequest()) ||
			record.ProviderAgentID != document.ProviderAgentID {
			return errors.New("relay journal protected request is invalid")
		}
		key := relayDurableRecordKey(record.StableActionID)
		if _, found := records[key]; found {
			return errors.New("relay journal contains a duplicate action")
		}
		if _, found := tombstones[key]; found {
			return errors.New("relay journal action is both active and retired")
		}
		requestDigest, digestErr := agentrelay.RelayQuoteRequestDigest(persisted.Request.QuoteRequest.Body)
		reservationKey := relayDurableQuoteReservationKey(document.ProviderAgentID, requestDigest)
		reservation, reserved := reservations[reservationKey]
		if digestErr != nil || !reserved || !reservation.Consumed || reservation.QuoteDigest != record.ProviderQuoteDigest ||
			reservation.StableActionID != record.StableActionID || reservation.ExecutionDigest != record.RelayExecutionDigest {
			return errors.New("relay journal record has no exact consumed quote reservation")
		}
		if reservation.ReservedSponsorship != nil {
			releasedWithSettlement := len(record.SponsorshipExposureReleaseEvidenceRefs) > 0
			if record.SponsorshipAttempted && reservation.ExposureReleased ||
				record.SponsorshipTransferReference != "" && reservation.ExposureReleased != releasedWithSettlement ||
				reservation.ExposureReleased && record.SponsorshipTransferReference == "" &&
					record.State != commerce.ActionRejected && record.State != commerce.ActionConflict &&
					record.State != commerce.ActionTerminal {
				return errors.New("relay journal sponsorship exposure release is inconsistent")
			}
		} else if record.SponsorshipAttempted || record.SponsorshipTransferReference != "" ||
			len(record.SponsorshipExposureReleaseEvidenceRefs) > 0 {
			return errors.New("relay journal records sponsorship without reserved exposure")
		}
		ownerKey := persisted.Request.AuthorizedAction.OwnerID + "\x00" + persisted.Request.AuthorizedAction.AgentID
		if document.WriterHighWater[ownerKey] < persisted.Request.AuthorizedAction.WriterGeneration {
			return errors.New("relay journal writer high-water mark regressed")
		}
		records[key] = record
	}
	for key, generation := range document.WriterHighWater {
		if generation == 0 || !strings.Contains(key, "\x00") {
			return errors.New("relay journal writer high-water map is invalid")
		}
	}
	if !validRelayQuoteAdmissions(document.QuoteAdmissions) {
		return errors.New("relay journal quote admission window is invalid")
	}
	if !reflect.DeepEqual(expectedQuotes, document.QuoteBindings) {
		return errors.New("relay journal quote bindings are inconsistent")
	}
	journal.providerAgentID, journal.records, journal.tombstones, journal.quoteReservations =
		document.ProviderAgentID, records, tombstones, reservations
	journal.quoteBindings, journal.writerHighWater = cloneRelayStrings(document.QuoteBindings),
		cloneRelayUint64(document.WriterHighWater)
	journal.quoteAdmissions = cloneRelayAdmissions(document.QuoteAdmissions)
	return nil
}

func (journal *DurableRelayJournal) persist(providerAgentID string, records map[string]agentrelay.Record,
	tombstones map[string]persistedRelayTombstone, reservations map[string]persistedRelayQuoteReservation,
	quoteBindings map[string]string, writers map[string]uint64, admissions map[string][]uint64) error {
	keys := make([]string, 0, len(records))
	for key := range records {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	persisted := make([]persistedRelayRecord, 0, len(keys))
	for _, key := range keys {
		record := records[key]
		persisted = append(persisted, persistedRelayRecord{Snapshot: record.Snapshot(), Request: record.ExecutionRequest(),
			SponsorshipRecoveryToken: record.SponsorshipRecoveryToken()})
	}
	tombstoneValues := make([]persistedRelayTombstone, 0, len(tombstones))
	for _, key := range sortedRelayTombstoneKeys(tombstones) {
		tombstoneValues = append(tombstoneValues, cloneRelayTombstone(tombstones[key]))
	}
	if err := journal.ensureStorageIdentityLocked(); err != nil {
		return err
	}
	raw, err := json.Marshal(relayJournalDocument{Schema: relayJournalSchema, ProviderAgentID: providerAgentID,
		Records: persisted, Tombstones: tombstoneValues, QuoteReservations: cloneRelayQuoteReservations(reservations),
		QuoteBindings: cloneRelayStrings(quoteBindings), WriterHighWater: cloneRelayUint64(writers),
		QuoteAdmissions: cloneRelayAdmissions(admissions)})
	if err != nil || len(raw) == 0 || len(raw) > maximumRelayJournalBytes {
		return errors.New("encode bounded relay journal")
	}
	writeErr := fileutil.WriteFileAtomicRoot(journal.root, relayJournalFile, raw, 0o600)
	protectErr := protectRootedJournalFile(journal.root, relayJournalFile)
	if writeErr != nil {
		journal.poisoned = true
		return errors.New("atomically persist relay journal through retained directory capability")
	}
	if protectErr != nil {
		journal.poisoned = true
		return protectErr
	}
	file, err := openRelayJournalRootFile(journal.root, relayJournalFile)
	if err != nil {
		return err
	}
	if closeErr := file.Close(); closeErr != nil {
		return errors.New("close verified relay journal")
	}
	return journal.ensureStorageIdentityLocked()
}

func openRelayJournalRootFile(root *os.Root, name string) (*os.File, error) {
	if root == nil {
		return nil, errors.New("relay journal root is unavailable")
	}
	before, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, os.ErrNotExist
	}
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !relayJournalFileInfoSecure(before) {
		return nil, errors.New("relay journal is not an owner-only regular file")
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, errors.New("open relay journal through retained directory capability")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || validateRelayJournalOpenedFile(file, after) != nil {
		_ = file.Close()
		return nil, errors.New("relay journal changed while opening")
	}
	return file, nil
}

func validFrozenRelayRequest(request agentrelay.RelayExecutionRequest) bool {
	digest, err := agentrelay.SignedTransactionDigest(request.SignedTransactionBytes)
	if err != nil || digest != request.QuoteRequest.Body.SignedTransactionDigest ||
		uint32(len(request.SignedTransactionBytes)) != request.QuoteRequest.Body.SignedTransactionSize {
		return false
	}
	underlyingDigest, err := commerce.ExactRequestDigest(request.UnderlyingActionRequest)
	return err == nil && underlyingDigest == request.AuthorizedAction.ExactRequestDigest &&
		agentrelay.VerifyRelaySideEffectAdmissionReceiptIntegrity(request.AdmissionReceipt, request) == nil
}

func validDurableRelayTransition(from, to commerce.ActionResolutionState) bool {
	switch from {
	case commerce.ActionPrepared:
		return to == commerce.ActionSubmitted || to == commerce.ActionRejected || to == commerce.ActionConflict || to == commerce.ActionTerminal
	case commerce.ActionSubmitted:
		return to == commerce.ActionAccepted || to == commerce.ActionRejected || to == commerce.ActionConflict || to == commerce.ActionTerminal
	case commerce.ActionAccepted:
		return to == commerce.ActionSubmitted || to == commerce.ActionTerminal
	default:
		return false
	}
}

func validDurableRelayOutcome(outcome agentrelay.TerminalOutcome) bool {
	switch outcome {
	case agentrelay.OutcomeFinalizedSuccess, agentrelay.OutcomeFinalizedExpired, agentrelay.OutcomeFinalizedAbsent,
		agentrelay.OutcomeFinalizedInvalidated, agentrelay.OutcomeFinalizedSponsorshipOnly,
		agentrelay.OutcomeFinalizedRelayOnly,
		agentrelay.OutcomeCorroboratedSuccess, agentrelay.OutcomeCorroboratedExpired,
		agentrelay.OutcomeCorroboratedAbsent, agentrelay.OutcomeCorroboratedInvalidated,
		agentrelay.OutcomeCorroboratedSponsorshipOnly, agentrelay.OutcomeCorroboratedRelayOnly:
		return true
	default:
		return false
	}
}

// validDurableRelayOutcomeForRecord prevents a durable store from accepting a
// truthful-looking terminal label that overstates the exact signed request.
// agentrelay.RestoreRecord performs the same protocol-level validation after
// construction; this admission check keeps the invariant explicit at the
// persistence boundary and before any state is written.
func validDurableRelayOutcomeForRecord(record agentrelay.Record, outcome agentrelay.TerminalOutcome,
	transactionReference string) bool {
	if !validDurableRelayOutcome(outcome) {
		return false
	}
	request := record.ExecutionRequest()
	body := request.QuoteRequest.Body
	quote := request.ProviderQuote.Body
	relayProfile, sponsorshipProfile := quote.RelayFinalityProfile, quote.SponsorshipTerminalProfile
	evidence := record.SponsorshipTransactionEvidence
	lowerAssurance := body.AssuranceLevel == agentrelay.AssuranceTrustedLocal ||
		body.AssuranceLevel == agentrelay.AssuranceAuthorizedSingleProvider
	lowerRelay := relayProfile != nil &&
		relayProfile.TerminalEvidenceClass == agentrelay.RelayTerminalProviderCorroborated
	validatorRelay := relayProfile != nil &&
		relayProfile.TerminalEvidenceClass == agentrelay.RelayTerminalValidatorFinality
	lowerSponsorProfile := sponsorshipProfile != nil &&
		sponsorshipProfile.ProfileURI == agentrelay.ClientCorroboratedTerminalProfileURI &&
		sponsorshipProfile.TerminalEvidenceClass == agentrelay.SponsorshipTerminalClientCorroborated
	validatorSponsorProfile := sponsorshipProfile != nil &&
		sponsorshipProfile.TerminalEvidenceClass == agentrelay.SponsorshipTerminalValidatorFinality
	lowerSponsor := lowerSponsorProfile && evidence != nil &&
		evidence.TerminalEvidenceClass == agentrelay.SponsorshipTerminalClientCorroborated &&
		!evidence.ValidatorAuthenticatedPortableProof && record.SponsorshipTransferReference != ""
	validatorSponsor := validatorSponsorProfile && evidence != nil &&
		evidence.TerminalEvidenceClass == agentrelay.SponsorshipTerminalValidatorFinality &&
		evidence.ValidatorAuthenticatedPortableProof && record.SponsorshipTransferReference != ""
	switch outcome {
	case agentrelay.OutcomeCorroboratedSponsorshipOnly:
		return lowerAssurance && lowerSponsor &&
			(body.Mode == agentrelay.ModeSponsorOnly || body.Mode == agentrelay.ModeSponsorAndRelay) &&
			transactionReference == record.SponsorshipTransferReference
	case agentrelay.OutcomeCorroboratedRelayOnly:
		return lowerAssurance && body.Mode == agentrelay.ModeSponsorAndRelay &&
			(lowerRelay || lowerSponsorProfile) && record.SponsorshipTransferReference == "" &&
			transactionReference != ""
	case agentrelay.OutcomeCorroboratedSuccess:
		return lowerAssurance && body.Mode != agentrelay.ModeSponsorOnly && relayProfile != nil &&
			(body.Mode == agentrelay.ModeRelayExact && lowerRelay ||
				body.Mode == agentrelay.ModeSponsorAndRelay && (lowerRelay || lowerSponsor)) &&
			(body.Mode == agentrelay.ModeRelayExact || record.SponsorshipTransferReference != "" &&
				(lowerSponsor || validatorSponsor)) && transactionReference != "" &&
			transactionReference != record.SponsorshipTransferReference
	case agentrelay.OutcomeCorroboratedExpired, agentrelay.OutcomeCorroboratedAbsent,
		agentrelay.OutcomeCorroboratedInvalidated:
		return lowerAssurance && transactionReference == "" &&
			(body.Mode == agentrelay.ModeRelayExact && lowerRelay ||
				body.Mode != agentrelay.ModeRelayExact && (lowerRelay || lowerSponsorProfile))
	case agentrelay.OutcomeFinalizedSponsorshipOnly:
		return validatorSponsor && transactionReference == record.SponsorshipTransferReference
	case agentrelay.OutcomeFinalizedRelayOnly:
		return body.Mode == agentrelay.ModeSponsorAndRelay && validatorRelay && validatorSponsorProfile &&
			record.SponsorshipTransferReference == "" && transactionReference != ""
	case agentrelay.OutcomeFinalizedSuccess:
		return body.Mode != agentrelay.ModeSponsorOnly && validatorRelay &&
			(body.Mode == agentrelay.ModeRelayExact || validatorSponsor) && transactionReference != "" &&
			transactionReference != record.SponsorshipTransferReference
	case agentrelay.OutcomeFinalizedExpired, agentrelay.OutcomeFinalizedAbsent,
		agentrelay.OutcomeFinalizedInvalidated:
		return transactionReference == "" &&
			(body.Mode == agentrelay.ModeRelayExact && validatorRelay ||
				body.Mode != agentrelay.ModeRelayExact && validatorSponsorProfile &&
					(body.Mode == agentrelay.ModeSponsorOnly || validatorRelay))
	default:
		return false
	}
}

func sortedRelayEvidenceRefs(values []string) bool {
	if len(values) > agentrelay.MaxRelayEvidenceRefs {
		return false
	}
	for index, value := range values {
		if !canonicalSHA256(value) || index > 0 && values[index-1] >= value {
			return false
		}
	}
	return true
}

func equalRelayEvidenceRefs(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func validDurableSponsorshipAbsenceOutcome(outcome agentrelay.TerminalOutcome) bool {
	return outcome == "" || safeRelayTerminalAbsenceOutcome(outcome) ||
		outcome == agentrelay.OutcomeFinalizedSponsorshipOnly ||
		outcome == agentrelay.OutcomeCorroboratedSponsorshipOnly
}

func relayAbsenceReferenceDigests(
	references []agentrelay.RelayAbsenceObservationReference) ([]string, error) {
	digests := make([]string, len(references))
	for index, reference := range references {
		digest, err := agentrelay.RelayAbsenceObservationReferenceDigest(reference)
		if err != nil || index > 0 && digests[index-1] >= digest {
			return nil, agentrelay.ErrRelayInvalidState
		}
		digests[index] = digest
	}
	return digests, nil
}

func mergeRelayEvidenceRefs(left, right []string) []string {
	seen := make(map[string]struct{}, len(left)+len(right))
	for _, value := range left {
		seen[value] = struct{}{}
	}
	for _, value := range right {
		seen[value] = struct{}{}
	}
	merged := make([]string, 0, len(seen))
	for value := range seen {
		merged = append(merged, value)
	}
	sort.Strings(merged)
	return merged
}

func relayEvidenceRefsContainAll(values, required []string) bool {
	if len(required) == 0 || !sortedRelayEvidenceRefs(values) || !sortedRelayEvidenceRefs(required) {
		return false
	}
	valueIndex := 0
	for _, requiredValue := range required {
		for valueIndex < len(values) && values[valueIndex] < requiredValue {
			valueIndex++
		}
		if valueIndex == len(values) || values[valueIndex] != requiredValue {
			return false
		}
		valueIndex++
	}
	return true
}

func relayAbsenceObservationDigestsForRecord(record agentrelay.Record, outcome agentrelay.TerminalOutcome,
	sponsorshipObservations, transactionObservations []agentrelay.RelayAbsenceObservationReference,
	at time.Time) ([]string, []string, []string, error) {
	if !safeRelayTerminalAbsenceOutcome(outcome) || at.IsZero() {
		return nil, nil, nil, agentrelay.ErrRelayInvalidState
	}
	request := record.ExecutionRequest()
	networkDigest, err := agentrelay.NetworkDomainDigest(request.QuoteRequest.Body.Network)
	if err != nil {
		return nil, nil, nil, err
	}
	executionDigest, err := agentrelay.RelayExecutionRequestDigest(request)
	if err != nil {
		return nil, nil, nil, err
	}
	maximumObserved := at.UTC().Unix()
	if maximumObserved <= 0 {
		return nil, nil, nil, agentrelay.ErrRelayInvalidState
	}
	if maximumObserved > (1<<63)-1-5*60 {
		return nil, nil, nil, agentrelay.ErrRelayInvalidState
	}
	maximumObserved += 5 * 60
	if request.ProviderQuote.Body.SponsorshipTerminalProfile == nil {
		return nil, nil, nil, agentrelay.ErrRelayInvalidState
	}
	profile := *request.ProviderQuote.Body.SponsorshipTerminalProfile
	sponsorshipDigests, sponsorshipProofs, checkpointID, checkpointSequence, checkpointUnix, err :=
		relayAbsenceObservationSetForRecord(record, sponsorshipObservations,
			agentrelay.AbsenceObservationSponsorshipAction, agentrelay.AbsenceConclusionExpiredWithoutInclusion,
			networkDigest, executionDigest, uint64(maximumObserved), profile)
	if err != nil {
		return nil, nil, nil, err
	}
	transactionDigests, transactionProofs, transactionCheckpointID, transactionCheckpointSequence,
		transactionCheckpointUnix, err :=
		relayAbsenceObservationSetForRecord(record, transactionObservations,
			agentrelay.AbsenceObservationClientTransaction, relayTransactionAbsenceConclusion(outcome),
			networkDigest, executionDigest, uint64(maximumObserved), profile)
	if err != nil || checkpointID != transactionCheckpointID || checkpointSequence != transactionCheckpointSequence ||
		checkpointUnix != transactionCheckpointUnix {
		return nil, nil, nil, agentrelay.ErrRelayInvalidState
	}
	for proof := range sponsorshipProofs {
		if _, reused := transactionProofs[proof]; reused {
			return nil, nil, nil, agentrelay.ErrRelayInvalidState
		}
	}
	merged := mergeRelayEvidenceRefs(sponsorshipDigests, transactionDigests)
	if len(merged) != len(sponsorshipDigests)+len(transactionDigests) || !sortedRelayEvidenceRefs(merged) {
		return nil, nil, nil, agentrelay.ErrRelayInvalidState
	}
	return sponsorshipDigests, transactionDigests, merged, nil
}

func relayAbsenceObservationSetForRecord(record agentrelay.Record,
	observations []agentrelay.RelayAbsenceObservationReference, kind agentrelay.RelayAbsenceObservationKind,
	conclusion agentrelay.RelayAbsenceConclusion, networkDigest, executionDigest string, maximumObserved uint64,
	profile agentrelay.FinalityProfile) ([]string, map[string]struct{}, string, uint64, uint64, error) {
	minimumObservers, minimumDomains := int(profile.MinimumObservers), int(profile.MinimumOperatorDomains)
	if conclusion == "" || len(observations) < minimumObservers || len(observations) > agentrelay.MaxRelayEvidenceRefs {
		return nil, nil, "", 0, 0, agentrelay.ErrRelayInvalidState
	}
	request := record.ExecutionRequest()
	observerIDs := make(map[string]struct{}, len(observations))
	operatorDomains := make(map[string]struct{}, len(observations))
	proofs := make(map[string]struct{}, len(observations))
	digests := make([]string, len(observations))
	checkpointID := observations[0].FinalizedCheckpointID
	checkpointSequence := observations[0].FinalizedCheckpointSequence
	checkpointUnix := observations[0].FinalizedCheckpointUnix
	for index, observation := range observations {
		digest, err := agentrelay.RelayAbsenceObservationReferenceDigest(observation)
		if err != nil || observation.ObservationKind != kind || observation.Conclusion != conclusion ||
			observation.ProviderAgentID != record.ProviderAgentID || observation.NetworkDigest != networkDigest ||
			observation.RelayStableActionID != record.StableActionID ||
			observation.RelayExactRequestDigest != record.ExactRequestDigest ||
			observation.RelayExecutionDigest != executionDigest ||
			observation.SponsorshipStableActionID != record.SponsorshipStableActionID ||
			observation.SponsorshipExactRequestDigest != record.SponsorshipExactRequestDigest ||
			observation.SponsorshipValidUntilUnix != record.SponsorshipValidUntilUnix ||
			observation.SignedTransactionDigest != record.SignedTransactionDigest ||
			observation.SignedTransactionCellHash != request.QuoteRequest.Body.SignedTransactionCellHash ||
			observation.TerminalProfileURI != profile.ProfileURI ||
			observation.TerminalProfileDigest != profile.ProfileDigest ||
			observation.TerminalEvidenceClass != profile.TerminalEvidenceClass ||
			observation.FinalizedCheckpointID != checkpointID ||
			observation.FinalizedCheckpointSequence != checkpointSequence ||
			observation.FinalizedCheckpointUnix != checkpointUnix ||
			observation.ObservedAtUnix > maximumObserved || index > 0 && digests[index-1] >= digest {
			return nil, nil, "", 0, 0, agentrelay.ErrRelayInvalidState
		}
		if _, duplicate := observerIDs[observation.ObserverID]; duplicate {
			return nil, nil, "", 0, 0, agentrelay.ErrRelayInvalidState
		}
		if _, duplicate := proofs[observation.ObservationDigest]; duplicate {
			return nil, nil, "", 0, 0, agentrelay.ErrRelayInvalidState
		}
		digests[index] = digest
		observerIDs[observation.ObserverID] = struct{}{}
		operatorDomains[observation.OperatorDomainID] = struct{}{}
		proofs[observation.ObservationDigest] = struct{}{}
	}
	if checkpointUnix < record.SponsorshipValidUntilUnix || len(observerIDs) < minimumObservers ||
		len(operatorDomains) < minimumDomains {
		return nil, nil, "", 0, 0, agentrelay.ErrRelayInvalidState
	}
	return digests, proofs, checkpointID, checkpointSequence, checkpointUnix, nil
}

func relayTransactionAbsenceConclusion(outcome agentrelay.TerminalOutcome) agentrelay.RelayAbsenceConclusion {
	switch outcome {
	case agentrelay.OutcomeFinalizedAbsent, agentrelay.OutcomeCorroboratedAbsent:
		return agentrelay.AbsenceConclusionAbsent
	case agentrelay.OutcomeFinalizedExpired, agentrelay.OutcomeCorroboratedExpired:
		return agentrelay.AbsenceConclusionExpiredWithoutInclusion
	case agentrelay.OutcomeFinalizedInvalidated, agentrelay.OutcomeCorroboratedInvalidated:
		return agentrelay.AbsenceConclusionInvalidated
	default:
		return ""
	}
}

func safeRelayTerminalAbsenceOutcome(outcome agentrelay.TerminalOutcome) bool {
	switch outcome {
	case agentrelay.OutcomeFinalizedAbsent, agentrelay.OutcomeFinalizedExpired,
		agentrelay.OutcomeFinalizedInvalidated, agentrelay.OutcomeCorroboratedAbsent,
		agentrelay.OutcomeCorroboratedExpired, agentrelay.OutcomeCorroboratedInvalidated:
		return true
	default:
		return false
	}
}

func relayDurableRecordKey(stableActionID string) string {
	return stableActionID
}

func relayRetiredRecordError(tombstones map[string]persistedRelayTombstone,
	stableActionID, exactRequestDigest string) error {
	tombstone, found := tombstones[relayDurableRecordKey(stableActionID)]
	if !found {
		return agentrelay.ErrRelayUnknown
	}
	if tombstone.ExactRequestDigest != exactRequestDigest {
		return agentrelay.ErrRelayConflict
	}
	return ErrRelayRetired
}

func relayDurableQuoteReservationKey(providerAgentID, requestDigest string) string {
	return providerAgentID + "\x00" + requestDigest
}

func releaseExpiredRelayReservations(reservations map[string]persistedRelayQuoteReservation,
	bindings map[string]string, nowUnix uint64) {
	for key, reservation := range reservations {
		if !reservation.Consumed && reservation.ExpiresAtUnix <= nowUnix {
			delete(reservations, key)
			if bindings[reservation.QuoteDigest] == key {
				delete(bindings, reservation.QuoteDigest)
			}
		}
	}
}

func validRelayAdmissionLimits(limits agentrelay.AdmissionLimits) bool {
	return limits.MaximumQuoteReservations > 0 && limits.MaximumQuoteReservations <= 1_000_000 &&
		limits.MaximumActiveExecutions > 0 && limits.MaximumActiveExecutions <= 1_000_000 &&
		limits.MaximumActivePerRequester > 0 &&
		limits.MaximumActivePerRequester <= limits.MaximumActiveExecutions &&
		limits.MaximumQuoteRequestsPerWindow > 0 && limits.MaximumQuoteRequestsPerWindow <= 1_000_000 &&
		limits.MaximumQuoteRequestsPerRequesterWindow > 0 &&
		limits.MaximumQuoteRequestsPerRequesterWindow <= limits.MaximumQuoteRequestsPerWindow &&
		limits.QuoteRequestWindowSeconds > 0 && limits.QuoteRequestWindowSeconds <= 24*60*60
}

func effectiveRelayAdmissionLimits(profile agentrelay.AdmissionLimits,
	local *agentrelay.AdmissionLimits) (agentrelay.AdmissionLimits, error) {
	if !validRelayAdmissionLimits(profile) {
		return agentrelay.AdmissionLimits{}, agentrelay.ErrRelayInvalidState
	}
	effective := profile
	effective.MaximumQuoteReservations = min(effective.MaximumQuoteReservations, uint32(maximumRelayReservations))
	effective.MaximumActiveExecutions = min(effective.MaximumActiveExecutions, uint32(maximumRelayRecords))
	effective.MaximumActivePerRequester = min(effective.MaximumActivePerRequester,
		effective.MaximumActiveExecutions)
	effective.MaximumQuoteRequestsPerWindow = min(effective.MaximumQuoteRequestsPerWindow,
		uint32(maximumRelayRateEvents/2))
	effective.MaximumQuoteRequestsPerRequesterWindow = min(effective.MaximumQuoteRequestsPerRequesterWindow,
		min(effective.MaximumQuoteRequestsPerWindow, uint32(maximumRelayRateEvents/20)))
	if local == nil {
		return effective, nil
	}
	if !validRelayAdmissionLimits(*local) || local.QuoteRequestWindowSeconds != profile.QuoteRequestWindowSeconds ||
		local.MaximumQuoteReservations > profile.MaximumQuoteReservations ||
		local.MaximumActiveExecutions > profile.MaximumActiveExecutions ||
		local.MaximumActivePerRequester > profile.MaximumActivePerRequester ||
		local.MaximumQuoteRequestsPerWindow > profile.MaximumQuoteRequestsPerWindow ||
		local.MaximumQuoteRequestsPerRequesterWindow > profile.MaximumQuoteRequestsPerRequesterWindow {
		return agentrelay.AdmissionLimits{}, errors.New("relay owner admission policy is not stricter than the signed profile")
	}
	effective.MaximumQuoteReservations = min(effective.MaximumQuoteReservations, local.MaximumQuoteReservations)
	effective.MaximumActiveExecutions = min(effective.MaximumActiveExecutions, local.MaximumActiveExecutions)
	effective.MaximumActivePerRequester = min(effective.MaximumActivePerRequester, local.MaximumActivePerRequester)
	effective.MaximumQuoteRequestsPerWindow = min(effective.MaximumQuoteRequestsPerWindow,
		local.MaximumQuoteRequestsPerWindow)
	effective.MaximumQuoteRequestsPerRequesterWindow = min(effective.MaximumQuoteRequestsPerRequesterWindow,
		local.MaximumQuoteRequestsPerRequesterWindow)
	return effective, nil
}

// relayExecutionAdmissionLimits applies the currently configured owner work
// ceiling even to a quote reserved before restart. A previously signed quote
// remains byte-for-byte retriable, but it cannot override a later owner safety
// reduction in concurrent active work. Loosening policy never widens the
// limits frozen into the reservation.
func relayExecutionAdmissionLimits(reserved agentrelay.AdmissionLimits,
	local *agentrelay.AdmissionLimits) (agentrelay.AdmissionLimits, error) {
	if !validRelayAdmissionLimits(reserved) {
		return agentrelay.AdmissionLimits{}, agentrelay.ErrRelayInvalidState
	}
	effective := reserved
	if local == nil {
		return effective, nil
	}
	if !validRelayAdmissionLimits(*local) || local.QuoteRequestWindowSeconds != reserved.QuoteRequestWindowSeconds {
		return agentrelay.AdmissionLimits{}, errors.New("relay owner admission policy conflicts with the reserved quote window")
	}
	effective.MaximumActiveExecutions = min(effective.MaximumActiveExecutions, local.MaximumActiveExecutions)
	effective.MaximumActivePerRequester = min(effective.MaximumActivePerRequester, local.MaximumActivePerRequester)
	return effective, nil
}

func activeRelayQuoteReservations(reservations map[string]persistedRelayQuoteReservation) uint64 {
	var count uint64
	for _, reservation := range reservations {
		if !reservation.Consumed {
			count++
		}
	}
	return count
}

func activeRelayExecutions(records map[string]agentrelay.Record, requesterAgentID string) uint64 {
	var count uint64
	for _, record := range records {
		if record.State == commerce.ActionTerminal || record.State == commerce.ActionRejected ||
			record.State == commerce.ActionConflict {
			continue
		}
		if requesterAgentID == "" || record.ExecutionRequest().QuoteRequest.Body.RequesterAgentID == requesterAgentID {
			count++
		}
	}
	return count
}

func admitRelayQuoteRate(admissions map[string][]uint64, requesterAgentID string,
	limits agentrelay.AdmissionLimits, nowUnix uint64) bool {
	if requesterAgentID == "" || !validRelayAdmissionLimits(limits) || nowUnix == 0 {
		return false
	}
	window := uint64(limits.QuoteRequestWindowSeconds)
	cutoff := uint64(0)
	if nowUnix > window {
		cutoff = nowUnix - window
	}
	global := pruneRelayAdmissionTimes(admissions[relayGlobalRateBucket], cutoff)
	requester := pruneRelayAdmissionTimes(admissions[requesterAgentID], cutoff)
	admissions[relayGlobalRateBucket] = global
	admissions[requesterAgentID] = requester
	if len(global) >= int(limits.MaximumQuoteRequestsPerWindow) ||
		len(requester) >= int(limits.MaximumQuoteRequestsPerRequesterWindow) ||
		len(global)+len(requester)+2 > maximumRelayRateEvents {
		return false
	}
	admissions[relayGlobalRateBucket] = append(global, nowUnix)
	admissions[requesterAgentID] = append(requester, nowUnix)
	return true
}

func pruneRelayAdmissionTimes(values []uint64, cutoff uint64) []uint64 {
	first := 0
	for first < len(values) && values[first] <= cutoff {
		first++
	}
	if first == len(values) {
		return nil
	}
	return append([]uint64(nil), values[first:]...)
}

func pruneAllRelayAdmissions(admissions map[string][]uint64, nowUnix uint64) {
	cutoff := uint64(0)
	if nowUnix > 24*60*60 {
		cutoff = nowUnix - 24*60*60
	}
	for requester, values := range admissions {
		values = pruneRelayAdmissionTimes(values, cutoff)
		if len(values) == 0 {
			delete(admissions, requester)
		} else {
			admissions[requester] = values
		}
	}
}

func validRelayQuoteAdmissions(admissions map[string][]uint64) bool {
	total := 0
	for requester, values := range admissions {
		if requester == "" || requester != relayGlobalRateBucket &&
			(len(requester) > 256 || strings.TrimSpace(requester) != requester || strings.ContainsAny(requester, "\x00\r\n\t")) {
			return false
		}
		total += len(values)
		if total > maximumRelayRateEvents {
			return false
		}
		for index, value := range values {
			if value == 0 || index > 0 && values[index-1] > value {
				return false
			}
		}
	}
	return true
}

func compactRelayTerminalRecords(records map[string]agentrelay.Record,
	tombstones map[string]persistedRelayTombstone, reservations map[string]persistedRelayQuoteReservation,
	providerAgentID string, retention time.Duration, nowUnix uint64) bool {
	if retention < time.Second || nowUnix == 0 || len(tombstones) >= maximumRelayTombstones {
		return false
	}
	retentionSeconds := uint64(retention / time.Second)
	changed := false
	keys := make([]string, 0, len(records))
	for key := range records {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if len(tombstones) >= maximumRelayTombstones {
			break
		}
		record := records[key]
		if record.State != commerce.ActionTerminal || record.SponsorshipAttempted ||
			record.UpdatedAtUnix == 0 || nowUnix < record.UpdatedAtUnix ||
			nowUnix-record.UpdatedAtUnix < retentionSeconds {
			continue
		}
		request := record.ExecutionRequest()
		quoteRequestDigest, err := agentrelay.RelayQuoteRequestDigest(request.QuoteRequest.Body)
		if err != nil {
			continue
		}
		reservationKey := relayDurableQuoteReservationKey(providerAgentID, quoteRequestDigest)
		reservation, found := reservations[reservationKey]
		if !found || !reservation.Consumed || reservation.StableActionID != record.StableActionID ||
			reservation.ExecutionDigest != record.RelayExecutionDigest || reservation.QuoteDigest != record.ProviderQuoteDigest {
			continue
		}
		if reservation.ReservedSponsorship != nil {
			if !reservation.ExposureReleased || record.SponsorshipTransferReference != "" &&
				len(record.SponsorshipExposureReleaseEvidenceRefs) == 0 ||
				record.SponsorshipTransferReference == "" &&
					len(record.SponsorshipAbsenceObservationDigests) == 0 ||
				(len(record.SponsorshipAbsenceObservationDigests) != 0 ||
					len(record.TransactionAbsenceObservationDigests) != 0) &&
					!canonicalSHA256(record.AbsenceProofBundleDigest) {
				continue
			}
		}
		tombstone := persistedRelayTombstone{
			StableActionID: record.StableActionID, ExactRequestDigest: record.ExactRequestDigest,
			RelayExecutionDigest: record.RelayExecutionDigest, AdmissionReceiptDigest: record.AdmissionReceiptDigest,
			SignedTransactionDigest: record.SignedTransactionDigest,
			ProviderQuoteDigest:     record.ProviderQuoteDigest, QuoteRequestDigest: quoteRequestDigest,
			QuoteReservationKey: reservationKey, Mode: request.QuoteRequest.Body.Mode,
			AssuranceLevel:       request.QuoteRequest.Body.AssuranceLevel,
			TransactionReference: record.TransactionReference, EvidenceRefs: append([]string(nil), record.EvidenceRefs...),
			TerminalOutcome: record.TerminalOutcome, SponsorshipStableActionID: record.SponsorshipStableActionID,
			SponsorshipExactRequestDigest:        record.SponsorshipExactRequestDigest,
			SponsorshipValidUntilUnix:            record.SponsorshipValidUntilUnix,
			SponsorshipTransferReference:         record.SponsorshipTransferReference,
			SponsorshipAbsenceObservationDigests: append([]string(nil), record.SponsorshipAbsenceObservationDigests...),
			TransactionAbsenceObservationDigests: append([]string(nil), record.TransactionAbsenceObservationDigests...),
			AbsenceProofBundleDigest:             record.AbsenceProofBundleDigest,
			ExposureReleaseEvidenceRefs:          append([]string(nil), record.SponsorshipExposureReleaseEvidenceRefs...),
			TerminalUpdatedAtUnix:                record.UpdatedAtUnix, RetiredAtUnix: nowUnix,
		}
		if profile := request.ProviderQuote.Body.RelayFinalityProfile; profile != nil {
			tombstone.RelayFinalityProfileURI = profile.ProfileURI
			tombstone.RelayFinalityProfileDigest = profile.ProfileDigest
			tombstone.RelayTerminalEvidenceClass = profile.TerminalEvidenceClass
			tombstone.RelayValidatorAuthenticatedProof =
				profile.TerminalEvidenceClass == agentrelay.RelayTerminalValidatorFinality &&
					record.TerminalOutcome != agentrelay.OutcomeCorroboratedSuccess &&
					record.TerminalOutcome != agentrelay.OutcomeCorroboratedRelayOnly &&
					record.TerminalOutcome != agentrelay.OutcomeCorroboratedExpired &&
					record.TerminalOutcome != agentrelay.OutcomeCorroboratedAbsent &&
					record.TerminalOutcome != agentrelay.OutcomeCorroboratedInvalidated
		}
		if profile := request.ProviderQuote.Body.SponsorshipTerminalProfile; profile != nil {
			tombstone.SponsorshipTerminalProfileURI = profile.ProfileURI
			tombstone.SponsorshipTerminalProfileDigest = profile.ProfileDigest
			tombstone.SponsorshipTerminalEvidenceClass = profile.TerminalEvidenceClass
			tombstone.SponsorshipValidatorAuthenticatedProof =
				profile.TerminalEvidenceClass == agentrelay.SponsorshipTerminalValidatorFinality &&
					record.TerminalOutcome != agentrelay.OutcomeCorroboratedSuccess &&
					record.TerminalOutcome != agentrelay.OutcomeCorroboratedExpired &&
					record.TerminalOutcome != agentrelay.OutcomeCorroboratedAbsent &&
					record.TerminalOutcome != agentrelay.OutcomeCorroboratedInvalidated &&
					record.TerminalOutcome != agentrelay.OutcomeCorroboratedSponsorshipOnly &&
					record.TerminalOutcome != agentrelay.OutcomeCorroboratedRelayOnly
		}
		if evidence := record.SponsorshipTransactionEvidence; evidence != nil {
			tombstone.SponsorshipTerminalEvidenceClass = evidence.TerminalEvidenceClass
			tombstone.SponsorshipValidatorAuthenticatedProof = evidence.ValidatorAuthenticatedPortableProof
		}
		if !validRelayTombstone(providerAgentID, tombstone) {
			continue
		}
		tombstones[key] = tombstone
		delete(records, key)
		delete(reservations, reservationKey)
		changed = true
	}
	return changed
}

func validRelayTombstone(providerAgentID string, tombstone persistedRelayTombstone) bool {
	if providerAgentID == "" || !canonicalSHA256(tombstone.StableActionID) ||
		!canonicalSHA256(tombstone.ExactRequestDigest) || !canonicalSHA256(tombstone.RelayExecutionDigest) ||
		!canonicalSHA256(tombstone.AdmissionReceiptDigest) ||
		!canonicalSHA256(tombstone.SignedTransactionDigest) || !canonicalSHA256(tombstone.ProviderQuoteDigest) ||
		!canonicalSHA256(tombstone.QuoteRequestDigest) ||
		tombstone.QuoteReservationKey != relayDurableQuoteReservationKey(providerAgentID, tombstone.QuoteRequestDigest) ||
		len(tombstone.TransactionReference) > 1024 || len(tombstone.SponsorshipTransferReference) > 1024 ||
		len(tombstone.EvidenceRefs) == 0 || !sortedRelayEvidenceRefs(tombstone.EvidenceRefs) ||
		!validDurableRelayOutcome(tombstone.TerminalOutcome) ||
		!validDurableRelayTombstoneOutcome(tombstone) || tombstone.TerminalUpdatedAtUnix == 0 ||
		tombstone.RetiredAtUnix < tombstone.TerminalUpdatedAtUnix {
		return false
	}
	switch tombstone.Mode {
	case agentrelay.ModeRelayExact:
		return tombstone.SponsorshipStableActionID == "" && tombstone.SponsorshipExactRequestDigest == "" &&
			tombstone.SponsorshipValidUntilUnix == 0 &&
			tombstone.SponsorshipTransferReference == "" &&
			tombstone.AbsenceProofBundleDigest == "" &&
			len(tombstone.SponsorshipAbsenceObservationDigests) == 0 &&
			len(tombstone.TransactionAbsenceObservationDigests) == 0 &&
			len(tombstone.ExposureReleaseEvidenceRefs) == 0
	case agentrelay.ModeSponsorOnly, agentrelay.ModeSponsorAndRelay:
		if !canonicalSHA256(tombstone.SponsorshipStableActionID) ||
			!canonicalSHA256(tombstone.SponsorshipExactRequestDigest) || tombstone.SponsorshipValidUntilUnix == 0 {
			return false
		}
		if tombstone.SponsorshipTransferReference != "" {
			if len(tombstone.SponsorshipAbsenceObservationDigests) != 0 ||
				len(tombstone.ExposureReleaseEvidenceRefs) == 0 ||
				!sortedRelayEvidenceRefs(tombstone.ExposureReleaseEvidenceRefs) {
				return false
			}
			if len(tombstone.TransactionAbsenceObservationDigests) == 0 {
				return tombstone.AbsenceProofBundleDigest == ""
			}
			return canonicalSHA256(tombstone.AbsenceProofBundleDigest) &&
				sortedRelayEvidenceRefs(tombstone.TransactionAbsenceObservationDigests) &&
				relayEvidenceRefsContainAll(tombstone.EvidenceRefs,
					tombstone.TransactionAbsenceObservationDigests)
		}
		if len(tombstone.SponsorshipAbsenceObservationDigests) == 0 ||
			!sortedRelayEvidenceRefs(tombstone.SponsorshipAbsenceObservationDigests) ||
			len(tombstone.TransactionAbsenceObservationDigests) != 0 &&
				!sortedRelayEvidenceRefs(tombstone.TransactionAbsenceObservationDigests) {
			return false
		}
		absenceRefs := mergeRelayEvidenceRefs(tombstone.SponsorshipAbsenceObservationDigests,
			tombstone.TransactionAbsenceObservationDigests)
		return canonicalSHA256(tombstone.AbsenceProofBundleDigest) &&
			len(tombstone.ExposureReleaseEvidenceRefs) == 0 &&
			relayEvidenceRefsContainAll(tombstone.EvidenceRefs, absenceRefs)
	default:
		return false
	}
}

// validDurableRelayTombstoneOutcome retains enough non-secret terminal
// authority metadata to re-check lower-assurance corroboration after protected
// request bytes have been compacted. Missing fields are tolerated for legacy
// validator-finalized tombstones, but never for the newer corroborated labels.
func validDurableRelayTombstoneOutcome(tombstone persistedRelayTombstone) bool {
	lowerAssurance := tombstone.AssuranceLevel == agentrelay.AssuranceTrustedLocal ||
		tombstone.AssuranceLevel == agentrelay.AssuranceAuthorizedSingleProvider
	lowerRelay := tombstone.RelayTerminalEvidenceClass == agentrelay.RelayTerminalProviderCorroborated &&
		canonicalSHA256(tombstone.RelayFinalityProfileDigest) && !tombstone.RelayValidatorAuthenticatedProof
	validatorRelay := tombstone.RelayTerminalEvidenceClass == agentrelay.RelayTerminalValidatorFinality &&
		canonicalSHA256(tombstone.RelayFinalityProfileDigest) && tombstone.RelayValidatorAuthenticatedProof
	lowerSponsorProfile := tombstone.SponsorshipTerminalProfileURI == agentrelay.ClientCorroboratedTerminalProfileURI &&
		canonicalSHA256(tombstone.SponsorshipTerminalProfileDigest)
	lowerSponsor := lowerSponsorProfile &&
		tombstone.SponsorshipTerminalEvidenceClass == agentrelay.SponsorshipTerminalClientCorroborated &&
		!tombstone.SponsorshipValidatorAuthenticatedProof && tombstone.SponsorshipTransferReference != ""
	validatorSponsorProfile := canonicalSHA256(tombstone.SponsorshipTerminalProfileDigest) &&
		tombstone.SponsorshipTerminalProfileURI != "" &&
		tombstone.SponsorshipTerminalEvidenceClass == agentrelay.SponsorshipTerminalValidatorFinality
	validatorSponsor := validatorSponsorProfile &&
		tombstone.SponsorshipTerminalEvidenceClass == agentrelay.SponsorshipTerminalValidatorFinality &&
		tombstone.SponsorshipValidatorAuthenticatedProof && tombstone.SponsorshipTransferReference != ""
	switch tombstone.TerminalOutcome {
	case agentrelay.OutcomeCorroboratedSponsorshipOnly:
		return lowerAssurance && lowerSponsor &&
			(tombstone.Mode == agentrelay.ModeSponsorOnly || tombstone.Mode == agentrelay.ModeSponsorAndRelay) &&
			tombstone.TransactionReference == tombstone.SponsorshipTransferReference
	case agentrelay.OutcomeCorroboratedRelayOnly:
		return lowerAssurance && tombstone.Mode == agentrelay.ModeSponsorAndRelay &&
			(lowerRelay || lowerSponsorProfile) && tombstone.SponsorshipTransferReference == "" &&
			tombstone.TransactionReference != ""
	case agentrelay.OutcomeCorroboratedSuccess:
		return lowerAssurance && tombstone.Mode != agentrelay.ModeSponsorOnly &&
			(tombstone.Mode == agentrelay.ModeRelayExact && lowerRelay ||
				tombstone.Mode == agentrelay.ModeSponsorAndRelay && (lowerRelay || lowerSponsor)) &&
			(tombstone.Mode == agentrelay.ModeRelayExact || lowerSponsor || validatorSponsor) &&
			tombstone.TransactionReference != "" &&
			tombstone.TransactionReference != tombstone.SponsorshipTransferReference
	case agentrelay.OutcomeCorroboratedExpired, agentrelay.OutcomeCorroboratedAbsent,
		agentrelay.OutcomeCorroboratedInvalidated:
		return lowerAssurance && tombstone.TransactionReference == "" &&
			(tombstone.Mode == agentrelay.ModeRelayExact && lowerRelay ||
				tombstone.Mode != agentrelay.ModeRelayExact && (lowerRelay || lowerSponsorProfile))
	case agentrelay.OutcomeFinalizedSponsorshipOnly:
		return validatorSponsor && tombstone.TransactionReference == tombstone.SponsorshipTransferReference
	case agentrelay.OutcomeFinalizedRelayOnly:
		return tombstone.Mode == agentrelay.ModeSponsorAndRelay && validatorRelay && validatorSponsorProfile &&
			tombstone.SponsorshipTransferReference == "" && tombstone.TransactionReference != ""
	case agentrelay.OutcomeFinalizedSuccess:
		return tombstone.Mode != agentrelay.ModeSponsorOnly && validatorRelay &&
			(tombstone.Mode == agentrelay.ModeRelayExact || validatorSponsor) &&
			tombstone.TransactionReference != "" &&
			tombstone.TransactionReference != tombstone.SponsorshipTransferReference
	case agentrelay.OutcomeFinalizedExpired, agentrelay.OutcomeFinalizedAbsent,
		agentrelay.OutcomeFinalizedInvalidated:
		return tombstone.TransactionReference == "" &&
			(tombstone.Mode == agentrelay.ModeRelayExact && validatorRelay ||
				tombstone.Mode != agentrelay.ModeRelayExact && validatorSponsorProfile &&
					(tombstone.Mode == agentrelay.ModeSponsorOnly || validatorRelay))
	default:
		return false
	}
}

func retiredRelayQuoteRequest(tombstones map[string]persistedRelayTombstone,
	quoteRequestDigest string) bool {
	for _, tombstone := range tombstones {
		if tombstone.QuoteRequestDigest == quoteRequestDigest {
			return true
		}
	}
	return false
}

func sortedRelayTombstoneKeys(tombstones map[string]persistedRelayTombstone) []string {
	keys := make([]string, 0, len(tombstones))
	for key := range tombstones {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func cloneRelayTombstone(tombstone persistedRelayTombstone) persistedRelayTombstone {
	tombstone.EvidenceRefs = append([]string(nil), tombstone.EvidenceRefs...)
	tombstone.SponsorshipAbsenceObservationDigests = append([]string(nil),
		tombstone.SponsorshipAbsenceObservationDigests...)
	tombstone.TransactionAbsenceObservationDigests = append([]string(nil),
		tombstone.TransactionAbsenceObservationDigests...)
	tombstone.ExposureReleaseEvidenceRefs = append([]string(nil), tombstone.ExposureReleaseEvidenceRefs...)
	return tombstone
}

func cloneRelayTombstones(input map[string]persistedRelayTombstone) map[string]persistedRelayTombstone {
	output := make(map[string]persistedRelayTombstone, len(input))
	for key, tombstone := range input {
		output[key] = cloneRelayTombstone(tombstone)
	}
	return output
}

func canReserveRelayExposure(profile agentrelay.RelayServiceProfile,
	reservations map[string]persistedRelayQuoteReservation, requested agentrelay.AssetAmount) bool {
	var maximumPerRequest, maximumOutstanding string
	for _, limit := range profile.ExposureLimits {
		if limit.Asset == requested.Asset {
			maximumPerRequest, maximumOutstanding = limit.MaximumPerRequestAtomic, limit.MaximumOutstandingAtomic
			break
		}
	}
	requestedValue, requestedOK := new(big.Int).SetString(requested.AmountAtomic, 10)
	perRequest, perRequestOK := new(big.Int).SetString(maximumPerRequest, 10)
	outstanding, outstandingOK := new(big.Int).SetString(maximumOutstanding, 10)
	if !requestedOK || !perRequestOK || !outstandingOK || requestedValue.Sign() <= 0 || requestedValue.Cmp(perRequest) > 0 {
		return false
	}
	total := new(big.Int).Set(requestedValue)
	for _, reservation := range reservations {
		if reservation.ExposureReleased || reservation.ReservedSponsorship == nil ||
			reservation.ReservedSponsorship.Asset != requested.Asset {
			continue
		}
		value, ok := new(big.Int).SetString(reservation.ReservedSponsorship.AmountAtomic, 10)
		if !ok || value.Sign() <= 0 {
			return false
		}
		total.Add(total, value)
	}
	return total.Cmp(outstanding) <= 0
}

func releaseRelayRecordExposure(reservations map[string]persistedRelayQuoteReservation, record agentrelay.Record) bool {
	// A finalized top-up is real provider spend. Expiry or rejection of the
	// subsequently relayed transaction cannot silently recreate that exposure
	// budget; an explicit reimbursement/settlement release boundary is needed.
	if record.SponsorshipAttempted || record.SponsorshipTransferReference != "" &&
		len(record.SponsorshipExposureReleaseEvidenceRefs) == 0 {
		return false
	}
	request := record.ExecutionRequest()
	requestDigest, err := agentrelay.RelayQuoteRequestDigest(request.QuoteRequest.Body)
	if err != nil {
		return false
	}
	key := relayDurableQuoteReservationKey(record.ProviderAgentID, requestDigest)
	reservation, found := reservations[key]
	if !found || !reservation.Consumed || reservation.StableActionID != record.StableActionID ||
		reservation.ExecutionDigest != record.RelayExecutionDigest || reservation.ReservedSponsorship == nil {
		return false
	}
	reservation.ExposureReleased = true
	reservations[key] = reservation
	return true
}

func sameRelayAssetAmount(left, right agentrelay.AssetAmount) bool {
	return left.Asset == right.Asset && left.AmountAtomic == right.AmountAtomic
}

func cloneRelaySignedQuote(quote agentrelay.SignedProviderRelayQuote) agentrelay.SignedProviderRelayQuote {
	quote.Body.FeeLines = append([]agentrelay.FeeLine(nil), quote.Body.FeeLines...)
	if quote.Body.ReservedSponsorship != nil {
		amount := *quote.Body.ReservedSponsorship
		quote.Body.ReservedSponsorship = &amount
	}
	return quote
}

func cloneRelayQuoteReservations(input map[string]persistedRelayQuoteReservation) map[string]persistedRelayQuoteReservation {
	output := make(map[string]persistedRelayQuoteReservation, len(input))
	for key, reservation := range input {
		reservation.Quote = cloneRelaySignedQuote(reservation.Quote)
		if reservation.ReservedSponsorship != nil {
			amount := *reservation.ReservedSponsorship
			reservation.ReservedSponsorship = &amount
		}
		output[key] = reservation
	}
	return output
}

func cloneRelayRecord(record agentrelay.Record) agentrelay.Record {
	cloned, err := agentrelay.RestoreRecord(record.Snapshot(), record.ExecutionRequest(),
		record.SponsorshipRecoveryToken())
	if err != nil {
		return agentrelay.Record{}
	}
	return cloned
}

func cloneRelayRecords(input map[string]agentrelay.Record) map[string]agentrelay.Record {
	output := make(map[string]agentrelay.Record, len(input))
	for key, record := range input {
		output[key] = cloneRelayRecord(record)
	}
	return output
}

func cloneRelayStrings(input map[string]string) map[string]string {
	output := make(map[string]string, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func cloneRelayUint64(input map[string]uint64) map[string]uint64 {
	output := make(map[string]uint64, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func cloneRelayAdmissions(input map[string][]uint64) map[string][]uint64 {
	output := make(map[string][]uint64, len(input))
	for key, values := range input {
		output[key] = append([]uint64(nil), values...)
	}
	return output
}

func sameRelayRecord(left, right agentrelay.Record) bool {
	return reflect.DeepEqual(left.Snapshot(), right.Snapshot()) && reflect.DeepEqual(left.ExecutionRequest(), right.ExecutionRequest()) &&
		bytes.Equal(left.SponsorshipRecoveryToken(), right.SponsorshipRecoveryToken())
}

var _ agentrelay.Journal = (*DurableRelayJournal)(nil)
