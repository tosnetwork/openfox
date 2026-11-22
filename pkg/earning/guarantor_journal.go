package earning

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"sync"
	"time"

	commerce "github.com/tosnetwork/ai/protocol/pkg/agentcommerce"
	guarantor "github.com/tosnetwork/ai/protocol/pkg/agentguarantor"
	"github.com/tosnetwork/ai/protocol/pkg/codec"

	"github.com/tosnetwork/openfox/pkg/fileutil"
)

const (
	// guarantorJournalSchema v4 tracks each claim's revision epoch, keeps the
	// immutable receipts it serves in content-addressed files beside the
	// document, which records only their media type, size and hash, and
	// stores each plan's semantic fields in their transport form. A v1 journal
	// has no epochs, a v2 journal holds the receipts inside the document and a
	// v3 journal holds plans without their semantic fields; all three are
	// refused rather than read or converted.
	guarantorJournalSchema          = "tos.openfox.agent-guarantor-journal.v4"
	retiredGuarantorJournalSchema   = "tos.openfox.agent-guarantor-journal.v1"
	retiredGuarantorJournalSchemaV2 = "tos.openfox.agent-guarantor-journal.v2"
	retiredGuarantorJournalSchemaV3 = "tos.openfox.agent-guarantor-journal.v3"
	guarantorJournalFile            = "agent-guarantor-journal.json"
	// guarantorEvidenceDirectory holds one file per stored immutable receipt,
	// named by the hex of its envelope digest.
	guarantorEvidenceDirectory = "immutable-evidence"
)

type GuarantorOfferPosition struct {
	QuoteRequestDigest          string                                                     `json:"quote_request_digest"`
	CoveredPartyAgentID         string                                                     `json:"covered_party_agent_id"`
	CoverageAsset               commerce.AssetIdentityV1                                   `json:"coverage_asset"`
	GrossExposureAtomic         string                                                     `json:"gross_exposure_atomic"`
	NetExposureAtomic           string                                                     `json:"net_exposure_atomic"`
	AcceptByUnix                uint64                                                     `json:"accept_by_unix"`
	ReservationExpiresAt        uint64                                                     `json:"reservation_expires_at_unix"`
	OfferEnvelopeDigest         string                                                     `json:"offer_envelope_digest,omitempty"`
	AuthorizedFirmOffer         *guarantor.AuthorizedFirmCoverageOfferV1                   `json:"authorized_firm_offer,omitempty"`
	NonAcceptanceEvidence       *guarantor.AuthorizedOfferNonAcceptanceEvidenceV1          `json:"non_acceptance_evidence,omitempty"`
	PreAcceptanceReleaseReceipt *guarantor.AuthorizedPreAcceptanceExposureReleaseReceiptV1 `json:"pre_acceptance_release_receipt,omitempty"`
	PreAcceptanceReleasePlan    *GuarantorPreAcceptanceReleasePlan                         `json:"pre_acceptance_release_plan,omitempty"`
	Record                      guarantor.OfferRecord                                      `json:"record"`
}

type GuarantorPreAcceptanceReleasePlan struct {
	Action                  commerce.AuthorizedAction                          `json:"authorized_action"`
	Fields                  map[string]commerce.SemanticValue                  `json:"semantic_fields"`
	CanonicalRequest        []byte                                             `json:"canonical_request"`
	RequestBody             guarantor.PreAcceptanceExposureReleaseActionBodyV1 `json:"request_body"`
	BasePortfolioRevision   uint64                                             `json:"base_portfolio_revision"`
	TargetPortfolioRevision uint64                                             `json:"target_portfolio_revision"`
	ReleasedAtUnix          uint64                                             `json:"released_at_unix"`
}

type GuarantorFirmOfferIssuancePlan struct {
	AuthorityInstanceID string                                  `json:"authority_instance_id"`
	AdmissionDomainID   string                                  `json:"admission_domain_id"`
	Action              commerce.AuthorizedAction               `json:"authorized_action"`
	Fields              map[string]commerce.SemanticValue       `json:"semantic_fields"`
	CanonicalRequest    []byte                                  `json:"canonical_request"`
	Reservation         ExposureReservation                     `json:"reservation"`
	Offer               guarantor.AuthorizedFirmCoverageOfferV1 `json:"offer"`
	OfferDigest         string                                  `json:"offer_digest"`
	ReceiptDigest       string                                  `json:"receipt_digest"`
	Position            GuarantorOfferPosition                  `json:"position"`
}

type GuarantorCoveragePosition struct {
	Terms                        guarantor.CoverageTermsV1                                        `json:"terms"`
	AcceptanceReceipt            *guarantor.AuthorizedCoverageAcceptanceReceiptV1                 `json:"acceptance_receipt,omitempty"`
	ActivationEvidence           *guarantor.AuthorizedCoverageActivationEvidenceV1                `json:"activation_evidence,omitempty"`
	NonActivationEvidence        *guarantor.AuthorizedCoverageNonActivationEvidenceV1             `json:"non_activation_evidence,omitempty"`
	NonActivationReleaseReceipt  *guarantor.AuthorizedNonActivationExposureReleaseReceiptV1       `json:"non_activation_release_receipt,omitempty"`
	CancellationReceipt          *guarantor.AuthorizedCoverageCancellationReceiptV1               `json:"cancellation_receipt,omitempty"`
	FilingCloseReceipt           *guarantor.AuthorizedClaimFilingCloseReceiptV1                   `json:"filing_close_receipt,omitempty"`
	TerminalClaimSet             *guarantor.AuthorizedTerminalClaimSetEvidenceV1                  `json:"terminal_claim_set,omitempty"`
	ExposureReleaseReceipt       *guarantor.AuthorizedExposureReleaseReceiptV1                    `json:"exposure_release_receipt,omitempty"`
	CoverageResolution           *guarantor.AuthorizedCoverageResolutionV1                        `json:"coverage_resolution,omitempty"`
	ExposureReleasePlan          *GuarantorExposureReleasePlan                                    `json:"exposure_release_plan,omitempty"`
	CoverageResolutionPlan       *GuarantorCoverageResolutionPlan                                 `json:"coverage_resolution_plan,omitempty"`
	Record                       guarantor.CoverageRecord                                         `json:"record"`
	Claims                       map[string]guarantor.ClaimRecord                                 `json:"claims"`
	ClaimEnvelopes               map[string]guarantor.AuthorizedCoverageClaimV1                   `json:"claim_envelopes"`
	ClaimIngressReceipts         map[string]guarantor.AuthorizedClaimSubmissionIngressReceiptV1   `json:"claim_ingress_receipts"`
	ClaimAdmissionReceipts       map[string]guarantor.AuthorizedClaimAdmissionReceiptV1           `json:"claim_admission_receipts"`
	Decisions                    map[string]guarantor.AuthorizedClaimDecisionV1                   `json:"decisions"`
	DecisionAdmissionReceipts    map[string]guarantor.AuthorizedClaimDecisionAdmissionReceiptV1   `json:"decision_admission_receipts"`
	ClaimStateTransitionReceipts map[string]guarantor.AuthorizedClaimStateTransitionReceiptV1     `json:"claim_state_transition_receipts"`
	DecisionApplicationReceipts  map[string]guarantor.AuthorizedClaimDecisionApplicationReceiptV1 `json:"decision_application_receipts"`
	DecisionApplicationTokens    map[string]guarantor.DecisionApplicationTokenV1                  `json:"decision_application_tokens"`
	ChallengeRoundsUsed          map[string]uint64                                                `json:"challenge_rounds_used"`
	NonterminalRoundsUsed        map[string]uint64                                                `json:"nonterminal_rounds_used"`
	ClaimAdmissionSequence       map[string]uint64                                                `json:"claim_admission_sequence"`
	ClaimAdmissionLogRoot        string                                                           `json:"claim_admission_log_root"`
	ClaimRevisionSequence        map[string]uint64                                                `json:"claim_revision_sequence"`
	ClaimRevisionLogRoot         map[string]string                                                `json:"claim_revision_log_root"`
	RevisionEpochs               map[string]GuarantorRevisionEpochState                           `json:"revision_epochs"`
	// ImmutableEvidence holds every receipt a compact proof or descriptor may
	// name, keyed by its envelope digest, so it can be served after the
	// position has moved past it.
	ImmutableEvidence                     map[string]GuarantorStoredEvidence                                `json:"immutable_evidence"`
	MaterializedPayouts                   map[string]guarantor.MaterializedPayoutObligationSetV1            `json:"materialized_payouts"`
	PayoutEvidence                        map[string]commerce.AgreementPaymentEvidence                      `json:"payout_evidence"`
	PayoutRequests                        map[string]commerce.AgreementPaymentRequest                       `json:"payout_requests"`
	PayoutExecutionEvidence               map[string]guarantor.AuthorizedGuarantorPayoutExecutionEvidenceV1 `json:"payout_execution_evidence"`
	PaidByObligation                      map[string]string                                                 `json:"paid_by_obligation"`
	DefaultedByObligation                 map[string]string                                                 `json:"defaulted_by_obligation"`
	PaidAtomic                            string                                                            `json:"paid_atomic"`
	DefaultedAtomic                       string                                                            `json:"defaulted_atomic"`
	AggregatePendingDecisionReserveAtomic string                                                            `json:"aggregate_pending_decision_reserve_atomic"`
	CumulativeAppliedApprovedAtomic       string                                                            `json:"cumulative_applied_approved_atomic"`
	NextPayoutSequence                    uint64                                                            `json:"next_payout_sequence"`
	MaterializedPayoutLineDigest          string                                                            `json:"materialized_payout_line_digest,omitempty"`
}

type GuarantorExposureReleasePlan struct {
	Action           commerce.AuthorizedAction                  `json:"authorized_action"`
	WriterFence      commerce.WriterFence                       `json:"writer_fence"`
	Fields           map[string]commerce.SemanticValue          `json:"semantic_fields"`
	CanonicalRequest []byte                                     `json:"canonical_request"`
	RequestBody      guarantor.ExposureReleaseActionBodyV1      `json:"request_body"`
	Disposition      guarantor.ExposureDispositionComputationV1 `json:"exposure_disposition"`
	CreatedAtUnix    uint64                                     `json:"created_at_unix"`
}

type GuarantorCoverageResolutionPlan struct {
	Action           commerce.AuthorizedAction                `json:"authorized_action"`
	WriterFence      commerce.WriterFence                     `json:"writer_fence"`
	Fields           map[string]commerce.SemanticValue        `json:"semantic_fields"`
	CanonicalRequest []byte                                   `json:"canonical_request"`
	RequestBody      guarantor.CoverageResolutionActionBodyV1 `json:"request_body"`
	TargetStatus     guarantor.CoverageStatus                 `json:"target_status"`
	TargetState      string                                   `json:"target_state"`
	CreatedAtUnix    uint64                                   `json:"created_at_unix"`
}

type guarantorJournalDocument struct {
	Schema                 string                                    `json:"schema"`
	OwnerID                string                                    `json:"owner_id"`
	AgentID                string                                    `json:"agent_id"`
	Revision               uint64                                    `json:"revision"`
	Offers                 map[string]GuarantorOfferPosition         `json:"offers"`
	Coverages              map[string]GuarantorCoveragePosition      `json:"coverages"`
	ClaimToCoverage        map[string]string                         `json:"claim_to_coverage"`
	AdmissionLogs          map[string]GuarantorAdmissionLog          `json:"admission_logs"`
	FirmOfferIssuancePlans map[string]GuarantorFirmOfferIssuancePlan `json:"firm_offer_issuance_plans"`
}

type GuarantorAdmissionEntry = guarantor.GuarantorAdmissionLogEntryV1

type GuarantorAdmissionLog struct {
	DomainID     string                             `json:"domain_id"`
	RootDomain   string                             `json:"root_domain,omitempty"`
	NextSequence uint64                             `json:"next_sequence"`
	CurrentRoot  string                             `json:"current_root"`
	Entries      map[string]GuarantorAdmissionEntry `json:"entries"`
}

type GuarantorAdmissionCut struct {
	DomainID  string
	HighWater uint64
	LogRoot   string
	Entries   []GuarantorAdmissionEntry
}

func guarantorAdmissionInitialRoot(rootDomain, domainID string) (string, error) {
	if rootDomain == "" {
		return guarantor.InitialAdmissionLogRootV1(domainID)
	}
	return guarantor.InitialClaimLogRootV1(rootDomain, domainID)
}

func guarantorAdmissionAdvanceRoot(rootDomain, domainID, priorRoot, stableActionID, exactRequestDigest string,
	sequence, receivedAtUnix uint64) (string, error) {
	if rootDomain == "" {
		return guarantor.AdvanceAdmissionLogRootV1(domainID, priorRoot, stableActionID, exactRequestDigest,
			sequence, receivedAtUnix)
	}
	return guarantor.AdvanceClaimLogRootV1(rootDomain, domainID, priorRoot, sequence,
		guarantor.ClaimIngressLogLeafV1{StableActionID: stableActionID,
			ExactRequestDigest: exactRequestDigest, ReceivedAtUnix: receivedAtUnix})
}

type GuarantorClaimAdmissionPreview struct {
	Initial                           bool
	PriorCoverageRevision             uint64
	AdmittedCoverageRevision          uint64
	PriorClaimRevision                uint64
	AdmittedClaimRevision             uint64
	ClaimAdmissionSequence            uint64
	ClaimRevisionAdmissionSequence    uint64
	ClaimAdmissionLogID               string
	ClaimRevisionLogID                string
	PriorClaimAdmissionLogRoot        string
	AdmittedClaimAdmissionLogRoot     string
	PriorClaimRevisionLogRoot         string
	AdmittedClaimRevisionLogRoot      string
	InitialAdmissionReceiptDigest     string
	PredecessorAdmissionReceiptDigest string
}

// GuarantorJournal is a durable provider-private projection. Economic
// admission remains authoritative in EconomicAuthority; this journal cannot
// sign, pay, or release exposure by itself.
type GuarantorJournal struct {
	mu         sync.Mutex
	directory  string
	root       *os.Root
	lock       *os.File
	domainLock *localEconomicDomainLock
	doc        guarantorJournalDocument
	now        func() time.Time
	// writeFile writes one journal file atomically: the document or an
	// immutable evidence file. Tests replace it to inject a failed write.
	writeFile func(root *os.Root, name string, data []byte, perm os.FileMode) error
	// syncDirectory makes the entries of a directory inside the journal
	// durable. Tests replace it to observe or fail a directory sync.
	syncDirectory func(root *os.Root, directory string) error
	// readOnly marks a journal opened for inspection. It writes nothing: no
	// document, no evidence file, and it removes nothing.
	readOnly bool
	// unconfirmed is set by a commit whose document was renamed into place
	// while the directory sync after it failed, and cleared once the same
	// document has been written again successfully. While it is set the
	// journal does nothing else.
	unconfirmed bool
}

// OpenGuarantorJournal opens the journal for the Provider that writes it. It
// creates a journal that does not exist yet and removes what a crash left
// behind.
func OpenGuarantorJournal(directory, ownerID, agentID string) (*GuarantorJournal, error) {
	return openGuarantorJournal(directory, ownerID, agentID, false)
}

// OpenGuarantorJournalReadOnly opens an existing journal for inspection. It
// loads the document with the same checks as the writer's open and changes
// nothing: it creates no journal and no evidence directory, removes no crash
// leftover, and refuses every commit. It takes the journal's locks like the
// writer's open, so it fails while a Provider has the journal open; taking
// them creates the journal's lock file if a restored journal has none.
func OpenGuarantorJournalReadOnly(directory, ownerID, agentID string) (*GuarantorJournal, error) {
	return openGuarantorJournal(directory, ownerID, agentID, true)
}

func openGuarantorJournal(directory, ownerID, agentID string, readOnly bool) (*GuarantorJournal, error) {
	return openGuarantorJournalSyncedBy(directory, ownerID, agentID, readOnly, fileutil.SyncDirectoryRoot)
}

// openGuarantorJournalSyncedBy opens the journal with syncDirectory as the
// function that makes a directory's entries durable. Tests pass one that
// observes or fails the syncs of the open itself.
func openGuarantorJournalSyncedBy(directory, ownerID, agentID string, readOnly bool,
	syncDirectory func(root *os.Root, directory string) error,
) (*GuarantorJournal, error) {
	if syncDirectory == nil {
		return nil, errors.New("Guarantor journal configuration or directory security is invalid")
	}
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || ownerID == "" || agentID == "" ||
		validateRelayJournalDirectorySecurity(directory) != nil {
		return nil, errors.New("Guarantor journal configuration or directory security is invalid")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("Guarantor journal directory is unavailable")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, errors.New("open Guarantor journal directory")
	}
	if readOnly {
		if _, statErr := root.Lstat(guarantorJournalFile); statErr != nil {
			_ = root.Close()
			return nil, errors.New("Guarantor journal does not exist or cannot be inspected")
		}
	}
	domainLock, err := acquireLocalEconomicDomainLock("agent-guarantor\x00" + ownerID + "\x00" + agentID)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	lock, err := acquireAuthorityLockRoot(root)
	if err != nil {
		_ = domainLock.Close()
		_ = root.Close()
		return nil, err
	}
	if !readOnly {
		if err := root.Mkdir(guarantorEvidenceDirectory, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			_ = releaseAuthorityLock(lock)
			_ = domainLock.Close()
			_ = root.Close()
			return nil, errors.New("create Guarantor immutable evidence directory")
		}
	}
	// A journal inspected read-only may have no evidence directory yet; the
	// load then refuses any record that names a receipt.
	evidenceInfo, evidenceErr := root.Lstat(guarantorEvidenceDirectory)
	if (evidenceErr != nil && (!readOnly || !errors.Is(evidenceErr, os.ErrNotExist))) ||
		(evidenceErr == nil && (!evidenceInfo.IsDir() || evidenceInfo.Mode().Perm()&0o077 != 0)) {
		_ = releaseAuthorityLock(lock)
		_ = domainLock.Close()
		_ = root.Close()
		return nil, errors.New("Guarantor immutable evidence directory security is invalid")
	}
	journal := &GuarantorJournal{directory: directory, root: root, lock: lock, domainLock: domainLock, now: time.Now,
		writeFile: fileutil.WriteFileAtomicRoot, syncDirectory: syncDirectory, readOnly: readOnly,
		doc: guarantorJournalDocument{Schema: guarantorJournalSchema, OwnerID: ownerID, AgentID: agentID, Revision: 1,
			Offers: map[string]GuarantorOfferPosition{}, Coverages: map[string]GuarantorCoveragePosition{}, ClaimToCoverage: map[string]string{},
			AdmissionLogs: map[string]GuarantorAdmissionLog{}, FirmOfferIssuancePlans: map[string]GuarantorFirmOfferIssuancePlan{}}}
	if _, err := root.Lstat(guarantorJournalFile); errors.Is(err, os.ErrNotExist) {
		if err := journal.persist(journal.doc); err != nil {
			_ = journal.Close()
			return nil, err
		}
	} else if err != nil {
		_ = journal.Close()
		return nil, fmt.Errorf("load Guarantor journal: %w", err)
	} else if loadErr := journal.load(ownerID, agentID); loadErr != nil {
		_ = journal.Close()
		return nil, fmt.Errorf("load Guarantor journal: %w", loadErr)
	}
	if readOnly {
		return journal, nil
	}
	// A crash between writing a receipt file and the document naming it, or
	// inside an atomic write, leaves a file no record names. The journal is
	// loaded and exclusively locked here, so those files are removed now. Only
	// the writer's open does this: an inspection removes nothing.
	if err := journal.sweepCrashLeftovers(); err != nil {
		_ = journal.Close()
		return nil, fmt.Errorf("sweep Guarantor journal crash leftovers: %w", err)
	}
	// The journal answers from what it just loaded, and whether the last
	// writer's final rename was made durable is not recorded anywhere: a
	// writer that lost a directory sync and then stopped leaves a document
	// that reads back and may still vanish in a crash. So the open confirms
	// what it loaded before it hands the journal out, and fails if it cannot.
	if err := journal.confirmLoadedDurable(); err != nil {
		_ = journal.Close()
		return nil, fmt.Errorf("confirm Guarantor journal durability: %w", err)
	}
	return journal, nil
}

// confirmLoadedDurable syncs the journal directory, which holds the document,
// and the evidence directory, which holds the receipt files the document
// names. Both syncs are cheap and change nothing, so every writer's open
// makes them. The caller holds the journal or is still opening it.
func (journal *GuarantorJournal) confirmLoadedDurable() error {
	for _, directory := range []string{".", guarantorEvidenceDirectory} {
		if err := journal.syncDirectory(journal.root, directory); err != nil {
			return fmt.Errorf("sync %s: %w", directory, err)
		}
	}
	return nil
}

// Close releases the journal. A commit whose durability is still unconfirmed
// is confirmed first, and a failure to confirm it is returned: the caller
// closing the journal is the last one who can be told. The journal is closed
// either way, and the next writer's open confirms what it loads.
func (journal *GuarantorJournal) Close() error {
	if journal == nil {
		return nil
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	var result error
	if journal.unconfirmed && journal.root != nil {
		result = journal.confirmDurable()
	}
	if journal.lock != nil {
		if err := releaseAuthorityLock(journal.lock); result == nil {
			result = err
		}
		journal.lock = nil
	}
	if journal.root != nil {
		if err := journal.root.Close(); result == nil {
			result = err
		}
		journal.root = nil
	}
	if journal.domainLock != nil {
		if err := journal.domainLock.Close(); result == nil {
			result = err
		}
		journal.domainLock = nil
	}
	return result
}

func (journal *GuarantorJournal) ReserveUnsignedOffer(position GuarantorOfferPosition) error {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if err := journal.ensureAttached(); err != nil {
		return err
	}
	if !canonicalSHA256(position.QuoteRequestDigest) || position.CoveredPartyAgentID == "" ||
		commerce.ValidateAssetIdentityV1(position.CoverageAsset) != nil ||
		!canonicalSHA256(position.Record.OfferID) || !canonicalSHA256(position.Record.ReservationID) ||
		position.Record.Status != guarantor.OfferReservedUnsigned || position.Record.StateRevision == 0 ||
		position.AcceptByUnix == 0 || position.ReservationExpiresAt <= position.AcceptByUnix {
		return errors.New("Guarantor unsigned offer reservation is invalid")
	}
	if _, err := positiveBig(position.GrossExposureAtomic); err != nil {
		return err
	}
	if _, err := nonnegativeBig(position.NetExposureAtomic); err != nil {
		return err
	}
	// A replayed reservation returns below without a working copy, so an
	// unconfirmed commit is confirmed here first.
	if err := journal.confirmDurable(); err != nil {
		return err
	}
	if existing, found := journal.doc.Offers[position.Record.OfferID]; found {
		if sameJSON(existing, position) {
			return nil
		}
		return errors.New("Guarantor offer identity conflicts with prior reservation")
	}
	next, err := journal.workingCopy()
	if err != nil {
		return err
	}
	next.Offers[position.Record.OfferID] = position
	next.Revision++
	return journal.commit(next)
}

func (journal *GuarantorJournal) SaveFirmOfferIssuancePlan(plan GuarantorFirmOfferIssuancePlan) error {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if err := journal.ensureAttached(); err != nil {
		return errors.New("Guarantor firm-offer issuance plan is invalid")
	}
	// A replayed plan returns below without a working copy, so an unconfirmed
	// commit is confirmed here first.
	if err := journal.confirmDurable(); err != nil {
		return err
	}
	// The plan is checked exactly as a load checks it, so nothing is stored
	// that a restart would refuse.
	var stored *GuarantorOfferPosition
	if position, found := journal.doc.Offers[plan.AuthorityInstanceID]; found {
		stored = &position
	}
	if err := validateFirmOfferIssuancePlan(journal.doc.OwnerID, journal.doc.AgentID, plan, stored); err != nil {
		return err
	}
	if existing, found := journal.doc.FirmOfferIssuancePlans[plan.AuthorityInstanceID]; found {
		if sameJSON(existing, plan) {
			return nil
		}
		return errors.New("Guarantor firm-offer issuance plan conflicts")
	}
	next, err := journal.workingCopy()
	if err != nil {
		return err
	}
	next.FirmOfferIssuancePlans[plan.AuthorityInstanceID] = plan
	next.Revision++
	return journal.commit(next)
}

// readable is what every reader whose answer a caller may act on checks
// before it reads: the journal is open on its own directory, and no commit is
// left without a confirmed sync. An unconfirmed commit is confirmed here
// first, exactly as a commit method does; if it cannot be, the reader fails
// with ErrGuarantorJournalDurabilityUnconfirmed instead of answering from a
// document that may not survive a crash. "Not found" is such an answer too.
// The caller holds the journal.
func (journal *GuarantorJournal) readable() error {
	if err := journal.ensureAttached(); err != nil {
		return err
	}
	return journal.confirmDurable()
}

// FirmOfferIssuancePlan returns the stored firm-offer issuance plan of
// authorityInstanceID as a private copy, and whether there is one. An error
// means the journal could not be read: it says nothing about the plan, and a
// caller must not treat it as "no plan".
func (journal *GuarantorJournal) FirmOfferIssuancePlan(authorityInstanceID string) (GuarantorFirmOfferIssuancePlan,
	bool, error,
) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if err := journal.readable(); err != nil {
		return GuarantorFirmOfferIssuancePlan{}, false, err
	}
	if _, found := journal.doc.FirmOfferIssuancePlans[authorityInstanceID]; !found {
		return GuarantorFirmOfferIssuancePlan{}, false, nil
	}
	doc, err := journal.workingCopy()
	if err != nil {
		return GuarantorFirmOfferIssuancePlan{}, false, err
	}
	plan, found := doc.FirmOfferIssuancePlans[authorityInstanceID]
	return plan, found, nil
}

// FirmOfferByDigest returns the exact authorized bytes retained at issuance,
// as a private copy, and whether the journal holds them. Acceptance never
// reconstructs a commercial offer from chat, a body digest, or a now-deleted
// outbound transport record. An error means the journal could not be read: it
// says nothing about the offer, and a caller must not treat it as "no offer".
func (journal *GuarantorJournal) FirmOfferByDigest(envelopeDigest string) (guarantor.AuthorizedFirmCoverageOfferV1,
	bool, error,
) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if err := journal.readable(); err != nil {
		return guarantor.AuthorizedFirmCoverageOfferV1{}, false, err
	}
	if !canonicalSHA256(envelopeDigest) {
		return guarantor.AuthorizedFirmCoverageOfferV1{}, false, nil
	}
	for offerID, position := range journal.doc.Offers {
		if position.OfferEnvelopeDigest != envelopeDigest || position.AuthorizedFirmOffer == nil {
			continue
		}
		digest, err := guarantor.FirmOfferDigest(*position.AuthorizedFirmOffer)
		if err != nil || digest != envelopeDigest {
			continue
		}
		doc, err := journal.workingCopy()
		if err != nil {
			return guarantor.AuthorizedFirmCoverageOfferV1{}, false, err
		}
		if doc.Offers[offerID].AuthorizedFirmOffer == nil {
			return guarantor.AuthorizedFirmCoverageOfferV1{}, false, errors.New("copy the stored Guarantor firm offer")
		}
		return *doc.Offers[offerID].AuthorizedFirmOffer, true, nil
	}
	return guarantor.AuthorizedFirmCoverageOfferV1{}, false, nil
}

func (journal *GuarantorJournal) CompleteFirmOfferIssuancePlan(authorityInstanceID, offerDigest string) error {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if err := journal.ensureAttached(); err != nil {
		return err
	}
	// A plan already completed returns below without a working copy, so an
	// unconfirmed commit is confirmed here first.
	if err := journal.confirmDurable(); err != nil {
		return err
	}
	plan, found := journal.doc.FirmOfferIssuancePlans[authorityInstanceID]
	position, offerFound := journal.doc.Offers[authorityInstanceID]
	if !found {
		return nil
	}
	if !offerFound || plan.OfferDigest != offerDigest || position.OfferEnvelopeDigest != offerDigest ||
		position.Record.Status != guarantor.OfferIssued {
		return errors.New("Guarantor firm-offer issuance plan cannot complete before its exact offer")
	}
	next, err := journal.workingCopy()
	if err != nil {
		return err
	}
	delete(next.FirmOfferIssuancePlans, authorityInstanceID)
	next.Revision++
	return journal.commit(next)
}

func (journal *GuarantorJournal) DiscardUnadmittedFirmOfferIssuancePlan(authorityInstanceID string,
	authority EconomicAuthority) error {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if err := journal.ensureAttached(); err != nil || authority == nil {
		return errors.New("Guarantor firm-offer plan discard is unavailable")
	}
	// A plan already discarded returns below without a working copy, so an
	// unconfirmed commit is confirmed here first.
	if err := journal.confirmDurable(); err != nil {
		return err
	}
	plan, found := journal.doc.FirmOfferIssuancePlans[authorityInstanceID]
	if !found {
		return nil
	}
	if authority.Resolve(plan.Action.StableActionID, plan.Action.ExactRequestDigest).State != commerce.ActionUnknown {
		return errors.New("an admitted Guarantor firm-offer plan cannot be discarded")
	}
	next, err := journal.workingCopy()
	if err != nil {
		return err
	}
	delete(next.FirmOfferIssuancePlans, authorityInstanceID)
	next.Revision++
	return journal.commit(next)
}

func (journal *GuarantorJournal) CommitFirmOffer(offerID, envelopeDigest string) (GuarantorOfferPosition, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if err := journal.ensureAttached(); err != nil || !canonicalSHA256(envelopeDigest) {
		return GuarantorOfferPosition{}, errors.New("Guarantor firm offer commit is invalid")
	}
	next, err := journal.workingCopy()
	if err != nil {
		return GuarantorOfferPosition{}, err
	}
	position, found := next.Offers[offerID]
	if !found || position.AuthorizedFirmOffer == nil {
		return GuarantorOfferPosition{}, errors.New("Guarantor firm offer has no reserved predecessor")
	}
	wantDigest, digestErr := guarantor.FirmOfferDigest(*position.AuthorizedFirmOffer)
	if digestErr != nil || wantDigest != envelopeDigest || position.AuthorizedFirmOffer.Body.OfferID != offerID {
		return GuarantorOfferPosition{}, errors.New("Guarantor firm offer predecessor bytes differ")
	}
	if position.Record.Status == guarantor.OfferIssued && position.OfferEnvelopeDigest == envelopeDigest {
		return position, nil
	}
	updated, err := guarantor.TransitionOffer(position.Record, position.Record.StateRevision, guarantor.OfferIssued, envelopeDigest)
	if err != nil {
		return GuarantorOfferPosition{}, err
	}
	position.Record, position.OfferEnvelopeDigest = updated, envelopeDigest
	next.Offers[offerID] = position
	next.Revision++
	if err := journal.commit(next); err != nil {
		return GuarantorOfferPosition{}, err
	}
	return position, nil
}

func (journal *GuarantorJournal) ExpireOffer(offerID string, expectedRevision uint64,
	evidence guarantor.AuthorizedOfferNonAcceptanceEvidenceV1, now time.Time) (GuarantorOfferPosition, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	evidenceDigest, digestErr := guarantor.OfferNonAcceptanceDigestV1(evidence)
	if err := journal.ensureAttached(); err != nil || digestErr != nil {
		return GuarantorOfferPosition{}, errors.New("Guarantor offer expiry is invalid")
	}
	next, err := journal.workingCopy()
	if err != nil {
		return GuarantorOfferPosition{}, err
	}
	position, found := next.Offers[offerID]
	if !found || uint64(now.UTC().Unix()) <= position.AcceptByUnix {
		return GuarantorOfferPosition{}, errors.New("Guarantor offer cutoff has not passed")
	}
	if position.Record.Status == guarantor.OfferExpired && position.NonAcceptanceEvidence != nil {
		priorDigest, priorErr := guarantor.OfferNonAcceptanceDigestV1(*position.NonAcceptanceEvidence)
		if priorErr == nil && priorDigest == evidenceDigest {
			return position, nil
		}
	}
	updated, err := guarantor.ExpireIssuedOffer(position.Record, expectedRevision, evidenceDigest)
	if err != nil {
		return GuarantorOfferPosition{}, err
	}
	position.Record, position.NonAcceptanceEvidence = updated, &evidence
	next.Offers[offerID] = position
	next.Revision++
	if err := journal.commit(next); err != nil {
		return GuarantorOfferPosition{}, err
	}
	return position, nil
}

func (journal *GuarantorJournal) ReleaseExpiredOffer(offerID string, expectedRevision uint64,
	receipt guarantor.AuthorizedPreAcceptanceExposureReleaseReceiptV1) (GuarantorOfferPosition, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	receiptDigest, digestErr := guarantor.PreAcceptanceExposureReleaseReceiptDigestV1(receipt)
	if err := journal.ensureAttached(); err != nil || digestErr != nil {
		return GuarantorOfferPosition{}, errors.New("Guarantor expired offer release is invalid")
	}
	next, err := journal.workingCopy()
	if err != nil {
		return GuarantorOfferPosition{}, err
	}
	position, found := next.Offers[offerID]
	if !found {
		return GuarantorOfferPosition{}, errors.New("Guarantor offer does not exist")
	}
	if position.Record.Status == guarantor.OfferReleased && position.PreAcceptanceReleaseReceipt != nil {
		priorDigest, priorErr := guarantor.PreAcceptanceExposureReleaseReceiptDigestV1(*position.PreAcceptanceReleaseReceipt)
		if priorErr == nil && priorDigest == receiptDigest {
			return position, nil
		}
	}
	updated, err := guarantor.ReleaseExpiredOffer(position.Record, expectedRevision, receiptDigest)
	if err != nil {
		return GuarantorOfferPosition{}, err
	}
	position.Record, position.PreAcceptanceReleaseReceipt = updated, &receipt
	next.Offers[offerID] = position
	next.Revision++
	if err := journal.commit(next); err != nil {
		return GuarantorOfferPosition{}, err
	}
	return position, nil
}

func (journal *GuarantorJournal) StoreOfferReleasePlan(offerID string,
	plan GuarantorPreAcceptanceReleasePlan) (GuarantorOfferPosition, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if err := journal.ensureAttached(); err != nil {
		return GuarantorOfferPosition{}, errors.New("Guarantor pre-acceptance release plan is invalid")
	}
	next, err := journal.workingCopy()
	if err != nil {
		return GuarantorOfferPosition{}, err
	}
	position, found := next.Offers[offerID]
	if !found || position.Record.Status != guarantor.OfferExpired {
		return GuarantorOfferPosition{}, errors.New("Guarantor offer is not awaiting pre-acceptance release")
	}
	// The plan is checked exactly as a load checks it, so nothing is stored
	// that a restart would refuse.
	if err := validatePreAcceptanceReleasePlan(next.OwnerID, next.AgentID, position, plan); err != nil {
		return GuarantorOfferPosition{}, err
	}
	if position.PreAcceptanceReleasePlan != nil {
		if sameJSON(*position.PreAcceptanceReleasePlan, plan) {
			return position, nil
		}
		return GuarantorOfferPosition{}, errors.New("Guarantor pre-acceptance release plan conflicts")
	}
	position.PreAcceptanceReleasePlan = &plan
	next.Offers[offerID] = position
	next.Revision++
	if err := journal.commit(next); err != nil {
		return GuarantorOfferPosition{}, err
	}
	return position, nil
}

func (journal *GuarantorJournal) RefreshOfferReleasePlanAction(offerID string,
	action commerce.AuthorizedAction) (GuarantorOfferPosition, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if err := journal.ensureAttached(); err != nil {
		return GuarantorOfferPosition{}, err
	}
	next, err := journal.workingCopy()
	if err != nil {
		return GuarantorOfferPosition{}, err
	}
	position, found := next.Offers[offerID]
	if !found || position.PreAcceptanceReleasePlan == nil ||
		position.PreAcceptanceReleasePlan.Action.StableActionID != action.StableActionID ||
		position.PreAcceptanceReleasePlan.Action.ExactRequestDigest != action.ExactRequestDigest ||
		action.ActionKind != "portfolio.release" {
		return GuarantorOfferPosition{}, errors.New("Guarantor release-plan reauthorization changes its semantic action")
	}
	if sameJSON(position.PreAcceptanceReleasePlan.Action, action) {
		return position, nil
	}
	position.PreAcceptanceReleasePlan.Action = action
	if err := validatePreAcceptanceReleasePlan(next.OwnerID, next.AgentID, position,
		*position.PreAcceptanceReleasePlan); err != nil {
		return GuarantorOfferPosition{}, err
	}
	next.Offers[offerID] = position
	next.Revision++
	if err := journal.commit(next); err != nil {
		return GuarantorOfferPosition{}, err
	}
	return position, nil
}

// AcceptOffer serializes acceptance against expiry and creates the exact
// coverage genesis. A late caller cannot race a release inside this journal.
func (journal *GuarantorJournal) AcceptOffer(offerID, agreementDigest string, terms guarantor.CoverageTermsV1,
	coverageObligationID, acceptanceEvidenceDigest string, receipt guarantor.AuthorizedCoverageAcceptanceReceiptV1,
	receivedAt time.Time) (GuarantorCoveragePosition, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if err := journal.ensureAttached(); err != nil || guarantor.ValidateCoverageTerms(terms) != nil ||
		!canonicalSHA256(agreementDigest) || !canonicalSHA256(acceptanceEvidenceDigest) || coverageObligationID == "" ||
		receipt.Body.CoverageAgreementBodyDigest != agreementDigest ||
		receipt.Body.AuthorizedAcceptanceRequestEnvelopeDigest != acceptanceEvidenceDigest {
		return GuarantorCoveragePosition{}, errors.New("Guarantor acceptance is invalid")
	}
	next, err := journal.workingCopy()
	if err != nil {
		return GuarantorCoveragePosition{}, err
	}
	offer, found := next.Offers[offerID]
	if !found || offer.Record.Status != guarantor.OfferIssued || uint64(receivedAt.UTC().Unix()) > offer.AcceptByUnix ||
		offer.Record.AgreementDigest != agreementDigest {
		return GuarantorCoveragePosition{}, errors.New("Guarantor offer is not eligible for acceptance")
	}
	if existing, found := next.Coverages[agreementDigest]; found {
		if existing.AcceptanceReceipt != nil && sameJSON(*existing.AcceptanceReceipt, receipt) {
			return existing, nil
		}
		return GuarantorCoveragePosition{}, errors.New("Guarantor accepted coverage identity conflicts")
	}
	accepted, err := guarantor.AcceptIssuedOffer(offer.Record, offer.Record.StateRevision, acceptanceEvidenceDigest)
	if err != nil {
		return GuarantorCoveragePosition{}, err
	}
	coverage, err := guarantor.NewAcceptedCoverageRecord(agreementDigest, coverageObligationID,
		offer.Record.ReservationID, acceptanceEvidenceDigest)
	if err != nil {
		return GuarantorCoveragePosition{}, err
	}
	position := GuarantorCoveragePosition{Terms: terms, AcceptanceReceipt: &receipt, Record: coverage, Claims: map[string]guarantor.ClaimRecord{},
		ClaimEnvelopes: map[string]guarantor.AuthorizedCoverageClaimV1{}, ClaimIngressReceipts: map[string]guarantor.AuthorizedClaimSubmissionIngressReceiptV1{},
		ClaimAdmissionReceipts:  map[string]guarantor.AuthorizedClaimAdmissionReceiptV1{},
		MaterializedPayouts:     map[string]guarantor.MaterializedPayoutObligationSetV1{},
		PayoutExecutionEvidence: map[string]guarantor.AuthorizedGuarantorPayoutExecutionEvidenceV1{}, PaidAtomic: "0",
		DefaultedAtomic: "0"}
	position.ClaimAdmissionSequence = map[string]uint64{}
	position.ClaimRevisionSequence = map[string]uint64{}
	position.ClaimRevisionLogRoot = map[string]string{}
	position.Decisions = map[string]guarantor.AuthorizedClaimDecisionV1{}
	position.DecisionAdmissionReceipts = map[string]guarantor.AuthorizedClaimDecisionAdmissionReceiptV1{}
	position.ClaimStateTransitionReceipts = map[string]guarantor.AuthorizedClaimStateTransitionReceiptV1{}
	position.DecisionApplicationReceipts = map[string]guarantor.AuthorizedClaimDecisionApplicationReceiptV1{}
	position.DecisionApplicationTokens = map[string]guarantor.DecisionApplicationTokenV1{}
	position.ChallengeRoundsUsed = map[string]uint64{}
	position.NonterminalRoundsUsed = map[string]uint64{}
	position.RevisionEpochs = map[string]GuarantorRevisionEpochState{}
	position.ImmutableEvidence = map[string]GuarantorStoredEvidence{}
	position.AggregatePendingDecisionReserveAtomic = "0"
	position.CumulativeAppliedApprovedAtomic = "0"
	position.NextPayoutSequence = 1
	claimLogID, err := guarantor.ClaimAdmissionLogIDV1(agreementDigest, coverageObligationID)
	if err != nil {
		return GuarantorCoveragePosition{}, err
	}
	position.ClaimAdmissionLogRoot, err = guarantor.InitialClaimLogRootV1(guarantor.ClaimAdmissionLogRootDomainV1, claimLogID)
	if err != nil {
		return GuarantorCoveragePosition{}, err
	}
	position.Record.ClaimAdmissionLogRoot = position.ClaimAdmissionLogRoot
	position.PayoutEvidence = map[string]commerce.AgreementPaymentEvidence{}
	position.PayoutRequests = map[string]commerce.AgreementPaymentRequest{}
	position.PaidByObligation = map[string]string{}
	position.DefaultedByObligation = map[string]string{}
	offer.Record = accepted
	next.Offers[offerID], next.Coverages[agreementDigest] = offer, position
	next.Revision++
	if err := journal.commit(next); err != nil {
		return GuarantorCoveragePosition{}, err
	}
	return position, nil
}

func (journal *GuarantorJournal) TransitionCoverage(agreementDigest string, expectedRevision uint64,
	target guarantor.CoverageStatus, evidenceDigest string) (GuarantorCoveragePosition, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if err := journal.ensureAttached(); err != nil {
		return GuarantorCoveragePosition{}, err
	}
	next, copyErr := journal.workingCopy()
	if copyErr != nil {
		return GuarantorCoveragePosition{}, copyErr
	}
	position, found := next.Coverages[agreementDigest]
	if !found {
		return GuarantorCoveragePosition{}, errors.New("Guarantor coverage does not exist")
	}
	updated, err := guarantor.TransitionCoverage(position.Record, expectedRevision, target, evidenceDigest)
	if err != nil {
		return GuarantorCoveragePosition{}, err
	}
	position.Record = updated
	next.Coverages[agreementDigest] = position
	next.Revision++
	if err := journal.commit(next); err != nil {
		return GuarantorCoveragePosition{}, err
	}
	return position, nil
}

func (journal *GuarantorJournal) ActivateCoverage(agreementDigest string, expectedCoverageRevision,
	expectedFilingRevision uint64, evidenceDigest string) (GuarantorCoveragePosition, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if err := journal.ensureAttached(); err != nil || !canonicalSHA256(evidenceDigest) {
		return GuarantorCoveragePosition{}, errors.New("Guarantor activation is invalid")
	}
	next, copyErr := journal.workingCopy()
	if copyErr != nil {
		return GuarantorCoveragePosition{}, copyErr
	}
	position, found := next.Coverages[agreementDigest]
	if !found {
		return GuarantorCoveragePosition{}, errors.New("Guarantor coverage does not exist")
	}
	updated, err := guarantor.ActivateAcceptedCoverage(position.Record, expectedCoverageRevision,
		expectedFilingRevision, evidenceDigest)
	if err != nil {
		return GuarantorCoveragePosition{}, err
	}
	position.Record = updated
	next.Coverages[agreementDigest] = position
	next.Revision++
	if err := journal.commit(next); err != nil {
		return GuarantorCoveragePosition{}, err
	}
	return position, nil
}

// CommitActivationEvidence atomically changes both coverage/filing state and
// stores the complete portable activation envelope. A crash can therefore
// leave the action authority terminal while this projection is still pending,
// but can never leave an ACTIVE coverage without its verification evidence.
func (journal *GuarantorJournal) CommitActivationEvidence(agreementDigest string, expectedCoverageRevision,
	expectedFilingRevision uint64, evidence guarantor.AuthorizedCoverageActivationEvidenceV1,
	prerequisites map[string]GuarantorStoredEvidence) (GuarantorCoveragePosition, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	digest, digestErr := guarantor.CoverageActivationEvidenceDigestV1(evidence)
	next, copyErr := journal.workingCopy()
	if copyErr != nil {
		return GuarantorCoveragePosition{}, copyErr
	}
	position, found := next.Coverages[agreementDigest]
	if err := journal.ensureAttached(); err != nil || digestErr != nil || !found ||
		evidence.Body.CoverageAgreementBodyDigest != agreementDigest {
		return GuarantorCoveragePosition{}, errors.New("Guarantor activation evidence commit is invalid")
	}
	if position.Record.CoverageStatus == guarantor.CoverageActive && position.ActivationEvidence != nil {
		prior, priorErr := guarantor.CoverageActivationEvidenceDigestV1(*position.ActivationEvidence)
		if priorErr == nil && prior == digest {
			return position, nil
		}
		return GuarantorCoveragePosition{}, errors.New("Guarantor activation evidence conflicts")
	}
	updated, err := guarantor.ActivateAcceptedCoverage(position.Record, expectedCoverageRevision,
		expectedFilingRevision, digest)
	if err != nil || updated.CoverageRevision != evidence.Body.ActivatedCoverageRevision ||
		updated.FilingStateRevision != evidence.Body.ActivatedClaimFilingStateRevision {
		return GuarantorCoveragePosition{}, errors.New("Guarantor activation evidence revisions differ from the journal CAS")
	}
	// The activation's prerequisite objects are stored with it, so every later
	// verification of this activation (claim admission, cancellation, closure)
	// resolves them from this coverage's journal.
	for digest, stored := range prerequisites {
		if err := storeImmutableWire(&position, stored.ContentType, digest, stored.Wire); err != nil {
			return GuarantorCoveragePosition{}, err
		}
	}
	position.Record, position.ActivationEvidence = updated, &evidence
	next.Coverages[agreementDigest] = position
	next.Revision++
	if err := journal.commit(next); err != nil {
		return GuarantorCoveragePosition{}, err
	}
	return position, nil
}

func (journal *GuarantorJournal) ConfirmNonActivation(agreementDigest string, expectedCoverageRevision,
	expectedFilingRevision uint64, evidence guarantor.AuthorizedCoverageNonActivationEvidenceV1) (GuarantorCoveragePosition, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	digest, digestErr := guarantor.CoverageNonActivationEvidenceDigestV1(evidence)
	next, copyErr := journal.workingCopy()
	if copyErr != nil {
		return GuarantorCoveragePosition{}, copyErr
	}
	position, found := next.Coverages[agreementDigest]
	if err := journal.ensureAttached(); err != nil || digestErr != nil || !found ||
		evidence.Body.CoverageAgreementBodyDigest != agreementDigest {
		return GuarantorCoveragePosition{}, errors.New("Guarantor non-activation evidence commit is invalid")
	}
	if position.Record.CoverageStatus == guarantor.CoverageNotActivatedConfirmed && position.NonActivationEvidence != nil {
		prior, priorErr := guarantor.CoverageNonActivationEvidenceDigestV1(*position.NonActivationEvidence)
		if priorErr == nil && prior == digest {
			return position, nil
		}
		return GuarantorCoveragePosition{}, errors.New("Guarantor non-activation evidence conflicts")
	}
	updated, err := guarantor.ConfirmCoverageNonActivation(position.Record, expectedCoverageRevision,
		expectedFilingRevision, digest)
	if err != nil {
		return GuarantorCoveragePosition{}, err
	}
	position.Record, position.NonActivationEvidence = updated, &evidence
	next.Coverages[agreementDigest] = position
	next.Revision++
	if err := journal.commit(next); err != nil {
		return GuarantorCoveragePosition{}, err
	}
	return position, nil
}

func (journal *GuarantorJournal) CommitNonActivationRelease(agreementDigest string,
	receipt guarantor.AuthorizedNonActivationExposureReleaseReceiptV1) (GuarantorCoveragePosition, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	digest, digestErr := guarantor.NonActivationExposureReleaseReceiptDigestV1(receipt)
	next, copyErr := journal.workingCopy()
	if copyErr != nil {
		return GuarantorCoveragePosition{}, copyErr
	}
	position, found := next.Coverages[agreementDigest]
	if err := journal.ensureAttached(); err != nil || digestErr != nil || !found ||
		position.Record.CoverageStatus != guarantor.CoverageNotActivatedConfirmed || position.NonActivationEvidence == nil ||
		receipt.Body.CoverageAgreementBodyDigest != agreementDigest {
		return GuarantorCoveragePosition{}, errors.New("Guarantor non-activation release commit is invalid")
	}
	if position.NonActivationReleaseReceipt != nil {
		prior, priorErr := guarantor.NonActivationExposureReleaseReceiptDigestV1(*position.NonActivationReleaseReceipt)
		if priorErr == nil && prior == digest {
			return position, nil
		}
		return GuarantorCoveragePosition{}, errors.New("Guarantor non-activation release conflicts")
	}
	position.NonActivationReleaseReceipt = &receipt
	position.Record.LastEvidenceDigest = digest
	next.Coverages[agreementDigest] = position
	next.Revision++
	if err := journal.commit(next); err != nil {
		return GuarantorCoveragePosition{}, err
	}
	return position, nil
}

func (journal *GuarantorJournal) ApplyCancellation(agreementDigest string, expectedCoverageRevision uint64,
	receipt guarantor.AuthorizedCoverageCancellationReceiptV1) (GuarantorCoveragePosition, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	digest, digestErr := guarantor.CoverageCancellationReceiptDigestV1(receipt)
	next, copyErr := journal.workingCopy()
	if copyErr != nil {
		return GuarantorCoveragePosition{}, copyErr
	}
	position, found := next.Coverages[agreementDigest]
	if err := journal.ensureAttached(); err != nil || digestErr != nil || !found ||
		receipt.Body.CoverageAgreementBodyDigest != agreementDigest {
		return GuarantorCoveragePosition{}, errors.New("Guarantor cancellation receipt commit is invalid")
	}
	if position.Record.CoverageStatus == guarantor.CoverageEnded && position.CancellationReceipt != nil {
		prior, priorErr := guarantor.CoverageCancellationReceiptDigestV1(*position.CancellationReceipt)
		if priorErr == nil && prior == digest {
			return position, nil
		}
		return GuarantorCoveragePosition{}, errors.New("Guarantor cancellation receipt conflicts")
	}
	updated, err := guarantor.ApplyCoverageCancellation(position.Record, expectedCoverageRevision,
		receipt.Body.EffectiveAtUnix, digest)
	if err != nil {
		return GuarantorCoveragePosition{}, err
	}
	position.Record, position.CancellationReceipt = updated, &receipt
	next.Coverages[agreementDigest] = position
	next.Revision++
	if err := journal.commit(next); err != nil {
		return GuarantorCoveragePosition{}, err
	}
	return position, nil
}

func guarantorClaimRevisionKey(claimID string, revision uint64) string {
	return claimID + "#" + strconv.FormatUint(revision, 10)
}

func (journal *GuarantorJournal) PreviewClaimAdmission(agreementDigest string,
	claim guarantor.AuthorizedCoverageClaimV1, claimEnvelopeDigest string) (GuarantorClaimAdmissionPreview, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if err := journal.readable(); err != nil {
		return GuarantorClaimAdmissionPreview{}, err
	}
	position, found := journal.doc.Coverages[agreementDigest]
	if !found || claim.Body.CoverageAgreementBodyDigest != agreementDigest || !canonicalSHA256(claimEnvelopeDigest) {
		return GuarantorClaimAdmissionPreview{}, errors.New("Guarantor claim admission preview is invalid")
	}
	actualDigest, err := guarantor.ClaimEnvelopeDigest(claim)
	if err != nil || actualDigest != claimEnvelopeDigest {
		return GuarantorClaimAdmissionPreview{}, errors.New("Guarantor claim envelope digest differs")
	}
	claimLogID, err := guarantor.ClaimAdmissionLogIDV1(agreementDigest, position.Record.CoverageObligationID)
	if err != nil {
		return GuarantorClaimAdmissionPreview{}, err
	}
	revisionLogID, err := guarantor.ClaimRevisionLogIDV1(agreementDigest, position.Record.CoverageObligationID, claim.Body.ClaimID)
	if err != nil {
		return GuarantorClaimAdmissionPreview{}, err
	}
	preview := GuarantorClaimAdmissionPreview{PriorCoverageRevision: position.Record.CoverageRevision,
		AdmittedCoverageRevision: position.Record.CoverageRevision + 1, AdmittedClaimRevision: claim.Body.ClaimRevision,
		ClaimAdmissionLogID: claimLogID, ClaimRevisionLogID: revisionLogID,
		PriorClaimAdmissionLogRoot: position.ClaimAdmissionLogRoot}
	current, exists := position.Claims[claim.Body.ClaimID]
	if !exists {
		if claim.Body.ClaimRevision != 1 || claim.Body.PredecessorClaimDigest != "" ||
			position.Record.CoverageStatus != guarantor.CoverageActive || position.Record.ClaimFilingStatus != guarantor.FilingOpen ||
			claim.Body.CreatedAtUnix > position.Terms.ClaimFilingEndsAtUnix || uint64(len(position.Claims)) >= position.Terms.MaximumClaims {
			return GuarantorClaimAdmissionPreview{}, errors.New("initial Guarantor claim cannot be admitted")
		}
		preview.Initial = true
		preview.ClaimAdmissionSequence = position.Record.ClaimAdmissionHighWater + 1
		preview.ClaimRevisionAdmissionSequence = 1
		preview.PriorClaimRevisionLogRoot, err = guarantor.InitialClaimLogRootV1(guarantor.ClaimRevisionLogRootDomainV1, revisionLogID)
		if err != nil {
			return GuarantorClaimAdmissionPreview{}, err
		}
		preview.AdmittedClaimAdmissionLogRoot, err = guarantor.AdvanceClaimLogRootV1(guarantor.ClaimAdmissionLogRootDomainV1,
			claimLogID, preview.PriorClaimAdmissionLogRoot, preview.ClaimAdmissionSequence,
			guarantor.InitialClaimAdmissionLeafV1{ClaimID: claim.Body.ClaimID,
				AdmissionSequence: preview.ClaimAdmissionSequence, AuthorizedClaimEnvelopeDigest: claimEnvelopeDigest})
	} else {
		currentEnvelope, envelopeFound := position.ClaimEnvelopes[claim.Body.ClaimID]
		currentBodyDigest, bodyErr := guarantor.ClaimBodyDigest(currentEnvelope.Body)
		predecessorKey := guarantorClaimRevisionKey(claim.Body.ClaimID, current.ClaimRevision)
		predecessorReceipt, receiptFound := position.ClaimAdmissionReceipts[predecessorKey]
		if !envelopeFound || bodyErr != nil || !receiptFound || claim.Body.ClaimRevision != current.ClaimRevision+1 ||
			claim.Body.PredecessorClaimDigest != currentBodyDigest || claim.Body.ClaimRevision > position.Terms.ClaimClosureCapacity.MaximumClaimRevisionsPerClaim ||
			(position.Record.CoverageStatus != guarantor.CoverageActive && position.Record.CoverageStatus != guarantor.CoverageEnded) ||
			(position.Record.ClaimFilingStatus != guarantor.FilingOpen && position.Record.ClaimFilingStatus != guarantor.FilingFrozen) ||
			claim.Body.CreatedAtUnix > position.Terms.TerminalResolutionDeadlineUnix ||
			claim.Body.IncidentKeyDigest != currentEnvelope.Body.IncidentKeyDigest || claim.Body.OccurredAtUnix != currentEnvelope.Body.OccurredAtUnix ||
			claim.Body.BeneficiaryAgentID != currentEnvelope.Body.BeneficiaryAgentID ||
			!sameJSON(claim.Body.TriggeredObligationSet, currentEnvelope.Body.TriggeredObligationSet) {
			return GuarantorClaimAdmissionPreview{}, errors.New("Guarantor claim revision does not extend the admitted head")
		}
		preview.PriorClaimRevision = current.ClaimRevision
		preview.ClaimAdmissionSequence = position.ClaimAdmissionSequence[claim.Body.ClaimID]
		preview.ClaimRevisionAdmissionSequence = position.ClaimRevisionSequence[claim.Body.ClaimID] + 1
		preview.PriorClaimRevisionLogRoot = position.ClaimRevisionLogRoot[claim.Body.ClaimID]
		preview.AdmittedClaimAdmissionLogRoot = preview.PriorClaimAdmissionLogRoot
		preview.InitialAdmissionReceiptDigest, err = guarantor.ClaimAdmissionReceiptDigestV1(
			position.ClaimAdmissionReceipts[guarantorClaimRevisionKey(claim.Body.ClaimID, 1)])
		if err == nil {
			preview.PredecessorAdmissionReceiptDigest, err = guarantor.ClaimAdmissionReceiptDigestV1(predecessorReceipt)
		}
	}
	if err != nil || !canonicalSHA256(preview.PriorClaimRevisionLogRoot) {
		return GuarantorClaimAdmissionPreview{}, errors.New("Guarantor claim log predecessor is invalid")
	}
	preview.AdmittedClaimRevisionLogRoot, err = guarantor.AdvanceClaimLogRootV1(guarantor.ClaimRevisionLogRootDomainV1,
		revisionLogID, preview.PriorClaimRevisionLogRoot, preview.ClaimRevisionAdmissionSequence,
		guarantor.ClaimRevisionAdmissionLeafV1{ClaimID: claim.Body.ClaimID,
			ClaimRevisionAdmissionSequence:            preview.ClaimRevisionAdmissionSequence,
			AuthorizedClaimEnvelopeDigest:             claimEnvelopeDigest,
			PredecessorRevisionAdmissionReceiptDigest: preview.PredecessorAdmissionReceiptDigest})
	if err != nil {
		return GuarantorClaimAdmissionPreview{}, err
	}
	return preview, nil
}

func (journal *GuarantorJournal) CommitClaimAdmission(agreementDigest string,
	ingress guarantor.AuthorizedClaimSubmissionIngressReceiptV1,
	receipt guarantor.AuthorizedClaimAdmissionReceiptV1, preview GuarantorClaimAdmissionPreview) (guarantor.ClaimRecord, error) {
	claim := ingress.AuthorizedClaim
	claimDigest, err := guarantor.ClaimEnvelopeDigest(claim)
	ingressDigest, ingressErr := guarantor.ClaimIngressReceiptDigestV1(ingress)
	receiptDigest, receiptErr := guarantor.ClaimAdmissionReceiptDigestV1(receipt)
	if err != nil || ingressErr != nil || receiptErr != nil || !sameJSON(receipt.AuthorizedClaimIngressReceipt, ingress) ||
		receipt.Body.AuthorizedClaimEnvelopeDigest != claimDigest || receipt.Body.ClaimSubmissionIngressReceiptDigest != ingressDigest ||
		receipt.Body.PriorCoverageRevision != preview.PriorCoverageRevision ||
		receipt.Body.AdmittedCoverageRevision != preview.AdmittedCoverageRevision ||
		receipt.Body.PriorClaimRevision != preview.PriorClaimRevision || receipt.Body.AdmittedClaimRevision != preview.AdmittedClaimRevision ||
		receipt.Body.ClaimAdmissionSequence != preview.ClaimAdmissionSequence ||
		receipt.Body.ClaimRevisionAdmissionSequence != preview.ClaimRevisionAdmissionSequence ||
		receipt.Body.PriorClaimAdmissionLogRoot != preview.PriorClaimAdmissionLogRoot ||
		receipt.Body.AdmittedClaimAdmissionLogRoot != preview.AdmittedClaimAdmissionLogRoot ||
		receipt.Body.PriorClaimRevisionLogRoot != preview.PriorClaimRevisionLogRoot ||
		receipt.Body.AdmittedClaimRevisionLogRoot != preview.AdmittedClaimRevisionLogRoot {
		return guarantor.ClaimRecord{}, errors.New("Guarantor claim admission receipt differs from the preview")
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if err := journal.ensureAttached(); err != nil {
		return guarantor.ClaimRecord{}, err
	}
	next, copyErr := journal.workingCopy()
	if copyErr != nil {
		return guarantor.ClaimRecord{}, copyErr
	}
	position, found := next.Coverages[agreementDigest]
	if !found || position.Record.CoverageRevision != preview.PriorCoverageRevision ||
		position.ClaimAdmissionLogRoot != preview.PriorClaimAdmissionLogRoot {
		return guarantor.ClaimRecord{}, errors.New("Guarantor claim admission lost its coverage CAS")
	}
	key := guarantorClaimRevisionKey(claim.Body.ClaimID, claim.Body.ClaimRevision)
	if existing, exists := position.ClaimAdmissionReceipts[key]; exists {
		existingDigest, digestErr := guarantor.ClaimAdmissionReceiptDigestV1(existing)
		if digestErr == nil && existingDigest == receiptDigest {
			return position.Claims[claim.Body.ClaimID], nil
		}
		return guarantor.ClaimRecord{}, errors.New("Guarantor claim admission identity conflicts")
	}
	record := position.Claims[claim.Body.ClaimID]
	if position.RevisionEpochs == nil {
		position.RevisionEpochs = map[string]GuarantorRevisionEpochState{}
	}
	if preview.Initial {
		position.RevisionEpochs[claim.Body.ClaimID] = GuarantorRevisionEpochState{Epoch: 1, State: revisionEpochOpen, StateRevision: 1}
	} else if revisionEpochOf(position, claim.Body.ClaimID).State != revisionEpochOpen {
		return guarantor.ClaimRecord{}, errors.New("Guarantor claim revision refused: its revision epoch is frozen")
	}
	if err := storeImmutableEvidence(&position, guarantorClaimAdmissionMediaType, receiptDigest, receipt); err != nil {
		return guarantor.ClaimRecord{}, err
	}
	if preview.Initial {
		claimBodyDigest, bodyErr := guarantor.ClaimBodyDigest(claim.Body)
		if bodyErr != nil {
			return guarantor.ClaimRecord{}, bodyErr
		}
		record = guarantor.ClaimRecord{ClaimID: claim.Body.ClaimID, ClaimRevision: 1,
			ClaimStatus: guarantor.ClaimAdmitted, PayoutStatus: guarantor.PayoutNotMaterialized,
			ClaimStateRevision: 1, CurrentClaimBodyDigest: claimBodyDigest, LastEvidenceDigest: receiptDigest}
		position.ClaimAdmissionSequence[claim.Body.ClaimID] = preview.ClaimAdmissionSequence
	} else {
		record, err = guarantor.ReviseAdmittedClaim(record, claim.Body.ClaimRevision,
			claim.Body.PredecessorClaimDigest, receiptDigest)
		if err != nil {
			return guarantor.ClaimRecord{}, err
		}
		record.CurrentClaimBodyDigest, err = guarantor.ClaimBodyDigest(claim.Body)
		if err != nil {
			return guarantor.ClaimRecord{}, err
		}
		delete(position.Decisions, claim.Body.ClaimID)
		delete(position.MaterializedPayouts, claim.Body.ClaimID)
	}
	position.Record, err = guarantor.AdmitClaimRevision(position.Record, preview.PriorCoverageRevision,
		preview.ClaimAdmissionSequence, preview.AdmittedClaimAdmissionLogRoot, receiptDigest, preview.Initial)
	if err != nil {
		return guarantor.ClaimRecord{}, err
	}
	position.Claims[claim.Body.ClaimID] = record
	position.ClaimEnvelopes[claim.Body.ClaimID] = claim
	position.ClaimIngressReceipts[key] = ingress
	position.ClaimAdmissionReceipts[key] = receipt
	position.ClaimAdmissionLogRoot = preview.AdmittedClaimAdmissionLogRoot
	position.ClaimRevisionSequence[claim.Body.ClaimID] = preview.ClaimRevisionAdmissionSequence
	position.ClaimRevisionLogRoot[claim.Body.ClaimID] = preview.AdmittedClaimRevisionLogRoot
	next.Coverages[agreementDigest] = position
	next.ClaimToCoverage[claim.Body.ClaimID] = agreementDigest
	next.Revision++
	if err := journal.commit(next); err != nil {
		return guarantor.ClaimRecord{}, err
	}
	return record, nil
}

func (journal *GuarantorJournal) RecordTerminalPayout(agreementDigest, claimID, obligationInstanceID,
	paidAtomic string, request commerce.AgreementPaymentRequest,
	evidence commerce.AgreementPaymentEvidence,
	execution guarantor.AuthorizedGuarantorPayoutExecutionEvidenceV1) (guarantor.ClaimRecord, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	evidenceDigest, digestErr := codec.Digest("tos.agreement-payment-evidence.v1", evidence)
	requestDigest, requestErr := commerce.AgreementPaymentRequestDigest(request)
	executionDigest, executionErr := guarantor.GuarantorPayoutExecutionEvidenceDigestV1(execution)
	if err := journal.ensureAttached(); err != nil || requestErr != nil || requestDigest != evidence.PaymentRequestDigest ||
		request.ObligationInstanceID != obligationInstanceID || !canonicalSHA256(obligationInstanceID) || !canonicalSHA256(evidenceDigest) {
		return guarantor.ClaimRecord{}, errors.New("Guarantor payout evidence is invalid")
	}
	next, copyErr := journal.workingCopy()
	if copyErr != nil {
		return guarantor.ClaimRecord{}, copyErr
	}
	position, found := next.Coverages[agreementDigest]
	record, claimFound := position.Claims[claimID]
	if digestErr != nil || executionErr != nil || !canonicalSHA256(executionDigest) || execution.ObligationInstanceID != obligationInstanceID ||
		!sameJSON(execution.AgreementPaymentEvidence, evidence) {
		return guarantor.ClaimRecord{}, errors.New("Guarantor payout evidence cannot be encoded")
	}
	if prior, exists := position.PayoutEvidence[obligationInstanceID]; exists {
		priorDigest, _ := codec.Digest("tos.agreement-payment-evidence.v1", prior)
		if priorDigest == evidenceDigest && sameJSON(position.PayoutRequests[obligationInstanceID], request) &&
			sameJSON(position.PayoutExecutionEvidence[obligationInstanceID], execution) &&
			position.PaidByObligation[obligationInstanceID] == paidAtomic {
			return record, nil
		}
		return guarantor.ClaimRecord{}, errors.New("Guarantor payout identity conflicts with prior terminal evidence")
	}
	materialized, materializedFound := position.MaterializedPayouts[claimID]
	var exactAmount string
	for _, obligation := range materialized.Obligations {
		if obligation.ObligationInstanceID == obligationInstanceID {
			exactAmount = obligation.Amount.AmountAtomic
		}
	}
	paid, amountErr := nonnegativeBig(paidAtomic)
	priorPaid, priorErr := nonnegativeBig(position.PaidAtomic)
	maximum, maximumErr := positiveBig(position.Terms.MaximumAggregatePayout.AmountAtomic)
	if !found || !claimFound || !materializedFound || exactAmount == "" || exactAmount != paidAtomic || amountErr != nil ||
		priorErr != nil || maximumErr != nil ||
		new(big.Int).Add(priorPaid, paid).Cmp(maximum) > 0 {
		return guarantor.ClaimRecord{}, errors.New("Guarantor payout exceeds the accepted aggregate cap")
	}
	target := guarantor.PayoutPartiallyPaid
	paidForClaim := 0
	for _, obligation := range materialized.Obligations {
		if _, paid := position.PayoutEvidence[obligation.ObligationInstanceID]; paid {
			paidForClaim++
		}
	}
	if paidForClaim+1 == len(materialized.Obligations) {
		target = guarantor.PayoutPaid
	}
	updated, err := guarantor.TransitionPayout(record, target, evidenceDigest)
	if err != nil {
		return guarantor.ClaimRecord{}, err
	}
	position.PaidAtomic = new(big.Int).Add(priorPaid, paid).String()
	position.PayoutEvidence[obligationInstanceID] = evidence
	position.PayoutRequests[obligationInstanceID] = request
	position.PayoutExecutionEvidence[obligationInstanceID] = execution
	position.PaidByObligation[obligationInstanceID] = paidAtomic
	position.Claims[claimID] = updated
	next.Coverages[agreementDigest] = position
	next.Revision++
	if err := journal.commit(next); err != nil {
		return guarantor.ClaimRecord{}, err
	}
	return updated, nil
}

func (journal *GuarantorJournal) RecordTerminalPayoutDefault(agreementDigest, claimID, obligationInstanceID string,
	request commerce.AgreementPaymentRequest, evidence commerce.AgreementPaymentEvidence,
	execution guarantor.AuthorizedGuarantorPayoutExecutionEvidenceV1) (guarantor.ClaimRecord, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	evidenceDigest, digestErr := codec.Digest("tos.agreement-payment-evidence.v1", evidence)
	requestDigest, requestErr := commerce.AgreementPaymentRequestDigest(request)
	executionDigest, executionErr := guarantor.GuarantorPayoutExecutionEvidenceDigestV1(execution)
	if err := journal.ensureAttached(); err != nil || requestErr != nil || requestDigest != evidence.PaymentRequestDigest ||
		request.ObligationInstanceID != obligationInstanceID || evidence.ResolvedState != "defaulted" ||
		!canonicalSHA256(obligationInstanceID) || !canonicalSHA256(evidenceDigest) {
		return guarantor.ClaimRecord{}, errors.New("Guarantor payout default evidence is invalid")
	}
	next, copyErr := journal.workingCopy()
	if copyErr != nil {
		return guarantor.ClaimRecord{}, copyErr
	}
	position, found := next.Coverages[agreementDigest]
	record, claimFound := position.Claims[claimID]
	if digestErr != nil || executionErr != nil || !canonicalSHA256(executionDigest) ||
		execution.ObligationInstanceID != obligationInstanceID || !sameJSON(execution.AgreementPaymentEvidence, evidence) {
		return guarantor.ClaimRecord{}, errors.New("Guarantor payout default evidence cannot be encoded")
	}
	if prior, exists := position.PayoutEvidence[obligationInstanceID]; exists {
		priorDigest, _ := codec.Digest("tos.agreement-payment-evidence.v1", prior)
		if priorDigest == evidenceDigest && sameJSON(position.PayoutRequests[obligationInstanceID], request) &&
			sameJSON(position.PayoutExecutionEvidence[obligationInstanceID], execution) &&
			position.DefaultedByObligation[obligationInstanceID] == request.Amount.AmountAtomic {
			return record, nil
		}
		return guarantor.ClaimRecord{}, errors.New("Guarantor payout default conflicts with prior terminal evidence")
	}
	materialized, materializedFound := position.MaterializedPayouts[claimID]
	matched := false
	for _, obligation := range materialized.Obligations {
		if obligation.ObligationInstanceID == obligationInstanceID && obligation.Amount == request.Amount {
			matched = true
		}
	}
	amount, amountErr := nonnegativeBig(request.Amount.AmountAtomic)
	priorDefaulted, priorErr := nonnegativeBig(position.DefaultedAtomic)
	maximum, maximumErr := positiveBig(position.Terms.MaximumAggregatePayout.AmountAtomic)
	paid, paidErr := nonnegativeBig(position.PaidAtomic)
	if !found || !claimFound || !materializedFound || !matched || amountErr != nil || priorErr != nil ||
		maximumErr != nil || paidErr != nil || new(big.Int).Add(new(big.Int).Add(paid, priorDefaulted), amount).Cmp(maximum) > 0 {
		return guarantor.ClaimRecord{}, errors.New("Guarantor payout default exceeds the accepted aggregate cap")
	}
	terminalCount := 0
	for _, obligation := range materialized.Obligations {
		if _, terminal := position.PayoutEvidence[obligation.ObligationInstanceID]; terminal {
			terminalCount++
		}
	}
	target := guarantor.PayoutPartiallyPaid
	if terminalCount+1 == len(materialized.Obligations) {
		target = guarantor.PayoutDefaulted
	}
	updated, err := guarantor.TransitionPayout(record, target, evidenceDigest)
	if err != nil {
		return guarantor.ClaimRecord{}, err
	}
	position.DefaultedAtomic = new(big.Int).Add(priorDefaulted, amount).String()
	position.PayoutEvidence[obligationInstanceID] = evidence
	position.PayoutRequests[obligationInstanceID] = request
	position.PayoutExecutionEvidence[obligationInstanceID] = execution
	position.DefaultedByObligation[obligationInstanceID] = request.Amount.AmountAtomic
	position.Claims[claimID] = updated
	next.Coverages[agreementDigest] = position
	next.Revision++
	if err := journal.commit(next); err != nil {
		return guarantor.ClaimRecord{}, err
	}
	return updated, nil
}

func (journal *GuarantorJournal) FreezeClaimFiling(agreementDigest, evidenceDigest string,
	filingCutoffUnix uint64, closedAt time.Time) (GuarantorCoveragePosition, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if err := journal.ensureAttached(); err != nil || !canonicalSHA256(evidenceDigest) {
		return GuarantorCoveragePosition{}, errors.New("Guarantor claim filing close is invalid")
	}
	next, copyErr := journal.workingCopy()
	if copyErr != nil {
		return GuarantorCoveragePosition{}, copyErr
	}
	position, found := next.Coverages[agreementDigest]
	if !found || (position.Record.CoverageStatus != guarantor.CoverageActive &&
		position.Record.CoverageStatus != guarantor.CoverageEnded) || filingCutoffUnix == 0 ||
		uint64(closedAt.UTC().Unix()) < filingCutoffUnix {
		return GuarantorCoveragePosition{}, errors.New("Guarantor claim filing cannot close yet")
	}
	updated, err := guarantor.FreezeClaimFiling(position.Record, position.Record.CoverageRevision,
		position.Record.FilingStateRevision, uint64(len(position.ClaimAdmissionSequence)),
		position.ClaimAdmissionLogRoot, evidenceDigest, false)
	if err != nil {
		return GuarantorCoveragePosition{}, err
	}
	position.Record = updated
	next.Coverages[agreementDigest] = position
	next.Revision++
	if err := journal.commit(next); err != nil {
		return GuarantorCoveragePosition{}, err
	}
	return position, nil
}

func (journal *GuarantorJournal) CommitClaimFilingCloseReceipt(agreementDigest string,
	receipt guarantor.AuthorizedClaimFilingCloseReceiptV1) (GuarantorCoveragePosition, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	digest, digestErr := guarantor.ClaimFilingCloseReceiptDigestV1(receipt)
	next, copyErr := journal.workingCopy()
	if copyErr != nil {
		return GuarantorCoveragePosition{}, copyErr
	}
	position, found := next.Coverages[agreementDigest]
	if err := journal.ensureAttached(); err != nil || digestErr != nil || !found ||
		receipt.Body.CoverageAgreementBodyDigest != agreementDigest {
		return GuarantorCoveragePosition{}, errors.New("Guarantor filing-close receipt commit is invalid")
	}
	if position.FilingCloseReceipt != nil {
		prior, priorErr := guarantor.ClaimFilingCloseReceiptDigestV1(*position.FilingCloseReceipt)
		if priorErr == nil && prior == digest {
			return position, nil
		}
		return GuarantorCoveragePosition{}, errors.New("Guarantor filing-close receipt conflicts")
	}
	if position.Record.ClaimFilingStatus != guarantor.FilingFrozen {
		updated, updateErr := guarantor.FreezeClaimFiling(position.Record, receipt.Body.PriorCoverageRevision,
			receipt.Body.PriorClaimFilingStateRevision, receipt.Body.FrozenClaimAdmissionHighWater,
			receipt.Body.FrozenClaimAdmissionLogRoot, receipt.Body.AuthorizedActionDigest, false)
		if updateErr != nil || updated.CoverageRevision != receipt.Body.ClosedCoverageRevision ||
			updated.FilingStateRevision != receipt.Body.ResultingClaimFilingStateRevision {
			return GuarantorCoveragePosition{}, errors.New("Guarantor filing-close receipt differs from the journal CAS")
		}
		position.Record = updated
	}
	if err := storeImmutableEvidence(&position, guarantorClaimFilingCloseMediaType, digest, receipt); err != nil {
		return GuarantorCoveragePosition{}, err
	}
	position.FilingCloseReceipt = &receipt
	next.Coverages[agreementDigest] = position
	next.Revision++
	if err := journal.commit(next); err != nil {
		return GuarantorCoveragePosition{}, err
	}
	return position, nil
}

func (journal *GuarantorJournal) CommitTerminalClaimSet(agreementDigest string,
	evidence guarantor.AuthorizedTerminalClaimSetEvidenceV1) (GuarantorCoveragePosition, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	digest, digestErr := guarantor.TerminalClaimSetDigestV1(evidence)
	next, copyErr := journal.workingCopy()
	if copyErr != nil {
		return GuarantorCoveragePosition{}, copyErr
	}
	position, found := next.Coverages[agreementDigest]
	if err := journal.ensureAttached(); err != nil || digestErr != nil || !found ||
		evidence.Body.CoverageAgreementBodyDigest != agreementDigest {
		return GuarantorCoveragePosition{}, errors.New("Guarantor terminal claim-set commit is invalid")
	}
	if position.TerminalClaimSet != nil {
		prior, priorErr := guarantor.TerminalClaimSetDigestV1(*position.TerminalClaimSet)
		if priorErr == nil && prior == digest {
			return position, nil
		}
		return GuarantorCoveragePosition{}, errors.New("Guarantor terminal claim-set conflicts")
	}
	if position.Record.CoverageStatus != guarantor.CoverageReleasePending {
		updated, updateErr := guarantor.TransitionCoverage(position.Record, evidence.Body.PriorCoverageRevision,
			guarantor.CoverageReleasePending, evidence.Body.AuthorizedActionDigest)
		if updateErr != nil || updated.CoverageRevision != evidence.Body.ReleasePendingCoverageRevision {
			return GuarantorCoveragePosition{}, errors.New("Guarantor terminal claim-set differs from the journal CAS")
		}
		position.Record = updated
	}
	position.TerminalClaimSet = &evidence
	next.Coverages[agreementDigest] = position
	next.Revision++
	if err := journal.commit(next); err != nil {
		return GuarantorCoveragePosition{}, err
	}
	return position, nil
}

func (journal *GuarantorJournal) CommitExposureReleaseReceipt(agreementDigest string,
	receipt guarantor.AuthorizedExposureReleaseReceiptV1) (GuarantorCoveragePosition, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	digest, digestErr := guarantor.ExposureReleaseReceiptDigestV1(receipt)
	next, copyErr := journal.workingCopy()
	if copyErr != nil {
		return GuarantorCoveragePosition{}, copyErr
	}
	position, found := next.Coverages[agreementDigest]
	if err := journal.ensureAttached(); err != nil || digestErr != nil || !found ||
		position.Record.CoverageStatus != guarantor.CoverageReleasePending ||
		receipt.Body.CoverageAgreementBodyDigest != agreementDigest || position.TerminalClaimSet == nil {
		return GuarantorCoveragePosition{}, errors.New("Guarantor exposure-release receipt commit is invalid")
	}
	if position.ExposureReleaseReceipt != nil {
		prior, priorErr := guarantor.ExposureReleaseReceiptDigestV1(*position.ExposureReleaseReceipt)
		if priorErr == nil && prior == digest {
			return position, nil
		}
		return GuarantorCoveragePosition{}, errors.New("Guarantor exposure-release receipt conflicts")
	}
	position.ExposureReleaseReceipt = &receipt
	next.Coverages[agreementDigest] = position
	next.Revision++
	if err := journal.commit(next); err != nil {
		return GuarantorCoveragePosition{}, err
	}
	return position, nil
}

func (journal *GuarantorJournal) PrepareExposureReleasePlan(agreementDigest string,
	plan GuarantorExposureReleasePlan) (GuarantorExposureReleasePlan, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	_, actionErr := commerce.AuthorizedActionDigest(plan.Action)
	next, copyErr := journal.workingCopy()
	if copyErr != nil {
		return GuarantorExposureReleasePlan{}, copyErr
	}
	position, found := next.Coverages[agreementDigest]
	if err := journal.ensureAttached(); err != nil || !found || position.Record.CoverageStatus != guarantor.CoverageReleasePending ||
		position.TerminalClaimSet == nil || actionErr != nil ||
		len(plan.CanonicalRequest) == 0 || plan.CreatedAtUnix == 0 {
		return GuarantorExposureReleasePlan{}, errors.New("Guarantor exposure-release plan is invalid")
	}
	// The plan is checked exactly as a load checks it, so nothing is stored
	// that a restart would refuse.
	if err := validateExposureReleasePlan(next.OwnerID, next.AgentID, agreementDigest, position, plan); err != nil {
		return GuarantorExposureReleasePlan{}, err
	}
	if position.ExposureReleasePlan != nil {
		if sameJSON(*position.ExposureReleasePlan, plan) {
			return *position.ExposureReleasePlan, nil
		}
		return GuarantorExposureReleasePlan{}, errors.New("Guarantor exposure-release plan conflicts")
	}
	position.ExposureReleasePlan = &plan
	next.Coverages[agreementDigest] = position
	next.Revision++
	if err := journal.commit(next); err != nil {
		return GuarantorExposureReleasePlan{}, err
	}
	return plan, nil
}

// ReauthorizeExposureReleasePlan replaces only the expiring authorization
// envelope of an already frozen semantic action. The request, semantic key,
// disposition, and stable identity remain byte-for-byte identical. This lets a
// newer fenced writer finish an unknown closure action without creating a
// second economic effect after takeover.
func (journal *GuarantorJournal) ReauthorizeExposureReleasePlan(agreementDigest string,
	plan GuarantorExposureReleasePlan) (GuarantorExposureReleasePlan, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	next, copyErr := journal.workingCopy()
	if copyErr != nil {
		return GuarantorExposureReleasePlan{}, copyErr
	}
	position, found := next.Coverages[agreementDigest]
	if err := journal.ensureAttached(); err != nil || !found || position.ExposureReleasePlan == nil ||
		position.ExposureReleaseReceipt != nil {
		return GuarantorExposureReleasePlan{}, errors.New("Guarantor exposure-release plan cannot be reauthorized")
	}
	prior := *position.ExposureReleasePlan
	// The semantic fields are frozen with the stable action identity: the
	// validation below requires them to derive it.
	if !bytes.Equal(prior.CanonicalRequest, plan.CanonicalRequest) ||
		!sameJSON(prior.RequestBody, plan.RequestBody) || !sameJSON(prior.Disposition, plan.Disposition) ||
		prior.Action.StableActionID != plan.Action.StableActionID ||
		prior.Action.ExactRequestDigest != plan.Action.ExactRequestDigest ||
		plan.Action.WriterGeneration <= prior.Action.WriterGeneration ||
		plan.WriterFence.Body.WriterGeneration != plan.Action.WriterGeneration ||
		plan.CreatedAtUnix < prior.CreatedAtUnix {
		return GuarantorExposureReleasePlan{}, errors.New("Guarantor exposure-release reauthorization changes frozen semantics")
	}
	if err := validateExposureReleasePlan(next.OwnerID, next.AgentID, agreementDigest, position, plan); err != nil {
		return GuarantorExposureReleasePlan{}, err
	}
	position.ExposureReleasePlan = &plan
	next.Coverages[agreementDigest] = position
	next.Revision++
	if err := journal.commit(next); err != nil {
		return GuarantorExposureReleasePlan{}, err
	}
	return plan, nil
}

func (journal *GuarantorJournal) PrepareCoverageResolutionPlan(agreementDigest string,
	plan GuarantorCoverageResolutionPlan) (GuarantorCoverageResolutionPlan, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	_, actionErr := commerce.AuthorizedActionDigest(plan.Action)
	next, copyErr := journal.workingCopy()
	if copyErr != nil {
		return GuarantorCoverageResolutionPlan{}, copyErr
	}
	position, found := next.Coverages[agreementDigest]
	if err := journal.ensureAttached(); err != nil || !found || position.Record.CoverageStatus != guarantor.CoverageReleasePending ||
		position.ExposureReleaseReceipt == nil || actionErr != nil ||
		len(plan.CanonicalRequest) == 0 || plan.CreatedAtUnix == 0 {
		return GuarantorCoverageResolutionPlan{}, errors.New("Guarantor coverage-resolution plan is invalid")
	}
	// The plan is checked exactly as a load checks it, so nothing is stored
	// that a restart would refuse.
	if err := validateCoverageResolutionPlan(next.OwnerID, next.AgentID, agreementDigest, position, plan); err != nil {
		return GuarantorCoverageResolutionPlan{}, err
	}
	if position.CoverageResolutionPlan != nil {
		if sameJSON(*position.CoverageResolutionPlan, plan) {
			return *position.CoverageResolutionPlan, nil
		}
		return GuarantorCoverageResolutionPlan{}, errors.New("Guarantor coverage-resolution plan conflicts")
	}
	position.CoverageResolutionPlan = &plan
	next.Coverages[agreementDigest] = position
	next.Revision++
	if err := journal.commit(next); err != nil {
		return GuarantorCoverageResolutionPlan{}, err
	}
	return plan, nil
}

// ReauthorizeCoverageResolutionPlan has the same invariant as its exposure
// counterpart: only the authority envelope and monotonically newer fence may
// change. The conditional-obligation transition itself is immutable.
func (journal *GuarantorJournal) ReauthorizeCoverageResolutionPlan(agreementDigest string,
	plan GuarantorCoverageResolutionPlan) (GuarantorCoverageResolutionPlan, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	next, copyErr := journal.workingCopy()
	if copyErr != nil {
		return GuarantorCoverageResolutionPlan{}, copyErr
	}
	position, found := next.Coverages[agreementDigest]
	if err := journal.ensureAttached(); err != nil || !found || position.CoverageResolutionPlan == nil ||
		position.CoverageResolution != nil {
		return GuarantorCoverageResolutionPlan{}, errors.New("Guarantor coverage-resolution plan cannot be reauthorized")
	}
	prior := *position.CoverageResolutionPlan
	// The semantic fields are frozen with the stable action identity: the
	// validation below requires them to derive it.
	if !bytes.Equal(prior.CanonicalRequest, plan.CanonicalRequest) ||
		!sameJSON(prior.RequestBody, plan.RequestBody) || prior.TargetStatus != plan.TargetStatus ||
		prior.TargetState != plan.TargetState || prior.Action.StableActionID != plan.Action.StableActionID ||
		prior.Action.ExactRequestDigest != plan.Action.ExactRequestDigest ||
		plan.Action.WriterGeneration <= prior.Action.WriterGeneration ||
		plan.WriterFence.Body.WriterGeneration != plan.Action.WriterGeneration ||
		plan.CreatedAtUnix < prior.CreatedAtUnix {
		return GuarantorCoverageResolutionPlan{}, errors.New("Guarantor coverage-resolution reauthorization changes frozen semantics")
	}
	if err := validateCoverageResolutionPlan(next.OwnerID, next.AgentID, agreementDigest, position, plan); err != nil {
		return GuarantorCoverageResolutionPlan{}, err
	}
	position.CoverageResolutionPlan = &plan
	next.Coverages[agreementDigest] = position
	next.Revision++
	if err := journal.commit(next); err != nil {
		return GuarantorCoverageResolutionPlan{}, err
	}
	return plan, nil
}

func (journal *GuarantorJournal) CommitCoverageResolution(agreementDigest string,
	resolution guarantor.AuthorizedCoverageResolutionV1) (GuarantorCoveragePosition, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	digest, digestErr := guarantor.CoverageResolutionDigestV1(resolution)
	next, copyErr := journal.workingCopy()
	if copyErr != nil {
		return GuarantorCoveragePosition{}, copyErr
	}
	position, found := next.Coverages[agreementDigest]
	if err := journal.ensureAttached(); err != nil || digestErr != nil || !found ||
		resolution.Body.CoverageAgreementBodyDigest != agreementDigest || position.ExposureReleaseReceipt == nil {
		return GuarantorCoveragePosition{}, errors.New("Guarantor coverage-resolution commit is invalid")
	}
	if position.CoverageResolution != nil {
		prior, priorErr := guarantor.CoverageResolutionDigestV1(*position.CoverageResolution)
		if priorErr == nil && prior == digest {
			return position, nil
		}
		return GuarantorCoveragePosition{}, errors.New("Guarantor coverage-resolution conflicts")
	}
	if position.Record.CoverageStatus == guarantor.CoverageReleasePending {
		updated, updateErr := guarantor.TransitionCoverage(position.Record, resolution.Body.PriorCoverageRevision,
			guarantorCoverageResolutionPlanTargetStatus(position.CoverageResolutionPlan), resolution.Body.ExposureReleaseReceiptDigest)
		if updateErr != nil || updated.CoverageRevision != resolution.Body.ResolvedCoverageRevision {
			return GuarantorCoveragePosition{}, errors.New("Guarantor coverage-resolution differs from the journal CAS")
		}
		position.Record = updated
	}
	position.CoverageResolution = &resolution
	next.Coverages[agreementDigest] = position
	next.Revision++
	if err := journal.commit(next); err != nil {
		return GuarantorCoveragePosition{}, err
	}
	return position, nil
}

func guarantorCoverageResolutionPlanTargetStatus(plan *GuarantorCoverageResolutionPlan) guarantor.CoverageStatus {
	if plan == nil {
		return ""
	}
	return plan.TargetStatus
}

func (journal *GuarantorJournal) BeginCoverageRelease(agreementDigest, terminalClaimSetDigest string) (GuarantorCoveragePosition, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if err := journal.ensureAttached(); err != nil || !canonicalSHA256(terminalClaimSetDigest) {
		return GuarantorCoveragePosition{}, errors.New("Guarantor coverage closure is invalid")
	}
	next, copyErr := journal.workingCopy()
	if copyErr != nil {
		return GuarantorCoveragePosition{}, copyErr
	}
	position, found := next.Coverages[agreementDigest]
	if !found || position.Record.ClaimFilingStatus != guarantor.FilingFrozen {
		return GuarantorCoveragePosition{}, errors.New("Guarantor claim filing cut is not frozen")
	}
	for claimID, record := range position.Claims {
		terminalClaim := record.ClaimStatus == guarantor.ClaimFinalApproved ||
			record.ClaimStatus == guarantor.ClaimFinalPartiallyApproved || record.ClaimStatus == guarantor.ClaimFinalDenied
		terminalPayout := record.PayoutStatus == guarantor.PayoutPaid || record.PayoutStatus == guarantor.PayoutNotApplicable ||
			record.PayoutStatus == guarantor.PayoutDefaulted
		if !terminalClaim || !terminalPayout || position.ClaimAdmissionSequence[claimID] == 0 {
			return GuarantorCoveragePosition{}, errors.New("Guarantor coverage has a nonterminal claim or payout")
		}
	}
	updated, err := guarantor.TransitionCoverage(position.Record, position.Record.CoverageRevision,
		guarantor.CoverageReleasePending, terminalClaimSetDigest)
	if err != nil {
		return GuarantorCoveragePosition{}, err
	}
	position.Record = updated
	next.Coverages[agreementDigest] = position
	next.Revision++
	if err := journal.commit(next); err != nil {
		return GuarantorCoveragePosition{}, err
	}
	return position, nil
}

func (journal *GuarantorJournal) ResolveCoverage(agreementDigest string, target guarantor.CoverageStatus,
	releaseEvidenceDigest string) (GuarantorCoveragePosition, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if err := journal.ensureAttached(); err != nil || !canonicalSHA256(releaseEvidenceDigest) {
		return GuarantorCoveragePosition{}, errors.New("Guarantor coverage resolution is invalid")
	}
	next, copyErr := journal.workingCopy()
	if copyErr != nil {
		return GuarantorCoveragePosition{}, copyErr
	}
	position, found := next.Coverages[agreementDigest]
	if !found {
		return GuarantorCoveragePosition{}, errors.New("Guarantor coverage does not exist")
	}
	updated, err := guarantor.TransitionCoverage(position.Record, position.Record.CoverageRevision, target, releaseEvidenceDigest)
	if err != nil {
		return GuarantorCoveragePosition{}, err
	}
	position.Record = updated
	next.Coverages[agreementDigest] = position
	next.Revision++
	if err := journal.commit(next); err != nil {
		return GuarantorCoveragePosition{}, err
	}
	return position, nil
}

// BeginAdmission durably sequences a business mutation before its side-effect
// authority is contacted. A crash therefore leaves a visible prepared entry
// which blocks a later cut until exact recovery resolves it.
func (journal *GuarantorJournal) BeginAdmission(domainID, stableActionID, exactRequestDigest string,
	receivedAt time.Time) (GuarantorAdmissionEntry, error) {
	return journal.beginAdmission(domainID, "", stableActionID, exactRequestDigest, receivedAt)
}

func (journal *GuarantorJournal) BeginClaimIngressAdmission(domainID, stableActionID, exactRequestDigest string,
	receivedAt time.Time) (GuarantorAdmissionEntry, error) {
	return journal.beginAdmission(domainID, guarantor.ClaimIngressLogRootDomainV1, stableActionID, exactRequestDigest, receivedAt)
}

func (journal *GuarantorJournal) beginAdmission(domainID, rootDomain, stableActionID, exactRequestDigest string,
	receivedAt time.Time) (GuarantorAdmissionEntry, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if err := journal.ensureAttached(); err != nil || !canonicalSHA256(domainID) || !canonicalSHA256(stableActionID) ||
		!canonicalSHA256(exactRequestDigest) || receivedAt.IsZero() {
		return GuarantorAdmissionEntry{}, errors.New("Guarantor admission identity is invalid")
	}
	next, copyErr := journal.workingCopy()
	if copyErr != nil {
		return GuarantorAdmissionEntry{}, copyErr
	}
	log, found := next.AdmissionLogs[domainID]
	if !found {
		root, err := guarantorAdmissionInitialRoot(rootDomain, domainID)
		if err != nil {
			return GuarantorAdmissionEntry{}, err
		}
		log = GuarantorAdmissionLog{DomainID: domainID, RootDomain: rootDomain, NextSequence: 1, CurrentRoot: root,
			Entries: map[string]GuarantorAdmissionEntry{}}
	} else if log.RootDomain != rootDomain {
		return GuarantorAdmissionEntry{}, errors.New("Guarantor admission root domain conflicts")
	}
	if existing, exists := log.Entries[stableActionID]; exists {
		if existing.ExactRequestDigest != exactRequestDigest {
			return GuarantorAdmissionEntry{}, errors.New("Guarantor admission semantic identity conflicts")
		}
		return existing, nil
	}
	for _, prior := range log.Entries {
		if prior.Sequence+1 == log.NextSequence && uint64(receivedAt.UTC().Unix()) < prior.ReceivedAtUnix {
			return GuarantorAdmissionEntry{}, errors.New("Guarantor admission clock moved backwards")
		}
	}
	sequence := log.NextSequence
	root, err := guarantorAdmissionAdvanceRoot(rootDomain, domainID, log.CurrentRoot, stableActionID,
		exactRequestDigest, sequence, uint64(receivedAt.UTC().Unix()))
	if err != nil {
		return GuarantorAdmissionEntry{}, err
	}
	entry := GuarantorAdmissionEntry{Sequence: sequence, StableActionID: stableActionID,
		ExactRequestDigest: exactRequestDigest, ReceivedAtUnix: uint64(receivedAt.UTC().Unix()), LogRootAfter: root,
		Resolution: commerce.ActionResolution{StableActionID: stableActionID, ExactRequestDigest: exactRequestDigest,
			State: commerce.ActionPrepared, StateRevision: 1}}
	log.Entries[stableActionID], log.NextSequence, log.CurrentRoot = entry, sequence+1, root
	next.AdmissionLogs[domainID] = log
	next.Revision++
	if err := journal.commit(next); err != nil {
		return GuarantorAdmissionEntry{}, err
	}
	return entry, nil
}

func (journal *GuarantorJournal) ResolveAdmission(domainID string, resolution commerce.ActionResolution) (GuarantorAdmissionEntry, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if err := journal.ensureAttached(); err != nil || !canonicalSHA256(domainID) || commerce.ValidateActionResolution(resolution) != nil {
		return GuarantorAdmissionEntry{}, errors.New("Guarantor admission resolution is invalid")
	}
	next, copyErr := journal.workingCopy()
	if copyErr != nil {
		return GuarantorAdmissionEntry{}, copyErr
	}
	log, found := next.AdmissionLogs[domainID]
	entry, entryFound := log.Entries[resolution.StableActionID]
	if !found || !entryFound || entry.ExactRequestDigest != resolution.ExactRequestDigest {
		return GuarantorAdmissionEntry{}, errors.New("Guarantor admission resolution has no exact predecessor")
	}
	if isGuarantorAdmissionTerminal(entry.Resolution.State) {
		if sameJSON(entry.Resolution, resolution) {
			return entry, nil
		}
		return GuarantorAdmissionEntry{}, errors.New("Guarantor terminal admission resolution conflicts")
	}
	if !isGuarantorAdmissionTerminal(resolution.State) || resolution.StateRevision <= entry.Resolution.StateRevision {
		return GuarantorAdmissionEntry{}, errors.New("Guarantor admission did not advance to a terminal result")
	}
	entry.Resolution = resolution
	log.Entries[resolution.StableActionID] = entry
	next.AdmissionLogs[domainID] = log
	next.Revision++
	if err := journal.commit(next); err != nil {
		return GuarantorAdmissionEntry{}, err
	}
	return entry, nil
}

func (journal *GuarantorJournal) AdmissionEntryRoots(domainID, stableActionID string) (string, string, uint64, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if err := journal.readable(); err != nil {
		return "", "", 0, err
	}
	log, found := journal.doc.AdmissionLogs[domainID]
	entry, entryFound := log.Entries[stableActionID]
	if !found || !entryFound {
		return "", "", 0, errors.New("Guarantor admission entry does not exist")
	}
	prior, err := guarantorAdmissionInitialRoot(log.RootDomain, domainID)
	if err != nil {
		return "", "", 0, err
	}
	if entry.Sequence > 1 {
		for _, candidate := range log.Entries {
			if candidate.Sequence == entry.Sequence-1 {
				prior = candidate.LogRootAfter
				break
			}
		}
	}
	return prior, entry.LogRootAfter, entry.Sequence, nil
}

func (journal *GuarantorJournal) FreezeAdmissionCut(domainID string, cutoffUnix uint64) (GuarantorAdmissionCut, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if err := journal.readable(); err != nil {
		return GuarantorAdmissionCut{}, fmt.Errorf("Guarantor admission cut is unavailable: %w", err)
	}
	if !canonicalSHA256(domainID) || cutoffUnix == 0 {
		return GuarantorAdmissionCut{}, errors.New("Guarantor admission cut is invalid")
	}
	log, found := journal.doc.AdmissionLogs[domainID]
	if !found {
		root, err := guarantorAdmissionInitialRoot("", domainID)
		if err != nil {
			return GuarantorAdmissionCut{}, err
		}
		return GuarantorAdmissionCut{DomainID: domainID, LogRoot: root, Entries: []GuarantorAdmissionEntry{}}, nil
	}
	entries := make([]GuarantorAdmissionEntry, 0, len(log.Entries))
	for _, entry := range log.Entries {
		if entry.ReceivedAtUnix <= cutoffUnix {
			entries = append(entries, entry)
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Sequence < entries[j].Sequence })
	root := ""
	for index, entry := range entries {
		if entry.Sequence != uint64(index+1) || !isGuarantorAdmissionTerminal(entry.Resolution.State) {
			return GuarantorAdmissionCut{}, errors.New("Guarantor admission cut has a gap or unresolved action")
		}
		root = entry.LogRootAfter
		// The cut's entries are private copies.
		entries[index].Resolution.EvidenceRefs = append([]string(nil), entry.Resolution.EvidenceRefs...)
	}
	if len(entries) == 0 {
		root, _ = guarantorAdmissionInitialRoot(log.RootDomain, domainID)
	}
	return GuarantorAdmissionCut{DomainID: domainID, HighWater: uint64(len(entries)), LogRoot: root, Entries: entries}, nil
}

func isGuarantorAdmissionTerminal(state commerce.ActionResolutionState) bool {
	return state == commerce.ActionTerminal || state == commerce.ActionRejected || state == commerce.ActionConflict ||
		state == commerce.ActionAccepted
}

// Snapshot returns the journal's revision, offers and coverages as private
// copies: changing them does not change the journal. An error means the
// journal could not be read, because it is closed, holds a commit whose
// durability is unconfirmed, or cannot be copied. It then returns nothing, and
// a caller must not read that as a journal holding no offers and no
// coverages.
func (journal *GuarantorJournal) Snapshot() (uint64, []GuarantorOfferPosition, []GuarantorCoveragePosition, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if err := journal.readable(); err != nil {
		return 0, nil, nil, err
	}
	doc, err := journal.workingCopy()
	if err != nil {
		return 0, nil, nil, err
	}
	offers := make([]GuarantorOfferPosition, 0, len(doc.Offers))
	for _, offer := range doc.Offers {
		offers = append(offers, offer)
	}
	sort.Slice(offers, func(i, j int) bool { return offers[i].Record.OfferID < offers[j].Record.OfferID })
	coverages := make([]GuarantorCoveragePosition, 0, len(doc.Coverages))
	for _, coverage := range doc.Coverages {
		coverages = append(coverages, coverage)
	}
	sort.Slice(coverages, func(i, j int) bool {
		return coverages[i].Record.CoverageAgreementBodyDigest < coverages[j].Record.CoverageAgreementBodyDigest
	})
	return doc.Revision, offers, coverages, nil
}

func (journal *GuarantorJournal) load(ownerID, agentID string) error {
	info, err := journal.root.Lstat(guarantorJournalFile)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() <= 0 || info.Size() > 64<<20 {
		return errors.New("Guarantor journal file security is invalid")
	}
	raw, err := journal.root.ReadFile(guarantorJournalFile)
	if err != nil {
		return err
	}
	var header struct {
		Schema string `json:"schema"`
	}
	if json.Unmarshal(raw, &header) == nil {
		switch header.Schema {
		case retiredGuarantorJournalSchema:
			return errors.New("Guarantor journal uses the retired v1 schema, which has no revision epochs; " +
				"it cannot be read safely and must be recreated")
		case retiredGuarantorJournalSchemaV2:
			return errors.New("Guarantor journal uses the retired v2 schema, which holds immutable receipts inside " +
				"the document; it cannot be read safely and must be recreated")
		case retiredGuarantorJournalSchemaV3:
			return errors.New("Guarantor journal uses the retired v3 schema, which holds plans without their " +
				"semantic fields; it cannot be resumed safely and must be recreated")
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var doc guarantorJournalDocument
	if err := decoder.Decode(&doc); err != nil {
		return fmt.Errorf("Guarantor journal document is invalid: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF || doc.Schema != guarantorJournalSchema || doc.OwnerID != ownerID ||
		doc.AgentID != agentID || doc.Revision == 0 || doc.Offers == nil || doc.Coverages == nil ||
		doc.ClaimToCoverage == nil || doc.AdmissionLogs == nil {
		return errors.New("Guarantor journal document is invalid")
	}
	// Checked before any default is filled in below: doc is still exactly what
	// was decoded.
	if err := requireExactGuarantorDocument(raw, doc); err != nil {
		return fmt.Errorf("Guarantor journal document is invalid: %w", err)
	}
	if err := validateGuarantorOffers(doc); err != nil {
		return err
	}
	if doc.FirmOfferIssuancePlans == nil {
		doc.FirmOfferIssuancePlans = map[string]GuarantorFirmOfferIssuancePlan{}
	}
	for key, log := range doc.AdmissionLogs {
		if key != log.DomainID || !canonicalSHA256(key) || log.NextSequence == 0 || !canonicalSHA256(log.CurrentRoot) || log.Entries == nil {
			return errors.New("Guarantor admission log is invalid")
		}
		if err := validateGuarantorAdmissionLog(log); err != nil {
			return err
		}
	}
	for key, coverage := range doc.Coverages {
		if coverage.Claims == nil || coverage.Decisions == nil || coverage.MaterializedPayouts == nil || coverage.PayoutEvidence == nil || coverage.PayoutRequests == nil || coverage.PaidByObligation == nil ||
			coverage.ClaimAdmissionSequence == nil || !canonicalSHA256(coverage.ClaimAdmissionLogRoot) {
			return errors.New("Guarantor coverage projection is incomplete")
		}
		if coverage.PayoutExecutionEvidence == nil {
			coverage.PayoutExecutionEvidence = map[string]guarantor.AuthorizedGuarantorPayoutExecutionEvidenceV1{}
		}
		if coverage.DefaultedByObligation == nil {
			coverage.DefaultedByObligation = map[string]string{}
		}
		if coverage.DefaultedAtomic == "" {
			coverage.DefaultedAtomic = "0"
		}
		if coverage.ClaimEnvelopes == nil {
			coverage.ClaimEnvelopes = map[string]guarantor.AuthorizedCoverageClaimV1{}
		}
		if coverage.ClaimIngressReceipts == nil {
			coverage.ClaimIngressReceipts = map[string]guarantor.AuthorizedClaimSubmissionIngressReceiptV1{}
		}
		if coverage.ClaimAdmissionReceipts == nil {
			coverage.ClaimAdmissionReceipts = map[string]guarantor.AuthorizedClaimAdmissionReceiptV1{}
		}
		if coverage.ClaimRevisionSequence == nil {
			coverage.ClaimRevisionSequence = map[string]uint64{}
		}
		if coverage.ClaimRevisionLogRoot == nil {
			coverage.ClaimRevisionLogRoot = map[string]string{}
		}
		if coverage.DecisionAdmissionReceipts == nil {
			coverage.DecisionAdmissionReceipts = map[string]guarantor.AuthorizedClaimDecisionAdmissionReceiptV1{}
		}
		if coverage.ClaimStateTransitionReceipts == nil {
			coverage.ClaimStateTransitionReceipts = map[string]guarantor.AuthorizedClaimStateTransitionReceiptV1{}
		}
		if coverage.DecisionApplicationReceipts == nil {
			coverage.DecisionApplicationReceipts = map[string]guarantor.AuthorizedClaimDecisionApplicationReceiptV1{}
		}
		if coverage.DecisionApplicationTokens == nil {
			coverage.DecisionApplicationTokens = map[string]guarantor.DecisionApplicationTokenV1{}
		}
		if coverage.ChallengeRoundsUsed == nil {
			coverage.ChallengeRoundsUsed = map[string]uint64{}
		}
		if coverage.NonterminalRoundsUsed == nil {
			coverage.NonterminalRoundsUsed = map[string]uint64{}
		}
		if coverage.RevisionEpochs == nil {
			coverage.RevisionEpochs = map[string]GuarantorRevisionEpochState{}
		}
		// Every admitted claim's epoch is recorded from its first admission
		// and must agree with its stored decision admission and transition; a
		// missing or contradicting record is refused rather than trusted.
		for claimID := range coverage.Claims {
			if err := validateLoadedRevisionEpoch(coverage, claimID); err != nil {
				return err
			}
		}
		if coverage.ImmutableEvidence == nil {
			coverage.ImmutableEvidence = map[string]GuarantorStoredEvidence{}
		}
		if len(coverage.ImmutableEvidence) > maximumGuarantorStoredEvidenceReceipts {
			return errors.New("Guarantor journal coverage holds more immutable receipts than its cap")
		}
		for digest, stored := range coverage.ImmutableEvidence {
			if err := journal.checkStoredEvidenceFile(digest, stored); err != nil {
				return err
			}
		}
		if coverage.AggregatePendingDecisionReserveAtomic == "" {
			coverage.AggregatePendingDecisionReserveAtomic = "0"
		}
		if coverage.CumulativeAppliedApprovedAtomic == "" {
			coverage.CumulativeAppliedApprovedAtomic = "0"
		}
		if coverage.NextPayoutSequence == 0 {
			coverage.NextPayoutSequence = 1
		}
		doc.Coverages[key] = coverage
	}
	// A plan is what a restart resumes from, so each one must still belong to
	// the receipts stored beside it.
	if err := validateGuarantorPlans(doc); err != nil {
		return fmt.Errorf("Guarantor journal plan is invalid: %w", err)
	}
	journal.doc = doc
	return nil
}

func validateGuarantorAdmissionLog(log GuarantorAdmissionLog) error {
	entries := make([]GuarantorAdmissionEntry, 0, len(log.Entries))
	for key, entry := range log.Entries {
		if key != entry.StableActionID || !canonicalSHA256(entry.StableActionID) ||
			!canonicalSHA256(entry.ExactRequestDigest) || entry.Sequence == 0 || entry.ReceivedAtUnix == 0 ||
			!canonicalSHA256(entry.LogRootAfter) || commerce.ValidateActionResolution(entry.Resolution) != nil ||
			entry.Resolution.StableActionID != entry.StableActionID ||
			entry.Resolution.ExactRequestDigest != entry.ExactRequestDigest ||
			entry.Resolution.State != commerce.ActionPrepared && !isGuarantorAdmissionTerminal(entry.Resolution.State) {
			return errors.New("Guarantor admission log entry is invalid")
		}
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Sequence < entries[j].Sequence })
	root, err := guarantorAdmissionInitialRoot(log.RootDomain, log.DomainID)
	if err != nil {
		return err
	}
	var priorReceived uint64
	for index, entry := range entries {
		sequence := uint64(index + 1)
		if entry.Sequence != sequence || entry.ReceivedAtUnix < priorReceived {
			return errors.New("Guarantor admission log sequence or clock is invalid")
		}
		root, err = guarantorAdmissionAdvanceRoot(log.RootDomain, log.DomainID, root, entry.StableActionID,
			entry.ExactRequestDigest, sequence, entry.ReceivedAtUnix)
		if err != nil || root != entry.LogRootAfter {
			return errors.New("Guarantor admission log root is invalid")
		}
		priorReceived = entry.ReceivedAtUnix
	}
	if log.NextSequence != uint64(len(entries))+1 || log.CurrentRoot != root {
		return errors.New("Guarantor admission log head is invalid")
	}
	return nil
}

func (journal *GuarantorJournal) ensureAttached() error {
	if journal == nil || journal.root == nil || journal.lock == nil || journal.domainLock == nil {
		return errors.New("Guarantor journal is closed")
	}
	opened, err := journal.root.Stat(".")
	current, pathErr := os.Lstat(journal.directory)
	if err != nil || pathErr != nil || !os.SameFile(opened, current) || validateRelayJournalDirectorySecurity(journal.directory) != nil {
		return errors.New("Guarantor journal directory was replaced")
	}
	return nil
}

// ErrGuarantorJournalCommittedNotSynced reports a commit whose document is on
// disk and in memory although the write returned an error: the new document
// was renamed into place and the directory sync after it failed. The commit
// has happened and must not be retried as if nothing was written, undone, or
// reported as a success: only the document's durability across a crash is
// unconfirmed. Until it is confirmed the journal does nothing else, and every
// further call fails with ErrGuarantorJournalDurabilityUnconfirmed.
var ErrGuarantorJournalCommittedNotSynced = errors.New("Guarantor journal document is committed but its directory sync failed")

// ErrGuarantorJournalDurabilityUnconfirmed reports a call that did nothing
// because an earlier commit is on disk without a confirmed directory sync and
// writing the same document again failed too. Unlike
// ErrGuarantorJournalCommittedNotSynced it says nothing was committed by this
// call. The call can be repeated; once the document is confirmed, repeating
// the call that committed it returns its committed result without writing.
var ErrGuarantorJournalDurabilityUnconfirmed = errors.New(
	"Guarantor journal holds a commit whose durability is not confirmed",
)

// errGuarantorJournalReadOnly refuses a write to a journal opened for
// inspection.
var errGuarantorJournalReadOnly = errors.New("Guarantor journal is open read-only")

// guarantorJournalDurabilityError returns err when it reports a committed
// document whose durability is unconfirmed, by the call itself or by an
// earlier one, and nil for any other error. A caller that otherwise ignores
// or replaces a journal error uses it so that this one is never lost.
func guarantorJournalDurabilityError(err error) error {
	if errors.Is(err, ErrGuarantorJournalCommittedNotSynced) ||
		errors.Is(err, ErrGuarantorJournalDurabilityUnconfirmed) {
		return err
	}
	return nil
}

// ConfirmDurable makes an unconfirmed commit durable by writing the committed
// document again, and reports whether the journal can be used. It writes
// nothing when no commit is unconfirmed.
func (journal *GuarantorJournal) ConfirmDurable() error {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if err := journal.ensureAttached(); err != nil {
		return err
	}
	return journal.confirmDurable()
}

// confirmDurable writes the committed document again when its commit's
// directory sync failed. The same bytes go through a complete atomic write,
// so success confirms exactly the document that was committed; nothing is
// committed a second time. The caller holds the journal.
func (journal *GuarantorJournal) confirmDurable() error {
	if !journal.unconfirmed {
		return nil
	}
	raw, err := encodeGuarantorDocument(journal.doc)
	if err == nil {
		err = journal.writeFile(journal.root, guarantorJournalFile, raw, 0o600)
	}
	if err != nil {
		return fmt.Errorf("%w: %w", ErrGuarantorJournalDurabilityUnconfirmed, err)
	}
	journal.unconfirmed = false
	return nil
}

func encodeGuarantorDocument(doc guarantorJournalDocument) ([]byte, error) {
	raw, err := json.Marshal(doc)
	if err != nil || len(raw) > 64<<20 {
		return nil, errors.New("encode bounded Guarantor journal")
	}
	return raw, nil
}

func (journal *GuarantorJournal) persist(doc guarantorJournalDocument) error {
	if journal.readOnly {
		return errGuarantorJournalReadOnly
	}
	raw, err := encodeGuarantorDocument(doc)
	if err != nil {
		return err
	}
	return journal.writeFile(journal.root, guarantorJournalFile, raw, 0o600)
}

// commit writes every newly stored immutable receipt to its own file, then the
// document that names them, and only then replaces the in-memory document. A
// crash between the two writes leaves only an unnamed, content-addressed file,
// never a document naming a receipt it cannot serve.
//
// The in-memory document always equals the one on disk. A write that fails
// before the document is renamed into place leaves both as they were: doc is
// the caller's working copy, so nothing staged in it outlives the failure. A
// write that fails after the rename has replaced the document, so memory is
// replaced too, the journal is marked unconfirmed and the error is
// ErrGuarantorJournalCommittedNotSynced. A later successful document write
// confirms it: its directory sync covers the earlier rename.
//
// The in-memory document is decoded from the bytes written, not taken from
// doc, so it shares no memory with the receipts and plans the caller put into
// doc or with the position the caller returns, and it holds exactly what a
// restart would load, each plan's semantic fields included.
func (journal *GuarantorJournal) commit(doc guarantorJournalDocument) error {
	if journal.readOnly {
		return errGuarantorJournalReadOnly
	}
	if err := journal.writeStagedEvidence(doc); err != nil {
		return err
	}
	raw, err := encodeGuarantorDocument(doc)
	if err != nil {
		return err
	}
	var committed guarantorJournalDocument
	if err := json.Unmarshal(raw, &committed); err != nil {
		return fmt.Errorf("decode the Guarantor journal document to commit: %w", err)
	}
	writeErr := journal.writeFile(journal.root, guarantorJournalFile, raw, 0o600)
	if writeErr != nil && !errors.Is(writeErr, fileutil.ErrReplacedNotSynced) {
		return writeErr
	}
	journal.doc = committed
	journal.unconfirmed = writeErr != nil
	if writeErr != nil {
		return fmt.Errorf("%w: %w", ErrGuarantorJournalCommittedNotSynced, writeErr)
	}
	return nil
}

// workingCopy returns a private deep copy of the committed document. A commit
// method reads everything it changes from this copy and changes only the copy;
// commit swaps it in after it is persisted. A commit that fails, and a method
// that returns early, therefore leave no trace in the in-memory document: not
// in a map, not behind a pointer, and not as staged evidence.
//
// Every commit method and every snapshot starts here, so this is where a
// commit whose durability is unconfirmed is confirmed first. If it cannot be,
// the caller gets ErrGuarantorJournalDurabilityUnconfirmed and does nothing:
// no method returns a result, replayed or new, from a document that may not
// survive a crash.
func (journal *GuarantorJournal) workingCopy() (guarantorJournalDocument, error) {
	if err := journal.confirmDurable(); err != nil {
		return guarantorJournalDocument{}, err
	}
	raw, err := json.Marshal(journal.doc)
	if err != nil {
		return guarantorJournalDocument{}, fmt.Errorf("copy Guarantor journal document: %w", err)
	}
	var copied guarantorJournalDocument
	if err := json.Unmarshal(raw, &copied); err != nil {
		return guarantorJournalDocument{}, fmt.Errorf("copy Guarantor journal document: %w", err)
	}
	return copied, nil
}

// sameJSON reports whether left and right have the same JSON encoding. A
// value that cannot be encoded equals nothing, itself included: every caller
// treats "not the same" as the refusing answer, so an encoding failure
// refuses instead of comparing two empty results as equal.
func sameJSON(left, right any) bool {
	l, leftErr := json.Marshal(left)
	r, rightErr := json.Marshal(right)
	if leftErr != nil || rightErr != nil {
		return false
	}
	return bytes.Equal(l, r)
}

// requireExactGuarantorDocument refuses a document on disk that is not, member
// for member, what this journal writes for the document it decoded from it.
// Decoding alone is more lenient than that: it matches a member name in any
// letter case and keeps the last of two members with one name, so a document
// could carry a second, differently spelled copy of a member, or a member
// decoding drops or defaults, and still load. The document is therefore
// walked for repeated member names at every depth, and then encoded again and
// compared with the bytes read as a tree: member order and spacing are free,
// every name and value is not.
func requireExactGuarantorDocument(raw []byte, doc guarantorJournalDocument) error {
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return err
	}
	encoded, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	read, err := decodeJSONTree(raw)
	if err != nil {
		return err
	}
	written, err := decodeJSONTree(encoded)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(read, written) {
		return errors.New("document has members or values this journal does not write")
	}
	return nil
}

// decodeJSONTree decodes one JSON value into maps, slices and scalars, keeping
// every number's exact digits.
func decodeJSONTree(raw []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var tree any
	if err := decoder.Decode(&tree); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("JSON contains trailing data")
	}
	return tree, nil
}

// validateGuarantorOffers checks each stored offer position against the key it
// is stored under and against the receipt its state claims: an offer is found
// by its key and summed by its record, so the two must name one offer, and a
// released offer must hold the release receipt its record commits to.
func validateGuarantorOffers(doc guarantorJournalDocument) error {
	for offerID, position := range doc.Offers {
		if offerID != position.Record.OfferID {
			return fmt.Errorf("Guarantor offer %s is stored under another identity", offerID)
		}
		if position.Record.Status != guarantor.OfferReleased {
			continue
		}
		if position.PreAcceptanceReleaseReceipt == nil {
			return fmt.Errorf("Guarantor offer %s is released without a release receipt", offerID)
		}
		receiptDigest, err := guarantor.PreAcceptanceExposureReleaseReceiptDigestV1(
			*position.PreAcceptanceReleaseReceipt,
		)
		if err != nil || receiptDigest != position.Record.LastEvidenceDigest {
			return fmt.Errorf("Guarantor offer %s is released by another receipt than the stored one", offerID)
		}
	}
	return nil
}
