package earning

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/tosnetwork/openfox/pkg/fileutil"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	guarantor "github.com/tosnetwork/tos-service-protocol/pkg/agentguarantor"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

const (
	guarantorJournalSchema = "tos.openfox.agent-guarantor-journal.v1"
	guarantorJournalFile   = "agent-guarantor-journal.json"
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
	Terms                                 guarantor.CoverageTermsV1                                         `json:"terms"`
	AcceptanceReceipt                     *guarantor.AuthorizedCoverageAcceptanceReceiptV1                  `json:"acceptance_receipt,omitempty"`
	ActivationEvidence                    *guarantor.AuthorizedCoverageActivationEvidenceV1                 `json:"activation_evidence,omitempty"`
	NonActivationEvidence                 *guarantor.AuthorizedCoverageNonActivationEvidenceV1              `json:"non_activation_evidence,omitempty"`
	NonActivationReleaseReceipt           *guarantor.AuthorizedNonActivationExposureReleaseReceiptV1        `json:"non_activation_release_receipt,omitempty"`
	CancellationReceipt                   *guarantor.AuthorizedCoverageCancellationReceiptV1                `json:"cancellation_receipt,omitempty"`
	FilingCloseReceipt                    *guarantor.AuthorizedClaimFilingCloseReceiptV1                    `json:"filing_close_receipt,omitempty"`
	TerminalClaimSet                      *guarantor.AuthorizedTerminalClaimSetEvidenceV1                   `json:"terminal_claim_set,omitempty"`
	ExposureReleaseReceipt                *guarantor.AuthorizedExposureReleaseReceiptV1                     `json:"exposure_release_receipt,omitempty"`
	CoverageResolution                    *guarantor.AuthorizedCoverageResolutionV1                         `json:"coverage_resolution,omitempty"`
	ExposureReleasePlan                   *GuarantorExposureReleasePlan                                     `json:"exposure_release_plan,omitempty"`
	CoverageResolutionPlan                *GuarantorCoverageResolutionPlan                                  `json:"coverage_resolution_plan,omitempty"`
	Record                                guarantor.CoverageRecord                                          `json:"record"`
	Claims                                map[string]guarantor.ClaimRecord                                  `json:"claims"`
	ClaimEnvelopes                        map[string]guarantor.AuthorizedCoverageClaimV1                    `json:"claim_envelopes"`
	ClaimIngressReceipts                  map[string]guarantor.AuthorizedClaimSubmissionIngressReceiptV1    `json:"claim_ingress_receipts"`
	ClaimAdmissionReceipts                map[string]guarantor.AuthorizedClaimAdmissionReceiptV1            `json:"claim_admission_receipts"`
	Decisions                             map[string]guarantor.AuthorizedClaimDecisionV1                    `json:"decisions"`
	DecisionAdmissionReceipts             map[string]guarantor.AuthorizedClaimDecisionAdmissionReceiptV1    `json:"decision_admission_receipts"`
	ClaimStateTransitionReceipts          map[string]guarantor.AuthorizedClaimStateTransitionReceiptV1      `json:"claim_state_transition_receipts"`
	DecisionApplicationReceipts           map[string]guarantor.AuthorizedClaimDecisionApplicationReceiptV1  `json:"decision_application_receipts"`
	DecisionApplicationTokens             map[string]guarantor.DecisionApplicationTokenV1                   `json:"decision_application_tokens"`
	ChallengeRoundsUsed                   map[string]uint64                                                 `json:"challenge_rounds_used"`
	NonterminalRoundsUsed                 map[string]uint64                                                 `json:"nonterminal_rounds_used"`
	ClaimAdmissionSequence                map[string]uint64                                                 `json:"claim_admission_sequence"`
	ClaimAdmissionLogRoot                 string                                                            `json:"claim_admission_log_root"`
	ClaimRevisionSequence                 map[string]uint64                                                 `json:"claim_revision_sequence"`
	ClaimRevisionLogRoot                  map[string]string                                                 `json:"claim_revision_log_root"`
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
}

func OpenGuarantorJournal(directory, ownerID, agentID string) (*GuarantorJournal, error) {
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
	journal := &GuarantorJournal{directory: directory, root: root, lock: lock, domainLock: domainLock, now: time.Now,
		doc: guarantorJournalDocument{Schema: guarantorJournalSchema, OwnerID: ownerID, AgentID: agentID, Revision: 1,
			Offers: map[string]GuarantorOfferPosition{}, Coverages: map[string]GuarantorCoveragePosition{}, ClaimToCoverage: map[string]string{},
			AdmissionLogs: map[string]GuarantorAdmissionLog{}, FirmOfferIssuancePlans: map[string]GuarantorFirmOfferIssuancePlan{}}}
	if _, err := root.Lstat(guarantorJournalFile); errors.Is(err, os.ErrNotExist) {
		if err := journal.persist(journal.doc); err != nil {
			_ = journal.Close()
			return nil, err
		}
	} else if err != nil || journal.load(ownerID, agentID) != nil {
		_ = journal.Close()
		return nil, errors.New("load Guarantor journal")
	}
	return journal, nil
}

func (journal *GuarantorJournal) Close() error {
	if journal == nil {
		return nil
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	var result error
	if journal.lock != nil {
		result = releaseAuthorityLock(journal.lock)
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
	if existing, found := journal.doc.Offers[position.Record.OfferID]; found {
		if sameJSON(existing, position) {
			return nil
		}
		return errors.New("Guarantor offer identity conflicts with prior reservation")
	}
	next := cloneGuarantorDocument(journal.doc)
	next.Offers[position.Record.OfferID] = position
	next.Revision++
	return journal.commit(next)
}

func (journal *GuarantorJournal) SaveFirmOfferIssuancePlan(plan GuarantorFirmOfferIssuancePlan) error {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if err := journal.ensureAttached(); err != nil || !canonicalSHA256(plan.AuthorityInstanceID) ||
		!canonicalSHA256(plan.AdmissionDomainID) || !canonicalSHA256(plan.OfferDigest) ||
		!canonicalSHA256(plan.ReceiptDigest) || plan.Action.StableActionID == "" ||
		plan.Action.ExactRequestDigest == "" || plan.Reservation.ReservationID == "" || len(plan.CanonicalRequest) == 0 {
		return errors.New("Guarantor firm-offer issuance plan is invalid")
	}
	wantOfferDigest, offerErr := guarantor.FirmOfferDigest(plan.Offer)
	wantRequestDigest, requestErr := commerce.ExactRequestDigest(plan.CanonicalRequest)
	if offerErr != nil || requestErr != nil || wantOfferDigest != plan.OfferDigest ||
		wantRequestDigest != plan.Action.ExactRequestDigest || plan.Offer.Body.OfferID != plan.AuthorityInstanceID ||
		plan.Offer.Body.ReservationID != plan.Reservation.ReservationID ||
		plan.Position.Record.OfferID != plan.AuthorityInstanceID {
		return errors.New("Guarantor firm-offer issuance plan binding is invalid")
	}
	if existing, found := journal.doc.FirmOfferIssuancePlans[plan.AuthorityInstanceID]; found {
		if sameJSON(existing, plan) {
			return nil
		}
		return errors.New("Guarantor firm-offer issuance plan conflicts")
	}
	next := cloneGuarantorDocument(journal.doc)
	next.FirmOfferIssuancePlans[plan.AuthorityInstanceID] = plan
	next.Revision++
	return journal.commit(next)
}

func (journal *GuarantorJournal) FirmOfferIssuancePlan(authorityInstanceID string) (GuarantorFirmOfferIssuancePlan, bool) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.ensureAttached() != nil {
		return GuarantorFirmOfferIssuancePlan{}, false
	}
	plan, found := journal.doc.FirmOfferIssuancePlans[authorityInstanceID]
	return plan, found
}

// FirmOfferByDigest returns the exact authorized bytes retained at issuance.
// Acceptance never reconstructs a commercial offer from chat, a body digest,
// or a now-deleted outbound transport record.
func (journal *GuarantorJournal) FirmOfferByDigest(envelopeDigest string) (guarantor.AuthorizedFirmCoverageOfferV1, bool) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.ensureAttached() != nil || !canonicalSHA256(envelopeDigest) {
		return guarantor.AuthorizedFirmCoverageOfferV1{}, false
	}
	for _, position := range journal.doc.Offers {
		if position.OfferEnvelopeDigest == envelopeDigest && position.AuthorizedFirmOffer != nil {
			digest, err := guarantor.FirmOfferDigest(*position.AuthorizedFirmOffer)
			if err == nil && digest == envelopeDigest {
				return *position.AuthorizedFirmOffer, true
			}
		}
	}
	return guarantor.AuthorizedFirmCoverageOfferV1{}, false
}

func (journal *GuarantorJournal) CompleteFirmOfferIssuancePlan(authorityInstanceID, offerDigest string) error {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if err := journal.ensureAttached(); err != nil {
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
	next := cloneGuarantorDocument(journal.doc)
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
	plan, found := journal.doc.FirmOfferIssuancePlans[authorityInstanceID]
	if !found {
		return nil
	}
	if authority.Resolve(plan.Action.StableActionID, plan.Action.ExactRequestDigest).State != commerce.ActionUnknown {
		return errors.New("an admitted Guarantor firm-offer plan cannot be discarded")
	}
	next := cloneGuarantorDocument(journal.doc)
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
	position, found := journal.doc.Offers[offerID]
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
	next := cloneGuarantorDocument(journal.doc)
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
	position, found := journal.doc.Offers[offerID]
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
	next := cloneGuarantorDocument(journal.doc)
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
	position, found := journal.doc.Offers[offerID]
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
	next := cloneGuarantorDocument(journal.doc)
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
	if err := journal.ensureAttached(); err != nil || plan.Action.ActionKind != "portfolio.release" ||
		!canonicalSHA256(plan.Action.StableActionID) || !canonicalSHA256(plan.Action.ExactRequestDigest) ||
		plan.TargetPortfolioRevision != plan.BasePortfolioRevision+1 || len(plan.CanonicalRequest) == 0 {
		return GuarantorOfferPosition{}, errors.New("Guarantor pre-acceptance release plan is invalid")
	}
	position, found := journal.doc.Offers[offerID]
	if !found || position.Record.Status != guarantor.OfferExpired {
		return GuarantorOfferPosition{}, errors.New("Guarantor offer is not awaiting pre-acceptance release")
	}
	if position.PreAcceptanceReleasePlan != nil {
		if sameJSON(*position.PreAcceptanceReleasePlan, plan) {
			return position, nil
		}
		return GuarantorOfferPosition{}, errors.New("Guarantor pre-acceptance release plan conflicts")
	}
	position.PreAcceptanceReleasePlan = &plan
	next := cloneGuarantorDocument(journal.doc)
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
	position, found := journal.doc.Offers[offerID]
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
	next := cloneGuarantorDocument(journal.doc)
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
	offer, found := journal.doc.Offers[offerID]
	if !found || offer.Record.Status != guarantor.OfferIssued || uint64(receivedAt.UTC().Unix()) > offer.AcceptByUnix ||
		offer.Record.AgreementDigest != agreementDigest {
		return GuarantorCoveragePosition{}, errors.New("Guarantor offer is not eligible for acceptance")
	}
	if existing, found := journal.doc.Coverages[agreementDigest]; found {
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
	next := cloneGuarantorDocument(journal.doc)
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
	position, found := journal.doc.Coverages[agreementDigest]
	if !found {
		return GuarantorCoveragePosition{}, errors.New("Guarantor coverage does not exist")
	}
	updated, err := guarantor.TransitionCoverage(position.Record, expectedRevision, target, evidenceDigest)
	if err != nil {
		return GuarantorCoveragePosition{}, err
	}
	position.Record = updated
	next := cloneGuarantorDocument(journal.doc)
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
	position, found := journal.doc.Coverages[agreementDigest]
	if !found {
		return GuarantorCoveragePosition{}, errors.New("Guarantor coverage does not exist")
	}
	updated, err := guarantor.ActivateAcceptedCoverage(position.Record, expectedCoverageRevision,
		expectedFilingRevision, evidenceDigest)
	if err != nil {
		return GuarantorCoveragePosition{}, err
	}
	position.Record = updated
	next := cloneGuarantorDocument(journal.doc)
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
	expectedFilingRevision uint64,
	evidence guarantor.AuthorizedCoverageActivationEvidenceV1) (GuarantorCoveragePosition, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	digest, digestErr := guarantor.CoverageActivationEvidenceDigestV1(evidence)
	position, found := journal.doc.Coverages[agreementDigest]
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
	position.Record, position.ActivationEvidence = updated, &evidence
	next := cloneGuarantorDocument(journal.doc)
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
	position, found := journal.doc.Coverages[agreementDigest]
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
	next := cloneGuarantorDocument(journal.doc)
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
	position, found := journal.doc.Coverages[agreementDigest]
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
	next := cloneGuarantorDocument(journal.doc)
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
	position, found := journal.doc.Coverages[agreementDigest]
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
	next := cloneGuarantorDocument(journal.doc)
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
	if err := journal.ensureAttached(); err != nil {
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
	position, found := journal.doc.Coverages[agreementDigest]
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
	next := cloneGuarantorDocument(journal.doc)
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
	position, found := journal.doc.Coverages[agreementDigest]
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
	next := cloneGuarantorDocument(journal.doc)
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
	position, found := journal.doc.Coverages[agreementDigest]
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
	next := cloneGuarantorDocument(journal.doc)
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
	position, found := journal.doc.Coverages[agreementDigest]
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
	next := cloneGuarantorDocument(journal.doc)
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
	position, found := journal.doc.Coverages[agreementDigest]
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
	position.FilingCloseReceipt = &receipt
	next := cloneGuarantorDocument(journal.doc)
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
	position, found := journal.doc.Coverages[agreementDigest]
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
	next := cloneGuarantorDocument(journal.doc)
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
	position, found := journal.doc.Coverages[agreementDigest]
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
	next := cloneGuarantorDocument(journal.doc)
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
	position, found := journal.doc.Coverages[agreementDigest]
	if err := journal.ensureAttached(); err != nil || !found || position.Record.CoverageStatus != guarantor.CoverageReleasePending ||
		position.TerminalClaimSet == nil || actionErr != nil ||
		len(plan.CanonicalRequest) == 0 || plan.CreatedAtUnix == 0 {
		return GuarantorExposureReleasePlan{}, errors.New("Guarantor exposure-release plan is invalid")
	}
	if position.ExposureReleasePlan != nil {
		if sameJSON(*position.ExposureReleasePlan, plan) {
			return *position.ExposureReleasePlan, nil
		}
		return GuarantorExposureReleasePlan{}, errors.New("Guarantor exposure-release plan conflicts")
	}
	position.ExposureReleasePlan = &plan
	next := cloneGuarantorDocument(journal.doc)
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
	position, found := journal.doc.Coverages[agreementDigest]
	if err := journal.ensureAttached(); err != nil || !found || position.ExposureReleasePlan == nil ||
		position.ExposureReleaseReceipt != nil {
		return GuarantorExposureReleasePlan{}, errors.New("Guarantor exposure-release plan cannot be reauthorized")
	}
	prior := *position.ExposureReleasePlan
	if !sameJSON(prior.Fields, plan.Fields) || !bytes.Equal(prior.CanonicalRequest, plan.CanonicalRequest) ||
		!sameJSON(prior.RequestBody, plan.RequestBody) || !sameJSON(prior.Disposition, plan.Disposition) ||
		prior.Action.StableActionID != plan.Action.StableActionID ||
		prior.Action.ExactRequestDigest != plan.Action.ExactRequestDigest ||
		plan.Action.WriterGeneration <= prior.Action.WriterGeneration ||
		plan.WriterFence.Body.WriterGeneration != plan.Action.WriterGeneration ||
		plan.CreatedAtUnix < prior.CreatedAtUnix {
		return GuarantorExposureReleasePlan{}, errors.New("Guarantor exposure-release reauthorization changes frozen semantics")
	}
	position.ExposureReleasePlan = &plan
	next := cloneGuarantorDocument(journal.doc)
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
	position, found := journal.doc.Coverages[agreementDigest]
	if err := journal.ensureAttached(); err != nil || !found || position.Record.CoverageStatus != guarantor.CoverageReleasePending ||
		position.ExposureReleaseReceipt == nil || actionErr != nil ||
		len(plan.CanonicalRequest) == 0 || plan.CreatedAtUnix == 0 {
		return GuarantorCoverageResolutionPlan{}, errors.New("Guarantor coverage-resolution plan is invalid")
	}
	if position.CoverageResolutionPlan != nil {
		if sameJSON(*position.CoverageResolutionPlan, plan) {
			return *position.CoverageResolutionPlan, nil
		}
		return GuarantorCoverageResolutionPlan{}, errors.New("Guarantor coverage-resolution plan conflicts")
	}
	position.CoverageResolutionPlan = &plan
	next := cloneGuarantorDocument(journal.doc)
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
	position, found := journal.doc.Coverages[agreementDigest]
	if err := journal.ensureAttached(); err != nil || !found || position.CoverageResolutionPlan == nil ||
		position.CoverageResolution != nil {
		return GuarantorCoverageResolutionPlan{}, errors.New("Guarantor coverage-resolution plan cannot be reauthorized")
	}
	prior := *position.CoverageResolutionPlan
	if !sameJSON(prior.Fields, plan.Fields) || !bytes.Equal(prior.CanonicalRequest, plan.CanonicalRequest) ||
		!sameJSON(prior.RequestBody, plan.RequestBody) || prior.TargetStatus != plan.TargetStatus ||
		prior.TargetState != plan.TargetState || prior.Action.StableActionID != plan.Action.StableActionID ||
		prior.Action.ExactRequestDigest != plan.Action.ExactRequestDigest ||
		plan.Action.WriterGeneration <= prior.Action.WriterGeneration ||
		plan.WriterFence.Body.WriterGeneration != plan.Action.WriterGeneration ||
		plan.CreatedAtUnix < prior.CreatedAtUnix {
		return GuarantorCoverageResolutionPlan{}, errors.New("Guarantor coverage-resolution reauthorization changes frozen semantics")
	}
	position.CoverageResolutionPlan = &plan
	next := cloneGuarantorDocument(journal.doc)
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
	position, found := journal.doc.Coverages[agreementDigest]
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
	next := cloneGuarantorDocument(journal.doc)
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
	position, found := journal.doc.Coverages[agreementDigest]
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
	next := cloneGuarantorDocument(journal.doc)
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
	position, found := journal.doc.Coverages[agreementDigest]
	if !found {
		return GuarantorCoveragePosition{}, errors.New("Guarantor coverage does not exist")
	}
	updated, err := guarantor.TransitionCoverage(position.Record, position.Record.CoverageRevision, target, releaseEvidenceDigest)
	if err != nil {
		return GuarantorCoveragePosition{}, err
	}
	position.Record = updated
	next := cloneGuarantorDocument(journal.doc)
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
	log, found := journal.doc.AdmissionLogs[domainID]
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
	next := cloneGuarantorDocument(journal.doc)
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
	log, found := journal.doc.AdmissionLogs[domainID]
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
	next := cloneGuarantorDocument(journal.doc)
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
	if err := journal.ensureAttached(); err != nil {
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
	if err := journal.ensureAttached(); err != nil || !canonicalSHA256(domainID) || cutoffUnix == 0 {
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

func (journal *GuarantorJournal) Snapshot() (uint64, []GuarantorOfferPosition, []GuarantorCoveragePosition) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	offers := make([]GuarantorOfferPosition, 0, len(journal.doc.Offers))
	for _, offer := range journal.doc.Offers {
		offers = append(offers, offer)
	}
	sort.Slice(offers, func(i, j int) bool { return offers[i].Record.OfferID < offers[j].Record.OfferID })
	coverages := make([]GuarantorCoveragePosition, 0, len(journal.doc.Coverages))
	for _, coverage := range journal.doc.Coverages {
		coverages = append(coverages, coverage)
	}
	sort.Slice(coverages, func(i, j int) bool {
		return coverages[i].Record.CoverageAgreementBodyDigest < coverages[j].Record.CoverageAgreementBodyDigest
	})
	return journal.doc.Revision, offers, coverages
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
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var doc guarantorJournalDocument
	if err := decoder.Decode(&doc); err != nil || decoder.Decode(&struct{}{}) != io.EOF || doc.Schema != guarantorJournalSchema || doc.OwnerID != ownerID || doc.AgentID != agentID ||
		doc.Revision == 0 || doc.Offers == nil || doc.Coverages == nil || doc.ClaimToCoverage == nil || doc.AdmissionLogs == nil {
		return errors.New("Guarantor journal document is invalid")
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

func (journal *GuarantorJournal) persist(doc guarantorJournalDocument) error {
	raw, err := json.Marshal(doc)
	if err != nil || len(raw) > 64<<20 {
		return errors.New("encode bounded Guarantor journal")
	}
	return fileutil.WriteFileAtomicRoot(journal.root, guarantorJournalFile, raw, 0o600)
}

func (journal *GuarantorJournal) commit(doc guarantorJournalDocument) error {
	if err := journal.persist(doc); err != nil {
		return err
	}
	journal.doc = doc
	return nil
}

func cloneGuarantorDocument(doc guarantorJournalDocument) guarantorJournalDocument {
	raw, _ := json.Marshal(doc)
	var cloned guarantorJournalDocument
	_ = json.Unmarshal(raw, &cloned)
	return cloned
}

func sameJSON(left, right interface{}) bool {
	l, _ := json.Marshal(left)
	r, _ := json.Marshal(right)
	return string(l) == string(r)
}
