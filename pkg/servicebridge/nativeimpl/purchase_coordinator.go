package nativeimpl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/tosnetwork/openfox/pkg/fileutil"
	"github.com/tosnetwork/openfox/pkg/opportunity"
)

const purchaseCoordinatorSchema = "tos.openfox.purchase-coordinator-journal.v1"

var ErrPurchasePolicyRejected = errors.New("nativeimpl: purchase rejected before custody")

type PreparedOpportunityQuote struct {
	Candidate       opportunity.CandidateKey `json:"candidate"`
	ArtifactDigest  string                   `json:"artifact_digest"`
	AssetMaster     string                   `json:"asset_master"`
	AtomicAmount    string                   `json:"atomic_amount"`
	QuoteExpiryUnix int64                    `json:"quote_expiry_unix"`
}

type PurchaseSettlement struct {
	AuthoritativePhase  string
	FinalizedCheckpoint uint64
	Released            bool
	Refunded            bool
}

// OpportunityPurchaseBackend owns all protocol and custody-bearing work. Its
// artifact digest is a durable opaque handle; OpenFox never receives Quote
// preimages, transaction bodies, keys, routes, or signatures.
type OpportunityPurchaseBackend interface {
	Prepare(context.Context, string, opportunity.VerifiedCandidate) (PreparedOpportunityQuote, error)
	Authorize(context.Context, string, PreparedOpportunityQuote) error
	Reference(context.Context, string, PreparedOpportunityQuote) (opportunity.PurchaseKey, string, error)
	Reconcile(context.Context, string, PreparedOpportunityQuote, opportunity.PurchaseKey) (PurchaseSettlement, error)
}

type purchaseCoordinatorRecord struct {
	IntentID           string                    `json:"intent_id"`
	Phase              opportunity.Phase         `json:"phase"`
	Prepared           *PreparedOpportunityQuote `json:"prepared,omitempty"`
	Key                *opportunity.PurchaseKey  `json:"purchase_key,omitempty"`
	AuthoritativePhase string                    `json:"authoritative_purchase_phase,omitempty"`
}

type purchaseCoordinatorDocument struct {
	Schema  string                      `json:"schema"`
	Records []purchaseCoordinatorRecord `json:"records"`
}

type PurchaseCoordinator struct {
	mu      sync.Mutex
	path    string
	backend OpportunityPurchaseBackend
	records map[string]purchaseCoordinatorRecord
}

func OpenPurchaseCoordinator(directory string, backend OpportunityPurchaseBackend) (*PurchaseCoordinator, error) {
	if backend == nil || !ownerDirectory(directory) {
		return nil, errors.New("nativeimpl: purchase coordinator needs an owner-private state directory and backend")
	}
	coordinator := &PurchaseCoordinator{path: filepath.Join(directory, "purchase-coordinator.json"), backend: backend,
		records: map[string]purchaseCoordinatorRecord{}}
	if err := coordinator.load(); err != nil {
		return nil, err
	}
	return coordinator, nil
}

func (c *PurchaseCoordinator) AdvancePurchase(ctx context.Context, request opportunity.PurchaseRequest) (opportunity.PurchaseProgress, error) {
	if c == nil || ctx == nil {
		return opportunity.PurchaseProgress{}, errors.New("nativeimpl: invalid purchase advance")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	record, exists := c.records[request.IntentID]
	if exists && (record.IntentID != request.IntentID || record.Phase != request.Current || record.Prepared == nil ||
		record.Prepared.Candidate != request.Candidate.Key || !samePurchaseKey(record.Key, request.Key)) {
		return opportunity.PurchaseProgress{}, errors.New("nativeimpl: purchase resume identity conflicts with durable state")
	}
	if !exists && request.Current != opportunity.PhaseQuoteRequested {
		return opportunity.PurchaseProgress{}, errors.New("nativeimpl: purchase intent has no durable Quote request")
	}

	var err error
	switch request.Current {
	case opportunity.PhaseQuoteRequested:
		prepared, prepareErr := c.backend.Prepare(ctx, request.IntentID, request.Candidate)
		if prepareErr != nil {
			return opportunity.PurchaseProgress{}, classifyPreFunding(prepareErr)
		}
		if !validPreparedQuote(prepared) || prepared.Candidate != request.Candidate.Key {
			return opportunity.PurchaseProgress{}, errors.New("nativeimpl: purchase backend returned an invalid Quote projection")
		}
		record = purchaseCoordinatorRecord{IntentID: request.IntentID, Phase: opportunity.PhaseQuoteVerified, Prepared: &prepared}
	case opportunity.PhaseQuoteVerified:
		if err = c.backend.Authorize(ctx, request.IntentID, *record.Prepared); err != nil {
			return opportunity.PurchaseProgress{}, classifyPreFunding(err)
		}
		record.Phase = opportunity.PhasePolicyAuthorized
	case opportunity.PhasePolicyAuthorized:
		var key opportunity.PurchaseKey
		key, record.AuthoritativePhase, err = c.backend.Reference(ctx, request.IntentID, *record.Prepared)
		if err != nil {
			return opportunity.PurchaseProgress{}, classifyPreFunding(err)
		}
		if !validNativePurchaseKey(key) || record.AuthoritativePhase == "" {
			return opportunity.PurchaseProgress{}, errors.New("nativeimpl: purchase backend returned an invalid payment identity")
		}
		record.Key = &key
		record.Phase = opportunity.PhasePurchaseReferenced
	case opportunity.PhasePurchaseReferenced:
		settlement, reconcileErr := c.backend.Reconcile(ctx, request.IntentID, *record.Prepared, *record.Key)
		if reconcileErr != nil {
			return opportunity.PurchaseProgress{}, reconcileErr
		}
		if settlement.AuthoritativePhase == "" {
			return opportunity.PurchaseProgress{}, errors.New("nativeimpl: purchase backend returned no authoritative phase")
		}
		record.AuthoritativePhase = settlement.AuthoritativePhase
		if settlement.Released || settlement.Refunded {
			if settlement.Released == settlement.Refunded || settlement.FinalizedCheckpoint == 0 || settlement.AuthoritativePhase != "resolved" {
				return opportunity.PurchaseProgress{}, errors.New("nativeimpl: purchase backend returned invalid terminal settlement")
			}
			record.Phase = opportunity.PhasePurchaseResolved
		}
		if err := c.persistRecord(record); err != nil {
			return opportunity.PurchaseProgress{}, err
		}
		return progressForRecord(record, settlement), nil
	default:
		return opportunity.PurchaseProgress{}, errors.New("nativeimpl: purchase phase cannot advance")
	}
	if err := c.persistRecord(record); err != nil {
		return opportunity.PurchaseProgress{}, err
	}
	return progressForRecord(record, PurchaseSettlement{}), nil
}

func (c *PurchaseCoordinator) persistRecord(record purchaseCoordinatorRecord) error {
	updated := make(map[string]purchaseCoordinatorRecord, len(c.records)+1)
	for key, value := range c.records {
		updated[key] = clonePurchaseCoordinatorRecord(value)
	}
	updated[record.IntentID] = clonePurchaseCoordinatorRecord(record)
	if err := c.persist(updated); err != nil {
		return err
	}
	c.records = updated
	return nil
}

func (c *PurchaseCoordinator) load() error {
	info, err := os.Lstat(c.path)
	if errors.Is(err, os.ErrNotExist) {
		return c.persist(c.records)
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 ||
		info.Size() <= 0 || info.Size() > 16<<20 {
		return errors.New("nativeimpl: invalid purchase coordinator journal file")
	}
	raw, err := os.ReadFile(c.path)
	if err != nil {
		return err
	}
	var document purchaseCoordinatorDocument
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&document) != nil || document.Schema != purchaseCoordinatorSchema {
		return errors.New("nativeimpl: invalid purchase coordinator journal")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("nativeimpl: trailing purchase coordinator journal data")
	}
	for _, record := range document.Records {
		if !validPurchaseCoordinatorRecord(record) || c.records[record.IntentID].IntentID != "" {
			return errors.New("nativeimpl: invalid or duplicate purchase coordinator record")
		}
		c.records[record.IntentID] = clonePurchaseCoordinatorRecord(record)
	}
	return nil
}

func (c *PurchaseCoordinator) persist(records map[string]purchaseCoordinatorRecord) error {
	document := purchaseCoordinatorDocument{Schema: purchaseCoordinatorSchema, Records: make([]purchaseCoordinatorRecord, 0, len(records))}
	for _, record := range records {
		document.Records = append(document.Records, clonePurchaseCoordinatorRecord(record))
	}
	sort.Slice(document.Records, func(i, j int) bool { return document.Records[i].IntentID < document.Records[j].IntentID })
	raw, err := json.Marshal(document)
	if err != nil || len(raw) > 16<<20 {
		return errors.New("nativeimpl: encode purchase coordinator journal")
	}
	return fileutil.WriteFileAtomic(c.path, raw, 0o600)
}

func progressForRecord(record purchaseCoordinatorRecord, settlement PurchaseSettlement) opportunity.PurchaseProgress {
	progress := opportunity.PurchaseProgress{IntentID: record.IntentID, CandidateKey: record.Prepared.Candidate,
		Phase: record.Phase, AssetMaster: record.Prepared.AssetMaster, AtomicAmount: record.Prepared.AtomicAmount,
		QuoteExpiryUnix: record.Prepared.QuoteExpiryUnix, AuthoritativePhase: record.AuthoritativePhase,
		FinalizedCheckpoint: settlement.FinalizedCheckpoint, Released: settlement.Released, Refunded: settlement.Refunded}
	if record.Key != nil {
		key := *record.Key
		progress.Key = &key
	}
	return progress
}

func validPreparedQuote(value PreparedOpportunityQuote) bool {
	return strings.HasPrefix(value.Candidate.CapabilityID, "cap_") && hexDigest(value.ArtifactDigest, "sha256:") &&
		isRawWorkchainZero(value.AssetMaster) && validPositiveDecimal(value.AtomicAmount) && value.QuoteExpiryUnix > 0
}

func validNativePurchaseKey(key opportunity.PurchaseKey) bool {
	return hexDigest(key.QuoteCommitment, "tvm-cell-sha256:") && isRawWorkchainZero(key.EscrowAddress)
}

func validPositiveDecimal(value string) bool {
	if value == "" || len(value) > 78 || value[0] == '0' {
		return false
	}
	for _, digit := range value {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return true
}

func validPurchaseCoordinatorRecord(record purchaseCoordinatorRecord) bool {
	if record.IntentID == "" || record.Prepared == nil || !validPreparedQuote(*record.Prepared) {
		return false
	}
	switch record.Phase {
	case opportunity.PhaseQuoteVerified, opportunity.PhasePolicyAuthorized:
		return record.Key == nil && record.AuthoritativePhase == ""
	case opportunity.PhasePurchaseReferenced, opportunity.PhasePurchaseResolved:
		return record.Key != nil && validNativePurchaseKey(*record.Key) && record.AuthoritativePhase != ""
	default:
		return false
	}
}

func samePurchaseKey(left, right *opportunity.PurchaseKey) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func clonePurchaseCoordinatorRecord(record purchaseCoordinatorRecord) purchaseCoordinatorRecord {
	if record.Prepared != nil {
		prepared := *record.Prepared
		record.Prepared = &prepared
	}
	if record.Key != nil {
		key := *record.Key
		record.Key = &key
	}
	return record
}

func classifyPreFunding(err error) error {
	if errors.Is(err, ErrPurchasePolicyRejected) {
		return &opportunity.PurchaseRejection{Reason: "Quote or exact signed owner policy rejected the purchase"}
	}
	return err
}

var _ opportunity.PurchaseRunner = (*PurchaseCoordinator)(nil)
