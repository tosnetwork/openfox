package prediction

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
	protocol "github.com/tosnetwork/tos-service-protocol/pkg/predictionmarket"

	"github.com/tosnetwork/openfox/pkg/fileutil"
)

const (
	portfolioSchemaVersion = 1
	portfolioStateFile     = "portfolio.json"
	maximumPortfolioBytes  = 32 << 20
)

type OwnerPortfolioProfile struct {
	OwnerID                  string `json:"owner_id"`
	OwnerAddress             string `json:"owner_address"`
	NetworkDomainHash        string `json:"network_domain_hash"`
	SourceAgentAccount       string `json:"source_agent_account"`
	CollateralAssetID        string `json:"collateral_asset_id"`
	MaximumAtRiskAtomic      uint64 `json:"maximum_at_risk_atomic"`
	MaximumPositionLots      uint64 `json:"maximum_position_lots"`
	MaximumOrderReservations uint32 `json:"maximum_order_reservations"`
	MaximumMarkets           uint32 `json:"maximum_markets"`
}

type PortfolioMarketSnapshot struct {
	OwnerAddress     string
	MarketID         string
	MarketAddress    string
	MarketConfigHash string
	ContractCodeHash string
	LotPayout        uint64
	FreeBalance      uint64
	YesLots          uint64
	NoLots           uint64
	MasterchainSeqno uint64
	ObservedAt       uint64
	FinalityViewID   string
	QuorumFinalized  bool
}

type PortfolioOrderStatus string

const (
	PortfolioOrderReserved         PortfolioOrderStatus = "reserved"
	PortfolioOrderBroadcasting     PortfolioOrderStatus = "broadcasting"
	PortfolioOrderAmbiguous        PortfolioOrderStatus = "ambiguous"
	PortfolioOrderPartiallyFilled  PortfolioOrderStatus = "partially_filled"
	PortfolioOrderFilled           PortfolioOrderStatus = "filled"
	PortfolioOrderCancelConfirmed  PortfolioOrderStatus = "cancel_confirmed"
	PortfolioOrderExpiredConfirmed PortfolioOrderStatus = "expired_confirmed"
	PortfolioOrderNonceInvalidated PortfolioOrderStatus = "nonce_invalidated"
	PortfolioOrderKeyInvalidated   PortfolioOrderStatus = "key_invalidated"
)

type PositionExposure struct {
	MarketID            string           `json:"market_id"`
	MarketAddress       string           `json:"market_address"`
	MarketConfigHash    string           `json:"market_config_hash"`
	ContractCodeHash    string           `json:"contract_code_hash"`
	Outcome             protocol.Outcome `json:"outcome"`
	Lots                uint64           `json:"lots"`
	AtRiskAtomic        uint64           `json:"at_risk_atomic"`
	MasterchainSeqno    uint64           `json:"masterchain_seqno"`
	FinalityViewID      string           `json:"finality_view_id"`
	LastTransactionHash string           `json:"last_transaction_hash,omitempty"`
}

type PortfolioOrderReservation struct {
	OrderDigest              string               `json:"order_digest"`
	AgentID                  string               `json:"agent_id"`
	MarketID                 string               `json:"market_id"`
	MarketAddress            string               `json:"market_address"`
	MarketConfigHash         string               `json:"market_config_hash"`
	ContractCodeHash         string               `json:"contract_code_hash"`
	Action                   protocol.Action      `json:"action"`
	Outcome                  protocol.Outcome     `json:"outcome"`
	QuantityLots             uint64               `json:"quantity_lots"`
	FilledLots               uint64               `json:"filled_lots"`
	LimitPriceTick           uint16               `json:"limit_price_tick"`
	LotPayout                uint64               `json:"lot_payout_atomic"`
	ValidUntil               uint64               `json:"valid_until"`
	PendingCollateralAtomic  uint64               `json:"pending_collateral_atomic"`
	PendingPositionLots      uint64               `json:"pending_position_lots"`
	CumulativeSpentAtomic    uint64               `json:"cumulative_spent_atomic"`
	CumulativeProceedsAtomic uint64               `json:"cumulative_proceeds_atomic"`
	Status                   PortfolioOrderStatus `json:"status"`
	LastTransactionHash      string               `json:"last_transaction_hash,omitempty"`
	LastFinalityViewID       string               `json:"last_finality_view_id,omitempty"`
	LastMasterchainSeqno     uint64               `json:"last_masterchain_seqno,omitempty"`
}

type PortfolioFillEvidence struct {
	OrderDigest              string
	CumulativeFilledLots     uint64
	CumulativeSpentAtomic    uint64
	CumulativeProceedsAtomic uint64
	TransactionHash          string
	FinalityViewID           string
	MasterchainSeqno         uint64
	QuorumFinalized          bool
}

// PortfolioReservationProofV1 is the bounded aggregate state presented to an
// isolated signer. The signer must independently validate its owner policy and
// reject stale revisions; this receipt does not grant authority by itself.
type PortfolioReservationProofV1 struct {
	SchemaVersion           uint16 `json:"schema_version"`
	PortfolioKey            string `json:"portfolio_key"`
	Revision                uint64 `json:"revision"`
	OrderDigest             string `json:"order_digest"`
	ReservationDigest       string `json:"reservation_digest"`
	AggregateAtRiskAtomic   uint64 `json:"aggregate_at_risk_atomic"`
	AggregatePositionLots   uint64 `json:"aggregate_position_lots"`
	FinalizedProceedsAtomic uint64 `json:"finalized_proceeds_atomic"`
}

type PortfolioInactiveReason string

const (
	PortfolioInactiveCanceled    PortfolioInactiveReason = "canceled"
	PortfolioInactiveExpired     PortfolioInactiveReason = "expired"
	PortfolioInactiveNonceFloor  PortfolioInactiveReason = "nonce_floor"
	PortfolioInactiveKeyRotation PortfolioInactiveReason = "key_rotation"
)

type PortfolioInactiveEvidence struct {
	OrderDigest      string
	Reason           PortfolioInactiveReason
	ChainTime        uint64
	TransactionHash  string
	FinalityViewID   string
	MasterchainSeqno uint64
	QuorumFinalized  bool
}

type PortfolioPositionExitReason string

const (
	PortfolioPositionExitMerge        PortfolioPositionExitReason = "merge"
	PortfolioPositionExitClaim        PortfolioPositionExitReason = "claim"
	PortfolioPositionExitExternalSale PortfolioPositionExitReason = "external_sale"
)

type PortfolioPositionExitEvidence struct {
	MarketID         string
	MarketAddress    string
	MarketConfigHash string
	ContractCodeHash string
	Outcome          protocol.Outcome
	RemainingLots    uint64
	Reason           PortfolioPositionExitReason
	TransactionHash  string
	FinalityViewID   string
	MasterchainSeqno uint64
	QuorumFinalized  bool
}

type portfolioDocument struct {
	SchemaVersion           uint16                               `json:"schema_version"`
	Revision                uint64                               `json:"revision"`
	Profile                 OwnerPortfolioProfile                `json:"profile"`
	Orders                  map[string]PortfolioOrderReservation `json:"orders"`
	Positions               map[string]PositionExposure          `json:"positions"`
	FinalizedProceedsAtomic uint64                               `json:"finalized_proceeds_atomic"`
}

type OwnerPortfolioLedger struct {
	mu        sync.Mutex
	directory string
	lock      *os.File
	doc       portfolioDocument
}

// OpenOwnerPortfolioLedger derives the only storage path from the complete
// owner/network/source/asset key. AgentID is deliberately absent: every Agent
// acting for this owner contends on the same OS lock and atomic document.
func OpenOwnerPortfolioLedger(root string, profile OwnerPortfolioProfile) (*OwnerPortfolioLedger, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || validatePortfolioProfile(profile) != nil {
		return nil, errors.New("prediction owner portfolio configuration is invalid")
	}
	if err := ensurePrivateDirectory(root); err != nil {
		return nil, err
	}
	key := portfolioKey(profile)
	directory := filepath.Join(root, "owner-portfolios", key[:2], key)
	for _, path := range []string{
		filepath.Join(root, "owner-portfolios"),
		filepath.Join(root, "owner-portfolios", key[:2]),
		directory,
	} {
		if err := ensurePrivateDirectory(path); err != nil {
			return nil, err
		}
	}
	lock, err := acquireBookLock(directory)
	if err != nil {
		return nil, err
	}
	ledger := &OwnerPortfolioLedger{directory: directory, lock: lock, doc: portfolioDocument{
		SchemaVersion: portfolioSchemaVersion, Profile: profile,
		Orders: map[string]PortfolioOrderReservation{}, Positions: map[string]PositionExposure{},
	}}
	if err := ledger.loadOrInitialize(); err != nil {
		_ = releaseBookLock(lock)
		return nil, err
	}
	return ledger, nil
}

func (ledger *OwnerPortfolioLedger) Close() error {
	if ledger == nil {
		return nil
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if ledger.lock == nil {
		return nil
	}
	err := releaseBookLock(ledger.lock)
	ledger.lock = nil
	return err
}

func (ledger *OwnerPortfolioLedger) ReserveOrder(ownerID, agentID, networkDomainHash, marketID,
	contractCodeHash string,
	order protocol.PredictionOrderV1, risk WorstCaseOrderRiskV1, snapshot PortfolioMarketSnapshot,
) (PortfolioOrderReservation, PortfolioReservationProofV1, error) {
	if ledger == nil || ownerID == "" || agentID == "" || !canonicalDigest(networkDomainHash, "sha256:") ||
		!canonicalDigest(marketID, "sha256:") ||
		!canonicalDigest(contractCodeHash, "tvm-cell-sha256:") {
		return PortfolioOrderReservation{}, PortfolioReservationProofV1{},
			errors.New("prediction portfolio reservation is invalid")
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if ledger.lock == nil {
		return PortfolioOrderReservation{}, PortfolioReservationProofV1{},
			errors.New("prediction owner portfolio is closed")
	}
	if ownerID != ledger.doc.Profile.OwnerID || networkDomainHash != ledger.doc.Profile.NetworkDomainHash {
		return PortfolioOrderReservation{}, PortfolioReservationProofV1{},
			errors.New("prediction reservation is outside the owner portfolio key")
	}
	if snapshotErr := validatePortfolioMarketSnapshot(
		ledger.doc.Profile,
		marketID,
		contractCodeHash,
		order,
		snapshot,
	); snapshotErr != nil {
		return PortfolioOrderReservation{}, PortfolioReservationProofV1{}, snapshotErr
	}
	expectedRisk, riskErr := portfolioRisk(order, snapshot.LotPayout)
	if riskErr != nil || !reflect.DeepEqual(expectedRisk, risk) {
		return PortfolioOrderReservation{}, PortfolioReservationProofV1{},
			errors.New("prediction order risk does not match exact order economics")
	}
	digest := risk.OrderDigest
	if prior, ok := ledger.doc.Orders[digest]; ok {
		expected := reservationFromOrder(agentID, marketID, contractCodeHash, order, risk, snapshot)
		if !sameReservationIdentity(prior, expected) {
			return PortfolioOrderReservation{}, PortfolioReservationProofV1{},
				errors.New("prediction order reservation conflicts with durable identity")
		}
		if isPortfolioOrderTerminal(prior.Status) {
			return PortfolioOrderReservation{}, PortfolioReservationProofV1{},
				errors.New("terminal prediction order reservation cannot be reactivated")
		}
		proof, proofErr := portfolioReservationProof(ledger.doc, prior)
		return prior, proof, proofErr
	}
	if uint32(len(ledger.doc.Orders)) >= ledger.doc.Profile.MaximumOrderReservations {
		return PortfolioOrderReservation{}, PortfolioReservationProofV1{},
			errors.New("prediction owner portfolio order capacity reached")
	}
	next := clonePortfolioDocument(ledger.doc)
	if reconcileErr := reconcilePortfolioPosition(next.Positions, snapshot, protocol.OutcomeYes); reconcileErr != nil {
		return PortfolioOrderReservation{}, PortfolioReservationProofV1{}, reconcileErr
	}
	if reconcileErr := reconcilePortfolioPosition(next.Positions, snapshot, protocol.OutcomeNo); reconcileErr != nil {
		return PortfolioOrderReservation{}, PortfolioReservationProofV1{}, reconcileErr
	}
	reservation := reservationFromOrder(agentID, marketID, contractCodeHash, order, risk, snapshot)
	if capacityErr := checkPortfolioReservationCapacity(next, reservation, snapshot); capacityErr != nil {
		return PortfolioOrderReservation{}, PortfolioReservationProofV1{}, capacityErr
	}
	next.Revision++
	next.Orders[digest] = reservation
	proof, err := portfolioReservationProof(next, reservation)
	if err != nil {
		return PortfolioOrderReservation{}, PortfolioReservationProofV1{}, err
	}
	if err := ledger.persist(next); err != nil {
		return PortfolioOrderReservation{}, PortfolioReservationProofV1{}, err
	}
	ledger.doc = next
	return reservation, proof, nil
}

func (ledger *OwnerPortfolioLedger) MarkOrderBroadcastState(orderDigest string, state PortfolioOrderStatus) error {
	if ledger == nil || (state != PortfolioOrderBroadcasting && state != PortfolioOrderAmbiguous) {
		return errors.New("invalid prediction broadcast risk state")
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	reservation, ok := ledger.doc.Orders[orderDigest]
	if !ok || ledger.lock == nil || isPortfolioOrderTerminal(reservation.Status) {
		return errors.New("prediction order reservation is unavailable")
	}
	if reservation.Status == state {
		return nil
	}
	reservation.Status = state
	next := clonePortfolioDocument(ledger.doc)
	next.Revision++
	next.Orders[orderDigest] = reservation
	if err := ledger.persist(next); err != nil {
		return err
	}
	ledger.doc = next
	return nil
}

func (ledger *OwnerPortfolioLedger) ApplyFinalizedFill(evidence PortfolioFillEvidence) error {
	if ledger == nil || !evidence.QuorumFinalized || !canonicalDigest(evidence.OrderDigest, "sha256:") ||
		!canonicalDigest(evidence.TransactionHash, "sha256:") ||
		!canonicalDigest(evidence.FinalityViewID, "sha256:") || evidence.MasterchainSeqno == 0 {
		return errors.New("prediction portfolio fill evidence is not finalized")
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	reservation, ok := ledger.doc.Orders[evidence.OrderDigest]
	if !ok || ledger.lock == nil || isPortfolioOrderTerminal(reservation.Status) ||
		evidence.CumulativeFilledLots < reservation.FilledLots ||
		evidence.CumulativeFilledLots > reservation.QuantityLots ||
		evidence.CumulativeSpentAtomic < reservation.CumulativeSpentAtomic ||
		evidence.CumulativeProceedsAtomic < reservation.CumulativeProceedsAtomic {
		return errors.New("prediction fill conflicts with owner portfolio")
	}
	if evidence.CumulativeFilledLots == reservation.FilledLots {
		if evidence.CumulativeSpentAtomic != reservation.CumulativeSpentAtomic ||
			evidence.CumulativeProceedsAtomic != reservation.CumulativeProceedsAtomic ||
			evidence.TransactionHash != reservation.LastTransactionHash ||
			evidence.FinalityViewID != reservation.LastFinalityViewID ||
			evidence.MasterchainSeqno != reservation.LastMasterchainSeqno {
			return errors.New("same prediction fill has conflicting finality evidence")
		}
		return nil
	}
	next := clonePortfolioDocument(ledger.doc)
	delta := evidence.CumulativeFilledLots - reservation.FilledLots
	positionKey := portfolioPositionKey(reservation.MarketID, reservation.Outcome)
	position := next.Positions[positionKey]
	if evidence.MasterchainSeqno < position.MasterchainSeqno ||
		evidence.MasterchainSeqno < reservation.LastMasterchainSeqno {
		return errors.New("prediction fill evidence rolls back finalized portfolio state")
	}
	if reservation.Action == protocol.ActionBuy {
		maximumSpent, valid := portfolioBuyRisk(reservation.LotPayout, reservation.LimitPriceTick,
			evidence.CumulativeFilledLots)
		spentDelta := evidence.CumulativeSpentAtomic - reservation.CumulativeSpentAtomic
		if !valid || evidence.CumulativeSpentAtomic > maximumSpent || evidence.CumulativeProceedsAtomic != 0 ||
			position.Lots > ^uint64(0)-delta || position.AtRiskAtomic > ^uint64(0)-spentDelta {
			return errors.New("prediction BUY fill exceeds its reserved limit")
		}
		position.Lots += delta
		position.AtRiskAtomic += spentDelta
		remainingRisk, valid := portfolioBuyRisk(reservation.LotPayout, reservation.LimitPriceTick,
			reservation.QuantityLots-evidence.CumulativeFilledLots)
		if !valid {
			return errors.New("prediction BUY remaining risk overflows")
		}
		reservation.PendingCollateralAtomic = remainingRisk
	} else {
		if evidence.CumulativeSpentAtomic != 0 || position.Lots < delta {
			return errors.New("prediction SELL fill conflicts with realized position")
		}
		position.AtRiskAtomic = remainingPositionRisk(position.AtRiskAtomic, position.Lots, delta)
		position.Lots -= delta
		reservation.PendingPositionLots = reservation.QuantityLots - evidence.CumulativeFilledLots
		proceedsDelta := evidence.CumulativeProceedsAtomic - reservation.CumulativeProceedsAtomic
		if next.FinalizedProceedsAtomic > ^uint64(0)-proceedsDelta {
			return errors.New("prediction finalized SELL proceeds overflow")
		}
		next.FinalizedProceedsAtomic += proceedsDelta
	}
	position.MasterchainSeqno = evidence.MasterchainSeqno
	position.FinalityViewID = evidence.FinalityViewID
	position.LastTransactionHash = evidence.TransactionHash
	next.Positions[positionKey] = position
	reservation.FilledLots = evidence.CumulativeFilledLots
	reservation.CumulativeSpentAtomic = evidence.CumulativeSpentAtomic
	reservation.CumulativeProceedsAtomic = evidence.CumulativeProceedsAtomic
	reservation.LastTransactionHash = evidence.TransactionHash
	reservation.LastFinalityViewID = evidence.FinalityViewID
	reservation.LastMasterchainSeqno = evidence.MasterchainSeqno
	if reservation.FilledLots == reservation.QuantityLots {
		reservation.Status = PortfolioOrderFilled
	} else {
		reservation.Status = PortfolioOrderPartiallyFilled
	}
	next.Revision++
	next.Orders[evidence.OrderDigest] = reservation
	if validatePortfolioTotals(next) != nil {
		return errors.New("prediction fill violates owner-wide portfolio limits")
	}
	if err := ledger.persist(next); err != nil {
		return err
	}
	ledger.doc = next
	return nil
}

// ApplyFinalizedPositionExit covers position changes outside a tracked SELL
// order, such as merge and claim. It only moves realized exposure downward;
// an increase must enter through a finalized snapshot import or BUY fill.
func (ledger *OwnerPortfolioLedger) ApplyFinalizedPositionExit(evidence PortfolioPositionExitEvidence) error {
	if ledger == nil || !evidence.QuorumFinalized || !canonicalDigest(evidence.MarketID, "sha256:") ||
		!validRawAddress(evidence.MarketAddress) ||
		!canonicalDigest(evidence.MarketConfigHash, "tvm-cell-sha256:") ||
		!canonicalDigest(evidence.ContractCodeHash, "tvm-cell-sha256:") ||
		!canonicalDigest(evidence.TransactionHash, "sha256:") ||
		!canonicalDigest(evidence.FinalityViewID, "sha256:") || evidence.MasterchainSeqno == 0 ||
		(evidence.Outcome != protocol.OutcomeYes && evidence.Outcome != protocol.OutcomeNo) ||
		!validPositionExitReason(evidence.Reason) {
		return errors.New("prediction position exit evidence is not finalized")
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	key := portfolioPositionKey(evidence.MarketID, evidence.Outcome)
	position, ok := ledger.doc.Positions[key]
	if !ok || ledger.lock == nil || position.MarketAddress != evidence.MarketAddress ||
		position.MarketConfigHash != evidence.MarketConfigHash ||
		position.ContractCodeHash != evidence.ContractCodeHash || evidence.RemainingLots > position.Lots ||
		evidence.MasterchainSeqno < position.MasterchainSeqno ||
		((evidence.Reason == PortfolioPositionExitClaim) && evidence.RemainingLots != 0) {
		return errors.New("prediction position exit conflicts with owner portfolio")
	}
	if evidence.MasterchainSeqno == position.MasterchainSeqno {
		if evidence.RemainingLots == position.Lots && evidence.FinalityViewID == position.FinalityViewID &&
			evidence.TransactionHash == position.LastTransactionHash {
			return nil
		}
		return errors.New("prediction position exit conflicts at one finalized checkpoint")
	}
	exited := position.Lots - evidence.RemainingLots
	position.AtRiskAtomic = remainingPositionRisk(position.AtRiskAtomic, position.Lots, exited)
	position.Lots = evidence.RemainingLots
	position.MasterchainSeqno = evidence.MasterchainSeqno
	position.FinalityViewID = evidence.FinalityViewID
	position.LastTransactionHash = evidence.TransactionHash
	next := clonePortfolioDocument(ledger.doc)
	next.Revision++
	next.Positions[key] = position
	if err := ledger.persist(next); err != nil {
		return err
	}
	ledger.doc = next
	return nil
}

func (ledger *OwnerPortfolioLedger) ConfirmOrderInactive(evidence PortfolioInactiveEvidence) error {
	if ledger == nil || !evidence.QuorumFinalized || !canonicalDigest(evidence.OrderDigest, "sha256:") ||
		!canonicalDigest(evidence.TransactionHash, "sha256:") ||
		!canonicalDigest(evidence.FinalityViewID, "sha256:") || evidence.MasterchainSeqno == 0 {
		return errors.New("prediction inactive-order evidence is not finalized")
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	reservation, ok := ledger.doc.Orders[evidence.OrderDigest]
	if !ok || ledger.lock == nil || reservation.Status == PortfolioOrderFilled {
		return errors.New("prediction order cannot release pending risk")
	}
	status, err := inactiveStatus(evidence.Reason)
	if err != nil || (evidence.Reason == PortfolioInactiveExpired && evidence.ChainTime < reservation.ValidUntil) {
		return errors.New("prediction order inactivity is not proven")
	}
	if isPortfolioOrderTerminal(reservation.Status) {
		if reservation.Status != status || reservation.LastTransactionHash != evidence.TransactionHash ||
			reservation.LastFinalityViewID != evidence.FinalityViewID ||
			reservation.LastMasterchainSeqno != evidence.MasterchainSeqno {
			return errors.New("terminal prediction order received conflicting evidence")
		}
		return nil
	}
	if evidence.MasterchainSeqno < reservation.LastMasterchainSeqno {
		return errors.New("prediction inactivity evidence rolls back finalized state")
	}
	reservation.PendingCollateralAtomic = 0
	reservation.PendingPositionLots = 0
	reservation.Status = status
	reservation.LastTransactionHash = evidence.TransactionHash
	reservation.LastFinalityViewID = evidence.FinalityViewID
	reservation.LastMasterchainSeqno = evidence.MasterchainSeqno
	next := clonePortfolioDocument(ledger.doc)
	next.Revision++
	next.Orders[evidence.OrderDigest] = reservation
	if err := ledger.persist(next); err != nil {
		return err
	}
	ledger.doc = next
	return nil
}

func (ledger *OwnerPortfolioLedger) Snapshot() ([]PortfolioOrderReservation, []PositionExposure) {
	if ledger == nil {
		return nil, nil
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	orders := make([]PortfolioOrderReservation, 0, len(ledger.doc.Orders))
	for _, reservation := range ledger.doc.Orders {
		orders = append(orders, reservation)
	}
	positions := make([]PositionExposure, 0, len(ledger.doc.Positions))
	for _, position := range ledger.doc.Positions {
		positions = append(positions, position)
	}
	sort.Slice(orders, func(i, j int) bool { return orders[i].OrderDigest < orders[j].OrderDigest })
	sort.Slice(positions, func(i, j int) bool {
		return portfolioPositionKey(positions[i].MarketID, positions[i].Outcome) <
			portfolioPositionKey(positions[j].MarketID, positions[j].Outcome)
	})
	return orders, positions
}

type OwnerPortfolioSummary struct {
	Revision                uint64
	AggregateAtRiskAtomic   uint64
	AggregatePositionLots   uint64
	FinalizedProceedsAtomic uint64
}

func (ledger *OwnerPortfolioLedger) Summary() OwnerPortfolioSummary {
	if ledger == nil {
		return OwnerPortfolioSummary{}
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	atRisk, lots, valid := portfolioTotals(ledger.doc)
	if ledger.lock == nil || !valid {
		return OwnerPortfolioSummary{}
	}
	return OwnerPortfolioSummary{
		Revision: ledger.doc.Revision, AggregateAtRiskAtomic: atRisk,
		AggregatePositionLots: lots, FinalizedProceedsAtomic: ledger.doc.FinalizedProceedsAtomic,
	}
}

func validatePortfolioProfile(profile OwnerPortfolioProfile) error {
	if profile.OwnerID == "" || !validRawAddress(profile.OwnerAddress) ||
		!canonicalDigest(profile.NetworkDomainHash, "sha256:") || !validRawAddress(profile.SourceAgentAccount) ||
		!canonicalDigest(profile.CollateralAssetID, "sha256:") || profile.MaximumAtRiskAtomic == 0 ||
		profile.MaximumPositionLots == 0 || profile.MaximumOrderReservations == 0 ||
		profile.MaximumOrderReservations > 10_000 || profile.MaximumMarkets == 0 || profile.MaximumMarkets > 1_000 {
		return errors.New("invalid prediction owner portfolio profile")
	}
	return nil
}

func validatePortfolioMarketSnapshot(profile OwnerPortfolioProfile, marketID, codeHash string,
	order protocol.PredictionOrderV1, snapshot PortfolioMarketSnapshot,
) error {
	if !snapshot.QuorumFinalized ||
		snapshot.OwnerAddress != profile.OwnerAddress ||
		snapshot.OwnerAddress != order.OwnerAddress ||
		snapshot.MarketID != marketID ||
		snapshot.MarketAddress != order.MarketAddress ||
		snapshot.MarketConfigHash != order.MarketConfigHash.CellHashString() ||
		snapshot.ContractCodeHash != codeHash ||
		snapshot.LotPayout == 0 ||
		snapshot.MasterchainSeqno == 0 ||
		snapshot.ObservedAt == 0 ||
		!canonicalDigest(snapshot.FinalityViewID, "sha256:") {
		return errors.New("prediction portfolio snapshot is not finalized in the exact market domain")
	}
	return nil
}

func portfolioRisk(order protocol.PredictionOrderV1, lotPayout uint64) (WorstCaseOrderRiskV1, error) {
	orderCell, err := protocol.BuildPredictionOrderCell(order)
	if err != nil {
		return WorstCaseOrderRiskV1{}, err
	}
	digest, err := protocol.PredictionOrderDigest(orderCell)
	if err != nil {
		return WorstCaseOrderRiskV1{}, err
	}
	risk := WorstCaseOrderRiskV1{
		SchemaVersion: 1, OrderDigest: digest.SHA256String(),
		OwnerAddress: order.OwnerAddress, MarketAddress: order.MarketAddress, Action: order.Action,
		Outcome: order.Outcome, QuantityLots: order.QuantityLots,
	}
	if order.Action == protocol.ActionBuy {
		value, valid := portfolioBuyRisk(lotPayout, order.LimitPriceTick, order.QuantityLots)
		if !valid {
			return WorstCaseOrderRiskV1{}, errors.New("prediction order portfolio risk overflows")
		}
		risk.CollateralDebit = value
	} else {
		risk.PositionDebit = order.QuantityLots
	}
	return risk, nil
}

func reservationFromOrder(agentID, marketID, codeHash string, order protocol.PredictionOrderV1,
	risk WorstCaseOrderRiskV1, snapshot PortfolioMarketSnapshot,
) PortfolioOrderReservation {
	return PortfolioOrderReservation{
		OrderDigest: risk.OrderDigest, AgentID: agentID, MarketID: marketID,
		MarketAddress: order.MarketAddress, MarketConfigHash: order.MarketConfigHash.CellHashString(),
		ContractCodeHash: codeHash, Action: order.Action, Outcome: order.Outcome,
		QuantityLots: order.QuantityLots, LimitPriceTick: order.LimitPriceTick, LotPayout: snapshot.LotPayout,
		ValidUntil: order.ValidUntil, PendingCollateralAtomic: risk.CollateralDebit,
		PendingPositionLots: risk.PositionDebit, Status: PortfolioOrderReserved,
	}
}

func sameReservationIdentity(left, right PortfolioOrderReservation) bool {
	left.FilledLots, right.FilledLots = 0, 0
	left.PendingCollateralAtomic, right.PendingCollateralAtomic = 0, 0
	left.PendingPositionLots, right.PendingPositionLots = 0, 0
	left.CumulativeSpentAtomic, right.CumulativeSpentAtomic = 0, 0
	left.CumulativeProceedsAtomic, right.CumulativeProceedsAtomic = 0, 0
	left.Status, right.Status = PortfolioOrderReserved, PortfolioOrderReserved
	left.LastTransactionHash, right.LastTransactionHash = "", ""
	left.LastFinalityViewID, right.LastFinalityViewID = "", ""
	left.LastMasterchainSeqno, right.LastMasterchainSeqno = 0, 0
	return reflect.DeepEqual(left, right)
}

func reconcilePortfolioPosition(positions map[string]PositionExposure, snapshot PortfolioMarketSnapshot,
	outcome protocol.Outcome,
) error {
	key := portfolioPositionKey(snapshot.MarketID, outcome)
	position, exists := positions[key]
	lots := snapshot.YesLots
	if outcome == protocol.OutcomeNo {
		lots = snapshot.NoLots
	}
	if exists && (position.MarketAddress != snapshot.MarketAddress ||
		position.MarketConfigHash != snapshot.MarketConfigHash || position.ContractCodeHash != snapshot.ContractCodeHash) {
		return errors.New("prediction position market identity changed")
	}
	if exists && snapshot.MasterchainSeqno < position.MasterchainSeqno {
		return errors.New("prediction position snapshot rolls back finalized state")
	}
	if exists && snapshot.MasterchainSeqno == position.MasterchainSeqno &&
		(lots != position.Lots || snapshot.FinalityViewID != position.FinalityViewID) {
		return errors.New("prediction position snapshot conflicts at one finalized checkpoint")
	}
	if exists && lots < position.Lots {
		return errors.New("prediction position decreased without exact finalized fill/exit evidence")
	}
	if !exists {
		position = PositionExposure{
			MarketID: snapshot.MarketID, MarketAddress: snapshot.MarketAddress,
			MarketConfigHash: snapshot.MarketConfigHash, ContractCodeHash: snapshot.ContractCodeHash, Outcome: outcome,
		}
	}
	delta := lots - position.Lots
	if delta != 0 {
		additional, valid := multiplyUint64(delta, snapshot.LotPayout)
		if !valid || position.AtRiskAtomic > ^uint64(0)-additional {
			return errors.New("prediction imported position risk overflows")
		}
		position.Lots = lots
		position.AtRiskAtomic += additional
	}
	if snapshot.MasterchainSeqno >= position.MasterchainSeqno {
		position.MasterchainSeqno = snapshot.MasterchainSeqno
		position.FinalityViewID = snapshot.FinalityViewID
	}
	positions[key] = position
	return nil
}

func checkPortfolioReservationCapacity(document portfolioDocument, reservation PortfolioOrderReservation,
	snapshot PortfolioMarketSnapshot,
) error {
	markets := map[string]struct{}{reservation.MarketID: {}}
	pendingMarketBuy := reservation.PendingCollateralAtomic
	pendingMarketSell := reservation.PendingPositionLots
	for _, prior := range document.Orders {
		markets[prior.MarketID] = struct{}{}
		if isPortfolioOrderTerminal(prior.Status) || prior.MarketID != reservation.MarketID {
			continue
		}
		if prior.Action == protocol.ActionBuy {
			if pendingMarketBuy > ^uint64(0)-prior.PendingCollateralAtomic {
				return errors.New("prediction pending collateral overflows")
			}
			pendingMarketBuy += prior.PendingCollateralAtomic
		} else if prior.Outcome == reservation.Outcome {
			if pendingMarketSell > ^uint64(0)-prior.PendingPositionLots {
				return errors.New("prediction pending position overflows")
			}
			pendingMarketSell += prior.PendingPositionLots
		}
	}
	if uint32(len(markets)) > document.Profile.MaximumMarkets {
		return errors.New("prediction owner portfolio market capacity reached")
	}
	if reservation.Action == protocol.ActionBuy && pendingMarketBuy > snapshot.FreeBalance {
		return errors.New("prediction owner has insufficient unreserved market collateral")
	}
	availablePosition := snapshot.YesLots
	if reservation.Outcome == protocol.OutcomeNo {
		availablePosition = snapshot.NoLots
	}
	if reservation.Action == protocol.ActionSell && pendingMarketSell > availablePosition {
		return errors.New("prediction owner has insufficient unreserved market position")
	}
	document.Orders[reservation.OrderDigest] = reservation
	return validatePortfolioTotals(document)
}

func validatePortfolioTotals(document portfolioDocument) error {
	atRisk, positionLots, valid := portfolioTotals(document)
	if !valid {
		return errors.New("prediction portfolio totals overflow")
	}
	if atRisk > document.Profile.MaximumAtRiskAtomic || positionLots > document.Profile.MaximumPositionLots {
		return errors.New("prediction owner-wide portfolio limit exceeded")
	}
	return nil
}

func portfolioTotals(document portfolioDocument) (uint64, uint64, bool) {
	atRisk, positionLots := uint64(0), uint64(0)
	for _, position := range document.Positions {
		if atRisk > ^uint64(0)-position.AtRiskAtomic || positionLots > ^uint64(0)-position.Lots {
			return 0, 0, false
		}
		atRisk += position.AtRiskAtomic
		positionLots += position.Lots
	}
	for _, reservation := range document.Orders {
		if isPortfolioOrderTerminal(reservation.Status) {
			continue
		}
		if atRisk > ^uint64(0)-reservation.PendingCollateralAtomic {
			return 0, 0, false
		}
		atRisk += reservation.PendingCollateralAtomic
	}
	return atRisk, positionLots, true
}

func portfolioReservationProof(document portfolioDocument,
	reservation PortfolioOrderReservation,
) (PortfolioReservationProofV1, error) {
	reservationDigest, err := codec.Digest("tos.prediction.owner-portfolio-reservation.v1", reservation)
	if err != nil {
		return PortfolioReservationProofV1{}, err
	}
	atRisk, positionLots, valid := portfolioTotals(document)
	if !valid {
		return PortfolioReservationProofV1{}, errors.New("prediction portfolio totals overflow")
	}
	return PortfolioReservationProofV1{
		SchemaVersion: portfolioSchemaVersion, PortfolioKey: "sha256:" + portfolioKey(document.Profile),
		Revision: document.Revision, OrderDigest: reservation.OrderDigest, ReservationDigest: reservationDigest,
		AggregateAtRiskAtomic: atRisk, AggregatePositionLots: positionLots,
		FinalizedProceedsAtomic: document.FinalizedProceedsAtomic,
	}, nil
}

func validPositionExitReason(reason PortfolioPositionExitReason) bool {
	return reason == PortfolioPositionExitMerge || reason == PortfolioPositionExitClaim ||
		reason == PortfolioPositionExitExternalSale
}

func portfolioBuyRisk(lotPayout uint64, price uint16, quantity uint64) (uint64, bool) {
	if lotPayout == 0 || lotPayout%uint64(protocol.PriceScale) != 0 || price == 0 ||
		price >= protocol.PriceScale {
		return 0, false
	}
	unit := lotPayout / uint64(protocol.PriceScale)
	base, valid := multiplyUint64(unit, uint64(price))
	if !valid {
		return 0, false
	}
	return multiplyUint64(base, quantity)
}

func multiplyUint64(left, right uint64) (uint64, bool) {
	if right != 0 && left > ^uint64(0)/right {
		return 0, false
	}
	return left * right, true
}

func remainingPositionRisk(atRisk, lots, sold uint64) uint64 {
	if sold >= lots {
		return 0
	}
	// Floor the released share, leaving rounding dust at risk. This is
	// deliberately conservative and converges to zero only on a full exit.
	released := (atRisk / lots) * sold
	return atRisk - released
}

func inactiveStatus(reason PortfolioInactiveReason) (PortfolioOrderStatus, error) {
	switch reason {
	case PortfolioInactiveCanceled:
		return PortfolioOrderCancelConfirmed, nil
	case PortfolioInactiveExpired:
		return PortfolioOrderExpiredConfirmed, nil
	case PortfolioInactiveNonceFloor:
		return PortfolioOrderNonceInvalidated, nil
	case PortfolioInactiveKeyRotation:
		return PortfolioOrderKeyInvalidated, nil
	default:
		return "", errors.New("unknown prediction inactivity reason")
	}
}

func isPortfolioOrderTerminal(status PortfolioOrderStatus) bool {
	return status == PortfolioOrderFilled || status == PortfolioOrderCancelConfirmed ||
		status == PortfolioOrderExpiredConfirmed || status == PortfolioOrderNonceInvalidated ||
		status == PortfolioOrderKeyInvalidated
}

func portfolioPositionKey(marketID string, outcome protocol.Outcome) string {
	return marketID + ":" + strconv.FormatUint(uint64(outcome), 10)
}

func portfolioKey(profile OwnerPortfolioProfile) string {
	material := strings.Join([]string{
		profile.OwnerID, profile.OwnerAddress, profile.NetworkDomainHash,
		profile.SourceAgentAccount, profile.CollateralAssetID,
	}, "\x00")
	digest := sha256.Sum256([]byte(material))
	return hex.EncodeToString(digest[:])
}

func ensurePrivateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errors.New("prediction portfolio path is not an owner-private directory")
	}
	return nil
}

func (ledger *OwnerPortfolioLedger) loadOrInitialize() error {
	path := filepath.Join(ledger.directory, portfolioStateFile)
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return ledger.persist(ledger.doc)
	}
	if err != nil || len(raw) > maximumPortfolioBytes {
		return errors.New("prediction owner portfolio state is unavailable")
	}
	var loaded portfolioDocument
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&loaded) != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		validatePortfolioDocument(loaded, ledger.doc.Profile) != nil {
		return errors.New("prediction owner portfolio state is corrupt")
	}
	ledger.doc = loaded
	return nil
}

func validatePortfolioDocument(document portfolioDocument, profile OwnerPortfolioProfile) error {
	if document.SchemaVersion != portfolioSchemaVersion || !reflect.DeepEqual(document.Profile, profile) ||
		document.Orders == nil || document.Positions == nil ||
		uint32(len(document.Orders)) > profile.MaximumOrderReservations {
		return errors.New("invalid prediction portfolio document shape")
	}
	markets := make(map[string]struct{})
	for digest, reservation := range document.Orders {
		if digest != reservation.OrderDigest || !canonicalDigest(digest, "sha256:") ||
			reservation.AgentID == "" || !canonicalDigest(reservation.MarketID, "sha256:") ||
			!validRawAddress(reservation.MarketAddress) ||
			!canonicalDigest(reservation.MarketConfigHash, "tvm-cell-sha256:") ||
			!canonicalDigest(reservation.ContractCodeHash, "tvm-cell-sha256:") ||
			reservation.QuantityLots == 0 || reservation.FilledLots > reservation.QuantityLots ||
			reservation.ValidUntil == 0 || reservation.LotPayout == 0 ||
			!validPortfolioOrderStatus(reservation.Status) {
			return errors.New("invalid prediction order reservation")
		}
		if (reservation.Action != protocol.ActionBuy && reservation.Action != protocol.ActionSell) ||
			(reservation.Outcome != protocol.OutcomeYes && reservation.Outcome != protocol.OutcomeNo) ||
			(reservation.LastMasterchainSeqno == 0) != (reservation.LastTransactionHash == "") ||
			(reservation.LastMasterchainSeqno == 0) != (reservation.LastFinalityViewID == "") ||
			(reservation.LastTransactionHash != "" &&
				!canonicalDigest(reservation.LastTransactionHash, "sha256:")) ||
			(reservation.LastFinalityViewID != "" &&
				!canonicalDigest(reservation.LastFinalityViewID, "sha256:")) {
			return errors.New("prediction order reservation has invalid semantic state")
		}
		remaining := reservation.QuantityLots - reservation.FilledLots
		if reservation.Action == protocol.ActionBuy {
			maximumPending, valid := portfolioBuyRisk(
				reservation.LotPayout,
				reservation.LimitPriceTick,
				remaining,
			)
			if !valid || reservation.PendingCollateralAtomic > maximumPending ||
				reservation.PendingPositionLots != 0 || reservation.CumulativeProceedsAtomic != 0 {
				return errors.New("prediction BUY reservation has invalid risk state")
			}
		} else if reservation.PendingCollateralAtomic != 0 || reservation.PendingPositionLots > remaining ||
			reservation.CumulativeSpentAtomic != 0 {
			return errors.New("prediction SELL reservation has invalid risk state")
		}
		if isPortfolioOrderTerminal(reservation.Status) &&
			(reservation.PendingCollateralAtomic != 0 || reservation.PendingPositionLots != 0) {
			return errors.New("terminal prediction order retains pending risk")
		}
		if (reservation.Status == PortfolioOrderFilled) != (reservation.FilledLots == reservation.QuantityLots) {
			return errors.New("prediction filled status conflicts with quantity")
		}
		markets[reservation.MarketID] = struct{}{}
	}
	for key, position := range document.Positions {
		if err := validatePositionExposure(key, position); err != nil {
			return err
		}
		markets[position.MarketID] = struct{}{}
	}
	if uint32(len(markets)) > profile.MaximumMarkets || validatePortfolioTotals(document) != nil {
		return errors.New("prediction portfolio document exceeds limits")
	}
	return nil
}

func validatePositionExposure(key string, position PositionExposure) error {
	if key != portfolioPositionKey(position.MarketID, position.Outcome) {
		return errors.New("prediction position key does not match its identity")
	}
	if !canonicalDigest(position.MarketID, "sha256:") || !validRawAddress(position.MarketAddress) ||
		!canonicalDigest(position.MarketConfigHash, "tvm-cell-sha256:") ||
		!canonicalDigest(position.ContractCodeHash, "tvm-cell-sha256:") {
		return errors.New("prediction position market identity is invalid")
	}
	if (position.MasterchainSeqno == 0) != (position.FinalityViewID == "") ||
		(position.FinalityViewID != "" && !canonicalDigest(position.FinalityViewID, "sha256:")) ||
		(position.LastTransactionHash != "" && !canonicalDigest(position.LastTransactionHash, "sha256:")) {
		return fmt.Errorf("prediction position finality identity is invalid: seqno=%d view=%q",
			position.MasterchainSeqno, position.FinalityViewID)
	}
	return nil
}

func validPortfolioOrderStatus(status PortfolioOrderStatus) bool {
	switch status {
	case PortfolioOrderReserved, PortfolioOrderBroadcasting, PortfolioOrderAmbiguous,
		PortfolioOrderPartiallyFilled, PortfolioOrderFilled, PortfolioOrderCancelConfirmed,
		PortfolioOrderExpiredConfirmed, PortfolioOrderNonceInvalidated, PortfolioOrderKeyInvalidated:
		return true
	default:
		return false
	}
}

func (ledger *OwnerPortfolioLedger) persist(document portfolioDocument) error {
	if err := validatePortfolioDocument(document, ledger.doc.Profile); err != nil {
		return fmt.Errorf("refuse to persist invalid prediction owner portfolio: %w", err)
	}
	raw, err := json.Marshal(document)
	if err != nil || len(raw) > maximumPortfolioBytes {
		return errors.New("prediction owner portfolio exceeds its durable bound")
	}
	return fileutil.WriteFileAtomic(filepath.Join(ledger.directory, portfolioStateFile), raw, 0o600)
}

func clonePortfolioDocument(value portfolioDocument) portfolioDocument {
	next := value
	next.Orders = make(map[string]PortfolioOrderReservation, len(value.Orders))
	for key, reservation := range value.Orders {
		next.Orders[key] = reservation
	}
	next.Positions = make(map[string]PositionExposure, len(value.Positions))
	for key, position := range value.Positions {
		next.Positions[key] = position
	}
	return next
}
