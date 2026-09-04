// Package prediction provides OpenFox's bounded off-chain coordination layer
// for TOS PredictionMarket V1. It never substitutes an Intent for the exact
// trading-key signature enforced by the market contract.
package prediction

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"

	protocol "github.com/tosnetwork/tos-service-protocol/pkg/predictionmarket"
	"github.com/tosnetwork/tosutils-go/address"
	"github.com/tosnetwork/tosutils-go/tvm/cell"

	"github.com/tosnetwork/openfox/pkg/fileutil"
)

const stateFile = "book.json"

type MarketProfile struct {
	GlobalID          int32  `json:"global_id"`
	WorkchainID       int8   `json:"workchain_id"`
	NetworkDomainHash string `json:"network_domain_hash"`
	MarketID          string `json:"market_id"`
	MarketAddress     string `json:"market_address"`
	MarketConfigHash  string `json:"market_config_hash"`
	ContractCodeHash  string `json:"contract_code_hash"`
	TradeClose        uint64 `json:"trade_close"`
	LotPayout         uint64 `json:"lot_payout"`
	MarketMinFillLots uint64 `json:"market_min_fill_lots"`
	MaxOrders         uint32 `json:"max_orders"`
	MaxOrdersPerOwner uint32 `json:"max_orders_per_owner"`
	MaxSnapshotAge    uint64 `json:"max_snapshot_age_seconds"`
}

type ChainAccountSnapshot struct {
	OwnerAddress     string
	TradingPublicKey [ed25519.PublicKeySize]byte
	KeyEpoch         uint32
	NonceFloor       uint64
	FreeBalance      uint64
	YesLots          uint64
	NoLots           uint64
	ObservedAt       uint64
	MasterchainSeqno uint64
	Finalized        bool
	MarketConfigHash string
	FinalityViewID   string
}

// ChainMarketSnapshot is one finalized, internally consistent market view.
// Accounts must contain every registered participant so the protocol
// reference model can prove global position supply and backing conservation.
type ChainMarketSnapshot struct {
	CompleteSets     uint64
	LockedCollateral uint64
	Accounts         map[string]protocol.AccountBalance
	ObservedAt       uint64
	Finalized        bool
	MarketConfigHash string
	ContractCodeHash string
	FinalityViewID   string
}

type OrderStatus string

const (
	OrderLive     OrderStatus = "live"
	OrderFilled   OrderStatus = "filled"
	OrderCanceled OrderStatus = "canceled"
)

type OrderRecord struct {
	Digest              string                     `json:"digest"`
	OrderCellHash       string                     `json:"order_cell_hash"`
	TradingPublicKey    string                     `json:"trading_public_key"`
	SignedOrderBOC      string                     `json:"signed_order_boc_base64"`
	Order               protocol.PredictionOrderV1 `json:"order"`
	Status              OrderStatus                `json:"status"`
	CumulativeFilled    uint64                     `json:"cumulative_filled_lots"`
	LastFinalizedTxHash string                     `json:"last_finalized_tx_hash,omitempty"`
	FinalityViewID      string                     `json:"finality_view_id,omitempty"`
}

type document struct {
	SchemaVersion uint16                 `json:"schema_version"`
	Revision      uint64                 `json:"revision"`
	Profile       MarketProfile          `json:"profile"`
	Orders        map[string]OrderRecord `json:"orders"`
}

type Book struct {
	mu        sync.Mutex
	directory string
	lock      *os.File
	doc       document
}

type MatchPlan struct {
	LeftDigest  string
	RightDigest string
	Quantity    uint64
	LeftBOC     []byte
	RightBOC    []byte
	Amounts     protocol.MatchAmounts
}

func OpenBook(directory string, profile MarketProfile) (*Book, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || validateProfile(profile) != nil {
		return nil, errors.New("prediction order-book configuration is invalid")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return nil, errors.New("prediction order-book directory must be owner-private")
	}
	lock, err := acquireBookLock(directory)
	if err != nil {
		return nil, err
	}
	book := &Book{
		directory: directory,
		lock:      lock,
		doc:       document{SchemaVersion: 1, Profile: profile, Orders: map[string]OrderRecord{}},
	}
	if err := book.loadOrInitialize(); err != nil {
		_ = releaseBookLock(lock)
		return nil, err
	}
	return book, nil
}

func (book *Book) Close() error {
	if book == nil {
		return nil
	}
	book.mu.Lock()
	defer book.mu.Unlock()
	if book.lock == nil {
		return nil
	}
	err := releaseBookLock(book.lock)
	book.lock = nil
	return err
}

func (book *Book) Admit(signedBOC []byte, snapshot ChainAccountSnapshot, now uint64) (OrderRecord, error) {
	if book == nil || now == 0 || len(signedBOC) == 0 || len(signedBOC) > 8192 {
		return OrderRecord{}, errors.New("prediction order book is unavailable")
	}
	root, err := cell.FromBOC(signedBOC)
	if err != nil || root == nil || !bytes.Equal(signedBOC, root.ToBOC()) {
		return OrderRecord{}, errors.New("signed prediction order BOC is not canonical")
	}
	verified, err := protocol.DecodeAndVerifySignedPredictionOrder(root)
	if err != nil {
		return OrderRecord{}, err
	}
	book.mu.Lock()
	defer book.mu.Unlock()
	return book.admitVerifiedLocked(signedBOC, *verified, snapshot, now)
}

// admitVerifiedLocked commits one already-verified signed order. The caller
// must hold book.mu; custody uses this to keep capacity validation, signing,
// and persistence in one local single-writer critical section.
func (book *Book) admitVerifiedLocked(
	signedBOC []byte,
	verified protocol.SignedPredictionOrderV1,
	snapshot ChainAccountSnapshot,
	now uint64,
) (OrderRecord, error) {
	if book.lock == nil {
		return OrderRecord{}, errors.New("prediction order book is closed")
	}
	digest := verified.OrderDigest.CellHashString()
	cellHash := verified.OrderCellHash.CellHashString()
	canonicalBOC := base64.StdEncoding.EncodeToString(signedBOC)
	if prior, ok := book.doc.Orders[digest]; ok {
		if prior.SignedOrderBOC != canonicalBOC || prior.OrderCellHash != cellHash {
			return OrderRecord{}, errors.New("prediction order digest conflicts with durable bytes")
		}
		return prior, nil
	}
	if err := book.validateAdmission(verified, snapshot, now); err != nil {
		return OrderRecord{}, err
	}
	for _, prior := range book.doc.Orders {
		if prior.Order.OwnerAddress == verified.Order.OwnerAddress && prior.Order.KeyEpoch == verified.Order.KeyEpoch &&
			prior.Order.Nonce == verified.Order.Nonce && prior.Digest != digest {
			return OrderRecord{}, errors.New("owner epoch/nonce is already bound to another order digest")
		}
	}
	record := OrderRecord{
		Digest: digest, OrderCellHash: cellHash,
		TradingPublicKey: hex.EncodeToString(verified.PublicKey[:]), SignedOrderBOC: canonicalBOC,
		Order: verified.Order, Status: OrderLive,
	}
	next := cloneDocument(book.doc)
	next.Revision++
	next.Orders[digest] = record
	if err := book.persist(next); err != nil {
		return OrderRecord{}, err
	}
	book.doc = next
	return record, nil
}

func (book *Book) ApplyFinalizedFill(digest string, cumulative uint64, txHash, finalityViewID string) error {
	if book == nil || !canonicalDigest(digest, "tvm-cell-sha256:") ||
		!canonicalDigest(txHash, "sha256:") || !canonicalDigest(finalityViewID, "sha256:") {
		return errors.New("finalized fill evidence is invalid")
	}
	book.mu.Lock()
	defer book.mu.Unlock()
	if book.lock == nil {
		return errors.New("prediction order book is closed")
	}
	record, ok := book.doc.Orders[digest]
	if !ok || record.Status == OrderCanceled || cumulative < record.CumulativeFilled ||
		cumulative > record.Order.QuantityLots {
		return errors.New("finalized fill conflicts with the durable order state")
	}
	if cumulative == record.CumulativeFilled {
		if record.LastFinalizedTxHash != txHash || record.FinalityViewID != finalityViewID {
			return errors.New("same cumulative fill has conflicting finality evidence")
		}
		return nil
	}
	record.CumulativeFilled = cumulative
	record.LastFinalizedTxHash = txHash
	record.FinalityViewID = finalityViewID
	if cumulative == record.Order.QuantityLots {
		record.Status = OrderFilled
	}
	next := cloneDocument(book.doc)
	next.Revision++
	next.Orders[digest] = record
	if err := book.persist(next); err != nil {
		return err
	}
	book.doc = next
	return nil
}

func (book *Book) SuppressFinalizedCancellation(digest, txHash, finalityViewID string) error {
	if book == nil || !canonicalDigest(digest, "tvm-cell-sha256:") || !canonicalDigest(txHash, "sha256:") ||
		!canonicalDigest(finalityViewID, "sha256:") {
		return errors.New("finalized cancellation evidence is invalid")
	}
	book.mu.Lock()
	defer book.mu.Unlock()
	if book.lock == nil {
		return errors.New("prediction order book is closed")
	}
	record, ok := book.doc.Orders[digest]
	if !ok || record.Status == OrderFilled {
		return errors.New("finalized cancellation conflicts with the durable order state")
	}
	if record.Status == OrderCanceled {
		if record.LastFinalizedTxHash != txHash || record.FinalityViewID != finalityViewID {
			return errors.New("cancellation has conflicting finality evidence")
		}
		return nil
	}
	record.Status, record.LastFinalizedTxHash, record.FinalityViewID = OrderCanceled, txHash, finalityViewID
	next := cloneDocument(book.doc)
	next.Revision++
	next.Orders[digest] = record
	if err := book.persist(next); err != nil {
		return err
	}
	book.doc = next
	return nil
}

func (book *Book) PlanMatch(leftDigest, rightDigest string, quantity, now uint64,
	marketSnapshot ChainMarketSnapshot, leftAccount, rightAccount ChainAccountSnapshot,
) (MatchPlan, error) {
	book.mu.Lock()
	defer book.mu.Unlock()
	if book.lock == nil {
		return MatchPlan{}, errors.New("prediction order book is closed")
	}
	left, leftOK := book.doc.Orders[leftDigest]
	right, rightOK := book.doc.Orders[rightDigest]
	if !leftOK || !rightOK || left.Status != OrderLive || right.Status != OrderLive || leftDigest == rightDigest {
		return MatchPlan{}, errors.New("match references absent or non-live orders")
	}
	if leftAccount.FinalityViewID != rightAccount.FinalityViewID ||
		leftAccount.FinalityViewID != marketSnapshot.FinalityViewID {
		return MatchPlan{}, errors.New("match account snapshots are not from one finalized chain view")
	}
	if err := book.validateMarketSnapshot(marketSnapshot, now); err != nil {
		return MatchPlan{}, err
	}
	for record, snapshot := range map[*OrderRecord]ChainAccountSnapshot{&left: leftAccount, &right: rightAccount} {
		if err := book.validateAuthority(record.Order, snapshot, now); err != nil {
			return MatchPlan{}, err
		}
		if record.TradingPublicKey != hex.EncodeToString(snapshot.TradingPublicKey[:]) {
			return MatchPlan{}, errors.New("durable order key is not the current on-chain trading key")
		}
		if err := protocol.ValidateOrderFill(record.Order, record.CumulativeFilled, quantity,
			book.doc.Profile.MarketMinFillLots, now, book.doc.Profile.TradeClose); err != nil {
			return MatchPlan{}, err
		}
	}
	model, err := protocol.NewReferenceModel(book.doc.Profile.LotPayout)
	if err != nil {
		return MatchPlan{}, err
	}
	model.CompleteSets = marketSnapshot.CompleteSets
	model.LockedCollateral = marketSnapshot.LockedCollateral
	for owner, balance := range marketSnapshot.Accounts {
		model.Accounts[owner] = balance
	}
	for _, snapshot := range []ChainAccountSnapshot{leftAccount, rightAccount} {
		balance, ok := model.Accounts[snapshot.OwnerAddress]
		if !ok ||
			balance != (protocol.AccountBalance{Free: snapshot.FreeBalance, YesLots: snapshot.YesLots, NoLots: snapshot.NoLots}) {
			return MatchPlan{}, errors.New("owner snapshot conflicts with the complete market account view")
		}
	}
	if invariantErr := model.CheckInvariants(); invariantErr != nil {
		return MatchPlan{}, errors.New("finalized market snapshot violates collateral invariants")
	}
	amounts, err := model.Match(left.Order, right.Order, quantity)
	if err != nil {
		return MatchPlan{}, err
	}
	leftBOC, _ := base64.StdEncoding.DecodeString(left.SignedOrderBOC)
	rightBOC, _ := base64.StdEncoding.DecodeString(right.SignedOrderBOC)
	return MatchPlan{
		LeftDigest: leftDigest, RightDigest: rightDigest, Quantity: quantity,
		LeftBOC: leftBOC, RightBOC: rightBOC, Amounts: amounts,
	}, nil
}

func (book *Book) validateMarketSnapshot(snapshot ChainMarketSnapshot, now uint64) error {
	if !snapshot.Finalized || snapshot.Accounts == nil || len(snapshot.Accounts) > 4096 ||
		snapshot.MarketConfigHash != book.doc.Profile.MarketConfigHash ||
		snapshot.ContractCodeHash != book.doc.Profile.ContractCodeHash ||
		!canonicalDigest(snapshot.FinalityViewID, "sha256:") || snapshot.ObservedAt == 0 ||
		snapshot.ObservedAt > now || now-snapshot.ObservedAt > book.doc.Profile.MaxSnapshotAge {
		return errors.New("market execution snapshot is stale or outside the admitted code/config domain")
	}
	return nil
}

func (book *Book) LiveOrders() []OrderRecord {
	if book == nil {
		return nil
	}
	book.mu.Lock()
	defer book.mu.Unlock()
	if book.lock == nil {
		return nil
	}
	result := make([]OrderRecord, 0)
	for _, record := range book.doc.Orders {
		if record.Status == OrderLive {
			result = append(result, record)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Digest < result[j].Digest })
	return result
}

func (book *Book) validateAdmission(
	order protocol.SignedPredictionOrderV1,
	snapshot ChainAccountSnapshot,
	now uint64,
) error {
	profile := book.doc.Profile
	if order.Order.GlobalID != profile.GlobalID || order.Order.WorkchainID != profile.WorkchainID ||
		order.Order.MarketAddress != profile.MarketAddress || order.Order.MarketConfigHash.CellHashString() != profile.MarketConfigHash ||
		order.Order.ValidUntil > profile.TradeClose || now >= profile.TradeClose {
		return errors.New("order is outside the admitted immutable market domain")
	}
	if err := book.validateAuthority(order.Order, snapshot, now); err != nil {
		return err
	}
	if !bytes.Equal(order.PublicKey[:], snapshot.TradingPublicKey[:]) {
		return errors.New("order signature key is not the current on-chain trading key")
	}
	if uint32(len(book.doc.Orders)) >= profile.MaxOrders {
		return errors.New("prediction order-book capacity reached")
	}
	ownerCount := uint32(0)
	reservedFree, reservedYes, reservedNo := uint64(0), uint64(0), uint64(0)
	for _, prior := range book.doc.Orders {
		if prior.Order.OwnerAddress != order.Order.OwnerAddress || prior.Status != OrderLive {
			continue
		}
		ownerCount++
		remaining := prior.Order.QuantityLots - prior.CumulativeFilled
		if prior.Order.Action == protocol.ActionBuy {
			debit, ok := buyReservation(profile.LotPayout, prior.Order.LimitPriceTick, remaining)
			if !ok || reservedFree > ^uint64(0)-debit {
				return errors.New("reserved collateral overflow")
			}
			reservedFree += debit
		} else if prior.Order.Outcome == protocol.OutcomeYes {
			if reservedYes > ^uint64(0)-remaining {
				return errors.New("reserved YES overflow")
			}
			reservedYes += remaining
		} else {
			if reservedNo > ^uint64(0)-remaining {
				return errors.New("reserved NO overflow")
			}
			reservedNo += remaining
		}
	}
	if ownerCount >= profile.MaxOrdersPerOwner {
		return errors.New("owner prediction-order capacity reached")
	}
	if order.Order.Action == protocol.ActionBuy {
		debit, ok := buyReservation(profile.LotPayout, order.Order.LimitPriceTick, order.Order.QuantityLots)
		if !ok || reservedFree > snapshot.FreeBalance || debit > snapshot.FreeBalance-reservedFree {
			return errors.New("order exceeds unreserved on-chain free collateral")
		}
	} else if order.Order.Outcome == protocol.OutcomeYes {
		if reservedYes > snapshot.YesLots || order.Order.QuantityLots > snapshot.YesLots-reservedYes {
			return errors.New("order exceeds unreserved YES position")
		}
	} else if reservedNo > snapshot.NoLots || order.Order.QuantityLots > snapshot.NoLots-reservedNo {
		return errors.New("order exceeds unreserved NO position")
	}
	return nil
}

func (book *Book) validateAuthority(order protocol.PredictionOrderV1, snapshot ChainAccountSnapshot, now uint64) error {
	if snapshot.OwnerAddress != order.OwnerAddress || snapshot.KeyEpoch != order.KeyEpoch ||
		order.Nonce < snapshot.NonceFloor || !snapshot.Finalized || snapshot.MarketConfigHash != book.doc.Profile.MarketConfigHash ||
		!canonicalDigest(snapshot.FinalityViewID, "sha256:") ||
		snapshot.ObservedAt == 0 || snapshot.ObservedAt > now || now-snapshot.ObservedAt > book.doc.Profile.MaxSnapshotAge {
		return errors.New("order is not executable under the finalized chain account snapshot")
	}
	return nil
}

func buyReservation(lot uint64, price uint16, quantity uint64) (uint64, bool) {
	unit := lot / uint64(protocol.PriceScale)
	if quantity != 0 && unit > ^uint64(0)/quantity {
		return 0, false
	}
	base := quantity * unit
	if price != 0 && base > ^uint64(0)/uint64(price) {
		return 0, false
	}
	return base * uint64(price), true
}

func validateProfile(profile MarketProfile) error {
	config, err := protocol.ParseHash32(profile.MarketConfigHash)
	market, addressErr := address.ParseRawAddr(profile.MarketAddress)
	if err != nil || config.IsZero() || !canonicalDigest(profile.NetworkDomainHash, "sha256:") ||
		!canonicalDigest(profile.MarketID, "sha256:") ||
		!canonicalDigest(profile.MarketConfigHash, "tvm-cell-sha256:") ||
		!canonicalDigest(profile.ContractCodeHash, "tvm-cell-sha256:") ||
		addressErr != nil || market == nil || market.Type() != address.StdAddress || market.BitsLen() != 256 ||
		market.StringRaw() != profile.MarketAddress || int8(market.Workchain()) != profile.WorkchainID ||
		profile.TradeClose == 0 || profile.LotPayout == 0 ||
		profile.LotPayout%uint64(protocol.PriceScale) != 0 || profile.MarketMinFillLots == 0 ||
		profile.MaxOrders == 0 || profile.MaxOrders > 100_000 || profile.MaxOrdersPerOwner == 0 ||
		profile.MaxOrdersPerOwner > profile.MaxOrders || profile.MaxSnapshotAge == 0 || profile.MaxSnapshotAge > 300 {
		return errors.New("invalid prediction market profile")
	}
	return nil
}

func canonicalDigest(value, prefix string) bool {
	if value != strings.ToLower(value) || !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+64 {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, prefix))
	return err == nil && len(decoded) == 32
}

func (book *Book) loadOrInitialize() error {
	path := filepath.Join(book.directory, stateFile)
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return book.persist(book.doc)
	}
	if err != nil || len(raw) > 64<<20 {
		return errors.New("prediction order-book state is unavailable")
	}
	var loaded document
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&loaded) != nil || decoder.Decode(&struct{}{}) != io.EOF || loaded.SchemaVersion != 1 ||
		loaded.Orders == nil ||
		!reflect.DeepEqual(loaded.Profile, book.doc.Profile) ||
		uint32(len(loaded.Orders)) > loaded.Profile.MaxOrders {
		return errors.New("prediction order-book state identity or shape is invalid")
	}
	for digest, record := range loaded.Orders {
		if digest != record.Digest || !canonicalDigest(digest, "tvm-cell-sha256:") ||
			(record.Status != OrderLive && record.Status != OrderFilled && record.Status != OrderCanceled) ||
			record.CumulativeFilled > record.Order.QuantityLots ||
			(record.Status == OrderLive && record.CumulativeFilled == record.Order.QuantityLots) ||
			(record.Status == OrderFilled && record.CumulativeFilled != record.Order.QuantityLots) ||
			(record.Status == OrderLive && record.CumulativeFilled == 0 &&
				(record.LastFinalizedTxHash != "" || record.FinalityViewID != "")) ||
			((record.Status != OrderLive || record.CumulativeFilled > 0) &&
				(!canonicalDigest(record.LastFinalizedTxHash, "sha256:") ||
					!canonicalDigest(record.FinalityViewID, "sha256:"))) {
			return errors.New("prediction order-book contains an invalid record")
		}
		if len(record.SignedOrderBOC) > 12_000 {
			return errors.New("prediction order-book record has an oversized exact BOC")
		}
		rawBOC, decodeErr := base64.StdEncoding.DecodeString(record.SignedOrderBOC)
		root, cellErr := cell.FromBOC(rawBOC)
		if decodeErr != nil || len(rawBOC) > 8192 || cellErr != nil || root == nil ||
			!bytes.Equal(rawBOC, root.ToBOC()) {
			return errors.New("prediction order-book record has an invalid exact BOC")
		}
		verified, verifyErr := protocol.DecodeAndVerifySignedPredictionOrder(root)
		if verifyErr != nil || verified.OrderDigest.CellHashString() != record.Digest ||
			verified.OrderCellHash.CellHashString() != record.OrderCellHash ||
			hex.EncodeToString(verified.PublicKey[:]) != record.TradingPublicKey ||
			!reflect.DeepEqual(verified.Order, record.Order) {
			return errors.New("prediction order-book record does not match its exact signed BOC")
		}
	}
	book.doc = loaded
	return nil
}

func (book *Book) persist(next document) error {
	raw, err := json.Marshal(next)
	if err != nil || len(raw) > 64<<20 {
		return errors.New("prediction order-book state exceeds its durable bound")
	}
	return fileutil.WriteFileAtomic(filepath.Join(book.directory, stateFile), raw, 0o600)
}

func cloneDocument(value document) document {
	next := value
	next.Orders = make(map[string]OrderRecord, len(value.Orders))
	for key, record := range value.Orders {
		next.Orders[key] = record
	}
	return next
}
