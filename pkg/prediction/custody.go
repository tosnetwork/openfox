package prediction

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
	protocol "github.com/tosnetwork/tos-service-protocol/pkg/predictionmarket"
)

const authorizeOrderAction = "prediction.order.authorize"

// WorstCaseOrderRiskV1 is the deterministic risk commitment approved by the
// owner before a trading-key signer is allowed to sign. BUY orders reserve the
// maximum collateral debit at their limit. SELL orders reserve the exact
// outcome position quantity.
type WorstCaseOrderRiskV1 struct {
	SchemaVersion   uint16           `json:"schema_version"`
	OrderDigest     string           `json:"order_digest"`
	OwnerAddress    string           `json:"owner_address"`
	MarketAddress   string           `json:"market_address"`
	Action          protocol.Action  `json:"action"`
	Outcome         protocol.Outcome `json:"outcome"`
	QuantityLots    uint64           `json:"quantity_lots"`
	CollateralDebit uint64           `json:"collateral_debit_atomic"`
	PositionDebit   uint64           `json:"position_debit_lots"`
}

// PredictionOrderSigningRequestV1 is the complete custody-bound request. A
// signer/HSM must independently validate the included owner authorization and
// sign only OrderDigest. Raw private key material never enters OpenFox.
type PredictionOrderSigningRequestV1 struct {
	SchemaVersion  uint16                        `json:"schema_version"`
	OrderCellBOC   []byte                        `json:"order_cell_boc"`
	OrderDigest    [32]byte                      `json:"order_digest"`
	Risk           WorstCaseOrderRiskV1          `json:"risk"`
	Authorization  commerce.AuthorizedAction     `json:"authorization"`
	WriterFence    commerce.WriterFence          `json:"writer_fence"`
	SemanticFields []commerce.SemanticFieldValue `json:"semantic_fields"`
}

type PredictionOrderSignatureV1 struct {
	PublicKey [ed25519.PublicKeySize]byte
	Signature [ed25519.SignatureSize]byte
}

// PredictionOrderCustodySigner is deliberately narrower than a generic byte
// signer. Implementations receive the complete order and authorization domain
// and must not expose or return private key material.
type PredictionOrderCustodySigner interface {
	SignAuthorizedPredictionOrder(
		ctx context.Context,
		request PredictionOrderSigningRequestV1,
	) (PredictionOrderSignatureV1, error)
}

type AuthorizedOrderCoordinator struct {
	Book          *Book
	Signer        PredictionOrderCustodySigner
	FenceResolver commerce.CurrentWriterFenceResolver
}

// AuthorizeSignAndAdmit verifies current Owner authority, calls the isolated
// trading signer, verifies the returned signature, then admits the exact bytes
// against finalized chain state. Failed admission never returns bearer bytes.
func (coordinator AuthorizedOrderCoordinator) AuthorizeSignAndAdmit(
	ctx context.Context,
	order protocol.PredictionOrderV1,
	authorization commerce.AuthorizedAction,
	fence commerce.WriterFence,
	snapshot ChainAccountSnapshot,
	now uint64,
) (OrderRecord, []byte, error) {
	if ctx == nil || coordinator.Book == nil || coordinator.Signer == nil || coordinator.FenceResolver == nil ||
		now == 0 || now > math.MaxInt64 {
		return OrderRecord{}, nil, errors.New("prediction order custody is unavailable")
	}
	orderCell, err := protocol.BuildPredictionOrderCell(order)
	if err != nil {
		return OrderRecord{}, nil, err
	}
	digest, err := protocol.PredictionOrderDigest(orderCell)
	if err != nil {
		return OrderRecord{}, nil, err
	}
	coordinator.Book.mu.Lock()
	defer coordinator.Book.mu.Unlock()
	if coordinator.Book.lock == nil {
		return OrderRecord{}, nil, errors.New("prediction order book is closed")
	}
	profile := coordinator.Book.doc.Profile
	risk, err := worstCaseRisk(profile, order, digest)
	if err != nil {
		return OrderRecord{}, nil, err
	}
	riskDigest, err := codec.Digest("tos.prediction.worst-case-order-risk.v1", risk)
	if err != nil {
		return OrderRecord{}, nil, err
	}
	fields := map[string]commerce.SemanticValue{
		"owner_id":               commerce.ID(authorization.OwnerID),
		"agent_id":               commerce.ID(authorization.AgentID),
		"network_domain_digest":  commerce.Digest32(profile.NetworkDomainHash),
		"market_id":              commerce.Digest32(profile.MarketID),
		"order_digest":           commerce.Digest32(digest.SHA256String()),
		"valid_until":            commerce.U64(order.ValidUntil),
		"worst_case_risk_digest": commerce.Digest32(riskDigest),
	}
	canonicalRequest := orderCell.ToBOC()
	when := time.Unix(int64(now), 0).UTC()
	if authorization.ActionKind != authorizeOrderAction ||
		commerce.VerifyAuthorizedAction(authorization, fields, canonicalRequest, fence,
			coordinator.FenceResolver, when) != nil ||
		commerce.ConfirmCurrentWriterFence(fence, coordinator.FenceResolver, when) != nil {
		return OrderRecord{}, nil, errors.New("prediction order lacks current exact owner authorization")
	}
	digestKey := digest.CellHashString()
	if prior, ok := coordinator.Book.doc.Orders[digestKey]; ok {
		authorityErr := coordinator.Book.validateAuthority(order, snapshot, now)
		if authorityErr != nil ||
			prior.TradingPublicKey != hex.EncodeToString(snapshot.TradingPublicKey[:]) {
			return OrderRecord{}, nil, errors.New("durable prediction order is no longer executable")
		}
		recovered, decodeErr := base64.StdEncoding.DecodeString(prior.SignedOrderBOC)
		if decodeErr != nil {
			return OrderRecord{}, nil, errors.New("durable prediction order bytes are unavailable")
		}
		return prior, recovered, nil
	}
	var publicKey [ed25519.PublicKeySize]byte
	copy(publicKey[:], snapshot.TradingPublicKey[:])
	var orderCellHash protocol.Hash32
	copy(orderCellHash[:], orderCell.Hash())
	preflight := protocol.SignedPredictionOrderV1{
		Order: order, PublicKey: publicKey, OrderCellHash: orderCellHash, OrderDigest: digest,
	}
	if admissionErr := coordinator.Book.validateAdmission(preflight, snapshot, now); admissionErr != nil {
		return OrderRecord{}, nil, admissionErr
	}
	for _, prior := range coordinator.Book.doc.Orders {
		if prior.Order.OwnerAddress == order.OwnerAddress && prior.Order.KeyEpoch == order.KeyEpoch &&
			prior.Order.Nonce == order.Nonce && prior.Digest != digestKey {
			return OrderRecord{}, nil, errors.New("owner epoch/nonce is already bound to another order digest")
		}
	}
	wireFields, err := commerce.ExportSemanticFields(authorizeOrderAction, fields)
	if err != nil {
		return OrderRecord{}, nil, err
	}
	if contextErr := ctx.Err(); contextErr != nil {
		return OrderRecord{}, nil, contextErr
	}
	signedByCustody, err := coordinator.Signer.SignAuthorizedPredictionOrder(ctx, PredictionOrderSigningRequestV1{
		SchemaVersion:  1,
		OrderCellBOC:   append([]byte(nil), canonicalRequest...),
		OrderDigest:    [32]byte(digest),
		Risk:           risk,
		Authorization:  authorization,
		WriterFence:    fence,
		SemanticFields: wireFields,
	})
	if err != nil {
		return OrderRecord{}, nil, err
	}
	if !bytes.Equal(signedByCustody.PublicKey[:], snapshot.TradingPublicKey[:]) {
		return OrderRecord{}, nil, errors.New("custody signer is not the current on-chain trading key")
	}
	signedCell, err := protocol.BuildSignedPredictionOrderCell(
		orderCell,
		signedByCustody.PublicKey[:],
		signedByCustody.Signature[:],
	)
	if err != nil {
		return OrderRecord{}, nil, err
	}
	signedBOC := signedCell.ToBOC()
	verified, err := protocol.DecodeAndVerifySignedPredictionOrder(signedCell)
	if err != nil {
		return OrderRecord{}, nil, err
	}
	record, err := coordinator.Book.admitVerifiedLocked(signedBOC, *verified, snapshot, now)
	if err != nil {
		return OrderRecord{}, nil, err
	}
	return record, append([]byte(nil), signedBOC...), nil
}

func worstCaseRisk(
	profile MarketProfile,
	order protocol.PredictionOrderV1,
	digest protocol.Hash32,
) (WorstCaseOrderRiskV1, error) {
	if order.GlobalID != profile.GlobalID || order.WorkchainID != profile.WorkchainID ||
		order.MarketAddress != profile.MarketAddress ||
		order.MarketConfigHash.CellHashString() != profile.MarketConfigHash {
		return WorstCaseOrderRiskV1{}, errors.New("prediction order is outside the custody market domain")
	}
	risk := WorstCaseOrderRiskV1{
		SchemaVersion: 1,
		OrderDigest:   digest.SHA256String(),
		OwnerAddress:  order.OwnerAddress,
		MarketAddress: order.MarketAddress,
		Action:        order.Action,
		Outcome:       order.Outcome,
		QuantityLots:  order.QuantityLots,
	}
	if order.Action == protocol.ActionBuy {
		debit, ok := buyReservation(profile.LotPayout, order.LimitPriceTick, order.QuantityLots)
		if !ok {
			return WorstCaseOrderRiskV1{}, errors.New("prediction order risk overflows")
		}
		risk.CollateralDebit = debit
	} else {
		risk.PositionDebit = order.QuantityLots
	}
	return risk, nil
}
