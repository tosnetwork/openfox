package prediction

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
	protocol "github.com/tosnetwork/tos-service-protocol/pkg/predictionmarket"
)

type custodyTestResolver struct {
	authorityID string
	key         ed25519.PublicKey
	current     bool
}

func (resolver *custodyTestResolver) AuthorizeFenceKey(
	authorityID string,
	publicKey ed25519.PublicKey,
	_ time.Time,
) error {
	if authorityID != resolver.authorityID || !bytes.Equal(publicKey, resolver.key) {
		return errors.New("authority key is not authorized")
	}
	return nil
}

func (resolver *custodyTestResolver) ConfirmCurrentWriterFence(
	_ commerce.WriterFence,
	_ time.Time,
) error {
	if !resolver.current {
		return errors.New("writer was superseded")
	}
	return nil
}

type custodyTestSigner struct {
	key   ed25519.PrivateKey
	calls int
}

func (signer *custodyTestSigner) SignAuthorizedPredictionOrder(
	_ context.Context,
	request PredictionOrderSigningRequestV1,
) (PredictionOrderSignatureV1, error) {
	signer.calls++
	if request.SchemaVersion != 1 || request.Risk.SchemaVersion != 1 || len(request.OrderCellBOC) == 0 ||
		request.Authorization.ActionKind != authorizeOrderAction || len(request.SemanticFields) != 7 ||
		validatePortfolioReservationProof(request.PortfolioProof, request.Risk.OrderDigest) != nil {
		return PredictionOrderSignatureV1{}, errors.New("incomplete custody request")
	}
	var result PredictionOrderSignatureV1
	copy(result.PublicKey[:], signer.key.Public().(ed25519.PublicKey))
	copy(result.Signature[:], ed25519.Sign(signer.key, request.OrderDigest[:]))
	return result, nil
}

func custodyPortfolio(t *testing.T, owner string) *OwnerPortfolioLedger {
	t.Helper()
	ledger, err := OpenOwnerPortfolioLedger(filepath.Join(t.TempDir(), "portfolio-root"), OwnerPortfolioProfile{
		OwnerID: "owner:test", OwnerAddress: owner, NetworkDomainHash: profile().NetworkDomainHash,
		SourceAgentAccount: rawAddress(0x99), CollateralAssetID: testHash(0x98).SHA256String(),
		MaximumAtRiskAtomic: 100 * testTOS, MaximumPositionLots: 1_000,
		MaximumOrderReservations: 100, MaximumMarkets: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	return ledger
}

func authorizedOrderFixture(
	t *testing.T,
	book *Book,
	order protocol.PredictionOrderV1,
	authorityKey ed25519.PrivateKey,
	now uint64,
) (commerce.AuthorizedAction, commerce.WriterFence, *custodyTestResolver) {
	t.Helper()
	orderCell, err := protocol.BuildPredictionOrderCell(order)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := protocol.PredictionOrderDigest(orderCell)
	if err != nil {
		t.Fatal(err)
	}
	risk, err := worstCaseRisk(profile(), order, digest)
	if err != nil {
		t.Fatal(err)
	}
	riskDigest, err := codec.Digest("tos.prediction.worst-case-order-risk.v1", risk)
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]commerce.SemanticValue{
		"owner_id":               commerce.ID("owner:test"),
		"agent_id":               commerce.ID("agent:test"),
		"network_domain_digest":  commerce.Digest32(profile().NetworkDomainHash),
		"market_id":              commerce.Digest32(profile().MarketID),
		"order_digest":           commerce.Digest32(digest.SHA256String()),
		"valid_until":            commerce.U64(order.ValidUntil),
		"worst_case_risk_digest": commerce.Digest32(riskDigest),
	}
	fenceBody := commerce.WriterFenceBody{
		SchemaVersion: 1,
		OwnerID:       "owner:test", AgentID: "agent:test", InstanceID: "runtime:test", LeaseID: "lease:test",
		WriterGeneration: 1, IssuedAtUnix: now - 10, ExpiresAtUnix: now + 1_000,
		AuthorityID: "authority:test", Scope: []string{authorizeOrderAction},
	}
	fence, err := commerce.SignWriterFence(fenceBody, authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	action, err := commerce.BuildAuthorizedAction(
		"owner:test", "agent:test", authorizeOrderAction, fields, orderCell.ToBOC(), fence, 1,
		testHash(0xa0).SHA256String(), "", "empty", now+500,
	)
	if err != nil {
		t.Fatal(err)
	}
	action, err = commerce.SignAuthorizedAction(action, authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	return action, fence, &custodyTestResolver{
		authorityID: "authority:test", key: authorityKey.Public().(ed25519.PublicKey), current: true,
	}
}

func custodyOrder(owner string) protocol.PredictionOrderV1 {
	return protocol.PredictionOrderV1{
		GlobalID: 42, WorkchainID: -1, MarketAddress: rawAddress(0x11),
		MarketConfigHash: testHash(0x22), OwnerAddress: owner, KeyEpoch: 3, Nonce: 7,
		Salt: testHash(0x47), Action: protocol.ActionBuy, Outcome: protocol.OutcomeYes,
		LiquidityRole: protocol.RoleMaker, QuantityLots: 10, MinFillLots: 1,
		AllowPartial: true, LimitPriceTick: 6_000, ValidAfter: 10_000, ValidUntil: 20_000,
	}
}

func TestAuthorizedOrderCoordinatorKeepsOwnerAuthorityInFrontOfCustody(t *testing.T) {
	book, err := OpenBook(filepath.Join(t.TempDir(), "orders"), profile())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = book.Close() }()

	now := uint64(10_001)
	owner := rawAddress(0x44)
	order := custodyOrder(owner)
	tradingKey := ed25519.NewKeyFromSeed(bytesOf(0x51, ed25519.SeedSize))
	authorityKey := ed25519.NewKeyFromSeed(bytesOf(0x61, ed25519.SeedSize))
	action, fence, resolver := authorizedOrderFixture(t, book, order, authorityKey, now)
	signer := &custodyTestSigner{key: tradingKey}
	coordinator := AuthorizedOrderCoordinator{
		Book: book, Portfolio: custodyPortfolio(t, owner), Signer: signer, FenceResolver: resolver,
	}
	record, signedBOC, err := coordinator.AuthorizeSignAndAdmit(
		t.Context(), order, action, fence, snapshot(owner, tradingKey, 10*testTOS, 0, 0), now,
	)
	if err != nil || len(signedBOC) == 0 || record.Order.Nonce != order.Nonce || signer.calls != 1 {
		t.Fatalf("authorized custody flow failed: record=%+v calls=%d err=%v", record, signer.calls, err)
	}
	retry, retryBOC, retryErr := coordinator.AuthorizeSignAndAdmit(
		t.Context(), order, action, fence, snapshot(owner, tradingKey, 10*testTOS, 0, 0), now,
	)
	if retryErr != nil || retry.Digest != record.Digest || !bytes.Equal(retryBOC, signedBOC) || signer.calls != 1 {
		t.Fatalf("exact retry did not recover durable bytes without re-signing: %v", retryErr)
	}

	mutated := order
	mutated.LimitPriceTick++
	if _, leaked, err := coordinator.AuthorizeSignAndAdmit(
		t.Context(), mutated, action, fence, snapshot(owner, tradingKey, 10*testTOS, 0, 0), now,
	); err == nil || len(leaked) != 0 || signer.calls != 1 {
		t.Fatal("a mutated order reached custody or leaked bearer bytes")
	}
}

func TestAuthorizedOrderCoordinatorRejectsSupersededFenceAndWrongTradingKey(t *testing.T) {
	book, err := OpenBook(filepath.Join(t.TempDir(), "orders"), profile())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = book.Close() }()

	now := uint64(10_001)
	owner := rawAddress(0x44)
	order := custodyOrder(owner)
	currentTradingKey := ed25519.NewKeyFromSeed(bytesOf(0x51, ed25519.SeedSize))
	authorityKey := ed25519.NewKeyFromSeed(bytesOf(0x61, ed25519.SeedSize))
	action, fence, resolver := authorizedOrderFixture(t, book, order, authorityKey, now)
	signer := &custodyTestSigner{key: currentTradingKey}
	coordinator := AuthorizedOrderCoordinator{
		Book: book, Portfolio: custodyPortfolio(t, owner), Signer: signer, FenceResolver: resolver,
	}

	resolver.current = false
	if _, leaked, err := coordinator.AuthorizeSignAndAdmit(
		t.Context(), order, action, fence, snapshot(owner, currentTradingKey, 10*testTOS, 0, 0), now,
	); err == nil || len(leaked) != 0 || signer.calls != 0 {
		t.Fatal("a superseded writer fence reached custody")
	}

	resolver.current = true
	wrongKey := ed25519.NewKeyFromSeed(bytesOf(0x52, ed25519.SeedSize))
	signer.key = wrongKey
	if _, leaked, err := coordinator.AuthorizeSignAndAdmit(
		t.Context(), order, action, fence, snapshot(owner, currentTradingKey, 10*testTOS, 0, 0), now,
	); err == nil || len(leaked) != 0 || signer.calls != 1 || len(book.LiveOrders()) != 0 {
		t.Fatal("a non-current custody key produced an admitted or returned order")
	}
	reservations, _ := coordinator.Portfolio.Snapshot()
	if len(reservations) != 1 || reservations[0].Status != PortfolioOrderReserved {
		t.Fatal("ambiguous custody failure released the owner-wide risk reservation")
	}
}
