package prediction

import (
	"path/filepath"
	"strings"
	"testing"

	protocol "github.com/tosnetwork/tos-service-protocol/pkg/predictionmarket"
)

func portfolioProfile(owner string, maximumRisk uint64) OwnerPortfolioProfile {
	return OwnerPortfolioProfile{
		OwnerID: "owner:test", OwnerAddress: owner, NetworkDomainHash: profile().NetworkDomainHash,
		SourceAgentAccount: rawAddress(0x99), CollateralAssetID: testHash(0x98).SHA256String(),
		MaximumAtRiskAtomic: maximumRisk, MaximumPositionLots: 10_000,
		MaximumOrderReservations: 100, MaximumMarkets: 10,
	}
}

func portfolioSnapshotFor(order protocol.PredictionOrderV1, free, yes, no, seqno uint64) PortfolioMarketSnapshot {
	return PortfolioMarketSnapshot{
		OwnerAddress: order.OwnerAddress, MarketID: profile().MarketID, MarketAddress: order.MarketAddress,
		MarketConfigHash: order.MarketConfigHash.CellHashString(), ContractCodeHash: profile().ContractCodeHash,
		LotPayout: profile().LotPayout, FreeBalance: free, YesLots: yes, NoLots: no,
		MasterchainSeqno: seqno, ObservedAt: 10_000, FinalityViewID: testHash(byte(seqno)).SHA256String(),
		QuorumFinalized: true,
	}
}

func reservePortfolioOrder(t *testing.T, ledger *OwnerPortfolioLedger, agentID string,
	order protocol.PredictionOrderV1, snapshot PortfolioMarketSnapshot,
) (PortfolioOrderReservation, PortfolioReservationProofV1, error) {
	t.Helper()
	risk, err := portfolioRisk(order, snapshot.LotPayout)
	if err != nil {
		t.Fatal(err)
	}
	return ledger.ReserveOrder("owner:test", agentID, profile().NetworkDomainHash, profile().MarketID,
		profile().ContractCodeHash, order, risk, snapshot)
}

func TestOwnerPortfolioSerializesRiskAcrossAgents(t *testing.T) {
	owner := rawAddress(0x44)
	root := filepath.Join(t.TempDir(), "portfolio-root")
	ledger, openErr := OpenOwnerPortfolioLedger(root, portfolioProfile(owner, 10*testTOS))
	if openErr != nil {
		t.Fatal(openErr)
	}
	defer ledger.Close()
	if _, secondOpenErr := OpenOwnerPortfolioLedger(root, portfolioProfile(owner, 10*testTOS)); secondOpenErr == nil {
		t.Fatal("a second Agent acquired the same owner/network/source/asset writer lock")
	}

	first := custodyOrder(owner)
	first.QuantityLots = 10
	first.Nonce = 1
	first.Salt = testHash(0x51)
	snapshot := portfolioSnapshotFor(first, 20*testTOS, 0, 0, 100)
	reservation, proof, err := reservePortfolioOrder(t, ledger, "agent:first", first, snapshot)
	if err != nil || reservation.PendingCollateralAtomic != 6*testTOS ||
		proof.AggregateAtRiskAtomic != 6*testTOS || proof.Revision == 0 ||
		!canonicalDigest(proof.ReservationDigest, "sha256:") {
		t.Fatalf("first owner-wide reservation failed: %#v %#v %v", reservation, proof, err)
	}
	second := first
	second.Nonce = 2
	second.Salt = testHash(0x52)
	if _, _, err := reservePortfolioOrder(t, ledger, "agent:second", second, snapshot); err == nil {
		t.Fatal("two Agents independently spent the same owner risk limit")
	}
	orders, _ := ledger.Snapshot()
	if len(orders) != 1 || orders[0].AgentID != "agent:first" {
		t.Fatalf("failed reservation changed durable owner risk: %#v", orders)
	}
}

func TestOwnerPortfolioBuyFillConvertsPendingToRealizedRisk(t *testing.T) {
	owner := rawAddress(0x45)
	root := filepath.Join(t.TempDir(), "portfolio-root")
	ledger, openErr := OpenOwnerPortfolioLedger(root, portfolioProfile(owner, 20*testTOS))
	if openErr != nil {
		t.Fatal(openErr)
	}
	order := custodyOrder(owner)
	order.Nonce = 11
	order.Salt = testHash(0x61)
	snapshot := portfolioSnapshotFor(order, 20*testTOS, 0, 0, 100)
	reservation, _, reserveErr := reservePortfolioOrder(t, ledger, "agent:first", order, snapshot)
	if reserveErr != nil {
		t.Fatal(reserveErr)
	}
	evidence := PortfolioFillEvidence{
		OrderDigest: reservation.OrderDigest, CumulativeFilledLots: 4,
		CumulativeSpentAtomic: 2_400_000_000, TransactionHash: testHash(0x71).SHA256String(),
		FinalityViewID: testHash(0x72).SHA256String(), MasterchainSeqno: 101, QuorumFinalized: true,
	}
	if applyErr := ledger.ApplyFinalizedFill(evidence); applyErr != nil {
		t.Fatal(applyErr)
	}
	orders, positions := ledger.Snapshot()
	if len(orders) != 1 || orders[0].Status != PortfolioOrderPartiallyFilled ||
		orders[0].PendingCollateralAtomic != 3_600_000_000 || len(positions) != 2 {
		t.Fatalf("BUY pending risk did not move to a position: %#v %#v", orders, positions)
	}
	yes := positionByOutcome(positions, protocol.OutcomeYes)
	if yes.Lots != 4 || yes.AtRiskAtomic != 2_400_000_000 {
		t.Fatalf("wrong realized BUY exposure: %#v", yes)
	}
	if applyErr := ledger.ApplyFinalizedFill(evidence); applyErr != nil {
		t.Fatalf("exact fill retry was not idempotent: %v", applyErr)
	}
	conflict := evidence
	conflict.TransactionHash = testHash(0x73).SHA256String()
	if applyErr := ledger.ApplyFinalizedFill(conflict); applyErr == nil {
		t.Fatal("same cumulative fill accepted conflicting finality")
	}
	if closeErr := ledger.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	restarted, restartErr := OpenOwnerPortfolioLedger(root, portfolioProfile(owner, 20*testTOS))
	if restartErr != nil {
		t.Fatal(restartErr)
	}
	defer restarted.Close()
	orders, positions = restarted.Snapshot()
	if orders[0].PendingCollateralAtomic != 3_600_000_000 ||
		positionByOutcome(positions, protocol.OutcomeYes).AtRiskAtomic != 2_400_000_000 {
		t.Fatal("restart lost pending or realized BUY exposure")
	}
}

func TestOwnerPortfolioSellReducesPositionButCancelOnlyReleasesPending(t *testing.T) {
	owner := rawAddress(0x46)
	ledger, err := OpenOwnerPortfolioLedger(filepath.Join(t.TempDir(), "portfolio-root"),
		portfolioProfile(owner, 20*testTOS))
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	order := custodyOrder(owner)
	order.Action = protocol.ActionSell
	order.Outcome = protocol.OutcomeYes
	order.QuantityLots = 6
	order.Nonce = 12
	order.Salt = testHash(0x62)
	snapshot := portfolioSnapshotFor(order, 0, 10, 0, 100)
	reservation, _, err := reservePortfolioOrder(t, ledger, "agent:seller", order, snapshot)
	if err != nil || reservation.PendingPositionLots != 6 {
		t.Fatalf("reserve SELL: %#v %v", reservation, err)
	}
	fill := PortfolioFillEvidence{
		OrderDigest: reservation.OrderDigest, CumulativeFilledLots: 2,
		CumulativeProceedsAtomic: 1_200_000_000, TransactionHash: testHash(0x74).SHA256String(),
		FinalityViewID: testHash(0x75).SHA256String(), MasterchainSeqno: 101, QuorumFinalized: true,
	}
	if err := ledger.ApplyFinalizedFill(fill); err != nil {
		t.Fatal(err)
	}
	orders, positions := ledger.Snapshot()
	if orders[0].PendingPositionLots != 4 || positionByOutcome(positions, protocol.OutcomeYes).Lots != 8 ||
		positionByOutcome(positions, protocol.OutcomeYes).AtRiskAtomic != 8*testTOS {
		t.Fatalf("SELL fill did not reduce both pending and realized risk: %#v %#v", orders, positions)
	}
	if summary := ledger.Summary(); summary.FinalizedProceedsAtomic != 1_200_000_000 ||
		summary.AggregateAtRiskAtomic != 8*testTOS {
		t.Fatalf("SELL proceeds were not separately classified: %#v", summary)
	}
	inactive := PortfolioInactiveEvidence{
		OrderDigest: reservation.OrderDigest, Reason: PortfolioInactiveCanceled,
		TransactionHash: testHash(0x76).SHA256String(), FinalityViewID: testHash(0x77).SHA256String(),
		MasterchainSeqno: 102, QuorumFinalized: true,
	}
	if err := ledger.ConfirmOrderInactive(inactive); err != nil {
		t.Fatal(err)
	}
	orders, positions = ledger.Snapshot()
	if orders[0].PendingPositionLots != 0 || orders[0].Status != PortfolioOrderCancelConfirmed ||
		positionByOutcome(positions, protocol.OutcomeYes).Lots != 8 {
		t.Fatal("cancel released a realized position instead of only pending SELL risk")
	}
	exit := PortfolioPositionExitEvidence{
		MarketID: profile().MarketID, MarketAddress: order.MarketAddress,
		MarketConfigHash: order.MarketConfigHash.CellHashString(), ContractCodeHash: profile().ContractCodeHash,
		Outcome: protocol.OutcomeYes, Reason: PortfolioPositionExitClaim,
		TransactionHash: testHash(0x7a).SHA256String(), FinalityViewID: testHash(0x7b).SHA256String(),
		MasterchainSeqno: 103, QuorumFinalized: true,
	}
	if err := ledger.ApplyFinalizedPositionExit(exit); err != nil {
		t.Fatal(err)
	}
	if summary := ledger.Summary(); summary.AggregatePositionLots != 0 || summary.AggregateAtRiskAtomic != 0 ||
		summary.FinalizedProceedsAtomic != 1_200_000_000 {
		t.Fatalf("claim did not release only realized position risk: %#v", summary)
	}
	if err := ledger.ApplyFinalizedPositionExit(exit); err != nil {
		t.Fatalf("exact position-exit retry was not idempotent: %v", err)
	}
}

func TestOwnerPortfolioAmbiguousAndUnprovenExpiryDoNotReleaseRisk(t *testing.T) {
	owner := rawAddress(0x47)
	ledger, err := OpenOwnerPortfolioLedger(filepath.Join(t.TempDir(), "portfolio-root"),
		portfolioProfile(owner, 10*testTOS))
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	order := custodyOrder(owner)
	order.Nonce = 13
	order.Salt = testHash(0x63)
	snapshot := portfolioSnapshotFor(order, 20*testTOS, 0, 0, 100)
	reservation, _, err := reservePortfolioOrder(t, ledger, "agent:first", order, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.MarkOrderBroadcastState(reservation.OrderDigest, PortfolioOrderAmbiguous); err != nil {
		t.Fatal(err)
	}
	second := order
	second.Nonce = 14
	second.Salt = testHash(0x64)
	if _, _, err := reservePortfolioOrder(t, ledger, "agent:second", second, snapshot); err == nil {
		t.Fatal("ambiguous order released its worst-case reservation")
	}
	expiry := PortfolioInactiveEvidence{
		OrderDigest: reservation.OrderDigest, Reason: PortfolioInactiveExpired,
		ChainTime: order.ValidUntil - 1, TransactionHash: testHash(0x78).SHA256String(),
		FinalityViewID: testHash(0x79).SHA256String(), MasterchainSeqno: 110, QuorumFinalized: true,
	}
	if err := ledger.ConfirmOrderInactive(expiry); err == nil {
		t.Fatal("wall-clock expiry released a still-chain-executable order")
	}
	expiry.ChainTime = order.ValidUntil
	if err := ledger.ConfirmOrderInactive(expiry); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reservePortfolioOrder(t, ledger, "agent:second", second, snapshot); err != nil {
		t.Fatalf("finalized expiry did not release only pending risk: %v", err)
	}
}

func TestOwnerPortfolioRejectsUnfinalizedOrConflictingSnapshots(t *testing.T) {
	owner := rawAddress(0x48)
	ledger, err := OpenOwnerPortfolioLedger(filepath.Join(t.TempDir(), "portfolio-root"),
		portfolioProfile(owner, 20*testTOS))
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	order := custodyOrder(owner)
	order.Nonce = 15
	order.Salt = testHash(0x65)
	snapshot := portfolioSnapshotFor(order, 20*testTOS, 1, 0, 100)
	unfinalized := snapshot
	unfinalized.QuorumFinalized = false
	if _, _, err := reservePortfolioOrder(t, ledger, "agent:first", order, unfinalized); err == nil {
		t.Fatal("unfinalized position snapshot reached the owner ledger")
	}
	if _, _, err := reservePortfolioOrder(t, ledger, "agent:first", order, snapshot); err != nil {
		t.Fatal(err)
	}
	second := order
	second.Nonce = 16
	second.Salt = testHash(0x66)
	conflict := snapshot
	conflict.YesLots = 2
	if _, _, err := reservePortfolioOrder(t, ledger, "agent:second", second, conflict); err == nil {
		t.Fatal("same finalized checkpoint changed the imported position")
	}
	rollback := snapshot
	rollback.MasterchainSeqno = 99
	rollback.FinalityViewID = testHash(0x7a).SHA256String()
	if _, _, err := reservePortfolioOrder(t, ledger, "agent:second", second, rollback); err == nil {
		t.Fatal("finalized portfolio position rolled back")
	}
}

func TestOwnerPortfolioKeyDoesNotContainAgentID(t *testing.T) {
	profile := portfolioProfile(rawAddress(0x49), 20*testTOS)
	key := portfolioKey(profile)
	if len(key) != 64 || strings.Contains(key, "agent") {
		t.Fatalf("portfolio key is not a fixed owner/network/source/asset digest: %q", key)
	}
}

func positionByOutcome(positions []PositionExposure, outcome protocol.Outcome) PositionExposure {
	for _, position := range positions {
		if position.Outcome == outcome {
			return position
		}
	}
	return PositionExposure{}
}
