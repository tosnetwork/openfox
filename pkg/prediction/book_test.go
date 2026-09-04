package prediction

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	protocol "github.com/tosnetwork/tos-service-protocol/pkg/predictionmarket"
)

const testTOS = uint64(1_000_000_000)

func testHash(value byte) protocol.Hash32 {
	var result protocol.Hash32
	for index := range result {
		result[index] = value
	}
	return result
}

func rawAddress(value byte) string {
	return "-1:" + strings.Repeat(hex.EncodeToString([]byte{value}), 32)
}

func profile() MarketProfile {
	return MarketProfile{
		GlobalID: 42, WorkchainID: -1, MarketAddress: rawAddress(0x11),
		NetworkDomainHash: testHash(0x20).SHA256String(), MarketID: testHash(0x21).SHA256String(),
		MarketConfigHash: testHash(0x22).CellHashString(), ContractCodeHash: testHash(0x33).CellHashString(),
		TradeClose: 20_000, LotPayout: testTOS, MarketMinFillLots: 1,
		MaxOrders: 8, MaxOrdersPerOwner: 4, MaxSnapshotAge: 30,
	}
}

func signedOrder(t *testing.T, private ed25519.PrivateKey, owner string, nonce uint64,
	action protocol.Action, outcome protocol.Outcome, role protocol.LiquidityRole,
	price uint16, quantity uint64,
) ([]byte, protocol.Hash32) {
	t.Helper()
	order := protocol.PredictionOrderV1{
		GlobalID: 42, WorkchainID: -1,
		MarketAddress: rawAddress(0x11), MarketConfigHash: testHash(0x22), OwnerAddress: owner,
		KeyEpoch: 3, Nonce: nonce, Salt: testHash(byte(nonce + 0x40)), Action: action,
		Outcome: outcome, LiquidityRole: role, QuantityLots: quantity, MinFillLots: 1,
		AllowPartial: true, LimitPriceTick: price, ValidAfter: 10_000, ValidUntil: 20_000,
	}
	signed, digest, err := protocol.SignPredictionOrder(order, private)
	if err != nil {
		t.Fatal(err)
	}
	return signed.ToBOC(), digest
}

func snapshot(owner string, private ed25519.PrivateKey, free, yes, no uint64) ChainAccountSnapshot {
	var public [ed25519.PublicKeySize]byte
	copy(public[:], private.Public().(ed25519.PublicKey))
	return ChainAccountSnapshot{
		OwnerAddress: owner, TradingPublicKey: public, KeyEpoch: 3,
		NonceFloor: 0, FreeBalance: free, YesLots: yes, NoLots: no, ObservedAt: 10_000,
		MarketConfigHash: testHash(0x22).CellHashString(), FinalityViewID: testHash(0x90).SHA256String(),
	}
}

func TestBookAdmissionPlanningAndCrashRecovery(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "orders")
	book, openErr := OpenBook(directory, profile())
	if openErr != nil {
		t.Fatal(openErr)
	}
	defer func() { _ = book.Close() }()
	if _, err := OpenBook(directory, profile()); err == nil {
		t.Fatal("a second writer acquired the order-book lock")
	}

	keyA := ed25519.NewKeyFromSeed(bytesOf(0x51, ed25519.SeedSize))
	keyB := ed25519.NewKeyFromSeed(bytesOf(0x52, ed25519.SeedSize))
	ownerA, ownerB := rawAddress(0x44), rawAddress(0x55)
	leftBOC, leftDigest := signedOrder(
		t,
		keyA,
		ownerA,
		1,
		protocol.ActionBuy,
		protocol.OutcomeYes,
		protocol.RoleMaker,
		6_000,
		10,
	)
	leftSnapshot := snapshot(ownerA, keyA, 6*testTOS, 0, 0)
	left, admitErr := book.Admit(leftBOC, leftSnapshot, 10_001)
	if admitErr != nil || left.Digest != leftDigest.CellHashString() {
		t.Fatalf("admit maker: record=%+v err=%v", left, admitErr)
	}
	retry, retryErr := book.Admit(leftBOC, leftSnapshot, 10_001)
	if retryErr != nil || retry.Digest != left.Digest {
		t.Fatalf("exact admission retry was not idempotent: %v", retryErr)
	}
	overBOC, _ := signedOrder(t, keyA, ownerA, 2, protocol.ActionBuy, protocol.OutcomeYes, protocol.RoleMaker, 1, 1)
	if _, err := book.Admit(overBOC, leftSnapshot, 10_001); err == nil {
		t.Fatal("admitted collateral exceeding the owner's unreserved chain balance")
	}

	rightBOC, rightDigest := signedOrder(
		t,
		keyB,
		ownerB,
		1,
		protocol.ActionBuy,
		protocol.OutcomeNo,
		protocol.RoleTaker,
		4_000,
		10,
	)
	rightSnapshot := snapshot(ownerB, keyB, 4*testTOS, 0, 0)
	if _, err := book.Admit(rightBOC, rightSnapshot, 10_001); err != nil {
		t.Fatal(err)
	}
	marketSnapshot := ChainMarketSnapshot{
		Accounts: map[string]protocol.AccountBalance{
			ownerA: {Free: 6 * testTOS}, ownerB: {Free: 4 * testTOS},
		}, ObservedAt: 10_000,
		MarketConfigHash: profile().MarketConfigHash, ContractCodeHash: profile().ContractCodeHash,
		FinalityViewID: leftSnapshot.FinalityViewID,
	}
	plan, planErr := book.PlanMatch(leftDigest.CellHashString(), rightDigest.CellHashString(), 10, 10_001,
		marketSnapshot, leftSnapshot, rightSnapshot)
	if planErr != nil || plan.Amounts.Notional != 10*testTOS || plan.Amounts.YesValue != 6*testTOS ||
		string(plan.LeftBOC) != string(leftBOC) || string(plan.RightBOC) != string(rightBOC) {
		t.Fatalf("unexpected exact match plan: %+v err=%v", plan, planErr)
	}
	rotated := leftSnapshot
	copy(rotated.TradingPublicKey[:], bytesOf(0x99, ed25519.PublicKeySize))
	if _, err := book.PlanMatch(left.Digest, rightDigest.CellHashString(), 1, 10_001,
		marketSnapshot, rotated, rightSnapshot); err == nil {
		t.Fatal("planned a fill after the owner's trading key changed")
	}

	txHash, view := testHash(0xa1).SHA256String(), testHash(0xa2).SHA256String()
	if err := book.ApplyFinalizedFill(left.Digest, 5, txHash, view); err != nil {
		t.Fatal(err)
	}
	if err := book.ApplyFinalizedFill(left.Digest, 5, testHash(0xa3).SHA256String(), view); err == nil {
		t.Fatal("same cumulative fill accepted conflicting finality evidence")
	}
	if err := book.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, reopenErr := OpenBook(directory, profile())
	if reopenErr != nil {
		t.Fatalf("crash recovery rejected valid durable state: %v", reopenErr)
	}
	book = reopened
	orders := book.LiveOrders()
	if len(orders) != 2 || orders[0].CumulativeFilled+orders[1].CumulativeFilled != 5 {
		t.Fatalf("recovered wrong live orders: %+v", orders)
	}
}

func TestBookRejectsTamperedDurableSignedBytes(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "orders")
	book, openErr := OpenBook(directory, profile())
	if openErr != nil {
		t.Fatal(openErr)
	}
	key := ed25519.NewKeyFromSeed(bytesOf(0x61, ed25519.SeedSize))
	owner := rawAddress(0x66)
	boc, _ := signedOrder(t, key, owner, 1, protocol.ActionBuy, protocol.OutcomeYes, protocol.RoleMaker, 5_000, 1)
	if _, err := book.Admit(boc, snapshot(owner, key, testTOS, 0, 0), 10_001); err != nil {
		t.Fatal(err)
	}
	if err := book.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, stateFile)
	raw, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	needle := []byte(`"trading_public_key":"`)
	index := bytes.Index(raw, needle) + len(needle)
	if index < len(needle) {
		t.Fatal("missing durable public key")
	}
	if raw[index] == '0' {
		raw[index] = '1'
	} else {
		raw[index] = '0'
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBook(directory, profile()); err == nil {
		t.Fatal("tampered signed-order binding survived durable reload")
	}
}

func bytesOf(value byte, length int) []byte {
	result := make([]byte, length)
	for index := range result {
		result[index] = value
	}
	return result
}
