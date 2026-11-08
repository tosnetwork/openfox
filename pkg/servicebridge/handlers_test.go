package servicebridge

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-ai/pkg/railgate"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
	"google.golang.org/protobuf/proto"
)

func TestTheProviderTakesAnAcknowledgementOnlyFromTheRequestsBuyerForItsResult(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "provider")
	if err := ensurePrivateDirectory(directory); err != nil {
		t.Fatal(err)
	}
	provider := &Provider{config: ProviderConfig{Directory: directory, Now: time.Now}}
	key := railgate.SlotKey{
		QuoteCommitment: "tvm-cell-sha256:" + strings.Repeat("aa", 32),
		Actor:           "0:" + hex.EncodeToString(testActor[:]),
		RequestID:       3,
	}
	responseHash := [32]byte{0x42}
	record := ProviderRecord{
		State: ProviderDelivering, BuyerAgentID: testBuyer, Actor: key.Actor, RequestID: 3,
		RequestHash: hex.EncodeToString(testRequest[:]), ResponseHash: hex.EncodeToString(responseHash[:]),
	}
	if err := provider.store(key, record, true); err != nil {
		t.Fatal(err)
	}
	ack := func(sender string, hash [32]byte) Message {
		body, err := EncodeAck(hash)
		if err != nil {
			t.Fatal(err)
		}
		return Message{
			SenderAgentID: sender,
			Kind:          FrameResultAck,
			ActorAccount:  testActor,
			RequestID:     3,
			RequestHash:   testRequest,
			Body:          body,
		}
	}
	if err := provider.HandleAck(ack(testSeller, responseHash)); err == nil {
		t.Fatal("an acknowledgement from another Agent than the buyer was taken")
	}
	if err := provider.HandleAck(ack(testBuyer, [32]byte{0x43})); err == nil {
		t.Fatal("an acknowledgement of another result was taken")
	}
	if loaded, _, _ := provider.load(key); loaded.State != ProviderDelivering {
		t.Fatalf("a refused acknowledgement changed the state to %s", loaded.State)
	}
	if err := provider.HandleAck(ack(testBuyer, responseHash)); err != nil {
		t.Fatal(err)
	}
	if loaded, _, _ := provider.load(key); loaded.State != ProviderAcked {
		t.Fatalf("state = %s", loaded.State)
	}
}

func TestTheBuyerTakesAResultOnlyFromThePurchasesProviderForItsRequest(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "purchases")
	if err := ensurePrivateDirectory(directory); err != nil {
		t.Fatal(err)
	}
	buyer := &Buyer{config: BuyerConfig{Directory: directory, Now: time.Now}}
	requestID := uint64(3)
	record := PurchaseRecord{
		Phase: PurchaseTaskSent, RequestHash: hex.EncodeToString(testRequest[:]),
		Actor: "0:" + hex.EncodeToString(testActor[:]), RequestID: &requestID, ProviderAgentID: testSeller,
		CapabilityID: "cap_" + strings.Repeat("33", 32), CommittedNanoTOS: "1",
	}
	if err := ensurePrivateDirectory(buyer.purchaseDir(record.RequestHash)); err != nil {
		t.Fatal(err)
	}
	if err := buyer.savePurchase(record, true); err != nil {
		t.Fatal(err)
	}
	body, err := EncodeResult([32]byte{0x42}, []byte{1, 2, 3}, []byte{4})
	if err != nil {
		t.Fatal(err)
	}
	message := Message{
		SenderAgentID: testBuyer,
		Kind:          FrameResult,
		ActorAccount:  testActor,
		RequestID:     3,
		RequestHash:   testRequest,
		Body:          body,
	}
	if err := buyer.HandleResult(context.Background(), message); err == nil {
		t.Fatal("a result from another Agent than the provider was taken")
	}
	message.SenderAgentID, message.RequestID = testSeller, 4
	if err := buyer.HandleResult(context.Background(), message); err == nil {
		t.Fatal("a result for another request was taken")
	}
	if _, err := os.Lstat(filepath.Join(buyer.purchaseDir(record.RequestHash), "result")); err == nil {
		t.Fatal("a refused result was stored")
	}
	message.RequestID = 3
	if err := buyer.HandleResult(context.Background(), message); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(buyer.purchaseDir(record.RequestHash), "result")); err != nil {
		t.Fatal("the provider's result was not stored")
	}
}

type countingLifecycle struct{ responds int }

func (c *countingLifecycle) Respond(context.Context, string, uint64, [32]byte, string) error {
	c.responds++
	return nil
}
func (c *countingLifecycle) Expire(context.Context, string, uint64) error { return nil }
func (c *countingLifecycle) ClaimRefund(context.Context, string, uint64, string) error {
	return nil
}

type emptyHistory struct{ railgate.Session }

func (emptyHistory) History(context.Context, string, *toschain.ActorTxID) (*toschain.ActorHistory, error) {
	return &toschain.ActorHistory{Result: toschain.HistoryComplete}, nil
}

type emptyHistoryReader struct{}

func (emptyHistoryReader) BeginSession(context.Context) (railgate.Session, error) {
	return emptyHistory{}, nil
}

func TestARespondRetryNeverReachesTheAttestorWithoutTheFreshGateCheck(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "provider")
	if err := ensurePrivateDirectory(directory); err != nil {
		t.Fatal(err)
	}
	lifecycle := &countingLifecycle{}
	now := time.Unix(2_000_000_000, 0)
	courier, err := OpenCourier(filepath.Join(t.TempDir(), "outbox"), testSigner(t, testSeller), &recordingTransport{})
	if err != nil {
		t.Fatal(err)
	}
	provider := &Provider{config: ProviderConfig{
		Directory: directory, Now: func() time.Time { return now }, Lifecycle: lifecycle,
		AttestorController: "service-attestor", History: emptyHistoryReader{}, Courier: courier,
	}}
	key := railgate.SlotKey{
		QuoteCommitment: "tvm-cell-sha256:" + strings.Repeat("aa", 32),
		Actor:           "0:" + hex.EncodeToString(testActor[:]),
		RequestID:       3,
	}
	record := ProviderRecord{
		State: ProviderResponding, BuyerAgentID: testBuyer, Actor: key.Actor, RequestID: 3,
		QuoteCommitment: key.QuoteCommitment, RequestHash: hex.EncodeToString(testRequest[:]),
		ResponseHash: strings.Repeat("42", 32), ResponseDeadline: uint64(now.Unix()) + 3000,
		RespondedAtUnix: now.Add(-time.Hour).Unix(),
	}
	if err = provider.store(key, record, true); err != nil {
		t.Fatal(err)
	}
	if err = provider.Tick(context.Background()); err == nil {
		t.Fatal("a retry without the data for the gate check did not report it")
	}
	if lifecycle.responds != 0 {
		t.Fatalf("the attestor was invoked %d times without a fresh gate check", lifecycle.responds)
	}

	// With every claim input recorded, the retry still reaches the attestor
	// only through the real gate, which refuses a request it never completed.
	verifier, err := railgate.NewVerifier(railgate.VerifierConfig{
		Reader: emptyHistoryReader{}, Manifests: &MemoryManifests{}, Network: testNetwork,
		ActorCodeHash: "tvm-cell-sha256:" + strings.Repeat("88", 32), ProviderAgentID: testSeller,
		CapabilityID: "cap_test", Version: "1.0.0", ExecutionBudget: time.Minute, RespondBudget: 2 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	gate, err := railgate.OpenGate(verifier, filepath.Join(t.TempDir(), "slots"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gate.Close() })
	provider.config.Gate = gate
	packageBytes, err := proto.Marshal(testPackage(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	record.PackageBase64 = base64.StdEncoding.EncodeToString(packageBytes)
	record.BuyerWallet, record.CallLT, record.CallHash = testWallet, 7, strings.Repeat("31", 32)
	record.ExecutionID, record.InputDigest = strings.Repeat("32", 32), strings.Repeat("33", 32)
	record.PriceNanoTOS, record.RespondedAtUnix = "1000000000", now.Add(-time.Hour).Unix()
	if err = provider.store(key, record, false); err != nil {
		t.Fatal(err)
	}
	if err = provider.Tick(context.Background()); err == nil || !strings.Contains(err.Error(), "execution slot") {
		t.Fatalf("a retry the gate cannot recheck was not refused by the gate: %v", err)
	}
	if lifecycle.responds != 0 {
		t.Fatalf("the attestor was invoked %d times past a refusing gate", lifecycle.responds)
	}
}

func TestEveryAuthorizedPurchaseDisclosesItsCostsBeforeTheCall(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "purchases")
	if err := ensurePrivateDirectory(directory); err != nil {
		t.Fatal(err)
	}
	policy := SpendingPolicy{
		MaxCommittedPerPurchase: big.NewInt(1_000_000_000),
		MaxCommittedInWindow:    big.NewInt(2_000_000_000),
		Window:                  time.Hour,
		MaxOpenPurchases:        2,
		AllowedProviders:        map[string]bool{testSeller: true},
		RefundReserve:           big.NewInt(1),
	}
	var shown []Costs
	buyer := &Buyer{config: BuyerConfig{
		Directory: directory, Now: time.Now, Policy: policy,
		Disclose: func(costs Costs) { shown = append(shown, costs) },
	}}
	costs, err := QuoteCosts(big.NewInt(100), big.NewInt(100), 3600, 3600, policy.RefundReserve)
	if err != nil {
		t.Fatal(err)
	}
	if err := buyer.authorize(context.Background(), testSeller, costs); err != nil || len(shown) != 1 {
		t.Fatalf("an automatically authorized purchase was not disclosed first: %d %v", len(shown), err)
	}
	if err := buyer.authorize(context.Background(), testBuyer, costs); err == nil || len(shown) != 1 {
		t.Fatalf("a refused purchase: %d %v", len(shown), err)
	}
}

func TestDispatchKeepsAFailedMessagePendingUntilTheAttemptCap(t *testing.T) {
	inbox, _ := openTestInbox(t, 2, 4)
	frames, err := SplitMessage(FrameResult, testActor, 2, testRequest, fill(100, 7))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = inbox.Put(testSeller, frames[0]); err != nil {
		t.Fatal(err)
	}
	var reports []string
	// A node without a buyer cannot handle a result, so every attempt fails.
	service := &Service{Inbox: inbox, Report: func(stage string, _ error) { reports = append(reports, stage) }}
	for attempt := 1; attempt < maxHandlingAttempts; attempt++ {
		if err := service.Dispatch(context.Background()); err != nil {
			t.Fatal(err)
		}
		if pending, err := inbox.Pending(); err != nil || len(pending) != 1 {
			t.Fatalf("after %d failed handlings the message is not retried: %d %v", attempt, len(pending), err)
		}
	}
	if err := service.Dispatch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if pending, err := inbox.Pending(); err != nil || len(pending) != 0 {
		t.Fatalf("a message that keeps failing is dispatched forever: %d %v", len(pending), err)
	}
	if len(reports) != maxHandlingAttempts {
		t.Fatalf("%d failures reported, want %d", len(reports), maxHandlingAttempts)
	}
}

func TestACorruptAttemptCounterRetiresTheMessageInsteadOfBlockingDispatch(t *testing.T) {
	inbox, directory := openTestInbox(t, 2, 4)
	var keys []string
	for seed := byte(1); seed <= 2; seed++ {
		frames, err := SplitMessage(FrameResult, testActor, uint64(seed), testRequest, fill(100, seed))
		if err != nil {
			t.Fatal(err)
		}
		_, message, err := inbox.Put(testSeller, frames[0])
		if err != nil || message == nil {
			t.Fatal(err)
		}
		keys = append(keys, message.Key)
	}
	var reports []string
	// A node without a buyer cannot handle a result, so every attempt fails.
	service := &Service{Inbox: inbox, Report: func(stage string, _ error) { reports = append(reports, stage) }}
	if err := service.Dispatch(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, key := range keys {
		if err := os.WriteFile(filepath.Join(directory, key, attemptsFile), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	reports = nil
	if err := service.Dispatch(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Both messages are reached: the first corrupt counter does not stop
	// the round, and each is retired with its corruption reported.
	if pending, err := inbox.Pending(); err != nil || len(pending) != 0 {
		t.Fatalf("a message with a corrupt counter stays pending: %d %v", len(pending), err)
	}
	attempts := 0
	for _, stage := range reports {
		if stage == "rail message attempt" {
			attempts++
		}
	}
	if attempts != len(keys) {
		t.Fatalf("%d corrupt counters reported, want %d: %v", attempts, len(keys), reports)
	}
}

func TestStepFreesTheSlotOfAStaleIncompleteMessage(t *testing.T) {
	inbox, directory := openTestInbox(t, 1, 1)
	frames, err := SplitMessage(FrameTask, testActor, 1, testRequest, fill(2*MaxChunkData, 9))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = inbox.Put(testBuyer, frames[0]); err != nil {
		t.Fatal(err)
	}
	assembly := filepath.Join(directory, assemblyKey(testBuyer, frames[0]))
	stale := time.Now().Add(-IncompleteRetention - time.Minute)
	if err = os.Chtimes(assembly, stale, stale); err != nil {
		t.Fatal(err)
	}
	service := &Service{Inbox: inbox, Report: func(stage string, err error) { t.Errorf("%s: %v", stage, err) }}
	service.Step(context.Background())
	if _, err = os.Lstat(assembly); !os.IsNotExist(err) {
		t.Fatal("a round left a stale incomplete message holding its slot")
	}
	next, err := SplitMessage(FrameTask, testActor, 2, testRequest, fill(2*MaxChunkData, 10))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = inbox.Put(testSeller, next[0]); err != nil {
		t.Fatalf("the freed slot is not reusable: %v", err)
	}
}

func TestReadOnlyReadersListStateAndRefuseSymlinkedDirectories(t *testing.T) {
	state := t.TempDir()
	if err := os.Chmod(state, 0o700); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(state, "provider")
	if err := ensurePrivateDirectory(directory); err != nil {
		t.Fatal(err)
	}
	provider := &Provider{config: ProviderConfig{Directory: directory, Now: time.Now}}
	key := railgate.SlotKey{
		QuoteCommitment: "tvm-cell-sha256:" + strings.Repeat("aa", 32),
		Actor:           "0:" + hex.EncodeToString(testActor[:]),
		RequestID:       3,
	}
	record := ProviderRecord{
		State: ProviderDelivering, BuyerAgentID: testBuyer, Actor: key.Actor, RequestID: 3,
		QuoteCommitment: key.QuoteCommitment, RequestHash: hex.EncodeToString(testRequest[:]),
	}
	if err := provider.store(key, record, true); err != nil {
		t.Fatal(err)
	}
	records, err := ReadProviderRecords(state)
	if err != nil || len(records) != 1 || records[0].RequestID != 3 {
		t.Fatalf("the provider's records were not listed: %v %v", records, err)
	}
	if err = ensurePrivateDirectory(filepath.Join(state, "purchases")); err != nil {
		t.Fatal(err)
	}
	if purchases, readErr := ReadPurchases(state); readErr != nil || len(purchases) != 0 {
		t.Fatalf("an empty purchase journal was not listed: %v %v", purchases, readErr)
	}

	elsewhere := t.TempDir()
	if err = os.Chmod(elsewhere, 0o700); err != nil {
		t.Fatal(err)
	}
	if err = ensurePrivateDirectory(filepath.Join(elsewhere, "provider")); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(elsewhere, filepath.Join(state, "linked")); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadProviderRecords(filepath.Join(state, "linked")); err == nil {
		t.Fatal("a symlinked state directory was read")
	}
	redirected := t.TempDir()
	if err = os.Rename(directory, filepath.Join(redirected, "provider")); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(filepath.Join(redirected, "provider"), directory); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadProviderRecords(state); err == nil {
		t.Fatal("a symlinked provider directory was read")
	}
	// The redirected purchase is a well-formed record, so only the directory
	// check refuses it.
	requestHash := strings.Repeat("ab", 32)
	other := &Buyer{config: BuyerConfig{Directory: filepath.Join(elsewhere, "purchases"), Now: time.Now}}
	if err = ensurePrivateDirectory(other.purchaseDir(requestHash)); err != nil {
		t.Fatal(err)
	}
	if err = other.savePurchase(PurchaseRecord{RequestHash: requestHash, Phase: PurchaseCalled}, true); err != nil {
		t.Fatal(err)
	}
	if purchases, readErr := other.Purchases(); readErr != nil || len(purchases) != 1 {
		t.Fatalf("the redirected purchase is not well formed: %v %v", purchases, readErr)
	}
	if err = os.Symlink(other.purchaseDir(requestHash), filepath.Join(state, "purchases", requestHash)); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadPurchases(state); err == nil {
		t.Fatal("a symlinked purchase directory was read")
	}
	if err = os.Chmod(filepath.Join(state, "purchases"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadPurchases(state); err == nil {
		t.Fatal("a purchase journal open to other users was read")
	}
}
