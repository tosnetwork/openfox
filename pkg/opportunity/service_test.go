package opportunity

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeCoordinator struct {
	hints       []CandidateHint
	verified    VerifiedCandidate
	searchErr   error
	verifyErr   error
	searchCalls int
	verifyCalls int
}

type fakePurchaseRunner struct {
	calls    int
	rejectAt Phase
}

func (f *fakePurchaseRunner) AdvancePurchase(_ context.Context, request PurchaseRequest) (PurchaseProgress, error) {
	f.calls++
	if f.rejectAt == request.Current {
		return PurchaseProgress{}, &PurchaseRejection{Reason: "outside exact owner policy"}
	}
	progress := PurchaseProgress{IntentID: request.IntentID, CandidateKey: request.Candidate.Key,
		AssetMaster: "0:" + strings.Repeat("1", 64), AtomicAmount: "25000000", QuoteExpiryUnix: 1_900_003_600}
	switch request.Current {
	case PhaseQuoteRequested:
		progress.Phase = PhaseQuoteVerified
	case PhaseQuoteVerified:
		progress.Phase = PhasePolicyAuthorized
	case PhasePolicyAuthorized:
		progress.Phase = PhasePurchaseReferenced
		progress.Key = &PurchaseKey{QuoteCommitment: "tvm-cell-sha256:" + strings.Repeat("2", 64), EscrowAddress: "0:" + strings.Repeat("3", 64)}
		progress.AuthoritativePhase = "prepared"
	case PhasePurchaseReferenced:
		progress.Phase = PhasePurchaseResolved
		progress.Key = request.Key
		progress.AuthoritativePhase = "resolved"
		progress.FinalizedCheckpoint = 99
		progress.Released = true
	default:
		return PurchaseProgress{}, errors.New("unexpected phase")
	}
	return progress, nil
}

func (f *fakeCoordinator) Search(_ context.Context, request SearchRequest) ([]CandidateHint, error) {
	f.searchCalls++
	if !requestPattern.MatchString(request.RequestID) || request.Query == "" || request.DeadlineUnixMS <= 0 {
		return nil, errors.New("bad request")
	}
	return append([]CandidateHint(nil), f.hints...), f.searchErr
}

func (f *fakeCoordinator) Verify(_ context.Context, _ CandidateHint) (VerifiedCandidate, error) {
	f.verifyCalls++
	return f.verified, f.verifyErr
}

func testCandidate() (CandidateHint, VerifiedCandidate) {
	key := CandidateKey{Network: Network{ID: "tos-test", GenesisRootHash: strings.Repeat("a", 64),
		GenesisFileHash: strings.Repeat("b", 64)}, CapabilityID: "cap_" + strings.Repeat("c", 64),
		Version: "1.0.0", ManifestDigest: "sha256:" + strings.Repeat("d", 64),
		ProviderAgentID: "agent_" + strings.Repeat("e", 64)}
	hint := CandidateHint{Key: key, GatewayIDs: []string{"gateway-a", "gateway-b"}, GatewayMatchScore: 77,
		HintCheckpoint: 40, DisplayName: "Bounded test", DisplayDescription: "Gateway-local display only",
		OperationHint: "test"}
	verified := VerifiedCandidate{Key: key, FinalizedCheckpoint: 42,
		TVMStateHash: "tvm-cell-sha256:" + strings.Repeat("f", 64), Operation: "test",
		ManifestName: "Bounded test", VerifiedAtUnix: 1_900_000_000}
	return hint, verified
}

func observeConfig() Config {
	return Config{Mode: ModeObserve, Queries: []string{"go test work"}, Interval: 5 * time.Minute,
		RequestTimeout: 5 * time.Second, PageSize: 10, MaxCandidates: 20, AllowedOperations: []string{"test"}}
}

func openTestJournal(t *testing.T) (*Journal, string) {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "opportunities")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	return journal, directory
}

func TestObserveCycleVerifiesAssessesAndSurvivesRestart(t *testing.T) {
	hint, verified := testCandidate()
	coordinator := &fakeCoordinator{hints: []CandidateHint{hint}, verified: verified}
	journal, directory := openTestJournal(t)
	service, err := NewService(observeConfig(), coordinator, journal, nil)
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return time.Unix(1_900_000_000, 0) }
	if err := service.Cycle(context.Background()); err != nil {
		t.Fatalf("cycle: %v", err)
	}
	records := journal.List()
	if len(records) != 1 || records[0].Phase != PhaseAssessed || records[0].Verified == nil ||
		records[0].Assessment == nil || !records[0].Assessment.Eligible || records[0].Assessment.Score != 77 {
		t.Fatalf("unexpected opportunity state: %+v", records)
	}

	reopened, err := OpenJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	restarted, _ := NewService(observeConfig(), coordinator, reopened, nil)
	restarted.now = service.now
	if err := restarted.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if coordinator.verifyCalls != 1 || len(reopened.List()) != 1 {
		t.Fatalf("restart repeated verification or duplicated intent: verifies=%d records=%d", coordinator.verifyCalls, len(reopened.List()))
	}
}

func TestGatewayHintCannotSubstituteFinalizedCandidate(t *testing.T) {
	hint, verified := testCandidate()
	verified.Key.ManifestDigest = "sha256:" + strings.Repeat("1", 64)
	coordinator := &fakeCoordinator{hints: []CandidateHint{hint}, verified: verified}
	journal, _ := openTestJournal(t)
	service, _ := NewService(observeConfig(), coordinator, journal, nil)
	service.now = func() time.Time { return time.Unix(1_900_000_000, 0) }
	if err := service.Cycle(context.Background()); err == nil {
		t.Fatal("finalized candidate substitution was accepted")
	}
	records := journal.List()
	if len(records) != 1 || records[0].Phase != PhaseDiscovered || records[0].Verified != nil {
		t.Fatalf("substituted candidate advanced: %+v", records)
	}
}

func TestFinalizedRejectionIsTerminalWithoutCustody(t *testing.T) {
	hint, _ := testCandidate()
	coordinator := &fakeCoordinator{hints: []CandidateHint{hint}, verifyErr: &Rejection{Reason: "Capability tombstoned"}}
	journal, _ := openTestJournal(t)
	service, _ := NewService(observeConfig(), coordinator, journal, nil)
	service.now = func() time.Time { return time.Unix(1_900_000_000, 0) }
	if err := service.Cycle(context.Background()); !errors.Is(err, ErrCoordinatorRejected) {
		t.Fatalf("unexpected rejection: %v", err)
	}
	records := journal.List()
	if len(records) != 1 || records[0].Phase != PhaseFailed || !strings.Contains(records[0].Failure, "tombstoned") {
		t.Fatalf("rejection was not retained: %+v", records)
	}
}

func TestOpportunityConfigurationFailsClosed(t *testing.T) {
	if err := (Config{Mode: ModeOff, Queries: []string{"unused"}}).Validate(); err == nil {
		t.Fatal("disabled mode accepted active settings")
	}
	config := observeConfig()
	config.AllowedProviders = []string{"agent_" + strings.Repeat("a", 64)}
	config.DeniedProviders = append([]string(nil), config.AllowedProviders...)
	if err := config.Validate(); err == nil {
		t.Fatal("overlapping provider policy was accepted")
	}
	config = observeConfig()
	config.Mode = ModePolicyGated
	journal, _ := openTestJournal(t)
	if _, err := NewService(config, &fakeCoordinator{}, journal, nil); !errors.Is(err, ErrPolicyRunnerRequired) {
		t.Fatalf("policy mode silently ran without a purchase runner: %v", err)
	}
}

func TestPolicyGatedCycleMirrorsPurchaseKeyAndResumesToFinalizedSettlement(t *testing.T) {
	hint, verified := testCandidate()
	coordinator := &fakeCoordinator{hints: []CandidateHint{hint}, verified: verified}
	runner := &fakePurchaseRunner{}
	journal, directory := openTestJournal(t)
	config := observeConfig()
	config.Mode = ModePolicyGated
	service, err := NewServiceWithPurchaseRunner(config, coordinator, runner, journal, nil)
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return time.Unix(1_900_000_000, 0) }
	if err := service.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	record := journal.List()[0]
	if record.Phase != PhasePurchaseReferenced || record.Purchase == nil || record.Purchase.Key == nil ||
		record.Purchase.AuthoritativePhase != "prepared" {
		t.Fatalf("purchase identity was not durably mirrored: %+v", record)
	}

	reopened, err := OpenJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	restarted, _ := NewServiceWithPurchaseRunner(config, coordinator, runner, reopened, nil)
	restarted.now = service.now
	if err := restarted.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	record = reopened.List()[0]
	if record.Phase != PhasePurchaseResolved || record.Purchase == nil || !record.Purchase.Released ||
		record.Purchase.Refunded || record.Purchase.FinalizedCheckpoint != 99 || runner.calls != 4 {
		t.Fatalf("purchase did not recover to exact finalized settlement: record=%+v calls=%d", record, runner.calls)
	}
}

func TestPolicyRejectionBeforePurchaseKeyIsTerminalWithoutCustodyRetry(t *testing.T) {
	hint, verified := testCandidate()
	coordinator := &fakeCoordinator{hints: []CandidateHint{hint}, verified: verified}
	runner := &fakePurchaseRunner{rejectAt: PhaseQuoteVerified}
	journal, _ := openTestJournal(t)
	config := observeConfig()
	config.Mode = ModePolicyGated
	service, _ := NewServiceWithPurchaseRunner(config, coordinator, runner, journal, nil)
	service.now = func() time.Time { return time.Unix(1_900_000_000, 0) }
	if err := service.Cycle(context.Background()); !errors.Is(err, ErrPurchaseRejected) {
		t.Fatalf("unexpected policy rejection: %v", err)
	}
	record := journal.List()[0]
	if record.Phase != PhaseFailed || record.Purchase == nil || record.Purchase.Key != nil || !strings.Contains(record.Failure, "owner policy") {
		t.Fatalf("pre-funding rejection was not terminally retained: %+v", record)
	}
}

func TestJournalRefusesWeakPermissionsAndUnknownFields(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "weak")
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJournal(directory); err == nil {
		t.Fatal("world-readable journal directory was accepted")
	}
	directory = filepath.Join(t.TempDir(), "strict")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, journalFile), []byte(`{"schema":"tos.openfox.opportunity-journal.v1","records":[],"authority":"gateway"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJournal(directory); err == nil {
		t.Fatal("unknown journal authority field was accepted")
	}
}
