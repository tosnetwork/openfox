package nativeimpl

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tosnetwork/openfox/pkg/opportunity"
)

type purchaseBackendFake struct {
	prepareCalls, authorizeCalls, referenceCalls, reconcileCalls int
	rejectAuthorization                                          bool
	settled                                                      bool
}

func (f *purchaseBackendFake) Prepare(_ context.Context, _ string, candidate opportunity.VerifiedCandidate) (PreparedOpportunityQuote, error) {
	f.prepareCalls++
	return PreparedOpportunityQuote{Candidate: candidate.Key, ArtifactDigest: "sha256:" + strings.Repeat("1", 64),
		AssetMaster: "0:" + strings.Repeat("2", 64), AtomicAmount: "25", QuoteExpiryUnix: 1_900_003_600}, nil
}

func (f *purchaseBackendFake) Authorize(context.Context, string, PreparedOpportunityQuote) error {
	f.authorizeCalls++
	if f.rejectAuthorization {
		return ErrPurchasePolicyRejected
	}
	return nil
}

func (f *purchaseBackendFake) Reference(context.Context, string, PreparedOpportunityQuote) (opportunity.PurchaseKey, string, error) {
	f.referenceCalls++
	return opportunity.PurchaseKey{QuoteCommitment: "tvm-cell-sha256:" + strings.Repeat("3", 64),
		EscrowAddress: "0:" + strings.Repeat("4", 64)}, "prepared", nil
}

func (f *purchaseBackendFake) Reconcile(context.Context, string, PreparedOpportunityQuote, opportunity.PurchaseKey) (PurchaseSettlement, error) {
	f.reconcileCalls++
	if !f.settled {
		return PurchaseSettlement{AuthoritativePhase: "funding_lease"}, nil
	}
	return PurchaseSettlement{AuthoritativePhase: "resolved", FinalizedCheckpoint: 77, Released: true}, nil
}

func purchaseCandidate() opportunity.VerifiedCandidate {
	return opportunity.VerifiedCandidate{Key: opportunity.CandidateKey{Network: opportunity.Network{ID: "tos-test",
		GenesisRootHash: strings.Repeat("a", 64), GenesisFileHash: strings.Repeat("b", 64)},
		CapabilityID: "cap_" + strings.Repeat("c", 64), Version: "1.0.0",
		ManifestDigest: "sha256:" + strings.Repeat("d", 64), ProviderAgentID: "agent_" + strings.Repeat("e", 64)},
		FinalizedCheckpoint: 42, TVMStateHash: "tvm-cell-sha256:" + strings.Repeat("f", 64),
		Operation: "test", ManifestName: "test", VerifiedAtUnix: 1_900_000_000}
}

func purchaseCoordinatorDirectory(t *testing.T) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "purchase")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func TestPurchaseCoordinatorPersistsExactIdentityAndRecovers(t *testing.T) {
	backend := &purchaseBackendFake{}
	directory := purchaseCoordinatorDirectory(t)
	coordinator, err := OpenPurchaseCoordinator(directory, backend)
	if err != nil {
		t.Fatal(err)
	}
	request := opportunity.PurchaseRequest{IntentID: "opp_" + strings.Repeat("a", 64),
		Current: opportunity.PhaseQuoteRequested, Candidate: purchaseCandidate()}
	quote, err := coordinator.AdvancePurchase(context.Background(), request)
	if err != nil || quote.Phase != opportunity.PhaseQuoteVerified || quote.Key != nil {
		t.Fatalf("quote: %+v err=%v", quote, err)
	}
	request.Current = quote.Phase
	policy, err := coordinator.AdvancePurchase(context.Background(), request)
	if err != nil || policy.Phase != opportunity.PhasePolicyAuthorized {
		t.Fatalf("policy: %+v err=%v", policy, err)
	}
	request.Current = policy.Phase
	referenced, err := coordinator.AdvancePurchase(context.Background(), request)
	if err != nil || referenced.Phase != opportunity.PhasePurchaseReferenced || referenced.Key == nil {
		t.Fatalf("reference: %+v err=%v", referenced, err)
	}

	reopened, err := OpenPurchaseCoordinator(directory, backend)
	if err != nil {
		t.Fatal(err)
	}
	request.Current, request.Key = referenced.Phase, referenced.Key
	pending, err := reopened.AdvancePurchase(context.Background(), request)
	if err != nil || pending.Phase != opportunity.PhasePurchaseReferenced || pending.AuthoritativePhase != "funding_lease" {
		t.Fatalf("pending reconcile: %+v err=%v", pending, err)
	}
	backend.settled = true
	resolved, err := reopened.AdvancePurchase(context.Background(), request)
	if err != nil || resolved.Phase != opportunity.PhasePurchaseResolved || !resolved.Released || resolved.Refunded ||
		resolved.FinalizedCheckpoint != 77 || backend.prepareCalls != 1 || backend.referenceCalls != 1 {
		t.Fatalf("resolved: %+v err=%v calls=%+v", resolved, err, backend)
	}
}

func TestPurchaseCoordinatorRejectsChangedResumeKeyAndPolicy(t *testing.T) {
	backend := &purchaseBackendFake{rejectAuthorization: true}
	coordinator, _ := OpenPurchaseCoordinator(purchaseCoordinatorDirectory(t), backend)
	request := opportunity.PurchaseRequest{IntentID: "opp_" + strings.Repeat("a", 64),
		Current: opportunity.PhaseQuoteRequested, Candidate: purchaseCandidate()}
	quote, _ := coordinator.AdvancePurchase(context.Background(), request)
	request.Current = quote.Phase
	if _, err := coordinator.AdvancePurchase(context.Background(), request); !errors.Is(err, opportunity.ErrPurchaseRejected) {
		t.Fatalf("signed-policy rejection was not classified before custody: %v", err)
	}
	request.Current = opportunity.PhasePolicyAuthorized
	request.Key = &opportunity.PurchaseKey{QuoteCommitment: "tvm-cell-sha256:" + strings.Repeat("9", 64),
		EscrowAddress: "0:" + strings.Repeat("8", 64)}
	if _, err := coordinator.AdvancePurchase(context.Background(), request); err == nil {
		t.Fatal("changed or invented PurchaseKey was accepted")
	}
}
