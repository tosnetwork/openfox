package earning

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-ai/pkg/commercegate"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

type milestoneRunnerFactory struct{}

func (milestoneRunnerFactory) RunnerFor(EngagementRecord) (AgreementRunner, error) {
	return nil, fmt.Errorf("obligation-scoped runner is required")
}

func (milestoneRunnerFactory) RunnerForObligation(_ EngagementRecord, obligationID string) (AgreementRunner, error) {
	fill := "8"
	if obligationID == "work-2" {
		fill = "9"
	}
	return successRunner{digest: "sha256:" + strings.Repeat(fill, 64)}, nil
}

func TestEngagementAutonomyExecutesAndBillsMultipleDependentObligations(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	_, authorityKey, _ := ed25519.GenerateKey(rand.Reader)
	providerPublic, providerKey, _ := ed25519.GenerateKey(rand.Reader)
	buyerPublic, buyerKey, _ := ed25519.GenerateKey(rand.Reader)
	authority, err := OpenPersonalAuthority(privateTempDir(t), "owner-provider", "agent-provider", "authority-provider",
		authorityKey, PortfolioLimits{ComputeUnits: 100, ReceivableAtomic: 1_000, MaximumLossAtomic: 1_000})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	authority.now = func() time.Time { return now }

	profileDigest := commerce.AgentSignatureProfileDigest()
	body := commerce.AgentAgreementBody{SchemaVersion: 1, AgreementID: "agreement-milestones", Version: 1,
		NetworkContext: "tos-local", Participants: []commerce.AgreementParticipant{
			{AgentID: "agent-buyer", Roles: []string{"buyer"}}, {AgentID: "agent-provider", Roles: []string{"provider"}},
		}, TermsContentType: "text/plain", Terms: []byte("two independently verifiable milestones"),
		ValidFromUnix: uint64(now.Add(-time.Minute).Unix()), ExpiresAtUnix: uint64(now.Add(50 * time.Minute).Unix()),
		Obligations: []commerce.AgreementObligation{
			{ObligationID: "pay-1", Kind: "payment", ObligorAgentID: "agent-buyer", BeneficiaryAgentID: "agent-provider",
				DependsOnObligationIDs: []string{"work-1"}, SubjectContentType: "text/plain", Subject: []byte("first milestone payment"),
				Amount:    &commerce.AgreementAmount{AssetNamespace: "tos.native", AssetIdentifier: "TOS", AmountAtomic: "20", Unit: "nano"},
				DueAtUnix: uint64(now.Add(30 * time.Minute).Unix()), ExpiresAtUnix: uint64(now.Add(45 * time.Minute).Unix()),
				ConfidentialityPolicy: "none", CancellationPolicy: "before-due", DisputePolicy: "evidence",
				SettlementAdapterURI: "tos.direct-payment.v1", SettlementParameters: []byte("destination-provider"),
				AuthorizationPredicateIDs: []string{"buyer-payments"}},
			{ObligationID: "pay-2", Kind: "payment", ObligorAgentID: "agent-buyer", BeneficiaryAgentID: "agent-provider",
				DependsOnObligationIDs: []string{"work-2"}, SubjectContentType: "text/plain", Subject: []byte("second milestone payment"),
				Amount:    &commerce.AgreementAmount{AssetNamespace: "tos.native", AssetIdentifier: "TOS", AmountAtomic: "30", Unit: "nano"},
				DueAtUnix: uint64(now.Add(35 * time.Minute).Unix()), ExpiresAtUnix: uint64(now.Add(45 * time.Minute).Unix()),
				ConfidentialityPolicy: "none", CancellationPolicy: "before-due", DisputePolicy: "evidence",
				SettlementAdapterURI: "tos.direct-payment.v1", SettlementParameters: []byte("destination-provider"),
				AuthorizationPredicateIDs: []string{"buyer-payments"}},
			{ObligationID: "work-1", Kind: "service", ObligorAgentID: "agent-provider", BeneficiaryAgentID: "agent-buyer",
				SubjectContentType: "text/plain", Subject: []byte("perform milestone one"), ConfidentialityPolicy: "private",
				CancellationPolicy: "before-start", DisputePolicy: "evidence", AuthorizationPredicateIDs: []string{"provider-work"}},
			{ObligationID: "work-2", Kind: "service", ObligorAgentID: "agent-provider", BeneficiaryAgentID: "agent-buyer",
				DependsOnObligationIDs: []string{"work-1"}, SubjectContentType: "text/plain", Subject: []byte("perform milestone two"),
				ConfidentialityPolicy: "private", CancellationPolicy: "before-start", DisputePolicy: "evidence",
				AuthorizationPredicateIDs: []string{"provider-work"}},
		}, AuthorizationPredicates: []commerce.AgreementAuthorizationPredicate{
			{PredicateID: "buyer-payments", AuthoritySubject: commerce.AgreementAuthoritySubject{SubjectKind: "agent", SubjectNamespace: "tos.agent", SubjectIdentifier: "agent-buyer"},
				ObligationIDs: []string{"pay-1", "pay-2"}, EvidenceProfileURI: commerce.EvidenceProfileAgentSignature,
				EvidenceProfileVersion: 1, EvidenceProfileDigest: profileDigest, ExpiresAtUnix: uint64(now.Add(50 * time.Minute).Unix())},
			{PredicateID: "provider-work", AuthoritySubject: commerce.AgreementAuthoritySubject{SubjectKind: "agent", SubjectNamespace: "tos.agent", SubjectIdentifier: "agent-provider"},
				ObligationIDs: []string{"work-1", "work-2"}, EvidenceProfileURI: commerce.EvidenceProfileAgentSignature,
				EvidenceProfileVersion: 1, EvidenceProfileDigest: profileDigest, ExpiresAtUnix: uint64(now.Add(50 * time.Minute).Unix())},
		}}
	body, err = commerce.PrepareAgreementTargets(body)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := commerce.AgreementBodyDigest(body)
	if _, err = authority.RecordAgreementProposal(body, "agent-buyer", "evt_"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	resolver := agreementKeyResolver{"agent-buyer": buyerPublic, "agent-provider": providerPublic}
	verifier := AgreementEvidenceRouter{AgentAuthority: resolver}
	for _, item := range []struct {
		predicate commerce.AgreementAuthorizationPredicate
		key       ed25519.PrivateKey
	}{
		{body.AuthorizationPredicates[0], buyerKey}, {body.AuthorizationPredicates[1], providerKey},
	} {
		acceptance, signErr := commerce.SignAgreementAcceptance(commerce.AgreementAcceptanceBody{AgreementID: body.AgreementID,
			AgreementVersion: body.Version, AgreementBodyDigest: digest, AcceptingSubject: item.predicate.AuthoritySubject,
			PredicateIDs: []string{item.predicate.PredicateID}, EvidenceTargetProjectionDigests: []string{item.predicate.EvidenceTargetProjectionDigest},
			ExpiresAtUnix: body.ExpiresAtUnix}, item.key)
		if signErr != nil {
			t.Fatal(signErr)
		}
		evidence, evidenceErr := commerce.AgentSignatureEvidence(body, acceptance)
		if evidenceErr != nil {
			t.Fatal(evidenceErr)
		}
		if _, evidenceErr = authority.RecordAgreementEvidence(digest, evidence, verifier); evidenceErr != nil {
			t.Fatal(evidenceErr)
		}
	}
	scope := []string{"billing.materialize", "billing.resolve", "delivery.release", "execution.prepare", "execution.start",
		"portfolio.reserve", "schedule.entry.transition", "reconcile.apply", "portfolio.release"}
	fence, err := authority.AcquireWriter(context.Background(), "runtime-provider", scope, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	engine := &Engine{OwnerID: "owner-provider", AgentID: "agent-provider", MandateDigest: "sha256:" + strings.Repeat("c", 64),
		Gates: FeatureGates{Execution: true}, Authority: authority, Now: func() time.Time { return now }}
	gateDirectory := t.TempDir()
	if err := os.Chmod(gateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	gate, err := commercegate.Open(gateDirectory, authority)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	inventory := InventorySourceFunc(func(context.Context) (InventorySnapshot, error) {
		revision, _, _ := authority.Snapshot()
		return InventorySnapshot{OwnerID: "owner-provider", AgentID: "agent-provider", CreatedAtUnix: uint64(now.Add(-time.Second).Unix()),
			ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()), SourceGeneration: 1, PortfolioRevision: revision, PolicyRevision: 1,
			ConsistencyToken: fmt.Sprintf("portfolio:%d", revision), Available: ResourceCapacity{CPUUnits: 100, Concurrency: 2},
			SupportedSettlementAdapters: []string{"tos.direct-payment.v1"}}, nil
	})
	scheduler := &SchedulerService{Authority: authority, OwnerID: "owner-provider", AgentID: "agent-provider",
		MandateDigest: engine.MandateDigest, PolicyRevision: 1}
	autonomy := EngagementAutonomy{Engine: engine, Inventory: inventory,
		Planner:      BoundedEngagementPlanner{OwnerID: "owner-provider", AgentID: "agent-provider", ComputeUnitsPerExecution: 5},
		Prerequisite: AdapterPrerequisitePolicy{LocalAgentID: "agent-provider", PostpaidAdapters: []string{"tos.direct-payment.v1"}},
		Gate:         gate, Scheduler: scheduler, Runners: milestoneRunnerFactory{}, Delivery: acceptedDelivery{},
		Fence: func(context.Context) (commerce.WriterFence, error) { return fence, nil }}
	advanced, err := autonomy.Process(context.Background(), 32)
	if err != nil {
		t.Fatalf("autonomy advanced=%d: %v", advanced, err)
	}
	record, _ := authority.Engagement(digest)
	for _, obligationID := range []string{"work-1", "work-2"} {
		if record.ObligationRuntime[obligationID].State != ObligationDelivered {
			t.Fatalf("%s runtime=%+v", obligationID, record.ObligationRuntime[obligationID])
		}
	}
	for _, obligationID := range []string{"pay-1", "pay-2"} {
		if record.ObligationRuntime[obligationID].State != ObligationSettling {
			t.Fatalf("%s runtime=%+v", obligationID, record.ObligationRuntime[obligationID])
		}
	}
	ledgers := authority.SettlementSnapshot(digest)
	if len(ledgers) != 2 {
		t.Fatalf("settlement ledger count=%d", len(ledgers))
	}
	entries, _ := authority.ScheduleSnapshot()
	if len(entries) != 2 || entries[0].State != commerce.ScheduleSucceeded || entries[1].State != commerce.ScheduleSucceeded {
		t.Fatalf("schedule entries=%+v", entries)
	}

	billing := BillingService{Engine: engine}
	for index, ledger := range ledgers {
		request, buildErr := commerce.BuildAgreementPaymentRequest("owner-provider", "agent-provider", "tos-local",
			[]byte("destination-provider"), ledger.Obligation)
		if buildErr != nil {
			t.Fatal(buildErr)
		}
		requestDigest, _ := commerce.AgreementPaymentRequestDigest(request)
		evidence := commerce.AgreementPaymentEvidence{PaymentRequestDigest: requestDigest, StableActionID: request.StableActionID,
			ExactTransferReference: fmt.Sprintf("tx-%d", index+1), AdapterEvidenceProfile: "tos.finalized-transfer.v1", ResolvedState: "finalized",
			ResolvedAtUnix: uint64(now.Unix()), FinalityReference: fmt.Sprintf("block-%d", index+1), Evidence: []byte("finalized proof")}
		if _, _, applyErr := billing.ApplyPayment(request, evidence, validPaymentEvidence{}, 1, fence); applyErr != nil {
			t.Fatal(applyErr)
		}
	}
	record, _ = authority.Engagement(digest)
	if record.State != EngagementSettled {
		t.Fatalf("final engagement=%s", record.State)
	}
}
