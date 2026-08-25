package earning

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-ai/pkg/commercegate"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type agreementKeyResolver map[string]ed25519.PublicKey

func (r agreementKeyResolver) AuthorizeIntentKey(agentID string, key ed25519.PublicKey, _ time.Time) error {
	if !key.Equal(r[agentID]) {
		return errors.New("untrusted Agent key")
	}
	return nil
}

type allowSettlement struct{}

func (allowSettlement) ValidateSettlementPrerequisite(context.Context, string, commerce.AgreementObligation) error {
	return nil
}

type funded struct{}

func (funded) VerifyExecutionPrerequisites(context.Context, EngagementRecord) (bool, []string, error) {
	return false, nil, nil
}

type successRunner struct{ digest string }

func (r successRunner) RunAgreement(context.Context, commercegate.Launch, *ExecutionEffects) (ExecutionOutcome, error) {
	return ExecutionOutcome{OutcomeDigest: r.digest}, nil
}

type acceptedDelivery struct{}

func (acceptedDelivery) AuthorizationRequest(request DeliveryReleaseRequest) ([]byte, error) {
	return codec.Marshal(request)
}

func (acceptedDelivery) SubmitDelivery(_ context.Context, action commerce.AuthorizedAction, _ commerce.WriterFence,
	_ map[string]commerce.SemanticValue, _ []byte, _ DeliveryReleaseRequest) (commerce.ActionResolution, error) {
	return commerce.ActionResolution{StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest,
		State: commerce.ActionAccepted, SinkReference: "delivery-1", EvidenceRefs: []string{"sha256:" + strings.Repeat("7", 64)}, StateRevision: 1}, nil
}
func (acceptedDelivery) ResolveAction(context.Context, string, string) (commerce.ActionResolution, error) {
	return commerce.ActionResolution{}, errors.New("unused")
}

type validPaymentEvidence struct{}

func (validPaymentEvidence) VerifyPaymentEvidence(commerce.AgreementPaymentRequest, commerce.AgreementPaymentEvidence, time.Time) error {
	return nil
}

func TestAuthorizedAgreementReservesAndExecutesAtMostOnce(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	_, ownerAuthorityKey, _ := ed25519.GenerateKey(rand.Reader)
	pubA, keyA, _ := ed25519.GenerateKey(rand.Reader)
	pubB, keyB, _ := ed25519.GenerateKey(rand.Reader)
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	authority, err := OpenPersonalAuthority(root, "owner-1", "agent-a", "authority-1", ownerAuthorityKey,
		PortfolioLimits{ComputeUnits: 100, ReceivableAtomic: 1_000, MaximumLossAtomic: 1_000})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	profileDigest := commerce.AgentSignatureProfileDigest()
	body := commerce.AgentAgreementBody{SchemaVersion: 1, AgreementID: "agreement-1", Version: 1, NetworkContext: "tos-local",
		Participants:     []commerce.AgreementParticipant{{AgentID: "agent-a", Roles: []string{"provider"}}, {AgentID: "agent-b", Roles: []string{"buyer"}}},
		TermsContentType: "text/plain", Terms: []byte("review one source tree"), ValidFromUnix: uint64(now.Add(-time.Minute).Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()),
		Obligations: []commerce.AgreementObligation{
			{ObligationID: "pay", Kind: "payment", ObligorAgentID: "agent-b", BeneficiaryAgentID: "agent-a", SubjectContentType: "text/plain", Subject: []byte("pay after delivery"),
				Amount:                &commerce.AgreementAmount{AssetNamespace: "tos.native", AssetIdentifier: "TOS", AmountAtomic: "50", Unit: "nano"},
				ConfidentialityPolicy: "none", CancellationPolicy: "before-start", DisputePolicy: "evidence", SettlementAdapterURI: "tos.direct-payment.v1",
				SettlementParameters: []byte("destination-a"), DueAtUnix: uint64(now.Add(40 * time.Minute).Unix()),
				ExpiresAtUnix: uint64(now.Add(50 * time.Minute).Unix()), AuthorizationPredicateIDs: []string{"buyer-pay"}},
			{ObligationID: "work", Kind: "service", ObligorAgentID: "agent-a", BeneficiaryAgentID: "agent-b", SubjectContentType: "text/plain", Subject: []byte("perform review"),
				ConfidentialityPolicy: "private", CancellationPolicy: "before-start", DisputePolicy: "evidence", AuthorizationPredicateIDs: []string{"provider-work"}},
		},
		AuthorizationPredicates: []commerce.AgreementAuthorizationPredicate{
			{PredicateID: "buyer-pay", AuthoritySubject: commerce.AgreementAuthoritySubject{SubjectKind: "agent", SubjectNamespace: "tos.agent", SubjectIdentifier: "agent-b"},
				ObligationIDs: []string{"pay"}, EvidenceProfileURI: commerce.EvidenceProfileAgentSignature, EvidenceProfileVersion: 1, EvidenceProfileDigest: profileDigest,
				ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())},
			{PredicateID: "provider-work", AuthoritySubject: commerce.AgreementAuthoritySubject{SubjectKind: "agent", SubjectNamespace: "tos.agent", SubjectIdentifier: "agent-a"},
				ObligationIDs: []string{"work"}, EvidenceProfileURI: commerce.EvidenceProfileAgentSignature, EvidenceProfileVersion: 1, EvidenceProfileDigest: profileDigest,
				ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())},
		},
	}
	body, err = commerce.PrepareAgreementTargets(body)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := commerce.AgreementBodyDigest(body)
	record, err := authority.RecordAgreementProposal(body, "agent-b", "evt_"+strings.Repeat("1", 64), "sha256:"+strings.Repeat("2", 64))
	if err != nil {
		t.Fatal(err)
	}
	resolver := agreementKeyResolver{"agent-a": pubA, "agent-b": pubB}
	verifier := AgreementEvidenceRouter{AgentAuthority: resolver}
	accept := func(agent string, key ed25519.PrivateKey, predicate commerce.AgreementAuthorizationPredicate) commerce.AgreementAuthorizationEvidence {
		signed, signErr := commerce.SignAgreementAcceptance(commerce.AgreementAcceptanceBody{AgreementID: body.AgreementID, AgreementVersion: body.Version,
			AgreementBodyDigest: digest, AcceptingSubject: predicate.AuthoritySubject, PredicateIDs: []string{predicate.PredicateID},
			EvidenceTargetProjectionDigests: []string{predicate.EvidenceTargetProjectionDigest}, ExpiresAtUnix: body.ExpiresAtUnix}, key)
		if signErr != nil {
			t.Fatal(signErr)
		}
		evidence, evidenceErr := commerce.AgentSignatureEvidence(body, signed)
		if evidenceErr != nil {
			t.Fatal(evidenceErr)
		}
		return evidence
	}
	record, err = authority.RecordAgreementEvidence(digest, accept("agent-b", keyB, body.AuthorizationPredicates[0]), verifier)
	if err != nil || record.State != EngagementAuthorizing {
		t.Fatalf("buyer evidence: %s %v", record.State, err)
	}
	record, err = authority.RecordAgreementEvidence(digest, accept("agent-a", keyA, body.AuthorizationPredicates[1]), verifier)
	if err != nil || record.State != EngagementAgreed {
		t.Fatalf("provider evidence: %s %v", record.State, err)
	}
	scope := []string{"billing.materialize", "billing.resolve", "delivery.release", "execution.prepare", "execution.start", "portfolio.reserve"}
	fence, err := authority.AcquireWriter(context.Background(), "instance-a", scope, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	engine := &Engine{OwnerID: "owner-1", AgentID: "agent-a", MandateDigest: "sha256:" + strings.Repeat("3", 64),
		Gates: FeatureGates{Execution: true}, Authority: authority}
	reservation := ExposureReservation{ReservationID: "sha256:" + strings.Repeat("4", 64), AgreementDigest: digest, ComputeUnits: 10, ReceivableAtomic: 50, MaximumLossAtomic: 50}
	_, record, err = engine.ReserveAgreement(context.Background(), digest, reservation, allowSettlement{}, 1, fence)
	if err != nil || record.State != EngagementReserved {
		t.Fatalf("reserve: %s %v", record.State, err)
	}
	gateDir := t.TempDir()
	if err := os.Chmod(gateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	gate, err := commercegate.Open(gateDir, authority)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	outcomeDigest := "sha256:" + strings.Repeat("5", 64)
	service := ExecutionService{Engine: engine, Gate: gate, Prerequisite: funded{}, Runner: successRunner{digest: outcomeDigest}}
	acceptedInputDigest, _, _, err := AcceptedExecutionInputSetDigest(record, "work")
	if err != nil {
		t.Fatal(err)
	}
	plan := commercegate.Plan{OwnerID: "owner-1", AgentID: "agent-a", AgreementBodyDigest: digest, ExecutionObligationID: "work",
		AcceptedInputManifestDigest: acceptedInputDigest, AttemptIndex: 0,
		PredecessorTerminalResolutionDigest: "sha256:" + strings.Repeat("0", 64), ReservationID: reservation.ReservationID,
		PolicyRevision: 1, LeaseLossPolicy: commercegate.LeaseLossKill}
	// Model a crash after the local Gate persisted PREPARED but before the
	// authority journal advanced the obligation. The normal retry must recover
	// the exact ticket and continue the same execution identity.
	preparedPlan, prepareRequest, prepareFields, err := commercegate.PrepareAuthorizationMaterial(plan, fence)
	if err != nil {
		t.Fatal(err)
	}
	prepareAction, err := commerce.BuildAuthorizedAction("owner-1", "agent-a", "execution.prepare", prepareFields,
		prepareRequest, fence, 1, engine.MandateDigest, "", "reserved",
		minUint64(record.Agreement.Body.ExpiresAtUnix, fence.Body.ExpiresAtUnix))
	if err == nil {
		prepareAction, err = authority.SignAction(prepareAction, fence)
	}
	if err != nil {
		t.Fatal(err)
	}
	preparedTicket, err := gate.Prepare(context.Background(), preparedPlan, fence, 2*time.Minute, prepareAction)
	if err != nil {
		t.Fatal(err)
	}
	record, err = service.Execute(context.Background(), digest, plan, 1, fence)
	if err != nil || record.State != EngagementExecutionSucceeded {
		t.Fatalf("execute: %s %v", record.State, err)
	}
	if record.ExecutionID != preparedTicket.ExecutionID {
		t.Fatal("retry allocated a second execution after PREPARED crash")
	}
	state, _, err := gate.Resolve(record.ExecutionID)
	if err != nil || state != commercegate.StateSucceeded {
		t.Fatalf("gate: %s %v", state, err)
	}
	// Model the only crash window after the Gate durably records success but
	// before the authority journal records the terminal obligation projection.
	// Recovery must consume the existing outcome, never run the work again.
	authority.mu.Lock()
	rolledBack := authority.doc.Engagements[digest]
	runtime := rolledBack.ObligationRuntime["work"]
	runtime.State = ObligationExecuting
	runtime.ExecutionEvidence = nil
	runtime.ExecutionCompletedAtUnix = 0
	rolledBack.ObligationRuntime["work"] = runtime
	rolledBack.State = EngagementExecuting
	next := cloneAuthorityDocument(authority.doc)
	next.Engagements[digest] = rolledBack
	if err := authority.persist(next); err != nil {
		authority.mu.Unlock()
		t.Fatal(err)
	}
	authority.doc = next
	authority.mu.Unlock()
	recovered, err := service.Execute(context.Background(), digest, plan, 1, fence)
	if err != nil || recovered.ObligationRuntime["work"].State != ObligationExecutionSucceeded ||
		recovered.ObligationRuntime["work"].ExecutionCompletedAtUnix == 0 {
		t.Fatalf("recover successful Gate outcome: %+v %v", recovered.ObligationRuntime["work"], err)
	}
	completedAt := recovered.ObligationRuntime["work"].ExecutionCompletedAtUnix
	authority.now = func() time.Time { return time.Unix(int64(completedAt), 0).UTC().Add(time.Minute) }
	record = recovered
	record, err = engine.Deliver(context.Background(), digest, "work", "agent-b", outcomeDigest, acceptedDelivery{}, 1, fence)
	if err != nil || record.State != EngagementDelivered {
		t.Fatalf("delivery: %s %v", record.State, err)
	}
	if record.ObligationRuntime["work"].ExecutionCompletedAtUnix != completedAt ||
		record.ObligationRuntime["work"].ExecutionCompletedAtUnix == record.ObligationRuntime["work"].LastTransitionAtUnix {
		t.Fatal("delivery overwrote the exact execution completion time")
	}
	billing := BillingService{Engine: engine}
	obligations, record, err := billing.MaterializeAfterDelivery(digest, 1, fence)
	if err != nil || len(obligations) != 1 || record.State != EngagementSettling {
		t.Fatalf("billing: %d %s %v", len(obligations), record.State, err)
	}
	authority.now = func() time.Time { return now.Add(41 * time.Minute) }
	record, err = (BillingService{Engine: engine}).MarkOverdue(digest, now.Add(41*time.Minute), 1, fence)
	if err != nil || record.State != EngagementUnpaid {
		t.Fatalf("overdue: %s %v", record.State, err)
	}
	paymentRequest, err := commerce.BuildAgreementPaymentRequest("owner-1", "agent-a", "tos-local", []byte("destination-a"), obligations[0].Obligation)
	if err != nil {
		t.Fatal(err)
	}
	paymentDigest, _ := commerce.AgreementPaymentRequestDigest(paymentRequest)
	paymentEvidence := commerce.AgreementPaymentEvidence{PaymentRequestDigest: paymentDigest, StableActionID: paymentRequest.StableActionID,
		ExactTransferReference: "tx-1", AdapterEvidenceProfile: "tos.finalized-transfer.v1", ResolvedState: "finalized",
		ResolvedAtUnix: uint64(now.Unix()), FinalityReference: "checkpoint-1", Evidence: []byte("finalized proof")}
	_, record, err = billing.ApplyPayment(paymentRequest, paymentEvidence, validPaymentEvidence{}, 1, fence)
	if err != nil || record.State != EngagementSettled {
		t.Fatalf("payment: %s %v", record.State, err)
	}
}
