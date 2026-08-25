package earning

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"strings"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

func TestReconciliationReleasesOnlyTerminalExactReservations(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	authority, err := OpenPersonalAuthority(directory, "owner:r", "agent:r", "authority:r", key,
		PortfolioLimits{ComputeUnits: 10, ReceivableAtomic: 100, MaximumLossAtomic: 100})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()

	now := time.Now().UTC().Truncate(time.Second)
	profileDigest := commerce.AgentSignatureProfileDigest()
	body := commerce.AgentAgreementBody{SchemaVersion: 1, AgreementID: "agreement:r", Version: 1, NetworkContext: "tos-local",
		Participants:     []commerce.AgreementParticipant{{AgentID: "agent:buyer", Roles: []string{"buyer"}}, {AgentID: "agent:r", Roles: []string{"provider"}}},
		TermsContentType: "text/plain", Terms: []byte("perform bounded work"),
		Obligations: []commerce.AgreementObligation{{ObligationID: "work", Kind: "service", ObligorAgentID: "agent:r",
			BeneficiaryAgentID: "agent:buyer", SubjectContentType: "text/plain", Subject: []byte("work"), ConfidentialityPolicy: "none",
			CancellationPolicy: "before-start", DisputePolicy: "evidence", AuthorizationPredicateIDs: []string{"provider"}}},
		AuthorizationPredicates: []commerce.AgreementAuthorizationPredicate{{PredicateID: "provider",
			AuthoritySubject: commerce.AgreementAuthoritySubject{SubjectKind: "agent", SubjectNamespace: "tos.agent", SubjectIdentifier: "agent:r"},
			ObligationIDs:    []string{"work"}, EvidenceProfileURI: commerce.EvidenceProfileAgentSignature, EvidenceProfileVersion: 1,
			EvidenceProfileDigest: profileDigest, ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}},
		ValidFromUnix: uint64(now.Add(-time.Minute).Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}
	body, err = commerce.PrepareAgreementTargets(body)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := commerce.AgreementBodyDigest(body)
	if err != nil {
		t.Fatal(err)
	}
	reservationID := "sha256:" + strings.Repeat("8", 64)
	authority.mu.Lock()
	next := cloneAuthorityDocument(authority.doc)
	next.Engagements[digest] = EngagementRecord{Agreement: commerce.AgentAgreement{Body: body}, AgreementDigest: digest,
		ProposerAgentID: "agent:buyer", ProposalEventID: "event:r", ProposalActionID: "action:r", State: EngagementSettled,
		StateRevision: 7, ReservationID: reservationID, SettlementEvidence: []string{"sha256:" + strings.Repeat("9", 64)},
		LastTransitionAtUnix: uint64(now.Unix())}
	next.Reservations[reservationID] = ExposureReservation{ReservationID: reservationID, AgreementDigest: digest, ComputeUnits: 1, Released: false}
	if err = authority.persist(next); err == nil {
		authority.doc = next
	}
	authority.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	engine := &Engine{OwnerID: "owner:r", AgentID: "agent:r", MandateDigest: "sha256:" + strings.Repeat("a", 64), Authority: authority}
	report, err := engine.ReconcileDryRun()
	if err != nil || len(report.Issues) != 1 || report.Issues[0].Kind != "releasable-reservation" || report.Issues[0].Blocking {
		t.Fatalf("dry run = %+v, %v", report, err)
	}
	fence, err := authority.AcquireWriter(context.Background(), "reconciler", []string{"portfolio.release"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	report, err = engine.ReconcileApply(context.Background(), 1, fence)
	if err != nil || len(report.AppliedActionIDs) != 1 {
		t.Fatalf("apply = %+v, %v", report, err)
	}
	_, _, reservations := authority.Snapshot()
	if len(reservations) != 1 || !reservations[0].Released {
		t.Fatalf("reservation was not released: %+v", reservations)
	}
	report, err = engine.ReconcileApply(context.Background(), 1, fence)
	if err != nil || len(report.AppliedActionIDs) != 0 || len(report.Issues) != 0 {
		t.Fatalf("second apply must be an idempotent no-op: %+v, %v", report, err)
	}
}

func TestReconciliationDoesNotGuessOrphanOwnership(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	authority, err := OpenPersonalAuthority(directory, "owner:r", "agent:r", "authority:r", key, PortfolioLimits{ComputeUnits: 10})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	reservationID := "sha256:" + strings.Repeat("b", 64)
	authority.mu.Lock()
	next := cloneAuthorityDocument(authority.doc)
	next.Reservations[reservationID] = ExposureReservation{ReservationID: reservationID, AgreementDigest: "sha256:" + strings.Repeat("c", 64), ComputeUnits: 1}
	_ = authority.persist(next)
	authority.doc = next
	authority.mu.Unlock()
	report, err := (&Engine{Authority: authority}).ReconcileDryRun()
	if err != nil || len(report.Issues) != 1 || report.Issues[0].Kind != "orphan-reservation" || !report.Issues[0].Blocking {
		t.Fatalf("orphan report = %+v, %v", report, err)
	}
}
