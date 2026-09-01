package earning

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/paiddemand"
)

type objectiveMilestoneTestFixture struct {
	plan       ObjectiveMilestoneEscrowPlan
	milestones []validatedObjectiveMilestone
}

type objectiveMilestoneTestAuthority struct {
	records      map[string]EngagementRecord
	ledgers      map[string][]SettlementLedgerRecord
	limits       PortfolioLimits
	reservations []ExposureReservation
	finalized    map[string]ObjectiveMilestoneFinalizedEvidence
}

type objectiveMilestoneStaticAdmission struct {
	decisions map[string]PaidDemandFundingAdmissionDecision
	errors    map[string]error
	visited   []string
}

func (admission *objectiveMilestoneStaticAdmission) DecidePaidDemandFunding(_ context.Context,
	record EngagementRecord) (PaidDemandFundingAdmissionDecision, error) {
	admission.visited = append(admission.visited, record.AgreementDigest)
	if err := admission.errors[record.AgreementDigest]; err != nil {
		return PaidDemandFundingAdmissionDecision{}, err
	}
	return admission.decisions[record.AgreementDigest], nil
}

func (authority *objectiveMilestoneTestAuthority) Engagement(digest string) (EngagementRecord, bool) {
	record, found := authority.records[digest]
	return record, found
}

func (authority *objectiveMilestoneTestAuthority) SettlementSnapshot(digest string) []SettlementLedgerRecord {
	return append([]SettlementLedgerRecord(nil), authority.ledgers[digest]...)
}

func (authority *objectiveMilestoneTestAuthority) Snapshot() (uint64, PortfolioLimits, []ExposureReservation) {
	return 1, authority.limits, append([]ExposureReservation(nil), authority.reservations...)
}

func (authority *objectiveMilestoneTestAuthority) ResolveFinalizedObjectiveMilestone(ctx context.Context,
	request ObjectiveMilestoneFinalizedEvidenceRequest) (ObjectiveMilestoneFinalizedEvidence, bool, error) {
	if err := ctx.Err(); err != nil {
		return ObjectiveMilestoneFinalizedEvidence{}, false, err
	}
	evidence, found := authority.finalized[request.AgreementBodyDigest]
	return evidence, found, nil
}

func TestObjectiveMilestoneEscrowPlanStablecoinFourPointZeroFixture(t *testing.T) {
	fixture := newObjectiveMilestoneTestFixture(t)
	if err := ValidateObjectiveMilestoneEscrowPlan(fixture.plan); err != nil {
		t.Fatalf("validate 4.0 milestone plan: %v", err)
	}
	if fixture.plan.MaximumCurrentExposureAtomic != 150 {
		t.Fatalf("current-exposure cap = %d, want 150 (1.5 display units)", fixture.plan.MaximumCurrentExposureAtomic)
	}
	wantAmounts := []uint64{120, 140, 140}
	var total uint64
	for index, milestone := range fixture.milestones {
		if milestone.amountAtomic != wantAmounts[index] {
			t.Fatalf("milestone %d amount = %d, want %d", index+1, milestone.amountAtomic, wantAmounts[index])
		}
		if milestone.projection.Amount != nil || milestone.projection.SettlementAdapterURI != "" ||
			len(milestone.projection.SettlementParameters) != 0 || milestone.projection.BillingTerms != nil {
			t.Fatalf("local projection milestone %d accidentally carries payment authority", index+1)
		}
		record := objectiveMilestoneProposedRecord(milestone)
		reservation, err := paidDemandBuyerReservation(record, milestone.payment.ObligorAgentID)
		if err != nil {
			t.Fatalf("milestone %d reservation: %v", index+1, err)
		}
		if reservation.Asset == nil || *reservation.Asset != fixture.plan.ExpectedAsset ||
			reservation.MaximumLossAtomic != wantAmounts[index] {
			t.Fatalf("milestone %d reservation does not bind exact asset/amount: %+v", index+1, reservation)
		}
		total += milestone.amountAtomic
	}
	if total != 400 {
		t.Fatalf("aggregate fixture amount = %d, want 400 (4.0 display units)", total)
	}

	swapped := fixture.plan
	swapped.Milestones = append([]ObjectiveMilestoneEscrow(nil), fixture.plan.Milestones...)
	swapped.Milestones[0].ChildAgreement, swapped.Milestones[1].ChildAgreement =
		swapped.Milestones[1].ChildAgreement, swapped.Milestones[0].ChildAgreement
	if err := ValidateObjectiveMilestoneEscrowPlan(swapped); err == nil {
		t.Fatal("accepted sibling child under the wrong local projection milestone")
	}
	wrongAsset := fixture.plan
	wrongAsset.ExpectedAsset.AssetIdentifier = "0:" + strings.Repeat("f", 64)
	if err := ValidateObjectiveMilestoneEscrowPlan(wrongAsset); err == nil {
		t.Fatal("accepted children that differ from the locally pinned asset")
	}
	sameAgreementID := fixture.plan
	sameAgreementID.Milestones = append([]ObjectiveMilestoneEscrow(nil), fixture.plan.Milestones...)
	child := sameAgreementID.Milestones[0].ChildAgreement
	child.AgreementID = sameAgreementID.ParentProjection.AgreementID
	child.AuthorizationPredicates = append([]commerce.AgreementAuthorizationPredicate(nil), child.AuthorizationPredicates...)
	for index := range child.AuthorizationPredicates {
		child.AuthorizationPredicates[index].EvidenceTargetProjectionDigest = ""
	}
	child, err := commerce.PrepareAgreementTargets(child)
	if err != nil {
		t.Fatalf("prepare child sharing parent Agreement ID: %v", err)
	}
	sameAgreementID.Milestones[0].ChildAgreement = child
	if err := ValidateObjectiveMilestoneEscrowPlan(sameAgreementID); err == nil {
		t.Fatal("accepted a child that shares the parent Agreement ID")
	}

	for _, test := range []struct {
		name   string
		mutate func(*commerce.AgentAgreementBody)
	}{
		{name: "post-delivery buyer acceptance", mutate: func(body *commerce.AgentAgreementBody) {
			body.Obligations[0].AcceptanceEvidenceRequirements = []string{"buyer-selected-acceptance"}
		}},
		{name: "custom body extension", mutate: func(body *commerce.AgentAgreementBody) {
			body.OptionalExtensions = map[string][]byte{"custom.settlement": {1}}
		}},
		{name: "custom cancellation", mutate: func(body *commerce.AgentAgreementBody) {
			body.Obligations[1].CancellationPolicy = "buyer-selected"
		}},
		{name: "changed settlement parameters", mutate: func(body *commerce.AgentAgreementBody) {
			body.Obligations[0].SettlementParameters = []byte("different escrow profile")
		}},
		{name: "wrong payment payee", mutate: func(body *commerce.AgentAgreementBody) {
			body.Obligations[0].BeneficiaryAgentID = "agent:buyer"
		}},
		{name: "wrong settlement adapter", mutate: func(body *commerce.AgentAgreementBody) {
			body.Obligations[0].SettlementAdapterURI = "tos.payment.direct.v1"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			mutated := objectiveMilestoneMutatedChildPlan(t, fixture.plan, 0, test.mutate)
			if err := ValidateObjectiveMilestoneEscrowPlan(mutated); err == nil {
				t.Fatal("accepted a child that reinterprets the current fixed-price escrow profile")
			}
		})
	}
}

func TestObjectiveMilestoneFundingAdmissionRejectsUnsafeSequenceStates(t *testing.T) {
	fixture := newObjectiveMilestoneTestFixture(t)
	ctx := context.Background()

	t.Run("all at once funding", func(t *testing.T) {
		authority := fixture.newAuthority()
		first := objectiveMilestoneProposedRecord(fixture.milestones[0])
		first.State = EngagementFundingPending
		first.ReservationID = objectiveMilestoneReservationID(fixture.milestones[0])
		authority.records[first.AgreementDigest] = first
		authority.reservations = []ExposureReservation{objectiveMilestoneReservation(fixture.milestones[0], false)}
		admission := objectiveMilestoneTestAdmission(authority, fixture.plan)
		requireObjectiveMilestoneDisposition(t, admission,
			objectiveMilestoneProposedRecord(fixture.milestones[1]), PaidDemandFundingDeferred)
	})

	t.Run("wrong reservation asset", func(t *testing.T) {
		authority := fixture.newAuthority()
		first := objectiveMilestoneProposedRecord(fixture.milestones[0])
		first.State = EngagementFundingPending
		first.ReservationID = objectiveMilestoneReservationID(fixture.milestones[0])
		authority.records[first.AgreementDigest] = first
		reservation := objectiveMilestoneReservation(fixture.milestones[0], false)
		wrong := *reservation.Asset
		wrong.AssetIdentifier = "0:" + strings.Repeat("e", 64)
		reservation.Asset = &wrong
		authority.reservations = []ExposureReservation{reservation}
		admission := objectiveMilestoneTestAdmission(authority, fixture.plan)
		if _, err := admission.DecidePaidDemandFunding(ctx, first); err == nil {
			t.Fatal("accepted current child with a wrong-asset reservation")
		}
	})

	t.Run("uncommitted sibling", func(t *testing.T) {
		authority := fixture.newAuthority()
		body := objectiveMilestoneChildBody(t, 9, "120", []byte("uncommitted sibling"))
		digest, err := commerce.AgreementBodyDigest(body)
		if err != nil {
			t.Fatal(err)
		}
		record := EngagementRecord{Agreement: commerce.AgentAgreement{Body: body}, AgreementDigest: digest,
			State: EngagementAuthorizing}
		authority.records[digest] = record
		admission := objectiveMilestoneTestAdmission(authority, fixture.plan)
		requireObjectiveMilestoneDisposition(t, admission, record, PaidDemandFundingNotApplicable)
	})

	t.Run("skip", func(t *testing.T) {
		authority := fixture.newAuthority()
		fixture.setTerminal(t, authority, 0, true)
		admission := objectiveMilestoneTestAdmission(authority, fixture.plan)
		requireObjectiveMilestoneDisposition(t, admission,
			objectiveMilestoneProposedRecord(fixture.milestones[2]), PaidDemandFundingDeferred)
	})

	t.Run("refund", func(t *testing.T) {
		authority := fixture.newAuthority()
		first := objectiveMilestoneProposedRecord(fixture.milestones[0])
		first.State = EngagementCancelled
		first.ReservationID = objectiveMilestoneReservationID(fixture.milestones[0])
		first.SettlementEvidence = []string{objectiveMilestoneTestDigest('9')}
		authority.records[first.AgreementDigest] = first
		authority.reservations = []ExposureReservation{objectiveMilestoneReservation(fixture.milestones[0], true)}
		admission := objectiveMilestoneTestAdmission(authority, fixture.plan)
		if _, err := admission.DecidePaidDemandFunding(ctx,
			objectiveMilestoneProposedRecord(fixture.milestones[1])); err == nil {
			t.Fatal("refund/cancellation unlocked the next child")
		}
	})

	t.Run("ambiguous", func(t *testing.T) {
		authority := fixture.newAuthority()
		first := objectiveMilestoneProposedRecord(fixture.milestones[0])
		first.State = EngagementAmbiguous
		first.ReservationID = objectiveMilestoneReservationID(fixture.milestones[0])
		authority.records[first.AgreementDigest] = first
		authority.reservations = []ExposureReservation{objectiveMilestoneReservation(fixture.milestones[0], false)}
		admission := objectiveMilestoneTestAdmission(authority, fixture.plan)
		requireObjectiveMilestoneDisposition(t, admission,
			objectiveMilestoneProposedRecord(fixture.milestones[1]), PaidDemandFundingDeferred)
		if len(authority.reservations) != 1 || authority.reservations[0].Released {
			t.Fatal("ambiguous predecessor did not retain its exact active exposure")
		}
	})

	t.Run("active reservation after settlement", func(t *testing.T) {
		authority := fixture.newAuthority()
		fixture.setTerminal(t, authority, 0, false)
		admission := objectiveMilestoneTestAdmission(authority, fixture.plan)
		requireObjectiveMilestoneDisposition(t, admission,
			objectiveMilestoneProposedRecord(fixture.milestones[1]), PaidDemandFundingDeferred)
	})

	t.Run("authority cap looser than plan", func(t *testing.T) {
		authority := fixture.newAuthority()
		authority.limits.MaximumLossAtomic = 151
		admission := objectiveMilestoneTestAdmission(authority, fixture.plan)
		if _, err := admission.DecidePaidDemandFunding(ctx,
			objectiveMilestoneProposedRecord(fixture.milestones[0])); err == nil {
			t.Fatal("authority maximum-loss limit exceeded the locally pinned 1.5 cap")
		}
	})

	t.Run("cancelled context", func(t *testing.T) {
		authority := fixture.newAuthority()
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		admission := objectiveMilestoneTestAdmission(authority, fixture.plan)
		if _, err := admission.DecidePaidDemandFunding(cancelled,
			objectiveMilestoneProposedRecord(fixture.milestones[0])); err == nil {
			t.Fatal("cancelled context reached milestone funding admission")
		}
	})
}

func TestObjectiveMilestoneFundingAdmissionRejectsTrueAllAtOnceFourPointZero(t *testing.T) {
	fixture := newObjectiveMilestoneTestFixture(t)
	authority := fixture.newAuthority()
	var total uint64
	for _, milestone := range fixture.milestones {
		record := objectiveMilestoneProposedRecord(milestone)
		record.State = EngagementFundingPending
		record.ReservationID = objectiveMilestoneReservationID(milestone)
		authority.records[record.AgreementDigest] = record
		authority.reservations = append(authority.reservations, objectiveMilestoneReservation(milestone, false))
		total += milestone.amountAtomic
	}
	if total != 400 || total <= fixture.plan.MaximumCurrentExposureAtomic {
		t.Fatalf("prefunded exposure=%d cap=%d, want the complete 4.0/1.5 adverse fixture",
			total, fixture.plan.MaximumCurrentExposureAtomic)
	}

	admission := objectiveMilestoneTestAdmission(authority, fixture.plan)
	for index, milestone := range fixture.milestones {
		record := authority.records[milestone.childDigest]
		decision, err := admission.DecidePaidDemandFunding(context.Background(), record)
		if err == nil && decision.Disposition == PaidDemandFundingAdmitted {
			t.Fatalf("milestone %d was admitted from an all-at-once 4.0 prefunding snapshot", index+1)
		}
	}
	for index, reservation := range authority.reservations {
		if reservation.Released {
			t.Fatalf("admission mutated prefunded reservation %d to released", index+1)
		}
	}
}

func TestObjectiveMilestoneFundingAdmissionValidatesExactCurrentReservation(t *testing.T) {
	fixture := newObjectiveMilestoneTestFixture(t)
	milestone := fixture.milestones[0]
	for _, test := range []struct {
		name      string
		mutate    func(*EngagementRecord, *ExposureReservation)
		wantAdmit bool
	}{
		{name: "exact live reservation", wantAdmit: true},
		{name: "nil asset", mutate: func(_ *EngagementRecord, reservation *ExposureReservation) {
			reservation.Asset = nil
		}},
		{name: "wrong asset", mutate: func(_ *EngagementRecord, reservation *ExposureReservation) {
			asset := *reservation.Asset
			asset.AssetIdentifier = "0:" + strings.Repeat("e", 64)
			reservation.Asset = &asset
		}},
		{name: "wrong spend", mutate: func(_ *EngagementRecord, reservation *ExposureReservation) {
			reservation.SpendAtomic--
		}},
		{name: "wrong locked capital", mutate: func(_ *EngagementRecord, reservation *ExposureReservation) {
			reservation.LockedCapitalAtomic--
		}},
		{name: "wrong maximum loss", mutate: func(_ *EngagementRecord, reservation *ExposureReservation) {
			reservation.MaximumLossAtomic--
		}},
		{name: "already released", mutate: func(_ *EngagementRecord, reservation *ExposureReservation) {
			reservation.Released = true
		}},
		{name: "wrong reservation identity", mutate: func(record *EngagementRecord, _ *ExposureReservation) {
			record.ReservationID = "reservation:" + strings.Repeat("f", 64)
		}},
		{name: "wrong Agreement binding", mutate: func(_ *EngagementRecord, reservation *ExposureReservation) {
			reservation.AgreementDigest = objectiveMilestoneTestDigest('f')
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			authority := fixture.newAuthority()
			record := objectiveMilestoneProposedRecord(milestone)
			record.State = EngagementFundingPending
			record.ReservationID = objectiveMilestoneReservationID(milestone)
			reservation := objectiveMilestoneReservation(milestone, false)
			if test.mutate != nil {
				test.mutate(&record, &reservation)
			}
			authority.records[milestone.childDigest] = record
			authority.reservations = []ExposureReservation{reservation}
			decision, err := objectiveMilestoneTestAdmission(authority, fixture.plan).
				DecidePaidDemandFunding(context.Background(), record)
			if test.wantAdmit {
				if err != nil || decision.Disposition != PaidDemandFundingAdmitted {
					t.Fatalf("exact current reservation disposition=%d err=%v", decision.Disposition, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("malformed current reservation was not a hard failure: disposition=%d", decision.Disposition)
			}
		})
	}
}

func TestObjectiveMilestoneFundingAdmissionRequiresExactReleasedPredecessorReservation(t *testing.T) {
	fixture := newObjectiveMilestoneTestFixture(t)
	for _, test := range []struct {
		name      string
		mutate    func(*objectiveMilestoneTestAuthority)
		wantAdmit bool
	}{
		{name: "exact released reservation", wantAdmit: true},
		{name: "missing reservation", mutate: func(authority *objectiveMilestoneTestAuthority) {
			authority.reservations = nil
		}},
		{name: "still active", mutate: func(authority *objectiveMilestoneTestAuthority) {
			authority.reservations[0].Released = false
		}},
		{name: "wrong released asset", mutate: func(authority *objectiveMilestoneTestAuthority) {
			asset := *authority.reservations[0].Asset
			asset.AssetIdentifier = "0:" + strings.Repeat("e", 64)
			authority.reservations[0].Asset = &asset
		}},
		{name: "wrong released spend", mutate: func(authority *objectiveMilestoneTestAuthority) {
			authority.reservations[0].SpendAtomic--
		}},
		{name: "wrong released locked capital", mutate: func(authority *objectiveMilestoneTestAuthority) {
			authority.reservations[0].LockedCapitalAtomic--
		}},
		{name: "wrong released maximum loss", mutate: func(authority *objectiveMilestoneTestAuthority) {
			authority.reservations[0].MaximumLossAtomic--
		}},
		{name: "wrong released reservation ID", mutate: func(authority *objectiveMilestoneTestAuthority) {
			authority.reservations[0].ReservationID = "reservation:" + strings.Repeat("f", 64)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			authority := fixture.newAuthority()
			fixture.setTerminal(t, authority, 0, true)
			if test.mutate != nil {
				test.mutate(authority)
			}
			admission := objectiveMilestoneTestAdmission(authority, fixture.plan)
			decision, err := admission.DecidePaidDemandFunding(context.Background(),
				objectiveMilestoneProposedRecord(fixture.milestones[1]))
			if err != nil {
				t.Fatalf("released-reservation matrix returned a hard error: %v", err)
			}
			want := PaidDemandFundingDeferred
			if test.wantAdmit {
				want = PaidDemandFundingAdmitted
			}
			if decision.Disposition != want {
				t.Fatalf("released-reservation disposition=%d want=%d", decision.Disposition, want)
			}
		})
	}
}

func TestObjectiveMilestoneFundingAdmissionSequentialSettlementPasses(t *testing.T) {
	fixture := newObjectiveMilestoneTestFixture(t)
	authority := fixture.newAuthority()
	admission := objectiveMilestoneTestAdmission(authority, fixture.plan)

	requireObjectiveMilestoneDisposition(t, admission,
		objectiveMilestoneProposedRecord(fixture.milestones[0]), PaidDemandFundingAdmitted)
	fixture.setTerminal(t, authority, 0, true)
	requireObjectiveMilestoneDisposition(t, admission,
		objectiveMilestoneProposedRecord(fixture.milestones[1]), PaidDemandFundingAdmitted)
	fixture.setTerminal(t, authority, 1, true)
	requireObjectiveMilestoneDisposition(t, admission,
		objectiveMilestoneProposedRecord(fixture.milestones[2]), PaidDemandFundingAdmitted)
}

func TestPaidDemandFundingAdmissionSkipsUnrelatedAndDeferredWithoutStarvation(t *testing.T) {
	fixture := newObjectiveMilestoneTestFixture(t)
	unrelatedBody := objectiveMilestoneChildBody(t, 9, "120", []byte("unrelated objective"))
	unrelatedDigest, err := commerce.AgreementBodyDigest(unrelatedBody)
	if err != nil {
		t.Fatal(err)
	}
	unrelated := EngagementRecord{Agreement: commerce.AgentAgreement{Body: unrelatedBody},
		AgreementDigest: unrelatedDigest, State: EngagementAuthorizing}
	deferred := objectiveMilestoneProposedRecord(fixture.milestones[1])
	admitted := objectiveMilestoneProposedRecord(fixture.milestones[0])
	admission := &objectiveMilestoneStaticAdmission{decisions: map[string]PaidDemandFundingAdmissionDecision{
		unrelated.AgreementDigest: {Disposition: PaidDemandFundingNotApplicable},
		deferred.AgreementDigest:  {Disposition: PaidDemandFundingDeferred},
		admitted.AgreementDigest:  {Disposition: PaidDemandFundingAdmitted},
	}, errors: make(map[string]error)}

	var selected []string
	for _, record := range []EngagementRecord{unrelated, deferred, admitted} {
		allowed, routeErr := paidDemandFundingAdmissionAllows(context.Background(), admission, record)
		if routeErr != nil {
			t.Fatalf("ordinary skip became fatal: %v", routeErr)
		}
		if allowed {
			selected = append(selected, record.AgreementDigest)
		}
	}
	if len(admission.visited) != 3 || len(selected) != 1 || selected[0] != admitted.AgreementDigest {
		t.Fatalf("funding routing starved admitted child: visited=%v selected=%v", admission.visited, selected)
	}
	if allowed, nilErr := paidDemandFundingAdmissionAllows(context.Background(), nil, unrelated); nilErr != nil || !allowed {
		t.Fatalf("nil admission changed the ordinary single-Agreement path: allowed=%v err=%v", allowed, nilErr)
	}
	admission.errors[unrelated.AgreementDigest] = fmt.Errorf("invalid qualified authority state")
	if _, hardErr := paidDemandFundingAdmissionAllows(context.Background(), admission, unrelated); hardErr == nil {
		t.Fatal("hard-invalid milestone admission was silently skipped")
	}
}

func TestPaidDemandFundingAdmissionRouterSelectsOneExactPlan(t *testing.T) {
	fixture := newObjectiveMilestoneTestFixture(t)
	record := objectiveMilestoneProposedRecord(fixture.milestones[0])
	notApplicable := &objectiveMilestoneStaticAdmission{decisions: map[string]PaidDemandFundingAdmissionDecision{
		record.AgreementDigest: {Disposition: PaidDemandFundingNotApplicable},
	}}
	admitted := &objectiveMilestoneStaticAdmission{decisions: map[string]PaidDemandFundingAdmissionDecision{
		record.AgreementDigest: {Disposition: PaidDemandFundingAdmitted},
	}}
	router := PaidDemandFundingAdmissionRouter{Admissions: []PaidDemandFundingAdmission{notApplicable, admitted}}
	decision, err := router.DecidePaidDemandFunding(context.Background(), record)
	if err != nil || decision.Disposition != PaidDemandFundingAdmitted {
		t.Fatalf("exact route disposition=%d err=%v", decision.Disposition, err)
	}
	overlap := PaidDemandFundingAdmissionRouter{Admissions: []PaidDemandFundingAdmission{admitted, admitted}}
	if _, err := overlap.DecidePaidDemandFunding(context.Background(), record); err == nil {
		t.Fatal("overlapping milestone funding routes did not fail closed")
	}
}

func TestObjectiveMilestoneFundingAdmissionDefersWithoutBuyerFinalityResolver(t *testing.T) {
	fixture := newObjectiveMilestoneTestFixture(t)
	authority := fixture.newAuthority()
	fixture.setTerminal(t, authority, 0, true)
	admission := ObjectiveMilestoneFundingAdmission{Authority: authority, Plan: fixture.plan}
	requireObjectiveMilestoneDisposition(t, admission,
		objectiveMilestoneProposedRecord(fixture.milestones[1]), PaidDemandFundingDeferred)
}

func TestObjectiveMilestoneFundingAdmissionFinalityMatrix(t *testing.T) {
	fixture := newObjectiveMilestoneTestFixture(t)

	t.Run("resolver found false or inconclusive", func(t *testing.T) {
		authority := fixture.newAuthority()
		fixture.setTerminal(t, authority, 0, true)
		delete(authority.finalized, fixture.milestones[0].childDigest)
		before := authority.reservations[0]
		requireObjectiveMilestoneDisposition(t, objectiveMilestoneTestAdmission(authority, fixture.plan),
			objectiveMilestoneProposedRecord(fixture.milestones[1]), PaidDemandFundingDeferred)
		if len(authority.reservations) != 1 || authority.reservations[0] != before {
			t.Fatal("inconclusive finalized-evidence resolution mutated Portfolio state")
		}
	})

	for _, test := range []struct {
		name   string
		mutate func(*ObjectiveMilestoneFinalizedEvidence)
	}{
		{name: "wrong resolution state", mutate: func(evidence *ObjectiveMilestoneFinalizedEvidence) {
			evidence.ResolutionState = "ambiguous"
		}},
		{name: "missing finality reference", mutate: func(evidence *ObjectiveMilestoneFinalizedEvidence) {
			evidence.FinalityReference = ""
		}},
		{name: "missing exact transfer reference", mutate: func(evidence *ObjectiveMilestoneFinalizedEvidence) {
			evidence.ExactTransferReference = ""
		}},
		{name: "zero resolution time", mutate: func(evidence *ObjectiveMilestoneFinalizedEvidence) {
			evidence.ResolvedAtUnix = 0
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			authority := fixture.newAuthority()
			fixture.setTerminal(t, authority, 0, true)
			evidence := authority.finalized[fixture.milestones[0].childDigest]
			test.mutate(&evidence)
			authority.finalized[fixture.milestones[0].childDigest] = evidence
			before := authority.reservations[0]
			if _, err := objectiveMilestoneTestAdmission(authority, fixture.plan).DecidePaidDemandFunding(
				context.Background(), objectiveMilestoneProposedRecord(fixture.milestones[1])); err == nil {
				t.Fatal("invalid finalized evidence was not a hard failure")
			}
			if len(authority.reservations) != 1 || authority.reservations[0] != before {
				t.Fatal("invalid finalized evidence mutated Portfolio state")
			}
		})
	}
}

func TestObjectiveMilestoneFundingAdmissionRejectsReusedQualifiedEvidence(t *testing.T) {
	fixture := newObjectiveMilestoneTestFixture(t)
	for _, field := range []string{
		"QuoteCommitment",
		"EscrowAddress",
		"ReceiptCommitment",
		"PaymentRequestDigest",
		"PaymentStableActionID",
		"PaymentEvidenceDigest",
		"ExactTransferReference",
		"FinalityReference",
		"DeliveryEvidenceDigests",
	} {
		t.Run(field, func(t *testing.T) {
			authority := fixture.newAuthority()
			fixture.setTerminal(t, authority, 0, true)
			fixture.setTerminal(t, authority, 1, true)
			firstMilestone, secondMilestone := fixture.milestones[0], fixture.milestones[1]
			first := authority.finalized[firstMilestone.childDigest]
			second := authority.finalized[secondMilestone.childDigest]
			switch field {
			case "QuoteCommitment":
				second.QuoteCommitment = first.QuoteCommitment
			case "EscrowAddress":
				second.EscrowAddress = first.EscrowAddress
			case "ReceiptCommitment":
				second.ReceiptCommitment = first.ReceiptCommitment
			case "PaymentRequestDigest":
				second.PaymentRequestDigest = first.PaymentRequestDigest
			case "PaymentStableActionID":
				second.PaymentStableActionID = first.PaymentStableActionID
			case "PaymentEvidenceDigest":
				second.PaymentEvidenceDigest = first.PaymentEvidenceDigest
				ledger := authority.ledgers[secondMilestone.childDigest][0]
				ledger.State.AppliedPaymentEvidence = []string{first.PaymentEvidenceDigest}
				ledger.State.EvidenceRefs = []string{first.PaymentEvidenceDigest}
				authority.ledgers[secondMilestone.childDigest] = []SettlementLedgerRecord{ledger}
				objectiveMilestoneSetLocalPaymentEvidence(authority, secondMilestone,
					[]string{first.PaymentEvidenceDigest})
			case "ExactTransferReference":
				second.ExactTransferReference = first.ExactTransferReference
			case "FinalityReference":
				second.FinalityReference = first.FinalityReference
			case "DeliveryEvidenceDigests":
				second.DeliveryEvidenceDigests = append([]string(nil), first.DeliveryEvidenceDigests...)
				record := authority.records[secondMilestone.childDigest]
				runtime := record.ObligationRuntime[secondMilestone.work.ObligationID]
				runtime.DeliveryEvidence = append([]string(nil), first.DeliveryEvidenceDigests...)
				record.ObligationRuntime[secondMilestone.work.ObligationID] = runtime
				authority.records[secondMilestone.childDigest] = record
			}
			authority.finalized[secondMilestone.childDigest] = second
			_, err := objectiveMilestoneTestAdmission(authority, fixture.plan).DecidePaidDemandFunding(
				context.Background(), objectiveMilestoneProposedRecord(fixture.milestones[2]))
			if err == nil || !strings.Contains(err.Error(), "evidence identity is reused") {
				t.Fatalf("reused %s did not reach the cross-milestone uniqueness guard: %v", field, err)
			}
		})
	}
}

func TestObjectiveMilestoneFundingAdmissionRejectsMisbindingQualifiedEvidence(t *testing.T) {
	fixture := newObjectiveMilestoneTestFixture(t)
	for _, test := range []struct {
		name   string
		mutate func(*ObjectiveMilestoneFinalizedEvidence)
	}{
		{name: "wrong work obligation", mutate: func(evidence *ObjectiveMilestoneFinalizedEvidence) {
			evidence.WorkObligationID = "work:other"
		}},
		{name: "wrong exact asset", mutate: func(evidence *ObjectiveMilestoneFinalizedEvidence) {
			evidence.Asset.AssetIdentifier = "0:" + strings.Repeat("f", 64)
		}},
		{name: "wrong payee", mutate: func(evidence *ObjectiveMilestoneFinalizedEvidence) {
			evidence.PayeeAgentID = "agent:other-provider"
		}},
		{name: "wrong settlement adapter", mutate: func(evidence *ObjectiveMilestoneFinalizedEvidence) {
			evidence.SettlementAdapterURI = "tos.payment.direct.v1"
		}},
		{name: "invalid Quote commitment", mutate: func(evidence *ObjectiveMilestoneFinalizedEvidence) {
			evidence.QuoteCommitment = objectiveMilestoneTestDigest('f')
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			authority := fixture.newAuthority()
			fixture.setTerminal(t, authority, 0, true)
			evidence := authority.finalized[fixture.milestones[0].childDigest]
			test.mutate(&evidence)
			authority.finalized[fixture.milestones[0].childDigest] = evidence
			admission := objectiveMilestoneTestAdmission(authority, fixture.plan)
			if _, err := admission.DecidePaidDemandFunding(context.Background(),
				objectiveMilestoneProposedRecord(fixture.milestones[1])); err == nil {
				t.Fatal("misbound qualified finalized evidence unlocked another milestone")
			}
		})
	}
}

func TestObjectiveMilestoneFundingAdmissionRejectsLedgerBindingAndNonFullSettlement(t *testing.T) {
	fixture := newObjectiveMilestoneTestFixture(t)
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *objectiveMilestoneTestAuthority, validatedObjectiveMilestone)
	}{
		{name: "wrong ledger Agreement", mutate: func(t *testing.T, authority *objectiveMilestoneTestAuthority,
			milestone validatedObjectiveMilestone) {
			ledger := authority.ledgers[milestone.childDigest][0]
			ledger.Obligation.AgreementBodyDigest = objectiveMilestoneTestDigest('f')
			objectiveMilestoneReplaceWithFullPaidLedger(t, authority, milestone, ledger.Obligation)
		}},
		{name: "wrong ledger obligation", mutate: func(t *testing.T, authority *objectiveMilestoneTestAuthority,
			milestone validatedObjectiveMilestone) {
			ledger := authority.ledgers[milestone.childDigest][0]
			ledger.Obligation.AgreementObligationID = "payment:other"
			objectiveMilestoneReplaceWithFullPaidLedger(t, authority, milestone, ledger.Obligation)
		}},
		{name: "wrong ledger payee", mutate: func(t *testing.T, authority *objectiveMilestoneTestAuthority,
			milestone validatedObjectiveMilestone) {
			ledger := authority.ledgers[milestone.childDigest][0]
			ledger.Obligation.PayeeAgentID = "agent:other-provider"
			objectiveMilestoneReplaceWithFullPaidLedger(t, authority, milestone, ledger.Obligation)
		}},
		{name: "wrong ledger adapter", mutate: func(t *testing.T, authority *objectiveMilestoneTestAuthority,
			milestone validatedObjectiveMilestone) {
			ledger := authority.ledgers[milestone.childDigest][0]
			ledger.Obligation.SettlementAdapterURI = "tos.payment.direct.v1"
			objectiveMilestoneReplaceWithFullPaidLedger(t, authority, milestone, ledger.Obligation)
		}},
		{name: "wrong ledger amount", mutate: func(t *testing.T, authority *objectiveMilestoneTestAuthority,
			milestone validatedObjectiveMilestone) {
			ledger := authority.ledgers[milestone.childDigest][0]
			ledger.Obligation.Amount.AmountAtomic = "119"
			ledger.Obligation.MaximumAggregateAmount.AmountAtomic = "119"
			objectiveMilestoneReplaceWithFullPaidLedger(t, authority, milestone, ledger.Obligation)
		}},
		{name: "wrong ledger asset", mutate: func(t *testing.T, authority *objectiveMilestoneTestAuthority,
			milestone validatedObjectiveMilestone) {
			ledger := authority.ledgers[milestone.childDigest][0]
			ledger.Obligation.Amount.AssetIdentifier = "0:" + strings.Repeat("f", 64)
			ledger.Obligation.MaximumAggregateAmount.AssetIdentifier = ledger.Obligation.Amount.AssetIdentifier
			objectiveMilestoneReplaceWithFullPaidLedger(t, authority, milestone, ledger.Obligation)
		}},
		{name: "partial payment", mutate: func(t *testing.T, authority *objectiveMilestoneTestAuthority,
			milestone validatedObjectiveMilestone) {
			ledger := authority.ledgers[milestone.childDigest][0]
			state, err := commerce.NewSettlementState(ledger.Obligation)
			partial := ledger.Obligation.Amount
			partial.AmountAtomic = "60"
			evidence := objectiveMilestoneTestDigest('e')
			if err == nil {
				state, err = commerce.ApplyPayment(state, ledger.Obligation, evidence, partial,
					time.Unix(1_000, 0).UTC())
			}
			if err != nil || state.State != commerce.SettlementPartiallyPaid {
				t.Fatalf("build partial settlement state: state=%s err=%v", state.State, err)
			}
			ledger.State = state
			authority.ledgers[milestone.childDigest] = []SettlementLedgerRecord{ledger}
			objectiveMilestoneSetLocalPaymentEvidence(authority, milestone, []string{evidence})
		}},
		{name: "disputed payment", mutate: func(t *testing.T, authority *objectiveMilestoneTestAuthority,
			milestone validatedObjectiveMilestone) {
			ledger := authority.ledgers[milestone.childDigest][0]
			state, err := commerce.NewSettlementState(ledger.Obligation)
			evidence := objectiveMilestoneTestDigest('e')
			if err == nil {
				state, err = commerce.ResolveSettlementState(state, ledger.Obligation, commerce.SettlementDisputed,
					evidence, time.Unix(1_000, 0).UTC())
			}
			if err != nil || state.State != commerce.SettlementDisputed {
				t.Fatalf("build disputed settlement state: state=%s err=%v", state.State, err)
			}
			ledger.State = state
			authority.ledgers[milestone.childDigest] = []SettlementLedgerRecord{ledger}
			objectiveMilestoneSetLocalPaymentEvidence(authority, milestone, []string{evidence})
		}},
		{name: "split payment evidence", mutate: func(t *testing.T, authority *objectiveMilestoneTestAuthority,
			milestone validatedObjectiveMilestone) {
			ledger := authority.ledgers[milestone.childDigest][0]
			state, err := commerce.NewSettlementState(ledger.Obligation)
			firstAmount, secondAmount := ledger.Obligation.Amount, ledger.Obligation.Amount
			firstAmount.AmountAtomic, secondAmount.AmountAtomic = "50", "70"
			firstEvidence, secondEvidence := objectiveMilestoneTestDigest('e'), objectiveMilestoneTestDigest('f')
			if err == nil {
				state, err = commerce.ApplyPayment(state, ledger.Obligation, firstEvidence, firstAmount,
					time.Unix(1_000, 0).UTC())
			}
			if err == nil {
				state, err = commerce.ApplyPayment(state, ledger.Obligation, secondEvidence, secondAmount,
					time.Unix(1_001, 0).UTC())
			}
			if err != nil || state.State != commerce.SettlementPaid || len(state.AppliedPaymentEvidence) != 2 {
				t.Fatalf("build split settlement state: state=%s evidence=%v err=%v",
					state.State, state.AppliedPaymentEvidence, err)
			}
			ledger.State = state
			authority.ledgers[milestone.childDigest] = []SettlementLedgerRecord{ledger}
			objectiveMilestoneSetLocalPaymentEvidence(authority, milestone,
				[]string{firstEvidence, secondEvidence})
		}},
		{name: "multiple settlement ledgers", mutate: func(_ *testing.T, authority *objectiveMilestoneTestAuthority,
			milestone validatedObjectiveMilestone) {
			ledger := authority.ledgers[milestone.childDigest][0]
			authority.ledgers[milestone.childDigest] = []SettlementLedgerRecord{ledger, ledger}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			authority := fixture.newAuthority()
			fixture.setTerminal(t, authority, 0, true)
			test.mutate(t, authority, fixture.milestones[0])
			if _, err := objectiveMilestoneTestAdmission(authority, fixture.plan).DecidePaidDemandFunding(
				context.Background(), objectiveMilestoneProposedRecord(fixture.milestones[1])); err == nil {
				t.Fatal("misbound or non-full settlement projection unlocked its successor")
			}
		})
	}
}

func TestPaidDemandBuyerReservationBindsAssetAndRejectsMixedAssets(t *testing.T) {
	fixture := newObjectiveMilestoneTestFixture(t)
	record := objectiveMilestoneProposedRecord(fixture.milestones[0])
	reservation, err := paidDemandBuyerReservation(record, fixture.milestones[0].payment.ObligorAgentID)
	if err != nil {
		t.Fatal(err)
	}
	if reservation.Asset == nil || *reservation.Asset != fixture.plan.ExpectedAsset {
		t.Fatalf("reservation asset = %+v, want %+v", reservation.Asset, fixture.plan.ExpectedAsset)
	}

	mixed := record
	mixed.Agreement.Body.Obligations = append([]commerce.AgreementObligation(nil), record.Agreement.Body.Obligations...)
	secondAmount := *fixture.milestones[0].payment.Amount
	secondAmount.AssetIdentifier = "0:" + strings.Repeat("d", 64)
	second := fixture.milestones[0].payment
	second.ObligationID = "payment:other-asset"
	second.Amount = &secondAmount
	mixed.Agreement.Body.Obligations = append(mixed.Agreement.Body.Obligations, second)
	if _, err := paidDemandBuyerReservation(mixed, fixture.milestones[0].payment.ObligorAgentID); err == nil {
		t.Fatal("accepted mixed buyer payment assets in one child")
	}
}

func newObjectiveMilestoneTestFixture(t *testing.T) objectiveMilestoneTestFixture {
	t.Helper()
	amounts := []string{"120", "140", "140"}
	children := make([]commerce.AgentAgreementBody, len(amounts))
	digests := make([]string, len(amounts))
	for index, amount := range amounts {
		children[index] = objectiveMilestoneChildBody(t, index+1, amount,
			[]byte(fmt.Sprintf("objective result %d", index+1)))
		var err error
		digests[index], err = commerce.AgreementBodyDigest(children[index])
		if err != nil {
			t.Fatalf("child %d digest: %v", index+1, err)
		}
	}
	parentAttachments := append([]string(nil), digests...)
	sort.Strings(parentAttachments)
	obligationIDs := []string{"milestone:1", "milestone:2", "milestone:3"}
	parentObligations := make([]commerce.AgreementObligation, len(children))
	for index, child := range children {
		var dependency []string
		if index > 0 {
			dependency = []string{obligationIDs[index-1]}
		}
		work := child.Obligations[1]
		parentObligations[index] = commerce.AgreementObligation{ObligationID: obligationIDs[index],
			Kind: "objective_milestone", ObligorAgentID: "agent:provider", BeneficiaryAgentID: "agent:buyer",
			DependsOnObligationIDs: dependency, SubjectContentType: work.SubjectContentType,
			Subject: append([]byte(nil), work.Subject...), AttachmentDigests: []string{digests[index]},
			ConfidentialityPolicy: "participants", CancellationPolicy: "objective",
			DisputePolicy: "objective", AuthorizationPredicateIDs: []string{"predicate:provider"}}
	}
	parent := commerce.AgentAgreementBody{SchemaVersion: 1, AgreementID: "agreement:objective-parent", Version: 1,
		NetworkContext: "network:test", Participants: []commerce.AgreementParticipant{
			{AgentID: "agent:buyer", Roles: []string{"buyer"}},
			{AgentID: "agent:provider", Roles: []string{"provider"}},
		}, TermsContentType: "text/plain", Terms: []byte("three independently settled objective milestones"),
		AttachmentDigests: parentAttachments, Obligations: parentObligations,
		AuthorizationPredicates: []commerce.AgreementAuthorizationPredicate{{PredicateID: "predicate:provider",
			AuthoritySubject: commerce.AgreementAuthoritySubject{SubjectKind: "agent", SubjectNamespace: "tos.agent",
				SubjectIdentifier: "agent:provider"}, RoleScope: []string{"provider"}, ObligationIDs: obligationIDs,
			EvidenceProfileURI: commerce.EvidenceProfileAgentSignature, EvidenceProfileVersion: 1,
			EvidenceProfileDigest: commerce.AgentSignatureProfileDigest(), ExpiresAtUnix: 11_000}},
		ValidFromUnix: 50, ExpiresAtUnix: 12_000}
	var err error
	parent, err = commerce.PrepareAgreementTargets(parent)
	if err != nil {
		t.Fatalf("prepare parent: %v", err)
	}
	plan := ObjectiveMilestoneEscrowPlan{ParentProjection: parent,
		ExpectedAsset: commerce.AssetIdentityV1{AssetNamespace: "tos.contract",
			AssetIdentifier: "0:" + strings.Repeat("a", 64), Unit: "atomic"},
		ExpectedSettlementParameters: []byte("fixed-price escrow"), MaximumCurrentExposureAtomic: 150,
		Milestones: []ObjectiveMilestoneEscrow{
			{ProjectionObligationID: obligationIDs[0], ChildAgreement: children[0]},
			{ProjectionObligationID: obligationIDs[1], ChildAgreement: children[1]},
			{ProjectionObligationID: obligationIDs[2], ChildAgreement: children[2]},
		}}
	validated, err := validateObjectiveMilestoneEscrowPlan(plan)
	if err != nil {
		t.Fatalf("fixture plan: %v", err)
	}
	return objectiveMilestoneTestFixture{plan: plan, milestones: validated}
}

func objectiveMilestoneChildBody(t *testing.T, sequence int, amountAtomic string,
	subject []byte) commerce.AgentAgreementBody {
	t.Helper()
	amount := &commerce.AgreementAmount{AssetNamespace: "tos.contract",
		AssetIdentifier: "0:" + strings.Repeat("a", 64), AmountAtomic: amountAtomic, Unit: "atomic"}
	hexCharacters := "0123456789abcdef"
	inputDigest := objectiveMilestoneTestDigest(hexCharacters[(sequence*2)%len(hexCharacters)])
	sourceDigest := objectiveMilestoneTestDigest(hexCharacters[(sequence*2+1)%len(hexCharacters)])
	executionAttachments := []string{inputDigest, sourceDigest}
	sort.Strings(executionAttachments)
	executionBindings := []string{"tos.input." + inputDigest[7:], "tos.source." + sourceDigest[7:]}
	sort.Strings(executionBindings)
	profileDigest := commerce.PaidDemandQuoteProfileDigest()
	body := commerce.AgentAgreementBody{SchemaVersion: 1,
		AgreementID: fmt.Sprintf("agreement:objective-child-%d", sequence), Version: 1, NetworkContext: "network:test",
		Participants: []commerce.AgreementParticipant{{AgentID: "agent:buyer", Roles: []string{"buyer"}},
			{AgentID: "agent:provider", Roles: []string{"provider"}}}, TermsContentType: "text/plain",
		Terms: []byte(fmt.Sprintf("fixed-price objective milestone %d", sequence)),
		Obligations: []commerce.AgreementObligation{
			{ObligationID: "payment", Kind: "payment", ObligorAgentID: "agent:buyer",
				BeneficiaryAgentID: "agent:provider", DependsOnObligationIDs: []string{"work"},
				SubjectContentType: "text/plain", Subject: []byte("payment after objective delivery"), Amount: amount,
				DueAtUnix: 8_000, ExpiresAtUnix: 9_000, ConfidentialityPolicy: "participants",
				CancellationPolicy: "chain-profile", DisputePolicy: "objective",
				SettlementAdapterURI: paiddemand.SettlementAdapterURI, SettlementParameters: []byte("fixed-price escrow"),
				AuthorizationPredicateIDs: []string{"predicate:buyer"}},
			{ObligationID: "work", Kind: "fulfillment", ObligorAgentID: "agent:provider",
				BeneficiaryAgentID: "agent:buyer", SubjectContentType: "text/plain", Subject: append([]byte(nil), subject...),
				AttachmentDigests: executionAttachments, RequiredExtensions: executionBindings,
				DueAtUnix: 8_000, ExpiresAtUnix: 9_000, ConfidentialityPolicy: "participants",
				CancellationPolicy: "chain-profile", DisputePolicy: "objective",
				AuthorizationPredicateIDs: []string{"predicate:provider"}},
		}, AuthorizationPredicates: []commerce.AgreementAuthorizationPredicate{
			{PredicateID: "predicate:buyer", AuthoritySubject: commerce.AgreementAuthoritySubject{SubjectKind: "wallet",
				SubjectNamespace: "tos.wallet", SubjectIdentifier: "wallet:buyer", RepresentedAgentID: "agent:buyer"},
				RoleScope: []string{"buyer"}, ObligationIDs: []string{"payment"},
				EvidenceProfileURI: commerce.EvidenceProfilePaidDemandQuote, EvidenceProfileVersion: 1,
				EvidenceProfileDigest: profileDigest, ExpiresAtUnix: 7_000},
			{PredicateID: "predicate:provider", AuthoritySubject: commerce.AgreementAuthoritySubject{SubjectKind: "agent",
				SubjectNamespace: "tos.agent", SubjectIdentifier: "agent:provider"}, RoleScope: []string{"provider"},
				ObligationIDs: []string{"work"}, EvidenceProfileURI: commerce.EvidenceProfilePaidDemandQuote,
				EvidenceProfileVersion: 1, EvidenceProfileDigest: profileDigest, ExpiresAtUnix: 7_000},
		}, ValidFromUnix: 100, ExpiresAtUnix: 10_000}
	prepared, err := commerce.PrepareAgreementTargets(body)
	if err != nil {
		t.Fatalf("prepare child %d: %v", sequence, err)
	}
	return prepared
}

func (fixture objectiveMilestoneTestFixture) newAuthority() *objectiveMilestoneTestAuthority {
	authority := &objectiveMilestoneTestAuthority{records: make(map[string]EngagementRecord),
		ledgers: make(map[string][]SettlementLedgerRecord), finalized: make(map[string]ObjectiveMilestoneFinalizedEvidence),
		limits: PortfolioLimits{MaximumLossAtomic: 150}}
	for _, milestone := range fixture.milestones {
		authority.records[milestone.childDigest] = objectiveMilestoneProposedRecord(milestone)
	}
	return authority
}

func (fixture objectiveMilestoneTestFixture) setTerminal(t *testing.T, authority *objectiveMilestoneTestAuthority,
	index int, released bool) {
	t.Helper()
	milestone := fixture.milestones[index]
	evidence := objectiveMilestoneTestDigest(byte('1' + index))
	delivery := objectiveMilestoneTestDigest(byte('4' + index))
	instances, err := commerce.MaterializeSettlementObligations("owner:test", milestone.payment.ObligorAgentID,
		milestone.childDigest, milestone.payment.ObligationID, objectiveMilestoneTestDigest('a'), milestone.payment)
	if err != nil || len(instances) != 1 {
		t.Fatalf("materialize milestone %d settlement: %v", index+1, err)
	}
	state, err := commerce.NewSettlementState(instances[0])
	if err == nil {
		state, err = commerce.ApplyPayment(state, instances[0], evidence, *milestone.payment.Amount,
			time.Unix(1_000, 0).UTC())
	}
	if err != nil {
		t.Fatalf("settle milestone %d: %v", index+1, err)
	}
	record := objectiveMilestoneProposedRecord(milestone)
	record.State = EngagementSettled
	record.ReservationID = objectiveMilestoneReservationID(milestone)
	record.SettlementEvidence = []string{evidence}
	record.ObligationRuntime = map[string]ObligationRuntimeRecord{
		milestone.payment.ObligationID: {ObligationID: milestone.payment.ObligationID, State: ObligationSettled,
			StateRevision: 1, SettlementEvidence: []string{evidence}},
		milestone.work.ObligationID: {ObligationID: milestone.work.ObligationID, State: ObligationDelivered,
			StateRevision: 1, DeliveryEvidence: []string{delivery}},
	}
	authority.records[milestone.childDigest] = record
	authority.ledgers[milestone.childDigest] = []SettlementLedgerRecord{{Obligation: instances[0], State: state}}
	authority.reservations = append(authority.reservations, objectiveMilestoneReservation(milestone, released))
	authority.finalized[milestone.childDigest] = ObjectiveMilestoneFinalizedEvidence{
		NetworkContext: milestone.child.NetworkContext, AgreementBodyDigest: milestone.childDigest,
		PaymentObligationID: milestone.payment.ObligationID, WorkObligationID: milestone.work.ObligationID,
		PayerAgentID: milestone.payment.ObligorAgentID, PayeeAgentID: milestone.payment.BeneficiaryAgentID,
		SettlementAdapterURI: paiddemand.SettlementAdapterURI, Asset: milestone.assetIdentity,
		AmountAtomic: milestone.payment.Amount.AmountAtomic, EvidenceProfileURI: paidDemandPaymentEvidenceProfile,
		ResolutionState:       "provider_credit_finalized",
		QuoteCommitment:       "tvm-cell-sha256:" + strings.Repeat(string(byte('a'+index)), 64),
		EscrowAddress:         "0:" + strings.Repeat(string(byte('a'+index)), 64),
		ProviderWalletAddress: "wallet:provider",
		ReceiptCommitment:     "tvm-cell-sha256:" + strings.Repeat(string(byte('d'+index)), 64),
		PaymentRequestDigest:  objectiveMilestoneTestDigest(byte('d' + index)),
		PaymentStableActionID: milestone.childDigest,
		PaymentEvidenceDigest: evidence, DeliveryEvidenceDigests: []string{delivery},
		ExactTransferReference: objectiveMilestoneTestDigest(byte('7' + index)),
		FinalityReference:      objectiveMilestoneTestDigest(byte('a' + index)), ResolvedAtUnix: 1_000,
	}
}

func objectiveMilestoneProposedRecord(milestone validatedObjectiveMilestone) EngagementRecord {
	return EngagementRecord{Agreement: commerce.AgentAgreement{Body: milestone.child}, AgreementDigest: milestone.childDigest,
		State: EngagementAuthorizing}
}

func objectiveMilestoneReservationID(milestone validatedObjectiveMilestone) string {
	return "reservation:" + milestone.childDigest[7:]
}

func objectiveMilestoneReservation(milestone validatedObjectiveMilestone, released bool) ExposureReservation {
	asset := milestone.assetIdentity
	return ExposureReservation{ReservationID: objectiveMilestoneReservationID(milestone),
		AgreementDigest: milestone.childDigest, Asset: &asset, SpendAtomic: milestone.amountAtomic,
		LockedCapitalAtomic: milestone.amountAtomic, MaximumLossAtomic: milestone.amountAtomic, Released: released}
}

func objectiveMilestoneTestAdmission(authority *objectiveMilestoneTestAuthority,
	plan ObjectiveMilestoneEscrowPlan) ObjectiveMilestoneFundingAdmission {
	return ObjectiveMilestoneFundingAdmission{Authority: authority, FinalizedEvidence: authority, Plan: plan}
}

func objectiveMilestoneMutatedChildPlan(t *testing.T, plan ObjectiveMilestoneEscrowPlan, index int,
	mutate func(*commerce.AgentAgreementBody)) ObjectiveMilestoneEscrowPlan {
	t.Helper()
	mutated := plan
	mutated.Milestones = append([]ObjectiveMilestoneEscrow(nil), plan.Milestones...)
	body := mutated.Milestones[index].ChildAgreement
	body.Obligations = append([]commerce.AgreementObligation(nil), body.Obligations...)
	body.AuthorizationPredicates = append([]commerce.AgreementAuthorizationPredicate(nil), body.AuthorizationPredicates...)
	mutate(&body)
	for predicateIndex := range body.AuthorizationPredicates {
		body.AuthorizationPredicates[predicateIndex].EvidenceTargetProjectionDigest = ""
	}
	prepared, err := commerce.PrepareAgreementTargets(body)
	if err != nil {
		t.Fatalf("prepare mutated objective milestone child: %v", err)
	}
	mutated.Milestones[index].ChildAgreement = prepared
	return mutated
}

func requireObjectiveMilestoneDisposition(t *testing.T, admission ObjectiveMilestoneFundingAdmission,
	record EngagementRecord, want PaidDemandFundingAdmissionDisposition) {
	t.Helper()
	decision, err := admission.DecidePaidDemandFunding(context.Background(), record)
	if err != nil || decision.Disposition != want {
		t.Fatalf("funding admission disposition=%d want=%d err=%v", decision.Disposition, want, err)
	}
}

func objectiveMilestoneReplaceWithFullPaidLedger(t *testing.T, authority *objectiveMilestoneTestAuthority,
	milestone validatedObjectiveMilestone, obligation commerce.SettlementObligation) {
	t.Helper()
	evidence := authority.records[milestone.childDigest].SettlementEvidence[0]
	state, err := commerce.NewSettlementState(obligation)
	if err == nil {
		state, err = commerce.ApplyPayment(state, obligation, evidence, obligation.Amount,
			time.Unix(1_000, 0).UTC())
	}
	if err != nil || state.State != commerce.SettlementPaid {
		t.Fatalf("rebuild full paid ledger: state=%s err=%v", state.State, err)
	}
	authority.ledgers[milestone.childDigest] = []SettlementLedgerRecord{{Obligation: obligation, State: state}}
	objectiveMilestoneSetLocalPaymentEvidence(authority, milestone, []string{evidence})
}

func objectiveMilestoneSetLocalPaymentEvidence(authority *objectiveMilestoneTestAuthority,
	milestone validatedObjectiveMilestone, evidence []string) {
	selected := append([]string(nil), evidence...)
	sort.Strings(selected)
	record := authority.records[milestone.childDigest]
	record.SettlementEvidence = append([]string(nil), selected...)
	runtime := record.ObligationRuntime[milestone.payment.ObligationID]
	runtime.SettlementEvidence = append([]string(nil), selected...)
	record.ObligationRuntime[milestone.payment.ObligationID] = runtime
	authority.records[milestone.childDigest] = record
}

func objectiveMilestoneTestDigest(character byte) string {
	return "sha256:" + strings.Repeat(string(character), 64)
}
