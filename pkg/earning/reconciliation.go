package earning

import (
	"context"
	"errors"
	"sort"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type ReconciliationIssue struct {
	Kind            string          `json:"kind"`
	AgreementDigest string          `json:"agreement_digest,omitempty"`
	ReservationID   string          `json:"reservation_id,omitempty"`
	EngagementState EngagementState `json:"engagement_state,omitempty"`
	Blocking        bool            `json:"blocking"`
	Detail          string          `json:"detail"`
}

type ReconciliationReport struct {
	PortfolioRevision uint64                `json:"portfolio_revision"`
	Issues            []ReconciliationIssue `json:"issues"`
	AppliedActionIDs  []string              `json:"applied_action_ids,omitempty"`
}

func (authority *PersonalAuthority) reconciliationSnapshot() (uint64, []ExposureReservation, map[string]EngagementRecord) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if authority.ensureStorageIdentityLocked() != nil {
		return 0, nil, nil
	}
	reservations := make([]ExposureReservation, 0, len(authority.doc.Reservations))
	for _, reservation := range authority.doc.Reservations {
		reservations = append(reservations, reservation)
	}
	engagements := make(map[string]EngagementRecord, len(authority.doc.Engagements))
	for digest, engagement := range authority.doc.Engagements {
		engagements[digest] = engagement
	}
	return authority.doc.PortfolioRevision, reservations, engagements
}

func (engine *Engine) ReconcileDryRun() (ReconciliationReport, error) {
	if engine == nil || engine.Authority == nil {
		return ReconciliationReport{}, errors.New("reconciliation authority is unavailable")
	}
	revision, reservations, engagements := engine.Authority.reconciliationSnapshot()
	report := ReconciliationReport{PortfolioRevision: revision}
	for _, engagement := range engagements {
		if engagement.State == EngagementAmbiguous || engagement.State == EngagementCancellationResolving || engagement.State == EngagementFundingPending {
			report.Issues = append(report.Issues, ReconciliationIssue{Kind: "unresolved-engagement", AgreementDigest: engagement.AgreementDigest,
				ReservationID: engagement.ReservationID, EngagementState: engagement.State, Blocking: true,
				Detail: "operator or adapter evidence is required; timeout is not success"})
		}
	}
	for _, reservation := range reservations {
		if reservation.Released {
			continue
		}
		engagement, found := engagements[reservation.AgreementDigest]
		if !found {
			report.Issues = append(report.Issues, ReconciliationIssue{Kind: "orphan-reservation", AgreementDigest: reservation.AgreementDigest,
				ReservationID: reservation.ReservationID, Blocking: true, Detail: "reservation has no Agreement record and cannot be released automatically"})
			continue
		}
		if terminalEngagement(engagement.State) {
			report.Issues = append(report.Issues, ReconciliationIssue{Kind: "releasable-reservation", AgreementDigest: reservation.AgreementDigest,
				ReservationID: reservation.ReservationID, EngagementState: engagement.State, Detail: "terminal engagement retains Portfolio exposure"})
		}
	}
	sort.Slice(report.Issues, func(i, j int) bool {
		left := report.Issues[i].Kind + "\x00" + report.Issues[i].AgreementDigest + "\x00" + report.Issues[i].ReservationID
		right := report.Issues[j].Kind + "\x00" + report.Issues[j].AgreementDigest + "\x00" + report.Issues[j].ReservationID
		return left < right
	})
	return report, nil
}

func terminalEngagement(state EngagementState) bool {
	return state == EngagementSettled || state == EngagementUnpaid || state == EngagementCancelled || state == EngagementFailed
}

func (engine *Engine) ReconcileApply(ctx context.Context, policyRevision uint64, fence commerce.WriterFence) (ReconciliationReport, error) {
	if !engine.permits("reconciliation", true, false) {
		return ReconciliationReport{}, errors.New("applied reconciliation is paused")
	}
	report, err := engine.ReconcileDryRun()
	if err != nil {
		return report, err
	}
	for _, issue := range report.Issues {
		if issue.Kind != "releasable-reservation" {
			continue
		}
		record, found := engine.Authority.Engagement(issue.AgreementDigest)
		if !found || !terminalEngagement(record.State) {
			return report, errors.New("reconciliation state changed before apply")
		}
		evidence := append(append([]string(nil), record.SettlementEvidence...), record.DeliveryEvidence...)
		stateEvidence, digestErr := codec.Digest("tos.openfox.reconciliation-terminal-state.v1", struct {
			AgreementDigest string          `json:"agreement_digest"`
			State           EngagementState `json:"state"`
			StateRevision   uint64          `json:"state_revision"`
		}{record.AgreementDigest, record.State, record.StateRevision})
		if digestErr != nil {
			return report, digestErr
		}
		evidence = append(evidence, stateEvidence)
		sort.Strings(evidence)
		evidence = uniqueStrings(evidence)
		evidenceSetDigest, digestErr := codec.Digest("tos.portfolio-terminal-evidence-set.v1", evidence)
		if digestErr != nil {
			return report, digestErr
		}
		revision, _, _ := engine.Authority.Snapshot()
		request := PortfolioReleaseRequest{ReservationID: issue.ReservationID, AgreementDigest: issue.AgreementDigest,
			TargetPortfolioRevision: revision + 1, TerminalEvidenceSetDigest: evidenceSetDigest}
		canonical, digestErr := codec.Marshal(request)
		if digestErr != nil {
			return report, digestErr
		}
		fields := map[string]commerce.SemanticValue{"owner_id": commerce.ID(engine.OwnerID), "agent_id": commerce.ID(engine.AgentID),
			"reservation_id": commerce.Digest32(issue.ReservationID), "target_revision": commerce.U64(request.TargetPortfolioRevision),
			"terminal_evidence_set_digest": commerce.Digest32(evidenceSetDigest)}
		action, buildErr := commerce.BuildAuthorizedAction(engine.OwnerID, engine.AgentID, "portfolio.release", fields, canonical, fence,
			policyRevision, engine.MandateDigest, "", string(record.State), fence.Body.ExpiresAtUnix)
		if buildErr == nil {
			action, buildErr = engine.Authority.SignAction(action, fence)
		}
		if buildErr != nil {
			return report, buildErr
		}
		resolution, releaseErr := engine.Authority.ReleaseReservation(action, fields, canonical, fence)
		if errors.Is(releaseErr, ErrCustodyAuthorizationLive) {
			// Settlement may be recorded, but caller-provided terminal evidence
			// cannot release an offline bearer. Authority time-based cleanup will
			// free the exact hold only after the signed payment validity ends.
			continue
		}
		if releaseErr != nil {
			return report, releaseErr
		}
		report.AppliedActionIDs = append(report.AppliedActionIDs, resolution.StableActionID)
	}
	return report, nil
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}
