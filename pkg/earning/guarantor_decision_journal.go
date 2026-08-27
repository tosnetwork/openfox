package earning

import (
	"errors"
	"math/big"
	"sort"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	guarantor "github.com/tosnetwork/tos-service-protocol/pkg/agentguarantor"
)

// InitialClaimIngressAdmissionCut freezes every initial-claim ingress action
// sequenced by the filing cutoff and projects its exact durable outcome. It is
// intentionally built from the write-ahead admission log rather than the
// admitted-claim index, so a crash between ingress and claim admission cannot
// disappear from filing close.
func (journal *GuarantorJournal) InitialClaimIngressAdmissionCut(agreementDigest string,
	cutoffUnix uint64) (guarantor.ClaimIngressAdmissionCutProofV1, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if err := journal.ensureAttached(); err != nil || !canonicalSHA256(agreementDigest) || cutoffUnix == 0 {
		return guarantor.ClaimIngressAdmissionCutProofV1{}, errors.New("Guarantor initial claim ingress cut input is invalid")
	}
	position, found := journal.doc.Coverages[agreementDigest]
	if !found {
		return guarantor.ClaimIngressAdmissionCutProofV1{}, errors.New("Guarantor initial claim ingress cut has no coverage")
	}
	logID, err := guarantor.ClaimIngressLogIDV1(agreementDigest, position.Record.CoverageObligationID, "")
	if err != nil {
		return guarantor.ClaimIngressAdmissionCutProofV1{}, err
	}
	log, logFound := journal.doc.AdmissionLogs[logID]
	if !logFound {
		root, rootErr := guarantor.InitialClaimLogRootV1(guarantor.ClaimIngressLogRootDomainV1, logID)
		if rootErr != nil {
			return guarantor.ClaimIngressAdmissionCutProofV1{}, rootErr
		}
		proof := guarantor.ClaimIngressAdmissionCutProofV1{SchemaVersion: 1,
			CoverageAgreementBodyDigest: agreementDigest, CoverageObligationID: position.Record.CoverageObligationID,
			CutKind: "initial_claims", ClaimIngressLogID: logID, IngressCutoffUnix: cutoffUnix,
			AdmissionLogRoot: root, Entries: []guarantor.ClaimIngressResolutionEntryV1{}}
		return proof, guarantor.ValidateClaimIngressAdmissionCutProofV1(proof)
	}
	type sequenced struct {
		entry GuarantorAdmissionEntry
	}
	ordered := make([]sequenced, 0, len(log.Entries))
	for _, entry := range log.Entries {
		if entry.ReceivedAtUnix <= cutoffUnix {
			ordered = append(ordered, sequenced{entry: entry})
		}
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].entry.Sequence < ordered[j].entry.Sequence })
	entries := make([]guarantor.ClaimIngressResolutionEntryV1, 0, len(ordered))
	var admitted, rejected, pending uint64
	for index, item := range ordered {
		entry := item.entry
		if entry.Sequence != uint64(index+1) {
			return guarantor.ClaimIngressAdmissionCutProofV1{}, errors.New("Guarantor initial claim ingress cut has a gap")
		}
		projected := guarantor.ClaimIngressResolutionEntryV1{ClaimIngressSequence: entry.Sequence,
			ReceivedAtUnix: entry.ReceivedAtUnix, IngressActionResolution: entry.Resolution,
			ResolutionKind: "pending_or_ambiguous"}
		if entry.Resolution.State == commerce.ActionRejected || entry.Resolution.State == commerce.ActionConflict {
			projected.ResolutionKind = "ingress_rejected"
			rejected++
		} else {
			var ingress *guarantor.AuthorizedClaimSubmissionIngressReceiptV1
			for _, receipt := range position.ClaimIngressReceipts {
				if receipt.Body.IngressKind == "initial" && receipt.Body.StableActionID == entry.StableActionID {
					copyReceipt := receipt
					ingress = &copyReceipt
					break
				}
			}
			if ingress != nil {
				ingressDigest, digestErr := guarantor.ClaimIngressReceiptDigestV1(*ingress)
				admission, admissionFound := position.ClaimAdmissionReceipts[guarantorClaimRevisionKey(ingress.Body.ClaimID, 1)]
				if digestErr == nil && admissionFound {
					admissionDigest, admissionErr := guarantor.ClaimAdmissionReceiptDigestV1(admission)
					if admissionErr == nil {
						resolution := admission.StageActionAdmissionEvidence.ActionResolution
						projected.ClaimIngressReceiptDigest = ingressDigest
						projected.ClaimAdmissionActionResolution = &resolution
						projected.ClaimAdmissionReceiptDigest = admissionDigest
						projected.ResolutionKind = "claim_admitted"
						admitted++
					}
				}
			}
			if projected.ResolutionKind == "pending_or_ambiguous" {
				pending++
			}
		}
		entries = append(entries, projected)
	}
	root := log.CurrentRoot
	if len(ordered) == 0 {
		root, _ = guarantor.InitialClaimLogRootV1(guarantor.ClaimIngressLogRootDomainV1, logID)
	} else {
		root = ordered[len(ordered)-1].entry.LogRootAfter
	}
	proof := guarantor.ClaimIngressAdmissionCutProofV1{SchemaVersion: 1,
		CoverageAgreementBodyDigest: agreementDigest, CoverageObligationID: position.Record.CoverageObligationID,
		CutKind: "initial_claims", ClaimIngressLogID: logID, IngressCutoffUnix: cutoffUnix,
		AdmissionHighWater: uint64(len(entries)), AdmissionLogRoot: root, Entries: entries,
		AdmittedClaimCount: admitted, RejectedIngressOrClaimCount: rejected, PendingOrAmbiguousCount: pending}
	if err := guarantor.ValidateClaimIngressAdmissionCutProofV1(proof); err != nil {
		return guarantor.ClaimIngressAdmissionCutProofV1{}, err
	}
	return proof, nil
}

// ClaimRevisionAdmissionCut freezes the exact per-claim revision ingress log.
// It is derived only from persisted portable receipts; a caller cannot supply
// a private database cursor or omit a previously sequenced revision.
func (journal *GuarantorJournal) ClaimRevisionAdmissionCut(agreementDigest, claimID string,
	cutoffUnix uint64) (guarantor.ClaimIngressAdmissionCutProofV1, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if err := journal.ensureAttached(); err != nil || !canonicalSHA256(agreementDigest) ||
		!canonicalSHA256(claimID) || cutoffUnix == 0 {
		return guarantor.ClaimIngressAdmissionCutProofV1{}, errors.New("Guarantor claim revision cut input is invalid")
	}
	position, found := journal.doc.Coverages[agreementDigest]
	record, claimFound := position.Claims[claimID]
	if !found || !claimFound || record.ClaimRevision == 0 {
		return guarantor.ClaimIngressAdmissionCutProofV1{}, errors.New("Guarantor claim revision cut has no admitted claim")
	}
	logID, err := guarantor.ClaimIngressLogIDV1(agreementDigest, position.Record.CoverageObligationID, claimID)
	if err != nil {
		return guarantor.ClaimIngressAdmissionCutProofV1{}, err
	}
	type sequenced struct {
		sequence uint64
		entry    guarantor.ClaimIngressResolutionEntryV1
	}
	entries := make([]sequenced, 0, record.ClaimRevision-1)
	for revision := uint64(2); revision <= record.ClaimRevision; revision++ {
		key := guarantorClaimRevisionKey(claimID, revision)
		ingress, ingressFound := position.ClaimIngressReceipts[key]
		admission, admissionFound := position.ClaimAdmissionReceipts[key]
		if !ingressFound || !admissionFound || ingress.Body.ClaimIngressLogID != logID ||
			ingress.Body.ReceivedAtUnix > cutoffUnix {
			return guarantor.ClaimIngressAdmissionCutProofV1{}, errors.New("Guarantor claim revision cut is incomplete")
		}
		ingressDigest, digestErr := guarantor.ClaimIngressReceiptDigestV1(ingress)
		admissionDigest, admissionErr := guarantor.ClaimAdmissionReceiptDigestV1(admission)
		if digestErr != nil || admissionErr != nil {
			return guarantor.ClaimIngressAdmissionCutProofV1{}, errors.New("Guarantor claim revision cut receipt is invalid")
		}
		admissionResolution := admission.StageActionAdmissionEvidence.ActionResolution
		entries = append(entries, sequenced{sequence: ingress.Body.ClaimIngressSequence,
			entry: guarantor.ClaimIngressResolutionEntryV1{ClaimIngressSequence: ingress.Body.ClaimIngressSequence,
				ReceivedAtUnix: ingress.Body.ReceivedAtUnix, IngressActionResolution: ingress.StageActionAdmissionEvidence.ActionResolution,
				ClaimIngressReceiptDigest: ingressDigest, ResolutionKind: "claim_admitted",
				ClaimAdmissionActionResolution: &admissionResolution, ClaimAdmissionReceiptDigest: admissionDigest}})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].sequence < entries[j].sequence })
	proofEntries := make([]guarantor.ClaimIngressResolutionEntryV1, len(entries))
	for index, item := range entries {
		if item.sequence != uint64(index+1) {
			return guarantor.ClaimIngressAdmissionCutProofV1{}, errors.New("Guarantor claim revision ingress log has a gap")
		}
		proofEntries[index] = item.entry
	}
	root, err := guarantor.InitialClaimLogRootV1(guarantor.ClaimIngressLogRootDomainV1, logID)
	if err != nil {
		return guarantor.ClaimIngressAdmissionCutProofV1{}, err
	}
	if len(proofEntries) > 0 {
		last := position.ClaimIngressReceipts[guarantorClaimRevisionKey(claimID, record.ClaimRevision)]
		root = last.Body.AdmittedClaimIngressLogRoot
	}
	proof := guarantor.ClaimIngressAdmissionCutProofV1{SchemaVersion: 1,
		CoverageAgreementBodyDigest: agreementDigest, CoverageObligationID: position.Record.CoverageObligationID,
		CutKind: "claim_revisions", ClaimID: claimID, RevisionEpoch: record.ClaimRevision,
		PriorEpochStateRevision: 1, FrozenEpochStateRevision: 2, ClaimIngressLogID: logID,
		IngressCutoffUnix: cutoffUnix, AdmissionHighWater: uint64(len(proofEntries)), AdmissionLogRoot: root,
		Entries: proofEntries, AdmittedClaimCount: uint64(len(proofEntries))}
	if err := guarantor.ValidateClaimIngressAdmissionCutProofV1(proof); err != nil {
		return guarantor.ClaimIngressAdmissionCutProofV1{}, err
	}
	return proof, nil
}

func claimStatusFromDecisionResult(result guarantor.ClaimDecisionResult) (guarantor.ClaimStatus, string, error) {
	switch result {
	case guarantor.DecisionApproved:
		return guarantor.ClaimApproved, "approved", nil
	case guarantor.DecisionPartiallyApproved:
		return guarantor.ClaimPartiallyApproved, "partially_approved", nil
	case guarantor.DecisionDenied:
		return guarantor.ClaimDenied, "denied", nil
	case guarantor.DecisionEvidenceRequired:
		return guarantor.ClaimEvidenceRequired, "evidence_required", nil
	case guarantor.DecisionDisputed:
		return guarantor.ClaimDisputed, "disputed", nil
	default:
		return "", "", errors.New("Guarantor decision result is unknown")
	}
}

func atomicAdd(left, right string) (string, error) {
	a, okA := new(big.Int).SetString(left, 10)
	b, okB := new(big.Int).SetString(right, 10)
	if !okA || !okB || a.Sign() < 0 || b.Sign() < 0 {
		return "", errors.New("Guarantor atomic amount is invalid")
	}
	return new(big.Int).Add(a, b).String(), nil
}

func atomicSub(left, right string) (string, error) {
	a, okA := new(big.Int).SetString(left, 10)
	b, okB := new(big.Int).SetString(right, 10)
	if !okA || !okB || a.Sign() < 0 || b.Sign() < 0 || a.Cmp(b) < 0 {
		return "", errors.New("Guarantor atomic amount underflows")
	}
	return new(big.Int).Sub(a, b).String(), nil
}

func (journal *GuarantorJournal) CommitDecisionAdmission(agreementDigest string,
	receipt guarantor.AuthorizedClaimDecisionAdmissionReceiptV1) (guarantor.ClaimRecord, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if err := journal.ensureAttached(); err != nil || !canonicalSHA256(agreementDigest) {
		return guarantor.ClaimRecord{}, errors.New("Guarantor decision admission commit is invalid")
	}
	body := receipt.Body
	position, found := journal.doc.Coverages[agreementDigest]
	record, claimFound := position.Claims[body.ClaimID]
	if !found || !claimFound || body.CoverageAgreementBodyDigest != agreementDigest ||
		position.Record.CoverageRevision != body.PriorCoverageRevision || record.ClaimStateRevision != body.PriorClaimStateRevision ||
		record.ClaimRevision != receipt.AuthorizedClaimDecision.Body.ExpectedClaimRevision ||
		position.AggregatePendingDecisionReserveAtomic != body.AggregatePendingDecisionReserveBefore.AmountAtomic {
		return guarantor.ClaimRecord{}, errors.New("Guarantor decision admission lost its state CAS")
	}
	if existing, exists := position.DecisionAdmissionReceipts[body.ClaimID]; exists {
		existingDigest, _ := guarantor.ClaimDecisionAdmissionReceiptDigestV1(existing)
		incomingDigest, _ := guarantor.ClaimDecisionAdmissionReceiptDigestV1(receipt)
		if existingDigest == incomingDigest {
			return record, nil
		}
		transition, transitioned := position.ClaimStateTransitionReceipts[body.ClaimID]
		transitionDigest, _ := guarantor.ClaimStateTransitionReceiptDigestV1(transition)
		reviewingSuccessor := transitioned && body.PriorClaimState == "reviewing" &&
			(body.DecisionPath == "successor" || body.DecisionPath == "terminal_fallback") &&
			body.PredecessorClaimStateTransitionReceiptDigest == transitionDigest &&
			(body.DecisionPath == "terminal_fallback" || receipt.PredecessorClaimStateTransitionReceipt != nil &&
				sameJSON(*receipt.PredecessorClaimStateTransitionReceipt, transition))
		nonterminalFallback := !transitioned && body.DecisionPath == "terminal_fallback" &&
			(body.PriorClaimState == "evidence_required" || body.PriorClaimState == "disputed") &&
			body.PredecessorClaimStateTransitionReceiptDigest == ""
		if body.PredecessorDecisionAdmissionReceiptDigest != existingDigest || (!reviewingSuccessor && !nonterminalFallback) {
			return guarantor.ClaimRecord{}, errors.New("Guarantor claim already has a conflicting decision head")
		}
	}
	initial := record.DecisionSequence == 0 && record.ClaimStatus == guarantor.ClaimAdmitted &&
		(body.DecisionPath == "initial" || body.DecisionPath == "initial_terminal_fallback")
	successorState := record.ClaimStatus == guarantor.ClaimReviewing || record.ClaimStatus == guarantor.ClaimEvidenceRequired ||
		record.ClaimStatus == guarantor.ClaimDisputed
	successor := record.DecisionSequence > 0 && successorState &&
		(body.DecisionPath == "successor" && record.ClaimStatus == guarantor.ClaimReviewing || body.DecisionPath == "terminal_fallback")
	if body.DecisionSequence != record.DecisionSequence+1 || (!initial && !successor) {
		return guarantor.ClaimRecord{}, errors.New("Guarantor decision lineage is invalid")
	}
	target, _, err := claimStatusFromDecisionResult(receipt.AuthorizedClaimDecision.Body.Result)
	if err != nil {
		return guarantor.ClaimRecord{}, err
	}
	if body.PriorClaimState != "admitted" || body.AdmittedClaimState != stringLowerClaimStatus(target) ||
		body.AdmittedClaimStateRevision != record.ClaimStateRevision+1 || body.AdmittedCoverageRevision != position.Record.CoverageRevision+1 {
		return guarantor.ClaimRecord{}, errors.New("Guarantor decision admission state projection differs")
	}
	pendingBase := position.AggregatePendingDecisionReserveAtomic
	if receipt.PriorPendingApplicationToken != nil {
		pendingBase, err = atomicSub(pendingBase, receipt.PriorPendingApplicationToken.ReservedApprovedAmount.AmountAtomic)
		if err != nil {
			return guarantor.ClaimRecord{}, errors.New("Guarantor replaced decision reserve underflows")
		}
	}
	pendingAfter, err := atomicAdd(pendingBase, receipt.AuthorizedClaimDecision.Body.ApprovedAmount.AmountAtomic)
	if err != nil || pendingAfter != body.AggregatePendingDecisionReserveAfter.AmountAtomic {
		return guarantor.ClaimRecord{}, errors.New("Guarantor decision reserve arithmetic differs")
	}
	record.ClaimStatus = target
	record.ClaimStateRevision++
	record.DecisionSequence = body.DecisionSequence
	receiptDigest, err := guarantor.ClaimDecisionAdmissionReceiptDigestV1(receipt)
	if err != nil {
		return guarantor.ClaimRecord{}, err
	}
	record.LastEvidenceDigest = receiptDigest
	position.Record.CoverageRevision++
	position.Record.LastEvidenceDigest = receiptDigest
	position.AggregatePendingDecisionReserveAtomic = pendingAfter
	position.Claims[body.ClaimID] = record
	position.Decisions[body.ClaimID] = receipt.AuthorizedClaimDecision
	position.DecisionAdmissionReceipts[body.ClaimID] = receipt
	delete(position.ClaimStateTransitionReceipts, body.ClaimID)
	if body.ResultingApplicationToken != nil {
		position.DecisionApplicationTokens[body.ClaimID] = *body.ResultingApplicationToken
	}
	next := cloneGuarantorDocument(journal.doc)
	next.Coverages[agreementDigest] = position
	next.Revision++
	if err := journal.commit(next); err != nil {
		return guarantor.ClaimRecord{}, err
	}
	return record, nil
}

func claimStatusFromWire(value string) (guarantor.ClaimStatus, error) {
	switch value {
	case "reviewing":
		return guarantor.ClaimReviewing, nil
	case "final_approved":
		return guarantor.ClaimFinalApproved, nil
	case "final_partially_approved":
		return guarantor.ClaimFinalPartiallyApproved, nil
	case "final_denied":
		return guarantor.ClaimFinalDenied, nil
	default:
		return "", errors.New("Guarantor wire claim state is unknown")
	}
}

func (journal *GuarantorJournal) CommitClaimStateTransition(agreementDigest string,
	receipt guarantor.AuthorizedClaimStateTransitionReceiptV1) (guarantor.ClaimRecord, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if err := journal.ensureAttached(); err != nil || !canonicalSHA256(agreementDigest) {
		return guarantor.ClaimRecord{}, errors.New("Guarantor claim transition commit is invalid")
	}
	body := receipt.Body
	position, found := journal.doc.Coverages[agreementDigest]
	record, claimFound := position.Claims[body.ClaimID]
	currentDecision, decisionFound := position.DecisionAdmissionReceipts[body.ClaimID]
	currentDecisionDigest, _ := guarantor.ClaimDecisionAdmissionReceiptDigestV1(currentDecision)
	if !found || !claimFound || !decisionFound || body.CoverageAgreementBodyDigest != agreementDigest ||
		record.ClaimStateRevision != body.PriorClaimStateRevision || stringLowerClaimStatus(record.ClaimStatus) != body.PriorClaimState ||
		position.ChallengeRoundsUsed[body.ClaimID] != body.ChallengeRoundsUsedBefore ||
		position.NonterminalRoundsUsed[body.ClaimID] != body.NonterminalRoundsUsedBefore ||
		currentDecisionDigest != receipt.DecisionAdmissionProof.ReceiptEnvelopeDigest {
		return guarantor.ClaimRecord{}, errors.New("Guarantor claim transition lost its state CAS or decision head")
	}
	if existing, exists := position.ClaimStateTransitionReceipts[body.ClaimID]; exists {
		existingDigest, _ := guarantor.ClaimStateTransitionReceiptDigestV1(existing)
		incomingDigest, _ := guarantor.ClaimStateTransitionReceiptDigestV1(receipt)
		if existingDigest == incomingDigest {
			return record, nil
		}
		if existing.DecisionAdmissionProof.ReceiptEnvelopeDigest == currentDecisionDigest {
			return guarantor.ClaimRecord{}, errors.New("Guarantor claim transition head conflicts")
		}
	}
	target, err := claimStatusFromWire(body.ResultingClaimState)
	if err != nil || body.ResultingClaimStateRevision != record.ClaimStateRevision+1 {
		return guarantor.ClaimRecord{}, errors.New("Guarantor claim transition result is invalid")
	}
	receiptDigest, err := guarantor.ClaimStateTransitionReceiptDigestV1(receipt)
	if err != nil {
		return guarantor.ClaimRecord{}, err
	}
	record.ClaimStatus = target
	record.ClaimStateRevision++
	record.LastEvidenceDigest = receiptDigest
	position.Claims[body.ClaimID] = record
	position.ClaimStateTransitionReceipts[body.ClaimID] = receipt
	position.ChallengeRoundsUsed[body.ClaimID] = body.ChallengeRoundsUsedAfter
	position.NonterminalRoundsUsed[body.ClaimID] = body.NonterminalRoundsUsedAfter
	next := cloneGuarantorDocument(journal.doc)
	next.Coverages[agreementDigest] = position
	next.Revision++
	if err := journal.commit(next); err != nil {
		return guarantor.ClaimRecord{}, err
	}
	return record, nil
}

func (journal *GuarantorJournal) CommitDecisionApplication(agreementDigest string,
	receipt guarantor.AuthorizedClaimDecisionApplicationReceiptV1) (guarantor.ClaimRecord, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if err := journal.ensureAttached(); err != nil || !canonicalSHA256(agreementDigest) {
		return guarantor.ClaimRecord{}, errors.New("Guarantor decision application commit is invalid")
	}
	body := receipt.Body
	position, found := journal.doc.Coverages[agreementDigest]
	record, claimFound := position.Claims[body.ClaimID]
	token, tokenFound := position.DecisionApplicationTokens[body.ClaimID]
	transition, transitionFound := position.ClaimStateTransitionReceipts[body.ClaimID]
	if !found || !claimFound || !tokenFound || !transitionFound || body.CoverageAgreementBodyDigest != agreementDigest ||
		position.Record.CoverageRevision != body.PriorCoverageRevision || record.ClaimStateRevision != body.PriorClaimStateRevision ||
		position.AggregatePendingDecisionReserveAtomic != body.AggregatePendingDecisionReserveBefore.AmountAtomic ||
		position.CumulativeAppliedApprovedAtomic != body.CumulativeApprovedBefore.AmountAtomic ||
		position.NextPayoutSequence != body.PriorNextPayoutSequence ||
		position.MaterializedPayoutLineDigest != body.PriorMaterializedPayoutLineDigest ||
		!sameJSON(token, receipt.DecisionApplicationToken) || !sameJSON(transition, receipt.AuthorizedTerminalClaimStateTransitionReceipt) {
		return guarantor.ClaimRecord{}, errors.New("Guarantor decision application lost its state CAS")
	}
	if existing, exists := position.DecisionApplicationReceipts[body.ClaimID]; exists {
		existingDigest, _ := guarantor.ClaimDecisionApplicationReceiptDigestV1(existing)
		incomingDigest, _ := guarantor.ClaimDecisionApplicationReceiptDigestV1(receipt)
		if existingDigest == incomingDigest {
			return record, nil
		}
		return guarantor.ClaimRecord{}, errors.New("Guarantor decision application identity conflicts")
	}
	pendingAfter, err := atomicSub(position.AggregatePendingDecisionReserveAtomic,
		token.ReservedApprovedAmount.AmountAtomic)
	if err != nil || pendingAfter != body.AggregatePendingDecisionReserveAfter.AmountAtomic {
		return guarantor.ClaimRecord{}, errors.New("Guarantor pending decision reserve arithmetic differs")
	}
	cumulativeAfter, err := atomicAdd(position.CumulativeAppliedApprovedAtomic,
		token.ReservedApprovedAmount.AmountAtomic)
	if err != nil || cumulativeAfter != body.CumulativeApprovedAfter.AmountAtomic {
		return guarantor.ClaimRecord{}, errors.New("Guarantor cumulative approval arithmetic differs")
	}
	if body.AppliedCoverageRevision != position.Record.CoverageRevision+1 ||
		body.AppliedClaimStateRevision != record.ClaimStateRevision || body.ResultingApplicationTokenState != "consumed" ||
		body.ResultingApplicationTokenRevision != token.TokenRevision+1 {
		return guarantor.ClaimRecord{}, errors.New("Guarantor decision application result revision is invalid")
	}
	applicationDigest, err := guarantor.ClaimDecisionApplicationReceiptDigestV1(receipt)
	if err != nil {
		return guarantor.ClaimRecord{}, err
	}
	token.TokenRevision++
	token.State = "consumed"
	position.DecisionApplicationTokens[body.ClaimID] = token
	position.AggregatePendingDecisionReserveAtomic = pendingAfter
	position.CumulativeAppliedApprovedAtomic = cumulativeAfter
	position.NextPayoutSequence = body.ResultingNextPayoutSequence
	position.MaterializedPayoutLineDigest = body.ResultingMaterializedPayoutLineDigest
	position.Record.CoverageRevision++
	position.Record.LastEvidenceDigest = applicationDigest
	record.LastEvidenceDigest = applicationDigest
	if receipt.MaterializedPayoutObligationSet.MaterializationState == "not_applicable" {
		record.PayoutStatus = guarantor.PayoutNotApplicable
	} else {
		record.PayoutStatus = guarantor.PayoutPrepared
	}
	position.Claims[body.ClaimID] = record
	position.MaterializedPayouts[body.ClaimID] = receipt.MaterializedPayoutObligationSet
	position.DecisionApplicationReceipts[body.ClaimID] = receipt
	next := cloneGuarantorDocument(journal.doc)
	next.Coverages[agreementDigest] = position
	next.Revision++
	if err := journal.commit(next); err != nil {
		return guarantor.ClaimRecord{}, err
	}
	return record, nil
}

func stringLowerClaimStatus(status guarantor.ClaimStatus) string {
	switch status {
	case guarantor.ClaimApproved:
		return "approved"
	case guarantor.ClaimPartiallyApproved:
		return "partially_approved"
	case guarantor.ClaimDenied:
		return "denied"
	case guarantor.ClaimEvidenceRequired:
		return "evidence_required"
	case guarantor.ClaimDisputed:
		return "disputed"
	case guarantor.ClaimReviewing:
		return "reviewing"
	case guarantor.ClaimFinalApproved:
		return "final_approved"
	case guarantor.ClaimFinalPartiallyApproved:
		return "final_partially_approved"
	case guarantor.ClaimFinalDenied:
		return "final_denied"
	case guarantor.ClaimAdmitted:
		return "admitted"
	default:
		return ""
	}
}
