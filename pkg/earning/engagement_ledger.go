package earning

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type PortfolioReservationRequest struct {
	Reservation             ExposureReservation `json:"reservation"`
	TargetPortfolioRevision uint64              `json:"target_portfolio_revision"`
}

func (authority *PersonalAuthority) RecordAgreementProposal(body commerce.AgentAgreementBody, proposerAgentID, eventID, proposalActionID string) (EngagementRecord, error) {
	if authority == nil || proposerAgentID == "" || eventID == "" || proposalActionID == "" {
		return EngagementRecord{}, errors.New("Agreement proposal observation is incomplete")
	}
	if err := commerce.ValidateAgreementBody(body); err != nil {
		return EngagementRecord{}, err
	}
	digest, err := commerce.AgreementBodyDigest(body)
	if err != nil {
		return EngagementRecord{}, err
	}
	participant := false
	for _, candidate := range body.Participants {
		participant = participant || candidate.AgentID == proposerAgentID
	}
	if !participant {
		return EngagementRecord{}, errors.New("Agreement proposer is not a body participant")
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if err := authority.ensureStorageIdentityLocked(); err != nil {
		return EngagementRecord{}, err
	}
	if existing, found := authority.doc.Engagements[digest]; found {
		if existing.ProposerAgentID == proposerAgentID && existing.ProposalActionID == proposalActionID {
			return existing, nil
		}
		if err := authority.recordNegotiationConflictLocked(body.AgreementID, "proposal_identity_conflict", digest); err != nil {
			return EngagementRecord{}, err
		}
		return EngagementRecord{}, errors.New("Agreement proposal identity conflicts with the retained exact body")
	}
	for priorDigest, existing := range authority.doc.Engagements {
		if existing.Agreement.Body.AgreementID == body.AgreementID &&
			existing.Agreement.Body.Version == body.Version && priorDigest != digest {
			if err := authority.recordNegotiationConflictLocked(body.AgreementID, "agreement_body_fork", priorDigest, digest); err != nil {
				return EngagementRecord{}, err
			}
			return EngagementRecord{}, errors.New("conflicting Agreement body for the same ID and version")
		}
	}
	for _, existing := range authority.doc.Engagements {
		if existing.Agreement.Body.AgreementID == body.AgreementID && existing.NegotiationAmbiguous {
			return EngagementRecord{}, errors.New("Agreement lineage has a retained negotiation conflict")
		}
	}
	if body.Version > 1 {
		predecessor, found := authority.doc.Engagements[body.PredecessorAgreementDigest]
		if !found {
			return EngagementRecord{}, errors.New("Agreement predecessor is not locally verified")
		}
		if err := validateAgreementSuccessor(predecessor.Agreement.Body, body); err != nil {
			return EngagementRecord{}, err
		}
	}
	now := authority.now().UTC()
	if now.Before(time.Unix(int64(body.ValidFromUnix), 0).UTC().Add(-commerce.MaxIntentClockSkew)) ||
		!now.Before(time.Unix(int64(body.ExpiresAtUnix), 0).UTC()) {
		return EngagementRecord{}, errors.New("Agreement proposal is premature or expired")
	}
	record := EngagementRecord{Agreement: commerce.AgentAgreement{Body: body}, AgreementDigest: digest,
		ProposerAgentID: proposerAgentID, ProposalEventID: eventID, ProposalActionID: proposalActionID, State: EngagementProposed,
		StateRevision: 1, LastTransitionAtUnix: uint64(now.Unix())}
	initializeObligationRuntime(&record)
	next := cloneAuthorityDocument(authority.doc)
	next.Engagements[digest] = record
	if err := authority.persist(next); err != nil {
		return EngagementRecord{}, err
	}
	authority.doc = next
	return record, nil
}

// recordNegotiationConflictLocked retains a verified equivocation before
// returning an error to the caller. The rejected body is not promoted to an
// Agreement, but every retained record in the same Agreement-ID graph is
// marked so automatic authorization cannot mistake the remaining branch for a
// unique head after restart.
func (authority *PersonalAuthority) recordNegotiationConflictLocked(agreementID, code string, digests ...string) error {
	next := cloneAuthorityDocument(authority.doc)
	updated := false
	for key, record := range next.Engagements {
		if record.Agreement.Body.AgreementID != agreementID {
			continue
		}
		record.NegotiationAmbiguous = true
		record.NegotiationConflictCodes = appendUniqueSorted(record.NegotiationConflictCodes, code)
		for _, digest := range digests {
			if canonicalSHA256(digest) {
				record.NegotiationConflictDigests = appendUniqueSorted(record.NegotiationConflictDigests, digest)
			}
		}
		next.Engagements[key] = record
		updated = true
	}
	if !updated {
		return errors.New("Agreement negotiation conflict has no retained lineage")
	}
	if err := authority.persist(next); err != nil {
		return err
	}
	authority.doc = next
	return nil
}

func validNegotiationConflictRecord(record EngagementRecord) bool {
	if !record.NegotiationAmbiguous {
		return len(record.NegotiationConflictCodes) == 0 && len(record.NegotiationConflictDigests) == 0
	}
	if len(record.NegotiationConflictCodes) == 0 || len(record.NegotiationConflictDigests) == 0 {
		return false
	}
	for index, code := range record.NegotiationConflictCodes {
		if code != "agreement_body_fork" && code != "proposal_identity_conflict" ||
			index > 0 && record.NegotiationConflictCodes[index-1] >= code {
			return false
		}
	}
	for index, digest := range record.NegotiationConflictDigests {
		if !canonicalSHA256(digest) || index > 0 && record.NegotiationConflictDigests[index-1] >= digest {
			return false
		}
	}
	return true
}

func (authority *PersonalAuthority) ObserveAgreementWithdrawal(agreementDigest, proposalActionID, senderAgentID, eventID string) (EngagementRecord, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if err := authority.ensureStorageIdentityLocked(); err != nil {
		return EngagementRecord{}, err
	}
	record, found := authority.doc.Engagements[agreementDigest]
	if !found || record.ProposalActionID != proposalActionID || record.ProposerAgentID != senderAgentID || eventID == "" {
		return EngagementRecord{}, errors.New("Agreement withdrawal is unrelated to the exact proposal")
	}
	switch record.State {
	case EngagementProposed, EngagementAuthorizing:
		if record.ReservationID != "" {
			record.State = EngagementCancellationResolving
		} else {
			record.State = EngagementCancelled
		}
	case EngagementCancelled, EngagementFailed:
		return record, nil
	case EngagementAgreed, EngagementReserved, EngagementFundingPending, EngagementReady, EngagementExecutionPrepared,
		EngagementExecuting, EngagementExecutionSucceeded, EngagementDelivered, EngagementSettling, EngagementSettled,
		EngagementUnpaid, EngagementCancellationResolving:
		return EngagementRecord{}, errors.New("accepted Agreement cannot be cancelled by withdrawing its proposal")
	default:
		return EngagementRecord{}, errors.New("Agreement proposal is not withdrawable in its current state")
	}
	record.StateRevision++
	record.LastTransitionAtUnix = uint64(authority.now().UTC().Unix())
	next := cloneAuthorityDocument(authority.doc)
	next.Engagements[agreementDigest] = record
	if err := authority.persist(next); err != nil {
		return EngagementRecord{}, err
	}
	authority.doc = next
	return record, nil
}

// ObserveAgreementDelivery records an authenticated typed delivery on the
// beneficiary side. It does not imply acceptance or payment; those remain
// separate body-bound evidence and settlement transitions.
func (authority *PersonalAuthority) ObserveAgreementDelivery(agreementDigest, obligationID, manifestDigest,
	senderAgentID, eventID string) (EngagementRecord, error) {
	if authority == nil || !canonicalSHA256(agreementDigest) || obligationID == "" || !canonicalSHA256(manifestDigest) || senderAgentID == "" || eventID == "" {
		return EngagementRecord{}, errors.New("Agreement delivery observation is incomplete")
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if err := authority.ensureStorageIdentityLocked(); err != nil {
		return EngagementRecord{}, err
	}
	record, found := authority.doc.Engagements[agreementDigest]
	if !found {
		return EngagementRecord{}, errors.New("delivery has no exact Agreement")
	}
	matched := false
	for _, obligation := range record.Agreement.Body.Obligations {
		if obligation.ObligationID == obligationID && obligation.ObligorAgentID == senderAgentID && obligation.BeneficiaryAgentID == authority.doc.AgentID {
			matched = true
		}
	}
	if !matched {
		return EngagementRecord{}, errors.New("delivery sender or beneficiary differs from the Agreement")
	}
	initializeObligationRuntime(&record)
	runtime := record.ObligationRuntime[obligationID]
	if runtime.DeliveryEventID != "" {
		if runtime.DeliveryEventID == eventID && containsString(runtime.DeliveryEvidence, manifestDigest) {
			return record, nil
		}
		return EngagementRecord{}, errors.New("Agreement delivery conflicts with prior evidence")
	}
	if runtime.State != ObligationPending && runtime.State != ObligationReady {
		return EngagementRecord{}, errors.New("Agreement is not awaiting counterparty delivery")
	}
	obligation, _ := obligationByID(record, obligationID)
	if !obligationDependenciesSatisfied(record, obligation) {
		return EngagementRecord{}, errors.New("Agreement delivery dependencies are unresolved")
	}
	runtime.State = ObligationDelivered
	runtime.StateRevision++
	runtime.DeliveryEvidence = []string{manifestDigest}
	runtime.DeliveryEventID = eventID
	runtime.LastTransitionAtUnix = uint64(authority.now().UTC().Unix())
	record.ObligationRuntime[obligationID] = runtime
	record.DeliveryEvidence = appendUniqueSorted(record.DeliveryEvidence, manifestDigest)
	record.DeliveryEventID = eventID
	record.StateRevision++
	record.LastTransitionAtUnix = runtime.LastTransitionAtUnix
	refreshEngagementProjection(&record)
	next := cloneAuthorityDocument(authority.doc)
	next.Engagements[agreementDigest] = record
	if err := authority.persist(next); err != nil {
		return EngagementRecord{}, err
	}
	authority.doc = next
	return record, nil
}

func (authority *PersonalAuthority) RecordAgreementEvidence(agreementDigest string,
	evidence commerce.AgreementAuthorizationEvidence, verifier commerce.AgreementEvidenceVerifier) (EngagementRecord, error) {
	if authority == nil || verifier == nil {
		return EngagementRecord{}, errors.New("Agreement evidence verifier is unavailable")
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if err := authority.ensureStorageIdentityLocked(); err != nil {
		return EngagementRecord{}, err
	}
	record, found := authority.doc.Engagements[agreementDigest]
	if !found || record.State == EngagementCancelled || record.State == EngagementFailed {
		return EngagementRecord{}, errors.New("Agreement evidence has no active proposal")
	}
	// Check the durable lineage marker before the exact-evidence replay path.
	// Otherwise a fork discovered after the first acceptance could turn a
	// replay into permission for another outbound authorization side effect.
	if record.NegotiationAmbiguous {
		return EngagementRecord{}, errors.New("Agreement evidence targets an ambiguous negotiation lineage")
	}
	evidenceDigest, err := codec.Digest("tos.agreement-authorization-evidence.v1", evidence)
	if err != nil {
		return EngagementRecord{}, err
	}
	for _, existing := range record.Agreement.AuthorizationEvidence {
		existingDigest, digestErr := codec.Digest("tos.agreement-authorization-evidence.v1", existing)
		if digestErr == nil && existingDigest == evidenceDigest {
			return record, nil
		}
	}
	if record.State == EngagementProposed || record.State == EngagementAuthorizing {
		for _, successor := range authority.doc.Engagements {
			if successor.Agreement.Body.PredecessorAgreementDigest == agreementDigest {
				return EngagementRecord{}, errors.New("Agreement evidence targets an unfinished proposal superseded by a verified successor")
			}
		}
	}
	candidate := record.Agreement
	candidate.AuthorizationEvidence = append(append([]commerce.AgreementAuthorizationEvidence(nil), candidate.AuthorizationEvidence...), evidence)
	sort.Slice(candidate.AuthorizationEvidence, func(i, j int) bool {
		left, right := candidate.AuthorizationEvidence[i], candidate.AuthorizationEvidence[j]
		lk := left.AuthoritySubject.SubjectKind + "\x00" + left.AuthoritySubject.SubjectNamespace + "\x00" + left.AuthoritySubject.SubjectIdentifier + "\x00" + left.EvidenceProfileURI
		rk := right.AuthoritySubject.SubjectKind + "\x00" + right.AuthoritySubject.SubjectNamespace + "\x00" + right.AuthoritySubject.SubjectIdentifier + "\x00" + right.EvidenceProfileURI
		return lk < rk
	})
	now := authority.now().UTC()
	if err := validateAgreementAuthorizationTimeForCurrentDependency(candidate, now); err != nil {
		return EngagementRecord{}, err
	}
	if err := commerce.ValidatePartialAgreementAuthorization(candidate, verifier, now); err != nil {
		return EngagementRecord{}, err
	}
	state := EngagementAuthorizing
	if err := commerce.ValidateAgreementAuthorization(candidate, verifier, now); err == nil {
		state = EngagementAgreed
		if record.ReservationID != "" {
			state = EngagementReserved
		}
	}
	next := cloneAuthorityDocument(authority.doc)
	record.Agreement, record.State = candidate, state
	record.StateRevision++
	record.LastTransitionAtUnix = uint64(now.Unix())
	next.Engagements[agreementDigest] = record
	if err := authority.persist(next); err != nil {
		return EngagementRecord{}, err
	}
	authority.doc = next
	return record, nil
}

// ReserveEngagement serializes the exact portfolio.reserve action, aggregate
// limit check, reservation creation, and lifecycle promotion in one durable
// authority transaction.
func (authority *PersonalAuthority) ReserveEngagement(action commerce.AuthorizedAction,
	fields map[string]commerce.SemanticValue, canonicalRequest []byte, fence commerce.WriterFence,
	request PortfolioReservationRequest) (commerce.ActionResolution, EngagementRecord, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if err := authority.ensureStorageIdentityLocked(); err != nil {
		return commerce.ActionResolution{}, EngagementRecord{}, err
	}
	record, found := authority.doc.Engagements[request.Reservation.AgreementDigest]
	if !found || !engagementEligibleForReservation(record, authority.doc.AgentID) || request.Reservation.Released ||
		request.TargetPortfolioRevision != authority.doc.PortfolioRevision+1 {
		return commerce.ActionResolution{}, EngagementRecord{}, errors.New("Agreement is not eligible for reservation")
	}
	if paidDemandBuyerCandidate(record, authority.doc.AgentID) {
		expected, expectedErr := paidDemandBuyerReservation(record, authority.doc.AgentID)
		if expectedErr != nil || !sameExposureReservation(request.Reservation, expected) {
			return commerce.ActionResolution{}, EngagementRecord{}, errors.New("Paid Demand buyer reservation does not exactly cover Agreement exposure")
		}
	}
	if authority.doc.CurrentFence == nil || fence.Body.WriterGeneration != authority.doc.WriterGeneration ||
		fence.Body.LeaseID != authority.doc.CurrentFence.Body.LeaseID {
		return commerce.ActionResolution{}, EngagementRecord{}, errors.New("stale writer cannot reserve an Agreement")
	}
	resolver := localFenceResolver{authorityID: authority.doc.AuthorityID, key: authority.key.Public().(ed25519.PublicKey)}
	if action.ActionKind != "portfolio.reserve" || commerce.VerifyAuthorizedAction(action, fields, canonicalRequest, fence, resolver, authority.now().UTC()) != nil {
		return commerce.ActionResolution{}, EngagementRecord{}, errors.New("portfolio reservation action is not authorized")
	}
	if prior, exists := authority.doc.Actions[action.StableActionID]; exists {
		if prior.ExactRequestDigest != action.ExactRequestDigest {
			return commerce.ActionResolution{}, EngagementRecord{}, errors.New("portfolio reservation identity conflicts")
		}
		return prior, record, nil
	}
	next := cloneAuthorityDocument(authority.doc)
	if err := admitReservation(next, request.Reservation); err != nil {
		return commerce.ActionResolution{}, EngagementRecord{}, err
	}
	next.Reservations[request.Reservation.ReservationID] = request.Reservation
	next.PortfolioRevision++
	resolution := commerce.ActionResolution{StableActionID: action.StableActionID,
		ExactRequestDigest: action.ExactRequestDigest, State: commerce.ActionTerminal, StateRevision: 1}
	next.Actions[action.StableActionID] = resolution
	recordAuthorizedAction(&next, action)
	record.ReservationID = request.Reservation.ReservationID
	if record.State == EngagementAgreed {
		record.State = EngagementReserved
	} else {
		record.State = EngagementAuthorizing
	}
	record.StateRevision++
	record.LastTransitionAtUnix = uint64(authority.now().UTC().Unix())
	next.Engagements[record.AgreementDigest] = record
	if err := authority.persist(next); err != nil {
		return commerce.ActionResolution{}, EngagementRecord{}, err
	}
	authority.doc = next
	return resolution, record, nil
}

// engagementEligibleForReservation permits the normal fully-authorized path
// and one narrow pre-authorization path: a local Provider must reserve before
// signing the Offer, and a local represented buyer wallet must reserve before
// accepting it on chain. Those acts themselves satisfy the Paid-Demand
// predicates, so reserving only after complete authorization would be circular.
func engagementEligibleForReservation(record EngagementRecord, localAgentID string) bool {
	if record.NegotiationAmbiguous {
		return false
	}
	if record.State == EngagementAgreed {
		return true
	}
	if record.State != EngagementProposed && record.State != EngagementAuthorizing || record.ReservationID != "" {
		return false
	}
	localPaidDemandPredicate := false
	for _, predicate := range record.Agreement.Body.AuthorizationPredicates {
		subject := predicate.AuthoritySubject
		localSubject := subject.SubjectKind == "agent" && subject.SubjectIdentifier == localAgentID ||
			subject.SubjectKind == "wallet" && subject.RepresentedAgentID == localAgentID
		if localSubject && predicate.EvidenceProfileURI == commerce.EvidenceProfilePaidDemandQuote &&
			predicate.EvidenceProfileVersion == 1 && predicate.EvidenceProfileDigest == commerce.PaidDemandQuoteProfileDigest() {
			localPaidDemandPredicate = true
		}
	}
	return localPaidDemandPredicate
}

func (authority *PersonalAuthority) Engagement(agreementDigest string) (EngagementRecord, bool) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if authority.ensureStorageIdentityLocked() != nil {
		return EngagementRecord{}, false
	}
	record, found := authority.doc.Engagements[agreementDigest]
	return record, found
}

func (authority *PersonalAuthority) EngagementSnapshot() []EngagementRecord {
	if authority == nil {
		return nil
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if authority.ensureStorageIdentityLocked() != nil {
		return nil
	}
	result := make([]EngagementRecord, 0, len(authority.doc.Engagements))
	for _, record := range authority.doc.Engagements {
		result = append(result, record)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].AgreementDigest < result[j].AgreementDigest })
	return result
}

func (authority *PersonalAuthority) BindAcceptedPrivateInput(agreementDigest, obligationID string,
	accepted commerce.AcceptedPrivateContentRecord) (EngagementRecord, error) {
	if authority == nil || commerce.ValidateAcceptedPrivateContent(accepted) != nil {
		return EngagementRecord{}, errors.New("accepted private input is invalid")
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if err := authority.ensureStorageIdentityLocked(); err != nil {
		return EngagementRecord{}, err
	}
	record, found := authority.doc.Engagements[agreementDigest]
	if !found || accepted.ChallengeDigest == "" || accepted.UploadActionID == "" {
		return EngagementRecord{}, errors.New("accepted private input has no Agreement")
	}
	if record.State != EngagementReserved && record.State != EngagementFundingPending && record.State != EngagementReady {
		return EngagementRecord{}, errors.New("engagement is not accepting private input")
	}
	validObligation := false
	for _, obligation := range record.Agreement.Body.Obligations {
		if obligation.ObligationID == obligationID {
			for _, extension := range obligation.RequiredExtensions {
				validObligation = validObligation || extension == "tos.private-handoff.v1"
			}
		}
	}
	if !validObligation {
		return EngagementRecord{}, errors.New("Agreement obligation does not select private handoff")
	}
	for _, existing := range record.AcceptedPrivateInputs {
		if existing.ChallengeDigest == accepted.ChallengeDigest {
			if existing.UploadActionID == accepted.UploadActionID && existing.ContentManifestDigest == accepted.ContentManifestDigest {
				return record, nil
			}
			return EngagementRecord{}, errors.New("private handoff challenge conflicts with an accepted input")
		}
	}
	for _, existing := range record.BoundPrivateInputs {
		if existing.ObligationID == obligationID && existing.Record.ChallengeDigest == accepted.ChallengeDigest {
			if existing.Record.UploadActionID == accepted.UploadActionID && existing.Record.ContentManifestDigest == accepted.ContentManifestDigest {
				return record, nil
			}
			return EngagementRecord{}, errors.New("private handoff challenge conflicts with an obligation-bound input")
		}
	}
	record.AcceptedPrivateInputs = append(record.AcceptedPrivateInputs, accepted)
	sort.Slice(record.AcceptedPrivateInputs, func(i, j int) bool {
		return record.AcceptedPrivateInputs[i].ChallengeDigest < record.AcceptedPrivateInputs[j].ChallengeDigest
	})
	record.BoundPrivateInputs = append(record.BoundPrivateInputs, BoundAcceptedPrivateInput{ObligationID: obligationID, Record: accepted})
	sort.Slice(record.BoundPrivateInputs, func(i, j int) bool {
		left, right := record.BoundPrivateInputs[i], record.BoundPrivateInputs[j]
		return left.ObligationID+"\x00"+left.Record.ChallengeDigest < right.ObligationID+"\x00"+right.Record.ChallengeDigest
	})
	record.StateRevision++
	record.LastTransitionAtUnix = uint64(authority.now().UTC().Unix())
	next := cloneAuthorityDocument(authority.doc)
	next.Engagements[agreementDigest] = record
	if err := authority.persist(next); err != nil {
		return EngagementRecord{}, err
	}
	authority.doc = next
	return record, nil
}

func (authority *PersonalAuthority) RecordPrivateHandoffChallenge(agreementDigest, obligationID, challengeDigest,
	sendActionID string) (EngagementRecord, error) {
	if authority == nil || obligationID == "" || !canonicalSHA256(challengeDigest) || !canonicalSHA256(sendActionID) {
		return EngagementRecord{}, errors.New("private handoff challenge record is invalid")
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if err := authority.ensureStorageIdentityLocked(); err != nil {
		return EngagementRecord{}, err
	}
	record, found := authority.doc.Engagements[agreementDigest]
	if !found || record.State != EngagementReserved && record.State != EngagementFundingPending && record.State != EngagementReady {
		return EngagementRecord{}, errors.New("private handoff challenge has no active Agreement")
	}
	valid := false
	for _, obligation := range record.Agreement.Body.Obligations {
		if obligation.ObligationID == obligationID && obligation.BeneficiaryAgentID == authority.doc.AgentID &&
			containsString(obligation.RequiredExtensions, "tos.private-handoff.v1") {
			valid = true
		}
	}
	if !valid {
		return EngagementRecord{}, errors.New("private handoff challenge is outside the Agreement")
	}
	for _, existing := range record.PrivateHandoffChallenges {
		if existing.ObligationID == obligationID {
			if existing.ChallengeDigest == challengeDigest && existing.SendActionID == sendActionID {
				return record, nil
			}
			return EngagementRecord{}, errors.New("private handoff obligation already binds another challenge")
		}
	}
	record.PrivateHandoffChallenges = append(record.PrivateHandoffChallenges, BoundPrivateHandoffChallenge{
		ObligationID: obligationID, ChallengeDigest: challengeDigest, SendActionID: sendActionID})
	sort.Slice(record.PrivateHandoffChallenges, func(i, j int) bool {
		return record.PrivateHandoffChallenges[i].ObligationID < record.PrivateHandoffChallenges[j].ObligationID
	})
	record.StateRevision++
	record.LastTransitionAtUnix = uint64(authority.now().UTC().Unix())
	next := cloneAuthorityDocument(authority.doc)
	next.Engagements[agreementDigest] = record
	if err := authority.persist(next); err != nil {
		return EngagementRecord{}, err
	}
	authority.doc = next
	return record, nil
}

func (authority *PersonalAuthority) transitionEngagement(agreementDigest string, expected, nextState EngagementState,
	executionID string, evidence []string) (EngagementRecord, error) {
	if !allowedEngagementTransition(expected, nextState) {
		return EngagementRecord{}, errors.New("engagement lifecycle transition is not allowed")
	}
	evidence = append([]string(nil), evidence...)
	sort.Strings(evidence)
	for index, digest := range evidence {
		decoded, decodeErr := hex.DecodeString(strings.TrimPrefix(digest, "sha256:"))
		if len(digest) != 71 || digest[:7] != "sha256:" || decodeErr != nil || len(decoded) != 32 || index > 0 && evidence[index-1] == digest {
			return EngagementRecord{}, errors.New("engagement transition evidence is invalid")
		}
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if err := authority.ensureStorageIdentityLocked(); err != nil {
		return EngagementRecord{}, err
	}
	record, found := authority.doc.Engagements[agreementDigest]
	if !found || record.State != expected || executionID != "" && record.ExecutionID != "" && record.ExecutionID != executionID {
		return EngagementRecord{}, errors.New("engagement transition has no exact predecessor")
	}
	if executionID != "" {
		record.ExecutionID = executionID
	}
	switch nextState {
	case EngagementReady:
		record.FundingEvidence = evidence
	case EngagementExecutionSucceeded, EngagementFailed, EngagementAmbiguous:
		record.ExecutionEvidence = evidence
	case EngagementDelivered:
		record.DeliveryEvidence = evidence
	case EngagementSettled, EngagementUnpaid:
		record.SettlementEvidence = evidence
	}
	record.State = nextState
	record.StateRevision++
	record.LastTransitionAtUnix = uint64(authority.now().UTC().Unix())
	next := cloneAuthorityDocument(authority.doc)
	next.Engagements[agreementDigest] = record
	if err := authority.persist(next); err != nil {
		return EngagementRecord{}, err
	}
	authority.doc = next
	return record, nil
}

func allowedEngagementTransition(from, to EngagementState) bool {
	switch from {
	case EngagementReserved:
		return to == EngagementFundingPending || to == EngagementReady
	case EngagementFundingPending:
		return to == EngagementReady || to == EngagementAmbiguous || to == EngagementFailed
	case EngagementReady:
		return to == EngagementExecutionPrepared || to == EngagementCancelled
	case EngagementExecutionPrepared:
		return to == EngagementExecuting || to == EngagementAmbiguous || to == EngagementFailed
	case EngagementExecuting:
		return to == EngagementExecutionSucceeded || to == EngagementFailed || to == EngagementAmbiguous
	case EngagementExecutionSucceeded:
		return to == EngagementDelivered || to == EngagementFailed
	case EngagementDelivered:
		return to == EngagementSettling || to == EngagementSettled || to == EngagementUnpaid
	case EngagementSettling:
		return to == EngagementSettled || to == EngagementUnpaid || to == EngagementAmbiguous || to == EngagementFailed
	case EngagementCancellationResolving:
		return to == EngagementCancelled || to == EngagementSettled || to == EngagementUnpaid || to == EngagementAmbiguous
	default:
		return false
	}
}
