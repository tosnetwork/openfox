package earning

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
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
	detachedBody, err := cloneAgreementBody(body)
	if err != nil {
		return EngagementRecord{}, err
	}
	body = detachedBody
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
			return cloneEngagementRecord(existing)
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
	next.Engagements[digest] = detachedEngagementRecord(record)
	if err := authority.persist(next); err != nil {
		return EngagementRecord{}, err
	}
	authority.doc = next
	return cloneEngagementRecord(record)
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
		next.Engagements[key] = detachedEngagementRecord(record)
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
	record = detachedEngagementRecord(record)
	switch record.State {
	case EngagementProposed, EngagementAuthorizing:
		if record.ReservationID != "" {
			record.State = EngagementCancellationResolving
		} else {
			record.State = EngagementCancelled
		}
	case EngagementCancelled, EngagementFailed:
		return detachedEngagementRecord(record), nil
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
	next.Engagements[agreementDigest] = detachedEngagementRecord(record)
	if err := authority.persist(next); err != nil {
		return EngagementRecord{}, err
	}
	authority.doc = next
	return detachedEngagementRecord(record), nil
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
	record = detachedEngagementRecord(record)
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
			return detachedEngagementRecord(record), nil
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
	next.Engagements[agreementDigest] = detachedEngagementRecord(record)
	if err := authority.persist(next); err != nil {
		return EngagementRecord{}, err
	}
	authority.doc = next
	return detachedEngagementRecord(record), nil
}

func (authority *PersonalAuthority) RecordAgreementEvidence(agreementDigest string,
	evidence commerce.AgreementAuthorizationEvidence, verifier commerce.AgreementEvidenceVerifier) (EngagementRecord, error) {
	if authority == nil || verifier == nil {
		return EngagementRecord{}, errors.New("Agreement evidence verifier is unavailable")
	}
	detachedEvidence, err := cloneAgreementEvidence(evidence)
	if err != nil {
		return EngagementRecord{}, err
	}
	evidence = detachedEvidence
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if err := authority.ensureStorageIdentityLocked(); err != nil {
		return EngagementRecord{}, err
	}
	record, found := authority.doc.Engagements[agreementDigest]
	if !found || record.State == EngagementCancelled || record.State == EngagementFailed {
		return EngagementRecord{}, errors.New("Agreement evidence has no active proposal")
	}
	record = detachedEngagementRecord(record)
	if !exactRetainedAgreementBody(record) || record.AgreementDigest != agreementDigest {
		return EngagementRecord{}, errors.New("Agreement evidence targets a mutated retained body")
	}
	// Check the durable lineage marker before the exact-evidence replay path.
	// Otherwise a fork discovered after the first acceptance could turn a
	// replay into permission for another outbound authorization side effect.
	if record.NegotiationAmbiguous {
		return EngagementRecord{}, errors.New("Agreement evidence targets an ambiguous negotiation lineage")
	}
	if evidence.EvidenceProfileURI == commerce.EvidenceProfileAgentSignature &&
		evidence.AuthoritySubject.SubjectKind == "agent" &&
		evidence.AuthoritySubject.SubjectIdentifier == authority.doc.AgentID {
		exposure, exposureErr := localAgreementPaymentExposure(record.Agreement.Body, authority.doc.AgentID)
		reservation, reservationFound := authority.doc.Reservations[record.ReservationID]
		if exposureErr != nil || exposure.MaximumLoss.Sign() > 0 &&
			(!reservationFound || !reservationExactlyCoversAgreementPayment(reservation, record, exposure)) {
			return EngagementRecord{}, errors.New("local buyer Agreement signature has no exact live maximum-loss hold")
		}
	}
	evidenceDigest, err := codec.Digest("tos.agreement-authorization-evidence.v1", evidence)
	if err != nil {
		return EngagementRecord{}, err
	}
	for _, existing := range record.Agreement.AuthorizationEvidence {
		existingDigest, digestErr := codec.Digest("tos.agreement-authorization-evidence.v1", existing)
		if digestErr == nil && existingDigest == evidenceDigest {
			return cloneEngagementRecord(record)
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
	fullyAuthorizedDigest := ""
	if err := commerce.ValidateAgreementAuthorization(candidate, verifier, now); err == nil {
		state = EngagementAgreed
		if record.ReservationID != "" {
			state = EngagementReserved
		}
		candidateRecord := record
		candidateRecord.Agreement = candidate
		fullyAuthorizedDigest, err = retainedAgreementAuthorizationSetDigest(candidateRecord)
		if err != nil {
			return EngagementRecord{}, err
		}
	}
	next := cloneAuthorityDocument(authority.doc)
	record.Agreement, record.State = candidate, state
	record.FullyAuthorizedEvidenceSetDigest = fullyAuthorizedDigest
	record.StateRevision++
	record.LastTransitionAtUnix = uint64(now.Unix())
	next.Engagements[agreementDigest] = detachedEngagementRecord(record)
	if err := authority.persist(next); err != nil {
		return EngagementRecord{}, err
	}
	authority.doc = next
	return cloneEngagementRecord(record)
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
	if err := authority.expireIssuedCustodyLocked(); err != nil {
		return commerce.ActionResolution{}, EngagementRecord{}, err
	}
	request.Reservation = cloneExposureReservation(request.Reservation)
	record, found := authority.doc.Engagements[request.Reservation.AgreementDigest]
	if !found || !engagementEligibleForReservation(record, authority.doc.AgentID) || request.Reservation.Released ||
		request.TargetPortfolioRevision != authority.doc.PortfolioRevision+1 {
		return commerce.ActionResolution{}, EngagementRecord{}, errors.New("Agreement is not eligible for reservation")
	}
	record = detachedEngagementRecord(record)
	if !exactRetainedAgreementBody(record) {
		return commerce.ActionResolution{}, EngagementRecord{}, errors.New("Agreement reservation targets a mutated retained body")
	}
	if paidDemandBuyerCandidate(record, authority.doc.AgentID) {
		expected, expectedErr := paidDemandBuyerReservation(record, authority.doc.AgentID)
		if expectedErr != nil || !sameExposureReservation(request.Reservation, expected) {
			return commerce.ActionResolution{}, EngagementRecord{}, errors.New("Paid Demand buyer reservation does not exactly cover Agreement exposure")
		}
	}
	exposure, exposureErr := localAgreementPaymentExposure(record.Agreement.Body, authority.doc.AgentID)
	if exposureErr != nil || exposure.MaximumLoss.Sign() > 0 &&
		!reservationExactlyCoversAgreementPayment(request.Reservation, record, exposure) {
		return commerce.ActionResolution{}, EngagementRecord{}, errors.New("buyer reservation does not exactly cover Agreement maximum-loss exposure")
	}
	if exposure.MaximumLoss.Sign() > 0 && !paidDemandBuyerCandidate(record, authority.doc.AgentID) {
		for _, obligation := range record.Agreement.Body.Obligations {
			if obligation.Amount == nil || obligation.ObligorAgentID != authority.doc.AgentID {
				continue
			}
			if obligation.SettlementAdapterURI != agentrelay.DirectPaymentAdapterURI {
				continue
			}
			asset := commerce.AssetIdentityV1{AssetNamespace: obligation.Amount.AssetNamespace,
				AssetIdentifier: obligation.Amount.AssetIdentifier, Unit: obligation.Amount.Unit}
			if authority.doc.Limits.CustodyNativeAsset == nil || *authority.doc.Limits.CustodyNativeAsset != asset {
				return commerce.ActionResolution{}, EngagementRecord{}, errors.New("buyer Agreement uses an unpinned settlement Adapter asset")
			}
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
		cloned, cloneErr := cloneEngagementRecord(record)
		return prior, cloned, cloneErr
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
	record.ReservationActionID = action.StableActionID
	record.ReservationActionExactRequestDigest = action.ExactRequestDigest
	if record.State == EngagementAgreed {
		record.State = EngagementReserved
	} else {
		record.State = EngagementAuthorizing
	}
	record.StateRevision++
	record.LastTransitionAtUnix = uint64(authority.now().UTC().Unix())
	next.Engagements[record.AgreementDigest] = detachedEngagementRecord(record)
	if err := authority.persist(next); err != nil {
		return commerce.ActionResolution{}, EngagementRecord{}, err
	}
	authority.doc = next
	cloned, cloneErr := cloneEngagementRecord(record)
	return resolution, cloned, cloneErr
}

// CancelUnsignedReservation compensates a cross-authority prepare in which
// this authority committed its hold but the counterparty could not commit its
// own. Once a local signature or executable side effect exists, recovery must
// resume the exact Agreement and this path fails closed.
func (authority *PersonalAuthority) CancelUnsignedReservation(agreementDigest, reservationID string,
	fence commerce.WriterFence) error {
	if authority == nil || agreementDigest == "" || reservationID == "" {
		return errors.New("unsigned reservation cancellation is incomplete")
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if err := authority.ensureStorageIdentityLocked(); err != nil {
		return err
	}
	now := authority.now().UTC()
	if authority.doc.CurrentFence == nil || fence.Body.WriterGeneration != authority.doc.WriterGeneration ||
		fence.Body.LeaseID != authority.doc.CurrentFence.Body.LeaseID || !now.Before(time.Unix(int64(fence.Body.ExpiresAtUnix), 0)) {
		return errors.New("stale writer cannot cancel an unsigned reservation")
	}
	record, found := authority.doc.Engagements[agreementDigest]
	reservation, reservationFound := authority.doc.Reservations[reservationID]
	if !found || !reservationFound || record.ReservationID != reservationID ||
		reservation.AgreementDigest != agreementDigest {
		return errors.New("unsigned reservation cancellation has no exact Engagement hold")
	}
	record = detachedEngagementRecord(record)
	reservation = cloneExposureReservation(reservation)
	if record.State == EngagementCancelled && reservation.Released {
		return nil
	}
	exposure, exposureErr := localAgreementPaymentExposure(record.Agreement.Body, authority.doc.AgentID)
	if record.State != EngagementAuthorizing || paidDemandBuyerCandidate(record, authority.doc.AgentID) ||
		!hasLocalAgentSignaturePredicate(record, authority.doc.AgentID) || exposureErr != nil ||
		!reservationExactlyCoversAgreementPayment(reservation, record, exposure) ||
		reservation.Released || record.ExecutionID != "" || record.CustodyAuthorizationExpiredAtUnix != 0 ||
		record.ExpiredCustodyAuthorization != nil {
		return errors.New("reservation is no longer an unsigned cancellable prepare")
	}
	for _, evidence := range record.Agreement.AuthorizationEvidence {
		if evidenceSenderMatches(evidence.AuthoritySubject, authority.doc.AgentID) {
			return errors.New("locally signed Agreement reservation cannot be compensated")
		}
	}
	for _, issued := range authority.doc.IssuedCustodyPayments {
		if issued.ReservationID == reservationID {
			return ErrCustodyAuthorizationLive
		}
	}
	for _, ledger := range authority.doc.SettlementLedger {
		if ledger.Obligation.AgreementBodyDigest == agreementDigest {
			return errors.New("materialized Agreement reservation cannot be compensated")
		}
	}
	next := cloneAuthorityDocument(authority.doc)
	reservation.Released = true
	next.Reservations[reservationID] = reservation
	record.State = EngagementCancelled
	record.StateRevision++
	record.LastTransitionAtUnix = uint64(now.Unix())
	next.Engagements[agreementDigest] = detachedEngagementRecord(record)
	next.PortfolioRevision++
	if err := authority.persist(next); err != nil {
		return err
	}
	authority.doc = next
	return nil
}

// engagementEligibleForReservation permits the normal fully-authorized path
// and two narrow pre-authorization paths. A generic buyer must atomically hold
// maximum loss before its Agent signature, while a Paid-Demand Provider or
// represented wallet must reserve before the Offer/on-chain acceptance that
// itself satisfies the selected predicate. Reserving only after those acts
// would leave a TOCTOU window or be circular.
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
	localPaidDemandPredicate, localAgentSignaturePredicate := false, false
	for _, predicate := range record.Agreement.Body.AuthorizationPredicates {
		subject := predicate.AuthoritySubject
		localSubject := subject.SubjectKind == "agent" && subject.SubjectIdentifier == localAgentID ||
			subject.SubjectKind == "wallet" && subject.RepresentedAgentID == localAgentID
		if subject.SubjectKind == "agent" && subject.SubjectIdentifier == localAgentID &&
			predicate.EvidenceProfileURI == commerce.EvidenceProfileAgentSignature &&
			predicate.EvidenceProfileVersion == 1 && predicate.EvidenceProfileDigest == commerce.AgentSignatureProfileDigest() {
			localAgentSignaturePredicate = true
		}
		if localSubject && predicate.EvidenceProfileURI == commerce.EvidenceProfilePaidDemandQuote &&
			predicate.EvidenceProfileVersion == 1 && predicate.EvidenceProfileDigest == commerce.PaidDemandQuoteProfileDigest() {
			localPaidDemandPredicate = true
		}
	}
	return localPaidDemandPredicate || localAgentSignaturePredicate
}

func reservationExactlyCoversAgreementPayment(reservation ExposureReservation, record EngagementRecord,
	exposure agreementPaymentExposure) bool {
	return exposure.Asset != nil && exposure.MaximumLoss.Sign() > 0 && exposure.MaximumLoss.IsUint64() &&
		reservation.AgreementDigest == record.AgreementDigest && !reservation.Released &&
		sameExposureAsset(reservation.Asset, exposure.Asset) &&
		reservation.MaximumLossAtomic == exposure.MaximumLoss.Uint64() &&
		reservation.SpendAtomic >= exposure.MaximumLoss.Uint64()
}

func (authority *PersonalAuthority) Engagement(agreementDigest string) (EngagementRecord, bool) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if authority.ensureStorageIdentityLocked() != nil {
		return EngagementRecord{}, false
	}
	record, found := authority.doc.Engagements[agreementDigest]
	if !found {
		return EngagementRecord{}, false
	}
	cloned, err := cloneEngagementRecord(record)
	return cloned, err == nil
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
		cloned, err := cloneEngagementRecord(record)
		if err != nil {
			return nil
		}
		result = append(result, cloned)
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
	record = detachedEngagementRecord(record)
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
				return detachedEngagementRecord(record), nil
			}
			return EngagementRecord{}, errors.New("private handoff challenge conflicts with an accepted input")
		}
	}
	for _, existing := range record.BoundPrivateInputs {
		if existing.ObligationID == obligationID && existing.Record.ChallengeDigest == accepted.ChallengeDigest {
			if existing.Record.UploadActionID == accepted.UploadActionID && existing.Record.ContentManifestDigest == accepted.ContentManifestDigest {
				return detachedEngagementRecord(record), nil
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
	next.Engagements[agreementDigest] = detachedEngagementRecord(record)
	if err := authority.persist(next); err != nil {
		return EngagementRecord{}, err
	}
	authority.doc = next
	return detachedEngagementRecord(record), nil
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
	record = detachedEngagementRecord(record)
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
				return detachedEngagementRecord(record), nil
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
	next.Engagements[agreementDigest] = detachedEngagementRecord(record)
	if err := authority.persist(next); err != nil {
		return EngagementRecord{}, err
	}
	authority.doc = next
	return detachedEngagementRecord(record), nil
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
	record = detachedEngagementRecord(record)
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
	next.Engagements[agreementDigest] = detachedEngagementRecord(record)
	if err := authority.persist(next); err != nil {
		return EngagementRecord{}, err
	}
	authority.doc = next
	return detachedEngagementRecord(record), nil
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
