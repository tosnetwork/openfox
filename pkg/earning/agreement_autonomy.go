package earning

import (
	"context"
	"crypto/ed25519"
	"errors"
	"math/big"
	"sort"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

type AgreementAdmissionDecision struct {
	Accept bool
	Reason string
}

type AgreementAdmissionPolicy interface {
	EvaluateAgreement(context.Context, EngagementRecord, InventorySnapshot, time.Time) (AgreementAdmissionDecision, error)
}

// PortfolioSnapshotSource exposes the typed, owner-authoritative aggregate
// exposure state used by Agreement admission. Keeping this narrower than
// EconomicAuthority also lets policy evaluation remain read-only.
type PortfolioSnapshotSource interface {
	Snapshot() (uint64, PortfolioLimits, []ExposureReservation)
}

// BoundedAgreementAdmissionPolicy is the deterministic boundary after any AI
// negotiation proposal. It never infers unknown prices, extensions, evidence
// profiles, or settlement support. A model may recommend an Agreement, but
// only this owner policy can promote it to a signature request.
type BoundedAgreementAdmissionPolicy struct {
	LocalAgentID                 string
	MaximumOutgoingPaymentAtomic string
	// MaximumLossAtomic is the hard worst-case loss ceiling for one asset
	// bucket. When Portfolio is set, admission also includes every live
	// reservation in that same bucket and rejects stale Inventory revisions.
	// Empty disables only this explicit ceiling for legacy callers; a supplied
	// Portfolio remains authoritative.
	MaximumLossAtomic         string
	Portfolio                 PortfolioSnapshotSource
	AllowedRequiredExtensions []string
	AllowedCounterparties     []string
	AllowedEvidenceProfiles   []string
}

func (policy BoundedAgreementAdmissionPolicy) EvaluateAgreement(_ context.Context, record EngagementRecord,
	inventory InventorySnapshot, now time.Time) (AgreementAdmissionDecision, error) {
	if policy.LocalAgentID == "" || record.AgreementDigest == "" || commerce.ValidateAgreementBody(record.Agreement.Body) != nil ||
		inventory.AgentID != policy.LocalAgentID || inventory.Validate(now.UTC()) != nil {
		return AgreementAdmissionDecision{}, errors.New("Agreement admission lacks a valid body or fresh Inventory")
	}
	maximum, ok := new(big.Int).SetString(policy.MaximumOutgoingPaymentAtomic, 10)
	if !ok || maximum.Sign() < 0 {
		return AgreementAdmissionDecision{}, errors.New("Agreement outgoing-payment policy is invalid")
	}
	var maximumLoss *big.Int
	if policy.MaximumLossAtomic != "" {
		maximumLoss, ok = new(big.Int).SetString(policy.MaximumLossAtomic, 10)
		if !ok || maximumLoss.Sign() < 0 {
			return AgreementAdmissionDecision{}, errors.New("Agreement maximum-loss policy is invalid")
		}
	}
	participant, counterpartyAllowed := false, true
	for _, candidate := range record.Agreement.Body.Participants {
		if candidate.AgentID == policy.LocalAgentID {
			participant = true
			continue
		}
		if len(policy.AllowedCounterparties) != 0 &&
			!containsString(policy.AllowedCounterparties, candidate.AgentID) {
			counterpartyAllowed = false
		}
	}
	if !participant || !counterpartyAllowed {
		return AgreementAdmissionDecision{Reason: "participant or counterparty is outside owner policy"}, nil
	}
	for _, extension := range record.Agreement.Body.RequiredExtensions {
		if !containsString(policy.AllowedRequiredExtensions, extension) {
			return AgreementAdmissionDecision{Reason: "Agreement requires an unavailable extension"}, nil
		}
	}
	allowedProfiles := append([]string{commerce.EvidenceProfileAgentSignature}, policy.AllowedEvidenceProfiles...)
	localPredicate := false
	for _, predicate := range record.Agreement.Body.AuthorizationPredicates {
		subject := predicate.AuthoritySubject
		if subject.SubjectKind == "agent" && subject.SubjectIdentifier == policy.LocalAgentID || subject.RepresentedAgentID == policy.LocalAgentID {
			localPredicate = true
			if !containsString(allowedProfiles, predicate.EvidenceProfileURI) ||
				predicate.EvidenceProfileURI == commerce.EvidenceProfileAgentSignature && predicate.EvidenceProfileDigest != commerce.AgentSignatureProfileDigest() ||
				predicate.EvidenceProfileURI == commerce.EvidenceProfilePaidDemandQuote && predicate.EvidenceProfileDigest != commerce.PaidDemandQuoteProfileDigest() {
				return AgreementAdmissionDecision{Reason: "local authorization requires an unsupported evidence profile"}, nil
			}
		}
	}
	if !localPredicate {
		return AgreementAdmissionDecision{Reason: "Agreement has no body-bound local authorization predicate"}, nil
	}
	for _, obligation := range record.Agreement.Body.Obligations {
		for _, extension := range obligation.RequiredExtensions {
			if !containsString(policy.AllowedRequiredExtensions, extension) {
				return AgreementAdmissionDecision{Reason: "obligation requires an unavailable extension"}, nil
			}
		}
		if obligation.Amount == nil {
			continue
		}
		if !inventory.SupportsSettlement(obligation.SettlementAdapterURI) {
			return AgreementAdmissionDecision{Reason: "settlement Adapter is unavailable"}, nil
		}
		if obligation.ObligorAgentID == policy.LocalAgentID {
			if len(policy.AllowedCounterparties) != 0 &&
				!containsString(policy.AllowedCounterparties, obligation.BeneficiaryAgentID) {
				return AgreementAdmissionDecision{Reason: "outgoing payment beneficiary is outside owner policy"}, nil
			}
			boundedAmount := maximumAgreementObligationAmount(obligation)
			if boundedAmount.AmountAtomic == "" {
				return AgreementAdmissionDecision{Reason: "outgoing decimal amount has no owner-pinned atomic conversion"}, nil
			}
			amount, ok := new(big.Int).SetString(boundedAmount.AmountAtomic, 10)
			if !ok || amount.Sign() < 0 || amount.Cmp(maximum) > 0 {
				return AgreementAdmissionDecision{Reason: "outgoing payment exceeds owner policy"}, nil
			}
		}
	}
	exposure, exposureErr := localAgreementPaymentExposure(record.Agreement.Body, policy.LocalAgentID)
	if exposureErr != nil {
		return AgreementAdmissionDecision{Reason: exposureErr.Error()}, nil
	}
	if maximumLoss != nil && exposure.MaximumLoss.Cmp(maximumLoss) > 0 {
		return AgreementAdmissionDecision{Reason: "Agreement maximum loss exceeds owner policy"}, nil
	}
	if policy.Portfolio != nil {
		revision, limits, reservations := policy.Portfolio.Snapshot()
		if revision != inventory.PortfolioRevision {
			return AgreementAdmissionDecision{}, errors.New("Agreement admission Inventory has a stale Portfolio revision")
		}
		effectiveLimit := new(big.Int).SetUint64(limits.MaximumLossAtomic)
		if maximumLoss != nil {
			if !maximumLoss.IsUint64() || limits.MaximumLossAtomic > maximumLoss.Uint64() {
				return AgreementAdmissionDecision{}, errors.New("Portfolio maximum-loss authority exceeds owner policy")
			}
			if maximumLoss.Cmp(effectiveLimit) < 0 {
				effectiveLimit.Set(maximumLoss)
			}
		}
		alreadyHeld := false
		if record.ReservationID != "" {
			if !hasExactLiveAgreementPaymentReservation(record, policy.LocalAgentID, reservations) {
				return AgreementAdmissionDecision{}, errors.New("Agreement admission has an invalid pre-sign maximum-loss hold")
			}
			alreadyHeld = true
		}
		used := new(big.Int)
		for _, reservation := range reservations {
			if reservation.Released || !sameExposureAsset(reservation.Asset, exposure.Asset) {
				continue
			}
			used.Add(used, new(big.Int).SetUint64(reservation.MaximumLossAtomic))
		}
		if !alreadyHeld {
			used.Add(used, exposure.MaximumLoss)
		}
		if used.Cmp(effectiveLimit) > 0 {
			return AgreementAdmissionDecision{Reason: "Agreement maximum loss exceeds aggregate Portfolio limit"}, nil
		}
	}
	return AgreementAdmissionDecision{Accept: true, Reason: "Agreement satisfies deterministic owner policy"}, nil
}

type agreementPaymentExposure struct {
	Asset       *commerce.AssetIdentityV1
	MaximumLoss *big.Int
}

// localAgreementPaymentExposure computes the exact bounded amount that the
// local Agent can owe under the Agreement. Periodic/installment obligations
// use their body-bound maximum aggregate, never merely one installment.
// Multiple outgoing assets are rejected because one generic Portfolio
// reservation cannot safely add unlike atomic units.
func localAgreementPaymentExposure(body commerce.AgentAgreementBody, localAgentID string) (agreementPaymentExposure, error) {
	exposure := agreementPaymentExposure{MaximumLoss: new(big.Int)}
	for _, obligation := range body.Obligations {
		if obligation.Amount == nil || obligation.ObligorAgentID != localAgentID {
			continue
		}
		amount := maximumAgreementObligationAmount(obligation)
		if amount.AmountAtomic == "" {
			return agreementPaymentExposure{}, errors.New("outgoing decimal amount has no owner-pinned atomic conversion")
		}
		atomic, ok := new(big.Int).SetString(amount.AmountAtomic, 10)
		if !ok || atomic.Sign() < 0 {
			return agreementPaymentExposure{}, errors.New("outgoing payment has an invalid atomic amount")
		}
		asset := commerce.AssetIdentityV1{AssetNamespace: amount.AssetNamespace,
			AssetIdentifier: amount.AssetIdentifier, Unit: amount.Unit}
		if exposure.Asset == nil {
			copy := asset
			exposure.Asset = &copy
		} else if *exposure.Asset != asset {
			return agreementPaymentExposure{}, errors.New("Agreement has multiple incomparable outgoing assets")
		}
		exposure.MaximumLoss.Add(exposure.MaximumLoss, atomic)
	}
	return exposure, nil
}

func maximumAgreementObligationAmount(obligation commerce.AgreementObligation) commerce.AgreementAmount {
	if obligation.BillingTerms != nil {
		return obligation.BillingTerms.MaximumAggregateAmount
	}
	return *obligation.Amount
}

func sameExposureAsset(left, right *commerce.AssetIdentityV1) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

type WriterFenceProvider func(context.Context) (commerce.WriterFence, error)

type AgreementAutonomy struct {
	Coordinator AgreementCoordinator
	Engine      *Engine
	Inventory   InventorySource
	Policy      AgreementAdmissionPolicy
	// Planner and Prerequisite are required only when this Agent can incur an
	// outgoing Agreement loss. They materialize the complete Portfolio hold at
	// the authority linearization point before any local signature is created.
	Planner      EngagementPlanner
	Prerequisite SettlementPrerequisiteChecker
	IdentityKey  ed25519.PrivateKey
	Verifier     commerce.AgreementEvidenceVerifier
	Fence        WriterFenceProvider
	Now          func() time.Time
}

// Process drains at most max typed Agreement events and then evaluates all
// locally active proposals. This makes proposer and recipient recovery
// symmetric: a crash after an accepted send can resume from the local ledger,
// and an exact acceptance retry reuses the same semantic action.
func (service AgreementAutonomy) Process(ctx context.Context, max uint32) (uint32, error) {
	if service.Engine == nil || service.Engine.Authority == nil || service.Inventory == nil || service.Policy == nil ||
		len(service.IdentityKey) != ed25519.PrivateKeySize || service.Verifier == nil || service.Fence == nil || max == 0 || max > 1000 {
		return 0, errors.New("Agreement autonomy is incomplete or unbounded")
	}
	processed := uint32(0)
	for processed < max {
		handled, _, err := service.Coordinator.HandleNext(ctx)
		if err != nil {
			return processed, err
		}
		if !handled {
			break
		}
		processed++
	}
	now := time.Now().UTC()
	if service.Now != nil {
		now = service.Now().UTC()
	}
	inventory, err := service.Inventory.Snapshot(ctx)
	if err != nil {
		return processed, err
	}
	records := service.Engine.Authority.EngagementSnapshot()
	for _, record := range records {
		if record.State != EngagementProposed && record.State != EngagementAuthorizing &&
			record.State != EngagementAgreed && record.State != EngagementReserved {
			continue
		}
		if !uniqueUnforkedAgreementLeaf(record, records) {
			continue
		}
		retainedLocalEvidence := hasAgentEvidence(record, service.Engine.AgentID)
		if !hasLocalAgentSignaturePredicate(record, service.Engine.AgentID) {
			// Non-generic body-bound profiles are driven by their installed
			// Adapter (for Paid Demand: reserved Provider Offer or wallet accept),
			// never substituted with an Agent chat signature.
			continue
		}
		if !retainedLocalEvidence {
			decision, evaluateErr := service.Policy.EvaluateAgreement(ctx, record, inventory, now)
			if evaluateErr != nil {
				return processed, evaluateErr
			}
			if !decision.Accept {
				continue
			}
		}
		exposure, exposureErr := localAgreementPaymentExposure(record.Agreement.Body, service.Engine.AgentID)
		if exposureErr != nil {
			return processed, exposureErr
		}
		recipient := agreementCounterparty(record, service.Engine.AgentID)
		if recipient == "" {
			return processed, errors.New("Agreement has no direct counterparty")
		}
		fence, fenceErr := service.Fence(ctx)
		if fenceErr != nil {
			return processed, fenceErr
		}
		if exposure.MaximumLoss.Sign() > 0 {
			if record.ReservationID == "" {
				if service.Planner == nil || service.Prerequisite == nil {
					return processed, errors.New("buyer Agreement has no pre-sign Portfolio reservation path")
				}
				planned, planErr := service.Planner.PlanEngagement(ctx, record, inventory, fence)
				if planErr != nil {
					return processed, planErr
				}
				_, held, reserveErr := service.Engine.ReserveAgreement(ctx, record.AgreementDigest,
					planned.Reservation, service.Prerequisite, inventory.PolicyRevision, fence)
				if reserveErr != nil {
					return processed, reserveErr
				}
				record = held
			} else {
				_, _, reservations := service.Engine.Authority.Snapshot()
				if !hasExactLiveAgreementPaymentReservation(record, service.Engine.AgentID, reservations) {
					return processed, errors.New("buyer Agreement has no exact live pre-sign maximum-loss hold")
				}
			}
		}
		if _, _, authorizeErr := service.Engine.AuthorizeAgreement(ctx, record.AgreementDigest, recipient,
			service.IdentityKey, service.Verifier, inventory.PolicyRevision, fence); authorizeErr != nil {
			return processed, authorizeErr
		}
	}
	return processed, nil
}

// hasExactLiveAgreementPaymentReservation recognizes the durable retry case:
// the authority committed the hold and Engagement linkage, but the process
// stopped before it could persist or send local Agreement evidence. The hold
// must cover the exact same-asset maximum loss; unrelated, undersized, or
// released reservations never turn a retry into permission to sign.
func hasExactLiveAgreementPaymentReservation(record EngagementRecord, localAgentID string,
	reservations []ExposureReservation) bool {
	exposure, err := localAgreementPaymentExposure(record.Agreement.Body, localAgentID)
	if err != nil || exposure.Asset == nil || exposure.MaximumLoss.Sign() <= 0 ||
		!exposure.MaximumLoss.IsUint64() || record.ReservationID == "" {
		return false
	}
	wanted := exposure.MaximumLoss.Uint64()
	for _, reservation := range reservations {
		if reservation.ReservationID == record.ReservationID {
			return !reservation.Released && reservation.AgreementDigest == record.AgreementDigest &&
				sameExposureAsset(reservation.Asset, exposure.Asset) &&
				reservation.MaximumLossAtomic == wanted && reservation.SpendAtomic >= wanted
		}
	}
	return false
}

// uniqueUnforkedAgreementLeaf permits automatic authorization only when one
// exact body is the sole leaf of its Agreement-ID graph. A successor makes its
// predecessor stale, while concurrent roots or successor forks require an
// explicit local decision and therefore produce no signing side effect.
func uniqueUnforkedAgreementLeaf(candidate EngagementRecord, records []EngagementRecord) bool {
	agreementID := candidate.Agreement.Body.AgreementID
	if agreementID == "" || candidate.AgreementDigest == "" || candidate.NegotiationAmbiguous {
		return false
	}
	successors := make(map[string]bool)
	for _, record := range records {
		if record.Agreement.Body.AgreementID == agreementID && record.NegotiationAmbiguous {
			return false
		}
		if record.Agreement.Body.AgreementID == agreementID && record.Agreement.Body.PredecessorAgreementDigest != "" {
			successors[record.Agreement.Body.PredecessorAgreementDigest] = true
		}
	}
	leaves := 0
	uniqueDigest := ""
	for _, record := range records {
		if record.Agreement.Body.AgreementID != agreementID || successors[record.AgreementDigest] {
			continue
		}
		leaves++
		uniqueDigest = record.AgreementDigest
	}
	return leaves == 1 && uniqueDigest == candidate.AgreementDigest
}

func hasLocalAgentSignaturePredicate(record EngagementRecord, agentID string) bool {
	for _, predicate := range record.Agreement.Body.AuthorizationPredicates {
		if predicate.AuthoritySubject.SubjectKind == "agent" && predicate.AuthoritySubject.SubjectIdentifier == agentID &&
			predicate.EvidenceProfileURI == commerce.EvidenceProfileAgentSignature {
			return true
		}
	}
	return false
}

func hasAgentEvidence(record EngagementRecord, agentID string) bool {
	for _, evidence := range record.Agreement.AuthorizationEvidence {
		if evidence.AuthoritySubject.SubjectKind == "agent" && evidence.AuthoritySubject.SubjectIdentifier == agentID &&
			evidence.EvidenceProfileURI == commerce.EvidenceProfileAgentSignature {
			return true
		}
	}
	return false
}

func agreementCounterparty(record EngagementRecord, local string) string {
	var others []string
	for _, participant := range record.Agreement.Body.Participants {
		if participant.AgentID != local {
			others = append(others, participant.AgentID)
		}
	}
	sort.Strings(others)
	if len(others) == 1 {
		return others[0]
	}
	return ""
}

func containsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
