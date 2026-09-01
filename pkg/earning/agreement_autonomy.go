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

// BoundedAgreementAdmissionPolicy is the deterministic boundary after any AI
// negotiation proposal. It never infers unknown prices, extensions, evidence
// profiles, or settlement support. A model may recommend an Agreement, but
// only this owner policy can promote it to a signature request.
type BoundedAgreementAdmissionPolicy struct {
	LocalAgentID                 string
	MaximumOutgoingPaymentAtomic string
	AllowedRequiredExtensions    []string
	AllowedCounterparties        []string
	AllowedEvidenceProfiles      []string
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
	participant, counterpartyAllowed := false, len(policy.AllowedCounterparties) == 0
	for _, candidate := range record.Agreement.Body.Participants {
		if candidate.AgentID == policy.LocalAgentID {
			participant = true
			continue
		}
		if containsString(policy.AllowedCounterparties, candidate.AgentID) {
			counterpartyAllowed = true
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
			if obligation.Amount.AmountAtomic == "" {
				return AgreementAdmissionDecision{Reason: "outgoing decimal amount has no owner-pinned atomic conversion"}, nil
			}
			amount, ok := new(big.Int).SetString(obligation.Amount.AmountAtomic, 10)
			if !ok || amount.Sign() < 0 || amount.Cmp(maximum) > 0 {
				return AgreementAdmissionDecision{Reason: "outgoing payment exceeds owner policy"}, nil
			}
		}
	}
	return AgreementAdmissionDecision{Accept: true, Reason: "Agreement satisfies deterministic owner policy"}, nil
}

type WriterFenceProvider func(context.Context) (commerce.WriterFence, error)

type AgreementAutonomy struct {
	Coordinator AgreementCoordinator
	Engine      *Engine
	Inventory   InventorySource
	Policy      AgreementAdmissionPolicy
	IdentityKey ed25519.PrivateKey
	Verifier    commerce.AgreementEvidenceVerifier
	Fence       WriterFenceProvider
	Now         func() time.Time
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
		if record.State != EngagementProposed && record.State != EngagementAuthorizing {
			continue
		}
		if !uniqueUnforkedAgreementLeaf(record, records) {
			continue
		}
		if hasAgentEvidence(record, service.Engine.AgentID) {
			continue
		}
		if !hasLocalAgentSignaturePredicate(record, service.Engine.AgentID) {
			// Non-generic body-bound profiles are driven by their installed
			// Adapter (for Paid Demand: reserved Provider Offer or wallet accept),
			// never substituted with an Agent chat signature.
			continue
		}
		decision, evaluateErr := service.Policy.EvaluateAgreement(ctx, record, inventory, now)
		if evaluateErr != nil {
			return processed, evaluateErr
		}
		if !decision.Accept {
			continue
		}
		recipient := agreementCounterparty(record, service.Engine.AgentID)
		if recipient == "" {
			return processed, errors.New("Agreement has no direct counterparty")
		}
		fence, fenceErr := service.Fence(ctx)
		if fenceErr != nil {
			return processed, fenceErr
		}
		if _, _, authorizeErr := service.Engine.AuthorizeAgreement(ctx, record.AgreementDigest, recipient,
			service.IdentityKey, service.Verifier, inventory.PolicyRevision, fence); authorizeErr != nil {
			return processed, authorizeErr
		}
	}
	return processed, nil
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
