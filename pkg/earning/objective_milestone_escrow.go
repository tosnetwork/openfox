package earning

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
	"github.com/tosnetwork/tos-service-protocol/pkg/paiddemand"
)

// ObjectiveMilestoneEscrowPlan is an OpenFox-local composition of complete,
// independent Agreement/Quote/escrow lifecycles. Milestones are ordered by
// this slice. No plan field is sent on the protocol wire.
//
// ParentProjection is explicitly not an accepted Agreement and carries no
// portable or economic authority. It only uses the existing Agreement body
// shape as a deterministic local manifest: its attachments commit child body
// digests and its obligations map their order. Only each independently
// profile-authorized child Agreement and its existing Quote/escrow can move
// value. A caller must never display ParentProjection as accepted Agreement
// evidence or use it to satisfy a child authorization predicate.
type ObjectiveMilestoneEscrowPlan struct {
	ParentProjection             commerce.AgentAgreementBody
	ExpectedAsset                commerce.AssetIdentityV1
	ExpectedSettlementParameters []byte
	MaximumCurrentExposureAtomic uint64
	Milestones                   []ObjectiveMilestoneEscrow
}

// ObjectiveMilestoneEscrow maps one non-authoritative local projection
// obligation to one fixed-price Paid Demand child Agreement. ChildAgreement
// remains an ordinary V1 Agreement with one payment and one objective work
// obligation.
type ObjectiveMilestoneEscrow struct {
	ProjectionObligationID string
	ChildAgreement         commerce.AgentAgreementBody
}

// ObjectiveMilestoneFundingState is the read-only authority projection needed
// to admit the next child. Both personal and shared economic authorities
// already expose these methods.
type ObjectiveMilestoneFundingState interface {
	Engagement(string) (EngagementRecord, bool)
	SettlementSnapshot(string) []SettlementLedgerRecord
	Snapshot() (uint64, PortfolioLimits, []ExposureReservation)
}

// ObjectiveMilestoneFinalizedEvidenceRequest is the exact scope a resolver
// must reconstruct from the retained Paid Demand package and finalized chain
// state. A resolver returns found=false while that evidence is unavailable or
// inconclusive; it must never promote the local settlement ledger itself into
// escrow or stablecoin finality.
type ObjectiveMilestoneFinalizedEvidenceRequest struct {
	NetworkContext       string
	AgreementBodyDigest  string
	PaymentObligationID  string
	WorkObligationID     string
	PayerAgentID         string
	PayeeAgentID         string
	SettlementAdapterURI string
	Asset                commerce.AssetIdentityV1
	AmountAtomic         string
}

// ObjectiveMilestoneFinalizedEvidence is a resolver-qualified observation of
// one existing Paid Demand escrow's objective release and exact finalized
// Provider stablecoin credit. Every identity is retained so admission can
// reject sibling substitution and evidence reuse.
type ObjectiveMilestoneFinalizedEvidence struct {
	NetworkContext          string
	AgreementBodyDigest     string
	PaymentObligationID     string
	WorkObligationID        string
	PayerAgentID            string
	PayeeAgentID            string
	SettlementAdapterURI    string
	Asset                   commerce.AssetIdentityV1
	AmountAtomic            string
	EvidenceProfileURI      string
	ResolutionState         string
	QuoteCommitment         string
	EscrowAddress           string
	ProviderWalletAddress   string
	ReceiptCommitment       string
	PaymentRequestDigest    string
	PaymentStableActionID   string
	PaymentEvidenceDigest   string
	DeliveryEvidenceDigests []string
	ExactTransferReference  string
	FinalityReference       string
	ResolvedAtUnix          uint64
}

// ObjectiveMilestoneFinalizedEvidenceResolver is intentionally injectable:
// OpenFox currently has no released buyer-side resolver that can safely create
// this projection. Until such a resolver is installed, milestone zero may be
// funded but every successor remains Deferred. Provider-local state or a
// counterparty message is not an implementation of this interface.
type ObjectiveMilestoneFinalizedEvidenceResolver interface {
	ResolveFinalizedObjectiveMilestone(context.Context, ObjectiveMilestoneFinalizedEvidenceRequest) (
		ObjectiveMilestoneFinalizedEvidence, bool, error)
}

// ObjectiveMilestoneFundingAdmission releases no money and changes no state.
// It only permits selection of the exact next child after every predecessor is
// durably settled and its Portfolio reservation has been released.
type ObjectiveMilestoneFundingAdmission struct {
	Authority         ObjectiveMilestoneFundingState
	FinalizedEvidence ObjectiveMilestoneFinalizedEvidenceResolver
	Plan              ObjectiveMilestoneEscrowPlan
}

type validatedObjectiveMilestone struct {
	projection    commerce.AgreementObligation
	child         commerce.AgentAgreementBody
	childDigest   string
	payment       commerce.AgreementObligation
	work          commerce.AgreementObligation
	amountAtomic  uint64
	assetIdentity commerce.AssetIdentityV1
}

// ValidateObjectiveMilestoneEscrowPlan rejects partial or implicit mappings.
// In particular, a projection-level attachment set without the per-obligation
// child binding is insufficient because it would allow siblings to be swapped.
func ValidateObjectiveMilestoneEscrowPlan(plan ObjectiveMilestoneEscrowPlan) error {
	_, err := validateObjectiveMilestoneEscrowPlan(plan)
	return err
}

func validateObjectiveMilestoneEscrowPlan(plan ObjectiveMilestoneEscrowPlan) ([]validatedObjectiveMilestone, error) {
	if err := commerce.ValidateAgreementBody(plan.ParentProjection); err != nil {
		return nil, fmt.Errorf("objective milestone local parent projection is invalid: %w", err)
	}
	if commerce.ValidateAssetIdentityV1(plan.ExpectedAsset) != nil || len(plan.ExpectedSettlementParameters) == 0 ||
		plan.MaximumCurrentExposureAtomic == 0 {
		return nil, errors.New("objective milestone asset, settlement-parameter, or current-exposure pin is invalid")
	}
	if len(plan.Milestones) < 2 || len(plan.Milestones) > commerce.MaxAgreementObligations ||
		len(plan.ParentProjection.Obligations) != len(plan.Milestones) || len(plan.ParentProjection.Participants) != 2 {
		return nil, errors.New("objective milestone plan must map every local projection obligation to an ordered child")
	}
	if len(plan.ParentProjection.RequiredExtensions) != 0 || len(plan.ParentProjection.OptionalExtensions) != 0 {
		return nil, errors.New("objective milestone local parent projection cannot carry extension semantics")
	}
	for _, predicate := range plan.ParentProjection.AuthorizationPredicates {
		if len(predicate.RequiredExtensions) != 0 || len(predicate.OptionalExtensions) != 0 {
			return nil, errors.New("objective milestone local parent projection predicate cannot carry extension semantics")
		}
	}

	projectionByID := make(map[string]commerce.AgreementObligation, len(plan.ParentProjection.Obligations))
	for _, obligation := range plan.ParentProjection.Obligations {
		projectionByID[obligation.ObligationID] = obligation
	}
	seenProjection := make(map[string]bool, len(plan.Milestones))
	seenAgreementID := make(map[string]bool, len(plan.Milestones))
	seenDigest := make(map[string]bool, len(plan.Milestones))
	wantAttachments := make([]string, 0, len(plan.Milestones))
	validated := make([]validatedObjectiveMilestone, 0, len(plan.Milestones))
	buyerAgentID, providerAgentID := "", ""

	for index, milestone := range plan.Milestones {
		projection, found := projectionByID[milestone.ProjectionObligationID]
		if !found || seenProjection[milestone.ProjectionObligationID] {
			return nil, errors.New("objective milestone local projection obligation mapping is absent or duplicated")
		}
		seenProjection[milestone.ProjectionObligationID] = true
		if err := commerce.ValidateAgreementBody(milestone.ChildAgreement); err != nil {
			return nil, fmt.Errorf("objective milestone child Agreement is invalid: %w", err)
		}
		if milestone.ChildAgreement.AgreementID == plan.ParentProjection.AgreementID {
			return nil, errors.New("objective milestone child must be independent from the local parent projection")
		}
		if milestone.ChildAgreement.NetworkContext != plan.ParentProjection.NetworkContext ||
			milestone.ChildAgreement.ValidFromUnix < plan.ParentProjection.ValidFromUnix ||
			milestone.ChildAgreement.ExpiresAtUnix > plan.ParentProjection.ExpiresAtUnix {
			return nil, errors.New("objective milestone child changes the local projection network or time envelope")
		}
		childDigest, err := commerce.AgreementBodyDigest(milestone.ChildAgreement)
		if err != nil {
			return nil, err
		}
		if seenAgreementID[milestone.ChildAgreement.AgreementID] || seenDigest[childDigest] {
			return nil, errors.New("objective milestone children are not independent and unique")
		}
		seenAgreementID[milestone.ChildAgreement.AgreementID] = true
		seenDigest[childDigest] = true
		wantAttachments = append(wantAttachments, childDigest)

		payment, work, err := objectiveMilestoneChildObligations(milestone.ChildAgreement)
		if err != nil {
			return nil, err
		}
		if err := objectiveMilestonePinnedChildProfile(milestone.ChildAgreement, payment, work); err != nil {
			return nil, err
		}
		if !bytes.Equal(payment.SettlementParameters, plan.ExpectedSettlementParameters) {
			return nil, errors.New("objective milestone child changes the pinned current Paid Demand settlement parameters")
		}
		if index == 0 {
			buyerAgentID, providerAgentID = payment.ObligorAgentID, payment.BeneficiaryAgentID
		}
		if buyerAgentID == providerAgentID || payment.ObligorAgentID != buyerAgentID ||
			payment.BeneficiaryAgentID != providerAgentID ||
			len(milestone.ChildAgreement.Participants) != 2 ||
			!objectiveMilestoneHasParticipant(milestone.ChildAgreement, payment.ObligorAgentID, "buyer") ||
			!objectiveMilestoneHasParticipant(milestone.ChildAgreement, payment.BeneficiaryAgentID, "provider") ||
			!objectiveMilestoneHasParticipant(plan.ParentProjection, buyerAgentID, "buyer") ||
			!objectiveMilestoneHasParticipant(plan.ParentProjection, providerAgentID, "provider") ||
			projection.ObligorAgentID != providerAgentID || projection.BeneficiaryAgentID != buyerAgentID ||
			work.ObligorAgentID != providerAgentID || work.BeneficiaryAgentID != buyerAgentID {
			return nil, errors.New("objective milestone child participants differ from the local projection milestone")
		}
		if projection.Amount != nil || projection.BillingTerms != nil || projection.SettlementAdapterURI != "" ||
			len(projection.SettlementParameters) != 0 || projection.DisputePolicy != "objective" ||
			len(projection.AcceptanceEvidenceRequirements) != 0 || len(projection.RequiredExtensions) != 0 ||
			len(projection.OptionalExtensions) != 0 {
			return nil, errors.New("objective milestone local parent projection must remain non-value and non-authoritative")
		}
		if projection.SubjectContentType != work.SubjectContentType || !bytes.Equal(projection.Subject, work.Subject) {
			return nil, errors.New("objective milestone child work subject differs from the local projection milestone")
		}
		if len(projection.AttachmentDigests) != 1 || projection.AttachmentDigests[0] != childDigest {
			return nil, errors.New("objective milestone local projection obligation does not bind its exact child digest")
		}
		if index == 0 && len(projection.DependsOnObligationIDs) != 0 || index > 0 &&
			(len(projection.DependsOnObligationIDs) != 1 || projection.DependsOnObligationIDs[0] != plan.Milestones[index-1].ProjectionObligationID) {
			return nil, errors.New("objective milestone projection dependency order differs from the local plan")
		}
		amountAtomic, err := strconv.ParseUint(payment.Amount.AmountAtomic, 10, 64)
		if err != nil || amountAtomic == 0 {
			return nil, errors.New("objective milestone payment is not a positive uint64 atomic amount")
		}
		asset := commerce.AssetIdentityV1{AssetNamespace: payment.Amount.AssetNamespace,
			AssetIdentifier: payment.Amount.AssetIdentifier, Unit: payment.Amount.Unit}
		if commerce.ValidateAssetIdentityV1(asset) != nil {
			return nil, errors.New("objective milestone payment asset is invalid")
		}
		if asset != plan.ExpectedAsset || amountAtomic > plan.MaximumCurrentExposureAtomic {
			return nil, errors.New("objective milestone payment differs from the pinned asset or exceeds the current-exposure cap")
		}
		validated = append(validated, validatedObjectiveMilestone{projection: projection, child: milestone.ChildAgreement,
			childDigest: childDigest, payment: payment, work: work, amountAtomic: amountAtomic, assetIdentity: asset})
	}

	sort.Strings(wantAttachments)
	if !sameOrderedStrings(plan.ParentProjection.AttachmentDigests, wantAttachments) {
		return nil, errors.New("objective milestone local projection attachments do not exactly commit the child Agreement bodies")
	}
	return validated, nil
}

func objectiveMilestoneChildObligations(body commerce.AgentAgreementBody) (commerce.AgreementObligation,
	commerce.AgreementObligation, error) {
	if len(body.Obligations) != 2 {
		return commerce.AgreementObligation{}, commerce.AgreementObligation{},
			errors.New("objective milestone child must contain exactly one payment and one work obligation")
	}
	var payment, work commerce.AgreementObligation
	paymentCount, workCount := 0, 0
	for _, obligation := range body.Obligations {
		switch {
		case obligation.Amount != nil && obligation.Kind == "payment" &&
			obligation.SettlementAdapterURI == paiddemand.SettlementAdapterURI:
			payment, paymentCount = obligation, paymentCount+1
		case obligation.Amount == nil && (obligation.Kind == "work" || obligation.Kind == "fulfillment") &&
			obligation.DisputePolicy == "objective":
			work, workCount = obligation, workCount+1
		}
	}
	if paymentCount != 1 || workCount != 1 || payment.BillingTerms != nil || payment.DisputePolicy != "objective" ||
		payment.Amount.AmountAtomic == "" || payment.Amount.AmountDecimal != "" ||
		len(payment.DependsOnObligationIDs) != 1 || payment.DependsOnObligationIDs[0] != work.ObligationID ||
		len(work.DependsOnObligationIDs) != 0 {
		return commerce.AgreementObligation{}, commerce.AgreementObligation{},
			errors.New("objective milestone child is not one fixed-price Paid Demand payment over one objective work")
	}
	return payment, work, nil
}

func objectiveMilestonePinnedChildProfile(body commerce.AgentAgreementBody, payment,
	work commerce.AgreementObligation) error {
	if len(body.RequiredExtensions) != 0 || len(body.OptionalExtensions) != 0 ||
		payment.Kind != "payment" || work.Kind != "fulfillment" ||
		payment.CancellationPolicy != "chain-profile" || work.CancellationPolicy != "chain-profile" ||
		payment.ConfidentialityPolicy != "participants" || work.ConfidentialityPolicy != "participants" ||
		len(payment.AcceptanceEvidenceRequirements) != 0 || len(work.AcceptanceEvidenceRequirements) != 0 ||
		len(payment.AttachmentDigests) != 0 || len(payment.RequiredExtensions) != 0 ||
		len(payment.OptionalExtensions) != 0 || len(work.OptionalExtensions) != 0 ||
		len(payment.SettlementParameters) == 0 || work.BillingTerms != nil || work.SettlementAdapterURI != "" ||
		len(work.SettlementParameters) != 0 || !objectiveMilestonePinnedExecutionBindings(work) {
		return errors.New("objective milestone child changes the current fixed-price Paid Demand obligation profile")
	}
	if len(body.AuthorizationPredicates) != 2 || len(payment.AuthorizationPredicateIDs) != 1 ||
		len(work.AuthorizationPredicateIDs) != 1 {
		return errors.New("objective milestone child must use one exact buyer and Provider Paid Demand predicate")
	}
	predicates := make(map[string]commerce.AgreementAuthorizationPredicate, len(body.AuthorizationPredicates))
	for _, predicate := range body.AuthorizationPredicates {
		if predicate.EvidenceProfileURI != commerce.EvidenceProfilePaidDemandQuote ||
			predicate.EvidenceProfileVersion != 1 || predicate.EvidenceProfileDigest != commerce.PaidDemandQuoteProfileDigest() ||
			len(predicate.RequiredExtensions) != 0 || len(predicate.OptionalExtensions) != 0 {
			return errors.New("objective milestone child authorization changes the current Paid Demand evidence profile")
		}
		predicates[predicate.PredicateID] = predicate
	}
	buyer, buyerFound := predicates[payment.AuthorizationPredicateIDs[0]]
	provider, providerFound := predicates[work.AuthorizationPredicateIDs[0]]
	if !buyerFound || !providerFound || buyer.PredicateID == provider.PredicateID ||
		buyer.AuthoritySubject.SubjectKind != "wallet" || buyer.AuthoritySubject.SubjectNamespace != "tos.wallet" ||
		buyer.AuthoritySubject.SubjectIdentifier == "" || buyer.AuthoritySubject.RepresentedAgentID != payment.ObligorAgentID ||
		!sameOrderedStrings(buyer.RoleScope, []string{"buyer"}) ||
		!sameOrderedStrings(buyer.ObligationIDs, []string{payment.ObligationID}) ||
		provider.AuthoritySubject.SubjectKind != "agent" || provider.AuthoritySubject.SubjectNamespace != "tos.agent" ||
		provider.AuthoritySubject.SubjectIdentifier != work.ObligorAgentID ||
		provider.AuthoritySubject.RepresentedAgentID != "" ||
		!sameOrderedStrings(provider.RoleScope, []string{"provider"}) ||
		!sameOrderedStrings(provider.ObligationIDs, []string{work.ObligationID}) {
		return errors.New("objective milestone child changes the exact buyer-wallet or Provider authorization scope")
	}
	return nil
}

func objectiveMilestonePinnedExecutionBindings(work commerce.AgreementObligation) bool {
	if len(work.RequiredExtensions) != 2 || len(work.AttachmentDigests) != 2 {
		return false
	}
	wantAttachments := make([]string, 0, 2)
	input, source := false, false
	for _, extension := range work.RequiredExtensions {
		var digest string
		switch {
		case strings.HasPrefix(extension, "tos.input.") && !input:
			input = true
			digest = "sha256:" + strings.TrimPrefix(extension, "tos.input.")
		case strings.HasPrefix(extension, "tos.source.") && !source:
			source = true
			digest = "sha256:" + strings.TrimPrefix(extension, "tos.source.")
		default:
			return false
		}
		if !canonicalSHA256(digest) {
			return false
		}
		wantAttachments = append(wantAttachments, digest)
	}
	sort.Strings(wantAttachments)
	return input && source && sameOrderedStrings(work.AttachmentDigests, wantAttachments)
}

func objectiveMilestoneHasParticipant(body commerce.AgentAgreementBody, agentID, role string) bool {
	for _, participant := range body.Participants {
		if participant.AgentID != agentID {
			continue
		}
		for _, candidate := range participant.Roles {
			if candidate == role {
				return true
			}
		}
	}
	return false
}

// DecidePaidDemandFunding implements PaidDemandFundingAdmission. A child from
// another plan is NotApplicable; a child waiting for predecessor finality or
// reservation release is Deferred; malformed or contradictory authority state
// is an error.
func (admission ObjectiveMilestoneFundingAdmission) DecidePaidDemandFunding(ctx context.Context,
	record EngagementRecord) (PaidDemandFundingAdmissionDecision, error) {
	if ctx == nil || admission.Authority == nil {
		return PaidDemandFundingAdmissionDecision{}, errors.New("objective milestone funding admission is incomplete")
	}
	if err := ctx.Err(); err != nil {
		return PaidDemandFundingAdmissionDecision{}, fmt.Errorf("objective milestone funding admission context: %w", err)
	}
	milestones, err := validateObjectiveMilestoneEscrowPlan(admission.Plan)
	if err != nil {
		return PaidDemandFundingAdmissionDecision{}, err
	}
	recordDigest, err := commerce.AgreementBodyDigest(record.Agreement.Body)
	if err != nil || record.AgreementDigest != recordDigest {
		return PaidDemandFundingAdmissionDecision{}, errors.New("objective milestone funding candidate has an invalid Agreement identity")
	}
	selected := -1
	for index := range milestones {
		if milestones[index].childDigest == recordDigest {
			selected = index
			break
		}
	}
	if selected < 0 {
		return PaidDemandFundingAdmissionDecision{Disposition: PaidDemandFundingNotApplicable}, nil
	}
	current, found := admission.Authority.Engagement(recordDigest)
	if !found || current.AgreementDigest != recordDigest {
		return PaidDemandFundingAdmissionDecision{}, errors.New("objective milestone funding candidate is absent from economic authority")
	}
	currentDigest, digestErr := commerce.AgreementBodyDigest(current.Agreement.Body)
	if digestErr != nil || currentDigest != recordDigest || !paidDemandBuyerCandidate(current,
		milestones[selected].payment.ObligorAgentID) {
		return PaidDemandFundingAdmissionDecision{}, errors.New("objective milestone funding candidate is not an exact fundable child")
	}

	_, limits, reservations := admission.Authority.Snapshot()
	if limits.MaximumLossAtomic > admission.Plan.MaximumCurrentExposureAtomic {
		return PaidDemandFundingAdmissionDecision{}, errors.New("economic authority maximum-loss limit exceeds the objective milestone exposure pin")
	}
	childIndex := make(map[string]int, len(milestones))
	for index := range milestones {
		childIndex[milestones[index].childDigest] = index
	}
	for _, reservation := range reservations {
		index, inPlan := childIndex[reservation.AgreementDigest]
		if inPlan && !reservation.Released && index != selected {
			if index < selected {
				return PaidDemandFundingAdmissionDecision{Disposition: PaidDemandFundingDeferred}, nil
			}
			return PaidDemandFundingAdmissionDecision{}, errors.New("a later objective milestone child retains an out-of-order funding reservation")
		}
	}
	if current.ReservationID != "" && !objectiveMilestoneLiveReservationExact(current, milestones[selected], reservations) {
		return PaidDemandFundingAdmissionDecision{}, errors.New("objective milestone child has no exact live funding reservation")
	}

	usedEvidence := make(map[string]string)
	for index := 0; index < selected; index++ {
		predecessor, predecessorFound := admission.Authority.Engagement(milestones[index].childDigest)
		if !predecessorFound {
			return PaidDemandFundingAdmissionDecision{Disposition: PaidDemandFundingDeferred}, nil
		}
		switch predecessor.State {
		case EngagementSettled:
		case EngagementCancelled, EngagementFailed, EngagementUnpaid:
			return PaidDemandFundingAdmissionDecision{}, errors.New("objective milestone predecessor ended without a qualified release")
		default:
			return PaidDemandFundingAdmissionDecision{Disposition: PaidDemandFundingDeferred}, nil
		}
		evidence, ready, evidenceErr := objectiveMilestoneTerminalSettlementExact(ctx, admission.Authority,
			admission.FinalizedEvidence, predecessor, milestones[index], reservations)
		if evidenceErr != nil {
			return PaidDemandFundingAdmissionDecision{}, evidenceErr
		}
		if !ready {
			return PaidDemandFundingAdmissionDecision{Disposition: PaidDemandFundingDeferred}, nil
		}
		if uniqueErr := retainUniqueObjectiveMilestoneEvidence(usedEvidence, milestones[index].childDigest, evidence); uniqueErr != nil {
			return PaidDemandFundingAdmissionDecision{}, uniqueErr
		}
	}
	for index := selected + 1; index < len(milestones); index++ {
		future, futureFound := admission.Authority.Engagement(milestones[index].childDigest)
		if futureFound && future.State != EngagementProposed && future.State != EngagementAuthorizing {
			return PaidDemandFundingAdmissionDecision{}, errors.New("a later objective milestone child was advanced out of order")
		}
	}
	return PaidDemandFundingAdmissionDecision{Disposition: PaidDemandFundingAdmitted}, nil
}

func objectiveMilestoneLiveReservationExact(record EngagementRecord, milestone validatedObjectiveMilestone,
	reservations []ExposureReservation) bool {
	for _, reservation := range reservations {
		if reservation.ReservationID == record.ReservationID && reservation.AgreementDigest == milestone.childDigest &&
			!reservation.Released && reservation.Asset != nil && *reservation.Asset == milestone.assetIdentity &&
			reservation.SpendAtomic == milestone.amountAtomic && reservation.LockedCapitalAtomic == milestone.amountAtomic &&
			reservation.MaximumLossAtomic == milestone.amountAtomic {
			return true
		}
	}
	return false
}

func objectiveMilestoneTerminalSettlementExact(ctx context.Context, authority ObjectiveMilestoneFundingState,
	resolver ObjectiveMilestoneFinalizedEvidenceResolver, record EngagementRecord,
	milestone validatedObjectiveMilestone, reservations []ExposureReservation) (
	ObjectiveMilestoneFinalizedEvidence, bool, error) {
	recordDigest, err := commerce.AgreementBodyDigest(record.Agreement.Body)
	if err != nil || recordDigest != milestone.childDigest || record.AgreementDigest != milestone.childDigest ||
		record.State != EngagementSettled || record.ReservationID == "" || len(record.ObligationRuntime) != 2 {
		return ObjectiveMilestoneFinalizedEvidence{}, false,
			errors.New("objective milestone predecessor has a malformed terminal Agreement projection")
	}
	reservationReleased := false
	for _, reservation := range reservations {
		if reservation.ReservationID == record.ReservationID && reservation.AgreementDigest == milestone.childDigest &&
			reservation.Released && reservation.Asset != nil && *reservation.Asset == milestone.assetIdentity &&
			reservation.SpendAtomic == milestone.amountAtomic && reservation.LockedCapitalAtomic == milestone.amountAtomic &&
			reservation.MaximumLossAtomic == milestone.amountAtomic {
			reservationReleased = true
			break
		}
	}
	if !reservationReleased {
		return ObjectiveMilestoneFinalizedEvidence{}, false, nil
	}
	paymentRuntime, paymentFound := record.ObligationRuntime[milestone.payment.ObligationID]
	workRuntime, workFound := record.ObligationRuntime[milestone.work.ObligationID]
	if !paymentFound || !workFound || paymentRuntime.ObligationID != milestone.payment.ObligationID ||
		workRuntime.ObligationID != milestone.work.ObligationID || paymentRuntime.State != ObligationSettled ||
		workRuntime.State != ObligationDelivered || len(workRuntime.DeliveryEvidence) == 0 {
		return ObjectiveMilestoneFinalizedEvidence{}, false,
			errors.New("objective milestone predecessor has a malformed obligation projection")
	}
	ledgers := authority.SettlementSnapshot(milestone.childDigest)
	if len(ledgers) != 1 {
		return ObjectiveMilestoneFinalizedEvidence{}, false,
			errors.New("objective milestone predecessor does not have one exact settlement obligation")
	}
	ledger := ledgers[0]
	parameterDigest, parameterErr := codec.Digest("tos.settlement-adapter-parameters.v1", milestone.payment.SettlementParameters)
	instanceDigest, instanceErr := codec.Digest("tos.settlement-obligation-instance.v1", struct {
		AgreementBodyDigest   string `json:"agreement_body_digest"`
		AgreementObligationID string `json:"agreement_obligation_id"`
		Sequence              uint64 `json:"sequence"`
		PredecessorInstanceID string `json:"predecessor_instance_id,omitempty"`
	}{milestone.childDigest, milestone.payment.ObligationID, 1, ""})
	stateObligationDigest, stateDigestErr := codec.Digest("tos.settlement-obligation.v1", ledger.Obligation)
	wantZero := *milestone.payment.Amount
	wantZero.AmountAtomic = "0"
	wantZero.AmountDecimal = ""
	if parameterErr != nil || instanceErr != nil || stateDigestErr != nil ||
		commerce.ValidateSettlementObligation(ledger.Obligation) != nil || commerce.ValidateSettlementState(ledger.State) != nil ||
		ledger.Obligation.AgreementBodyDigest != milestone.childDigest ||
		ledger.Obligation.AgreementObligationID != milestone.payment.ObligationID || ledger.Obligation.Sequence != 1 ||
		ledger.Obligation.ObligationInstanceID != instanceDigest || ledger.Obligation.PredecessorInstanceID != "" ||
		ledger.Obligation.PayerAgentID != milestone.payment.ObligorAgentID ||
		ledger.Obligation.PayeeAgentID != milestone.payment.BeneficiaryAgentID ||
		ledger.Obligation.Amount != *milestone.payment.Amount || ledger.Obligation.MaximumAggregateAmount != *milestone.payment.Amount ||
		ledger.Obligation.NotBeforeUnix != milestone.payment.NotBeforeUnix || ledger.Obligation.DueAtUnix != milestone.payment.DueAtUnix ||
		ledger.Obligation.ExpiresAtUnix != milestone.payment.ExpiresAtUnix ||
		ledger.Obligation.SettlementAdapterURI != paiddemand.SettlementAdapterURI ||
		ledger.Obligation.SettlementParametersDigest != parameterDigest || ledger.State.ObligationDigest != stateObligationDigest ||
		ledger.State.State != commerce.SettlementPaid || ledger.State.PaidToDate != *milestone.payment.Amount ||
		ledger.State.OutstandingAmount != wantZero || len(ledger.State.AppliedPaymentEvidence) != 1 ||
		!sameCanonicalEvidenceSet(ledger.State.AppliedPaymentEvidence, ledger.State.EvidenceRefs) ||
		!sameCanonicalEvidenceSet(ledger.State.AppliedPaymentEvidence, paymentRuntime.SettlementEvidence) ||
		!sameCanonicalEvidenceSet(ledger.State.AppliedPaymentEvidence, record.SettlementEvidence) {
		return ObjectiveMilestoneFinalizedEvidence{}, false,
			errors.New("objective milestone predecessor settlement projection is not exact")
	}
	for _, evidence := range workRuntime.DeliveryEvidence {
		if !canonicalSHA256(evidence) {
			return ObjectiveMilestoneFinalizedEvidence{}, false,
				errors.New("objective milestone predecessor delivery evidence is invalid")
		}
	}
	if resolver == nil {
		// No released buyer-side finalized resolver currently exists. Keeping the
		// successor deferred is safer than promoting Provider-local or hash-only
		// business state into custody authority.
		return ObjectiveMilestoneFinalizedEvidence{}, false, nil
	}
	request := ObjectiveMilestoneFinalizedEvidenceRequest{NetworkContext: milestone.child.NetworkContext,
		AgreementBodyDigest: milestone.childDigest, PaymentObligationID: milestone.payment.ObligationID,
		WorkObligationID: milestone.work.ObligationID, PayerAgentID: milestone.payment.ObligorAgentID,
		PayeeAgentID: milestone.payment.BeneficiaryAgentID, SettlementAdapterURI: paiddemand.SettlementAdapterURI,
		Asset:        milestone.assetIdentity,
		AmountAtomic: milestone.payment.Amount.AmountAtomic}
	qualified, found, resolveErr := resolver.ResolveFinalizedObjectiveMilestone(ctx, request)
	if resolveErr != nil {
		return ObjectiveMilestoneFinalizedEvidence{}, false,
			fmt.Errorf("resolve objective milestone finalized evidence: %w", resolveErr)
	}
	if !found {
		return ObjectiveMilestoneFinalizedEvidence{}, false, nil
	}
	if validateErr := validateObjectiveMilestoneFinalizedEvidence(request, qualified); validateErr != nil {
		return ObjectiveMilestoneFinalizedEvidence{}, false, validateErr
	}
	if qualified.PaymentEvidenceDigest != ledger.State.AppliedPaymentEvidence[0] ||
		!sameCanonicalEvidenceSet(qualified.DeliveryEvidenceDigests, workRuntime.DeliveryEvidence) {
		return ObjectiveMilestoneFinalizedEvidence{}, false,
			errors.New("qualified objective milestone evidence differs from the exact local obligation projection")
	}
	return qualified, true, nil
}

func validateObjectiveMilestoneFinalizedEvidence(request ObjectiveMilestoneFinalizedEvidenceRequest,
	evidence ObjectiveMilestoneFinalizedEvidence) error {
	if evidence.NetworkContext != request.NetworkContext ||
		evidence.AgreementBodyDigest != request.AgreementBodyDigest ||
		evidence.PaymentObligationID != request.PaymentObligationID ||
		evidence.WorkObligationID != request.WorkObligationID ||
		evidence.PayerAgentID != request.PayerAgentID || evidence.PayeeAgentID != request.PayeeAgentID ||
		evidence.SettlementAdapterURI != request.SettlementAdapterURI ||
		evidence.Asset != request.Asset || evidence.AmountAtomic != request.AmountAtomic ||
		evidence.EvidenceProfileURI != paidDemandPaymentEvidenceProfile ||
		evidence.ResolutionState != "provider_credit_finalized" || evidence.ResolvedAtUnix == 0 ||
		!canonicalTVMCellSHA256(evidence.QuoteCommitment) || !canonicalTVMCellSHA256(evidence.ReceiptCommitment) ||
		!objectiveMilestoneOpaqueIdentity(evidence.EscrowAddress) ||
		!objectiveMilestoneOpaqueIdentity(evidence.ProviderWalletAddress) ||
		!canonicalSHA256(evidence.PaymentRequestDigest) || !canonicalSHA256(evidence.PaymentStableActionID) ||
		!canonicalSHA256(evidence.PaymentEvidenceDigest) || len(evidence.DeliveryEvidenceDigests) == 0 ||
		!objectiveMilestoneOpaqueIdentity(evidence.ExactTransferReference) ||
		!objectiveMilestoneOpaqueIdentity(evidence.FinalityReference) {
		return errors.New("qualified objective milestone finalized evidence is invalid or targets another payment")
	}
	for index, digest := range evidence.DeliveryEvidenceDigests {
		if !canonicalSHA256(digest) || index > 0 && evidence.DeliveryEvidenceDigests[index-1] >= digest {
			return errors.New("qualified objective milestone delivery evidence set is invalid")
		}
	}
	return nil
}

func retainUniqueObjectiveMilestoneEvidence(used map[string]string, agreementDigest string,
	evidence ObjectiveMilestoneFinalizedEvidence) error {
	identities := []string{evidence.QuoteCommitment, evidence.EscrowAddress, evidence.ReceiptCommitment,
		evidence.PaymentRequestDigest, evidence.PaymentStableActionID, evidence.PaymentEvidenceDigest,
		evidence.ExactTransferReference, evidence.FinalityReference}
	identities = append(identities, evidence.DeliveryEvidenceDigests...)
	for _, identity := range identities {
		if predecessor, exists := used[identity]; exists {
			return fmt.Errorf("objective milestone evidence identity is reused by %s and %s", predecessor, agreementDigest)
		}
		used[identity] = agreementDigest
	}
	return nil
}

func canonicalTVMCellSHA256(value string) bool {
	const prefix = "tvm-cell-sha256:"
	if len(value) != len(prefix)+64 || !strings.HasPrefix(value, prefix) {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, prefix))
	return err == nil && len(decoded) == 32
}

func objectiveMilestoneOpaqueIdentity(value string) bool {
	return len(value) > 0 && len(value) <= 512 && utf8.ValidString(value) && strings.TrimSpace(value) == value
}

func sameCanonicalEvidenceSet(left, right []string) bool {
	if len(left) == 0 || !sameOrderedStrings(left, right) {
		return false
	}
	for index, value := range left {
		if !canonicalSHA256(value) || index > 0 && left[index-1] >= value {
			return false
		}
	}
	return true
}

func sameOrderedStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

var _ PaidDemandFundingAdmission = ObjectiveMilestoneFundingAdmission{}
