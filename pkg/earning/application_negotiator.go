package earning

import (
	"context"
	"errors"
	"math/big"
	"sort"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type PublishedIntentResolver interface {
	IntentByDigest(string) (commerce.SignedAgentIntent, bool)
}

// DemandAgreementCompiler converts a generic REQUEST/BUY Intent and one
// authenticated application into a business-neutral work/payment obligation
// graph. It deliberately handles no industry-specific task type.
type DemandAgreementCompiler struct {
	LocalAgentID string
	MaximumTTL   time.Duration
	Now          func() time.Time
}

func (compiler DemandAgreementCompiler) Compile(intent commerce.SignedAgentIntent, application commerce.IntentApplication,
	inventory InventorySnapshot) (commerce.AgentAgreementBody, error) {
	now := time.Now().UTC()
	if compiler.Now != nil {
		now = compiler.Now().UTC()
	}
	intentDigest, err := commerce.IntentBodyDigest(intent.Body)
	if err != nil || commerce.ValidateIntentApplication(application) != nil || intentDigest != application.IntentDigest || intent.Body.IssuerAgentID != compiler.LocalAgentID ||
		application.IntentIssuerAgentID != compiler.LocalAgentID || inventory.AgentID != compiler.LocalAgentID || inventory.Validate(now) != nil ||
		!now.Before(time.Unix(int64(application.ExpiresAtUnix), 0).UTC()) {
		return commerce.AgentAgreementBody{}, errors.New("Intent application cannot be compiled against current issuer state")
	}
	if application.ProposedAgreementBody != nil {
		return compiler.validateGenericProposal(intent, application, inventory, intentDigest, now)
	}
	if !containsIntentMode(intent.Body.Payload.DiscoveryCard.IntentModes, commerce.IntentRequest) &&
		!containsIntentMode(intent.Body.Payload.DiscoveryCard.IntentModes, commerce.IntentBuy) {
		return commerce.AgentAgreementBody{}, errors.New("automatic demand compilation supports only an issuer requesting or buying fulfillment")
	}
	if application.ProposedAmount == nil || len(application.PaymentDestination) == 0 {
		return commerce.AgentAgreementBody{}, errors.New("application lacks an exact amount or payment destination")
	}
	if !amountAllowedByCard(*application.ProposedAmount, intent.Body.Payload.DiscoveryCard.ValueHints) {
		return commerce.AgentAgreementBody{}, errors.New("application amount is outside the signed discovery card")
	}
	adapter := commonSettlementAdapter(intent.Body.Payload.SettlementPreferences, application.SettlementOffers, inventory)
	if adapter == "" {
		return commerce.AgentAgreementBody{}, errors.New("application and issuer have no common installed settlement Adapter")
	}
	detail := intent.Body.Payload.DetailDescriptor.InlineContent
	if len(detail) == 0 {
		return commerce.AgentAgreementBody{}, errors.New("automatic Agreement compilation requires issuer-owned inline detail")
	}
	expires := time.Unix(int64(intent.Body.ExpiresAtUnix), 0).UTC()
	applicationExpiry := time.Unix(int64(application.ExpiresAtUnix), 0).UTC()
	if applicationExpiry.Before(expires) {
		expires = applicationExpiry
	}
	maximum := compiler.MaximumTTL
	if maximum == 0 {
		maximum = time.Hour
	}
	if now.Add(maximum).Before(expires) {
		expires = now.Add(maximum)
	}
	if !expires.After(now.Add(time.Minute)) {
		return commerce.AgentAgreementBody{}, errors.New("Agreement validity would be too short")
	}
	applicationDigest, err := codec.Digest("tos.intent-application.v1", application)
	if err != nil {
		return commerce.AgentAgreementBody{}, err
	}
	agreementID, err := codec.Digest("tos.intent-application-agreement-id.v1", struct {
		Intent, Application string
	}{intentDigest, applicationDigest})
	if err != nil {
		return commerce.AgentAgreementBody{}, err
	}
	providerPredicate := "predicate:provider"
	buyerPredicate := "predicate:buyer"
	profile := commerce.AgentSignatureProfileDigest()
	body := commerce.AgentAgreementBody{SchemaVersion: 1, AgreementID: "agreement:" + agreementID[7:], Version: 1,
		NetworkContext: intent.Body.NetworkID,
		Participants: []commerce.AgreementParticipant{{AgentID: application.ApplicantAgentID, Roles: []string{"provider"}},
			{AgentID: compiler.LocalAgentID, Roles: []string{"buyer"}}}, ReferencedIntents: []string{intentDigest},
		TermsContentType: "text/plain", Terms: []byte(application.Message),
		Obligations: []commerce.AgreementObligation{
			{ObligationID: "payment", Kind: "payment", ObligorAgentID: compiler.LocalAgentID, BeneficiaryAgentID: application.ApplicantAgentID,
				DependsOnObligationIDs: []string{"work"}, SubjectContentType: "text/plain", Subject: []byte("payment for accepted fulfillment"),
				Amount: application.ProposedAmount, DueAtUnix: uint64(expires.Unix()), ExpiresAtUnix: uint64(expires.Unix()),
				ConfidentialityPolicy: "participants", CancellationPolicy: "before-start", DisputePolicy: "evidence",
				SettlementAdapterURI: adapter, SettlementParameters: append([]byte(nil), application.PaymentDestination...),
				AuthorizationPredicateIDs: []string{buyerPredicate}},
			{ObligationID: "work", Kind: "fulfillment", ObligorAgentID: application.ApplicantAgentID, BeneficiaryAgentID: compiler.LocalAgentID,
				SubjectContentType: intent.Body.Payload.DetailDescriptor.ContentType, Subject: append([]byte(nil), detail...),
				ConfidentialityPolicy: "participants", CancellationPolicy: "before-start", DisputePolicy: "evidence",
				AuthorizationPredicateIDs: []string{providerPredicate}},
		}, AuthorizationPredicates: []commerce.AgreementAuthorizationPredicate{
			{PredicateID: buyerPredicate, AuthoritySubject: commerce.AgreementAuthoritySubject{SubjectKind: "agent", SubjectNamespace: "tos.agent", SubjectIdentifier: compiler.LocalAgentID},
				RoleScope: []string{"buyer"}, ObligationIDs: []string{"payment"}, EvidenceProfileURI: commerce.EvidenceProfileAgentSignature,
				EvidenceProfileVersion: 1, EvidenceProfileDigest: profile, ExpiresAtUnix: uint64(expires.Unix())},
			{PredicateID: providerPredicate, AuthoritySubject: commerce.AgreementAuthoritySubject{SubjectKind: "agent", SubjectNamespace: "tos.agent", SubjectIdentifier: application.ApplicantAgentID},
				RoleScope: []string{"provider"}, ObligationIDs: []string{"work"}, EvidenceProfileURI: commerce.EvidenceProfileAgentSignature,
				EvidenceProfileVersion: 1, EvidenceProfileDigest: profile, ExpiresAtUnix: uint64(expires.Unix())},
		}, ValidFromUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(expires.Unix())}
	sort.Slice(body.Participants, func(i, j int) bool { return body.Participants[i].AgentID < body.Participants[j].AgentID })
	sort.Slice(body.AuthorizationPredicates, func(i, j int) bool {
		return body.AuthorizationPredicates[i].PredicateID < body.AuthorizationPredicates[j].PredicateID
	})
	return commerce.PrepareAgreementTargets(body)
}

func (compiler DemandAgreementCompiler) validateGenericProposal(intent commerce.SignedAgentIntent,
	application commerce.IntentApplication, inventory InventorySnapshot, intentDigest string,
	now time.Time) (commerce.AgentAgreementBody, error) {
	body := *application.ProposedAgreementBody
	if body.NetworkContext != intent.Body.NetworkID || body.Version != 1 || body.PredecessorAgreementDigest != "" ||
		!containsString(body.ReferencedIntents, intentDigest) ||
		body.ValidFromUnix > uint64(now.Unix()) || !now.Before(time.Unix(int64(body.ExpiresAtUnix), 0).UTC()) ||
		body.ExpiresAtUnix > intent.Body.ExpiresAtUnix || body.ExpiresAtUnix > application.ExpiresAtUnix {
		return commerce.AgentAgreementBody{}, errors.New("generic Agreement proposal does not bind the active Intent window")
	}
	issuerParticipant, applicantParticipant := false, false
	issuerActs, issuerBenefits := false, false
	detailBound := false
	for _, participant := range body.Participants {
		issuerParticipant = issuerParticipant || participant.AgentID == compiler.LocalAgentID
		applicantParticipant = applicantParticipant || participant.AgentID == application.ApplicantAgentID
	}
	for _, obligation := range body.Obligations {
		issuerActs = issuerActs || obligation.ObligorAgentID == compiler.LocalAgentID
		issuerBenefits = issuerBenefits || obligation.BeneficiaryAgentID == compiler.LocalAgentID
		detailBound = detailBound || len(intent.Body.Payload.DetailDescriptor.InlineContent) != 0 &&
			obligation.SubjectContentType == intent.Body.Payload.DetailDescriptor.ContentType &&
			string(obligation.Subject) == string(intent.Body.Payload.DetailDescriptor.InlineContent)
		if obligation.Amount != nil {
			if !amountAllowedByCard(*obligation.Amount, intent.Body.Payload.DiscoveryCard.ValueHints) ||
				!inventory.SupportsSettlement(obligation.SettlementAdapterURI) ||
				!settlementAdapterOffered(obligation.SettlementAdapterURI, intent.Body.Payload.SettlementPreferences, application.SettlementOffers) {
				return commerce.AgentAgreementBody{}, errors.New("generic Agreement selects an unavailable settlement Adapter")
			}
		}
	}
	if !issuerParticipant || !applicantParticipant || !issuerActs || !issuerBenefits || !detailBound {
		return commerce.AgentAgreementBody{}, errors.New("generic Agreement does not preserve both parties and the exact Intent subject")
	}
	modes := intent.Body.Payload.DiscoveryCard.IntentModes
	if (containsIntentMode(modes, commerce.IntentOffer) || containsIntentMode(modes, commerce.IntentSell)) && !issuerActs {
		return commerce.AgentAgreementBody{}, errors.New("supply Intent proposal does not retain issuer fulfillment")
	}
	if (containsIntentMode(modes, commerce.IntentRequest) || containsIntentMode(modes, commerce.IntentBuy)) && !issuerBenefits {
		return commerce.AgentAgreementBody{}, errors.New("demand Intent proposal does not retain issuer benefit")
	}
	// ValidateIntentApplication already invokes ValidateAgreementBody, whose
	// exact non-circular projection check rejects targets prepared over any
	// different terms or predicate policy.
	return body, nil
}

func settlementAdapterOffered(adapter string, issuer, applicant []commerce.SettlementPreference) bool {
	issuerFound, applicantFound := false, false
	for _, candidate := range issuer {
		issuerFound = issuerFound || candidate.AdapterURI == adapter
	}
	for _, candidate := range applicant {
		applicantFound = applicantFound || candidate.AdapterURI == adapter
	}
	return issuerFound && applicantFound
}

func containsIntentMode(modes []commerce.IntentMode, target commerce.IntentMode) bool {
	for _, mode := range modes {
		if mode == target {
			return true
		}
	}
	return false
}

func amountAllowedByCard(amount commerce.AgreementAmount, hints []commerce.ValueHint) bool {
	value, ok := new(big.Int).SetString(amount.AmountAtomic, 10)
	if !ok || value.Sign() < 0 {
		return false
	}
	for _, hint := range hints {
		if hint.AssetNamespace != amount.AssetNamespace || hint.AssetIdentifier != amount.AssetIdentifier || hint.Unit != amount.Unit {
			continue
		}
		minimum, minOK := new(big.Int).SetString(hint.MinimumDecimal, 10)
		maximum, maxOK := new(big.Int).SetString(hint.MaximumDecimal, 10)
		if minOK && maxOK && minimum.Sign() >= 0 && maximum.Cmp(minimum) >= 0 && value.Cmp(minimum) >= 0 && value.Cmp(maximum) <= 0 {
			return true
		}
	}
	return false
}

func commonSettlementAdapter(issuer, applicant []commerce.SettlementPreference, inventory InventorySnapshot) string {
	candidates := make([]string, 0)
	for _, first := range issuer {
		if !inventory.SupportsSettlement(first.AdapterURI) {
			continue
		}
		for _, second := range applicant {
			if first.AdapterURI == second.AdapterURI {
				candidates = append(candidates, first.AdapterURI)
			}
		}
	}
	sort.Strings(candidates)
	if len(candidates) == 0 {
		return ""
	}
	return candidates[0]
}

type DemandApplicationNegotiator struct {
	Publications PublishedIntentResolver
	Engine       *Engine
	Inventory    InventorySource
	Compiler     DemandAgreementCompiler
	Fence        WriterFenceProvider
	Profiles     map[string]DemandApplicationProfileHandler
}

type DemandApplicationProfileHandler interface {
	HandleDemandApplication(context.Context, commerce.SignedAgentIntent, commerce.IntentApplication,
		commerce.AgentAgreementBody, InventorySnapshot, commerce.WriterFence) error
}

func (negotiator DemandApplicationNegotiator) HandleIntentApplication(ctx context.Context, event ClaimedAgreementEvent) error {
	if negotiator.Publications == nil || negotiator.Engine == nil || negotiator.Inventory == nil || negotiator.Fence == nil || event.Application == nil {
		return errors.New("Intent application negotiator is incomplete")
	}
	application := *event.Application
	if application.ApplicantAgentID != event.SenderAgentID || application.IntentIssuerAgentID != negotiator.Engine.AgentID {
		return errors.New("Intent application authenticated participants mismatch")
	}
	intent, found := negotiator.Publications.IntentByDigest(application.IntentDigest)
	if !found {
		return errors.New("Intent application references no active issuer publication")
	}
	inventory, err := negotiator.Inventory.Snapshot(ctx)
	if err != nil {
		return err
	}
	body, err := negotiator.Compiler.Compile(intent, application, inventory)
	if err != nil {
		return err
	}
	fence, err := negotiator.Fence(ctx)
	if err != nil {
		return err
	}
	recipients := make([]string, 0, len(body.Participants)-1)
	for _, participant := range body.Participants {
		if participant.AgentID != negotiator.Engine.AgentID {
			recipients = append(recipients, participant.AgentID)
		}
	}
	sort.Strings(recipients)
	resolution, err := negotiator.Engine.ProposeAgreement(ctx, body, recipients, inventory.PolicyRevision, fence)
	if err != nil {
		return err
	}
	if resolution.State != commerce.ActionAccepted && resolution.State != commerce.ActionTerminal {
		return errors.New("Agreement proposal remains unresolved")
	}
	handledProfiles := map[string]bool{}
	for _, obligation := range body.Obligations {
		if obligation.Amount == nil {
			continue
		}
		if profile := negotiator.Profiles[obligation.SettlementAdapterURI]; profile != nil && !handledProfiles[obligation.SettlementAdapterURI] {
			if err := profile.HandleDemandApplication(ctx, intent, application, body, inventory, fence); err != nil {
				return err
			}
			handledProfiles[obligation.SettlementAdapterURI] = true
		}
	}
	return nil
}
