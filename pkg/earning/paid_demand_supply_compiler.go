package earning

import (
	"context"
	"errors"
	"math"
	"sort"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/paiddemand"
)

type PaidDemandSupplyAgreementCompiler struct {
	Network     *nativev1.NetworkDomain
	BuyerWallet string
	Store       *PaidDemandNegotiationStore
	Now         func() time.Time
}

func (compiler PaidDemandSupplyAgreementCompiler) CompileSupplyAgreement(_ context.Context, applicantAgentID string,
	candidate CandidateAssessment, application commerce.IntentApplication,
	expires time.Time) (commerce.AgentAgreementBody, []byte, error) {
	if compiler.Network == nil || compiler.Network.NetworkId != candidate.Intent.Body.NetworkID || compiler.BuyerWallet == "" ||
		compiler.Store == nil || application.ProposedAmount == nil || applicantAgentID == "" ||
		len(candidate.Intent.Body.Payload.DetailDescriptor.InlineContent) == 0 {
		return commerce.AgentAgreementBody{}, nil, errors.New("Paid Demand supply compiler is incomplete")
	}
	now := time.Now().UTC()
	if compiler.Now != nil {
		now = compiler.Now().UTC()
	}
	publicCanonical := paidDemandPreferenceParameters(candidate.Intent.Body.Payload.SettlementPreferences)
	public, err := paiddemand.DecodeCanonicalPublicTerms(publicCanonical)
	if err != nil || public.ExecutionProfileURI != paiddemand.ExecutionManifestProfileV1 {
		return commerce.AgentAgreementBody{}, nil, errors.New("supply Intent has no valid generic Paid Demand public terms")
	}
	asset, err := paiddemand.AssetFromPublicTerms(public)
	if err != nil || application.ProposedAmount.AssetNamespace != "tos.contract" ||
		application.ProposedAmount.AssetIdentifier != public.AssetMasterAddress || application.ProposedAmount.Unit != "atomic" {
		return commerce.AgentAgreementBody{}, nil, errors.New("Paid Demand amount uses another asset identity")
	}
	acceptWindow := minU32(public.FundingWindowSeconds/2, 900)
	if acceptWindow < 60 {
		acceptWindow = 60
	}
	acceptBy, ok := addUnix(now, uint64(acceptWindow))
	if !ok {
		return commerce.AgentAgreementBody{}, nil, errors.New("Paid Demand deadline overflow")
	}
	fundingDeadline, ok := addSeconds(acceptBy, uint64(public.FundingWindowSeconds))
	if !ok {
		return commerce.AgentAgreementBody{}, nil, errors.New("Paid Demand deadline overflow")
	}
	executionDeadline, ok := addSeconds(fundingDeadline, uint64(public.ExecutionWindowSeconds))
	if !ok {
		return commerce.AgentAgreementBody{}, nil, errors.New("Paid Demand deadline overflow")
	}
	refundAt, ok := addSeconds(executionDeadline, uint64(public.RefundDelaySeconds))
	if !ok || expires.Unix() < 0 || refundAt > uint64(expires.Unix()) || refundAt <= executionDeadline {
		return commerce.AgentAgreementBody{}, nil, errors.New("Paid Demand windows do not fit the Agreement validity")
	}
	issuerAgentID := candidate.Intent.Body.IssuerAgentID
	sourceDigest, err := codec.Digest("tos.paid-demand-source-material.v1", struct {
		IntentDigest string `json:"intent_digest"`
		ContentType  string `json:"content_type"`
		Content      []byte `json:"content"`
	}{candidate.IntentDigest, candidate.Intent.Body.Payload.DetailDescriptor.ContentType,
		candidate.Intent.Body.Payload.DetailDescriptor.InlineContent})
	if err != nil {
		return commerce.AgentAgreementBody{}, nil, err
	}
	inputDigest, err := codec.Digest("tos.paid-demand-accepted-input-set.v1", struct {
		SourceDigest string `json:"source_digest"`
	}{sourceDigest})
	if err != nil || inputDigest == sourceDigest {
		return commerce.AgentAgreementBody{}, nil, errors.New("build distinct Paid Demand input commitments")
	}
	attachments := []string{inputDigest, sourceDigest}
	sort.Strings(attachments)
	requiredExecutionBindings := []string{"tos.input." + inputDigest[7:], "tos.source." + sourceDigest[7:]}
	sort.Strings(requiredExecutionBindings)
	agreementSeed, err := codec.Digest("tos.paid-demand-supply-agreement-id.v1", struct {
		IntentDigest, BuyerAgentID, ProviderAgentID, AmountAtomic string
		ExpiresAtUnix                                             uint64
	}{candidate.IntentDigest, applicantAgentID, issuerAgentID,
		application.ProposedAmount.AmountAtomic, uint64(expires.Unix())})
	if err != nil {
		return commerce.AgentAgreementBody{}, nil, err
	}
	profile := commerce.PaidDemandQuoteProfileDigest()
	body := commerce.AgentAgreementBody{SchemaVersion: 1, AgreementID: "agreement:" + agreementSeed[7:], Version: 1,
		NetworkContext: candidate.Intent.Body.NetworkID,
		Participants: []commerce.AgreementParticipant{{AgentID: issuerAgentID, Roles: []string{"provider"}},
			{AgentID: applicantAgentID, Roles: []string{"buyer"}}}, ReferencedIntents: []string{candidate.IntentDigest},
		TermsContentType: "text/plain", Terms: []byte(application.Message), Obligations: []commerce.AgreementObligation{
			{ObligationID: "payment", Kind: "payment", ObligorAgentID: applicantAgentID, BeneficiaryAgentID: issuerAgentID,
				DependsOnObligationIDs: []string{"work"}, SubjectContentType: "text/plain", Subject: []byte("payment for accepted fulfillment"),
				Amount: application.ProposedAmount, DueAtUnix: executionDeadline, ExpiresAtUnix: refundAt,
				ConfidentialityPolicy: "participants", CancellationPolicy: "chain-profile", DisputePolicy: "objective",
				SettlementAdapterURI: paiddemand.SettlementAdapterURI, SettlementParameters: append([]byte(nil), publicCanonical...),
				AuthorizationPredicateIDs: []string{"predicate:buyer"}},
			{ObligationID: "work", Kind: "fulfillment", ObligorAgentID: issuerAgentID, BeneficiaryAgentID: applicantAgentID,
				SubjectContentType: candidate.Intent.Body.Payload.DetailDescriptor.ContentType,
				Subject:            append([]byte(nil), candidate.Intent.Body.Payload.DetailDescriptor.InlineContent...),
				AttachmentDigests:  append([]string(nil), attachments...), RequiredExtensions: append([]string(nil), requiredExecutionBindings...),
				DueAtUnix: executionDeadline, ExpiresAtUnix: refundAt, ConfidentialityPolicy: "participants",
				CancellationPolicy: "chain-profile", DisputePolicy: "objective", AuthorizationPredicateIDs: []string{"predicate:provider"}},
		}, AuthorizationPredicates: []commerce.AgreementAuthorizationPredicate{
			{PredicateID: "predicate:buyer", AuthoritySubject: commerce.AgreementAuthoritySubject{SubjectKind: "wallet",
				SubjectNamespace: "tos.wallet", SubjectIdentifier: compiler.BuyerWallet, RepresentedAgentID: applicantAgentID},
				RoleScope: []string{"buyer"}, ObligationIDs: []string{"payment"}, EvidenceProfileURI: commerce.EvidenceProfilePaidDemandQuote,
				EvidenceProfileVersion: 1, EvidenceProfileDigest: profile, ExpiresAtUnix: acceptBy},
			{PredicateID: "predicate:provider", AuthoritySubject: commerce.AgreementAuthoritySubject{SubjectKind: "agent",
				SubjectNamespace: "tos.agent", SubjectIdentifier: issuerAgentID}, RoleScope: []string{"provider"},
				ObligationIDs: []string{"work"}, EvidenceProfileURI: commerce.EvidenceProfilePaidDemandQuote,
				EvidenceProfileVersion: 1, EvidenceProfileDigest: profile, ExpiresAtUnix: acceptBy},
		}, ValidFromUnix: uint64(now.Unix()), ExpiresAtUnix: refundAt}
	sort.Slice(body.Participants, func(i, j int) bool { return body.Participants[i].AgentID < body.Participants[j].AgentID })
	body, err = commerce.PrepareAgreementTargets(body)
	if err != nil {
		return commerce.AgentAgreementBody{}, nil, err
	}
	agreementDigest, _ := commerce.AgreementBodyDigest(body)
	workPlan, err := codec.Marshal(struct {
		AgreementDigest string `json:"agreement_digest"`
		ObligationID    string `json:"obligation_id"`
		ContentType     string `json:"content_type"`
		Subject         []byte `json:"subject"`
	}{agreementDigest, "work", body.Obligations[1].SubjectContentType, body.Obligations[1].Subject})
	if err != nil {
		return commerce.AgentAgreementBody{}, nil, err
	}
	deliverablePolicy, err := codec.Digest("tos.paid-demand-deliverable-policy.v1", body.Obligations[1])
	if err != nil {
		return commerce.AgentAgreementBody{}, nil, err
	}
	manifest := paiddemand.ExecutionManifestV1{SchemaVersion: 1, AgreementBodyDigest: agreementDigest,
		WorkObligationIDs: []string{"work"}, ExecutionProfileURI: public.ExecutionProfileURI,
		PlanContentType: "application/vnd.tos.agreement-obligation-plan.v1+cbor", Plan: workPlan,
		AcceptedInputSetDigestOrZero: inputDigest, DeliverablePolicyDigestOrZero: deliverablePolicy}
	manifestCanonical, manifestDigest, err := paiddemand.CanonicalExecutionManifest(manifest)
	if err != nil {
		return commerce.AgentAgreementBody{}, nil, err
	}
	escrowTerms := nativecore.EscrowTermsV1{BuyerAddress: compiler.BuyerWallet, ProviderAddress: public.ProviderWallet,
		FundingDeadline: fundingDeadline, RefundAvailableAt: refundAt}
	escrowTermsCell, err := nativecore.BuildEscrowTermsCellV1(escrowTerms)
	if err != nil {
		return commerce.AgentAgreementBody{}, nil, err
	}
	_, transportDigest, err := nativecore.BuildTransportBindingCellV1(public.TransportBinding)
	if err != nil {
		return commerce.AgentAgreementBody{}, nil, err
	}
	_, disputeDigest := nativecore.BuildObjectiveDisputePolicyCellV1()
	proposal := &nativev1.QuoteProposalV1{CapabilityId: public.CapabilityID, CapabilityVersion: public.CapabilityVersion,
		ProviderAgentId: issuerAgentID, ManifestDigest: manifestDigest, TransportBindingDigest: transportDigest,
		ExpiresAtUnixSeconds: acceptBy, EscrowTermsDigest: "sha256:" + encodeHex(escrowTermsCell.Hash()),
		DisputePolicyDigest: disputeDigest, MaximumPrice: &nativev1.MoneyV1{AtomicAmount: application.ProposedAmount.AmountAtomic, Asset: asset}}
	authorization, err := nativecore.BuildEscrowAuthorizationCellV1(public.ExecutionSignerEd25519)
	if err != nil {
		return commerce.AgentAgreementBody{}, nil, err
	}
	_, nativeProjection, err := nativecore.BuildAcceptedQuoteCommitment(compiler.Network, proposal,
		"sha256:"+encodeHex(authorization.Hash()))
	if err != nil {
		return commerce.AgentAgreementBody{}, nil, err
	}
	offerID, err := codec.Digest("tos.paid-demand-provider-offer-id.v1", struct {
		AgreementDigest, DemandMutationDigest, ProviderAgentID, BuyerAgentID string
	}{agreementDigest, candidate.IntentDigest, issuerAgentID, applicantAgentID})
	if err != nil {
		return commerce.AgentAgreementBody{}, nil, err
	}
	predicateIDs := []string{"predicate:buyer", "predicate:provider"}
	targets := make([]string, 0, 2)
	for _, id := range predicateIDs {
		for _, predicate := range body.AuthorizationPredicates {
			if predicate.PredicateID == id {
				targets = append(targets, predicate.EvidenceTargetProjectionDigest)
			}
		}
	}
	binding := commerce.PaidDemandQuoteBindingBody{SchemaVersion: 1, NetworkContext: body.NetworkContext,
		AgreementBodyDigest: agreementDigest, AgreementObligationIDs: []string{"payment", "work"},
		AgreementAuthorizationPredicateIDs: predicateIDs, AgreementAuthorizationTargetDigests: targets,
		EvidenceProfileURI: commerce.EvidenceProfilePaidDemandQuote, EvidenceProfileVersion: 1,
		EvidenceProfileDigest: profile, DemandMutationDigest: candidate.IntentDigest,
		ProviderOfferID: "offer:" + offerID[7:], ProviderAgentID: issuerAgentID, BuyerAgentID: applicantAgentID,
		BuyerWallet: compiler.BuyerWallet, ProviderWallet: public.ProviderWallet,
		NativeQuoteTermsProjectionDigest: nativeProjection, AcceptByUnix: acceptBy}
	proposalProto, err := paiddemand.EncodeQuoteProposal(proposal)
	if err != nil {
		return commerce.AgentAgreementBody{}, nil, err
	}
	packageValue := paiddemand.NegotiationPackageV1{SchemaVersion: 1, AgreementBodyDigest: agreementDigest,
		ProposalProto: proposalProto, ManifestCanonical: manifestCanonical, EscrowTerms: escrowTerms,
		ExecutionSignerEd25519: append([]byte(nil), public.ExecutionSignerEd25519...), TransportBinding: public.TransportBinding,
		ExecutionDeadlineUnix: executionDeadline, Binding: binding}
	if _, err := paiddemand.ValidateNegotiationPackageOnNetwork(body, public, packageValue, compiler.Network, now); err != nil {
		return commerce.AgentAgreementBody{}, nil, err
	}
	packageCanonical, err := paiddemand.CanonicalNegotiationPackage(packageValue)
	if err != nil || compiler.Store.Put(agreementDigest, packageCanonical) != nil {
		return commerce.AgentAgreementBody{}, nil, errors.New("persist Paid Demand negotiation package")
	}
	return body, packageCanonical, nil
}

func paidDemandPreferenceParameters(preferences []commerce.SettlementPreference) []byte {
	for _, preference := range preferences {
		if preference.AdapterURI == paiddemand.SettlementAdapterURI {
			return append([]byte(nil), preference.Parameters...)
		}
	}
	return nil
}

func addUnix(now time.Time, seconds uint64) (uint64, bool) {
	if now.Unix() < 0 {
		return 0, false
	}
	return addSeconds(uint64(now.Unix()), seconds)
}

func addSeconds(value, seconds uint64) (uint64, bool) {
	if seconds > math.MaxUint64-value {
		return 0, false
	}
	return value + seconds, true
}

func minU32(left, right uint32) uint32 {
	if left < right {
		return left
	}
	return right
}

func encodeHex(value []byte) string {
	const alphabet = "0123456789abcdef"
	output := make([]byte, len(value)*2)
	for index, item := range value {
		output[index*2], output[index*2+1] = alphabet[item>>4], alphabet[item&15]
	}
	return string(output)
}

var _ SupplyAgreementProfileCompiler = PaidDemandSupplyAgreementCompiler{}
