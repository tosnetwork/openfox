package earning

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

func TestDemandAgreementCompilerCreatesExactGenericGraph(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	_, issuerKey, _ := ed25519.GenerateKey(rand.Reader)
	intent := earningIntent(t, now, issuerKey)
	intent.Body.Payload.SettlementPreferences = []commerce.SettlementPreference{{AdapterURI: "tos.payment.direct.v1", Required: true}}
	intent, _ = commerce.SignIntent(intent.Body, issuerKey)
	digest, _ := commerce.IntentBodyDigest(intent.Body)
	application := commerce.IntentApplication{SchemaVersion: 1, IntentDigest: digest, IntentIssuerAgentID: intent.Body.IssuerAgentID,
		ApplicantAgentID: "agent:provider", Message: "I will perform the exact signed request.",
		SettlementOffers:   []commerce.SettlementPreference{{AdapterURI: "tos.payment.direct.v1", Required: true}},
		ProposedAmount:     &commerce.AgreementAmount{AssetNamespace: "tos.asset", AssetIdentifier: "native", AmountAtomic: "50", Unit: "total"},
		PaymentDestination: []byte("tos1provider"), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}
	inventory := InventorySnapshot{OwnerID: "owner", AgentID: intent.Body.IssuerAgentID, CreatedAtUnix: uint64(now.Unix()),
		ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()), SourceGeneration: 1, PortfolioRevision: 1, PolicyRevision: 1,
		ConsistencyToken: "snapshot:issuer", SupportedSettlementAdapters: []string{"tos.payment.direct.v1"}}
	body, err := (DemandAgreementCompiler{LocalAgentID: intent.Body.IssuerAgentID, Now: func() time.Time { return now }}).Compile(intent, application, inventory)
	if err != nil {
		t.Fatal(err)
	}
	if err := commerce.ValidateAgreementBody(body); err != nil || len(body.Obligations) != 2 || len(body.AuthorizationPredicates) != 2 ||
		body.Obligations[0].SettlementAdapterURI != "tos.payment.direct.v1" || body.Obligations[1].SubjectContentType != "text/plain" {
		t.Fatalf("body=%+v err=%v", body, err)
	}
	mutated := application
	mutated.ProposedAmount = &commerce.AgreementAmount{AssetNamespace: "tos.asset", AssetIdentifier: "native", AmountAtomic: "51", Unit: "total"}
	if _, err := (DemandAgreementCompiler{LocalAgentID: intent.Body.IssuerAgentID, Now: func() time.Time { return now }}).Compile(intent, mutated, inventory); err == nil {
		t.Fatal("out-of-card application amount was accepted")
	}
}

func TestGenericAgreementProposalSupportsSupplyAndRejectsUnrelatedTerms(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	_, issuerKey, _ := ed25519.GenerateKey(rand.Reader)
	intent := earningIntent(t, now, issuerKey)
	intent.Body.Payload.DiscoveryCard.IntentModes = []commerce.IntentMode{commerce.IntentOffer, commerce.IntentSell}
	intent.Body.Payload.SettlementPreferences = []commerce.SettlementPreference{{AdapterURI: "tos.payment.direct.v1", Required: true}}
	intent, _ = commerce.SignIntent(intent.Body, issuerKey)
	intentDigest, _ := commerce.IntentBodyDigest(intent.Body)
	issuer, applicant := intent.Body.IssuerAgentID, "agent:customer"
	profile := commerce.AgentSignatureProfileDigest()
	body := commerce.AgentAgreementBody{SchemaVersion: 1, AgreementID: "agreement:supply", Version: 1,
		NetworkContext: intent.Body.NetworkID, Participants: []commerce.AgreementParticipant{{AgentID: issuer, Roles: []string{"provider"}}, {AgentID: applicant, Roles: []string{"buyer"}}},
		ReferencedIntents: []string{intentDigest}, TermsContentType: "text/plain", Terms: []byte("generic signed-Intent fulfillment"),
		Obligations: []commerce.AgreementObligation{
			{ObligationID: "pay", Kind: "payment", ObligorAgentID: applicant, BeneficiaryAgentID: issuer, DependsOnObligationIDs: []string{"work"},
				SubjectContentType: "text/plain", Subject: []byte("payment"), Amount: &commerce.AgreementAmount{AssetNamespace: "tos.asset", AssetIdentifier: "native", AmountAtomic: "50", Unit: "total"},
				ConfidentialityPolicy: "participants", CancellationPolicy: "before-start", DisputePolicy: "evidence", SettlementAdapterURI: "tos.payment.direct.v1",
				SettlementParameters: []byte("tos1issuer"), AuthorizationPredicateIDs: []string{"predicate:buyer"}},
			{ObligationID: "work", Kind: "fulfillment", ObligorAgentID: issuer, BeneficiaryAgentID: applicant,
				SubjectContentType: intent.Body.Payload.DetailDescriptor.ContentType, Subject: append([]byte(nil), intent.Body.Payload.DetailDescriptor.InlineContent...),
				ConfidentialityPolicy: "participants", CancellationPolicy: "before-start", DisputePolicy: "evidence", AuthorizationPredicateIDs: []string{"predicate:provider"}}},
		AuthorizationPredicates: []commerce.AgreementAuthorizationPredicate{
			{PredicateID: "predicate:buyer", AuthoritySubject: commerce.AgreementAuthoritySubject{SubjectKind: "agent", SubjectNamespace: "tos.agent", SubjectIdentifier: applicant},
				RoleScope: []string{"buyer"}, ObligationIDs: []string{"pay"}, EvidenceProfileURI: commerce.EvidenceProfileAgentSignature, EvidenceProfileVersion: 1, EvidenceProfileDigest: profile, ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())},
			{PredicateID: "predicate:provider", AuthoritySubject: commerce.AgreementAuthoritySubject{SubjectKind: "agent", SubjectNamespace: "tos.agent", SubjectIdentifier: issuer},
				RoleScope: []string{"provider"}, ObligationIDs: []string{"work"}, EvidenceProfileURI: commerce.EvidenceProfileAgentSignature, EvidenceProfileVersion: 1, EvidenceProfileDigest: profile, ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}},
		ValidFromUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}
	body, err := commerce.PrepareAgreementTargets(body)
	if err != nil {
		t.Fatal(err)
	}
	application := commerce.IntentApplication{SchemaVersion: 2, IntentDigest: intentDigest, IntentIssuerAgentID: issuer,
		ApplicantAgentID: applicant, Message: "I accept the published scope as a proposal, subject to typed Agreement acceptance.",
		SettlementOffers:      []commerce.SettlementPreference{{AdapterURI: "tos.payment.direct.v1", Required: true}},
		ProposedAgreementBody: &body, ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}
	inventory := InventorySnapshot{OwnerID: "owner", AgentID: issuer, CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()),
		SourceGeneration: 1, PortfolioRevision: 1, PolicyRevision: 1, ConsistencyToken: "snapshot:supply",
		SupportedSettlementAdapters: []string{"tos.payment.direct.v1"}}
	compiler := DemandAgreementCompiler{LocalAgentID: issuer, Now: func() time.Time { return now }}
	compiled, err := compiler.Compile(intent, application, inventory)
	if err != nil || compiled.AgreementID != body.AgreementID {
		t.Fatalf("compiled=%+v err=%v", compiled, err)
	}
	mutated := application
	changed := body
	changed.Obligations = append([]commerce.AgreementObligation(nil), body.Obligations...)
	changed.AuthorizationPredicates = append([]commerce.AgreementAuthorizationPredicate(nil), body.AuthorizationPredicates...)
	changed.Obligations[1].Subject = []byte("unrelated work selected by hostile application")
	for index := range changed.AuthorizationPredicates {
		changed.AuthorizationPredicates[index].EvidenceTargetProjectionDigest = ""
	}
	changed, err = commerce.PrepareAgreementTargets(changed)
	if err != nil {
		t.Fatal(err)
	}
	mutated.ProposedAgreementBody = &changed
	if _, err := compiler.Compile(intent, mutated, inventory); err == nil {
		t.Fatal("application replaced the exact signed Intent subject")
	}
}
