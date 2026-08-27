package earning

import (
	"errors"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	guarantor "github.com/tosnetwork/tos-service-protocol/pkg/agentguarantor"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type GuarantorFirmOfferAgreementEvidenceVerifier struct {
	AuthorityResolver   guarantor.AuthorityKeyResolver
	PublicationResolver commerce.AgentOperationAuthorityResolver
	UnderlyingResolver  guarantor.UnderlyingAgreementResolver
	AgreementVerifier   commerce.AgreementEvidenceVerifier
}

func (verifier GuarantorFirmOfferAgreementEvidenceVerifier) VerifyAgreementEvidence(
	evidence commerce.AgreementAuthorizationEvidence, now time.Time) error {
	return guarantor.VerifyFirmOfferAgreementEvidenceIntrinsicV1(evidence, verifier.AuthorityResolver,
		verifier.PublicationResolver, verifier.UnderlyingResolver, verifier.AgreementVerifier, now)
}

type ExternalAgreementEvidenceVerifier interface {
	VerifyAgreementEvidence(commerce.AgreementAuthorizationEvidence, time.Time) error
}

// AgreementEvidenceRouter keeps evidence-profile choice in the Agreement
// body. It implements the generic Agent signature profile locally and only
// delegates explicitly configured non-generic profiles.
type AgreementEvidenceRouter struct {
	AgentAuthority commerce.IntentAuthorityResolver
	Profiles       map[string]ExternalAgreementEvidenceVerifier
}

func (router AgreementEvidenceRouter) VerifyAgreementEvidence(evidence commerce.AgreementAuthorizationEvidence, now time.Time) error {
	switch evidence.EvidenceProfileURI {
	case commerce.EvidenceProfileAgentSignature:
		if evidence.EvidenceContentType != commerce.AgreementAcceptanceContentType ||
			evidence.EvidenceProfileDigest != commerce.AgentSignatureProfileDigest() || router.AgentAuthority == nil {
			return errors.New("Agent-signature Agreement evidence has no finalized authority resolver")
		}
		var acceptance commerce.SignedAgreementAcceptance
		if err := codec.Unmarshal(evidence.Evidence, &acceptance); err != nil {
			return err
		}
		return commerce.VerifySignedAgreementAcceptance(acceptance, evidence, router.AgentAuthority, now)
	default:
		verifier := router.Profiles[evidence.EvidenceProfileURI]
		if verifier == nil {
			return errors.New("Agreement evidence profile is not installed")
		}
		return verifier.VerifyAgreementEvidence(evidence, now)
	}
}
