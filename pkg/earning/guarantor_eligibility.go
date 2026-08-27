package earning

import (
	"errors"
	"sort"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	guarantor "github.com/tosnetwork/tos-service-protocol/pkg/agentguarantor"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

// buildGuarantorEligibilityProofSet turns authority-finality evidence into the
// portable, admission-bound representation required on the wire.  The raw
// evidence remains resolver-profile-specific, while every security-relevant
// interpretation is explicit and covered by the canonical digest.
func buildGuarantorEligibilityProofSet(raw []byte, action commerce.AuthorizedAction, inputEnvelopeDigest string,
	subjects []string, objectKind, bodyDigest, scopeDigest string, resolverProfile commerce.ProfileRefV1,
	domainID string, sequence, admittedAtUnix uint64) (guarantor.AuthorityAdmissionEligibilityProofSetV1, error) {
	if len(raw) == 0 || len(raw) > 64<<10 || len(subjects) == 0 {
		return guarantor.AuthorityAdmissionEligibilityProofSetV1{}, errors.New("Guarantor authority finality evidence is invalid")
	}
	actionDigest, err := commerce.AuthorizedActionDigest(action)
	if err != nil {
		return guarantor.AuthorityAdmissionEligibilityProofSetV1{}, err
	}
	principalDigest, err := codec.Digest("tos.service.agent-guarantor-finalized-authority-principal.v1", raw)
	if err != nil {
		return guarantor.AuthorityAdmissionEligibilityProofSetV1{}, err
	}
	entries := make([]guarantor.AuthorityAdmissionEligibilityProofV1, 0, len(subjects))
	seen := make(map[string]struct{}, len(subjects))
	for _, subject := range subjects {
		if _, exists := seen[subject]; exists {
			continue
		}
		seen[subject] = struct{}{}
		entries = append(entries, guarantor.AuthorityAdmissionEligibilityProofV1{SchemaVersion: 1,
			InputAuthorizedEnvelopeDigest: inputEnvelopeDigest, AuthoritySubject: subject,
			AuthorityKeyOrPrincipalDigest: principalDigest, AuthorizedObjectKind: objectKind,
			AuthorizedBodyDigest: bodyDigest, RequiredScopeDigest: scopeDigest,
			AuthorityResolverProfile: resolverProfile, FinalizedAuthorityStateRevision: sequence,
			FinalizedAuthorityStateRoot: principalDigest, ResolverFinalityEvidence: append([]byte(nil), raw...),
			AdmissionDomainID: domainID, AdmissionSequence: sequence, AdmissionTimeUnix: admittedAtUnix,
			EligibilityState: "eligible"})
	}
	sort.Slice(entries, func(i, j int) bool {
		left, _ := codec.Marshal(entries[i])
		right, _ := codec.Marshal(entries[j])
		return string(left) < string(right)
	})
	set := guarantor.AuthorityAdmissionEligibilityProofSetV1{SchemaVersion: 1, AdmittedActionDigest: actionDigest,
		AdmissionDomainID: domainID, AdmissionSequence: sequence, AdmissionTimeUnix: admittedAtUnix, Entries: entries}
	if err := guarantor.ValidateAuthorityAdmissionEligibilityProofSetV1(set); err != nil {
		return guarantor.AuthorityAdmissionEligibilityProofSetV1{}, err
	}
	return set, nil
}
