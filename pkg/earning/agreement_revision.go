package earning

import (
	"errors"
	"fmt"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

// AgreementRevisionFunc changes a private deep copy of the complete
// predecessor body. It must describe exact replacement terms; the builder adds
// lineage and recomputes every non-circular authorization target afterwards.
type AgreementRevisionFunc func(*commerce.AgentAgreementBody) error

// BuildAgreementRevision creates one complete, predecessor-bound successor.
// Agreement ID, network, consecutive version, and predecessor digest are
// enforced by the lineage validator after the caller's exact price/scope
// changes have been applied.
func BuildAgreementRevision(predecessor commerce.AgentAgreementBody,
	revise AgreementRevisionFunc) (commerce.AgentAgreementBody, error) {
	if err := commerce.ValidateAgreementBody(predecessor); err != nil {
		return commerce.AgentAgreementBody{}, err
	}
	if revise == nil || predecessor.Version == ^uint64(0) {
		return commerce.AgentAgreementBody{}, errors.New("Agreement revision is invalid")
	}
	canonical, err := codec.Marshal(predecessor)
	if err != nil {
		return commerce.AgentAgreementBody{}, err
	}
	var successor commerce.AgentAgreementBody
	if err := codec.Unmarshal(canonical, &successor); err != nil {
		return commerce.AgentAgreementBody{}, err
	}
	predecessorDigest, err := commerce.AgreementBodyDigest(predecessor)
	if err != nil {
		return commerce.AgentAgreementBody{}, err
	}
	successor.Version = predecessor.Version + 1
	successor.PredecessorAgreementDigest = predecessorDigest
	if err := revise(&successor); err != nil {
		return commerce.AgentAgreementBody{}, err
	}
	for index := range successor.AuthorizationPredicates {
		successor.AuthorizationPredicates[index].EvidenceTargetProjectionDigest = ""
	}
	successor, err = commerce.PrepareAgreementTargets(successor)
	if err != nil {
		return commerce.AgentAgreementBody{}, err
	}
	if err := validateAgreementSuccessor(predecessor, successor); err != nil {
		return commerce.AgentAgreementBody{}, err
	}
	return successor, nil
}

// validateAgreementAuthorizationTimeForCurrentDependency mirrors the protocol
// validity checks while OpenFox remains pinned to the previous released
// module. Structural body validation alone never permits evidence to form an
// Agreement before valid-from, at/after expiry, or with a signed acceptance
// that outlives the body-bound predicate group.
func validateAgreementAuthorizationTimeForCurrentDependency(agreement commerce.AgentAgreement, now time.Time) error {
	if now.IsZero() {
		return errors.New("Agreement authorization time is unavailable")
	}
	now = now.UTC()
	if now.Before(time.Unix(int64(agreement.Body.ValidFromUnix), 0).UTC()) ||
		!now.Before(time.Unix(int64(agreement.Body.ExpiresAtUnix), 0).UTC()) {
		return errors.New("Agreement body is outside its authorization validity window")
	}
	predicates := make(map[string]commerce.AgreementAuthorizationPredicate, len(agreement.Body.AuthorizationPredicates))
	for _, predicate := range agreement.Body.AuthorizationPredicates {
		if predicate.ValidFromUnix != 0 && now.Before(time.Unix(int64(predicate.ValidFromUnix), 0).UTC()) ||
			!now.Before(time.Unix(int64(predicate.ExpiresAtUnix), 0).UTC()) {
			return errors.New("Agreement authorization predicate is outside its validity window")
		}
		predicates[predicate.PredicateID] = predicate
	}
	for _, evidence := range agreement.AuthorizationEvidence {
		if evidence.EvidenceProfileURI != commerce.EvidenceProfileAgentSignature &&
			evidence.EvidenceProfileURI != commerce.EvidenceProfileAuthoritySignature {
			continue
		}
		acceptance, err := commerce.DecodeSignedAgreementAcceptance(evidence.Evidence)
		if err != nil || acceptance.Body.ExpiresAtUnix > agreement.Body.ExpiresAtUnix {
			return errors.New("Agreement acceptance exceeds the body validity window")
		}
		for _, predicateID := range evidence.PredicateIDs {
			predicate, found := predicates[predicateID]
			if !found || acceptance.Body.ExpiresAtUnix > predicate.ExpiresAtUnix {
				return errors.New("Agreement acceptance exceeds its predicate validity window")
			}
		}
	}
	return nil
}

// validateAgreementSuccessor mirrors agentcommerce.ValidateAgreementSuccessor
// while OpenFox remains pinned to the last released protocol module. It can be
// replaced by the public helper when that module revision is published.
func validateAgreementSuccessor(predecessor, successor commerce.AgentAgreementBody) error {
	if err := commerce.ValidateAgreementBody(predecessor); err != nil {
		return fmt.Errorf("agreement predecessor body: %w", err)
	}
	if err := commerce.ValidateAgreementBody(successor); err != nil {
		return fmt.Errorf("agreement successor body: %w", err)
	}
	if successor.AgreementID != predecessor.AgreementID {
		return errors.New("agreement successor changes Agreement ID")
	}
	if predecessor.Version == ^uint64(0) || successor.Version != predecessor.Version+1 {
		return errors.New("agreement successor version is not consecutive")
	}
	digest, err := commerce.AgreementBodyDigest(predecessor)
	if err != nil {
		return err
	}
	if successor.PredecessorAgreementDigest != digest {
		return errors.New("agreement successor does not bind the exact predecessor")
	}
	if successor.NetworkContext != predecessor.NetworkContext {
		return errors.New("agreement successor changes network context")
	}
	return nil
}
