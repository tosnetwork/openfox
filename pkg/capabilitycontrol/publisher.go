package capabilitycontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	trusted "github.com/tosnetwork/tos-service-protocol/pkg/trustedcapability"
)

func (s *Store) revalidatePublisherLocked(entry *Entry, now uint64) error {
	if s.publisherVerifier == nil || entry == nil || entry.ArtifactObject == nil || entry.PublisherObject == nil || entry.PublisherEnvelope == nil {
		return errors.New("current publisher authority is unavailable")
	}
	var artifact trusted.ExecutableCapabilityArtifactBodyV1
	if err := trusted.DecodeBody(*entry.ArtifactObject, "artifact", &artifact); err != nil {
		return err
	}
	var publisher trusted.ArtifactPublisherEnvelopeBodyV1
	if err := trusted.DecodeBody(*entry.PublisherObject, "publisher-envelope", &publisher); err != nil {
		return err
	}
	if err := trusted.ValidatePublisherEnvelope(publisher, artifact, now); err != nil {
		return err
	}
	if err := trusted.VerifyAuthorization(*entry.PublisherEnvelope, *entry.PublisherObject, now, 0); err != nil {
		return err
	}
	artifactDigest, err := trusted.ObjectDigest(*entry.ArtifactObject)
	if err != nil || !bytes.Equal(artifactDigest, entry.ArtifactDigest) {
		return errors.New("stored publisher artifact identity changed")
	}
	publisherEnvelopeDigest, err := authorizationEnvelopeDigest(*entry.PublisherEnvelope)
	if err != nil {
		return err
	}
	observations, err := s.publisherVerifier.CurrentPublisherObservations(context.Background(), *entry.ArtifactObject, *entry.PublisherEnvelope, *entry.PublisherObject, now)
	if err != nil || len(observations) == 0 {
		return errors.New("fresh publisher revocation coverage is unavailable")
	}
	required, err := s.publisherVerifier.RequiredPublisherSources(context.Background(), s.state.CapabilityPolicyDigest)
	if err != nil || len(required) == 0 {
		return errors.New("policy-bound publisher revocation source set is unavailable")
	}
	requiredSet := make(map[string]struct{}, len(required))
	for _, source := range required {
		if len(source) != sha256.Size {
			return errors.New("policy-bound publisher revocation source identity is invalid")
		}
		requiredSet[hex.EncodeToString(source)] = struct{}{}
	}
	if entry.PublisherSourceHeads == nil {
		entry.PublisherSourceHeads = map[string]PublisherSourceHead{}
	}
	seen := map[string]struct{}{}
	for _, supplied := range observations {
		var observation trusted.PublisherRevocationObservationV1
		if err := trusted.DecodeBody(supplied.Object, "publisher-revocation-observation", &observation); err != nil {
			return err
		}
		if err := trusted.ValidatePublisherRevocationObservation(observation, artifact.PublisherSubject, artifactDigest, publisherEnvelopeDigest, now); err != nil {
			return err
		}
		if err := trusted.VerifyAuthorization(supplied.Envelope, supplied.Object, now, 0); err != nil ||
			supplied.Envelope.Body.AuthorityKind != "publisher-revocation-observation" ||
			!bytes.Equal(supplied.Envelope.Body.IssuerSubject.Identifier, observation.SourceID) {
			return errors.New("publisher revocation observation authorization is invalid")
		}
		source := hex.EncodeToString(observation.SourceID)
		if _, requiredSource := requiredSet[source]; !requiredSource {
			return errors.New("publisher revocation observation came from an untrusted source")
		}
		if _, duplicate := seen[source]; duplicate {
			return errors.New("duplicate publisher revocation source")
		}
		seen[source] = struct{}{}
		if prior, exists := entry.PublisherSourceHeads[source]; exists {
			if observation.SourceGeneration < prior.SourceGeneration || observation.ObservedGeneration < prior.ObservedGeneration {
				return errors.New("publisher revocation observation rollback")
			}
			if observation.SourceGeneration == prior.SourceGeneration && !bytes.Equal(observation.CheckpointRoot, prior.CheckpointRoot) {
				return errors.New("publisher revocation checkpoint equivocation")
			}
		}
		if observation.Revoked || observation.ObservedGeneration > publisher.RevocationGeneration {
			return errors.New("publisher or artifact has been revoked")
		}
		entry.PublisherSourceHeads[source] = PublisherSourceHead{SourceGeneration: observation.SourceGeneration,
			ObservedGeneration: observation.ObservedGeneration, CheckpointRoot: append([]byte(nil), observation.CheckpointRoot...)}
	}
	if len(seen) != len(requiredSet) {
		return errors.New("publisher revocation observations do not cover every policy-required source")
	}
	entry.PublisherEnvelopeExpiresAt = publisher.ExpiresAtUnix
	entry.PublisherRevocationGeneration = publisher.RevocationGeneration
	return nil
}
