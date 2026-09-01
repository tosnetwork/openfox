package earning

import (
	"errors"
	"sort"
	"sync"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type OutcomeAssertionKey struct {
	NetworkID               string `json:"network_id"`
	ActorAgentID            string `json:"actor_agent_id"`
	OperationID             string `json:"operation_id"`
	OperationEnvelopeDigest string `json:"operation_envelope_digest"`
}

type VerifiedOutcomeAssertion struct {
	Key              OutcomeAssertionKey                   `json:"key"`
	EventContentID   string                                `json:"event_content_id"`
	Body             commerce.OperationOutcomeEventBodyV1  `json:"body"`
	AssertionPayload []byte                                `json:"assertion_payload"`
	Manifest         commerce.OutcomeEvidenceManifestV1    `json:"evidence_manifest"`
	Extensions       commerce.OutcomeExtensionSetV1        `json:"extension_set"`
	Authority        commerce.OutcomeAuthorityAssessmentV1 `json:"authority"`
	// payloadEvidenceBound is deliberately unexported. Authority qualification
	// authenticates an evidence source, but an Adapter-specific verifier must
	// additionally prove that source describes the exact assertion payload
	// before economic or counterparty projections may consume it.
	payloadEvidenceBound bool
}

type OutcomeProjection struct {
	mu         sync.RWMutex
	assertions map[OutcomeAssertionKey]VerifiedOutcomeAssertion
	bySubject  map[string][]OutcomeAssertionKey
	byContent  map[string][]OutcomeAssertionKey
}

func NewOutcomeProjection() *OutcomeProjection {
	return &OutcomeProjection{assertions: make(map[OutcomeAssertionKey]VerifiedOutcomeAssertion),
		bySubject: make(map[string][]OutcomeAssertionKey), byContent: make(map[string][]OutcomeAssertionKey)}
}

func (projection *OutcomeProjection) Ingest(envelope commerce.AgentOperationEnvelopeV1, eventPayload, assertionPayload []byte,
	manifest commerce.OutcomeEvidenceManifestV1, extensions commerce.OutcomeExtensionSetV1,
	resolver commerce.AgentOperationAuthorityResolver, now time.Time) (VerifiedOutcomeAssertion, error) {
	if projection == nil {
		return VerifiedOutcomeAssertion{}, errors.New("outcome projection is unavailable")
	}
	body, err := commerce.VerifyOperationOutcomeEnvelopeV1(envelope, eventPayload, resolver, now.UTC())
	if err != nil {
		return VerifiedOutcomeAssertion{}, err
	}
	if err := verifyOperationOutcomeArtifactsForCurrentDependency(body, assertionPayload, manifest, extensions); err != nil {
		return VerifiedOutcomeAssertion{}, err
	}
	envelopeDigest, err := commerce.AgentOperationEnvelopeDigestV1(envelope)
	if err != nil {
		return VerifiedOutcomeAssertion{}, err
	}
	key := OutcomeAssertionKey{NetworkID: envelope.Body.NetworkID, ActorAgentID: envelope.Body.ActorAgentID,
		OperationID: envelope.Body.OperationID, OperationEnvelopeDigest: envelopeDigest}
	verified := VerifiedOutcomeAssertion{Key: key, EventContentID: envelope.Body.ObjectID, Body: body,
		AssertionPayload: append([]byte(nil), assertionPayload...), Manifest: manifest, Extensions: extensions,
		Authority: commerce.OutcomeAuthorityAssessmentV1{VerifiedEvidenceDigests: []string{}}}
	return projection.store(verified)
}

// IngestAuthorityQualified performs the separate historical authority pass.
// Carrier retention and outer self-signature verification never call this
// implicitly, so an issuer cannot promote its own assertion into accounting or
// learning truth merely by publishing it.
func (projection *OutcomeProjection) IngestAuthorityQualified(envelope commerce.AgentOperationEnvelopeV1,
	eventPayload, assertionPayload []byte, manifest commerce.OutcomeEvidenceManifestV1,
	extensions commerce.OutcomeExtensionSetV1, operationResolver commerce.AgentOperationAuthorityResolver,
	materials []commerce.OutcomeAuthorityProofMaterialV1, authorityVerifier commerce.OutcomeEvidenceAuthorityVerifierV1,
	now time.Time) (VerifiedOutcomeAssertion, error) {
	return projection.ingestAuthorityQualified(envelope, eventPayload, assertionPayload, manifest, extensions,
		operationResolver, materials, authorityVerifier, now, false)
}

func (projection *OutcomeProjection) ingestAuthorityQualified(envelope commerce.AgentOperationEnvelopeV1,
	eventPayload, assertionPayload []byte, manifest commerce.OutcomeEvidenceManifestV1,
	extensions commerce.OutcomeExtensionSetV1, operationResolver commerce.AgentOperationAuthorityResolver,
	materials []commerce.OutcomeAuthorityProofMaterialV1, authorityVerifier commerce.OutcomeEvidenceAuthorityVerifierV1,
	now time.Time, payloadEvidenceBound bool) (VerifiedOutcomeAssertion, error) {
	if projection == nil {
		return VerifiedOutcomeAssertion{}, errors.New("outcome projection is unavailable")
	}
	body, err := commerce.VerifyOperationOutcomeEnvelopeV1(envelope, eventPayload, operationResolver, now.UTC())
	if err != nil {
		return VerifiedOutcomeAssertion{}, err
	}
	if err := verifyOperationOutcomeArtifactsForCurrentDependency(body, assertionPayload, manifest, extensions); err != nil {
		return VerifiedOutcomeAssertion{}, err
	}
	authority, err := commerce.VerifyOperationOutcomeAuthorityV1(body, manifest, materials, authorityVerifier, now.UTC())
	if err != nil || !authority.AuthorityQualified {
		if err == nil {
			err = errors.New("outcome assertion profile is not authority-qualifiable")
		}
		return VerifiedOutcomeAssertion{}, err
	}
	envelopeDigest, err := commerce.AgentOperationEnvelopeDigestV1(envelope)
	if err != nil {
		return VerifiedOutcomeAssertion{}, err
	}
	verified := VerifiedOutcomeAssertion{Key: OutcomeAssertionKey{NetworkID: envelope.Body.NetworkID,
		ActorAgentID: envelope.Body.ActorAgentID, OperationID: envelope.Body.OperationID,
		OperationEnvelopeDigest: envelopeDigest}, EventContentID: envelope.Body.ObjectID, Body: body,
		AssertionPayload: append([]byte(nil), assertionPayload...), Manifest: manifest, Extensions: extensions,
		Authority: authority, payloadEvidenceBound: payloadEvidenceBound}
	return projection.store(verified)
}

func (projection *OutcomeProjection) store(verified VerifiedOutcomeAssertion) (VerifiedOutcomeAssertion, error) {
	key := verified.Key
	immutable := cloneVerifiedOutcomeAssertion(verified)
	projection.mu.Lock()
	defer projection.mu.Unlock()
	if prior, found := projection.assertions[key]; found {
		left, _ := codec.Marshal(prior)
		right, _ := codec.Marshal(immutable)
		if string(left) != string(right) {
			return VerifiedOutcomeAssertion{}, errors.New("exact outcome assertion key conflicts")
		}
		if immutable.payloadEvidenceBound && !prior.payloadEvidenceBound {
			prior.payloadEvidenceBound = true
			projection.assertions[key] = prior
		}
		return cloneVerifiedOutcomeAssertion(prior), nil
	}
	projection.assertions[key] = immutable
	subject := immutable.Body.PrimarySubjectRef.SubjectProfileURI + "\x00" + immutable.Body.PrimarySubjectRef.SubjectID
	projection.bySubject[subject] = append(projection.bySubject[subject], key)
	projection.byContent[immutable.EventContentID] = append(projection.byContent[immutable.EventContentID], key)
	return cloneVerifiedOutcomeAssertion(immutable), nil
}

func (projection *OutcomeProjection) BySubject(profileURI, subjectID string) []VerifiedOutcomeAssertion {
	if projection == nil {
		return nil
	}
	projection.mu.RLock()
	defer projection.mu.RUnlock()
	return projection.copyForKeys(projection.bySubject[profileURI+"\x00"+subjectID])
}

// ByContent intentionally returns all issuers. event_content_id is a content
// index and never a cross-issuer deduplication key.
func (projection *OutcomeProjection) ByContent(eventContentID string) []VerifiedOutcomeAssertion {
	if projection == nil {
		return nil
	}
	projection.mu.RLock()
	defer projection.mu.RUnlock()
	return projection.copyForKeys(projection.byContent[eventContentID])
}

func (projection *OutcomeProjection) copyForKeys(keys []OutcomeAssertionKey) []VerifiedOutcomeAssertion {
	ordered := append([]OutcomeAssertionKey(nil), keys...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].ActorAgentID != ordered[j].ActorAgentID {
			return ordered[i].ActorAgentID < ordered[j].ActorAgentID
		}
		if ordered[i].OperationID != ordered[j].OperationID {
			return ordered[i].OperationID < ordered[j].OperationID
		}
		return ordered[i].OperationEnvelopeDigest < ordered[j].OperationEnvelopeDigest
	})
	result := make([]VerifiedOutcomeAssertion, 0, len(ordered))
	for _, key := range ordered {
		if value, ok := projection.assertions[key]; ok {
			result = append(result, cloneVerifiedOutcomeAssertion(value))
		}
	}
	return result
}

func cloneVerifiedOutcomeAssertion(value VerifiedOutcomeAssertion) VerifiedOutcomeAssertion {
	clone := value
	clone.AssertionPayload = append([]byte(nil), value.AssertionPayload...)
	clone.Body.CausalPredecessorAssertionRefs = append([]commerce.OutcomeAssertionRefV1(nil), value.Body.CausalPredecessorAssertionRefs...)
	clone.Manifest.AuthorityProofRefs = append([]commerce.OutcomeAuthorityProofRefV1(nil), value.Manifest.AuthorityProofRefs...)
	clone.Manifest.EvidenceItems = append([]commerce.OutcomeEvidenceItemV1(nil), value.Manifest.EvidenceItems...)
	clone.Extensions.Extensions = append([]commerce.OutcomeExtensionV1(nil), value.Extensions.Extensions...)
	for index := range clone.Extensions.Extensions {
		clone.Extensions.Extensions[index].CanonicalValue = append([]byte(nil), value.Extensions.Extensions[index].CanonicalValue...)
	}
	clone.Authority.VerifiedEvidenceDigests = append([]string(nil), value.Authority.VerifiedEvidenceDigests...)
	return clone
}

type OutcomeLearningCut struct {
	Checkpoint VerifiedOutcomeAssertion   `json:"checkpoint"`
	Assertions []VerifiedOutcomeAssertion `json:"assertions"`
}

// LearningCut refuses to create a denominator from a success-only stream. A
// released, qualified cohort checkpoint is mandatory and assertions remain
// evidence inputs only; this function grants no model or execution authority.
func (projection *OutcomeProjection) LearningCut(checkpointKey OutcomeAssertionKey, explicitMembers ...OutcomeAssertionKey) (OutcomeLearningCut, error) {
	if projection == nil {
		return OutcomeLearningCut{}, errors.New("outcome projection is unavailable")
	}
	projection.mu.RLock()
	defer projection.mu.RUnlock()
	checkpoint, found := projection.assertions[checkpointKey]
	if !found || checkpoint.Body.EventKind != commerce.OutcomeCohortCheckpoint || checkpoint.Body.AssertionProfileURI != commerce.OutcomeProfileCohortCheckpoint {
		return OutcomeLearningCut{}, errors.New("verified cohort checkpoint is required for learning")
	}
	if !checkpoint.Authority.AuthorityQualified || !checkpoint.payloadEvidenceBound {
		return OutcomeLearningCut{}, errors.New("authority-qualified and source-bound cohort checkpoint is required for learning")
	}
	var payload commerce.CohortCheckpointPayloadV1
	if codec.Unmarshal(checkpoint.AssertionPayload, &payload) != nil || payload.AdmissionClosureState != "closed" {
		return OutcomeLearningCut{}, errors.New("learning cohort admission is not closed")
	}
	if len(explicitMembers) == 0 || uint64(len(explicitMembers)) != payload.EligibleCount {
		return OutcomeLearningCut{}, errors.New("learning cut requires the exact checkpoint member set")
	}
	refs := make([]commerce.OutcomeAssertionRefV1, len(explicitMembers))
	all := make([]VerifiedOutcomeAssertion, 0, len(explicitMembers))
	for index, key := range explicitMembers {
		value, found := projection.assertions[key]
		if !found || !value.Authority.AuthorityQualified || !value.payloadEvidenceBound {
			return OutcomeLearningCut{}, errors.New("learning cut member is absent, unqualified, or not source-bound")
		}
		refs[index] = commerce.OutcomeAssertionRefV1{NetworkID: key.NetworkID, ActorAgentID: key.ActorAgentID,
			OperationID: key.OperationID, OperationEnvelopeDigest: key.OperationEnvelopeDigest}
		all = append(all, value)
	}
	root, err := commerce.OutcomeAssertionSetRootV1(refs)
	if err != nil || root != payload.IncludedAttemptSetRoot {
		return OutcomeLearningCut{}, errors.New("learning cut member set does not match the checkpoint")
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Key.OperationEnvelopeDigest < all[j].Key.OperationEnvelopeDigest })
	checkpointClone := cloneVerifiedOutcomeAssertion(checkpoint)
	cloned := make([]VerifiedOutcomeAssertion, len(all))
	for index := range all {
		cloned[index] = cloneVerifiedOutcomeAssertion(all[index])
	}
	return OutcomeLearningCut{Checkpoint: checkpointClone, Assertions: cloned}, nil
}
