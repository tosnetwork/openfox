package earning

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type projectionOperationResolver map[string]ed25519.PublicKey

func (resolver projectionOperationResolver) AuthorizeAgentOperationKey(agentID string, _ commerce.ProfileRefV1,
	key ed25519.PublicKey, _ time.Time, proof []byte) error {
	if expected, found := resolver[agentID]; !found || !key.Equal(expected) || string(proof) != "proof" {
		return errors.New("operation key is not authorized")
	}
	return nil
}

func TestOutcomeProjectionDoesNotDeduplicateAssertionsAcrossIssuers(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	terminal := commerce.TerminalDispositionV1{TerminalScope: "execution", TerminalSubjectID: "execution:shared",
		OwningStateProfileURI: "tos.execution.state.v1", AuthoritativeResolutionDigest: testDigest, TerminalStateRevision: 1,
		SuccessorPolicyDigest: zeroSHA256Digest(), Disposition: "succeeded", FailureStage: "not_applicable", FailureCode: "not_applicable",
		RetryDisposition: "none", ResolvedAtUnix: uint64(now.Unix())}
	assertionPayload, err := codec.Marshal(terminal)
	if err != nil {
		t.Fatal(err)
	}
	manifest := commerce.OutcomeEvidenceManifestV1{SchemaVersion: 1, ManifestPurpose: "qualified_assertion",
		AuthorityProofRefs: []commerce.OutcomeAuthorityProofRefV1{
			{ProofProfileURI: "tos.proof.authority-time.v1", ObjectDigest: testDigest, CanonicalSize: 128},
			{ProofProfileURI: "tos.proof.issuer-qualification.v1", ObjectDigest: zeroSHA256Digest(), CanonicalSize: 128}},
		EvidenceItems: []commerce.OutcomeEvidenceItemV1{{EvidenceRole: "authoritative_resolution", EvidenceProfileURI: "tos.execution.resolution.v1",
			SourceObjectProfileURI: "tos.execution.state.v1", SourceObjectDigest: testDigest, ObjectDigest: testDigest, CanonicalSize: 128,
			MediaType: "application/cbor", IssuerDescriptor: "issuer:pseudonym", SubjectDescriptor: "execution:pseudonym",
			ClaimedObservationTimeUnix: uint64(now.Unix()), AuthorityTimeProofDigest: testDigest,
			IssuerQualificationProofDigest: zeroSHA256Digest(), Visibility: "local_private", AudienceDigest: testDigest,
			RetentionPolicyDigest: testDigest, RetrievalPolicyDigest: testDigest}}}
	if err := commerce.SortOutcomeAuthorityProofRefsV1(manifest.AuthorityProofRefs); err != nil {
		t.Fatal(err)
	}
	if err := commerce.SortOutcomeEvidenceItemsV1(manifest.EvidenceItems); err != nil {
		t.Fatal(err)
	}
	event, err := commerce.BuildOperationOutcomeEventV1(commerce.OutcomeTerminalObservation,
		commerce.OutcomeSubjectRefV1{SubjectProfileURI: "tos.subject.execution.v1", SubjectID: "execution:shared"}, nil,
		commerce.OutcomeProfileTerminal, assertionPayload, manifest, commerce.EmptyOutcomeExtensionSetV1())
	if err != nil {
		t.Fatal(err)
	}
	contentID, eventPayload, err := commerce.OperationOutcomeEventContentIDV1(event)
	if err != nil {
		t.Fatal(err)
	}

	projection := NewOutcomeProjection()
	resolver := projectionOperationResolver{}
	for index, actor := range []string{"agent:a", "agent:b"} {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		resolver[actor] = public
		body := commerce.AgentOperationBodyV1{SchemaVersion: 1, NetworkID: "tos:test", OpcodeNamespace: "OPERATION", OpcodeName: "OUTCOME", OpcodeVersion: 1,
			ActorAgentID: actor, AuthorizationRef: commerce.ProfileRefV1{ProfileURI: "tos.identity.agent-key.v1", ProfileVersion: 1, ProfileDigest: testDigest},
			AudienceDescriptor: "local-private", ObjectID: contentID, OrderingDomain: "outcome:independent", Sequence: uint64(index + 1), Epoch: 1,
			CreatedAtUnix: uint64(now.Unix()), PayloadProfile: commerce.OperationOutcomeProfileRefV1(), PayloadDigest: contentID, PayloadSize: uint64(len(eventPayload))}
		body.OperationID, err = commerce.DeriveAgentOperationIDV1(body)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := commerce.SignAgentOperationV1(body, actor, private, []byte("proof"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := projection.Ingest(envelope, eventPayload, assertionPayload, manifest, commerce.EmptyOutcomeExtensionSetV1(), resolver, now); err != nil {
			t.Fatal(err)
		}
	}
	byContent := projection.ByContent(contentID)
	if len(byContent) != 2 || byContent[0].Key.ActorAgentID == byContent[1].Key.ActorAgentID {
		t.Fatalf("cross-issuer assertions were collapsed: %+v", byContent)
	}
	originalByte := byContent[0].AssertionPayload[0]
	byContent[0].AssertionPayload[0] ^= 0xff
	manifest.EvidenceItems[0].ObjectDigest = zeroSHA256Digest()
	again := projection.ByContent(contentID)
	if again[0].AssertionPayload[0] != originalByte || again[0].Manifest.EvidenceItems[0].ObjectDigest != testDigest {
		t.Fatal("projection state was mutable through caller-owned slices")
	}
	if _, err := projection.LearningCut(byContent[0].Key); err == nil {
		t.Fatal("success-only stream was accepted as a learning denominator")
	}
}

func TestOutcomeLearningCutRequiresPayloadSourceBinding(t *testing.T) {
	memberKey := OutcomeAssertionKey{NetworkID: "tos:test", ActorAgentID: "agent:member",
		OperationID: testDigest, OperationEnvelopeDigest: zeroSHA256Digest()}
	memberRef := commerce.OutcomeAssertionRefV1{NetworkID: memberKey.NetworkID, ActorAgentID: memberKey.ActorAgentID,
		OperationID: memberKey.OperationID, OperationEnvelopeDigest: memberKey.OperationEnvelopeDigest}
	root, err := commerce.OutcomeAssertionSetRootV1([]commerce.OutcomeAssertionRefV1{memberRef})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := codec.Marshal(commerce.CohortCheckpointPayloadV1{
		AdmissionClosureState: "closed", EligibleCount: 1, IncludedAttemptSetRoot: root,
	})
	if err != nil {
		t.Fatal(err)
	}
	checkpointKey := OutcomeAssertionKey{NetworkID: "tos:test", ActorAgentID: "agent:checkpoint",
		OperationID: zeroSHA256Digest(), OperationEnvelopeDigest: testDigest}
	checkpoint := VerifiedOutcomeAssertion{Key: checkpointKey,
		Body: commerce.OperationOutcomeEventBodyV1{EventKind: commerce.OutcomeCohortCheckpoint,
			AssertionProfileURI: commerce.OutcomeProfileCohortCheckpoint}, AssertionPayload: payload,
		Authority: commerce.OutcomeAuthorityAssessmentV1{AuthorityQualified: true}}
	member := VerifiedOutcomeAssertion{Key: memberKey,
		Authority: commerce.OutcomeAuthorityAssessmentV1{AuthorityQualified: true}, payloadEvidenceBound: true}
	projection := NewOutcomeProjection()
	projection.assertions[checkpointKey] = checkpoint
	projection.assertions[memberKey] = member
	if _, err := projection.LearningCut(checkpointKey, memberKey); err == nil {
		t.Fatal("source-unbound cohort checkpoint created a learning cut")
	}
	checkpoint.payloadEvidenceBound = true
	member.payloadEvidenceBound = false
	projection.assertions[checkpointKey] = checkpoint
	projection.assertions[memberKey] = member
	if _, err := projection.LearningCut(checkpointKey, memberKey); err == nil {
		t.Fatal("source-unbound cohort member entered a learning cut")
	}
	member.payloadEvidenceBound = true
	projection.assertions[memberKey] = member
	if cut, err := projection.LearningCut(checkpointKey, memberKey); err != nil || len(cut.Assertions) != 1 {
		t.Fatalf("fully qualified source-bound learning cut was rejected: cut=%+v err=%v", cut, err)
	}
}
