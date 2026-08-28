package earning

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

func TestTwoDirectoryOutcomeCarrierInstancesRecoverAfterDatabaseLoss(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	_, authorityKey, _ := ed25519.GenerateKey(rand.Reader)
	authority, err := OpenPersonalAuthority(privateTempDir(t), "owner:source-loss", "agent:source-loss", "authority:source-loss", authorityKey, PortfolioLimits{})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	authority.now = func() time.Time { return now }
	fence, err := authority.AcquireWriter(context.Background(), "runtime:source-loss", []string{"operation.publish"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	directoryA, directoryB := filepath.Join(root, "carrier-a"), filepath.Join(root, "carrier-b")
	carrierA, err := OpenDirectoryOutcomeCarrier(directoryA, "carrier:a", authority)
	if err != nil {
		t.Fatal(err)
	}
	defer carrierA.Close()
	carrierB, err := OpenDirectoryOutcomeCarrier(directoryB, "carrier:b", authority)
	if err != nil {
		t.Fatal(err)
	}
	requestA := testDirectoryOutcomeRequest(t, "carrier:a", "a", now)
	requestB := requestA
	requestB.CarrierID = "carrier:b"
	requestB.CarrierProfile = commerce.ProfileRefV1{ProfileURI: "tos.carrier.directory-outcome.v1", ProfileVersion: 1,
		ProfileDigest: "sha256:" + strings.Repeat("b", 64)}
	engine := &Engine{OwnerID: "owner:source-loss", AgentID: "agent:source-loss", MandateDigest: testDigest,
		Gates: FeatureGates{Publication: true}, Authority: authority,
		OutcomePublicationSinks: map[string]OutcomePublicationSink{"carrier:a": carrierA, "carrier:b": carrierB},
		OutcomePublicationPolicy: PublicOutcomePublicationPolicyV1{AllowedAudiencePolicyDigests: map[string]struct{}{testDigest: {}},
			AllowedAssertionProfiles: map[string]struct{}{commerce.OutcomeProfileActionResolutionReference: {}}}, Now: func() time.Time { return now }}
	for _, request := range []commerce.OperationCarrierRequestV1{requestA, requestB} {
		resolution, err := engine.PublishOutcome(context.Background(), request, 1, fence)
		if err != nil || resolution.State != commerce.ActionTerminal {
			t.Fatalf("publish %s: %+v %v", request.CarrierID, resolution, err)
		}
	}
	if err := carrierB.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(directoryB); err != nil {
		t.Fatal(err)
	}
	carrierB, err = OpenDirectoryOutcomeCarrier(directoryB, "carrier:b", authority)
	if err != nil {
		t.Fatal(err)
	}
	defer carrierB.Close()
	engine.OutcomePublicationSinks["carrier:b"] = carrierB
	page, err := carrierA.SearchOutcomes(context.Background(), OutcomeCarrierQuery{Limit: 10})
	if err != nil || len(page.Results) != 1 {
		t.Fatalf("surviving Carrier page=%+v err=%v", page, err)
	}
	recovered := page.Results[0].Request
	recovered.CarrierID = requestB.CarrierID
	recovered.CarrierProfile = requestB.CarrierProfile
	resolution, err := engine.PublishOutcome(context.Background(), recovered, 1, fence)
	if err != nil || resolution.State != commerce.ActionTerminal {
		t.Fatalf("rebuild=%+v err=%v", resolution, err)
	}
	rebuilt, err := carrierB.SearchOutcomes(context.Background(), OutcomeCarrierQuery{Limit: 10})
	if err != nil || len(rebuilt.Results) != 1 || string(rebuilt.Results[0].Request.OperationEnvelope) != string(requestA.OperationEnvelope) {
		t.Fatalf("rebuilt page=%+v err=%v", rebuilt, err)
	}
	retainedPath := filepath.Join(directoryB, directoryOutcomeName(recovered.OperationEnvelopeDigest))
	raw, err := os.ReadFile(retainedPath)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 1
	if err = os.WriteFile(retainedPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = carrierB.SearchOutcomes(context.Background(), OutcomeCarrierQuery{Limit: 10}); err == nil {
		t.Fatal("directory Carrier silently omitted a corrupt retained outcome")
	}
	if _, err = engine.PublishOutcome(context.Background(), recovered, 1, fence); err == nil {
		t.Fatal("terminal outcome Action concealed missing or corrupt retained bytes")
	}
}

func TestEnginePrivateOutcomeUsesTypedNonChatMessengerEffect(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	_, authorityKey, _ := ed25519.GenerateKey(rand.Reader)
	authority, err := OpenPersonalAuthority(privateTempDir(t), "owner:private-outcome", "agent:source-loss", "authority", authorityKey, PortfolioLimits{})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	authority.now = func() time.Time { return now }
	fence, err := authority.AcquireWriter(context.Background(), "runtime:private-outcome", []string{"operation.private-send"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	carrierRequest := testDirectoryOutcomeRequest(t, "carrier:unused", "a", now)
	recipients := []string{"agent:recipient"}
	recipientDigest, err := codec.Digest("tos.messenger-recipient-set.v1", recipients)
	if err != nil {
		t.Fatal(err)
	}
	request := commerce.OperationPrivateRequestV1{SchemaVersion: 1, RecipientSetDigest: recipientDigest,
		RecipientAgentIDs: recipients, MembershipEpoch: 1, AudiencePolicyDigest: testDigest,
		OperationID: carrierRequest.OperationID, OperationEnvelopeDigest: carrierRequest.OperationEnvelopeDigest,
		ConversationScopeDigest: zeroSHA256Digest(), TransportProfile: commerce.ProfileRefV1{ProfileURI: "tos.messenger.operation-outcome.v1",
			ProfileVersion: 1, ProfileDigest: testDigest}, OperationEnvelope: carrierRequest.OperationEnvelope,
		EventPayload: carrierRequest.EventPayload, Artifacts: carrierRequest.Artifacts}
	sink := &exactSink{key: authorityKey.Public().(ed25519.PublicKey), now: now, resolutions: map[string]commerce.ActionResolution{}}
	engine := &Engine{OwnerID: "owner:private-outcome", AgentID: "agent:source-loss", MandateDigest: testDigest,
		Gates: FeatureGates{Contact: true}, Authority: authority, Sink: sink, Now: func() time.Time { return now }}
	resolution, err := engine.SendOutcomePrivate(context.Background(), request, 1, fence)
	if err != nil || resolution.State != commerce.ActionTerminal {
		t.Fatalf("private outcome resolution=%+v err=%v", resolution, err)
	}
	if len(sink.messages) != 1 || sink.messages[0].Kind != "operation.outcome" ||
		sink.messages[0].ContentType != "application/vnd.tos.operation-outcome-private+cbor" || len(sink.messages[0].RecipientAgentIDs) != 1 {
		t.Fatalf("outcome crossed the Messenger boundary as ordinary chat: %+v", sink.messages)
	}
	var decoded commerce.OperationPrivateRequestV1
	if codec.Unmarshal(sink.messages[0].Payload, &decoded) != nil || decoded.OperationEnvelopeDigest != request.OperationEnvelopeDigest {
		t.Fatal("Messenger did not receive the exact private outcome request")
	}
}

func testDirectoryOutcomeRequest(t *testing.T, carrierID, fill string, now time.Time) commerce.OperationCarrierRequestV1 {
	t.Helper()
	assertion, _ := codec.Marshal(commerce.ActionResolutionReferencePayloadV1{StableActionID: testDigest,
		ExactRequestDigest: zeroSHA256Digest(), AuthorizedActionDigest: testDigest, ActionResolutionDigest: zeroSHA256Digest(),
		ResolutionState: commerce.ActionTerminal, ResolutionStateRevision: 1})
	manifest := commerce.EmptyOutcomeEvidenceManifestV1("unverified_reference")
	extensions := commerce.EmptyOutcomeExtensionSetV1()
	event, err := commerce.BuildOperationOutcomeEventV1(commerce.OutcomeObservation,
		commerce.OutcomeSubjectRefV1{SubjectProfileURI: "tos.subject.semantic-action.v1", SubjectID: testDigest}, nil,
		commerce.OutcomeProfileActionResolutionReference, assertion, manifest, extensions)
	if err != nil {
		t.Fatal(err)
	}
	contentID, payload, err := commerce.OperationOutcomeEventContentIDV1(event)
	if err != nil {
		t.Fatal(err)
	}
	_, operationKey, _ := ed25519.GenerateKey(rand.Reader)
	body := commerce.AgentOperationBodyV1{SchemaVersion: 1, NetworkID: "tos:test", OpcodeNamespace: "OPERATION", OpcodeName: "OUTCOME", OpcodeVersion: 1,
		ActorAgentID: "agent:source-loss", AuthorizationRef: commerce.ProfileRefV1{ProfileURI: "tos.identity.test.v1", ProfileVersion: 1, ProfileDigest: testDigest},
		AudienceDescriptor: "public", ObjectID: contentID, OrderingDomain: zeroSHA256Digest(), Epoch: 1, Sequence: 1,
		CreatedAtUnix: uint64(now.Unix()), PayloadProfile: commerce.OperationOutcomeProfileRefV1(), PayloadDigest: contentID, PayloadSize: uint64(len(payload))}
	body.OperationID, err = commerce.DeriveAgentOperationIDV1(body)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := commerce.SignAgentOperationV1(body, body.ActorAgentID, operationKey, []byte("historical-proof"))
	if err != nil {
		t.Fatal(err)
	}
	envelopeBytes, envelopeDigest, err := commerce.MarshalAgentOperationEnvelopeV1(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return commerce.OperationCarrierRequestV1{SchemaVersion: 1, CarrierID: carrierID,
		CarrierProfile: commerce.ProfileRefV1{ProfileURI: "tos.carrier.directory-outcome.v1", ProfileVersion: 1,
			ProfileDigest: "sha256:" + strings.Repeat(fill, 64)}, AudiencePolicyDigest: testDigest,
		OperationID: body.OperationID, OperationEnvelopeDigest: envelopeDigest, OperationEnvelope: envelopeBytes, EventPayload: payload,
		Artifacts: commerce.OperationOutcomeArtifactBundleV1{AssertionPayload: assertion, EvidenceManifest: manifest,
			ExtensionSet: extensions, AuthorityProofs: []commerce.OutcomeAuthorityProofMaterialV1{}}}
}
