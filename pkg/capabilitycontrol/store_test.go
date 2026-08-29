package capabilitycontrol

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	trusted "github.com/tosnetwork/tos-service-protocol/pkg/trustedcapability"
)

type memoryMonotonic struct {
	revision               uint64
	digest                 []byte
	acquisitionTransitions []bool
}

func (m *memoryMonotonic) ResolveInstallationID(context.Context, trusted.DomainKind, []byte, []byte, []byte) ([]byte, error) {
	return bytes.Repeat([]byte{0x42}, 16), nil
}

func (m *memoryMonotonic) Read(_ context.Context, _ []byte) (uint64, []byte, error) {
	return m.revision, append([]byte(nil), m.digest...), nil
}

type fixedTrustedClock struct{ at time.Time }

func (clock fixedTrustedClock) Now(context.Context) (time.Time, error) { return clock.at, nil }

type evidenceTrustedClock struct {
	at    time.Time
	epoch uint64
}

func (clock *evidenceTrustedClock) Now(context.Context) (time.Time, error) { return clock.at, nil }
func (clock *evidenceTrustedClock) ObserveTrustedTime(context.Context) (TrustedTimeEvidenceObservation, error) {
	evidence := sha256.Sum256([]byte("signed-time-evidence"))
	return TrustedTimeEvidenceObservation{UnixSeconds: uint64(clock.at.Unix()), Epoch: clock.epoch, EvidenceDigest: evidence[:]}, nil
}

func TestStoreRejectsTrustedTimeEpochRollback(t *testing.T) {
	clock := &evidenceTrustedClock{at: time.Unix(100, 0), epoch: 4}
	store, err := OpenProductionInDomain(t.TempDir(), trusted.DomainOwnerLocal, []byte("owner"), []byte("owner"), []byte("agent"), &memoryMonotonic{}, clock, allowInstallation{}, allowPublisher{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if observation, err := store.ObserveTrustedTime(t.Context()); err != nil || observation.Epoch != 4 {
		t.Fatalf("signed time observation failed: %#v %v", observation, err)
	}
	clock.epoch = 3
	if _, err := store.ObserveTrustedTime(t.Context()); err == nil {
		t.Fatal("trusted time epoch rollback was accepted")
	}
}

func TestPromotionRequiresGeneratorSignatureOverExactBody(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, ed25519.SeedSize))
	keyRef := trusted.Ed25519KeyReference(key.Public().(ed25519.PublicKey))
	agentID := []byte("agent")
	policyDigest := bytes.Repeat([]byte{0x32}, sha256.Size)
	promotion := trusted.PromotionAuthorityBodyV1{SchemaVersion: 1, GeneratorIdentityDigest: keyRef, AgentID: agentID}
	signedBody := trusted.EvaluationEvidenceV1{SchemaVersion: 1, EvidenceKind: "candidate-origin", CandidateDigest: bytes.Repeat([]byte{1}, 32),
		PermissionDigest: bytes.Repeat([]byte{2}, 32), PolicyDigest: policyDigest, ProducerDigest: keyRef,
		ContentCommitment: bytes.Repeat([]byte{3}, 32), CreatedAtUnix: 90, ExpiresAtUnix: 200}
	object, err := trusted.NewObject(trusted.DomainOwnerLocal, []byte("owner"), "evaluation-evidence", signedBody)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := trusted.ObjectDigest(object)
	authorizationBody := trusted.ProfileAuthorizationEnvelopeBodyV1{SchemaVersion: 1, DomainKind: object.DomainKind, DomainID: object.DomainID,
		BodyKind: object.ObjectKind, BodyProfileURI: object.ProfileURI, BodyProfileVersion: 1, BodyDigest: digest, OwnerID: []byte("owner"), AgentID: &agentID,
		AuthorityKind: "capability-generator", AuthorityID: bytes.Repeat([]byte{0x33}, 16), AuthorityRevision: 0, AuthorityEpoch: 7,
		PolicyRevision: 2, PolicyDigest: policyDigest, IssuerSubject: trusted.TypedAuthoritySubjectV1{Kind: "verification-key", Namespace: trusted.Ed25519ProofProfile, Identifier: keyRef},
		ProofProfileURI: trusted.Ed25519ProofProfile, ProofProfileVersion: 1, NotBeforeUnix: 90, ExpiresAtUnix: 200, ExtensionsDigest: bytes.Repeat([]byte{0}, sha256.Size)}
	proof := trusted.ProfileAuthorizationProofV1{Algorithm: trusted.Ed25519ProofProfile, KeyReference: keyRef, NotBeforeUnix: 90, ExpiresAtUnix: 200}
	envelope, err := trusted.SignAuthorization(authorizationBody, []trusted.ProfileAuthorizationProofV1{proof}, []ed25519.PrivateKey{key})
	if err != nil {
		t.Fatal(err)
	}
	store := &Store{state: DurableState{OwnerID: []byte("owner"), AgentID: agentID, AuthorityEpoch: 7, PolicyRevision: 2, PolicyDigest: policyDigest,
		AuthorizedSubjects: map[string][][]byte{"capability-generator": {keyRef}}}}
	if err := store.verifyPromotionGeneratorLocked(envelope, object, promotion, 100); err != nil {
		t.Fatal(err)
	}
	promotion.GeneratorIdentityDigest = bytes.Repeat([]byte{0x34}, sha256.Size)
	if err := store.verifyPromotionGeneratorLocked(envelope, object, promotion, 100); err == nil {
		t.Fatal("an approver-supplied generator label was accepted without that generator's signature")
	}
}

type allowInstallation struct{}

func (allowInstallation) VerifyCapabilityInstallation(context.Context, trusted.CapabilityInstallationTransactionV1) error {
	return nil
}

type allowPublisher struct{}

func (allowPublisher) RequiredPublisherSources(context.Context, []byte) ([][]byte, error) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{99}, ed25519.SeedSize))
	return [][]byte{trusted.Ed25519KeyReference(key.Public().(ed25519.PublicKey))}, nil
}

func (allowPublisher) CurrentPublisherObservations(_ context.Context, artifactObject trusted.ProfileObjectV1, publisherAuthorization trusted.ProfileAuthorizationEnvelopeV1, _ trusted.ProfileObjectV1, now uint64) ([]PublisherObservation, error) {
	artifactDigest, _ := trusted.ObjectDigest(artifactObject)
	publisherEnvelopeObject, _ := trusted.NewObject(trusted.DomainKind(publisherAuthorization.Body.DomainKind), publisherAuthorization.Body.DomainID, "authorization-envelope", publisherAuthorization)
	publisherEnvelopeDigest, _ := trusted.ObjectDigest(publisherEnvelopeObject)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{99}, ed25519.SeedSize))
	keyRef := trusted.Ed25519KeyReference(key.Public().(ed25519.PublicKey))
	var artifact trusted.ExecutableCapabilityArtifactBodyV1
	_ = trusted.DecodeBody(artifactObject, "artifact", &artifact)
	body := trusted.PublisherRevocationObservationV1{SchemaVersion: 1, PublisherSubject: artifact.PublisherSubject,
		ArtifactVersionDigest: artifactDigest, PublisherEnvelopeDigest: publisherEnvelopeDigest, ObservedGeneration: 1,
		SourceID: keyRef, SourceGeneration: 1, CheckpointRoot: bytes.Repeat([]byte{71}, sha256.Size), ObservedAtUnix: now, ExpiresAtUnix: now + 100}
	object, _ := trusted.NewObject(trusted.DomainKind(artifactObject.DomainKind), artifactObject.DomainID, "publisher-revocation-observation", body)
	digest, _ := trusted.ObjectDigest(object)
	authorizationBody := trusted.ProfileAuthorizationEnvelopeBodyV1{SchemaVersion: 1, DomainKind: object.DomainKind, DomainID: object.DomainID,
		BodyKind: object.ObjectKind, BodyProfileURI: object.ProfileURI, BodyProfileVersion: 1, BodyDigest: digest, OwnerID: []byte("publisher-status"),
		AuthorityKind: "publisher-revocation-observation", AuthorityID: bytes.Repeat([]byte{7}, 16), AuthorityEpoch: 1, PolicyRevision: 1,
		PolicyDigest: bytes.Repeat([]byte{8}, sha256.Size), IssuerSubject: trusted.TypedAuthoritySubjectV1{Kind: "verification-key", Namespace: trusted.Ed25519ProofProfile, Identifier: keyRef},
		ProofProfileURI: trusted.Ed25519ProofProfile, ProofProfileVersion: 1, NotBeforeUnix: now, ExpiresAtUnix: now + 100, ExtensionsDigest: bytes.Repeat([]byte{0}, sha256.Size)}
	proof := trusted.ProfileAuthorizationProofV1{Algorithm: trusted.Ed25519ProofProfile, KeyReference: keyRef, NotBeforeUnix: now, ExpiresAtUnix: now + 100}
	envelope, _ := trusted.SignAuthorization(authorizationBody, []trusted.ProfileAuthorizationProofV1{proof}, []ed25519.PrivateKey{key})
	return []PublisherObservation{{Object: object, Envelope: envelope}}, nil
}

func (m *memoryMonotonic) Check(_ context.Context, _ []byte, revision uint64, digest []byte) error {
	if m.digest == nil && revision == 0 {
		m.digest = append([]byte(nil), digest...)
		return nil
	}
	if m.revision != revision || !bytes.Equal(m.digest, digest) {
		return errors.New("monotonic state mismatch")
	}
	return nil
}

func (m *memoryMonotonic) CompareAndAdvance(_ context.Context, _ []byte, prior, next uint64, digest []byte) error {
	if prior != m.revision || next != prior+1 {
		return errors.New("monotonic compare-and-advance conflict")
	}
	m.revision = next
	m.digest = append([]byte(nil), digest...)
	return nil
}

func (m *memoryMonotonic) CompareAndAdvanceCapabilityControl(ctx context.Context, scope []byte, prior, next uint64, digest, _, _ []byte, accepting bool) error {
	if err := m.CompareAndAdvance(ctx, scope, prior, next, digest); err != nil {
		return err
	}
	m.acquisitionTransitions = append(m.acquisitionTransitions, accepting)
	return nil
}

func (m *memoryMonotonic) AdmitCapabilityAcquisition(_ context.Context, request CapabilityAcquisitionRequest) error {
	if request.SchemaVersion != 1 || len(request.OwnerID) == 0 || len(request.AgentID) == 0 || len(request.LedgerID) != 16 ||
		(request.Phase != "reserve" && request.Phase != "commit") || request.NextRevision != request.PriorRevision+1 {
		return errors.New("invalid capability acquisition transition")
	}
	return nil
}

func TestOwnerPauseAtomicallyClosesExternalAcquisitionFence(t *testing.T) {
	authority := &memoryMonotonic{}
	store, err := OpenProductionInDomain(t.TempDir(), trusted.DomainOwnerLocal, []byte("owner"), []byte("owner"), []byte("agent"),
		authority, fixedTrustedClock{time.Unix(100, 0)}, allowInstallation{}, allowPublisher{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	store.state.Initialized = true
	parameters, err := trusted.MarshalBody(OwnerCommandParametersV1{SchemaVersion: 1, ArtifactDigest: []byte{}, SessionDigest: []byte{}})
	if err != nil {
		t.Fatal(err)
	}
	agent := []byte("agent")
	effect := trusted.OwnerCommandEffectV1{DomainKind: uint8(trusted.DomainOwnerLocal), DomainID: []byte("owner"), OwnerID: []byte("owner"), AgentID: &agent,
		CommandKind: "owner.pause", TargetObjectKind: "agent", TargetObjectID: agent, ControlScopeGeneration: 1, ExpectedTargetRevision: 1}
	attempt := trusted.OwnerCommandAuthorizationAttemptV1{ActionID: bytes.Repeat([]byte{91}, 32), ExactRequestDigest: bytes.Repeat([]byte{92}, 32)}
	if _, err := store.applyOwnerCommand(effect, attempt, parameters, bytes.Repeat([]byte{93}, 32)); err != nil {
		t.Fatal(err)
	}
	if len(authority.acquisitionTransitions) != 1 || authority.acquisitionTransitions[0] {
		t.Fatal("owner pause did not atomically advance the external acquisition state to fenced")
	}
	if err := store.requireNewCapabilityWorkLocked(); err == nil {
		t.Fatal("owner pause left new admission/promotion/installation work enabled")
	}
}

func TestCleanStoreCreatesPrivateObjectParentAndMaterializes(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("handle-relative materializer is currently Linux-only")
	}
	root := filepath.Join(t.TempDir(), "control")
	store, err := Open(root, []byte("owner"), []byte("agent"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	objects := filepath.Join(root, "objects")
	if info, err := os.Lstat(objects); err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("clean object parent is not private and pinned: %v %v", info, err)
	}
	source := filepath.Join(t.TempDir(), "candidate")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "SKILL.md"), []byte("clean install"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(objects, strings.Repeat("a", 64))
	if err := copyTreeNoFollow(source, target); err != nil {
		t.Fatalf("first materialization on a clean store failed: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(target, "SKILL.md")); err != nil || string(got) != "clean install" {
		t.Fatalf("clean materialization bytes = %q, %v", got, err)
	}
}

func TestLegacyImportIsFailClosedAndDurable(t *testing.T) {
	root := t.TempDir()
	skills := filepath.Join(root, "skills", "review")
	if err := os.MkdirAll(skills, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skills, "SKILL.md"), []byte("# review"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := OpenProductionInDomain(filepath.Join(root, "control"), trusted.DomainOwnerLocal, []byte("owner"), []byte("owner"), []byte("agent"), &memoryMonotonic{}, fixedTrustedClock{time.Unix(100, 0)}, allowInstallation{}, allowPublisher{})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ImportLegacySkillRoots([]string{filepath.Join(root, "skills")}, time.Unix(100, 0)); err != nil {
		t.Fatal(err)
	}
	state := store.Snapshot()
	if len(state.Entries) != 1 {
		t.Fatalf("entries=%d", len(state.Entries))
	}
	for _, entry := range state.Entries {
		if entry.State != StateUnverifiedLegacy {
			t.Fatalf("state=%s", entry.State)
		}
		request := StartRequest{}
		request.Binding.ArtifactVersionDigest = entry.ArtifactDigest
		if _, err := store.PrepareUse(request); !errors.Is(err, ErrUnverifiedLegacy) && err == nil {
			t.Fatal("legacy capability was not rejected")
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(filepath.Join(root, "control"), []byte("owner"), []byte("agent"))
	if err != nil {
		t.Fatal(err)
	}
	if len(reopened.Snapshot().Entries) != 1 {
		t.Fatal("legacy projection was not durable")
	}
	_ = reopened.Close()
}

func TestVerifyCandidateRequiresCompletePublisherAndManifestClosure(t *testing.T) {
	root := t.TempDir()
	candidate := filepath.Join(root, "candidate")
	if err := os.Mkdir(candidate, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(candidate, "SKILL.md"), []byte("---\nname: bounded\ndescription: test\n---\n# Bounded\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, err := BuildContentManifest(candidate)
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenProductionInDomain(filepath.Join(root, "control"), trusted.DomainOwnerLocal, []byte("owner"), []byte("owner"), []byte("agent"), &memoryMonotonic{}, fixedTrustedClock{time.Unix(100, 0)}, allowInstallation{}, allowPublisher{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.registerQuarantined(Entry{ObservedContentDigest: manifest.ClosureRoot}, candidate, time.Unix(100, 0)); err != nil {
		t.Fatal(err)
	}
	d := func(value byte) []byte { return bytes.Repeat([]byte{value}, sha256.Size) }
	domain := []byte("owner")
	contentObject, err := trusted.NewObject(trusted.DomainOwnerLocal, domain, "content-manifest", manifest)
	if err != nil {
		t.Fatal(err)
	}
	contentDigest, _ := trusted.ObjectDigest(contentObject)
	entrypoint := trusted.CapabilityEntrypointDescriptorV1{SchemaVersion: 1, ExecutableObjectDigest: d(1), WorkingDirectoryPolicyDigest: d(2), RuntimeSubjectDigest: d(3),
		EnvironmentNameSetDigest: d(4), EnvironmentValueSourceDigest: d(5), FilesystemRootSetDigest: d(6), ProcessModelDigest: d(7), SandboxProfileDigest: d(8), Arguments: []string{}}
	entrypointObject, err := trusted.NewObject(trusted.DomainOwnerLocal, domain, "entrypoint-descriptor", entrypoint)
	if err != nil {
		t.Fatal(err)
	}
	entrypointDigest, _ := trusted.ObjectDigest(entrypointObject)
	seed := bytes.Repeat([]byte{42}, ed25519.SeedSize)
	key := ed25519.NewKeyFromSeed(seed)
	keyRef := trusted.Ed25519KeyReference(key.Public().(ed25519.PublicKey))
	artifact := trusted.ExecutableCapabilityArtifactBodyV1{SchemaVersion: 1, ArtifactKind: "skill", ArtifactNamespace: "test", ArtifactName: "bounded", ArtifactVersion: "1",
		PublisherSubject: trusted.TypedAuthoritySubjectV1{Kind: "verification-key", Namespace: trusted.Ed25519ProofProfile, Identifier: keyRef}, PublisherAuthorityProfile: d(9),
		SourceDescriptorDigest: d(10), ContentManifestDigest: contentDigest, EntrypointDescriptorDigest: entrypointDigest, LicenseManifestDigest: d(11),
		StandardsProfileSetDigest: d(12), CompatibilityManifestDigest: d(13), SupplyChainEvidenceDigest: d(14), CreatedAtUnix: 90, Extensions: [][]byte{}}
	pre, err := trusted.ArtifactPreManifestDigest(artifact)
	if err != nil {
		t.Fatal(err)
	}
	permission := trusted.CapabilityPermissionManifestV1{SchemaVersion: 1, ArtifactPreManifestDigest: pre, ToolCapabilities: []string{}, ProcessCapabilities: []string{},
		FilesystemCapabilities: []trusted.FilesystemCapabilityV1{}, NetworkCapabilities: []trusted.NetworkCapabilityV1{}, CredentialCapabilities: []trusted.CredentialCapabilityV1{}, DataClassesRead: []string{}, DataClassesWrite: []string{},
		DisclosureCapabilities: []trusted.DisclosureCapabilityV1{}, UploadCapabilities: []trusted.UploadCapabilityV1{}, DestructiveCapabilities: []string{},
		ResourceCeiling: trusted.ResourceCeilingV1{CPUMillis: 1, MemoryBytes: 1, StorageBytes: 1, RuntimeMillis: 1}, DirectCostCeiling: "0", ConcurrencyCeiling: 1,
		RetentionPolicy: trusted.RetentionPolicyV1{MaximumRetentionSeconds: 1, DeleteOnTerminal: true, EvidenceOnlyAfterDelete: true},
		LoggingPolicy:   trusted.LoggingPolicyV1{AllowedDataClasses: []string{}, MaximumBytes: 1, RedactionRequired: true}, Extensions: [][]byte{}}
	permissionObject, err := trusted.NewObject(trusted.DomainOwnerLocal, domain, "permission-manifest", permission)
	if err != nil {
		t.Fatal(err)
	}
	permissionDigest, _ := trusted.ObjectDigest(permissionObject)
	artifact.PermissionManifestDigest = &permissionDigest
	artifactObject, err := trusted.NewObject(trusted.DomainOwnerLocal, domain, "artifact", artifact)
	if err != nil {
		t.Fatal(err)
	}
	publisher := trusted.ArtifactPublisherEnvelopeBodyV1{SchemaVersion: 1, ArtifactPreManifestDigest: pre, ArtifactKind: artifact.ArtifactKind,
		ArtifactNamespace: artifact.ArtifactNamespace, ArtifactName: artifact.ArtifactName, ArtifactVersion: artifact.ArtifactVersion, PublisherSubject: artifact.PublisherSubject,
		PermissionManifestDigest: &permissionDigest, ContentManifestDigest: contentDigest, EntrypointDescriptorDigest: entrypointDigest, CreatedAtUnix: 90,
		NotBeforeUnix: 90, ExpiresAtUnix: 200, RevocationGeneration: 1, Extensions: [][]byte{}}
	publisherObject, err := trusted.NewObject(trusted.DomainOwnerLocal, domain, "publisher-envelope", publisher)
	if err != nil {
		t.Fatal(err)
	}
	publisherDigest, _ := trusted.ObjectDigest(publisherObject)
	authBody := trusted.ProfileAuthorizationEnvelopeBodyV1{SchemaVersion: 1, DomainKind: uint8(trusted.DomainOwnerLocal), DomainID: domain, BodyKind: "publisher-envelope",
		BodyProfileURI: trusted.ProfileURI, BodyProfileVersion: 1, BodyDigest: publisherDigest, OwnerID: []byte("publisher"), AuthorityKind: "artifact-publisher",
		AuthorityID: bytes.Repeat([]byte{1}, 16), AuthorityEpoch: 1, PolicyDigest: d(15), IssuerSubject: artifact.PublisherSubject,
		ProofProfileURI: trusted.Ed25519ProofProfile, ProofProfileVersion: 1, NotBeforeUnix: 90, ExpiresAtUnix: 200, ExtensionsDigest: d(0)}
	authorization, err := trusted.SignAuthorization(authBody, []trusted.ProfileAuthorizationProofV1{{Algorithm: trusted.Ed25519ProofProfile, NotBeforeUnix: 90, ExpiresAtUnix: 200}}, []ed25519.PrivateKey{key})
	if err != nil {
		t.Fatal(err)
	}
	request := VerificationRequest{QuarantineDigest: manifest.ClosureRoot, ArtifactObject: artifactObject, ContentManifestObject: contentObject,
		EntrypointObject: entrypointObject, PermissionObject: &permissionObject, PublisherObject: publisherObject, PublisherAuthorization: authorization}
	bad := request
	bad.PublisherAuthorization.Body.IssuerSubject.Identifier = d(99)
	if err := store.VerifyCandidate(bad); err == nil {
		t.Fatal("forged publisher subject was accepted")
	}
	artifactVersionDigest, err := trusted.ObjectDigest(artifactObject)
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.state.Tombstones[hex.EncodeToString(artifactVersionDigest)] = Tombstone{ArtifactDigest: artifactVersionDigest, DeletionGeneration: 1}
	store.mu.Unlock()
	if err := store.VerifyCandidate(request); err == nil {
		t.Fatal("tombstoned artifact was resurrected through quarantine verification")
	}
	store.mu.Lock()
	delete(store.state.Tombstones, hex.EncodeToString(artifactVersionDigest))
	store.mu.Unlock()
	if err := store.VerifyCandidate(request); err != nil {
		t.Fatal(err)
	}
	state := store.Snapshot()
	if len(state.Entries) != 1 {
		t.Fatalf("entries=%d", len(state.Entries))
	}
	for _, verified := range state.Entries {
		if verified.State != StateVerified || len(verified.ArtifactDigest) != sha256.Size || verified.PromotionRequired {
			t.Fatalf("unexpected verified state: %#v", verified)
		}
	}
}

func TestQuarantineRequiresExactDigestAndPauseAdvancesGeneration(t *testing.T) {
	root := t.TempDir()
	candidate := filepath.Join(root, "candidate")
	if err := os.Mkdir(candidate, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(candidate, "SKILL.md"), []byte("bounded"), 0o600); err != nil {
		t.Fatal(err)
	}
	digest, err := HashTree(candidate)
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenProductionInDomain(filepath.Join(root, "control"), trusted.DomainOwnerLocal, []byte("owner"), []byte("owner"), []byte("agent"), &memoryMonotonic{}, fixedTrustedClock{time.Unix(100, 0)}, allowInstallation{}, allowPublisher{})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.registerQuarantined(Entry{ArtifactDigest: digest, ArtifactKind: "skill", Namespace: "test", Name: "bounded", Version: "1", PromotionRequired: true}, candidate, time.Unix(100, 0)); err != nil {
		t.Fatal(err)
	}
	store.state.Initialized = true
	before := store.Snapshot().ControlScopeGeneration
	parameters, err := trusted.MarshalBody(OwnerCommandParametersV1{SchemaVersion: 1, ArtifactDigest: []byte{}, SessionDigest: []byte{}})
	if err != nil {
		t.Fatal(err)
	}
	agent := []byte("agent")
	effect := trusted.OwnerCommandEffectV1{DomainKind: uint8(trusted.DomainOwnerLocal), DomainID: []byte("owner"), OwnerID: []byte("owner"), AgentID: &agent,
		CommandKind: "owner.pause", TargetObjectKind: "agent", TargetObjectID: agent, ControlScopeGeneration: before, ExpectedTargetRevision: store.Snapshot().InventoryRevision}
	attempt := trusted.OwnerCommandAuthorizationAttemptV1{ActionID: bytes.Repeat([]byte{1}, 32), ExactRequestDigest: bytes.Repeat([]byte{2}, 32)}
	if _, err := store.applyOwnerCommand(effect, attempt, parameters, bytes.Repeat([]byte{3}, 32)); err != nil {
		t.Fatal(err)
	}
	if store.Snapshot().ControlScopeGeneration != before+1 {
		t.Fatal("pause did not fence prior work")
	}
	if _, err := store.Install(InstallationRequest{}); err == nil {
		t.Fatal("installed unknown digest")
	}
}

func TestProductionStoreRejectsProjectionRollback(t *testing.T) {
	root := filepath.Join(t.TempDir(), "control")
	monotonic := &memoryMonotonic{}
	store, err := OpenProductionInDomain(root, trusted.DomainOwnerLocal, []byte("owner"), []byte("owner"), []byte("agent"), monotonic, fixedTrustedClock{time.Unix(100, 0)}, allowInstallation{}, allowPublisher{})
	if err != nil {
		t.Fatal(err)
	}
	old, err := os.ReadFile(filepath.Join(root, stateFile))
	if err != nil {
		t.Fatal(err)
	}
	candidate := filepath.Join(t.TempDir(), "candidate")
	if err := os.Mkdir(candidate, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(candidate, "SKILL.md"), []byte("bounded"), 0o600); err != nil {
		t.Fatal(err)
	}
	digest, err := HashTree(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.registerQuarantined(Entry{ObservedContentDigest: digest}, candidate, time.Unix(100, 0)); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, stateFile), old, 0o600); err != nil {
		t.Fatal(err)
	}
	if rolledBack, err := OpenProductionInDomain(root, trusted.DomainOwnerLocal, []byte("owner"), []byte("owner"), []byte("agent"), monotonic, fixedTrustedClock{time.Unix(100, 0)}, allowInstallation{}, allowPublisher{}); err == nil {
		_ = rolledBack.Close()
		t.Fatal("rollback-resistant authority store accepted restored projection")
	}
}

func TestProductionStoreRecoversExternallyLinearizedPendingCommit(t *testing.T) {
	root := filepath.Join(t.TempDir(), "control")
	monotonic := &memoryMonotonic{}
	store, err := OpenProductionInDomain(root, trusted.DomainOwnerLocal, []byte("owner"), []byte("owner"), []byte("agent"), monotonic, fixedTrustedClock{time.Unix(100, 0)}, allowInstallation{}, allowPublisher{})
	if err != nil {
		t.Fatal(err)
	}
	prior := store.state.MonotonicRevision
	nextState := store.state
	nextState.ControlScopeGeneration++
	nextState.MonotonicRevision = prior + 1
	commitment, err := stateCommitment(nextState)
	if err != nil {
		t.Fatal(err)
	}
	pending := pendingAuthorityCommit{SchemaVersion: 1, PriorRevision: prior, NextRevision: prior + 1, Commitment: commitment, NextState: nextState}
	if err := store.persistPendingLocked(pending); err != nil {
		t.Fatal(err)
	}
	if err := monotonic.CompareAndAdvance(context.Background(), store.monotonicScopeLocked(), prior, prior+1, commitment); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	recovered, err := OpenProductionInDomain(root, trusted.DomainOwnerLocal, []byte("owner"), []byte("owner"), []byte("agent"), monotonic, fixedTrustedClock{time.Unix(100, 0)}, allowInstallation{}, allowPublisher{})
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	if recovered.state.MonotonicRevision != prior+1 || recovered.state.ControlScopeGeneration != nextState.ControlScopeGeneration {
		t.Fatal("pending externally-linearized authority state was not recovered")
	}
}
