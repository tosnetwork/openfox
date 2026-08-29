package capabilitycontrol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	trusted "github.com/tosnetwork/tos-service-protocol/pkg/trustedcapability"
)

func TestUseResolutionRequiresOriginalCapability(t *testing.T) {
	store, err := OpenProductionInDomain(t.TempDir(), trusted.DomainOwnerLocal, []byte("owner"), []byte("owner"), []byte("agent"),
		&memoryMonotonic{}, fixedTrustedClock{time.Unix(200, 0)}, allowInstallation{}, allowPublisher{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	executionID := bytes.Repeat([]byte{1}, sha256.Size)
	token := bytes.Repeat([]byte{2}, sha256.Size)
	tokenDigest := sha256.Sum256(append([]byte("openfox.capability-use-resolution.v1\x00"), token...))
	store.state.UseSlots[hex.EncodeToString(executionID)] = UseSlot{ExecutionID: executionID, ActionID: bytes.Repeat([]byte{3}, 32),
		ArtifactDigest: bytes.Repeat([]byte{4}, 32), State: "started", ResolutionTokenDigest: tokenDigest[:]}
	if err := store.ResolveUse(executionID, bytes.Repeat([]byte{5}, 32), "failed"); err == nil {
		t.Fatal("forged resolution capability terminated an execution slot")
	}
	if store.state.UseSlots[hex.EncodeToString(executionID)].State != "started" {
		t.Fatal("failed resolution changed the execution slot")
	}
	if err := store.ResolveUse(executionID, token, "failed"); err != nil {
		t.Fatal(err)
	}
	if store.state.UseSlots[hex.EncodeToString(executionID)].TerminalDisposition != "failed" {
		t.Fatal("valid resolution capability did not close the slot")
	}
}

func TestUseSlotIdempotencyRequiresExactRequestDigest(t *testing.T) {
	slot := UseSlot{State: "started", ActionID: bytes.Repeat([]byte{1}, 32), ExactRequestDigest: bytes.Repeat([]byte{2}, 32)}
	if !useSlotMatchesExactRequest(slot, slot.ActionID, slot.ExactRequestDigest) {
		t.Fatal("exact execution-slot replay was not recognized")
	}
	mutated := append([]byte(nil), slot.ExactRequestDigest...)
	mutated[0] ^= 0xff
	if useSlotMatchesExactRequest(slot, slot.ActionID, mutated) {
		t.Fatal("execution slot accepted a conflicting exact request")
	}
}

func signedOutcomeRecovery(t *testing.T, store *Store, key ed25519.PrivateKey, evidence trusted.ActionOutcomeEvidenceV1) ActionOutcomeRecoveryRequest {
	t.Helper()
	object, err := trusted.NewObject(trusted.DomainKind(store.state.DomainKind), store.state.DomainID, "action-outcome-evidence", evidence)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := trusted.ObjectDigest(object)
	if err != nil {
		t.Fatal(err)
	}
	keyRef := trusted.Ed25519KeyReference(key.Public().(ed25519.PublicKey))
	agent := append([]byte(nil), store.state.AgentID...)
	body := trusted.ProfileAuthorizationEnvelopeBodyV1{SchemaVersion: 1, DomainKind: object.DomainKind, DomainID: object.DomainID,
		BodyKind: object.ObjectKind, BodyProfileURI: object.ProfileURI, BodyProfileVersion: 1, BodyDigest: digest,
		OwnerID: store.state.OwnerID, AgentID: &agent, AuthorityKind: "action-outcome", AuthorityID: bytes.Repeat([]byte{71}, 16),
		AuthorityRevision: 0, AuthorityEpoch: store.state.AuthorityEpoch, PolicyRevision: store.state.PolicyRevision, PolicyDigest: store.state.PolicyDigest,
		IssuerSubject:   trusted.TypedAuthoritySubjectV1{Kind: "verification-key", Namespace: trusted.Ed25519ProofProfile, Identifier: keyRef},
		ProofProfileURI: trusted.Ed25519ProofProfile, ProofProfileVersion: 1, NotBeforeUnix: evidence.NotBeforeUnix,
		ExpiresAtUnix: evidence.ExpiresAtUnix, ExtensionsDigest: bytes.Repeat([]byte{0}, sha256.Size)}
	proof := trusted.ProfileAuthorizationProofV1{Algorithm: trusted.Ed25519ProofProfile, KeyReference: keyRef,
		NotBeforeUnix: evidence.NotBeforeUnix, ExpiresAtUnix: evidence.ExpiresAtUnix}
	envelope, err := trusted.SignAuthorization(body, []trusted.ProfileAuthorizationProofV1{proof}, []ed25519.PrivateKey{key})
	if err != nil {
		t.Fatal(err)
	}
	return ActionOutcomeRecoveryRequest{Object: object, Envelope: envelope}
}

func TestAmbiguousUseCannotBeClearedByLaunchCapability(t *testing.T) {
	store, err := OpenProductionInDomain(t.TempDir(), trusted.DomainOwnerLocal, []byte("owner"), []byte("owner"), []byte("agent"),
		&memoryMonotonic{}, fixedTrustedClock{time.Unix(200, 0)}, allowInstallation{}, allowPublisher{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	executionID := bytes.Repeat([]byte{11}, sha256.Size)
	token := bytes.Repeat([]byte{12}, sha256.Size)
	tokenDigest := sha256.Sum256(append([]byte("openfox.capability-use-resolution.v1\x00"), token...))
	store.state.UseSlots[hex.EncodeToString(executionID)] = UseSlot{ExecutionID: executionID, ActionID: bytes.Repeat([]byte{13}, 32),
		ArtifactDigest: bytes.Repeat([]byte{14}, 32), State: "started", ResolutionTokenDigest: tokenDigest[:]}
	if err := store.ResolveUse(executionID, token, "ambiguous"); err != nil {
		t.Fatal(err)
	}
	if got := store.state.UseSlots[hex.EncodeToString(executionID)].State; got != "ambiguous" {
		t.Fatalf("ambiguous execution became %q", got)
	}
	if err := store.ResolveUse(executionID, token, "failed"); err == nil {
		t.Fatal("launch capability cleared an ambiguous execution without outcome evidence")
	}
	if got := store.state.UseSlots[hex.EncodeToString(executionID)].State; got != "ambiguous" {
		t.Fatalf("failed resolution changed ambiguous execution to %q", got)
	}
}

func TestSignedOutcomeRecoversExactAmbiguousMCPActionAcrossRestart(t *testing.T) {
	root := t.TempDir()
	authority := &memoryMonotonic{}
	clock := fixedTrustedClock{time.Unix(200, 0)}
	store, err := OpenProductionInDomain(root, trusted.DomainOwnerLocal, []byte("owner"), []byte("owner"), []byte("agent"), authority, clock, allowInstallation{}, allowPublisher{})
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{61}, ed25519.SeedSize))
	keyRef := trusted.Ed25519KeyReference(key.Public().(ed25519.PublicKey))
	store.state.Initialized, store.state.AuthorityEpoch, store.state.PolicyRevision = true, 1, 1
	store.state.PolicyDigest = bytes.Repeat([]byte{62}, sha256.Size)
	store.state.AuthorizedSubjects["action-outcome"] = [][]byte{keyRef}
	if err := store.commitAuthorityLocked(); err != nil {
		t.Fatal(err)
	}
	action, requestDigest := bytes.Repeat([]byte{63}, 32), bytes.Repeat([]byte{64}, 32)
	token, err := store.PrepareMCPAction(action, requestDigest)
	if err != nil || store.ResolveMCPAction(action, requestDigest, token, "ambiguous") != nil {
		t.Fatalf("prepare ambiguous action: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenProductionInDomain(root, trusted.DomainOwnerLocal, []byte("owner"), []byte("owner"), []byte("agent"), authority, clock, allowInstallation{}, allowPublisher{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	base := trusted.ActionOutcomeEvidenceV1{SchemaVersion: 1, EvidenceID: bytes.Repeat([]byte{65}, 16), OwnerID: []byte("owner"), AgentID: []byte("agent"),
		ActionKind: "mcp-tool", ActionID: action, ExactRequestDigest: requestDigest, Disposition: "failed", ResultDigest: bytes.Repeat([]byte{66}, 32),
		SinkAuthorityID: keyRef, SinkEpoch: 1, ObservedAtUnix: 190, NotBeforeUnix: 100, ExpiresAtUnix: 300, Extensions: [][]byte{}}
	cross := base
	cross.ActionID = bytes.Repeat([]byte{67}, 32)
	if err := store.RecoverAmbiguousAction(signedOutcomeRecovery(t, store, key, cross)); err == nil {
		t.Fatal("cross-action outcome evidence was accepted")
	}
	forged := signedOutcomeRecovery(t, store, key, base)
	forged.Envelope.Proofs[0].Signature[0] ^= 0xff
	if err := store.RecoverAmbiguousAction(forged); err == nil {
		t.Fatal("forged outcome evidence was accepted")
	}
	expired := base
	expired.ObservedAtUnix, expired.NotBeforeUnix, expired.ExpiresAtUnix = 150, 100, 199
	if err := store.RecoverAmbiguousAction(signedOutcomeRecovery(t, store, key, expired)); err == nil {
		t.Fatal("expired outcome evidence was accepted")
	}
	staleEpoch := base
	staleEpoch.SinkEpoch = 2
	if err := store.RecoverAmbiguousAction(signedOutcomeRecovery(t, store, key, staleEpoch)); err == nil {
		t.Fatal("wrong sink epoch outcome evidence was accepted")
	}
	if err := store.RecoverAmbiguousAction(signedOutcomeRecovery(t, store, key, base)); err != nil {
		t.Fatal(err)
	}
	record, ok := store.MCPAction(action)
	if !ok || record.State != "terminal" || record.TerminalDisposition != "failed" || !bytes.Equal(record.ResultDigest, base.ResultDigest) {
		t.Fatalf("signed recovery was not durably applied: %#v", record)
	}
}

func TestSignedOutcomeRecoversOnlyExactAmbiguousCapabilityUse(t *testing.T) {
	store, err := OpenProductionInDomain(t.TempDir(), trusted.DomainOwnerLocal, []byte("owner"), []byte("owner"), []byte("agent"),
		&memoryMonotonic{}, fixedTrustedClock{time.Unix(200, 0)}, allowInstallation{}, allowPublisher{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{81}, ed25519.SeedSize))
	keyRef := trusted.Ed25519KeyReference(key.Public().(ed25519.PublicKey))
	store.state.Initialized, store.state.AuthorityEpoch, store.state.PolicyRevision = true, 1, 1
	store.state.PolicyDigest = bytes.Repeat([]byte{82}, 32)
	store.state.AuthorizedSubjects["action-outcome"] = [][]byte{keyRef}
	executionID, actionID, requestDigest := bytes.Repeat([]byte{83}, 32), bytes.Repeat([]byte{84}, 32), bytes.Repeat([]byte{85}, 32)
	store.state.UseSlots[hex.EncodeToString(executionID)] = UseSlot{ExecutionID: executionID, ActionID: actionID, ExactRequestDigest: requestDigest,
		ArtifactDigest: bytes.Repeat([]byte{86}, 32), State: "ambiguous", ResolutionTokenDigest: bytes.Repeat([]byte{87}, 32),
		OutcomeAuthorityID: keyRef, OutcomeAuthorityEpoch: 1}
	evidence := trusted.ActionOutcomeEvidenceV1{SchemaVersion: 1, EvidenceID: bytes.Repeat([]byte{88}, 16), OwnerID: []byte("owner"), AgentID: []byte("agent"),
		ActionKind: "capability-use", ActionID: actionID, ExactRequestDigest: requestDigest, ExecutionID: &executionID, Disposition: "killed",
		ResultDigest: bytes.Repeat([]byte{89}, 32), SinkAuthorityID: keyRef, SinkEpoch: 1, ObservedAtUnix: 190,
		NotBeforeUnix: 100, ExpiresAtUnix: 300, Extensions: [][]byte{}}
	wrongRequest := evidence
	wrongRequest.ExactRequestDigest = bytes.Repeat([]byte{90}, 32)
	if err := store.RecoverAmbiguousAction(signedOutcomeRecovery(t, store, key, wrongRequest)); err == nil {
		t.Fatal("cross-request execution evidence was accepted")
	}
	if err := store.RecoverAmbiguousAction(signedOutcomeRecovery(t, store, key, evidence)); err != nil {
		t.Fatal(err)
	}
	slot := store.state.UseSlots[hex.EncodeToString(executionID)]
	if slot.State != "terminal" || slot.TerminalDisposition != "killed" || !bytes.Equal(slot.ResultDigest, evidence.ResultDigest) {
		t.Fatalf("capability execution outcome was not applied: %#v", slot)
	}
}
