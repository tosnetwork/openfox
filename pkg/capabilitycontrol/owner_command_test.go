package capabilitycontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
	"time"

	ownercontrol "github.com/tosnetwork/tos-messenger/pkg/ownercontrol"
	trusted "github.com/tosnetwork/tos-service-protocol/pkg/trustedcapability"
)

func TestOwnerCommandSinkRecoversAppliedActionAfterRestart(t *testing.T) {
	root := t.TempDir()
	authority, err := OpenFileMonotonicAuthority(t.TempDir(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	store, err := openInDomain(root, trusted.DomainOwnerLocal, []byte("owner"), []byte("owner"), []byte("agent"), authority, systemTrustedTime{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	parameters, err := trusted.MarshalBody(OwnerCommandParametersV1{SchemaVersion: 1, ArtifactDigest: []byte{}, SessionDigest: []byte{}})
	if err != nil {
		t.Fatal(err)
	}
	store.state.Initialized = true
	agent := []byte("agent")
	effect := trusted.OwnerCommandEffectV1{DomainKind: uint8(trusted.DomainOwnerLocal), DomainID: []byte("owner"), OwnerID: []byte("owner"), AgentID: &agent,
		CommandKind: "owner.pause", TargetObjectKind: "agent", TargetObjectID: agent, ControlScopeGeneration: 1, ExpectedTargetRevision: 1}
	attempt := trusted.OwnerCommandAuthorizationAttemptV1{ActionID: bytes.Repeat([]byte{1}, 32), ExactRequestDigest: bytes.Repeat([]byte{2}, 32)}
	fence := bytes.Repeat([]byte{3}, 32)
	revision, err := store.applyOwnerCommand(effect, attempt, parameters, fence)
	if err != nil || revision != 2 {
		t.Fatalf("revision=%d err=%v", revision, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := openInDomain(root, trusted.DomainOwnerLocal, []byte("owner"), []byte("owner"), []byte("agent"), authority, systemTrustedTime{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	state, recoveredRevision, err := reopened.ResolveOwnerCommand(attempt, fence)
	if err != nil || state != "applied" || recoveredRevision != revision {
		t.Fatalf("state=%s revision=%d err=%v", state, recoveredRevision, err)
	}
	if reopened.Snapshot().OwnerPaused != true {
		t.Fatal("owner pause did not survive restart")
	}
}

func TestOwnerCommandConfirmationIsDerivedFromExactParameters(t *testing.T) {
	artifact := bytes.Repeat([]byte{7}, sha256.Size)
	policy := bytes.Repeat([]byte{8}, sha256.Size)
	input := OwnerCommandParametersV1{SchemaVersion: 1, ArtifactDigest: artifact, ExpectedGeneration: 3, NewGeneration: 4}
	parameterWire, err := trusted.MarshalBody(input)
	if err != nil {
		t.Fatal(err)
	}
	parameterDigest := sha256.Sum256(parameterWire)
	agent := []byte("agent")
	effect := trusted.OwnerCommandEffectV1{SchemaVersion: 1, DomainKind: 2, DomainID: []byte("domain"), OwnerID: []byte("owner"), AgentID: &agent, CommandKind: "capability.revoke",
		CommandInstanceID: []byte("command-instance"), TargetObjectKind: "capability", TargetObjectID: artifact, SinkAuthorityID: []byte("sink"), SinkClusterEpoch: 1,
		ResolutionNamespace: bytes.Repeat([]byte{5}, 32), ControlScopeGeneration: 1, ExactParameterDigest: parameterDigest[:], PolicyRevision: 4, PolicyDigest: policy,
		SemanticConfirmationDigest: bytes.Repeat([]byte{6}, 32), AuthorityPredicateSetDigest: bytes.Repeat([]byte{7}, 32), CreatedAtUnix: 100, ExpiresAtUnix: 300, Extensions: [][]byte{}}
	confirmation, err := RenderOwnerCommandConfirmation(effect, input, bytes.Repeat([]byte{9}, 32), 200)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateConfirmationProjection(confirmation, effect, input); err != nil {
		t.Fatal(err)
	}
	confirmation.PermissionDelta = []byte("benign capability change")
	if err := validateConfirmationProjection(confirmation, effect, input); err == nil {
		t.Fatal("accepted a misleading human-facing permission projection")
	}
}

func TestDeviceSessionIsSelectedOnlyByAuthenticatedChannelBinding(t *testing.T) {
	store, err := Open(t.TempDir(), []byte("owner"), []byte("agent"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	store.state.Initialized = true
	channel := bytes.Repeat([]byte{41}, sha256.Size)
	fixture, err := trusted.NewConformanceBodyValue("device-session", 1)
	if err != nil {
		t.Fatal(err)
	}
	session := *fixture.(*trusted.OwnerDeviceSessionV1)
	session.OwnerID = []byte("owner")
	session.Audience = "openfox.owner-control.dashboard.v1"
	session.ChannelBindingDigest = channel
	session.NotBeforeUnix, session.ExpiresAtUnix = 100, 300
	object, err := trusted.NewObject(trusted.DomainOwnerLocal, []byte("owner"), "device-session", session)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := trusted.ObjectDigest(object)
	if err != nil {
		t.Fatal(err)
	}
	store.state.DeviceSessions[hex.EncodeToString(digest)] = DeviceSessionRecord{Object: object, SessionGeneration: 1, RevocationGeneration: 1}
	selected, err := store.DeviceSessionForAuthenticatedChannel("openfox.owner-control.dashboard.v1", channel, 200)
	if err != nil || !bytes.Equal(selected, digest) {
		t.Fatalf("selected=%x err=%v", selected, err)
	}
	if _, err := store.DeviceSessionForAuthenticatedChannel("openfox.owner-control.dashboard.v1", bytes.Repeat([]byte{42}, 32), 200); err == nil {
		t.Fatal("cross-channel replay selected a device session")
	}
	principal := ownercontrol.AuthenticatedPrincipal{DomainKind: uint8(trusted.DomainOwnerLocal), DomainID: []byte("owner"), OwnerID: []byte("owner"),
		Audience: session.Audience, SessionDigest: digest, ChannelBindingDigest: bytes.Repeat([]byte{42}, 32)}
	if err := store.VerifyOwnerCommandQuery(principal, 200); err == nil {
		t.Fatal("query authorization accepted the wrong channel binding")
	}
}

func TestEveryImplementedOwnerCommandRejectsDisplayExecutionTargetMismatch(t *testing.T) {
	agent := bytes.Repeat([]byte{31}, sha256.Size)
	artifact := bytes.Repeat([]byte{32}, sha256.Size)
	session := bytes.Repeat([]byte{33}, sha256.Size)
	tests := []struct {
		kind       string
		targetKind string
		targetID   []byte
		parameters OwnerCommandParametersV1
	}{
		{"owner.pause", "agent", agent, OwnerCommandParametersV1{SchemaVersion: 1, ArtifactDigest: []byte{}, SessionDigest: []byte{}}},
		{"owner.resume", "agent", agent, OwnerCommandParametersV1{SchemaVersion: 1, ArtifactDigest: []byte{}, SessionDigest: []byte{}}},
		{"owner.exit", "owner", []byte("owner"), OwnerCommandParametersV1{SchemaVersion: 1, ArtifactDigest: []byte{}, SessionDigest: []byte{}, OwnerExitPlan: &trusted.OwnerExitPlanV1{OwnerID: []byte("owner"), Stage: "fence-new-work", Revision: 1}}},
		{"capability.promotion.activate", "capability", artifact, OwnerCommandParametersV1{SchemaVersion: 1, ArtifactDigest: artifact}},
		{"capability.suspend", "capability", artifact, OwnerCommandParametersV1{SchemaVersion: 1, ArtifactDigest: artifact}},
		{"capability.resume", "capability", artifact, OwnerCommandParametersV1{SchemaVersion: 1, ArtifactDigest: artifact}},
		{"capability.revoke", "capability", artifact, OwnerCommandParametersV1{SchemaVersion: 1, ArtifactDigest: artifact}},
		{"capability.promotion.revoke", "capability", artifact, OwnerCommandParametersV1{SchemaVersion: 1, ArtifactDigest: artifact}},
		{"capability.remove", "capability", artifact, OwnerCommandParametersV1{SchemaVersion: 1, ArtifactDigest: artifact}},
		{"device-session.revoke", "device-session", session, OwnerCommandParametersV1{SchemaVersion: 1, SessionDigest: session}},
		{"session.revoke", "device-session", session, OwnerCommandParametersV1{SchemaVersion: 1, SessionDigest: session}},
	}
	for _, test := range tests {
		t.Run(test.kind, func(t *testing.T) {
			effect := trusted.OwnerCommandEffectV1{SchemaVersion: 1, DomainKind: uint8(trusted.DomainOwnerLocal), DomainID: []byte("owner"), OwnerID: []byte("owner"),
				AgentID: &agent, CommandKind: test.kind, CommandInstanceID: bytes.Repeat([]byte{2}, 16), TargetObjectKind: test.targetKind,
				TargetObjectID: append([]byte(nil), test.targetID...), SinkAuthorityID: bytes.Repeat([]byte{3}, 32), SinkClusterEpoch: 1,
				ResolutionNamespace: bytes.Repeat([]byte{4}, 32), ControlScopeGeneration: 1, ExactParameterDigest: bytes.Repeat([]byte{5}, 32),
				PolicyRevision: 1, PolicyDigest: bytes.Repeat([]byte{6}, 32), SemanticConfirmationDigest: bytes.Repeat([]byte{7}, 32),
				AuthorityPredicateSetDigest: bytes.Repeat([]byte{8}, 32), CreatedAtUnix: 1, ExpiresAtUnix: 200, Extensions: [][]byte{}}
			if _, err := RenderOwnerCommandConfirmation(effect, test.parameters, bytes.Repeat([]byte{1}, 32), 100); err != nil {
				t.Fatalf("valid target rejected: %v", err)
			}
			effect.TargetObjectID[0] ^= 0xff
			if _, err := RenderOwnerCommandConfirmation(effect, test.parameters, bytes.Repeat([]byte{1}, 32), 100); err == nil {
				t.Fatal("mismatched target was rendered")
			}
		})
	}
}

func TestAmbiguousMCPActionBlocksSameRequestAcrossRestart(t *testing.T) {
	root := t.TempDir()
	authority, err := OpenFileMonotonicAuthority(t.TempDir(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	store, err := openInDomain(root, trusted.DomainOwnerLocal, []byte("owner"), []byte("owner"), []byte("agent"), authority, systemTrustedTime{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	action := bytes.Repeat([]byte{21}, sha256.Size)
	request := bytes.Repeat([]byte{22}, sha256.Size)
	store.state.AuthorizedSubjects["action-outcome"] = [][]byte{bytes.Repeat([]byte{20}, sha256.Size)}
	resolutionToken, err := store.PrepareMCPAction(action, request)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.ResolveMCPAction(action, request, resolutionToken, "ambiguous"); err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := openInDomain(root, trusted.DomainOwnerLocal, []byte("owner"), []byte("owner"), []byte("agent"), authority, systemTrustedTime{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err = reopened.PrepareMCPAction(bytes.Repeat([]byte{23}, sha256.Size), request); !errors.Is(err, ErrAmbiguousMCPAction) {
		t.Fatalf("same request after restart was not fenced: %v", err)
	}
	if err = reopened.ResolveMCPAction(action, request, bytes.Repeat([]byte{99}, sha256.Size), "failed"); err == nil {
		t.Fatal("caller without the original resolution capability cleared an ambiguous action")
	}
	if err = reopened.ResolveMCPAction(action, request, resolutionToken, "failed"); err == nil {
		t.Fatal("original launch capability cleared an ambiguous action without sink evidence")
	}
	if _, err = reopened.PrepareMCPAction(bytes.Repeat([]byte{24}, sha256.Size), request); !errors.Is(err, ErrAmbiguousMCPAction) {
		t.Fatalf("failed resolution attack released the semantic request: %v", err)
	}
}

func TestHighRiskOwnerCommandRequiresRolesAndIndependentControllers(t *testing.T) {
	device := bytes.Repeat([]byte{41}, 32)
	independent := bytes.Repeat([]byte{42}, 32)
	predicate := trusted.OwnerCommandAuthorizationPredicateSetV1{
		RequiredAuthorityKinds:    []string{"authenticated-device", "independent-owner-authority"},
		MinimumDistinctPrincipals: 2, RequireAuthenticatedDevice: true, RequireIndependentApprover: true, ForbidSelfAuthorization: true,
	}
	subjects := map[string][][]byte{"authenticated-device": {device}, "independent-owner-authority": {independent}}
	controllers := map[string]string{fmt.Sprintf("%x", device): "owner-device", fmt.Sprintf("%x", independent): "owner-device"}
	if err := validateOwnerCommandRoleCoverage(predicate, device, [][]byte{device, independent}, subjects, controllers); err == nil {
		t.Fatal("two keys controlled by one principal satisfied the high-risk quorum")
	}
	controllers[fmt.Sprintf("%x", independent)] = "independent-custodian"
	if err := validateOwnerCommandRoleCoverage(predicate, device, [][]byte{device, independent}, subjects, controllers); err != nil {
		t.Fatal(err)
	}
	wrongRoles := map[string][][]byte{"authenticated-device": {device, independent}}
	if err := validateOwnerCommandRoleCoverage(predicate, device, [][]byte{device, independent}, wrongRoles, controllers); err == nil {
		t.Fatal("a second signer with the wrong role satisfied the high-risk quorum")
	}
}

func TestOwnerExitCommonFenceRejectsEveryNewCapabilityPath(t *testing.T) {
	root := t.TempDir()
	authority, err := OpenFileMonotonicAuthority(t.TempDir(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	store, err := openInDomain(root, trusted.DomainOwnerLocal, []byte("owner"), []byte("owner"), []byte("agent"), authority, systemTrustedTime{}, allowInstallation{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	store.state.Initialized = true
	store.state.OwnerExit = &trusted.OwnerExitPlanV1{Stage: "tombstone"}

	checks := []struct {
		name string
		call func() error
	}{
		{"legacy import", func() error { return store.ImportLegacySkillRoots(nil, time.Now()) }},
		{"quarantine", func() error {
			return store.RegisterQuarantined(context.Background(), Entry{}, QuarantineCommitReceipt{}, time.Now())
		}},
		{"verification", func() error { return store.VerifyCandidate(VerificationRequest{}) }},
		{"admission", func() error { return store.Admit(AdmissionRequest{}) }},
		{"promotion", func() error { return store.Promote(PromotionRequest{}) }},
		{"installation", func() error { _, err := store.Install(InstallationRequest{}); return err }},
		{"MCP prepare", func() error {
			_, err := store.PrepareMCPAction(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32))
			return err
		}},
		{"Skill load", func() error { _, err := store.SealLLMSkill(bytes.Repeat([]byte{3}, 32)); return err }},
		{"entrypoint load", func() error { _, err := store.ResolveInstalledEntrypoint(bytes.Repeat([]byte{4}, 32)); return err }},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			if err := check.call(); err == nil {
				t.Fatal("new capability work was accepted after owner exit")
			}
		})
	}
}

func TestOwnerPauseCommonFenceRejectsLifecycleExpansion(t *testing.T) {
	root := t.TempDir()
	authority, err := OpenFileMonotonicAuthority(t.TempDir(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	store, err := openInDomain(root, trusted.DomainOwnerLocal, []byte("owner"), []byte("owner"), []byte("agent"), authority, systemTrustedTime{}, allowInstallation{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	store.state.Initialized = true
	store.state.OwnerPaused = true

	checks := []struct {
		name string
		call func() error
	}{
		{"device-session issue", func() error { return store.IssueDeviceSession(DeviceSessionRequest{}) }},
		{"verification", func() error { return store.VerifyCandidate(VerificationRequest{}) }},
		{"admission", func() error { return store.Admit(AdmissionRequest{}) }},
		{"promotion", func() error { return store.Promote(PromotionRequest{}) }},
		{"installation", func() error { _, err := store.Install(InstallationRequest{}); return err }},
		{"MCP prepare", func() error {
			_, err := store.PrepareMCPAction(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32))
			return err
		}},
		{"Skill load", func() error { _, err := store.SealLLMSkill(bytes.Repeat([]byte{3}, 32)); return err }},
		{"entrypoint load", func() error { _, err := store.ResolveInstalledEntrypoint(bytes.Repeat([]byte{4}, 32)); return err }},
		{"execution measurement", func() error { _, _, err := store.MeasureInstalledArtifact(bytes.Repeat([]byte{5}, 32)); return err }},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			if err := check.call(); err == nil {
				t.Fatal("capability lifecycle expansion was accepted while paused")
			}
		})
	}
	for _, forbidden := range []string{"capability.promotion.activate", "capability.resume", "owner.pause", "policy.rotate"} {
		if ownerCommandAllowedWhilePaused(forbidden) {
			t.Fatalf("expansive command %q was allowed while paused", forbidden)
		}
	}
	for _, permitted := range []string{"owner.resume", "owner.exit", "capability.suspend", "capability.revoke", "capability.promotion.revoke", "capability.remove", "device-session.revoke"} {
		if !ownerCommandAllowedWhilePaused(permitted) {
			t.Fatalf("restrictive command %q was blocked while paused", permitted)
		}
	}
}

func TestOwnerCommandRecoveryLeaseEpochRules(t *testing.T) {
	if ownerCommandRecoveryEpochAdmits(3, 4, false) {
		t.Fatal("new command accepted a non-exact sink epoch")
	}
	if !ownerCommandRecoveryEpochAdmits(3, 4, true) {
		t.Fatal("recovery rejected a monotonic sink failover")
	}
	if ownerCommandRecoveryEpochAdmits(4, 3, true) {
		t.Fatal("recovery accepted a sink epoch rollback")
	}
}
