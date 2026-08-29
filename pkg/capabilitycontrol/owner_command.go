package capabilitycontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	ownercontrol "github.com/tosnetwork/tos-messenger/pkg/ownercontrol"
	trusted "github.com/tosnetwork/tos-service-protocol/pkg/trustedcapability"
)

type OwnerCommandParametersV1 struct {
	SchemaVersion      uint16                   `cbor:"1,keyasint" json:"schema_version"`
	ArtifactDigest     []byte                   `cbor:"2,keyasint" json:"artifact_digest"`
	SessionDigest      []byte                   `cbor:"3,keyasint" json:"session_digest"`
	ExpectedGeneration uint64                   `cbor:"4,keyasint" json:"expected_generation"`
	NewGeneration      uint64                   `cbor:"5,keyasint" json:"new_generation"`
	OwnerExitPlan      *trusted.OwnerExitPlanV1 `cbor:"6,keyasint" json:"owner_exit_plan"`
}

func validateOwnerExitPlan(plan *trusted.OwnerExitPlanV1, ownerID, policyDigest []byte) error {
	if plan == nil || len(plan.ExitID) != 16 || !bytes.Equal(plan.OwnerID, ownerID) || !bytes.Equal(plan.PredecessorPolicyDigest, policyDigest) ||
		len(plan.StageEvidenceRoot) != sha256.Size || len(plan.AmbiguousActionSetRoot) != sha256.Size ||
		len(plan.CustodyDispositionDigest) != sha256.Size || len(plan.ExportDigest) != sha256.Size ||
		plan.TombstoneDigest != nil && len(*plan.TombstoneDigest) != sha256.Size {
		return errors.New("owner exit plan fields are incomplete")
	}
	if plan.Stage == "tombstone" && plan.TombstoneDigest == nil {
		return errors.New("terminal owner exit lacks its irreversible tombstone")
	}
	return nil
}

func validOwnerExitTransition(from, to string) bool {
	switch from {
	case "":
		return to == "fence-new-work"
	case "fence-new-work":
		return to == "revoke-authorities" || to == "abort"
	case "revoke-authorities":
		return to == "resolve-actions"
	case "resolve-actions":
		return to == "custody-disposition"
	case "custody-disposition":
		return to == "export-evidence"
	case "export-evidence":
		return to == "tombstone"
	default:
		return false
	}
}

func (s *Store) ambiguousActionSetRootLocked() []byte {
	items := make([]string, 0)
	for key, action := range s.state.MCPToolActions {
		if action.State == "prepared" || action.State == "ambiguous" {
			items = append(items, "mcp:"+key+":"+hex.EncodeToString(action.ExactRequestDigest))
		}
	}
	for key, slot := range s.state.UseSlots {
		if slot.State != "terminal" {
			items = append(items, "use:"+key+":"+hex.EncodeToString(slot.ExactRequestDigest))
		}
	}
	sort.Strings(items)
	hash := sha256.New()
	hash.Write([]byte("tos.owner-exit-ambiguous-action-set.v1\x00"))
	for _, item := range items {
		hash.Write([]byte(item))
		hash.Write([]byte{0})
	}
	return hash.Sum(nil)
}

func byteFromHex(value string) []byte {
	decoded, _ := hex.DecodeString(value)
	return decoded
}

func (s *Store) VerifyOwnerCommand(principal ownercontrol.AuthenticatedPrincipal, effect trusted.OwnerCommandEffectV1, attempt trusted.OwnerCommandAuthorizationAttemptV1, evidence ownercontrol.SubmissionEvidence, now uint64) error {
	return s.verifyOwnerCommand(principal, effect, attempt, evidence, now, false)
}

func (s *Store) VerifyOwnerCommandRecovery(_ context.Context, principal ownercontrol.AuthenticatedPrincipal, effect trusted.OwnerCommandEffectV1, attempt trusted.OwnerCommandAuthorizationAttemptV1, evidence ownercontrol.SubmissionEvidence) error {
	now, err := s.TrustedNow()
	if err != nil {
		return err
	}
	return s.verifyOwnerCommand(principal, effect, attempt, evidence, now, true)
}

func (s *Store) verifyOwnerCommand(principal ownercontrol.AuthenticatedPrincipal, effect trusted.OwnerCommandEffectV1, attempt trusted.OwnerCommandAuthorizationAttemptV1, evidence ownercontrol.SubmissionEvidence, now uint64, recovery bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validateOwnerCommandScopeLocked(effect); err != nil {
		return err
	}
	exitBlocks := !recovery && s.state.OwnerExit != nil && (effect.CommandKind != "owner.exit" || s.state.OwnerExit.Stage == "tombstone")
	if !s.state.Initialized || exitBlocks || principal.Audience == "" || !recovery && (effect.PolicyRevision != s.state.PolicyRevision ||
		!bytes.Equal(effect.PolicyDigest, s.state.PolicyDigest) || effect.ControlScopeGeneration != s.state.ControlScopeGeneration) ||
		attempt.AuthorityEpoch != s.state.AuthorityEpoch || now < attempt.AttemptedAtUnix || now >= attempt.ExpiresAtUnix {
		return errors.New("owner command authority is stale or unavailable")
	}
	record, ok := s.state.DeviceSessions[hex.EncodeToString(attempt.DeviceSessionDigest)]
	if !ok || record.Revoked || record.SessionGeneration != attempt.SessionGeneration || record.RevocationGeneration != attempt.SessionRevocationGeneration {
		return errors.New("owner command device session is unknown, stale, or revoked")
	}
	var session trusted.OwnerDeviceSessionV1
	if trusted.DecodeBody(record.Object, "device-session", &session) != nil || session.Audience != principal.Audience ||
		!bytes.Equal(session.ChannelBindingDigest, principal.ChannelBindingDigest) || now < session.NotBeforeUnix || now >= session.ExpiresAtUnix {
		return errors.New("owner command device session scope is invalid")
	}
	classesDigest, err := ownercontrol.OwnerCommandClassSetDigest(evidence.AllowedCommandKinds)
	if err != nil || !bytes.Equal(classesDigest, session.AllowedCommandClassesDigest) {
		return errors.New("owner command class set is not authorized by the device session")
	}
	var lease trusted.OwnerCommandLeaseV1
	if trusted.DecodeBody(evidence.CommandLeaseObject, "owner-command-lease", &lease) != nil || lease.SchemaVersion != 1 || lease.DomainKind != s.state.DomainKind ||
		!bytes.Equal(lease.DomainID, s.state.DomainID) || !bytes.Equal(lease.OwnerID, s.state.OwnerID) || !bytes.Equal(lease.DeviceSessionDigest, attempt.DeviceSessionDigest) ||
		!bytes.Equal(lease.AllowedCommandClassesDigest, classesDigest) || lease.Audience != principal.Audience || !bytes.Equal(lease.SinkAuthorityID, effect.SinkAuthorityID) ||
		!ownerCommandRecoveryEpochAdmits(effect.SinkClusterEpoch, lease.SinkClusterEpoch, recovery) || lease.ControlScopeGeneration != s.state.ControlScopeGeneration || lease.PolicyRevision != s.state.PolicyRevision ||
		!bytes.Equal(lease.PolicyDigest, s.state.PolicyDigest) || lease.AuthorityEpoch != s.state.AuthorityEpoch || now < lease.NotBeforeUnix || now >= lease.ExpiresAtUnix {
		return errors.New("owner command lease is incomplete, stale, or cross-scope")
	}
	if trusted.VerifyAuthorization(evidence.CommandLeaseAuthorization, evidence.CommandLeaseObject, now, s.state.AuthorityEpoch) != nil ||
		s.verifyPolicyAuthorizationLocked(evidence.CommandLeaseAuthorization, "owner-command-lease", s.state.AgentID) != nil {
		return errors.New("owner command lease authorization is invalid")
	}
	if len(attempt.AuthorizationEnvelopes) == 0 || len(attempt.AuthorizationEnvelopes) > 8 {
		return errors.New("owner command authorization predicate is incomplete")
	}
	predicate, err := trusted.OwnerCommandAuthorizationPredicateSet(effect)
	if err != nil {
		return err
	}
	predicateDigest, err := trusted.OwnerCommandAuthorizationPredicateSetDigest(effect)
	if err != nil || !bytes.Equal(predicateDigest, effect.AuthorityPredicateSetDigest) {
		return errors.New("owner command selected an unauthorized predicate set")
	}
	confirmationDigest, err := trusted.SemanticConfirmationDigest(evidence.SemanticConfirmation)
	confirmationTime := now
	if now >= effect.ExpiresAtUnix {
		confirmationTime = effect.CreatedAtUnix
	}
	if err != nil || !bytes.Equal(confirmationDigest, effect.SemanticConfirmationDigest) ||
		trusted.ValidateSemanticConfirmation(evidence.SemanticConfirmation, effect, attempt.ActionID, confirmationTime) != nil {
		return errors.New("owner command semantic confirmation is invalid")
	}
	var commandParameters OwnerCommandParametersV1
	if trusted.UnmarshalBody(evidence.Parameters, &commandParameters) != nil || commandParameters.SchemaVersion != 1 {
		return errors.New("owner command parameters are not canonical V1")
	}
	reencodedParameters, err := trusted.MarshalBody(commandParameters)
	if err != nil || !bytes.Equal(reencodedParameters, evidence.Parameters) {
		return errors.New("owner command parameters are not exact canonical bytes")
	}
	parameterDigest := sha256.Sum256(evidence.Parameters)
	if !bytes.Equal(parameterDigest[:], effect.ExactParameterDigest) || validateConfirmationProjection(evidence.SemanticConfirmation, effect, commandParameters) != nil {
		return errors.New("owner command confirmation does not render the exact parameters")
	}
	effectObject, _ := trusted.NewObject(trusted.DomainKind(effect.DomainKind), effect.DomainID, "owner-command-effect", effect)
	deviceKeyRef := trusted.Ed25519KeyReference(session.DevicePublicKey)
	issuerIDs := make([][]byte, 0, len(attempt.AuthorizationEnvelopes))
	for _, envelope := range attempt.AuthorizationEnvelopes {
		if trusted.VerifyAuthorization(envelope, effectObject, now, s.state.AuthorityEpoch) != nil || envelope.Body.AuthorityKind != "owner-command" ||
			envelope.Body.PolicyRevision != s.state.PolicyRevision || !bytes.Equal(envelope.Body.PolicyDigest, s.state.PolicyDigest) ||
			!bytes.Equal(envelope.Body.OwnerID, s.state.OwnerID) {
			return errors.New("owner command authorization envelope is invalid")
		}
		issuerIDs = append(issuerIDs, append([]byte(nil), envelope.Body.IssuerSubject.Identifier...))
	}
	return validateOwnerCommandRoleCoverage(predicate, deviceKeyRef, issuerIDs, s.state.AuthorizedSubjects, s.state.AuthorityControllers)
}

func ownerCommandRecoveryEpochAdmits(effectEpoch, leaseEpoch uint64, recovery bool) bool {
	if recovery {
		return leaseEpoch >= effectEpoch
	}
	return leaseEpoch == effectEpoch
}

func validateOwnerCommandRoleCoverage(predicate trusted.OwnerCommandAuthorizationPredicateSetV1, deviceKeyRef []byte, issuerIDs [][]byte, subjects map[string][][]byte, authorityControllers map[string]string) error {
	issuers := make([]string, 0, len(issuerIDs))
	controllers := make([]string, 0, len(issuerIDs))
	coveredRoles := map[string]bool{}
	for _, identifier := range issuerIDs {
		issuer := hex.EncodeToString(identifier)
		controller := authorityControllers[issuer]
		if controller == "" {
			return errors.New("owner command signer lacks a policy-bound controlling principal")
		}
		role := "independent-owner-authority"
		if bytes.Equal(identifier, deviceKeyRef) {
			role = "authenticated-device"
		}
		if !subjectAllowed(subjects, role, identifier) {
			return errors.New("owner command signer does not hold the required authority role")
		}
		coveredRoles[role] = true
		issuers = append(issuers, issuer)
		controllers = append(controllers, controller)
	}
	sort.Strings(issuers)
	sort.Strings(controllers)
	for index := 1; index < len(issuers); index++ {
		if issuers[index] == issuers[index-1] {
			return errors.New("owner command authorization principals are not disjoint")
		}
	}
	for index := 1; index < len(controllers); index++ {
		if controllers[index] == controllers[index-1] {
			return errors.New("owner command signers are controlled by the same principal")
		}
	}
	wanted := hex.EncodeToString(deviceKeyRef)
	if index := sort.SearchStrings(issuers, wanted); index == len(issuers) || issuers[index] != wanted {
		return errors.New("owner command lacks authorization by the authenticated device")
	}
	for _, role := range predicate.RequiredAuthorityKinds {
		if !coveredRoles[role] {
			return errors.New("owner command authorization role coverage is incomplete")
		}
	}
	if len(controllers) < int(predicate.MinimumDistinctPrincipals) || predicate.RequireIndependentApprover && len(controllers) < 2 {
		return errors.New("owner command authorization quorum is incomplete")
	}
	return nil
}

func validateConfirmationProjection(confirmation trusted.SemanticConfirmationV1, effect trusted.OwnerCommandEffectV1, input OwnerCommandParametersV1) error {
	expected, err := RenderOwnerCommandConfirmation(effect, input, confirmation.ActionID, confirmation.ExpiresAtUnix)
	if err != nil {
		return err
	}
	if confirmation.DisplayProfileURI != expected.DisplayProfileURI || confirmation.DisplayProfileVersion != expected.DisplayProfileVersion ||
		confirmation.RiskClass != expected.RiskClass || !bytes.Equal(confirmation.DomainID, expected.DomainID) || !bytes.Equal(confirmation.OwnerID, expected.OwnerID) ||
		confirmation.CommandKind != expected.CommandKind || confirmation.Target != expected.Target || confirmation.RecipientOrDestination != nil || confirmation.AmountAndAssetOrCostCeiling != nil ||
		!bytes.Equal(confirmation.PermissionDelta, expected.PermissionDelta) || !bytes.Equal(confirmation.PolicyDelta, expected.PolicyDelta) {
		return errors.New("semantic confirmation display fields are not the canonical command projection")
	}
	return nil
}

func RenderOwnerCommandConfirmation(effect trusted.OwnerCommandEffectV1, input OwnerCommandParametersV1, actionID []byte, expiresAtUnix uint64) (trusted.SemanticConfirmationV1, error) {
	var permission string
	targetKind, targetID, err := ownerCommandTarget(effect, input)
	if err != nil {
		return trusted.SemanticConfirmationV1{}, err
	}
	switch effect.CommandKind {
	case "owner.pause", "owner.resume":
		if len(input.ArtifactDigest) != 0 || len(input.SessionDigest) != 0 || input.ExpectedGeneration != 0 || input.NewGeneration != 0 || input.OwnerExitPlan != nil {
			return trusted.SemanticConfirmationV1{}, errors.New("owner command parameters do not match the owner target")
		}
	case "owner.exit":
		if input.OwnerExitPlan == nil || len(input.ArtifactDigest) != 0 || len(input.SessionDigest) != 0 || input.ExpectedGeneration != 0 || input.NewGeneration != 0 {
			return trusted.SemanticConfirmationV1{}, errors.New("owner exit parameters do not contain exactly one exit plan")
		}
		permission = fmt.Sprintf("exit_stage=%s;exit_revision=%d", input.OwnerExitPlan.Stage, input.OwnerExitPlan.Revision)
	case "capability.promotion.activate", "capability.suspend", "capability.resume", "capability.revoke", "capability.promotion.revoke", "capability.remove":
		if len(input.ArtifactDigest) != sha256.Size || len(input.SessionDigest) != 0 || input.OwnerExitPlan != nil {
			return trusted.SemanticConfirmationV1{}, errors.New("owner command parameters do not match the capability target")
		}
		permission = fmt.Sprintf("artifact=sha256:%s;expected_generation=%d;new_generation=%d", hex.EncodeToString(input.ArtifactDigest), input.ExpectedGeneration, input.NewGeneration)
	case "device-session.revoke", "session.revoke":
		if len(input.SessionDigest) != sha256.Size || len(input.ArtifactDigest) != 0 || input.OwnerExitPlan != nil {
			return trusted.SemanticConfirmationV1{}, errors.New("owner command parameters do not match the session target")
		}
		permission = fmt.Sprintf("session=sha256:%s;expected_generation=%d;new_generation=%d", hex.EncodeToString(input.SessionDigest), input.ExpectedGeneration, input.NewGeneration)
	default:
		return trusted.SemanticConfirmationV1{}, errors.New("owner command has no released confirmation renderer")
	}
	policy := fmt.Sprintf("revision=%d;digest=sha256:%s", effect.PolicyRevision, hex.EncodeToString(effect.PolicyDigest))
	predicate, err := trusted.OwnerCommandAuthorizationPredicateSet(effect)
	if err != nil {
		return trusted.SemanticConfirmationV1{}, err
	}
	risk := "bounded"
	if predicate.RequireIndependentApprover {
		risk = "high"
	}
	return trusted.SemanticConfirmationV1{
		DisplayProfileURI: trusted.OwnerCommandConfirmationProfileV1, DisplayProfileVersion: 1, RiskClass: risk,
		DomainID: append([]byte(nil), effect.DomainID...), OwnerID: append([]byte(nil), effect.OwnerID...), ActionID: append([]byte(nil), actionID...),
		CommandKind: effect.CommandKind, Target: targetKind + ":" + hex.EncodeToString(targetID),
		PermissionDelta: []byte(permission), PolicyDelta: []byte(policy),
		CriticalParameters: [][]byte{append([]byte(nil), effect.ExactParameterDigest...), append([]byte(nil), effect.PolicyDigest...), append([]byte(nil), effect.TargetObjectID...)},
		ExpiresAtUnix:      expiresAtUnix,
	}, nil
}

// ownerCommandTarget is the sole V1 projection from typed command parameters
// to the authority-bearing target. The effect may not independently select a
// different display target from the object the sink will mutate.
func ownerCommandTarget(effect trusted.OwnerCommandEffectV1, input OwnerCommandParametersV1) (string, []byte, error) {
	var kind string
	var identifier []byte
	switch effect.CommandKind {
	case "owner.pause", "owner.resume":
		if effect.AgentID == nil || len(*effect.AgentID) == 0 || len(input.ArtifactDigest) != 0 || len(input.SessionDigest) != 0 || input.ExpectedGeneration != 0 || input.NewGeneration != 0 || input.OwnerExitPlan != nil {
			return "", nil, errors.New("owner command parameters do not identify the current Agent")
		}
		kind, identifier = "agent", *effect.AgentID
	case "owner.exit":
		if input.OwnerExitPlan == nil || len(input.ArtifactDigest) != 0 || len(input.SessionDigest) != 0 || input.ExpectedGeneration != 0 || input.NewGeneration != 0 {
			return "", nil, errors.New("owner exit parameters do not identify exactly one plan")
		}
		kind, identifier = "owner", effect.OwnerID
	case "capability.promotion.activate", "capability.suspend", "capability.resume", "capability.revoke", "capability.promotion.revoke", "capability.remove":
		if len(input.ArtifactDigest) != sha256.Size || len(input.SessionDigest) != 0 || input.OwnerExitPlan != nil {
			return "", nil, errors.New("capability command parameters do not identify one artifact")
		}
		kind, identifier = "capability", input.ArtifactDigest
	case "device-session.revoke", "session.revoke":
		if len(input.SessionDigest) != sha256.Size || len(input.ArtifactDigest) != 0 || input.OwnerExitPlan != nil {
			return "", nil, errors.New("session command parameters do not identify one session")
		}
		kind, identifier = "device-session", input.SessionDigest
	default:
		return "", nil, errors.New("owner command has no released target projection")
	}
	if effect.TargetObjectKind != kind || !bytes.Equal(effect.TargetObjectID, identifier) {
		return "", nil, errors.New("owner command effect target differs from its canonical parameter target")
	}
	return kind, append([]byte(nil), identifier...), nil
}

func (s *Store) validateOwnerCommandScopeLocked(effect trusted.OwnerCommandEffectV1) error {
	if !s.state.Initialized || effect.DomainKind != s.state.DomainKind || !bytes.Equal(effect.DomainID, s.state.DomainID) ||
		!bytes.Equal(effect.OwnerID, s.state.OwnerID) || effect.AgentID == nil || !bytes.Equal(*effect.AgentID, s.state.AgentID) {
		return errors.New("owner command effect is outside the current owner-scoped Agent domain")
	}
	return nil
}

func (s *Store) VerifyOwnerCommandQuery(principal ownercontrol.AuthenticatedPrincipal, now uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.state.Initialized || principal.DomainKind != s.state.DomainKind || !bytes.Equal(principal.DomainID, s.state.DomainID) || !bytes.Equal(principal.OwnerID, s.state.OwnerID) {
		return errors.New("owner command query scope is invalid")
	}
	record, ok := s.state.DeviceSessions[hex.EncodeToString(principal.SessionDigest)]
	if !ok || record.Revoked {
		return errors.New("owner command query device session is unavailable")
	}
	var session trusted.OwnerDeviceSessionV1
	if trusted.DecodeBody(record.Object, "device-session", &session) != nil || session.Audience != principal.Audience ||
		!bytes.Equal(session.ChannelBindingDigest, principal.ChannelBindingDigest) || now < session.NotBeforeUnix || now >= session.ExpiresAtUnix {
		return errors.New("owner command query device session is stale")
	}
	return nil
}

// DeviceSessionForAuthenticatedChannel maps a server-authenticated transport
// channel to exactly one live device session. It deliberately accepts no
// request headers or caller-provided session identity.
func (s *Store) DeviceSessionForAuthenticatedChannel(audience string, channelBindingDigest []byte, now uint64) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.state.Initialized || audience == "" || len(channelBindingDigest) != sha256.Size {
		return nil, errors.New("authenticated owner channel is unavailable")
	}
	var selected []byte
	for encoded, record := range s.state.DeviceSessions {
		if record.Revoked {
			continue
		}
		var session trusted.OwnerDeviceSessionV1
		if trusted.DecodeBody(record.Object, "device-session", &session) != nil || session.Audience != audience ||
			!bytes.Equal(session.ChannelBindingDigest, channelBindingDigest) || now < session.NotBeforeUnix || now >= session.ExpiresAtUnix {
			continue
		}
		digest, err := hex.DecodeString(encoded)
		if err != nil || len(digest) != sha256.Size || selected != nil {
			return nil, errors.New("authenticated owner channel does not select exactly one device session")
		}
		selected = digest
	}
	if selected == nil {
		return nil, errors.New("authenticated owner channel has no live device session")
	}
	return append([]byte(nil), selected...), nil
}

// ApplySignedOwnerCommand is the only public authority-bearing mutation entry.
// It re-verifies the complete signed evidence immediately before the sink
// transition; callers cannot obtain a raw capability state mutator.
func (s *Store) ApplySignedOwnerCommand(principal ownercontrol.AuthenticatedPrincipal, effect trusted.OwnerCommandEffectV1, attempt trusted.OwnerCommandAuthorizationAttemptV1, evidence ownercontrol.SubmissionEvidence, fencingToken []byte) (uint64, error) {
	now, err := s.TrustedNow()
	if err != nil {
		return 0, err
	}
	if err := s.VerifyOwnerCommand(principal, effect, attempt, evidence, now); err != nil {
		return 0, err
	}
	return s.applyOwnerCommand(effect, attempt, evidence.Parameters, fencingToken)
}

func (s *Store) applyOwnerCommand(effect trusted.OwnerCommandEffectV1, attempt trusted.OwnerCommandAuthorizationAttemptV1, parameters, fencingToken []byte) (uint64, error) {
	var input OwnerCommandParametersV1
	if trusted.UnmarshalBody(parameters, &input) != nil || input.SchemaVersion != 1 {
		return 0, errors.New("owner command parameters are not canonical V1")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validateOwnerCommandScopeLocked(effect); err != nil {
		return 0, err
	}
	if _, _, err := ownerCommandTarget(effect, input); err != nil {
		return 0, err
	}
	actionKey := hex.EncodeToString(attempt.ActionID)
	if prior, ok := s.state.OwnerCommandActions[actionKey]; ok {
		if !bytes.Equal(prior.ExactRequestDigest, attempt.ExactRequestDigest) || !bytes.Equal(prior.FencingToken, fencingToken) {
			return 0, errors.New("owner command action identity or fence conflict")
		}
		if prior.State == "applied" {
			return prior.ResultRevision, nil
		}
		return 0, errors.New("owner command action is indeterminate")
	}
	if effect.ControlScopeGeneration != s.state.ControlScopeGeneration || effect.PolicyRevision != s.state.PolicyRevision || !bytes.Equal(effect.PolicyDigest, s.state.PolicyDigest) {
		return 0, ErrStaleAuthority
	}
	if s.state.OwnerPaused && !ownerCommandAllowedWhilePaused(effect.CommandKind) {
		return 0, errors.New("owner pause permits only resume, restriction, revocation, removal, exit, or exact Action resolution")
	}
	var acquisitionAccepting *bool
	switch effect.CommandKind {
	case "owner.pause", "owner.resume":
		if effect.ExpectedTargetRevision != s.state.InventoryRevision || len(input.ArtifactDigest)+len(input.SessionDigest) != 0 || input.OwnerExitPlan != nil {
			return 0, ErrStaleAuthority
		}
		s.state.OwnerPaused = effect.CommandKind == "owner.pause"
		accepting := effect.CommandKind == "owner.resume"
		acquisitionAccepting = &accepting
	case "owner.exit":
		plan := input.OwnerExitPlan
		if plan == nil || effect.ExpectedTargetRevision != s.state.InventoryRevision || validateOwnerExitPlan(plan, s.state.OwnerID, s.state.PolicyDigest) != nil {
			return 0, errors.New("owner exit plan is incomplete or stale")
		}
		priorStage := ""
		priorRevision := uint64(0)
		if s.state.OwnerExit != nil {
			if !bytes.Equal(plan.ExitID, s.state.OwnerExit.ExitID) || !bytes.Equal(plan.PredecessorPolicyDigest, s.state.OwnerExit.PredecessorPolicyDigest) {
				return 0, errors.New("owner exit successor changed immutable plan identity")
			}
			priorStage, priorRevision = s.state.OwnerExit.Stage, s.state.OwnerExit.Revision
		}
		if plan.Revision != priorRevision+1 || !validOwnerExitTransition(priorStage, plan.Stage) {
			return 0, errors.New("owner exit stage is not the exact predecessor-bound successor")
		}
		if plan.Stage == "resolve-actions" && !bytes.Equal(plan.AmbiguousActionSetRoot, s.ambiguousActionSetRootLocked()) {
			return 0, errors.New("owner exit ambiguous Action set is not the current complete set")
		}
		if plan.Stage == "revoke-authorities" {
			for key, record := range s.state.DeviceSessions {
				if !bytes.Equal(byteFromHex(key), attempt.DeviceSessionDigest) {
					record.Revoked = true
					record.RevocationGeneration++
					s.state.DeviceSessions[key] = record
				}
			}
			for key, entry := range s.state.Entries {
				entry.State = StateRevoked
				entry.AdmissionRevocationGeneration++
				entry.PromotionRevocationGeneration++
				s.state.Entries[key] = entry
			}
		}
		if plan.Stage == "abort" {
			s.state.OwnerExit = nil
			s.state.OwnerPaused = false
			accepting := true
			acquisitionAccepting = &accepting
			break
		}
		if priorStage == "" {
			accepting := false
			acquisitionAccepting = &accepting
		}
		copyPlan := *plan
		s.state.OwnerExit = &copyPlan
		s.state.OwnerPaused = true
		if plan.Stage == "tombstone" {
			for key, record := range s.state.DeviceSessions {
				record.Revoked = true
				record.RevocationGeneration++
				s.state.DeviceSessions[key] = record
			}
		}
	case "capability.promotion.activate", "capability.suspend", "capability.resume", "capability.revoke":
		if len(input.ArtifactDigest) != sha256.Size || len(input.SessionDigest) != 0 {
			return 0, errors.New("capability command target is invalid")
		}
		key := hex.EncodeToString(input.ArtifactDigest)
		entry, ok := s.state.Entries[key]
		if !ok || effect.ExpectedTargetRevision != entry.AdmissionRevision || input.ExpectedGeneration != entry.AdmissionRevocationGeneration || input.NewGeneration <= input.ExpectedGeneration {
			return 0, ErrStaleAuthority
		}
		switch effect.CommandKind {
		case "capability.promotion.activate":
			if entry.State != StateAdmitted || entry.InstalledPath == "" || entry.PromotionRequired && entry.PromotionEnvelope == nil {
				return 0, errors.New("capability is not installed with all required promotion evidence")
			}
			entry.State = StateActive
		case "capability.suspend":
			if entry.State != StateActive {
				return 0, ErrStaleAuthority
			}
			entry.State = StateSuspended
		case "capability.resume":
			if entry.State != StateSuspended {
				return 0, ErrStaleAuthority
			}
			entry.State = StateActive
		case "capability.revoke":
			if entry.State != StateAdmitted && entry.State != StateActive && entry.State != StateSuspended {
				return 0, ErrStaleAuthority
			}
			entry.State = StateRevoked
		}
		entry.AdmissionRevocationGeneration = input.NewGeneration
		entry.AdmissionRevision++
		s.state.Entries[key] = entry
	case "capability.promotion.revoke":
		key := hex.EncodeToString(input.ArtifactDigest)
		entry, ok := s.state.Entries[key]
		if !ok || entry.PromotionEnvelope == nil || effect.ExpectedTargetRevision != entry.PromotionRevision || input.ExpectedGeneration != entry.PromotionRevocationGeneration || input.NewGeneration <= input.ExpectedGeneration {
			return 0, ErrStaleAuthority
		}
		entry.State = StateAdmitted
		entry.PromotionRevocationGeneration = input.NewGeneration
		entry.PromotionRevision++
		s.state.Entries[key] = entry
	case "capability.remove":
		key := hex.EncodeToString(input.ArtifactDigest)
		entry, ok := s.state.Entries[key]
		if !ok || effect.ExpectedTargetRevision != s.state.InventoryRevision || input.ExpectedGeneration != s.state.DeletionGeneration || input.NewGeneration <= input.ExpectedGeneration {
			return 0, ErrStaleAuthority
		}
		if entry.State != StateRevoked && entry.State != StateRejected && entry.State != StateExpired {
			return 0, errors.New("capability must be terminal before removal")
		}
		for _, slot := range s.state.UseSlots {
			if slot.State != "terminal" && bytes.Equal(slot.ArtifactDigest, input.ArtifactDigest) {
				return 0, errors.New("artifact has unresolved execution references")
			}
		}
		now, err := s.trustedNowLocked()
		if err != nil {
			return 0, err
		}
		delete(s.state.Entries, key)
		s.state.DeletionGeneration = input.NewGeneration
		s.state.Tombstones[key] = Tombstone{
			ArtifactDigest: append([]byte(nil), input.ArtifactDigest...), PredecessorInventoryRevision: effect.ExpectedTargetRevision,
			InventoryRevision: s.state.InventoryRevision + 1, DeletionGeneration: input.NewGeneration, RemovedAtUnix: now,
			RemovalActionID: append([]byte(nil), attempt.ActionID...), ExactRequestDigest: append([]byte(nil), attempt.ExactRequestDigest...),
			PolicyDigest: append([]byte(nil), effect.PolicyDigest...), ControlScopeGeneration: effect.ControlScopeGeneration,
		}
	case "device-session.revoke", "session.revoke":
		if len(input.SessionDigest) != sha256.Size || len(input.ArtifactDigest) != 0 {
			return 0, errors.New("session command target is invalid")
		}
		key := hex.EncodeToString(input.SessionDigest)
		record, ok := s.state.DeviceSessions[key]
		if !ok || record.Revoked || record.SessionGeneration != effect.ExpectedTargetRevision || record.RevocationGeneration != input.ExpectedGeneration || input.NewGeneration <= input.ExpectedGeneration {
			return 0, ErrStaleAuthority
		}
		record.Revoked, record.RevocationGeneration = true, input.NewGeneration
		s.state.DeviceSessions[key] = record
	default:
		return 0, errors.New("owner command is not implemented by the capability-control sink")
	}
	s.state.ControlScopeGeneration++
	s.state.InventoryRevision++
	s.state.OwnerCommandActions[actionKey] = OwnerCommandAction{ExactRequestDigest: append([]byte(nil), attempt.ExactRequestDigest...), FencingToken: append([]byte(nil), fencingToken...), State: "applied", ResultRevision: s.state.InventoryRevision}
	if err := s.commitAuthorityWithAcquisitionLocked(acquisitionAccepting); err != nil {
		return 0, err
	}
	return s.state.InventoryRevision, nil
}

func ownerCommandAllowedWhilePaused(kind string) bool {
	switch kind {
	case "owner.resume", "owner.exit", "capability.suspend", "capability.revoke", "capability.promotion.revoke", "capability.remove", "device-session.revoke", "session.revoke":
		return true
	default:
		return false
	}
}

func (s *Store) ResolveOwnerCommand(attempt trusted.OwnerCommandAuthorizationAttemptV1, fencingToken []byte) (string, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	prior, ok := s.state.OwnerCommandActions[hex.EncodeToString(attempt.ActionID)]
	if !ok {
		return "unknown", 0, nil
	}
	if !bytes.Equal(prior.ExactRequestDigest, attempt.ExactRequestDigest) || !bytes.Equal(prior.FencingToken, fencingToken) {
		return "conflict", 0, nil
	}
	return prior.State, prior.ResultRevision, nil
}
