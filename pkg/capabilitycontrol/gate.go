package capabilitycontrol

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	trusted "github.com/tosnetwork/tos-service-protocol/pkg/trustedcapability"
)

func (s *Store) Promote(request PromotionRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.state.Initialized {
		return errors.New("owner trust root is not initialized")
	}
	if err := s.requireNewCapabilityWorkLocked(); err != nil {
		return err
	}
	key := hex.EncodeToString(request.ArtifactDigest)
	entry, ok := s.state.Entries[key]
	if !ok || entry.State != StateAdmitted || entry.AdmissionEnvelope == nil {
		return ErrNotAdmitted
	}
	var body trusted.PromotionAuthorityBodyV1
	if err := trusted.DecodeBody(request.Object, "promotion-authority", &body); err != nil {
		return err
	}
	now, err := s.trustedNowLocked()
	if err != nil {
		return err
	}
	if err := s.revalidatePublisherLocked(&entry, now); err != nil {
		return err
	}
	if now < body.NotBeforeUnix || now >= body.ExpiresAtUnix || len(body.PromotionID) != 16 || body.RevocationGeneration == 0 {
		return errors.New("promotion authority is invalid or expired")
	}
	if !bytes.Equal(body.OwnerID, s.state.OwnerID) || !bytes.Equal(body.AgentID, s.state.AgentID) || !bytes.Equal(body.CandidateArtifactVersionDigest, request.ArtifactDigest) ||
		request.Object.DomainKind != s.state.DomainKind || !bytes.Equal(request.Object.DomainID, s.state.DomainID) ||
		!bytes.Equal(body.CandidatePermissionManifestDigest, entry.PermissionManifestDigest) || body.PolicyRevision != s.state.PolicyRevision || !bytes.Equal(body.PolicyDigest, s.state.PolicyDigest) ||
		len(body.GeneratorIdentityDigest) != sha256.Size || len(body.IndependentVerifierSubject.Identifier) != sha256.Size || len(body.ApproverSubject.Identifier) != sha256.Size ||
		len(body.EvaluationManifestDigest) != sha256.Size || len(body.RetainedControlArtifactDigest) != sha256.Size || len(body.RetainedControlResultDigest) != sha256.Size ||
		len(body.PrimaryMetricResultDigest) != sha256.Size || len(body.HarmMetricResultDigest) != sha256.Size || len(body.AllowedRegressionBoundsDigest) != sha256.Size ||
		len(body.ApproverPolicyDigest) != sha256.Size || !bytes.Equal(body.ApproverPolicyDigest, s.state.PolicyDigest) ||
		trusted.ValidateReference(body.EvaluationResultReference) != nil || trusted.ValidateReference(body.VerifierAuthorizationEnvelopeReference) != nil ||
		bytes.Equal(body.GeneratorIdentityDigest, body.ApproverSubject.Identifier) || sameAuthoritySubject(body.IndependentVerifierSubject, body.ApproverSubject) ||
		bytes.Equal(body.GeneratorIdentityDigest, body.IndependentVerifierSubject.Identifier) {
		return errors.New("promotion scope or separation-of-duty predicate failed")
	}
	if err := trusted.VerifyAuthorization(request.Envelope, request.Object, now, s.state.AuthorityEpoch); err != nil {
		return err
	}
	if err := s.verifyPolicyAuthorizationLocked(request.Envelope, "promotion-authority", body.AgentID); err != nil {
		return err
	}
	// The approver identity is the policy-authorized signing principal. It is
	// never accepted as an unauthenticated label supplied by the generator.
	if !sameAuthoritySubject(body.ApproverSubject, request.Envelope.Body.IssuerSubject) {
		return errors.New("promotion approver is not the verified envelope issuer")
	}
	if !subjectAllowed(s.state.AuthorizedSubjects, "evaluation-verifier", body.IndependentVerifierSubject.Identifier) {
		return errors.New("promotion verifier is not pinned by the active owner policy")
	}
	if !subjectAllowed(s.state.AuthorizedSubjects, "capability-generator", body.GeneratorIdentityDigest) ||
		!bytes.Equal(s.state.PromotionSeparationPolicyDigest, v1PromotionSeparationPolicyDigest()) {
		return errors.New("promotion generator or separation policy is not pinned by the active owner policy")
	}
	// The generator must attest the exact promotion body. Merely naming an
	// otherwise authorized generator cannot manufacture separation of duty.
	if err := s.verifyPromotionGeneratorLocked(request.GeneratorAuthorization, request.Object, body, now); err != nil {
		return errors.New("promotion generator did not authorize the exact candidate promotion")
	}
	generatorController := s.state.AuthorityControllers[hex.EncodeToString(body.GeneratorIdentityDigest)]
	verifierController := s.state.AuthorityControllers[hex.EncodeToString(body.IndependentVerifierSubject.Identifier)]
	approverController := s.state.AuthorityControllers[hex.EncodeToString(body.ApproverSubject.Identifier)]
	if generatorController == "" || verifierController == "" || approverController == "" ||
		generatorController == verifierController || generatorController == approverController || verifierController == approverController {
		return errors.New("promotion generator, verifier, and approver lack policy-bound controller separation")
	}
	if !bytes.Equal(body.PromotionID, request.Envelope.Body.AuthorityID) || body.AuthorityRevision != request.Envelope.Body.AuthorityRevision ||
		!optionalBytesEqual(body.PredecessorEnvelopeDigest, request.Envelope.Body.PredecessorEnvelopeDigest) {
		return errors.New("promotion body and authorization chain identity diverge")
	}
	if err := trusted.ReferenceMatchesObject(body.EvaluationResultReference, request.EvaluationObject); err != nil {
		return err
	}
	if err := trusted.ReferenceMatchesObject(body.VerifierAuthorizationEnvelopeReference, request.VerifierEnvelopeObject); err != nil {
		return err
	}
	var evaluation trusted.EvaluationResultV1
	if err := trusted.DecodeBody(request.EvaluationObject, "evaluation-result", &evaluation); err != nil {
		return err
	}
	var verifierEnvelope trusted.ProfileAuthorizationEnvelopeV1
	if err := trusted.DecodeBody(request.VerifierEnvelopeObject, "authorization-envelope", &verifierEnvelope); err != nil {
		return err
	}
	if err := trusted.VerifyAuthorization(verifierEnvelope, request.EvaluationObject, now, s.state.AuthorityEpoch); err != nil {
		return err
	}
	if verifierEnvelope.Body.AuthorityKind != "evaluation-verifier" || !sameAuthoritySubject(verifierEnvelope.Body.IssuerSubject, body.IndependentVerifierSubject) ||
		!bytes.Equal(verifierEnvelope.Body.OwnerID, s.state.OwnerID) || verifierEnvelope.Body.AgentID == nil || !bytes.Equal(*verifierEnvelope.Body.AgentID, s.state.AgentID) ||
		verifierEnvelope.Body.PolicyRevision != s.state.PolicyRevision || !bytes.Equal(verifierEnvelope.Body.PolicyDigest, s.state.PolicyDigest) ||
		evaluation.SchemaVersion != trusted.SchemaVersion || !bytes.Equal(evaluation.CandidateArtifactDigest, request.ArtifactDigest) ||
		!bytes.Equal(evaluation.PermissionManifestDigest, entry.PermissionManifestDigest) || !bytes.Equal(evaluation.PolicyDigest, s.state.PolicyDigest) ||
		evaluation.PolicyRevision != s.state.PolicyRevision || now >= evaluation.ExpiresAtUnix ||
		!bytes.Equal(evaluation.RetainedControlResultDigest, body.RetainedControlResultDigest) {
		return errors.New("promotion evaluation or independent verifier evidence is not exact and current")
	}
	if err := validatePromotionEvidence(request, body, evaluation, s.state.OwnerID, s.state.AgentID, s.state.PolicyDigest, s.state.PolicyRevision, now); err != nil {
		return err
	}
	if err := s.acceptAuthorityHeadLocked(request.Envelope); err != nil {
		return err
	}
	entry.PromotionObject = &request.Object
	entry.PromotionEnvelope = &request.Envelope
	entry.PromotionRevision = body.AuthorityRevision + 1
	entry.PromotionRevocationGeneration = body.RevocationGeneration
	// Promotion records independent evidence but does not itself start using the
	// executable bytes. Activation is a separate, explicitly confirmed Owner
	// Command after installation has completed.
	entry.State = StateAdmitted
	entry.UpdatedAtUnix = now
	s.state.Entries[key] = entry
	s.state.InventoryRevision++
	return s.commitAuthorityLocked()
}

func (s *Store) verifyPromotionGeneratorLocked(envelope trusted.ProfileAuthorizationEnvelopeV1, object trusted.ProfileObjectV1, body trusted.PromotionAuthorityBodyV1, now uint64) error {
	if err := trusted.VerifyAuthorization(envelope, object, now, s.state.AuthorityEpoch); err != nil {
		return err
	}
	if err := s.verifyPolicyAuthorizationLocked(envelope, "capability-generator", body.AgentID); err != nil {
		return err
	}
	if !bytes.Equal(envelope.Body.IssuerSubject.Identifier, body.GeneratorIdentityDigest) {
		return errors.New("generator authorization subject mismatch")
	}
	return nil
}

func v1PromotionSeparationPolicyDigest() []byte {
	value := sha256.Sum256([]byte("tos.openfox.promotion-separation.v1\x00capability-generator\x00evaluation-verifier\x00promotion-authority\x00minimum-distinct-controllers=3"))
	return value[:]
}

func validatePromotionEvidence(request PromotionRequest, promotion trusted.PromotionAuthorityBodyV1, result trusted.EvaluationResultV1, ownerID, agentID, policyDigest []byte, policyRevision, now uint64) error {
	sourcingDigest, err := trusted.ObjectDigest(request.SourcingDecisionObject)
	if err != nil || !bytes.Equal(sourcingDigest, promotion.SourcingDecisionDigest) {
		return errors.New("exact sourcing decision is unavailable")
	}
	var sourcing trusted.CapabilitySourcingDecisionV1
	if err := trusted.DecodeBody(request.SourcingDecisionObject, "sourcing-decision", &sourcing); err != nil {
		return err
	}
	if err := trusted.ValidateSourcingDecision(sourcing, promotion.CandidateArtifactVersionDigest, ownerID, agentID, policyDigest, policyRevision, now); err != nil {
		return err
	}
	manifestDigest, err := trusted.ObjectDigest(request.EvaluationManifestObject)
	if err != nil || !bytes.Equal(manifestDigest, promotion.EvaluationManifestDigest) {
		return errors.New("exact evaluation manifest is unavailable")
	}
	var manifest trusted.CapabilityEvaluationManifestV1
	if err := trusted.DecodeBody(request.EvaluationManifestObject, "evaluation-manifest", &manifest); err != nil {
		return err
	}
	if err := trusted.ValidateEvaluationManifest(manifest, promotion, policyDigest, policyRevision, now); err != nil {
		return err
	}
	if !bytes.Equal(result.RuntimeSandboxDigest, manifest.RuntimeSandboxDigest) || !bytes.Equal(result.CorpusCommitment, manifest.CorpusCommitment) ||
		!bytes.Equal(result.CompleteResultSetDigest, manifest.CompleteResultSetDigest) || !bytes.Equal(result.RetainedControlResultDigest, manifest.RetainedControlResultDigest) {
		return errors.New("evaluation result and manifest diverge")
	}
	objects := map[string]trusted.ProfileObjectV1{}
	var prior []byte
	for _, object := range request.EvidenceObjects {
		digest, err := trusted.ObjectDigest(object)
		if err != nil || prior != nil && bytes.Compare(prior, digest) >= 0 {
			return errors.New("promotion evidence objects are invalid, duplicated, or unsorted")
		}
		objects[hex.EncodeToString(digest)] = object
		prior = digest
	}
	for _, attempt := range sourcing.SourceAttempts {
		object, ok := objects[hex.EncodeToString(attempt.SourceSnapshotReference.ObjectDigest)]
		if !ok || trusted.ReferenceMatchesObject(attempt.SourceSnapshotReference, object) != nil {
			return errors.New("source snapshot evidence is unavailable")
		}
	}
	required := []struct {
		kind   string
		digest []byte
	}{
		{"candidate-origin", promotion.CandidateOriginDigest},
		{"retained-control-artifact", promotion.RetainedControlArtifactDigest},
		{"retained-control-result", promotion.RetainedControlResultDigest},
		{"unseen-task-commitment", promotion.UnseenTaskCommitment},
		{"primary-metric-result", promotion.PrimaryMetricResultDigest},
		{"harm-metric-result", promotion.HarmMetricResultDigest},
		{"regression-bounds", promotion.AllowedRegressionBoundsDigest},
		{"rollback-artifact", promotion.RollbackArtifactDigest},
		{"rollback-plan", promotion.RollbackPlanDigest},
	}
	for _, item := range required {
		object, ok := objects[hex.EncodeToString(item.digest)]
		if !ok {
			return errors.New("required promotion evidence object is unavailable: " + item.kind)
		}
		var evidence trusted.EvaluationEvidenceV1
		if err := trusted.DecodeBody(object, "evaluation-evidence", &evidence); err != nil {
			return err
		}
		if err := trusted.ValidateEvaluationEvidence(evidence, item.kind, promotion.CandidateArtifactVersionDigest, promotion.CandidatePermissionManifestDigest, policyDigest, now); err != nil {
			return err
		}
	}
	for _, digest := range manifest.EvidenceObjectDigests {
		if _, ok := objects[hex.EncodeToString(digest)]; !ok {
			return errors.New("evaluation manifest evidence closure is incomplete")
		}
	}
	return nil
}

func sameAuthoritySubject(left, right trusted.TypedAuthoritySubjectV1) bool {
	return left.Kind == right.Kind && left.Namespace == right.Namespace && bytes.Equal(left.Identifier, right.Identifier)
}

func optionalBytesEqual(left, right *[]byte) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return bytes.Equal(*left, *right)
}

func (s *Store) Install(request InstallationRequest) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.installVerifier == nil || !s.state.Initialized {
		return "", errors.New("authorized installation broker is unavailable")
	}
	if err := s.requireNewCapabilityWorkLocked(); err != nil {
		return "", err
	}
	var transaction trusted.CapabilityInstallationTransactionV1
	if err := trusted.DecodeBody(request.Object, "installation-transaction", &transaction); err != nil {
		return "", err
	}
	now, err := s.trustedNowLocked()
	if err != nil {
		return "", err
	}
	if request.Object.DomainKind != s.state.DomainKind || !bytes.Equal(request.Object.DomainID, s.state.DomainID) ||
		transaction.SchemaVersion != trusted.SchemaVersion || len(transaction.InstallationID) != 16 ||
		!bytes.Equal(transaction.InstallationID, s.state.InstallationID) || transaction.State != "prepared" ||
		transaction.ExpectedInventoryRevision != s.state.InventoryRevision || transaction.PolicyRevision != s.state.PolicyRevision ||
		len(transaction.QuarantineObjectDigest) != sha256.Size || len(transaction.TargetStoreDigest) != sha256.Size ||
		len(transaction.DependencyClosureDigest) != sha256.Size || len(transaction.InstallPlanDigest) != sha256.Size || len(transaction.RollbackPlanDigest) != sha256.Size ||
		len(transaction.WriterFenceDigest) != sha256.Size || len(transaction.StableActionID) != sha256.Size || len(transaction.ExactRequestDigest) != sha256.Size ||
		trusted.ValidateReference(transaction.SourceObjectReference) != nil {
		return "", errors.New("installation transaction is incomplete or stale")
	}
	if err := trusted.VerifyAuthorization(request.Envelope, request.Object, now, s.state.AuthorityEpoch); err != nil {
		return "", err
	}
	if err := s.verifyPolicyAuthorizationLocked(request.Envelope, "capability-installation", s.state.AgentID); err != nil {
		return "", err
	}
	if err := s.installVerifier.VerifyCapabilityInstallation(context.Background(), transaction); err != nil {
		return "", err
	}
	wantAction, wantRequest, err := deriveInstallationIdentity(s.state.OwnerID, s.state.AgentID, transaction)
	if err != nil || !bytes.Equal(wantAction, transaction.StableActionID) || !bytes.Equal(wantRequest, transaction.ExactRequestDigest) {
		return "", errors.New("installation semantic Action identity mismatch")
	}
	storeHash := sha256.Sum256(append([]byte("tos.capability-target-store.v1\x00"), s.state.InstallationID...))
	if !bytes.Equal(transaction.TargetStoreDigest, storeHash[:]) {
		return "", errors.New("installation target store mismatch")
	}
	key := hex.EncodeToString(transaction.ArtifactVersionDigest)
	entry, ok := s.state.Entries[key]
	if !ok || entry.State != StateAdmitted && entry.State != StateActive || entry.AdmissionEnvelope == nil {
		return "", ErrNotAdmitted
	}
	if err := s.revalidatePublisherLocked(&entry, now); err != nil {
		return "", err
	}
	if entry.QuarantinePath == "" || !bytes.Equal(transaction.QuarantineObjectDigest, entry.ObservedContentDigest) {
		return "", ErrStaleAuthority
	}
	admissionDigest, err := authorizationEnvelopeDigest(*entry.AdmissionEnvelope)
	if err != nil || !bytes.Equal(transaction.AdmissionEnvelopeDigest, admissionDigest) {
		return "", ErrStaleAuthority
	}
	slotKey := hex.EncodeToString(transaction.StableActionID)
	if prior, exists := s.state.InstallationSlots[slotKey]; exists {
		if !bytes.Equal(prior.ExactRequestDigest, transaction.ExactRequestDigest) || !bytes.Equal(prior.ArtifactDigest, transaction.ArtifactVersionDigest) {
			return "", errors.New("installation Action identity conflict")
		}
		if prior.State == "installed" {
			return prior.TargetPath, nil
		}
		if prior.State != "activating" {
			return "", ErrAmbiguousStart
		}
	} else if err := s.acceptAuthorityHeadLocked(request.Envelope); err != nil {
		return "", err
	}
	actual, err := HashTree(entry.QuarantinePath)
	if err != nil {
		return "", err
	}
	if !bytes.Equal(actual, entry.ObservedContentDigest) {
		return "", errors.New("quarantine bytes do not match artifact digest")
	}
	target := filepath.Join(s.root, "objects", key)
	if _, exists := s.state.InstallationSlots[slotKey]; !exists {
		s.state.InstallationSlots[slotKey] = InstallationSlot{ActionID: transaction.StableActionID, ExactRequestDigest: transaction.ExactRequestDigest, ArtifactDigest: transaction.ArtifactVersionDigest, State: "activating", TargetPath: target}
		if err := s.commitAuthorityLocked(); err != nil {
			return "", err
		}
	}
	if err := copyTreeNoFollow(entry.QuarantinePath, target); err != nil {
		return "", err
	}
	verified, err := HashTree(target)
	if err != nil || !bytes.Equal(verified, entry.ObservedContentDigest) {
		_ = os.RemoveAll(target)
		return "", errors.New("materialized artifact verification failed")
	}
	if err := sealTreeReadOnly(target); err != nil {
		return "", err
	}
	entry.InstalledPath = target
	entry.InstallationRevision++
	entry.UpdatedAtUnix = now
	s.state.Entries[key] = entry
	s.state.InventoryRevision++
	slot := s.state.InstallationSlots[slotKey]
	slot.State = "installed"
	s.state.InstallationSlots[slotKey] = slot
	if err := s.commitAuthorityLocked(); err != nil {
		return "", err
	}
	return target, nil
}

func deriveInstallationIdentity(ownerID, agentID []byte, transaction trusted.CapabilityInstallationTransactionV1) ([]byte, []byte, error) {
	copyForRequest := transaction
	copyForRequest.StableActionID = nil
	copyForRequest.ExactRequestDigest = nil
	canonical, err := trusted.MarshalBody(copyForRequest)
	if err != nil {
		return nil, nil, err
	}
	action, _, err := commerce.DeriveStableActionID("capability.install", map[string]commerce.SemanticValue{
		"owner_id": commerce.ID(hex.EncodeToString(ownerID)), "agent_id": commerce.ID(hex.EncodeToString(agentID)),
		"artifact_version_digest":     commerce.Digest32("sha256:" + hex.EncodeToString(transaction.ArtifactVersionDigest)),
		"installation_id":             commerce.ID(hex.EncodeToString(transaction.InstallationID)),
		"target_store_digest":         commerce.Digest32("sha256:" + hex.EncodeToString(transaction.TargetStoreDigest)),
		"expected_inventory_revision": commerce.U64(transaction.ExpectedInventoryRevision),
	})
	if err != nil {
		return nil, nil, err
	}
	actionRaw, err := hex.DecodeString(action[len("sha256:"):])
	if err != nil {
		return nil, nil, err
	}
	requestDigest, err := commerce.ExactRequestDigest(canonical)
	if err != nil {
		return nil, nil, err
	}
	requestRaw, err := hex.DecodeString(requestDigest[len("sha256:"):])
	if err != nil {
		return nil, nil, err
	}
	return actionRaw, requestRaw, nil
}

// PrepareUse atomically creates a one-shot execution slot and returns the
// unpersisted resolution capability. A retry after an ambiguous return cannot
// obtain a replacement token and must reconcile the original runner.
func (s *Store) PrepareUse(request StartRequest) ([]byte, error) {
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return nil, errors.New("generate execution resolution capability")
	}
	digest := sha256.Sum256(append([]byte("openfox.capability-use-resolution.v1\x00"), token...))
	if err := s.validateUse(request, true, digest[:]); err != nil {
		return nil, err
	}
	return token, nil
}

// RevalidateUse checks current authority and immutable resources for an
// already-started slot. It cannot create a new slot.
func (s *Store) RevalidateUse(request StartRequest) error {
	return s.validateUse(request, false, nil)
}

func (s *Store) validateUse(request StartRequest, create bool, resolutionTokenDigest []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.OwnerPaused {
		return errors.New("owner control scope is paused")
	}
	now, err := s.trustedNowLocked()
	if err != nil {
		return err
	}
	if !s.state.Initialized {
		return errors.New("owner trust root is not initialized")
	}
	if create && s.state.OwnerExit != nil {
		return errors.New("owner exit fences new capability work")
	}
	if err := trusted.ValidateUseBindingShape(request.Binding, request.Remote); err != nil {
		return err
	}
	var lease trusted.CapabilityUseLeaseV1
	if err := trusted.DecodeBody(request.LeaseObject, "use-lease", &lease); err != nil {
		return err
	}
	if err := trusted.ValidateUseLease(lease, now, s.state.AuthorityEpoch, request.Binding.AdmissionRevocationGeneration,
		valueOrZero(request.Binding.PromotionRevocationGeneration)); err != nil {
		return err
	}
	if err := trusted.VerifyAuthorization(request.LeaseEnvelope, request.LeaseObject, now, s.state.AuthorityEpoch); err != nil {
		return err
	}
	if entryPermissionObject := request.PermissionSubsetObject; entryPermissionObject.ObjectKind == "" {
		return errors.New("exact selected permission subset is required")
	}
	if err := s.verifyPolicyAuthorizationLocked(request.LeaseEnvelope, "use-lease", lease.AgentID); err != nil {
		return err
	}
	if request.LeaseObject.DomainKind != s.state.DomainKind || !bytes.Equal(request.LeaseObject.DomainID, s.state.DomainID) {
		return ErrStaleAuthority
	}
	leaseDigest, err := trusted.ObjectDigest(request.LeaseObject)
	if err != nil {
		return err
	}
	if !bytes.Equal(request.Binding.UseLeaseDigest, leaseDigest) ||
		trusted.ValidateLeaseBinding(lease, request.Binding, s.state.InstallationID) != nil {
		return ErrStaleAuthority
	}
	key := hex.EncodeToString(request.Binding.ArtifactVersionDigest)
	entry, ok := s.state.Entries[key]
	if !ok || entry.State == StateUnverifiedLegacy {
		return ErrUnverifiedLegacy
	}
	if entry.State != StateActive || entry.AdmissionEnvelope == nil || entry.InstalledPath == "" {
		return ErrNotAdmitted
	}
	if err := s.revalidatePublisherLocked(&entry, now); err != nil {
		return err
	}
	if entry.PermissionObject == nil {
		return errors.New("admitted permission manifest is unavailable")
	}
	var admissionBody trusted.CapabilityAdmissionBodyV1
	if entry.AdmissionObject == nil || trusted.DecodeBody(*entry.AdmissionObject, "capability-admission", &admissionBody) != nil ||
		trusted.ValidateAdmission(admissionBody, now) != nil || trusted.VerifyAuthorization(*entry.AdmissionEnvelope, *entry.AdmissionObject, now, s.state.AuthorityEpoch) != nil {
		return errors.New("stored admission authority is invalid or expired")
	}
	admissionEnvelopeDigest, err := authorizationEnvelopeDigest(*entry.AdmissionEnvelope)
	if err != nil || !bytes.Equal(admissionEnvelopeDigest, request.Binding.AdmissionEnvelopeDigest) ||
		!bytes.Equal(admissionEnvelopeDigest, lease.AdmissionEnvelopeDigest) {
		return ErrStaleAuthority
	}
	var promotionEnvelopeDigest []byte
	if entry.PromotionRequired {
		if entry.PromotionObject == nil || entry.PromotionEnvelope == nil {
			return ErrPromotionRequired
		}
		var promotionBody trusted.PromotionAuthorityBodyV1
		if trusted.DecodeBody(*entry.PromotionObject, "promotion-authority", &promotionBody) != nil || now < promotionBody.NotBeforeUnix || now >= promotionBody.ExpiresAtUnix ||
			trusted.VerifyAuthorization(*entry.PromotionEnvelope, *entry.PromotionObject, now, s.state.AuthorityEpoch) != nil {
			return errors.New("stored promotion authority is invalid or expired")
		}
		promotionEnvelopeDigest, err = authorizationEnvelopeDigest(*entry.PromotionEnvelope)
		if err != nil || request.Binding.PromotionEnvelopeDigest == nil || !bytes.Equal(*request.Binding.PromotionEnvelopeDigest, promotionEnvelopeDigest) {
			return ErrStaleAuthority
		}
	} else if request.Binding.PromotionEnvelopeDigest != nil {
		return ErrStaleAuthority
	}
	var admittedPermissions, selectedPermissions trusted.CapabilityPermissionManifestV1
	if err := trusted.DecodeBody(*entry.PermissionObject, "permission-manifest", &admittedPermissions); err != nil {
		return err
	}
	if err := trusted.DecodeBody(request.PermissionSubsetObject, "permission-manifest", &selectedPermissions); err != nil {
		return err
	}
	selectedDigest, err := trusted.ObjectDigest(request.PermissionSubsetObject)
	if err != nil || !bytes.Equal(selectedDigest, request.Binding.PermissionSubsetDigest) || trusted.PermissionSubsetOf(selectedPermissions, admittedPermissions) != nil {
		return errors.New("selected permission subset exceeds admitted authority")
	}
	loadedClosure, err := HashTree(entry.InstalledPath)
	if err != nil || !bytes.Equal(loadedClosure, entry.ObservedContentDigest) {
		return errors.New("installed capability bytes changed after verification")
	}
	if entry.AdmissionRevision != request.Binding.AdmissionRevision || entry.AdmissionRevocationGeneration != request.Binding.AdmissionRevocationGeneration ||
		entry.PromotionRevision != valueOrZero(request.Binding.PromotionRevision) || entry.PromotionRevocationGeneration != valueOrZero(request.Binding.PromotionRevocationGeneration) ||
		request.Binding.AuthorityEpoch != s.state.AuthorityEpoch || request.Binding.PolicyRevision != s.state.PolicyRevision || !bytes.Equal(request.Binding.PolicyDigest, s.state.PolicyDigest) ||
		request.Binding.ControlScopeGeneration != s.state.ControlScopeGeneration || request.Binding.InventoryRevision != s.state.InventoryRevision ||
		request.Binding.InstallationRevision != entry.InstallationRevision || !bytes.Equal(request.Binding.LoadedObjectDigest, request.Binding.ArtifactVersionDigest) ||
		!bytes.Equal(request.Binding.PermissionSubsetDigest, lease.PermissionSubsetDigest) {
		return ErrStaleAuthority
	}
	observed := request.Observed
	if !bytes.Equal(observed.LoadedObjectDigest, request.Binding.LoadedObjectDigest) || observed.InstallationRevision != request.Binding.InstallationRevision ||
		!bytes.Equal(observed.RuntimeAndSandboxDigest, request.Binding.RuntimeAndSandboxDigest) ||
		!bytes.Equal(observed.EffectiveEnvironmentDigest, request.Binding.EffectiveEnvironmentDigest) ||
		!bytes.Equal(observed.CredentialCapabilityReferenceSetDigest, request.Binding.CredentialCapabilityReferenceSetDigest) ||
		!bytes.Equal(observed.FilesystemHandleSetDigest, request.Binding.FilesystemHandleSetDigest) ||
		!bytes.Equal(observed.NetworkBrokerPolicyDigest, request.Binding.NetworkBrokerPolicyDigest) ||
		!optionalBytesEqual(observed.RemoteSessionHandshakeDigest, request.Binding.RemoteSessionHandshakeDigest) {
		return errors.New("capability start rejected caller-selected runtime resources")
	}
	requestDigest, err := capabilityUseRequestDigest(s.state.DomainKind, s.state.DomainID, request.Binding)
	if err != nil {
		return err
	}
	slotKey := hex.EncodeToString(request.Binding.ExecutionID)
	if current, exists := s.state.UseSlots[slotKey]; exists {
		if useSlotMatchesExactRequest(current, request.Binding.ActionID, requestDigest) {
			if !create {
				return nil
			}
			return ErrAmbiguousStart
		}
		// The execution identity is permanently consumed. A different request is
		// a terminal conflict, never a fresh or idempotent start.
		return ErrAmbiguousStart
	}
	if !create || len(resolutionTokenDigest) != sha256.Size {
		return errors.New("execution slot is not durably started")
	}
	outcomeAuthority, err := s.singleOutcomeAuthorityLocked()
	if err != nil {
		return err
	}
	s.state.Entries[key] = entry
	s.state.UseSlots[slotKey] = UseSlot{ExecutionID: request.Binding.ExecutionID, ActionID: request.Binding.ActionID, ExactRequestDigest: requestDigest, ArtifactDigest: request.Binding.ArtifactVersionDigest,
		State: "started", LeaseDigest: leaseDigest, ControlScopeGeneration: s.state.ControlScopeGeneration,
		AdmissionRevision: entry.AdmissionRevision, AdmissionRevocationGeneration: entry.AdmissionRevocationGeneration,
		PromotionRevision: entry.PromotionRevision, PromotionRevocationGeneration: entry.PromotionRevocationGeneration, StartedAtUnix: now,
		ResolutionTokenDigest: append([]byte(nil), resolutionTokenDigest...), OutcomeAuthorityID: outcomeAuthority, OutcomeAuthorityEpoch: s.state.AuthorityEpoch}
	return s.commitAuthorityLocked()
}

func useSlotMatchesExactRequest(current UseSlot, actionID, exactRequestDigest []byte) bool {
	return current.State == "started" && bytes.Equal(current.ActionID, actionID) && bytes.Equal(current.ExactRequestDigest, exactRequestDigest)
}

func authorizationEnvelopeDigest(envelope trusted.ProfileAuthorizationEnvelopeV1) ([]byte, error) {
	object, err := trusted.NewObject(trusted.DomainKind(envelope.Body.DomainKind), envelope.Body.DomainID, "authorization-envelope", envelope)
	if err != nil {
		return nil, err
	}
	return trusted.ObjectDigest(object)
}

func (s *Store) ResolveUse(executionID, resolutionToken []byte, disposition string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if disposition != "succeeded" && disposition != "failed" && disposition != "killed" && disposition != "rejected" && disposition != "ambiguous" {
		return errors.New("execution disposition is invalid")
	}
	key := hex.EncodeToString(executionID)
	slot, ok := s.state.UseSlots[key]
	if !ok {
		return errors.New("execution slot is unknown")
	}
	tokenDigest := sha256.Sum256(append([]byte("openfox.capability-use-resolution.v1\x00"), resolutionToken...))
	if len(resolutionToken) != sha256.Size || !bytes.Equal(tokenDigest[:], slot.ResolutionTokenDigest) {
		return errors.New("execution resolution capability is invalid")
	}
	if slot.State == "terminal" {
		if slot.TerminalDisposition == disposition {
			return nil
		}
		return errors.New("execution slot terminal disposition conflicts")
	}
	if slot.State == "ambiguous" {
		if disposition == "ambiguous" {
			return nil
		}
		// The start capability authorizes the original runner to record a
		// directly observed result. Once that runner reports uncertainty, the
		// capability cannot manufacture a result. Keep the slot unresolved
		// until a separately authenticated executor/sink evidence profile is
		// available.
		return errors.New("ambiguous execution requires authoritative outcome evidence")
	}
	if disposition == "succeeded" {
		entry, exists := s.state.Entries[hex.EncodeToString(slot.ArtifactDigest)]
		if !exists || entry.State != StateActive || slot.ControlScopeGeneration != s.state.ControlScopeGeneration || entry.AdmissionRevision != slot.AdmissionRevision ||
			entry.AdmissionRevocationGeneration != slot.AdmissionRevocationGeneration || entry.PromotionRevision != slot.PromotionRevision || entry.PromotionRevocationGeneration != slot.PromotionRevocationGeneration {
			return ErrStaleAuthority
		}
	}
	now, err := s.trustedNowLocked()
	if err != nil {
		return err
	}
	if disposition == "ambiguous" {
		slot.State = "ambiguous"
	} else {
		slot.State = "terminal"
	}
	slot.ResolvedAtUnix = now
	slot.TerminalDisposition = disposition
	s.state.UseSlots[key] = slot
	return s.commitAuthorityLocked()
}

func copyTreeNoFollow(source, target string) error {
	return secureMaterializeTree(source, target)
}

func sealTreeReadOnly(root string) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		// Manifest-committed modes are part of artifact identity and cannot be
		// rewritten while claiming the same closure. Consequential execution
		// remeasures the tree and consumes a pinned/sealed descriptor or copied
		// instruction bytes, so pathname permissions are not the trust boundary.
		return nil
	})
}

func valueOrZero(value *uint64) uint64 {
	if value == nil {
		return 0
	}
	return *value
}

var _ = sha256.Size
