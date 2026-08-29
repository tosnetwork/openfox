package capabilitycontrol

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"

	trusted "github.com/tosnetwork/tos-service-protocol/pkg/trustedcapability"
)

type ExecutionAuthoritySnapshot struct {
	AuthorityEpoch, PolicyRevision, AdmissionRevocationGeneration, PromotionRevocationGeneration, ControlScopeGeneration uint64
	AdmissionRevision, PromotionRevision, InstallationRevision, InventoryRevision                                        uint64
	PolicyDigest, AdmissionEnvelopeDigest, PromotionEnvelopeDigest, PermissionManifestDigest                             []byte
	AdmittedPermissionManifest                                                                                           trusted.CapabilityPermissionManifestV1
	LeaseIssuerSubject                                                                                                   trusted.TypedAuthoritySubjectV1
	LeaseAuthorityID                                                                                                     []byte
	LeaseProofProfileURI                                                                                                 string
	InFlightRevocationPolicy                                                                                             string
	OwnerID, AgentID, InstallationID                                                                                     []byte
}

// InstalledEntrypoint is an exact, remeasured executable selected from the
// signed content and entrypoint manifests. Callers must launch Path without
// substituting another command or argument vector.
type InstalledEntrypoint struct {
	Path             string
	Arguments        []string
	Artifact         []byte
	Descriptor       []byte
	ExecutableDigest []byte
}

func (s *Store) OpenInstalledEntrypoint(artifactDigest []byte) (InstalledEntrypoint, *os.File, error) {
	entrypoint, err := s.ResolveInstalledEntrypoint(artifactDigest)
	if err != nil {
		return InstalledEntrypoint{}, nil, err
	}
	before, err := os.Lstat(entrypoint.Path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return InstalledEntrypoint{}, nil, errors.New("entrypoint changed before open")
	}
	file, err := os.Open(entrypoint.Path)
	if err != nil {
		return InstalledEntrypoint{}, nil, err
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		_ = file.Close()
		return InstalledEntrypoint{}, nil, errors.New("entrypoint pathname was substituted during open")
	}
	return entrypoint, file, nil
}

type SealedLLMSkill struct {
	ArtifactDigest []byte
	Instructions   []byte
}

// SealLLMSkill copies exact SKILL.md bytes from the admitted immutable tree.
func (s *Store) SealLLMSkill(artifactDigest []byte) (SealedLLMSkill, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.state.Initialized || s.state.OwnerPaused || s.state.OwnerExit != nil {
		return SealedLLMSkill{}, errors.New("capability execution authority is unavailable")
	}
	entry, ok := s.state.Entries[hex.EncodeToString(artifactDigest)]
	if !ok || entry.State != StateActive || entry.ArtifactKind != "skill" || entry.InstalledPath == "" {
		return SealedLLMSkill{}, ErrNotAdmitted
	}
	closure, err := HashTree(entry.InstalledPath)
	if err != nil || !bytes.Equal(closure, entry.ObservedContentDigest) {
		return SealedLLMSkill{}, errors.New("installed skill closure changed")
	}
	path := filepath.Join(entry.InstalledPath, "SKILL.md")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > 64<<10 {
		return SealedLLMSkill{}, errors.New("admitted skill has no bounded direct SKILL.md")
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return SealedLLMSkill{}, errors.New("admitted SKILL.md changed before open")
	}
	file, err := os.Open(path)
	if err != nil {
		return SealedLLMSkill{}, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		return SealedLLMSkill{}, errors.New("admitted SKILL.md was substituted during open")
	}
	raw, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	if err != nil || len(raw) == 0 || len(raw) > 64<<10 {
		return SealedLLMSkill{}, errors.New("admitted SKILL.md is unreadable or oversized")
	}
	var manifest trusted.CapabilityContentManifestV1
	if entry.ContentManifestObject == nil || trusted.DecodeBody(*entry.ContentManifestObject, "content-manifest", &manifest) != nil {
		return SealedLLMSkill{}, errors.New("admitted Skill content manifest is unavailable")
	}
	var want []byte
	for _, item := range manifest.Entries {
		if item.Path == "SKILL.md" && item.ObjectType == "regular" {
			want = item.ContentDigest
		}
	}
	digest := sha256.Sum256(raw)
	if len(want) != sha256.Size || !bytes.Equal(want, digest[:]) {
		return SealedLLMSkill{}, errors.New("admitted SKILL.md bytes differ from the immutable manifest")
	}
	return SealedLLMSkill{ArtifactDigest: append([]byte(nil), artifactDigest...), Instructions: raw}, nil
}

func (s *Store) ResolveInstalledEntrypoint(artifactDigest []byte) (InstalledEntrypoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.state.Initialized || s.state.OwnerPaused || s.state.OwnerExit != nil {
		return InstalledEntrypoint{}, errors.New("capability execution authority is unavailable")
	}
	entry, ok := s.state.Entries[hex.EncodeToString(artifactDigest)]
	if !ok || entry.State != StateActive || entry.InstalledPath == "" || entry.ArtifactObject == nil ||
		entry.ContentManifestObject == nil || entry.EntrypointObject == nil {
		return InstalledEntrypoint{}, ErrNotAdmitted
	}
	if closure, err := HashTree(entry.InstalledPath); err != nil || !bytes.Equal(closure, entry.ObservedContentDigest) {
		return InstalledEntrypoint{}, errors.New("installed capability closure changed")
	}
	var artifact trusted.ExecutableCapabilityArtifactBodyV1
	var manifest trusted.CapabilityContentManifestV1
	var descriptor trusted.CapabilityEntrypointDescriptorV1
	if trusted.DecodeBody(*entry.ArtifactObject, "artifact", &artifact) != nil || artifact.ArtifactKind != "mcp-local" ||
		trusted.DecodeBody(*entry.ContentManifestObject, "content-manifest", &manifest) != nil ||
		trusted.DecodeBody(*entry.EntrypointObject, "entrypoint-descriptor", &descriptor) != nil {
		return InstalledEntrypoint{}, errors.New("installed capability has no local MCP entrypoint")
	}
	descriptorDigest, err := trusted.ObjectDigest(*entry.EntrypointObject)
	if err != nil || !bytes.Equal(descriptorDigest, artifact.EntrypointDescriptorDigest) {
		return InstalledEntrypoint{}, errors.New("installed entrypoint descriptor binding changed")
	}
	path := ""
	for _, item := range manifest.Entries {
		if item.ObjectType == "regular" && bytes.Equal(item.ContentDigest, descriptor.ExecutableObjectDigest) {
			if path != "" {
				return InstalledEntrypoint{}, errors.New("entrypoint digest resolves to multiple files")
			}
			path = filepath.Join(entry.InstalledPath, filepath.FromSlash(item.Path))
		}
	}
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return InstalledEntrypoint{}, errors.New("entrypoint is absent from the immutable manifest")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o111 == 0 {
		return InstalledEntrypoint{}, errors.New("entrypoint is not a direct executable file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return InstalledEntrypoint{}, err
	}
	digest := sha256.Sum256(raw)
	if !bytes.Equal(digest[:], descriptor.ExecutableObjectDigest) {
		return InstalledEntrypoint{}, errors.New("entrypoint bytes changed")
	}
	if err := validateHermeticStaticELF(raw); err != nil {
		return InstalledEntrypoint{}, err
	}
	return InstalledEntrypoint{Path: path, Arguments: append([]string(nil), descriptor.Arguments...),
		Artifact: append([]byte(nil), artifactDigest...), Descriptor: descriptorDigest, ExecutableDigest: append([]byte(nil), descriptor.ExecutableObjectDigest...)}, nil
}

// validateHermeticStaticELF keeps the initial consequential local-MCP profile
// independent of mutable host interpreters, loaders, libraries, modules, and
// certificate stores. A later profile may admit a content-addressed rootfs,
// but this profile accepts only one self-contained Linux ELF image.
func validateHermeticStaticELF(raw []byte) error {
	file, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil || file.Class == elf.ELFCLASSNONE || file.Type != elf.ET_EXEC && file.Type != elf.ET_DYN {
		return errors.New("hermetic local MCP entrypoint must be a valid static ELF executable")
	}
	defer file.Close()
	for _, program := range file.Progs {
		if program.Type == elf.PT_INTERP {
			return errors.New("hermetic local MCP entrypoint cannot use a host dynamic loader")
		}
	}
	if libraries, importErr := file.ImportedLibraries(); importErr != nil || len(libraries) != 0 {
		return errors.New("hermetic local MCP entrypoint cannot use host shared libraries")
	}
	return nil
}

func (s *Store) ResolveExecutionAuthority(artifactDigest []byte, leaseEnvelope trusted.ProfileAuthorizationEnvelopeV1) (ExecutionAuthoritySnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.state.Initialized || s.state.OwnerPaused || s.state.OwnerExit != nil {
		return ExecutionAuthoritySnapshot{}, errors.New("capability execution authority is unavailable")
	}
	now, err := s.trustedNowLocked()
	if err != nil {
		return ExecutionAuthoritySnapshot{}, err
	}
	key := hex.EncodeToString(artifactDigest)
	entry, ok := s.state.Entries[key]
	if !ok || entry.State != StateActive || entry.AdmissionObject == nil || entry.AdmissionEnvelope == nil || entry.PermissionObject == nil || entry.InstalledPath == "" {
		return ExecutionAuthoritySnapshot{}, ErrNotAdmitted
	}
	if err := s.revalidatePublisherLocked(&entry, now); err != nil {
		return ExecutionAuthoritySnapshot{}, err
	}
	if err := s.verifyPolicyAuthorizationLocked(leaseEnvelope, "use-lease", s.state.AgentID); err != nil {
		return ExecutionAuthoritySnapshot{}, err
	}
	var admitted trusted.CapabilityPermissionManifestV1
	if err := trusted.DecodeBody(*entry.PermissionObject, "permission-manifest", &admitted); err != nil {
		return ExecutionAuthoritySnapshot{}, err
	}
	var admission trusted.CapabilityAdmissionBodyV1
	if err := trusted.DecodeBody(*entry.AdmissionObject, "capability-admission", &admission); err != nil {
		return ExecutionAuthoritySnapshot{}, err
	}
	admissionDigest, err := authorizationEnvelopeDigest(*entry.AdmissionEnvelope)
	if err != nil {
		return ExecutionAuthoritySnapshot{}, err
	}
	var promotionDigest []byte
	if entry.PromotionRequired {
		if entry.PromotionEnvelope == nil {
			return ExecutionAuthoritySnapshot{}, ErrPromotionRequired
		}
		promotionDigest, err = authorizationEnvelopeDigest(*entry.PromotionEnvelope)
		if err != nil {
			return ExecutionAuthoritySnapshot{}, err
		}
	}
	s.state.Entries[key] = entry
	if err := s.commitAuthorityLocked(); err != nil {
		return ExecutionAuthoritySnapshot{}, err
	}
	return ExecutionAuthoritySnapshot{AuthorityEpoch: s.state.AuthorityEpoch, PolicyRevision: s.state.PolicyRevision,
		AdmissionRevocationGeneration: entry.AdmissionRevocationGeneration, PromotionRevocationGeneration: entry.PromotionRevocationGeneration,
		ControlScopeGeneration: s.state.ControlScopeGeneration, AdmissionRevision: entry.AdmissionRevision, PromotionRevision: entry.PromotionRevision,
		InstallationRevision: entry.InstallationRevision, InventoryRevision: s.state.InventoryRevision, PolicyDigest: append([]byte(nil), s.state.PolicyDigest...),
		AdmissionEnvelopeDigest: admissionDigest, PromotionEnvelopeDigest: promotionDigest, PermissionManifestDigest: append([]byte(nil), entry.PermissionManifestDigest...),
		AdmittedPermissionManifest: admitted, LeaseIssuerSubject: leaseEnvelope.Body.IssuerSubject, LeaseAuthorityID: append([]byte(nil), leaseEnvelope.Body.AuthorityID...),
		LeaseProofProfileURI: leaseEnvelope.Body.ProofProfileURI, OwnerID: append([]byte(nil), s.state.OwnerID...), AgentID: append([]byte(nil), s.state.AgentID...),
		InFlightRevocationPolicy: admission.InFlightRevocationPolicy,
		InstallationID:           append([]byte(nil), s.state.InstallationID...)}, nil
}

func (s *Store) MeasureInstalledArtifact(artifactDigest []byte) ([]byte, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.OwnerPaused || s.state.OwnerExit != nil {
		return nil, 0, errors.New("capability execution authority is unavailable")
	}
	entry, ok := s.state.Entries[hex.EncodeToString(artifactDigest)]
	if !ok || entry.InstalledPath == "" || entry.State != StateActive {
		return nil, 0, ErrNotAdmitted
	}
	closure, err := HashTree(entry.InstalledPath)
	if err != nil || !bytes.Equal(closure, entry.ObservedContentDigest) {
		return nil, 0, errors.New("installed artifact closure changed")
	}
	return append([]byte(nil), entry.ArtifactDigest...), entry.InstallationRevision, nil
}
