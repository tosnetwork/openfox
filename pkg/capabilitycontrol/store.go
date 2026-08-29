package capabilitycontrol

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tosnetwork/openfox/pkg/fileutil"
	trusted "github.com/tosnetwork/tos-service-protocol/pkg/trustedcapability"
)

const (
	stateFile   = "control-state.json"
	pendingFile = "control-state.pending.json"
)

type Store struct {
	root               string
	mu                 sync.Mutex
	lock               *stateLock
	monotonic          MonotonicAuthorityStore
	clock              TrustedTimeSource
	installVerifier    InstallationFenceVerifier
	publisherVerifier  PublisherAuthorityVerifier
	acquisitionControl CapabilityAcquisitionControl
	acquisitionFence   CapabilityAcquisitionFence
	state              DurableState
}

func Open(root string, ownerID, agentID []byte) (*Store, error) {
	return OpenInDomain(root, trusted.DomainOwnerLocal, ownerID, ownerID, agentID)
}

func OpenInDomain(root string, domainKind trusted.DomainKind, domainID, ownerID, agentID []byte) (*Store, error) {
	return openInDomain(root, domainKind, domainID, ownerID, agentID, nil, systemTrustedTime{}, nil)
}

func OpenProductionInDomain(root string, domainKind trusted.DomainKind, domainID, ownerID, agentID []byte, monotonic MonotonicAuthorityStore, clock TrustedTimeSource, installVerifier InstallationFenceVerifier, publisherVerifier PublisherAuthorityVerifier) (*Store, error) {
	if monotonic == nil || clock == nil || installVerifier == nil || publisherVerifier == nil {
		return nil, errors.New("production capability control requires rollback-resistant monotonic authority, trusted time, installation fencing, and publisher status")
	}
	identityAuthority, ok := monotonic.(InstallationIdentityAuthority)
	if !ok {
		return nil, errors.New("production capability control requires an external installation identity authority")
	}
	installationID, err := identityAuthority.ResolveInstallationID(context.Background(), domainKind, domainID, ownerID, agentID)
	if err != nil || len(installationID) != 16 {
		return nil, errors.New("stable external installation identity is unavailable")
	}
	store, err := openInDomainWithInstallation(root, domainKind, domainID, ownerID, agentID, monotonic, clock, installVerifier, installationID)
	if err == nil {
		store.publisherVerifier = publisherVerifier
		store.acquisitionControl, _ = monotonic.(CapabilityAcquisitionControl)
		store.acquisitionFence, _ = monotonic.(CapabilityAcquisitionFence)
		if store.acquisitionControl == nil || store.acquisitionFence == nil {
			_ = store.Close()
			return nil, errors.New("production capability control requires an atomic external acquisition-control high-water")
		}
	}
	return store, err
}

func openInDomain(root string, domainKind trusted.DomainKind, domainID, ownerID, agentID []byte, monotonic MonotonicAuthorityStore, clock TrustedTimeSource, installVerifier InstallationFenceVerifier) (*Store, error) {
	return openInDomainWithInstallation(root, domainKind, domainID, ownerID, agentID, monotonic, clock, installVerifier, nil)
}

func openInDomainWithInstallation(root string, domainKind trusted.DomainKind, domainID, ownerID, agentID []byte, monotonic MonotonicAuthorityStore, clock TrustedTimeSource, installVerifier InstallationFenceVerifier, authorityInstallationID []byte) (*Store, error) {
	if root == "" || len(ownerID) == 0 || len(agentID) == 0 {
		return nil, errors.New("capability control root, owner, and Agent are required")
	}
	clean, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(clean, 0o700); err != nil {
		return nil, err
	}
	if err := prepareObjectStore(clean); err != nil {
		return nil, err
	}
	lock, err := acquireStateLock(filepath.Join(clean, ".writer.lock"))
	if err != nil {
		return nil, fmt.Errorf("capability control writer already active: %w", err)
	}
	store := &Store{root: clean, lock: lock, monotonic: monotonic, clock: clock, installVerifier: installVerifier}
	raw, err := os.ReadFile(filepath.Join(clean, stateFile))
	if errors.Is(err, os.ErrNotExist) {
		installation := make([]byte, 16)
		if len(authorityInstallationID) == 16 {
			copy(installation, authorityInstallationID)
		} else if _, err := rand.Read(installation); err != nil {
			_ = lock.close()
			return nil, err
		}
		store.state = DurableState{SchemaVersion: 1, DomainKind: uint8(domainKind), DomainID: append([]byte(nil), domainID...), InstallationID: installation, DeploymentFormatEpoch: 1,
			OwnerID: append([]byte(nil), ownerID...), AgentID: append([]byte(nil), agentID...),
			InventoryRevision: 1, SourceGeneration: 1, ControlScopeGeneration: 1, PortfolioRevision: 1,
			Entries: map[string]Entry{}, UseSlots: map[string]UseSlot{}, InstallationSlots: map[string]InstallationSlot{}, DeviceSessions: map[string]DeviceSessionRecord{}, Tombstones: map[string]Tombstone{}, AuthorizedSubjects: map[string][][]byte{}, AuthorityControllers: map[string]string{}, AuthorityHeads: map[string]AuthorityHead{}, OwnerCommandActions: map[string]OwnerCommandAction{}, MCPToolActions: map[string]MCPToolAction{}}
		if err := store.persistLocked(); err != nil {
			_ = lock.close()
			return nil, err
		}
		if monotonic != nil {
			if err := store.reconcileMonotonicLocked(); err != nil {
				_ = lock.close()
				return nil, err
			}
		}
		return store, nil
	}
	if err != nil {
		_ = lock.close()
		return nil, err
	}
	if err := json.Unmarshal(raw, &store.state); err != nil {
		_ = lock.close()
		return nil, fmt.Errorf("decode capability control state: %w", err)
	}
	if store.state.SchemaVersion != 1 || store.state.DomainKind != uint8(domainKind) || !bytes.Equal(store.state.DomainID, domainID) ||
		!bytes.Equal(store.state.OwnerID, ownerID) || !bytes.Equal(store.state.AgentID, agentID) ||
		len(store.state.InstallationID) != 16 || store.state.DeploymentFormatEpoch < 1 || store.state.InventoryRevision == 0 ||
		store.state.SourceGeneration == 0 || store.state.ControlScopeGeneration == 0 || store.state.PortfolioRevision == 0 {
		_ = lock.close()
		return nil, errors.New("capability control state identity or epoch mismatch")
	}
	if len(authorityInstallationID) == 16 && !bytes.Equal(store.state.InstallationID, authorityInstallationID) {
		_ = lock.close()
		return nil, errors.New("local projection belongs to a different external installation identity")
	}
	if store.state.Entries == nil {
		store.state.Entries = map[string]Entry{}
	}
	if store.state.UseSlots == nil {
		store.state.UseSlots = map[string]UseSlot{}
	}
	if store.state.Tombstones == nil {
		store.state.Tombstones = map[string]Tombstone{}
	}
	if store.state.InstallationSlots == nil {
		store.state.InstallationSlots = map[string]InstallationSlot{}
	}
	if store.state.DeviceSessions == nil {
		store.state.DeviceSessions = map[string]DeviceSessionRecord{}
	}
	if store.state.AuthorizedSubjects == nil {
		store.state.AuthorizedSubjects = map[string][][]byte{}
	}
	if store.state.AuthorityControllers == nil {
		store.state.AuthorityControllers = map[string]string{}
	}
	if store.state.MCPToolActions == nil {
		store.state.MCPToolActions = map[string]MCPToolAction{}
	}
	if store.state.AuthorityHeads == nil {
		store.state.AuthorityHeads = map[string]AuthorityHead{}
	}
	if store.state.OwnerCommandActions == nil {
		store.state.OwnerCommandActions = map[string]OwnerCommandAction{}
	}
	if monotonic != nil {
		if err := store.reconcileMonotonicLocked(); err != nil {
			_ = lock.close()
			return nil, err
		}
	}
	return store, nil
}

func prepareObjectStore(root string) error {
	target := filepath.Join(root, "objects")
	if err := os.Mkdir(target, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create capability object store: %w", err)
	}
	info, err := os.Lstat(target)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("capability object store must be an owner-private direct directory")
	}
	handle, err := os.Open(target)
	if err != nil {
		return err
	}
	handleInfo, statErr := handle.Stat()
	syncErr := handle.Sync()
	closeErr := handle.Close()
	if statErr != nil || !os.SameFile(info, handleInfo) || syncErr != nil || closeErr != nil {
		return errors.Join(errors.New("capability object store could not be pinned and synced"), statErr, syncErr, closeErr)
	}
	parent, err := os.Open(root)
	if err != nil {
		return err
	}
	err = errors.Join(parent.Sync(), parent.Close())
	return err
}

func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.lock.close()
	s.lock = nil
	return err
}

// Bootstrap is the only operation that can establish a trust root. Opening a
// database, importing legacy files, or loading model configuration leaves the
// store uninitialized and incapable of admission or execution.
func (s *Store) Bootstrap(request BootstrapRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var ceremony trusted.OwnerBootstrapCeremonyV1
	if err := trusted.DecodeBody(request.CeremonyObject, "owner-bootstrap", &ceremony); err != nil {
		return err
	}
	ceremonyDigest, err := trusted.ObjectDigest(request.CeremonyObject)
	if err != nil {
		return err
	}
	if s.state.Initialized {
		if bytes.Equal(s.state.GenesisCeremonyDigest, ceremonyDigest) && bytes.Equal(s.state.BootstrapNonce, ceremony.CeremonyNonce) {
			return nil
		}
		return errors.New("conflicting owner trust genesis")
	}
	var policy trusted.OwnerPolicyBodyV1
	if err := trusted.DecodeBody(request.PolicyObject, "owner-policy", &policy); err != nil {
		return err
	}
	digest, err := trusted.ObjectDigest(request.PolicyObject)
	if err != nil {
		return err
	}
	now, err := s.trustedNowLocked()
	if err != nil {
		return err
	}
	bindings, err := canonicalSubjects(request.AuthorizedSubjects, request.AuthorityControllers)
	if err != nil {
		return err
	}
	subjectBytes, err := trusted.MarshalBody(bindings)
	if err != nil {
		return err
	}
	subjectDigest := sha256.Sum256(subjectBytes)
	if ceremony.SchemaVersion != trusted.SchemaVersion || ceremony.DomainKind != s.state.DomainKind || !bytes.Equal(ceremony.DomainID, s.state.DomainID) ||
		!bytes.Equal(ceremony.OwnerID, s.state.OwnerID) || len(ceremony.CeremonyNonce) != sha256.Size || len(ceremony.OwnerConfirmationDigest) != sha256.Size ||
		len(ceremony.PossessionChallengeDigest) != sha256.Size || ceremony.Generation != 0 || ceremony.State != "owner-confirmed" ||
		now < ceremony.NotBeforeUnix || now >= ceremony.ExpiresAtUnix || !bytes.Equal(ceremony.GenesisPolicyObjectDigest, digest) ||
		!bytes.Equal(ceremony.AuthoritySubjectSetDigest, subjectDigest[:]) || !bytes.Equal(policy.PromotionSeparationPolicyDigest, v1PromotionSeparationPolicyDigest()) ||
		!subjectAllowed(request.AuthorizedSubjects, "owner-bootstrap", ceremony.RootSubject.Identifier) ||
		!bytes.Equal(policy.AuthorityProfileSetDigest, subjectDigest[:]) || request.PolicyObject.DomainKind != s.state.DomainKind || !bytes.Equal(request.PolicyObject.DomainID, s.state.DomainID) ||
		!bytes.Equal(policy.OwnerID, s.state.OwnerID) || policy.Revision != 1 || policy.PredecessorPolicyDigest != nil ||
		policy.AuthorityEpoch == 0 || now < policy.NotBeforeUnix || now >= policy.ExpiresAtUnix ||
		request.Envelope.Body.PolicyRevision != policy.Revision || !bytes.Equal(request.Envelope.Body.PolicyDigest, digest) ||
		request.Envelope.Body.AuthorityKind != "owner-bootstrap-policy" || request.Envelope.Body.AuthorityRevision != 0 || request.Envelope.Body.PredecessorEnvelopeDigest != nil ||
		request.Envelope.Body.AuthorityEpoch != policy.AuthorityEpoch || !bytes.Equal(request.Envelope.Body.OwnerID, s.state.OwnerID) || request.Envelope.Body.AgentID != nil {
		return errors.New("invalid owner bootstrap policy")
	}
	if err := trusted.VerifyAuthorization(request.RootCeremonyAuthorization, request.CeremonyObject, now, ceremony.Generation); err != nil ||
		request.RootCeremonyAuthorization.Body.AuthorityKind != "owner-bootstrap" || !sameAuthoritySubject(request.RootCeremonyAuthorization.Body.IssuerSubject, ceremony.RootSubject) ||
		!bytes.Equal(request.RootCeremonyAuthorization.Body.OwnerID, s.state.OwnerID) || request.RootCeremonyAuthorization.Body.AgentID != nil {
		return errors.New("root possession or ceremony authorization failed")
	}
	if len(ceremony.RecoverySubjects) == 0 || len(request.RecoveryCeremonyAuthorizations) != len(ceremony.RecoverySubjects) {
		return errors.New("recovery possession proofs are incomplete")
	}
	for index, subject := range ceremony.RecoverySubjects {
		if index > 0 && compareAuthoritySubject(ceremony.RecoverySubjects[index-1], subject) >= 0 {
			return errors.New("recovery subjects are not canonical")
		}
		authorization := request.RecoveryCeremonyAuthorizations[index]
		if err := trusted.VerifyAuthorization(authorization, request.CeremonyObject, now, ceremony.Generation); err != nil ||
			authorization.Body.AuthorityKind != "owner-bootstrap-recovery" || !sameAuthoritySubject(authorization.Body.IssuerSubject, subject) ||
			!bytes.Equal(authorization.Body.OwnerID, s.state.OwnerID) || authorization.Body.AgentID != nil {
			return errors.New("recovery possession proof failed")
		}
	}
	if err := trusted.VerifyAuthorization(request.Envelope, request.PolicyObject, now, policy.AuthorityEpoch); err != nil {
		return err
	}
	if !sameAuthoritySubject(request.Envelope.Body.IssuerSubject, ceremony.RootSubject) {
		return errors.New("genesis policy is not authorized by the confirmed root")
	}
	s.state.Initialized = true
	s.state.AuthorityEpoch = policy.AuthorityEpoch
	s.state.PolicyRevision = policy.Revision
	s.state.PolicyDigest = digest
	s.state.CapabilityPolicyDigest = append([]byte(nil), policy.CapabilityPolicyDigest...)
	s.state.PromotionSeparationPolicyDigest = append([]byte(nil), policy.PromotionSeparationPolicyDigest...)
	s.state.GenesisCeremonyDigest = ceremonyDigest
	s.state.BootstrapNonce = append([]byte(nil), ceremony.CeremonyNonce...)
	s.state.AuthorizedSubjects = cloneSubjects(request.AuthorizedSubjects)
	s.state.AuthorityControllers = cloneControllers(request.AuthorityControllers)
	s.state.InventoryRevision++
	return s.commitAuthorityLocked()
}

func compareAuthoritySubject(left, right trusted.TypedAuthoritySubjectV1) int {
	if left.Kind != right.Kind {
		return strings.Compare(left.Kind, right.Kind)
	}
	if left.Namespace != right.Namespace {
		return strings.Compare(left.Namespace, right.Namespace)
	}
	return bytes.Compare(left.Identifier, right.Identifier)
}

func (s *Store) RotatePolicy(request PolicyRotationRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.state.Initialized {
		return errors.New("owner trust root is not initialized")
	}
	if err := s.requireNewCapabilityWorkLocked(); err != nil {
		return err
	}
	var policy trusted.OwnerPolicyBodyV1
	if err := trusted.DecodeBody(request.PolicyObject, "owner-policy", &policy); err != nil {
		return err
	}
	now, err := s.trustedNowLocked()
	if err != nil {
		return err
	}
	newDigest, err := trusted.ObjectDigest(request.PolicyObject)
	if err != nil {
		return err
	}
	bindings, err := canonicalSubjects(request.AuthorizedSubjects, request.AuthorityControllers)
	if err != nil {
		return err
	}
	subjectBytes, err := trusted.MarshalBody(bindings)
	if err != nil {
		return err
	}
	subjectDigest := sha256.Sum256(subjectBytes)
	if request.PolicyObject.DomainKind != s.state.DomainKind || !bytes.Equal(request.PolicyObject.DomainID, s.state.DomainID) || !bytes.Equal(policy.OwnerID, s.state.OwnerID) ||
		policy.Revision != s.state.PolicyRevision+1 || policy.PredecessorPolicyDigest == nil || !bytes.Equal(*policy.PredecessorPolicyDigest, s.state.PolicyDigest) ||
		policy.AuthorityEpoch < s.state.AuthorityEpoch || !bytes.Equal(policy.AuthorityProfileSetDigest, subjectDigest[:]) ||
		!bytes.Equal(policy.PromotionSeparationPolicyDigest, v1PromotionSeparationPolicyDigest()) || now < policy.NotBeforeUnix || now >= policy.ExpiresAtUnix {
		return errors.New("owner policy successor is stale, forked, or incomplete")
	}
	if err := trusted.VerifyAuthorization(request.Envelope, request.PolicyObject, now, s.state.AuthorityEpoch); err != nil {
		return err
	}
	governing := request.Envelope.Body
	if governing.AuthorityKind != "owner-policy" || governing.AgentID != nil || governing.AuthorityEpoch != s.state.AuthorityEpoch || governing.PolicyRevision != s.state.PolicyRevision ||
		!bytes.Equal(governing.PolicyDigest, s.state.PolicyDigest) || !bytes.Equal(governing.OwnerID, s.state.OwnerID) || !subjectAllowed(s.state.AuthorizedSubjects, "owner-policy", governing.IssuerSubject.Identifier) {
		return errors.New("owner policy successor is not authorized by the prior policy")
	}
	if err := s.acceptAuthorityHeadLocked(request.Envelope); err != nil {
		return err
	}
	if policy.AuthorityEpoch > s.state.AuthorityEpoch {
		s.state.AuthorityHeads = map[string]AuthorityHead{}
		s.state.ControlScopeGeneration++
	}
	s.state.AuthorityEpoch = policy.AuthorityEpoch
	s.state.PolicyRevision = policy.Revision
	s.state.PolicyDigest = newDigest
	s.state.CapabilityPolicyDigest = append([]byte(nil), policy.CapabilityPolicyDigest...)
	s.state.PromotionSeparationPolicyDigest = append([]byte(nil), policy.PromotionSeparationPolicyDigest...)
	s.state.AuthorizedSubjects = cloneSubjects(request.AuthorizedSubjects)
	s.state.AuthorityControllers = cloneControllers(request.AuthorityControllers)
	s.state.InventoryRevision++
	return s.commitAuthorityLocked()
}

func (s *Store) IssueDeviceSession(request DeviceSessionRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.state.Initialized || s.state.OwnerExit != nil {
		return errors.New("owner authority is unavailable")
	}
	if err := s.requireNewCapabilityWorkLocked(); err != nil {
		return err
	}
	var session trusted.OwnerDeviceSessionV1
	if err := trusted.DecodeBody(request.Object, "device-session", &session); err != nil {
		return err
	}
	now, err := s.trustedNowLocked()
	if err != nil {
		return err
	}
	digest, err := trusted.ObjectDigest(request.Object)
	if err != nil {
		return err
	}
	key := hex.EncodeToString(digest)
	if len(session.SessionID) != 16 || len(session.OwnerID) == 0 || !bytes.Equal(session.OwnerID, s.state.OwnerID) || len(session.DevicePublicKey) != 32 ||
		len(session.AllowedCommandClassesDigest) != sha256.Size || session.Audience == "" || len(session.ChannelBindingDigest) != sha256.Size ||
		session.SessionGeneration == 0 || session.SessionRevocationGeneration == 0 || session.AuthorityEpoch != s.state.AuthorityEpoch ||
		session.PolicyRevision != s.state.PolicyRevision || !bytes.Equal(session.PolicyDigest, s.state.PolicyDigest) || now < session.NotBeforeUnix || now >= session.ExpiresAtUnix ||
		trusted.ValidateReference(session.RevocationObjectReference) != nil {
		return errors.New("device session is incomplete, stale, or cross-owner")
	}
	if err := trusted.VerifyAuthorization(request.Envelope, request.Object, now, s.state.AuthorityEpoch); err != nil {
		return err
	}
	body := request.Envelope.Body
	if body.AuthorityKind != "device-session" || body.AgentID != nil || body.PolicyRevision != s.state.PolicyRevision || !bytes.Equal(body.PolicyDigest, s.state.PolicyDigest) ||
		!bytes.Equal(body.OwnerID, s.state.OwnerID) || !subjectAllowed(s.state.AuthorizedSubjects, "device-session", body.IssuerSubject.Identifier) {
		return errors.New("device session issuer is not authorized by current policy")
	}
	if prior, exists := s.state.DeviceSessions[key]; exists {
		if prior.SessionGeneration == session.SessionGeneration && !prior.Revoked {
			return nil
		}
		return errors.New("device session identity conflict")
	}
	if err := s.acceptAuthorityHeadLocked(request.Envelope); err != nil {
		return err
	}
	s.state.DeviceSessions[key] = DeviceSessionRecord{Object: request.Object, Envelope: request.Envelope, SessionGeneration: session.SessionGeneration, RevocationGeneration: session.SessionRevocationGeneration}
	return s.commitAuthorityLocked()
}

func (s *Store) Root() string { return s.root }

func (s *Store) TrustedNow() (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.trustedNowLocked()
}

// ObserveTrustedTime returns evidence produced by the external authority and
// monotonically commits both its epoch and timestamp before exposing it to an
// executor. Test/development wall clocks deliberately do not implement this.
func (s *Store) ObserveTrustedTime(ctx context.Context) (TrustedTimeEvidenceObservation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	source, ok := s.clock.(TrustedTimeEvidenceSource)
	if !ok {
		return TrustedTimeEvidenceObservation{}, errors.New("signed external trusted-time evidence is unavailable")
	}
	observation, err := source.ObserveTrustedTime(ctx)
	if err != nil || observation.UnixSeconds == 0 || observation.Epoch == 0 || len(observation.EvidenceDigest) != sha256.Size ||
		observation.UnixSeconds < s.state.TrustedTimeHighWater || observation.Epoch < s.state.TrustedTimeEpochHighWater {
		return TrustedTimeEvidenceObservation{}, errors.New("signed external trusted-time evidence is stale or invalid")
	}
	changed := observation.UnixSeconds > s.state.TrustedTimeHighWater || observation.Epoch > s.state.TrustedTimeEpochHighWater
	if observation.UnixSeconds > s.state.TrustedTimeHighWater {
		s.state.TrustedTimeHighWater = observation.UnixSeconds
	}
	if observation.Epoch > s.state.TrustedTimeEpochHighWater {
		s.state.TrustedTimeEpochHighWater = observation.Epoch
	}
	if changed {
		if err := s.commitAuthorityLocked(); err != nil {
			return TrustedTimeEvidenceObservation{}, err
		}
	}
	return TrustedTimeEvidenceObservation{UnixSeconds: observation.UnixSeconds, Epoch: observation.Epoch, EvidenceDigest: append([]byte(nil), observation.EvidenceDigest...)}, nil
}

func (s *Store) Snapshot() DurableState {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, _ := json.Marshal(s.state)
	var out DurableState
	_ = json.Unmarshal(raw, &out)
	return out
}

func (s *Store) ImportLegacySkillRoots(roots []string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.requireNewCapabilityWorkLocked(); err != nil {
		return err
	}
	changed := false
	for _, root := range roots {
		children, err := os.ReadDir(root)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		for _, child := range children {
			if !child.IsDir() {
				continue
			}
			path := filepath.Join(root, child.Name(), "SKILL.md")
			digest, err := hashRegularFile(path)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return err
			}
			key := hex.EncodeToString(digest)
			if _, tombstoned := s.state.Tombstones[key]; tombstoned {
				continue
			}
			if _, exists := s.state.Entries[key]; exists {
				continue
			}
			s.state.Entries[key] = Entry{ArtifactDigest: digest, ArtifactKind: "skill", Namespace: "openfox.legacy",
				Name: child.Name(), Version: "legacy", State: StateUnverifiedLegacy, InstalledPath: path, PromotionRequired: true, UpdatedAtUnix: uint64(now.UTC().Unix())}
			changed = true
		}
	}
	if changed {
		s.state.InventoryRevision++
		s.state.SourceGeneration++
		return s.commitProjectionLocked()
	}
	return nil
}

func (s *Store) RegisterQuarantined(ctx context.Context, entry Entry, receipt QuarantineCommitReceipt, now time.Time) error {
	if s.acquisitionFence == nil {
		return errors.New("quarantine registration requires the external acquisition authority")
	}
	if !bytes.Equal(receipt.Transition.OwnerID, s.state.OwnerID) || !bytes.Equal(receipt.Transition.AgentID, s.state.AgentID) {
		return errors.New("quarantine receipt is cross-owner or cross-Agent")
	}
	path, err := ValidateQuarantineCommitReceipt(ctx, receipt, s.acquisitionFence)
	if err != nil {
		return err
	}
	if len(entry.ObservedContentDigest) != 0 && !bytes.Equal(entry.ObservedContentDigest, receipt.Transition.ContentDigest) {
		return errors.New("quarantine entry conflicts with the authoritative receipt")
	}
	entry.ObservedContentDigest = append([]byte(nil), receipt.Transition.ContentDigest...)
	entry.ArtifactDigest = nil
	return s.registerQuarantined(entry, path, now)
}

// registerQuarantined is deliberately package-private. Production callers
// must present a live ledger receipt through RegisterQuarantined; unit fixtures
// can exercise later lifecycle stages without constructing an external service.
func (s *Store) registerQuarantined(entry Entry, path string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.requireNewCapabilityWorkLocked(); err != nil {
		return err
	}
	observed := entry.ObservedContentDigest
	if len(observed) == 0 {
		observed = entry.ArtifactDigest // legacy caller compatibility; never treated as verified identity.
	}
	if len(observed) != sha256.Size || path == "" {
		return errors.New("quarantined entry is incomplete")
	}
	actualManifest, err := BuildContentManifest(path)
	if err != nil || !bytes.Equal(actualManifest.ClosureRoot, observed) {
		return errors.New("quarantined bytes do not match observed content digest")
	}
	key := hex.EncodeToString(observed)
	if _, deleted := s.state.Tombstones[key]; deleted {
		return errors.New("artifact is tombstoned")
	}
	if current, exists := s.state.Entries[key]; exists && current.State != StateQuarantined {
		return errors.New("artifact already exists outside quarantine")
	}
	entry.State = StateQuarantined
	entry.ArtifactDigest = nil
	entry.ObservedContentDigest = append([]byte(nil), observed...)
	entry.QuarantinePath = filepath.Clean(path)
	entry.InstalledPath = ""
	entry.UpdatedAtUnix = uint64(now.UTC().Unix())
	s.state.Entries[key] = entry
	s.state.InventoryRevision++
	return s.commitProjectionLocked()
}

// VerifyCandidate performs the complete provenance and closure transition. A
// raw tree hash or caller-selected permission digest can never become a
// verified artifact identity.
func (s *Store) VerifyCandidate(request VerificationRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.requireNewCapabilityWorkLocked(); err != nil {
		return err
	}
	key := hex.EncodeToString(request.QuarantineDigest)
	entry, ok := s.state.Entries[key]
	if !ok || entry.State != StateQuarantined || !bytes.Equal(entry.ObservedContentDigest, request.QuarantineDigest) {
		return errors.New("only an exact quarantined artifact can be verified")
	}
	actualManifest, err := BuildContentManifest(entry.QuarantinePath)
	if err != nil || !bytes.Equal(actualManifest.ClosureRoot, request.QuarantineDigest) {
		return errors.New("quarantine content changed before verification")
	}
	var artifact trusted.ExecutableCapabilityArtifactBodyV1
	if err := trusted.DecodeBody(request.ArtifactObject, "artifact", &artifact); err != nil {
		return err
	}
	if err := trusted.ValidateExecutableArtifact(artifact); err != nil {
		return err
	}
	if request.ArtifactObject.DomainKind != s.state.DomainKind || !bytes.Equal(request.ArtifactObject.DomainID, s.state.DomainID) {
		return errors.New("artifact domain mismatch")
	}
	var declaredManifest trusted.CapabilityContentManifestV1
	if err := trusted.DecodeBody(request.ContentManifestObject, "content-manifest", &declaredManifest); err != nil {
		return err
	}
	if err := trusted.ValidateContentManifest(declaredManifest); err != nil || !bytes.Equal(declaredManifest.ClosureRoot, actualManifest.ClosureRoot) {
		return errors.New("content manifest does not match quarantined closure")
	}
	contentDigest, err := trusted.ObjectDigest(request.ContentManifestObject)
	if err != nil || !bytes.Equal(contentDigest, artifact.ContentManifestDigest) {
		return errors.New("artifact content manifest reference mismatch")
	}
	var entrypoint trusted.CapabilityEntrypointDescriptorV1
	if err := trusted.DecodeBody(request.EntrypointObject, "entrypoint-descriptor", &entrypoint); err != nil {
		return err
	}
	if err := trusted.ValidateEntrypointDescriptor(entrypoint); err != nil {
		return err
	}
	entrypointDigest, err := trusted.ObjectDigest(request.EntrypointObject)
	if err != nil || !bytes.Equal(entrypointDigest, artifact.EntrypointDescriptorDigest) {
		return errors.New("artifact entrypoint reference mismatch")
	}
	preManifest, err := trusted.ArtifactPreManifestDigest(artifact)
	if err != nil {
		return err
	}
	var permission trusted.CapabilityPermissionManifestV1
	if artifact.PermissionManifestDigest == nil || request.PermissionObject == nil {
		return errors.New("executable artifact requires an exact permission manifest")
	}
	if err := trusted.DecodeBody(*request.PermissionObject, "permission-manifest", &permission); err != nil {
		return err
	}
	permissionDigest, err := trusted.ObjectDigest(*request.PermissionObject)
	if err != nil || !bytes.Equal(permissionDigest, *artifact.PermissionManifestDigest) || !bytes.Equal(permission.ArtifactPreManifestDigest, preManifest) {
		return errors.New("permission manifest reference mismatch")
	}
	if err := trusted.ValidatePermissionManifest(permission); err != nil {
		return err
	}
	if artifact.DependencyManifestDigest != nil {
		if request.DependencyObject == nil {
			return errors.New("dependency manifest is missing")
		}
		var dependencies trusted.DependencyManifestV1
		if err := trusted.DecodeBody(*request.DependencyObject, "dependency-manifest", &dependencies); err != nil {
			return err
		}
		dependencyDigest, err := trusted.ObjectDigest(*request.DependencyObject)
		if err != nil || !bytes.Equal(dependencyDigest, *artifact.DependencyManifestDigest) {
			return errors.New("dependency manifest reference mismatch")
		}
		if err := trusted.ValidateDependencyManifest(dependencies, preManifest); err != nil {
			return err
		}
	} else if request.DependencyObject != nil {
		return errors.New("unexpected dependency manifest")
	}
	var publisher trusted.ArtifactPublisherEnvelopeBodyV1
	if err := trusted.DecodeBody(request.PublisherObject, "publisher-envelope", &publisher); err != nil {
		return err
	}
	now, err := s.trustedNowLocked()
	if err != nil {
		return err
	}
	if err := trusted.ValidatePublisherEnvelope(publisher, artifact, now); err != nil {
		return err
	}
	if err := trusted.VerifyAuthorization(request.PublisherAuthorization, request.PublisherObject, now, 0); err != nil {
		return err
	}
	issuer := request.PublisherAuthorization.Body.IssuerSubject
	if issuer.Kind != artifact.PublisherSubject.Kind || issuer.Namespace != artifact.PublisherSubject.Namespace || !bytes.Equal(issuer.Identifier, artifact.PublisherSubject.Identifier) ||
		request.PublisherAuthorization.Body.AuthorityKind != "artifact-publisher" {
		return errors.New("publisher proof subject mismatch")
	}
	artifactDigest, err := trusted.ObjectDigest(request.ArtifactObject)
	if err != nil {
		return err
	}
	newKey := hex.EncodeToString(artifactDigest)
	if _, deleted := s.state.Tombstones[newKey]; deleted {
		return errors.New("verified artifact is tombstoned and cannot be resurrected")
	}
	if existing, exists := s.state.Entries[newKey]; exists && !bytes.Equal(existing.ObservedContentDigest, entry.ObservedContentDigest) {
		return errors.New("artifact version digest equivocation")
	}
	entry.State = StateVerified
	entry.ArtifactDigest = artifactDigest
	entry.ArtifactObject = &request.ArtifactObject
	entry.PublisherObject = &request.PublisherObject
	entry.PublisherEnvelope = &request.PublisherAuthorization
	entry.PublisherEnvelopeExpiresAt = publisher.ExpiresAtUnix
	entry.PublisherRevocationGeneration = publisher.RevocationGeneration
	entry.PublisherSourceHeads = map[string]PublisherSourceHead{}
	entry.PermissionManifestDigest = append([]byte(nil), permissionDigest...)
	entry.PermissionObject = request.PermissionObject
	entry.ContentManifestObject = &request.ContentManifestObject
	entry.EntrypointObject = &request.EntrypointObject
	entry.ArtifactKind = artifact.ArtifactKind
	entry.Namespace = artifact.ArtifactNamespace
	entry.Name = artifact.ArtifactName
	entry.Version = artifact.ArtifactVersion
	entry.PromotionRequired = permissionRequiresPromotion(permission)
	entry.UpdatedAtUnix = now
	if err := s.revalidatePublisherLocked(&entry, now); err != nil {
		return err
	}
	delete(s.state.Entries, key)
	s.state.Entries[newKey] = entry
	s.state.InventoryRevision++
	return s.commitProjectionLocked()
}

func permissionRequiresPromotion(permission trusted.CapabilityPermissionManifestV1) bool {
	return len(permission.ToolCapabilities) > 0 || len(permission.ProcessCapabilities) > 0 || len(permission.FilesystemCapabilities) > 0 || len(permission.NetworkCapabilities) > 0 ||
		len(permission.CredentialCapabilities) > 0 || len(permission.DataClassesWrite) > 0 || len(permission.DisclosureCapabilities) > 0 ||
		len(permission.DataClassesRead) > 0 || len(permission.UploadCapabilities) > 0 || len(permission.DestructiveCapabilities) > 0 || permission.DirectCostCeiling != "0"
}

func (s *Store) Admit(request AdmissionRequest) error {
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
	if !ok || entry.State != StateVerified {
		return errors.New("artifact is not verified")
	}
	var body trusted.CapabilityAdmissionBodyV1
	if err := trusted.DecodeBody(request.Object, "capability-admission", &body); err != nil {
		return err
	}
	now, err := s.trustedNowLocked()
	if err != nil {
		return err
	}
	if err := s.revalidatePublisherLocked(&entry, now); err != nil {
		return err
	}
	if err := trusted.ValidateAdmission(body, now); err != nil {
		return err
	}
	if !bytes.Equal(body.OwnerID, s.state.OwnerID) || !bytes.Equal(body.AgentID, s.state.AgentID) || !bytes.Equal(body.ArtifactVersionDigest, request.ArtifactDigest) ||
		request.Object.DomainKind != s.state.DomainKind || !bytes.Equal(request.Object.DomainID, s.state.DomainID) ||
		!bytes.Equal(body.PermissionManifestDigest, entry.PermissionManifestDigest) || body.PolicyRevision != s.state.PolicyRevision || !bytes.Equal(body.PolicyDigest, s.state.PolicyDigest) {
		return errors.New("admission does not match current artifact or owner policy")
	}
	if err := trusted.VerifyAuthorization(request.Envelope, request.Object, now, s.state.AuthorityEpoch); err != nil {
		return err
	}
	if err := s.verifyPolicyAuthorizationLocked(request.Envelope, "capability-admission", body.AgentID); err != nil {
		return err
	}
	if err := s.acceptAuthorityHeadLocked(request.Envelope); err != nil {
		return err
	}
	entry.State = StateAdmitted
	entry.AdmissionObject = &request.Object
	entry.AdmissionEnvelope = &request.Envelope
	entry.AdmissionRevision = request.Envelope.Body.AuthorityRevision + 1
	entry.AdmissionRevocationGeneration = body.RevocationGeneration
	entry.UpdatedAtUnix = now
	s.state.Entries[key] = entry
	s.state.InventoryRevision++
	return s.commitAuthorityLocked()
}

// requireNewCapabilityWorkLocked is the single lifecycle fence for every path
// that can add, admit, promote, install, or otherwise prepare a new
// capability. Once owner exit starts, only evidence inspection and resolution
// of already-retained Actions remain available.
func (s *Store) requireNewCapabilityWorkLocked() error {
	if s.state.OwnerPaused {
		return errors.New("owner pause fences new capability work")
	}
	if s.state.OwnerExit != nil {
		return errors.New("owner exit fences new capability work")
	}
	return nil
}

type systemTrustedTime struct{}

func (systemTrustedTime) Now(context.Context) (time.Time, error) { return time.Now().UTC(), nil }

func (s *Store) trustedNowLocked() (uint64, error) {
	if s.clock == nil {
		return 0, errors.New("trusted time is unavailable")
	}
	now, err := s.clock.Now(context.Background())
	if err != nil || now.IsZero() || now.Unix() < 0 {
		return 0, errors.New("trusted time is unavailable")
	}
	value := uint64(now.UTC().Unix())
	if value < s.state.TrustedTimeHighWater {
		return 0, errors.New("trusted time rollback detected")
	}
	if value > s.state.TrustedTimeHighWater {
		s.state.TrustedTimeHighWater = value
		if err := s.commitAuthorityLocked(); err != nil {
			return 0, err
		}
	}
	return value, nil
}

func (s *Store) Inventory(ttl time.Duration) (trusted.CapabilityInventorySnapshotV1, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.state.Initialized || ttl <= 0 || s.state.PortfolioRevision == 0 {
		return trusted.CapabilityInventorySnapshotV1{}, errors.New("authoritative Inventory requires an initialized owner policy and positive freshness bound")
	}
	nowUnix, err := s.trustedNowLocked()
	if err != nil {
		return trusted.CapabilityInventorySnapshotV1{}, err
	}
	now := time.Unix(int64(nowUnix), 0).UTC()
	entries := make([]trusted.InventoryEntryV1, 0, len(s.state.Entries))
	keys := make([]string, 0, len(s.state.Entries))
	for key := range s.state.Entries {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		item := s.state.Entries[key]
		if item.AdmissionObject == nil || len(item.ArtifactDigest) != sha256.Size {
			continue
		}
		promotionID := (*[]byte)(nil)
		if item.PromotionObject != nil {
			d, _ := trusted.ObjectDigest(*item.PromotionObject)
			promotionID = &d
		}
		admissionID := []byte{}
		evidence := []trusted.ImmutableObjectReferenceV1{}
		if item.AdmissionObject != nil {
			var b trusted.CapabilityAdmissionBodyV1
			if trusted.DecodeBody(*item.AdmissionObject, "capability-admission", &b) == nil {
				admissionID = b.AdmissionID
			}
			reference, err := localEvidenceReference(*item.AdmissionObject)
			if err != nil {
				return trusted.CapabilityInventorySnapshotV1{}, err
			}
			evidence = append(evidence, reference)
			if item.AdmissionEnvelope != nil {
				envelopeObject, err := trusted.NewObject(trusted.DomainKind(item.AdmissionEnvelope.Body.DomainKind), item.AdmissionEnvelope.Body.DomainID, "authorization-envelope", *item.AdmissionEnvelope)
				if err != nil {
					return trusted.CapabilityInventorySnapshotV1{}, err
				}
				reference, err := localEvidenceReference(envelopeObject)
				if err != nil {
					return trusted.CapabilityInventorySnapshotV1{}, err
				}
				evidence = append(evidence, reference)
			}
		}
		if item.PromotionObject != nil {
			reference, err := localEvidenceReference(*item.PromotionObject)
			if err != nil {
				return trusted.CapabilityInventorySnapshotV1{}, err
			}
			evidence = append(evidence, reference)
		}
		if item.PromotionEnvelope != nil {
			envelopeObject, err := trusted.NewObject(trusted.DomainKind(item.PromotionEnvelope.Body.DomainKind), item.PromotionEnvelope.Body.DomainID, "authorization-envelope", *item.PromotionEnvelope)
			if err != nil {
				return trusted.CapabilityInventorySnapshotV1{}, err
			}
			reference, err := localEvidenceReference(envelopeObject)
			if err != nil {
				return trusted.CapabilityInventorySnapshotV1{}, err
			}
			evidence = append(evidence, reference)
		}
		entries = append(entries, trusted.InventoryEntryV1{ArtifactVersionDigest: item.ArtifactDigest, AdmissionID: admissionID, AdmissionRevision: item.AdmissionRevision,
			PromotionID: promotionID, PermissionManifestDigest: item.PermissionManifestDigest, RevocationGeneration: item.AdmissionRevocationGeneration, ProjectedState: string(item.State), EvidenceRefs: evidence})
	}
	created := uint64(now.UTC().Unix())
	token := sha256Bytes([]byte("inventory"), s.state.InstallationID, uint64Bytes(s.state.InventoryRevision), s.state.PolicyDigest)
	return trusted.CapabilityInventorySnapshotV1{OwnerID: append([]byte(nil), s.state.OwnerID...), AgentID: append([]byte(nil), s.state.AgentID...), SnapshotRevision: s.state.InventoryRevision,
		SourceGeneration: s.state.SourceGeneration, PolicyRevision: s.state.PolicyRevision, PolicyDigest: append([]byte(nil), s.state.PolicyDigest...), PortfolioRevision: s.state.PortfolioRevision,
		ConsistencyToken: token, CreatedAtUnix: created, ExpiresAtUnix: uint64(now.Add(ttl).UTC().Unix()), Entries: entries}, nil
}

func localEvidenceReference(object trusted.ProfileObjectV1) (trusted.ImmutableObjectReferenceV1, error) {
	raw, err := trusted.EncodeObject(object)
	if err != nil {
		return trusted.ImmutableObjectReferenceV1{}, err
	}
	digest, err := trusted.ObjectDigest(object)
	if err != nil {
		return trusted.ImmutableObjectReferenceV1{}, err
	}
	policy := sha256.Sum256([]byte("tos.owner-local-evidence-retrieval.v1"))
	return trusted.ImmutableObjectReferenceV1{DomainKind: object.DomainKind, DomainID: append([]byte(nil), object.DomainID...), ObjectKind: object.ObjectKind, ProfileURI: object.ProfileURI,
		ProfileVersion: object.ProfileVersion, ObjectDigest: digest, CanonicalSize: uint32(len(raw)), MediaType: "application/cbor", RetrievalPolicyDigest: policy[:], RetrievalHints: []string{}}, nil
}

func (s *Store) persistLocked() error {
	if s.lock == nil {
		_ = s.reloadLocked()
		return errors.New("capability control store is closed or unfenced")
	}
	raw, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	if err := fileutil.WriteFileAtomic(filepath.Join(s.root, stateFile), append(raw, '\n'), 0o600); err != nil {
		// A failed fsync/rename is ambiguous. Re-read the durable projection so a
		// retry cannot return success from an in-memory-only transition.
		_ = s.reloadLocked()
		return err
	}
	return nil
}

func (s *Store) monotonicScopeLocked() []byte {
	return sha256Bytes([]byte("trusted-capability-control"), []byte{s.state.DomainKind}, s.state.DomainID, s.state.OwnerID, s.state.AgentID, s.state.InstallationID)
}

func (s *Store) stateCommitmentLocked(revision uint64) ([]byte, error) {
	copyState := s.state
	copyState.MonotonicRevision = revision
	raw, err := json.Marshal(copyState)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(raw)
	return digest[:], nil
}

func (s *Store) checkMonotonicLocked() error {
	digest, err := s.stateCommitmentLocked(s.state.MonotonicRevision)
	if err != nil {
		return err
	}
	return s.monotonic.Check(context.Background(), s.monotonicScopeLocked(), s.state.MonotonicRevision, digest)
}

func (s *Store) reconcileMonotonicLocked() error {
	if s.monotonic == nil {
		return nil
	}
	raw, err := os.ReadFile(filepath.Join(s.root, pendingFile))
	if errors.Is(err, os.ErrNotExist) {
		return s.checkMonotonicLocked()
	}
	if err != nil {
		return err
	}
	var pending pendingAuthorityCommit
	if json.Unmarshal(raw, &pending) != nil || pending.SchemaVersion != 1 || pending.NextRevision != pending.PriorRevision+1 ||
		pending.NextState.MonotonicRevision != pending.NextRevision || pending.PriorRevision > s.state.MonotonicRevision ||
		pending.NextRevision < s.state.MonotonicRevision {
		return errors.New("pending capability authority transition is corrupt or inconsistent")
	}
	want, err := stateCommitment(pending.NextState)
	if err != nil || !bytes.Equal(want, pending.Commitment) {
		return errors.New("pending capability authority commitment mismatch")
	}
	revision, commitment, err := s.monotonic.Read(context.Background(), s.monotonicScopeLocked())
	if err != nil {
		return err
	}
	switch {
	case revision == pending.PriorRevision && s.state.MonotonicRevision == pending.PriorRevision:
		if err := s.advancePendingAuthorityLocked(pending); err != nil {
			return err
		}
	case revision == pending.NextRevision && bytes.Equal(commitment, pending.Commitment):
		// External linearization already happened; finish the durable projection.
	default:
		return errors.New("pending capability authority transition conflicts with external high-water")
	}
	s.state = pending.NextState
	if err := s.persistLocked(); err != nil {
		return err
	}
	return s.clearPendingLocked()
}

func (s *Store) commitAuthorityLocked() error {
	return s.commitAuthorityWithAcquisitionLocked(nil)
}

func (s *Store) commitAuthorityWithAcquisitionLocked(accepting *bool) error {
	if s.monotonic == nil {
		_ = s.reloadLocked()
		return errors.New("consequential capability mutation requires rollback-resistant monotonic authority storage")
	}
	if _, err := os.Stat(filepath.Join(s.root, pendingFile)); err == nil {
		_ = s.reloadLocked()
		return errors.New("prior capability authority commit is ambiguous; reopen to reconcile")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	prior := s.state.MonotonicRevision
	next := prior + 1
	nextState := s.state
	nextState.MonotonicRevision = next
	digest, err := stateCommitment(nextState)
	if err != nil {
		return err
	}
	pending := pendingAuthorityCommit{SchemaVersion: 1, PriorRevision: prior, NextRevision: next, Commitment: digest, NextState: nextState, AcquisitionAccepting: accepting}
	if err := s.persistPendingLocked(pending); err != nil {
		_ = s.reloadLocked()
		return err
	}
	if err := s.advancePendingAuthorityLocked(pending); err != nil {
		_ = s.reloadLocked()
		return err
	}
	s.state = nextState
	if err := s.persistLocked(); err != nil {
		return err // pending marker permits deterministic startup completion.
	}
	return s.clearPendingLocked()
}

func (s *Store) advancePendingAuthorityLocked(pending pendingAuthorityCommit) error {
	if pending.AcquisitionAccepting == nil {
		return s.monotonic.CompareAndAdvance(context.Background(), s.monotonicScopeLocked(), pending.PriorRevision, pending.NextRevision, pending.Commitment)
	}
	if s.acquisitionControl == nil {
		control, ok := s.monotonic.(CapabilityAcquisitionControl)
		if !ok {
			return errors.New("atomic external acquisition-control high-water is unavailable")
		}
		s.acquisitionControl = control
	}
	return s.acquisitionControl.CompareAndAdvanceCapabilityControl(context.Background(), s.monotonicScopeLocked(), pending.PriorRevision,
		pending.NextRevision, pending.Commitment, s.state.OwnerID, s.state.AgentID, *pending.AcquisitionAccepting)
}

func stateCommitment(state DurableState) ([]byte, error) {
	raw, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(raw)
	return digest[:], nil
}

func (s *Store) persistPendingLocked(pending pendingAuthorityCommit) error {
	raw, err := json.MarshalIndent(pending, "", "  ")
	if err != nil {
		return err
	}
	return fileutil.WriteFileAtomic(filepath.Join(s.root, pendingFile), append(raw, '\n'), 0o600)
}

func (s *Store) clearPendingLocked() error {
	if err := os.Remove(filepath.Join(s.root, pendingFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	directory, err := os.Open(s.root)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (s *Store) commitProjectionLocked() error {
	if s.monotonic == nil {
		return s.persistLocked()
	}
	return s.commitAuthorityLocked()
}

func (s *Store) reloadLocked() error {
	raw, err := os.ReadFile(filepath.Join(s.root, stateFile))
	if err != nil {
		return err
	}
	var durable DurableState
	if err := json.Unmarshal(raw, &durable); err != nil {
		return err
	}
	s.state = durable
	return nil
}

func (s *Store) verifyPolicyAuthorizationLocked(envelope trusted.ProfileAuthorizationEnvelopeV1, authorityKind string, agentID []byte) error {
	body := envelope.Body
	if body.AuthorityKind != authorityKind || body.AuthorityEpoch != s.state.AuthorityEpoch || body.PolicyRevision != s.state.PolicyRevision ||
		!bytes.Equal(body.PolicyDigest, s.state.PolicyDigest) || !bytes.Equal(body.OwnerID, s.state.OwnerID) || body.AgentID == nil ||
		!bytes.Equal(*body.AgentID, agentID) || !subjectAllowed(s.state.AuthorizedSubjects, authorityKind, body.IssuerSubject.Identifier) {
		return errors.New("authorization issuer or current policy scope mismatch")
	}
	return nil
}

func (s *Store) acceptAuthorityHeadLocked(envelope trusted.ProfileAuthorizationEnvelopeV1) error {
	body := envelope.Body
	key := body.AuthorityKind + "\x00" + hex.EncodeToString(body.AuthorityID)
	if prior, ok := s.state.AuthorityHeads[key]; ok {
		if err := trusted.ValidateLinearSuccessor(prior.EnvelopeDigest, prior.Revision, prior.Epoch, body); err != nil {
			return err
		}
	} else if body.AuthorityRevision != 0 || body.PredecessorEnvelopeDigest != nil || body.AuthorityEpoch != s.state.AuthorityEpoch {
		return errors.New("authority genesis is invalid")
	}
	object, err := trusted.NewObject(trusted.DomainKind(body.DomainKind), body.DomainID, "authorization-envelope", envelope)
	if err != nil {
		return err
	}
	digest, err := trusted.ObjectDigest(object)
	if err != nil {
		return err
	}
	s.state.AuthorityHeads[key] = AuthorityHead{Revision: body.AuthorityRevision, Epoch: body.AuthorityEpoch, EnvelopeDigest: digest}
	return nil
}

func subjectAllowed(subjects map[string][][]byte, kind string, identifier []byte) bool {
	for _, candidate := range subjects[kind] {
		if bytes.Equal(candidate, identifier) {
			return true
		}
	}
	return false
}

func cloneSubjects(input map[string][][]byte) map[string][][]byte {
	output := make(map[string][][]byte, len(input))
	for kind, list := range input {
		for _, item := range list {
			output[kind] = append(output[kind], append([]byte(nil), item...))
		}
	}
	return output
}

type subjectBinding struct {
	Kind        string   `cbor:"1,keyasint"`
	Identifiers [][]byte `cbor:"2,keyasint"`
	Controllers []string `cbor:"3,keyasint"`
}

func canonicalSubjects(input map[string][][]byte, controllers map[string]string) ([]subjectBinding, error) {
	kinds := make([]string, 0, len(input))
	for kind := range input {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	result := make([]subjectBinding, 0, len(kinds))
	for _, kind := range kinds {
		ids := cloneSubjects(map[string][][]byte{kind: input[kind]})[kind]
		sort.Slice(ids, func(i, j int) bool { return bytes.Compare(ids[i], ids[j]) < 0 })
		owners := make([]string, len(ids))
		for index, id := range ids {
			controller := controllers[hex.EncodeToString(id)]
			if controller == "" || strings.TrimSpace(controller) != controller {
				return nil, errors.New("every authority subject must bind a non-empty controlling principal")
			}
			owners[index] = controller
		}
		result = append(result, subjectBinding{kind, ids, owners})
	}
	return result, nil
}

func cloneControllers(input map[string]string) map[string]string {
	output := make(map[string]string, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func hashRegularFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("capability file is not regular")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	return sum[:], nil
}

func HashTree(root string) ([]byte, error) {
	manifest, err := BuildContentManifest(root)
	if err != nil {
		return nil, err
	}
	return manifest.ClosureRoot, nil
}

func BuildContentManifest(root string) (trusted.CapabilityContentManifestV1, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return trusted.CapabilityContentManifestV1{}, err
	}
	entries := make([]trusted.ContentManifestEntryV1, 0)
	count := 0
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		if entry.Name() == ".skill-origin.json" {
			return nil
		}
		count++
		if count > 4096 {
			return errors.New("capability tree exceeds file limit")
		}
		rel, err := filepath.Rel(root, path)
		if err != nil || strings.HasPrefix(rel, "..") {
			return errors.New("capability path escapes root")
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !entry.IsDir() && !info.Mode().IsRegular() {
			return errors.New("capability tree contains unsupported file")
		}
		rel = filepath.ToSlash(rel)
		mode := info.Mode().Perm() & 0o555
		if entry.IsDir() {
			mode = 0o700
		}
		// File closures are normalized to read/execute-only modes before
		// acquisition, so the digest remains identical after immutable publish.
		manifestEntry := trusted.ContentManifestEntryV1{Path: rel, Mode: uint32(mode)}
		if entry.IsDir() {
			manifestEntry.ObjectType = "directory"
		} else {
			if fileLinkCount(info) != 1 {
				return errors.New("capability tree contains a hard-linked file")
			}
			manifestEntry.ObjectType = "regular"
			manifestEntry.Size = uint64(info.Size())
		}
		if info.Mode().IsRegular() {
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if uint64(len(raw)) != manifestEntry.Size {
				return errors.New("capability file changed during observation")
			}
			digest := sha256.Sum256(raw)
			manifestEntry.ContentDigest = digest[:]
		}
		entries = append(entries, manifestEntry)
		return nil
	})
	if err != nil {
		return trusted.CapabilityContentManifestV1{}, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	closure, err := trusted.ContentClosureRoot(entries)
	if err != nil {
		return trusted.CapabilityContentManifestV1{}, err
	}
	return trusted.CapabilityContentManifestV1{SchemaVersion: trusted.SchemaVersion, Entries: entries, ClosureRoot: closure}, nil
}

func sha256Bytes(fields ...[]byte) []byte {
	h := sha256.New()
	for _, value := range fields {
		h.Write(value)
		h.Write([]byte{0})
	}
	return h.Sum(nil)
}
func uint64Bytes(value uint64) []byte {
	return []byte{byte(value >> 56), byte(value >> 48), byte(value >> 40), byte(value >> 32), byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)}
}
