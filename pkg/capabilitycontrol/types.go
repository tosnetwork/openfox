// Package capabilitycontrol is OpenFox's owner-local trusted capability
// control plane. Portable bytes and verification live in tos-service-protocol;
// this package owns durable projections, installation and execution admission.
package capabilitycontrol

import (
	"context"
	"errors"
	"time"

	trusted "github.com/tosnetwork/tos-service-protocol/pkg/trustedcapability"
)

type State string

const (
	StateUnverifiedLegacy State = "UNVERIFIED_LEGACY"
	StateQuarantined      State = "quarantined"
	StateVerified         State = "verified"
	StateAdmitted         State = "admitted"
	StateActive           State = "active"
	StateSuspended        State = "suspended"
	StateRevoked          State = "revoked"
	StateExpired          State = "expired"
	StateRejected         State = "rejected"
)

type Entry struct {
	ArtifactDigest                []byte                                  `json:"artifact_digest"`
	ObservedContentDigest         []byte                                  `json:"observed_content_digest"`
	ArtifactKind                  string                                  `json:"artifact_kind"`
	Namespace                     string                                  `json:"namespace"`
	Name                          string                                  `json:"name"`
	Version                       string                                  `json:"version"`
	State                         State                                   `json:"state"`
	InstalledPath                 string                                  `json:"installed_path,omitempty"`
	QuarantinePath                string                                  `json:"quarantine_path,omitempty"`
	PermissionManifestDigest      []byte                                  `json:"permission_manifest_digest,omitempty"`
	PermissionObject              *trusted.ProfileObjectV1                `json:"permission_object,omitempty"`
	ContentManifestObject         *trusted.ProfileObjectV1                `json:"content_manifest_object,omitempty"`
	EntrypointObject              *trusted.ProfileObjectV1                `json:"entrypoint_object,omitempty"`
	ArtifactObject                *trusted.ProfileObjectV1                `json:"artifact_object,omitempty"`
	PublisherObject               *trusted.ProfileObjectV1                `json:"publisher_object,omitempty"`
	PublisherEnvelope             *trusted.ProfileAuthorizationEnvelopeV1 `json:"publisher_envelope,omitempty"`
	PublisherEnvelopeExpiresAt    uint64                                  `json:"publisher_envelope_expires_at"`
	PublisherRevocationGeneration uint64                                  `json:"publisher_revocation_generation"`
	PublisherSourceHeads          map[string]PublisherSourceHead          `json:"publisher_source_heads,omitempty"`
	AdmissionObject               *trusted.ProfileObjectV1                `json:"admission_object,omitempty"`
	AdmissionEnvelope             *trusted.ProfileAuthorizationEnvelopeV1 `json:"admission_envelope,omitempty"`
	AdmissionRevision             uint64                                  `json:"admission_revision"`
	AdmissionRevocationGeneration uint64                                  `json:"admission_revocation_generation"`
	PromotionObject               *trusted.ProfileObjectV1                `json:"promotion_object,omitempty"`
	PromotionEnvelope             *trusted.ProfileAuthorizationEnvelopeV1 `json:"promotion_envelope,omitempty"`
	PromotionRevision             uint64                                  `json:"promotion_revision"`
	PromotionRevocationGeneration uint64                                  `json:"promotion_revocation_generation"`
	PromotionRequired             bool                                    `json:"promotion_required"`
	InstallationRevision          uint64                                  `json:"installation_revision"`
	UpdatedAtUnix                 uint64                                  `json:"updated_at_unix"`
}

type DurableState struct {
	SchemaVersion                   uint16                         `json:"schema_version"`
	Initialized                     bool                           `json:"initialized"`
	DomainKind                      uint8                          `json:"domain_kind"`
	DomainID                        []byte                         `json:"domain_id"`
	InstallationID                  []byte                         `json:"installation_id"`
	DeploymentFormatEpoch           uint64                         `json:"deployment_format_epoch"`
	OwnerID                         []byte                         `json:"owner_id"`
	AgentID                         []byte                         `json:"agent_id"`
	AuthorityEpoch                  uint64                         `json:"authority_epoch"`
	PolicyRevision                  uint64                         `json:"policy_revision"`
	PolicyDigest                    []byte                         `json:"policy_digest"`
	CapabilityPolicyDigest          []byte                         `json:"capability_policy_digest"`
	PromotionSeparationPolicyDigest []byte                         `json:"promotion_separation_policy_digest"`
	AuthorizedSubjects              map[string][][]byte            `json:"authorized_subjects"`
	AuthorityControllers            map[string]string              `json:"authority_controllers"`
	AuthorityHeads                  map[string]AuthorityHead       `json:"authority_heads"`
	InventoryRevision               uint64                         `json:"inventory_revision"`
	SourceGeneration                uint64                         `json:"source_generation"`
	ControlScopeGeneration          uint64                         `json:"control_scope_generation"`
	OwnerPaused                     bool                           `json:"owner_paused"`
	DeletionGeneration              uint64                         `json:"deletion_generation"`
	MonotonicRevision               uint64                         `json:"monotonic_revision"`
	TrustedTimeHighWater            uint64                         `json:"trusted_time_high_water"`
	TrustedTimeEpochHighWater       uint64                         `json:"trusted_time_epoch_high_water"`
	GenesisCeremonyDigest           []byte                         `json:"genesis_ceremony_digest,omitempty"`
	BootstrapNonce                  []byte                         `json:"bootstrap_nonce,omitempty"`
	Entries                         map[string]Entry               `json:"entries"`
	UseSlots                        map[string]UseSlot             `json:"use_slots"`
	Tombstones                      map[string]Tombstone           `json:"tombstones"`
	InstallationSlots               map[string]InstallationSlot    `json:"installation_slots"`
	PortfolioRevision               uint64                         `json:"portfolio_revision"`
	DeviceSessions                  map[string]DeviceSessionRecord `json:"device_sessions"`
	OwnerExit                       *trusted.OwnerExitPlanV1       `json:"owner_exit,omitempty"`
	OwnerCommandActions             map[string]OwnerCommandAction  `json:"owner_command_actions"`
	MCPToolActions                  map[string]MCPToolAction       `json:"mcp_tool_actions"`
}

type OwnerCommandAction struct {
	ExactRequestDigest []byte `json:"exact_request_digest"`
	FencingToken       []byte `json:"fencing_token"`
	State              string `json:"state"`
	ResultRevision     uint64 `json:"result_revision"`
}

type MCPToolAction struct {
	ActionID              []byte `json:"action_id"`
	ExactRequestDigest    []byte `json:"exact_request_digest"`
	ResolutionTokenDigest []byte `json:"resolution_token_digest"`
	State                 string `json:"state"`
	PreparedAtUnix        uint64 `json:"prepared_at_unix"`
	ResolvedAtUnix        uint64 `json:"resolved_at_unix,omitempty"`
	TerminalDisposition   string `json:"terminal_disposition,omitempty"`
	ResultDigest          []byte `json:"result_digest,omitempty"`
	OutcomeEvidenceDigest []byte `json:"outcome_evidence_digest,omitempty"`
	OutcomeAuthorityID    []byte `json:"outcome_authority_id"`
	OutcomeAuthorityEpoch uint64 `json:"outcome_authority_epoch"`
}

// MonotonicAuthorityStore is a rollback-resistant linearization service (for
// example a hardware-backed counter or separately administered custody
// journal). A filesystem copy next to control-state.json is not conforming.
type MonotonicAuthorityStore interface {
	Read(context.Context, []byte) (uint64, []byte, error)
	Check(context.Context, []byte, uint64, []byte) error
	CompareAndAdvance(context.Context, []byte, uint64, uint64, []byte) error
}

type ProductionAuthority interface {
	MonotonicAuthorityStore
	CapabilityAcquisitionControl
	TrustedTimeSource
	TrustedTimeEvidenceSource
	InstallationFenceVerifier
	InstallationIdentityAuthority
	CapabilityAcquisitionFence
	Close() error
}

// CapabilityAcquisitionFence is the external linearization boundary consulted
// before a supply-chain retrieval starts and again before its quarantine
// result becomes durable. It rejects every phase once owner exit has fenced new
// work.
type CapabilityAcquisitionFence interface {
	AdmitCapabilityAcquisition(context.Context, CapabilityAcquisitionRequest) error
}

// CapabilityAcquisitionRequest is the canonical rollback-resistant closure
// for one quarantine transition. The external authority binds a single
// LedgerID to each Owner/Agent scope and performs an idempotent CAS on
// PriorRevision -> NextRevision. A repeated acquisition ID with different
// provenance, quotas, expiry or content is therefore a conflict.
type CapabilityAcquisitionRequest = trusted.CapabilityAcquisitionTransitionV1

// CapabilityAcquisitionControl atomically advances the capability-control
// high-water and the external new-acquisition state. Implementations must make
// the two updates one linearizable transaction: acknowledging a fenced state
// while leaving acquisition admission open is forbidden.
type CapabilityAcquisitionControl interface {
	CompareAndAdvanceCapabilityControl(context.Context, []byte, uint64, uint64, []byte, []byte, []byte, bool) error
}

// InstallationIdentityAuthority assigns the stable, non-exportable identity
// which namespaces every rollback-resistant high-water for one deployment.
type InstallationIdentityAuthority interface {
	ResolveInstallationID(context.Context, trusted.DomainKind, []byte, []byte, []byte) ([]byte, error)
}

type pendingAuthorityCommit struct {
	SchemaVersion uint16       `json:"schema_version"`
	PriorRevision uint64       `json:"prior_revision"`
	NextRevision  uint64       `json:"next_revision"`
	Commitment    []byte       `json:"commitment"`
	NextState     DurableState `json:"next_state"`
	// AcquisitionAccepting is present only when this authority transition must
	// atomically change the external acquisition fence.
	AcquisitionAccepting *bool `json:"acquisition_accepting,omitempty"`
}

type TrustedTimeSource interface {
	Now(context.Context) (time.Time, error)
}

// TrustedTimeEvidenceSource exposes the signed authority observation required
// by an external executor Gate. A locally recomputed timestamp hash is not
// authority evidence.
type TrustedTimeEvidenceSource interface {
	ObserveTrustedTime(context.Context) (TrustedTimeEvidenceObservation, error)
}

type TrustedTimeEvidenceObservation struct {
	UnixSeconds    uint64
	Epoch          uint64
	EvidenceDigest []byte
}

type InstallationFenceVerifier interface {
	VerifyCapabilityInstallation(context.Context, trusted.CapabilityInstallationTransactionV1) error
}

// PublisherAuthorityVerifier resolves policy-required revocation sources and
// returns freshly verified source-local observations. The Store independently
// validates object signatures, bindings and monotonic high-waters.
type PublisherAuthorityVerifier interface {
	RequiredPublisherSources(context.Context, []byte) ([][]byte, error)
	CurrentPublisherObservations(context.Context, trusted.ProfileObjectV1, trusted.ProfileAuthorizationEnvelopeV1, trusted.ProfileObjectV1, uint64) ([]PublisherObservation, error)
}

type PublisherObservation struct {
	Object   trusted.ProfileObjectV1
	Envelope trusted.ProfileAuthorizationEnvelopeV1
}

type PublisherSourceHead struct {
	SourceGeneration   uint64 `json:"source_generation"`
	ObservedGeneration uint64 `json:"observed_generation"`
	CheckpointRoot     []byte `json:"checkpoint_root"`
}

type InstallationSlot struct {
	ActionID           []byte `json:"action_id"`
	ExactRequestDigest []byte `json:"exact_request_digest"`
	ArtifactDigest     []byte `json:"artifact_digest"`
	State              string `json:"state"`
	TargetPath         string `json:"target_path"`
}

type DeviceSessionRecord struct {
	Object               trusted.ProfileObjectV1                `json:"object"`
	Envelope             trusted.ProfileAuthorizationEnvelopeV1 `json:"envelope"`
	SessionGeneration    uint64                                 `json:"session_generation"`
	RevocationGeneration uint64                                 `json:"revocation_generation"`
	Revoked              bool                                   `json:"revoked"`
}

type DeviceSessionRequest struct {
	Object   trusted.ProfileObjectV1
	Envelope trusted.ProfileAuthorizationEnvelopeV1
}

type AuthorityHead struct {
	Revision       uint64 `json:"revision"`
	Epoch          uint64 `json:"epoch"`
	EnvelopeDigest []byte `json:"envelope_digest"`
}

type UseSlot struct {
	ExecutionID                   []byte `json:"execution_id"`
	ActionID                      []byte `json:"action_id"`
	ExactRequestDigest            []byte `json:"exact_request_digest"`
	ArtifactDigest                []byte `json:"artifact_digest"`
	State                         string `json:"state"`
	LeaseDigest                   []byte `json:"lease_digest"`
	ControlScopeGeneration        uint64 `json:"control_scope_generation"`
	AdmissionRevision             uint64 `json:"admission_revision"`
	AdmissionRevocationGeneration uint64 `json:"admission_revocation_generation"`
	PromotionRevision             uint64 `json:"promotion_revision"`
	PromotionRevocationGeneration uint64 `json:"promotion_revocation_generation"`
	StartedAtUnix                 uint64 `json:"started_at_unix,omitempty"`
	ResolvedAtUnix                uint64 `json:"resolved_at_unix,omitempty"`
	TerminalDisposition           string `json:"terminal_disposition,omitempty"`
	ResolutionTokenDigest         []byte `json:"resolution_token_digest"`
	ResultDigest                  []byte `json:"result_digest,omitempty"`
	OutcomeEvidenceDigest         []byte `json:"outcome_evidence_digest,omitempty"`
	OutcomeAuthorityID            []byte `json:"outcome_authority_id"`
	OutcomeAuthorityEpoch         uint64 `json:"outcome_authority_epoch"`
}

type ActionOutcomeRecoveryRequest struct {
	Object   trusted.ProfileObjectV1                `json:"object"`
	Envelope trusted.ProfileAuthorizationEnvelopeV1 `json:"envelope"`
}

type Tombstone struct {
	ArtifactDigest               []byte `json:"artifact_digest"`
	PredecessorInventoryRevision uint64 `json:"predecessor_inventory_revision"`
	InventoryRevision            uint64 `json:"inventory_revision"`
	DeletionGeneration           uint64 `json:"deletion_generation"`
	RemovedAtUnix                uint64 `json:"removed_at_unix"`
	RemovalActionID              []byte `json:"removal_action_id"`
	ExactRequestDigest           []byte `json:"exact_request_digest"`
	PolicyDigest                 []byte `json:"policy_digest"`
	ControlScopeGeneration       uint64 `json:"control_scope_generation"`
}

type AdmissionRequest struct {
	ArtifactDigest []byte                                 `json:"artifact_digest"`
	Object         trusted.ProfileObjectV1                `json:"object"`
	Envelope       trusted.ProfileAuthorizationEnvelopeV1 `json:"envelope"`
}

type VerificationRequest struct {
	QuarantineDigest       []byte                                 `json:"quarantine_digest"`
	ArtifactObject         trusted.ProfileObjectV1                `json:"artifact_object"`
	ContentManifestObject  trusted.ProfileObjectV1                `json:"content_manifest_object"`
	EntrypointObject       trusted.ProfileObjectV1                `json:"entrypoint_object"`
	PermissionObject       *trusted.ProfileObjectV1               `json:"permission_object"`
	DependencyObject       *trusted.ProfileObjectV1               `json:"dependency_object"`
	PublisherObject        trusted.ProfileObjectV1                `json:"publisher_object"`
	PublisherAuthorization trusted.ProfileAuthorizationEnvelopeV1 `json:"publisher_authorization"`
}

type BootstrapRequest struct {
	CeremonyObject                 trusted.ProfileObjectV1                  `json:"ceremony_object"`
	RootCeremonyAuthorization      trusted.ProfileAuthorizationEnvelopeV1   `json:"root_ceremony_authorization"`
	RecoveryCeremonyAuthorizations []trusted.ProfileAuthorizationEnvelopeV1 `json:"recovery_ceremony_authorizations"`
	PolicyObject                   trusted.ProfileObjectV1                  `json:"policy_object"`
	Envelope                       trusted.ProfileAuthorizationEnvelopeV1   `json:"envelope"`
	AuthorizedSubjects             map[string][][]byte                      `json:"authorized_subjects"`
	AuthorityControllers           map[string]string                        `json:"authority_controllers"`
}

type PromotionRequest struct {
	ArtifactDigest           []byte                                 `json:"artifact_digest"`
	Object                   trusted.ProfileObjectV1                `json:"object"`
	Envelope                 trusted.ProfileAuthorizationEnvelopeV1 `json:"envelope"`
	GeneratorAuthorization   trusted.ProfileAuthorizationEnvelopeV1 `json:"generator_authorization"`
	EvaluationObject         trusted.ProfileObjectV1                `json:"evaluation_object"`
	VerifierEnvelopeObject   trusted.ProfileObjectV1                `json:"verifier_envelope_object"`
	SourcingDecisionObject   trusted.ProfileObjectV1                `json:"sourcing_decision_object"`
	EvaluationManifestObject trusted.ProfileObjectV1                `json:"evaluation_manifest_object"`
	// EvidenceObjects contains every immutable object named by a digest in the
	// evaluation/promotion predicate, sorted by ObjectDigest.
	EvidenceObjects []trusted.ProfileObjectV1 `json:"evidence_objects"`
}

type PolicyRotationRequest struct {
	PolicyObject         trusted.ProfileObjectV1                `json:"policy_object"`
	Envelope             trusted.ProfileAuthorizationEnvelopeV1 `json:"envelope"`
	AuthorizedSubjects   map[string][][]byte                    `json:"authorized_subjects"`
	AuthorityControllers map[string]string                      `json:"authority_controllers"`
}

type StartRequest struct {
	Binding                trusted.CapabilityUseBindingV1
	LeaseObject            trusted.ProfileObjectV1
	LeaseEnvelope          trusted.ProfileAuthorizationEnvelopeV1
	PermissionSubsetObject trusted.ProfileObjectV1
	Remote                 bool
	Observed               ObservedUseContext
}

type InstallationRequest struct {
	Object   trusted.ProfileObjectV1                `json:"object"`
	Envelope trusted.ProfileAuthorizationEnvelopeV1 `json:"envelope"`
}

type ObservedUseContext struct {
	LoadedObjectDigest                     []byte
	InstallationRevision                   uint64
	RuntimeAndSandboxDigest                []byte
	EffectiveEnvironmentDigest             []byte
	CredentialCapabilityReferenceSetDigest []byte
	FilesystemHandleSetDigest              []byte
	NetworkBrokerPolicyDigest              []byte
	RemoteSessionHandshakeDigest           *[]byte
}

var (
	ErrUnverifiedLegacy  = errors.New("unverified legacy capability cannot perform consequential work")
	ErrNotAdmitted       = errors.New("capability is not admitted and active")
	ErrPromotionRequired = errors.New("current promotion authority is required")
	ErrStaleAuthority    = errors.New("capability authority, policy, or control generation is stale")
	ErrAmbiguousStart    = errors.New("execution start is already prepared or ambiguous")
)
