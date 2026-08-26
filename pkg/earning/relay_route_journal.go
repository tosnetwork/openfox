package earning

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

const (
	relayRouteJournalSchema            = "tos.openfox.agent-relay-route-journal.v1"
	relayRouteJournalFile              = "agent-relay-route-journal.json"
	maximumRelayRouteJournalBytes      = 64 << 20
	maximumRelayRoutes                 = 4096
	maximumRelayRouteCandidates        = 32
	maximumRelayRouteHops              = 32
	maximumLegacySponsorshipEffects    = 4096
	maximumRelaySponsorshipEffectCache = 1024
	maximumRelaySponsorshipEffectBytes = 16 << 10
	relaySponsorshipEffectDirectory    = ".agent-relay-sponsorship-effects"
	maximumRelayTerminalRouteBytes     = 64 << 10
	maximumRelayTerminalArtifactBytes  = 8 << 20
	maximumRelayTerminalHandoffBytes   = 16 << 10
	maximumRelayTerminalArtifacts      = 256
	relayTerminalRouteDirectory        = ".agent-relay-terminal-routes"
	relayTerminalArtifactDirectory     = ".agent-relay-terminal-artifacts"
	relayTerminalRouteTombstoneSchema  = "tos.openfox.agent-relay-terminal-route.v1"
	relayTerminalRouteArtifactSchema   = "tos.openfox.agent-relay-terminal-route-artifact.v1"
	relayTerminalRouteArtifactDomain   = "tos.openfox.agent-relay-terminal-route-artifact.v1"
)

type relayResolveQueryOutcome string

const (
	relayResolveRemoteUnknown relayResolveQueryOutcome = "remote_unknown"
	relayResolveUnavailable   relayResolveQueryOutcome = "transport_unavailable"
	relayResolveAmbiguous     relayResolveQueryOutcome = "signed_ambiguous"

	relayFailoverGateFinality = "finality"
	relayFailoverGateQuery    = "resolve_query"
)

// relayRouteResolveQueryAttempt is owner-local evidence that the exact
// selected Provider route was queried through its authenticated transport
// before relay_exact failover. It does not assert non-broadcast: the frozen,
// byte-identical transaction identity makes that uncertainty safe.
type relayRouteResolveQueryAttempt struct {
	SchemaVersion                 uint16                            `json:"schema_version"`
	RouteGeneration               uint64                            `json:"route_generation"`
	ProviderAgentID               string                            `json:"provider_agent_id"`
	ProviderProfileDigest         string                            `json:"provider_profile_digest"`
	AuthenticatedPrincipal        string                            `json:"authenticated_principal_id"`
	TransportAuthenticationDigest string                            `json:"transport_authentication_digest"`
	NetworkDigest                 string                            `json:"network_digest"`
	TransactionIdentityDigest     string                            `json:"transaction_identity_digest"`
	StableActionID                string                            `json:"stable_action_id"`
	ExactRequestDigest            string                            `json:"exact_request_digest"`
	RelayExecutionDigest          string                            `json:"relay_execution_digest"`
	Outcome                       relayResolveQueryOutcome          `json:"outcome"`
	ResolutionDigest              string                            `json:"resolution_digest,omitempty"`
	Resolution                    *agentrelay.SignedRelayResolution `json:"protected_resolution,omitempty"`
	StartedAtUnix                 uint64                            `json:"started_at_unix"`
	CompletedAtUnix               uint64                            `json:"completed_at_unix"`
}

// RelayProviderProvenance is owner-attested configuration, not a provider
// self-assertion. Its failure-domain data is part of the durable route gate.
type RelayProviderProvenance struct {
	ProviderAgentID            string `json:"provider_agent_id"`
	IntentDigest               string `json:"intent_digest"`
	ProfileDigest              string `json:"profile_digest"`
	OperatorDomain             string `json:"operator_domain"`
	FailureDomain              string `json:"failure_domain"`
	EndpointOrigin             string `json:"endpoint_origin"`
	CertificatePinDigest       string `json:"certificate_pin_digest"`
	ImplementationEvidenceHash string `json:"implementation_evidence_digest"`
}

type RelayRouteHop struct {
	Generation                     uint64                                  `json:"generation"`
	Provider                       RelayProviderProvenance                 `json:"provider"`
	RelayExecutionDigest           string                                  `json:"relay_execution_digest"`
	Attempt                        RelayAttempt                            `json:"protected_exact_attempt"`
	SubmitStarted                  bool                                    `json:"submit_started"`
	TerminalResolutionDigest       string                                  `json:"terminal_resolution_digest,omitempty"`
	TerminalResolution             *agentrelay.SignedRelayResolution       `json:"protected_terminal_resolution,omitempty"`
	TerminalFinalityEvidenceDigest string                                  `json:"terminal_finality_evidence_digest,omitempty"`
	TerminalFinalityEvidence       *agentrelay.SignedRelayFinalityEvidence `json:"protected_terminal_finality_evidence,omitempty"`
	FailoverFinalityEvidenceDigest string                                  `json:"failover_finality_evidence_digest,omitempty"`
	FailoverFinalityEvidence       *agentrelay.SignedRelayFinalityEvidence `json:"protected_failover_finality_evidence,omitempty"`
	FailoverQueryAttemptDigest     string                                  `json:"failover_query_attempt_digest,omitempty"`
	FailoverQueryAttempt           *relayRouteResolveQueryAttempt          `json:"protected_failover_query_attempt,omitempty"`
}

// RelayRoutePendingSwitch is persisted before asking the Action Authority for
// a successor receipt. It contains no side-effect authority: its receipt field
// must be empty. Its sole purpose is to make the exact successor lookup
// recoverable if the process crashes after receipt issuance but before the
// route switch is committed.
type RelayRoutePendingSwitch struct {
	Generation                      uint64                      `json:"generation"`
	Provider                        RelayProviderProvenance     `json:"provider"`
	RelayExecutionDigest            string                      `json:"relay_execution_digest"`
	Attempt                         RelayAttempt                `json:"protected_exact_attempt_without_receipt"`
	FailoverGateKind                string                      `json:"failover_gate_kind"`
	FailoverGateDigest              string                      `json:"failover_gate_digest"`
	CumulativeServiceFeeAtomicAfter string                      `json:"cumulative_service_fee_atomic_after"`
	AdmissionEnvelopeDigest         string                      `json:"admission_envelope_digest"`
	AdmissionRevision               uint64                      `json:"admission_revision"`
	AdmissionStarted                bool                        `json:"admission_started"`
	AdmissionStartedAtUnix          uint64                      `json:"admission_started_at_unix,omitempty"`
	Rebase                          *relayAdmissionRebaseRecord `json:"protected_rebase,omitempty"`
	PreparedAtUnix                  uint64                      `json:"prepared_at_unix"`
}

type RelayRouteRecord struct {
	StableActionID                    string                    `json:"stable_action_id"`
	ExactRequestDigest                string                    `json:"exact_request_digest"`
	Candidates                        []RelayProviderProvenance `json:"candidates"`
	Hops                              []RelayRouteHop           `json:"hops"`
	PendingSwitch                     *RelayRoutePendingSwitch  `json:"pending_switch,omitempty"`
	MaximumRouteAttempts              uint32                    `json:"maximum_route_attempts"`
	ServiceFeeAsset                   agentrelay.AssetIdentity  `json:"service_fee_asset"`
	MaximumCumulativeServiceFeeAtomic string                    `json:"maximum_cumulative_service_fee_atomic"`
	CumulativeServiceFeeAtomic        string                    `json:"cumulative_service_fee_atomic"`
	CreatedAtUnix                     uint64                    `json:"created_at_unix"`
	UpdatedAtUnix                     uint64                    `json:"updated_at_unix"`
}

// RelaySponsorshipChainEffect is the owner-wide replay identity for one
// Provider-funded chain effect. The identity is deliberately independent of
// an Agreement; BindingDigest records the one Agreement/payment projection
// allowed to consume it. A genuine old top-up can therefore never be reused
// to settle a new Agreement after restart or Provider-profile rotation.
type RelaySponsorshipChainEffect struct {
	EffectIdentityDigest          string `json:"effect_identity_digest"`
	BindingDigest                 string `json:"binding_digest"`
	NetworkDigest                 string `json:"network_digest"`
	ProviderSponsorSourceAccount  string `json:"provider_sponsor_source_account"`
	ProviderSponsorSourceSequence uint64 `json:"provider_sponsor_source_sequence"`
	SignedTransactionCellHash     string `json:"signed_transaction_cell_hash"`
	SubmittedTransactionHash      string `json:"submitted_transaction_hash"`
	AgreementBodyDigest           string `json:"agreement_body_digest"`
	AgreementObligationID         string `json:"agreement_obligation_id"`
	AgreementPaymentRequestDigest string `json:"agreement_payment_request_digest"`
	SponsorshipStableActionID     string `json:"sponsorship_stable_action_id"`
	SponsorshipExactRequestDigest string `json:"sponsorship_exact_request_digest"`
	ConsumedAtUnix                uint64 `json:"consumed_at_unix"`
}

// RelayRouteJournal is the actual mutation boundary used by decentralized
// execution. An alternative rollback-resistant implementation must implement
// the complete route CAS/state machine; a detached capability flag cannot make
// the shipped file journal autonomous-safe.
type RelayRouteJournal interface {
	Resolve(string, string) (RelayRouteRecord, error)
	Bind(PreparedRelayTransaction, []RelayProviderProvenance, RelayProviderProvenance, RelayAttempt,
		uint32, time.Time) (RelayRouteRecord, bool, error)
	MarkSubmitStarted(string, string, uint64, string, time.Time) (RelayRouteRecord, error)
	recordResolveQuery(string, string, uint64, relayRouteResolveQueryAttempt) (RelayRouteRecord, error)
	RecordTerminal(string, string, uint64, string, RelayExecutionResult, time.Time) (RelayRouteRecord, error)
	AcknowledgeTerminalHandoff(RelayTerminalHandoffAcknowledgement) error
	PrepareSwitch(string, string, uint64, string, RelayProviderProvenance, RelayAttempt,
		time.Time) (RelayRouteRecord, error)
	MarkPendingAdmissionStarted(string, string, uint64, uint64, string, time.Time) (RelayRouteRecord, error)
	RebasePendingAdmission(string, string, uint64, uint64, string, RelayAttempt,
		relayAdmissionReauthorization, time.Time) (RelayRouteRecord, error)
	Switch(string, string, uint64, string, RelayProviderProvenance, RelayAttempt,
		time.Time) (RelayRouteRecord, error)
	BindSponsorshipChainEffect(agentrelay.RelayExecutionRequest,
		agentrelay.RelaySponsorshipTransactionEvidence, time.Time) error
}

// RelayTerminalHandoffReference is the immutable bridge between terminal
// route recovery and the caller's durable accounting/portfolio ledger.  The
// protected artifact may be archived only after the ledger acknowledges this
// exact reference.  The permanent route tombstone continues to retain these
// digests as a lifetime replay/conflict fence.
type RelayTerminalHandoffReference struct {
	StableActionID           string `json:"stable_action_id"`
	ExactRequestDigest       string `json:"exact_request_digest"`
	RelayExecutionDigest     string `json:"relay_execution_digest"`
	ProviderAgentID          string `json:"provider_agent_id"`
	RouteGeneration          uint64 `json:"route_generation"`
	ProtectedArtifactDigest  string `json:"protected_artifact_digest"`
	TerminalResolutionDigest string `json:"terminal_resolution_digest"`
	TerminalEvidenceDigest   string `json:"terminal_evidence_digest"`
}

// RelayTerminalHandoffAcknowledgement is supplied only after the terminal
// result and its economic effects have been committed to a separate durable
// accounting/portfolio record.  A receipt digest plus monotonic revision make
// a conflicting or rolled-back handoff fail closed.
type RelayTerminalHandoffAcknowledgement struct {
	Reference               RelayTerminalHandoffReference
	AccountingReceiptDigest string
	AccountingRevision      uint64
	AcknowledgedAt          time.Time
}

// RelaySponsorshipEffectRegistry is the minimum owner-wide terminal replay
// boundary consumed by a RelayCoordinator. Ready clients bind this to their
// actual route journal; a detached cache or Provider-local journal is not
// sufficient.
type RelaySponsorshipEffectRegistry interface {
	BindSponsorshipChainEffect(agentrelay.RelayExecutionRequest,
		agentrelay.RelaySponsorshipTransactionEvidence, time.Time) error
}

func (record RelayRouteRecord) Current() (RelayRouteHop, bool) {
	if len(record.Hops) == 0 {
		return RelayRouteHop{}, false
	}
	return cloneRelayRouteHop(record.Hops[len(record.Hops)-1]), true
}

type relayRouteJournalDocument struct {
	Schema             string                        `json:"schema"`
	Records            []RelayRouteRecord            `json:"records"`
	SponsorshipEffects []RelaySponsorshipChainEffect `json:"sponsorship_effects,omitempty"`
}

// relayTerminalRouteTombstone is the small permanent semantic replay fence.
// Large signed BOCs, Agreements, and proof bytes live in a separate protected
// artifact until a durable accounting/portfolio handoff is acknowledged.
type relayTerminalRouteTombstone struct {
	Schema                         string                     `json:"schema"`
	StableActionID                 string                     `json:"stable_action_id"`
	ExactRequestDigest             string                     `json:"exact_request_digest"`
	RelayExecutionDigest           string                     `json:"relay_execution_digest"`
	ProviderAgentID                string                     `json:"provider_agent_id"`
	RouteGeneration                uint64                     `json:"route_generation"`
	TerminalOutcome                agentrelay.TerminalOutcome `json:"terminal_outcome"`
	TerminalResolutionDigest       string                     `json:"terminal_resolution_digest"`
	TerminalFinalityEvidenceDigest string                     `json:"terminal_finality_evidence_digest"`
	ProtectedArtifactDigest        string                     `json:"protected_artifact_digest"`
	CompletedAtUnix                uint64                     `json:"completed_at_unix"`
	HandoffAcknowledged            bool                       `json:"handoff_acknowledged"`
	HandoffReceiptDigest           string                     `json:"handoff_receipt_digest,omitempty"`
	HandoffRevision                uint64                     `json:"handoff_revision,omitempty"`
	HandoffAtUnix                  uint64                     `json:"handoff_at_unix,omitempty"`
}

type relayTerminalRouteArtifact struct {
	Schema string           `json:"schema"`
	Record RelayRouteRecord `json:"record"`
}

type relayTerminalArtifactHandoff struct {
	Schema                   string `json:"schema"`
	ProtectedArtifactDigest  string `json:"protected_artifact_digest"`
	StableActionID           string `json:"stable_action_id"`
	ExactRequestDigest       string `json:"exact_request_digest"`
	RelayExecutionDigest     string `json:"relay_execution_digest"`
	ProviderAgentID          string `json:"provider_agent_id"`
	RouteGeneration          uint64 `json:"route_generation"`
	TerminalResolutionDigest string `json:"terminal_resolution_digest"`
	TerminalEvidenceDigest   string `json:"terminal_evidence_digest"`
	HandoffReceiptDigest     string `json:"handoff_receipt_digest"`
	HandoffRevision          uint64 `json:"handoff_revision"`
	HandoffAtUnix            uint64 `json:"handoff_at_unix"`
}

const relayTerminalArtifactHandoffSchema = "tos.openfox.agent-relay-terminal-artifact-handoff.v1"

var errRelayTerminalArtifactArchived = errors.New("relay terminal proof artifact is archived")

// DurableRelayRouteJournal is the owner-wide provider selection boundary. It
// must use a dedicated owner-private directory because its process lock is
// intentionally exclusive with every other relay journal in that directory.
// Exact BOC and Agreement bytes are protected by the 0600 journal and are
// never included in status strings or errors.
type DurableRelayRouteJournal struct {
	mu                        sync.Mutex
	directory                 string
	path                      string
	effectDirectory           string
	terminalDirectory         string
	terminalArtifactDirectory string
	lock                      *os.File
	records                   map[string]RelayRouteRecord
	sponsorshipEffects        map[string]RelaySponsorshipChainEffect
}

// The local route journal is crash-durable and process-locked, but restoring a
// prior filesystem snapshot can erase route lineage or submit_started. Lower
// scoped assurance may use it; every autonomous mode needs a rollback-
// resistant route implementation and therefore remains disabled with this
// implementation.
func (*DurableRelayRouteJournal) HasRollbackResistantRelayRouteHighWater() bool { return false }

func OpenDurableRelayRouteJournal(directory string) (*DurableRelayRouteJournal, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, errors.New("relay route journal directory must be clean and absolute")
	}
	if err := validateRelayJournalDirectorySecurity(directory); err != nil {
		return nil, errors.New("relay route journal directory must be owner-private and cannot be a symlink")
	}
	if _, err := os.Lstat(filepath.Join(directory, relayJournalFile)); err == nil || !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("relay route journal requires a directory separate from provider attempt journals")
	}
	lock, err := acquireRelayJournalLock(directory)
	if err != nil {
		return nil, err
	}
	effectDirectory := filepath.Join(directory, relaySponsorshipEffectDirectory)
	if err := os.Mkdir(effectDirectory, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		_ = releaseRelayJournalLock(lock)
		return nil, errors.New("create relay sponsorship effect registry")
	}
	if err := validateRelayJournalDirectorySecurity(effectDirectory); err != nil {
		_ = releaseRelayJournalLock(lock)
		return nil, errors.New("relay sponsorship effect registry must be owner-private")
	}
	terminalDirectory := filepath.Join(directory, relayTerminalRouteDirectory)
	if err := os.Mkdir(terminalDirectory, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		_ = releaseRelayJournalLock(lock)
		return nil, errors.New("create relay terminal route registry")
	}
	if err := validateRelayJournalDirectorySecurity(terminalDirectory); err != nil {
		_ = releaseRelayJournalLock(lock)
		return nil, errors.New("relay terminal route registry must be owner-private")
	}
	terminalArtifactDirectory := filepath.Join(directory, relayTerminalArtifactDirectory)
	if err := os.Mkdir(terminalArtifactDirectory, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		_ = releaseRelayJournalLock(lock)
		return nil, errors.New("create relay terminal artifact registry")
	}
	if err := validateRelayJournalDirectorySecurity(terminalArtifactDirectory); err != nil {
		_ = releaseRelayJournalLock(lock)
		return nil, errors.New("relay terminal artifact registry must be owner-private")
	}
	journal := &DurableRelayRouteJournal{directory: directory, path: filepath.Join(directory, relayRouteJournalFile),
		effectDirectory: effectDirectory, terminalDirectory: terminalDirectory,
		terminalArtifactDirectory: terminalArtifactDirectory,
		lock:                      lock, records: map[string]RelayRouteRecord{},
		sponsorshipEffects: map[string]RelaySponsorshipChainEffect{}}
	if err := journal.load(); err != nil {
		_ = releaseRelayJournalLock(lock)
		return nil, err
	}
	return journal, nil
}

func (journal *DurableRelayRouteJournal) Close() error {
	if journal == nil {
		return nil
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.lock == nil {
		return nil
	}
	lock := journal.lock
	journal.lock = nil
	return releaseRelayJournalLock(lock)
}

type relaySponsorshipEffectIdentityV1 struct {
	NetworkDigest                 string `json:"network_digest"`
	ProviderSponsorSourceAccount  string `json:"provider_sponsor_source_account"`
	ProviderSponsorSourceSequence uint64 `json:"provider_sponsor_source_sequence"`
	SignedTransactionCellHash     string `json:"signed_transaction_cell_hash"`
	SubmittedTransactionHash      string `json:"submitted_transaction_hash"`
}

type relaySponsorshipEffectBindingV1 struct {
	AgreementBodyDigest           string `json:"agreement_body_digest"`
	AgreementObligationID         string `json:"agreement_obligation_id"`
	AgreementPaymentRequestDigest string `json:"agreement_payment_request_digest"`
	SponsorshipStableActionID     string `json:"sponsorship_stable_action_id"`
	SponsorshipExactRequestDigest string `json:"sponsorship_exact_request_digest"`
}

func (journal *DurableRelayRouteJournal) BindSponsorshipChainEffect(execution agentrelay.RelayExecutionRequest,
	evidence agentrelay.RelaySponsorshipTransactionEvidence, at time.Time) error {
	if journal == nil || at.IsZero() || execution.QuoteRequest.Body.Mode == agentrelay.ModeRelayExact {
		return agentrelay.ErrRelayInvalidState
	}
	expected, err := relaySponsorshipEvidenceContext(execution, evidence)
	if err != nil || agentrelay.VerifySponsorshipPaymentRequestForEvidence(
		evidence.AgreementPaymentRequest, evidence, expected) != nil {
		return errors.New("sponsorship chain effect does not bind the exact execution")
	}
	identity := relaySponsorshipEffectIdentityV1{NetworkDigest: evidence.NetworkDigest,
		ProviderSponsorSourceAccount:  evidence.ProviderSponsorSourceAccount,
		ProviderSponsorSourceSequence: evidence.ProviderSponsorSourceSequence,
		SignedTransactionCellHash:     evidence.SignedTopUpTransactionCellHash,
		SubmittedTransactionHash:      evidence.SubmittedTransactionHash}
	binding := relaySponsorshipEffectBindingV1{AgreementBodyDigest: execution.AgreementBodyDigest,
		AgreementObligationID:         execution.SponsorshipObligationID,
		AgreementPaymentRequestDigest: evidence.AgreementPaymentRequestDigest,
		SponsorshipStableActionID:     evidence.SponsorshipStableActionID,
		SponsorshipExactRequestDigest: evidence.SponsorshipExactRequestDigest}
	effectDigest, err := codec.Digest("tos.openfox.agent-relay-sponsorship-chain-effect.v1", identity)
	if err != nil {
		return err
	}
	bindingDigest, err := codec.Digest("tos.openfox.agent-relay-sponsorship-chain-effect-binding.v1", binding)
	if err != nil {
		return err
	}
	nowUnix := at.UTC().Unix()
	if nowUnix <= 0 {
		return agentrelay.ErrRelayInvalidState
	}
	record := RelaySponsorshipChainEffect{EffectIdentityDigest: effectDigest, BindingDigest: bindingDigest,
		NetworkDigest: evidence.NetworkDigest, ProviderSponsorSourceAccount: evidence.ProviderSponsorSourceAccount,
		ProviderSponsorSourceSequence: evidence.ProviderSponsorSourceSequence,
		SignedTransactionCellHash:     evidence.SignedTopUpTransactionCellHash,
		SubmittedTransactionHash:      evidence.SubmittedTransactionHash,
		AgreementBodyDigest:           execution.AgreementBodyDigest,
		AgreementObligationID:         execution.SponsorshipObligationID,
		AgreementPaymentRequestDigest: evidence.AgreementPaymentRequestDigest,
		SponsorshipStableActionID:     evidence.SponsorshipStableActionID,
		SponsorshipExactRequestDigest: evidence.SponsorshipExactRequestDigest,
		ConsumedAtUnix:                uint64(nowUnix)}
	if !validRelaySponsorshipChainEffect(record) {
		return agentrelay.ErrRelayInvalidState
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.lock == nil {
		return errors.New("relay route journal is closed")
	}
	if prior, found := journal.sponsorshipEffects[effectDigest]; found {
		if prior.BindingDigest != bindingDigest || prior.AgreementBodyDigest != record.AgreementBodyDigest ||
			prior.AgreementObligationID != record.AgreementObligationID ||
			prior.AgreementPaymentRequestDigest != record.AgreementPaymentRequestDigest ||
			prior.SponsorshipStableActionID != record.SponsorshipStableActionID ||
			prior.SponsorshipExactRequestDigest != record.SponsorshipExactRequestDigest {
			return agentrelay.ErrRelayConflict
		}
		return nil
	}
	prior, found, err := journal.readSponsorshipChainEffect(effectDigest)
	if err != nil {
		return err
	}
	if found {
		if prior.BindingDigest != bindingDigest || prior.AgreementBodyDigest != record.AgreementBodyDigest ||
			prior.AgreementObligationID != record.AgreementObligationID ||
			prior.AgreementPaymentRequestDigest != record.AgreementPaymentRequestDigest ||
			prior.SponsorshipStableActionID != record.SponsorshipStableActionID ||
			prior.SponsorshipExactRequestDigest != record.SponsorshipExactRequestDigest {
			return agentrelay.ErrRelayConflict
		}
		journal.cacheSponsorshipChainEffect(prior)
		return nil
	}
	if err := journal.writeSponsorshipChainEffect(record); err != nil {
		return err
	}
	journal.cacheSponsorshipChainEffect(record)
	return nil
}

func (journal *DurableRelayRouteJournal) Resolve(stableActionID,
	exactRequestDigest string) (RelayRouteRecord, error) {
	if journal == nil || !canonicalSHA256(stableActionID) || !canonicalSHA256(exactRequestDigest) {
		return RelayRouteRecord{}, agentrelay.ErrRelayUnknown
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.lock == nil {
		return RelayRouteRecord{}, errors.New("relay route journal is closed")
	}
	record, found := journal.records[stableActionID]
	if !found {
		terminal, terminalFound, err := journal.readTerminalRoute(stableActionID)
		if err != nil {
			return RelayRouteRecord{}, err
		}
		if !terminalFound {
			return RelayRouteRecord{}, agentrelay.ErrRelayUnknown
		}
		record = terminal
	}
	record = cloneRelayRouteRecord(record)
	if record.ExactRequestDigest != exactRequestDigest {
		return cloneRelayRouteRecord(record), agentrelay.ErrRelayConflict
	}
	return cloneRelayRouteRecord(record), nil
}

func (journal *DurableRelayRouteJournal) Bind(prepared PreparedRelayTransaction,
	candidates []RelayProviderProvenance, selected RelayProviderProvenance, attempt RelayAttempt,
	ownerMaximumRouteAttempts uint32, at time.Time) (RelayRouteRecord, bool, error) {
	return journal.bind(prepared, candidates, selected, attempt, ownerMaximumRouteAttempts, false, at)
}

// BindSingle durably freezes the sole owner-pinned Provider before a lower-
// assurance sponsorship may cross the socket boundary. It is not a degraded
// decentralized route: maximum attempts is exactly one and no successor can
// ever be allocated. The journal is used only as the crash-safe first-dispatch
// fence that prevents a second top-up after an ambiguous send.
func (journal *DurableRelayRouteJournal) BindSingle(prepared PreparedRelayTransaction,
	selected RelayProviderProvenance, attempt RelayAttempt, at time.Time) (RelayRouteRecord, bool, error) {
	return journal.bind(prepared, []RelayProviderProvenance{selected}, selected, attempt, 1, true, at)
}

func (journal *DurableRelayRouteJournal) bind(prepared PreparedRelayTransaction,
	candidates []RelayProviderProvenance, selected RelayProviderProvenance, attempt RelayAttempt,
	ownerMaximumRouteAttempts uint32, allowSingle bool, at time.Time) (RelayRouteRecord, bool, error) {
	if journal == nil || at.IsZero() || !attemptMatchesPrepared(attempt, prepared) ||
		ownerMaximumRouteAttempts == 0 || ownerMaximumRouteAttempts > agentrelay.MaxRelayRouteAttempts ||
		attempt.Execution.AdmissionReceipt.Body.RouteAttempt != 1 ||
		agentrelay.VerifyRelaySideEffectAdmissionReceiptIntegrity(
			attempt.Execution.AdmissionReceipt, attempt.Execution) != nil {
		return RelayRouteRecord{}, false, agentrelay.ErrRelayConflict
	}
	candidates = append([]RelayProviderProvenance(nil), candidates...)
	sort.Slice(candidates, func(left, right int) bool {
		return relayProvenanceKey(candidates[left]) < relayProvenanceKey(candidates[right])
	})
	validCandidates := validIndependentRelayProvenance(candidates)
	if allowSingle {
		validCandidates = len(candidates) == 1 && ownerMaximumRouteAttempts == 1 &&
			validRelayProvenance(selected) && sameRelayProvenance(candidates[0], selected) &&
			attempt.Execution.QuoteRequest.Body.AssuranceLevel != agentrelay.AssuranceAutonomousDecentralized
	}
	if !validCandidates || !containsRelayProvenance(candidates, selected) ||
		attempt.Execution.ProviderQuote.Body.ProviderAgentID != selected.ProviderAgentID {
		return RelayRouteRecord{}, false, errors.New("relay route candidates lack independent owner provenance")
	}
	executionDigest, err := agentrelay.RelayExecutionRequestDigest(attempt.Execution)
	if err != nil {
		return RelayRouteRecord{}, false, err
	}
	serviceFee, feeAsset, err := relayAttemptServiceFee(attempt)
	if err != nil || feeAsset != prepared.QuoteBody.MaximumServiceFee.Asset ||
		compareRelayAtomic(serviceFee, prepared.QuoteBody.MaximumServiceFee.AmountAtomic) > 0 {
		return RelayRouteRecord{}, false, errors.New("initial relay route exceeds its cumulative service-fee budget")
	}
	nowUnix := at.UTC().Unix()
	if nowUnix <= 0 {
		return RelayRouteRecord{}, false, errors.New("relay route time is invalid")
	}
	stableActionID, exactRequestDigest := prepared.UnderlyingAction.StableActionID,
		prepared.UnderlyingAction.ExactRequestDigest
	maximumRouteAttempts := ownerMaximumRouteAttempts
	if candidateCount := uint32(len(candidates)); candidateCount < maximumRouteAttempts {
		maximumRouteAttempts = candidateCount
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.lock == nil {
		return RelayRouteRecord{}, false, errors.New("relay route journal is closed")
	}
	if existing, found := journal.records[stableActionID]; found {
		if existing.ExactRequestDigest != exactRequestDigest || !attemptMatchesPrepared(existing.Hops[len(existing.Hops)-1].Attempt, prepared) {
			return cloneRelayRouteRecord(existing), false, agentrelay.ErrRelayConflict
		}
		return cloneRelayRouteRecord(existing), false, nil
	}
	if existing, found, err := journal.readTerminalRoute(stableActionID); err != nil {
		return RelayRouteRecord{}, false, err
	} else if found {
		if existing.ExactRequestDigest != exactRequestDigest ||
			!attemptMatchesPrepared(existing.Hops[len(existing.Hops)-1].Attempt, prepared) {
			return cloneRelayRouteRecord(existing), false, agentrelay.ErrRelayConflict
		}
		return cloneRelayRouteRecord(existing), false, nil
	}
	if len(journal.records) >= maximumRelayRoutes {
		return RelayRouteRecord{}, false, errors.New("relay route journal capacity is exhausted")
	}
	if err := journal.reserveTerminalArtifactCapacity(); err != nil {
		return RelayRouteRecord{}, false, err
	}
	record := RelayRouteRecord{StableActionID: stableActionID, ExactRequestDigest: exactRequestDigest,
		Candidates: candidates, Hops: []RelayRouteHop{{Generation: 1, Provider: selected,
			RelayExecutionDigest: executionDigest, Attempt: cloneRelayAttempt(attempt)}},
		MaximumRouteAttempts: maximumRouteAttempts, ServiceFeeAsset: feeAsset,
		MaximumCumulativeServiceFeeAtomic: prepared.QuoteBody.MaximumServiceFee.AmountAtomic,
		CumulativeServiceFeeAtomic:        serviceFee,
		CreatedAtUnix:                     uint64(nowUnix), UpdatedAtUnix: uint64(nowUnix)}
	next := cloneRelayRouteRecords(journal.records)
	next[stableActionID] = record
	if err := journal.persist(next); err != nil {
		return RelayRouteRecord{}, false, err
	}
	journal.records = next
	return cloneRelayRouteRecord(record), true, nil
}

func (journal *DurableRelayRouteJournal) MarkSubmitStarted(stableActionID, exactRequestDigest string,
	expectedGeneration uint64, executionDigest string, at time.Time) (RelayRouteRecord, error) {
	if journal == nil || expectedGeneration == 0 || !canonicalSHA256(executionDigest) || at.IsZero() {
		return RelayRouteRecord{}, agentrelay.ErrRelayInvalidState
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.lock == nil {
		return RelayRouteRecord{}, errors.New("relay route journal is closed")
	}
	record, found := journal.records[stableActionID]
	if !found {
		if terminal, terminalFound, err := journal.readTerminalRoute(stableActionID); err != nil {
			return RelayRouteRecord{}, err
		} else if terminalFound {
			return terminal, agentrelay.ErrRelayConflict
		}
		return RelayRouteRecord{}, agentrelay.ErrRelayUnknown
	}
	record = cloneRelayRouteRecord(record)
	if record.ExactRequestDigest != exactRequestDigest {
		return cloneRelayRouteRecord(record), agentrelay.ErrRelayConflict
	}
	current := &record.Hops[len(record.Hops)-1]
	if current.Generation != expectedGeneration || current.RelayExecutionDigest != executionDigest {
		return cloneRelayRouteRecord(record), agentrelay.ErrRelayConflict
	}
	if current.SubmitStarted {
		return cloneRelayRouteRecord(record), nil
	}
	nowUnix := at.UTC().Unix()
	if nowUnix <= 0 || uint64(nowUnix) < record.UpdatedAtUnix {
		return cloneRelayRouteRecord(record), agentrelay.ErrRelayInvalidState
	}
	current.SubmitStarted = true
	record.UpdatedAtUnix = uint64(nowUnix)
	next := cloneRelayRouteRecords(journal.records)
	next[stableActionID] = record
	if err := journal.persist(next); err != nil {
		return RelayRouteRecord{}, err
	}
	journal.records = next
	return cloneRelayRouteRecord(record), nil
}

func relayRouteResolveQueryAttemptDigest(attempt relayRouteResolveQueryAttempt) (string, error) {
	if attempt.SchemaVersion != 1 {
		return "", errors.New("relay resolve query attempt is invalid")
	}
	return codec.Digest("tos.openfox.agent-relay-resolve-query-attempt.v1", attempt)
}

func relayTransportAuthenticationDigest(provider RelayProviderProvenance,
	authenticatedPrincipal string) (string, error) {
	if !validRelayProvenance(provider) || !boundedRelayTrustDomain(authenticatedPrincipal) {
		return "", errors.New("relay transport provenance is invalid")
	}
	return codec.Digest("tos.openfox.agent-relay-authenticated-provider-route.v1", struct {
		Provider               RelayProviderProvenance `json:"provider"`
		AuthenticatedPrincipal string                  `json:"authenticated_principal_id"`
	}{Provider: provider, AuthenticatedPrincipal: authenticatedPrincipal})
}

// recordResolveQuery persists the completed authenticated query before any
// relay_exact successor is selected. A timeout, unavailable database, or
// signed non-terminal status is ambiguity—not proof of absence—but exact BOC
// identity makes retrying through another Provider economically idempotent.
func (journal *DurableRelayRouteJournal) recordResolveQuery(stableActionID, exactRequestDigest string,
	expectedGeneration uint64, attempt relayRouteResolveQueryAttempt) (RelayRouteRecord, error) {
	if journal == nil || expectedGeneration == 0 {
		return RelayRouteRecord{}, agentrelay.ErrRelayInvalidState
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.lock == nil {
		return RelayRouteRecord{}, errors.New("relay route journal is closed")
	}
	record, found := journal.records[stableActionID]
	if !found {
		if terminal, terminalFound, err := journal.readTerminalRoute(stableActionID); err != nil {
			return RelayRouteRecord{}, err
		} else if terminalFound {
			return terminal, agentrelay.ErrRelayConflict
		}
		return RelayRouteRecord{}, agentrelay.ErrRelayUnknown
	}
	record = cloneRelayRouteRecord(record)
	if record.ExactRequestDigest != exactRequestDigest {
		return cloneRelayRouteRecord(record), agentrelay.ErrRelayConflict
	}
	current := &record.Hops[len(record.Hops)-1]
	digest, err := relayRouteResolveQueryAttemptDigest(attempt)
	if err != nil {
		return cloneRelayRouteRecord(record), err
	}
	if current.FailoverQueryAttempt != nil || current.FailoverQueryAttemptDigest != "" {
		if current.Generation == expectedGeneration && current.FailoverQueryAttempt != nil &&
			current.FailoverQueryAttemptDigest == digest && reflect.DeepEqual(*current.FailoverQueryAttempt, attempt) {
			return cloneRelayRouteRecord(record), nil
		}
		return cloneRelayRouteRecord(record), agentrelay.ErrRelayConflict
	}
	if current.Generation != expectedGeneration || record.PendingSwitch != nil ||
		current.TerminalResolution != nil || current.TerminalFinalityEvidence != nil ||
		current.FailoverFinalityEvidence != nil || current.FailoverFinalityEvidenceDigest != "" ||
		!validRelayResolveQueryAttempt(record, *current, attempt) || attempt.StartedAtUnix < record.UpdatedAtUnix {
		return cloneRelayRouteRecord(record), agentrelay.ErrRelayConflict
	}
	queryCopy := cloneRelayResolveQueryAttempt(attempt)
	current.FailoverQueryAttemptDigest, current.FailoverQueryAttempt = digest, &queryCopy
	record.UpdatedAtUnix = attempt.CompletedAtUnix
	next := cloneRelayRouteRecords(journal.records)
	next[stableActionID] = record
	if err := journal.persist(next); err != nil {
		return RelayRouteRecord{}, err
	}
	journal.records = next
	return cloneRelayRouteRecord(record), nil
}

// RecordTerminal persists the complete, independently verified terminal result
// before it is returned to accounting. Provider status databases are caches;
// restart and source-loss recovery use this owner-private evidence copy.
func (journal *DurableRelayRouteJournal) RecordTerminal(stableActionID, exactRequestDigest string,
	expectedGeneration uint64, executionDigest string, result RelayExecutionResult,
	at time.Time) (RelayRouteRecord, error) {
	if journal == nil || expectedGeneration == 0 || !canonicalSHA256(executionDigest) ||
		result.Evidence == nil || at.IsZero() {
		return RelayRouteRecord{}, agentrelay.ErrRelayInvalidState
	}
	resolutionDigest, resolutionErr := agentrelay.RelayResolutionDigest(result.Resolution.Body)
	evidenceDigest, evidenceErr := agentrelay.RelayFinalityEvidenceDigest(result.Evidence.Body)
	if resolutionErr != nil || evidenceErr != nil || result.Resolution.Body.State != commerce.ActionTerminal ||
		result.Resolution.Body.TerminalOutcome != result.Evidence.Body.Outcome ||
		!relayResolutionReferenceMatchesEvidence(result.Resolution.Body, result.Evidence.Body) {
		return RelayRouteRecord{}, agentrelay.ErrRelayInvalidState
	}

	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.lock == nil {
		return RelayRouteRecord{}, errors.New("relay route journal is closed")
	}
	record, found := journal.records[stableActionID]
	if !found {
		terminal, terminalFound, err := journal.readTerminalRoute(stableActionID)
		if err != nil {
			return RelayRouteRecord{}, err
		}
		if !terminalFound {
			return RelayRouteRecord{}, agentrelay.ErrRelayUnknown
		}
		if terminal.ExactRequestDigest != exactRequestDigest {
			return terminal, agentrelay.ErrRelayConflict
		}
		current := terminal.Hops[len(terminal.Hops)-1]
		if current.Generation == expectedGeneration && current.RelayExecutionDigest == executionDigest &&
			current.TerminalResolutionDigest == resolutionDigest &&
			current.TerminalFinalityEvidenceDigest == evidenceDigest &&
			reflect.DeepEqual(*current.TerminalResolution, result.Resolution) &&
			reflect.DeepEqual(*current.TerminalFinalityEvidence, *result.Evidence) {
			return cloneRelayRouteRecord(terminal), nil
		}
		return terminal, agentrelay.ErrRelayConflict
	}
	record = cloneRelayRouteRecord(record)
	if record.ExactRequestDigest != exactRequestDigest {
		return cloneRelayRouteRecord(record), agentrelay.ErrRelayConflict
	}
	current := &record.Hops[len(record.Hops)-1]
	if current.Generation != expectedGeneration || current.RelayExecutionDigest != executionDigest ||
		!current.SubmitStarted || result.Resolution.Body.ProviderAgentID != current.Provider.ProviderAgentID ||
		result.Resolution.Body.StableActionID != stableActionID ||
		result.Resolution.Body.ExactRequestDigest != exactRequestDigest ||
		result.Resolution.Body.RelayExecutionDigest != executionDigest ||
		result.Resolution.Body.Network != current.Attempt.Execution.QuoteRequest.Body.Network ||
		result.Evidence.Body.ProviderAgentID != current.Provider.ProviderAgentID ||
		result.Evidence.Body.StableActionID != stableActionID ||
		result.Evidence.Body.ExactRequestDigest != exactRequestDigest ||
		result.Evidence.Body.RelayExecutionDigest != executionDigest ||
		result.Evidence.Body.Network != current.Attempt.Execution.QuoteRequest.Body.Network {
		return cloneRelayRouteRecord(record), agentrelay.ErrRelayConflict
	}
	if record.PendingSwitch != nil && record.PendingSwitch.AdmissionStarted {
		return cloneRelayRouteRecord(record), errors.New("relay successor admission has started; prior terminal reconciliation is ambiguous")
	}
	if current.TerminalResolution != nil || current.TerminalFinalityEvidence != nil ||
		current.TerminalResolutionDigest != "" || current.TerminalFinalityEvidenceDigest != "" {
		if current.TerminalResolution != nil && current.TerminalFinalityEvidence != nil &&
			current.TerminalResolutionDigest == resolutionDigest &&
			current.TerminalFinalityEvidenceDigest == evidenceDigest &&
			reflect.DeepEqual(*current.TerminalResolution, result.Resolution) &&
			reflect.DeepEqual(*current.TerminalFinalityEvidence, *result.Evidence) {
			return cloneRelayRouteRecord(record), nil
		}
		return cloneRelayRouteRecord(record), agentrelay.ErrRelayConflict
	}
	nowUnix := at.UTC().Unix()
	if nowUnix <= 0 || uint64(nowUnix) < record.UpdatedAtUnix {
		return cloneRelayRouteRecord(record), agentrelay.ErrRelayInvalidState
	}
	resolutionCopy, evidenceCopy := result.Resolution, *result.Evidence
	// A completed query is a liveness observation, not stronger evidence than a
	// later independently verified terminal result. Until successor admission
	// starts, terminal reconciliation atomically replaces the query gate and
	// cancels the side-effect-free pending draft.
	current.FailoverQueryAttemptDigest, current.FailoverQueryAttempt = "", nil
	record.PendingSwitch = nil
	current.TerminalResolutionDigest, current.TerminalResolution = resolutionDigest, &resolutionCopy
	current.TerminalFinalityEvidenceDigest, current.TerminalFinalityEvidence = evidenceDigest, &evidenceCopy
	record.UpdatedAtUnix = uint64(nowUnix)
	next := cloneRelayRouteRecords(journal.records)
	if relayRouteRecordIsTerminal(record) {
		// Write the immutable tombstone before removing this completed owner
		// route from the bounded hot journal. A crash between the two writes
		// leaves a safely duplicated record that load() verifies and compacts.
		if err := journal.writeTerminalRoute(record); err != nil {
			return RelayRouteRecord{}, err
		}
		delete(next, stableActionID)
	} else {
		// A finality-proven relay_exact absence remains an active route while a
		// bounded unused successor can still submit the immutable BOC.
		next[stableActionID] = record
	}
	if err := journal.persist(next); err != nil {
		return RelayRouteRecord{}, err
	}
	journal.records = next
	return cloneRelayRouteRecord(record), nil
}

// PrepareSwitch durably freezes the exact relay-only successor before receipt
// issuance. A crash can therefore retry Admit/Resolve for precisely this
// lookup; it can never choose a different Provider route after an ambiguous
// authority response.
func (journal *DurableRelayRouteJournal) PrepareSwitch(stableActionID, exactRequestDigest string,
	expectedGeneration uint64, currentExecutionDigest string, successor RelayProviderProvenance,
	draft RelayAttempt, at time.Time) (RelayRouteRecord, error) {
	if journal == nil || expectedGeneration == 0 || !canonicalSHA256(currentExecutionDigest) ||
		at.IsZero() || !relayAttemptHasNoAdmissionReceipt(draft) {
		return RelayRouteRecord{}, agentrelay.ErrRelayInvalidState
	}
	executionDigest, err := agentrelay.RelayExecutionRequestDigest(draft.Execution)
	if err != nil {
		return RelayRouteRecord{}, err
	}
	serviceFee, feeAsset, feeErr := relayAttemptServiceFee(draft)
	if feeErr != nil {
		return RelayRouteRecord{}, feeErr
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.lock == nil {
		return RelayRouteRecord{}, errors.New("relay route journal is closed")
	}
	record, found := journal.records[stableActionID]
	if !found {
		return RelayRouteRecord{}, agentrelay.ErrRelayUnknown
	}
	record = cloneRelayRouteRecord(record)
	if record.ExactRequestDigest != exactRequestDigest {
		return cloneRelayRouteRecord(record), agentrelay.ErrRelayConflict
	}
	current := &record.Hops[len(record.Hops)-1]
	gateKind, gateDigest, gateOK := relayHopFailoverGate(record, *current)
	cumulativeAfter, cumulativeErr := addRelayAtomic(record.CumulativeServiceFeeAtomic, serviceFee)
	if !gateOK || feeAsset != record.ServiceFeeAsset || cumulativeErr != nil ||
		compareRelayAtomic(cumulativeAfter, record.MaximumCumulativeServiceFeeAtomic) > 0 {
		return cloneRelayRouteRecord(record), errors.New("relay successor exceeds its failover gate or cumulative service-fee budget")
	}
	if record.PendingSwitch != nil {
		pending := record.PendingSwitch
		if pending.Generation == expectedGeneration+1 && pending.RelayExecutionDigest == executionDigest &&
			sameRelayProvenance(pending.Provider, successor) && reflect.DeepEqual(pending.Attempt, draft) &&
			pending.FailoverGateKind == gateKind && pending.FailoverGateDigest == gateDigest &&
			pending.CumulativeServiceFeeAtomicAfter == cumulativeAfter {
			return cloneRelayRouteRecord(record), nil
		}
		return cloneRelayRouteRecord(record), agentrelay.ErrRelayConflict
	}
	if current.Generation != expectedGeneration || current.RelayExecutionDigest != currentExecutionDigest ||
		current.Attempt.Execution.QuoteRequest.Body.Mode != agentrelay.ModeRelayExact || !current.SubmitStarted ||
		current.FailoverFinalityEvidenceDigest != "" || current.FailoverFinalityEvidence != nil ||
		!containsRelayProvenance(record.Candidates, successor) ||
		draft.Execution.ProviderQuote.Body.ProviderAgentID != successor.ProviderAgentID ||
		!sameRelayExecutionBaseIdentityWithCredentials(current.Attempt.Execution, draft.Execution) {
		return cloneRelayRouteRecord(record), agentrelay.ErrRelayConflict
	}
	for _, hop := range record.Hops {
		if sameRelayProvenance(hop.Provider, successor) {
			return cloneRelayRouteRecord(record), agentrelay.ErrRelayConflict
		}
	}
	if len(record.Hops) >= maximumRelayRouteHops || uint32(len(record.Hops)) >= record.MaximumRouteAttempts {
		return cloneRelayRouteRecord(record), errors.New("relay route failover capacity is exhausted")
	}
	nowUnix := at.UTC().Unix()
	if nowUnix <= 0 || uint64(nowUnix) < record.UpdatedAtUnix {
		return cloneRelayRouteRecord(record), agentrelay.ErrRelayInvalidState
	}
	envelopeDigest, envelopeErr := relayPendingAdmissionEnvelopeDigest(draft, current.Attempt.Execution.AdmissionReceipt)
	if envelopeErr != nil {
		return cloneRelayRouteRecord(record), envelopeErr
	}
	record.PendingSwitch = &RelayRoutePendingSwitch{Generation: expectedGeneration + 1, Provider: successor,
		RelayExecutionDigest: executionDigest, Attempt: cloneRelayAttempt(draft),
		FailoverGateKind: gateKind, FailoverGateDigest: gateDigest,
		CumulativeServiceFeeAtomicAfter: cumulativeAfter, AdmissionEnvelopeDigest: envelopeDigest,
		AdmissionRevision: 1, PreparedAtUnix: uint64(nowUnix)}
	record.UpdatedAtUnix = uint64(nowUnix)
	next := cloneRelayRouteRecords(journal.records)
	next[stableActionID] = record
	if err := journal.persist(next); err != nil {
		return RelayRouteRecord{}, err
	}
	journal.records = next
	return cloneRelayRouteRecord(record), nil
}

// MarkPendingAdmissionStarted is persisted immediately before the Action
// Authority call. Before this transition the draft has no side-effect
// authority and may be cancelled by a newly verified terminal result from the
// prior Provider. Afterwards receipt issuance is ambiguous until Resolve and
// the prior result cannot silently discard the possibly linearized successor.
func (journal *DurableRelayRouteJournal) MarkPendingAdmissionStarted(stableActionID, exactRequestDigest string,
	expectedGeneration uint64, admissionRevision uint64, admissionEnvelopeDigest string,
	at time.Time) (RelayRouteRecord, error) {
	if journal == nil || expectedGeneration == 0 || admissionRevision == 0 ||
		!canonicalSHA256(admissionEnvelopeDigest) || at.IsZero() {
		return RelayRouteRecord{}, agentrelay.ErrRelayInvalidState
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.lock == nil {
		return RelayRouteRecord{}, errors.New("relay route journal is closed")
	}
	record, found := journal.records[stableActionID]
	if !found {
		return RelayRouteRecord{}, agentrelay.ErrRelayUnknown
	}
	record = cloneRelayRouteRecord(record)
	if record.ExactRequestDigest != exactRequestDigest || record.PendingSwitch == nil {
		return cloneRelayRouteRecord(record), agentrelay.ErrRelayConflict
	}
	current, pending := record.Hops[len(record.Hops)-1], record.PendingSwitch
	if current.Generation != expectedGeneration || pending.Generation != expectedGeneration+1 ||
		pending.AdmissionRevision != admissionRevision || pending.AdmissionEnvelopeDigest != admissionEnvelopeDigest ||
		!validRelayPendingSwitch(record,
			relayUsedProviderSet(record.Hops)) {
		return cloneRelayRouteRecord(record), agentrelay.ErrRelayConflict
	}
	if pending.AdmissionStarted {
		return cloneRelayRouteRecord(record), nil
	}
	nowUnix := at.UTC().Unix()
	if nowUnix <= 0 || uint64(nowUnix) < record.UpdatedAtUnix {
		return cloneRelayRouteRecord(record), agentrelay.ErrRelayInvalidState
	}
	pending.AdmissionStarted = true
	pending.AdmissionStartedAtUnix = uint64(nowUnix)
	record.UpdatedAtUnix = uint64(nowUnix)
	next := cloneRelayRouteRecords(journal.records)
	next[stableActionID] = record
	if err := journal.persist(next); err != nil {
		return RelayRouteRecord{}, err
	}
	journal.records = next
	return cloneRelayRouteRecord(record), nil
}

// RebasePendingAdmission atomically persists PersonalAuthority's signed
// not-found confirmation and replaces only the pending writer/action envelope.
// The rebased admission is durably marked started in the same write. The old
// lookup may be replaced only after the same Authority proves that it did not
// linearize a receipt for it; a crash then recovers through the exact new
// lookup rather than permitting another unaudited rebase.
func (journal *DurableRelayRouteJournal) RebasePendingAdmission(stableActionID, exactRequestDigest string,
	expectedGeneration uint64, expectedAdmissionRevision uint64, expectedAdmissionEnvelopeDigest string,
	rebased RelayAttempt,
	authorization relayAdmissionReauthorization, at time.Time) (RelayRouteRecord, error) {
	if journal == nil || expectedGeneration == 0 || expectedAdmissionRevision == 0 ||
		!canonicalSHA256(expectedAdmissionEnvelopeDigest) ||
		at.IsZero() || !relayAttemptHasNoAdmissionReceipt(rebased) {
		return RelayRouteRecord{}, agentrelay.ErrRelayInvalidState
	}
	newExecutionDigest, err := agentrelay.RelayExecutionRequestDigest(rebased.Execution)
	if err != nil {
		return RelayRouteRecord{}, err
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.lock == nil {
		return RelayRouteRecord{}, errors.New("relay route journal is closed")
	}
	record, found := journal.records[stableActionID]
	if !found {
		return RelayRouteRecord{}, agentrelay.ErrRelayUnknown
	}
	record = cloneRelayRouteRecord(record)
	if record.ExactRequestDigest != exactRequestDigest || record.PendingSwitch == nil {
		return cloneRelayRouteRecord(record), agentrelay.ErrRelayConflict
	}
	current, pending := record.Hops[len(record.Hops)-1], record.PendingSwitch
	if current.Generation != expectedGeneration || pending.Generation != expectedGeneration+1 ||
		pending.AdmissionRevision != expectedAdmissionRevision ||
		pending.AdmissionEnvelopeDigest != expectedAdmissionEnvelopeDigest ||
		!validRelayPendingSwitch(record, relayUsedProviderSet(record.Hops)) ||
		pending.Provider.ProviderAgentID != rebased.Execution.ProviderQuote.Body.ProviderAgentID {
		return cloneRelayRouteRecord(record), agentrelay.ErrRelayConflict
	}
	predecessor := current.Attempt.Execution.AdmissionReceipt
	if err := verifyRelayAdmissionReauthorization(authorization, pending.Attempt, rebased, predecessor); err != nil {
		return cloneRelayRouteRecord(record), errors.New("relay admission reauthorization does not match pending route: " + err.Error())
	}
	serviceFee, feeAsset, feeErr := relayAttemptServiceFee(rebased)
	cumulativeAfter, cumulativeErr := addRelayAtomic(record.CumulativeServiceFeeAtomic, serviceFee)
	if feeErr != nil || cumulativeErr != nil || feeAsset != record.ServiceFeeAsset ||
		cumulativeAfter != pending.CumulativeServiceFeeAtomicAfter ||
		compareRelayAtomic(cumulativeAfter, record.MaximumCumulativeServiceFeeAtomic) > 0 {
		return cloneRelayRouteRecord(record), agentrelay.ErrRelayConflict
	}
	nowUnix := at.UTC().Unix()
	if nowUnix <= 0 || uint64(nowUnix) < record.UpdatedAtUnix ||
		authorization.Body.ResolvedNotFoundAtUnix < pending.PreparedAtUnix ||
		authorization.Body.ResolvedNotFoundAtUnix > uint64(nowUnix) {
		return cloneRelayRouteRecord(record), agentrelay.ErrRelayInvalidState
	}
	newEnvelopeDigest, envelopeErr := relayPendingAdmissionEnvelopeDigest(rebased, predecessor)
	if envelopeErr != nil || pending.AdmissionRevision == ^uint64(0) {
		return cloneRelayRouteRecord(record), agentrelay.ErrRelayInvalidState
	}
	pending.Rebase = &relayAdmissionRebaseRecord{PriorAttempt: cloneRelayAttempt(pending.Attempt),
		Authorization: authorization}
	pending.Attempt = cloneRelayAttempt(rebased)
	pending.RelayExecutionDigest = newExecutionDigest
	pending.AdmissionEnvelopeDigest = newEnvelopeDigest
	pending.AdmissionRevision++
	// Rebase and Begin are one CAS-protected journal mutation. A crash after
	// this write must Resolve the new envelope before any further rebase.
	pending.AdmissionStarted = true
	pending.AdmissionStartedAtUnix = uint64(nowUnix)
	record.UpdatedAtUnix = uint64(nowUnix)
	next := cloneRelayRouteRecords(journal.records)
	next[stableActionID] = record
	if err := journal.persist(next); err != nil {
		return RelayRouteRecord{}, err
	}
	journal.records = next
	return cloneRelayRouteRecord(record), nil
}

// Switch consumes the receipt for a previously prepared relay-only successor.
// The receipt chain, rather than provider availability, is the authoritative
// route lineage.
func (journal *DurableRelayRouteJournal) Switch(stableActionID, exactRequestDigest string,
	expectedGeneration uint64, currentExecutionDigest string, successor RelayProviderProvenance,
	attempt RelayAttempt, at time.Time) (RelayRouteRecord, error) {
	if journal == nil || expectedGeneration == 0 || !canonicalSHA256(currentExecutionDigest) || at.IsZero() {
		return RelayRouteRecord{}, agentrelay.ErrRelayInvalidState
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.lock == nil {
		return RelayRouteRecord{}, errors.New("relay route journal is closed")
	}
	record, found := journal.records[stableActionID]
	if !found {
		return RelayRouteRecord{}, agentrelay.ErrRelayUnknown
	}
	record = cloneRelayRouteRecord(record)
	if record.ExactRequestDigest != exactRequestDigest {
		return cloneRelayRouteRecord(record), agentrelay.ErrRelayConflict
	}
	current := &record.Hops[len(record.Hops)-1]
	pending := record.PendingSwitch
	gateKind, gateDigest, gateOK := relayHopFailoverGate(record, *current)
	if current.Generation != expectedGeneration || current.RelayExecutionDigest != currentExecutionDigest ||
		pending == nil || pending.Generation != expectedGeneration+1 || !pending.AdmissionStarted || !current.SubmitStarted ||
		current.Attempt.Execution.QuoteRequest.Body.Mode != agentrelay.ModeRelayExact ||
		current.FailoverFinalityEvidenceDigest != "" ||
		current.FailoverFinalityEvidence != nil || !gateOK || pending.FailoverGateKind != gateKind ||
		pending.FailoverGateDigest != gateDigest ||
		!containsRelayProvenance(record.Candidates, successor) ||
		attempt.Execution.ProviderQuote.Body.ProviderAgentID != successor.ProviderAgentID ||
		!sameRelayProvenance(pending.Provider, successor) ||
		pending.RelayExecutionDigest == "" || !sameRelayAttemptWithoutAdmission(pending.Attempt, attempt) ||
		!(pending.Rebase == nil && sameRelayExecutionBaseIdentityWithCredentials(current.Attempt.Execution, attempt.Execution) ||
			pending.Rebase != nil && sameRelayExecutionBaseIdentity(current.Attempt.Execution, attempt.Execution)) ||
		!validRelayAdmissionSuccessor(current.Attempt.Execution.AdmissionReceipt, attempt.Execution) {
		return cloneRelayRouteRecord(record), agentrelay.ErrRelayConflict
	}
	for _, hop := range record.Hops {
		if sameRelayProvenance(hop.Provider, successor) {
			return cloneRelayRouteRecord(record), agentrelay.ErrRelayConflict
		}
	}
	if len(record.Hops) >= maximumRelayRouteHops || uint32(len(record.Hops)) >= record.MaximumRouteAttempts {
		return cloneRelayRouteRecord(record), errors.New("relay route failover capacity is exhausted")
	}
	executionDigest, err := agentrelay.RelayExecutionRequestDigest(attempt.Execution)
	if err != nil {
		return cloneRelayRouteRecord(record), err
	}
	if executionDigest != pending.RelayExecutionDigest {
		return cloneRelayRouteRecord(record), agentrelay.ErrRelayConflict
	}
	serviceFee, feeAsset, feeErr := relayAttemptServiceFee(attempt)
	cumulativeAfter, cumulativeErr := addRelayAtomic(record.CumulativeServiceFeeAtomic, serviceFee)
	if feeErr != nil || cumulativeErr != nil || feeAsset != record.ServiceFeeAsset ||
		cumulativeAfter != pending.CumulativeServiceFeeAtomicAfter ||
		compareRelayAtomic(cumulativeAfter, record.MaximumCumulativeServiceFeeAtomic) > 0 {
		return cloneRelayRouteRecord(record), agentrelay.ErrRelayConflict
	}
	nowUnix := at.UTC().Unix()
	if nowUnix <= 0 || uint64(nowUnix) < record.UpdatedAtUnix {
		return cloneRelayRouteRecord(record), agentrelay.ErrRelayInvalidState
	}
	if gateKind == relayFailoverGateFinality {
		current.FailoverFinalityEvidenceDigest = current.TerminalFinalityEvidenceDigest
		evidenceCopy := *current.TerminalFinalityEvidence
		current.FailoverFinalityEvidence = &evidenceCopy
	}
	record.Hops = append(record.Hops, RelayRouteHop{Generation: expectedGeneration + 1,
		Provider: successor, RelayExecutionDigest: executionDigest, Attempt: cloneRelayAttempt(attempt)})
	record.PendingSwitch = nil
	record.CumulativeServiceFeeAtomic = cumulativeAfter
	record.UpdatedAtUnix = uint64(nowUnix)
	next := cloneRelayRouteRecords(journal.records)
	next[stableActionID] = record
	if err := journal.persist(next); err != nil {
		return RelayRouteRecord{}, err
	}
	journal.records = next
	return cloneRelayRouteRecord(record), nil
}

func (journal *DurableRelayRouteJournal) load() error {
	file, err := openRelayJournalFile(journal.path)
	if errors.Is(err, os.ErrNotExist) {
		return journal.persist(journal.records)
	}
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 ||
		info.Size() <= 0 || info.Size() > maximumRelayRouteJournalBytes {
		return errors.New("relay route journal is not a bounded owner-only regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximumRelayRouteJournalBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maximumRelayRouteJournalBytes {
		return errors.New("read bounded relay route journal")
	}
	var document relayRouteJournalDocument
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&document) != nil || document.Schema != relayRouteJournalSchema ||
		len(document.Records) > maximumRelayRoutes ||
		len(document.SponsorshipEffects) > maximumLegacySponsorshipEffects {
		return errors.New("relay route journal document is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("relay route journal has trailing JSON")
	}
	records := make(map[string]RelayRouteRecord, len(document.Records))
	seenRoutes := make(map[string]struct{}, len(document.Records))
	compactedTerminalRoutes := false
	for _, record := range document.Records {
		if !validRelayRouteRecord(record) {
			return errors.New("relay route journal record is invalid")
		}
		if _, found := seenRoutes[record.StableActionID]; found {
			return errors.New("relay route journal contains a duplicate action")
		}
		seenRoutes[record.StableActionID] = struct{}{}
		if relayRouteRecordIsTerminal(record) {
			if err := journal.writeTerminalRoute(record); err != nil {
				return errors.New("compact relay terminal route: " + err.Error())
			}
			compactedTerminalRoutes = true
			continue
		}
		records[record.StableActionID] = cloneRelayRouteRecord(record)
	}
	if reconciled, reconcileErr := journal.reconcileTerminalArtifacts(records); reconcileErr != nil {
		return reconcileErr
	} else if reconciled {
		compactedTerminalRoutes = true
	}
	if err := journal.validateTerminalTombstoneRegistry(); err != nil {
		return err
	}
	effects := make(map[string]RelaySponsorshipChainEffect)
	legacyEffects := make(map[string]struct{}, len(document.SponsorshipEffects))
	for _, effect := range document.SponsorshipEffects {
		if !validRelaySponsorshipChainEffect(effect) {
			return errors.New("relay route journal sponsorship effect is invalid")
		}
		if _, found := legacyEffects[effect.EffectIdentityDigest]; found {
			return errors.New("relay route journal contains a duplicate sponsorship chain effect")
		}
		legacyEffects[effect.EffectIdentityDigest] = struct{}{}
		if err := journal.writeSponsorshipChainEffect(effect); err != nil {
			return errors.New("migrate relay sponsorship chain effect: " + err.Error())
		}
	}
	journal.records = records
	journal.sponsorshipEffects = effects
	if len(document.SponsorshipEffects) != 0 || compactedTerminalRoutes {
		// Legacy V1 documents stored a permanently bounded inline replay set.
		// Migrate each exact identity to the content-addressed registry before
		// clearing the inline list. A crash at either side is idempotent.
		if err := journal.persistState(records, nil); err != nil {
			return err
		}
	}
	return nil
}

func (journal *DurableRelayRouteJournal) validateTerminalTombstoneRegistry() error {
	shards, err := os.ReadDir(journal.terminalDirectory)
	if err != nil {
		return errors.New("read relay terminal tombstone registry")
	}
	for _, shard := range shards {
		if !shard.IsDir() || len(shard.Name()) != 2 {
			return errors.New("relay terminal tombstone registry contains an invalid shard")
		}
		shardPath := filepath.Join(journal.terminalDirectory, shard.Name())
		if validateRelayJournalDirectorySecurity(shardPath) != nil {
			return errors.New("relay terminal tombstone shard is not owner-private")
		}
		entries, readErr := os.ReadDir(shardPath)
		if readErr != nil {
			return errors.New("read relay terminal tombstone shard")
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || len(name) != 64+len(".json") || !strings.HasSuffix(name, ".json") {
				return errors.New("relay terminal tombstone registry contains an invalid file")
			}
			hexDigest := strings.TrimSuffix(name, ".json")
			stableActionID := "sha256:" + hexDigest
			if !canonicalSHA256(stableActionID) || !strings.HasPrefix(hexDigest, shard.Name()) {
				return errors.New("relay terminal tombstone registry contains an invalid digest")
			}
			tombstone, found, tombstoneErr := journal.readTerminalRouteTombstone(stableActionID)
			if tombstoneErr != nil || !found {
				return errors.New("relay terminal tombstone cannot be verified")
			}
			artifactPath, pathErr := journal.terminalArtifactPath(tombstone.ProtectedArtifactDigest, false)
			if pathErr != nil {
				return pathErr
			}
			_, statErr := os.Lstat(artifactPath)
			if !tombstone.HandoffAcknowledged && errors.Is(statErr, os.ErrNotExist) {
				return errors.New("unacknowledged relay terminal tombstone lost its recovery artifact")
			}
			if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
				return errors.New("stat relay terminal recovery artifact")
			}
		}
	}
	return nil
}

func relayTerminalRecordIsMonotonicSuccessor(active, terminal RelayRouteRecord) bool {
	if !validRelayRouteRecord(active) || relayRouteRecordIsTerminal(active) ||
		!relayRouteRecordIsTerminal(terminal) || active.StableActionID != terminal.StableActionID ||
		active.ExactRequestDigest != terminal.ExactRequestDigest || len(active.Hops) != len(terminal.Hops) ||
		terminal.UpdatedAtUnix < active.UpdatedAtUnix || active.PendingSwitch != nil && active.PendingSwitch.AdmissionStarted {
		return false
	}
	activeCurrent := active.Hops[len(active.Hops)-1]
	if activeCurrent.TerminalResolution != nil || activeCurrent.TerminalFinalityEvidence != nil ||
		activeCurrent.TerminalResolutionDigest != "" || activeCurrent.TerminalFinalityEvidenceDigest != "" {
		return false
	}
	normalized := cloneRelayRouteRecord(terminal)
	normalized.PendingSwitch = cloneRelayRouteRecord(active).PendingSwitch
	normalized.UpdatedAtUnix = active.UpdatedAtUnix
	normalizedCurrent := &normalized.Hops[len(normalized.Hops)-1]
	normalizedCurrent.TerminalResolutionDigest = activeCurrent.TerminalResolutionDigest
	normalizedCurrent.TerminalResolution = activeCurrent.TerminalResolution
	normalizedCurrent.TerminalFinalityEvidenceDigest = activeCurrent.TerminalFinalityEvidenceDigest
	normalizedCurrent.TerminalFinalityEvidence = activeCurrent.TerminalFinalityEvidence
	normalizedCurrent.FailoverQueryAttemptDigest = activeCurrent.FailoverQueryAttemptDigest
	normalizedCurrent.FailoverQueryAttempt = cloneRelayResolveQueryAttemptPointer(activeCurrent.FailoverQueryAttempt)
	return reflect.DeepEqual(active, normalized)
}

func cloneRelayResolveQueryAttemptPointer(value *relayRouteResolveQueryAttempt) *relayRouteResolveQueryAttempt {
	if value == nil {
		return nil
	}
	copy := cloneRelayResolveQueryAttempt(*value)
	return &copy
}

// reconcileTerminalArtifacts closes the artifact->tombstone->hot-delete crash
// windows. A protected artifact is accepted only as the exact monotonic
// terminal successor of the still-hot route, after which its tombstone is
// created/verified and the stale hot record is removed. Arbitrary orphan
// artifacts or divergent lineages fail startup closed.
func (journal *DurableRelayRouteJournal) reconcileTerminalArtifacts(
	records map[string]RelayRouteRecord) (bool, error) {
	artifacts, err := journal.scanTerminalArtifacts()
	if err != nil {
		return false, err
	}
	reconciled := false
	for _, artifactFile := range artifacts {
		terminal, err := journal.readTerminalArtifact(artifactFile.digest)
		if err != nil {
			return false, err
		}
		tombstone, tombstoneFound, err := journal.readTerminalRouteTombstone(terminal.StableActionID)
		if err != nil {
			return false, err
		}
		if tombstoneFound && !terminalRouteTombstoneMatchesRecord(tombstone, terminal) {
			return false, errors.New("relay terminal artifact conflicts with its permanent tombstone")
		}
		active, activeFound := records[terminal.StableActionID]
		if !tombstoneFound {
			if !activeFound || !relayTerminalRecordIsMonotonicSuccessor(active, terminal) {
				return false, errors.New("orphan relay terminal artifact has no recoverable route lineage")
			}
			if err := journal.writeTerminalRoute(terminal); err != nil {
				return false, errors.New("recover relay terminal tombstone: " + err.Error())
			}
			tombstoneFound = true
		}
		if activeFound {
			if !relayTerminalRecordIsMonotonicSuccessor(active, terminal) {
				return false, errors.New("relay terminal artifact is not a monotonic successor of its hot route")
			}
			delete(records, terminal.StableActionID)
			reconciled = true
		}
		if !tombstoneFound {
			return false, errors.New("relay terminal artifact has no permanent replay fence")
		}
	}
	return reconciled, nil
}

func (journal *DurableRelayRouteJournal) persist(records map[string]RelayRouteRecord) error {
	return journal.persistState(records, journal.sponsorshipEffects)
}

func (journal *DurableRelayRouteJournal) persistState(records map[string]RelayRouteRecord,
	_ map[string]RelaySponsorshipChainEffect) error {
	keys := make([]string, 0, len(records))
	for key := range records {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	values := make([]RelayRouteRecord, 0, len(keys))
	for _, key := range keys {
		values = append(values, cloneRelayRouteRecord(records[key]))
	}
	raw, err := json.Marshal(relayRouteJournalDocument{Schema: relayRouteJournalSchema, Records: values})
	if err != nil || len(raw) == 0 || len(raw) > maximumRelayRouteJournalBytes {
		return errors.New("encode bounded relay route journal")
	}
	return writeRelayJournalAtomic(journal.directory, journal.path, raw)
}

func relayRouteRecordIsTerminal(record RelayRouteRecord) bool {
	if !validRelayRouteRecord(record) || record.PendingSwitch != nil || len(record.Hops) == 0 {
		return false
	}
	current := record.Hops[len(record.Hops)-1]
	if current.TerminalResolution == nil || current.TerminalFinalityEvidence == nil ||
		current.TerminalResolutionDigest == "" || current.TerminalFinalityEvidenceDigest == "" {
		return false
	}
	// A relay_exact absence/expiry/invalidation is a terminal Provider attempt,
	// but not yet a terminal owner route while a bounded unused successor may
	// still submit the same immutable BOC. Keep that route hot until failover is
	// exhausted or a non-failover outcome closes the economic action.
	return current.Attempt.Execution.QuoteRequest.Body.Mode != agentrelay.ModeRelayExact ||
		!safeRelayFailoverOutcome(current.TerminalFinalityEvidence.Body.Outcome) ||
		uint32(len(record.Hops)) >= record.MaximumRouteAttempts
}

func (journal *DurableRelayRouteJournal) terminalRoutePath(stableActionID string,
	createShard bool) (string, error) {
	if journal == nil || !canonicalSHA256(stableActionID) || !filepath.IsAbs(journal.terminalDirectory) {
		return "", agentrelay.ErrRelayInvalidState
	}
	hexDigest := strings.TrimPrefix(stableActionID, "sha256:")
	shard := filepath.Join(journal.terminalDirectory, hexDigest[:2])
	if createShard {
		if err := os.Mkdir(shard, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return "", errors.New("create relay terminal route shard")
		}
		if err := validateRelayJournalDirectorySecurity(shard); err != nil {
			return "", errors.New("relay terminal route shard is not owner-private")
		}
	}
	return filepath.Join(shard, hexDigest+".json"), nil
}

func validRelayTerminalRouteTombstone(tombstone relayTerminalRouteTombstone) bool {
	validHandoff := (!tombstone.HandoffAcknowledged && tombstone.HandoffReceiptDigest == "" &&
		tombstone.HandoffRevision == 0 && tombstone.HandoffAtUnix == 0) ||
		(tombstone.HandoffAcknowledged && canonicalSHA256(tombstone.HandoffReceiptDigest) &&
			tombstone.HandoffRevision > 0 && tombstone.HandoffAtUnix >= tombstone.CompletedAtUnix)
	return tombstone.Schema == relayTerminalRouteTombstoneSchema && validHandoff &&
		canonicalSHA256(tombstone.StableActionID) && canonicalSHA256(tombstone.ExactRequestDigest) &&
		canonicalSHA256(tombstone.RelayExecutionDigest) && boundedRelayTrustDomain(tombstone.ProviderAgentID) &&
		tombstone.RouteGeneration > 0 && validDurableRelayOutcome(tombstone.TerminalOutcome) &&
		canonicalSHA256(tombstone.TerminalResolutionDigest) &&
		canonicalSHA256(tombstone.TerminalFinalityEvidenceDigest) &&
		canonicalSHA256(tombstone.ProtectedArtifactDigest) && tombstone.CompletedAtUnix > 0
}

func relayTerminalHandoffReference(record RelayRouteRecord) (RelayTerminalHandoffReference, error) {
	if !relayRouteRecordIsTerminal(record) {
		return RelayTerminalHandoffReference{}, agentrelay.ErrRelayInvalidState
	}
	artifactDigest, err := codec.Digest(relayTerminalRouteArtifactDomain, record)
	if err != nil {
		return RelayTerminalHandoffReference{}, err
	}
	current := record.Hops[len(record.Hops)-1]
	reference := RelayTerminalHandoffReference{StableActionID: record.StableActionID,
		ExactRequestDigest: record.ExactRequestDigest, RelayExecutionDigest: current.RelayExecutionDigest,
		ProviderAgentID: current.Provider.ProviderAgentID, RouteGeneration: current.Generation,
		ProtectedArtifactDigest: artifactDigest, TerminalResolutionDigest: current.TerminalResolutionDigest,
		TerminalEvidenceDigest: current.TerminalFinalityEvidenceDigest}
	if !validRelayTerminalHandoffReference(reference) {
		return RelayTerminalHandoffReference{}, agentrelay.ErrRelayInvalidState
	}
	return reference, nil
}

// RelayTerminalHandoffReferenceForRecord returns the exact protected-artifact
// and evidence identities that a durable accounting entry must acknowledge.
func RelayTerminalHandoffReferenceForRecord(record RelayRouteRecord) (RelayTerminalHandoffReference, error) {
	return relayTerminalHandoffReference(record)
}

func validRelayTerminalHandoffReference(reference RelayTerminalHandoffReference) bool {
	return canonicalSHA256(reference.StableActionID) && canonicalSHA256(reference.ExactRequestDigest) &&
		canonicalSHA256(reference.RelayExecutionDigest) && boundedRelayTrustDomain(reference.ProviderAgentID) &&
		reference.RouteGeneration > 0 && canonicalSHA256(reference.ProtectedArtifactDigest) &&
		canonicalSHA256(reference.TerminalResolutionDigest) && canonicalSHA256(reference.TerminalEvidenceDigest)
}

func terminalRouteTombstoneMatchesRecord(tombstone relayTerminalRouteTombstone,
	record RelayRouteRecord) bool {
	reference, err := relayTerminalHandoffReference(record)
	if err != nil || reference.StableActionID != tombstone.StableActionID ||
		reference.ExactRequestDigest != tombstone.ExactRequestDigest ||
		reference.RelayExecutionDigest != tombstone.RelayExecutionDigest ||
		reference.ProviderAgentID != tombstone.ProviderAgentID ||
		reference.RouteGeneration != tombstone.RouteGeneration ||
		reference.ProtectedArtifactDigest != tombstone.ProtectedArtifactDigest ||
		reference.TerminalResolutionDigest != tombstone.TerminalResolutionDigest ||
		reference.TerminalEvidenceDigest != tombstone.TerminalFinalityEvidenceDigest {
		return false
	}
	expected, err := terminalRouteTombstone(record, reference.ProtectedArtifactDigest)
	if err != nil {
		return false
	}
	expected.HandoffAcknowledged = tombstone.HandoffAcknowledged
	expected.HandoffReceiptDigest = tombstone.HandoffReceiptDigest
	expected.HandoffRevision = tombstone.HandoffRevision
	expected.HandoffAtUnix = tombstone.HandoffAtUnix
	return reflect.DeepEqual(expected, tombstone)
}

func terminalRouteTombstone(record RelayRouteRecord, artifactDigest string) (relayTerminalRouteTombstone, error) {
	if !relayRouteRecordIsTerminal(record) || !canonicalSHA256(artifactDigest) {
		return relayTerminalRouteTombstone{}, agentrelay.ErrRelayInvalidState
	}
	current := record.Hops[len(record.Hops)-1]
	tombstone := relayTerminalRouteTombstone{Schema: relayTerminalRouteTombstoneSchema,
		StableActionID: record.StableActionID, ExactRequestDigest: record.ExactRequestDigest,
		RelayExecutionDigest: current.RelayExecutionDigest, ProviderAgentID: current.Provider.ProviderAgentID,
		RouteGeneration: current.Generation, TerminalOutcome: current.TerminalFinalityEvidence.Body.Outcome,
		TerminalResolutionDigest:       current.TerminalResolutionDigest,
		TerminalFinalityEvidenceDigest: current.TerminalFinalityEvidenceDigest,
		ProtectedArtifactDigest:        artifactDigest, CompletedAtUnix: record.UpdatedAtUnix}
	if !validRelayTerminalRouteTombstone(tombstone) {
		return relayTerminalRouteTombstone{}, agentrelay.ErrRelayInvalidState
	}
	return tombstone, nil
}

func (journal *DurableRelayRouteJournal) readTerminalRouteTombstone(stableActionID string) (
	relayTerminalRouteTombstone, bool, error) {
	path, err := journal.terminalRoutePath(stableActionID, false)
	if err != nil {
		return relayTerminalRouteTombstone{}, false, err
	}
	file, err := openRelayJournalFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return relayTerminalRouteTombstone{}, false, nil
	}
	if err != nil {
		return relayTerminalRouteTombstone{}, false, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 ||
		info.Size() <= 0 || info.Size() > maximumRelayTerminalRouteBytes {
		return relayTerminalRouteTombstone{}, false, errors.New("relay terminal route tombstone is invalid")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximumRelayTerminalRouteBytes+1))
	var tombstone relayTerminalRouteTombstone
	if err != nil || len(raw) == 0 || len(raw) > maximumRelayTerminalRouteBytes ||
		decodeStrictJSON(raw, &tombstone) != nil || tombstone.StableActionID != stableActionID ||
		!validRelayTerminalRouteTombstone(tombstone) {
		return relayTerminalRouteTombstone{}, false, errors.New("relay terminal route tombstone cannot be verified")
	}
	return tombstone, true, nil
}

func (journal *DurableRelayRouteJournal) terminalArtifactPath(digest string, createShard bool) (string, error) {
	if journal == nil || !canonicalSHA256(digest) || !filepath.IsAbs(journal.terminalArtifactDirectory) {
		return "", agentrelay.ErrRelayInvalidState
	}
	hexDigest := strings.TrimPrefix(digest, "sha256:")
	shard := filepath.Join(journal.terminalArtifactDirectory, hexDigest[:2])
	if createShard {
		if err := os.Mkdir(shard, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return "", errors.New("create relay terminal artifact shard")
		}
		if err := validateRelayJournalDirectorySecurity(shard); err != nil {
			return "", errors.New("relay terminal artifact shard is not owner-private")
		}
	}
	return filepath.Join(shard, hexDigest+".json"), nil
}

func (journal *DurableRelayRouteJournal) terminalArtifactHandoffPath(digest string,
	createShard bool) (string, error) {
	artifactPath, err := journal.terminalArtifactPath(digest, createShard)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(artifactPath, ".json") + ".handoff.json", nil
}

func validRelayTerminalArtifactHandoff(handoff relayTerminalArtifactHandoff) bool {
	return handoff.Schema == relayTerminalArtifactHandoffSchema &&
		canonicalSHA256(handoff.ProtectedArtifactDigest) && canonicalSHA256(handoff.StableActionID) &&
		canonicalSHA256(handoff.ExactRequestDigest) && canonicalSHA256(handoff.RelayExecutionDigest) &&
		boundedRelayTrustDomain(handoff.ProviderAgentID) && handoff.RouteGeneration > 0 &&
		canonicalSHA256(handoff.TerminalResolutionDigest) && canonicalSHA256(handoff.TerminalEvidenceDigest) &&
		canonicalSHA256(handoff.HandoffReceiptDigest) && handoff.HandoffRevision > 0 &&
		handoff.HandoffAtUnix > 0
}

func (journal *DurableRelayRouteJournal) readTerminalArtifactHandoff(artifactDigest string) (
	relayTerminalArtifactHandoff, bool, error) {
	path, err := journal.terminalArtifactHandoffPath(artifactDigest, false)
	if err != nil {
		return relayTerminalArtifactHandoff{}, false, err
	}
	file, err := openRelayJournalFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return relayTerminalArtifactHandoff{}, false, nil
	}
	if err != nil {
		return relayTerminalArtifactHandoff{}, false, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 ||
		info.Size() <= 0 || info.Size() > maximumRelayTerminalHandoffBytes {
		return relayTerminalArtifactHandoff{}, false, errors.New("relay terminal artifact handoff is invalid")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximumRelayTerminalHandoffBytes+1))
	var handoff relayTerminalArtifactHandoff
	if err != nil || len(raw) == 0 || len(raw) > maximumRelayTerminalHandoffBytes ||
		decodeStrictJSON(raw, &handoff) != nil || handoff.ProtectedArtifactDigest != artifactDigest ||
		!validRelayTerminalArtifactHandoff(handoff) {
		return relayTerminalArtifactHandoff{}, false,
			errors.New("relay terminal artifact handoff cannot be verified")
	}
	return handoff, true, nil
}

func relayTerminalHandoffMatchesTombstone(handoff relayTerminalArtifactHandoff,
	tombstone relayTerminalRouteTombstone) bool {
	return tombstone.HandoffAcknowledged && handoff.ProtectedArtifactDigest == tombstone.ProtectedArtifactDigest &&
		handoff.StableActionID == tombstone.StableActionID &&
		handoff.ExactRequestDigest == tombstone.ExactRequestDigest &&
		handoff.RelayExecutionDigest == tombstone.RelayExecutionDigest &&
		handoff.ProviderAgentID == tombstone.ProviderAgentID &&
		handoff.RouteGeneration == tombstone.RouteGeneration &&
		handoff.TerminalResolutionDigest == tombstone.TerminalResolutionDigest &&
		handoff.TerminalEvidenceDigest == tombstone.TerminalFinalityEvidenceDigest &&
		handoff.HandoffReceiptDigest == tombstone.HandoffReceiptDigest &&
		handoff.HandoffRevision == tombstone.HandoffRevision && handoff.HandoffAtUnix == tombstone.HandoffAtUnix
}

// AcknowledgeTerminalHandoff is deliberately separate from RecordTerminal.
// The caller must first persist the exact terminal evidence in its independent
// accounting/portfolio store and supply that store's receipt digest/revision.
// Only then does the protected recovery artifact become archive-eligible.
func (journal *DurableRelayRouteJournal) AcknowledgeTerminalHandoff(
	acknowledgement RelayTerminalHandoffAcknowledgement) error {
	if journal == nil || !validRelayTerminalHandoffReference(acknowledgement.Reference) ||
		!canonicalSHA256(acknowledgement.AccountingReceiptDigest) ||
		acknowledgement.AccountingRevision == 0 || acknowledgement.AcknowledgedAt.IsZero() {
		return agentrelay.ErrRelayInvalidState
	}
	j := journal
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.lock == nil {
		return errors.New("relay route journal is closed")
	}
	tombstone, found, err := j.readTerminalRouteTombstone(acknowledgement.Reference.StableActionID)
	if err != nil {
		return err
	}
	if !found {
		return agentrelay.ErrRelayUnknown
	}
	if tombstone.ExactRequestDigest != acknowledgement.Reference.ExactRequestDigest ||
		tombstone.RelayExecutionDigest != acknowledgement.Reference.RelayExecutionDigest ||
		tombstone.ProviderAgentID != acknowledgement.Reference.ProviderAgentID ||
		tombstone.RouteGeneration != acknowledgement.Reference.RouteGeneration ||
		tombstone.ProtectedArtifactDigest != acknowledgement.Reference.ProtectedArtifactDigest ||
		tombstone.TerminalResolutionDigest != acknowledgement.Reference.TerminalResolutionDigest ||
		tombstone.TerminalFinalityEvidenceDigest != acknowledgement.Reference.TerminalEvidenceDigest {
		return agentrelay.ErrRelayConflict
	}
	nowUnix := acknowledgement.AcknowledgedAt.UTC().Unix()
	if nowUnix <= 0 || uint64(nowUnix) < tombstone.CompletedAtUnix {
		return agentrelay.ErrRelayInvalidState
	}
	expected := relayTerminalArtifactHandoff{Schema: relayTerminalArtifactHandoffSchema,
		ProtectedArtifactDigest: tombstone.ProtectedArtifactDigest, StableActionID: tombstone.StableActionID,
		ExactRequestDigest: tombstone.ExactRequestDigest, RelayExecutionDigest: tombstone.RelayExecutionDigest,
		ProviderAgentID: tombstone.ProviderAgentID, RouteGeneration: tombstone.RouteGeneration,
		TerminalResolutionDigest: tombstone.TerminalResolutionDigest,
		TerminalEvidenceDigest:   tombstone.TerminalFinalityEvidenceDigest,
		HandoffReceiptDigest:     acknowledgement.AccountingReceiptDigest,
		HandoffRevision:          acknowledgement.AccountingRevision, HandoffAtUnix: uint64(nowUnix)}
	if !validRelayTerminalArtifactHandoff(expected) {
		return agentrelay.ErrRelayInvalidState
	}
	if tombstone.HandoffAcknowledged {
		if tombstone.HandoffReceiptDigest != expected.HandoffReceiptDigest ||
			tombstone.HandoffRevision != expected.HandoffRevision {
			return agentrelay.ErrRelayConflict
		}
		// The accounting receipt owns the original durable timestamp. A crash
		// after tombstone update but before sidecar creation may retry later;
		// reconstruct the marker from the tombstone instead of requiring the
		// caller's wall clock to reproduce that instant.
		expected.HandoffAtUnix = tombstone.HandoffAtUnix
		if prior, markerFound, markerErr := j.readTerminalArtifactHandoff(tombstone.ProtectedArtifactDigest); markerErr != nil {
			return markerErr
		} else if markerFound && !reflect.DeepEqual(prior, expected) {
			return agentrelay.ErrRelayConflict
		} else if markerFound {
			return j.compactTerminalArtifacts("")
		}
		artifactPath, pathErr := j.terminalArtifactPath(tombstone.ProtectedArtifactDigest, false)
		if pathErr != nil {
			return pathErr
		}
		if _, statErr := os.Lstat(artifactPath); errors.Is(statErr, os.ErrNotExist) {
			// Already archived after a complete prior acknowledgement.
			return nil
		} else if statErr != nil {
			return errors.New("stat acknowledged relay terminal artifact")
		}
	} else {
		// An unacknowledged artifact is guaranteed to remain locally
		// recoverable; acknowledge cannot bless a missing/tampered artifact.
		if _, artifactFound, artifactErr := j.readTerminalRoute(tombstone.StableActionID); artifactErr != nil || !artifactFound {
			if artifactErr != nil {
				return artifactErr
			}
			return errors.New("relay terminal handoff has no protected recovery artifact")
		}
		tombstone.HandoffAcknowledged = true
		tombstone.HandoffReceiptDigest = expected.HandoffReceiptDigest
		tombstone.HandoffRevision = expected.HandoffRevision
		tombstone.HandoffAtUnix = expected.HandoffAtUnix
		if !validRelayTerminalRouteTombstone(tombstone) {
			return agentrelay.ErrRelayInvalidState
		}
		tombstonePath, pathErr := j.terminalRoutePath(tombstone.StableActionID, true)
		if pathErr != nil {
			return pathErr
		}
		raw, marshalErr := json.Marshal(tombstone)
		if marshalErr != nil || len(raw) == 0 || len(raw) > maximumRelayTerminalRouteBytes {
			return errors.New("encode relay terminal handoff tombstone")
		}
		// Persist the permanent accounting binding before making the large
		// artifact evictable. A crash here leaves the artifact protected until
		// an idempotent retry writes the sidecar below.
		if err := writeRelayJournalAtomic(filepath.Dir(tombstonePath), tombstonePath, raw); err != nil {
			return err
		}
	}
	handoffPath, err := j.terminalArtifactHandoffPath(tombstone.ProtectedArtifactDigest, true)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(expected)
	if err != nil || len(raw) == 0 || len(raw) > maximumRelayTerminalHandoffBytes {
		return errors.New("encode relay terminal artifact handoff")
	}
	if err := writeRelayJournalAtomic(filepath.Dir(handoffPath), handoffPath, raw); err != nil {
		return err
	}
	return j.compactTerminalArtifacts("")
}

func (journal *DurableRelayRouteJournal) readTerminalRoute(stableActionID string) (
	RelayRouteRecord, bool, error) {
	tombstone, found, err := journal.readTerminalRouteTombstone(stableActionID)
	if err != nil || !found {
		return RelayRouteRecord{}, found, err
	}
	record, err := journal.readTerminalArtifact(tombstone.ProtectedArtifactDigest)
	if errors.Is(err, os.ErrNotExist) {
		return RelayRouteRecord{}, true, errRelayTerminalArtifactArchived
	}
	if err != nil {
		return RelayRouteRecord{}, true, err
	}
	if !terminalRouteTombstoneMatchesRecord(tombstone, record) {
		return RelayRouteRecord{}, true, errors.New("relay terminal route artifact conflicts with its tombstone")
	}
	return cloneRelayRouteRecord(record), true, nil
}

func (journal *DurableRelayRouteJournal) readTerminalArtifact(artifactDigest string) (RelayRouteRecord, error) {
	path, err := journal.terminalArtifactPath(artifactDigest, false)
	if err != nil {
		return RelayRouteRecord{}, err
	}
	file, err := openRelayJournalFile(path)
	if err != nil {
		return RelayRouteRecord{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 ||
		info.Size() <= 0 || info.Size() > maximumRelayTerminalArtifactBytes {
		return RelayRouteRecord{}, errors.New("relay terminal route artifact is invalid")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximumRelayTerminalArtifactBytes+1))
	var artifact relayTerminalRouteArtifact
	if err != nil || len(raw) == 0 || len(raw) > maximumRelayTerminalArtifactBytes ||
		decodeStrictJSON(raw, &artifact) != nil || artifact.Schema != relayTerminalRouteArtifactSchema ||
		!relayRouteRecordIsTerminal(artifact.Record) {
		return RelayRouteRecord{}, errors.New("relay terminal route artifact cannot be verified")
	}
	digest, digestErr := codec.Digest(relayTerminalRouteArtifactDomain, artifact.Record)
	if digestErr != nil || digest != artifactDigest {
		return RelayRouteRecord{}, errors.New("relay terminal route artifact digest is invalid")
	}
	return cloneRelayRouteRecord(artifact.Record), nil
}

func (journal *DurableRelayRouteJournal) writeTerminalRoute(record RelayRouteRecord) error {
	if !relayRouteRecordIsTerminal(record) {
		return agentrelay.ErrRelayInvalidState
	}
	artifactDigest, err := codec.Digest(relayTerminalRouteArtifactDomain, record)
	if err != nil {
		return err
	}
	tombstone, err := terminalRouteTombstone(record, artifactDigest)
	if err != nil {
		return err
	}
	if prior, found, err := journal.readTerminalRouteTombstone(record.StableActionID); err != nil {
		return err
	} else if found {
		if !terminalRouteTombstoneMatchesRecord(prior, record) {
			return agentrelay.ErrRelayConflict
		}
		return nil
	}
	artifactPath, err := journal.terminalArtifactPath(artifactDigest, true)
	if err != nil {
		return err
	}
	artifactRaw, err := json.Marshal(relayTerminalRouteArtifact{
		Schema: relayTerminalRouteArtifactSchema, Record: cloneRelayRouteRecord(record)})
	if err != nil || len(artifactRaw) == 0 || len(artifactRaw) > maximumRelayTerminalArtifactBytes {
		return errors.New("encode bounded relay terminal route artifact")
	}
	if _, statErr := os.Lstat(artifactPath); errors.Is(statErr, os.ErrNotExist) {
		if err := writeRelayJournalAtomic(filepath.Dir(artifactPath), artifactPath, artifactRaw); err != nil {
			return err
		}
	} else if statErr != nil {
		return errors.New("stat relay terminal route artifact")
	} else if existing, readErr := journal.readTerminalArtifact(artifactDigest); readErr != nil ||
		!reflect.DeepEqual(existing, record) {
		return errors.New("existing relay terminal route artifact conflicts with exact terminal result")
	}
	tombstonePath, err := journal.terminalRoutePath(record.StableActionID, true)
	if err != nil {
		return err
	}
	tombstoneRaw, err := json.Marshal(tombstone)
	if err != nil || len(tombstoneRaw) == 0 || len(tombstoneRaw) > maximumRelayTerminalRouteBytes {
		return errors.New("encode bounded relay terminal route tombstone")
	}
	if err := writeRelayJournalAtomic(filepath.Dir(tombstonePath), tombstonePath, tombstoneRaw); err != nil {
		return err
	}
	return journal.compactTerminalArtifacts(artifactDigest)
}

type relayTerminalArtifactFile struct {
	digest  string
	path    string
	modTime time.Time
	handoff *relayTerminalArtifactHandoff
}

func (journal *DurableRelayRouteJournal) scanTerminalArtifacts() ([]relayTerminalArtifactFile, error) {
	shards, err := os.ReadDir(journal.terminalArtifactDirectory)
	if err != nil {
		return nil, errors.New("read relay terminal artifact registry")
	}
	artifacts := make([]relayTerminalArtifactFile, 0, maximumRelayTerminalArtifacts+1)
	for _, shard := range shards {
		if !shard.IsDir() || len(shard.Name()) != 2 {
			return nil, errors.New("relay terminal artifact registry contains an invalid shard")
		}
		shardPath := filepath.Join(journal.terminalArtifactDirectory, shard.Name())
		if validateRelayJournalDirectorySecurity(shardPath) != nil {
			return nil, errors.New("relay terminal artifact shard is not owner-private")
		}
		entries, readErr := os.ReadDir(shardPath)
		if readErr != nil {
			return nil, errors.New("read relay terminal artifact shard")
		}
		artifactNames := make(map[string]bool)
		markerNames := make(map[string]bool)
		for _, entry := range entries {
			name := entry.Name()
			path := filepath.Join(shardPath, name)
			info, infoErr := entry.Info()
			if infoErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
				return nil, errors.New("relay terminal artifact registry contains an invalid file")
			}
			switch {
			case len(name) == 64+len(".json") && strings.HasSuffix(name, ".json"):
				hexDigest := strings.TrimSuffix(name, ".json")
				digest := "sha256:" + hexDigest
				if !canonicalSHA256(digest) || !strings.HasPrefix(hexDigest, shard.Name()) {
					return nil, errors.New("relay terminal artifact registry contains an invalid digest")
				}
				artifactNames[digest] = true
				artifacts = append(artifacts, relayTerminalArtifactFile{digest: digest, path: path,
					modTime: info.ModTime()})
			case len(name) == 64+len(".handoff.json") && strings.HasSuffix(name, ".handoff.json"):
				hexDigest := strings.TrimSuffix(name, ".handoff.json")
				digest := "sha256:" + hexDigest
				if !canonicalSHA256(digest) || !strings.HasPrefix(hexDigest, shard.Name()) {
					return nil, errors.New("relay terminal artifact registry contains an invalid handoff digest")
				}
				markerNames[digest] = true
			default:
				return nil, errors.New("relay terminal artifact registry contains an unknown file")
			}
		}
		// A crash can leave a handoff sidecar after its acknowledged artifact
		// was removed. It is safe to delete because the permanent tombstone
		// retains the receipt/revision and lifetime replay fence.
		for digest := range markerNames {
			if artifactNames[digest] {
				continue
			}
			path, pathErr := journal.terminalArtifactHandoffPath(digest, false)
			if pathErr != nil || os.Remove(path) != nil {
				return nil, errors.New("clean archived relay terminal handoff marker")
			}
		}
	}
	for index := range artifacts {
		handoff, found, readErr := journal.readTerminalArtifactHandoff(artifacts[index].digest)
		if readErr != nil {
			return nil, readErr
		}
		if !found {
			continue
		}
		tombstone, tombstoneFound, tombstoneErr := journal.readTerminalRouteTombstone(handoff.StableActionID)
		if tombstoneErr != nil || !tombstoneFound || !relayTerminalHandoffMatchesTombstone(handoff, tombstone) {
			return nil, errors.New("relay terminal artifact handoff conflicts with its permanent tombstone")
		}
		copy := handoff
		artifacts[index].handoff = &copy
	}
	return artifacts, nil
}

func (journal *DurableRelayRouteJournal) compactTerminalArtifacts(protectedDigest string) error {
	if protectedDigest != "" && !canonicalSHA256(protectedDigest) {
		return agentrelay.ErrRelayInvalidState
	}
	artifacts, err := journal.scanTerminalArtifacts()
	if err != nil {
		return err
	}
	if len(artifacts) <= maximumRelayTerminalArtifacts {
		return nil
	}
	sort.Slice(artifacts, func(left, right int) bool {
		if artifacts[left].modTime.Equal(artifacts[right].modTime) {
			return artifacts[left].path < artifacts[right].path
		}
		return artifacts[left].modTime.Before(artifacts[right].modTime)
	})
	remove := len(artifacts) - maximumRelayTerminalArtifacts
	for _, artifact := range artifacts {
		if remove == 0 {
			break
		}
		if artifact.digest == protectedDigest || artifact.handoff == nil {
			continue
		}
		// The permanent tombstone was verified above to bind the exact
		// accounting receipt. Remove the large artifact first; a crash before
		// sidecar cleanup is safely repaired by scanTerminalArtifacts.
		if err := os.Remove(artifact.path); err != nil {
			return errors.New("archive acknowledged relay terminal artifact")
		}
		handoffPath, pathErr := journal.terminalArtifactHandoffPath(artifact.digest, false)
		if pathErr != nil {
			return pathErr
		}
		if err := os.Remove(handoffPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.New("remove archived relay terminal handoff marker")
		}
		remove--
	}
	if remove != 0 {
		return errors.New("relay terminal recovery capacity is reserved by unacknowledged accounting handoffs")
	}
	return nil
}

// reserveTerminalArtifactCapacity runs before the first route is admitted and
// therefore before any Provider can observe a side effect. Every active route
// reserves one future artifact slot; every unacknowledged terminal artifact
// keeps its slot until a separate accounting ledger accepts the handoff.
func (journal *DurableRelayRouteJournal) reserveTerminalArtifactCapacity() error {
	if err := journal.compactTerminalArtifacts(""); err != nil {
		return err
	}
	artifacts, err := journal.scanTerminalArtifacts()
	if err != nil {
		return err
	}
	unacknowledged := 0
	for _, artifact := range artifacts {
		if artifact.handoff == nil {
			unacknowledged++
		}
	}
	if len(journal.records)+unacknowledged >= maximumRelayTerminalArtifacts {
		return errors.New("relay terminal recovery capacity requires durable accounting handoff")
	}
	return nil
}

func (journal *DurableRelayRouteJournal) sponsorshipChainEffectPath(effectDigest string,
	createShard bool) (string, error) {
	if journal == nil || !canonicalSHA256(effectDigest) ||
		!filepath.IsAbs(journal.effectDirectory) {
		return "", agentrelay.ErrRelayInvalidState
	}
	hexDigest := strings.TrimPrefix(effectDigest, "sha256:")
	shard := filepath.Join(journal.effectDirectory, hexDigest[:2])
	if createShard {
		if err := os.Mkdir(shard, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return "", errors.New("create relay sponsorship effect shard")
		}
		if err := validateRelayJournalDirectorySecurity(shard); err != nil {
			return "", errors.New("relay sponsorship effect shard is not owner-private")
		}
	}
	return filepath.Join(shard, hexDigest+".json"), nil
}

func (journal *DurableRelayRouteJournal) readSponsorshipChainEffect(effectDigest string) (
	RelaySponsorshipChainEffect, bool, error) {
	path, err := journal.sponsorshipChainEffectPath(effectDigest, false)
	if err != nil {
		return RelaySponsorshipChainEffect{}, false, err
	}
	file, err := openRelayJournalFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return RelaySponsorshipChainEffect{}, false, nil
	}
	if err != nil {
		return RelaySponsorshipChainEffect{}, false, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 ||
		info.Size() <= 0 || info.Size() > maximumRelaySponsorshipEffectBytes {
		return RelaySponsorshipChainEffect{}, false, errors.New("relay sponsorship effect file is invalid")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximumRelaySponsorshipEffectBytes+1))
	var effect RelaySponsorshipChainEffect
	if err != nil || len(raw) == 0 || len(raw) > maximumRelaySponsorshipEffectBytes ||
		decodeStrictJSON(raw, &effect) != nil || effect.EffectIdentityDigest != effectDigest ||
		!validRelaySponsorshipChainEffect(effect) {
		return RelaySponsorshipChainEffect{}, false, errors.New("relay sponsorship effect record is invalid")
	}
	return effect, true, nil
}

func (journal *DurableRelayRouteJournal) writeSponsorshipChainEffect(effect RelaySponsorshipChainEffect) error {
	if !validRelaySponsorshipChainEffect(effect) {
		return agentrelay.ErrRelayInvalidState
	}
	if prior, found, err := journal.readSponsorshipChainEffect(effect.EffectIdentityDigest); err != nil {
		return err
	} else if found {
		if !reflect.DeepEqual(prior, effect) {
			return agentrelay.ErrRelayConflict
		}
		return nil
	}
	path, err := journal.sponsorshipChainEffectPath(effect.EffectIdentityDigest, true)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(effect)
	if err != nil || len(raw) == 0 || len(raw) > maximumRelaySponsorshipEffectBytes {
		return errors.New("encode relay sponsorship effect record")
	}
	return writeRelayJournalAtomic(filepath.Dir(path), path, raw)
}

func (journal *DurableRelayRouteJournal) cacheSponsorshipChainEffect(effect RelaySponsorshipChainEffect) {
	if journal.sponsorshipEffects == nil {
		journal.sponsorshipEffects = make(map[string]RelaySponsorshipChainEffect)
	}
	journal.sponsorshipEffects[effect.EffectIdentityDigest] = effect
	for len(journal.sponsorshipEffects) > maximumRelaySponsorshipEffectCache {
		var oldestKey string
		var oldestAt uint64
		for key, candidate := range journal.sponsorshipEffects {
			if oldestKey == "" || candidate.ConsumedAtUnix < oldestAt ||
				candidate.ConsumedAtUnix == oldestAt && key < oldestKey {
				oldestKey, oldestAt = key, candidate.ConsumedAtUnix
			}
		}
		delete(journal.sponsorshipEffects, oldestKey)
	}
}

func cloneRelaySponsorshipChainEffects(values map[string]RelaySponsorshipChainEffect) map[string]RelaySponsorshipChainEffect {
	result := make(map[string]RelaySponsorshipChainEffect, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func validRelaySponsorshipChainEffect(record RelaySponsorshipChainEffect) bool {
	identity := relaySponsorshipEffectIdentityV1{NetworkDigest: record.NetworkDigest,
		ProviderSponsorSourceAccount:  record.ProviderSponsorSourceAccount,
		ProviderSponsorSourceSequence: record.ProviderSponsorSourceSequence,
		SignedTransactionCellHash:     record.SignedTransactionCellHash,
		SubmittedTransactionHash:      record.SubmittedTransactionHash}
	binding := relaySponsorshipEffectBindingV1{AgreementBodyDigest: record.AgreementBodyDigest,
		AgreementObligationID:         record.AgreementObligationID,
		AgreementPaymentRequestDigest: record.AgreementPaymentRequestDigest,
		SponsorshipStableActionID:     record.SponsorshipStableActionID,
		SponsorshipExactRequestDigest: record.SponsorshipExactRequestDigest}
	effectDigest, effectErr := codec.Digest("tos.openfox.agent-relay-sponsorship-chain-effect.v1", identity)
	bindingDigest, bindingErr := codec.Digest("tos.openfox.agent-relay-sponsorship-chain-effect-binding.v1", binding)
	return effectErr == nil && bindingErr == nil && effectDigest == record.EffectIdentityDigest &&
		bindingDigest == record.BindingDigest && canonicalSHA256(record.NetworkDigest) &&
		record.ProviderSponsorSourceAccount != "" &&
		validTVMCellSHA256(record.SignedTransactionCellHash) && record.SubmittedTransactionHash != "" &&
		canonicalSHA256(record.AgreementBodyDigest) && record.AgreementObligationID != "" &&
		canonicalSHA256(record.AgreementPaymentRequestDigest) && canonicalSHA256(record.SponsorshipStableActionID) &&
		canonicalSHA256(record.SponsorshipExactRequestDigest) && record.ConsumedAtUnix > 0
}

func validRelayRouteRecord(record RelayRouteRecord) bool {
	if len(record.Hops) == 0 {
		return false
	}
	maximumServiceFee := record.Hops[0].Attempt.Execution.QuoteRequest.Body.MaximumServiceFee
	singleProvider := len(record.Candidates) == 1 && record.MaximumRouteAttempts == 1 &&
		validRelayProvenance(record.Candidates[0]) &&
		record.Hops[0].Attempt.Execution.QuoteRequest.Body.AssuranceLevel != agentrelay.AssuranceAutonomousDecentralized
	if !canonicalSHA256(record.StableActionID) || !canonicalSHA256(record.ExactRequestDigest) ||
		(!validIndependentRelayProvenance(record.Candidates) && !singleProvider) ||
		len(record.Hops) > maximumRelayRouteHops || record.MaximumRouteAttempts > uint32(len(record.Candidates)) ||
		record.MaximumRouteAttempts > agentrelay.MaxRelayRouteAttempts || record.MaximumRouteAttempts == 0 ||
		uint32(len(record.Hops)) > record.MaximumRouteAttempts ||
		record.ServiceFeeAsset != maximumServiceFee.Asset ||
		record.MaximumCumulativeServiceFeeAtomic != maximumServiceFee.AmountAtomic ||
		record.CreatedAtUnix == 0 || record.UpdatedAtUnix < record.CreatedAtUnix {
		return false
	}
	used := map[string]bool{}
	cumulativeServiceFee := "0"
	for index, hop := range record.Hops {
		digest, err := agentrelay.RelayExecutionRequestDigest(hop.Attempt.Execution)
		fee, feeAsset, feeErr := relayAttemptServiceFee(hop.Attempt)
		nextCumulativeFee, addFeeErr := addRelayAtomic(cumulativeServiceFee, fee)
		pastHop := index+1 < len(record.Hops)
		hasFinalityGate := hop.FailoverFinalityEvidenceDigest != "" || hop.FailoverFinalityEvidence != nil
		hasQueryGate := hop.FailoverQueryAttemptDigest != "" || hop.FailoverQueryAttempt != nil
		if err != nil || hop.Generation != uint64(index+1) || digest != hop.RelayExecutionDigest ||
			feeErr != nil || addFeeErr != nil || feeAsset != record.ServiceFeeAsset ||
			hop.Attempt.Execution.AdmissionReceipt.Body.RouteAttempt != uint32(index+1) ||
			agentrelay.VerifyRelaySideEffectAdmissionReceiptIntegrity(
				hop.Attempt.Execution.AdmissionReceipt, hop.Attempt.Execution) != nil ||
			!containsRelayProvenance(record.Candidates, hop.Provider) ||
			hop.Attempt.Execution.AuthorizedAction.StableActionID != record.StableActionID ||
			hop.Attempt.Execution.AuthorizedAction.ExactRequestDigest != record.ExactRequestDigest ||
			hop.Attempt.Execution.ProviderQuote.Body.ProviderAgentID != hop.Provider.ProviderAgentID ||
			used[relayProvenanceKey(hop.Provider)] ||
			!validStoredRelayTerminalShape(record, hop, pastHop && hasFinalityGate) ||
			pastHop && (hasFinalityGate == hasQueryGate) || !pastHop && hasFinalityGate ||
			(hasFinalityGate && (hop.FailoverFinalityEvidenceDigest == "" ||
				hop.FailoverFinalityEvidence == nil || !validStoredRelayFailoverEvidence(record, hop))) ||
			(hasQueryGate && (hop.FailoverQueryAttemptDigest == "" || hop.FailoverQueryAttempt == nil ||
				!validStoredRelayResolveQuery(record, hop))) {
			return false
		}
		cumulativeServiceFee = nextCumulativeFee
		if index > 0 && !sameRelayExecutionBaseIdentity(record.Hops[0].Attempt.Execution, hop.Attempt.Execution) {
			return false
		}
		if index > 0 && !validRelayAdmissionSuccessor(
			record.Hops[index-1].Attempt.Execution.AdmissionReceipt, hop.Attempt.Execution) {
			return false
		}
		used[relayProvenanceKey(hop.Provider)] = true
	}
	if cumulativeServiceFee != record.CumulativeServiceFeeAtomic ||
		compareRelayAtomic(cumulativeServiceFee, record.MaximumCumulativeServiceFeeAtomic) > 0 {
		return false
	}
	if record.PendingSwitch != nil && !validRelayPendingSwitch(record, used) {
		return false
	}
	return true
}

func validRelayResolveQueryAttempt(record RelayRouteRecord, hop RelayRouteHop,
	attempt relayRouteResolveQueryAttempt) bool {
	networkDigest, networkErr := agentrelay.NetworkDomainDigest(hop.Attempt.Execution.QuoteRequest.Body.Network)
	transactionDigest, transactionErr := agentrelay.RelayTransactionIdentityDigest(hop.Attempt.Execution.QuoteRequest.Body)
	authDigest, authErr := relayTransportAuthenticationDigest(hop.Provider,
		hop.Attempt.Execution.AdmissionReceipt.Body.AuthenticatedPrincipal)
	if networkErr != nil || transactionErr != nil || authErr != nil || attempt.SchemaVersion != 1 ||
		hop.Attempt.Execution.QuoteRequest.Body.Mode != agentrelay.ModeRelayExact || !hop.SubmitStarted ||
		hop.TerminalResolution != nil || hop.TerminalResolutionDigest != "" ||
		hop.TerminalFinalityEvidence != nil || hop.TerminalFinalityEvidenceDigest != "" ||
		attempt.RouteGeneration != hop.Generation || attempt.ProviderAgentID != hop.Provider.ProviderAgentID ||
		attempt.ProviderProfileDigest != hop.Provider.ProfileDigest ||
		attempt.AuthenticatedPrincipal != hop.Attempt.Execution.AdmissionReceipt.Body.AuthenticatedPrincipal ||
		attempt.TransportAuthenticationDigest != authDigest ||
		attempt.NetworkDigest != networkDigest || attempt.TransactionIdentityDigest != transactionDigest ||
		attempt.StableActionID != record.StableActionID || attempt.ExactRequestDigest != record.ExactRequestDigest ||
		attempt.RelayExecutionDigest != hop.RelayExecutionDigest || attempt.StartedAtUnix < record.CreatedAtUnix ||
		attempt.StartedAtUnix < hop.Attempt.Execution.CreatedAtUnix ||
		attempt.CompletedAtUnix < attempt.StartedAtUnix {
		return false
	}
	switch attempt.Outcome {
	case relayResolveRemoteUnknown, relayResolveUnavailable:
		return attempt.Resolution == nil && attempt.ResolutionDigest == ""
	case relayResolveAmbiguous:
		if attempt.Resolution == nil || attempt.ResolutionDigest == "" ||
			attempt.Resolution.Body.State == commerce.ActionTerminal {
			return false
		}
		digest, err := agentrelay.RelayResolutionDigest(attempt.Resolution.Body)
		body := attempt.Resolution.Body
		return err == nil && digest == attempt.ResolutionDigest && body.ProviderAgentID == hop.Provider.ProviderAgentID &&
			body.Network == hop.Attempt.Execution.QuoteRequest.Body.Network && body.StableActionID == record.StableActionID &&
			body.ExactRequestDigest == record.ExactRequestDigest && body.RelayExecutionDigest == hop.RelayExecutionDigest
	default:
		return false
	}
}

func validStoredRelayResolveQuery(record RelayRouteRecord, hop RelayRouteHop) bool {
	if hop.FailoverQueryAttempt == nil || hop.FailoverQueryAttemptDigest == "" ||
		!validRelayResolveQueryAttempt(record, hop, *hop.FailoverQueryAttempt) ||
		hop.FailoverQueryAttempt.CompletedAtUnix > record.UpdatedAtUnix {
		return false
	}
	digest, err := relayRouteResolveQueryAttemptDigest(*hop.FailoverQueryAttempt)
	return err == nil && digest == hop.FailoverQueryAttemptDigest
}

// relayHopFailoverGate returns the single durable gate that may authorize an
// exact-transaction route successor. Finalized non-execution remains the
// strongest gate; a completed authenticated query is sufficient only because
// relay_exact successors carry byte-identical transaction identity and cannot
// sponsor or create a second semantic payment.
func relayHopFailoverGate(record RelayRouteRecord, hop RelayRouteHop) (string, string, bool) {
	hasFinality := hop.TerminalResolution != nil && hop.TerminalFinalityEvidence != nil &&
		hop.TerminalResolutionDigest != "" && hop.TerminalFinalityEvidenceDigest != "" &&
		validStoredRelayTerminalShape(record, hop, false) &&
		safeRelayFailoverOutcome(hop.TerminalFinalityEvidence.Body.Outcome) &&
		relayEvidenceProvesNoSponsorshipOrClientTransaction(hop.TerminalFinalityEvidence.Body) &&
		relayFailoverEvidenceMatchesMode(hop.TerminalFinalityEvidence.Body, agentrelay.ModeRelayExact)
	hasQuery := validStoredRelayResolveQuery(record, hop)
	if hasFinality == hasQuery {
		return "", "", false
	}
	if hasFinality {
		return relayFailoverGateFinality, hop.TerminalFinalityEvidenceDigest, true
	}
	return relayFailoverGateQuery, hop.FailoverQueryAttemptDigest, true
}

func validRelayPendingSwitch(record RelayRouteRecord, used map[string]bool) bool {
	pending := record.PendingSwitch
	current := record.Hops[len(record.Hops)-1]
	digest, err := agentrelay.RelayExecutionRequestDigest(pending.Attempt.Execution)
	gateKind, gateDigest, gateOK := relayHopFailoverGate(record, current)
	serviceFee, feeAsset, feeErr := relayAttemptServiceFee(pending.Attempt)
	cumulativeAfter, cumulativeErr := addRelayAtomic(record.CumulativeServiceFeeAtomic, serviceFee)
	envelopeDigest, envelopeErr := relayPendingAdmissionEnvelopeDigest(pending.Attempt,
		current.Attempt.Execution.AdmissionReceipt)
	rebaseValid := pending.Rebase == nil
	if pending.Rebase != nil {
		rebaseValid = pending.AdmissionRevision >= 2 && pending.AdmissionStarted &&
			pending.Rebase.Authorization.Body.ResolvedNotFoundAtUnix >= pending.PreparedAtUnix &&
			pending.Rebase.Authorization.Body.ResolvedNotFoundAtUnix <= record.UpdatedAtUnix &&
			verifyRelayAdmissionReauthorization(pending.Rebase.Authorization, pending.Rebase.PriorAttempt,
				pending.Attempt, current.Attempt.Execution.AdmissionReceipt) == nil
	} else {
		rebaseValid = pending.AdmissionRevision == 1 &&
			sameRelayExecutionBaseIdentityWithCredentials(current.Attempt.Execution, pending.Attempt.Execution)
	}
	startedValid := !pending.AdmissionStarted && pending.AdmissionStartedAtUnix == 0 ||
		pending.AdmissionStarted && pending.AdmissionStartedAtUnix >= pending.PreparedAtUnix &&
			pending.AdmissionStartedAtUnix <= record.UpdatedAtUnix
	return err == nil && envelopeErr == nil && envelopeDigest == pending.AdmissionEnvelopeDigest &&
		canonicalSHA256(pending.AdmissionEnvelopeDigest) && pending.AdmissionRevision > 0 && startedValid && rebaseValid &&
		pending.Generation == current.Generation+1 && pending.Generation == uint64(len(record.Hops)+1) &&
		pending.RelayExecutionDigest == digest && relayAttemptHasNoAdmissionReceipt(pending.Attempt) &&
		pending.PreparedAtUnix >= record.CreatedAtUnix && pending.PreparedAtUnix <= record.UpdatedAtUnix &&
		current.Attempt.Execution.QuoteRequest.Body.Mode == agentrelay.ModeRelayExact && current.SubmitStarted &&
		current.FailoverFinalityEvidenceDigest == "" && current.FailoverFinalityEvidence == nil &&
		gateOK && pending.FailoverGateKind == gateKind && pending.FailoverGateDigest == gateDigest &&
		feeErr == nil && cumulativeErr == nil && feeAsset == record.ServiceFeeAsset &&
		pending.CumulativeServiceFeeAtomicAfter == cumulativeAfter &&
		compareRelayAtomic(cumulativeAfter, record.MaximumCumulativeServiceFeeAtomic) <= 0 &&
		uint32(len(record.Hops)) < record.MaximumRouteAttempts &&
		containsRelayProvenance(record.Candidates, pending.Provider) &&
		!used[relayProvenanceKey(pending.Provider)] &&
		pending.Attempt.Execution.ProviderQuote.Body.ProviderAgentID == pending.Provider.ProviderAgentID &&
		sameRelayExecutionBaseIdentity(current.Attempt.Execution, pending.Attempt.Execution)
}

func relayUsedProviderSet(hops []RelayRouteHop) map[string]bool {
	used := make(map[string]bool, len(hops))
	for _, hop := range hops {
		used[relayProvenanceKey(hop.Provider)] = true
	}
	return used
}

func validIndependentRelayProvenance(values []RelayProviderProvenance) bool {
	if len(values) < 2 || len(values) > maximumRelayRouteCandidates {
		return false
	}
	operators, failures, origins, certificates, implementations := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	previous := ""
	for _, value := range values {
		key := relayProvenanceKey(value)
		if key <= previous || !validRelayProvenance(value) || operators[value.OperatorDomain] ||
			failures[value.FailureDomain] || origins[value.EndpointOrigin] || certificates[value.CertificatePinDigest] ||
			implementations[value.ImplementationEvidenceHash] {
			return false
		}
		previous = key
		operators[value.OperatorDomain], failures[value.FailureDomain] = true, true
		origins[value.EndpointOrigin], certificates[value.CertificatePinDigest] = true, true
		implementations[value.ImplementationEvidenceHash] = true
	}
	return true
}

func validRelayProvenance(value RelayProviderProvenance) bool {
	return len(value.ProviderAgentID) > 0 && len(value.ProviderAgentID) <= 256 &&
		canonicalSHA256(value.IntentDigest) && canonicalSHA256(value.ProfileDigest) &&
		boundedRelayTrustDomain(value.OperatorDomain) && boundedRelayTrustDomain(value.FailureDomain) &&
		canonicalRelayEndpointOrigin(value.EndpointOrigin) &&
		canonicalSHA256(value.CertificatePinDigest) && canonicalSHA256(value.ImplementationEvidenceHash)
}

func boundedRelayTrustDomain(value string) bool {
	return len(value) > 0 && len(value) <= 256 && strings.TrimSpace(value) == value &&
		!strings.ContainsAny(value, "\x00\r\n\t")
}

func canonicalRelayEndpointOrigin(value string) bool {
	if len(value) == 0 || len(value) > 512 {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.Path == "" &&
		parsed.RawQuery == "" && parsed.Fragment == "" && value == "https://"+strings.ToLower(parsed.Host)
}

func safeRelayFailoverOutcome(outcome agentrelay.TerminalOutcome) bool {
	switch outcome {
	case agentrelay.OutcomeFinalizedAbsent, agentrelay.OutcomeFinalizedExpired, agentrelay.OutcomeFinalizedInvalidated:
		return true
	default:
		return false
	}
}

func validStoredRelayFailoverEvidence(record RelayRouteRecord, hop RelayRouteHop) bool {
	if hop.FailoverFinalityEvidence == nil {
		return false
	}
	digest, err := agentrelay.RelayFinalityEvidenceDigest(hop.FailoverFinalityEvidence.Body)
	body := hop.FailoverFinalityEvidence.Body
	return err == nil && digest == hop.FailoverFinalityEvidenceDigest && body.ProviderAgentID == hop.Provider.ProviderAgentID &&
		body.StableActionID == record.StableActionID && body.ExactRequestDigest == record.ExactRequestDigest &&
		body.RelayExecutionDigest == hop.RelayExecutionDigest &&
		body.Network == hop.Attempt.Execution.QuoteRequest.Body.Network && body.SponsorshipTransferReference == "" &&
		safeRelayFailoverOutcome(body.Outcome) && relayEvidenceProvesNoSponsorshipOrClientTransaction(body) &&
		relayFailoverEvidenceMatchesMode(body, hop.Attempt.Execution.QuoteRequest.Body.Mode)
}

func validStoredRelayTerminalShape(record RelayRouteRecord, hop RelayRouteHop, failoverHop bool) bool {
	hasResolution := hop.TerminalResolution != nil || hop.TerminalResolutionDigest != ""
	hasEvidence := hop.TerminalFinalityEvidence != nil || hop.TerminalFinalityEvidenceDigest != ""
	if hasResolution != hasEvidence || (hop.TerminalResolution == nil) != (hop.TerminalResolutionDigest == "") ||
		(hop.TerminalFinalityEvidence == nil) != (hop.TerminalFinalityEvidenceDigest == "") ||
		failoverHop && !hasResolution || hasResolution && !hop.SubmitStarted {
		return false
	}
	if !hasResolution {
		return true
	}
	resolutionDigest, resolutionErr := agentrelay.RelayResolutionDigest(hop.TerminalResolution.Body)
	evidenceDigest, evidenceErr := agentrelay.RelayFinalityEvidenceDigest(hop.TerminalFinalityEvidence.Body)
	resolution, evidence := hop.TerminalResolution.Body, hop.TerminalFinalityEvidence.Body
	return resolutionErr == nil && evidenceErr == nil && resolutionDigest == hop.TerminalResolutionDigest &&
		evidenceDigest == hop.TerminalFinalityEvidenceDigest && resolution.State == commerce.ActionTerminal &&
		resolution.ProviderAgentID == hop.Provider.ProviderAgentID && resolution.StableActionID == record.StableActionID &&
		resolution.ExactRequestDigest == record.ExactRequestDigest && resolution.RelayExecutionDigest == hop.RelayExecutionDigest &&
		resolution.Network == hop.Attempt.Execution.QuoteRequest.Body.Network &&
		evidence.ProviderAgentID == hop.Provider.ProviderAgentID && evidence.StableActionID == record.StableActionID &&
		evidence.ExactRequestDigest == record.ExactRequestDigest && evidence.RelayExecutionDigest == hop.RelayExecutionDigest &&
		evidence.Network == hop.Attempt.Execution.QuoteRequest.Body.Network &&
		resolution.TerminalOutcome == evidence.Outcome && relayResolutionReferenceMatchesEvidence(resolution, evidence)
}

func relayFailoverEvidenceMatchesMode(body agentrelay.RelayFinalityEvidenceBody, mode agentrelay.Mode) bool {
	if mode == agentrelay.ModeRelayExact {
		return body.SponsorshipStableActionID == "" && body.SponsorshipExactRequestDigest == "" &&
			body.SponsorshipValidUntilUnix == 0 && len(body.SponsorshipAbsenceObservations) == 0
	}
	return canonicalSHA256(body.SponsorshipStableActionID) && canonicalSHA256(body.SponsorshipExactRequestDigest) &&
		body.SponsorshipValidUntilUnix > 0 && len(body.SponsorshipAbsenceObservations) > 0
}

func relayAttemptServiceFee(attempt RelayAttempt) (string, agentrelay.AssetIdentity, error) {
	return relayProviderQuoteServiceFee(attempt.Execution.ProviderQuote)
}

func relayProviderQuoteServiceFee(quote agentrelay.SignedProviderRelayQuote) (string, agentrelay.AssetIdentity, error) {
	lines := quote.Body.FeeLines
	if len(lines) == 0 {
		return "", agentrelay.AssetIdentity{}, errors.New("relay attempt has no service fee")
	}
	asset := lines[0].Amount.Asset
	total := new(big.Int)
	for _, line := range lines {
		value, ok := new(big.Int).SetString(line.Amount.AmountAtomic, 10)
		if !ok || value.Sign() < 0 || line.Amount.Asset != asset {
			return "", agentrelay.AssetIdentity{}, errors.New("relay attempt service fee is invalid")
		}
		total.Add(total, value)
	}
	return total.String(), asset, nil
}

func addRelayAtomic(left, right string) (string, error) {
	a, okA := new(big.Int).SetString(left, 10)
	b, okB := new(big.Int).SetString(right, 10)
	if !okA || !okB || a.Sign() < 0 || b.Sign() < 0 {
		return "", errors.New("relay atomic amount is invalid")
	}
	return new(big.Int).Add(a, b).String(), nil
}

func compareRelayAtomic(left, right string) int {
	a, okA := new(big.Int).SetString(left, 10)
	b, okB := new(big.Int).SetString(right, 10)
	if !okA || !okB || a.Sign() < 0 || b.Sign() < 0 {
		return 1
	}
	return a.Cmp(b)
}

func relayProvenanceKey(value RelayProviderProvenance) string {
	return value.ProviderAgentID + "\x00" + value.IntentDigest + "\x00" + value.ProfileDigest
}

func containsRelayProvenance(values []RelayProviderProvenance, expected RelayProviderProvenance) bool {
	for _, value := range values {
		if sameRelayProvenance(value, expected) {
			return true
		}
	}
	return false
}

func sameRelayProvenance(left, right RelayProviderProvenance) bool {
	return reflect.DeepEqual(left, right)
}

func sameRelayExecutionBaseIdentity(left, right agentrelay.RelayExecutionRequest) bool {
	leftBody, rightBody := left.QuoteRequest.Body, right.QuoteRequest.Body
	leftBody.ProviderAgentID, rightBody.ProviderAgentID = "", ""
	leftBody.RequestID, rightBody.RequestID = "", ""
	return reflect.DeepEqual(leftBody, rightBody) && bytes.Equal(left.SignedTransactionBytes, right.SignedTransactionBytes) &&
		bytes.Equal(left.UnderlyingActionRequest, right.UnderlyingActionRequest) &&
		reflect.DeepEqual(left.SemanticFields, right.SemanticFields) &&
		sameRelayAuthorizedActionContext(left.AuthorizedAction, right.AuthorizedAction) &&
		left.WriterFence.Body.OwnerID == right.WriterFence.Body.OwnerID &&
		left.WriterFence.Body.AgentID == right.WriterFence.Body.AgentID &&
		left.WriterFence.Body.AuthorityID == right.WriterFence.Body.AuthorityID &&
		left.WriterFence.PublicKey == right.WriterFence.PublicKey
}

func sameRelayExecutionBaseIdentityWithCredentials(left, right agentrelay.RelayExecutionRequest) bool {
	return sameRelayExecutionBaseIdentity(left, right) &&
		reflect.DeepEqual(left.AuthorizedAction, right.AuthorizedAction) &&
		reflect.DeepEqual(left.WriterFence, right.WriterFence)
}

func sameRelayAuthorizedActionContext(left, right commerce.AuthorizedAction) bool {
	return left.SchemaVersion == right.SchemaVersion && left.OwnerID == right.OwnerID && left.AgentID == right.AgentID &&
		left.ActionKind == right.ActionKind && left.StableActionID == right.StableActionID &&
		left.ExactRequestDigest == right.ExactRequestDigest && left.PolicyRevision == right.PolicyRevision &&
		left.MandateDigest == right.MandateDigest && left.ApprovalDigest == right.ApprovalDigest &&
		left.ExpectedPriorState == right.ExpectedPriorState && left.AuthorityID == right.AuthorityID &&
		left.AuthorityPublicKey == right.AuthorityPublicKey
}

func relayAttemptHasNoAdmissionReceipt(attempt RelayAttempt) bool {
	return reflect.DeepEqual(attempt.Execution.AdmissionReceipt,
		agentrelay.SignedRelaySideEffectAdmissionReceipt{})
}

func sameRelayAttemptWithoutAdmission(draft, admitted RelayAttempt) bool {
	admitted = cloneRelayAttempt(admitted)
	admitted.Execution.AdmissionReceipt = agentrelay.SignedRelaySideEffectAdmissionReceipt{}
	return relayAttemptHasNoAdmissionReceipt(draft) && reflect.DeepEqual(draft, admitted)
}

func validRelayAdmissionSuccessor(predecessor agentrelay.SignedRelaySideEffectAdmissionReceipt,
	execution agentrelay.RelayExecutionRequest) bool {
	receipt := execution.AdmissionReceipt
	if receipt.Body.IssuedAtUnix == 0 || receipt.Body.IssuedAtUnix > uint64(^uint64(0)>>1) {
		return false
	}
	return agentrelay.VerifyRelaySideEffectAdmissionSuccessorReceipt(receipt, execution, predecessor,
		time.Unix(int64(receipt.Body.IssuedAtUnix), 0).UTC()) == nil
}

func cloneRelayAttempt(attempt RelayAttempt) RelayAttempt {
	raw, _ := json.Marshal(attempt)
	var cloned RelayAttempt
	_ = json.Unmarshal(raw, &cloned)
	return cloned
}

func cloneRelayRouteHop(hop RelayRouteHop) RelayRouteHop {
	hop.Attempt = cloneRelayAttempt(hop.Attempt)
	if hop.TerminalResolution != nil {
		raw, _ := json.Marshal(hop.TerminalResolution)
		var resolution agentrelay.SignedRelayResolution
		_ = json.Unmarshal(raw, &resolution)
		hop.TerminalResolution = &resolution
	}
	if hop.TerminalFinalityEvidence != nil {
		raw, _ := json.Marshal(hop.TerminalFinalityEvidence)
		var evidence agentrelay.SignedRelayFinalityEvidence
		_ = json.Unmarshal(raw, &evidence)
		hop.TerminalFinalityEvidence = &evidence
	}
	if hop.FailoverFinalityEvidence != nil {
		raw, _ := json.Marshal(hop.FailoverFinalityEvidence)
		var evidence agentrelay.SignedRelayFinalityEvidence
		_ = json.Unmarshal(raw, &evidence)
		hop.FailoverFinalityEvidence = &evidence
	}
	if hop.FailoverQueryAttempt != nil {
		attempt := cloneRelayResolveQueryAttempt(*hop.FailoverQueryAttempt)
		hop.FailoverQueryAttempt = &attempt
	}
	return hop
}

func cloneRelayResolveQueryAttempt(attempt relayRouteResolveQueryAttempt) relayRouteResolveQueryAttempt {
	if attempt.Resolution != nil {
		raw, _ := json.Marshal(attempt.Resolution)
		var resolution agentrelay.SignedRelayResolution
		_ = json.Unmarshal(raw, &resolution)
		attempt.Resolution = &resolution
	}
	return attempt
}

func cloneRelayRouteRecord(record RelayRouteRecord) RelayRouteRecord {
	record.Candidates = append([]RelayProviderProvenance(nil), record.Candidates...)
	record.Hops = append([]RelayRouteHop(nil), record.Hops...)
	for index := range record.Hops {
		record.Hops[index] = cloneRelayRouteHop(record.Hops[index])
	}
	if record.PendingSwitch != nil {
		pending := *record.PendingSwitch
		pending.Attempt = cloneRelayAttempt(pending.Attempt)
		if pending.Rebase != nil {
			raw, _ := json.Marshal(pending.Rebase)
			var rebase relayAdmissionRebaseRecord
			_ = json.Unmarshal(raw, &rebase)
			pending.Rebase = &rebase
		}
		record.PendingSwitch = &pending
	}
	return record
}

func cloneRelayRouteRecords(input map[string]RelayRouteRecord) map[string]RelayRouteRecord {
	output := make(map[string]RelayRouteRecord, len(input))
	for key, record := range input {
		output[key] = cloneRelayRouteRecord(record)
	}
	return output
}
