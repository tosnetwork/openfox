package earning

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/tosnetwork/openfox/pkg/fileutil"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

const (
	authoritySchema = "tos.openfox.owner-economic-action-authority.v1"
	authorityFile   = "economic-authority.json"
	authorityLock   = "economic-authority.lock"
)

type ExposureReservation struct {
	ReservationID       string `json:"reservation_id"`
	AgreementDigest     string `json:"agreement_digest"`
	ComputeUnits        uint64 `json:"compute_units"`
	SpendAtomic         uint64 `json:"spend_atomic"`
	LockedCapitalAtomic uint64 `json:"locked_capital_atomic"`
	ReceivableAtomic    uint64 `json:"receivable_atomic"`
	MaximumLossAtomic   uint64 `json:"maximum_loss_atomic"`
	Released            bool   `json:"released"`
}

func (authority *PersonalAuthority) AuthorizeCustodyPayment(action commerce.AuthorizedAction,
	fields map[string]commerce.SemanticValue, canonicalRequest []byte, fence commerce.WriterFence,
	payment commerce.AgreementPaymentRequest, sourceAccount string, networkGlobalID int32) (commerce.CustodyActionAuthorization, error) {
	if authority == nil || sourceAccount == "" || networkGlobalID == 0 {
		return commerce.CustodyActionAuthorization{}, errors.New("custody payment binding is incomplete")
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if authority.doc.CurrentFence == nil || fence.Body.WriterGeneration != authority.doc.WriterGeneration || fence.Body.LeaseID != authority.doc.CurrentFence.Body.LeaseID {
		return commerce.CustodyActionAuthorization{}, errors.New("stale writer cannot authorize custody")
	}
	resolver := localFenceResolver{authorityID: authority.doc.AuthorityID, key: authority.key.Public().(ed25519.PublicKey)}
	if action.ActionKind != "payment.direct" || action.StableActionID != payment.StableActionID ||
		commerce.VerifyAuthorizedAction(action, fields, canonicalRequest, fence, resolver, authority.now().UTC()) != nil {
		return commerce.CustodyActionAuthorization{}, errors.New("custody payment is not the exact authorized action")
	}
	prior, found := authority.doc.Actions[action.StableActionID]
	if !found || prior.ExactRequestDigest != action.ExactRequestDigest || prior.State != commerce.ActionPrepared {
		return commerce.CustodyActionAuthorization{}, errors.New("custody payment has no prepared authority record")
	}
	amount, err := strconv.ParseUint(payment.Amount.AmountAtomic, 10, 64)
	if err != nil || amount == 0 {
		return commerce.CustodyActionAuthorization{}, errors.New("native custody amount exceeds uint64")
	}
	fenceDigest, err := commerce.WriterFenceDigest(fence)
	if err != nil {
		return commerce.CustodyActionAuthorization{}, err
	}
	approval := action.ApprovalDigest
	if approval == "" {
		approval = zeroSHA256Digest()
	}
	body := commerce.CustodyActionAuthorization{SchemaVersion: 1, AuthorityID: authority.doc.AuthorityID,
		OwnerID: authority.doc.OwnerID, AgentID: authority.doc.AgentID, SourceAccount: sourceAccount,
		NetworkID: payment.NetworkID, NetworkGlobalID: networkGlobalID, StableActionID: action.StableActionID,
		ExactRequestDigest: action.ExactRequestDigest, WriterGeneration: action.WriterGeneration, WriterFenceDigest: fenceDigest,
		PolicyRevision: action.PolicyRevision, MandateDigest: action.MandateDigest, ApprovalDigestOrZero: approval,
		AgreementBodyDigest: payment.AgreementBodyDigest, ObligationInstanceID: payment.ObligationInstanceID,
		Destination: string(payment.Destination), AmountAtomic: amount, ExpiresAtUnix: action.ExpiresAtUnix}
	return commerce.SignCustodyActionAuthorization(body, authority.key)
}

// AuthorizeCustodyEffect turns an already admitted semantic action into a
// purpose-limited custody capability for one exact TVM effect. The caller may
// describe the contract effect, but cannot choose the authority identity,
// writer generation, policy, mandate, approval or semantic action identity.
func (authority *PersonalAuthority) AuthorizeCustodyEffect(action commerce.AuthorizedAction,
	fields map[string]commerce.SemanticValue, canonicalRequest []byte, fence commerce.WriterFence,
	template commerce.CustodyEffectAuthorization) (commerce.CustodyEffectAuthorization, error) {
	if authority == nil {
		return commerce.CustodyEffectAuthorization{}, errors.New("custody effect authority is unavailable")
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	now := authority.now().UTC()
	if authority.doc.CurrentFence == nil || fence.Body.WriterGeneration != authority.doc.WriterGeneration ||
		fence.Body.LeaseID != authority.doc.CurrentFence.Body.LeaseID {
		return commerce.CustodyEffectAuthorization{}, errors.New("stale writer cannot authorize custody effect")
	}
	resolver := localFenceResolver{authorityID: authority.doc.AuthorityID, key: authority.key.Public().(ed25519.PublicKey)}
	if action.ActionKind != "escrow.transition" ||
		commerce.VerifyAuthorizedAction(action, fields, canonicalRequest, fence, resolver, now) != nil {
		return commerce.CustodyEffectAuthorization{}, errors.New("custody effect is not the exact authorized action")
	}
	prior, found := authority.doc.Actions[action.StableActionID]
	if !found || prior.ExactRequestDigest != action.ExactRequestDigest || prior.State != commerce.ActionPrepared {
		return commerce.CustodyEffectAuthorization{}, errors.New("custody effect has no prepared authority record")
	}
	fenceDigest, err := commerce.WriterFenceDigest(fence)
	if err != nil {
		return commerce.CustodyEffectAuthorization{}, err
	}
	approval := action.ApprovalDigest
	if approval == "" {
		approval = zeroSHA256Digest()
	}
	template.SchemaVersion = 1
	template.AuthorityID = authority.doc.AuthorityID
	template.OwnerID = authority.doc.OwnerID
	template.AgentID = authority.doc.AgentID
	template.StableActionID = action.StableActionID
	template.ExactRequestDigest = action.ExactRequestDigest
	template.WriterGeneration = action.WriterGeneration
	template.WriterFenceDigest = fenceDigest
	template.PolicyRevision = action.PolicyRevision
	template.MandateDigest = action.MandateDigest
	template.ApprovalDigestOrZero = approval
	template.ExpiresAtUnix = minUint64(template.ExpiresAtUnix, action.ExpiresAtUnix)
	return commerce.SignCustodyEffectAuthorization(template, authority.key)
}

type PortfolioLimits struct {
	ComputeUnits        uint64 `json:"compute_units"`
	SpendAtomic         uint64 `json:"spend_atomic"`
	LockedCapitalAtomic uint64 `json:"locked_capital_atomic"`
	ReceivableAtomic    uint64 `json:"receivable_atomic"`
	MaximumLossAtomic   uint64 `json:"maximum_loss_atomic"`
}

type PortfolioReleaseRequest struct {
	ReservationID             string `json:"reservation_id"`
	AgreementDigest           string `json:"agreement_digest"`
	TargetPortfolioRevision   uint64 `json:"target_portfolio_revision"`
	TerminalEvidenceSetDigest string `json:"terminal_evidence_set_digest"`
}

type EngagementState string

const (
	EngagementProposed              EngagementState = "proposed"
	EngagementAuthorizing           EngagementState = "authorizing"
	EngagementAgreed                EngagementState = "agreed"
	EngagementReserved              EngagementState = "reserved"
	EngagementFundingPending        EngagementState = "funding_pending"
	EngagementReady                 EngagementState = "ready"
	EngagementExecutionPrepared     EngagementState = "execution_prepared"
	EngagementExecuting             EngagementState = "executing"
	EngagementExecutionSucceeded    EngagementState = "execution_succeeded"
	EngagementDelivered             EngagementState = "delivered"
	EngagementSettling              EngagementState = "settling"
	EngagementSettled               EngagementState = "settled"
	EngagementUnpaid                EngagementState = "unpaid"
	EngagementCancellationResolving EngagementState = "cancellation_resolving"
	EngagementCancelled             EngagementState = "cancelled"
	EngagementFailed                EngagementState = "failed"
	EngagementAmbiguous             EngagementState = "ambiguous"
)

type EngagementRecord struct {
	Agreement                commerce.AgentAgreement                 `json:"agreement"`
	AgreementDigest          string                                  `json:"agreement_digest"`
	ProposerAgentID          string                                  `json:"proposer_agent_id"`
	ProposalEventID          string                                  `json:"proposal_event_id"`
	ProposalActionID         string                                  `json:"proposal_action_id"`
	State                    EngagementState                         `json:"state"`
	StateRevision            uint64                                  `json:"state_revision"`
	ReservationID            string                                  `json:"reservation_id,omitempty"`
	ExecutionID              string                                  `json:"execution_id,omitempty"`
	FundingEvidence          []string                                `json:"funding_evidence,omitempty"`
	ExecutionEvidence        []string                                `json:"execution_evidence,omitempty"`
	DeliveryEvidence         []string                                `json:"delivery_evidence,omitempty"`
	DeliveryEventID          string                                  `json:"delivery_event_id,omitempty"`
	SettlementEvidence       []string                                `json:"settlement_evidence,omitempty"`
	AcceptedPrivateInputs    []commerce.AcceptedPrivateContentRecord `json:"accepted_private_inputs,omitempty"`
	BoundPrivateInputs       []BoundAcceptedPrivateInput             `json:"bound_private_inputs,omitempty"`
	PrivateHandoffChallenges []BoundPrivateHandoffChallenge          `json:"private_handoff_challenges,omitempty"`
	// ObligationRuntime is the durable, obligation-scoped execution and
	// settlement projection. Agreement is still the authority; this map only
	// records verified progress and must contain exactly one entry for every
	// canonical Agreement obligation.
	ObligationRuntime    map[string]ObligationRuntimeRecord `json:"obligation_runtime,omitempty"`
	LastTransitionAtUnix uint64                             `json:"last_transition_at_unix"`
}

type SettlementLedgerRecord struct {
	Obligation commerce.SettlementObligation      `json:"obligation"`
	State      commerce.SettlementObligationState `json:"state"`
}

type authorityDocument struct {
	Schema               string                                      `json:"schema"`
	OwnerID              string                                      `json:"owner_id"`
	AgentID              string                                      `json:"agent_id"`
	AuthorityID          string                                      `json:"authority_id"`
	WriterGeneration     uint64                                      `json:"writer_generation"`
	CurrentFence         *commerce.WriterFence                       `json:"current_fence,omitempty"`
	Actions              map[string]commerce.ActionResolution        `json:"actions"`
	AuthorityInstances   map[string]commerce.AuthorityInstanceRecord `json:"authority_instances"`
	NextInstanceSequence uint64                                      `json:"next_instance_sequence"`
	PortfolioRevision    uint64                                      `json:"portfolio_revision"`
	Limits               PortfolioLimits                             `json:"limits"`
	Reservations         map[string]ExposureReservation              `json:"reservations"`
	ScheduleEntries      map[string]commerce.EngagementScheduleEntry `json:"schedule_entries"`
	Dependencies         []commerce.PortfolioDependency              `json:"portfolio_dependencies"`
	Engagements          map[string]EngagementRecord                 `json:"engagements"`
	SettlementLedger     map[string]SettlementLedgerRecord           `json:"settlement_ledger"`
	Accounting           map[string]AccountingEntry                  `json:"accounting"`
}

type PersonalAuthority struct {
	mu   sync.Mutex
	path string
	lock *os.File
	key  ed25519.PrivateKey
	doc  authorityDocument
	now  func() time.Time
}

func (authority *PersonalAuthority) AuthorityNow() time.Time {
	if authority == nil {
		return time.Time{}
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	return authority.now().UTC()
}

func OpenPersonalAuthority(directory, ownerID, agentID, authorityID string, key ed25519.PrivateKey, limits PortfolioLimits) (*PersonalAuthority, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || ownerID == "" || agentID == "" || authorityID == "" || len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("personal authority configuration is invalid")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return nil, errors.New("personal authority directory must be owner-private")
	}
	lock, err := acquireAuthorityLock(directory)
	if err != nil {
		return nil, err
	}
	authority := &PersonalAuthority{path: filepath.Join(directory, authorityFile), lock: lock, key: append(ed25519.PrivateKey(nil), key...), now: time.Now}
	authority.doc = authorityDocument{Schema: authoritySchema, OwnerID: ownerID, AgentID: agentID, AuthorityID: authorityID,
		Actions: map[string]commerce.ActionResolution{}, AuthorityInstances: map[string]commerce.AuthorityInstanceRecord{},
		NextInstanceSequence: 1, PortfolioRevision: 1, Limits: limits, Reservations: map[string]ExposureReservation{},
		ScheduleEntries: map[string]commerce.EngagementScheduleEntry{}}
	authority.doc.Engagements = map[string]EngagementRecord{}
	authority.doc.SettlementLedger = map[string]SettlementLedgerRecord{}
	authority.doc.Accounting = map[string]AccountingEntry{}
	if _, err := os.Lstat(authority.path); errors.Is(err, os.ErrNotExist) {
		if err := authority.persist(authority.doc); err != nil {
			_ = releaseAuthorityLock(lock)
			return nil, err
		}
	} else if err != nil {
		_ = releaseAuthorityLock(lock)
		return nil, err
	} else if err := authority.load(ownerID, agentID, authorityID); err != nil {
		_ = releaseAuthorityLock(lock)
		return nil, err
	}
	return authority, nil
}

func (authority *PersonalAuthority) Close() error {
	if authority == nil {
		return nil
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if authority.lock == nil {
		return nil
	}
	err := releaseAuthorityLock(authority.lock)
	authority.lock = nil
	for index := range authority.key {
		authority.key[index] = 0
	}
	return err
}

func (authority *PersonalAuthority) AcquireWriter(_ context.Context, instanceID string, scope []string, ttl time.Duration) (commerce.WriterFence, error) {
	if authority == nil || instanceID == "" || ttl < time.Second || ttl > 24*time.Hour {
		return commerce.WriterFence{}, errors.New("writer acquisition is invalid")
	}
	scope = append([]string(nil), scope...)
	sort.Strings(scope)
	authority.mu.Lock()
	defer authority.mu.Unlock()
	now := authority.now().UTC()
	next := cloneAuthorityDocument(authority.doc)
	if next.WriterGeneration == ^uint64(0) {
		return commerce.WriterFence{}, errors.New("writer generation exhausted")
	}
	next.WriterGeneration++
	leaseID, err := randomIdentifier("lease:")
	if err != nil {
		return commerce.WriterFence{}, err
	}
	fence, err := commerce.SignWriterFence(commerce.WriterFenceBody{SchemaVersion: 1, OwnerID: next.OwnerID, AgentID: next.AgentID,
		InstanceID: instanceID, LeaseID: leaseID, WriterGeneration: next.WriterGeneration, IssuedAtUnix: uint64(now.Unix()),
		ExpiresAtUnix: uint64(now.Add(ttl).Unix()), AuthorityID: next.AuthorityID, Scope: scope}, authority.key)
	if err != nil {
		return commerce.WriterFence{}, err
	}
	next.CurrentFence = &fence
	if err := authority.persist(next); err != nil {
		return commerce.WriterFence{}, err
	}
	authority.doc = next
	return fence, nil
}

func (authority *PersonalAuthority) Admit(action commerce.AuthorizedAction, fields map[string]commerce.SemanticValue, request []byte,
	fence commerce.WriterFence, reservation *ExposureReservation) (commerce.ActionResolution, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	now := authority.now().UTC()
	if authority.doc.CurrentFence == nil || authority.doc.CurrentFence.Body.WriterGeneration != authority.doc.WriterGeneration ||
		fence.Body.WriterGeneration != authority.doc.WriterGeneration || fence.Body.LeaseID != authority.doc.CurrentFence.Body.LeaseID {
		return commerce.ActionResolution{}, errors.New("stale writer cannot admit an action")
	}
	resolver := localFenceResolver{authorityID: authority.doc.AuthorityID, key: authority.key.Public().(ed25519.PublicKey)}
	if err := commerce.VerifyAuthorizedAction(action, fields, request, fence, resolver, now); err != nil {
		return commerce.ActionResolution{}, err
	}
	if existing, found := authority.doc.Actions[action.StableActionID]; found {
		if existing.ExactRequestDigest != action.ExactRequestDigest {
			return commerce.ActionResolution{StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest,
				State: commerce.ActionConflict, StateRevision: existing.StateRevision + 1}, errors.New("semantic action identity conflicts with prior request")
		}
		return existing, nil
	}
	next := cloneAuthorityDocument(authority.doc)
	if reservation != nil {
		if err := admitReservation(next, *reservation); err != nil {
			return commerce.ActionResolution{}, err
		}
		next.Reservations[reservation.ReservationID] = *reservation
		next.PortfolioRevision++
	}
	resolution := commerce.ActionResolution{StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest,
		State: commerce.ActionPrepared, StateRevision: 1}
	next.Actions[action.StableActionID] = resolution
	if err := authority.persist(next); err != nil {
		return commerce.ActionResolution{}, err
	}
	authority.doc = next
	return resolution, nil
}

func (authority *PersonalAuthority) Resolve(stableActionID, requestDigest string) commerce.ActionResolution {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	resolution, found := authority.doc.Actions[stableActionID]
	if !found {
		return commerce.ActionResolution{StableActionID: stableActionID, ExactRequestDigest: requestDigest, State: commerce.ActionUnknown, StateRevision: 1}
	}
	if resolution.ExactRequestDigest != requestDigest {
		return commerce.ActionResolution{StableActionID: stableActionID, ExactRequestDigest: requestDigest, State: commerce.ActionConflict,
			StateRevision: resolution.StateRevision + 1}
	}
	return resolution
}

func (authority *PersonalAuthority) Transition(stableActionID, requestDigest string, state commerce.ActionResolutionState,
	sinkReference string, evidence []string) (commerce.ActionResolution, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	existing, found := authority.doc.Actions[stableActionID]
	if !found || existing.ExactRequestDigest != requestDigest {
		return commerce.ActionResolution{}, errors.New("action transition has no exact admitted predecessor")
	}
	if existing.State == commerce.ActionTerminal || existing.State == commerce.ActionRejected || existing.State == commerce.ActionConflict {
		return commerce.ActionResolution{}, errors.New("terminal action cannot transition")
	}
	next := cloneAuthorityDocument(authority.doc)
	resolution := existing
	resolution.State, resolution.SinkReference, resolution.EvidenceRefs = state, sinkReference, append([]string(nil), evidence...)
	resolution.StateRevision++
	if err := commerce.ValidateActionResolution(resolution); err != nil {
		return commerce.ActionResolution{}, err
	}
	next.Actions[stableActionID] = resolution
	if err := authority.persist(next); err != nil {
		return commerce.ActionResolution{}, err
	}
	authority.doc = next
	return resolution, nil
}

func (authority *PersonalAuthority) AllocateInstance(request commerce.AuthorityInstanceAllocationRequest,
	fence commerce.WriterFence) (commerce.AuthorityInstanceRecord, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if authority.doc.CurrentFence == nil || fence.Body.WriterGeneration != authority.doc.WriterGeneration ||
		fence.Body.LeaseID != authority.doc.CurrentFence.Body.LeaseID {
		return commerce.AuthorityInstanceRecord{}, errors.New("stale writer cannot allocate an authority instance")
	}
	digest, err := commerce.AuthorityInstanceAllocationRequestDigest(request)
	if err != nil {
		return commerce.AuthorityInstanceRecord{}, err
	}
	if existing, found := authority.doc.AuthorityInstances[digest]; found {
		return existing, nil
	}
	next := cloneAuthorityDocument(authority.doc)
	sequence := next.NextInstanceSequence
	identifier, err := commerce.DeriveAuthorityInstanceID(request, sequence)
	if err != nil {
		return commerce.AuthorityInstanceRecord{}, err
	}
	record := commerce.AuthorityInstanceRecord{RequestDigest: digest, AllocationSequence: sequence, AuthorityInstanceID: identifier,
		PolicyRevision: next.PortfolioRevision}
	next.AuthorityInstances[digest] = record
	next.NextInstanceSequence++
	if err := authority.persist(next); err != nil {
		return commerce.AuthorityInstanceRecord{}, err
	}
	authority.doc = next
	return record, nil
}

func (authority *PersonalAuthority) Snapshot() (uint64, PortfolioLimits, []ExposureReservation) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	reservations := make([]ExposureReservation, 0, len(authority.doc.Reservations))
	for _, reservation := range authority.doc.Reservations {
		reservations = append(reservations, reservation)
	}
	sort.Slice(reservations, func(i, j int) bool { return reservations[i].ReservationID < reservations[j].ReservationID })
	return authority.doc.PortfolioRevision, authority.doc.Limits, reservations
}

// ReleaseReservation admits portfolio.release and applies it in one journal
// transaction. A fence alone cannot release economic capacity.
func (authority *PersonalAuthority) ReleaseReservation(action commerce.AuthorizedAction,
	fields map[string]commerce.SemanticValue, request []byte, fence commerce.WriterFence) (commerce.ActionResolution, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if authority.doc.CurrentFence == nil || fence.Body.WriterGeneration != authority.doc.WriterGeneration ||
		fence.Body.LeaseID != authority.doc.CurrentFence.Body.LeaseID || !authority.now().UTC().Before(time.Unix(int64(fence.Body.ExpiresAtUnix), 0)) {
		return commerce.ActionResolution{}, errors.New("stale writer cannot release a reservation")
	}
	resolver := localFenceResolver{authorityID: authority.doc.AuthorityID, key: authority.key.Public().(ed25519.PublicKey)}
	if action.ActionKind != "portfolio.release" || commerce.VerifyAuthorizedAction(action, fields, request, fence, resolver, authority.now().UTC()) != nil {
		return commerce.ActionResolution{}, errors.New("portfolio release action is not authorized")
	}
	if prior, found := authority.doc.Actions[action.StableActionID]; found {
		if prior.ExactRequestDigest != action.ExactRequestDigest {
			return commerce.ActionResolution{}, errors.New("portfolio release identity conflicts")
		}
		return prior, nil
	}
	var release PortfolioReleaseRequest
	if err := codec.Unmarshal(request, &release); err != nil || release.TargetPortfolioRevision != authority.doc.PortfolioRevision+1 {
		return commerce.ActionResolution{}, errors.New("portfolio release request or target revision is invalid")
	}
	existing, found := authority.doc.Reservations[release.ReservationID]
	if !found || existing.AgreementDigest != release.AgreementDigest || existing.Released {
		return commerce.ActionResolution{}, errors.New("portfolio reservation does not match or is already released")
	}
	next := cloneAuthorityDocument(authority.doc)
	existing.Released = true
	next.Reservations[release.ReservationID] = existing
	next.PortfolioRevision++
	resolution := commerce.ActionResolution{StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest,
		State: commerce.ActionTerminal, EvidenceRefs: []string{release.TerminalEvidenceSetDigest}, StateRevision: 1}
	if err := commerce.ValidateActionResolution(resolution); err != nil {
		return commerce.ActionResolution{}, err
	}
	next.Actions[action.StableActionID] = resolution
	if err := authority.persist(next); err != nil {
		return commerce.ActionResolution{}, err
	}
	authority.doc = next
	return resolution, nil
}

func (authority *PersonalAuthority) load(ownerID, agentID, authorityID string) error {
	info, err := os.Lstat(authority.path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > 32<<20 {
		return errors.New("personal authority journal is not an owner-only bounded regular file")
	}
	raw, err := os.ReadFile(authority.path)
	if err != nil {
		return err
	}
	var document authorityDocument
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&document) != nil || document.Schema != authoritySchema || document.OwnerID != ownerID || document.AgentID != agentID ||
		document.AuthorityID != authorityID || document.PortfolioRevision == 0 || document.NextInstanceSequence == 0 || document.Actions == nil ||
		document.AuthorityInstances == nil || document.Reservations == nil {
		return errors.New("personal authority journal is invalid")
	}
	if document.ScheduleEntries == nil {
		document.ScheduleEntries = map[string]commerce.EngagementScheduleEntry{}
	}
	if document.Engagements == nil {
		document.Engagements = map[string]EngagementRecord{}
	}
	if document.SettlementLedger == nil {
		document.SettlementLedger = map[string]SettlementLedgerRecord{}
	}
	if document.Accounting == nil {
		document.Accounting = map[string]AccountingEntry{}
	}
	if err := commerce.ValidatePortfolioDependencies(document.Dependencies); err != nil {
		return errors.New("personal authority dependency graph is invalid")
	}
	for _, entry := range document.ScheduleEntries {
		if err := commerce.ValidateScheduleEntry(entry); err != nil {
			return errors.New("personal authority schedule is invalid")
		}
	}
	for digest, engagement := range document.Engagements {
		initializeObligationRuntime(&engagement)
		computed, err := commerce.AgreementBodyDigest(engagement.Agreement.Body)
		if err != nil || computed != digest || engagement.AgreementDigest != digest || engagement.StateRevision == 0 ||
			engagement.LastTransitionAtUnix == 0 || !knownEngagementState(engagement.State) {
			return errors.New("personal authority engagement ledger is invalid")
		}
		if err := validateObligationRuntime(engagement); err != nil {
			return err
		}
		for _, accepted := range engagement.AcceptedPrivateInputs {
			if commerce.ValidateAcceptedPrivateContent(accepted) != nil {
				return errors.New("personal authority accepted private input is invalid")
			}
		}
		for _, bound := range engagement.BoundPrivateInputs {
			if bound.ObligationID == "" || commerce.ValidateAcceptedPrivateContent(bound.Record) != nil {
				return errors.New("personal authority obligation-bound private input is invalid")
			}
			if _, found := obligationByID(engagement, bound.ObligationID); !found {
				return errors.New("personal authority private input names an absent obligation")
			}
		}
		for index, challenge := range engagement.PrivateHandoffChallenges {
			if challenge.ObligationID == "" || !canonicalSHA256(challenge.ChallengeDigest) || !canonicalSHA256(challenge.SendActionID) ||
				index > 0 && engagement.PrivateHandoffChallenges[index-1].ObligationID >= challenge.ObligationID {
				return errors.New("personal authority private handoff challenge binding is invalid")
			}
			if obligation, found := obligationByID(engagement, challenge.ObligationID); !found ||
				obligation.BeneficiaryAgentID != document.AgentID || !containsString(obligation.RequiredExtensions, "tos.private-handoff.v1") {
				return errors.New("personal authority private handoff challenge names an unauthorized obligation")
			}
		}
		document.Engagements[digest] = engagement
	}
	for instanceID, settlement := range document.SettlementLedger {
		if settlement.Obligation.ObligationInstanceID != instanceID || commerce.ValidateSettlementObligation(settlement.Obligation) != nil ||
			commerce.ValidateSettlementState(settlement.State) != nil {
			return errors.New("personal authority settlement ledger is invalid")
		}
	}
	for entryID, entry := range document.Accounting {
		computed, err := AccountingEntryID(entry.Body)
		if err != nil || computed != entryID || entry.EntryID != entryID || entry.WriterGeneration == 0 {
			return errors.New("personal authority accounting ledger is invalid")
		}
	}
	authority.doc = document
	return nil
}

func knownEngagementState(state EngagementState) bool {
	switch state {
	case EngagementProposed, EngagementAuthorizing, EngagementAgreed, EngagementReserved, EngagementFundingPending,
		EngagementReady, EngagementExecutionPrepared, EngagementExecuting, EngagementExecutionSucceeded, EngagementDelivered, EngagementSettling,
		EngagementSettled, EngagementUnpaid, EngagementCancellationResolving, EngagementCancelled, EngagementFailed,
		EngagementAmbiguous:
		return true
	default:
		return false
	}
}

func (authority *PersonalAuthority) persist(document authorityDocument) error {
	raw, err := json.Marshal(document)
	if err != nil || len(raw) > 32<<20 {
		return errors.New("encode personal authority journal")
	}
	return fileutil.WriteFileAtomic(authority.path, raw, 0o600)
}

type localFenceResolver struct {
	authorityID string
	key         ed25519.PublicKey
}

// AuthorizeFenceKey and ConfirmCurrentWriterFence let independent local sinks
// verify both cryptographic authority and the current high-water lease. They
// expose no signing key or mutation surface.
func (authority *PersonalAuthority) AuthorizeFenceKey(authorityID string, publicKey ed25519.PublicKey, _ time.Time) error {
	if authority == nil {
		return errors.New("writer authority is unavailable")
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if authorityID != authority.doc.AuthorityID || !authority.key.Public().(ed25519.PublicKey).Equal(publicKey) {
		return errors.New("writer fence key is not the owner authority key")
	}
	return nil
}

func (authority *PersonalAuthority) ConfirmCurrentWriterFence(fence commerce.WriterFence, now time.Time) error {
	if authority == nil {
		return errors.New("writer authority is unavailable")
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if authority.doc.CurrentFence == nil || fence.Body.WriterGeneration != authority.doc.WriterGeneration ||
		fence.Body.LeaseID != authority.doc.CurrentFence.Body.LeaseID || fence.Body.AuthorityID != authority.doc.AuthorityID ||
		!now.UTC().Before(time.Unix(int64(fence.Body.ExpiresAtUnix), 0).UTC()) {
		return errors.New("writer fence is not the current owner lease")
	}
	return nil
}

// SignAction is the only production path that turns a deterministic action
// body into authority. Holding or observing a WriterFence is insufficient.
func (authority *PersonalAuthority) SignAction(action commerce.AuthorizedAction,
	fence commerce.WriterFence) (commerce.AuthorizedAction, error) {
	if authority == nil {
		return commerce.AuthorizedAction{}, errors.New("action authority is unavailable")
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	now := authority.now().UTC()
	if authority.doc.CurrentFence == nil || fence.Body.WriterGeneration != authority.doc.WriterGeneration ||
		fence.Body.LeaseID != authority.doc.CurrentFence.Body.LeaseID || action.AuthorityID != authority.doc.AuthorityID ||
		action.OwnerID != authority.doc.OwnerID || action.AgentID != authority.doc.AgentID ||
		!now.Before(time.Unix(int64(fence.Body.ExpiresAtUnix), 0).UTC()) {
		return commerce.AuthorizedAction{}, errors.New("stale writer cannot sign an action")
	}
	return commerce.SignAuthorizedAction(action, authority.key)
}

func (resolver localFenceResolver) AuthorizeFenceKey(authorityID string, publicKey ed25519.PublicKey, _ time.Time) error {
	if authorityID != resolver.authorityID || !resolver.key.Equal(publicKey) {
		return errors.New("writer fence key is not the local authority key")
	}
	return nil
}

func admitReservation(document authorityDocument, candidate ExposureReservation) error {
	if candidate.ReservationID == "" || candidate.AgreementDigest == "" || candidate.Released {
		return errors.New("portfolio reservation is invalid")
	}
	if existing, found := document.Reservations[candidate.ReservationID]; found {
		if existing == candidate {
			return nil
		}
		return errors.New("portfolio reservation identity conflicts")
	}
	used := PortfolioLimits{}
	for _, reservation := range document.Reservations {
		if reservation.Released {
			continue
		}
		used.ComputeUnits += reservation.ComputeUnits
		used.SpendAtomic += reservation.SpendAtomic
		used.LockedCapitalAtomic += reservation.LockedCapitalAtomic
		used.ReceivableAtomic += reservation.ReceivableAtomic
		used.MaximumLossAtomic += reservation.MaximumLossAtomic
	}
	if exceeds(used.ComputeUnits, candidate.ComputeUnits, document.Limits.ComputeUnits) || exceeds(used.SpendAtomic, candidate.SpendAtomic, document.Limits.SpendAtomic) ||
		exceeds(used.LockedCapitalAtomic, candidate.LockedCapitalAtomic, document.Limits.LockedCapitalAtomic) ||
		exceeds(used.ReceivableAtomic, candidate.ReceivableAtomic, document.Limits.ReceivableAtomic) ||
		exceeds(used.MaximumLossAtomic, candidate.MaximumLossAtomic, document.Limits.MaximumLossAtomic) {
		return errors.New("aggregate Portfolio limit would be exceeded")
	}
	return nil
}

func exceeds(current, additional, limit uint64) bool {
	return additional > limit || current > limit-additional
}

func cloneAuthorityDocument(document authorityDocument) authorityDocument {
	raw, _ := json.Marshal(document)
	var cloned authorityDocument
	_ = json.Unmarshal(raw, &cloned)
	return cloned
}

func randomIdentifier(prefix string) (string, error) {
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(value[:]), nil
}
