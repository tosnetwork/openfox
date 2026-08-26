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
	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
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
	payment commerce.AgreementPaymentRequest, sourceAccount string,
	networkDomain commerce.CustodyNetworkDomain,
	sponsorship *SponsorshipCustodyBinding) (commerce.CustodyActionAuthorization, error) {
	if authority == nil || sourceAccount == "" || commerce.ValidateCustodyNetworkDomain(networkDomain) != nil ||
		networkDomain.NetworkID != payment.NetworkID || networkDomain.GlobalID == 0 {
		return commerce.CustodyActionAuthorization{}, errors.New("custody payment binding is incomplete")
	}
	domainDigest, err := agentrelay.NetworkDomainDigest(agentrelay.NetworkDomain{NetworkID: networkDomain.NetworkID,
		GlobalID: networkDomain.GlobalID, ZeroStateRootHash: networkDomain.ZeroStateRootHash,
		ZeroStateFileHash: networkDomain.ZeroStateFileHash, WorkchainID: networkDomain.WorkchainID})
	if err != nil || payment.SchemaVersion == 3 && payment.NetworkDomainDigest != domainDigest ||
		payment.SchemaVersion == 1 && payment.NetworkDomainDigest != "" ||
		payment.SchemaVersion != 1 && payment.SchemaVersion != 3 {
		return commerce.CustodyActionAuthorization{}, errors.New("custody payment does not bind the pinned network domain")
	}
	if sponsorship != nil && (payment.SchemaVersion != 3 ||
		!canonicalSHA256(sponsorship.FinalityProfileCBORDigest) ||
		!canonicalSHA256(sponsorship.ReleaseProfileDigest) ||
		!canonicalSHA256(sponsorship.CorroborationSnapshotID)) {
		return commerce.CustodyActionAuthorization{}, errors.New("custody sponsorship finality binding is incomplete")
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
	authorizationSchema := uint16(2)
	paymentRequestDigest := ""
	if payment.SchemaVersion == 3 {
		authorizationSchema = 3
		paymentRequestDigest, err = commerce.AgreementPaymentRequestDigest(payment)
		if err != nil {
			return commerce.CustodyActionAuthorization{}, errors.New("custody payment request cannot be bound to relay evidence")
		}
	}
	body := commerce.CustodyActionAuthorization{SchemaVersion: authorizationSchema, AuthorityID: authority.doc.AuthorityID,
		OwnerID: authority.doc.OwnerID, AgentID: authority.doc.AgentID, SourceAccount: sourceAccount,
		NetworkID: payment.NetworkID, NetworkGlobalID: networkDomain.GlobalID,
		NetworkDomain: &commerce.CustodyNetworkDomain{NetworkID: networkDomain.NetworkID, GlobalID: networkDomain.GlobalID,
			ZeroStateRootHash: networkDomain.ZeroStateRootHash, ZeroStateFileHash: networkDomain.ZeroStateFileHash,
			WorkchainID: networkDomain.WorkchainID}, StableActionID: action.StableActionID,
		ExactRequestDigest: action.ExactRequestDigest, WriterGeneration: action.WriterGeneration, WriterFenceDigest: fenceDigest,
		AgreementPaymentRequestDigest: paymentRequestDigest,
		PolicyRevision:                action.PolicyRevision, MandateDigest: action.MandateDigest, ApprovalDigestOrZero: approval,
		AgreementBodyDigest: payment.AgreementBodyDigest, ObligationInstanceID: payment.ObligationInstanceID,
		Destination: string(payment.Destination), AmountAtomic: amount, ExpiresAtUnix: action.ExpiresAtUnix}
	if sponsorship != nil {
		body.SponsorshipFinalityProfileCBORDigest = sponsorship.FinalityProfileCBORDigest
		body.SponsorshipReleaseProfileDigest = sponsorship.ReleaseProfileDigest
		body.SponsorshipCorroborationSnapshotIdentity = sponsorship.CorroborationSnapshotID
	}
	return commerce.SignCustodyActionAuthorization(body, authority.key)
}

// AuthorizeCustodyEffect turns an already admitted semantic action into a
// purpose-limited custody capability for one exact TVM effect. The caller may
// describe the contract effect, but cannot choose the authority identity,
// writer generation, policy, mandate, approval or semantic action identity.
func (authority *PersonalAuthority) AuthorizeCustodyEffect(action commerce.AuthorizedAction,
	fields map[string]commerce.SemanticValue, canonicalRequest []byte, fence commerce.WriterFence,
	template commerce.CustodyEffectAuthorization) (commerce.CustodyEffectAuthorization, error) {
	if authority == nil || template.NetworkDomain == nil ||
		commerce.ValidateCustodyNetworkDomain(*template.NetworkDomain) != nil ||
		template.NetworkID != template.NetworkDomain.NetworkID ||
		template.NetworkGlobalID != template.NetworkDomain.GlobalID {
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
	domain := *template.NetworkDomain
	template.SchemaVersion = 2
	template.NetworkDomain = &domain
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
	Schema                     string                                                      `json:"schema"`
	OwnerID                    string                                                      `json:"owner_id"`
	AgentID                    string                                                      `json:"agent_id"`
	AuthorityID                string                                                      `json:"authority_id"`
	WriterGeneration           uint64                                                      `json:"writer_generation"`
	CurrentFence               *commerce.WriterFence                                       `json:"current_fence,omitempty"`
	Actions                    map[string]commerce.ActionResolution                        `json:"actions"`
	AuthorityInstances         map[string]commerce.AuthorityInstanceRecord                 `json:"authority_instances"`
	NextInstanceSequence       uint64                                                      `json:"next_instance_sequence"`
	NextRelayAdmissionSequence uint64                                                      `json:"next_relay_admission_sequence"`
	RelayAdmissions            map[string]agentrelay.SignedRelaySideEffectAdmissionReceipt `json:"relay_admissions"`
	RelayAdmissionBindings     map[string]string                                           `json:"relay_admission_bindings"`
	PortfolioRevision          uint64                                                      `json:"portfolio_revision"`
	Limits                     PortfolioLimits                                             `json:"limits"`
	Reservations               map[string]ExposureReservation                              `json:"reservations"`
	ScheduleEntries            map[string]commerce.EngagementScheduleEntry                 `json:"schedule_entries"`
	Dependencies               []commerce.PortfolioDependency                              `json:"portfolio_dependencies"`
	Engagements                map[string]EngagementRecord                                 `json:"engagements"`
	SettlementLedger           map[string]SettlementLedgerRecord                           `json:"settlement_ledger"`
	Accounting                 map[string]AccountingEntry                                  `json:"accounting"`
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
		NextInstanceSequence: 1, NextRelayAdmissionSequence: 1,
		RelayAdmissions:        map[string]agentrelay.SignedRelaySideEffectAdmissionReceipt{},
		RelayAdmissionBindings: map[string]string{},
		PortfolioRevision:      1, Limits: limits, Reservations: map[string]ExposureReservation{},
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
	if document.RelayAdmissions == nil {
		document.RelayAdmissions = map[string]agentrelay.SignedRelaySideEffectAdmissionReceipt{}
	}
	if document.RelayAdmissionBindings == nil {
		document.RelayAdmissionBindings = map[string]string{}
	}
	if document.NextRelayAdmissionSequence == 0 && len(document.RelayAdmissions) == 0 {
		document.NextRelayAdmissionSequence = 1
	}
	relayAdmissionSequences := make(map[uint64]struct{}, len(document.RelayAdmissions))
	expectedRelayAdmissionBindings := make(map[string]string, len(document.RelayAdmissions))
	type relayAdmissionRouteEntry struct {
		lookupDigest string
		receipt      agentrelay.SignedRelaySideEffectAdmissionReceipt
	}
	relayAdmissionRoutes := make(map[string][]relayAdmissionRouteEntry, len(document.RelayAdmissions))
	var maximumRelayAdmissionSequence uint64
	for lookupDigest, receipt := range document.RelayAdmissions {
		body := receipt.Body
		lookup := agentrelay.RelaySideEffectAdmissionLookup{SchemaVersion: 1, OwnerID: body.OwnerID, AgentID: body.AgentID,
			AuthenticatedPrincipal: body.AuthenticatedPrincipal, AuthorityID: body.AuthorityID,
			ProviderAgentID: body.ProviderAgentID, ServiceProfileDigest: body.ServiceProfileDigest,
			ProviderQuoteDigest: body.ProviderQuoteDigest, NetworkDigest: body.NetworkDigest,
			TransactionIdentityDigest: body.TransactionIdentityDigest, Mode: body.Mode,
			AssuranceLevel: body.AssuranceLevel,
			RouteAttempt:   body.RouteAttempt, PredecessorReceiptDigest: body.PredecessorReceiptDigest,
			StableActionID:     body.StableActionID,
			ExactRequestDigest: body.ExactRequestDigest, RelayExecutionDigest: body.RelayExecutionDigest,
			StageMask: append([]agentrelay.SideEffectStage(nil), body.StageMask...)}
		computed, digestErr := agentrelay.RelaySideEffectAdmissionLookupDigest(lookup)
		if digestErr != nil || computed != lookupDigest || body.OwnerID != document.OwnerID ||
			body.AgentID != document.AgentID || body.AuthorityID != document.AuthorityID ||
			body.AdmissionSequence == 0 ||
			receipt.PublicKey != "ed25519:"+hex.EncodeToString(authority.key.Public().(ed25519.PublicKey)) ||
			agentrelay.VerifyRelaySideEffectAdmissionReceiptSignature(receipt) != nil {
			return errors.New("personal authority relay admission ledger is invalid")
		}
		if _, duplicate := relayAdmissionSequences[body.AdmissionSequence]; duplicate {
			return errors.New("personal authority relay admission sequence is reused")
		}
		relayAdmissionSequences[body.AdmissionSequence] = struct{}{}
		if body.AdmissionSequence > maximumRelayAdmissionSequence {
			maximumRelayAdmissionSequence = body.AdmissionSequence
		}
		bindingKey := relayAdmissionStableBindingKey(body.OwnerID, body.AgentID, body.StableActionID)
		relayAdmissionRoutes[bindingKey] = append(relayAdmissionRoutes[bindingKey], relayAdmissionRouteEntry{
			lookupDigest: lookupDigest, receipt: receipt,
		})
	}
	for bindingKey, route := range relayAdmissionRoutes {
		if len(route) > int(agentrelay.MaxRelayRouteAttempts) {
			return errors.New("personal authority relay admission route chain exceeds the V1 limit")
		}
		sort.Slice(route, func(left, right int) bool {
			return route[left].receipt.Body.RouteAttempt < route[right].receipt.Body.RouteAttempt
		})
		chain := make([]agentrelay.SignedRelaySideEffectAdmissionReceipt, len(route))
		for index := range route {
			chain[index] = route[index].receipt
		}
		if agentrelay.ValidateRelaySideEffectAdmissionRouteChain(chain) != nil {
			return errors.New("personal authority relay admission route chain is invalid")
		}
		expectedRelayAdmissionBindings[bindingKey] = route[len(route)-1].lookupDigest
	}
	if maximumRelayAdmissionSequence == ^uint64(0) ||
		document.NextRelayAdmissionSequence != maximumRelayAdmissionSequence+1 {
		return errors.New("personal authority relay admission high-water is invalid")
	}
	if len(document.RelayAdmissionBindings) == 0 && len(expectedRelayAdmissionBindings) != 0 {
		// Migrate only from already verified, contiguous receipt chains. The
		// highest route attempt is the one and only successor admission point.
		document.RelayAdmissionBindings = expectedRelayAdmissionBindings
	} else if !equalRelayAdmissionBindings(document.RelayAdmissionBindings, expectedRelayAdmissionBindings) {
		return errors.New("personal authority relay admission binding index is invalid")
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
	if authority.doc.CurrentFence == nil || authority.doc.CurrentFence.Body.WriterGeneration != authority.doc.WriterGeneration ||
		fence.Body.WriterGeneration != authority.doc.WriterGeneration || fence.Body.AuthorityID != authority.doc.AuthorityID ||
		!now.UTC().Before(time.Unix(int64(fence.Body.ExpiresAtUnix), 0).UTC()) {
		return errors.New("writer fence is not the current owner lease")
	}
	// Currentness is about the exact authority-issued lease, not merely a
	// generation number. This also rejects a stale/corrupt envelope that happens
	// to reuse the current generation or lease ID with another instance, scope,
	// validity bound, or proof.
	wanted, wantedErr := commerce.WriterFenceDigest(*authority.doc.CurrentFence)
	got, gotErr := commerce.WriterFenceDigest(fence)
	if wantedErr != nil || gotErr != nil || got != wanted {
		return errors.New("writer fence is not the current owner lease")
	}
	return nil
}

// AdmitRelaySideEffects atomically checks the current writer high-water and
// persists the one recoverable receipt that authorizes the exact Provider
// route. Receipt issuance is the linearization point; a later takeover cannot
// revoke already-admitted stages, while a stale writer can never mint a new
// receipt after takeover.
func (authority *PersonalAuthority) admitRelaySideEffects(ctx context.Context,
	descriptor agentrelay.RelaySideEffectAdmissionDescriptor) (agentrelay.SignedRelaySideEffectAdmissionReceipt, error) {
	if authority == nil || ctx == nil {
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, errors.New("relay admission authority is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, err
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	now := authority.now().UTC()
	if authority.doc.CurrentFence == nil || descriptor.OwnerID != authority.doc.OwnerID ||
		descriptor.AgentID != authority.doc.AgentID || descriptor.WriterFence.Body.AuthorityID != authority.doc.AuthorityID ||
		descriptor.WriterFence.Body.WriterGeneration != authority.doc.WriterGeneration ||
		descriptor.WriterFence.Body.LeaseID != authority.doc.CurrentFence.Body.LeaseID {
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, errors.New("stale writer cannot admit relay side effects")
	}
	wantedFence, wantedErr := commerce.WriterFenceDigest(*authority.doc.CurrentFence)
	gotFence, gotErr := commerce.WriterFenceDigest(descriptor.WriterFence)
	if wantedErr != nil || gotErr != nil || wantedFence != gotFence {
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, errors.New("relay admission does not carry the current writer fence")
	}
	resolver := localFenceResolver{authorityID: authority.doc.AuthorityID,
		key: authority.key.Public().(ed25519.PublicKey)}
	if err := agentrelay.ValidateRelaySideEffectAdmissionDescriptor(descriptor, resolver, now); err != nil {
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, err
	}
	if descriptor.RouteAttempt > maximumRelayRouteHops {
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, errors.New("relay admission route attempt exceeds the V1 limit")
	}
	lookupDigest, err := agentrelay.RelaySideEffectAdmissionLookupDigest(descriptor.Lookup())
	if err != nil {
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, err
	}
	if existing, found := authority.doc.RelayAdmissions[lookupDigest]; found {
		issuedAt := time.Unix(int64(existing.Body.IssuedAtUnix), 0).UTC()
		if err := agentrelay.VerifyRelaySideEffectAdmissionReceiptForDescriptor(existing, descriptor,
			agentrelay.RelayExecutionRequest{}, issuedAt); err != nil {
			return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, errors.New("stored relay admission conflicts with exact retry")
		}
		return cloneRelayAdmissionReceipt(existing), nil
	}
	bindingKey := relayAdmissionStableBindingKey(descriptor.OwnerID, descriptor.AgentID, descriptor.StableActionID)
	boundLookup, hasBoundRoute := authority.doc.RelayAdmissionBindings[bindingKey]
	if !hasBoundRoute {
		if descriptor.RouteAttempt != 1 || descriptor.PredecessorReceiptDigest != "" {
			return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, agentrelay.ErrRelayConflict
		}
	} else {
		predecessor, found := authority.doc.RelayAdmissions[boundLookup]
		if !found || agentrelay.ValidateRelaySideEffectAdmissionRouteTransition(predecessor, descriptor) != nil {
			return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, agentrelay.ErrRelayConflict
		}
	}
	if authority.doc.NextRelayAdmissionSequence == 0 || authority.doc.NextRelayAdmissionSequence == ^uint64(0) ||
		now.Unix() < 0 || descriptor.StartNotAfterCapUnix <= uint64(now.Unix()) {
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, errors.New("relay admission sequence or start window is exhausted")
	}
	startNotAfter := uint64(now.Add(agentrelay.MaxRelayAdmissionStartDelay * time.Second).Unix())
	if descriptor.StartNotAfterCapUnix < startNotAfter {
		startNotAfter = descriptor.StartNotAfterCapUnix
	}
	body, err := agentrelay.BuildRelaySideEffectAdmissionReceiptBody(descriptor,
		authority.doc.NextRelayAdmissionSequence, uint64(now.Unix()), startNotAfter)
	if err != nil {
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, err
	}
	receipt, err := agentrelay.SignRelaySideEffectAdmissionReceipt(body, authority.key)
	if err != nil {
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, err
	}
	next := cloneAuthorityDocument(authority.doc)
	next.RelayAdmissions[lookupDigest] = receipt
	next.RelayAdmissionBindings[bindingKey] = lookupDigest
	next.NextRelayAdmissionSequence++
	if err := authority.persist(next); err != nil {
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, err
	}
	authority.doc = next
	return cloneRelayAdmissionReceipt(receipt), nil
}

func (authority *PersonalAuthority) resolveRelaySideEffectAdmission(ctx context.Context,
	lookup agentrelay.RelaySideEffectAdmissionLookup) (agentrelay.SignedRelaySideEffectAdmissionReceipt, error) {
	if authority == nil || ctx == nil {
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, errors.New("relay admission authority is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, err
	}
	lookupDigest, err := agentrelay.RelaySideEffectAdmissionLookupDigest(lookup)
	if err != nil {
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, err
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if lookup.OwnerID != authority.doc.OwnerID || lookup.AgentID != authority.doc.AgentID ||
		lookup.AuthorityID != authority.doc.AuthorityID {
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, errors.New("relay side-effect admission lookup is outside this authority")
	}
	receipt, found := authority.doc.RelayAdmissions[lookupDigest]
	if !found {
		// This typed result is safe because it comes from the same locked journal
		// that linearizes Admit. Callers must not translate transport failures or
		// arbitrary remote strings into ErrRelayUnknown.
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, agentrelay.ErrRelayUnknown
	}
	return cloneRelayAdmissionReceipt(receipt), nil
}

func cloneRelayAdmissionReceipt(receipt agentrelay.SignedRelaySideEffectAdmissionReceipt) agentrelay.SignedRelaySideEffectAdmissionReceipt {
	receipt.Body.StageMask = append([]agentrelay.SideEffectStage(nil), receipt.Body.StageMask...)
	return receipt
}

func relayAdmissionStableBindingKey(ownerID, agentID, stableActionID string) string {
	return ownerID + "\x00" + agentID + "\x00" + stableActionID
}

func equalRelayAdmissionBindings(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
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
