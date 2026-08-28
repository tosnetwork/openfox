package earning

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"reflect"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

const relayAdmissionReauthorizationSignatureDomain = "tos.openfox.relay-admission-reauthorization.v1\x00"

// relayAdmissionReauthorizationBody is owner-private evidence that the same
// PersonalAuthority which owns the receipt high-water atomically observed an
// old successor lookup as absent and reauthorized only its writer envelope.
// It is not a side-effect admission and cannot be presented to a Provider.
type relayAdmissionReauthorizationBody struct {
	SchemaVersion             uint16                       `json:"schema_version"`
	OwnerID                   string                       `json:"owner_id"`
	AgentID                   string                       `json:"agent_id"`
	AuthorityID               string                       `json:"authority_id"`
	AuthenticatedPrincipal    string                       `json:"authenticated_principal_id"`
	ProviderAgentID           string                       `json:"provider_agent_id"`
	ServiceProfileDigest      string                       `json:"service_profile_digest"`
	ProviderQuoteDigest       string                       `json:"provider_quote_digest"`
	NetworkDigest             string                       `json:"network_digest"`
	TransactionIdentityDigest string                       `json:"transaction_identity_digest"`
	Mode                      agentrelay.Mode              `json:"mode"`
	AssuranceLevel            agentrelay.AssuranceLevel    `json:"assurance_level"`
	StageMask                 []agentrelay.SideEffectStage `json:"stage_mask"`
	RouteAttempt              uint32                       `json:"route_attempt"`
	PredecessorReceiptDigest  string                       `json:"predecessor_receipt_digest"`
	StableActionID            string                       `json:"stable_action_id"`
	ExactRequestDigest        string                       `json:"exact_request_digest"`
	OldAdmissionLookupDigest  string                       `json:"old_admission_lookup_digest"`
	OldRelayExecutionDigest   string                       `json:"old_relay_execution_request_digest"`
	OldAuthorizedActionDigest string                       `json:"old_authorized_action_digest"`
	OldWriterFenceDigest      string                       `json:"old_writer_fence_digest"`
	NewAuthorizedActionDigest string                       `json:"new_authorized_action_digest"`
	NewWriterFenceDigest      string                       `json:"new_writer_fence_digest"`
	NewWriterLeaseID          string                       `json:"new_writer_lease_id"`
	NewWriterGeneration       uint64                       `json:"new_writer_generation"`
	OldActionExpiresAtUnix    uint64                       `json:"old_action_expires_at_unix"`
	NewActionExpiresAtUnix    uint64                       `json:"new_action_expires_at_unix"`
	PolicyRevision            uint64                       `json:"policy_revision"`
	MandateDigest             string                       `json:"mandate_digest"`
	ApprovalDigest            string                       `json:"approval_digest,omitempty"`
	ResolvedNotFoundAtUnix    uint64                       `json:"resolved_not_found_at_unix"`
}

type relayAdmissionReauthorization struct {
	Body             relayAdmissionReauthorizationBody `json:"body"`
	AuthorizedAction commerce.AuthorizedAction         `json:"authorized_action"`
	WriterFence      commerce.WriterFence              `json:"writer_fence"`
	PublicKey        string                            `json:"public_key"`
	Signature        string                            `json:"signature"`
}

type relayAdmissionRebaseRecord struct {
	PriorAttempt  RelayAttempt                  `json:"protected_prior_attempt"`
	Authorization relayAdmissionReauthorization `json:"protected_authorization"`
}

// relayAdmissionReauthorizer is deliberately package-private. Implementations
// must share the exact linearization store used by Admit/Resolve; a generic
// transport or caller assertion cannot manufacture a not-found confirmation.
type relayAdmissionReauthorizer interface {
	reauthorizeUnlinearizedRelayAdmission(context.Context,
		agentrelay.RelaySideEffectAdmissionDescriptor,
		agentrelay.RelayExecutionRequest) (relayAdmissionReauthorization, error)
}

// PersonalRelaySideEffectAuthority is a sealed local capability for one exact
// writer lease. Its fields are private so callers cannot manufacture a current
// writer identity from a stale PersonalAuthority pointer.
type PersonalRelaySideEffectAuthority struct {
	authority        *PersonalAuthority
	instanceID       string
	leaseID          string
	writerGeneration uint64
	fenceDigest      string
}

func (bound *PersonalRelaySideEffectAuthority) HasLinearizableRelayAdmission() bool {
	return bound != nil && bound.authority != nil && bound.authority.storageIdentityAttached()
}

// A locked local file gives one-host linearization but can be restored from an
// older disk snapshot. It must never be advertised as autonomous rollback-
// resistant authority without an external monotonic CAS/anchor.
func (*PersonalRelaySideEffectAuthority) HasRollbackResistantRelayAdmissionHighWater() bool {
	return false
}

// BindRelaySideEffectAuthority returns a capability only for the exact current
// writer fence. A later takeover makes the returned capability stale.
func (authority *PersonalAuthority) BindRelaySideEffectAuthority(
	fence commerce.WriterFence) (*PersonalRelaySideEffectAuthority, error) {
	if authority == nil {
		return nil, errors.New("relay admission authority is unavailable")
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if err := authority.ensureStorageIdentityLocked(); err != nil {
		return nil, err
	}
	if authority.doc.CurrentFence == nil {
		return nil, errors.New("relay admission authority has no current writer")
	}
	wanted, wantedErr := commerce.WriterFenceDigest(*authority.doc.CurrentFence)
	got, gotErr := commerce.WriterFenceDigest(fence)
	now := authority.now().UTC()
	if wantedErr != nil || gotErr != nil || wanted != got ||
		fence.Body.WriterGeneration != authority.doc.WriterGeneration ||
		fence.Body.AuthorityID != authority.doc.AuthorityID ||
		!now.Before(time.Unix(int64(fence.Body.ExpiresAtUnix), 0).UTC()) {
		return nil, errors.New("relay admission capability requires the exact current writer fence")
	}
	return &PersonalRelaySideEffectAuthority{authority: authority, instanceID: fence.Body.InstanceID,
		leaseID: fence.Body.LeaseID, writerGeneration: fence.Body.WriterGeneration, fenceDigest: got}, nil
}

func (bound *PersonalRelaySideEffectAuthority) AdmitRelaySideEffects(ctx context.Context,
	descriptor agentrelay.RelaySideEffectAdmissionDescriptor) (agentrelay.SignedRelaySideEffectAdmissionReceipt, error) {
	if bound == nil || bound.authority == nil {
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, errors.New("relay admission capability is unavailable")
	}
	fenceDigest, err := commerce.WriterFenceDigest(descriptor.WriterFence)
	if err != nil || descriptor.WriterFence.Body.InstanceID != bound.instanceID ||
		descriptor.WriterFence.Body.LeaseID != bound.leaseID ||
		descriptor.WriterFence.Body.WriterGeneration != bound.writerGeneration ||
		fenceDigest != bound.fenceDigest || descriptor.WriterFenceDigest != bound.fenceDigest ||
		descriptor.AuthorizedAction.WriterGeneration != bound.writerGeneration ||
		descriptor.AuthorizedAction.WriterFenceDigest != bound.fenceDigest {
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{},
			errors.New("relay admission descriptor exceeds the bound writer capability")
	}
	return bound.authority.admitRelaySideEffects(ctx, descriptor)
}

func (bound *PersonalRelaySideEffectAuthority) ResolveRelaySideEffectAdmission(ctx context.Context,
	lookup agentrelay.RelaySideEffectAdmissionLookup) (agentrelay.SignedRelaySideEffectAdmissionReceipt, error) {
	if bound == nil || bound.authority == nil {
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, errors.New("relay admission capability is unavailable")
	}
	return bound.authority.resolveRelaySideEffectAdmission(ctx, lookup)
}

func (bound *PersonalRelaySideEffectAuthority) reauthorizeUnlinearizedRelayAdmission(ctx context.Context,
	descriptor agentrelay.RelaySideEffectAdmissionDescriptor,
	execution agentrelay.RelayExecutionRequest) (relayAdmissionReauthorization, error) {
	if bound == nil || bound.authority == nil {
		return relayAdmissionReauthorization{}, errors.New("relay admission capability is unavailable")
	}
	return bound.authority.reauthorizeUnlinearizedRelayAdmissionForCapability(ctx, descriptor, execution,
		relayAdmissionReauthorizationCapability{instanceID: bound.instanceID, leaseID: bound.leaseID,
			writerGeneration: bound.writerGeneration, fenceDigest: bound.fenceDigest})
}

type relayAdmissionReauthorizationCapability struct {
	instanceID       string
	leaseID          string
	writerGeneration uint64
	fenceDigest      string
}

func (authority *PersonalAuthority) reauthorizeUnlinearizedRelayAdmissionForInstance(ctx context.Context,
	descriptor agentrelay.RelaySideEffectAdmissionDescriptor,
	execution agentrelay.RelayExecutionRequest,
	expectedCurrentInstance string) (relayAdmissionReauthorization, error) {
	return authority.reauthorizeUnlinearizedRelayAdmissionForCapability(ctx, descriptor, execution,
		relayAdmissionReauthorizationCapability{instanceID: expectedCurrentInstance})
}

func (authority *PersonalAuthority) reauthorizeUnlinearizedRelayAdmissionForCapability(ctx context.Context,
	descriptor agentrelay.RelaySideEffectAdmissionDescriptor,
	execution agentrelay.RelayExecutionRequest,
	capability relayAdmissionReauthorizationCapability) (relayAdmissionReauthorization, error) {
	if authority == nil || ctx == nil {
		return relayAdmissionReauthorization{}, errors.New("relay admission reauthorization authority is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return relayAdmissionReauthorization{}, err
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if err := authority.ensureStorageIdentityLocked(); err != nil {
		return relayAdmissionReauthorization{}, err
	}
	now := authority.now().UTC()
	if authority.doc.CurrentFence == nil || descriptor.OwnerID != authority.doc.OwnerID ||
		descriptor.AgentID != authority.doc.AgentID || descriptor.WriterFence.Body.AuthorityID != authority.doc.AuthorityID ||
		descriptor.RouteAttempt <= 1 || descriptor.RouteAttempt > agentrelay.MaxRelayRouteAttempts ||
		descriptor.Mode != agentrelay.ModeRelayExact {
		return relayAdmissionReauthorization{}, errors.New("relay admission reauthorization context is invalid")
	}
	resolver := localFenceResolver{authorityID: authority.doc.AuthorityID,
		key: authority.key.Public().(ed25519.PublicKey)}
	oldExecutionDigest, digestErr := agentrelay.RelayExecutionRequestDigest(execution)
	if digestErr != nil || oldExecutionDigest != descriptor.RelayExecutionDigest ||
		execution.AdmissionReceipt.Body.SchemaVersion != 0 {
		return relayAdmissionReauthorization{}, errors.New("old relay execution does not match its admission descriptor")
	}
	reconstructed, reconstructErr := agentrelay.BuildRelaySideEffectAdmissionSuccessorDescriptor(execution,
		descriptor.AuthenticatedPrincipal, predecessorForRelayDescriptor(authority.doc, descriptor))
	if reconstructErr != nil || !reflect.DeepEqual(reconstructed, descriptor) {
		return relayAdmissionReauthorization{}, errors.New("old relay execution cannot reconstruct its admission descriptor")
	}
	// Validate old credentials at a time when both the immutable execution and
	// its current historical writer envelope existed. On a repeated takeover a
	// prior safe rebase has a fence issued after execution.CreatedAtUnix.
	historicalUnix := execution.CreatedAtUnix
	if descriptor.WriterFence.Body.IssuedAtUnix > historicalUnix {
		historicalUnix = descriptor.WriterFence.Body.IssuedAtUnix
	}
	historicalAt := time.Unix(int64(historicalUnix), 0).UTC()
	historicalErr := agentrelay.ValidateRelaySideEffectAdmissionDescriptor(descriptor, resolver, historicalAt)
	if execution.CreatedAtUnix == 0 || historicalUnix == 0 || historicalAt.After(now) || historicalErr != nil ||
		!now.Before(time.Unix(int64(descriptor.AuthorizedAction.ExpiresAtUnix), 0).UTC()) {
		return relayAdmissionReauthorization{}, errors.New("old relay admission descriptor is invalid")
	}
	oldLookupDigest, err := agentrelay.RelaySideEffectAdmissionLookupDigest(descriptor.Lookup())
	if err != nil {
		return relayAdmissionReauthorization{}, err
	}
	if _, found := authority.doc.RelayAdmissions[oldLookupDigest]; found {
		return relayAdmissionReauthorization{}, errors.New("relay admission already linearized")
	}
	bindingKey := relayAdmissionStableBindingKey(descriptor.OwnerID, descriptor.AgentID, descriptor.StableActionID)
	boundLookup, found := authority.doc.RelayAdmissionBindings[bindingKey]
	predecessor, predecessorFound := authority.doc.RelayAdmissions[boundLookup]
	if !found || !predecessorFound ||
		agentrelay.ValidateRelaySideEffectAdmissionRouteTransition(predecessor, descriptor) != nil {
		return relayAdmissionReauthorization{}, agentrelay.ErrRelayConflict
	}
	currentFence := *authority.doc.CurrentFence
	currentFenceDigest, currentFenceDigestErr := commerce.WriterFenceDigest(currentFence)
	if currentFence.Body.AuthorityID != authority.doc.AuthorityID ||
		currentFence.Body.WriterGeneration != authority.doc.WriterGeneration ||
		currentFence.Body.WriterGeneration <= descriptor.WriterFence.Body.WriterGeneration ||
		currentFence.Body.LeaseID == descriptor.WriterFence.Body.LeaseID ||
		capability.instanceID == "" || currentFence.Body.InstanceID != capability.instanceID ||
		capability.leaseID != "" && currentFence.Body.LeaseID != capability.leaseID ||
		capability.writerGeneration != 0 && currentFence.Body.WriterGeneration != capability.writerGeneration ||
		capability.fenceDigest != "" && currentFenceDigest != capability.fenceDigest || currentFenceDigestErr != nil ||
		!now.Before(time.Unix(int64(currentFence.Body.ExpiresAtUnix), 0).UTC()) {
		return relayAdmissionReauthorization{}, errors.New("current writer cannot reauthorize relay admission")
	}
	fields, err := commerce.ImportSemanticFields(descriptor.AuthorizedAction.ActionKind, descriptor.SemanticFields)
	if err != nil {
		return relayAdmissionReauthorization{}, err
	}
	oldAction := descriptor.AuthorizedAction
	newActionExpiry := relayAdmissionReauthorizationExpiry(execution, currentFence)
	if newActionExpiry <= uint64(now.Unix()) {
		return relayAdmissionReauthorization{}, errors.New("immutable relay execution windows have expired")
	}
	newAction, err := commerce.BuildAuthorizedAction(oldAction.OwnerID, oldAction.AgentID, oldAction.ActionKind,
		fields, descriptor.UnderlyingActionRequest, currentFence, oldAction.PolicyRevision, oldAction.MandateDigest,
		oldAction.ApprovalDigest, oldAction.ExpectedPriorState, newActionExpiry)
	if err != nil {
		return relayAdmissionReauthorization{}, err
	}
	newAction, err = commerce.SignAuthorizedAction(newAction, authority.key)
	if err != nil {
		return relayAdmissionReauthorization{}, err
	}
	newActionDigest, err := commerce.AuthorizedActionDigest(newAction)
	if err != nil {
		return relayAdmissionReauthorization{}, err
	}
	newFenceDigest, err := commerce.WriterFenceDigest(currentFence)
	if err != nil {
		return relayAdmissionReauthorization{}, err
	}
	rebasedExecution := execution
	rebasedExecution.AuthorizedAction = newAction
	rebasedExecution.WriterFence = currentFence
	rebasedDescriptor, err := agentrelay.BuildRelaySideEffectAdmissionSuccessorDescriptor(rebasedExecution,
		descriptor.AuthenticatedPrincipal, predecessor)
	if err != nil || rebasedDescriptor.RelayExecutionDigest != descriptor.RelayExecutionDigest {
		return relayAdmissionReauthorization{}, errors.New("rebased relay execution changes immutable execution identity")
	}
	if err := agentrelay.ValidateRelaySideEffectAdmissionDescriptor(rebasedDescriptor, resolver, now); err != nil {
		return relayAdmissionReauthorization{}, errors.New("rebased relay admission descriptor is invalid: " + err.Error())
	}
	oldActionDigest, _ := commerce.AuthorizedActionDigest(oldAction)
	oldFenceDigest, _ := commerce.WriterFenceDigest(descriptor.WriterFence)
	body := relayAdmissionReauthorizationBody{SchemaVersion: 1, OwnerID: descriptor.OwnerID,
		AgentID: descriptor.AgentID, AuthorityID: authority.doc.AuthorityID,
		AuthenticatedPrincipal: descriptor.AuthenticatedPrincipal, ProviderAgentID: descriptor.ProviderAgentID,
		ServiceProfileDigest: descriptor.ServiceProfileDigest, ProviderQuoteDigest: descriptor.ProviderQuoteDigest,
		NetworkDigest: descriptor.NetworkDigest, TransactionIdentityDigest: descriptor.TransactionIdentityDigest,
		Mode: descriptor.Mode, AssuranceLevel: descriptor.AssuranceLevel,
		StageMask:    append([]agentrelay.SideEffectStage(nil), descriptor.StageMask...),
		RouteAttempt: descriptor.RouteAttempt, PredecessorReceiptDigest: descriptor.PredecessorReceiptDigest,
		StableActionID: descriptor.StableActionID, ExactRequestDigest: descriptor.ExactRequestDigest,
		OldAdmissionLookupDigest: oldLookupDigest, OldRelayExecutionDigest: descriptor.RelayExecutionDigest,
		OldAuthorizedActionDigest: oldActionDigest, OldWriterFenceDigest: oldFenceDigest,
		NewAuthorizedActionDigest: newActionDigest, NewWriterFenceDigest: newFenceDigest,
		NewWriterLeaseID: currentFence.Body.LeaseID, NewWriterGeneration: currentFence.Body.WriterGeneration,
		OldActionExpiresAtUnix: oldAction.ExpiresAtUnix, NewActionExpiresAtUnix: newActionExpiry,
		PolicyRevision: oldAction.PolicyRevision, MandateDigest: oldAction.MandateDigest,
		ApprovalDigest: oldAction.ApprovalDigest, ResolvedNotFoundAtUnix: uint64(now.Unix())}
	return signRelayAdmissionReauthorization(body, newAction, currentFence, authority.key)
}

func predecessorForRelayDescriptor(document authorityDocument,
	descriptor agentrelay.RelaySideEffectAdmissionDescriptor) agentrelay.SignedRelaySideEffectAdmissionReceipt {
	bindingKey := relayAdmissionStableBindingKey(descriptor.OwnerID, descriptor.AgentID, descriptor.StableActionID)
	return document.RelayAdmissions[document.RelayAdmissionBindings[bindingKey]]
}

func relayAdmissionReauthorizationExpiry(execution agentrelay.RelayExecutionRequest,
	fence commerce.WriterFence) uint64 {
	values := []uint64{fence.Body.ExpiresAtUnix, execution.AuthorizedAction.ExpiresAtUnix,
		execution.ExpiresAtUnix, execution.AgreementExpiresAtUnix,
		execution.ProviderQuote.Body.ExpiresAtUnix, execution.QuoteRequest.Body.TransactionValidUntilUnix}
	result := values[0]
	for _, value := range values[1:] {
		if value < result {
			result = value
		}
	}
	return result
}

func signRelayAdmissionReauthorization(body relayAdmissionReauthorizationBody, action commerce.AuthorizedAction,
	fence commerce.WriterFence, key ed25519.PrivateKey) (relayAdmissionReauthorization, error) {
	if len(key) != ed25519.PrivateKeySize || body.ResolvedNotFoundAtUnix == 0 {
		return relayAdmissionReauthorization{}, errors.New("relay admission reauthorization is invalid")
	}
	canonical, err := codec.Marshal(body)
	if err != nil {
		return relayAdmissionReauthorization{}, err
	}
	message := relayAdmissionReauthorizationMessage(canonical)
	public := key.Public().(ed25519.PublicKey)
	return relayAdmissionReauthorization{Body: body, AuthorizedAction: action, WriterFence: fence,
		PublicKey: "ed25519:" + hex.EncodeToString(public),
		Signature: "ed25519:" + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, message))}, nil
}

func verifyRelayAdmissionReauthorization(authorization relayAdmissionReauthorization,
	oldAttempt, newAttempt RelayAttempt, predecessor agentrelay.SignedRelaySideEffectAdmissionReceipt) error {
	body := authorization.Body
	if body.SchemaVersion != 1 || body.Mode != agentrelay.ModeRelayExact ||
		body.AssuranceLevel != agentrelay.AssuranceAutonomousDecentralized || body.RouteAttempt <= 1 ||
		body.RouteAttempt > agentrelay.MaxRelayRouteAttempts || body.ResolvedNotFoundAtUnix == 0 ||
		!canonicalSHA256(body.ServiceProfileDigest) || !canonicalSHA256(body.ProviderQuoteDigest) ||
		!canonicalSHA256(body.NetworkDigest) || !canonicalSHA256(body.TransactionIdentityDigest) ||
		!canonicalSHA256(body.PredecessorReceiptDigest) || !canonicalSHA256(body.StableActionID) ||
		!canonicalSHA256(body.ExactRequestDigest) || !canonicalSHA256(body.OldAdmissionLookupDigest) ||
		!canonicalSHA256(body.OldRelayExecutionDigest) || !canonicalSHA256(body.OldAuthorizedActionDigest) ||
		!canonicalSHA256(body.OldWriterFenceDigest) || !canonicalSHA256(body.NewAuthorizedActionDigest) ||
		!canonicalSHA256(body.NewWriterFenceDigest) || body.NewWriterLeaseID == "" || body.NewWriterGeneration == 0 {
		return errors.New("relay admission reauthorization body is invalid")
	}
	stages, err := agentrelay.RelaySideEffectStages(body.Mode)
	if err != nil || !reflect.DeepEqual(stages, body.StageMask) || !reflect.DeepEqual(newAttempt.Agreement, oldAttempt.Agreement) {
		return errors.New("relay admission reauthorization changes stages or Agreement")
	}
	oldExecution, newExecution := oldAttempt.Execution, newAttempt.Execution
	if oldExecution.AdmissionReceipt.Body.SchemaVersion != 0 || newExecution.AdmissionReceipt.Body.SchemaVersion != 0 {
		return errors.New("relay admission reauthorization cannot replace an issued receipt")
	}
	oldDescriptor, err := agentrelay.BuildRelaySideEffectAdmissionSuccessorDescriptor(oldExecution,
		oldExecution.QuoteRequest.Body.RequesterAgentID, predecessor)
	if err != nil {
		return err
	}
	newDescriptor, err := agentrelay.BuildRelaySideEffectAdmissionSuccessorDescriptor(newExecution,
		newExecution.QuoteRequest.Body.RequesterAgentID, predecessor)
	if err != nil {
		return err
	}
	oldLookupDigest, _ := agentrelay.RelaySideEffectAdmissionLookupDigest(oldDescriptor.Lookup())
	oldActionDigest, _ := commerce.AuthorizedActionDigest(oldExecution.AuthorizedAction)
	oldFenceDigest, _ := commerce.WriterFenceDigest(oldExecution.WriterFence)
	newActionDigest, _ := commerce.AuthorizedActionDigest(newExecution.AuthorizedAction)
	newFenceDigest, _ := commerce.WriterFenceDigest(newExecution.WriterFence)
	oldDigest, _ := agentrelay.RelayExecutionRequestDigest(oldExecution)
	if body.OwnerID != oldDescriptor.OwnerID || body.AgentID != oldDescriptor.AgentID ||
		body.AuthorityID != predecessor.Body.AuthorityID || body.AuthenticatedPrincipal != oldDescriptor.AuthenticatedPrincipal ||
		body.ProviderAgentID != oldDescriptor.ProviderAgentID || body.ServiceProfileDigest != oldDescriptor.ServiceProfileDigest ||
		body.ProviderQuoteDigest != oldDescriptor.ProviderQuoteDigest || body.NetworkDigest != oldDescriptor.NetworkDigest ||
		body.TransactionIdentityDigest != oldDescriptor.TransactionIdentityDigest ||
		body.AssuranceLevel != oldDescriptor.AssuranceLevel || body.RouteAttempt != oldDescriptor.RouteAttempt ||
		body.PredecessorReceiptDigest != oldDescriptor.PredecessorReceiptDigest || body.StableActionID != oldDescriptor.StableActionID ||
		body.ExactRequestDigest != oldDescriptor.ExactRequestDigest || body.OldAdmissionLookupDigest != oldLookupDigest ||
		body.OldRelayExecutionDigest != oldDigest || body.OldAuthorizedActionDigest != oldActionDigest ||
		body.OldWriterFenceDigest != oldFenceDigest || body.NewAuthorizedActionDigest != newActionDigest ||
		body.NewWriterFenceDigest != newFenceDigest || body.NewWriterLeaseID != newExecution.WriterFence.Body.LeaseID ||
		body.NewWriterGeneration != newExecution.WriterFence.Body.WriterGeneration ||
		body.OldActionExpiresAtUnix != oldExecution.AuthorizedAction.ExpiresAtUnix ||
		body.NewActionExpiresAtUnix != newExecution.AuthorizedAction.ExpiresAtUnix ||
		body.NewActionExpiresAtUnix > body.OldActionExpiresAtUnix ||
		body.NewActionExpiresAtUnix != relayAdmissionReauthorizationExpiry(newExecution, newExecution.WriterFence) ||
		body.ResolvedNotFoundAtUnix >= body.NewActionExpiresAtUnix ||
		body.PolicyRevision != oldExecution.AuthorizedAction.PolicyRevision ||
		body.MandateDigest != oldExecution.AuthorizedAction.MandateDigest ||
		body.ApprovalDigest != oldExecution.AuthorizedAction.ApprovalDigest ||
		newDescriptor.OwnerID != oldDescriptor.OwnerID || newDescriptor.AgentID != oldDescriptor.AgentID ||
		newDescriptor.AuthenticatedPrincipal != oldDescriptor.AuthenticatedPrincipal ||
		newDescriptor.ProviderAgentID != oldDescriptor.ProviderAgentID ||
		newDescriptor.ServiceProfileDigest != oldDescriptor.ServiceProfileDigest ||
		newDescriptor.ProviderQuoteDigest != oldDescriptor.ProviderQuoteDigest ||
		newDescriptor.NetworkDigest != oldDescriptor.NetworkDigest ||
		newDescriptor.TransactionIdentityDigest != oldDescriptor.TransactionIdentityDigest ||
		newDescriptor.Mode != oldDescriptor.Mode || newDescriptor.AssuranceLevel != oldDescriptor.AssuranceLevel ||
		!reflect.DeepEqual(newDescriptor.StageMask, oldDescriptor.StageMask) ||
		newDescriptor.RouteAttempt != oldDescriptor.RouteAttempt ||
		newDescriptor.PredecessorReceiptDigest != oldDescriptor.PredecessorReceiptDigest ||
		newDescriptor.StableActionID != oldDescriptor.StableActionID ||
		newDescriptor.ExactRequestDigest != oldDescriptor.ExactRequestDigest ||
		newExecution.AuthorizedAction.AuthorityID != oldExecution.AuthorizedAction.AuthorityID ||
		newExecution.AuthorizedAction.PolicyRevision != oldExecution.AuthorizedAction.PolicyRevision ||
		newExecution.AuthorizedAction.MandateDigest != oldExecution.AuthorizedAction.MandateDigest ||
		newExecution.AuthorizedAction.ApprovalDigest != oldExecution.AuthorizedAction.ApprovalDigest ||
		newExecution.AuthorizedAction.ExpectedPriorState != oldExecution.AuthorizedAction.ExpectedPriorState {
		return errors.New("relay admission reauthorization changes immutable execution authority")
	}
	comparison := newExecution
	comparison.AuthorizedAction = oldExecution.AuthorizedAction
	comparison.WriterFence = oldExecution.WriterFence
	// PersonalAuthority V1 deliberately has one fixed signing key. Supporting
	// key rotation here would require a separately verified historical-key
	// lineage; fail closed until that lineage is part of the authority journal.
	if !reflect.DeepEqual(comparison, oldExecution) ||
		authorization.AuthorizedAction != newExecution.AuthorizedAction ||
		!reflect.DeepEqual(authorization.WriterFence, newExecution.WriterFence) ||
		newExecution.WriterFence.Body.WriterGeneration <= oldExecution.WriterFence.Body.WriterGeneration ||
		newExecution.WriterFence.Body.LeaseID == oldExecution.WriterFence.Body.LeaseID ||
		authorization.PublicKey != predecessor.PublicKey || authorization.PublicKey != oldExecution.AuthorizedAction.AuthorityPublicKey ||
		authorization.PublicKey != newExecution.AuthorizedAction.AuthorityPublicKey ||
		authorization.PublicKey != oldExecution.WriterFence.PublicKey || authorization.PublicKey != newExecution.WriterFence.PublicKey {
		return errors.New("relay admission reauthorization changes the exact execution")
	}
	const keyPrefix = "ed25519:"
	if len(authorization.PublicKey) <= len(keyPrefix) || authorization.PublicKey[:len(keyPrefix)] != keyPrefix ||
		len(authorization.Signature) <= len(keyPrefix) || authorization.Signature[:len(keyPrefix)] != keyPrefix {
		return errors.New("relay admission reauthorization signature is invalid")
	}
	publicRaw, err := hex.DecodeString(authorization.PublicKey[len(keyPrefix):])
	signatureRaw, signatureErr := base64.RawURLEncoding.DecodeString(authorization.Signature[len(keyPrefix):])
	canonical, canonicalErr := codec.Marshal(body)
	if err != nil || signatureErr != nil || canonicalErr != nil || len(publicRaw) != ed25519.PublicKeySize ||
		len(signatureRaw) != ed25519.SignatureSize ||
		authorization.PublicKey != keyPrefix+hex.EncodeToString(publicRaw) ||
		authorization.Signature != keyPrefix+base64.RawURLEncoding.EncodeToString(signatureRaw) ||
		!ed25519.Verify(ed25519.PublicKey(publicRaw),
			relayAdmissionReauthorizationMessage(canonical), signatureRaw) {
		return errors.New("relay admission reauthorization signature is invalid")
	}
	return nil
}

func relayAdmissionReauthorizationMessage(canonical []byte) []byte {
	digest := sha256.New()
	_, _ = digest.Write([]byte(relayAdmissionReauthorizationSignatureDomain))
	_, _ = digest.Write(canonical)
	return digest.Sum(nil)
}

func relayPendingAdmissionEnvelopeDigest(attempt RelayAttempt,
	predecessor agentrelay.SignedRelaySideEffectAdmissionReceipt) (string, error) {
	if !relayAttemptHasNoAdmissionReceipt(attempt) {
		return "", errors.New("pending relay admission already has a receipt")
	}
	descriptor, err := agentrelay.BuildRelaySideEffectAdmissionSuccessorDescriptor(attempt.Execution,
		attempt.Execution.QuoteRequest.Body.RequesterAgentID, predecessor)
	if err != nil {
		return "", err
	}
	return codec.Digest("tos.openfox.relay-pending-admission-envelope.v1", descriptor)
}
