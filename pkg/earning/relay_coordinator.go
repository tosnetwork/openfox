package earning

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

var ErrRelaySuccessorAdmissionNotEnabled = errors.New("relay successor-route admission is not enabled for sponsorship modes")

// PreparedRelayTransaction is produced only after local custody has signed a
// transaction. The bearer-executable BOC remains local until one provider has
// been selected and its complete Agreement has been authorized.
type PreparedRelayTransaction struct {
	QuoteBody               agentrelay.RelayQuoteRequestBody
	ExactSignedBOC          []byte
	UnderlyingAction        commerce.AuthorizedAction
	WriterFence             commerce.WriterFence
	SemanticFields          map[string]commerce.SemanticValue
	UnderlyingActionRequest []byte
}

type RelayAgreementMaterial struct {
	Agreement               commerce.AgentAgreement
	RelayObligationID       string
	SponsorshipObligationID string
	FeeObligationIDs        []string
	ExecutionExpiresAtUnix  uint64
}

type RelayAgreementAuthorizer interface {
	AuthorizeRelayAgreement(context.Context, agentrelay.SignedRelayQuoteRequest,
		agentrelay.SignedProviderRelayQuote) (RelayAgreementMaterial, error)
}

type RelayAgreementAuthorizerFunc func(context.Context, agentrelay.SignedRelayQuoteRequest,
	agentrelay.SignedProviderRelayQuote) (RelayAgreementMaterial, error)

func (function RelayAgreementAuthorizerFunc) AuthorizeRelayAgreement(ctx context.Context,
	request agentrelay.SignedRelayQuoteRequest, quote agentrelay.SignedProviderRelayQuote) (RelayAgreementMaterial, error) {
	return function(ctx, request, quote)
}

// RelayFinalityVerifier independently verifies referenced chain checkpoints,
// observers, source execution and destination credits. A provider signature
// authenticates an attestation but never makes that attestation chain truth.
// Capability checks are deliberately exact: readiness and the pre-finish
// boundary both use the same signed mode/network/profile/evidence tuple.
type RelayFinalityVerifier interface {
	agentrelay.RelayFinalityEvidenceVerifier
}

const maximumRelayClientEvidenceSnapshotBytes = 256 << 10

// RelayClientEvidenceSnapshot is protected requester state frozen before a
// Quote is sent. It binds the exact evidence capability to the verifier's
// immutable endpoint/operator/config material, so a restart or owner config
// rotation cannot reinterpret an already admitted attempt under a different
// trust set.
type RelayClientEvidenceSnapshot struct {
	SchemaVersion               uint16                             `json:"schema_version"`
	Capability                  agentrelay.RelayEvidenceCapability `json:"capability"`
	DualAbsence                 bool                               `json:"dual_absence"`
	SponsorshipComponentAbsence bool                               `json:"sponsorship_component_absence"`
	TransactionComponentAbsence bool                               `json:"transaction_component_absence"`
	PortableProof               bool                               `json:"portable_proof"`
	Opaque                      []byte                             `json:"protected_opaque_snapshot"`
	Identity                    string                             `json:"snapshot_identity"`
}

// RelayClientFinalitySnapshotVerifier is mandatory for execution readiness.
// The opaque bytes are verifier-defined and stored only in protected attempt
// and route journals. OpenFox independently binds them to the exact capability
// and rejects missing, mutated, or substituted snapshots before verification.
type RelayClientFinalitySnapshotVerifier interface {
	RelayFinalityVerifier
	FreezeRelayFinalityEvidenceSnapshot(context.Context, agentrelay.RelayEvidenceCapability) ([]byte, error)
	ValidateRelayFinalityEvidenceSnapshot(agentrelay.RelayEvidenceCapability, []byte) error
	VerifyRelayFinalityFromSnapshot(context.Context, agentrelay.RelayExecutionRequest,
		agentrelay.SignedRelayFinalityEvidence, []byte) error
}

// RelayQuotedTransaction freezes a candidate locally. ExactSignedBOC is absent
// from SignedRelayQuoteRequest and therefore is not disclosed by Quote.
type RelayQuotedTransaction struct {
	Prepared                          PreparedRelayTransaction
	Request                           agentrelay.SignedRelayQuoteRequest
	Quote                             agentrelay.SignedProviderRelayQuote
	ClientFinalityEvidenceSnapshot    *RelayClientEvidenceSnapshot
	ClientSponsorshipEvidenceSnapshot *RelaySponsorshipEvidenceSnapshot
}

// RelayAttempt is the exact provider-scoped artifact persisted before any
// potentially ambiguous Submit. It does not create a new semantic identity
// for the underlying payment.direct action.
type RelayAttempt struct {
	Execution                         agentrelay.RelayExecutionRequest
	Agreement                         commerce.AgentAgreement
	ClientFinalityEvidenceSnapshot    *RelayClientEvidenceSnapshot      `json:"client_finality_evidence_snapshot,omitempty"`
	ClientSponsorshipEvidenceSnapshot *RelaySponsorshipEvidenceSnapshot `json:"client_sponsorship_evidence_snapshot,omitempty"`
}

type RelayExecutionResult struct {
	Resolution agentrelay.SignedRelayResolution
	Evidence   *agentrelay.SignedRelayFinalityEvidence
}

type RelayCoordinator struct {
	VerifiedProfile     VerifiedRelayServiceProfile
	Transport           RelayTransport
	RequesterKey        ed25519.PrivateKey
	AgentResolver       agentrelay.AgentKeyResolver
	FenceResolver       commerce.CurrentWriterFenceResolver
	Inspector           agentrelay.TransactionInspector
	ActionBinder        agentrelay.ActionTransactionBinder
	AgreementVerifier   commerce.AgreementEvidenceVerifier
	AgreementAuthorizer RelayAgreementAuthorizer
	SideEffectAdmission agentrelay.RelaySideEffectAdmissionAuthority
	FinalityVerifier    RelayFinalityVerifier
	// SponsorshipEvidenceVerifier validates the exact nested Provider-funded
	// top-up proof. A Provider signature or generic client-transaction finality
	// callback cannot promote a transfer reference into Agreement-bound credit.
	SponsorshipEvidenceVerifier agentrelay.SponsorshipTransactionEvidenceVerifier
	// SponsorshipEffectRegistry is the owner-wide durable replay boundary for
	// terminal Provider-funded chain effects. It prevents one genuine old
	// top-up from closing a different Agreement after restart or route/profile
	// rotation.
	SponsorshipEffectRegistry RelaySponsorshipEffectRegistry
	// SponsorshipReleasePolicy is the exact owner-selected class/profile copied
	// into the signed request, Provider quote, Agreement and admission evidence.
	// A model or Provider cannot replace it after pricing.
	SponsorshipReleasePolicy RelaySponsorshipReleasePolicy
	// Autonomous Submit is disabled unless an owner-private, process-locked
	// durable journal is explicitly configured.
	AttemptJournal *DurableRelayJournal
	Now            func() time.Time
}

// Quote validates the locally held BOC and sends only its signed descriptor to
// one independently verified profile. It creates no Agreement or fee promise.
func (coordinator RelayCoordinator) Quote(ctx context.Context,
	prepared PreparedRelayTransaction) (RelayQuotedTransaction, error) {
	now := coordinator.now()
	if ctx == nil || coordinator.Transport == nil || len(coordinator.RequesterKey) != ed25519.PrivateKeySize ||
		coordinator.AgentResolver == nil || coordinator.FenceResolver == nil || coordinator.Inspector == nil ||
		coordinator.ActionBinder == nil {
		return RelayQuotedTransaction{}, errors.New("relay quote coordinator is incomplete")
	}
	frozen, err := clonePreparedRelayTransaction(prepared)
	if err != nil {
		return RelayQuotedTransaction{}, err
	}
	profile := coordinator.VerifiedProfile.Profile()
	if err := coordinator.validatePrepared(frozen, profile, now); err != nil {
		return RelayQuotedTransaction{}, err
	}
	signedRequest, err := agentrelay.SignRelayQuoteRequest(frozen.QuoteBody, coordinator.RequesterKey)
	if err != nil {
		return RelayQuotedTransaction{}, err
	}
	if err := coordinator.VerifiedProfile.authorizeQuoteRequest(signedRequest, now); err != nil ||
		agentrelay.VerifyRelayQuoteRequest(signedRequest, profile, coordinator.AgentResolver, now) != nil {
		return RelayQuotedTransaction{}, errors.New("locally signed relay quote descriptor failed independent verification")
	}
	capability, capabilityErr := relayEvidenceCapabilityForQuoteBody(profile, signedRequest.Body)
	snapshotVerifier, snapshotOK := coordinator.FinalityVerifier.(RelayClientFinalitySnapshotVerifier)
	if capabilityErr != nil || !snapshotOK {
		return RelayQuotedTransaction{}, errors.New("relay quote has no client-owned frozen finality verifier")
	}
	opaqueSnapshot, freezeErr := snapshotVerifier.FreezeRelayFinalityEvidenceSnapshot(ctx, capability)
	dualAbsence := snapshotVerifier.SupportsRelayDualAbsenceEvidence(capability)
	sponsorshipComponentAbsence := snapshotVerifier.SupportsRelaySponsorshipComponentAbsenceEvidence(capability)
	transactionComponentAbsence := snapshotVerifier.SupportsRelayTransactionComponentAbsenceEvidence(capability)
	portableVerifier, portableOK := snapshotVerifier.(agentrelay.PortableRelayFinalityEvidenceVerifier)
	portableProof := portableOK && portableVerifier.HasIndependentPortableRelayFinalityProofs()
	clientFinalitySnapshot, snapshotErr := newRelayClientEvidenceSnapshot(capability, opaqueSnapshot,
		dualAbsence, sponsorshipComponentAbsence, transactionComponentAbsence, portableProof)
	if freezeErr != nil || snapshotErr != nil ||
		snapshotVerifier.ValidateRelayFinalityEvidenceSnapshot(capability, opaqueSnapshot) != nil {
		return RelayQuotedTransaction{}, errors.New("freeze exact client relay verification snapshot")
	}
	var clientSnapshot *RelaySponsorshipEvidenceSnapshot
	if signedRequest.Body.SponsorshipReleaseEvidenceClass == agentrelay.SponsorshipReleaseObservedUnproven {
		verifier, ok := coordinator.SponsorshipEvidenceVerifier.(RelaySponsorshipClientSnapshotVerifier)
		if !ok {
			return RelayQuotedTransaction{}, errors.New("observed sponsorship has no client-owned frozen verifier snapshot")
		}
		frozen, freezeErr := verifier.FreezeRelaySponsorshipClientEvidenceSnapshot(ctx, signedRequest.Body)
		selected := signedRequest.Body.SelectedSponsorshipReleaseProfile()
		if freezeErr != nil || !validClientRelaySponsorshipSnapshot(selected, frozen) ||
			verifier.ValidateRelaySponsorshipClientEvidenceSnapshot(selected, frozen) != nil {
			return RelayQuotedTransaction{}, errors.New("freeze exact client sponsorship verification snapshot")
		}
		copy := frozen
		clientSnapshot = &copy
	}
	// Parse and bind the exact local bytes before even disclosing their digest.
	wireFields, err := commerce.ExportSemanticFields(frozen.UnderlyingAction.ActionKind, frozen.SemanticFields)
	if err != nil {
		return RelayQuotedTransaction{}, errors.New("relay semantic fields cannot be exported for transaction binding")
	}
	bindingRequest := agentrelay.RelayExecutionRequest{QuoteRequest: signedRequest,
		SignedTransactionBytes:  append([]byte(nil), frozen.ExactSignedBOC...),
		UnderlyingActionRequest: append([]byte(nil), frozen.UnderlyingActionRequest...), SemanticFields: wireFields,
		AuthorizedAction: frozen.UnderlyingAction, WriterFence: frozen.WriterFence}
	if err := agentrelay.VerifyActionTransactionBinding(ctx, bindingRequest, profile, coordinator.Inspector,
		coordinator.ActionBinder); err != nil {
		return RelayQuotedTransaction{}, errors.New("signed transaction does not realize the authorized economic action")
	}
	quote, err := coordinator.Transport.Quote(ctx, signedRequest)
	if err != nil {
		return RelayQuotedTransaction{}, err
	}
	if err := agentrelay.VerifyProviderRelayQuote(quote, signedRequest, profile, coordinator.AgentResolver, now); err != nil ||
		quote.Body.OfferIntentDigest != coordinator.VerifiedProfile.IntentDigest() {
		return RelayQuotedTransaction{}, errors.New("relay quote failed independent verification")
	}
	if quote.Body.Mode == agentrelay.ModeSponsorOnly || quote.Body.Mode == agentrelay.ModeSponsorAndRelay {
		capability, ok := coordinator.SponsorshipEvidenceVerifier.(RelaySponsorshipClientEvidenceCapability)
		if quote.Body.SponsorshipTerminalProfile == nil {
			return RelayQuotedTransaction{}, errors.New("relay sponsorship quote omits its terminal evidence profile")
		}
		if !ok || !capability.SupportsRelaySponsorshipTransactionEvidence(quote.Body.AssuranceLevel,
			coordinator.SponsorshipReleasePolicy, *quote.Body.SponsorshipTerminalProfile) {
			return RelayQuotedTransaction{}, errors.New("relay sponsorship quote selects an unverifiable terminal evidence profile")
		}
	}
	return RelayQuotedTransaction{Prepared: frozen, Request: signedRequest, Quote: quote,
		ClientFinalityEvidenceSnapshot:    clientFinalitySnapshot,
		ClientSponsorshipEvidenceSnapshot: clientSnapshot}, nil
}

// Authorize creates the generic Agreement for a selected quote and only then
// attaches the exact BOC to the execution envelope.
func (coordinator RelayCoordinator) Authorize(ctx context.Context,
	quoted RelayQuotedTransaction) (RelayAttempt, error) {
	return coordinator.authorize(ctx, quoted, nil)
}

// authorizeSuccessor creates a new Provider-specific Agreement and admission
// receipt for the same relay_exact transaction. The receipt's predecessor
// chain is the authority-visible proof that this is route attempt n+1, not a
// second semantic payment. Sponsorship modes deliberately have no successor
// path until a portable, independently verifiable top-up proof is standardized.
func (coordinator RelayCoordinator) authorizeSuccessor(ctx context.Context, quoted RelayQuotedTransaction,
	predecessor agentrelay.SignedRelaySideEffectAdmissionReceipt) (RelayAttempt, error) {
	if predecessor.Body.Mode != agentrelay.ModeRelayExact || quoted.Request.Body.Mode != agentrelay.ModeRelayExact ||
		predecessor.Body.AssuranceLevel != agentrelay.AssuranceAutonomousDecentralized ||
		quoted.Request.Body.AssuranceLevel != agentrelay.AssuranceAutonomousDecentralized {
		return RelayAttempt{}, ErrRelaySuccessorAdmissionNotEnabled
	}
	return coordinator.authorize(ctx, quoted, &predecessor)
}

func (coordinator RelayCoordinator) authorize(ctx context.Context, quoted RelayQuotedTransaction,
	predecessor *agentrelay.SignedRelaySideEffectAdmissionReceipt) (RelayAttempt, error) {
	draft, err := coordinator.buildAttempt(ctx, quoted)
	if err != nil {
		return RelayAttempt{}, err
	}
	return coordinator.admitAttempt(ctx, draft, predecessor)
}

// buildAttempt freezes the exact Provider Agreement and execution before the
// Action Authority is contacted. The decentralized route journal persists a
// successor draft first, so a crash after receipt issuance can reconstruct the
// same lookup and recover the one linearized receipt.
func (coordinator RelayCoordinator) buildAttempt(ctx context.Context,
	quoted RelayQuotedTransaction) (RelayAttempt, error) {
	now := coordinator.now()
	if ctx == nil || coordinator.AgreementVerifier == nil || coordinator.AgreementAuthorizer == nil {
		return RelayAttempt{}, errors.New("relay Agreement coordinator is incomplete")
	}
	profile := coordinator.VerifiedProfile.Profile()
	if err := coordinator.validateQuoted(quoted, profile, now); err != nil {
		return RelayAttempt{}, err
	}
	material, err := coordinator.AgreementAuthorizer.AuthorizeRelayAgreement(ctx, quoted.Request, quoted.Quote)
	if err != nil {
		return RelayAttempt{}, err
	}
	agreementDigest, err := commerce.AgreementBodyDigest(material.Agreement.Body)
	if err != nil {
		return RelayAttempt{}, err
	}
	wireFields, err := commerce.ExportSemanticFields(quoted.Prepared.UnderlyingAction.ActionKind,
		quoted.Prepared.SemanticFields)
	if err != nil {
		return RelayAttempt{}, err
	}
	execution := agentrelay.RelayExecutionRequest{SchemaVersion: 1, QuoteRequest: quoted.Request, ProviderQuote: quoted.Quote,
		SignedTransactionBytes: append([]byte(nil), quoted.Prepared.ExactSignedBOC...),
		AgreementBodyDigest:    agreementDigest, AgreementExpiresAtUnix: material.Agreement.Body.ExpiresAtUnix,
		RelayObligationID: material.RelayObligationID, SponsorshipObligationID: material.SponsorshipObligationID,
		FeeObligationIDs:        append([]string(nil), material.FeeObligationIDs...),
		UnderlyingActionRequest: append([]byte(nil), quoted.Prepared.UnderlyingActionRequest...), SemanticFields: wireFields,
		AuthorizedAction: quoted.Prepared.UnderlyingAction, WriterFence: quoted.Prepared.WriterFence,
		CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: material.ExecutionExpiresAtUnix}
	if err := agentrelay.VerifyRelayExecutionRequestForAdmission(ctx, execution, profile, coordinator.AgentResolver,
		coordinator.FenceResolver, coordinator.Inspector, now); err != nil {
		return RelayAttempt{}, errors.New("relay execution failed owner-side admission preflight: " + err.Error())
	}
	if err := agentrelay.VerifyActionTransactionBinding(ctx, execution, profile, coordinator.Inspector,
		coordinator.ActionBinder); err != nil {
		return RelayAttempt{}, err
	}
	if err := agentrelay.VerifyRelayExecutionAgreement(execution, material.Agreement,
		coordinator.AgreementVerifier, now); err != nil {
		return RelayAttempt{}, err
	}
	return RelayAttempt{Execution: execution, Agreement: material.Agreement,
		ClientFinalityEvidenceSnapshot: cloneRelayClientEvidenceSnapshot(
			quoted.ClientFinalityEvidenceSnapshot),
		ClientSponsorshipEvidenceSnapshot: cloneRelaySponsorshipEvidenceSnapshot(
			quoted.ClientSponsorshipEvidenceSnapshot)}, nil
}

func (coordinator RelayCoordinator) admitAttempt(ctx context.Context, draft RelayAttempt,
	predecessor *agentrelay.SignedRelaySideEffectAdmissionReceipt) (RelayAttempt, error) {
	now := coordinator.now()
	if ctx == nil || coordinator.SideEffectAdmission == nil {
		return RelayAttempt{}, errors.New("relay side-effect admission authority is unavailable")
	}
	execution := draft.Execution
	if execution.AdmissionReceipt.Body.SchemaVersion != 0 {
		return RelayAttempt{}, errors.New("relay admission draft already carries a receipt")
	}
	var descriptor agentrelay.RelaySideEffectAdmissionDescriptor
	var err error
	if predecessor == nil {
		descriptor, err = agentrelay.BuildRelaySideEffectAdmissionDescriptor(execution)
	} else {
		descriptor, err = agentrelay.BuildRelaySideEffectAdmissionSuccessorDescriptor(execution,
			execution.QuoteRequest.Body.RequesterAgentID, *predecessor)
	}
	if err != nil {
		return RelayAttempt{}, err
	}
	receipt, admitErr := coordinator.SideEffectAdmission.AdmitRelaySideEffects(ctx, descriptor)
	if admitErr != nil {
		receipt, err = coordinator.SideEffectAdmission.ResolveRelaySideEffectAdmission(ctx, descriptor.Lookup())
		if err != nil {
			return RelayAttempt{}, errors.Join(errors.New("relay side-effect admission outcome is ambiguous"), admitErr, err)
		}
	}
	execution.AdmissionReceipt = receipt
	if predecessor != nil {
		if err := agentrelay.VerifyRelaySideEffectAdmissionSuccessorReceipt(receipt, execution,
			*predecessor, now); err != nil {
			return RelayAttempt{}, errors.New("relay successor admission receipt is invalid: " + err.Error())
		}
	}
	attempt := RelayAttempt{Execution: execution, Agreement: draft.Agreement,
		ClientFinalityEvidenceSnapshot: cloneRelayClientEvidenceSnapshot(
			draft.ClientFinalityEvidenceSnapshot),
		ClientSponsorshipEvidenceSnapshot: cloneRelaySponsorshipEvidenceSnapshot(
			draft.ClientSponsorshipEvidenceSnapshot)}
	if err := coordinator.validateAttempt(ctx, attempt, now); err != nil {
		return RelayAttempt{}, err
	}
	return attempt, nil
}

// resolveAttempt performs recovery without replaying Admit. It is required
// after writer takeover when a pending admission was already marked started:
// the superseded envelope must first be resolved at the same linearization
// authority and may never be resubmitted with stale writer credentials.
func (coordinator RelayCoordinator) resolveAttempt(ctx context.Context, draft RelayAttempt,
	predecessor agentrelay.SignedRelaySideEffectAdmissionReceipt) (RelayAttempt, error) {
	if ctx == nil || coordinator.SideEffectAdmission == nil {
		return RelayAttempt{}, errors.New("relay side-effect admission authority is unavailable")
	}
	execution := draft.Execution
	if execution.AdmissionReceipt.Body.SchemaVersion != 0 {
		return RelayAttempt{}, errors.New("relay admission draft already carries a receipt")
	}
	descriptor, err := agentrelay.BuildRelaySideEffectAdmissionSuccessorDescriptor(execution,
		execution.QuoteRequest.Body.RequesterAgentID, predecessor)
	if err != nil {
		return RelayAttempt{}, err
	}
	receipt, err := coordinator.SideEffectAdmission.ResolveRelaySideEffectAdmission(ctx, descriptor.Lookup())
	if err != nil {
		return RelayAttempt{}, err
	}
	execution.AdmissionReceipt = receipt
	now := coordinator.now()
	if err := agentrelay.VerifyRelaySideEffectAdmissionSuccessorReceipt(receipt, execution,
		predecessor, now); err != nil {
		return RelayAttempt{}, errors.New("resolved relay successor admission receipt is invalid: " + err.Error())
	}
	attempt := RelayAttempt{Execution: execution, Agreement: draft.Agreement,
		ClientFinalityEvidenceSnapshot: cloneRelayClientEvidenceSnapshot(
			draft.ClientFinalityEvidenceSnapshot),
		ClientSponsorshipEvidenceSnapshot: cloneRelaySponsorshipEvidenceSnapshot(
			draft.ClientSponsorshipEvidenceSnapshot)}
	if err := coordinator.validateAttempt(ctx, attempt, now); err != nil {
		return RelayAttempt{}, err
	}
	return attempt, nil
}

func (coordinator RelayCoordinator) reauthorizePendingAttempt(ctx context.Context, draft RelayAttempt,
	predecessor agentrelay.SignedRelaySideEffectAdmissionReceipt) (RelayAttempt, relayAdmissionReauthorization, error) {
	reauthorizer, ok := coordinator.SideEffectAdmission.(relayAdmissionReauthorizer)
	if !ok {
		return RelayAttempt{}, relayAdmissionReauthorization{},
			errors.New("relay admission authority cannot prove an unlinearized takeover rebase")
	}
	descriptor, err := agentrelay.BuildRelaySideEffectAdmissionSuccessorDescriptor(draft.Execution,
		draft.Execution.QuoteRequest.Body.RequesterAgentID, predecessor)
	if err != nil {
		return RelayAttempt{}, relayAdmissionReauthorization{}, err
	}
	authorization, err := reauthorizer.reauthorizeUnlinearizedRelayAdmission(ctx, descriptor, draft.Execution)
	if err != nil {
		return RelayAttempt{}, relayAdmissionReauthorization{}, err
	}
	rebased := cloneRelayAttempt(draft)
	rebased.Execution.AuthorizedAction = authorization.AuthorizedAction
	rebased.Execution.WriterFence = authorization.WriterFence
	if err := verifyRelayAdmissionReauthorization(authorization, draft, rebased, predecessor); err != nil {
		return RelayAttempt{}, relayAdmissionReauthorization{}, err
	}
	now := coordinator.now()
	profile := coordinator.VerifiedProfile.Profile()
	if err := agentrelay.VerifyRelayExecutionRequestForAdmission(ctx, rebased.Execution, profile,
		coordinator.AgentResolver, coordinator.FenceResolver, coordinator.Inspector, now); err != nil {
		return RelayAttempt{}, relayAdmissionReauthorization{},
			errors.New("rebased relay execution failed current-writer preflight: " + err.Error())
	}
	if err := agentrelay.VerifyActionTransactionBinding(ctx, rebased.Execution, profile,
		coordinator.Inspector, coordinator.ActionBinder); err != nil {
		return RelayAttempt{}, relayAdmissionReauthorization{}, err
	}
	if err := agentrelay.VerifyRelayExecutionAgreement(rebased.Execution, rebased.Agreement,
		coordinator.AgreementVerifier, now); err != nil {
		return RelayAttempt{}, relayAdmissionReauthorization{}, err
	}
	return rebased, authorization, nil
}

// Prepare is the single-provider convenience seam. Multi-provider users
// should use DecentralizedRelayCoordinator so selection precedes Agreement.
func (coordinator RelayCoordinator) Prepare(ctx context.Context,
	prepared PreparedRelayTransaction) (RelayAttempt, error) {
	quoted, err := coordinator.Quote(ctx, prepared)
	if err != nil {
		return RelayAttempt{}, err
	}
	return coordinator.Authorize(ctx, quoted)
}

// Submit durably admits the exact request and resolves the selected provider.
// Exact relay bytes may be retried because the chain transaction identity is
// unchanged. A sponsorship is never first-dispatched through this provider-
// scoped method: that requires the owner-wide route journal to persist the
// ambiguity boundary before the socket write. A signed PREPARED provider record
// may be resumed because the provider has already admitted the stable identity.
func (coordinator RelayCoordinator) Submit(ctx context.Context, attempt RelayAttempt) (RelayExecutionResult, error) {
	return coordinator.submit(ctx, attempt, false)
}

// submit permits a fresh sponsorship dispatch only when the decentralized
// route journal has atomically changed SubmitStarted from false to true for the
// exact route. The boolean is deliberately private: it is an admission fact,
// not a caller-controlled retry option.
func (coordinator RelayCoordinator) submit(ctx context.Context, attempt RelayAttempt,
	allowFreshSponsorship bool) (RelayExecutionResult, error) {
	now := coordinator.now()
	if ctx == nil || coordinator.Transport == nil || coordinator.AttemptJournal == nil {
		return RelayExecutionResult{}, errors.New("autonomous relay submit requires a durable attempt journal")
	}
	if err := coordinator.validateAttempt(ctx, attempt, now); err != nil {
		return RelayExecutionResult{}, err
	}
	profile := coordinator.VerifiedProfile.Profile()
	reserved, _, err := coordinator.AttemptJournal.ReserveQuote(profile, attempt.Execution.QuoteRequest,
		attempt.Execution.ProviderQuote, now)
	if err != nil || !reflect.DeepEqual(reserved, attempt.Execution.ProviderQuote) {
		return RelayExecutionResult{}, errors.New("relay attempt quote could not be durably reserved")
	}
	record, _, err := coordinator.AttemptJournal.Admit(attempt.Execution, now)
	if err != nil {
		return RelayExecutionResult{}, err
	}
	call := agentrelay.ResolveCall{StableActionID: attempt.Execution.AuthorizedAction.StableActionID,
		ExactRequestDigest: attempt.Execution.AuthorizedAction.ExactRequestDigest}
	prior, resolveErr := coordinator.Transport.Resolve(ctx, call, attempt.Execution)
	remotePrepared := resolveErr == nil && prior.Body.State == commerce.ActionPrepared
	if resolveErr == nil {
		if !remotePrepared {
			return coordinator.acceptResolution(ctx, attempt, record, prior)
		}
		// PREPARED is permission to resume a sponsorship only when it is an
		// authentic, exact provider record. An unverified transport response
		// cannot create that authority.
		if err := coordinator.verifyResolution(attempt.Execution, prior); err != nil {
			return RelayExecutionResult{}, err
		}
	}
	if resolveErr != nil && !errors.Is(resolveErr, ErrRelayRemoteUnknown) {
		return RelayExecutionResult{}, resolveErr
	}
	mode := attempt.Execution.QuoteRequest.Body.Mode
	if mode == agentrelay.ModeRelayExact {
		if record.State == commerce.ActionPrepared {
			record, err = coordinator.AttemptJournal.Transition(record.StableActionID, record.ExactRequestDigest,
				record.StateRevision, commerce.ActionSubmitted, "", nil, "", now)
			if err != nil {
				return RelayExecutionResult{}, err
			}
		} else if record.State != commerce.ActionSubmitted {
			return RelayExecutionResult{}, errors.New("local relay state forbids another ambiguous submit")
		}
	} else {
		if record.State != commerce.ActionPrepared {
			return RelayExecutionResult{}, errors.New("local sponsorship attempt is not awaiting provider resolution")
		}
		if !allowFreshSponsorship && !remotePrepared {
			// A missing provider record is not proof that a top-up did not happen.
			// Keep the outcome ambiguous until the exact sponsor transaction has
			// expired and independently verified, profile-qualified absence evidence
			// authorizes provider failover.
			return RelayExecutionResult{}, fmt.Errorf("%w: sponsorship dispatch has no durable provider record or fresh route admission",
				ErrRelaySubmissionAmbiguous)
		}
	}
	stage := agentrelay.SideEffectBroadcast
	if mode != agentrelay.ModeRelayExact {
		stage = agentrelay.SideEffectSponsorship
	}
	now = coordinator.now()
	if err := agentrelay.VerifyRelayRemainingValidity(attempt.Execution, now, stage); err != nil {
		return RelayExecutionResult{}, errors.New("relay attempt lacks a safe remaining side-effect window")
	}
	resolution, submitErr := coordinator.Transport.Submit(ctx, attempt.Execution, attempt.Agreement)
	if submitErr != nil {
		// Query the exact identity after every Submit error. Provider failover is
		// never inferred from a timeout, status code, or malformed response.
		resolved, retryErr := coordinator.Transport.Resolve(ctx, call, attempt.Execution)
		if retryErr != nil {
			return RelayExecutionResult{}, submitErr
		}
		resolution = resolved
	}
	return coordinator.acceptResolution(ctx, attempt, record, resolution)
}

func (coordinator RelayCoordinator) Execute(ctx context.Context,
	prepared PreparedRelayTransaction) (RelayAttempt, RelayExecutionResult, error) {
	attempt, err := coordinator.Prepare(ctx, prepared)
	if err != nil {
		return RelayAttempt{}, RelayExecutionResult{}, err
	}
	result, err := coordinator.Submit(ctx, attempt)
	return attempt, result, err
}

func (coordinator RelayCoordinator) acceptResolution(ctx context.Context, attempt RelayAttempt,
	record agentrelay.Record, resolution agentrelay.SignedRelayResolution) (RelayExecutionResult, error) {
	execution := attempt.Execution
	if err := coordinator.verifyResolution(execution, resolution); err != nil {
		return RelayExecutionResult{}, err
	}
	if resolution.Body.State != commerce.ActionTerminal {
		if err := coordinator.syncAttemptRecord(record, resolution.Body.State,
			resolution.Body.TransactionReference, nil, ""); err != nil {
			return RelayExecutionResult{}, err
		}
		return RelayExecutionResult{Resolution: resolution}, nil
	}
	result, err := coordinator.finish(ctx, attempt, resolution)
	if err != nil {
		return RelayExecutionResult{}, err
	}
	evidenceDigest, err := agentrelay.RelayFinalityEvidenceDigest(result.Evidence.Body)
	if err != nil {
		return RelayExecutionResult{}, err
	}
	if execution.QuoteRequest.Body.Mode != agentrelay.ModeRelayExact {
		body := result.Evidence.Body
		if body.SponsorshipTransferReference == "" && len(body.SponsorshipAbsenceObservations) == 0 {
			return RelayExecutionResult{}, errors.New("terminal sponsorship result lacks transfer or typed absence proof")
		}
		if body.SponsorshipTransactionEvidence != nil {
			if coordinator.SponsorshipEffectRegistry == nil {
				return RelayExecutionResult{}, errors.New("terminal sponsorship has no owner-wide chain-effect replay registry")
			}
			if err := coordinator.SponsorshipEffectRegistry.BindSponsorshipChainEffect(execution,
				*body.SponsorshipTransactionEvidence, coordinator.now()); err != nil {
				return RelayExecutionResult{}, errors.New("bind terminal sponsorship chain effect: " + err.Error())
			}
		}
		// The client does not own the provider's protected sponsorship recovery
		// handle and must not manufacture one after finality (an absence proof is
		// necessarily after its expiry). Keep the provider-scoped attempt PREPARED;
		// the owner-wide route journal already persisted SubmitStarted and every
		// restart resolves that same provider before any failover. The provider is
		// solely responsible for Begin/RecordSponsorship in its durable journal.
		return result, nil
	}
	if err := coordinator.syncAttemptRecord(record, commerce.ActionTerminal, resolution.Body.TransactionReference,
		[]string{evidenceDigest}, resolution.Body.TerminalOutcome); err != nil {
		return RelayExecutionResult{}, err
	}
	return result, nil
}

func (coordinator RelayCoordinator) syncAttemptRecord(record agentrelay.Record, target commerce.ActionResolutionState,
	transactionReference string, evidenceRefs []string, outcome agentrelay.TerminalOutcome) error {
	if record.ExecutionRequest().QuoteRequest.Body.Mode != agentrelay.ModeRelayExact &&
		(target == commerce.ActionSubmitted || target == commerce.ActionAccepted) {
		// These are provider-side states after sponsorship. The client has no
		// independently verified transfer reference until terminal Evidence, so
		// its durable mirror remains PREPARED and Resolve remains mandatory.
		return nil
	}
	for record.State != target {
		next := target
		switch record.State {
		case commerce.ActionPrepared:
			if target == commerce.ActionAccepted {
				next = commerce.ActionSubmitted
			}
		case commerce.ActionSubmitted:
		case commerce.ActionAccepted:
			if target != commerce.ActionSubmitted && target != commerce.ActionTerminal {
				return errors.New("relay resolution regresses an accepted local attempt")
			}
		default:
			return errors.New("relay resolution conflicts with a locally completed attempt")
		}
		stepReference, stepEvidence, stepOutcome := "", []string(nil), agentrelay.TerminalOutcome("")
		if next == target {
			stepReference, stepEvidence, stepOutcome = transactionReference, evidenceRefs, outcome
		}
		updated, err := coordinator.AttemptJournal.Transition(record.StableActionID, record.ExactRequestDigest,
			record.StateRevision, next, stepReference, stepEvidence, stepOutcome, coordinator.now())
		if err != nil {
			return err
		}
		record = updated
	}
	return nil
}

func (coordinator RelayCoordinator) finish(ctx context.Context, attempt RelayAttempt,
	resolution agentrelay.SignedRelayResolution) (RelayExecutionResult, error) {
	execution := attempt.Execution
	if coordinator.FinalityVerifier == nil {
		return RelayExecutionResult{}, errors.New("terminal relay result has no independent finality verifier")
	}
	call := agentrelay.EvidenceCall{StableActionID: execution.AuthorizedAction.StableActionID,
		ExactRequestDigest: execution.AuthorizedAction.ExactRequestDigest}
	evidence, err := coordinator.Transport.Evidence(ctx, call, execution)
	if err != nil {
		return RelayExecutionResult{}, err
	}
	if evidence.Body.Outcome != resolution.Body.TerminalOutcome ||
		coordinator.verifyIndependentFinality(ctx, attempt, evidence) != nil {
		return RelayExecutionResult{}, errors.New("relay terminal evidence failed independent chain verification")
	}
	if !relayResolutionReferenceMatchesEvidence(resolution.Body, evidence.Body) {
		return RelayExecutionResult{}, errors.New("relay terminal resolution reference is not bound to independent evidence")
	}
	return RelayExecutionResult{Resolution: resolution, Evidence: &evidence}, nil
}

func relayResolutionReferenceMatchesEvidence(resolution agentrelay.RelayResolutionBody,
	evidence agentrelay.RelayFinalityEvidenceBody) bool {
	evidenceRefs, err := relayFinalityEvidenceRefs(evidence)
	if err != nil {
		return false
	}
	evidenceSetDigest, err := agentrelay.RelayEvidenceSetDigest(evidenceRefs)
	if err != nil || resolution.EvidenceSetDigest != evidenceSetDigest {
		return false
	}
	if resolution.SponsorshipStableActionID != evidence.SponsorshipStableActionID ||
		resolution.SponsorshipExactRequestDigest != evidence.SponsorshipExactRequestDigest ||
		resolution.SponsorshipValidUntilUnix != evidence.SponsorshipValidUntilUnix ||
		resolution.SponsorshipTransferReference != evidence.SponsorshipTransferReference {
		return false
	}
	switch evidence.Outcome {
	case agentrelay.OutcomeFinalizedSuccess, agentrelay.OutcomeCorroboratedSuccess:
		return evidence.SubmittedTransactionHash != "" &&
			resolution.TransactionReference == evidence.SubmittedTransactionHash
	case agentrelay.OutcomeFinalizedRelayOnly, agentrelay.OutcomeCorroboratedRelayOnly:
		return evidence.SubmittedTransactionHash != "" && evidence.SponsorshipTransferReference == "" &&
			resolution.TransactionReference == evidence.SubmittedTransactionHash
	case agentrelay.OutcomeFinalizedSponsorshipOnly,
		agentrelay.OutcomeCorroboratedSponsorshipOnly:
		return evidence.SponsorshipTransferReference != "" &&
			resolution.TransactionReference == evidence.SponsorshipTransferReference
	case agentrelay.OutcomeFinalizedAbsent, agentrelay.OutcomeFinalizedExpired, agentrelay.OutcomeFinalizedInvalidated,
		agentrelay.OutcomeCorroboratedAbsent, agentrelay.OutcomeCorroboratedExpired,
		agentrelay.OutcomeCorroboratedInvalidated:
		return resolution.TransactionReference == ""
	default:
		return false
	}
}

func relayFinalityEvidenceRefs(evidence agentrelay.RelayFinalityEvidenceBody) ([]string, error) {
	refs := append([]string(nil), evidence.RelayObservationDigests...)
	if evidence.SponsorshipTransactionEvidence != nil {
		refs = append(refs, evidence.SponsorshipTransactionEvidence.ObservationDigests...)
	}
	for _, observations := range [][]agentrelay.RelayAbsenceObservationReference{
		evidence.SponsorshipAbsenceObservations, evidence.TransactionAbsenceObservations,
	} {
		for _, observation := range observations {
			digest, err := agentrelay.RelayAbsenceObservationReferenceDigest(observation)
			if err != nil {
				return nil, err
			}
			refs = append(refs, digest)
		}
	}
	sort.Strings(refs)
	if len(refs) == 0 {
		return nil, errors.New("relay finality evidence has no observation references")
	}
	for index := 1; index < len(refs); index++ {
		if refs[index-1] == refs[index] {
			return nil, errors.New("relay finality evidence repeats an observation reference")
		}
	}
	return refs, nil
}

func (coordinator RelayCoordinator) verifyResolution(execution agentrelay.RelayExecutionRequest,
	resolution agentrelay.SignedRelayResolution) error {
	now := coordinator.now()
	body := resolution.Body
	if coordinator.AgentResolver == nil || agentrelay.VerifyRelayResolutionForExecution(resolution, execution,
		coordinator.AgentResolver, now) != nil ||
		body.ObservedAtUnix > uint64(now.Add(5*time.Minute).Unix()) || uint64(now.Unix()) >= body.ExpiresAtUnix {
		return errors.New("relay resolution conflicts with the frozen execution")
	}
	return coordinator.verifyResolutionSponsorshipAssurance(execution, body)
}

// verifyHistoricalTerminalResolution validates a terminal status at its signed
// observation time. Status expiry limits online caching; it must not invalidate
// a terminal result that was durably paired with independently verified chain
// evidence before returning to accounting.
func (coordinator RelayCoordinator) verifyHistoricalTerminalResolution(execution agentrelay.RelayExecutionRequest,
	resolution agentrelay.SignedRelayResolution) error {
	body := resolution.Body
	if body.State != commerce.ActionTerminal {
		return errors.New("stored relay terminal resolution is not terminal")
	}
	return coordinator.verifyHistoricalResolution(execution, resolution)
}

// verifyHistoricalResolution verifies a durably observed Provider status at
// its signed observation time. The short online status TTL must not brick a
// route journal after a process restart.
func (coordinator RelayCoordinator) verifyHistoricalResolution(execution agentrelay.RelayExecutionRequest,
	resolution agentrelay.SignedRelayResolution) error {
	body := resolution.Body
	if body.ObservedAtUnix == 0 || body.ObservedAtUnix > uint64(^uint64(0)>>1) ||
		body.ExpiresAtUnix <= body.ObservedAtUnix {
		return errors.New("stored relay terminal resolution has invalid time bounds")
	}
	observedAt := time.Unix(int64(body.ObservedAtUnix), 0).UTC()
	if coordinator.AgentResolver == nil || agentrelay.VerifyRelayResolutionForExecution(resolution, execution,
		coordinator.AgentResolver, observedAt) != nil {
		return errors.New("stored relay resolution signature is invalid")
	}
	return coordinator.verifyResolutionSponsorshipAssurance(execution, body)
}

func (coordinator RelayCoordinator) verifyResolutionSponsorshipAssurance(execution agentrelay.RelayExecutionRequest,
	body agentrelay.RelayResolutionBody) error {
	if body.SponsorshipStatus != agentrelay.SponsorshipResolutionObservedUnproven {
		return nil
	}
	selected := relaySponsorshipReleasePolicyFromRequest(execution.QuoteRequest.Body)
	if selected != coordinator.SponsorshipReleasePolicy ||
		selected.EvidenceClass != agentrelay.SponsorshipReleaseObservedUnproven {
		return errors.New("relay Provider used an owner-disabled unproven sponsorship evidence path")
	}
	if body.SponsorshipObservationDigest == "" {
		return errors.New("unproven sponsorship status has no bound observation digest")
	}
	return nil
}

type relaySnapshotBoundSponsorshipVerifier struct {
	delegate RelaySponsorshipClientSnapshotVerifier
	snapshot RelaySponsorshipEvidenceSnapshot
}

type relaySnapshotBoundFinalityVerifier struct {
	delegate   RelayClientFinalitySnapshotVerifier
	capability agentrelay.RelayEvidenceCapability
	snapshot   RelayClientEvidenceSnapshot
}

func (verifier relaySnapshotBoundFinalityVerifier) SupportsRelayEvidenceCapability(
	capability agentrelay.RelayEvidenceCapability) bool {
	return reflect.DeepEqual(capability, verifier.capability) &&
		validRelayClientEvidenceSnapshot(capability, verifier.snapshot) &&
		verifier.delegate.ValidateRelayFinalityEvidenceSnapshot(capability, verifier.snapshot.Opaque) == nil
}

func (verifier relaySnapshotBoundFinalityVerifier) SupportsRelayDualAbsenceEvidence(
	capability agentrelay.RelayEvidenceCapability) bool {
	return verifier.SupportsRelayEvidenceCapability(capability) && verifier.snapshot.DualAbsence
}

func (verifier relaySnapshotBoundFinalityVerifier) SupportsRelaySponsorshipComponentAbsenceEvidence(
	capability agentrelay.RelayEvidenceCapability) bool {
	return verifier.SupportsRelayEvidenceCapability(capability) &&
		verifier.snapshot.SponsorshipComponentAbsence
}

func (verifier relaySnapshotBoundFinalityVerifier) SupportsRelayTransactionComponentAbsenceEvidence(
	capability agentrelay.RelayEvidenceCapability) bool {
	return verifier.SupportsRelayEvidenceCapability(capability) &&
		verifier.snapshot.TransactionComponentAbsence
}

func (verifier relaySnapshotBoundFinalityVerifier) VerifyRelayFinality(ctx context.Context,
	execution agentrelay.RelayExecutionRequest, evidence agentrelay.SignedRelayFinalityEvidence) error {
	return verifier.delegate.VerifyRelayFinalityFromSnapshot(ctx, execution, evidence, verifier.snapshot.Opaque)
}

func (verifier relaySnapshotBoundFinalityVerifier) HasIndependentPortableRelayFinalityProofs() bool {
	return verifier.snapshot.PortableProof
}

func (verifier relaySnapshotBoundSponsorshipVerifier) VerifySponsorshipTransactionEvidence(ctx context.Context,
	evidence agentrelay.RelaySponsorshipTransactionEvidence, expected agentrelay.RelaySponsorshipEvidenceContext,
	profile agentrelay.FinalityProfile) error {
	return verifier.delegate.VerifySponsorshipTransactionEvidenceFromSnapshot(ctx, evidence, expected,
		profile, verifier.snapshot)
}

func (coordinator RelayCoordinator) verifyIndependentFinality(ctx context.Context,
	attempt RelayAttempt, evidence agentrelay.SignedRelayFinalityEvidence) error {
	execution := attempt.Execution
	now := coordinator.now()
	capability, capabilityErr := relayEvidenceCapabilityForExecution(execution)
	snapshotVerifier, snapshotOK := coordinator.FinalityVerifier.(RelayClientFinalitySnapshotVerifier)
	if capabilityErr != nil || !snapshotOK || attempt.ClientFinalityEvidenceSnapshot == nil ||
		!validRelayClientEvidenceSnapshot(capability, *attempt.ClientFinalityEvidenceSnapshot) ||
		snapshotVerifier.ValidateRelayFinalityEvidenceSnapshot(capability,
			attempt.ClientFinalityEvidenceSnapshot.Opaque) != nil {
		return errors.New("relay terminal evidence lost its client-owned finality snapshot")
	}
	finalityVerifier := relaySnapshotBoundFinalityVerifier{delegate: snapshotVerifier,
		capability: capability, snapshot: *cloneRelayClientEvidenceSnapshot(attempt.ClientFinalityEvidenceSnapshot)}
	sponsorshipVerifier := coordinator.SponsorshipEvidenceVerifier
	if execution.QuoteRequest.Body.SponsorshipReleaseEvidenceClass == agentrelay.SponsorshipReleaseObservedUnproven {
		delegate, ok := coordinator.SponsorshipEvidenceVerifier.(RelaySponsorshipClientSnapshotVerifier)
		if !ok || attempt.ClientSponsorshipEvidenceSnapshot == nil ||
			delegate.ValidateRelaySponsorshipClientEvidenceSnapshot(
				execution.QuoteRequest.Body.SelectedSponsorshipReleaseProfile(),
				*attempt.ClientSponsorshipEvidenceSnapshot) != nil {
			return errors.New("relay terminal evidence lost its client-owned verification snapshot")
		}
		sponsorshipVerifier = relaySnapshotBoundSponsorshipVerifier{delegate: delegate,
			snapshot: *attempt.ClientSponsorshipEvidenceSnapshot}
	}
	if coordinator.AgentResolver == nil ||
		agentrelay.VerifyRelayFinalityEvidenceForExecution(ctx, evidence, execution,
			coordinator.AgentResolver, finalityVerifier, sponsorshipVerifier, now) != nil {
		return errors.New("relay evidence signature is invalid")
	}
	if evidence.Body.ProviderAgentID != coordinator.VerifiedProfile.Profile().ProviderAgentID {
		return errors.New("relay evidence conflicts with the frozen execution")
	}
	return nil
}

func (coordinator RelayCoordinator) validatePrepared(prepared PreparedRelayTransaction,
	profile agentrelay.RelayServiceProfile, now time.Time) error {
	body := prepared.QuoteBody
	if body.Mode == agentrelay.ModeRelayExact {
		if coordinator.SponsorshipReleasePolicy != (RelaySponsorshipReleasePolicy{}) ||
			relaySponsorshipReleasePolicyFromRequest(body) != (RelaySponsorshipReleasePolicy{}) {
			return errors.New("relay-only request carries a sponsorship release policy")
		}
	} else {
		selected := relaySponsorshipReleasePolicyFromRequest(body)
		if selected != coordinator.SponsorshipReleasePolicy ||
			!validRelaySponsorshipReleasePolicy(body.AssuranceLevel, selected) {
			return errors.New("sponsorship request changes the owner-selected release evidence profile")
		}
	}
	capability, capabilityErr := relayEvidenceCapabilityForQuoteBody(profile, body)
	if capabilityErr != nil || coordinator.FinalityVerifier == nil ||
		!coordinator.FinalityVerifier.SupportsRelayEvidenceCapability(capability) ||
		body.Mode != agentrelay.ModeRelayExact &&
			!coordinator.FinalityVerifier.SupportsRelaySponsorshipComponentAbsenceEvidence(capability) ||
		body.Mode == agentrelay.ModeSponsorAndRelay &&
			!coordinator.FinalityVerifier.SupportsRelayDualAbsenceEvidence(capability) ||
		body.Mode == agentrelay.ModeSponsorAndRelay &&
			!coordinator.FinalityVerifier.SupportsRelayTransactionComponentAbsenceEvidence(capability) {
		return errors.New("relay request has no verifier for its exact terminal evidence capability")
	}
	requiresPortable := body.AssuranceLevel == agentrelay.AssuranceAutonomousDecentralized ||
		body.RelayTerminalEvidenceClass == agentrelay.RelayTerminalValidatorFinality ||
		body.SponsorshipTerminalEvidenceClass == agentrelay.SponsorshipTerminalValidatorFinality
	if requiresPortable {
		portable, ok := coordinator.FinalityVerifier.(agentrelay.PortableRelayFinalityEvidenceVerifier)
		if !ok || !portable.HasIndependentPortableRelayFinalityProofs() {
			return errors.New("relay request terminal predicate requires portable independent verification")
		}
	}
	digest, err := agentrelay.SignedTransactionDigest(prepared.ExactSignedBOC)
	if err != nil || digest != body.SignedTransactionDigest || uint32(len(prepared.ExactSignedBOC)) != body.SignedTransactionSize {
		return errors.New("locally prepared BOC differs from its frozen digest or size")
	}
	underlyingDigest, err := commerce.ExactRequestDigest(prepared.UnderlyingActionRequest)
	if err != nil || underlyingDigest != prepared.UnderlyingAction.ExactRequestDigest ||
		body.UnderlyingActionKind != prepared.UnderlyingAction.ActionKind ||
		body.StableActionID != prepared.UnderlyingAction.StableActionID ||
		body.ExactRequestDigest != prepared.UnderlyingAction.ExactRequestDigest ||
		body.RequesterAgentID != prepared.UnderlyingAction.AgentID || body.ProviderAgentID != profile.ProviderAgentID {
		return errors.New("relay quote metadata does not bind the underlying authorized action")
	}
	if err := commerce.VerifyAuthorizedAction(prepared.UnderlyingAction, prepared.SemanticFields,
		prepared.UnderlyingActionRequest, prepared.WriterFence, coordinator.FenceResolver, now); err != nil {
		return errors.New("underlying economic action authorization is invalid")
	}
	if err := commerce.ConfirmCurrentWriterFence(prepared.WriterFence, coordinator.FenceResolver, now); err != nil {
		return errors.New("underlying economic action writer fence is no longer current")
	}
	return nil
}

func relaySponsorshipReleasePolicyFromRequest(body agentrelay.RelayQuoteRequestBody) RelaySponsorshipReleasePolicy {
	return RelaySponsorshipReleasePolicy{EvidenceClass: body.SponsorshipReleaseEvidenceClass,
		ProfileURI: body.SponsorshipReleaseProfileURI, ProfileDigest: body.SponsorshipReleaseProfileDigest}
}

func validClientRelaySponsorshipSnapshot(selected agentrelay.SponsorshipReleaseProfile,
	snapshot RelaySponsorshipEvidenceSnapshot) bool {
	validVersion := snapshot.SchemaVersion == 1 || snapshot.SchemaVersion == 2 &&
		filepath.IsAbs(snapshot.RegistryRoot) && filepath.Clean(snapshot.RegistryRoot) == snapshot.RegistryRoot &&
		snapshot.CustodyWallet == "" && snapshot.ProviderSourceAccount == "" && snapshot.FeeReserveNanoTOS == 0
	return selected.EvidenceClass == agentrelay.SponsorshipReleaseObservedUnproven && validVersion &&
		snapshot.EvidenceClass == string(selected.EvidenceClass) &&
		snapshot.ProfileURI == selected.ProfileURI && snapshot.ProfileDigest == selected.ProfileDigest &&
		snapshot.MaximumTransactions > 0 && snapshot.MaximumTransactions <= 10_000 &&
		filepath.IsAbs(snapshot.SnapshotPath) && validSHA256Digest(snapshot.SnapshotIdentity)
}

func newRelayClientEvidenceSnapshot(capability agentrelay.RelayEvidenceCapability,
	opaque []byte, dualAbsence, sponsorshipComponentAbsence, transactionComponentAbsence,
	portableProof bool) (*RelayClientEvidenceSnapshot, error) {
	if len(opaque) == 0 || len(opaque) > maximumRelayClientEvidenceSnapshotBytes {
		return nil, errors.New("client relay evidence snapshot is empty or oversized")
	}
	snapshot := RelayClientEvidenceSnapshot{SchemaVersion: 1, Capability: capability,
		DualAbsence: dualAbsence, SponsorshipComponentAbsence: sponsorshipComponentAbsence,
		TransactionComponentAbsence: transactionComponentAbsence,
		PortableProof:               portableProof, Opaque: append([]byte(nil), opaque...)}
	identity, err := relayClientEvidenceSnapshotIdentity(snapshot)
	if err != nil {
		return nil, err
	}
	snapshot.Identity = identity
	return &snapshot, nil
}

func relayClientEvidenceSnapshotIdentity(snapshot RelayClientEvidenceSnapshot) (string, error) {
	projection := struct {
		SchemaVersion               uint16                             `json:"schema_version"`
		Capability                  agentrelay.RelayEvidenceCapability `json:"capability"`
		DualAbsence                 bool                               `json:"dual_absence"`
		SponsorshipComponentAbsence bool                               `json:"sponsorship_component_absence"`
		TransactionComponentAbsence bool                               `json:"transaction_component_absence"`
		PortableProof               bool                               `json:"portable_proof"`
		Opaque                      []byte                             `json:"protected_opaque_snapshot"`
	}{SchemaVersion: snapshot.SchemaVersion, Capability: snapshot.Capability,
		DualAbsence:                 snapshot.DualAbsence,
		SponsorshipComponentAbsence: snapshot.SponsorshipComponentAbsence,
		TransactionComponentAbsence: snapshot.TransactionComponentAbsence,
		PortableProof:               snapshot.PortableProof, Opaque: snapshot.Opaque}
	return codec.Digest("tos.openfox.relay-client-evidence-snapshot.v1", projection)
}

func validRelayClientEvidenceSnapshot(capability agentrelay.RelayEvidenceCapability,
	snapshot RelayClientEvidenceSnapshot) bool {
	if snapshot.SchemaVersion != 1 || !reflect.DeepEqual(snapshot.Capability, capability) ||
		len(snapshot.Opaque) == 0 || len(snapshot.Opaque) > maximumRelayClientEvidenceSnapshotBytes ||
		!canonicalSHA256(snapshot.Identity) {
		return false
	}
	if capability.Mode != agentrelay.ModeRelayExact && !snapshot.SponsorshipComponentAbsence ||
		capability.Mode == agentrelay.ModeSponsorAndRelay &&
			(!snapshot.DualAbsence || !snapshot.TransactionComponentAbsence) ||
		(capability.AssuranceLevel == agentrelay.AssuranceAutonomousDecentralized ||
			capability.RelayTerminalEvidenceClass == agentrelay.RelayTerminalValidatorFinality ||
			capability.SponsorshipTerminalEvidenceClass == agentrelay.SponsorshipTerminalValidatorFinality) &&
			!snapshot.PortableProof {
		return false
	}
	identity, err := relayClientEvidenceSnapshotIdentity(snapshot)
	return err == nil && identity == snapshot.Identity
}

func cloneRelayClientEvidenceSnapshot(snapshot *RelayClientEvidenceSnapshot) *RelayClientEvidenceSnapshot {
	if snapshot == nil {
		return nil
	}
	copy := *snapshot
	copy.Opaque = append([]byte(nil), snapshot.Opaque...)
	if snapshot.Capability.RelayFinalityProfile != nil {
		profile := *snapshot.Capability.RelayFinalityProfile
		copy.Capability.RelayFinalityProfile = &profile
	}
	if snapshot.Capability.SponsorshipTerminalProfile != nil {
		profile := *snapshot.Capability.SponsorshipTerminalProfile
		copy.Capability.SponsorshipTerminalProfile = &profile
	}
	return &copy
}

func cloneRelaySponsorshipEvidenceSnapshot(snapshot *RelaySponsorshipEvidenceSnapshot) *RelaySponsorshipEvidenceSnapshot {
	if snapshot == nil {
		return nil
	}
	copy := *snapshot
	return &copy
}

func (coordinator RelayCoordinator) validateQuoted(quoted RelayQuotedTransaction,
	profile agentrelay.RelayServiceProfile, now time.Time) error {
	if err := coordinator.validatePrepared(quoted.Prepared, profile, now); err != nil {
		return err
	}
	if !reflect.DeepEqual(quoted.Request.Body, quoted.Prepared.QuoteBody) ||
		coordinator.VerifiedProfile.authorizeQuoteRequest(quoted.Request, now) != nil ||
		agentrelay.VerifyRelayQuoteRequest(quoted.Request, profile, coordinator.AgentResolver, now) != nil ||
		agentrelay.VerifyProviderRelayQuote(quoted.Quote, quoted.Request, profile, coordinator.AgentResolver, now) != nil ||
		quoted.Quote.Body.OfferIntentDigest != coordinator.VerifiedProfile.IntentDigest() {
		return errors.New("relay quoted transaction is invalid or mutated")
	}
	capability, capabilityErr := relayEvidenceCapabilityForQuoteBody(profile, quoted.Request.Body)
	snapshotVerifier, snapshotOK := coordinator.FinalityVerifier.(RelayClientFinalitySnapshotVerifier)
	if capabilityErr != nil || !snapshotOK || quoted.ClientFinalityEvidenceSnapshot == nil ||
		!validRelayClientEvidenceSnapshot(capability, *quoted.ClientFinalityEvidenceSnapshot) ||
		snapshotVerifier.ValidateRelayFinalityEvidenceSnapshot(capability,
			quoted.ClientFinalityEvidenceSnapshot.Opaque) != nil {
		return errors.New("relay quote lost its client-owned finality verification snapshot")
	}
	if quoted.Quote.Body.Mode == agentrelay.ModeSponsorOnly ||
		quoted.Quote.Body.Mode == agentrelay.ModeSponsorAndRelay {
		capability, ok := coordinator.SponsorshipEvidenceVerifier.(RelaySponsorshipClientEvidenceCapability)
		if quoted.Quote.Body.SponsorshipTerminalProfile == nil {
			return errors.New("relay sponsorship terminal profile is missing")
		}
		if !ok || !capability.SupportsRelaySponsorshipTransactionEvidence(quoted.Quote.Body.AssuranceLevel,
			coordinator.SponsorshipReleasePolicy, *quoted.Quote.Body.SponsorshipTerminalProfile) {
			return errors.New("relay sponsorship terminal evidence profile is not independently verifiable")
		}
		selected := quoted.Request.Body.SelectedSponsorshipReleaseProfile()
		if selected.EvidenceClass == agentrelay.SponsorshipReleaseObservedUnproven {
			verifier, snapshotOK := coordinator.SponsorshipEvidenceVerifier.(RelaySponsorshipClientSnapshotVerifier)
			if !snapshotOK || quoted.ClientSponsorshipEvidenceSnapshot == nil ||
				!validClientRelaySponsorshipSnapshot(selected, *quoted.ClientSponsorshipEvidenceSnapshot) ||
				verifier.ValidateRelaySponsorshipClientEvidenceSnapshot(selected,
					*quoted.ClientSponsorshipEvidenceSnapshot) != nil {
				return errors.New("relay sponsorship quote lost its client-owned verification snapshot")
			}
		} else if quoted.ClientSponsorshipEvidenceSnapshot != nil {
			return errors.New("finalized sponsorship quote carries an unrelated RPC verification snapshot")
		}
	} else if quoted.ClientSponsorshipEvidenceSnapshot != nil {
		return errors.New("relay-only quote carries a sponsorship verification snapshot")
	}
	return nil
}

func (coordinator RelayCoordinator) validateAttempt(ctx context.Context, attempt RelayAttempt, now time.Time) error {
	profile := coordinator.VerifiedProfile.Profile()
	request := attempt.Execution
	if coordinator.AgentResolver == nil || coordinator.FenceResolver == nil || coordinator.Inspector == nil ||
		coordinator.ActionBinder == nil || coordinator.AgreementVerifier == nil ||
		coordinator.VerifiedProfile.authorizeQuoteRequest(request.QuoteRequest, now) != nil {
		return errors.New("relay attempt verifier is incomplete")
	}
	digest, err := agentrelay.SignedTransactionDigest(request.SignedTransactionBytes)
	if err != nil || digest != request.QuoteRequest.Body.SignedTransactionDigest ||
		uint32(len(request.SignedTransactionBytes)) != request.QuoteRequest.Body.SignedTransactionSize {
		return errors.New("relay attempt changes the exact signed transaction")
	}
	if err := agentrelay.VerifyRelayExecutionRequest(ctx, request, profile, coordinator.AgentResolver,
		coordinator.FenceResolver, coordinator.Inspector, now); err != nil {
		return errors.New("relay execution request failed independent verification")
	}
	if err := agentrelay.VerifyActionTransactionBinding(ctx, request, profile, coordinator.Inspector,
		coordinator.ActionBinder); err != nil {
		return errors.New("signed transaction does not realize the authorized economic action")
	}
	if err := agentrelay.VerifyRelayExecutionAgreement(request, attempt.Agreement,
		coordinator.AgreementVerifier, now); err != nil {
		return errors.New("relay Agreement failed independent verification")
	}
	capability, capabilityErr := relayEvidenceCapabilityForExecution(request)
	snapshotVerifier, snapshotOK := coordinator.FinalityVerifier.(RelayClientFinalitySnapshotVerifier)
	if capabilityErr != nil || !snapshotOK || attempt.ClientFinalityEvidenceSnapshot == nil ||
		!validRelayClientEvidenceSnapshot(capability, *attempt.ClientFinalityEvidenceSnapshot) ||
		snapshotVerifier.ValidateRelayFinalityEvidenceSnapshot(capability,
			attempt.ClientFinalityEvidenceSnapshot.Opaque) != nil {
		return errors.New("relay attempt has no exact client finality verification snapshot")
	}
	selected := request.QuoteRequest.Body.SelectedSponsorshipReleaseProfile()
	if selected.EvidenceClass == agentrelay.SponsorshipReleaseObservedUnproven {
		verifier, ok := coordinator.SponsorshipEvidenceVerifier.(RelaySponsorshipClientSnapshotVerifier)
		if !ok || attempt.ClientSponsorshipEvidenceSnapshot == nil ||
			!validClientRelaySponsorshipSnapshot(selected, *attempt.ClientSponsorshipEvidenceSnapshot) ||
			verifier.ValidateRelaySponsorshipClientEvidenceSnapshot(selected,
				*attempt.ClientSponsorshipEvidenceSnapshot) != nil {
			return errors.New("relay attempt has no exact client sponsorship verification snapshot")
		}
	} else if attempt.ClientSponsorshipEvidenceSnapshot != nil {
		return errors.New("relay attempt carries an inapplicable client sponsorship verification snapshot")
	}
	return nil
}

// RelayProviderSelector is owner-controlled policy. Discovery provides signed
// candidates; there is no built-in central provider list or global ranking.
type RelayProviderSelector interface {
	SelectRelayProvider(context.Context, []RelayQuoteCandidate) (int, error)
}

type RelayProviderSelectorFunc func(context.Context, []RelayQuoteCandidate) (int, error)

func (function RelayProviderSelectorFunc) SelectRelayProvider(ctx context.Context,
	candidates []RelayQuoteCandidate) (int, error) {
	return function(ctx, candidates)
}

type RelayQuoteCandidate struct {
	Coordinator *RelayCoordinator
	Quoted      RelayQuotedTransaction
}

// RelayProviderProvenanceVerifier is an owner-controlled trust source. A
// signed provider profile cannot attest its own operator or failure domain.
type RelayProviderProvenanceVerifier interface {
	VerifyRelayProviderProvenance(context.Context, VerifiedRelayServiceProfile) (RelayProviderProvenance, error)
}

type RelayProviderProvenanceVerifierFunc func(context.Context,
	VerifiedRelayServiceProfile) (RelayProviderProvenance, error)

func (function RelayProviderProvenanceVerifierFunc) VerifyRelayProviderProvenance(ctx context.Context,
	profile VerifiedRelayServiceProfile) (RelayProviderProvenance, error) {
	return function(ctx, profile)
}

// DecentralizedRelayCoordinator obtains at least two independently verified
// signed quotes before owner policy selects one. Quotes do not expose BOC
// bytes or authorize payment.
type DecentralizedRelayCoordinator struct {
	Providers          []*RelayCoordinator
	Selector           RelayProviderSelector
	ProvenanceVerifier RelayProviderProvenanceVerifier
	// AgentResolver is an owner-retained historical key authority. It must
	// outlive Provider configuration/source loss so persisted signed query
	// responses can be verified at their observation time.
	AgentResolver agentrelay.AgentKeyResolver
	RouteJournal  RelayRouteJournal
	// MaximumRouteAttempts is an explicit owner policy ceiling, including the
	// initial Provider. Zero is disabled; V1 is capped by the protocol at 32.
	MaximumRouteAttempts uint32
}

type DecentralizedRelayPlan struct {
	candidates      []RelayQuoteCandidate
	provenance      []RelayProviderProvenance
	used            map[int]bool
	selected        int
	routeGeneration uint64
	base            PreparedRelayTransaction
	Attempt         RelayAttempt
}

func (orchestrator DecentralizedRelayCoordinator) Prepare(ctx context.Context,
	prepared PreparedRelayTransaction) (*DecentralizedRelayPlan, error) {
	if ctx == nil || orchestrator.Selector == nil || orchestrator.ProvenanceVerifier == nil ||
		orchestrator.AgentResolver == nil || orchestrator.RouteJournal == nil ||
		orchestrator.MaximumRouteAttempts == 0 ||
		orchestrator.MaximumRouteAttempts > agentrelay.MaxRelayRouteAttempts {
		return nil, errors.New("decentralized relay requires owner selection, provenance, durable routing, and an explicit route-attempt ceiling")
	}
	if prepared.QuoteBody.AssuranceLevel != agentrelay.AssuranceAutonomousDecentralized {
		return nil, errors.New("decentralized relay requires the signed autonomous-decentralized assurance level")
	}
	base, err := clonePreparedRelayTransaction(prepared)
	if err != nil {
		return nil, err
	}
	if existing, resolveErr := orchestrator.RouteJournal.Resolve(base.UnderlyingAction.StableActionID,
		base.UnderlyingAction.ExactRequestDigest); resolveErr == nil {
		return orchestrator.resumeRelayPlan(ctx, base, existing)
	} else if !errors.Is(resolveErr, agentrelay.ErrRelayUnknown) {
		return nil, resolveErr
	}
	if len(orchestrator.Providers) < 2 {
		return nil, errors.New("a new decentralized relay route requires at least two independent providers")
	}
	seenProviders, seenIntents := map[string]bool{}, map[string]bool{}
	candidates := make([]RelayQuoteCandidate, 0, len(orchestrator.Providers))
	provenance := make([]RelayProviderProvenance, 0, len(orchestrator.Providers))
	var quoteErrors []error
	for _, coordinator := range orchestrator.Providers {
		if coordinator == nil || coordinator.AttemptJournal == nil {
			quoteErrors = append(quoteErrors, errors.New("relay provider lacks a durable submit gate"))
			continue
		}
		profile, intentDigest := coordinator.VerifiedProfile.Profile(), coordinator.VerifiedProfile.IntentDigest()
		if profile.ProviderAgentID == "" || intentDigest == "" || seenProviders[profile.ProviderAgentID] || seenIntents[intentDigest] {
			quoteErrors = append(quoteErrors, errors.New("relay profiles are not independently discovered"))
			continue
		}
		attested, provenanceErr := orchestrator.verifyRelayProvenance(ctx, coordinator)
		if provenanceErr != nil {
			quoteErrors = append(quoteErrors, provenanceErr)
			continue
		}
		seenProviders[profile.ProviderAgentID], seenIntents[intentDigest] = true, true
		routed, cloneErr := clonePreparedRelayTransaction(base)
		if cloneErr != nil {
			return nil, cloneErr
		}
		routed.QuoteBody.ProviderAgentID = profile.ProviderAgentID
		routed.QuoteBody.RequestID = relayProviderRouteID(base, profile.ProviderAgentID, intentDigest)
		if !sameRelayBaseIdentity(base, routed) {
			return nil, errors.New("provider routing changed the underlying relay action")
		}
		quoted, quoteErr := coordinator.Quote(ctx, routed)
		if quoteErr != nil {
			quoteErrors = append(quoteErrors, quoteErr)
			continue
		}
		if !sameRelayBaseIdentity(base, quoted.Prepared) {
			return nil, errors.New("provider quote changed the underlying relay action")
		}
		candidates = append(candidates, RelayQuoteCandidate{Coordinator: coordinator, Quoted: quoted})
		provenance = append(provenance, attested)
	}
	sortedProvenance := append([]RelayProviderProvenance(nil), provenance...)
	sort.Slice(sortedProvenance, func(left, right int) bool {
		return relayProvenanceKey(sortedProvenance[left]) < relayProvenanceKey(sortedProvenance[right])
	})
	if len(candidates) < 2 || !validIndependentRelayProvenance(sortedProvenance) {
		return nil, fmt.Errorf("fewer than two independent relay quotes: %w", errors.Join(quoteErrors...))
	}
	selected, err := orchestrator.Selector.SelectRelayProvider(ctx, append([]RelayQuoteCandidate(nil), candidates...))
	if err != nil || selected < 0 || selected >= len(candidates) {
		return nil, errors.New("owner relay provider selection failed")
	}
	attempt, err := candidates[selected].Coordinator.Authorize(ctx, candidates[selected].Quoted)
	if err != nil {
		return nil, err
	}
	if !attemptMatchesPrepared(attempt, base) {
		return nil, errors.New("selected relay attempt changed the underlying action or signed bytes")
	}
	route, created, err := orchestrator.RouteJournal.Bind(base, provenance, provenance[selected], attempt,
		orchestrator.MaximumRouteAttempts, candidates[selected].Coordinator.now())
	if err != nil {
		return nil, err
	}
	if !created {
		return orchestrator.resumeRelayPlan(ctx, base, route)
	}
	current, _ := route.Current()
	return &DecentralizedRelayPlan{candidates: candidates, provenance: provenance,
		used: map[int]bool{selected: true}, selected: selected, routeGeneration: current.Generation,
		base: base, Attempt: cloneRelayAttempt(attempt)}, nil
}

func (orchestrator DecentralizedRelayCoordinator) resumeRelayPlan(ctx context.Context,
	base PreparedRelayTransaction, route RelayRouteRecord) (*DecentralizedRelayPlan, error) {
	current, found := route.Current()
	if !found || !attemptMatchesPrepared(current.Attempt, base) {
		return nil, errors.New("durable relay route conflicts with the locally prepared transaction")
	}
	if err := orchestrator.verifyRelayRouteHistory(ctx, route); err != nil {
		return nil, err
	}
	usedProvenance := make(map[string]bool, len(route.Hops))
	for _, hop := range route.Hops {
		usedProvenance[relayProvenanceKey(hop.Provider)] = true
	}
	candidates := make([]RelayQuoteCandidate, 1, len(orchestrator.Providers))
	provenance := make([]RelayProviderProvenance, 1, len(orchestrator.Providers))
	provenance[0] = current.Provider
	selectedFound := false
	for _, coordinator := range orchestrator.Providers {
		if coordinator == nil || coordinator.AttemptJournal == nil {
			continue
		}
		attested, err := orchestrator.verifyRelayProvenance(ctx, coordinator)
		if err != nil || !containsRelayProvenance(route.Candidates, attested) {
			continue
		}
		if sameRelayProvenance(attested, current.Provider) {
			candidates[0].Coordinator = coordinator
			selectedFound = true
			continue
		}
		if usedProvenance[relayProvenanceKey(attested)] {
			continue
		}
		if route.PendingSwitch != nil && sameRelayProvenance(attested, route.PendingSwitch.Provider) {
			// The exact Agreement/execution draft is already protected by the
			// owner route journal. Re-quoting here could create a different
			// lookup after an ambiguous authority response.
			candidates = append(candidates, RelayQuoteCandidate{Coordinator: coordinator})
			provenance = append(provenance, attested)
			continue
		}
		routed, err := clonePreparedRelayTransaction(base)
		if err != nil {
			return nil, err
		}
		routed.QuoteBody.ProviderAgentID = attested.ProviderAgentID
		routed.QuoteBody.RequestID = relayProviderRouteID(base, attested.ProviderAgentID, attested.IntentDigest)
		quoted, err := coordinator.Quote(ctx, routed)
		if err != nil {
			continue
		}
		candidates = append(candidates, RelayQuoteCandidate{Coordinator: coordinator, Quoted: quoted})
		provenance = append(provenance, attested)
	}
	queryFailoverRecoverable := current.FailoverQueryAttempt != nil && validStoredRelayResolveQuery(route, current)
	if !selectedFound && !queryFailoverRecoverable {
		return nil, errors.New("durably selected relay provider is unavailable under owner provenance policy")
	}
	return &DecentralizedRelayPlan{candidates: candidates, provenance: provenance, used: map[int]bool{0: true},
		selected: 0, routeGeneration: current.Generation, base: base, Attempt: cloneRelayAttempt(current.Attempt)}, nil
}

func (orchestrator DecentralizedRelayCoordinator) verifyRelayRouteHistory(ctx context.Context,
	route RelayRouteRecord) error {
	for index := 0; index+1 < len(route.Hops); index++ {
		hop := route.Hops[index]
		hasFinality := hop.FailoverFinalityEvidence != nil && validStoredRelayFailoverEvidence(route, hop)
		hasQuery := hop.FailoverQueryAttempt != nil && validStoredRelayResolveQuery(route, hop)
		if hasFinality == hasQuery {
			return errors.New("durable relay failover route lacks one unambiguous failover gate")
		}
		if hasQuery {
			// Query failover is an owner-local liveness checkpoint, not Provider
			// evidence. Its exact provenance/principal binding was sealed by the
			// concrete transport before persistence; receipt and transaction chains
			// make it independently recoverable after complete Provider removal.
			if err := orchestrator.verifyHistoricalRelayResolveQuery(route, hop); err != nil {
				return err
			}
			continue
		}
		verified := false
		for _, coordinator := range orchestrator.Providers {
			attested, err := orchestrator.verifyRelayProvenance(ctx, coordinator)
			if err != nil || !sameRelayProvenance(attested, hop.Provider) {
				continue
			}
			if err := coordinator.verifyIndependentFinality(ctx, hop.Attempt,
				*hop.FailoverFinalityEvidence); err != nil {
				return errors.New("durable relay failover proof no longer verifies independently")
			}
			verified = true
			break
		}
		if !verified {
			return errors.New("durable relay failover gate has no trusted verifier for its prior provider")
		}
	}
	return nil
}

func (orchestrator DecentralizedRelayCoordinator) verifyHistoricalRelayResolveQuery(route RelayRouteRecord,
	hop RelayRouteHop) error {
	if !validStoredRelayResolveQuery(route, hop) {
		return errors.New("durable relay Resolve query is invalid")
	}
	query := hop.FailoverQueryAttempt
	if query.Resolution == nil {
		return nil
	}
	body := query.Resolution.Body
	if orchestrator.AgentResolver == nil || body.State == commerce.ActionTerminal || body.ObservedAtUnix == 0 ||
		body.ObservedAtUnix > uint64(^uint64(0)>>1) || body.ExpiresAtUnix <= body.ObservedAtUnix {
		return errors.New("durable relay Resolve response has invalid historical bounds")
	}
	observedAt := time.Unix(int64(body.ObservedAtUnix), 0).UTC()
	if agentrelay.VerifyRelayResolutionForExecution(*query.Resolution, hop.Attempt.Execution,
		orchestrator.AgentResolver, observedAt) != nil ||
		body.ProviderAgentID != hop.Provider.ProviderAgentID ||
		body.StableActionID != route.StableActionID || body.ExactRequestDigest != route.ExactRequestDigest {
		return errors.New("durable relay Resolve response failed historical Provider authorization")
	}
	return nil
}

func (orchestrator DecentralizedRelayCoordinator) recordAuthenticatedRelayResolveQuery(ctx context.Context,
	route RelayRouteRecord, current RelayRouteHop, coordinator *RelayCoordinator) (RelayRouteRecord, error) {
	if ctx == nil || coordinator == nil || current.Attempt.Execution.QuoteRequest.Body.Mode != agentrelay.ModeRelayExact ||
		current.Attempt.Execution.QuoteRequest.Body.AssuranceLevel != agentrelay.AssuranceAutonomousDecentralized ||
		!current.SubmitStarted {
		return RelayRouteRecord{}, errors.New("relay failover query is outside an ambiguous relay-only route")
	}
	principal := current.Attempt.Execution.AdmissionReceipt.Body.AuthenticatedPrincipal
	authenticated, ok := coordinator.Transport.(relayAuthenticatedResolveTransport)
	if !ok || ctx.Err() != nil {
		return RelayRouteRecord{}, errors.New("relay failover requires an authenticated Provider Resolve route")
	}
	networkDigest, networkErr := agentrelay.NetworkDomainDigest(current.Attempt.Execution.QuoteRequest.Body.Network)
	transactionDigest, transactionErr := agentrelay.RelayTransactionIdentityDigest(
		current.Attempt.Execution.QuoteRequest.Body)
	if networkErr != nil || transactionErr != nil {
		return RelayRouteRecord{}, errors.New("relay failover query identity is invalid")
	}
	started := coordinator.now()
	call := agentrelay.ResolveCall{StableActionID: route.StableActionID,
		ExactRequestDigest: route.ExactRequestDigest}
	resolution, authDigest, dispatched, resolveErr := authenticated.resolveForFailover(ctx, call,
		current.Attempt.Execution, current.Provider, principal)
	completed := coordinator.now()
	expectedAuthDigest, authErr := relayTransportAuthenticationDigest(current.Provider, principal)
	if started.Unix() <= 0 || completed.Before(started) || !dispatched || authErr != nil ||
		authDigest != expectedAuthDigest || errors.Is(resolveErr, errRelayResolveAuthenticationRejected) ||
		errors.Is(resolveErr, context.Canceled) {
		return RelayRouteRecord{}, errors.New("relay failover Resolve was not authentically dispatched on the pinned route")
	}
	attempt := relayRouteResolveQueryAttempt{SchemaVersion: 1, RouteGeneration: current.Generation,
		ProviderAgentID: current.Provider.ProviderAgentID, ProviderProfileDigest: current.Provider.ProfileDigest,
		AuthenticatedPrincipal: principal, TransportAuthenticationDigest: authDigest, NetworkDigest: networkDigest,
		TransactionIdentityDigest: transactionDigest, StableActionID: route.StableActionID,
		ExactRequestDigest: route.ExactRequestDigest, RelayExecutionDigest: current.RelayExecutionDigest,
		StartedAtUnix: uint64(started.Unix()), CompletedAtUnix: uint64(completed.Unix())}
	if resolveErr != nil {
		if errors.Is(resolveErr, ErrRelayRemoteUnknown) {
			attempt.Outcome = relayResolveRemoteUnknown
		} else {
			attempt.Outcome = relayResolveUnavailable
		}
	} else {
		if err := coordinator.verifyResolution(current.Attempt.Execution, resolution); err != nil {
			attempt.Outcome = relayResolveUnavailable
		} else {
			if resolution.Body.State == commerce.ActionTerminal {
				return RelayRouteRecord{}, errors.New("relay Provider returned a terminal result; resolve finality instead of failing over")
			}
			digest, err := agentrelay.RelayResolutionDigest(resolution.Body)
			if err != nil {
				return RelayRouteRecord{}, err
			}
			attempt.Outcome, attempt.ResolutionDigest = relayResolveAmbiguous, digest
			resolutionCopy := resolution
			attempt.Resolution = &resolutionCopy
		}
	}
	return orchestrator.RouteJournal.recordResolveQuery(route.StableActionID, route.ExactRequestDigest,
		current.Generation, attempt)
}

func (orchestrator DecentralizedRelayCoordinator) verifyRelayProvenance(ctx context.Context,
	coordinator *RelayCoordinator) (RelayProviderProvenance, error) {
	if coordinator == nil || orchestrator.ProvenanceVerifier == nil {
		return RelayProviderProvenance{}, errors.New("relay provider has no owner provenance verifier")
	}
	profile := coordinator.VerifiedProfile.Profile()
	profileDigest, err := agentrelay.RelayServiceProfileDigest(profile)
	if err != nil {
		return RelayProviderProvenance{}, err
	}
	origin, err := relayProfileEndpointOrigin(profile.Endpoints)
	if err != nil {
		return RelayProviderProvenance{}, err
	}
	attested, err := orchestrator.ProvenanceVerifier.VerifyRelayProviderProvenance(ctx,
		coordinator.VerifiedProfile)
	if err != nil || !validRelayProvenance(attested) || attested.ProviderAgentID != profile.ProviderAgentID ||
		attested.IntentDigest != coordinator.VerifiedProfile.IntentDigest() || attested.ProfileDigest != profileDigest ||
		attested.EndpointOrigin != origin {
		return RelayProviderProvenance{}, errors.New("relay provider provenance is not owner-verified for the exact profile and endpoint origin")
	}
	if client, ok := coordinator.Transport.(*RelayHTTPClient); ok &&
		(client.provenance == nil || !sameRelayProvenance(*client.provenance, attested)) {
		return RelayProviderProvenance{}, errors.New("relay HTTP transport does not enforce the owner provenance SPKI pin")
	}
	return attested, nil
}

func relayProfileEndpointOrigin(endpoints agentrelay.ServiceEndpoints) (string, error) {
	values := []string{endpoints.QuoteURL, endpoints.SubmitURL, endpoints.ResolveURL, endpoints.EvidenceURL}
	origin := ""
	for _, value := range values {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
			return "", errors.New("relay endpoint origin is invalid")
		}
		candidate := "https://" + strings.ToLower(parsed.Host)
		if origin == "" {
			origin = candidate
		} else if candidate != origin {
			return "", errors.New("relay profile endpoints cross owner provenance origins")
		}
	}
	return origin, nil
}

func (orchestrator DecentralizedRelayCoordinator) Submit(ctx context.Context,
	plan *DecentralizedRelayPlan) (RelayExecutionResult, error) {
	if ctx == nil || orchestrator.RouteJournal == nil || plan == nil || plan.selected < 0 || plan.selected >= len(plan.candidates) ||
		!attemptMatchesPrepared(plan.Attempt, plan.base) {
		return RelayExecutionResult{}, errors.New("decentralized relay plan is invalid")
	}
	coordinator := plan.candidates[plan.selected].Coordinator
	if coordinator == nil {
		return RelayExecutionResult{}, errors.New("selected relay provider is unavailable")
	}
	executionDigest, err := agentrelay.RelayExecutionRequestDigest(plan.Attempt.Execution)
	if err != nil {
		return RelayExecutionResult{}, err
	}
	route, err := orchestrator.RouteJournal.Resolve(plan.base.UnderlyingAction.StableActionID,
		plan.base.UnderlyingAction.ExactRequestDigest)
	if err != nil {
		return RelayExecutionResult{}, err
	}
	current, found := route.Current()
	if !found || current.Generation != plan.routeGeneration || current.RelayExecutionDigest != executionDigest ||
		current.Provider.ProviderAgentID != plan.Attempt.Execution.ProviderQuote.Body.ProviderAgentID ||
		!reflect.DeepEqual(current.Attempt, plan.Attempt) {
		return RelayExecutionResult{}, errors.New("decentralized relay plan differs from the durable selected route")
	}
	if current.TerminalResolution != nil && current.TerminalFinalityEvidence != nil {
		stored := RelayExecutionResult{Resolution: *current.TerminalResolution,
			Evidence: current.TerminalFinalityEvidence}
		if coordinator.verifyHistoricalTerminalResolution(plan.Attempt.Execution, stored.Resolution) != nil ||
			coordinator.verifyIndependentFinality(ctx, plan.Attempt, *stored.Evidence) != nil ||
			stored.Resolution.Body.TerminalOutcome != stored.Evidence.Body.Outcome ||
			!relayResolutionReferenceMatchesEvidence(stored.Resolution.Body, stored.Evidence.Body) {
			return RelayExecutionResult{}, errors.New("durable relay terminal result failed independent recovery verification")
		}
		return stored, nil
	}
	if current.FailoverFinalityEvidence != nil || current.FailoverFinalityEvidenceDigest != "" ||
		route.PendingSwitch != nil && route.PendingSwitch.AdmissionStarted {
		return RelayExecutionResult{}, errors.New("selected relay route is retired or has a successor in progress")
	}
	if current.FailoverQueryAttempt != nil || current.FailoverQueryAttemptDigest != "" {
		// A persisted query gate retires fresh Submit on this Provider. It may
		// still be superseded by a later exact terminal result before successor
		// preparation, so recovery performs Resolve/Evidence only.
		call := agentrelay.ResolveCall{StableActionID: route.StableActionID,
			ExactRequestDigest: route.ExactRequestDigest}
		resolution, resolveErr := coordinator.Transport.Resolve(ctx, call, plan.Attempt.Execution)
		if resolveErr != nil || resolution.Body.State != commerce.ActionTerminal {
			return RelayExecutionResult{}, fmt.Errorf("%w: selected relay route is awaiting failover",
				ErrRelaySubmissionAmbiguous)
		}
		record, err := coordinator.AttemptJournal.Resolve(route.StableActionID, route.ExactRequestDigest)
		if err != nil {
			return RelayExecutionResult{}, errors.New("queried terminal relay result lacks its durable local attempt")
		}
		result, acceptErr := coordinator.acceptResolution(ctx, plan.Attempt, record, resolution)
		return orchestrator.recordRelayRouteResult(plan, executionDigest, result, acceptErr)
	}
	wasStarted := current.SubmitStarted
	route, err = orchestrator.RouteJournal.MarkSubmitStarted(route.StableActionID, route.ExactRequestDigest,
		current.Generation, executionDigest, coordinator.now())
	if err != nil {
		return RelayExecutionResult{}, err
	}
	if !wasStarted {
		result, submitErr := coordinator.submit(ctx, plan.Attempt, true)
		return orchestrator.recordRelayRouteResult(plan, executionDigest, result, submitErr)
	}
	// A restarted route always queries the exact selected provider before any
	// authorization window or retry logic can create another side effect.
	call := agentrelay.ResolveCall{StableActionID: route.StableActionID, ExactRequestDigest: route.ExactRequestDigest}
	resolution, resolveErr := coordinator.Transport.Resolve(ctx, call, plan.Attempt.Execution)
	if resolveErr != nil {
		if errors.Is(resolveErr, ErrRelayRemoteUnknown) {
			if plan.Attempt.Execution.QuoteRequest.Body.Mode != agentrelay.ModeRelayExact {
				return RelayExecutionResult{}, fmt.Errorf("%w: selected sponsor has no durable action record",
					ErrRelaySubmissionAmbiguous)
			}
			result, submitErr := coordinator.Submit(ctx, plan.Attempt)
			return orchestrator.recordRelayRouteResult(plan, executionDigest, result, submitErr)
		}
		return RelayExecutionResult{}, resolveErr
	}
	if resolution.Body.State == commerce.ActionUnknown {
		if plan.Attempt.Execution.QuoteRequest.Body.Mode != agentrelay.ModeRelayExact {
			return RelayExecutionResult{}, fmt.Errorf("%w: selected sponsor reports an unknown action",
				ErrRelaySubmissionAmbiguous)
		}
		result, submitErr := coordinator.Submit(ctx, plan.Attempt)
		return orchestrator.recordRelayRouteResult(plan, executionDigest, result, submitErr)
	}
	if resolution.Body.State == commerce.ActionPrepared {
		result, submitErr := coordinator.Submit(ctx, plan.Attempt)
		return orchestrator.recordRelayRouteResult(plan, executionDigest, result, submitErr)
	}
	record, err := coordinator.AttemptJournal.Resolve(route.StableActionID, route.ExactRequestDigest)
	if err != nil {
		return RelayExecutionResult{}, errors.New("selected provider resolved a side effect absent from the durable local attempt")
	}
	result, acceptErr := coordinator.acceptResolution(ctx, plan.Attempt, record, resolution)
	return orchestrator.recordRelayRouteResult(plan, executionDigest, result, acceptErr)
}

func (orchestrator DecentralizedRelayCoordinator) recordRelayRouteResult(plan *DecentralizedRelayPlan,
	executionDigest string, result RelayExecutionResult, resultErr error) (RelayExecutionResult, error) {
	if resultErr != nil {
		return RelayExecutionResult{}, resultErr
	}
	if result.Resolution.Body.State != commerce.ActionTerminal {
		return result, nil
	}
	if result.Evidence == nil {
		return RelayExecutionResult{}, errors.New("terminal relay result has no evidence to persist")
	}
	coordinator := plan.candidates[plan.selected].Coordinator
	if coordinator == nil {
		return RelayExecutionResult{}, errors.New("terminal relay result has no route clock")
	}
	if _, err := orchestrator.RouteJournal.RecordTerminal(
		plan.Attempt.Execution.AuthorizedAction.StableActionID,
		plan.Attempt.Execution.AuthorizedAction.ExactRequestDigest,
		plan.routeGeneration, executionDigest, result, coordinator.now()); err != nil {
		return RelayExecutionResult{}, errors.New("persist terminal relay result before accounting: " + err.Error())
	}
	return result, nil
}

// Failover advances only a relay_exact route. It prefers independently
// finalized non-execution, but may also advance after one completed,
// authenticated Resolve attempt reports unknown, unavailable, or a signed
// non-terminal state. The latter is safe because every successor receipt
// commits the same byte-identical transaction identity; it is never available
// to sponsor_only or sponsor_and_relay.
func (orchestrator DecentralizedRelayCoordinator) Failover(ctx context.Context, plan *DecentralizedRelayPlan,
	prior RelayExecutionResult) (RelayExecutionResult, error) {
	if ctx == nil || orchestrator.RouteJournal == nil || plan == nil || plan.selected < 0 || plan.selected >= len(plan.candidates) ||
		!attemptMatchesPrepared(plan.Attempt, plan.base) {
		return RelayExecutionResult{}, errors.New("relay failover plan is invalid")
	}
	if plan.Attempt.Execution.QuoteRequest.Body.Mode != agentrelay.ModeRelayExact {
		return RelayExecutionResult{}, ErrRelaySuccessorAdmissionNotEnabled
	}
	if plan.Attempt.Execution.QuoteRequest.Body.AssuranceLevel != agentrelay.AssuranceAutonomousDecentralized {
		return RelayExecutionResult{}, errors.New("relay failover cannot change or overstate the signed assurance level")
	}
	current := plan.candidates[plan.selected].Coordinator
	route, err := orchestrator.RouteJournal.Resolve(plan.base.UnderlyingAction.StableActionID,
		plan.base.UnderlyingAction.ExactRequestDigest)
	if err != nil {
		return RelayExecutionResult{}, err
	}
	currentHop, found := route.Current()
	if !found || currentHop.Generation != plan.routeGeneration ||
		!reflect.DeepEqual(currentHop.Attempt, plan.Attempt) || !currentHop.SubmitStarted {
		return RelayExecutionResult{}, errors.New("relay failover differs from the durable ambiguous route")
	}
	effectiveMaximumRouteAttempts := route.MaximumRouteAttempts
	if orchestrator.MaximumRouteAttempts < effectiveMaximumRouteAttempts {
		effectiveMaximumRouteAttempts = orchestrator.MaximumRouteAttempts
	}
	// A lower current owner ceiling blocks any not-yet-admitted successor but
	// never revokes an admission call that may already have linearized. Raising
	// the configuration cannot expand the immutable initial route ceiling.
	if uint32(len(route.Hops)) >= effectiveMaximumRouteAttempts &&
		(route.PendingSwitch == nil || !route.PendingSwitch.AdmissionStarted) {
		return RelayExecutionResult{}, errors.New("current owner route-attempt ceiling forbids a new successor")
	}
	if route.PendingSwitch != nil {
		switch route.PendingSwitch.FailoverGateKind {
		case relayFailoverGateQuery:
			if err := orchestrator.verifyHistoricalRelayResolveQuery(route, currentHop); err != nil {
				return RelayExecutionResult{}, err
			}
		case relayFailoverGateFinality:
			if current == nil || currentHop.TerminalFinalityEvidence == nil {
				return RelayExecutionResult{}, errors.New("pending finality failover has no trusted verifier")
			}
			stored := RelayExecutionResult{Resolution: *currentHop.TerminalResolution,
				Evidence: currentHop.TerminalFinalityEvidence}
			if !relayFailoverPermittedForExecution(stored, currentHop.Attempt.Execution) ||
				current.verifyIndependentFinality(ctx, currentHop.Attempt, *stored.Evidence) != nil {
				return RelayExecutionResult{}, errors.New("pending finality failover no longer verifies independently")
			}
		default:
			return RelayExecutionResult{}, errors.New("pending relay successor has an unknown failover gate")
		}
	} else {
		switch {
		case currentHop.TerminalResolution != nil && currentHop.TerminalFinalityEvidence != nil:
			if current == nil {
				return RelayExecutionResult{}, errors.New("durable finality failover has no trusted verifier for the removed Provider")
			}
			stored := RelayExecutionResult{Resolution: *currentHop.TerminalResolution,
				Evidence: currentHop.TerminalFinalityEvidence}
			if !reflect.DeepEqual(prior, RelayExecutionResult{}) && (prior.Evidence == nil ||
				!reflect.DeepEqual(prior.Resolution, stored.Resolution) ||
				!reflect.DeepEqual(*prior.Evidence, *stored.Evidence)) {
				return RelayExecutionResult{}, errors.New("caller finality evidence conflicts with the durable route")
			}
			if !relayFailoverPermittedForExecution(stored, currentHop.Attempt.Execution) ||
				current.verifyIndependentFinality(ctx, currentHop.Attempt, *stored.Evidence) != nil {
				return RelayExecutionResult{}, errors.New("durable provider non-execution no longer verifies independently")
			}
		case currentHop.FailoverQueryAttempt != nil:
			if err := orchestrator.verifyHistoricalRelayResolveQuery(route, currentHop); err != nil {
				return RelayExecutionResult{}, err
			}
		default:
			if current == nil {
				return RelayExecutionResult{}, errors.New("relay failover has no authenticated route to query the current Provider")
			}
			route, err = orchestrator.recordAuthenticatedRelayResolveQuery(ctx, route, currentHop, current)
			if err != nil {
				return RelayExecutionResult{}, err
			}
			currentHop, _ = route.Current()
		}
	}
	currentExecutionDigest := currentHop.RelayExecutionDigest
	var candidateIndex int
	var successor *RelayCoordinator
	var successorProvenance RelayProviderProvenance
	var draft RelayAttempt
	if route.PendingSwitch != nil {
		candidateIndex = relayPlanCandidateIndex(plan, route.PendingSwitch.Provider)
		if candidateIndex < 0 {
			return RelayExecutionResult{}, errors.New("prepared relay successor is unavailable under owner provenance policy")
		}
		successor = plan.candidates[candidateIndex].Coordinator
		successorProvenance = route.PendingSwitch.Provider
		draft = cloneRelayAttempt(route.PendingSwitch.Attempt)
	} else {
		available, indexes := make([]RelayQuoteCandidate, 0, len(plan.candidates)), make([]int, 0, len(plan.candidates))
		for index, candidate := range plan.candidates {
			if !plan.used[index] && candidate.Coordinator != nil && candidate.Quoted.Request.Body.SchemaVersion != 0 &&
				relayQuoteWithinRouteBudget(route, candidate.Quoted.Quote) {
				available, indexes = append(available, candidate), append(indexes, index)
			}
		}
		if len(available) == 0 {
			return RelayExecutionResult{}, errors.New("no independently verified unused relay provider remains")
		}
		selected, selectErr := orchestrator.Selector.SelectRelayProvider(ctx, available)
		if selectErr != nil || selected < 0 || selected >= len(available) {
			return RelayExecutionResult{}, errors.New("owner relay failover provider selection failed")
		}
		candidateIndex = indexes[selected]
		successor = plan.candidates[candidateIndex].Coordinator
		successorProvenance = plan.provenance[candidateIndex]
		draft, err = successor.buildAttempt(ctx, plan.candidates[candidateIndex].Quoted)
		if err != nil {
			return RelayExecutionResult{}, err
		}
		if !attemptMatchesPrepared(draft, plan.base) || !relayAttemptHasNoAdmissionReceipt(draft) {
			return RelayExecutionResult{}, errors.New("relay successor draft changed the exact transaction")
		}
		route, err = orchestrator.RouteJournal.PrepareSwitch(route.StableActionID, route.ExactRequestDigest,
			currentHop.Generation, currentExecutionDigest, successorProvenance, draft, successor.now())
		if err != nil {
			return RelayExecutionResult{}, err
		}
	}
	if successor == nil {
		return RelayExecutionResult{}, errors.New("selected relay successor is unavailable")
	}
	admissionWasStarted := route.PendingSwitch != nil && route.PendingSwitch.AdmissionStarted
	writerEnvelopeIsStale := successor.FenceResolver.ConfirmCurrentWriterFence(
		draft.Execution.WriterFence, successor.now()) != nil
	// A prepared draft has no side-effect authority. If takeover happened
	// before admission started, replace its writer envelope only after the same
	// PersonalAuthority confirms the old lookup is absent.
	if route.PendingSwitch != nil && !admissionWasStarted && writerEnvelopeIsStale {
		oldRevision, oldEnvelope := route.PendingSwitch.AdmissionRevision,
			route.PendingSwitch.AdmissionEnvelopeDigest
		rebased, authorization, rebaseErr := successor.reauthorizePendingAttempt(ctx, draft,
			currentHop.Attempt.Execution.AdmissionReceipt)
		if rebaseErr != nil {
			return RelayExecutionResult{}, rebaseErr
		}
		route, err = orchestrator.RouteJournal.RebasePendingAdmission(route.StableActionID,
			route.ExactRequestDigest, currentHop.Generation, oldRevision, oldEnvelope,
			rebased, authorization, successor.now())
		if err != nil {
			return RelayExecutionResult{}, err
		}
		draft = cloneRelayAttempt(route.PendingSwitch.Attempt)
	}
	pendingExecutionDigest, err := agentrelay.RelayExecutionRequestDigest(draft.Execution)
	if err != nil {
		return RelayExecutionResult{}, err
	}
	if _, err = orchestrator.RouteJournal.MarkPendingAdmissionStarted(route.StableActionID,
		route.ExactRequestDigest, currentHop.Generation, route.PendingSwitch.AdmissionRevision,
		route.PendingSwitch.AdmissionEnvelopeDigest, successor.now()); err != nil {
		return RelayExecutionResult{}, err
	}
	var attempt RelayAttempt
	if admissionWasStarted && writerEnvelopeIsStale {
		// Never replay an already-started superseded writer envelope. Resolve
		// first: a found receipt drains under the old credentials; only the
		// authority's typed linearizable not-found may enter reauthorization.
		attempt, err = successor.resolveAttempt(ctx, draft, currentHop.Attempt.Execution.AdmissionReceipt)
	} else {
		attempt, err = successor.admitAttempt(ctx, draft, &currentHop.Attempt.Execution.AdmissionReceipt)
	}
	if err != nil && errors.Is(err, agentrelay.ErrRelayUnknown) {
		// AdmissionStarted means the old lookup had to be resolved through the
		// exact linearization authority. Only its typed not-found result permits
		// a signed reauthorization; timeout, transport failure, or an ambiguous
		// Resolve remains blocked and will retry the same lookup.
		stored, resolveErr := orchestrator.RouteJournal.Resolve(route.StableActionID, route.ExactRequestDigest)
		if resolveErr != nil || stored.PendingSwitch == nil || !stored.PendingSwitch.AdmissionStarted ||
			stored.PendingSwitch.RelayExecutionDigest != pendingExecutionDigest {
			return RelayExecutionResult{}, errors.Join(err, resolveErr)
		}
		rebased, authorization, rebaseErr := successor.reauthorizePendingAttempt(ctx, draft,
			currentHop.Attempt.Execution.AdmissionReceipt)
		if rebaseErr != nil {
			return RelayExecutionResult{}, errors.Join(err, rebaseErr)
		}
		route, rebaseErr = orchestrator.RouteJournal.RebasePendingAdmission(route.StableActionID,
			route.ExactRequestDigest, currentHop.Generation, stored.PendingSwitch.AdmissionRevision,
			stored.PendingSwitch.AdmissionEnvelopeDigest, rebased,
			authorization, successor.now())
		if rebaseErr != nil {
			return RelayExecutionResult{}, errors.Join(err, rebaseErr)
		}
		draft = cloneRelayAttempt(route.PendingSwitch.Attempt)
		pendingExecutionDigest, rebaseErr = agentrelay.RelayExecutionRequestDigest(draft.Execution)
		if rebaseErr != nil {
			return RelayExecutionResult{}, rebaseErr
		}
		if _, rebaseErr = orchestrator.RouteJournal.MarkPendingAdmissionStarted(route.StableActionID,
			route.ExactRequestDigest, currentHop.Generation, route.PendingSwitch.AdmissionRevision,
			route.PendingSwitch.AdmissionEnvelopeDigest, successor.now()); rebaseErr != nil {
			return RelayExecutionResult{}, rebaseErr
		}
		attempt, err = successor.admitAttempt(ctx, draft, &currentHop.Attempt.Execution.AdmissionReceipt)
	}
	if err != nil {
		return RelayExecutionResult{}, err
	}
	route, err = orchestrator.RouteJournal.Switch(route.StableActionID, route.ExactRequestDigest,
		currentHop.Generation, currentExecutionDigest, successorProvenance, attempt, successor.now())
	if err != nil {
		return RelayExecutionResult{}, err
	}
	next, found := route.Current()
	if !found || next.Generation != currentHop.Generation+1 || !reflect.DeepEqual(next.Attempt, attempt) {
		return RelayExecutionResult{}, errors.New("durable relay successor commit is inconsistent")
	}
	plan.selected, plan.routeGeneration, plan.Attempt = candidateIndex, next.Generation, cloneRelayAttempt(attempt)
	plan.used[candidateIndex] = true
	return orchestrator.Submit(ctx, plan)
}

func relayQuoteWithinRouteBudget(route RelayRouteRecord, quote agentrelay.SignedProviderRelayQuote) bool {
	fee, asset, err := relayProviderQuoteServiceFee(quote)
	cumulative, addErr := addRelayAtomic(route.CumulativeServiceFeeAtomic, fee)
	return err == nil && addErr == nil && asset == route.ServiceFeeAsset &&
		compareRelayAtomic(cumulative, route.MaximumCumulativeServiceFeeAtomic) <= 0 &&
		uint32(len(route.Hops)) < route.MaximumRouteAttempts
}

func relayPlanCandidateIndex(plan *DecentralizedRelayPlan, provider RelayProviderProvenance) int {
	if plan == nil {
		return -1
	}
	for index := range plan.provenance {
		if sameRelayProvenance(plan.provenance[index], provider) && plan.candidates[index].Coordinator != nil {
			return index
		}
	}
	return -1
}

// RelayFailoverPermitted is structural only; Failover additionally re-runs
// independent finality verification over the persisted evidence before acting.
func RelayFailoverPermitted(result RelayExecutionResult) bool {
	if result.Evidence == nil || result.Resolution.Body.State != commerce.ActionTerminal ||
		result.Evidence.Body.Outcome != result.Resolution.Body.TerminalOutcome ||
		result.Evidence.Body.SponsorshipTransferReference != "" {
		return false
	}
	switch result.Evidence.Body.Outcome {
	case agentrelay.OutcomeFinalizedAbsent, agentrelay.OutcomeFinalizedExpired, agentrelay.OutcomeFinalizedInvalidated:
		return relayEvidenceProvesNoSponsorshipOrClientTransaction(result.Evidence.Body)
	default:
		return false
	}
}

func relayFailoverPermittedForExecution(result RelayExecutionResult,
	execution agentrelay.RelayExecutionRequest) bool {
	if !RelayFailoverPermitted(result) {
		return false
	}
	body := result.Evidence.Body
	if execution.QuoteRequest.Body.Mode == agentrelay.ModeRelayExact {
		return body.SponsorshipStableActionID == "" && body.SponsorshipExactRequestDigest == "" &&
			body.SponsorshipValidUntilUnix == 0 && len(body.SponsorshipAbsenceObservations) == 0
	}
	return canonicalSHA256(body.SponsorshipStableActionID) && canonicalSHA256(body.SponsorshipExactRequestDigest) &&
		body.SponsorshipValidUntilUnix > 0 && len(body.SponsorshipAbsenceObservations) > 0
}

func relayEvidenceProvesNoSponsorshipOrClientTransaction(body agentrelay.RelayFinalityEvidenceBody) bool {
	hasSponsorshipIdentity := body.SponsorshipStableActionID != "" || body.SponsorshipExactRequestDigest != ""
	if body.SubmittedTransactionHash != "" ||
		body.SourceExecutionReference != "" || len(body.DestinationCreditReferences) != 0 {
		return false
	}
	if !hasSponsorshipIdentity {
		return body.SponsorshipValidUntilUnix == 0 && len(body.SponsorshipAbsenceObservations) == 0 &&
			len(body.TransactionAbsenceObservations) == 0
	}
	if !canonicalSHA256(body.SponsorshipStableActionID) ||
		!canonicalSHA256(body.SponsorshipExactRequestDigest) || body.SponsorshipValidUntilUnix == 0 ||
		len(body.SponsorshipAbsenceObservations) == 0 {
		return false
	}
	// A sponsor-only execution has no client relay transaction to disprove. A
	// combined execution must independently prove absence in both domains. This
	// structural result does not authorize a sponsorship successor; V1 keeps the
	// owner-wide no-replacement fence in Failover.
	if body.RelayFinalityProfile == nil {
		return len(body.TransactionAbsenceObservations) == 0 && body.SponsorshipTerminalProfile != nil
	}
	return body.SponsorshipTerminalProfile != nil && len(body.TransactionAbsenceObservations) > 0
}

func relayProviderRouteID(prepared PreparedRelayTransaction, providerAgentID, intentDigest string) string {
	message := "tos.openfox.agent-relay-provider-route.v1\x00" + prepared.UnderlyingAction.StableActionID + "\x00" +
		prepared.UnderlyingAction.ExactRequestDigest + "\x00" + providerAgentID + "\x00" + intentDigest
	digest := sha256.Sum256([]byte(message))
	return "route:" + hex.EncodeToString(digest[:])
}

func relayClientSponsorshipRecoveryToken(executionDigest string) []byte {
	digest := sha256.Sum256([]byte("tos.openfox.relay-client-sponsorship-attempt.v1\x00" + executionDigest))
	return append([]byte(nil), digest[:]...)
}

func clonePreparedRelayTransaction(prepared PreparedRelayTransaction) (PreparedRelayTransaction, error) {
	wire, err := commerce.ExportSemanticFields(prepared.UnderlyingAction.ActionKind, prepared.SemanticFields)
	if err != nil {
		return PreparedRelayTransaction{}, errors.New("relay semantic fields are invalid")
	}
	fields, err := commerce.ImportSemanticFields(prepared.UnderlyingAction.ActionKind, wire)
	if err != nil {
		return PreparedRelayTransaction{}, errors.New("relay semantic fields cannot be frozen")
	}
	cloned := prepared
	cloned.ExactSignedBOC = append([]byte(nil), prepared.ExactSignedBOC...)
	cloned.UnderlyingActionRequest = append([]byte(nil), prepared.UnderlyingActionRequest...)
	cloned.SemanticFields = fields
	cloned.WriterFence.Body.Scope = append([]string(nil), prepared.WriterFence.Body.Scope...)
	if prepared.QuoteBody.RequestedSponsorship != nil {
		value := *prepared.QuoteBody.RequestedSponsorship
		cloned.QuoteBody.RequestedSponsorship = &value
	}
	return cloned, nil
}

func sameRelayBaseIdentity(left, right PreparedRelayTransaction) bool {
	leftBody, rightBody := left.QuoteBody, right.QuoteBody
	leftBody.ProviderAgentID, rightBody.ProviderAgentID = "", ""
	leftBody.RequestID, rightBody.RequestID = "", ""
	return reflect.DeepEqual(leftBody, rightBody) && bytes.Equal(left.ExactSignedBOC, right.ExactSignedBOC) &&
		bytes.Equal(left.UnderlyingActionRequest, right.UnderlyingActionRequest) &&
		reflect.DeepEqual(left.UnderlyingAction, right.UnderlyingAction) && reflect.DeepEqual(left.WriterFence, right.WriterFence) &&
		reflect.DeepEqual(left.SemanticFields, right.SemanticFields)
}

func attemptMatchesPrepared(attempt RelayAttempt, prepared PreparedRelayTransaction) bool {
	request := attempt.Execution
	attemptBody, preparedBody := request.QuoteRequest.Body, prepared.QuoteBody
	attemptBody.ProviderAgentID, preparedBody.ProviderAgentID = "", ""
	attemptBody.RequestID, preparedBody.RequestID = "", ""
	wireFields, err := commerce.ExportSemanticFields(prepared.UnderlyingAction.ActionKind, prepared.SemanticFields)
	if err != nil {
		return false
	}
	return reflect.DeepEqual(attemptBody, preparedBody) &&
		request.ProviderQuote.Body.Mode == request.QuoteRequest.Body.Mode &&
		request.ProviderQuote.Body.AssuranceLevel == request.QuoteRequest.Body.AssuranceLevel &&
		request.AuthorizedAction.StableActionID == prepared.UnderlyingAction.StableActionID &&
		request.AuthorizedAction.ExactRequestDigest == prepared.UnderlyingAction.ExactRequestDigest &&
		sameRelayAuthorizedActionContext(request.AuthorizedAction, prepared.UnderlyingAction) &&
		request.WriterFence.Body.OwnerID == prepared.WriterFence.Body.OwnerID &&
		request.WriterFence.Body.AgentID == prepared.WriterFence.Body.AgentID &&
		request.WriterFence.Body.AuthorityID == prepared.WriterFence.Body.AuthorityID &&
		request.WriterFence.PublicKey == prepared.WriterFence.PublicKey &&
		reflect.DeepEqual(request.SemanticFields, wireFields) &&
		bytes.Equal(request.UnderlyingActionRequest, prepared.UnderlyingActionRequest) &&
		bytes.Equal(request.SignedTransactionBytes, prepared.ExactSignedBOC)
}

func (coordinator RelayCoordinator) now() time.Time {
	if coordinator.Now != nil {
		return coordinator.Now().UTC()
	}
	return time.Now().UTC()
}
