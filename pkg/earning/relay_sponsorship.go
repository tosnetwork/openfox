package earning

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

// AgreementSponsorshipProcessor is the production bridge from agentrelay's
// gas_sponsorship obligation to OpenFox's durable payment.direct authority and
// an AgreementPaymentSink such as TOSCTLPaymentSink. DirectPayment remains
// feature-gated and default-off through Engine.Gates.
type AgreementSponsorshipProcessor struct {
	Engine           *Engine
	Sink             AgreementPaymentSink
	Verifier         commerce.PaymentEvidenceVerifier
	FinalityVerifier RelaySponsorshipFinalityVerifier
	// TransactionEvidenceVerifier independently verifies the exact nested
	// Provider-funded transaction proof before local payment authority is
	// accepted or the client transaction may be broadcast.
	TransactionEvidenceVerifier agentrelay.SponsorshipTransactionEvidenceVerifier
	// EvidenceResolver is the query-only bridge from the exact custody journal
	// to either typed finalized transaction evidence or explicit nonterminal RPC
	// corroboration. It owns no signing or transfer authority.
	EvidenceResolver RelaySponsorshipEvidenceResolver
	AbsenceResolver  RelaySponsorshipAbsenceResolver
	NetworkDomain    agentrelay.NetworkDomain
	NativeAsset      agentrelay.AssetIdentity
	PolicyRevision   uint64
	WriterFence      commerce.WriterFence
	Now              func() time.Time
}

// VerifySponsorshipCreditObservation binds ProviderService's post-processor
// gate to the same concrete resolver that produced and already snapshot-
// verified the observation. Runtime wiring always selects this method from
// the configured Sponsorship object, preventing verifier/processor A-B
// substitution.
func (processor *AgreementSponsorshipProcessor) VerifySponsorshipCreditObservation(ctx context.Context,
	observation agentrelay.RelaySponsorshipCreditObservation,
	profile agentrelay.SponsorshipReleaseProfile) error {
	if processor == nil || processor.EvidenceResolver == nil {
		return errors.New("sponsorship observation resolver is unavailable")
	}
	verifier, ok := processor.EvidenceResolver.(agentrelay.SponsorshipCreditObservationVerifier)
	if !ok {
		return errors.New("sponsorship observation resolver has no protocol verifier")
	}
	return verifier.VerifySponsorshipCreditObservation(ctx, observation, profile)
}

// RelaySponsorshipEvidenceResolver resolves the already admitted
// AgreementPaymentRequestV3. It must never prepare, sign, submit, or replace a
// transfer. Unknown is a normal result. ObservedUnproven is available only at
// lower assurance and remains nonterminal; autonomous assurance requires a
// portable finalized TransactionEvidence.
type RelaySponsorshipEvidenceResolver interface {
	ResolveRelaySponsorshipEvidence(context.Context, agentrelay.RelayExecutionRequest,
		commerce.AgreementPaymentRequest) (agentrelay.SponsorshipResolution, error)
	RelaySponsorshipEvidenceCapabilities() RelaySponsorshipEvidenceCapabilities
}

// RelaySponsorshipTerminalEvidenceResolver performs a chain-side-effect-free
// recovery query for the complete typed top-up transaction proof. A concrete
// custody adapter may atomically journal the exact quorum winner locally before
// returning it. Only an explicit bounded not-found/not-mature/unavailable
// result becomes SponsorshipResolutionUnknown; malformed or contradictory
// evidence is an error. Terminal results carry the full nested evidence and
// are independently verified before the Provider can broadcast the client
// transaction.
type RelaySponsorshipTerminalEvidenceResolver interface {
	ResolveRelaySponsorshipTerminalEvidence(context.Context, agentrelay.RelayExecutionRequest,
		commerce.AgreementPaymentRequest, *RelaySponsorshipEvidenceSnapshot) (agentrelay.SponsorshipResolution, error)
}

// RelaySponsorshipFrozenEvidenceResolver is implemented by resolvers that
// retain an immutable content-addressed evidence configuration per signed
// release profile. It is used only for recovery of an already admitted
// action: new capability advertisement still requires the current owner
// configuration to reproduce the selected profile exactly.
type RelaySponsorshipEvidenceSnapshot struct {
	SchemaVersion       uint16 `json:"schema_version"`
	EvidenceClass       string `json:"evidence_class"`
	ProfileURI          string `json:"profile_uri"`
	ProfileDigest       string `json:"profile_digest"`
	MaximumTransactions uint32 `json:"maximum_transactions"`
	// RegistryRoot, CustodyWallet, and ProviderSourceAccount are immutable
	// per-action custody locators. Owner rotation changes only snapshots frozen
	// for later Quotes; recovery never borrows these values from the current
	// process configuration.
	RegistryRoot          string `json:"registry_root,omitempty"`
	CustodyWallet         string `json:"custody_wallet,omitempty"`
	ProviderSourceAccount string `json:"provider_source_account,omitempty"`
	FeeReserveNanoTOS     uint64 `json:"fee_reserve_nanotos,omitempty"`
	SnapshotPath          string `json:"snapshot_path"`
	SnapshotIdentity      string `json:"snapshot_identity"`
}

type RelaySponsorshipSnapshotPaymentSink interface {
	SubmitRelaySponsorshipPayment(context.Context, commerce.AuthorizedAction, commerce.WriterFence,
		map[string]commerce.SemanticValue, []byte, commerce.AgreementPaymentRequest,
		agentrelay.FinalityProfile, RelaySponsorshipEvidenceSnapshot) (commerce.AgreementPaymentEvidence, error)
}

// RelaySponsorshipBroadcastResumer may resume only the already prepared exact
// custody BOC identified by the recovery token. A Signed custody record may
// cross its durable begin-broadcast boundary; a Broadcasting record remains
// query-only and must never be rebuilt or assigned another sequence.
type RelaySponsorshipBroadcastResumer interface {
	ResumeRelaySponsorshipBroadcast(context.Context, commerce.AgreementPaymentRequest,
		*RelaySponsorshipEvidenceSnapshot) error
}

// RelaySponsorshipSubmissionFenceSink establishes the durable submitted
// boundary itself after it has prepared/authorized the exact custody request
// and before its first network broadcast. Sinks that do not implement this
// interface are fenced by AgreementSponsorshipProcessor before SubmitPayment
// is called.
type RelaySponsorshipSubmissionFenceSink interface {
	ManagesRelaySponsorshipSubmissionFence() bool
}

type RelaySponsorshipFrozenEvidenceResolver interface {
	FreezeRelaySponsorshipEvidenceSnapshot(context.Context, agentrelay.RelayExecutionRequest) (
		RelaySponsorshipEvidenceSnapshot, error)
	ValidateRelaySponsorshipEvidenceSnapshot(agentrelay.SponsorshipReleaseProfile,
		RelaySponsorshipEvidenceSnapshot) error
	ResolveRelaySponsorshipEvidenceFromSnapshot(context.Context, agentrelay.RelayExecutionRequest,
		commerce.AgreementPaymentRequest, RelaySponsorshipEvidenceSnapshot) (agentrelay.SponsorshipResolution, error)
}

// RelaySponsorshipCreditObservationVerifier verifies the bounded RPC bundle,
// operator/profile pin and exact PaymentRequestV3 projection. Merely returning
// a structurally valid observation is insufficient to release sponsorship.
type RelaySponsorshipCreditObservationVerifier interface {
	VerifyRelaySponsorshipCreditObservation(context.Context, agentrelay.RelaySponsorshipCreditObservation,
		agentrelay.RelayExecutionRequest, commerce.AgreementPaymentRequest) error
}

// RelaySponsorshipFrozenCreditObservationVerifier verifies an observation
// against the immutable Provider snapshot retained for this exact funded
// action. Recovery must never silently fall back to the resolver's rotated
// current configuration.
type RelaySponsorshipFrozenCreditObservationVerifier interface {
	VerifyRelaySponsorshipCreditObservationFromSnapshot(context.Context,
		agentrelay.RelaySponsorshipCreditObservation, agentrelay.RelayExecutionRequest,
		commerce.AgreementPaymentRequest, RelaySponsorshipEvidenceSnapshot) error
}

// RelaySponsorshipFrozenTransactionEvidenceVerifier is the snapshot-bound
// terminal verifier used after Provider config rotation. It mirrors the
// concrete tosctl requester re-query seam and cannot infer current settings.
type RelaySponsorshipFrozenTransactionEvidenceVerifier interface {
	VerifyRelaySponsorshipTransactionEvidenceFromSnapshot(context.Context,
		agentrelay.RelaySponsorshipTransactionEvidence, agentrelay.RelaySponsorshipEvidenceContext,
		agentrelay.FinalityProfile, RelaySponsorshipEvidenceSnapshot) error
}

// RelaySponsorshipFinalityVerifier maps custody evidence to the complete,
// owner-pinned Relay FinalityProfile. Generic payment evidence verification is
// necessary but insufficient because it need not enforce the same depth,
// observer, operator-domain, reorg-window, and resolution rules.
type RelaySponsorshipFinalityVerifier interface {
	VerifyRelaySponsorshipFinality(context.Context, agentrelay.RelayExecutionRequest,
		commerce.AgreementPaymentRequest, commerce.AgreementPaymentEvidence) error
}

type RelaySponsorshipFinalityVerifierFunc func(context.Context, agentrelay.RelayExecutionRequest,
	commerce.AgreementPaymentRequest, commerce.AgreementPaymentEvidence) error

func (function RelaySponsorshipFinalityVerifierFunc) VerifyRelaySponsorshipFinality(ctx context.Context,
	execution agentrelay.RelayExecutionRequest, payment commerce.AgreementPaymentRequest,
	evidence commerce.AgreementPaymentEvidence) error {
	return function(ctx, execution, payment, evidence)
}

// RelaySponsorshipAbsenceResolver independently proves both non-credit of the
// exact provider payment action and non-execution of the exact client
// transaction. An ordinary custody "not found" error is never such proof.
type RelaySponsorshipAbsenceResolver interface {
	ResolveRelaySponsorshipAbsence(context.Context, agentrelay.RelayExecutionRequest,
		commerce.AgreementPaymentRequest, *RelaySponsorshipEvidenceSnapshot) (RelaySponsorshipAbsenceResult, error)
}

// RelaySponsorshipDualAbsenceAggregator is the query-only second phase for a
// combined action whose sponsorship-component absence is already durable.
// It receives the protected prior bundle and must preserve its sponsorship
// references exactly while adding independently observed transaction absence.
type RelaySponsorshipDualAbsenceAggregator interface {
	ResolveRelaySponsorshipDualAbsence(context.Context, agentrelay.RelayExecutionRequest,
		commerce.AgreementPaymentRequest, RelaySponsorshipEvidenceSnapshot,
		[]agentrelay.RelayAbsenceObservationReference, string, []byte) (RelaySponsorshipAbsenceResult, error)
}

// RelaySponsorshipTransactionAbsenceResolver is the no-write S+/R- producer.
// It uses the retained per-action sponsorship recovery snapshot after the
// top-up is already durable; it cannot authorize or construct another top-up.
type RelaySponsorshipTransactionAbsenceResolver interface {
	SupportsRelayTransactionComponentAbsenceEvidence(agentrelay.RelayEvidenceCapability,
		*RelaySponsorshipEvidenceSnapshot) bool
	ResolveRelayTransactionAbsence(context.Context, agentrelay.RelayExecutionRequest,
		commerce.AgreementPaymentRequest, RelaySponsorshipEvidenceSnapshot,
		agentrelay.TerminalOutcome) (RelaySponsorshipAbsenceResult, error)
}

// RelaySponsorshipAbsenceResult binds the typed reference arrays to the exact
// bounded generic proof wrapper transported to the requester. Provider-local
// observations without this content-addressed attachment cannot close or
// release an economic action.
type RelaySponsorshipAbsenceResult struct {
	Outcome                        agentrelay.TerminalOutcome
	SponsorshipAbsenceObservations []agentrelay.RelayAbsenceObservationReference
	TransactionAbsenceObservations []agentrelay.RelayAbsenceObservationReference
	ProofBundleDigest              string
	ProofBundle                    []byte
}

// RelaySponsorshipAbsenceCapability binds the absence producer to the same
// exact signed tuple as the Provider evidence source.  A happy-path terminal
// resolver is not sufficient: after an ambiguous top-up, the Provider must be
// able to prove both that the provider-funded action did not credit and that
// the client transaction did not execute before it releases exposure.
type RelaySponsorshipAbsenceCapability interface {
	SupportsRelaySponsorshipComponentAbsenceEvidence(agentrelay.RelayEvidenceCapability,
		*RelaySponsorshipEvidenceSnapshot) bool
	SupportsRelayDualAbsenceEvidence(agentrelay.RelayEvidenceCapability,
		*RelaySponsorshipEvidenceSnapshot) bool
}

// ErrRelaySponsorshipAbsenceUnresolved is the only non-error absence result.
// Implementations use it when the exact dual-absence predicate is not mature
// yet. Integrity, profile, checkpoint and quorum conflicts remain hard errors.
var ErrRelaySponsorshipAbsenceUnresolved = errors.New("relay sponsorship absence is not yet resolved")

type RelaySponsorshipAbsenceResolverFunc func(context.Context, agentrelay.RelayExecutionRequest,
	commerce.AgreementPaymentRequest, *RelaySponsorshipEvidenceSnapshot) (RelaySponsorshipAbsenceResult, error)

func (function RelaySponsorshipAbsenceResolverFunc) ResolveRelaySponsorshipAbsence(ctx context.Context,
	execution agentrelay.RelayExecutionRequest, payment commerce.AgreementPaymentRequest,
	snapshot *RelaySponsorshipEvidenceSnapshot) (RelaySponsorshipAbsenceResult, error) {
	return function(ctx, execution, payment, snapshot)
}

const relaySponsorshipRecoverySchema = "tos.openfox.relay-sponsorship-recovery.v1"

type relaySponsorshipRecoveryToken struct {
	Schema                          string                            `json:"schema"`
	RelayExecutionDigest            string                            `json:"relay_execution_digest"`
	Payment                         commerce.AgreementPaymentRequest  `json:"payment"`
	PaymentActionStableID           string                            `json:"payment_action_stable_id"`
	PaymentActionExactRequestDigest string                            `json:"payment_action_exact_request_digest"`
	EvidenceSnapshot                *RelaySponsorshipEvidenceSnapshot `json:"evidence_snapshot,omitempty"`
}

type relaySponsorshipPaymentMaterial struct {
	payment   commerce.AgreementPaymentRequest
	fields    map[string]commerce.SemanticValue
	canonical []byte
	action    commerce.AuthorizedAction
}

func (processor *AgreementSponsorshipProcessor) PrepareRecovery(ctx context.Context,
	execution agentrelay.RelayExecutionRequest, agreement commerce.AgentAgreement,
	obligation commerce.AgreementObligation) (agentrelay.SponsorshipRecoveryHandle, error) {
	material, err := processor.prepareSponsorshipPayment(ctx, execution, agreement, obligation, nil)
	if err != nil {
		return agentrelay.SponsorshipRecoveryHandle{}, err
	}
	executionDigest, err := agentrelay.RelayExecutionRequestDigest(execution)
	if err != nil {
		return agentrelay.SponsorshipRecoveryHandle{}, err
	}
	var snapshot *RelaySponsorshipEvidenceSnapshot
	if execution.QuoteRequest.Body.SponsorshipReleaseEvidenceClass ==
		agentrelay.SponsorshipReleaseObservedUnproven {
		resolver, ok := processor.EvidenceResolver.(RelaySponsorshipFrozenEvidenceResolver)
		if !ok {
			return agentrelay.SponsorshipRecoveryHandle{}, errors.New("observed sponsorship has no immutable corroboration snapshot")
		}
		frozen, freezeErr := resolver.FreezeRelaySponsorshipEvidenceSnapshot(ctx, execution)
		if freezeErr != nil {
			return agentrelay.SponsorshipRecoveryHandle{}, freezeErr
		}
		snapshot = &frozen
	}
	token, err := codec.Marshal(relaySponsorshipRecoveryToken{Schema: relaySponsorshipRecoverySchema,
		RelayExecutionDigest: executionDigest, Payment: material.payment,
		PaymentActionStableID:           material.action.StableActionID,
		PaymentActionExactRequestDigest: material.action.ExactRequestDigest,
		EvidenceSnapshot:                snapshot})
	if err != nil || len(token) == 0 || len(token) > agentrelay.MaxSignedTransactionBytes {
		return agentrelay.SponsorshipRecoveryHandle{}, errors.New("encode bounded relay sponsorship recovery token")
	}
	paymentDigest, err := commerce.AgreementPaymentRequestDigest(material.payment)
	if err != nil {
		return agentrelay.SponsorshipRecoveryHandle{}, errors.New("digest exact gas sponsorship payment request")
	}
	return agentrelay.SponsorshipRecoveryHandle{AgreementPaymentRequestDigest: paymentDigest,
		StableActionID:     material.action.StableActionID,
		ExactRequestDigest: material.action.ExactRequestDigest, ValidUntilUnix: material.payment.ExpiresAtUnix,
		OpaqueToken: token}, nil
}

func (processor *AgreementSponsorshipProcessor) EnsureFinalized(ctx context.Context,
	execution agentrelay.RelayExecutionRequest, agreement commerce.AgentAgreement,
	obligation commerce.AgreementObligation,
	recovery agentrelay.SponsorshipRecoveryHandle) (agentrelay.SponsorshipResolution, error) {
	token, err := decodeRelaySponsorshipRecoveryHandle(recovery, execution)
	if err != nil {
		return agentrelay.SponsorshipResolution{}, err
	}
	material, err := processor.prepareSponsorshipPayment(ctx, execution, agreement, obligation,
		token.EvidenceSnapshot)
	if err != nil {
		return agentrelay.SponsorshipResolution{}, err
	}
	if err := verifyRelaySponsorshipRecoveryHandle(recovery, execution, material); err != nil {
		return agentrelay.SponsorshipResolution{}, err
	}
	action, err := processor.Engine.Authority.SignAction(material.action, processor.WriterFence)
	if err != nil {
		return agentrelay.SponsorshipResolution{}, errors.New("sign exact gas sponsorship payment action")
	}
	payment, fields, canonical := material.payment, material.fields, material.canonical

	prior := processor.Engine.Authority.Resolve(action.StableActionID, action.ExactRequestDigest)
	admitted, err := processor.Engine.Authority.Admit(action, fields, canonical, processor.WriterFence, nil)
	if err != nil {
		return agentrelay.SponsorshipResolution{}, err
	}
	// Any recovered action is queried before an exact retry. SUBMITTED is the
	// durable before-socket ambiguity boundary: if custody cannot resolve it,
	// OpenFox must not call SubmitPayment again because a lost custody database
	// could otherwise build a different seqno transaction for the same payment.
	if prior.State != commerce.ActionUnknown {
		var resumeErr error
		if prior.State == commerce.ActionSubmitted {
			if resumer, ok := processor.Sink.(RelaySponsorshipBroadcastResumer); ok {
				resumeErr = resumer.ResumeRelaySponsorshipBroadcast(ctx, payment, token.EvidenceSnapshot)
			} else {
				resumeErr = errors.New("submitted sponsorship has no exact custody broadcast resumer")
			}
		}
		if processor.EvidenceResolver != nil {
			resolved, resolveErr := processor.resolveTypedEvidence(ctx, execution, payment, action, admitted,
				token.EvidenceSnapshot)
			if resolveErr == nil && !(prior.State == commerce.ActionPrepared &&
				resolved.Status == agentrelay.SponsorshipResolutionUnknown) {
				if resolveErr == nil && resolved.Status == agentrelay.SponsorshipResolutionUnknown && resumeErr != nil {
					return resolved, errors.Join(resumeErr, ErrRelaySubmissionAmbiguous)
				}
				return resolved, resolveErr
			}
			if prior.State == commerce.ActionAccepted || prior.State == commerce.ActionTerminal ||
				prior.State == commerce.ActionSubmitted {
				return resolved, resolveErr
			}
		}
		if processor.EvidenceResolver == nil {
			if evidence, resolveErr := processor.Sink.ResolvePayment(ctx, payment); resolveErr == nil {
				return processor.acceptEvidence(ctx, execution, payment, action, evidence, admitted)
			} else if prior.State == commerce.ActionAccepted || prior.State == commerce.ActionTerminal {
				return agentrelay.SponsorshipResolution{}, errors.New("finalized sponsorship payment evidence is unavailable")
			} else if prior.State == commerce.ActionSubmitted {
				return agentrelay.SponsorshipResolution{}, errors.Join(ErrRelaySubmissionAmbiguous,
					errors.New("submitted sponsorship payment is unresolved; refusing another custody submission"))
			}
		}
	}
	sinkOwnsSubmissionFence := false
	if fencedSink, ok := processor.Sink.(RelaySponsorshipSubmissionFenceSink); ok {
		sinkOwnsSubmissionFence = fencedSink.ManagesRelaySponsorshipSubmissionFence()
	}
	if admitted.State == commerce.ActionPrepared && !sinkOwnsSubmissionFence {
		admitted, err = processor.Engine.Authority.Transition(action.StableActionID, action.ExactRequestDigest,
			commerce.ActionSubmitted, "", nil)
		if err != nil {
			return agentrelay.SponsorshipResolution{}, err
		}
	} else if admitted.State != commerce.ActionPrepared && admitted.State != commerce.ActionSubmitted {
		return agentrelay.SponsorshipResolution{}, errors.New("gas sponsorship payment cannot be submitted from its durable state")
	}
	var evidence commerce.AgreementPaymentEvidence
	var submitErr error
	if token.EvidenceSnapshot != nil {
		terminalProfile, profileErr := relaySponsorshipTerminalProfile(execution)
		if profileErr != nil {
			return agentrelay.SponsorshipResolution{}, profileErr
		}
		if sink, ok := processor.Sink.(RelaySponsorshipSnapshotPaymentSink); ok {
			evidence, submitErr = sink.SubmitRelaySponsorshipPayment(ctx, action, processor.WriterFence,
				fields, canonical, payment, terminalProfile, *token.EvidenceSnapshot)
		} else {
			submitErr = errors.New("observed sponsorship payment sink cannot use its frozen corroboration snapshot")
		}
	} else {
		evidence, submitErr = processor.Sink.SubmitPayment(ctx, action, processor.WriterFence, fields, canonical, payment)
	}
	if processor.EvidenceResolver != nil {
		resolved, resolveErr := processor.resolveTypedEvidence(ctx, execution, payment, action, admitted,
			token.EvidenceSnapshot)
		if resolveErr == nil {
			if submitErr != nil && resolved.Status == agentrelay.SponsorshipResolutionUnknown {
				return resolved, errors.Join(submitErr, ErrRelaySubmissionAmbiguous)
			}
			return resolved, nil
		}
		if submitErr != nil {
			return agentrelay.SponsorshipResolution{}, errors.Join(submitErr, resolveErr)
		}
		return agentrelay.SponsorshipResolution{}, resolveErr
	}
	if submitErr != nil {
		evidence, err = processor.Sink.ResolvePayment(ctx, payment)
		if err != nil {
			return agentrelay.SponsorshipResolution{}, submitErr
		}
	}
	return processor.acceptEvidence(ctx, execution, payment, action, evidence, admitted)
}

func (processor *AgreementSponsorshipProcessor) ResolveFinalized(ctx context.Context,
	execution agentrelay.RelayExecutionRequest,
	recovery agentrelay.SponsorshipRecoveryHandle) (agentrelay.SponsorshipResolution, error) {
	if err := processor.validateRecovery(ctx); err != nil {
		return agentrelay.SponsorshipResolution{}, err
	}
	token, err := decodeRelaySponsorshipRecoveryHandle(recovery, execution)
	if err != nil {
		return agentrelay.SponsorshipResolution{}, err
	}
	if err := processor.validateEvidencePathForExecution(execution, token.EvidenceSnapshot); err != nil {
		return agentrelay.SponsorshipResolution{}, err
	}
	if !processor.recoveryNetworkMatches(execution, token.EvidenceSnapshot) ||
		token.Payment.OwnerID != processor.Engine.OwnerID || token.Payment.AgentID != processor.Engine.AgentID ||
		token.EvidenceSnapshot == nil && (token.Payment.Amount.AssetNamespace != processor.NativeAsset.AssetNamespace ||
			token.Payment.Amount.AssetIdentifier != processor.NativeAsset.AssetIdentifier ||
			token.Payment.Amount.Unit != processor.NativeAsset.Unit) {
		return agentrelay.SponsorshipResolution{}, errors.New("relay sponsorship recovery token conflicts with provider custody policy")
	}
	if sink, ok := processor.Sink.(*TOSCTLPaymentSink); ok {
		configPath := sink.ConfigPath
		if token.EvidenceSnapshot != nil {
			configPath, err = sink.relaySponsorshipSnapshotPrimaryConfig(*token.EvidenceSnapshot)
		}
		if err != nil {
			return agentrelay.SponsorshipResolution{}, err
		}
		if err := sink.verifyRelayNetworkDomainAt(ctx, execution.QuoteRequest.Body.Network, configPath); err != nil {
			return agentrelay.SponsorshipResolution{}, err
		}
	}
	if terminal, ok := processor.EvidenceResolver.(RelaySponsorshipTerminalEvidenceResolver); ok {
		resolution, terminalErr := terminal.ResolveRelaySponsorshipTerminalEvidence(ctx, execution,
			token.Payment, token.EvidenceSnapshot)
		if terminalErr != nil {
			return agentrelay.SponsorshipResolution{}, terminalErr
		}
		if resolution.Status != agentrelay.SponsorshipResolutionUnknown {
			if err := processor.validateTypedSponsorshipResolution(ctx, execution, token.Payment,
				token.EvidenceSnapshot, resolution); err != nil {
				return agentrelay.SponsorshipResolution{}, err
			}
			if relaySponsorshipResolutionHasTransfer(resolution.Status) {
				if err := processor.acceptRecoveredTypedSponsorshipEvidence(token, resolution); err != nil {
					return agentrelay.SponsorshipResolution{}, err
				}
			}
			return resolution, nil
		}
		// Once the initial bounded release observation is journaled, recovery is
		// terminal-query-only. Re-running corroboration can mint a different
		// observation timestamp/checkpoint for the same funded action and conflict
		// with the immutable journal record. A terminal Unknown may, however, fall
		// through to the separately capability-qualified dual-absence resolver.
		// That resolver is also query-only and can return only an exact terminal
		// proof or ErrRelaySponsorshipAbsenceUnresolved.
		return processor.resolveSponsorshipAbsence(ctx, execution, token.Payment,
			token.EvidenceSnapshot, resolution)
	}
	if processor.EvidenceResolver != nil {
		resolution, err := processor.resolveSponsorshipEvidence(ctx, execution, token.Payment,
			token.EvidenceSnapshot)
		if err != nil {
			return agentrelay.SponsorshipResolution{}, err
		}
		if err := processor.validateTypedSponsorshipResolution(ctx, execution, token.Payment,
			token.EvidenceSnapshot, resolution); err != nil {
			return agentrelay.SponsorshipResolution{}, err
		}
		if relaySponsorshipResolutionHasTransfer(resolution.Status) {
			if err := processor.acceptRecoveredTypedSponsorshipEvidence(token, resolution); err != nil {
				return agentrelay.SponsorshipResolution{}, err
			}
		}
		return resolution, nil
	}
	evidence, err := processor.Sink.ResolvePayment(ctx, token.Payment)
	if err != nil {
		return processor.resolveSponsorshipAbsence(ctx, execution, token.Payment, token.EvidenceSnapshot,
			agentrelay.SponsorshipResolution{Status: agentrelay.SponsorshipResolutionUnknown})
	}
	evidenceDigest, err := processor.verifyEvidence(ctx, execution, token.Payment, evidence)
	if err != nil {
		return agentrelay.SponsorshipResolution{}, err
	}
	return agentrelay.SponsorshipResolution{Status: agentrelay.SponsorshipResolutionFinalized,
		TransferReference: evidence.ExactTransferReference, EvidenceRefs: []string{evidenceDigest}}, nil
}

// ResolveRelayDualAbsence implements agentrelay's protected S-/R- promotion
// seam. The first sponsorship-component tombstone stays authoritative; this
// method cannot submit payment and accepts a dual wrapper only when every
// stored sponsorship reference is byte-identical.
func (processor *AgreementSponsorshipProcessor) ResolveRelayDualAbsence(ctx context.Context,
	execution agentrelay.RelayExecutionRequest, recovery agentrelay.SponsorshipRecoveryHandle,
	existingSponsorship []agentrelay.RelayAbsenceObservationReference,
	existingBundleDigest string, existingBundle []byte) (agentrelay.SponsorshipResolution, error) {
	if err := processor.validateRecovery(ctx); err != nil {
		return agentrelay.SponsorshipResolution{}, err
	}
	token, err := decodeRelaySponsorshipRecoveryHandle(recovery, execution)
	if err != nil || token.EvidenceSnapshot == nil || execution.QuoteRequest.Body.Mode != agentrelay.ModeSponsorAndRelay {
		return agentrelay.SponsorshipResolution{}, errors.New("combined dual-absence recovery lost its exact frozen sponsorship token")
	}
	if err := processor.validateEvidencePathForExecution(execution, token.EvidenceSnapshot); err != nil {
		return agentrelay.SponsorshipResolution{}, err
	}
	computedPriorDigest, err := agentrelay.RelayAbsenceProofBundleDigest(existingBundle)
	var prior agentrelay.RelayAbsenceProofBundleV1
	if err != nil || computedPriorDigest != existingBundleDigest || codec.Unmarshal(existingBundle, &prior) != nil ||
		prior.ProofScope != agentrelay.RelayAbsenceProofSponsorshipOnly ||
		!reflect.DeepEqual(prior.SponsorshipAbsenceObservations, existingSponsorship) ||
		len(prior.TransactionAbsenceObservations) != 0 {
		return agentrelay.SponsorshipResolution{}, errors.New("combined dual-absence recovery conflicts with its protected sponsorship component")
	}
	aggregator, ok := processor.AbsenceResolver.(RelaySponsorshipDualAbsenceAggregator)
	capability, capabilityErr := relayEvidenceCapabilityForExecution(execution)
	qualified, qualifiedOK := processor.AbsenceResolver.(RelaySponsorshipAbsenceCapability)
	if !ok || capabilityErr != nil || !qualifiedOK ||
		!qualified.SupportsRelayDualAbsenceEvidence(capability, token.EvidenceSnapshot) {
		return agentrelay.SponsorshipResolution{}, errors.New("combined dual-absence aggregator is unavailable for the frozen capability")
	}
	absence, err := aggregator.ResolveRelaySponsorshipDualAbsence(ctx, execution, token.Payment,
		*token.EvidenceSnapshot, existingSponsorship, existingBundleDigest, existingBundle)
	if errors.Is(err, ErrRelaySponsorshipAbsenceUnresolved) {
		return agentrelay.SponsorshipResolution{Status: agentrelay.SponsorshipResolutionUnknown}, nil
	}
	if err != nil {
		return agentrelay.SponsorshipResolution{}, err
	}
	if !reflect.DeepEqual(absence.SponsorshipAbsenceObservations, existingSponsorship) ||
		len(absence.TransactionAbsenceObservations) == 0 {
		return agentrelay.SponsorshipResolution{}, errors.New("combined dual-absence aggregation substituted a durable component")
	}
	status, err := relaySponsorshipAbsenceStatus(absence.Outcome)
	if err != nil {
		return agentrelay.SponsorshipResolution{}, err
	}
	resolution := agentrelay.SponsorshipResolution{Status: status, AbsenceOutcome: absence.Outcome,
		SponsorshipAbsenceObservations: append([]agentrelay.RelayAbsenceObservationReference(nil),
			absence.SponsorshipAbsenceObservations...),
		TransactionAbsenceObservations: append([]agentrelay.RelayAbsenceObservationReference(nil),
			absence.TransactionAbsenceObservations...),
		AbsenceProofBundleDigest: absence.ProofBundleDigest,
		AbsenceProofBundle:       append([]byte(nil), absence.ProofBundle...)}
	if err := processor.validateTypedSponsorshipResolution(ctx, execution, token.Payment,
		token.EvidenceSnapshot, resolution); err != nil {
		return agentrelay.SponsorshipResolution{}, err
	}
	return resolution, nil
}

// ResolveRelayTransactionAbsence implements the protected S+/R- component
// seam. The durable sponsorship effect has already consumed the one-shot
// payment authority; the retained recovery handle supplies only immutable
// PaymentRequest/snapshot material for a query-only transaction proof.
func (processor *AgreementSponsorshipProcessor) ResolveRelayTransactionAbsence(ctx context.Context,
	execution agentrelay.RelayExecutionRequest, recovery agentrelay.SponsorshipRecoveryHandle,
	relayOutcome agentrelay.TerminalOutcome) (agentrelay.ChainResolution, error) {
	if err := processor.validateRecovery(ctx); err != nil {
		return agentrelay.ChainResolution{}, err
	}
	token, err := decodeRelaySponsorshipRecoveryHandle(recovery, execution)
	if err != nil || token.EvidenceSnapshot == nil || execution.QuoteRequest.Body.Mode != agentrelay.ModeSponsorAndRelay ||
		!safeRelayTerminalAbsenceOutcome(relayOutcome) {
		return agentrelay.ChainResolution{}, errors.New("combined transaction-absence recovery lost its exact frozen sponsorship token")
	}
	if err := processor.validateEvidencePathForExecution(execution, token.EvidenceSnapshot); err != nil {
		return agentrelay.ChainResolution{}, err
	}
	resolver, ok := processor.AbsenceResolver.(RelaySponsorshipTransactionAbsenceResolver)
	capability, capabilityErr := relayEvidenceCapabilityForExecution(execution)
	if !ok || capabilityErr != nil ||
		!resolver.SupportsRelayTransactionComponentAbsenceEvidence(capability, token.EvidenceSnapshot) {
		return agentrelay.ChainResolution{}, errors.New("combined transaction-component absence resolver is unavailable for the frozen capability")
	}
	absence, err := resolver.ResolveRelayTransactionAbsence(ctx, execution, token.Payment,
		*token.EvidenceSnapshot, relayOutcome)
	if errors.Is(err, ErrRelaySponsorshipAbsenceUnresolved) {
		return agentrelay.ChainResolution{}, nil
	}
	if err != nil {
		return agentrelay.ChainResolution{}, err
	}
	if len(absence.SponsorshipAbsenceObservations) != 0 ||
		len(absence.TransactionAbsenceObservations) == 0 ||
		!sameRelayAbsenceConclusion(absence.Outcome, relayOutcome) ||
		absence.ProofBundleDigest == "" || len(absence.ProofBundle) == 0 {
		return agentrelay.ChainResolution{}, errors.New("combined transaction-component resolver substituted the signed relay conclusion or scope")
	}
	return agentrelay.ChainResolution{State: commerce.ActionTerminal,
		TerminalOutcome: absence.Outcome,
		TransactionAbsenceObservations: append([]agentrelay.RelayAbsenceObservationReference(nil),
			absence.TransactionAbsenceObservations...),
		AbsenceProofBundleDigest: absence.ProofBundleDigest,
		AbsenceProofBundle:       append([]byte(nil), absence.ProofBundle...)}, nil
}

func sameRelayAbsenceConclusion(left, right agentrelay.TerminalOutcome) bool {
	class := func(value agentrelay.TerminalOutcome) int {
		switch value {
		case agentrelay.OutcomeFinalizedExpired, agentrelay.OutcomeCorroboratedExpired:
			return 1
		case agentrelay.OutcomeFinalizedAbsent, agentrelay.OutcomeCorroboratedAbsent:
			return 2
		case agentrelay.OutcomeFinalizedInvalidated, agentrelay.OutcomeCorroboratedInvalidated:
			return 3
		default:
			return 0
		}
	}
	return class(left) != 0 && class(left) == class(right)
}

func (processor *AgreementSponsorshipProcessor) resolveSponsorshipAbsence(ctx context.Context,
	execution agentrelay.RelayExecutionRequest, payment commerce.AgreementPaymentRequest,
	snapshot *RelaySponsorshipEvidenceSnapshot,
	unresolved agentrelay.SponsorshipResolution) (agentrelay.SponsorshipResolution, error) {
	if processor.AbsenceResolver == nil {
		return unresolved, nil
	}
	capability, err := relayEvidenceCapabilityForExecution(execution)
	qualified, ok := processor.AbsenceResolver.(RelaySponsorshipAbsenceCapability)
	if err != nil || !ok ||
		!qualified.SupportsRelaySponsorshipComponentAbsenceEvidence(capability, snapshot) ||
		execution.QuoteRequest.Body.Mode == agentrelay.ModeSponsorAndRelay &&
			!qualified.SupportsRelayDualAbsenceEvidence(capability, snapshot) {
		return agentrelay.SponsorshipResolution{}, errors.New("gas sponsorship absence resolver does not support every reachable signed component")
	}
	absence, err :=
		processor.AbsenceResolver.ResolveRelaySponsorshipAbsence(ctx, execution, payment, snapshot)
	if errors.Is(err, ErrRelaySponsorshipAbsenceUnresolved) {
		return unresolved, nil
	}
	if err != nil {
		return agentrelay.SponsorshipResolution{}, err
	}
	status, err := relaySponsorshipAbsenceStatus(absence.Outcome)
	if err != nil {
		return agentrelay.SponsorshipResolution{}, err
	}
	resolution := agentrelay.SponsorshipResolution{Status: status, AbsenceOutcome: absence.Outcome,
		SponsorshipAbsenceObservations: absence.SponsorshipAbsenceObservations,
		TransactionAbsenceObservations: absence.TransactionAbsenceObservations,
		AbsenceProofBundleDigest:       absence.ProofBundleDigest,
		AbsenceProofBundle:             append([]byte(nil), absence.ProofBundle...)}
	if err := processor.validateTypedSponsorshipResolution(ctx, execution, payment, snapshot, resolution); err != nil {
		return agentrelay.SponsorshipResolution{}, err
	}
	return resolution, nil
}

func relaySponsorshipAbsenceStatus(outcome agentrelay.TerminalOutcome) (agentrelay.SponsorshipResolutionStatus, error) {
	switch outcome {
	case agentrelay.OutcomeCorroboratedExpired, agentrelay.OutcomeCorroboratedAbsent,
		agentrelay.OutcomeCorroboratedInvalidated:
		return agentrelay.SponsorshipResolutionCorroboratedAbsent, nil
	case agentrelay.OutcomeFinalizedExpired, agentrelay.OutcomeFinalizedAbsent,
		agentrelay.OutcomeFinalizedInvalidated:
		return agentrelay.SponsorshipResolutionFinalizedAbsent, nil
	default:
		return "", errors.New("gas sponsorship absence resolver returned a non-absence outcome")
	}
}

func (processor *AgreementSponsorshipProcessor) acceptRecoveredTypedSponsorshipEvidence(
	token relaySponsorshipRecoveryToken, resolution agentrelay.SponsorshipResolution) error {
	if processor == nil || processor.Engine == nil || processor.Engine.Authority == nil ||
		!relaySponsorshipResolutionHasTransfer(resolution.Status) || resolution.TransferReference == "" ||
		len(resolution.EvidenceRefs) == 0 {
		return errors.New("recovered sponsorship terminal evidence is incomplete")
	}
	prior := processor.Engine.Authority.Resolve(token.PaymentActionStableID,
		token.PaymentActionExactRequestDigest)
	if prior.State == commerce.ActionUnknown || prior.State == commerce.ActionRejected ||
		prior.State == commerce.ActionConflict {
		return errors.New("recovered sponsorship has no exact admitted payment action")
	}
	if prior.State == commerce.ActionAccepted || prior.State == commerce.ActionTerminal {
		if prior.SinkReference != resolution.TransferReference || !equalStrings(prior.EvidenceRefs, resolution.EvidenceRefs) {
			return errors.New("recovered sponsorship evidence conflicts with the accepted payment action")
		}
		return nil
	}
	_, err := processor.Engine.Authority.Transition(token.PaymentActionStableID,
		token.PaymentActionExactRequestDigest, commerce.ActionAccepted,
		resolution.TransferReference, resolution.EvidenceRefs)
	return err
}

func (processor *AgreementSponsorshipProcessor) resolveTypedEvidence(ctx context.Context,
	execution agentrelay.RelayExecutionRequest, payment commerce.AgreementPaymentRequest,
	action commerce.AuthorizedAction, admitted commerce.ActionResolution,
	snapshot *RelaySponsorshipEvidenceSnapshot) (agentrelay.SponsorshipResolution, error) {
	resolution, err := processor.resolveSponsorshipEvidence(ctx, execution, payment, snapshot)
	if err != nil {
		return agentrelay.SponsorshipResolution{}, err
	}
	if err := processor.validateTypedSponsorshipResolution(ctx, execution, payment, snapshot, resolution); err != nil {
		return agentrelay.SponsorshipResolution{}, err
	}
	switch resolution.Status {
	case agentrelay.SponsorshipResolutionUnknown,
		agentrelay.SponsorshipResolutionObservedUnproven,
		agentrelay.SponsorshipResolutionCorroboratedAbsent,
		agentrelay.SponsorshipResolutionFinalizedAbsent:
		return resolution, nil
	case agentrelay.SponsorshipResolutionCorroboratedTerminal, agentrelay.SponsorshipResolutionFinalized:
		if resolution.TransactionEvidence == nil || resolution.TransferReference == "" ||
			len(resolution.EvidenceRefs) == 0 {
			return agentrelay.SponsorshipResolution{}, errors.New("typed gas sponsorship finality evidence is incomplete")
		}
		if admitted.State != commerce.ActionAccepted && admitted.State != commerce.ActionTerminal {
			if _, err := processor.Engine.Authority.Transition(action.StableActionID, action.ExactRequestDigest,
				commerce.ActionAccepted, resolution.TransferReference, resolution.EvidenceRefs); err != nil {
				return agentrelay.SponsorshipResolution{}, err
			}
		}
		return resolution, nil
	default:
		return agentrelay.SponsorshipResolution{}, errors.New("typed gas sponsorship resolution status is unknown")
	}
}

func (processor *AgreementSponsorshipProcessor) resolveSponsorshipEvidence(ctx context.Context,
	execution agentrelay.RelayExecutionRequest, payment commerce.AgreementPaymentRequest,
	snapshot *RelaySponsorshipEvidenceSnapshot) (agentrelay.SponsorshipResolution, error) {
	if snapshot != nil {
		resolver, ok := processor.EvidenceResolver.(RelaySponsorshipFrozenEvidenceResolver)
		if !ok {
			return agentrelay.SponsorshipResolution{}, errors.New("frozen sponsorship evidence resolver is unavailable")
		}
		return resolver.ResolveRelaySponsorshipEvidenceFromSnapshot(ctx, execution, payment, *snapshot)
	}
	return processor.EvidenceResolver.ResolveRelaySponsorshipEvidence(ctx, execution, payment)
}

func (processor *AgreementSponsorshipProcessor) prepareSponsorshipPayment(ctx context.Context,
	execution agentrelay.RelayExecutionRequest, agreement commerce.AgentAgreement,
	obligation commerce.AgreementObligation,
	snapshot *RelaySponsorshipEvidenceSnapshot) (relaySponsorshipPaymentMaterial, error) {
	if err := processor.validate(ctx); err != nil {
		return relaySponsorshipPaymentMaterial{}, err
	}
	if err := processor.validateEvidencePathForExecution(execution, snapshot); err != nil {
		return relaySponsorshipPaymentMaterial{}, err
	}
	body := execution.QuoteRequest.Body
	if body.Mode == agentrelay.ModeRelayExact || !processor.recoveryNetworkMatches(execution, snapshot) ||
		execution.SponsorshipObligationID == "" ||
		body.RequestedSponsorship == nil || execution.ProviderQuote.Body.ReservedSponsorship == nil {
		return relaySponsorshipPaymentMaterial{}, errors.New("relay execution has no exact gas sponsorship on the pinned network domain")
	}
	if sink, ok := processor.Sink.(*TOSCTLPaymentSink); ok {
		configPath := sink.ConfigPath
		if snapshot != nil {
			frozenConfigPath, snapshotErr := sink.relaySponsorshipSnapshotPrimaryConfig(*snapshot)
			if snapshotErr != nil {
				return relaySponsorshipPaymentMaterial{}, snapshotErr
			}
			configPath = frozenConfigPath
		}
		if err := sink.verifyRelayNetworkDomainAt(ctx, body.Network, configPath); err != nil {
			return relaySponsorshipPaymentMaterial{}, err
		}
	}
	agreementDigest, err := commerce.AgreementBodyDigest(agreement.Body)
	if err != nil || agreementDigest != execution.AgreementBodyDigest || obligation.ObligationID != execution.SponsorshipObligationID {
		return relaySponsorshipPaymentMaterial{}, errors.New("gas sponsorship does not belong to the verified Agreement")
	}
	binding, err := agentrelay.CompileRelayAgreementBinding(execution.QuoteRequest, execution.ProviderQuote)
	if err != nil {
		return relaySponsorshipPaymentMaterial{}, err
	}
	bindingBytes, err := agentrelay.RelayAgreementBindingBytes(binding)
	if err != nil {
		return relaySponsorshipPaymentMaterial{}, err
	}
	reserved := *execution.ProviderQuote.Body.ReservedSponsorship
	nativeAssetMatches := snapshot != nil || reserved.Asset == processor.NativeAsset
	if !sameRelaySponsorshipAmount(*body.RequestedSponsorship, reserved) || obligation.Amount == nil ||
		!sameRelayAgreementAssetAmount(*obligation.Amount, reserved) || !nativeAssetMatches ||
		obligation.Kind != agentrelay.ObligationSponsorDelivery || obligation.ObligorAgentID != processor.Engine.AgentID ||
		obligation.BeneficiaryAgentID != body.RequesterAgentID || obligation.SettlementAdapterURI != agentrelay.DirectPaymentAdapterURI ||
		obligation.SubjectContentType != agentrelay.AgreementBindingContentType || !bytes.Equal(obligation.Subject, bindingBytes) {
		return relaySponsorshipPaymentMaterial{}, errors.New("gas sponsorship obligation changes source, native asset, amount, or provider identity")
	}

	// The signed quote digest in the Agreement binding commits SourceAccount.
	// The resulting payment request also carries that account byte-for-byte as
	// its custody destination, so no display alias can redirect the transfer.
	materializedObligation := obligation
	materializedObligation.ExpiresAtUnix = relaySponsorshipExpiry(obligation.ExpiresAtUnix,
		agreement.Body.ExpiresAtUnix, execution.ExpiresAtUnix)
	instances, err := commerce.MaterializeSettlementObligations(processor.Engine.OwnerID, processor.Engine.AgentID,
		agreementDigest, obligation.ObligationID, processor.Engine.MandateDigest, materializedObligation)
	if err != nil || len(instances) != 1 || instances[0].Sequence != 1 {
		return relaySponsorshipPaymentMaterial{}, errors.New("gas sponsorship must materialize as one exact payment obligation")
	}
	networkDomainDigest, err := agentrelay.NetworkDomainDigest(body.Network)
	if err != nil {
		return relaySponsorshipPaymentMaterial{}, err
	}
	payment, err := commerce.BuildDomainBoundAgreementPaymentRequest(processor.Engine.OwnerID,
		processor.Engine.AgentID, body.Network.NetworkID, networkDomainDigest,
		[]byte(body.SourceAccount), instances[0])
	if err != nil {
		return relaySponsorshipPaymentMaterial{}, err
	}
	canonical, fields, err := commerce.PaymentAuthorizationMaterial(payment)
	if err != nil {
		return relaySponsorshipPaymentMaterial{}, err
	}
	action, err := commerce.BuildAuthorizedAction(processor.Engine.OwnerID, processor.Engine.AgentID, "payment.direct",
		fields, canonical, processor.WriterFence, processor.PolicyRevision, processor.Engine.MandateDigest, "", "pending",
		minUint64(payment.ExpiresAtUnix, processor.WriterFence.Body.ExpiresAtUnix))
	if err != nil || action.StableActionID != payment.StableActionID {
		return relaySponsorshipPaymentMaterial{}, errors.New("gas sponsorship payment identity mismatch")
	}
	return relaySponsorshipPaymentMaterial{payment: payment, fields: fields,
		canonical: append([]byte(nil), canonical...), action: action}, nil
}

func (processor *AgreementSponsorshipProcessor) recoveryNetworkMatches(execution agentrelay.RelayExecutionRequest,
	snapshot *RelaySponsorshipEvidenceSnapshot) bool {
	if processor == nil {
		return false
	}
	if snapshot == nil {
		return execution.QuoteRequest.Body.Network == processor.NetworkDomain
	}
	if sink, ok := processor.Sink.(*TOSCTLPaymentSink); ok {
		frozen, err := sink.relaySponsorshipSnapshotNetwork(*snapshot)
		return err == nil && frozen == execution.QuoteRequest.Body.Network
	}
	// A non-tosctl frozen resolver has no released network locator in this V1
	// snapshot. Keep its existing owner-pinned network requirement rather than
	// silently treating an opaque profile digest as a wildcard.
	return execution.QuoteRequest.Body.Network == processor.NetworkDomain
}

func verifyRelaySponsorshipRecoveryHandle(recovery agentrelay.SponsorshipRecoveryHandle,
	execution agentrelay.RelayExecutionRequest,
	material relaySponsorshipPaymentMaterial) error {
	token, err := decodeRelaySponsorshipRecoveryHandle(recovery, execution)
	if err != nil {
		return err
	}
	paymentDigest, err := commerce.AgreementPaymentRequestDigest(material.payment)
	if err != nil || recovery.AgreementPaymentRequestDigest != paymentDigest ||
		recovery.StableActionID != material.action.StableActionID ||
		recovery.ExactRequestDigest != material.action.ExactRequestDigest ||
		recovery.ValidUntilUnix != material.payment.ExpiresAtUnix ||
		!reflect.DeepEqual(token.Payment, material.payment) ||
		token.PaymentActionStableID != material.action.StableActionID ||
		token.PaymentActionExactRequestDigest != material.action.ExactRequestDigest {
		return errors.New("relay sponsorship recovery token changes the exact payment identity")
	}
	return nil
}

func decodeRelaySponsorshipRecoveryHandle(recovery agentrelay.SponsorshipRecoveryHandle,
	execution agentrelay.RelayExecutionRequest) (relaySponsorshipRecoveryToken, error) {
	encoded := recovery.OpaqueToken
	if len(encoded) == 0 || len(encoded) > agentrelay.MaxSignedTransactionBytes {
		return relaySponsorshipRecoveryToken{}, errors.New("relay sponsorship recovery token is not bounded")
	}
	var token relaySponsorshipRecoveryToken
	if err := codec.Unmarshal(encoded, &token); err != nil || token.Schema != relaySponsorshipRecoverySchema {
		return relaySponsorshipRecoveryToken{}, errors.New("relay sponsorship recovery token is not canonical")
	}
	executionDigest, err := agentrelay.RelayExecutionRequestDigest(execution)
	if err != nil || token.RelayExecutionDigest != executionDigest {
		return relaySponsorshipRecoveryToken{}, errors.New("relay sponsorship recovery token belongs to another execution")
	}
	body, payment := execution.QuoteRequest.Body, token.Payment
	selected := body.SelectedSponsorshipReleaseProfile()
	if selected.EvidenceClass == agentrelay.SponsorshipReleaseObservedUnproven {
		snapshot := token.EvidenceSnapshot
		if snapshot == nil || (snapshot.SchemaVersion != 1 && snapshot.SchemaVersion != 2) ||
			snapshot.EvidenceClass != string(selected.EvidenceClass) || snapshot.ProfileURI != selected.ProfileURI ||
			snapshot.ProfileDigest != selected.ProfileDigest || snapshot.MaximumTransactions == 0 ||
			snapshot.MaximumTransactions > 10_000 || !filepath.IsAbs(snapshot.SnapshotPath) ||
			!validSHA256Digest(snapshot.SnapshotIdentity) {
			return relaySponsorshipRecoveryToken{}, errors.New("relay sponsorship recovery token has no exact frozen corroboration snapshot")
		}
		if snapshot.SchemaVersion == 2 && (!filepath.IsAbs(snapshot.RegistryRoot) ||
			filepath.Clean(snapshot.RegistryRoot) != snapshot.RegistryRoot ||
			!validFrozenRelayCustodyLocator(snapshot.CustodyWallet) ||
			!validFrozenRelayCustodyLocator(snapshot.ProviderSourceAccount) || snapshot.FeeReserveNanoTOS == 0) {
			return relaySponsorshipRecoveryToken{}, errors.New("relay sponsorship recovery token has invalid frozen custody locators")
		}
	} else if token.EvidenceSnapshot != nil {
		return relaySponsorshipRecoveryToken{}, errors.New("finalized sponsorship recovery token carries an RPC corroboration snapshot")
	}
	canonical, _, err := commerce.PaymentAuthorizationMaterial(payment)
	exactDigest, digestErr := commerce.ExactRequestDigest(canonical)
	paymentDigest, paymentDigestErr := commerce.AgreementPaymentRequestDigest(payment)
	if err != nil || digestErr != nil || paymentDigestErr != nil || body.Mode == agentrelay.ModeRelayExact ||
		body.RequestedSponsorship == nil || execution.ProviderQuote.Body.ReservedSponsorship == nil ||
		payment.StableActionID != token.PaymentActionStableID || exactDigest != token.PaymentActionExactRequestDigest ||
		recovery.AgreementPaymentRequestDigest != paymentDigest ||
		recovery.StableActionID != token.PaymentActionStableID || recovery.ExactRequestDigest != token.PaymentActionExactRequestDigest ||
		recovery.ValidUntilUnix != payment.ExpiresAtUnix ||
		payment.AgreementBodyDigest != execution.AgreementBodyDigest ||
		payment.AgreementObligationID != execution.SponsorshipObligationID ||
		payment.PayerAgentID != body.ProviderAgentID || payment.PayeeAgentID != body.RequesterAgentID ||
		payment.NetworkID != body.Network.NetworkID || !bytes.Equal(payment.Destination, []byte(body.SourceAccount)) ||
		payment.ExpiresAtUnix == 0 || payment.ExpiresAtUnix > execution.ExpiresAtUnix ||
		!sameRelayAgreementAssetAmount(payment.Amount, *body.RequestedSponsorship) {
		return relaySponsorshipRecoveryToken{}, errors.New("relay sponsorship recovery token changes the frozen payment")
	}
	return token, nil
}

func validFrozenRelayCustodyLocator(value string) bool {
	if value == "" || len(value) > 256 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, char := range value {
		if unicode.IsControl(char) {
			return false
		}
	}
	return true
}

func (processor *AgreementSponsorshipProcessor) acceptEvidence(ctx context.Context,
	execution agentrelay.RelayExecutionRequest, payment commerce.AgreementPaymentRequest,
	action commerce.AuthorizedAction, evidence commerce.AgreementPaymentEvidence,
	resolution commerce.ActionResolution) (agentrelay.SponsorshipResolution, error) {
	evidenceDigest, err := processor.verifyEvidence(ctx, execution, payment, evidence)
	if err != nil {
		return agentrelay.SponsorshipResolution{}, err
	}
	if resolution.State != commerce.ActionAccepted && resolution.State != commerce.ActionTerminal {
		if _, err := processor.Engine.Authority.Transition(action.StableActionID, action.ExactRequestDigest,
			commerce.ActionAccepted, evidence.ExactTransferReference, []string{evidenceDigest}); err != nil {
			return agentrelay.SponsorshipResolution{}, err
		}
	}
	return agentrelay.SponsorshipResolution{Status: agentrelay.SponsorshipResolutionFinalized,
		TransferReference: evidence.ExactTransferReference, EvidenceRefs: []string{evidenceDigest}}, nil
}

func (processor *AgreementSponsorshipProcessor) verifyEvidence(ctx context.Context,
	execution agentrelay.RelayExecutionRequest, payment commerce.AgreementPaymentRequest,
	evidence commerce.AgreementPaymentEvidence) (string, error) {
	now := processor.now()
	if commerce.VerifyAgreementPaymentEvidence(payment, evidence, processor.Verifier, now) != nil ||
		evidence.ResolvedState != "finalized" || evidence.ExactTransferReference == "" ||
		processor.FinalityVerifier.VerifyRelaySponsorshipFinality(ctx, execution, payment, evidence) != nil {
		return "", errors.New("gas sponsorship lacks independently verified payment finality")
	}
	evidenceDigest, err := codec.Digest("tos.agreement-payment-evidence.v1", evidence)
	if err != nil {
		return "", err
	}
	return evidenceDigest, nil
}

func (processor *AgreementSponsorshipProcessor) validate(ctx context.Context) error {
	if err := processor.validateRecovery(ctx); err != nil || processor.Engine.Authority == nil || processor.PolicyRevision == 0 ||
		!processor.Engine.permits("payment", processor.Engine.Gates.DirectPayment, false) {
		return errors.New("Agreement gas sponsorship payment is disabled or incomplete")
	}
	return processor.Engine.Authority.ConfirmCurrentWriterFence(processor.WriterFence, processor.now())
}

func (processor *AgreementSponsorshipProcessor) validateRecovery(ctx context.Context) error {
	if ctx == nil || processor == nil || processor.Engine == nil || processor.Sink == nil ||
		(processor.EvidenceResolver == nil && (processor.Verifier == nil || processor.FinalityVerifier == nil)) ||
		processor.NetworkDomain.NetworkID == "" ||
		processor.NativeAsset.AssetNamespace == "" || processor.NativeAsset.AssetIdentifier == "" || processor.NativeAsset.Unit == "" {
		return errors.New("Agreement gas sponsorship recovery is incomplete")
	}
	if _, err := agentrelay.NetworkDomainDigest(processor.NetworkDomain); err != nil {
		return errors.New("Agreement gas sponsorship network domain is invalid")
	}
	return nil
}

func (processor *AgreementSponsorshipProcessor) validateEvidencePathForExecution(
	execution agentrelay.RelayExecutionRequest,
	snapshot *RelaySponsorshipEvidenceSnapshot) error {
	if processor == nil || processor.EvidenceResolver == nil {
		if processor != nil && processor.Verifier != nil && processor.FinalityVerifier != nil {
			return nil
		}
		return errors.New("Agreement gas sponsorship has no evidence path")
	}
	capabilities := processor.EvidenceResolver.RelaySponsorshipEvidenceCapabilities()
	policy := relaySponsorshipReleasePolicyFromRequest(execution.QuoteRequest.Body)
	supported := supportsRelaySponsorshipReleasePolicy(capabilities.SupportedReleasePolicies, policy)
	frozenSnapshot := false
	if snapshot != nil {
		if frozen, ok := processor.EvidenceResolver.(RelaySponsorshipFrozenEvidenceResolver); ok &&
			frozen.ValidateRelaySponsorshipEvidenceSnapshot(execution.QuoteRequest.Body.SelectedSponsorshipReleaseProfile(),
				*snapshot) == nil {
			supported, frozenSnapshot = true, true
		}
	}
	if !validRelaySponsorshipReleasePolicy(execution.QuoteRequest.Body.AssuranceLevel, policy) || !supported {
		return errors.New("gas sponsorship evidence path does not support the signed release profile")
	}
	terminalProfile, profileErr := relaySponsorshipTerminalProfile(execution)
	profileCapability, profileOK := processor.EvidenceResolver.(RelaySponsorshipTerminalProfileCapability)
	if profileErr != nil || !profileOK ||
		!profileCapability.SupportsRelaySponsorshipTerminalFinalityProfile(terminalProfile, snapshot) {
		return errors.New("gas sponsorship evidence path does not support the signed terminal profile")
	}
	capability, capabilityErr := relayEvidenceCapabilityForExecution(execution)
	absenceCapability, absenceOK := processor.AbsenceResolver.(RelaySponsorshipAbsenceCapability)
	_, dualAggregatorOK := processor.AbsenceResolver.(RelaySponsorshipDualAbsenceAggregator)
	if capabilityErr != nil || !absenceOK ||
		!absenceCapability.SupportsRelaySponsorshipComponentAbsenceEvidence(capability, snapshot) ||
		execution.QuoteRequest.Body.Mode == agentrelay.ModeSponsorAndRelay &&
			(!absenceCapability.SupportsRelayDualAbsenceEvidence(capability, snapshot) || !dualAggregatorOK) {
		return errors.New("gas sponsorship evidence path lacks an exact component absence resolver")
	}
	switch policy.EvidenceClass {
	case agentrelay.SponsorshipReleaseObservedUnproven:
		_, terminalResolver := processor.EvidenceResolver.(RelaySponsorshipTerminalEvidenceResolver)
		// Current capability state gates only a new Quote. Recovery with a
		// validated immutable snapshot remains eligible after owner config
		// rotation; the exact terminal-profile check above is snapshot-bound.
		terminalEvidence := (capabilities.TerminalEvidence || frozenSnapshot) && terminalResolver &&
			processor.TransactionEvidenceVerifier != nil
		if (capabilities.FreshBalanceSequenceRecheck || frozenSnapshot) && terminalEvidence {
			if _, ok := processor.EvidenceResolver.(RelaySponsorshipCreditObservationVerifier); ok {
				return nil
			}
		}
		return errors.New("unproven sponsorship release lacks observation verification, fresh recheck, or eventual finality")
	case agentrelay.SponsorshipReleaseValidatorFinality:
		if processor.TransactionEvidenceVerifier == nil {
			return errors.New("finalized sponsorship release lacks an independent transaction verifier")
		}
		if execution.QuoteRequest.Body.AssuranceLevel == agentrelay.AssuranceAutonomousDecentralized {
			portable, ok := processor.TransactionEvidenceVerifier.(agentrelay.PortableSponsorshipTransactionEvidenceVerifier)
			if !capabilities.PortableFinalityEvidence || !ok || !portable.HasIndependentPortableSponsorshipProofs() {
				return errors.New("autonomous gas sponsorship requires portable finalized transaction evidence")
			}
		}
		return nil
	default:
		return errors.New("gas sponsorship release profile is unknown")
	}
}

func (processor *AgreementSponsorshipProcessor) SupportsRelaySponsorshipTerminalFinalityProfile(
	profile agentrelay.FinalityProfile) bool {
	if processor == nil || processor.EvidenceResolver == nil || processor.TransactionEvidenceVerifier == nil {
		return false
	}
	capability, ok := processor.EvidenceResolver.(RelaySponsorshipTerminalProfileCapability)
	return ok && capability.SupportsRelaySponsorshipTerminalFinalityProfile(profile, nil)
}

func (processor *AgreementSponsorshipProcessor) validateTypedSponsorshipResolution(ctx context.Context,
	execution agentrelay.RelayExecutionRequest, payment commerce.AgreementPaymentRequest,
	snapshot *RelaySponsorshipEvidenceSnapshot, resolution agentrelay.SponsorshipResolution) error {
	noTerminalData := func() bool {
		return resolution.TransferReference == "" && len(resolution.EvidenceRefs) == 0 &&
			resolution.AbsenceOutcome == "" && len(resolution.SponsorshipAbsenceObservations) == 0 &&
			len(resolution.TransactionAbsenceObservations) == 0
	}
	switch resolution.Status {
	case agentrelay.SponsorshipResolutionUnknown:
		if !noTerminalData() || resolution.CreditObservation != nil || resolution.TransactionEvidence != nil {
			return errors.New("unknown gas sponsorship resolution carries economic evidence")
		}
		return nil
	case agentrelay.SponsorshipResolutionObservedUnproven:
		selected := relaySponsorshipReleasePolicyFromRequest(execution.QuoteRequest.Body)
		if selected.EvidenceClass != agentrelay.SponsorshipReleaseObservedUnproven ||
			!noTerminalData() || resolution.CreditObservation == nil || resolution.TransactionEvidence != nil {
			return errors.New("unproven gas sponsorship observation is not permitted for this assurance")
		}
		observation := *resolution.CreditObservation
		if _, err := agentrelay.RelaySponsorshipCreditObservationDigest(observation); err != nil ||
			observation.EvidenceProfileURI != selected.ProfileURI ||
			observation.EvidenceProfileDigest != selected.ProfileDigest {
			return errors.New("unproven gas sponsorship observation is invalid")
		}
		var verifyErr error
		if snapshot != nil {
			verifier, ok := processor.EvidenceResolver.(RelaySponsorshipFrozenCreditObservationVerifier)
			if !ok {
				verifyErr = errors.New("frozen observation verifier is unavailable")
			} else {
				verifyErr = verifier.VerifyRelaySponsorshipCreditObservationFromSnapshot(ctx,
					observation, execution, payment, *snapshot)
			}
		} else if verifier, ok := processor.EvidenceResolver.(RelaySponsorshipCreditObservationVerifier); !ok {
			verifyErr = errors.New("observation verifier is unavailable")
		} else {
			verifyErr = verifier.VerifyRelaySponsorshipCreditObservation(ctx, observation, execution, payment)
		}
		if verifyErr != nil {
			return errors.New("unproven gas sponsorship observation failed its owner-pinned verifier")
		}
		projected := agentrelay.RelaySponsorshipTransactionEvidence{
			AgreementPaymentRequestDigest: observation.AgreementPaymentRequestDigest,
			SponsorshipStableActionID:     observation.SponsorshipStableActionID,
			SponsorshipExactRequestDigest: observation.SponsorshipExactRequestDigest,
			ProviderSponsorValidUntilUnix: observation.ProviderSponsorValidUntilUnix,
		}
		return validateRelaySponsorshipPaymentBinding(execution, payment, projected)
	case agentrelay.SponsorshipResolutionCorroboratedTerminal, agentrelay.SponsorshipResolutionFinalized:
		if resolution.CreditObservation != nil || resolution.TransactionEvidence == nil ||
			resolution.TransferReference == "" || len(resolution.EvidenceRefs) == 0 ||
			resolution.AbsenceOutcome != "" || len(resolution.SponsorshipAbsenceObservations) != 0 ||
			len(resolution.TransactionAbsenceObservations) != 0 {
			return errors.New("finalized gas sponsorship transaction evidence is incomplete")
		}
		evidence := *resolution.TransactionEvidence
		if _, err := agentrelay.RelaySponsorshipTransactionEvidenceDigest(evidence); err != nil ||
			evidence.SubmittedTransactionHash != resolution.TransferReference ||
			!reflect.DeepEqual(evidence.ObservationDigests, resolution.EvidenceRefs) {
			return errors.New("finalized gas sponsorship transaction evidence is invalid")
		}
		if execution.QuoteRequest.Body.AssuranceLevel == agentrelay.AssuranceAutonomousDecentralized &&
			evidence.PortableProofLocator == "" {
			return errors.New("autonomous gas sponsorship evidence is not portable")
		}
		if resolution.Status == agentrelay.SponsorshipResolutionCorroboratedTerminal {
			if execution.QuoteRequest.Body.AssuranceLevel == agentrelay.AssuranceAutonomousDecentralized ||
				evidence.TerminalEvidenceClass != agentrelay.SponsorshipTerminalClientCorroborated ||
				evidence.ValidatorAuthenticatedPortableProof {
				return errors.New("client-corroborated sponsorship evidence is not permitted for this assurance")
			}
		} else if evidence.TerminalEvidenceClass != agentrelay.SponsorshipTerminalValidatorFinality ||
			!evidence.ValidatorAuthenticatedPortableProof {
			return errors.New("finalized sponsorship lacks validator-authenticated portable proof")
		}
		if err := validateRelaySponsorshipPaymentBinding(execution, payment, evidence); err != nil {
			return err
		}
		expected, err := relaySponsorshipEvidenceContext(execution, evidence)
		terminalProfile, profileErr := relaySponsorshipTerminalProfile(execution)
		var verifyErr error
		if snapshot != nil {
			verifier, ok := processor.TransactionEvidenceVerifier.(RelaySponsorshipFrozenTransactionEvidenceVerifier)
			if !ok {
				verifyErr = errors.New("frozen transaction verifier is unavailable")
			} else {
				verifyErr = verifier.VerifyRelaySponsorshipTransactionEvidenceFromSnapshot(ctx, evidence, expected,
					terminalProfile, *snapshot)
			}
		} else if processor.TransactionEvidenceVerifier == nil {
			verifyErr = errors.New("transaction verifier is unavailable")
		} else {
			verifyErr = processor.TransactionEvidenceVerifier.VerifySponsorshipTransactionEvidence(ctx,
				evidence, expected, terminalProfile)
		}
		if err != nil || profileErr != nil || verifyErr != nil {
			return errors.New("gas sponsorship transaction proof failed independent verification")
		}
		if execution.QuoteRequest.Body.AssuranceLevel == agentrelay.AssuranceAutonomousDecentralized {
			portable, ok := processor.TransactionEvidenceVerifier.(agentrelay.PortableSponsorshipTransactionEvidenceVerifier)
			if !ok || !portable.HasIndependentPortableSponsorshipProofs() {
				return errors.New("autonomous gas sponsorship verifier has no independent portable proofs")
			}
		}
		return nil
	case agentrelay.SponsorshipResolutionCorroboratedAbsent,
		agentrelay.SponsorshipResolutionFinalizedAbsent:
		if resolution.TransferReference != "" || len(resolution.EvidenceRefs) != 0 ||
			resolution.CreditObservation != nil || resolution.TransactionEvidence != nil ||
			resolution.AbsenceOutcome == "" || len(resolution.SponsorshipAbsenceObservations) == 0 ||
			len(resolution.TransactionAbsenceObservations) == 0 {
			return errors.New("finalized gas sponsorship absence proof is incomplete")
		}
		corroborated := resolution.AbsenceOutcome == agentrelay.OutcomeCorroboratedExpired ||
			resolution.AbsenceOutcome == agentrelay.OutcomeCorroboratedAbsent ||
			resolution.AbsenceOutcome == agentrelay.OutcomeCorroboratedInvalidated
		if resolution.Status == agentrelay.SponsorshipResolutionCorroboratedAbsent && !corroborated ||
			resolution.Status == agentrelay.SponsorshipResolutionFinalizedAbsent && corroborated {
			return errors.New("gas sponsorship absence status conflicts with its evidence class")
		}
		return nil
	default:
		return errors.New("typed gas sponsorship resolution status is unknown")
	}
}

func relaySponsorshipTerminalProfile(execution agentrelay.RelayExecutionRequest) (agentrelay.FinalityProfile, error) {
	if execution.ProviderQuote.Body.SponsorshipTerminalProfile == nil {
		return agentrelay.FinalityProfile{}, errors.New("relay sponsorship terminal profile is missing")
	}
	return *execution.ProviderQuote.Body.SponsorshipTerminalProfile, nil
}

func relaySponsorshipResolutionHasTransfer(status agentrelay.SponsorshipResolutionStatus) bool {
	return status == agentrelay.SponsorshipResolutionCorroboratedTerminal ||
		status == agentrelay.SponsorshipResolutionFinalized
}

func validateRelaySponsorshipPaymentBinding(execution agentrelay.RelayExecutionRequest,
	payment commerce.AgreementPaymentRequest, evidence agentrelay.RelaySponsorshipTransactionEvidence) error {
	expected, err := relaySponsorshipEvidenceContext(execution, evidence)
	if err != nil {
		return err
	}
	if err := agentrelay.VerifySponsorshipPaymentRequestForEvidence(payment, evidence, expected); err != nil {
		return errors.New("gas sponsorship evidence does not bind the exact payment: " + err.Error())
	}
	return nil
}

func relaySponsorshipEvidenceContext(execution agentrelay.RelayExecutionRequest,
	evidence agentrelay.RelaySponsorshipTransactionEvidence) (agentrelay.RelaySponsorshipEvidenceContext, error) {
	networkDigest, err := agentrelay.NetworkDomainDigest(execution.QuoteRequest.Body.Network)
	reserved := execution.ProviderQuote.Body.ReservedSponsorship
	if err != nil || reserved == nil {
		return agentrelay.RelaySponsorshipEvidenceContext{}, errors.New("gas sponsorship execution context is incomplete")
	}
	return agentrelay.RelaySponsorshipEvidenceContext{
		AgreementBodyDigest: execution.AgreementBodyDigest, AgreementObligationID: execution.SponsorshipObligationID,
		PayerAgentID: execution.QuoteRequest.Body.ProviderAgentID, PayeeAgentID: execution.QuoteRequest.Body.RequesterAgentID,
		NetworkID: execution.QuoteRequest.Body.Network.NetworkID, NetworkDomainDigest: networkDigest,
		DestinationSourceAccount: execution.QuoteRequest.Body.SourceAccount, Amount: *reserved,
		MaximumExpiresAtUnix: execution.ExpiresAtUnix, SponsorshipStableActionID: evidence.SponsorshipStableActionID,
		SponsorshipExactRequestDigest: evidence.SponsorshipExactRequestDigest,
	}, nil
}

func (processor *AgreementSponsorshipProcessor) RelaySponsorshipEvidenceCapabilities() RelaySponsorshipEvidenceCapabilities {
	// Capability advertisement is an execution-readiness claim for this
	// concrete processor, not merely a statement that one resolver object is
	// non-nil. The owner gate, current writer fence, custody sink, network and
	// payment authority must all be usable now.
	if processor == nil || processor.EvidenceResolver == nil || processor.validate(context.Background()) != nil {
		return RelaySponsorshipEvidenceCapabilities{}
	}
	capabilities := processor.EvidenceResolver.RelaySponsorshipEvidenceCapabilities()
	_, terminalResolver := processor.EvidenceResolver.(RelaySponsorshipTerminalEvidenceResolver)
	terminalEvidence := capabilities.TerminalEvidence && terminalResolver &&
		processor.TransactionEvidenceVerifier != nil
	filtered := make([]RelaySponsorshipReleasePolicy, 0, len(capabilities.SupportedReleasePolicies))
	_, observationVerifier := processor.EvidenceResolver.(RelaySponsorshipCreditObservationVerifier)
	for _, policy := range capabilities.SupportedReleasePolicies {
		switch policy.EvidenceClass {
		case agentrelay.SponsorshipReleaseObservedUnproven:
			if observationVerifier && capabilities.FreshBalanceSequenceRecheck && terminalEvidence {
				filtered = append(filtered, policy)
			}
		case agentrelay.SponsorshipReleaseValidatorFinality:
			if processor.TransactionEvidenceVerifier != nil && capabilities.TerminalEvidence {
				filtered = append(filtered, policy)
			}
		}
	}
	capabilities.SupportedReleasePolicies = filtered
	capabilities.TerminalEvidence = terminalEvidence
	portable, ok := processor.TransactionEvidenceVerifier.(agentrelay.PortableSponsorshipTransactionEvidenceVerifier)
	capabilities.PortableFinalityEvidence = capabilities.PortableFinalityEvidence && ok &&
		portable.HasIndependentPortableSponsorshipProofs()
	return capabilities
}

// SupportsRelaySponsorshipComponentAbsenceEvidence is deliberately exact and
// delegates to the query-only producer for the top-up-absent component.
func (processor *AgreementSponsorshipProcessor) SupportsRelaySponsorshipComponentAbsenceEvidence(
	capability agentrelay.RelayEvidenceCapability) bool {
	if processor == nil || processor.AbsenceResolver == nil {
		return false
	}
	qualified, ok := processor.AbsenceResolver.(RelaySponsorshipAbsenceCapability)
	return ok && qualified.SupportsRelaySponsorshipComponentAbsenceEvidence(capability, nil)
}

// SupportsRelayDualAbsenceEvidence covers the whole-negative combined path.
// It is separate from component support because each can fail independently.
func (processor *AgreementSponsorshipProcessor) SupportsRelayDualAbsenceEvidence(
	capability agentrelay.RelayEvidenceCapability) bool {
	if processor == nil || processor.AbsenceResolver == nil {
		return false
	}
	qualified, ok := processor.AbsenceResolver.(RelaySponsorshipAbsenceCapability)
	_, aggregatorOK := processor.AbsenceResolver.(RelaySponsorshipDualAbsenceAggregator)
	return ok && aggregatorOK && qualified.SupportsRelayDualAbsenceEvidence(capability, nil)
}

func (processor *AgreementSponsorshipProcessor) SupportsRelayTransactionComponentAbsenceEvidence(
	capability agentrelay.RelayEvidenceCapability) bool {
	if processor == nil || processor.AbsenceResolver == nil || capability.Mode != agentrelay.ModeSponsorAndRelay {
		return false
	}
	resolver, ok := processor.AbsenceResolver.(RelaySponsorshipTransactionAbsenceResolver)
	return ok && resolver.SupportsRelayTransactionComponentAbsenceEvidence(capability, nil)
}

func (processor *AgreementSponsorshipProcessor) now() time.Time {
	if processor.Now != nil {
		return processor.Now().UTC()
	}
	if processor.Engine != nil {
		return processor.Engine.now()
	}
	return time.Now().UTC()
}

func sameRelaySponsorshipAmount(left, right agentrelay.AssetAmount) bool {
	return left.Asset == right.Asset && left.AmountAtomic == right.AmountAtomic
}

func sameRelayAgreementAssetAmount(left commerce.AgreementAmount, right agentrelay.AssetAmount) bool {
	return left.AssetNamespace == right.Asset.AssetNamespace && left.AssetIdentifier == right.Asset.AssetIdentifier &&
		left.Unit == right.Asset.Unit && left.AmountAtomic == right.AmountAtomic && left.AmountDecimal == ""
}

func relaySponsorshipExpiry(values ...uint64) uint64 {
	result := uint64(0)
	for _, value := range values {
		if value != 0 && (result == 0 || value < result) {
			result = value
		}
	}
	return result
}

var _ agentrelay.SponsorshipProcessor = (*AgreementSponsorshipProcessor)(nil)
