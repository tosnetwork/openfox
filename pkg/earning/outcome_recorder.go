package earning

import (
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"sort"
	"sync"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type ActionOutcomeRecorder interface {
	RecordActionResolution(commerce.AuthorizedAction, commerce.ActionResolution, time.Time) error
}

// ManagedOutcomeRecorder follows Writer Fence generations and keeps the
// append-only journal usable across lease renewal or host takeover. It never
// publishes; public/private propagation remains a separate AuthorizedAction.
type ManagedOutcomeRecorder struct {
	mu                 sync.Mutex
	Directory          string
	OwnerID            string
	AgentID            string
	AuthorityID        string
	Purpose            string
	CohortScopeDigest  string
	NetworkID          string
	AudienceDescriptor string
	OperationAuthority commerce.PinnedAgentOperationAuthorityRecordV1
	OperationKey       ed25519.PrivateKey
	FenceSource        WriterFenceProvider
	FenceResolver      interface {
		commerce.FenceAuthorityResolver
		commerce.CurrentWriterFenceResolver
	}
	AppendAuthority EconomicAuthority
	journal         *OutcomeJournal
}

func (recorder *ManagedOutcomeRecorder) Close() error {
	if recorder == nil {
		return nil
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if recorder.journal == nil {
		return nil
	}
	err := recorder.journal.Close()
	recorder.journal = nil
	return err
}

func (recorder *ManagedOutcomeRecorder) RecordActionResolution(action commerce.AuthorizedAction,
	resolution commerce.ActionResolution, observedAt time.Time) error {
	if recorder == nil || recorder.FenceSource == nil || recorder.FenceResolver == nil || observedAt.IsZero() {
		return errors.New("managed outcome recorder is incomplete")
	}
	if len(recorder.OperationKey) != ed25519.PrivateKeySize || len(recorder.OperationAuthority.Key) != ed25519.PublicKeySize ||
		!recorder.OperationAuthority.Key.Equal(recorder.OperationKey.Public().(ed25519.PublicKey)) {
		return errors.New("managed outcome recorder operation authority is invalid")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	fence, err := recorder.FenceSource(ctx)
	if err != nil {
		return err
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if recorder.journal == nil || recorder.journal.Head().WriterGeneration != fence.Body.WriterGeneration {
		if recorder.journal != nil {
			if err := recorder.journal.Close(); err != nil {
				return err
			}
		}
		journal, err := OpenOutcomeJournal(filepath.Clean(recorder.Directory), recorder.OwnerID, recorder.AgentID,
			recorder.AuthorityID, recorder.Purpose, recorder.CohortScopeDigest, fence, recorder.FenceResolver, observedAt.UTC())
		if err != nil {
			return err
		}
		recorder.journal = journal
	}
	delegate := JournalOutcomeRecorder{Journal: recorder.journal, NetworkID: recorder.NetworkID,
		AudienceDescriptor: recorder.AudienceDescriptor, AuthorizationRef: recorder.OperationAuthority.Profile,
		OperationKey: recorder.OperationKey, HistoricalProof: recorder.OperationAuthority.Proof,
		Fence: fence, FenceResolver: recorder.FenceResolver, AppendAuthority: recorder.AppendAuthority}
	return delegate.RecordActionResolution(action, resolution, observedAt.UTC())
}

type JournalOutcomeRecorder struct {
	Journal            *OutcomeJournal
	NetworkID          string
	AudienceDescriptor string
	AuthorizationRef   commerce.ProfileRefV1
	OperationKey       ed25519.PrivateKey
	HistoricalProof    []byte
	Fence              commerce.WriterFence
	FenceResolver      commerce.CurrentWriterFenceResolver
	AppendAuthority    EconomicAuthority
}

type fixedOutcomeOperationResolver struct {
	agentID string
	key     ed25519.PublicKey
	profile commerce.ProfileRefV1
	proof   []byte
}

func (resolver fixedOutcomeOperationResolver) AuthorizeAgentOperationKey(agentID string, profile commerce.ProfileRefV1,
	key ed25519.PublicKey, _ time.Time, proof []byte) error {
	if agentID != resolver.agentID || profile != resolver.profile || !key.Equal(resolver.key) || string(proof) != string(resolver.proof) {
		return errors.New("outcome operation authority does not match the recorder")
	}
	return nil
}

func (recorder *JournalOutcomeRecorder) RecordActionResolution(action commerce.AuthorizedAction,
	resolution commerce.ActionResolution, observedAt time.Time) error {
	if recorder == nil || recorder.Journal == nil || len(recorder.OperationKey) != ed25519.PrivateKeySize ||
		recorder.NetworkID == "" || recorder.AudienceDescriptor == "" || commerce.ValidateProfileRefV1(recorder.AuthorizationRef) != nil ||
		len(recorder.HistoricalProof) == 0 || recorder.FenceResolver == nil || recorder.AppendAuthority == nil || observedAt.IsZero() {
		return errors.New("outcome recorder is incomplete")
	}
	if resolution.StableActionID != action.StableActionID || resolution.ExactRequestDigest != action.ExactRequestDigest ||
		resolution.State == commerce.ActionUnknown || commerce.ValidateActionResolution(resolution) != nil {
		return errors.New("outcome recorder received an unrelated Action resolution")
	}
	if record, found, err := recorder.Journal.ActionResolutionRecord(action.StableActionID, resolution.StateRevision); err != nil {
		return err
	} else if found {
		return recorder.finishAppendResolution(record)
	}
	actionDigest, err := commerce.AuthorizedActionDigest(action)
	if err != nil {
		return err
	}
	resolutionDigest, err := codec.Digest("tos.action-resolution.v1", resolution)
	if err != nil {
		return err
	}
	assertion := commerce.ActionResolutionReferencePayloadV1{StableActionID: action.StableActionID,
		ExactRequestDigest: action.ExactRequestDigest, AuthorizedActionDigest: actionDigest,
		ActionResolutionDigest: resolutionDigest, ResolutionState: resolution.State, ResolutionStateRevision: resolution.StateRevision}
	assertionPayload, err := codec.Marshal(assertion)
	if err != nil {
		return err
	}
	event, err := commerce.BuildOperationOutcomeEventV1(commerce.OutcomeObservation,
		commerce.OutcomeSubjectRefV1{SubjectProfileURI: "tos.subject.semantic-action.v1", SubjectID: action.StableActionID}, nil,
		commerce.OutcomeProfileActionResolutionReference, assertionPayload,
		commerce.EmptyOutcomeEvidenceManifestV1("unverified_reference"), commerce.EmptyOutcomeExtensionSetV1())
	if err != nil {
		return err
	}
	contentID, eventPayload, err := commerce.OperationOutcomeEventContentIDV1(event)
	if err != nil {
		return err
	}
	sequence, err := recorder.Journal.Reserve(recorder.Fence, recorder.FenceResolver, observedAt.UTC())
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = recorder.Journal.AbortReserved(sequence)
		}
	}()
	head := recorder.Journal.Head()
	predecessors := []string{}
	if head.LastEnvelopeDigest != "" {
		predecessors = append(predecessors, head.LastEnvelopeDigest)
		sort.Strings(predecessors)
	}
	// The signed assertion records the authenticated observation instant, not
	// the lease issuance instant. The append Action makes retries deterministic;
	// collapsing every observation in a lease onto one timestamp would destroy
	// useful ordering evidence.
	stableObservedAt := observedAt.UTC()
	body := commerce.AgentOperationBodyV1{SchemaVersion: 1, NetworkID: recorder.NetworkID, OpcodeNamespace: "OPERATION", OpcodeName: "OUTCOME", OpcodeVersion: 1,
		ActorAgentID: action.AgentID, AuthorizationRef: recorder.AuthorizationRef, AudienceDescriptor: recorder.AudienceDescriptor,
		ObjectID: contentID, OrderingDomain: head.OrderingDomain, Sequence: sequence, Epoch: head.WriterGeneration,
		PredecessorDigests: predecessors, CreatedAtUnix: uint64(stableObservedAt.Unix()), PayloadProfile: commerce.OperationOutcomeProfileRefV1(),
		PayloadDigest: contentID, PayloadSize: uint64(len(eventPayload))}
	body.OperationID, err = commerce.DeriveAgentOperationIDV1(body)
	if err != nil {
		return err
	}
	envelope, err := commerce.SignAgentOperationV1(body, action.AgentID, recorder.OperationKey, recorder.HistoricalProof)
	if err != nil {
		return err
	}
	resolver := fixedOutcomeOperationResolver{agentID: action.AgentID, key: recorder.OperationKey.Public().(ed25519.PublicKey), profile: recorder.AuthorizationRef, proof: recorder.HistoricalProof}
	artifacts := commerce.OperationOutcomeArtifactBundleV1{AssertionPayload: assertionPayload,
		EvidenceManifest: commerce.EmptyOutcomeEvidenceManifestV1("unverified_reference"),
		ExtensionSet:     commerce.EmptyOutcomeExtensionSetV1(), AuthorityProofs: []commerce.OutcomeAuthorityProofMaterialV1{}}
	envelopeDigest, err := commerce.AgentOperationEnvelopeDigestV1(envelope)
	if err != nil {
		return err
	}
	gapDigest, err := codec.Digest("tos.openfox.outcome-journal-gap-set.v1", head.GapSequences)
	if err != nil {
		return err
	}
	appendRequest := commerce.OperationJournalAppendAdmissionRequestV1{OrderingDomain: head.OrderingDomain, Epoch: head.WriterGeneration,
		Sequence: sequence, EventContentID: contentID, OperationEnvelopeDigest: envelopeDigest, GapSetDigest: gapDigest}
	appendCanonical, err := codec.Marshal(appendRequest)
	if err != nil {
		return err
	}
	appendFields, err := commerce.OperationJournalAppendSemanticFieldsV1(action.OwnerID, action.AgentID, head.OrderingDomain,
		head.WriterGeneration, sequence, contentID)
	if err != nil {
		return err
	}
	appendAction, err := commerce.BuildAuthorizedAction(action.OwnerID, action.AgentID, outcomeJournalScope, appendFields, appendCanonical,
		recorder.Fence, action.PolicyRevision, action.MandateDigest, action.ApprovalDigest, "journal-head", recorder.Fence.Body.ExpiresAtUnix)
	if err == nil {
		appendAction, err = recorder.AppendAuthority.SignAction(appendAction, recorder.Fence)
	}
	if err != nil {
		return err
	}
	appendResolution, err := recorder.AppendAuthority.Admit(appendAction, appendFields, appendCanonical, recorder.Fence, nil)
	if err != nil {
		return err
	}
	if appendResolution.State != commerce.ActionPrepared && appendResolution.State != commerce.ActionTerminal {
		return errors.New("outcome journal append was not admitted")
	}
	appendAdmission := &OutcomeJournalAppendAdmission{Request: appendRequest, Action: appendAction, Fence: recorder.Fence}
	source := &OutcomeJournalSourceResolution{Action: action, Resolution: resolution}
	if _, err := recorder.Journal.Commit(sequence, envelope, eventPayload, artifacts, resolver, observedAt.UTC(), appendAdmission, source); err != nil {
		commitErr := err
		if _, transitionErr := recorder.AppendAuthority.Transition(appendAction.StableActionID, appendAction.ExactRequestDigest,
			commerce.ActionRejected, "journal:commit-failed", []string{envelopeDigest}); transitionErr != nil {
			commitErr = errors.Join(commitErr, transitionErr)
		}
		return commitErr
	}
	committed = true
	if appendResolution.State != commerce.ActionTerminal {
		if _, err := recorder.AppendAuthority.Transition(appendAction.StableActionID, appendAction.ExactRequestDigest,
			commerce.ActionTerminal, envelopeDigest, []string{envelopeDigest}); err != nil {
			return err
		}
	}
	return nil
}

type authorizedActionResolver interface {
	ResolveAuthorizedAction(stableActionID, exactRequestDigest string) (commerce.AuthorizedAction, bool)
}

// finishAppendResolution closes the only ambiguous crash window: the signed
// Operation is durable, but the authority-side append action may still be in
// PREPARED because the terminal transition was interrupted. It never invents
// a replacement action; recovery requires the exact action retained by the
// authority journal.
func (recorder *JournalOutcomeRecorder) finishAppendResolution(record OutcomeJournalRecord) error {
	if record.JournalAppendRequestDigest == "" {
		return errors.New("outcome journal record is missing append admission evidence")
	}
	resolution := recorder.AppendAuthority.Resolve(record.JournalAppendActionID, record.JournalAppendRequestDigest)
	if resolution.State == commerce.ActionTerminal {
		return nil
	}
	if resolution.State != commerce.ActionPrepared {
		return errors.New("outcome journal append is not recoverable from its current state")
	}
	resolver, ok := recorder.AppendAuthority.(authorizedActionResolver)
	if !ok {
		return errors.New("outcome append authority cannot recover the exact admitted action")
	}
	action, found := resolver.ResolveAuthorizedAction(record.JournalAppendActionID, record.JournalAppendRequestDigest)
	if !found || action.StableActionID != record.JournalAppendActionID || action.ExactRequestDigest != record.JournalAppendRequestDigest {
		return errors.New("outcome append authority recovered an unrelated action")
	}
	_, err := recorder.AppendAuthority.Transition(action.StableActionID, action.ExactRequestDigest,
		commerce.ActionTerminal, record.OperationEnvelopeDigest, []string{record.OperationEnvelopeDigest})
	return err
}
