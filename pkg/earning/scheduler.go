package earning

import (
	"context"
	"crypto/ed25519"
	"errors"
	"reflect"
	"sort"
	"time"

	"github.com/tosnetwork/tos-ai/pkg/commercegate"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type ScheduleTransitionRequest struct {
	ScheduleEntryID          string                            `json:"schedule_entry_id"`
	ExpectedStateRevision    uint64                            `json:"expected_state_revision"`
	TargetState              commerce.EngagementScheduleState  `json:"target_state"`
	TargetDispatchGeneration uint64                            `json:"target_dispatch_generation"`
	InitialEntry             *commerce.EngagementScheduleEntry `json:"initial_entry,omitempty"`
	Dependencies             []commerce.PortfolioDependency    `json:"dependencies,omitempty"`
}

type DependencyTransitionRequest struct {
	Dependency        commerce.PortfolioDependency `json:"dependency"`
	TransitionKind    string                       `json:"transition_kind"`
	GraphBaseRevision uint64                       `json:"graph_base_revision"`
	EvidenceRefs      []string                     `json:"evidence_refs,omitempty"`
}

type SchedulerService struct {
	Authority      EconomicAuthority
	OwnerID        string
	AgentID        string
	MandateDigest  string
	PolicyRevision uint64
}

// EnsureExecution creates the unique durable queue entry for a Gate-derived
// execution ID. It does not dispatch or execute the entry.
func (service SchedulerService) EnsureExecution(ctx context.Context, plan commercegate.Plan, deadline time.Time,
	fence commerce.WriterFence) (commerce.EngagementScheduleEntry, bool, error) {
	if service.Authority == nil || service.OwnerID == "" || service.AgentID == "" || service.PolicyRevision == 0 || ctx == nil || ctx.Err() != nil {
		return commerce.EngagementScheduleEntry{}, false, errors.New("scheduler service is incomplete")
	}
	prepared, _, _, err := commercegate.PrepareAuthorizationMaterial(plan, fence)
	if err != nil {
		return commerce.EngagementScheduleEntry{}, false, err
	}
	identifier, err := codec.Digest("tos.engagement-schedule-entry.v1", struct {
		Agent, Agreement, Execution string
	}{service.AgentID, prepared.AgreementBodyDigest, prepared.ExecutionID})
	if err != nil {
		return commerce.EngagementScheduleEntry{}, false, err
	}
	for _, entry := range service.entries() {
		if entry.ScheduleEntryID == identifier {
			return entry, false, nil
		}
	}
	entry := commerce.EngagementScheduleEntry{SchemaVersion: 2, ScheduleEntryID: identifier,
		AgreementBodyDigest: prepared.AgreementBodyDigest, ExecutionObligationID: plan.ExecutionObligationID,
		ExecutionID: prepared.ExecutionID, State: commerce.ScheduleQueued,
		StateRevision: 1, DispatchGeneration: 1, DeadlineUnix: uint64(deadline.UTC().Unix()), ComputeUnits: 1,
		ConcurrencyUnits: 1, CancelClass: "before-start", PreemptClass: "drain", IrreversibleBoundary: "execution-start",
		WriterGeneration: fence.Body.WriterGeneration}
	updated, err := service.mutate(ctx, commerce.EngagementScheduleEntry{}, entry, &entry, fence)
	return updated, err == nil, err
}

func (service SchedulerService) Transition(ctx context.Context, current commerce.EngagementScheduleEntry,
	target commerce.EngagementScheduleState, fence commerce.WriterFence) (commerce.EngagementScheduleEntry, error) {
	if service.Authority == nil || current.ScheduleEntryID == "" {
		return commerce.EngagementScheduleEntry{}, errors.New("schedule transition is incomplete")
	}
	dispatch := current.DispatchGeneration
	if target == commerce.ScheduleDispatched {
		dispatch++
	}
	updated, err := commerce.TransitionScheduleEntry(current, target, dispatch, fence.Body.WriterGeneration)
	if err != nil {
		return commerce.EngagementScheduleEntry{}, err
	}
	return service.mutate(ctx, current, updated, nil, fence)
}

func (service SchedulerService) mutate(ctx context.Context, current, target commerce.EngagementScheduleEntry,
	initial *commerce.EngagementScheduleEntry, fence commerce.WriterFence) (commerce.EngagementScheduleEntry, error) {
	request := ScheduleTransitionRequest{ScheduleEntryID: target.ScheduleEntryID, ExpectedStateRevision: current.StateRevision,
		TargetState: target.State, TargetDispatchGeneration: target.DispatchGeneration, InitialEntry: initial}
	canonical, err := codec.Marshal(request)
	if err != nil {
		return commerce.EngagementScheduleEntry{}, err
	}
	fields := map[string]commerce.SemanticValue{"owner_id": commerce.ID(service.OwnerID), "agent_id": commerce.ID(service.AgentID),
		"schedule_entry_id": commerce.ID(target.ScheduleEntryID), "agreement_body_digest": commerce.Digest32(target.AgreementBodyDigest),
		"execution_id": commerce.Digest32(target.ExecutionID), "expected_state_revision": commerce.U64(current.StateRevision),
		"target_state": commerce.State(string(target.State)), "target_dispatch_generation": commerce.U64(target.DispatchGeneration)}
	expires := target.DeadlineUnix
	if fence.Body.ExpiresAtUnix < expires {
		expires = fence.Body.ExpiresAtUnix
	}
	prior := "absent"
	if current.State != "" {
		prior = string(current.State)
	}
	action, err := commerce.BuildAuthorizedAction(service.OwnerID, service.AgentID, "schedule.entry.transition", fields, canonical,
		fence, service.PolicyRevision, service.MandateDigest, "", prior, expires)
	if err == nil {
		action, err = service.Authority.SignAction(action, fence)
	}
	if err != nil {
		return commerce.EngagementScheduleEntry{}, err
	}
	resolution, err := service.Authority.AdmitScheduleTransition(action, canonical, fence)
	if err != nil || resolution.State != commerce.ActionTerminal {
		return commerce.EngagementScheduleEntry{}, errors.New("schedule transition was not durably admitted")
	}
	for _, entry := range service.entries() {
		if entry.ScheduleEntryID == target.ScheduleEntryID {
			return entry, nil
		}
	}
	return commerce.EngagementScheduleEntry{}, errors.New("schedule transition disappeared after admission")
}

func (service SchedulerService) entries() []commerce.EngagementScheduleEntry {
	entries, _ := service.Authority.ScheduleSnapshot()
	return entries
}

func (service SchedulerService) AddDependency(ctx context.Context, dependency commerce.PortfolioDependency,
	fence commerce.WriterFence) (commerce.ActionResolution, error) {
	return service.transitionDependency(ctx, dependency, "add", nil, fence)
}

func (service SchedulerService) RemoveDependency(ctx context.Context, dependency commerce.PortfolioDependency,
	evidence []string, fence commerce.WriterFence) (commerce.ActionResolution, error) {
	return service.transitionDependency(ctx, dependency, "remove", evidence, fence)
}

// PropagateTerminalDependency applies only the scheduling consequence frozen
// by a blocking dependency.  It never mutates, accepts, or cancels either
// Agreement: those remain independently authorized objects.  Evidence is
// required to release the edge, and every affected queue mutation is itself a
// writer-fenced semantic action, making crash recovery an idempotent replay of
// the same transitions.
func (service SchedulerService) PropagateTerminalDependency(ctx context.Context, upstreamAgreementDigest,
	upstreamObligationID, outcome string, evidence []string, fence commerce.WriterFence) (uint32, error) {
	if outcome != "succeeded" && outcome != "failed" && outcome != "cancelled" {
		return 0, errors.New("dependency outcome is not terminal")
	}
	entries, dependencies := service.Authority.ScheduleSnapshot()
	var changed uint32
	for _, dependency := range dependencies {
		if dependency.DependencyClass != "blocking" || dependency.UpstreamAgreementDigest != upstreamAgreementDigest ||
			dependency.UpstreamObligationID != upstreamObligationID {
			continue
		}
		propagation := dependency.FailurePropagation
		if outcome == "succeeded" {
			propagation = "continue"
		}
		switch propagation {
		case "continue", "release":
			// Releasing the edge is the only local scheduling effect.
		case "cancel":
			for _, entry := range entries {
				if entry.AgreementBodyDigest != dependency.DownstreamAgreementDigest ||
					entry.ExecutionObligationID != dependency.DownstreamObligationID {
					continue
				}
				target := commerce.ScheduleCancelled
				if entry.State == commerce.ScheduleRunning {
					target = commerce.ScheduleDraining
				}
				switch entry.State {
				case commerce.ScheduleQueued, commerce.ScheduleReady, commerce.ScheduleDispatched, commerce.ScheduleRunning:
					if _, err := service.Transition(ctx, entry, target, fence); err != nil {
						return changed, err
					}
					changed++
				case commerce.ScheduleDraining, commerce.ScheduleSucceeded, commerce.ScheduleFailed, commerce.ScheduleCancelled:
					// Already safe or terminal.  Never reinterpret its outcome.
				case commerce.ScheduleAmbiguous:
					return changed, errors.New("ambiguous downstream execution must be reconciled before dependency release")
				default:
					return changed, errors.New("downstream schedule state is unknown")
				}
			}
		case "hold", "manual":
			// Preserve the blocking edge until exact owner-reviewed evidence selects
			// a later transition.
			continue
		default:
			return changed, errors.New("dependency failure propagation policy is unsupported")
		}
		if _, err := service.RemoveDependency(ctx, dependency, evidence, fence); err != nil {
			return changed, err
		}
		changed++
	}
	return changed, nil
}

func (service SchedulerService) transitionDependency(ctx context.Context, dependency commerce.PortfolioDependency,
	kind string, evidence []string, fence commerce.WriterFence) (commerce.ActionResolution, error) {
	if service.Authority == nil || ctx == nil || ctx.Err() != nil || service.PolicyRevision == 0 || (kind != "add" && kind != "remove") {
		return commerce.ActionResolution{}, errors.New("dependency transition is incomplete")
	}
	revision, _, _ := service.Authority.Snapshot()
	request := DependencyTransitionRequest{Dependency: dependency, TransitionKind: kind, GraphBaseRevision: revision,
		EvidenceRefs: append([]string(nil), evidence...)}
	sort.Strings(request.EvidenceRefs)
	canonical, err := codec.Marshal(request)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	fields := map[string]commerce.SemanticValue{"owner_id": commerce.ID(service.OwnerID), "agent_id": commerce.ID(service.AgentID),
		"upstream_agreement_digest":   commerce.Digest32(dependency.UpstreamAgreementDigest),
		"upstream_obligation_id":      commerce.ID(dependency.UpstreamObligationID),
		"downstream_agreement_digest": commerce.Digest32(dependency.DownstreamAgreementDigest),
		"downstream_obligation_id":    commerce.ID(dependency.DownstreamObligationID), "dependency_type": commerce.Kind(dependency.DependencyType),
		"dependency_class": commerce.Kind(dependency.DependencyClass), "transition_kind": commerce.Kind(kind), "graph_base_revision": commerce.U64(revision)}
	action, err := commerce.BuildAuthorizedAction(service.OwnerID, service.AgentID, "schedule.dependency.transition", fields, canonical,
		fence, service.PolicyRevision, service.MandateDigest, "", "graph-current", fence.Body.ExpiresAtUnix)
	if err == nil {
		action, err = service.Authority.SignAction(action, fence)
	}
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	return service.Authority.AdmitDependencyTransition(action, fields, canonical, fence, request)
}

// AdmitScheduleTransition is the durable scheduler's only mutation entry. It
// couples the registry action, current writer, exact state revision, dispatch
// generation and dependency-cycle check in one authority journal commit.
func (authority *PersonalAuthority) AdmitScheduleTransition(action commerce.AuthorizedAction,
	request []byte, fence commerce.WriterFence) (commerce.ActionResolution, error) {
	if authority == nil {
		return commerce.ActionResolution{}, errors.New("scheduler authority is unavailable")
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	now := authority.now().UTC()
	if authority.doc.CurrentFence == nil || fence.Body.WriterGeneration != authority.doc.WriterGeneration ||
		fence.Body.LeaseID != authority.doc.CurrentFence.Body.LeaseID || !now.Before(time.Unix(int64(fence.Body.ExpiresAtUnix), 0)) {
		return commerce.ActionResolution{}, errors.New("stale writer cannot mutate the scheduler")
	}
	var transition ScheduleTransitionRequest
	if err := codec.Unmarshal(request, &transition); err != nil || transition.ScheduleEntryID == "" || transition.TargetDispatchGeneration == 0 {
		return commerce.ActionResolution{}, errors.New("schedule transition request is invalid")
	}
	if prior, found := authority.doc.Actions[action.StableActionID]; found {
		requestDigest, err := commerce.ExactRequestDigest(request)
		if err != nil || prior.ExactRequestDigest != requestDigest || action.ExactRequestDigest != requestDigest {
			return commerce.ActionResolution{}, errors.New("schedule transition identity conflicts")
		}
		return prior, nil
	}
	current, exists := authority.doc.ScheduleEntries[transition.ScheduleEntryID]
	var target commerce.EngagementScheduleEntry
	if !exists {
		if transition.ExpectedStateRevision != 0 || transition.TargetState != commerce.ScheduleQueued || transition.InitialEntry == nil ||
			transition.InitialEntry.ScheduleEntryID != transition.ScheduleEntryID || transition.InitialEntry.State != commerce.ScheduleQueued ||
			transition.InitialEntry.StateRevision != 1 || transition.InitialEntry.DispatchGeneration != transition.TargetDispatchGeneration ||
			transition.InitialEntry.WriterGeneration != fence.Body.WriterGeneration {
			return commerce.ActionResolution{}, errors.New("new schedule entry has no canonical initial state")
		}
		target = *transition.InitialEntry
		if err := commerce.ValidateScheduleEntry(target); err != nil {
			return commerce.ActionResolution{}, err
		}
	} else {
		if transition.InitialEntry != nil || current.StateRevision != transition.ExpectedStateRevision {
			return commerce.ActionResolution{}, errors.New("schedule transition has a stale state revision")
		}
		var err error
		target, err = commerce.TransitionScheduleEntry(current, transition.TargetState,
			transition.TargetDispatchGeneration, fence.Body.WriterGeneration)
		if err != nil {
			return commerce.ActionResolution{}, err
		}
	}
	prospectiveDependencies := append(append([]commerce.PortfolioDependency(nil), authority.doc.Dependencies...), transition.Dependencies...)
	if err := commerce.ValidatePortfolioDependencies(prospectiveDependencies); err != nil {
		return commerce.ActionResolution{}, err
	}
	fields := map[string]commerce.SemanticValue{"owner_id": commerce.ID(authority.doc.OwnerID), "agent_id": commerce.ID(authority.doc.AgentID),
		"schedule_entry_id": commerce.ID(target.ScheduleEntryID), "agreement_body_digest": commerce.Digest32(target.AgreementBodyDigest),
		"execution_id": commerce.Digest32(target.ExecutionID), "expected_state_revision": commerce.U64(transition.ExpectedStateRevision),
		"target_state": commerce.State(string(transition.TargetState)), "target_dispatch_generation": commerce.U64(transition.TargetDispatchGeneration)}
	resolver := localFenceResolver{authorityID: authority.doc.AuthorityID, key: authority.key.Public().(ed25519.PublicKey)}
	if action.ActionKind != "schedule.entry.transition" || commerce.VerifyAuthorizedAction(action, fields, request, fence, resolver, now) != nil {
		return commerce.ActionResolution{}, errors.New("schedule transition is not an exact authorized action")
	}
	next := cloneAuthorityDocument(authority.doc)
	next.ScheduleEntries[target.ScheduleEntryID] = target
	next.Dependencies = prospectiveDependencies
	next.PortfolioRevision++
	resolution := commerce.ActionResolution{StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest,
		State: commerce.ActionTerminal, StateRevision: 1}
	next.Actions[action.StableActionID] = resolution
	if err := authority.persist(next); err != nil {
		return commerce.ActionResolution{}, err
	}
	authority.doc = next
	return resolution, nil
}

func (authority *PersonalAuthority) AdmitDependencyTransition(action commerce.AuthorizedAction,
	fields map[string]commerce.SemanticValue, canonicalRequest []byte, fence commerce.WriterFence,
	request DependencyTransitionRequest) (commerce.ActionResolution, error) {
	if authority == nil {
		return commerce.ActionResolution{}, errors.New("dependency authority is unavailable")
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	now := authority.now().UTC()
	if authority.doc.CurrentFence == nil || fence.Body.WriterGeneration != authority.doc.WriterGeneration ||
		fence.Body.LeaseID != authority.doc.CurrentFence.Body.LeaseID || request.GraphBaseRevision != authority.doc.PortfolioRevision ||
		!now.Before(time.Unix(int64(fence.Body.ExpiresAtUnix), 0).UTC()) {
		return commerce.ActionResolution{}, errors.New("stale writer or graph revision cannot mutate dependencies")
	}
	canonical, err := codec.Marshal(request)
	if err != nil || !reflect.DeepEqual(canonical, canonicalRequest) {
		return commerce.ActionResolution{}, errors.New("dependency request is not canonical")
	}
	expected := map[string]commerce.SemanticValue{"owner_id": commerce.ID(authority.doc.OwnerID), "agent_id": commerce.ID(authority.doc.AgentID),
		"upstream_agreement_digest":   commerce.Digest32(request.Dependency.UpstreamAgreementDigest),
		"upstream_obligation_id":      commerce.ID(request.Dependency.UpstreamObligationID),
		"downstream_agreement_digest": commerce.Digest32(request.Dependency.DownstreamAgreementDigest),
		"downstream_obligation_id":    commerce.ID(request.Dependency.DownstreamObligationID), "dependency_type": commerce.Kind(request.Dependency.DependencyType),
		"dependency_class": commerce.Kind(request.Dependency.DependencyClass), "transition_kind": commerce.Kind(request.TransitionKind),
		"graph_base_revision": commerce.U64(request.GraphBaseRevision)}
	resolver := localFenceResolver{authorityID: authority.doc.AuthorityID, key: authority.key.Public().(ed25519.PublicKey)}
	if action.ActionKind != "schedule.dependency.transition" || !reflect.DeepEqual(fields, expected) ||
		commerce.VerifyAuthorizedAction(action, expected, canonicalRequest, fence, resolver, now) != nil {
		return commerce.ActionResolution{}, errors.New("dependency action is not exact or authorized")
	}
	if prior, found := authority.doc.Actions[action.StableActionID]; found {
		if prior.ExactRequestDigest != action.ExactRequestDigest {
			return commerce.ActionResolution{}, errors.New("dependency action identity conflicts")
		}
		return prior, nil
	}
	prospective := append([]commerce.PortfolioDependency(nil), authority.doc.Dependencies...)
	index := -1
	for offset, dependency := range prospective {
		if reflect.DeepEqual(dependency, request.Dependency) {
			index = offset
			break
		}
	}
	switch request.TransitionKind {
	case "add":
		if index >= 0 {
			return commerce.ActionResolution{}, errors.New("dependency already exists under another action")
		}
		prospective = append(prospective, request.Dependency)
	case "remove":
		if index < 0 {
			return commerce.ActionResolution{}, errors.New("dependency is absent")
		}
		if request.Dependency.EvidenceDrivenReleaseRequired && len(request.EvidenceRefs) == 0 {
			return commerce.ActionResolution{}, errors.New("dependency release lacks exact evidence")
		}
		for i, evidence := range request.EvidenceRefs {
			if !canonicalSHA256(evidence) || i > 0 && evidence == request.EvidenceRefs[i-1] {
				return commerce.ActionResolution{}, errors.New("dependency release evidence is invalid")
			}
		}
		prospective = append(prospective[:index], prospective[index+1:]...)
	default:
		return commerce.ActionResolution{}, errors.New("dependency transition kind is unknown")
	}
	if err := commerce.ValidatePortfolioDependencies(prospective); err != nil {
		return commerce.ActionResolution{}, err
	}
	next := cloneAuthorityDocument(authority.doc)
	next.Dependencies = prospective
	next.PortfolioRevision++
	resolution := commerce.ActionResolution{StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest,
		State: commerce.ActionTerminal, EvidenceRefs: append([]string(nil), request.EvidenceRefs...), StateRevision: 1}
	next.Actions[action.StableActionID] = resolution
	if err := authority.persist(next); err != nil {
		return commerce.ActionResolution{}, err
	}
	authority.doc = next
	return resolution, nil
}

func (authority *PersonalAuthority) ScheduleSnapshot() ([]commerce.EngagementScheduleEntry, []commerce.PortfolioDependency) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	entries := make([]commerce.EngagementScheduleEntry, 0, len(authority.doc.ScheduleEntries))
	for _, entry := range authority.doc.ScheduleEntries {
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ScheduleEntryID < entries[j].ScheduleEntryID })
	return entries, append([]commerce.PortfolioDependency(nil), authority.doc.Dependencies...)
}
