package earning

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/tosnetwork/tos-ai/pkg/commercegate"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type ExecutionPrerequisiteVerifier interface {
	VerifyExecutionPrerequisites(context.Context, EngagementRecord) (required bool, evidenceDigests []string, err error)
}

// NativeExecutionAdmission is an optional chain-profile Gate. It runs after
// the deterministic local execution identity has been derived and before the
// local start ticket is issued.
type NativeExecutionAdmission interface {
	AdmitNativeExecution(context.Context, EngagementRecord, commercegate.Plan) (required bool, evidenceDigests []string, err error)
}

type ExecutionOutcome struct {
	OutcomeDigest string
}

type AgreementRunner interface {
	RunAgreement(context.Context, commercegate.Launch, *ExecutionEffects) (ExecutionOutcome, error)
}

type ExecutionService struct {
	Engine       *Engine
	Gate         *commercegate.Gate
	Prerequisite ExecutionPrerequisiteVerifier
	Native       NativeExecutionAdmission
	Runner       AgreementRunner
	Credentials  commercegate.CredentialResolver
}

type ExecutionEffects struct {
	Authority      EconomicAuthority
	Gate           *commercegate.Gate
	Launch         commercegate.Launch
	Plan           commercegate.Plan
	Fence          commerce.WriterFence
	PolicyRevision uint64
	MandateDigest  string
	Credentials    commercegate.CredentialResolver
}

func (effects *ExecutionEffects) HTTPS(ctx context.Context, request commercegate.HTTPSRequest) (commercegate.HTTPSResponse, error) {
	if effects == nil || effects.Authority == nil || effects.Gate == nil {
		return commercegate.HTTPSResponse{}, errors.New("execution effect broker is unavailable")
	}
	canonical, fields, err := commercegate.EffectAuthorizationMaterial(effects.Plan, request)
	if err != nil {
		return commercegate.HTTPSResponse{}, err
	}
	action, err := commerce.BuildAuthorizedAction(effects.Plan.OwnerID, effects.Plan.AgentID, "executor.effect", fields, canonical,
		effects.Fence, effects.PolicyRevision, effects.MandateDigest, "", "not-submitted", effects.Fence.Body.ExpiresAtUnix)
	if err != nil {
		return commercegate.HTTPSResponse{}, err
	}
	action, err = effects.Authority.SignAction(action, effects.Fence)
	if err != nil {
		return commercegate.HTTPSResponse{}, err
	}
	admitted, err := effects.Authority.Admit(action, fields, canonical, effects.Fence, nil)
	if err != nil {
		return commercegate.HTTPSResponse{}, err
	}
	if admitted.State == commerce.ActionAccepted || admitted.State == commerce.ActionTerminal {
		return commercegate.HTTPSResponse{}, errors.New("effect already resolved; runner must recover its exact output")
	}
	response, err := effects.Gate.PerformHTTPS(ctx, effects.Launch, request, action, effects.Fence, effects.Credentials)
	if err != nil {
		return commercegate.HTTPSResponse{}, err
	}
	_, err = effects.Authority.Transition(action.StableActionID, action.ExactRequestDigest, commerce.ActionAccepted,
		response.Digest, []string{response.Digest})
	return response, err
}

func (service ExecutionService) Execute(ctx context.Context, agreementDigest string, plan commercegate.Plan,
	policyRevision uint64, fence commerce.WriterFence) (EngagementRecord, error) {
	if service.Engine == nil || service.Engine.Authority == nil || service.Gate == nil || service.Prerequisite == nil || service.Runner == nil ||
		!service.Engine.permits("execution", service.Engine.Gates.Execution, false) {
		return EngagementRecord{}, errors.New("Agreement execution is disabled or incomplete")
	}
	record, found := service.Engine.Authority.Engagement(agreementDigest)
	runtime, runtimeFound := record.ObligationRuntime[plan.ExecutionObligationID]
	if !found || !runtimeFound || (runtime.State != ObligationPending && runtime.State != ObligationReady &&
		runtime.State != ObligationExecutionPrepared && runtime.State != ObligationExecuting) || record.ReservationID != plan.ReservationID ||
		plan.OwnerID != service.Engine.OwnerID || plan.AgentID != service.Engine.AgentID || plan.AgreementBodyDigest != agreementDigest {
		return EngagementRecord{}, errors.New("execution plan does not match a reserved Agreement")
	}
	if runtime.State == ObligationExecuting {
		return service.reconcileStartedExecution(agreementDigest, plan.ExecutionObligationID, runtime)
	}
	acceptedSetDigest, requiresPrivateInput, acceptedInputCount, digestErr := AcceptedExecutionInputSetDigest(record, plan.ExecutionObligationID)
	if digestErr != nil {
		return EngagementRecord{}, digestErr
	}
	if plan.AcceptedInputManifestDigest != acceptedSetDigest {
		return EngagementRecord{}, errors.New("execution plan does not bind its obligation-scoped accepted input set")
	}
	if requiresPrivateInput {
		if acceptedInputCount == 0 {
			return EngagementRecord{}, errors.New("Agreement private input has not been immutably accepted")
		}
	}
	required, fundingEvidence, err := service.Prerequisite.VerifyExecutionPrerequisites(ctx, record)
	if err != nil {
		return EngagementRecord{}, err
	}
	if required && len(fundingEvidence) == 0 {
		if record.State == EngagementReserved {
			_, _ = service.Engine.Authority.transitionEngagement(agreementDigest, EngagementReserved, EngagementFundingPending, "", nil)
		}
		return EngagementRecord{}, errors.New("required prepayment or finalized escrow funding is unresolved")
	}
	preparedPlan, prepareRequest, prepareFields, err := commercegate.PrepareAuthorizationMaterial(plan, fence)
	if err != nil {
		return EngagementRecord{}, err
	}
	if service.Native != nil {
		nativeRequired, nativeEvidence, nativeErr := service.Native.AdmitNativeExecution(ctx, record, preparedPlan)
		if nativeErr != nil || nativeRequired && len(nativeEvidence) == 0 {
			if nativeErr == nil {
				nativeErr = errors.New("native execution Gate returned no authority evidence")
			}
			return EngagementRecord{}, nativeErr
		}
		fundingEvidence = appendUniqueSorted(fundingEvidence, nativeEvidence...)
	}
	prepareAction, err := commerce.BuildAuthorizedAction(service.Engine.OwnerID, service.Engine.AgentID, "execution.prepare", prepareFields,
		prepareRequest, fence, policyRevision, service.Engine.MandateDigest, "", "reserved", minUint64(record.Agreement.Body.ExpiresAtUnix, fence.Body.ExpiresAtUnix))
	if err != nil {
		return EngagementRecord{}, err
	}
	prepareAction, err = service.Engine.Authority.SignAction(prepareAction, fence)
	if err != nil {
		return EngagementRecord{}, err
	}
	if _, err := service.Engine.Authority.Admit(prepareAction, prepareFields, prepareRequest, fence, nil); err != nil {
		return EngagementRecord{}, err
	}
	ticket, err := service.Gate.Prepare(ctx, preparedPlan, fence, 2*time.Minute, prepareAction)
	if err != nil {
		return EngagementRecord{}, err
	}
	ticketDigest, _ := codec.Digest("tos.execution-start-ticket.v1", ticket)
	if _, err := service.Engine.Authority.Transition(prepareAction.StableActionID, prepareAction.ExactRequestDigest,
		commerce.ActionAccepted, preparedPlan.ExecutionID, []string{ticketDigest}); err != nil {
		return EngagementRecord{}, err
	}
	if runtime.State != ObligationExecutionPrepared {
		record, err = service.Engine.Authority.transitionObligation(agreementDigest, plan.ExecutionObligationID,
			runtime.State, ObligationExecutionPrepared, preparedPlan.ExecutionID,
			appendUniqueSorted(fundingEvidence, ticketDigest), "")
		if err != nil {
			return EngagementRecord{}, err
		}
	}
	startRequest, startFields, err := commercegate.StartAuthorizationMaterial(preparedPlan, ticket)
	if err != nil {
		return EngagementRecord{}, err
	}
	startAction, err := commerce.BuildAuthorizedAction(service.Engine.OwnerID, service.Engine.AgentID, "execution.start", startFields,
		startRequest, fence, policyRevision, service.Engine.MandateDigest, "", "prepared", minUint64(ticket.StartNotAfterUnix, fence.Body.ExpiresAtUnix))
	if err != nil {
		return EngagementRecord{}, err
	}
	startAction, err = service.Engine.Authority.SignAction(startAction, fence)
	if err != nil {
		return EngagementRecord{}, err
	}
	if _, err := service.Engine.Authority.Admit(startAction, startFields, startRequest, fence, nil); err != nil {
		return EngagementRecord{}, err
	}
	launch, err := service.Gate.Start(ctx, ticket, fence, startAction)
	if err != nil {
		_, _ = service.Engine.Authority.transitionObligation(agreementDigest, plan.ExecutionObligationID,
			ObligationExecutionPrepared, ObligationAmbiguous, preparedPlan.ExecutionID, nil, "")
		return EngagementRecord{}, err
	}
	if _, err := service.Engine.Authority.Transition(startAction.StableActionID, startAction.ExactRequestDigest,
		commerce.ActionAccepted, preparedPlan.ExecutionID, nil); err != nil {
		return EngagementRecord{}, err
	}
	if err := service.Gate.MarkRunning(launch); err != nil {
		return EngagementRecord{}, err
	}
	record, err = service.Engine.Authority.transitionObligation(agreementDigest, plan.ExecutionObligationID,
		ObligationExecutionPrepared, ObligationExecuting, preparedPlan.ExecutionID, nil, "")
	if err != nil {
		return EngagementRecord{}, err
	}
	effects := &ExecutionEffects{Authority: service.Engine.Authority, Gate: service.Gate, Launch: launch, Plan: preparedPlan,
		Fence: fence, PolicyRevision: policyRevision, MandateDigest: service.Engine.MandateDigest, Credentials: service.Credentials}
	runContext := ctx
	var cancel context.CancelFunc
	if obligation, present := obligationByID(record, plan.ExecutionObligationID); present {
		if deadline, deadlineErr := obligationExecutionDeadline(record, obligation, service.Engine.now()); deadlineErr != nil {
			return EngagementRecord{}, deadlineErr
		} else if current, hasCurrent := ctx.Deadline(); !hasCurrent || deadline.Before(current) {
			runContext, cancel = context.WithDeadline(ctx, deadline)
		}
	}
	var leaseLost atomic.Bool
	monitorDone := make(chan struct{})
	if preparedPlan.LeaseLossPolicy == commercegate.LeaseLossKill {
		var leaseCancel context.CancelFunc
		runContext, leaseCancel = context.WithCancel(runContext)
		priorCancel := cancel
		cancel = func() {
			leaseCancel()
			if priorCancel != nil {
				priorCancel()
			}
		}
		go func() {
			ticker := time.NewTicker(250 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-monitorDone:
					return
				case <-ticker.C:
					if service.Engine.Authority.ConfirmCurrentWriterFence(fence, service.Engine.now()) != nil {
						leaseLost.Store(true)
						cancel()
						return
					}
				}
			}
		}()
	}
	outcome, runErr := service.Runner.RunAgreement(runContext, launch, effects)
	close(monitorDone)
	if cancel != nil {
		cancel()
	}
	if preparedPlan.LeaseLossPolicy == commercegate.LeaseLossKill &&
		(service.Engine.Authority.ConfirmCurrentWriterFence(fence, service.Engine.now()) != nil || leaseLost.Load()) {
		failureDigest, _ := codec.Digest("tos.execution-lease-loss.v1", preparedPlan.ExecutionID)
		_ = service.Gate.Complete(launch, commercegate.StateKilled, failureDigest)
		record, _ = service.Engine.Authority.transitionObligation(agreementDigest, plan.ExecutionObligationID,
			ObligationExecuting, ObligationFailed, preparedPlan.ExecutionID, []string{failureDigest}, "")
		return record, errors.New("execution was killed after writer authority was superseded")
	}
	if runErr != nil {
		failureDigest, _ := codec.Digest("tos.execution-failure.v1", runErr.Error())
		_ = service.Gate.Complete(launch, commercegate.StateFailed, failureDigest)
		record, _ = service.Engine.Authority.transitionObligation(agreementDigest, plan.ExecutionObligationID,
			ObligationExecuting, ObligationFailed, preparedPlan.ExecutionID, []string{failureDigest}, "")
		return record, runErr
	}
	if len(outcome.OutcomeDigest) != 71 {
		return EngagementRecord{}, errors.New("runner returned no canonical outcome digest")
	}
	if err := service.Gate.Complete(launch, commercegate.StateSucceeded, outcome.OutcomeDigest); err != nil {
		return EngagementRecord{}, err
	}
	return service.Engine.Authority.transitionObligation(agreementDigest, plan.ExecutionObligationID,
		ObligationExecuting, ObligationExecutionSucceeded, preparedPlan.ExecutionID, []string{outcome.OutcomeDigest}, "")
}

func (service ExecutionService) reconcileStartedExecution(agreementDigest, obligationID string,
	runtime ObligationRuntimeRecord) (EngagementRecord, error) {
	resolution, err := service.Gate.Inspect(runtime.ExecutionID)
	if err != nil {
		return EngagementRecord{}, err
	}
	switch resolution.State {
	case commercegate.StateSucceeded:
		if !canonicalSHA256(resolution.OutcomeDigest) {
			return EngagementRecord{}, errors.New("successful Gate record has no canonical outcome")
		}
		return service.Engine.Authority.transitionObligation(agreementDigest, obligationID,
			ObligationExecuting, ObligationExecutionSucceeded, runtime.ExecutionID,
			[]string{resolution.OutcomeDigest}, "")
	case commercegate.StateFailed, commercegate.StateCancelled, commercegate.StateKilled:
		evidence := resolution.OutcomeDigest
		if !canonicalSHA256(evidence) {
			evidence, _ = codec.Digest("tos.execution-terminal-gate.v1", struct {
				ExecutionID string `json:"execution_id"`
				State       string `json:"state"`
			}{runtime.ExecutionID, string(resolution.State)})
		}
		record, transitionErr := service.Engine.Authority.transitionObligation(agreementDigest, obligationID,
			ObligationExecuting, ObligationFailed, runtime.ExecutionID, []string{evidence}, "")
		if transitionErr != nil {
			return EngagementRecord{}, transitionErr
		}
		return record, errors.New("execution Gate resolved unsuccessfully")
	case commercegate.StateAmbiguousStart, commercegate.StateAmbiguousRun:
		evidence, _ := codec.Digest("tos.execution-ambiguous-gate.v1", struct {
			ExecutionID string `json:"execution_id"`
			State       string `json:"state"`
		}{runtime.ExecutionID, string(resolution.State)})
		record, transitionErr := service.Engine.Authority.transitionObligation(agreementDigest, obligationID,
			ObligationExecuting, ObligationAmbiguous, runtime.ExecutionID, []string{evidence}, "")
		if transitionErr != nil {
			return EngagementRecord{}, transitionErr
		}
		return record, errors.New("execution start or run remains ambiguous")
	case commercegate.StateStarting, commercegate.StateRunning:
		return EngagementRecord{}, errors.New("execution is still owned by an active runner")
	default:
		return EngagementRecord{}, errors.New("executing obligation conflicts with pre-start Gate state")
	}
}
