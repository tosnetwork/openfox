package earning

import (
	"context"
	"errors"
	"math"
	"os"
	"strconv"
	"time"

	"github.com/tosnetwork/tos-ai/pkg/commercegate"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type PlannedEngagement struct {
	Reservation           ExposureReservation
	ExecutionPlan         commercegate.Plan
	Executable            bool
	ExecutionObligationID string
	DeliveryRecipientID   string
	Executions            []PlannedExecution
}

type PlannedExecution struct {
	ExecutionPlan       commercegate.Plan
	ObligationID        string
	DeliveryRecipientID string
}

type EngagementPlanner interface {
	PlanEngagement(context.Context, EngagementRecord, InventorySnapshot, commerce.WriterFence) (PlannedEngagement, error)
}

// BoundedEngagementPlanner converts an accepted generic Agreement into local
// aggregate exposure and, when this Agent owes work, one no-network execution
// slot. Skill-specific planners can add immutable files/effects but must still
// return the same Gate plan and reservation types.
type BoundedEngagementPlanner struct {
	OwnerID, AgentID         string
	ComputeUnitsPerExecution uint64
	SpendAtomicPerExecution  uint64
}

func (planner BoundedEngagementPlanner) PlanEngagement(_ context.Context, record EngagementRecord,
	inventory InventorySnapshot, fence commerce.WriterFence) (PlannedEngagement, error) {
	if planner.OwnerID == "" || planner.AgentID == "" || inventory.OwnerID != planner.OwnerID || inventory.AgentID != planner.AgentID ||
		record.State != EngagementAgreed && record.State != EngagementReserved && record.State != EngagementFundingPending &&
			record.State != EngagementReady && record.State != EngagementExecutionPrepared && record.State != EngagementExecuting &&
			record.State != EngagementExecutionSucceeded && record.State != EngagementDelivered && record.State != EngagementSettling ||
		commerce.ValidateAgreementBody(record.Agreement.Body) != nil {
		return PlannedEngagement{}, errors.New("engagement cannot be deterministically planned")
	}
	projection := struct {
		Agreement           string `json:"agreement_body_digest"`
		Policy              uint64 `json:"policy_revision"`
		Compute, ModelSpend uint64
	}{
		record.AgreementDigest, inventory.PolicyRevision, planner.ComputeUnitsPerExecution, planner.SpendAtomicPerExecution}
	reservationID, err := codec.Digest("tos.portfolio-reservation.v1", projection)
	if err != nil {
		return PlannedEngagement{}, err
	}
	reservation := ExposureReservation{ReservationID: reservationID, AgreementDigest: record.AgreementDigest}
	var executions []PlannedExecution
	for _, obligation := range record.Agreement.Body.Obligations {
		if obligation.Amount != nil {
			if obligation.Amount.AmountAtomic == "" {
				if obligation.ObligorAgentID == planner.AgentID || obligation.BeneficiaryAgentID == planner.AgentID {
					return PlannedEngagement{}, errors.New("local Portfolio cannot reserve a value without atomic conversion")
				}
				continue
			}
			amount, parseErr := strconv.ParseUint(obligation.Amount.AmountAtomic, 10, 64)
			if parseErr != nil {
				return PlannedEngagement{}, errors.New("Agreement amount exceeds local Portfolio range")
			}
			if obligation.ObligorAgentID == planner.AgentID {
				if reservation.SpendAtomic > math.MaxUint64-amount || reservation.MaximumLossAtomic > math.MaxUint64-amount {
					return PlannedEngagement{}, errors.New("Agreement payment exposure exceeds local Portfolio range")
				}
				reservation.SpendAtomic += amount
				reservation.MaximumLossAtomic += amount
			}
			if obligation.BeneficiaryAgentID == planner.AgentID {
				if reservation.ReceivableAtomic > math.MaxUint64-amount {
					return PlannedEngagement{}, errors.New("Agreement receivable exposure exceeds local Portfolio range")
				}
				reservation.ReceivableAtomic += amount
			}
			continue
		}
		if obligation.ObligorAgentID == planner.AgentID {
			plan := commercegate.Plan{OwnerID: planner.OwnerID, AgentID: planner.AgentID, AgreementBodyDigest: record.AgreementDigest,
				ExecutionObligationID: obligation.ObligationID, AttemptIndex: 0,
				PredecessorTerminalResolutionDigest: zeroSHA256Digest(), PolicyRevision: inventory.PolicyRevision,
				WriterGeneration: fence.Body.WriterGeneration, LeaseLossPolicy: commercegate.LeaseLossKill}
			executions = append(executions, PlannedExecution{ExecutionPlan: plan, ObligationID: obligation.ObligationID,
				DeliveryRecipientID: obligation.BeneficiaryAgentID})
		}
	}
	if len(executions) != 0 {
		count := uint64(len(executions))
		if planner.ComputeUnitsPerExecution != 0 && count > math.MaxUint64/planner.ComputeUnitsPerExecution ||
			planner.SpendAtomicPerExecution != 0 && count > math.MaxUint64/planner.SpendAtomicPerExecution {
			return PlannedEngagement{}, errors.New("execution reservation exceeds local Portfolio range")
		}
		reservation.ComputeUnits = planner.ComputeUnitsPerExecution * count
		executionSpend := planner.SpendAtomicPerExecution * count
		if reservation.SpendAtomic > math.MaxUint64-executionSpend {
			return PlannedEngagement{}, errors.New("execution cost exceeds local Portfolio range")
		}
		reservation.SpendAtomic += executionSpend
	}
	if record.ReservationID != "" {
		reservation.ReservationID = record.ReservationID
	}
	for index := range executions {
		acceptedDigest, _, _, digestErr := AcceptedExecutionInputSetDigest(record, executions[index].ObligationID)
		if digestErr != nil {
			return PlannedEngagement{}, digestErr
		}
		executions[index].ExecutionPlan.AcceptedInputManifestDigest = acceptedDigest
		executions[index].ExecutionPlan.ReservationID = reservation.ReservationID
	}
	result := PlannedEngagement{Reservation: reservation, Executable: len(executions) != 0, Executions: executions}
	if len(executions) != 0 {
		result.ExecutionPlan, result.ExecutionObligationID, result.DeliveryRecipientID = executions[0].ExecutionPlan,
			executions[0].ObligationID, executions[0].DeliveryRecipientID
	}
	return result, nil
}

type FundingEvidenceResolver interface {
	ResolveFundingPrerequisite(context.Context, EngagementRecord, commerce.AgreementObligation) ([]string, error)
}

type AdapterPrerequisitePolicy struct {
	LocalAgentID     string
	PostpaidAdapters []string
	PrepaidAdapters  []string
	Funding          FundingEvidenceResolver
}

func (policy AdapterPrerequisitePolicy) ValidateSettlementPrerequisite(_ context.Context, _ string, obligation commerce.AgreementObligation) error {
	if obligation.Amount == nil {
		return nil
	}
	if containsString(policy.PostpaidAdapters, obligation.SettlementAdapterURI) ||
		containsString(policy.PrepaidAdapters, obligation.SettlementAdapterURI) && policy.Funding != nil {
		return nil
	}
	return errors.New("settlement Adapter has no installed prerequisite verifier")
}

func (policy AdapterPrerequisitePolicy) VerifyExecutionPrerequisites(ctx context.Context, record EngagementRecord) (bool, []string, error) {
	var evidence []string
	for _, obligation := range record.Agreement.Body.Obligations {
		if obligation.Amount == nil || obligation.BeneficiaryAgentID != policy.LocalAgentID {
			continue
		}
		if containsString(policy.PostpaidAdapters, obligation.SettlementAdapterURI) {
			continue
		}
		if !containsString(policy.PrepaidAdapters, obligation.SettlementAdapterURI) || policy.Funding == nil {
			return true, nil, errors.New("settlement Adapter has no exact funding verifier")
		}
		resolved, err := policy.Funding.ResolveFundingPrerequisite(ctx, record, obligation)
		if err != nil {
			return true, nil, err
		}
		evidence = append(evidence, resolved...)
	}
	return len(evidence) > 0, evidence, nil
}

type AgreementRunnerFactory interface {
	RunnerFor(EngagementRecord) (AgreementRunner, error)
}

type ObligationRunnerFactory interface {
	RunnerForObligation(EngagementRecord, string) (AgreementRunner, error)
}

type AgreementPaymentRequestBuilder interface {
	BuildPaymentRequest(EngagementRecord, SettlementLedgerRecord) (commerce.AgreementPaymentRequest, error)
}

type ExternalAdapterIdentity struct {
	SystemID             string
	AdapterProfileDigest string
}

type DirectPaymentRequestBuilder struct {
	OwnerID, AgentID string
	ExternalAdapters map[string]ExternalAdapterIdentity
}

func (builder DirectPaymentRequestBuilder) BuildPaymentRequest(record EngagementRecord, ledger SettlementLedgerRecord) (commerce.AgreementPaymentRequest, error) {
	for _, obligation := range record.Agreement.Body.Obligations {
		if obligation.ObligationID == ledger.Obligation.AgreementObligationID && obligation.SettlementAdapterURI == ledger.Obligation.SettlementAdapterURI {
			if external, ok := builder.ExternalAdapters[obligation.SettlementAdapterURI]; ok {
				return commerce.BuildExternalAgreementPaymentRequestAmount(builder.OwnerID, builder.AgentID,
					record.Agreement.Body.NetworkContext, external.SystemID, external.AdapterProfileDigest,
					obligation.SettlementParameters, ledger.Obligation, ledger.State.OutstandingAmount)
			}
			return commerce.BuildAgreementPaymentRequestAmount(builder.OwnerID, builder.AgentID, record.Agreement.Body.NetworkContext,
				obligation.SettlementParameters, ledger.Obligation, ledger.State.OutstandingAmount)
		}
	}
	return commerce.AgreementPaymentRequest{}, errors.New("materialized payment has no exact Agreement Adapter parameters")
}

type AgreementRunnerFactoryFunc func(EngagementRecord) (AgreementRunner, error)

func (function AgreementRunnerFactoryFunc) RunnerFor(record EngagementRecord) (AgreementRunner, error) {
	return function(record)
}

type EngagementAutonomy struct {
	Engine         *Engine
	Inventory      InventorySource
	Planner        EngagementPlanner
	Prerequisite   AdapterPrerequisitePolicy
	Native         NativeExecutionAdmission
	Gate           *commercegate.Gate
	Scheduler      *SchedulerService
	Runners        AgreementRunnerFactory
	Delivery       DeliverySink
	Payment        *PaymentService
	Payments       map[string]*PaymentService
	Receivables    ReceivableSettlementService
	PaymentBuilder AgreementPaymentRequestBuilder
	Fence          WriterFenceProvider
}

func (service EngagementAutonomy) Process(ctx context.Context, maximum uint32) (uint32, error) {
	if service.Engine == nil || service.Engine.Authority == nil || service.Inventory == nil || service.Planner == nil ||
		service.Fence == nil || maximum == 0 || maximum > 1000 {
		return 0, errors.New("engagement autonomy is incomplete or unbounded")
	}
	advanced := uint32(0)
	for advanced < maximum {
		progress := false
		inventory, err := service.Inventory.Snapshot(ctx)
		if err != nil || inventory.Validate(service.Engine.now()) != nil {
			return advanced, errors.New("fresh Inventory is unavailable")
		}
		for _, snapshot := range service.Engine.Authority.EngagementSnapshot() {
			if advanced >= maximum {
				break
			}
			fence, fenceErr := service.Fence(ctx)
			if fenceErr != nil {
				return advanced, fenceErr
			}
			planned, planErr := service.Planner.PlanEngagement(ctx, snapshot, inventory, fence)
			switch snapshot.State {
			case EngagementAgreed:
				if planErr != nil {
					return advanced, planErr
				}
				if _, _, err := service.Engine.ReserveAgreement(ctx, snapshot.AgreementDigest, planned.Reservation,
					service.Prerequisite, inventory.PolicyRevision, fence); err != nil {
					return advanced, err
				}
				progress = true
			case EngagementReserved, EngagementFundingPending, EngagementReady, EngagementExecutionPrepared,
				EngagementExecuting, EngagementExecutionSucceeded, EngagementDelivered, EngagementSettling:
				if planErr != nil {
					return advanced, planErr
				}
				progress, err = service.processActiveEngagement(ctx, snapshot, planned, inventory, fence)
				if err != nil {
					return advanced, err
				}
			case EngagementSettled, EngagementUnpaid, EngagementCancelled, EngagementFailed:
				if snapshot.ReservationID == "" {
					continue
				}
				report, reconcileErr := service.Engine.ReconcileApply(ctx, inventory.PolicyRevision, fence)
				if reconcileErr != nil {
					return advanced, reconcileErr
				}
				progress = len(report.AppliedActionIDs) != 0
			}
			if progress {
				advanced++
				break
			}
		}
		if !progress {
			break
		}
	}
	return advanced, nil
}

func (service EngagementAutonomy) processActiveEngagement(ctx context.Context, snapshot EngagementRecord,
	planned PlannedEngagement, inventory InventorySnapshot, fence commerce.WriterFence) (bool, error) {
	// A completed execution is delivered before another irreversible execution
	// starts. This bounds ambiguity and makes each milestone independently
	// recoverable.
	for _, execution := range planned.Executions {
		runtime := snapshot.ObligationRuntime[execution.ObligationID]
		if runtime.State != ObligationExecutionSucceeded {
			continue
		}
		if service.Delivery == nil || len(runtime.ExecutionEvidence) != 1 {
			return false, errors.New("successful obligation execution lacks exact delivery material")
		}
		delivered, err := service.Engine.Deliver(ctx, snapshot.AgreementDigest, execution.ObligationID,
			execution.DeliveryRecipientID, runtime.ExecutionEvidence[0], service.Delivery, inventory.PolicyRevision, fence)
		if err != nil {
			return false, err
		}
		if service.Scheduler != nil {
			deliveryEvidence := []string{runtime.ExecutionEvidence[0]}
			if deliveredRuntime, ok := delivered.ObligationRuntime[execution.ObligationID]; ok && len(deliveredRuntime.DeliveryEvidence) != 0 {
				deliveryEvidence = append([]string(nil), deliveredRuntime.DeliveryEvidence...)
			}
			if _, err := service.Scheduler.PropagateTerminalDependency(ctx, snapshot.AgreementDigest,
				execution.ObligationID, "succeeded", deliveryEvidence, fence); err != nil {
				return false, err
			}
		}
		return true, nil
	}

	// Materialize every newly-ready value obligation. The method is idempotent
	// and only admits obligations whose canonical dependencies are satisfied.
	created, updated, err := (BillingService{Engine: service.Engine}).MaterializeAfterDelivery(snapshot.AgreementDigest,
		inventory.PolicyRevision, fence)
	if err != nil {
		return false, err
	}
	if len(created) != 0 || updated.StateRevision != snapshot.StateRevision {
		return true, nil
	}
	if service.Receivables != nil {
		settled, settleErr := service.Receivables.ResolveReceivable(ctx, snapshot, inventory.PolicyRevision, fence)
		if settleErr != nil {
			return false, settleErr
		}
		if settled {
			return true, nil
		}
	}

	ledgers := service.Engine.Authority.SettlementSnapshot(snapshot.AgreementDigest)
	for _, ledger := range ledgers {
		if ledger.Obligation.PayerAgentID != service.Engine.AgentID || ledger.State.State == commerce.SettlementPaid ||
			ledger.State.State == commerce.SettlementCancelled || ledger.State.State == commerce.SettlementWrittenOff {
			continue
		}
		paymentService := service.Payment
		if selected := service.Payments[ledger.Obligation.SettlementAdapterURI]; selected != nil {
			paymentService = selected
		}
		if paymentService == nil || service.PaymentBuilder == nil {
			continue
		}
		now := service.Engine.now()
		if ledger.Obligation.NotBeforeUnix != 0 && now.Before(time.Unix(int64(ledger.Obligation.NotBeforeUnix), 0).UTC()) {
			continue
		}
		if ledger.Obligation.PredecessorInstanceID != "" &&
			!settlementInstancePaid(service.Engine.Authority, snapshot.AgreementDigest, ledger.Obligation.PredecessorInstanceID) {
			continue
		}
		request, buildErr := service.PaymentBuilder.BuildPaymentRequest(snapshot, ledger)
		if buildErr != nil {
			return false, buildErr
		}
		if _, _, _, payErr := paymentService.Pay(ctx, request, inventory.PolicyRevision, fence); payErr != nil {
			return false, payErr
		}
		return true, nil
	}

	// An overdue observation is only emitted when every still-outstanding item
	// is due. Missing evidence never becomes payment.
	hasOutstanding, allDue := false, true
	now := service.Engine.now()
	for _, ledger := range ledgers {
		if ledger.State.State == commerce.SettlementPaid || ledger.State.State == commerce.SettlementOverdue ||
			ledger.State.State == commerce.SettlementCancelled || ledger.State.State == commerce.SettlementWrittenOff {
			continue
		}
		hasOutstanding = true
		allDue = allDue && ledger.Obligation.DueAtUnix != 0 &&
			!now.Before(time.Unix(int64(ledger.Obligation.DueAtUnix), 0).UTC())
	}
	if hasOutstanding && allDue {
		if _, overdueErr := (BillingService{Engine: service.Engine}).MarkOverdue(snapshot.AgreementDigest, now,
			inventory.PolicyRevision, fence); overdueErr != nil {
			return false, overdueErr
		}
		return true, nil
	}

	// Dispatch the first deterministic, dependency-ready local work
	// obligation. The remaining entries stay pending in the same durable graph.
	for _, execution := range planned.Executions {
		runtime := snapshot.ObligationRuntime[execution.ObligationID]
		obligation, found := obligationByID(snapshot, execution.ObligationID)
		if !found || !obligationDependenciesSatisfied(snapshot, obligation) {
			continue
		}
		switch runtime.State {
		case ObligationPending, ObligationReady, ObligationExecutionPrepared, ObligationExecuting:
		default:
			continue
		}
		if service.Gate == nil || service.Runners == nil || service.Scheduler == nil {
			return false, errors.New("accepted work has no Gate, execution Adapter, or durable scheduler")
		}
		service.Scheduler.PolicyRevision = inventory.PolicyRevision
		deadline, deadlineErr := obligationExecutionDeadline(snapshot, obligation, service.Engine.now())
		if deadlineErr != nil {
			return false, deadlineErr
		}
		scheduled, created, scheduleErr := service.Scheduler.EnsureExecution(ctx, execution.ExecutionPlan, deadline, fence)
		if scheduleErr != nil {
			return false, scheduleErr
		}
		if created {
			return true, nil
		}
		executeNow := false
		switch scheduled.State {
		case commerce.ScheduleQueued:
			_, scheduleErr = service.Scheduler.Transition(ctx, scheduled, commerce.ScheduleReady, fence)
		case commerce.ScheduleReady:
			_, scheduleErr = service.Scheduler.Transition(ctx, scheduled, commerce.ScheduleDispatched, fence)
		case commerce.ScheduleDispatched:
			scheduled, scheduleErr = service.Scheduler.Transition(ctx, scheduled, commerce.ScheduleRunning, fence)
			executeNow = scheduleErr == nil
		case commerce.ScheduleRunning, commerce.ScheduleAmbiguous:
			resolution, resolveErr := service.Gate.Inspect(scheduled.ExecutionID)
			if errors.Is(resolveErr, os.ErrNotExist) {
				if runtime.State != ObligationPending && runtime.State != ObligationReady {
					return false, errors.New("durable obligation preparation has no Gate record")
				}
				if scheduled.State == commerce.ScheduleAmbiguous {
					scheduled, scheduleErr = service.Scheduler.Transition(ctx, scheduled, commerce.ScheduleRunning, fence)
				}
				executeNow = scheduleErr == nil
			} else if resolveErr != nil {
				return false, resolveErr
			} else {
				switch resolution.State {
				case commercegate.StatePrepared:
					if runtime.State != ObligationPending && runtime.State != ObligationReady && runtime.State != ObligationExecutionPrepared {
						return false, errors.New("executing obligation conflicts with a pre-start Gate")
					}
					if scheduled.State == commerce.ScheduleAmbiguous {
						scheduled, scheduleErr = service.Scheduler.Transition(ctx, scheduled, commerce.ScheduleRunning, fence)
					}
					executeNow = scheduleErr == nil
				case commercegate.StateSucceeded, commercegate.StateFailed, commercegate.StateCancelled, commercegate.StateKilled:
					if runtime.State != ObligationExecuting {
						return false, errors.New("terminal Gate record conflicts with an obligation that never started")
					}
					executeNow = true
				case commercegate.StateAmbiguousStart, commercegate.StateAmbiguousRun:
					if runtime.State != ObligationExecutionPrepared && runtime.State != ObligationExecuting {
						return false, errors.New("ambiguous Gate record conflicts with a pre-preparation obligation")
					}
					evidence, _ := codec.Digest("tos.execution-ambiguous-gate.v1", struct {
						ExecutionID string `json:"execution_id"`
						State       string `json:"state"`
					}{runtime.ExecutionID, string(resolution.State)})
					if _, transitionErr := service.Engine.Authority.transitionObligation(snapshot.AgreementDigest,
						execution.ObligationID, runtime.State, ObligationAmbiguous, runtime.ExecutionID,
						[]string{evidence}, ""); transitionErr != nil {
						return false, transitionErr
					}
					if scheduled.State == commerce.ScheduleRunning {
						if _, scheduleErr = service.Scheduler.Transition(ctx, scheduled, commerce.ScheduleAmbiguous, fence); scheduleErr != nil {
							return false, scheduleErr
						}
					}
					return true, nil
				case commercegate.StateStarting, commercegate.StateRunning:
					return false, errors.New("execution remains owned by an active runner")
				default:
					return false, errors.New("execution Gate returned an unknown state")
				}
			}
		case commerce.ScheduleSucceeded:
			return false, errors.New("schedule succeeded before obligation outcome was recorded")
		case commerce.ScheduleFailed, commerce.ScheduleCancelled:
			return false, errors.New("terminal scheduler state blocks execution")
		default:
			return false, errors.New("scheduler returned an unknown state")
		}
		if scheduleErr != nil {
			return false, scheduleErr
		}
		if !executeNow {
			return true, nil
		}
		var runner AgreementRunner
		if factory, ok := service.Runners.(ObligationRunnerFactory); ok {
			runner, err = factory.RunnerForObligation(snapshot, execution.ObligationID)
		} else {
			runner, err = service.Runners.RunnerFor(snapshot)
		}
		if err != nil {
			return false, err
		}
		executor := ExecutionService{Engine: service.Engine, Gate: service.Gate, Prerequisite: service.Prerequisite,
			Native: service.Native, Runner: runner}
		executed, executeErr := executor.Execute(ctx, snapshot.AgreementDigest, execution.ExecutionPlan, inventory.PolicyRevision, fence)
		if executeErr != nil {
			target := commerce.ScheduleAmbiguous
			if obligationRuntime, present := executed.ObligationRuntime[execution.ObligationID]; present && obligationRuntime.State == ObligationFailed {
				target = commerce.ScheduleFailed
			}
			_, _ = service.Scheduler.Transition(ctx, scheduled, target, fence)
			if target == commerce.ScheduleFailed {
				failureEvidence := executed.ObligationRuntime[execution.ObligationID].ExecutionEvidence
				if _, propagationErr := service.Scheduler.PropagateTerminalDependency(ctx, snapshot.AgreementDigest,
					execution.ObligationID, "failed", failureEvidence, fence); propagationErr != nil {
					return false, errors.Join(executeErr, propagationErr)
				}
			}
			return false, executeErr
		}
		if _, err := service.Scheduler.Transition(ctx, scheduled, commerce.ScheduleSucceeded, fence); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

func obligationExecutionDeadline(record EngagementRecord, obligation commerce.AgreementObligation, now time.Time) (time.Time, error) {
	deadline := time.Unix(int64(record.Agreement.Body.ExpiresAtUnix), 0).UTC()
	if obligation.DueAtUnix != 0 {
		candidate := time.Unix(int64(obligation.DueAtUnix), 0).UTC()
		if candidate.Before(deadline) {
			deadline = candidate
		}
	}
	if obligation.ExpiresAtUnix != 0 {
		candidate := time.Unix(int64(obligation.ExpiresAtUnix), 0).UTC()
		if candidate.Before(deadline) {
			deadline = candidate
		}
	}
	if !deadline.After(now) {
		return time.Time{}, errors.New("execution obligation has expired")
	}
	return deadline, nil
}

func settlementInstancePaid(authority EconomicAuthority, agreementDigest, instanceID string) bool {
	for _, ledger := range authority.SettlementSnapshot(agreementDigest) {
		if ledger.Obligation.ObligationInstanceID == instanceID {
			return ledger.State.State == commerce.SettlementPaid
		}
	}
	return false
}
