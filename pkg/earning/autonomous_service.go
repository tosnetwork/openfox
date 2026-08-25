package earning

import (
	"context"
	"errors"
	"math/rand/v2"
	"sync"
	"time"
)

type CandidateHandler interface {
	HandleCandidate(context.Context, CandidateAssessment) error
}

type CandidateHandlerFunc func(context.Context, CandidateAssessment) error

func (function CandidateHandlerFunc) HandleCandidate(ctx context.Context, candidate CandidateAssessment) error {
	return function(ctx, candidate)
}

type AutonomousServiceConfig struct {
	Query        IntentQuery
	Interval     time.Duration
	MaxJitter    time.Duration
	CycleTimeout time.Duration
}

type AutonomousServiceStatus struct {
	Running               bool      `json:"running"`
	Cycles                uint64    `json:"cycles"`
	CandidatesAssessed    uint64    `json:"candidates_assessed"`
	CandidatesCommitted   uint64    `json:"candidates_committed"`
	AgreementEvents       uint64    `json:"agreement_events"`
	PaidDemandTransitions uint64    `json:"paid_demand_transitions"`
	PrivateHandoffs       uint64    `json:"private_handoffs"`
	EngagementTransitions uint64    `json:"engagement_transitions"`
	PublicationChanges    uint64    `json:"publication_changes"`
	Failures              uint64    `json:"failures"`
	LastCycleStarted      time.Time `json:"last_cycle_started,omitempty"`
	LastCycleCompleted    time.Time `json:"last_cycle_completed,omitempty"`
	LastError             string    `json:"last_error,omitempty"`
}

// AutonomousService continuously acquires and assesses opportunities. It only
// acknowledges a durable observation after the caller-supplied handler has
// safely completed, so crash, timeout, and handler failure replay the same
// semantic candidate instead of skipping it or inventing a new action.
type AutonomousService struct {
	Collector       Collector
	Handler         CandidateHandler
	Operations      *OperationalController
	Agreements      *AgreementAutonomy
	PaidDemand      *PaidDemandBuyerAutonomy
	PrivateHandoffs *PrivateHandoffAutonomy
	Engagements     *EngagementAutonomy
	Publications    *PublicationAutonomy
	Config          AutonomousServiceConfig
	Now             func() time.Time

	mu     sync.Mutex
	status AutonomousServiceStatus
}

func (service *AutonomousService) validate() error {
	if service == nil || service.Handler == nil || service.Config.Query.MaximumResults == 0 || service.Config.Query.MaximumResults > 1000 ||
		service.Config.Interval < time.Second || service.Config.Interval > 24*time.Hour || service.Config.MaxJitter < 0 ||
		service.Config.MaxJitter > service.Config.Interval || service.Config.CycleTimeout < time.Second || service.Config.CycleTimeout > service.Config.Interval {
		return errors.New("autonomous earning service configuration is invalid or unbounded")
	}
	return nil
}

func (service *AutonomousService) Status() AutonomousServiceStatus {
	service.mu.Lock()
	defer service.mu.Unlock()
	return service.status
}

func (service *AutonomousService) RunCycle(ctx context.Context) error {
	if err := service.validate(); err != nil {
		return err
	}
	now := time.Now().UTC()
	if service.Now != nil {
		now = service.Now().UTC()
	}
	service.mu.Lock()
	service.status.Cycles++
	service.status.LastCycleStarted = now
	service.mu.Unlock()
	cycle, cancel := context.WithTimeout(ctx, service.Config.CycleTimeout)
	defer cancel()
	if service.Agreements != nil {
		processed, agreementErr := service.Agreements.Process(cycle, 100)
		service.mu.Lock()
		service.status.AgreementEvents += uint64(processed)
		service.mu.Unlock()
		if agreementErr != nil {
			service.recordFailure(agreementErr)
			return agreementErr
		}
	}
	// Paid Demand consumes Provider Offer evidence processed above and must
	// establish finalized funding before any Provider execution.
	if service.PaidDemand != nil {
		advanced, paidDemandErr := service.PaidDemand.Process(cycle, 100)
		service.mu.Lock()
		service.status.PaidDemandTransitions += uint64(advanced)
		service.mu.Unlock()
		if paidDemandErr != nil {
			service.recordFailure(paidDemandErr)
			return paidDemandErr
		}
	}
	if service.PrivateHandoffs != nil {
		processed, handoffErr := service.PrivateHandoffs.Process(cycle, 100)
		service.mu.Lock()
		service.status.PrivateHandoffs += uint64(processed)
		service.mu.Unlock()
		if handoffErr != nil {
			service.recordFailure(handoffErr)
			return handoffErr
		}
	}
	if service.Engagements != nil {
		advanced, engagementErr := service.Engagements.Process(cycle, 100)
		service.mu.Lock()
		service.status.EngagementTransitions += uint64(advanced)
		service.mu.Unlock()
		if engagementErr != nil {
			service.recordFailure(engagementErr)
			return engagementErr
		}
	}
	if service.Publications != nil {
		changed, _, publicationErr := service.Publications.Process(cycle)
		if changed {
			service.mu.Lock()
			service.status.PublicationChanges++
			service.mu.Unlock()
		}
		if publicationErr != nil {
			service.recordFailure(publicationErr)
			return publicationErr
		}
	}
	if service.Operations != nil && !service.Operations.Permits("acquisition", false) {
		return errors.New("opportunity acquisition is paused")
	}
	assessments, err := service.Collector.Collect(cycle, service.Config.Query)
	if err != nil {
		service.recordFailure(err)
		return err
	}
	for _, assessment := range assessments {
		service.mu.Lock()
		service.status.CandidatesAssessed++
		service.mu.Unlock()
		if !assessment.Decision.Eligible {
			continue
		}
		if err := service.Handler.HandleCandidate(cycle, assessment); err != nil {
			service.recordFailure(err)
			return err
		}
		if err := service.Collector.Acknowledge(assessment); err != nil {
			service.recordFailure(err)
			return err
		}
		service.mu.Lock()
		service.status.CandidatesCommitted++
		service.mu.Unlock()
	}
	service.mu.Lock()
	service.status.LastCycleCompleted = now
	service.status.LastError = ""
	service.mu.Unlock()
	return nil
}

func (service *AutonomousService) recordFailure(err error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.status.Failures++
	service.status.LastError = err.Error()
}

func (service *AutonomousService) Run(ctx context.Context) error {
	if err := service.validate(); err != nil {
		return err
	}
	service.mu.Lock()
	if service.status.Running {
		service.mu.Unlock()
		return errors.New("autonomous earning service is already running")
	}
	service.status.Running = true
	service.mu.Unlock()
	defer func() {
		service.mu.Lock()
		service.status.Running = false
		service.mu.Unlock()
	}()
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		_ = service.RunCycle(ctx)
		delay := service.Config.Interval
		if service.Config.MaxJitter > 0 {
			delay += time.Duration(rand.Int64N(int64(service.Config.MaxJitter) + 1))
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}
