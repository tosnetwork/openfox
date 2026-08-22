package opportunity

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"
)

var (
	ErrCoordinatorRejected  = errors.New("opportunity coordinator rejected candidate")
	ErrPolicyRunnerRequired = errors.New("policy-gated opportunity mode requires the Phase D purchase runner")
	ErrPurchaseRejected     = errors.New("opportunity purchase was rejected before funding")
)

type Rejection struct{ Reason string }

func (e *Rejection) Error() string {
	if e == nil || e.Reason == "" {
		return ErrCoordinatorRejected.Error()
	}
	return ErrCoordinatorRejected.Error() + ": " + e.Reason
}

func (e *Rejection) Unwrap() error { return ErrCoordinatorRejected }

type PurchaseRejection struct{ Reason string }

func (e *PurchaseRejection) Error() string {
	if e == nil || e.Reason == "" {
		return ErrPurchaseRejected.Error()
	}
	return ErrPurchaseRejected.Error() + ": " + e.Reason
}

func (e *PurchaseRejection) Unwrap() error { return ErrPurchaseRejected }

type Reporter interface {
	OpportunityAssessed(Record)
	OpportunityCycleFailed(error)
}

type Service struct {
	config      Config
	coordinator Coordinator
	purchases   PurchaseRunner
	journal     *Journal
	reporter    Reporter
	now         func() time.Time

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

func NewService(config Config, coordinator Coordinator, journal *Journal, reporter Reporter) (*Service, error) {
	return NewServiceWithPurchaseRunner(config, coordinator, nil, journal, reporter)
}

func NewServiceWithPurchaseRunner(config Config, coordinator Coordinator, purchases PurchaseRunner, journal *Journal, reporter Reporter) (*Service, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if config.Mode == ModeOff {
		return &Service{config: config}, nil
	}
	if config.Mode == ModePolicyGated && purchases == nil {
		return nil, ErrPolicyRunnerRequired
	}
	if coordinator == nil || journal == nil {
		return nil, errors.New("observe opportunity service needs a coordinator and durable journal")
	}
	return &Service{config: cloneConfig(config), coordinator: coordinator, purchases: purchases, journal: journal, reporter: reporter, now: time.Now}, nil
}

func (s *Service) Start(ctx context.Context) error {
	if s == nil || ctx == nil {
		return errors.New("invalid opportunity service start")
	}
	if s.config.Mode == ModeOff {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		return nil
	}
	run, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.done = make(chan struct{})
	go s.loop(run, s.done)
	return nil
}

func (s *Service) Stop() {
	if s == nil {
		return
	}
	s.mu.Lock()
	cancel, done := s.cancel, s.done
	s.cancel, s.done = nil, nil
	s.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}

func (s *Service) Cycle(ctx context.Context) error {
	if s == nil || s.config.Mode == ModeOff {
		return nil
	}
	if ctx == nil || s.coordinator == nil || s.journal == nil {
		return errors.New("invalid opportunity cycle")
	}
	now := s.now().UTC()
	if now.Unix() <= 0 {
		return errors.New("opportunity clock is invalid")
	}
	remaining := int(s.config.MaxCandidates)
	var failures []error
	for _, query := range s.config.Queries {
		if remaining == 0 {
			break
		}
		requestID, err := newRequestID()
		if err != nil {
			return err
		}
		pageSize := s.config.PageSize
		if uint32(remaining) < pageSize {
			pageSize = uint32(remaining)
		}
		call, cancel := context.WithTimeout(ctx, s.config.RequestTimeout)
		request := SearchRequest{RequestID: requestID, Query: query, PageSize: pageSize,
			MaxCandidates: uint32(remaining), DeadlineUnixMS: now.Add(s.config.RequestTimeout).UnixMilli()}
		hints, err := s.coordinator.Search(call, request)
		cancel()
		if err != nil {
			failures = append(failures, fmt.Errorf("search %q: %w", query, err))
			continue
		}
		if len(hints) > remaining || len(hints) > int(s.config.PageSize) {
			failures = append(failures, fmt.Errorf("search %q exceeded candidate bounds", query))
			continue
		}
		remaining -= len(hints)
		for _, hint := range hints {
			if err := s.process(ctx, hint, now); err != nil {
				failures = append(failures, err)
			}
		}
	}
	return errors.Join(failures...)
}

func (s *Service) process(ctx context.Context, hint CandidateHint, now time.Time) error {
	record, _, err := s.journal.Observe(hint, now)
	if err != nil {
		return err
	}
	if record.Phase == PhaseFailed || record.Phase == PhasePurchaseResolved {
		return nil
	}
	if record.Phase == PhaseDiscovered {
		call, cancel := context.WithTimeout(ctx, s.config.RequestTimeout)
		verified, verifyErr := s.coordinator.Verify(call, hint)
		cancel()
		if verifyErr != nil {
			if errors.Is(verifyErr, ErrCoordinatorRejected) {
				reason := "candidate failed independent finalized verification"
				if rejection := new(Rejection); errors.As(verifyErr, &rejection) && boundedText(rejection.Reason, 1, 400) {
					reason += ": " + rejection.Reason
				}
				_, markErr := s.journal.MarkFailed(record.IntentID, reason, now)
				return errors.Join(verifyErr, markErr)
			}
			return verifyErr
		}
		record, err = s.journal.MarkVerified(record.IntentID, verified, now)
		if err != nil {
			return err
		}
	}
	if record.Phase == PhaseVerified {
		assessment := s.assess(record, now)
		record, err = s.journal.MarkAssessed(record.IntentID, assessment, now)
		if err == nil && s.reporter != nil {
			s.reporter.OpportunityAssessed(record)
		}
		if err != nil || s.config.Mode == ModeObserve || !assessment.Eligible {
			return err
		}
	}
	if s.config.Mode != ModePolicyGated {
		return nil
	}
	return s.advancePurchase(ctx, record, now)
}

func (s *Service) advancePurchase(ctx context.Context, record Record, now time.Time) error {
	if s.purchases == nil || record.Verified == nil || record.Assessment == nil || !record.Assessment.Eligible {
		return ErrPolicyRunnerRequired
	}
	if record.Phase == PhaseAssessed {
		var err error
		record, err = s.journal.MarkQuoteRequested(record.IntentID, now)
		if err != nil {
			return err
		}
	}
	// The isolated coordinator exposes one durable transition per call. Four
	// steps cover Quote verification, signed-policy authorization, immutable
	// PurchaseKey creation, and one authoritative purchase reconciliation.
	for step := 0; step < 4 && record.Phase != PhasePurchaseResolved; step++ {
		var key *PurchaseKey
		if record.Purchase != nil && record.Purchase.Key != nil {
			owned := *record.Purchase.Key
			key = &owned
		}
		call, cancel := context.WithTimeout(ctx, s.config.RequestTimeout)
		progress, runErr := s.purchases.AdvancePurchase(call, PurchaseRequest{IntentID: record.IntentID,
			Current: record.Phase, Candidate: *record.Verified, Key: key})
		cancel()
		if runErr != nil {
			if errors.Is(runErr, ErrPurchaseRejected) && record.Phase != PhasePurchaseReferenced {
				reason := "purchase rejected by exact signed policy"
				var rejection *PurchaseRejection
				if errors.As(runErr, &rejection) && boundedText(rejection.Reason, 1, 400) {
					reason += ": " + rejection.Reason
				}
				_, markErr := s.journal.MarkFailed(record.IntentID, reason, now)
				return errors.Join(runErr, markErr)
			}
			return runErr
		}
		var err error
		record, err = s.journal.MarkPurchaseProgress(record.IntentID, progress, now)
		if err != nil {
			return err
		}
		if record.Phase == PhasePurchaseReferenced {
			// Funding/dispatch/settlement may be slow. One reconciliation per
			// scheduler cycle keeps the autonomous loop bounded.
			return nil
		}
	}
	return nil
}

func (s *Service) assess(record Record, now time.Time) Assessment {
	verified := record.Verified
	eligible, reason := true, "verified candidate is eligible for operator review"
	if slices.Contains(s.config.DeniedProviders, verified.Key.ProviderAgentID) {
		eligible, reason = false, "provider is denied by local policy"
	} else if len(s.config.AllowedProviders) > 0 && !slices.Contains(s.config.AllowedProviders, verified.Key.ProviderAgentID) {
		eligible, reason = false, "provider is not locally allowed"
	} else if len(s.config.AllowedOperations) > 0 && !slices.Contains(s.config.AllowedOperations, verified.Operation) {
		eligible, reason = false, "operation is not locally allowed"
	}
	return Assessment{Eligible: eligible, Score: record.Hint.GatewayMatchScore, Reason: reason, AssessedAtUnix: now.Unix()}
}

func (s *Service) loop(ctx context.Context, done chan struct{}) {
	defer close(done)
	for {
		if err := s.Cycle(ctx); err != nil && !errors.Is(err, context.Canceled) && s.reporter != nil {
			s.reporter.OpportunityCycleFailed(err)
		}
		delay := s.config.Interval + secureJitter(s.config.Jitter)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-timer.C:
		}
	}
}

func newRequestID() (string, error) {
	var material [32]byte
	if _, err := rand.Read(material[:]); err != nil {
		return "", errors.New("generate opportunity request identity")
	}
	return "opp-request_" + hex.EncodeToString(material[:]), nil
}

func secureJitter(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	var material [8]byte
	if _, err := rand.Read(material[:]); err != nil {
		return 0
	}
	var value uint64
	for _, b := range material {
		value = value<<8 | uint64(b)
	}
	return time.Duration(value % uint64(max+1))
}

func cloneConfig(config Config) Config {
	config.Queries = append([]string(nil), config.Queries...)
	config.AllowedOperations = append([]string(nil), config.AllowedOperations...)
	config.AllowedProviders = append([]string(nil), config.AllowedProviders...)
	config.DeniedProviders = append([]string(nil), config.DeniedProviders...)
	return config
}
