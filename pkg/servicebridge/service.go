package servicebridge

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Service dispatches complete inbound rail messages to the local provider
// and buyer and drives their periodic duties. A message whose handling fails
// stays pending and is retried on later rounds, up to the inbox's attempt
// cap; a duplicate of a processed message is handled again. The provider's
// slot and the buyer's journal make every handling idempotent.
type Service struct {
	Inbox    *Inbox
	Provider *Provider
	Buyer    *Buyer
	Report   func(stage string, err error)
	// Now is the clock of the inbox's time bounds; nil means time.Now.
	Now  func() time.Time
	wake chan struct{}
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// ExecutorWait is how long a task is kept for an executor service that
// cannot run it. The node cannot know the request's response deadline before
// it admits the task, so the bound is the inbox's own lifetime of an entry
// that is not processed.
const ExecutorWait = IncompleteRetention

// retireUnready ends the wait of tasks no executor could run for
// ExecutorWait, saying so, before the inbox would prune them silently.
func (s *Service) retireUnready(now time.Time) error {
	held, err := s.Inbox.UnreadySince()
	if err != nil {
		return err
	}
	for key, since := range held {
		if now.Sub(since) < ExecutorWait {
			continue
		}
		s.Report("executor not ready", fmt.Errorf("a task was retired after %s without an executor service that "+
			"could run it; nothing was admitted or spent, and the request is answered only if its buyer "+
			"delivers the task again in time", ExecutorWait))
		if err := s.Inbox.Done(key); err != nil {
			return err
		}
	}
	return nil
}

// NewService wires the dispatcher; either role may be absent.
func NewService(inbox *Inbox, provider *Provider, buyer *Buyer, report func(string, error)) (*Service, error) {
	if inbox == nil || (provider == nil && buyer == nil) {
		return nil, errors.New("servicebridge: a service needs an inbox and a role")
	}
	if report == nil {
		report = func(string, error) {}
	}
	return &Service{Inbox: inbox, Provider: provider, Buyer: buyer, Report: report, wake: make(chan struct{}, 1)}, nil
}

// Notify is the Receiver hook: it wakes the dispatch loop.
func (s *Service) Notify(status InboxStatus, message Message) {
	if status == InboxDuplicate {
		// A duplicate of a processed message is handled again.
		if err := s.handle(context.Background(), message); err != nil {
			s.Report("duplicate rail message", err)
		}
		return
	}
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *Service) handle(ctx context.Context, message Message) error {
	switch message.Kind {
	case FrameTask:
		if s.Provider == nil {
			return errors.New("servicebridge: this node does not sell work")
		}
		return s.Provider.HandleTask(ctx, message)
	case FrameResultAck:
		if s.Provider == nil {
			return errors.New("servicebridge: this node does not sell work")
		}
		return s.Provider.HandleAck(ctx, message)
	case FrameResult:
		if s.Buyer == nil {
			return errors.New("servicebridge: this node does not buy work")
		}
		return s.Buyer.HandleResult(ctx, message)
	default:
		return fmt.Errorf("servicebridge: unknown message kind %d", message.Kind)
	}
}

// Dispatch handles every complete pending message once.
func (s *Service) Dispatch(ctx context.Context) error {
	messages, err := s.Inbox.Pending()
	if err != nil {
		return err
	}
	held, retired := 0, 0
	unready, unreadyRetired := 0, 0
	var pauseErr, unreadyErr error
	defer func() {
		// One line per round while tasks wait for the executor service.
		if unready > 0 || unreadyRetired > 0 {
			s.Report("executor not ready", fmt.Errorf("%d task(s) wait unadmitted, %d retired over the hold "+
				"bound: %w", unready, unreadyRetired, unreadyErr))
		}
	}()
	defer func() {
		// One line per round while tasks are held, not one per task.
		if held > 0 || retired > 0 || pauseErr != nil {
			s.Report("admission paused", fmt.Errorf("%d task(s) held, %d retired over the hold bound: %w",
				held, retired, pauseErr))
		}
	}()
	for _, message := range messages {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := s.handle(ctx, message); err != nil {
			if errors.Is(err, ErrAdmissionPaused) {
				// Held, not failed: the attempt cap must not retire a funded
				// request's task while the owner has paused admission. A held
				// task leaves the open-message bounds, so it cannot keep out
				// results and acknowledgements of admitted work.
				pauseErr = err
				switch holdErr := s.Inbox.Hold(message.Key); {
				case errors.Is(holdErr, ErrHoldFull):
					// Over the hold bound the task is retired; an unanswered
					// request falls to the buyer's refund path.
					retired++
					if doneErr := s.Inbox.Done(message.Key); doneErr != nil {
						return doneErr
					}
				case holdErr != nil:
					s.Report("rail message hold", holdErr)
				default:
					held++
				}
				continue
			}
			if errors.Is(err, ErrExecutorNotReady) {
				// Not a failed handling: nothing about the task was wrong
				// and nothing was claimed, so an outage of the executor
				// service must not use up the task's attempts. It waits,
				// outside the open-message bounds, and is handled again
				// every round.
				unreadyErr = err
				switch holdErr := s.Inbox.HoldForExecutor(message.Key); {
				case errors.Is(holdErr, ErrHoldFull):
					unreadyRetired++
					if doneErr := s.Inbox.Done(message.Key); doneErr != nil {
						return doneErr
					}
				case holdErr != nil:
					s.Report("rail message hold", holdErr)
				default:
					unready++
				}
				continue
			}
			s.Report("rail message", err)
			if err := s.Inbox.Failed(message.Key); err != nil {
				s.Report("rail message attempt", err)
			}
			continue
		}
		if err := s.Inbox.Done(message.Key); err != nil {
			return err
		}
	}
	return nil
}

// Step runs one round: dispatch, then the provider's delivery and the
// buyer's purchase duties.
func (s *Service) Step(ctx context.Context) {
	now := s.now()
	if err := s.retireUnready(now); err != nil {
		s.Report("executor not ready", err)
	}
	if err := s.Inbox.Prune(now, IncompleteRetention, DoneRetention); err != nil {
		s.Report("inbox prune", err)
	}
	if err := s.Dispatch(ctx); err != nil {
		s.Report("dispatch", err)
	}
	if s.Provider != nil {
		if err := s.Provider.Tick(ctx); err != nil {
			s.Report("provider", err)
		}
	}
	if s.Buyer != nil {
		if err := s.Buyer.Advance(ctx); err != nil {
			s.Report("buyer", err)
		}
	}
}

// Run steps on every wake-up and every interval until ctx ends.
func (s *Service) Run(ctx context.Context, interval time.Duration) error {
	if interval < time.Second {
		return errors.New("servicebridge: the service interval is too short")
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		s.Step(ctx)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		case <-s.wake:
		}
	}
}
