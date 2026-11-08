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
	wake     chan struct{}
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
		return s.Provider.HandleAck(message)
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
	for _, message := range messages {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := s.handle(ctx, message); err != nil {
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
	if err := s.Inbox.Prune(time.Now(), IncompleteRetention, DoneRetention); err != nil {
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
