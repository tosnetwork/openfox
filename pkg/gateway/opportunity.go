package gateway

import (
	"context"
	"errors"
	"math"
	"path/filepath"
	"time"

	"github.com/tosnetwork/openfox/pkg/actionauth"
	"github.com/tosnetwork/openfox/pkg/agent"
	"github.com/tosnetwork/openfox/pkg/config"
	"github.com/tosnetwork/openfox/pkg/logger"
	"github.com/tosnetwork/openfox/pkg/opportunity"
	"github.com/tosnetwork/openfox/pkg/tools"
)

func opportunityRuntimeConfig(settings config.OpportunitySettings) (opportunity.Config, error) {
	mode := opportunity.Mode(settings.Mode)
	if settings.IntervalMinutes > math.MaxInt64/uint64(time.Minute) ||
		settings.JitterSeconds > math.MaxInt64/uint64(time.Second) ||
		settings.RequestTimeoutSeconds > math.MaxInt64/uint64(time.Second) {
		return opportunity.Config{}, errors.New("opportunity duration overflows")
	}
	runtime := opportunity.Config{Mode: mode, Queries: append([]string(nil), settings.Queries...),
		Interval:       time.Duration(settings.IntervalMinutes) * time.Minute,
		Jitter:         time.Duration(settings.JitterSeconds) * time.Second,
		RequestTimeout: time.Duration(settings.RequestTimeoutSeconds) * time.Second,
		PageSize:       settings.PageSize, MaxCandidates: settings.MaxCandidates,
		AllowedOperations: append([]string(nil), settings.AllowedOperations...),
		AllowedProviders:  append([]string(nil), settings.AllowedProviders...),
		DeniedProviders:   append([]string(nil), settings.DeniedProviders...)}
	if err := runtime.Validate(); err != nil {
		return opportunity.Config{}, err
	}
	if mode == opportunity.ModeOff {
		if settings.CoordinatorSocket != "" || settings.StateDir != "" {
			return opportunity.Config{}, errors.New("disabled opportunity mode carries unused paths")
		}
		return runtime, nil
	}
	if !filepath.IsAbs(settings.CoordinatorSocket) || filepath.Clean(settings.CoordinatorSocket) != settings.CoordinatorSocket ||
		!filepath.IsAbs(settings.StateDir) || filepath.Clean(settings.StateDir) != settings.StateDir {
		return opportunity.Config{}, errors.New("opportunity socket and state directory must be clean absolute paths")
	}
	return runtime, nil
}

func setupOpportunityService(cfg *config.Config, agentLoop *agent.AgentLoop) (*opportunity.Service, error) {
	runtime, err := opportunityRuntimeConfig(cfg.Opportunity)
	if err != nil {
		return nil, err
	}
	if runtime.Mode == opportunity.ModeOff {
		return nil, nil
	}
	journal, err := opportunity.OpenJournal(cfg.Opportunity.StateDir)
	if err != nil {
		return nil, err
	}
	client, err := opportunity.NewUnixClient(cfg.Opportunity.CoordinatorSocket, runtime.RequestTimeout)
	if err != nil {
		return nil, err
	}
	service, err := opportunity.NewService(runtime, client, journal, opportunityLogReporter{})
	if err != nil {
		return nil, err
	}
	agentLoop.RegisterToolWithEffect(tools.NewOpportunityTool(journal), actionauth.EffectLocalRead)
	if err := service.Start(context.Background()); err != nil {
		return nil, err
	}
	return service, nil
}

type opportunityLogReporter struct{}

func (opportunityLogReporter) OpportunityAssessed(record opportunity.Record) {
	logger.InfoCF("opportunity", "Verified opportunity assessed", map[string]any{
		"intent_id": record.IntentID, "capability_id": record.Hint.Key.CapabilityID,
		"provider_agent_id": record.Hint.Key.ProviderAgentID,
		"eligible":          record.Assessment != nil && record.Assessment.Eligible,
	})
}

func (opportunityLogReporter) OpportunityCycleFailed(err error) {
	logger.WarnCF("opportunity", "Opportunity cycle failed", map[string]any{"error": err.Error()})
}
