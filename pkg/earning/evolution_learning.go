package earning

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/tosnetwork/openfox/pkg/capabilitycontrol"
	"github.com/tosnetwork/openfox/pkg/config"
	"github.com/tosnetwork/openfox/pkg/evolution"
	"github.com/tosnetwork/openfox/pkg/providers"
	"github.com/tosnetwork/openfox/pkg/skills"
)

// ExecutionLearningEvent is evidence from one completed, Gate-admitted earning
// execution. Learning is advisory: it cannot authorize execution or any other
// economic side effect.
type ExecutionLearningEvent struct {
	ExecutionID         string
	AgreementBodyDigest string
	AgentID             string
	ObligationID        string
	Task                string
	// ReusableProcedureSummary must contain only disclosure-authorized,
	// de-identified procedural evidence. Raw deliverables never enter the
	// cross-engagement skill pipeline.
	ReusableProcedureSummary string
	ActiveSkillNames         []string
}

type ExecutionLearningRecorder interface {
	RecordExecution(context.Context, ExecutionLearningEvent) error
}

// EvolutionExecutionLearningRecorder connects the earning runner to the same
// reviewed, rollback-capable evolution pipeline used by interactive turns.
type EvolutionExecutionLearningRecorder struct {
	mu        sync.Mutex
	runtime   *evolution.Runtime
	workspace string
	agentID   string
	coldPath  bool
}

func NewEvolutionExecutionLearningRecorder(cfg config.EvolutionConfig, workspace, agentID string,
	provider providers.LLMProvider, model string, capability ...string) (*EvolutionExecutionLearningRecorder, error) {
	if cfg.Enabled && cfg.EffectiveMode() == "apply" {
		return nil, errors.New("earning evolution apply requires the acquisition-fenced constructor")
	}
	return newEvolutionExecutionLearningRecorder(cfg, workspace, "", agentID, provider, model, nil, capability...)
}

// NewEvolutionExecutionLearningRecorderWithAcquisition connects apply-mode
// earning evolution to the same externally fenced quarantine admission used
// by every other capability acquisition path. Model-authored drafts remain
// non-loader-visible until a separate review and promotion step.
func NewEvolutionExecutionLearningRecorderWithAcquisition(cfg config.EvolutionConfig, workspace, ownerID, agentID string,
	provider providers.LLMProvider, model string, fence capabilitycontrol.CapabilityAcquisitionFence,
	capability ...string,
) (*EvolutionExecutionLearningRecorder, error) {
	if cfg.Enabled && cfg.EffectiveMode() == "apply" && fence == nil {
		return nil, errors.New("earning evolution apply requires an external capability-acquisition fence")
	}
	return newEvolutionExecutionLearningRecorder(cfg, workspace, ownerID, agentID, provider, model, fence, capability...)
}

func newEvolutionExecutionLearningRecorder(cfg config.EvolutionConfig, workspace, ownerID, agentID string,
	provider providers.LLMProvider, model string, fence capabilitycontrol.CapabilityAcquisitionFence,
	capability ...string,
) (*EvolutionExecutionLearningRecorder, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if !filepath.IsAbs(workspace) || filepath.Clean(workspace) != workspace || strings.TrimSpace(agentID) == "" {
		return nil, errors.New("earning evolution requires a canonical workspace and Agent identity")
	}
	if fence != nil && strings.TrimSpace(ownerID) == "" {
		return nil, errors.New("earning evolution acquisition requires an Owner identity")
	}
	info, err := os.Lstat(workspace)
	resolved, resolveErr := filepath.EvalSymlinks(workspace)
	if err != nil || resolveErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || resolved != workspace {
		return nil, errors.New("earning evolution requires a direct workspace directory")
	}
	clusterer := evolution.NewLLMPatternClusterer(provider, model,
		evolution.NewHeuristicPatternClusterer(cfg.EffectiveMinTaskCount(), nil), cfg.EffectiveMinTaskCount(), nil)
	var patternClusterer evolution.PatternClusterer = clusterer
	if len(capability) > 0 && strings.TrimSpace(capability[0]) != "" {
		name := strings.TrimSpace(capability[0])
		if skills.ValidateSkillName(name) != nil {
			return nil, errors.New("earning evolution capability key is invalid")
		}
		patternClusterer = capabilityLearningClusterer{capability: name, delegate: clusterer}
	}
	runtime, err := evolution.NewRuntime(evolution.RuntimeOptions{
		Config:           cfg,
		PatternClusterer: patternClusterer,
		GeneratorFactory: func(current string) evolution.DraftGenerator {
			return evolution.NewDraftGeneratorForWorkspace(current, provider, model)
		},
		SuccessJudgeFactory: func(string) evolution.SuccessJudge {
			return evolution.NewLLMTaskSuccessJudge(provider, model, &evolution.HeuristicSuccessJudge{})
		},
		ApplierFactory: func(current string) *evolution.Applier {
			if fence != nil {
				return evolution.NewTrustedApplierWithAcquisition(
					evolution.NewPaths(current, cfg.StateDir), nil, fence, []byte(ownerID), []byte(agentID),
				)
			}
			return evolution.NewTrustedApplier(evolution.NewPaths(current, cfg.StateDir), nil)
		},
	})
	if err != nil {
		return nil, err
	}
	return &EvolutionExecutionLearningRecorder{runtime: runtime, workspace: workspace, agentID: agentID,
		coldPath: cfg.RunsColdPathAfterTurn()}, nil
}

type capabilityLearningClusterer struct {
	capability string
	delegate   *evolution.LLMPatternClusterer
}

func (clusterer capabilityLearningClusterer) BuildPatterns(ctx context.Context, workspace string,
	tasks, existing []evolution.LearningRecord) ([]evolution.LearningRecord, []string, error) {
	return clusterer.delegate.BuildPatterns(ctx, workspace, clusterer.withCapability(tasks), existing)
}

func (clusterer capabilityLearningClusterer) BuildPatternsWithEvidence(ctx context.Context, workspace string,
	successfulTasks, evidenceTasks, existing []evolution.LearningRecord, minimumSuccessRatio float64,
) ([]evolution.LearningRecord, []string, error) {
	return clusterer.delegate.BuildPatternsWithEvidence(ctx, workspace, clusterer.withCapability(successfulTasks),
		clusterer.withCapability(evidenceTasks), existing, minimumSuccessRatio)
}

func (clusterer capabilityLearningClusterer) withCapability(records []evolution.LearningRecord) []evolution.LearningRecord {
	out := append([]evolution.LearningRecord(nil), records...)
	for index := range out {
		out[index].Summary = "Reusable earning capability " + clusterer.capability + " task: " + out[index].Summary
	}
	return out
}

func (recorder *EvolutionExecutionLearningRecorder) RecordExecution(ctx context.Context, event ExecutionLearningEvent) error {
	if recorder == nil || recorder.runtime == nil {
		return nil
	}
	if event.ExecutionID == "" || event.AgreementBodyDigest == "" || strings.TrimSpace(event.Task) == "" ||
		strings.TrimSpace(event.ReusableProcedureSummary) == "" || event.AgentID != recorder.agentID {
		return errors.New("earning evolution event is incomplete or belongs to another Agent")
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if err := recorder.runtime.FinalizeTurn(ctx, evolution.TurnCaseInput{
		Workspace: recorder.workspace, WorkspaceID: recorder.workspace, TurnID: event.ExecutionID,
		SessionKey: event.AgreementBodyDigest, AgentID: event.AgentID, Status: "completed",
		UserMessage: event.Task, FinalContent: event.ReusableProcedureSummary,
		ActiveSkillNames:    append([]string(nil), event.ActiveSkillNames...),
		AttemptedSkillNames: append([]string(nil), event.ActiveSkillNames...),
		FinalSuccessfulPath: append([]string(nil), event.ActiveSkillNames...),
	}); err != nil {
		return err
	}
	if recorder.coldPath {
		return recorder.runtime.RunColdPathOnce(ctx, recorder.workspace)
	}
	return nil
}
