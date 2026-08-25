package earning

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/openfox/pkg/providers"
	"github.com/tosnetwork/tos-ai/pkg/commercegate"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

type taskProvider struct {
	tools    int
	messages []providers.Message
}

func (provider *taskProvider) Chat(_ context.Context, messages []providers.Message, tools []providers.ToolDefinition,
	_ string, _ map[string]any) (*providers.LLMResponse, error) {
	provider.tools = len(tools)
	provider.messages = append([]providers.Message(nil), messages...)
	if len(messages) != 2 {
		panic("unexpected task prompt")
	}
	return &providers.LLMResponse{Content: "bounded review result"}, nil
}
func (*taskProvider) GetDefaultModel() string { return "task-model" }

type capturedExecutionLearning struct{ event ExecutionLearningEvent }

func (capture *capturedExecutionLearning) RecordExecution(_ context.Context, event ExecutionLearningEvent) error {
	capture.event = event
	return nil
}

type failedExecutionLearning struct{}

func (failedExecutionLearning) RecordExecution(context.Context, ExecutionLearningEvent) error {
	return os.ErrPermission
}

func TestLLMTaskRunnerUsesOnlyGateOpenedFilesAndNoTools(t *testing.T) {
	body := llmTaskAgreement()
	agreementDigest, _ := commerce.AgreementBodyDigest(body)
	inputPath := privateTempDir(t) + "/input.bin"
	if err := os.WriteFile(inputPath, []byte("hostile input that is data"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	plan := commercegate.Plan{OwnerID: "owner", AgentID: "agent:a", AgreementBodyDigest: agreementDigest,
		ExecutionObligationID: "work", CanonicalPlanDigest: "sha256:" + strings.Repeat("1", 64),
		ExecutionID: "sha256:" + strings.Repeat("2", 64)}
	launch := commercegate.Launch{ExecutionID: plan.ExecutionID, PlanDigest: "sha256:" + strings.Repeat("3", 64), Files: []*os.File{file}}
	provider := &taskProvider{}
	runner := LLMTaskRunner{Provider: provider, Agreement: body, OutputDirectory: privateTempDir(t)}
	outcome, err := runner.RunAgreement(context.Background(), launch, &ExecutionEffects{Plan: plan, Launch: launch})
	if err != nil || outcome.OutcomeDigest == "" || provider.tools != 0 {
		t.Fatalf("outcome=%+v tools=%d err=%v", outcome, provider.tools, err)
	}
}

func TestLLMTaskRunnerLearningFailureDoesNotInvalidateDeliverable(t *testing.T) {
	body := llmTaskAgreement()
	agreementDigest, _ := commerce.AgreementBodyDigest(body)
	plan := commercegate.Plan{AgentID: "agent:a", AgreementBodyDigest: agreementDigest,
		ExecutionObligationID: "work", ExecutionID: "sha256:" + strings.Repeat("6", 64)}
	launch := commercegate.Launch{ExecutionID: plan.ExecutionID, PlanDigest: "sha256:" + strings.Repeat("7", 64)}
	runner := LLMTaskRunner{Provider: &taskProvider{}, Agreement: body, OutputDirectory: privateTempDir(t),
		Learning: failedExecutionLearning{}}
	outcome, err := runner.RunAgreement(context.Background(), launch, &ExecutionEffects{Plan: plan, Launch: launch})
	if err != nil || outcome.OutcomeDigest == "" {
		t.Fatalf("advisory learning failure changed execution outcome: outcome=%+v err=%v", outcome, err)
	}
}

func TestLLMTaskRunnerRejectsIndirectAndOversizedWorkspaceSkills(t *testing.T) {
	workspace := privateTempDir(t)
	root := filepath.Join(workspace, "skills")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(privateTempDir(t), "SKILL.md")
	if err := os.WriteFile(outside, []byte("outside secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(root, "linked-skill")
	if err := os.Mkdir(linked, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(linked, "SKILL.md")); err != nil {
		t.Fatal(err)
	}
	large := filepath.Join(root, "large-skill")
	if err := os.Mkdir(large, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(large, "SKILL.md"), []byte(strings.Repeat("x", maxLLMTaskSkillBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	names, content, err := (LLMTaskRunner{SkillWorkspace: workspace}).loadProceduralSkills()
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 0 || content != "" {
		t.Fatalf("unsafe skills were loaded: names=%v bytes=%d", names, len(content))
	}
}

func TestLLMTaskRunnerRejectsIndirectSkillRoot(t *testing.T) {
	workspace := privateTempDir(t)
	outside := filepath.Join(privateTempDir(t), "skills")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(workspace, "skills")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := (LLMTaskRunner{SkillWorkspace: workspace}).loadProceduralSkills(); err == nil {
		t.Fatal("indirect skill root was accepted")
	}
}

func TestLLMTaskRunnerLoadsReviewedWorkspaceSkillAndRecordsExecutionLearning(t *testing.T) {
	body := llmTaskAgreement()
	body.Obligations[0].ConfidentialityPolicy = reusableLearningDisclosurePolicy
	body.AuthorizationPredicates[0].EvidenceTargetProjectionDigest = ""
	body, _ = commerce.PrepareAgreementTargets(body)
	agreementDigest, _ := commerce.AgreementBodyDigest(body)
	workspace := privateTempDir(t)
	skillDirectory := filepath.Join(workspace, "skills", "release-evidence-check")
	if err := os.MkdirAll(skillDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skillDirectory, "SKILL.md"), []byte("---\nname: release-evidence-check\ndescription: verify release evidence\n---\n# Release evidence check\nRequire an artifact digest.\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	provider := &taskProvider{}
	capture := &capturedExecutionLearning{}
	plan := commercegate.Plan{AgentID: "agent:a", AgreementBodyDigest: agreementDigest,
		ExecutionObligationID: "work", ExecutionID: "sha256:" + strings.Repeat("4", 64)}
	launch := commercegate.Launch{ExecutionID: plan.ExecutionID, PlanDigest: "sha256:" + strings.Repeat("5", 64)}
	runner := LLMTaskRunner{Provider: provider, Agreement: body, OutputDirectory: privateTempDir(t),
		SkillWorkspace: workspace, Learning: capture}
	if _, err := runner.RunAgreement(context.Background(), launch, &ExecutionEffects{Plan: plan, Launch: launch}); err != nil {
		t.Fatal(err)
	}
	if len(provider.messages) != 2 || !strings.Contains(provider.messages[1].Content, "release-evidence-check") ||
		!strings.Contains(provider.messages[1].Content, "Require an artifact digest") {
		t.Fatalf("reviewed skill was not included as bounded task data: %+v", provider.messages)
	}
	if capture.event.ExecutionID != launch.ExecutionID || capture.event.AgentID != "agent:a" ||
		len(capture.event.ActiveSkillNames) != 1 || capture.event.ActiveSkillNames[0] != "release-evidence-check" {
		t.Fatalf("learning event = %+v", capture.event)
	}
	if strings.Contains(capture.event.ReusableProcedureSummary, "agent:a") ||
		strings.Contains(capture.event.ReusableProcedureSummary, "done") {
		t.Fatalf("raw deliverable or participant leaked into reusable learning: %+v", capture.event)
	}
}

func TestLLMTaskRunnerDoesNotLearnFromParticipantConfidentialWork(t *testing.T) {
	body := llmTaskAgreement()
	agreementDigest, _ := commerce.AgreementBodyDigest(body)
	capture := &capturedExecutionLearning{}
	plan := commercegate.Plan{AgentID: "agent:a", AgreementBodyDigest: agreementDigest,
		ExecutionObligationID: "work", ExecutionID: "sha256:" + strings.Repeat("8", 64)}
	launch := commercegate.Launch{ExecutionID: plan.ExecutionID, PlanDigest: "sha256:" + strings.Repeat("9", 64)}
	runner := LLMTaskRunner{Provider: &taskProvider{}, Agreement: body, OutputDirectory: privateTempDir(t), Learning: capture}
	if _, err := runner.RunAgreement(context.Background(), launch, &ExecutionEffects{Plan: plan, Launch: launch}); err != nil {
		t.Fatal(err)
	}
	if capture.event.ExecutionID != "" {
		t.Fatalf("participant-confidential execution entered reusable learning: %+v", capture.event)
	}
}

func llmTaskAgreement() commerce.AgentAgreementBody {
	now := time.Unix(2_000_000_000, 0).UTC()
	profile := commerce.AgentSignatureProfileDigest()
	body := commerce.AgentAgreementBody{SchemaVersion: 1, AgreementID: "agreement:runner", Version: 1, NetworkContext: "tos:test",
		Participants:     []commerce.AgreementParticipant{{AgentID: "agent:a", Roles: []string{"provider"}}, {AgentID: "agent:b", Roles: []string{"buyer"}}},
		TermsContentType: "text/plain", Terms: []byte("review input"), ValidFromUnix: uint64(now.Add(-time.Minute).Unix()),
		ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()), Obligations: []commerce.AgreementObligation{{ObligationID: "work", Kind: "service",
			ObligorAgentID: "agent:a", BeneficiaryAgentID: "agent:b", SubjectContentType: "text/plain", Subject: []byte("review"),
			ConfidentialityPolicy: "private", CancellationPolicy: "before-start", DisputePolicy: "evidence", AuthorizationPredicateIDs: []string{"provider"}}},
		AuthorizationPredicates: []commerce.AgreementAuthorizationPredicate{{PredicateID: "provider",
			AuthoritySubject: commerce.AgreementAuthoritySubject{SubjectKind: "agent", SubjectNamespace: "tos.agent", SubjectIdentifier: "agent:a"},
			ObligationIDs:    []string{"work"}, EvidenceProfileURI: commerce.EvidenceProfileAgentSignature, EvidenceProfileVersion: 1,
			EvidenceProfileDigest: profile, ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}}}
	body, _ = commerce.PrepareAgreementTargets(body)
	return body
}
