package earning

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/openfox/pkg/providers"
	"github.com/tosnetwork/tos-ai/pkg/commercegate"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

type taskProvider struct{ tools int }

func (provider *taskProvider) Chat(_ context.Context, messages []providers.Message, tools []providers.ToolDefinition,
	_ string, _ map[string]any) (*providers.LLMResponse, error) {
	provider.tools = len(tools)
	if len(messages) != 2 {
		panic("unexpected task prompt")
	}
	return &providers.LLMResponse{Content: "bounded review result"}, nil
}
func (*taskProvider) GetDefaultModel() string { return "task-model" }

func TestLLMTaskRunnerUsesOnlyGateOpenedFilesAndNoTools(t *testing.T) {
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
