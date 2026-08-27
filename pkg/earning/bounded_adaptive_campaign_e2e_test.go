package earning

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tosnetwork/openfox/pkg/providers"
)

const boundedAdaptiveCampaignSchema = "tos.openfox.bounded-adaptive-campaign-local-rehearsal.v1"

type boundedAdaptiveTradeSpec struct {
	Seller int
	Task   int
}

type boundedAdaptiveOpinionBody struct {
	Stance              string `json:"stance"`
	TOSGratitude        string `json:"tos_gratitude"`
	TOSComplaint        string `json:"tos_complaint"`
	Suggestion          string `json:"suggestion"`
	Proposal            string `json:"proposal"`
	Learning            string `json:"learning"`
	ProposedSkillChange string `json:"proposed_skill_change"`
	RequiredEvidence    string `json:"required_evidence"`
	NextExperiment      string `json:"next_experiment"`
}

type boundedAdaptiveContribution struct {
	Campaign          int                        `json:"campaign"`
	Kind              string                     `json:"kind"`
	Agent             string                     `json:"agent"`
	AgentID           string                     `json:"agent_id"`
	Capability        string                     `json:"capability"`
	ModelKind         string                     `json:"model_kind"`
	CreatedAt         string                     `json:"created_at"`
	Body              boundedAdaptiveOpinionBody `json:"body"`
	BodyDigest        string                     `json:"body_digest"`
	IdentityPublicKey string                     `json:"identity_public_key"`
	Signature         string                     `json:"signature"`
}

type boundedAdaptiveSkillSnapshot struct {
	Agent  string   `json:"agent"`
	Before []string `json:"before"`
	After  []string `json:"after"`
}

type boundedAdaptivePhase struct {
	Campaign            int                            `json:"campaign"`
	Objective           string                         `json:"objective"`
	LocalRehearsalState string                         `json:"local_rehearsal_state"`
	NormativeResult     string                         `json:"normative_result"`
	NormativeReason     string                         `json:"normative_reason"`
	StartedAt           string                         `json:"started_at"`
	CompletedAt         string                         `json:"completed_at"`
	Trades              []eightAgentJobResult          `json:"trades"`
	TradeErrors         []string                       `json:"trade_errors,omitempty"`
	Contributions       []boundedAdaptiveContribution  `json:"contributions"`
	Skills              []boundedAdaptiveSkillSnapshot `json:"skills"`
}

type boundedAdaptiveReport struct {
	Schema           string                 `json:"schema"`
	Network          string                 `json:"network"`
	Topology         string                 `json:"topology"`
	StartedAt        string                 `json:"started_at"`
	UpdatedAt        string                 `json:"updated_at"`
	AgentCount       int                    `json:"agent_count"`
	CarrierCount     int                    `json:"carrier_count"`
	TOSFinalityViews int                    `json:"tos_finality_views"`
	ExternalRevenue  bool                   `json:"external_revenue"`
	IndependentHosts bool                   `json:"independent_hosts"`
	Campaigns        []boundedAdaptivePhase `json:"campaigns"`
}

type boundedAdaptivePhaseDefinition struct {
	Objective       string
	NormativeResult string
	NormativeReason string
	Trades          []boundedAdaptiveTradeSpec
}

// TestBoundedAdaptiveEarningCampaignsLocal is an opt-in, same-host rehearsal.
// It deliberately cannot promote Campaign 5 or 6: same-host processes are not
// independent operators, and transfers among campaign Agents are not external
// revenue. The test exercises the real two-Carrier discovery, Agreement,
// bounded LLM execution, local-chain payment, learning, and signed discussion
// paths without treating model conversation as economic authorization.
func TestBoundedAdaptiveEarningCampaignsLocal(t *testing.T) {
	if os.Getenv("OPENFOX_BOUNDED_ADAPTIVE_CAMPAIGNS") != "1" {
		t.Skip("set OPENFOX_BOUNDED_ADAPTIVE_CAMPAIGNS=1")
	}
	root := mustEnv(t, "OPENFOX_EIGHT_AGENT_CAMPAIGN_ROOT")
	manifest := loadEightAgentManifest(t, filepath.Join(root, "eight-agent-manifest.json"))
	runtimes := openCampaignRuntimes(t, root, manifest)
	defer closeCampaignRuntimes(runtimes)
	for _, runtime := range runtimes {
		if runtime.cfg.Evolution.AutoAppliesDrafts() {
			t.Fatalf("bounded campaign refuses automatic skill application for %s", runtime.definition.Name)
		}
	}

	definitions := boundedAdaptiveDefinitions()

	now := time.Now().UTC()
	report := boundedAdaptiveReport{Schema: boundedAdaptiveCampaignSchema, Network: "tos:local-three-node",
		Topology:  "eight isolated Agent identities in one orchestrator process; two same-host Carrier processes; three same-host validator views",
		StartedAt: now.Format(time.RFC3339Nano), UpdatedAt: now.Format(time.RFC3339Nano), AgentCount: len(runtimes),
		CarrierCount: 2, TOSFinalityViews: 3, ExternalRevenue: false, IndependentHosts: false}
	reportPath := filepath.Join(root, "reports", "bounded-adaptive-campaigns-checkpoint.json")
	if err := os.MkdirAll(filepath.Dir(reportPath), 0o700); err != nil {
		t.Fatal(err)
	}
	startCampaign := 1
	if configured := strings.TrimSpace(os.Getenv("OPENFOX_BOUNDED_ADAPTIVE_START_CAMPAIGN")); configured != "" {
		value, err := strconv.Atoi(configured)
		if err != nil || value < 1 || value > len(definitions) {
			t.Fatal("OPENFOX_BOUNDED_ADAPTIVE_START_CAMPAIGN must identify Campaign 1 through 6")
		}
		startCampaign = value
		if startCampaign > 1 {
			raw, readErr := os.ReadFile(reportPath)
			if readErr != nil || json.Unmarshal(raw, &report) != nil || len(report.Campaigns) < startCampaign-1 {
				t.Fatal("resume requires a valid checkpoint containing every preceding campaign")
			}
			report.Campaigns = report.Campaigns[:startCampaign-1]
		}
	}
	previousDiscussion := "No prior campaign discussion is available."
	if startCampaign > 1 {
		previousDiscussion = boundedAdaptiveDiscussionSummary(report.Campaigns[startCampaign-2].Contributions)
	}
	sequence := 10_000
	if configured := strings.TrimSpace(os.Getenv("OPENFOX_BOUNDED_ADAPTIVE_SEQUENCE_BASE")); configured != "" {
		value, err := strconv.Atoi(configured)
		if err != nil || value < 1 {
			t.Fatal("OPENFOX_BOUNDED_ADAPTIVE_SEQUENCE_BASE must be a positive integer")
		}
		sequence = value
	}
	for index, definition := range definitions {
		campaign := index + 1
		if campaign < startCampaign {
			continue
		}
		phaseStarted := time.Now().UTC()
		phase := boundedAdaptivePhase{Campaign: campaign, Objective: definition.Objective,
			LocalRehearsalState: "PASS", NormativeResult: definition.NormativeResult,
			NormativeReason: definition.NormativeReason, StartedAt: phaseStarted.Format(time.RFC3339Nano)}
		before := boundedAdaptiveSkills(runtimes)
		for tradeIndex, spec := range definition.Trades {
			seller := runtimes[spec.Seller]
			buyerIndex := boundedAdaptiveBuyerIndex(spec.Seller, campaign, tradeIndex, len(runtimes))
			if buyerIndex < 0 {
				t.Fatal("bounded campaign needs at least two valid Agent runtimes")
			}
			buyer := runtimes[buyerIndex]
			task := seller.definition.Tasks[spec.Task%len(seller.definition.Tasks)]
			result, err := runEightAgentJob(t.Context(), root, sequence, campaign, 0, buyer, seller, task, time.Now().UTC())
			sequence++
			if err != nil {
				phase.TradeErrors = append(phase.TradeErrors, fmt.Sprintf("buyer=%s seller=%s: %v", buyer.definition.Name, seller.definition.Name, err))
				for _, runtime := range []*campaignRuntime{buyer, seller} {
					engine := &Engine{OwnerID: runtime.definition.OwnerID, AgentID: runtime.definition.AgentID,
						MandateDigest: runtime.cfg.Earning.MandateDigest, Authority: runtime.authority}
					_, _ = engine.ReconcileApply(t.Context(), 1, runtime.fence)
				}
				continue
			}
			phase.Trades = append(phase.Trades, result)
		}
		tradeSummary, _ := json.Marshal(phase.Trades)
		opening, err := boundedAdaptiveRoundtable(t.Context(), campaign, "opening", definition.Objective,
			string(tradeSummary), previousDiscussion, runtimes, nil)
		if err != nil {
			phase.LocalRehearsalState = "FAIL"
			phase.TradeErrors = append(phase.TradeErrors, "roundtable opening: "+err.Error())
		} else {
			phase.Contributions = append(phase.Contributions, opening...)
			current, _ := json.Marshal(opening)
			repliers := []*campaignRuntime{runtimes[campaign%len(runtimes)], runtimes[(campaign+4)%len(runtimes)]}
			replies, replyErr := boundedAdaptiveRoundtable(t.Context(), campaign, "reply", definition.Objective,
				string(tradeSummary), string(current), repliers, opening)
			if replyErr != nil {
				phase.LocalRehearsalState = "FAIL"
				phase.TradeErrors = append(phase.TradeErrors, "roundtable replies: "+replyErr.Error())
			} else {
				phase.Contributions = append(phase.Contributions, replies...)
			}
		}
		after := boundedAdaptiveSkills(runtimes)
		phase.Skills = boundedAdaptiveSkillDiff(before, after)
		phase.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if len(phase.Trades) == 0 {
			phase.LocalRehearsalState = "FAIL"
		}
		report.Campaigns = append(report.Campaigns, phase)
		report.UpdatedAt = phase.CompletedAt
		writeCampaignJSON(t, reportPath, report)
		previousDiscussion = boundedAdaptiveDiscussionSummary(phase.Contributions)
		t.Logf("campaign=%d local=%s normative=%s trades=%d contributions=%d skills_changed=%d",
			campaign, phase.LocalRehearsalState, phase.NormativeResult, len(phase.Trades), len(phase.Contributions), len(phase.Skills))
	}
	for _, phase := range report.Campaigns {
		if phase.LocalRehearsalState != "PASS" {
			t.Fatalf("Campaign %d local rehearsal did not complete: %v", phase.Campaign, phase.TradeErrors)
		}
	}
	if err := validateBoundedAdaptiveReport(report, manifest, definitions); err != nil {
		t.Fatal(err)
	}
}

func boundedAdaptiveBuyerIndex(seller, campaign, tradeIndex, agentCount int) int {
	if agentCount < 2 || seller < 0 || seller >= agentCount {
		return -1
	}
	buyer := (seller + campaign + tradeIndex + 1) % agentCount
	if buyer == seller {
		buyer = (buyer + 1) % agentCount
	}
	return buyer
}

func TestBoundedAdaptiveCampaignScheduleNeverSelfTrades(t *testing.T) {
	for index, definition := range boundedAdaptiveDefinitions() {
		campaign := index + 1
		for tradeIndex, trade := range definition.Trades {
			buyer := boundedAdaptiveBuyerIndex(trade.Seller, campaign, tradeIndex, 8)
			if buyer < 0 || buyer == trade.Seller {
				t.Fatalf("Campaign %d trade %d selected seller %d as buyer %d", campaign, tradeIndex, trade.Seller, buyer)
			}
		}
	}
}

func boundedAdaptiveDefinitions() []boundedAdaptivePhaseDefinition {
	return []boundedAdaptivePhaseDefinition{
		{Objective: "Calibrate opportunity selection, completion probability, cost, and maximum loss before optimization.",
			NormativeResult: "INCONCLUSIVE", NormativeReason: "The local rehearsal does not satisfy the frozen 48-opportunity statistical and independent-scoring floor.",
			Trades: []boundedAdaptiveTradeSpec{{Seller: 0, Task: 0}, {Seller: 1, Task: 0}, {Seller: 2, Task: 0}}},
		{Objective: "Compare reviewed procedural guidance with an unchanged control on unseen work without expanding authority.",
			NormativeResult: "INCONCLUSIVE", NormativeReason: "The local rehearsal observes skill formation but is not a blinded 24-per-arm causal trial.",
			Trades: []boundedAdaptiveTradeSpec{{Seller: 3, Task: 0}, {Seller: 4, Task: 0}, {Seller: 5, Task: 0}}},
		{Objective: "Exercise trust and settlement reasoning while keeping Gifts separate from Agreement-bound payment.",
			NormativeResult: "INCONCLUSIVE", NormativeReason: "The representative trades use the released direct Agent Account adapter; the full 36-case direct/escrow/Gift matrix is not executed here.",
			Trades: []boundedAdaptiveTradeSpec{{Seller: 6, Task: 0}, {Seller: 7, Task: 0}}},
		{Objective: "Compose unlike businesses through one Intent, Agreement, Gate, and settlement core.",
			NormativeResult: "INCONCLUSIVE", NormativeReason: "Eight semantic classes are exercised, but the formal 64-Intent corpus and independent codec verifier remain outside this local rehearsal.",
			Trades: []boundedAdaptiveTradeSpec{{Seller: 0, Task: 1}, {Seller: 1, Task: 1}, {Seller: 2, Task: 1}, {Seller: 3, Task: 1}, {Seller: 4, Task: 1}, {Seller: 5, Task: 1}, {Seller: 6, Task: 1}, {Seller: 7, Task: 1}}},
		{Objective: "Probe replay, hostile content, ambiguous outcomes, Carrier loss, and writer takeover assumptions.",
			NormativeResult: "BLOCKED", NormativeReason: "Eight identities and two Carrier processes share one host and one operator; this cannot evidence independent failure domains.",
			Trades: []boundedAdaptiveTradeSpec{{Seller: 2, Task: 2}, {Seller: 3, Task: 2}}},
		{Objective: "Observe a bounded multi-generation earning and learning loop and identify the evidence needed for external operation.",
			NormativeResult: "BLOCKED", NormativeReason: "All buyers and providers are campaign-controlled, so there are no arm's-length buyers, independently controlled providers, or external revenue.",
			Trades: []boundedAdaptiveTradeSpec{{Seller: 6, Task: 2}, {Seller: 7, Task: 2}}},
	}
}

func validateBoundedAdaptiveReport(report boundedAdaptiveReport, manifest eightAgentManifest,
	definitions []boundedAdaptivePhaseDefinition) error {
	if report.Schema != boundedAdaptiveCampaignSchema || report.Network != "tos:local-three-node" ||
		report.StartedAt == "" || report.UpdatedAt == "" ||
		len(report.Campaigns) != len(definitions) || report.AgentCount != len(manifest.Agents) ||
		report.CarrierCount != 2 || report.TOSFinalityViews != 3 || report.ExternalRevenue || report.IndependentHosts {
		return fmt.Errorf("bounded campaign topology or phase count is inconsistent")
	}
	agentsByID := make(map[string]eightAgentManifestEntry, len(manifest.Agents))
	agentsByName := make(map[string]eightAgentManifestEntry, len(manifest.Agents))
	for _, agent := range manifest.Agents {
		if _, duplicate := agentsByID[agent.AgentID]; duplicate {
			return fmt.Errorf("manifest repeats Agent ID %s", agent.AgentID)
		}
		if _, duplicate := agentsByName[agent.Name]; duplicate {
			return fmt.Errorf("manifest repeats Agent name %s", agent.Name)
		}
		agentsByID[agent.AgentID] = agent
		agentsByName[agent.Name] = agent
	}
	transactions := make(map[string]struct{})
	sequences := make(map[int]struct{})
	contributionDigests := make(map[string]struct{})
	for index, phase := range report.Campaigns {
		if phase.Campaign != index+1 || len(phase.Trades) != len(definitions[index].Trades) ||
			phase.Objective != definitions[index].Objective || phase.LocalRehearsalState != "PASS" ||
			phase.NormativeResult != definitions[index].NormativeResult ||
			phase.NormativeReason != definitions[index].NormativeReason || phase.StartedAt == "" ||
			phase.CompletedAt == "" || len(phase.Contributions) != 10 || len(phase.TradeErrors) != 0 ||
			len(phase.Skills) != 0 {
			return fmt.Errorf("Campaign %d has incomplete trades, discussion, or an unexpected error", phase.Campaign)
		}
		openingAgents := make(map[string]struct{}, len(manifest.Agents))
		replyAgents := make(map[string]struct{}, 2)
		for tradeIndex, trade := range phase.Trades {
			carriers := make(map[string]struct{}, len(trade.CarrierIDs))
			for _, carrier := range trade.CarrierIDs {
				carriers[carrier] = struct{}{}
			}
			spec := definitions[index].Trades[tradeIndex]
			expectedSeller := manifest.Agents[spec.Seller]
			expectedBuyer := manifest.Agents[boundedAdaptiveBuyerIndex(spec.Seller, phase.Campaign, tradeIndex, len(manifest.Agents))]
			_, buyerKnown := agentsByName[trade.Buyer]
			if !buyerKnown || trade.Buyer != expectedBuyer.Name || trade.Seller != expectedSeller.Name ||
				trade.Buyer == trade.Seller || trade.Capability != expectedSeller.Capability || trade.Round != phase.Campaign ||
				trade.Disposition != "settled" || len(carriers) != 2 ||
				len(trade.CarrierIDs) != 2 || !containsCarrier(carriers, "carrier:gateway-local-pilot") ||
				!containsCarrier(carriers, "carrier:messenger-local-pilot") ||
				!canonicalSHA256(trade.DemandIntentDigest) || !canonicalSHA256(trade.AgreementDigest) ||
				!canonicalSHA256(trade.ExecutionID) || !canonicalSHA256(trade.DeliverableDigest) ||
				!canonicalSHA256(trade.PaymentTransaction) || !canonicalSHA256(trade.FinalityReference) ||
				!canonicalSHA256(trade.EconomicEvidenceDigest) || trade.RevenueNanoTOS != expectedSeller.Price ||
				trade.MaximumInternalCostNanoTOS != expectedSeller.MaximumCost ||
				trade.ProjectedNetNanoTOS != trade.RevenueNanoTOS-trade.MaximumInternalCostNanoTOS ||
				trade.ExpectedNetNanoTOS != strconv.FormatUint(trade.ProjectedNetNanoTOS, 10) ||
				trade.EconomicAnalysisMode != "bounded-owner-fallback" || trade.ExecutionElapsedMillis <= 0 ||
				trade.SettlementElapsedMillis <= 0 || trade.CompletedAt == "" ||
				strings.Join(trade.SkillsBefore, "\x00") != strings.Join(trade.SkillsAfter, "\x00") {
				return fmt.Errorf("Campaign %d trade %d lacks dual-Carrier, economic, deliverable, or finality evidence",
					phase.Campaign, trade.Sequence)
			}
			if _, duplicate := sequences[trade.Sequence]; duplicate {
				return fmt.Errorf("trade sequence %d appears more than once", trade.Sequence)
			}
			sequences[trade.Sequence] = struct{}{}
			if _, duplicate := transactions[trade.PaymentTransaction]; duplicate {
				return fmt.Errorf("payment transaction %s appears more than once", trade.PaymentTransaction)
			}
			transactions[trade.PaymentTransaction] = struct{}{}
		}
		for _, contribution := range phase.Contributions {
			agent, known := agentsByID[contribution.AgentID]
			if !known || contribution.Campaign != phase.Campaign || contribution.Agent != agent.Name ||
				contribution.Capability != agent.Capability || contribution.ModelKind != agent.ModelKind ||
				(contribution.Kind != "opening" && contribution.Kind != "reply") || contribution.CreatedAt == "" ||
				!boundedAdaptiveOpinionComplete(contribution.Body) {
				return fmt.Errorf("Campaign %d contribution has inconsistent participant metadata", phase.Campaign)
			}
			if contribution.Kind == "opening" {
				if _, duplicate := openingAgents[contribution.AgentID]; duplicate {
					return fmt.Errorf("Campaign %d has duplicate opening contribution from %s", phase.Campaign, contribution.Agent)
				}
				openingAgents[contribution.AgentID] = struct{}{}
			} else {
				if _, duplicate := replyAgents[contribution.AgentID]; duplicate {
					return fmt.Errorf("Campaign %d has duplicate reply contribution from %s", phase.Campaign, contribution.Agent)
				}
				replyAgents[contribution.AgentID] = struct{}{}
			}
			canonical, err := json.Marshal(struct {
				Campaign int                        `json:"campaign"`
				Kind     string                     `json:"kind"`
				AgentID  string                     `json:"agent_id"`
				Created  string                     `json:"created_at"`
				Body     boundedAdaptiveOpinionBody `json:"body"`
			}{contribution.Campaign, contribution.Kind, contribution.AgentID, contribution.CreatedAt,
				contribution.Body})
			if err != nil {
				return fmt.Errorf("encode contribution from %s: %w", contribution.Agent, err)
			}
			digest := sha256.Sum256(canonical)
			if contribution.BodyDigest != "sha256:"+hex.EncodeToString(digest[:]) ||
				agent.IdentityPin != contribution.IdentityPublicKey {
				return fmt.Errorf("contribution from %s has an invalid digest or identity pin", contribution.Agent)
			}
			if _, duplicate := contributionDigests[contribution.BodyDigest]; duplicate {
				return fmt.Errorf("contribution digest %s appears more than once", contribution.BodyDigest)
			}
			contributionDigests[contribution.BodyDigest] = struct{}{}
			publicKey, publicErr := hex.DecodeString(strings.TrimPrefix(contribution.IdentityPublicKey, "ed25519:"))
			signature, signatureErr := hex.DecodeString(strings.TrimPrefix(contribution.Signature, "ed25519:"))
			if publicErr != nil || signatureErr != nil || !ed25519.Verify(publicKey, canonical, signature) {
				return fmt.Errorf("contribution from %s has an invalid signature", contribution.Agent)
			}
		}
		if len(openingAgents) != len(manifest.Agents) || len(replyAgents) != 2 {
			return fmt.Errorf("Campaign %d does not have one opening per Agent and two distinct replies", phase.Campaign)
		}
		for _, replyIndex := range []int{phase.Campaign % len(manifest.Agents), (phase.Campaign + 4) % len(manifest.Agents)} {
			if _, ok := replyAgents[manifest.Agents[replyIndex].AgentID]; !ok {
				return fmt.Errorf("Campaign %d is missing its scheduled reply Agent", phase.Campaign)
			}
		}
	}
	return nil
}

func containsCarrier(carriers map[string]struct{}, carrier string) bool {
	_, ok := carriers[carrier]
	return ok
}

func boundedAdaptiveOpinionComplete(body boundedAdaptiveOpinionBody) bool {
	values := []string{body.Stance, body.TOSGratitude, body.TOSComplaint, body.Suggestion, body.Proposal,
		body.Learning, body.ProposedSkillChange, body.RequiredEvidence, body.NextExperiment}
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return false
		}
	}
	return true
}

func TestValidateBoundedAdaptiveCampaignReport(t *testing.T) {
	if os.Getenv("OPENFOX_VERIFY_BOUNDED_ADAPTIVE_REPORT") != "1" {
		t.Skip("set OPENFOX_VERIFY_BOUNDED_ADAPTIVE_REPORT=1")
	}
	root := mustEnv(t, "OPENFOX_EIGHT_AGENT_CAMPAIGN_ROOT")
	manifest := loadEightAgentManifest(t, filepath.Join(root, "eight-agent-manifest.json"))
	raw, err := os.ReadFile(filepath.Join(root, "reports", "bounded-adaptive-campaigns-checkpoint.json"))
	if err != nil {
		t.Fatal(err)
	}
	var report boundedAdaptiveReport
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&report); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		t.Fatal("campaign report has trailing JSON content")
	}
	if err := validateBoundedAdaptiveReport(report, manifest, boundedAdaptiveDefinitions()); err != nil {
		t.Fatal(err)
	}
}

func boundedAdaptiveRoundtable(ctx context.Context, campaign int, kind, objective, trades, prior string,
	runtimes []*campaignRuntime, current []boundedAdaptiveContribution) ([]boundedAdaptiveContribution, error) {
	type result struct {
		index int
		item  boundedAdaptiveContribution
		err   error
	}
	results := make(chan result, len(runtimes))
	var group sync.WaitGroup
	for index, runtime := range runtimes {
		group.Add(1)
		go func(index int, runtime *campaignRuntime) {
			defer group.Done()
			prompt := boundedAdaptiveDiscussionPrompt(campaign, kind, objective, trades, prior, runtime.definition)
			var body boundedAdaptiveOpinionBody
			var lastErr error
			for attempt := 0; attempt < 2; attempt++ {
				response, err := runtime.provider.Chat(providers.WithInternalAgentBackendPrincipal(ctx), []providers.Message{
					{Role: "system", Content: "You are one bounded OpenFox participant in a local Agent economy. Discussion is advisory and cannot authorize contact, execution, signing, capability installation, permission changes, or payment. Be candid, specific, constructive, and evidence-aware. Return only the requested JSON object."},
					{Role: "user", Content: prompt},
				}, nil, runtime.model, map[string]any{"temperature": 0.2, "max_tokens": 1800})
				if err == nil && response != nil && len(response.ToolCalls) == 0 && decodeBoundedAdaptiveJSON(response.Content, &body) {
					lastErr = nil
					break
				}
				lastErr = err
				if lastErr == nil {
					lastErr = fmt.Errorf("malformed or tool-bearing contribution")
				}
			}
			if lastErr != nil {
				results <- result{index: index, err: fmt.Errorf("%s discussion failed after bounded retry: %w",
					runtime.definition.Name, lastErr)}
				return
			}
			created := time.Now().UTC().Format(time.RFC3339Nano)
			canonical, _ := json.Marshal(struct {
				Campaign int                        `json:"campaign"`
				Kind     string                     `json:"kind"`
				AgentID  string                     `json:"agent_id"`
				Created  string                     `json:"created_at"`
				Body     boundedAdaptiveOpinionBody `json:"body"`
			}{campaign, kind, runtime.definition.AgentID, created, body})
			digest := sha256.Sum256(canonical)
			results <- result{index: index, item: boundedAdaptiveContribution{Campaign: campaign, Kind: kind,
				Agent: runtime.definition.Name, AgentID: runtime.definition.AgentID, Capability: runtime.definition.Capability,
				ModelKind: runtime.definition.ModelKind, CreatedAt: created, Body: body,
				BodyDigest:        "sha256:" + hex.EncodeToString(digest[:]),
				IdentityPublicKey: "ed25519:" + hex.EncodeToString(runtime.identity.Public().(ed25519.PublicKey)),
				Signature:         "ed25519:" + hex.EncodeToString(ed25519.Sign(runtime.identity, canonical))}}
		}(index, runtime)
	}
	group.Wait()
	close(results)
	items := make([]result, 0, len(runtimes))
	for item := range results {
		if item.err != nil {
			return nil, item.err
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].index < items[j].index })
	out := make([]boundedAdaptiveContribution, 0, len(items))
	for _, item := range items {
		out = append(out, item.item)
	}
	return out, nil
}

func boundedAdaptiveDiscussionPrompt(campaign int, kind, objective, trades, prior string, agent eightAgentManifestEntry) string {
	return fmt.Sprintf(`Campaign %d %s round.
Your role: %s
Your offered capability: %s
Campaign objective: %s
Observed local trade records: %s
Prior or peer discussion: %s

Discuss TOS Network from this role's actual operational perspective. React to the supplied peer discussion when present. Distinguish gratitude for something that worked from complaints about friction or missing evidence. Suggest one bounded improvement and, only if justified, one generic infrastructure proposal. Describe what you learned and one procedural skill change you would recommend for independent review. Do not claim external revenue, independent-host evidence, public-network finality, or authority you do not have.

Return exactly one JSON object with non-empty string fields:
{"stance":"...","tos_gratitude":"...","tos_complaint":"...","suggestion":"...","proposal":"...","learning":"...","proposed_skill_change":"...","required_evidence":"...","next_experiment":"..."}`,
		campaign, kind, agent.Name, agent.Capability, objective, boundedAdaptiveLimit(trades, 18<<10), boundedAdaptiveLimit(prior, 24<<10))
}

func decodeBoundedAdaptiveJSON(content string, target any) bool {
	content = strings.TrimSpace(content)
	start, end := strings.IndexByte(content, '{'), strings.LastIndexByte(content, '}')
	if start < 0 || end < start {
		return false
	}
	decoder := json.NewDecoder(strings.NewReader(content[start : end+1]))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return false
	}
	raw, _ := json.Marshal(target)
	return !strings.Contains(string(raw), `:""`)
}

func boundedAdaptiveLimit(value string, maximum int) string {
	if len(value) <= maximum {
		return value
	}
	return value[:maximum] + "...[truncated]"
}

func boundedAdaptiveSkills(runtimes []*campaignRuntime) map[string][]string {
	out := make(map[string][]string, len(runtimes))
	for _, runtime := range runtimes {
		out[runtime.definition.Name] = campaignSkillNames(runtime.cfg.WorkspacePath())
	}
	return out
}

func boundedAdaptiveSkillDiff(before, after map[string][]string) []boundedAdaptiveSkillSnapshot {
	names := make([]string, 0, len(after))
	for name := range after {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]boundedAdaptiveSkillSnapshot, 0, len(names))
	for _, name := range names {
		if strings.Join(before[name], "\x00") != strings.Join(after[name], "\x00") {
			out = append(out, boundedAdaptiveSkillSnapshot{Agent: name, Before: before[name], After: after[name]})
		}
	}
	return out
}

func boundedAdaptiveDiscussionSummary(items []boundedAdaptiveContribution) string {
	var summary strings.Builder
	for _, item := range items {
		fmt.Fprintf(&summary, "%s (%s): gratitude=%s; complaint=%s; suggestion=%s; proposal=%s; learning=%s\n",
			item.Agent, item.Kind, item.Body.TOSGratitude, item.Body.TOSComplaint, item.Body.Suggestion,
			item.Body.Proposal, item.Body.Learning)
	}
	return boundedAdaptiveLimit(summary.String(), 24<<10)
}
