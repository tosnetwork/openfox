package earning

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/openfox/pkg/config"
	"github.com/tosnetwork/openfox/pkg/fileutil"
	"github.com/tosnetwork/openfox/pkg/providers"
	"github.com/tosnetwork/openfox/pkg/skills"
	"github.com/tosnetwork/tos-ai/pkg/commercegate"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

const eightAgentCampaignSchema = "tos.openfox.eight-agent-market-campaign.v1"

type eightAgentDefinition struct {
	Name, OwnerID, AgentID, AuthorityID, Wallet, Capability, Taxonomy, ModelKind, Template string
	Price, MaximumCost                                                                     uint64
	Tasks                                                                                  []string
}

type eightAgentManifestEntry struct {
	Name            string   `json:"name"`
	OwnerID         string   `json:"owner_id"`
	AgentID         string   `json:"agent_id"`
	AuthorityID     string   `json:"authority_id"`
	Wallet          string   `json:"wallet"`
	Target          string   `json:"target"`
	Capability      string   `json:"capability"`
	Taxonomy        string   `json:"taxonomy"`
	ModelKind       string   `json:"model_kind"`
	ConfigDirectory string   `json:"config_directory"`
	AuthorityPin    string   `json:"authority_pin"`
	IdentityPin     string   `json:"identity_pin"`
	Price           uint64   `json:"price_nanotos"`
	MaximumCost     uint64   `json:"maximum_internal_cost_nanotos"`
	Tasks           []string `json:"tasks"`
}

type eightAgentManifest struct {
	Schema    string                    `json:"schema"`
	CreatedAt string                    `json:"created_at"`
	Agents    []eightAgentManifestEntry `json:"agents"`
}

type eightAgentJobResult struct {
	Sequence                   int      `json:"sequence"`
	Disposition                string   `json:"disposition"`
	Round                      int      `json:"round"`
	Buyer                      string   `json:"buyer"`
	Seller                     string   `json:"seller"`
	Capability                 string   `json:"capability"`
	DemandIntentDigest         string   `json:"demand_intent_digest"`
	AgreementDigest            string   `json:"agreement_digest"`
	ExecutionID                string   `json:"execution_id"`
	DeliverableDigest          string   `json:"deliverable_digest"`
	PaymentTransaction         string   `json:"payment_transaction"`
	FinalityReference          string   `json:"finality_reference"`
	RevenueNanoTOS             uint64   `json:"revenue_nanotos"`
	MaximumInternalCostNanoTOS uint64   `json:"maximum_internal_cost_nanotos"`
	ProjectedNetNanoTOS        uint64   `json:"projected_net_nanotos"`
	SkillsBefore               []string `json:"skills_before"`
	SkillsAfter                []string `json:"skills_after"`
	ExecutionElapsedMillis     int64    `json:"execution_elapsed_millis"`
	SettlementElapsedMillis    int64    `json:"settlement_elapsed_millis"`
	EconomicEvidenceDigest     string   `json:"economic_evidence_digest"`
	EconomicAnalysisMode       string   `json:"economic_analysis_mode"`
	ExpectedNetNanoTOS         string   `json:"expected_net_nanotos"`
	CompletedAt                string   `json:"completed_at"`
	CarrierIDs                 []string `json:"carrier_ids"`
}

type eightAgentCampaignReport struct {
	Schema          string                `json:"schema"`
	Network         string                `json:"network"`
	StartedAt       string                `json:"started_at"`
	UpdatedAt       string                `json:"updated_at"`
	RequestedRunSec int64                 `json:"requested_run_seconds"`
	Results         []eightAgentJobResult `json:"results"`
}

type campaignRuntime struct {
	definition eightAgentManifestEntry
	cfg        *config.Config
	provider   providers.LLMProvider
	model      string
	identity   ed25519.PrivateKey
	authority  *PersonalAuthority
	fence      commerce.WriterFence
	publisher  *PublicationManager
	payment    *TOSCTLPaymentSink
	learning   ExecutionLearningRecorder
	collector  Collector
}

type campaignIntentAuthority map[string]ed25519.PublicKey

func (authority campaignIntentAuthority) AuthorizeIntentKey(agentID string, publicKey ed25519.PublicKey, _ time.Time) error {
	expected, ok := authority[agentID]
	if !ok || !expected.Equal(publicKey) {
		return errors.New("campaign Intent key is not pinned")
	}
	return nil
}

type boundedCampaignEstimator struct {
	AI          LLMEconomicEstimator
	Price       uint64
	MaximumCost uint64
}

func (estimator boundedCampaignEstimator) Estimate(ctx context.Context, intent commerce.SignedAgentIntent,
	inventory InventorySnapshot) (EconomicEstimate, error) {
	return estimator.EstimateWithContent(ctx, intent, intent.Body.Payload.DetailDescriptor.InlineContent, inventory)
}

func (estimator boundedCampaignEstimator) EstimateWithContent(ctx context.Context, intent commerce.SignedAgentIntent,
	detail []byte, inventory InventorySnapshot) (EconomicEstimate, error) {
	estimate, err := estimator.AI.EstimateWithContent(ctx, intent, detail, inventory)
	if err == nil && estimate.RevenueAtomic == strconv.FormatUint(estimator.Price, 10) {
		if campaignEstimateWithinOwnerBounds(estimate, estimator.MaximumCost) {
			return estimate, nil
		}
	}
	now := time.Now().UTC()
	return EconomicEstimate{RevenueAtomic: strconv.FormatUint(estimator.Price, 10), PaymentProbabilityPPM: 1_000_000,
		CompletionProbabilityPPM: 1_000_000, ComputeCostAtomic: strconv.FormatUint(estimator.MaximumCost, 10),
		MaximumLossAtomic: strconv.FormatUint(estimator.MaximumCost, 10), EstimatedAtUnix: uint64(now.Unix()),
		ExpiresAtUnix:  uint64(now.Add(10 * time.Minute).Unix()),
		EvidenceDigest: campaignDigest("bounded-owner-fallback:" + intent.Body.ObjectID + ":" + strconv.FormatUint(estimator.Price, 10))}, nil
}

func campaignEstimateWithinOwnerBounds(estimate EconomicEstimate, maximumCost uint64) bool {
	bound := new(big.Int).SetUint64(maximumCost)
	maximumLoss, err := nonnegativeInteger(estimate.MaximumLossAtomic)
	if err != nil || maximumLoss.Cmp(bound) > 0 {
		return false
	}
	total := new(big.Int)
	for _, field := range []string{estimate.ComputeCostAtomic, estimate.ModelCostAtomic, estimate.APICostAtomic,
		estimate.ToolCostAtomic, estimate.SubcontractCostAtomic, estimate.OpportunityCostAtomic,
		estimate.FailureReserveAtomic, estimate.DisputeReserveAtomic, estimate.PrivacyLegalReserveAtomic} {
		value, parseErr := nonnegativeInteger(field)
		if parseErr != nil {
			return false
		}
		total.Add(total, value)
	}
	return total.Cmp(bound) <= 0
}

func eightAgentDefinitions() []eightAgentDefinition {
	return []eightAgentDefinition{
		{Name: "security-auditor", OwnerID: "owner:security-studio", AgentID: "agent:security-auditor", AuthorityID: "authority:security-studio", Wallet: "pilot-security-seller", Capability: "secure-code-review", Taxonomy: "security", ModelKind: "claude", Template: "security-auditor", Price: 500_000, MaximumCost: 80_000, Tasks: []string{
			"Audit a bounded authentication state machine for replay, confused-deputy, and stale-session risks. Return ranked findings and concrete invariants.",
			"Audit a bounded webhook verifier design for signature wrapping, timestamp replay, and key rotation races. Return ranked remediation.",
			"Audit a bounded capability-token verifier for scope escalation, audience confusion, and revocation races. Return ranked remediation.",
		}},
		{Name: "software-builder", OwnerID: "owner:software-studio", AgentID: "agent:software-builder", AuthorityID: "authority:software-studio", Wallet: "pilot-software-seller", Capability: "bounded-code-implementation", Taxonomy: "software", ModelKind: "codex", Template: "software-builder", Price: 750_000, MaximumCost: 150_000, Tasks: []string{
			"Implement a self-contained Go function ParseAtomicAmount with strict canonical decimal validation and table-driven tests. Return code only plus a short rationale.",
			"Implement a self-contained Go bounded retry classifier with explicit ambiguous state and table-driven tests. Return code plus invariants.",
			"Implement a self-contained Go stable action ID helper using domain-separated SHA-256 and mutation tests. Return code plus invariants.",
		}},
		{Name: "evidence-verifier", OwnerID: "owner:evidence-studio", AgentID: "agent:evidence-verifier", AuthorityID: "authority:evidence-studio", Wallet: "pilot-evidence-seller", Capability: "release-evidence-verification", Taxonomy: "evidence", ModelKind: "codex", Template: "evidence-verifier", Price: 300_000, MaximumCost: 50_000, Tasks: []string{
			"Verify a release claim with pinned commit, Linux tests, Windows compile, artifact digest, signer identity, and reproducible command. Return PASS/FAIL per field.",
			"Verify a Carrier independence claim with operator, store, upstream, implementation, and source-loss evidence. Return PASS/FAIL per failure domain.",
			"Verify a payment-finality claim with exact transfer, destination credit, quorum views, network identity, and reorg window. Return PASS/FAIL per field.",
		}},
		{Name: "storage-provider", OwnerID: "owner:storage-studio", AgentID: "agent:storage-provider", AuthorityID: "authority:storage-studio", Wallet: "pilot-storage-seller", Capability: "content-retention", Taxonomy: "storage", ModelKind: "claude", Template: "security-auditor", Price: 250_000, MaximumCost: 40_000, Tasks: []string{
			"Design a content-addressed retention manifest for one 64 KiB object, including digest, replica policy, expiry, retrieval proof, and deletion evidence.",
			"Evaluate an immutable object retention request and return a bounded replica placement and integrity-check schedule without claiming unavailable storage.",
			"Produce a deterministic retention receipt schema binding object digest, byte size, expiry, replica set, and periodic verification evidence.",
		}},
		{Name: "data-curator", OwnerID: "owner:data-studio", AgentID: "agent:data-curator", AuthorityID: "authority:data-studio", Wallet: "pilot-data-curator", Capability: "data-normalization", Taxonomy: "data", ModelKind: "codex", Template: "software-builder", Price: 220_000, MaximumCost: 35_000, Tasks: []string{
			"Normalize a small task catalog into stable category, keywords, amount band, date window, and provenance fields. Return canonical JSON schema guidance.",
			"Deduplicate a conceptual Intent feed using immutable digest, revision lineage, issuer, and source-local cursor. Return deterministic rules.",
			"Design a bounded two-stage retrieval card for a mixed service catalog with diversity and source provenance. Return canonical field rules.",
		}},
		{Name: "localization-writer", OwnerID: "owner:localization-studio", AgentID: "agent:localization-writer", AuthorityID: "authority:localization-studio", Wallet: "pilot-localization-writer", Capability: "technical-localization", Taxonomy: "localization", ModelKind: "claude", Template: "security-auditor", Price: 180_000, MaximumCost: 30_000, Tasks: []string{
			"Localize a short Agent commerce error catalog into concise Simplified Chinese while preserving identifiers and security meaning.",
			"Localize a short decentralized discovery operator guide into concise Japanese while preserving protocol names and exact commands.",
			"Create a terminology-safe bilingual glossary for Agreement, obligation, evidence, settlement, Carrier, and writer fence.",
		}},
		{Name: "transaction-operator", OwnerID: "owner:transaction-studio", AgentID: "agent:transaction-operator", AuthorityID: "authority:transaction-studio", Wallet: "pilot-transaction-operator", Capability: "transaction-reliability", Taxonomy: "transaction", ModelKind: "codex", Template: "software-builder", Price: 280_000, MaximumCost: 45_000, Tasks: []string{
			"Diagnose a transaction stuck after ambiguous broadcast and return a safe query-before-retry recovery procedure with stable action identity.",
			"Design a bounded transaction-relayer request envelope with fee quote, expiry, idempotency, finality, and anti-replay fields.",
			"Evaluate a gas-readiness failure and return a deterministic preflight checklist for balance, fees, sequence, endpoint quorum, and expiry.",
		}},
		{Name: "guarantor-analyst", OwnerID: "owner:guarantor-studio", AgentID: "agent:guarantor-analyst", AuthorityID: "authority:guarantor-studio", Wallet: "pilot-guarantor-analyst", Capability: "agreement-risk-analysis", Taxonomy: "risk", ModelKind: "claude", Template: "security-auditor", Price: 350_000, MaximumCost: 60_000, Tasks: []string{
			"Score a two-party postpaid Agreement for counterparty, delivery, evidence, cancellation, and settlement risk. Recommend a bounded guarantee structure.",
			"Design a decentralized guarantor quote binding Agreement digest, covered obligations, maximum loss, collateral, expiry, and dispute evidence.",
			"Review a milestone Agreement and return guarantor admission rules that prevent double coverage, stale writer use, and aggregate exposure overflow.",
		}},
	}
}

// TestPrepareEightOpenFoxCampaign creates only owner-private local runtime
// material. Chain Agent Accounts must already exist; this test never funds or
// deploys them and never prints private keys or Carrier tokens.
func TestPrepareEightOpenFoxCampaign(t *testing.T) {
	if os.Getenv("OPENFOX_PREPARE_EIGHT_AGENT_CAMPAIGN") != "1" {
		t.Skip("set OPENFOX_PREPARE_EIGHT_AGENT_CAMPAIGN=1")
	}
	root := mustEnv(t, "OPENFOX_EIGHT_AGENT_CAMPAIGN_ROOT")
	tosctl := mustEnv(t, "OPENFOX_TOSCTL")
	primary := mustEnv(t, "OPENFOX_TOSCTL_PRIMARY_CONFIG")
	vaultURL := mustEnv(t, "OPENFOX_TOS_VAULT_URL")
	readToken := readOwnerText(t, filepath.Join(root, "carrier-control", "read.token"), 8192)
	writeToken := readOwnerText(t, filepath.Join(root, "carrier-control", "write.token"), 8192)
	targets := campaignWalletTargets(t, tosctl, primary, vaultURL)
	definitions := eightAgentDefinitions()
	entries := make([]eightAgentManifestEntry, 0, len(definitions))
	identityPins := map[string]string{}
	for _, definition := range definitions {
		directory := filepath.Join(root, "agents", definition.Name)
		state := filepath.Join(directory, "state")
		workspace := filepath.Join(directory, "workspace")
		campaignOwnerID := "owner:eight-campaign:" + definition.Name
		campaignAgentID := "agent:eight-campaign:" + definition.Name
		campaignAuthorityID := "authority:eight-campaign:" + definition.Name
		for _, path := range []string{directory, state, workspace, filepath.Join(state, "campaign-authority-v2"), filepath.Join(state, "identity")} {
			if err := os.MkdirAll(path, 0o700); err != nil {
				t.Fatal(err)
			}
			_ = os.Chmod(path, 0o700)
		}
		authority := ensureCampaignKey(t, filepath.Join(state, "campaign-authority-v2", "authority-ed25519.key"))
		identity := ensureCampaignKey(t, filepath.Join(state, "identity", "agent-ed25519.key"))
		identityPins[campaignAgentID] = "ed25519:" + hex.EncodeToString(identity.Public().(ed25519.PublicKey))
		target, ok := targets[definition.Wallet]
		if !ok {
			t.Fatalf("Agent Account target for %s is unavailable", definition.Wallet)
		}
		entries = append(entries, eightAgentManifestEntry{Name: definition.Name, OwnerID: campaignOwnerID, AgentID: campaignAgentID,
			AuthorityID: campaignAuthorityID, Wallet: definition.Wallet, Target: target, Capability: definition.Capability,
			Taxonomy: definition.Taxonomy, ModelKind: definition.ModelKind, ConfigDirectory: directory,
			AuthorityPin: "ed25519:" + hex.EncodeToString(authority.Public().(ed25519.PublicKey)), IdentityPin: identityPins[campaignAgentID],
			Price: definition.Price, MaximumCost: definition.MaximumCost, Tasks: append([]string(nil), definition.Tasks...)})
	}
	for index, definition := range definitions {
		entry := entries[index]
		templatePath := filepath.Join(root, "agents", definition.Template, "config.json")
		raw, err := os.ReadFile(templatePath)
		if err != nil {
			t.Fatal(err)
		}
		var document map[string]any
		if json.Unmarshal(raw, &document) != nil {
			t.Fatalf("invalid template config %s", templatePath)
		}
		configureCampaignDocument(t, document, entry, identityPins, readToken, writeToken)
		encoded, err := json.MarshalIndent(document, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		configPath := filepath.Join(entry.ConfigDirectory, "config.json")
		if err := fileutil.WriteFileAtomic(configPath, encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := config.LoadConfig(configPath); err != nil {
			t.Fatalf("validate %s: %v", definition.Name, err)
		}
	}
	manifest := eightAgentManifest{Schema: eightAgentCampaignSchema, CreatedAt: time.Now().UTC().Format(time.RFC3339), Agents: entries}
	writeCampaignJSON(t, filepath.Join(root, "eight-agent-manifest.json"), manifest)
	t.Logf("prepared eight-agent manifest=%s", filepath.Join(root, "eight-agent-manifest.json"))
}

func configureCampaignDocument(t *testing.T, document map[string]any, entry eightAgentManifestEntry,
	identityPins map[string]string, readToken, writeToken string) {
	t.Helper()
	agents := document["agents"].(map[string]any)
	defaults := agents["defaults"].(map[string]any)
	defaults["workspace"] = filepath.Join(entry.ConfigDirectory, "workspace")
	modelName := "codex-subscription-personal"
	if entry.ModelKind == "claude" {
		modelName = "claude-code-personal"
	}
	defaults["model_name"] = modelName
	models := document["model_list"].([]any)
	model := models[0].(map[string]any)
	model["model_name"] = modelName
	model["workspace"] = filepath.Join(entry.ConfigDirectory, "workspace")
	backend := model["agent_backend"].(map[string]any)
	backend["timeout_seconds"] = float64(300)
	backend["owner_principal"] = map[string]any{"channel": "pilot-owner", "sender_id": entry.OwnerID}
	evolutionMode := strings.ToLower(strings.TrimSpace(os.Getenv("OPENFOX_CAMPAIGN_EVOLUTION_MODE")))
	if evolutionMode == "" {
		evolutionMode = "apply"
	}
	if evolutionMode != "observe" && evolutionMode != "draft" && evolutionMode != "apply" {
		t.Fatalf("OPENFOX_CAMPAIGN_EVOLUTION_MODE must be observe, draft, or apply")
	}
	document["evolution"] = map[string]any{"enabled": true, "mode": evolutionMode,
		"state_dir": filepath.Join(entry.ConfigDirectory, "state", "evolution"), "min_task_count": 2,
		"min_success_ratio": 0.7, "cold_path_trigger": "after_turn"}
	earning := document["earning"].(map[string]any)
	earning["state_dir"] = filepath.Join(entry.ConfigDirectory, "state")
	earning["owner_id"], earning["agent_id"], earning["authority_id"] = entry.OwnerID, entry.AgentID, entry.AuthorityID
	earning["trusted_intent_issuer_keys"] = identityPins
	earning["carriers"] = []any{
		map[string]any{"kind": "http", "id": "carrier:gateway-local-pilot", "endpoint": "http://127.0.0.1:18191/v1/intents", "read_token": readToken, "relay_token": writeToken},
		map[string]any{"kind": "http", "id": "carrier:messenger-local-pilot", "endpoint": "http://127.0.0.1:18192/v1/intents", "read_token": readToken, "relay_token": writeToken},
	}
	earning["capabilities"] = []any{map[string]any{"namespace": "tos.skill", "identifier": entry.Capability,
		"version": "1.0.0", "evidence_digest": campaignDigest("capability:" + entry.Capability), "offer": map[string]any{
			"asset_namespace": "tos.asset", "asset_identifier": "native", "unit": "nanotos",
			"minimum_revenue_atomic": strconv.FormatUint(entry.Price, 10), "maximum_revenue_atomic": strconv.FormatUint(entry.Price, 10),
			"maximum_unit_cost_atomic": strconv.FormatUint(entry.MaximumCost, 10), "settlement_adapter_uri": "tos.payment.direct.v1",
			"taxonomy_prefixes": []any{"tos.taxonomy.v1/service/" + entry.Taxonomy + "/pilot"},
			"required_keywords": []any{entry.Capability}, "minimum_ttl_seconds": 3600, "maximum_ttl_seconds": 86400,
		}}}
	publication := earning["publication"].(map[string]any)
	publication["maximum_active"] = float64(64)
	publication["maximum_publications_per_period"] = float64(64)
	publication["period_seconds"] = float64(86400)
}

func campaignWalletTargets(t *testing.T, tosctl, configPath, vaultURL string) map[string]string {
	t.Helper()
	command := exec.Command(tosctl, "agent", "wallet", "ls", "-c", configPath, "--format", "json")
	command.Env = append(os.Environ(), "VAULT_URL="+vaultURL)
	raw, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	var wallets []struct {
		Name    string  `json:"name"`
		Account *string `json:"agent_account_address"`
	}
	if json.Unmarshal(raw, &wallets) != nil {
		t.Fatal("invalid Agent Wallet inventory")
	}
	out := map[string]string{}
	for _, wallet := range wallets {
		if wallet.Account != nil && strings.HasPrefix(*wallet.Account, "0:") {
			out[wallet.Name] = *wallet.Account
		}
	}
	return out
}

func ensureCampaignKey(t *testing.T, path string) ed25519.PrivateKey {
	t.Helper()
	if raw, err := os.ReadFile(path); err == nil {
		if len(raw) != ed25519.PrivateKeySize {
			t.Fatalf("invalid campaign key %s", path)
		}
		return ed25519.PrivateKey(raw)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.Write(key); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func readOwnerText(t *testing.T, path string, maximum int64) string {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > maximum {
		t.Fatalf("owner-only input is invalid: %s", path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(raw))
}

func writeCampaignJSON(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := fileutil.WriteFileAtomic(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func campaignDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func TestPublishEightOpenFoxSupply(t *testing.T) {
	if os.Getenv("OPENFOX_PUBLISH_EIGHT_AGENT_SUPPLY") != "1" {
		t.Skip("set OPENFOX_PUBLISH_EIGHT_AGENT_SUPPLY=1")
	}
	root := mustEnv(t, "OPENFOX_EIGHT_AGENT_CAMPAIGN_ROOT")
	manifest := loadEightAgentManifest(t, filepath.Join(root, "eight-agent-manifest.json"))
	runtimes := openCampaignRuntimes(t, root, manifest)
	defer closeCampaignRuntimes(runtimes)
	for _, runtime := range runtimes {
		now := time.Now().UTC().Truncate(time.Second)
		detail := []byte("Owner-bounded " + runtime.definition.Capability + " service. Exact scope is negotiated and frozen in a typed Agreement before execution.")
		body := commerce.AgentIntentBody{SchemaVersion: 1, NetworkID: "tos:local-three-node", IssuerAgentID: runtime.definition.AgentID,
			Audience: "public:indexable", ObjectID: "intent:" + strings.TrimPrefix(campaignDigest("supply:"+runtime.definition.AgentID+now.Format(time.RFC3339Nano)), "sha256:"),
			Revision: 1, CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(12 * time.Hour).Unix()),
			Payload: commerce.AgentIntentPayload{DiscoveryCard: commerce.DiscoveryCard{Summary: "Owner-bounded " + runtime.definition.Capability + " service",
				IntentModes: []commerce.IntentMode{commerce.IntentOffer}, SubjectClasses: []commerce.SubjectClass{commerce.SubjectService},
				TaxonomyPaths: []string{"tos.taxonomy.v1/service/" + runtime.definition.Taxonomy + "/pilot"},
				Keywords:      []commerce.IntentKeyword{{Text: runtime.definition.Capability}}, CapabilityHints: []commerce.CapabilityHint{{Relation: "required",
					CapabilityNamespace: "tos.skill", CapabilityIdentifier: runtime.definition.Capability}}, ValueState: commerce.ValueSpecified,
				ValueHints: []commerce.ValueHint{{Role: "price", AssetNamespace: "tos.asset", AssetIdentifier: "native", AmountKind: "exact",
					MinimumDecimal: strconv.FormatUint(runtime.definition.Price, 10), MaximumDecimal: strconv.FormatUint(runtime.definition.Price, 10), Unit: "nanotos"}},
				Schedule: commerce.IntentSchedule{Flexibility: "flexible"}, FulfillmentModes: []string{"remote"}},
				DetailDescriptor: commerce.ContentDescriptor{ContentType: "text/plain", ContentDigest: campaignDigest(string(detail)), ContentSize: uint64(len(detail)), InlineContent: detail},
				ReplyRoutes:      []commerce.ReplyRoute{{ProfileURI: "tos.messenger.direct.v1", AgentID: runtime.definition.AgentID}},
				SettlementPreferences: []commerce.SettlementPreference{{AdapterURI: "tos.payment.direct.v1", Required: true,
					Parameters: []byte(`{"network_id":"tos:local-three-node","asset":"native","unit":"nanotos"}`)}}}}
		draft := PublicationDraft{Body: body, Economics: PublicationEconomics{RevenueAtomic: strconv.FormatUint(runtime.definition.Price, 10),
			UnitCostAtomic: strconv.FormatUint(runtime.definition.MaximumCost, 10), AssetNamespace: "tos.asset", AssetIdentifier: "native",
			ValueHintRole: "price", Unit: "nanotos", EvidenceDigest: campaignDigest("pricing:" + runtime.definition.AgentID),
			ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}}
		record, err := runtime.publisher.Publish(t.Context(), draft,
			[]string{"carrier:gateway-local-pilot", "carrier:messenger-local-pilot"}, 1, runtime.fence)
		if err != nil {
			t.Fatalf("publish %s: %v", runtime.definition.Name, err)
		}
		t.Logf("published seller=%s digest=%s", runtime.definition.Name, record.LatestDigest)
	}
}

// TestEightOpenFoxAgenticInternetCampaign runs a wall-clock campaign. It is
// intentionally opt-in because it consumes personal subscription quota and
// local-chain funds. Checkpoints are durable after every settled job.
func TestEightOpenFoxAgenticInternetCampaign(t *testing.T) {
	if os.Getenv("OPENFOX_EIGHT_AGENT_CAMPAIGN") != "1" {
		t.Skip("set OPENFOX_EIGHT_AGENT_CAMPAIGN=1")
	}
	root := mustEnv(t, "OPENFOX_EIGHT_AGENT_CAMPAIGN_ROOT")
	manifest := loadEightAgentManifest(t, filepath.Join(root, "eight-agent-manifest.json"))
	duration := parseCampaignDuration(t, "OPENFOX_EIGHT_AGENT_CAMPAIGN_DURATION", 3*time.Hour)
	interval := parseCampaignDuration(t, "OPENFOX_EIGHT_AGENT_CAMPAIGN_INTERVAL", duration/time.Duration(len(manifest.Agents)*3))
	if duration < 3*time.Hour || interval < 30*time.Second {
		t.Fatal("campaign must preserve three real hours and bounded pacing")
	}
	reportPath := filepath.Join(root, "reports", "eight-agent-campaign-checkpoint.json")
	if err := os.MkdirAll(filepath.Dir(reportPath), 0o700); err != nil {
		t.Fatal(err)
	}
	report := loadOrCreateCampaignReport(t, reportPath, duration)
	runtimes := openCampaignRuntimes(t, root, manifest)
	defer closeCampaignRuntimes(runtimes)

	queue := campaignQueue(manifest)
	completed := map[int]bool{}
	for _, result := range report.Results {
		completed[result.Sequence] = true
	}
	start, err := time.Parse(time.RFC3339Nano, report.StartedAt)
	if err != nil {
		t.Fatal(err)
	}
	for sequence, item := range queue {
		if completed[sequence] {
			continue
		}
		due := start.Add(time.Duration(sequence) * interval)
		if delay := time.Until(due); delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-t.Context().Done():
				timer.Stop()
				t.Fatal(t.Context().Err())
			case <-timer.C:
			}
		}
		var result eightAgentJobResult
		var jobErr error
		for attempt := 0; attempt < 3; attempt++ {
			result, jobErr = runEightAgentJob(t.Context(), root, sequence, item.round, attempt,
				runtimes[item.buyer], runtimes[item.seller], item.task, due)
			if jobErr == nil {
				break
			}
			var retryable retryableCampaignJobError
			if !errors.As(jobErr, &retryable) || attempt == 2 {
				break
			}
			for _, runtime := range []*campaignRuntime{runtimes[item.seller], runtimes[item.buyer]} {
				engine := &Engine{OwnerID: runtime.definition.OwnerID, AgentID: runtime.definition.AgentID,
					MandateDigest: runtime.cfg.Earning.MandateDigest, Authority: runtime.authority}
				if _, reconcileErr := engine.ReconcileApply(t.Context(), 1, runtime.fence); reconcileErr != nil {
					t.Fatalf("campaign job %d retry reconciliation: %v", sequence, reconcileErr)
				}
			}
			t.Logf("safe retry sequence=%d attempt=%d error=%v", sequence, attempt+1, jobErr)
		}
		if jobErr != nil {
			t.Fatalf("campaign job %d buyer=%s seller=%s: %v", sequence,
				manifest.Agents[item.buyer].Name, manifest.Agents[item.seller].Name, jobErr)
		}
		report.Results = append(report.Results, result)
		report.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		writeCampaignJSON(t, reportPath, report)
		if campaignResultSettled(result) {
			t.Logf("settled sequence=%d round=%d buyer=%s seller=%s tx=%s skills=%d->%d", sequence, item.round,
				result.Buyer, result.Seller, result.PaymentTransaction, len(result.SkillsBefore), len(result.SkillsAfter))
		} else {
			t.Logf("declined sequence=%d round=%d buyer=%s seller=%s reason=%s", sequence, item.round,
				result.Buyer, result.Seller, result.Disposition)
		}
	}
	if remaining := start.Add(duration).Sub(time.Now()); remaining > 0 {
		timer := time.NewTimer(remaining)
		select {
		case <-t.Context().Done():
			timer.Stop()
			t.Fatal(t.Context().Err())
		case <-timer.C:
		}
	}
	report.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	writeCampaignJSON(t, reportPath, report)
	writeCampaignSummaries(t, root, report, manifest)
	t.Logf("eight-agent campaign completed report=%s", reportPath)
}

type queuedCampaignJob struct {
	round, buyer, seller int
	task                 string
}

type retryableCampaignJobError struct{ err error }

func (failure retryableCampaignJobError) Error() string { return failure.err.Error() }
func (failure retryableCampaignJobError) Unwrap() error { return failure.err }

func campaignQueue(manifest eightAgentManifest) []queuedCampaignJob {
	queue := make([]queuedCampaignJob, 0, len(manifest.Agents)*3)
	for round := 0; round < 3; round++ {
		for seller := range manifest.Agents {
			buyer := (seller + round + 1) % len(manifest.Agents)
			queue = append(queue, queuedCampaignJob{round: round + 1, buyer: buyer, seller: seller,
				task: manifest.Agents[seller].Tasks[round]})
		}
	}
	return queue
}

func loadEightAgentManifest(t *testing.T, path string) eightAgentManifest {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var manifest eightAgentManifest
	if json.Unmarshal(raw, &manifest) != nil || manifest.Schema != eightAgentCampaignSchema || len(manifest.Agents) != 8 {
		t.Fatal("eight-agent manifest is invalid")
	}
	return manifest
}

func parseCampaignDuration(t *testing.T, name string, fallback time.Duration) time.Duration {
	t.Helper()
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return duration
}

func loadOrCreateCampaignReport(t *testing.T, path string, duration time.Duration) eightAgentCampaignReport {
	t.Helper()
	if raw, err := os.ReadFile(path); err == nil {
		var report eightAgentCampaignReport
		if json.Unmarshal(raw, &report) != nil || report.Schema != eightAgentCampaignSchema || report.RequestedRunSec != int64(duration/time.Second) {
			t.Fatal("campaign checkpoint is incompatible")
		}
		return report
	}
	now := time.Now().UTC()
	report := eightAgentCampaignReport{Schema: eightAgentCampaignSchema, Network: "tos:local-three-node",
		StartedAt: now.Format(time.RFC3339Nano), UpdatedAt: now.Format(time.RFC3339Nano), RequestedRunSec: int64(duration / time.Second)}
	writeCampaignJSON(t, path, report)
	return report
}

func openCampaignRuntimes(t *testing.T, root string, manifest eightAgentManifest) []*campaignRuntime {
	t.Helper()
	trustedIntents := campaignIntentAuthority{}
	for _, entry := range manifest.Agents {
		encoded := strings.TrimPrefix(entry.IdentityPin, "ed25519:")
		publicKey, decodeErr := hex.DecodeString(encoded)
		if decodeErr != nil || len(publicKey) != ed25519.PublicKeySize || encoded == entry.IdentityPin {
			t.Fatalf("campaign identity pin is invalid for %s", entry.Name)
		}
		trustedIntents[entry.AgentID] = ed25519.PublicKey(publicKey)
	}
	runtimes := make([]*campaignRuntime, 0, len(manifest.Agents))
	for _, entry := range manifest.Agents {
		cfg, err := config.LoadConfig(filepath.Join(entry.ConfigDirectory, "config.json"))
		if err != nil {
			t.Fatal(err)
		}
		provider, model, err := providers.CreateProvider(cfg)
		if err != nil {
			t.Fatal(err)
		}
		authorityKey := readPilotPrivateKey(t, filepath.Join(cfg.Earning.StateDir, "campaign-authority-v2", "authority-ed25519.key"))
		identityKey := readPilotPrivateKey(t, filepath.Join(cfg.Earning.StateDir, "identity", "agent-ed25519.key"))
		authority, err := OpenPersonalAuthority(filepath.Join(cfg.Earning.StateDir, "campaign-authority-v2"), entry.OwnerID, entry.AgentID,
			entry.AuthorityID, authorityKey, PortfolioLimits{ComputeUnits: 64, SpendAtomic: 1_000_000_000,
				ReceivableAtomic: 1_000_000_000, MaximumLossAtomic: 1_000_000_000})
		if err != nil {
			t.Fatal(err)
		}
		fence, err := authority.AcquireWriter(t.Context(), "writer:eight-agent:"+entry.Name,
			[]string{"billing.materialize", "billing.resolve", "delivery.release", "execution.prepare", "execution.start", "payment.direct", "portfolio.release", "portfolio.reserve", "publication.publish"}, 4*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		engine := &Engine{OwnerID: entry.OwnerID, AgentID: entry.AgentID, MandateDigest: cfg.Earning.MandateDigest,
			Gates: FeatureGates{Publication: true, Execution: true}, Authority: authority, PublicationSinks: map[string]PublicationSink{},
			Collector: Collector{Authority: trustedIntents}}
		if _, reconcileErr := engine.ReconcileApply(t.Context(), 1, fence); reconcileErr != nil {
			t.Fatalf("startup reconciliation %s: %v", entry.Name, reconcileErr)
		}
		for _, carrier := range cfg.Earning.Carriers {
			sink, sinkErr := NewHTTPPublicationSink(carrier.ID, carrier.Endpoint, carrier.RelayToken.String(), 30*time.Second)
			if sinkErr != nil {
				t.Fatal(sinkErr)
			}
			engine.PublicationSinks[carrier.ID] = sink
		}
		inventory := InventorySourceFunc(func(context.Context) (InventorySnapshot, error) {
			now := time.Now().UTC()
			return InventorySnapshot{OwnerID: entry.OwnerID, AgentID: entry.AgentID, CreatedAtUnix: uint64(now.Add(-time.Second).Unix()),
				ExpiresAtUnix: uint64(now.Add(10 * time.Minute).Unix()), SourceGeneration: 1, PortfolioRevision: 1, PolicyRevision: 1,
				ConsistencyToken: campaignDigest("inventory:" + entry.AgentID), Available: ResourceCapacity{CPUUnits: 64},
				Capabilities: []Capability{{Namespace: "tos.skill", Identifier: entry.Capability, Version: "1.0.0", State: CapabilityReady,
					Authority: entry.AuthorityID, EvidenceDigest: campaignDigest("capability:" + entry.Capability), RevocationGeneration: 1,
					ExpiresAtUnix: uint64(now.Add(10 * time.Minute).Unix())}},
				SupportedSettlementAdapters: []string{"tos.payment.direct.v1"}}, nil
		})
		carriers := make([]Carrier, 0, len(cfg.Earning.Carriers))
		for _, carrierConfig := range cfg.Earning.Carriers {
			carrier, carrierErr := NewHTTPCarrier(carrierConfig.ID, carrierConfig.Endpoint, carrierConfig.ReadToken.String(), 30*time.Second)
			if carrierErr != nil {
				t.Fatal(carrierErr)
			}
			carriers = append(carriers, carrier)
		}
		collector := Collector{Carriers: carriers, Authority: trustedIntents, Inventory: inventory,
			Estimator: boundedCampaignEstimator{AI: LLMEconomicEstimator{Provider: provider, Model: model}, Price: entry.Price, MaximumCost: entry.MaximumCost},
			Policy: EconomicPolicy{MinimumExpectedProfitAtomic: "1", MinimumROIPPM: 1, MaximumLossAtomic: strconv.FormatUint(entry.Price, 10),
				MinimumPaymentProbabilityPPM: 500_000, MinimumCompletionProbabilityPPM: 500_000},
			Shortlist: ShortlistPolicy{Size: 16, MaximumPerIssuer: 4, MaximumPerSource: 16, MaximumPerTaxonomy: 16, MaximumPerValueBand: 16}}
		publisher, err := OpenPublicationManager(filepath.Join(cfg.Earning.StateDir, "campaign-publications-v3"), engine, inventory, identityKey,
			PublicationPolicy{MinimumTTL: time.Hour, MaximumTTL: 24 * time.Hour, MinimumMarginPPM: 100_000,
				MaximumPriceChangePPM: 1_000_000, MaximumActive: 64, MaximumRevisionsPerObject: 3,
				MaximumPublicationsPerPeriod: 64, Period: 24 * time.Hour, AllowedAudiences: []string{"public:indexable"}, AllowDemand: true})
		if err != nil {
			t.Fatal(err)
		}
		learning, err := NewEvolutionExecutionLearningRecorder(cfg.Evolution, cfg.WorkspacePath(), entry.AgentID, provider, model,
			entry.Capability)
		if err != nil {
			t.Fatal(err)
		}
		custodyDirectory := filepath.Join(root, "campaign", "custody", entry.Name)
		if err := os.MkdirAll(custodyDirectory, 0o700); err != nil {
			t.Fatal(err)
		}
		bindCampaignPayer(t, entry, authorityKey, custodyDirectory)
		payment := &TOSCTLPaymentSink{Authority: authority, Executable: mustEnv(t, "OPENFOX_TOSCTL"),
			ConfigPath: mustEnv(t, "OPENFOX_TOSCTL_PRIMARY_CONFIG"), Wallet: entry.Wallet, SourceAccount: entry.Target,
			NetworkGlobalID: 3, FeeReserveNanoTOS: 50_000_000,
			RelayNetworkDomain:  liveTOSCustodyNetworkDomain(t, "tos:local-three-node", 3),
			QuorumConfigPaths:   []string{mustEnv(t, "OPENFOX_TOSCTL_QUORUM_CONFIG_2"), mustEnv(t, "OPENFOX_TOSCTL_QUORUM_CONFIG_3")},
			MaximumTransactions: 1000, VaultURL: mustEnv(t, "OPENFOX_TOS_VAULT_URL"),
			EvidenceDirectory: filepath.Join(root, "campaign", "payment-evidence", entry.Name), ResolveAttempts: 60, ResolveInterval: time.Second}
		runtimes = append(runtimes, &campaignRuntime{definition: entry, cfg: cfg, provider: provider, model: model, identity: identityKey,
			authority: authority, fence: fence, publisher: publisher, payment: payment, learning: learning, collector: collector})
	}
	return runtimes
}

func bindCampaignPayer(t *testing.T, entry eightAgentManifestEntry, key ed25519.PrivateKey, journal string) {
	t.Helper()
	command := exec.Command(mustEnv(t, "OPENFOX_TOSCTL"), "agent", "wallet", "bind-runtime", "--name", entry.Wallet,
		"--runner-id", "openfox-eight-agent-campaign", "--endpoint", "local://openfox/eight-agent-campaign",
		"--economic-authority-id", entry.AuthorityID, "--economic-authority-public-key", hex.EncodeToString(key.Public().(ed25519.PublicKey)),
		"--economic-custody-journal-directory", journal, "-c", mustEnv(t, "OPENFOX_TOSCTL_PRIMARY_CONFIG"), "--format", "json")
	command.Env = append(os.Environ(), "VAULT_URL="+mustEnv(t, "OPENFOX_TOS_VAULT_URL"))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("bind %s: %v: %s", entry.Name, err, output)
	}
}

func closeCampaignRuntimes(runtimes []*campaignRuntime) {
	for _, runtime := range runtimes {
		if runtime.publisher != nil {
			_ = runtime.publisher.Close()
		}
		if runtime.authority != nil {
			_ = runtime.authority.Close()
		}
		if closeable, ok := runtime.provider.(providers.StatefulProvider); ok {
			closeable.Close()
		}
	}
}

func runEightAgentJob(ctx context.Context, root string, sequence, round, attempt int, buyer, seller *campaignRuntime,
	task string, scheduledAt time.Time) (result eightAgentJobResult, err error) {
	paymentStarted := false
	defer func() {
		if err != nil && !paymentStarted {
			err = retryableCampaignJobError{err: err}
		}
	}()
	if buyer == nil || seller == nil || buyer == seller {
		return eightAgentJobResult{}, errors.New("campaign counterparties are invalid")
	}
	now := scheduledAt.UTC().Truncate(time.Second)
	demand, err := publishCampaignDemand(ctx, sequence, buyer, seller, task, now)
	if err != nil {
		return eightAgentJobResult{}, err
	}
	assessments, err := seller.collector.Collect(ctx, IntentQuery{Modes: []commerce.IntentMode{commerce.IntentRequest},
		SubjectClasses: []commerce.SubjectClass{commerce.SubjectService},
		TaxonomyPrefix: "tos.taxonomy.v1/service/" + seller.definition.Taxonomy + "/pilot",
		Keywords:       []string{seller.definition.Capability}, MaximumResults: 100})
	if err != nil {
		return eightAgentJobResult{}, fmt.Errorf("market discovery and economic analysis: %w", err)
	}
	var selected CandidateAssessment
	for _, assessment := range assessments {
		if assessment.IntentDigest == demand {
			selected = assessment
			break
		}
	}
	if selected.IntentDigest == "" || len(selected.CarrierIDs) != 2 {
		return eightAgentJobResult{}, errors.New("seller did not independently discover the two-Carrier opportunity")
	}
	analysisMode := "ai"
	if selected.Estimate.EvidenceDigest == campaignDigest("bounded-owner-fallback:"+selected.Intent.Body.ObjectID+":"+strconv.FormatUint(seller.definition.Price, 10)) {
		analysisMode = "bounded-owner-fallback"
	}
	if !selected.Decision.Eligible {
		return eightAgentJobResult{Sequence: sequence, Round: round, Disposition: "declined:" + selected.Decision.Reason,
			Buyer: buyer.definition.Name, Seller: seller.definition.Name, Capability: seller.definition.Capability,
			DemandIntentDigest: demand, EconomicEvidenceDigest: selected.Estimate.EvidenceDigest,
			EconomicAnalysisMode: analysisMode, ExpectedNetNanoTOS: selected.Decision.ExpectedNetAtomic,
			CompletedAt: time.Now().UTC().Format(time.RFC3339Nano), CarrierIDs: append([]string(nil), selected.CarrierIDs...)}, nil
	}
	body, err := campaignAgreement(sequence, attempt, buyer.definition, seller.definition, task, now)
	if err != nil {
		return eightAgentJobResult{}, err
	}
	digest, _ := commerce.AgreementBodyDigest(body)
	for _, participant := range []*campaignRuntime{seller, buyer} {
		if _, err = participant.authority.RecordAgreementProposal(body, buyer.definition.AgentID,
			"evt_"+strings.TrimPrefix(campaignDigest("proposal:"+digest), "sha256:"), campaignDigest("envelope:"+digest)); err != nil {
			return eightAgentJobResult{}, err
		}
	}
	resolver := agreementKeyResolver{buyer.definition.AgentID: buyer.identity.Public().(ed25519.PublicKey),
		seller.definition.AgentID: seller.identity.Public().(ed25519.PublicKey)}
	verifier := AgreementEvidenceRouter{AgentAuthority: resolver}
	keys := map[string]ed25519.PrivateKey{buyer.definition.AgentID: buyer.identity, seller.definition.AgentID: seller.identity}
	for _, predicate := range body.AuthorizationPredicates {
		acceptance, signErr := commerce.SignAgreementAcceptance(commerce.AgreementAcceptanceBody{AgreementID: body.AgreementID,
			AgreementVersion: body.Version, AgreementBodyDigest: digest, AcceptingSubject: predicate.AuthoritySubject,
			PredicateIDs: []string{predicate.PredicateID}, EvidenceTargetProjectionDigests: []string{predicate.EvidenceTargetProjectionDigest},
			ExpiresAtUnix: body.ExpiresAtUnix}, keys[predicate.AuthoritySubject.SubjectIdentifier])
		if signErr != nil {
			return eightAgentJobResult{}, signErr
		}
		evidence, evidenceErr := commerce.AgentSignatureEvidence(body, acceptance)
		if evidenceErr != nil {
			return eightAgentJobResult{}, evidenceErr
		}
		for _, participant := range []*campaignRuntime{seller, buyer} {
			if _, evidenceErr = participant.authority.RecordAgreementEvidence(digest, evidence, verifier); evidenceErr != nil {
				return eightAgentJobResult{}, evidenceErr
			}
		}
	}
	sellerEngine := &Engine{OwnerID: seller.definition.OwnerID, AgentID: seller.definition.AgentID,
		MandateDigest: seller.cfg.Earning.MandateDigest, Gates: FeatureGates{Execution: true}, Authority: seller.authority}
	buyerEngine := &Engine{OwnerID: buyer.definition.OwnerID, AgentID: buyer.definition.AgentID,
		MandateDigest: buyer.cfg.Earning.MandateDigest, Gates: FeatureGates{Execution: true}, Authority: buyer.authority}
	reservation := ExposureReservation{ReservationID: campaignDigest(fmt.Sprintf("reservation:%d:%s", sequence, digest)), AgreementDigest: digest,
		ComputeUnits: 1, ReceivableAtomic: seller.definition.Price, MaximumLossAtomic: seller.definition.MaximumCost}
	_, record, err := sellerEngine.ReserveAgreement(ctx, digest, reservation, allowSettlement{}, 1, seller.fence)
	if err != nil {
		return eightAgentJobResult{}, err
	}
	buyerReservation := ExposureReservation{ReservationID: campaignDigest(fmt.Sprintf("buyer-reservation:%d:%s", sequence, digest)),
		AgreementDigest: digest, SpendAtomic: seller.definition.Price, MaximumLossAtomic: seller.definition.Price}
	if _, _, err = buyerEngine.ReserveAgreement(ctx, digest, buyerReservation, allowSettlement{}, 1, buyer.fence); err != nil {
		return eightAgentJobResult{}, err
	}
	gateDirectory := filepath.Join(root, "campaign", "execution-gates", seller.definition.Name)
	if err := os.MkdirAll(gateDirectory, 0o700); err != nil {
		return eightAgentJobResult{}, err
	}
	gate, err := commercegate.Open(gateDirectory, seller.authority)
	if err != nil {
		return eightAgentJobResult{}, err
	}
	defer gate.Close()
	acceptedInputDigest, _, _, err := AcceptedExecutionInputSetDigest(record, "work")
	if err != nil {
		return eightAgentJobResult{}, err
	}
	plan := commercegate.Plan{OwnerID: seller.definition.OwnerID, AgentID: seller.definition.AgentID, AgreementBodyDigest: digest,
		ExecutionObligationID: "work", AcceptedInputManifestDigest: acceptedInputDigest, AttemptIndex: 0,
		PredecessorTerminalResolutionDigest: "sha256:" + strings.Repeat("0", 64), ReservationID: reservation.ReservationID,
		PolicyRevision: 1, LeaseLossPolicy: commercegate.LeaseLossKill}
	before := campaignSkillNames(seller.cfg.WorkspacePath())
	deliverableDirectory := filepath.Join(root, "campaign", "deliverables", seller.definition.Name)
	executionStarted := time.Now()
	record, err = (ExecutionService{Engine: sellerEngine, Gate: gate, Prerequisite: funded{}, Runner: LLMTaskRunner{
		Provider: seller.provider, Model: seller.model, Agreement: body, OutputDirectory: deliverableDirectory,
		SkillWorkspace: seller.cfg.WorkspacePath(), Learning: seller.learning}}).Execute(ctx, digest, plan, 1, seller.fence)
	if err != nil {
		return eightAgentJobResult{}, err
	}
	executionElapsed := time.Since(executionStarted)
	manifestDigest := record.ObligationRuntime["work"].ExecutionEvidence[0]
	if _, err = sellerEngine.Deliver(ctx, digest, "work", buyer.definition.AgentID, manifestDigest, acceptedDelivery{}, 1, seller.fence); err != nil {
		return eightAgentJobResult{}, err
	}
	if _, err = buyer.authority.ObserveAgreementDelivery(digest, "work", manifestDigest, seller.definition.AgentID,
		"evt_"+strings.TrimPrefix(campaignDigest("delivery:"+digest), "sha256:")); err != nil {
		return eightAgentJobResult{}, err
	}
	ledgers, record, err := (BillingService{Engine: sellerEngine}).MaterializeAfterDelivery(digest, 1, seller.fence)
	if err != nil || len(ledgers) != 1 {
		return eightAgentJobResult{}, fmt.Errorf("billing ledgers=%d: %w", len(ledgers), err)
	}
	buyerLedgers, _, err := (BillingService{Engine: buyerEngine}).MaterializeAfterDelivery(digest, 1, buyer.fence)
	if err != nil || len(buyerLedgers) != 1 || buyerLedgers[0].Obligation.ObligationInstanceID != ledgers[0].Obligation.ObligationInstanceID {
		return eightAgentJobResult{}, fmt.Errorf("buyer billing projection differs: ledgers=%d: %w", len(buyerLedgers), err)
	}
	request, err := commerce.BuildAgreementPaymentRequest(buyer.definition.OwnerID, buyer.definition.AgentID, "tos:local-three-node",
		[]byte(seller.definition.Target), buyerLedgers[0].Obligation)
	if err != nil {
		return eightAgentJobResult{}, err
	}
	canonical, fields, err := commerce.PaymentAuthorizationMaterial(request)
	if err != nil {
		return eightAgentJobResult{}, err
	}
	action, err := commerce.BuildAuthorizedAction(buyer.definition.OwnerID, buyer.definition.AgentID, "payment.direct", fields, canonical,
		buyer.fence, 1, ledgers[0].Obligation.MandateDigest, "", "pending", request.ExpiresAtUnix)
	if err == nil {
		action, err = buyer.authority.SignAction(action, buyer.fence)
	}
	if err != nil || action.StableActionID != request.StableActionID {
		return eightAgentJobResult{}, errors.New("payment action identity mismatch")
	}
	if _, err = buyer.authority.Admit(action, fields, canonical, buyer.fence, nil); err != nil {
		return eightAgentJobResult{}, err
	}
	settlementStarted := time.Now()
	paymentStarted = true
	paymentEvidence, err := buyer.payment.SubmitPayment(ctx, action, buyer.fence, fields, canonical, request)
	if err != nil {
		return eightAgentJobResult{}, err
	}
	settlementElapsed := time.Since(settlementStarted)
	if _, err = buyer.authority.Transition(action.StableActionID, action.ExactRequestDigest, commerce.ActionAccepted,
		paymentEvidence.ExactTransferReference, []string{paymentEvidence.FinalityReference}); err != nil {
		return eightAgentJobResult{}, err
	}
	if _, _, err = (BillingService{Engine: buyerEngine}).ApplyPayment(request, paymentEvidence, buyer.payment, 1, buyer.fence); err != nil {
		return eightAgentJobResult{}, fmt.Errorf("buyer payment reconciliation: %w", err)
	}
	if _, record, err = (BillingService{Engine: sellerEngine}).ApplyPayment(request, paymentEvidence, buyer.payment, 1, seller.fence); err != nil || record.State != EngagementSettled {
		return eightAgentJobResult{}, fmt.Errorf("provider payment reconciliation state=%s: %w", record.State, err)
	}
	if _, err = sellerEngine.ReconcileApply(ctx, 1, seller.fence); err != nil {
		return eightAgentJobResult{}, fmt.Errorf("seller reservation release: %w", err)
	}
	if _, err = buyerEngine.ReconcileApply(ctx, 1, buyer.fence); err != nil {
		return eightAgentJobResult{}, fmt.Errorf("buyer reservation release: %w", err)
	}
	after := campaignSkillNames(seller.cfg.WorkspacePath())
	return eightAgentJobResult{Sequence: sequence, Round: round, Disposition: "settled", Buyer: buyer.definition.Name, Seller: seller.definition.Name,
		Capability: seller.definition.Capability, DemandIntentDigest: demand, AgreementDigest: digest, ExecutionID: record.ExecutionID,
		DeliverableDigest: manifestDigest, PaymentTransaction: paymentEvidence.ExactTransferReference,
		FinalityReference: paymentEvidence.FinalityReference, RevenueNanoTOS: seller.definition.Price,
		MaximumInternalCostNanoTOS: seller.definition.MaximumCost, ProjectedNetNanoTOS: seller.definition.Price - seller.definition.MaximumCost,
		SkillsBefore: before, SkillsAfter: after, ExecutionElapsedMillis: executionElapsed.Milliseconds(),
		SettlementElapsedMillis: settlementElapsed.Milliseconds(), EconomicEvidenceDigest: selected.Estimate.EvidenceDigest, EconomicAnalysisMode: analysisMode,
		ExpectedNetNanoTOS: selected.Decision.ExpectedNetAtomic, CompletedAt: time.Now().UTC().Format(time.RFC3339Nano),
		CarrierIDs: append([]string(nil), selected.CarrierIDs...)}, nil
}

func publishCampaignDemand(ctx context.Context, sequence int, buyer, seller *campaignRuntime, task string, now time.Time) (string, error) {
	detail := []byte(task)
	objectID := "intent:" + strings.TrimPrefix(campaignDigest(fmt.Sprintf("demand:%d:%s", sequence, task)), "sha256:")
	if existing, found := buyer.publisher.PublicationByObjectID(objectID); found {
		if existing.Latest.Body.IssuerAgentID != buyer.definition.AgentID || existing.Latest.Body.Payload.DetailDescriptor.ContentDigest != campaignDigest(task) ||
			(existing.Status != "active" && existing.Status != "publishing") {
			return "", errors.New("durable campaign demand conflicts with the queued task")
		}
		if existing.Status == "active" {
			return existing.LatestDigest, nil
		}
		recovered, err := buyer.publisher.Publish(ctx, PublicationDraft{Body: existing.Latest.Body, Economics: existing.Economics},
			[]string{"carrier:gateway-local-pilot", "carrier:messenger-local-pilot"}, 1, buyer.fence)
		if err != nil {
			return "", err
		}
		return recovered.LatestDigest, nil
	}
	body := commerce.AgentIntentBody{SchemaVersion: 1, NetworkID: "tos:local-three-node", IssuerAgentID: buyer.definition.AgentID,
		Audience: "public:indexable", ObjectID: objectID,
		Revision: 1, CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(4 * time.Hour).Unix()),
		Payload: commerce.AgentIntentPayload{DiscoveryCard: commerce.DiscoveryCard{Summary: task, IntentModes: []commerce.IntentMode{commerce.IntentRequest},
			SubjectClasses: []commerce.SubjectClass{commerce.SubjectService}, TaxonomyPaths: []string{"tos.taxonomy.v1/service/" + seller.definition.Taxonomy + "/pilot"},
			Keywords: []commerce.IntentKeyword{{Text: seller.definition.Capability}}, CapabilityHints: []commerce.CapabilityHint{{Relation: "required",
				CapabilityNamespace: "tos.skill", CapabilityIdentifier: seller.definition.Capability}}, ValueState: commerce.ValueSpecified,
			ValueHints: []commerce.ValueHint{{Role: "budget", AssetNamespace: "tos.asset", AssetIdentifier: "native", AmountKind: "exact",
				MinimumDecimal: strconv.FormatUint(seller.definition.Price, 10), MaximumDecimal: strconv.FormatUint(seller.definition.Price, 10), Unit: "nanotos"}},
			Schedule: commerce.IntentSchedule{DesiredCompletionUnix: uint64(now.Add(time.Hour).Unix()), Flexibility: "flexible"}, FulfillmentModes: []string{"remote"}},
			DetailDescriptor: commerce.ContentDescriptor{ContentType: "text/plain", ContentDigest: campaignDigest(task), ContentSize: uint64(len(detail)), InlineContent: detail},
			ReplyRoutes:      []commerce.ReplyRoute{{ProfileURI: "tos.messenger.direct.v1", AgentID: buyer.definition.AgentID}},
			SettlementPreferences: []commerce.SettlementPreference{{AdapterURI: "tos.payment.direct.v1", Required: true,
				Parameters: []byte(`{"network_id":"tos:local-three-node","asset":"native","unit":"nanotos"}`)}}}}
	record, err := buyer.publisher.Publish(ctx, PublicationDraft{Body: body},
		[]string{"carrier:gateway-local-pilot", "carrier:messenger-local-pilot"}, 1, buyer.fence)
	if err != nil {
		return "", err
	}
	return record.LatestDigest, nil
}

func campaignAgreement(sequence, attempt int, buyer, seller eightAgentManifestEntry, task string, now time.Time) (commerce.AgentAgreementBody, error) {
	if buyer.AgentID == "" || seller.AgentID == "" || buyer.AgentID == seller.AgentID {
		return commerce.AgentAgreementBody{}, errors.New("campaign Agreement requires distinct buyer and provider Agents")
	}
	profile := commerce.AgentSignatureProfileDigest()
	body := commerce.AgentAgreementBody{SchemaVersion: 1, AgreementID: "agreement:" + strings.TrimPrefix(campaignDigest(fmt.Sprintf("campaign:v5:%d:%s", sequence, task)), "sha256:"),
		Version: uint64(attempt + 1), NetworkContext: "tos:local-three-node", Participants: []commerce.AgreementParticipant{{AgentID: buyer.AgentID, Roles: []string{"buyer"}}, {AgentID: seller.AgentID, Roles: []string{"provider"}}},
		TermsContentType: "text/plain", Terms: []byte(task), ValidFromUnix: uint64(now.Add(-time.Minute).Unix()), ExpiresAtUnix: uint64(now.Add(2 * time.Hour).Unix()),
		Obligations: []commerce.AgreementObligation{{ObligationID: "pay", Kind: "payment", ObligorAgentID: buyer.AgentID, BeneficiaryAgentID: seller.AgentID,
			DependsOnObligationIDs: []string{"work"}, SubjectContentType: "text/plain", Subject: []byte("pay after verified delivery"),
			Amount:    &commerce.AgreementAmount{AssetNamespace: "tos.asset", AssetIdentifier: "native", AmountAtomic: strconv.FormatUint(seller.Price, 10), Unit: "nanotos"},
			DueAtUnix: uint64(now.Add(40 * time.Minute).Unix()), ExpiresAtUnix: uint64(now.Add(50 * time.Minute).Unix()), ConfidentialityPolicy: "participants",
			CancellationPolicy: "before-due", DisputePolicy: "evidence", SettlementAdapterURI: "tos.payment.direct.v1", SettlementParameters: []byte(seller.Target),
			AuthorizationPredicateIDs: []string{"buyer-payment"}},
			{ObligationID: "work", Kind: "service", ObligorAgentID: seller.AgentID, BeneficiaryAgentID: buyer.AgentID, SubjectContentType: "text/plain",
				Subject: []byte(task), ConfidentialityPolicy: reusableLearningDisclosurePolicy, CancellationPolicy: "before-start", DisputePolicy: "evidence",
				AuthorizationPredicateIDs: []string{"provider-work"}}},
		AuthorizationPredicates: []commerce.AgreementAuthorizationPredicate{{PredicateID: "buyer-payment",
			AuthoritySubject: commerce.AgreementAuthoritySubject{SubjectKind: "agent", SubjectNamespace: "tos.agent", SubjectIdentifier: buyer.AgentID},
			ObligationIDs:    []string{"pay"}, EvidenceProfileURI: commerce.EvidenceProfileAgentSignature, EvidenceProfileVersion: 1,
			EvidenceProfileDigest: profile, ExpiresAtUnix: uint64(now.Add(2 * time.Hour).Unix())}, {PredicateID: "provider-work",
			AuthoritySubject: commerce.AgreementAuthoritySubject{SubjectKind: "agent", SubjectNamespace: "tos.agent", SubjectIdentifier: seller.AgentID},
			ObligationIDs:    []string{"work"}, EvidenceProfileURI: commerce.EvidenceProfileAgentSignature, EvidenceProfileVersion: 1,
			EvidenceProfileDigest: profile, ExpiresAtUnix: uint64(now.Add(2 * time.Hour).Unix())}}}
	if attempt > 0 {
		predecessor, predecessorErr := campaignAgreement(sequence, attempt-1, buyer, seller, task, now)
		if predecessorErr != nil {
			return commerce.AgentAgreementBody{}, predecessorErr
		}
		body.PredecessorAgreementDigest, predecessorErr = commerce.AgreementBodyDigest(predecessor)
		if predecessorErr != nil {
			return commerce.AgentAgreementBody{}, predecessorErr
		}
	}
	sort.Slice(body.Participants, func(i, j int) bool { return body.Participants[i].AgentID < body.Participants[j].AgentID })
	return commerce.PrepareAgreementTargets(body)
}

func TestCampaignAgreementRetryHasDeterministicPredecessor(t *testing.T) {
	definitions := eightAgentDefinitions()
	buyer := eightAgentManifestEntry{AgentID: definitions[1].AgentID}
	seller := eightAgentManifestEntry{AgentID: definitions[0].AgentID, Target: "0:" + strings.Repeat("a", 64), Price: definitions[0].Price}
	now := time.Unix(2_000_000_000, 0).UTC()
	first, err := campaignAgreement(7, 0, buyer, seller, definitions[0].Tasks[0], now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := campaignAgreement(7, 1, buyer, seller, definitions[0].Tasks[0], now)
	if err != nil {
		t.Fatal(err)
	}
	firstDigest, _ := commerce.AgreementBodyDigest(first)
	if first.AgreementID != second.AgreementID || second.Version != 2 || second.PredecessorAgreementDigest != firstDigest {
		t.Fatalf("retry lineage is not deterministic: first=%+v second=%+v", first, second)
	}
}

func campaignSkillNames(workspace string) []string {
	listed := skills.NewSkillsLoader(workspace, "", "").ListSkills()
	names := make([]string, 0, len(listed))
	for _, skill := range listed {
		names = append(names, skill.Name)
	}
	sort.Strings(names)
	return names
}

type campaignFinancialLine struct {
	Agent               string `json:"agent"`
	JobsSold            int    `json:"jobs_sold"`
	JobsBought          int    `json:"jobs_bought"`
	GrossRevenueNanoTOS uint64 `json:"gross_revenue_nanotos"`
	SpendNanoTOS        uint64 `json:"spend_nanotos"`
	MaximumCostNanoTOS  uint64 `json:"maximum_internal_cost_nanotos"`
	TransferNetNanoTOS  int64  `json:"transfer_net_nanotos"`
	ProjectedNetNanoTOS int64  `json:"projected_net_nanotos"`
	SkillsAtEnd         int    `json:"skills_at_end"`
}

func writeCampaignSummaries(t *testing.T, root string, report eightAgentCampaignReport, manifest eightAgentManifest) {
	t.Helper()
	lines := make(map[string]*campaignFinancialLine, len(manifest.Agents))
	for _, agent := range manifest.Agents {
		lines[agent.Name] = &campaignFinancialLine{Agent: agent.Name}
	}
	for _, result := range report.Results {
		if !campaignResultSettled(result) {
			continue
		}
		seller, buyer := lines[result.Seller], lines[result.Buyer]
		seller.JobsSold++
		seller.GrossRevenueNanoTOS += result.RevenueNanoTOS
		seller.MaximumCostNanoTOS += result.MaximumInternalCostNanoTOS
		buyer.JobsBought++
		buyer.SpendNanoTOS += result.RevenueNanoTOS
	}
	ordered := make([]campaignFinancialLine, 0, len(manifest.Agents))
	var totalRevenue, totalCost uint64
	for _, agent := range manifest.Agents {
		line := lines[agent.Name]
		line.TransferNetNanoTOS = int64(line.GrossRevenueNanoTOS) - int64(line.SpendNanoTOS)
		line.ProjectedNetNanoTOS = int64(line.GrossRevenueNanoTOS) - int64(line.SpendNanoTOS) - int64(line.MaximumCostNanoTOS)
		line.SkillsAtEnd = len(campaignSkillNames(filepath.Join(agent.ConfigDirectory, "workspace")))
		totalRevenue += line.GrossRevenueNanoTOS
		totalCost += line.MaximumCostNanoTOS
		ordered = append(ordered, *line)
	}
	modes, dispositions, transactions := map[string]int{}, map[string]int{}, map[string]bool{}
	settledJobs := 0
	var executionMillis, settlementMillis int64
	for _, result := range report.Results {
		mode := result.EconomicAnalysisMode
		if mode == "" {
			mode = "legacy-unclassified"
		}
		modes[mode]++
		disposition := result.Disposition
		if disposition == "" {
			disposition = "settled"
		}
		dispositions[disposition]++
		if campaignResultSettled(result) {
			settledJobs++
			transactions[result.PaymentTransaction] = true
		}
		executionMillis += result.ExecutionElapsedMillis
		settlementMillis += result.SettlementElapsedMillis
	}
	averageExecution, averageSettlement := int64(0), int64(0)
	if settledJobs > 0 {
		averageExecution = executionMillis / int64(settledJobs)
		averageSettlement = settlementMillis / int64(settledJobs)
	}
	writeCampaignJSON(t, filepath.Join(root, "reports", "eight-agent-financial-summary.json"), map[string]any{
		"schema": "tos.openfox.eight-agent-financial-summary.v1", "generated_at": time.Now().UTC().Format(time.RFC3339Nano),
		"agents": ordered, "aggregate": map[string]any{"decisions": len(report.Results), "settled_jobs": settledJobs, "unique_payment_transactions": len(transactions),
			"service_revenue_nanotos": totalRevenue, "internal_transfer_net_nanotos": 0, "maximum_internal_cost_nanotos": totalCost,
			"closed_economy_projected_net_nanotos": -int64(totalCost), "economic_analysis_modes": modes, "dispositions": dispositions,
			"average_execution_millis": averageExecution, "average_settlement_millis": averageSettlement}})
}

func campaignResultSettled(result eightAgentJobResult) bool {
	return result.Disposition == "" || result.Disposition == "settled"
}

func TestCampaignEstimateCannotExceedOwnerCostAuthority(t *testing.T) {
	base := EconomicEstimate{ComputeCostAtomic: "20", ModelCostAtomic: "10", APICostAtomic: "0",
		ToolCostAtomic: "0", SubcontractCostAtomic: "0", OpportunityCostAtomic: "5",
		FailureReserveAtomic: "5", DisputeReserveAtomic: "5", PrivacyLegalReserveAtomic: "0",
		MaximumLossAtomic: "45"}
	if !campaignEstimateWithinOwnerBounds(base, 50) {
		t.Fatal("bounded estimate was rejected")
	}
	overCost := base
	overCost.ModelCostAtomic = "20"
	if campaignEstimateWithinOwnerBounds(overCost, 50) {
		t.Fatal("aggregate cost above the owner bound was accepted")
	}
	overLoss := base
	overLoss.MaximumLossAtomic = "51"
	if campaignEstimateWithinOwnerBounds(overLoss, 50) {
		t.Fatal("maximum loss above the owner bound was accepted")
	}
}
