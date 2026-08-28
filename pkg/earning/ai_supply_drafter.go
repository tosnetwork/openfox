package earning

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/tosnetwork/openfox/pkg/providers"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type LLMSupplyDrafter struct {
	Provider                            providers.LLMProvider
	Model, NetworkID, AgentID, Audience string
	SettlementParameters                map[string][]byte
	OfferPolicies                       []SupplyOfferPolicy
	Now                                 func() time.Time
	AgentContext                        AgentContextSource
}

// SupplyOfferPolicy is trusted owner configuration, not model output. It gives
// the supply planner enough bounded commercial context to make a proposal
// without letting the model invent an asset, payment route, or price range.
type SupplyOfferPolicy struct {
	CapabilityNamespace, CapabilityIdentifier   string
	AssetNamespace, AssetIdentifier, Unit       string
	MinimumRevenueAtomic, MaximumRevenueAtomic  string
	MaximumUnitCostAtomic, SettlementAdapterURI string
	TaxonomyPrefixes, RequiredKeywords          []string
	MinimumTTLSeconds, MaximumTTLSeconds        uint32
}

type modelSupplyProposal struct {
	Publish              bool     `json:"publish"`
	Summary              string   `json:"summary"`
	Detail               string   `json:"detail"`
	TaxonomyPaths        []string `json:"taxonomy_paths"`
	Keywords             []string `json:"keywords"`
	CapabilityNamespace  string   `json:"capability_namespace"`
	CapabilityIdentifier string   `json:"capability_identifier"`
	RevenueAtomic        string   `json:"revenue_atomic"`
	UnitCostAtomic       string   `json:"unit_cost_atomic"`
	AssetNamespace       string   `json:"asset_namespace"`
	AssetIdentifier      string   `json:"asset_identifier"`
	Unit                 string   `json:"unit"`
	SettlementAdapterURI string   `json:"settlement_adapter_uri"`
	TTLSeconds           uint32   `json:"ttl_seconds"`
	Rationale            string   `json:"rationale"`
}

func (drafter LLMSupplyDrafter) DraftSupply(ctx context.Context, inventory InventorySnapshot) (PublicationDraft, error) {
	if drafter.Provider == nil || drafter.NetworkID == "" || drafter.AgentID == "" || drafter.Audience == "" || inventory.AgentID != drafter.AgentID {
		return PublicationDraft{}, errors.New("AI supply drafter is incomplete")
	}
	now := time.Now().UTC()
	if drafter.Now != nil {
		now = drafter.Now().UTC()
	}
	if inventory.Validate(now) != nil {
		return PublicationDraft{}, errors.New("AI supply draft has no fresh Inventory")
	}
	input, err := json.Marshal(struct {
		Inventory     InventorySnapshot   `json:"trusted_inventory"`
		OfferPolicies []SupplyOfferPolicy `json:"trusted_owner_offer_policies"`
	}{inventory, drafter.OfferPolicies})
	if err != nil {
		return PublicationDraft{}, err
	}
	system, err := contextualAgentSystemPrompt(drafter.AgentContext, `You are acting as this OpenFox's read-only supply planner. Apply its identity, business preferences, and owner instructions. Propose at most one profitable, business-neutral service Intent using only a READY capability, supported settlement Adapter, and matching trusted_owner_offer_policy. The typed policy is a safety envelope, not a command to advertise: publish only when the natural-language business strategy also supports the offer. Every asset, price, cost, taxonomy, required keyword, Adapter, and TTL must stay inside that envelope. Return exactly one JSON object with these keys and no others: publish (boolean), summary (string), detail (string), taxonomy_paths (string array), keywords (string array), capability_namespace (string), capability_identifier (string), revenue_atomic (canonical unsigned integer string), unit_cost_atomic (canonical unsigned integer string), asset_namespace (string), asset_identifier (string), unit (string), settlement_adapter_uri (string), ttl_seconds (integer), and rationale (string). Do not call tools, publish, message, sign, spend, or claim authorization. Taxonomy paths and keywords must be concise; missing policy means publish=false.`)
	if err != nil {
		return PublicationDraft{}, err
	}
	response, err := drafter.Provider.Chat(providers.WithInternalAgentBackendPrincipal(ctx), []providers.Message{{Role: "system", Content: system}, {Role: "user", Content: string(input)}}, nil,
		drafter.model(), map[string]any{"temperature": 0, "max_tokens": 1400})
	if err != nil || response == nil || len(response.Content) == 0 || len(response.Content) > 32<<10 || len(response.ToolCalls) != 0 {
		return PublicationDraft{}, errors.New("AI supply planning failed or attempted a tool call")
	}
	var proposal modelSupplyProposal
	object, err := strictModelJSONObject(response.Content)
	if err != nil {
		return PublicationDraft{}, errors.New("AI supply proposal is not a strict JSON object")
	}
	decoder := json.NewDecoder(bytes.NewReader(object))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&proposal); err != nil {
		return PublicationDraft{}, errors.New("AI supply proposal is not a strict JSON object")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return PublicationDraft{}, errors.New("AI supply proposal contains trailing content")
	}
	if !proposal.Publish {
		return PublicationDraft{}, errors.New("AI supply planner declined publication")
	}
	if len(proposal.Summary) == 0 || len(proposal.Summary) > 1024 || len(proposal.Detail) == 0 || len(proposal.Detail) > 64<<10 ||
		len(proposal.TaxonomyPaths) == 0 || len(proposal.TaxonomyPaths) > 16 || len(proposal.Keywords) == 0 || len(proposal.Keywords) > 32 ||
		len(proposal.Rationale) == 0 || len(proposal.Rationale) > 4096 {
		return PublicationDraft{}, errors.New("AI supply proposal has missing or unbounded text fields")
	}
	if proposal.TTLSeconds < 60 || proposal.TTLSeconds > 90*86400 {
		return PublicationDraft{}, errors.New("AI supply proposal TTL is outside the released bound")
	}
	if nonnegativeText(proposal.RevenueAtomic) != nil || nonnegativeText(proposal.UnitCostAtomic) != nil {
		return PublicationDraft{}, errors.New("AI supply proposal economics are not canonical unsigned integers")
	}
	if !inventory.HasCapability(proposal.CapabilityNamespace, proposal.CapabilityIdentifier, now) || !inventory.SupportsSettlement(proposal.SettlementAdapterURI) {
		return PublicationDraft{}, errors.New("AI supply proposal exceeds current capabilities or settlement support")
	}
	policy, found := drafter.offerPolicy(proposal.CapabilityNamespace, proposal.CapabilityIdentifier)
	if !found || !policy.permits(proposal) {
		return PublicationDraft{}, errors.New("AI supply proposal exceeds the owner offer policy")
	}
	parameters := append([]byte(nil), drafter.SettlementParameters[proposal.SettlementAdapterURI]...)
	if len(parameters) == 0 || len(parameters) > 4096 {
		return PublicationDraft{}, errors.New("selected settlement Adapter has no owner-configured public parameters")
	}
	sort.Strings(proposal.TaxonomyPaths)
	sort.Strings(proposal.Keywords)
	for index := range proposal.TaxonomyPaths {
		if index > 0 && proposal.TaxonomyPaths[index] == proposal.TaxonomyPaths[index-1] {
			return PublicationDraft{}, errors.New("AI supply taxonomy is duplicated")
		}
	}
	keywords := make([]commerce.IntentKeyword, 0, len(proposal.Keywords))
	for index, keyword := range proposal.Keywords {
		if keyword == "" || index > 0 && keyword == proposal.Keywords[index-1] {
			return PublicationDraft{}, errors.New("AI supply keywords are invalid")
		}
		keywords = append(keywords, commerce.IntentKeyword{Text: keyword})
	}
	canonicalProposal, err := codec.Marshal(proposal)
	if err != nil {
		return PublicationDraft{}, err
	}
	objectDigest, err := codec.Digest("tos.openfox.supply-object.v1", struct {
		Agent                string   `json:"agent_id"`
		CapabilityNamespace  string   `json:"capability_namespace"`
		CapabilityIdentifier string   `json:"capability_identifier"`
		TaxonomyPaths        []string `json:"taxonomy_paths"`
	}{drafter.AgentID, proposal.CapabilityNamespace, proposal.CapabilityIdentifier, proposal.TaxonomyPaths})
	if err != nil {
		return PublicationDraft{}, err
	}
	detail := []byte(proposal.Detail)
	detailHash := sha256.Sum256(detail)
	body := commerce.AgentIntentBody{SchemaVersion: 1, NetworkID: drafter.NetworkID, IssuerAgentID: drafter.AgentID, Audience: drafter.Audience,
		ObjectID: "intent:" + objectDigest[7:], Revision: 1, CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(time.Duration(proposal.TTLSeconds) * time.Second).Unix()),
		Payload: commerce.AgentIntentPayload{DiscoveryCard: commerce.DiscoveryCard{Summary: proposal.Summary, IntentModes: []commerce.IntentMode{commerce.IntentOffer},
			SubjectClasses: []commerce.SubjectClass{commerce.SubjectService}, TaxonomyPaths: proposal.TaxonomyPaths, Keywords: keywords,
			CapabilityHints: []commerce.CapabilityHint{{Relation: "offered", CapabilityNamespace: proposal.CapabilityNamespace, CapabilityIdentifier: proposal.CapabilityIdentifier}},
			ValueState:      commerce.ValueSpecified, ValueHints: []commerce.ValueHint{{Role: "price", AssetNamespace: proposal.AssetNamespace, AssetIdentifier: proposal.AssetIdentifier,
				AmountKind: "exact", MinimumDecimal: proposal.RevenueAtomic, MaximumDecimal: proposal.RevenueAtomic, Unit: proposal.Unit}},
			Schedule: commerce.IntentSchedule{Flexibility: "flexible"}, FulfillmentModes: []string{"remote"}},
			DetailDescriptor:      commerce.ContentDescriptor{ContentType: "text/plain", ContentDigest: "sha256:" + hex.EncodeToString(detailHash[:]), ContentSize: uint64(len(detail)), InlineContent: detail},
			ReplyRoutes:           []commerce.ReplyRoute{{ProfileURI: "tos.messenger.direct.v1", AgentID: drafter.AgentID}},
			SettlementPreferences: []commerce.SettlementPreference{{AdapterURI: proposal.SettlementAdapterURI, Required: true, Parameters: parameters}}}}
	evidence, err := codec.Digest("tos.openfox.ai-supply-evidence.v1", struct {
		Inventory string            `json:"inventory_consistency_token"`
		Proposal  []byte            `json:"proposal"`
		Policy    SupplyOfferPolicy `json:"owner_offer_policy"`
		Model     string            `json:"model"`
	}{inventory.ConsistencyToken, canonicalProposal, policy, drafter.model()})
	if err != nil {
		return PublicationDraft{}, err
	}
	return PublicationDraft{Body: body, Economics: PublicationEconomics{RevenueAtomic: proposal.RevenueAtomic, UnitCostAtomic: proposal.UnitCostAtomic,
		AssetNamespace: proposal.AssetNamespace, AssetIdentifier: proposal.AssetIdentifier, ValueHintRole: "price", Unit: proposal.Unit,
		EvidenceDigest: evidence, ExpiresAtUnix: uint64(now.Add(10 * time.Minute).Unix())}}, nil
}

// strictModelJSONObject accepts either a bare JSON object or the same object
// inside one exact Markdown JSON fence. Some local subscription CLIs preserve
// a presentation fence despite an exact-JSON instruction. No prose, nested
// fence, or suffix is tolerated, so normalization does not broaden the
// authority-bearing parser.
func strictModelJSONObject(content string) ([]byte, error) {
	trimmed := strings.TrimSpace(content)
	if strings.HasPrefix(trimmed, "```json\n") && strings.HasSuffix(trimmed, "\n```") {
		trimmed = strings.TrimSuffix(strings.TrimPrefix(trimmed, "```json\n"), "\n```")
	} else if strings.HasPrefix(trimmed, "```\n") && strings.HasSuffix(trimmed, "\n```") {
		trimmed = strings.TrimSuffix(strings.TrimPrefix(trimmed, "```\n"), "\n```")
	}
	trimmed = strings.TrimSpace(trimmed)
	if trimmed == "" || strings.Contains(trimmed, "```") || trimmed[0] != '{' || trimmed[len(trimmed)-1] != '}' {
		return nil, errors.New("model response is not one JSON object")
	}
	return []byte(trimmed), nil
}

func (drafter LLMSupplyDrafter) model() string {
	if drafter.Model != "" {
		return drafter.Model
	}
	return drafter.Provider.GetDefaultModel()
}

func (drafter LLMSupplyDrafter) offerPolicy(namespace, identifier string) (SupplyOfferPolicy, bool) {
	for _, policy := range drafter.OfferPolicies {
		if policy.CapabilityNamespace == namespace && policy.CapabilityIdentifier == identifier {
			return policy, true
		}
	}
	return SupplyOfferPolicy{}, false
}

func (policy SupplyOfferPolicy) permits(proposal modelSupplyProposal) bool {
	if policy.AssetNamespace != proposal.AssetNamespace || policy.AssetIdentifier != proposal.AssetIdentifier ||
		policy.Unit != proposal.Unit || policy.SettlementAdapterURI != proposal.SettlementAdapterURI ||
		proposal.TTLSeconds < policy.MinimumTTLSeconds || proposal.TTLSeconds > policy.MaximumTTLSeconds {
		return false
	}
	revenue, revenueOK := new(big.Int).SetString(proposal.RevenueAtomic, 10)
	cost, costOK := new(big.Int).SetString(proposal.UnitCostAtomic, 10)
	minimum, minimumOK := new(big.Int).SetString(policy.MinimumRevenueAtomic, 10)
	maximum, maximumOK := new(big.Int).SetString(policy.MaximumRevenueAtomic, 10)
	maximumCost, maximumCostOK := new(big.Int).SetString(policy.MaximumUnitCostAtomic, 10)
	if !revenueOK || !costOK || !minimumOK || !maximumOK || !maximumCostOK ||
		revenue.Cmp(minimum) < 0 || revenue.Cmp(maximum) > 0 || cost.Cmp(maximumCost) > 0 {
		return false
	}
	for _, path := range proposal.TaxonomyPaths {
		allowed := false
		for _, prefix := range policy.TaxonomyPrefixes {
			allowed = allowed || path == prefix || strings.HasPrefix(path, strings.TrimRight(prefix, "/")+"/")
		}
		if !allowed {
			return false
		}
	}
	keywords := make(map[string]bool, len(proposal.Keywords))
	for _, keyword := range proposal.Keywords {
		keywords[keyword] = true
	}
	for _, required := range policy.RequiredKeywords {
		if !keywords[required] {
			return false
		}
	}
	return true
}

func nonnegativeText(value string) error { _, err := nonnegativeInteger(value); return err }
