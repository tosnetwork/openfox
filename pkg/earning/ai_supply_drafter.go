package earning

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"time"

	"github.com/tosnetwork/openfox/pkg/providers"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type LLMSupplyDrafter struct {
	Provider                            providers.LLMProvider
	Model, NetworkID, AgentID, Audience string
	SettlementParameters                map[string][]byte
	Now                                 func() time.Time
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
		Inventory InventorySnapshot `json:"trusted_inventory"`
	}{inventory})
	if err != nil {
		return PublicationDraft{}, err
	}
	system := `You are OpenFox's read-only supply planner. Propose at most one profitable, business-neutral service Intent using only a READY capability and supported settlement Adapter in the trusted Inventory. Return exactly one JSON object with these keys and no others: publish (boolean), summary (string), detail (string), taxonomy_paths (string array), keywords (string array), capability_namespace (string), capability_identifier (string), revenue_atomic (canonical unsigned integer string), unit_cost_atomic (canonical unsigned integer string), asset_namespace (string), asset_identifier (string), unit (string), settlement_adapter_uri (string), ttl_seconds (integer), and rationale (string). Do not call tools, publish, message, sign, spend, or claim authorization. Taxonomy paths and keywords must be concise; unknowns mean publish=false.`
	response, err := drafter.Provider.Chat(ctx, []providers.Message{{Role: "system", Content: system}, {Role: "user", Content: string(input)}}, nil,
		drafter.model(), map[string]any{"temperature": 0, "max_tokens": 1400})
	if err != nil || response == nil || len(response.Content) == 0 || len(response.Content) > 32<<10 || len(response.ToolCalls) != 0 {
		return PublicationDraft{}, errors.New("AI supply planning failed or attempted a tool call")
	}
	var proposal modelSupplyProposal
	decoder := json.NewDecoder(bytes.NewReader([]byte(response.Content)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&proposal) != nil || decoder.Decode(&struct{}{}) != io.EOF || !proposal.Publish || len(proposal.Summary) == 0 || len(proposal.Summary) > 1024 ||
		len(proposal.Detail) == 0 || len(proposal.Detail) > 64<<10 || len(proposal.TaxonomyPaths) == 0 || len(proposal.TaxonomyPaths) > 16 ||
		len(proposal.Keywords) == 0 || len(proposal.Keywords) > 32 || len(proposal.Rationale) == 0 || len(proposal.Rationale) > 4096 ||
		proposal.TTLSeconds < 60 || proposal.TTLSeconds > 90*86400 || nonnegativeText(proposal.RevenueAtomic) != nil ||
		nonnegativeText(proposal.UnitCostAtomic) != nil {
		return PublicationDraft{}, errors.New("AI supply proposal is not strict bounded JSON")
	}
	if !inventory.HasCapability(proposal.CapabilityNamespace, proposal.CapabilityIdentifier, now) || !inventory.SupportsSettlement(proposal.SettlementAdapterURI) {
		return PublicationDraft{}, errors.New("AI supply proposal exceeds current capabilities or settlement support")
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
		Inventory string `json:"inventory_consistency_token"`
		Proposal  []byte `json:"proposal"`
		Model     string `json:"model"`
	}{inventory.ConsistencyToken, canonicalProposal, drafter.model()})
	if err != nil {
		return PublicationDraft{}, err
	}
	return PublicationDraft{Body: body, Economics: PublicationEconomics{RevenueAtomic: proposal.RevenueAtomic, UnitCostAtomic: proposal.UnitCostAtomic,
		AssetNamespace: proposal.AssetNamespace, AssetIdentifier: proposal.AssetIdentifier, ValueHintRole: "price", Unit: proposal.Unit,
		EvidenceDigest: evidence, ExpiresAtUnix: uint64(now.Add(10 * time.Minute).Unix())}}, nil
}

func (drafter LLMSupplyDrafter) model() string {
	if drafter.Model != "" {
		return drafter.Model
	}
	return drafter.Provider.GetDefaultModel()
}
func nonnegativeText(value string) error { _, err := nonnegativeInteger(value); return err }
