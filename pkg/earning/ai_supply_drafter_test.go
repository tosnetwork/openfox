package earning

import (
	"context"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

func TestLLMSupplyDrafterCannotExceedInventory(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	provider := estimatorProvider{response: `{"publish":true,"summary":"Bounded source review","detail":"Review one supplied source tree and deliver a concise report.","taxonomy_paths":["tos.taxonomy.v1/service/security/review"],"keywords":["review","security"],"capability_namespace":"skill","capability_identifier":"source-review","revenue_atomic":"150","unit_cost_atomic":"100","asset_namespace":"tos.asset","asset_identifier":"native","unit":"total","settlement_adapter_uri":"tos.payment.direct.v1","ttl_seconds":3600,"rationale":"capacity and margin are available"}`}
	inventory := InventorySnapshot{OwnerID: "owner", AgentID: "agent:supply", CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()),
		SourceGeneration: 1, PortfolioRevision: 1, PolicyRevision: 1, ConsistencyToken: "inventory:supply",
		Capabilities: []Capability{{Namespace: "skill", Identifier: "source-review", Version: "1", State: CapabilityReady, Authority: "owner",
			EvidenceDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", RevocationGeneration: 1, ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}},
		SupportedSettlementAdapters: []string{"tos.payment.direct.v1"}}
	drafter := LLMSupplyDrafter{Provider: provider, NetworkID: "tos:test", AgentID: "agent:supply", Audience: "public:indexable",
		SettlementParameters: map[string][]byte{"tos.payment.direct.v1": []byte("tos1supply")}, Now: func() time.Time { return now }}
	draft, err := drafter.DraftSupply(context.Background(), inventory)
	if err != nil || draft.Body.Payload.DiscoveryCard.IntentModes[0] != commerce.IntentOffer || draft.Economics.RevenueAtomic != "150" {
		t.Fatalf("draft=%+v err=%v", draft, err)
	}
	if string(draft.Body.Payload.SettlementPreferences[0].Parameters) != "tos1supply" {
		t.Fatal("supply Intent omitted owner-configured exact settlement parameters")
	}
	bad := inventory
	bad.Capabilities = nil
	if _, err := drafter.DraftSupply(context.Background(), bad); err == nil {
		t.Fatal("model advertised an unavailable capability")
	}
}
