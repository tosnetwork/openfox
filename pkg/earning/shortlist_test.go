package earning

import (
	"fmt"
	"testing"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

func TestShortlistBoundsIssuerTaxonomyAndExpensiveStage(t *testing.T) {
	observed := map[string]*observedCandidate{}
	var digests []string
	for index := 0; index < 12; index++ {
		digest := fmt.Sprintf("sha256:%064x", index+1)
		issuer := "agent:dominant"
		if index >= 8 {
			issuer = fmt.Sprintf("agent:%d", index)
		}
		observed[digest] = &observedCandidate{intent: commerce.SignedAgentIntent{Body: commerce.AgentIntentBody{
			IssuerAgentID: issuer, Payload: commerce.AgentIntentPayload{DiscoveryCard: commerce.DiscoveryCard{
				TaxonomyPaths: []string{"tos.taxonomy.v1/service/review"}, Keywords: []commerce.IntentKeyword{{Text: "review"}},
				ValueState: commerce.ValueSpecified, ValueHints: []commerce.ValueHint{{AssetNamespace: "tos.asset", AssetIdentifier: "native", AmountKind: "exact"}},
			}}}}, carriers: map[string]bool{"carrier:a": true}}
		digests = append(digests, digest)
	}
	selected := shortlistDigests(digests, observed, IntentQuery{Keywords: []string{"review"}}, ShortlistPolicy{
		Size: 5, MaximumPerIssuer: 2, MaximumPerSource: 5, MaximumPerTaxonomy: 5, MaximumPerValueBand: 5, ExplorationPercent: 20,
	})
	if len(selected) != 5 {
		t.Fatalf("shortlist size=%d want=5: %v", len(selected), selected)
	}
	dominant := 0
	for _, digest := range selected {
		if observed[digest].intent.Body.IssuerAgentID == "agent:dominant" {
			dominant++
		}
	}
	if dominant > 2 {
		t.Fatalf("one issuer consumed %d expensive slots", dominant)
	}
}
