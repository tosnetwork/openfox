package earning

import (
	"slices"
	"testing"

	"github.com/tosnetwork/openfox/pkg/config"
)

func TestGuarantorWriterScopesIncludeEveryPayoutVariant(t *testing.T) {
	scopes := configuredWriterScopes(config.EarningSettings{Gates: config.EarningGateSettings{AgentGuarantor: true}})
	for _, required := range []string{"payment.direct", "payment.domain-bound", "settlement.external"} {
		if !slices.Contains(scopes, required) {
			t.Fatalf("Guarantor writer scope omits %q: %v", required, scopes)
		}
	}
}
