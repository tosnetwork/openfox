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

func TestAgreementOnlyWriterScopesIncludeAtomicPortfolioReserve(t *testing.T) {
	scopes := configuredWriterScopes(config.EarningSettings{Gates: config.EarningGateSettings{Agreement: true}})
	for _, required := range []string{"agreement.authorize", "portfolio.reserve"} {
		if !slices.Contains(scopes, required) {
			t.Fatalf("Agreement-only writer scope omits %q: %v", required, scopes)
		}
	}
}

func TestGenericEarningCLIFailsClosedForGuarantorRuntime(t *testing.T) {
	settings := config.EarningSettings{Gates: config.EarningGateSettings{AgentGuarantor: true},
		AgentGuarantor: config.EarningAgentGuarantorSettings{Enabled: true}}
	if err := validateGuarantorCLIAssembly(settings); err == nil {
		t.Fatal("generic earning CLI silently accepted an unassembled Guarantor runtime")
	}
	if err := validateGuarantorCLIAssembly(config.EarningSettings{}); err != nil {
		t.Fatalf("disabled Guarantor unexpectedly blocks the generic earning CLI: %v", err)
	}
}
