package gateway

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/openfox/pkg/config"
	"github.com/tosnetwork/openfox/pkg/opportunity"
)

func TestOpportunityRuntimeConfigDefaultsOffAndBoundsObserveMode(t *testing.T) {
	if runtime, err := opportunityRuntimeConfig(config.OpportunitySettings{Mode: "off"}); err != nil || runtime.Mode != opportunity.ModeOff {
		t.Fatalf("off: %+v err=%v", runtime, err)
	}
	settings := config.OpportunitySettings{Mode: "observe", CoordinatorSocket: "/run/openfox/opportunity.sock",
		StateDir: "/var/lib/openfox/opportunities", Queries: []string{"go test"}, IntervalMinutes: 5,
		JitterSeconds: 30, RequestTimeoutSeconds: 10, PageSize: 20, MaxCandidates: 40,
		AllowedOperations: []string{"test"}, DeniedProviders: []string{"agent_" + strings.Repeat("a", 64)}}
	runtime, err := opportunityRuntimeConfig(settings)
	if err != nil || runtime.Mode != opportunity.ModeObserve || runtime.Interval != 5*time.Minute || runtime.PageSize != 20 {
		t.Fatalf("observe: %+v err=%v", runtime, err)
	}
	settings.CoordinatorSocket = filepath.Clean("relative.sock")
	if _, err := opportunityRuntimeConfig(settings); err == nil {
		t.Fatal("relative coordinator socket was accepted")
	}
}

func TestOpportunityRuntimeConfigCannotEnableUnboundedOrSilentSpending(t *testing.T) {
	settings := config.OpportunitySettings{Mode: "policy-gated", CoordinatorSocket: "/run/openfox/opportunity.sock",
		StateDir: "/var/lib/openfox/opportunities", Queries: []string{"work"}, IntervalMinutes: 5,
		RequestTimeoutSeconds: 10, PageSize: 20, MaxCandidates: 40}
	runtime, err := opportunityRuntimeConfig(settings)
	if err != nil || runtime.Mode != opportunity.ModePolicyGated {
		t.Fatalf("typed policy mode should parse before runner assembly: %+v err=%v", runtime, err)
	}
	settings.IntervalMinutes = 1
	if _, err := opportunityRuntimeConfig(settings); err == nil {
		t.Fatal("unbounded polling interval was accepted")
	}
	settings = config.OpportunitySettings{Mode: "off", CoordinatorSocket: "/tmp/unused.sock"}
	if _, err := opportunityRuntimeConfig(settings); err == nil {
		t.Fatal("disabled mode accepted a hidden coordinator")
	}
}
