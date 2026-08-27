package earning

import (
	"math"
	"testing"
)

func TestGuarantorProviderRuntimeFailsClosedBeforeClaimingInbox(t *testing.T) {
	if runtime, err := NewGuarantorProviderRuntime(GuarantorProviderRuntimeConfig{}); err == nil || runtime != nil {
		t.Fatal("partial Guarantor Provider runtime was enabled")
	}
}

func TestGuarantorRuntimeRejectsUnixTimestampWraparound(t *testing.T) {
	if validGuarantorUnix(0) || validGuarantorUnix(uint64(math.MaxInt64)+1) || !validGuarantorUnix(math.MaxInt64) {
		t.Fatal("Guarantor runtime Unix timestamp boundary is not fail-closed")
	}
}
