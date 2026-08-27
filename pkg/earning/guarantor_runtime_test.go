package earning

import "testing"

func TestGuarantorProviderRuntimeFailsClosedBeforeClaimingInbox(t *testing.T) {
	if runtime, err := NewGuarantorProviderRuntime(GuarantorProviderRuntimeConfig{}); err == nil || runtime != nil {
		t.Fatal("partial Guarantor Provider runtime was enabled")
	}
}
