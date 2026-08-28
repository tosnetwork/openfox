package earning

import "testing"

func TestLocalEconomicDomainLockIsKernelGlobalAndDomainSeparated(t *testing.T) {
	first, err := acquireLocalEconomicDomainLock(t.Name() + ":same")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if duplicate, err := acquireLocalEconomicDomainLock(t.Name() + ":same"); err == nil {
		_ = duplicate.Close()
		t.Fatal("same logical economic domain acquired a second host lock")
	}
	other, err := acquireLocalEconomicDomainLock(t.Name() + ":other")
	if err != nil {
		t.Fatal(err)
	}
	if err := other.Close(); err != nil {
		t.Fatal(err)
	}
}
