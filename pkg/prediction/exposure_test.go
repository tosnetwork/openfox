package prediction

import (
	"path/filepath"
	"testing"
)

func exposureProfile() OracleExposureProfile {
	return OracleExposureProfile{
		NetworkDomainHash:      testHash(0x10).SHA256String(),
		EventFamilyHash:        testHash(0x11).SHA256String(),
		OracleEpochHash:        testHash(0x12).SHA256String(),
		ContractCodeHash:       testHash(0x13).CellHashString(),
		MaximumExposure:        100 * testTOS,
		MaximumMarketsPerEpoch: 4,
	}
}

func exposureAdmission(id byte, ceiling uint64) MarketExposureAdmission {
	return MarketExposureAdmission{
		MarketID:         testHash(id).SHA256String(),
		MarketAddress:    rawAddress(id),
		MarketConfigHash: testHash(id + 1).CellHashString(),
		ExposureCeiling:  ceiling,
	}
}

func exposureObservation(admission MarketExposureAdmission, locked, seqno uint64) MarketExposureObservation {
	return MarketExposureObservation{
		MarketID:         admission.MarketID,
		MarketAddress:    admission.MarketAddress,
		MarketConfigHash: admission.MarketConfigHash,
		ContractCodeHash: exposureProfile().ContractCodeHash,
		LockedCollateral: locked,
		MasterchainSeqno: seqno,
		FinalityViewID:   testHash(byte(seqno)).SHA256String(),
		QuorumFinalized:  true,
	}
}

func TestOracleExposureReservesCeilingsAcrossMarketsAndRecovers(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "exposure")
	ledger, openErr := OpenOracleExposureLedger(directory, exposureProfile())
	if openErr != nil {
		t.Fatal(openErr)
	}
	first := exposureAdmission(0x21, 60*testTOS)
	second := exposureAdmission(0x31, 40*testTOS)
	if err := ledger.AdmitMarket(first); err != nil {
		t.Fatal(err)
	}
	if err := ledger.AdmitMarket(second); err != nil {
		t.Fatal(err)
	}
	if err := ledger.AdmitMarket(exposureAdmission(0x41, 1)); err == nil {
		t.Fatal("aggregate Oracle exposure ceiling was overcommitted")
	}
	if err := ledger.ObserveMarket(exposureObservation(first, 10*testTOS, 100)); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, reopenErr := OpenOracleExposureLedger(directory, exposureProfile())
	if reopenErr != nil {
		t.Fatalf("durable exposure ledger did not recover: %v", reopenErr)
	}
	ledger = reopened
	defer func() { _ = ledger.Close() }()
	if markets := ledger.ActiveMarkets(); len(markets) != 2 || markets[0].MarketID != first.MarketID {
		t.Fatalf("wrong recovered exposure admissions: %+v", markets)
	}
}

func TestOracleExposureRejectsRollbackAndReleasesOnlyClearedTerminal(t *testing.T) {
	ledger, err := OpenOracleExposureLedger(filepath.Join(t.TempDir(), "exposure"), exposureProfile())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ledger.Close() }()
	market := exposureAdmission(0x21, 60*testTOS)
	if err := ledger.AdmitMarket(market); err != nil {
		t.Fatal(err)
	}
	if err := ledger.ObserveMarket(exposureObservation(market, 20*testTOS, 100)); err != nil {
		t.Fatal(err)
	}
	if err := ledger.ObserveMarket(exposureObservation(market, 19*testTOS, 99)); err == nil {
		t.Fatal("older finalized observation rolled back exposure state")
	}
	conflict := exposureObservation(market, 19*testTOS, 100)
	if err := ledger.ObserveMarket(conflict); err == nil {
		t.Fatal("conflicting observation at one checkpoint was accepted")
	}
	terminal := exposureObservation(market, 1, 101)
	terminal.TerminalCompacted = true
	terminal.LiabilitiesCleared = true
	if err := ledger.ObserveMarket(terminal); err == nil {
		t.Fatal("terminal market released exposure while collateral remained")
	}
	terminal.LockedCollateral = 0
	terminal.LiabilitiesCleared = false
	if err := ledger.ObserveMarket(terminal); err == nil {
		t.Fatal("terminal market released exposure before liabilities cleared")
	}
	terminal.LiabilitiesCleared = true
	if err := ledger.ObserveMarket(terminal); err != nil {
		t.Fatal(err)
	}
	if err := ledger.ObserveMarket(terminal); err != nil {
		t.Fatal("exact terminal observation was not idempotent")
	}
	if len(ledger.ActiveMarkets()) != 0 {
		t.Fatal("cleared terminal market retained its aggregate exposure reservation")
	}
	if err := ledger.AdmitMarket(market); err == nil {
		t.Fatal("released market identity was reactivated")
	}
	if err := ledger.AdmitMarket(exposureAdmission(0x41, 100*testTOS)); err != nil {
		t.Fatal("released exposure was not reusable")
	}
}
