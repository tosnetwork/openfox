package earning

import (
	"math"
	"testing"
)

// TestGuarantorPortfolioClaimCountIsChecked: the claim count of a portfolio is
// added with a range check at both ends of the range.
func TestGuarantorPortfolioClaimCountIsChecked(t *testing.T) {
	if total, err := addGuarantorClaimCount(math.MaxUint32-2, 2); err != nil || total != math.MaxUint32 {
		t.Fatalf("a claim count that fits: %d err=%v", total, err)
	}
	if total, err := addGuarantorClaimCount(0, 0); err != nil || total != 0 {
		t.Fatalf("an empty claim count: %d err=%v", total, err)
	}
	if total, err := addGuarantorClaimCount(math.MaxUint32-2, 3); err == nil {
		t.Fatalf("a claim count past its range was added as %d", total)
	}
	if total, err := addGuarantorClaimCount(0, math.MaxUint32+1); err == nil {
		t.Fatalf("one coverage's claim count past the range was added as %d", total)
	}
}
