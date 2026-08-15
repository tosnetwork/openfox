package atosbridge

import (
	"errors"
	"testing"
	"time"
)

func basePolicy() SpendingPolicy {
	return SpendingPolicy{
		Asset:             AssetIdentity{Master: "EQmaster", WalletCodeHash: "tvm-cell-sha256:wc"},
		MaxAtomicPurchase: 25_000_000,
		DailyBudgetAtomic: 100_000_000,
		Window:            24 * time.Hour,
		Expiry:            time.Unix(2_000_000_000, 0),
		CapabilityAllow:   map[string]bool{"cap_sw": true},
		ConfirmationMode:  ConfirmAuto,
		OwnerSignature:    []byte("sig"),
	}
}

func baseProposal() QuoteProposal {
	return QuoteProposal{
		Capability:      CapabilityRef{CapabilityID: "cap_sw"},
		Asset:           AssetIdentity{Master: "EQmaster", WalletCodeHash: "tvm-cell-sha256:wc"},
		MaxAtomicAmount: 25_000_000,
	}
}

func TestPolicyAuthorize(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	eng := PolicyEngine{}

	t.Run("auto happy", func(t *testing.T) {
		if err := eng.Authorize(basePolicy(), baseProposal(), 0, now); err != nil {
			t.Fatalf("want nil, got %v", err)
		}
	})
	t.Run("invalid unsigned policy", func(t *testing.T) {
		p := basePolicy()
		p.OwnerSignature = nil
		if err := eng.Authorize(p, baseProposal(), 0, now); !errors.Is(err, ErrPolicyInvalid) {
			t.Fatalf("want ErrPolicyInvalid, got %v", err)
		}
	})
	t.Run("expired", func(t *testing.T) {
		p := basePolicy()
		p.Expiry = now.Add(-time.Second)
		if err := eng.Authorize(p, baseProposal(), 0, now); !errors.Is(err, ErrPolicyExpired) {
			t.Fatalf("want ErrPolicyExpired, got %v", err)
		}
	})
	t.Run("wrong asset master", func(t *testing.T) {
		pr := baseProposal()
		pr.Asset.Master = "EQother"
		if err := eng.Authorize(basePolicy(), pr, 0, now); !errors.Is(err, ErrAssetNotAllowed) {
			t.Fatalf("want ErrAssetNotAllowed, got %v", err)
		}
	})
	t.Run("wrong wallet code hash", func(t *testing.T) {
		pr := baseProposal()
		pr.Asset.WalletCodeHash = "tvm-cell-sha256:other"
		if err := eng.Authorize(basePolicy(), pr, 0, now); !errors.Is(err, ErrAssetNotAllowed) {
			t.Fatalf("want ErrAssetNotAllowed, got %v", err)
		}
	})
	t.Run("capability not allow-listed", func(t *testing.T) {
		pr := baseProposal()
		pr.Capability.CapabilityID = "cap_other"
		if err := eng.Authorize(basePolicy(), pr, 0, now); !errors.Is(err, ErrCapabilityNotAllowed) {
			t.Fatalf("want ErrCapabilityNotAllowed, got %v", err)
		}
	})
	t.Run("over per-purchase", func(t *testing.T) {
		pr := baseProposal()
		pr.MaxAtomicAmount = 25_000_001
		if err := eng.Authorize(basePolicy(), pr, 0, now); !errors.Is(err, ErrOverPurchaseLimit) {
			t.Fatalf("want ErrOverPurchaseLimit, got %v", err)
		}
	})
	t.Run("zero amount", func(t *testing.T) {
		pr := baseProposal()
		pr.MaxAtomicAmount = 0
		if err := eng.Authorize(basePolicy(), pr, 0, now); !errors.Is(err, ErrOverPurchaseLimit) {
			t.Fatalf("want ErrOverPurchaseLimit, got %v", err)
		}
	})
	t.Run("over daily budget", func(t *testing.T) {
		// budget 100M, already spent 80M, this 25M -> 105M > 100M.
		if err := eng.Authorize(basePolicy(), baseProposal(), 80_000_000, now); !errors.Is(err, ErrOverDailyBudget) {
			t.Fatalf("want ErrOverDailyBudget, got %v", err)
		}
	})
	t.Run("exact budget boundary allowed", func(t *testing.T) {
		// spent 75M + 25M == 100M == budget -> allowed.
		if err := eng.Authorize(basePolicy(), baseProposal(), 75_000_000, now); err != nil {
			t.Fatalf("boundary must pass, got %v", err)
		}
	})
	t.Run("overflow guard", func(t *testing.T) {
		p := basePolicy()
		p.DailyBudgetAtomic = ^uint64(0)
		p.MaxAtomicPurchase = ^uint64(0)
		pr := baseProposal()
		pr.MaxAtomicAmount = 10
		// spent already at max: no room, must reject without wrapping.
		if err := eng.Authorize(p, pr, ^uint64(0), now); !errors.Is(err, ErrOverDailyBudget) {
			t.Fatalf("overflow must reject, got %v", err)
		}
	})
	t.Run("manual requires confirmation", func(t *testing.T) {
		p := basePolicy()
		p.ConfirmationMode = ConfirmManual
		if err := eng.Authorize(p, baseProposal(), 0, now); !errors.Is(err, ErrManualConfirmation) {
			t.Fatalf("want ErrManualConfirmation, got %v", err)
		}
	})
}
