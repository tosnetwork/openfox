package nativeimpl

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tosnetwork/openfox/pkg/servicebridge"
)

// The spending-policy vectors are the shared iOS/Android ground truth for the
// owner authorization the mobile client enforces before every purchase. This
// test proves they match the real servicebridge.PolicyEngine, mapping its typed
// errors to the deterministic reason the platforms reproduce.

type policyFields struct {
	AssetMaster         *string   `json:"asset_master"`
	AssetWalletCodeHash *string   `json:"asset_wallet_code_hash"`
	MaxAtomicPurchase   *string   `json:"max_atomic_purchase"`
	DailyBudgetAtomic   *string   `json:"daily_budget_atomic"`
	WindowSeconds       *int64    `json:"window_seconds"`
	ExpiryUnix          *int64    `json:"expiry_unix"`
	CapabilityAllow     *[]string `json:"capability_allow"`
	ConfirmationMode    *string   `json:"confirmation_mode"`
	HasOwnerSignature   *bool     `json:"has_owner_signature"`
}

type proposalFields struct {
	AssetMaster         *string `json:"asset_master"`
	AssetWalletCodeHash *string `json:"asset_wallet_code_hash"`
	MaxAtomicAmount     *string `json:"max_atomic_amount"`
	CapabilityID        *string `json:"capability_id"`
}

type policyCase struct {
	Name          string          `json:"name"`
	Policy        *policyFields   `json:"policy"`
	Proposal      *proposalFields `json:"proposal"`
	SpentInWindow string          `json:"spent_in_window_atomic"`
	Expect        string          `json:"expect"`
}

type policyVectors struct {
	Schema       string         `json:"schema"`
	NowUnix      int64          `json:"now_unix"`
	PolicyBase   policyFields   `json:"policy_base"`
	ProposalBase proposalFields `json:"proposal_base"`
	Cases        []policyCase   `json:"cases"`
}

func reasonFor(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, servicebridge.ErrPolicyInvalid):
		return "policy_invalid"
	case errors.Is(err, servicebridge.ErrPolicyExpired):
		return "policy_expired"
	case errors.Is(err, servicebridge.ErrAssetNotAllowed):
		return "asset_not_allowed"
	case errors.Is(err, servicebridge.ErrCapabilityNotAllowed):
		return "capability_not_allowed"
	case errors.Is(err, servicebridge.ErrOverPurchaseLimit):
		return "over_purchase_limit"
	case errors.Is(err, servicebridge.ErrOverDailyBudget):
		return "over_daily_budget"
	case errors.Is(err, servicebridge.ErrManualConfirmation):
		return "manual_confirmation"
	default:
		return "unexpected:" + err.Error()
	}
}

func mergePolicy(base policyFields, over *policyFields) policyFields {
	result := base
	if over == nil {
		return result
	}
	if over.AssetMaster != nil {
		result.AssetMaster = over.AssetMaster
	}
	if over.AssetWalletCodeHash != nil {
		result.AssetWalletCodeHash = over.AssetWalletCodeHash
	}
	if over.MaxAtomicPurchase != nil {
		result.MaxAtomicPurchase = over.MaxAtomicPurchase
	}
	if over.DailyBudgetAtomic != nil {
		result.DailyBudgetAtomic = over.DailyBudgetAtomic
	}
	if over.WindowSeconds != nil {
		result.WindowSeconds = over.WindowSeconds
	}
	if over.ExpiryUnix != nil {
		result.ExpiryUnix = over.ExpiryUnix
	}
	if over.CapabilityAllow != nil {
		result.CapabilityAllow = over.CapabilityAllow
	}
	if over.ConfirmationMode != nil {
		result.ConfirmationMode = over.ConfirmationMode
	}
	if over.HasOwnerSignature != nil {
		result.HasOwnerSignature = over.HasOwnerSignature
	}
	return result
}

func mergeProposal(base proposalFields, over *proposalFields) proposalFields {
	result := base
	if over == nil {
		return result
	}
	if over.AssetMaster != nil {
		result.AssetMaster = over.AssetMaster
	}
	if over.AssetWalletCodeHash != nil {
		result.AssetWalletCodeHash = over.AssetWalletCodeHash
	}
	if over.MaxAtomicAmount != nil {
		result.MaxAtomicAmount = over.MaxAtomicAmount
	}
	if over.CapabilityID != nil {
		result.CapabilityID = over.CapabilityID
	}
	return result
}

func buildPolicy(t *testing.T, f policyFields) servicebridge.SpendingPolicy {
	t.Helper()
	allow := map[string]bool{}
	for _, id := range *f.CapabilityAllow {
		allow[id] = true
	}
	var signature []byte
	if *f.HasOwnerSignature {
		signature = []byte("owner-signature")
	}
	return servicebridge.SpendingPolicy{
		Asset:             servicebridge.AssetIdentity{Master: *f.AssetMaster, WalletCodeHash: *f.AssetWalletCodeHash},
		MaxAtomicPurchase: mustU64(t, *f.MaxAtomicPurchase),
		DailyBudgetAtomic: mustU64(t, *f.DailyBudgetAtomic),
		Window:            time.Duration(*f.WindowSeconds) * time.Second,
		Expiry:            time.Unix(*f.ExpiryUnix, 0),
		CapabilityAllow:   allow,
		ConfirmationMode:  servicebridge.ConfirmationMode(*f.ConfirmationMode),
		OwnerSignature:    signature,
	}
}

func buildProposal(t *testing.T, f proposalFields) servicebridge.QuoteProposal {
	t.Helper()
	return servicebridge.QuoteProposal{
		Capability:      servicebridge.CapabilityRef{CapabilityID: *f.CapabilityID},
		Asset:           servicebridge.AssetIdentity{Master: *f.AssetMaster, WalletCodeHash: *f.AssetWalletCodeHash},
		MaxAtomicAmount: mustU64(t, *f.MaxAtomicAmount),
	}
}

func mustU64(t *testing.T, value string) uint64 {
	n, err := atomicUint64(value)
	if err != nil {
		t.Fatalf("bad atomic amount %q: %v", value, err)
	}
	return n
}

func TestMobileSpendingPolicyVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "mobile_buyer_spending_policy_v1.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vectors policyVectors
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("decode vectors: %v", err)
	}
	if vectors.Schema != "tos.service.mobile-buyer-spending-policy.v1" || len(vectors.Cases) == 0 {
		t.Fatalf("unexpected vector schema/shape: %q", vectors.Schema)
	}
	now := time.Unix(vectors.NowUnix, 0)

	for _, c := range vectors.Cases {
		t.Run(c.Name, func(t *testing.T) {
			policy := buildPolicy(t, mergePolicy(vectors.PolicyBase, c.Policy))
			proposal := buildProposal(t, mergeProposal(vectors.ProposalBase, c.Proposal))
			spent := mustU64(t, c.SpentInWindow)

			err := (servicebridge.PolicyEngine{}).Authorize(policy, proposal, spent, now)
			if got := reasonFor(err); got != c.Expect {
				t.Fatalf("case %s: got reason %q, want %q", c.Name, got, c.Expect)
			}
		})
	}
}
