package servicebridge

import (
	"errors"
	"time"
)

// ConfirmationMode controls whether a spend proceeds automatically or requires
// explicit owner confirmation.
type ConfirmationMode string

const (
	ConfirmAuto   ConfirmationMode = "auto"
	ConfirmManual ConfirmationMode = "manual"
)

// SpendingPolicy is the owner-signed authorization envelope that bounds what an
// autonomous OpenFox buyer may spend. It is enforced locally before every
// purchase; it is not a consensus object, but it is signed by the owner and its
// signature is verified out of band before the engine trusts it.
type SpendingPolicy struct {
	Asset             AssetIdentity   // exact stablecoin master + wallet code hash
	MaxAtomicPurchase uint64          // per-purchase ceiling
	DailyBudgetAtomic uint64          // cumulative ceiling over Window
	Window            time.Duration   // budget window (>= 1 minute)
	Expiry            time.Time       // policy validity deadline
	CapabilityAllow   map[string]bool // explicit allow-list of Capability IDs
	ConfirmationMode  ConfirmationMode
	OwnerSignature    []byte // owner signature over the canonical policy preimage
}

func (p SpendingPolicy) valid() bool {
	return p.Asset.Master != "" && p.Asset.WalletCodeHash != "" &&
		p.MaxAtomicPurchase > 0 && p.DailyBudgetAtomic >= p.MaxAtomicPurchase &&
		p.Window >= time.Minute && !p.Expiry.IsZero() &&
		len(p.CapabilityAllow) > 0 && len(p.OwnerSignature) > 0 &&
		(p.ConfirmationMode == ConfirmAuto || p.ConfirmationMode == ConfirmManual)
}

var (
	ErrPolicyInvalid        = errors.New("servicebridge: owner spending policy is invalid or unsigned")
	ErrPolicyExpired        = errors.New("servicebridge: owner spending policy has expired")
	ErrAssetNotAllowed      = errors.New("servicebridge: quote asset does not match the policy asset identity")
	ErrCapabilityNotAllowed = errors.New("servicebridge: capability is not on the owner allow-list")
	ErrOverPurchaseLimit    = errors.New("servicebridge: quote amount exceeds the per-purchase limit")
	ErrOverDailyBudget      = errors.New("servicebridge: quote amount exceeds the remaining windowed budget")
	ErrManualConfirmation   = errors.New("servicebridge: policy requires manual owner confirmation")
)

// PolicyEngine authorizes a Quote Proposal against an owner spending policy.
// spentInWindowAtomic is the exact amount already reserved/spent within the
// policy Window (counted from the crash-safe journal, including unresolved
// reservations). All arithmetic is overflow-safe.
type PolicyEngine struct{}

// Authorize returns nil if the proposal is within policy. It never mutates
// state; budget accounting is the caller's crash-safe journal responsibility.
// When the policy is in ConfirmManual mode it returns ErrManualConfirmation so
// the caller can route the proposal through a Confirmer before proceeding.
func (PolicyEngine) Authorize(policy SpendingPolicy, proposal QuoteProposal, spentInWindowAtomic uint64, now time.Time) error {
	if !policy.valid() {
		return ErrPolicyInvalid
	}
	if !now.Before(policy.Expiry) {
		return ErrPolicyExpired
	}
	if proposal.Asset.Master != policy.Asset.Master ||
		proposal.Asset.WalletCodeHash != policy.Asset.WalletCodeHash {
		return ErrAssetNotAllowed
	}
	if !policy.CapabilityAllow[proposal.Capability.CapabilityID] {
		return ErrCapabilityNotAllowed
	}
	amount := proposal.MaxAtomicAmount
	if amount == 0 || amount > policy.MaxAtomicPurchase {
		return ErrOverPurchaseLimit
	}
	// spentInWindow + amount <= DailyBudget, overflow-safe.
	if spentInWindowAtomic > policy.DailyBudgetAtomic ||
		amount > policy.DailyBudgetAtomic-spentInWindowAtomic {
		return ErrOverDailyBudget
	}
	if policy.ConfirmationMode == ConfirmManual {
		return ErrManualConfirmation
	}
	return nil
}
