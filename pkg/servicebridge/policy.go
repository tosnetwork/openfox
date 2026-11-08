package servicebridge

import (
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
)

const nanoPerTOS = 1_000_000_000

// Costs is what one purchase commits, in nanoTOS, shown to the owner before
// the call.
type Costs struct {
	// Price is the service charge, returned only if no attested response
	// arrives and the refund is claimed in its window.
	Price *big.Int
	// StorageFee is never refunded, even when the provider never answers.
	StorageFee *big.Int
	// Allowance is the admission allowance attached with the call; the
	// contract returns unused execution funding.
	Allowance *big.Int
	// Attached is price + storage fee + allowance, the call's value.
	Attached *big.Int
	// RefundReserve is held for the two refund transactions.
	RefundReserve *big.Int
	// Committed is attached + refund reserve, what the policy bounds.
	Committed *big.Int
	// LossIfUnanswered is storage fee + refund reserve: the most a purchase
	// loses when the provider never answers and the refund is claimed.
	LossIfUnanswered  *big.Int
	ResponseSLA       uint32
	RefundClaimWindow uint32
}

// Disclosure is the text shown to the owner before a call.
func (c Costs) Disclosure() string {
	return fmt.Sprintf(
		"price %s TOS (refunded only if there is no attested response and the refund is claimed); "+
			"storage fee %s TOS (non-refundable, kept by the provider even on refund); admission allowance %s TOS; "+
			"attached with the call %s TOS (unused execution funding is returned); "+
			"a refund takes two transactions from this wallet inside a %d s window after the %d s response deadline, "+
			"expire then claim_refund (claim_refund attaches 0.2 TOS), each paying fees; %s TOS is reserved for them",
		tos(
			c.Price,
		),
		tos(c.StorageFee),
		tos(c.Allowance),
		tos(c.Attached),
		c.RefundClaimWindow,
		c.ResponseSLA,
		tos(c.RefundReserve),
	)
}

func tos(value *big.Int) string {
	if value == nil {
		return "?"
	}
	whole, fraction := new(big.Int).QuoRem(value, big.NewInt(nanoPerTOS), new(big.Int))
	return fmt.Sprintf("%s.%09d", whole.String(), fraction.Int64())
}

// QuoteCosts derives the costs of a Quote's rail terms.
func QuoteCosts(price, storageFee *big.Int, responseSLA, refundWindow uint32, refundReserve *big.Int) (Costs, error) {
	if price == nil || storageFee == nil || refundReserve == nil || price.Sign() <= 0 || storageFee.Sign() < 0 ||
		refundReserve.Sign() < 0 {
		return Costs{}, errors.New("servicebridge: invalid Quote costs")
	}
	attached, err := nativecore.MinimumServiceActorCallPayment(price, storageFee)
	if err != nil {
		return Costs{}, err
	}
	allowance := new(big.Int).Sub(attached, new(big.Int).Add(price, storageFee))
	return Costs{
		Price: new(
			big.Int,
		).Set(price),
		StorageFee:    new(big.Int).Set(storageFee),
		Allowance:     allowance,
		Attached:      attached,
		RefundReserve: new(big.Int).Set(refundReserve),
		Committed:     new(big.Int).Add(attached, refundReserve),
		LossIfUnanswered: new(
			big.Int,
		).Add(storageFee, refundReserve),
		ResponseSLA:       responseSLA,
		RefundClaimWindow: refundWindow,
	}, nil
}

// SpendingPolicy is the owner's bound on autonomous purchases.
type SpendingPolicy struct {
	MaxCommittedPerPurchase *big.Int
	MaxCommittedInWindow    *big.Int
	Window                  time.Duration
	MaxOpenPurchases        int
	// ConfirmAbove requires owner confirmation for a purchase committing
	// more; nil confirms every purchase automatically within the bounds.
	ConfirmAbove     *big.Int
	AllowedProviders map[string]bool
	RefundReserve    *big.Int
}

var (
	ErrOverPurchaseLimit = errors.New("servicebridge: the purchase commits more than the per-purchase limit")
	ErrOverWindowBudget  = errors.New("servicebridge: the purchase exceeds the remaining budget of the window")
	ErrTooManyOpen       = errors.New("servicebridge: too many purchases are open")
	ErrProviderNotAllow  = errors.New("servicebridge: the provider is not on the owner's allow-list")
	ErrNeedsConfirmation = errors.New("servicebridge: the owner must confirm this purchase")
)

// Validate refuses an unbounded policy.
func (p SpendingPolicy) Validate() error {
	if p.MaxCommittedPerPurchase == nil || p.MaxCommittedPerPurchase.Sign() <= 0 || p.MaxCommittedInWindow == nil ||
		p.MaxCommittedInWindow.Cmp(
			p.MaxCommittedPerPurchase,
		) < 0 || p.Window < time.Minute || p.Window > 366*24*time.Hour ||
		p.MaxOpenPurchases <= 0 || p.MaxOpenPurchases > 1024 || p.RefundReserve == nil || p.RefundReserve.Sign() < 0 ||
		(p.ConfirmAbove != nil && p.ConfirmAbove.Sign() < 0) || len(p.AllowedProviders) == 0 {
		return errors.New("servicebridge: the spending policy is incomplete or unbounded")
	}
	return nil
}

// Authorize checks one purchase against the policy given what the window
// already committed and how many purchases are open. It returns
// ErrNeedsConfirmation when the owner must confirm.
func (p SpendingPolicy) Authorize(provider string, costs Costs, committedInWindow *big.Int, open int) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if !p.AllowedProviders[provider] {
		return ErrProviderNotAllow
	}
	if costs.Committed == nil || committedInWindow == nil || committedInWindow.Sign() < 0 {
		return errors.New("servicebridge: invalid purchase accounting")
	}
	if costs.Committed.Cmp(p.MaxCommittedPerPurchase) > 0 {
		return ErrOverPurchaseLimit
	}
	if new(big.Int).Add(committedInWindow, costs.Committed).Cmp(p.MaxCommittedInWindow) > 0 {
		return ErrOverWindowBudget
	}
	if open >= p.MaxOpenPurchases {
		return ErrTooManyOpen
	}
	if p.ConfirmAbove != nil && costs.Committed.Cmp(p.ConfirmAbove) > 0 {
		return ErrNeedsConfirmation
	}
	return nil
}
