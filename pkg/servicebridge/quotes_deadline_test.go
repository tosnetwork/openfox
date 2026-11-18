package servicebridge

import (
	"context"
	"testing"
	"time"
)

func TestGatewayQuoteDeadlineIsFutureAndBounded(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	got := gatewayQuoteDeadline(context.Background(), now)
	if !got.After(now) {
		t.Fatalf("deadline %v is not after now %v; a gateway refuses it as expired", got, now)
	}
	if got.Sub(now) > 15*time.Minute {
		t.Fatalf("deadline %v is more than 15 minutes ahead; a gateway refuses it", got.Sub(now))
	}
	if got != now.Add(GatewayQuoteTimeout) {
		t.Fatalf("deadline %v, want now + %v", got, GatewayQuoteTimeout)
	}
}

func TestGatewayQuoteDeadlineKeepsASoonerCallerDeadline(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	sooner := now.Add(5 * time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), sooner)
	defer cancel()
	if got := gatewayQuoteDeadline(ctx, now); !got.Equal(sooner) {
		t.Fatalf("deadline %v, want the caller's sooner deadline %v", got, sooner)
	}
	later, cancelLater := context.WithDeadline(context.Background(), now.Add(time.Hour))
	defer cancelLater()
	if got := gatewayQuoteDeadline(later, now); !got.Equal(now.Add(GatewayQuoteTimeout)) {
		t.Fatalf("deadline %v, want the bounded default", got)
	}
}
