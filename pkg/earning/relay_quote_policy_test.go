package earning

import (
	"testing"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
)

func TestBoundedRelayQuotePolicyBindsFixedFeesAndSignedIntent(t *testing.T) {
	for _, mode := range []agentrelay.Mode{agentrelay.ModeRelayExact, agentrelay.ModeSponsorOnly,
		agentrelay.ModeSponsorAndRelay} {
		t.Run(string(mode), func(t *testing.T) {
			fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
			if mode != agentrelay.ModeRelayExact {
				fixture.enableSponsorship(t, mode)
			}
			policy, err := NewBoundedRelayQuotePolicy(fixture.verified.IntentDigest(),
				agentrelay.AssetAmount{Asset: fixture.asset, AmountAtomic: "3"},
				agentrelay.AssetAmount{Asset: fixture.asset, AmountAtomic: "2"}, 2*time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			request, err := agentrelay.SignRelayQuoteRequest(fixture.prepared.QuoteBody, fixture.clientKey)
			if err != nil {
				t.Fatal(err)
			}
			body, err := policy.Quote(t.Context(), fixture.profile, request, fixture.now)
			if err != nil {
				t.Fatal(err)
			}
			signed, err := agentrelay.SignProviderRelayQuote(body, fixture.providerKey)
			if err != nil || agentrelay.VerifyProviderRelayQuote(signed, request, fixture.profile,
				fixture.resolver, fixture.now) != nil {
				t.Fatalf("fixed quote did not verify: body=%+v err=%v", body, err)
			}
			if body.OfferIntentDigest != fixture.verified.IntentDigest() ||
				body.ExpiresAtUnix != uint64(fixture.now.Add(2*time.Minute).Unix()) {
				t.Fatalf("quote changed owner discovery or lifetime: %+v", body)
			}
			wantLines := 1
			if mode == agentrelay.ModeSponsorAndRelay {
				wantLines = 2
			}
			if len(body.FeeLines) != wantLines || mode != agentrelay.ModeRelayExact && body.ReservedSponsorship == nil {
				t.Fatalf("quote mode has wrong fee/sponsorship shape: %+v", body)
			}
		})
	}
}

func TestBoundedRelayQuotePolicyRejectsRequestAboveOwnerPricingOrFutureCreation(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	policy, err := NewBoundedRelayQuotePolicy(fixture.verified.IntentDigest(),
		agentrelay.AssetAmount{Asset: fixture.asset, AmountAtomic: "11"},
		agentrelay.AssetAmount{Asset: fixture.asset, AmountAtomic: "2"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	request, err := agentrelay.SignRelayQuoteRequest(fixture.prepared.QuoteBody, fixture.clientKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Quote(t.Context(), fixture.profile, request, fixture.now); err == nil {
		t.Fatal("fixed owner fee above requester maximum was quoted")
	}
	policy, err = NewBoundedRelayQuotePolicy(fixture.verified.IntentDigest(),
		agentrelay.AssetAmount{Asset: fixture.asset, AmountAtomic: "3"},
		agentrelay.AssetAmount{Asset: fixture.asset, AmountAtomic: "2"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	future := fixture.prepared.QuoteBody
	future.CreatedAtUnix = uint64(fixture.now.Add(time.Second).Unix())
	request, err = agentrelay.SignRelayQuoteRequest(future, fixture.clientKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Quote(t.Context(), fixture.profile, request, fixture.now); err == nil {
		t.Fatal("future-created request received a currently valid quote")
	}
}
