package earning

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

func TestProviderOfferAuthorityPinsEveryClaimedContextField(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, ed25519.SeedSize))
	digest := func(marker string) string { return "sha256:" + strings.Repeat(marker, 64) }
	policy := ProviderOfferAuthorityPolicy{AgentID: "agent:provider", PublicKey: key.Public().(ed25519.PublicKey), AgentGeneration: 3,
		ControllerPolicyDigest: digest("1"), DelegationDigest: digest("2"), ScopeBoundsDigest: digest("3"),
		OwnerMandateDigest: digest("4"), IssuanceAuthorityReferenceDigest: digest("5")}
	now := time.Unix(2_000_000_000, 0).UTC()
	context, err := policy.ProofContext("tos:test", uint64(now.Add(-time.Minute).Unix()), uint64(now.Add(time.Hour).Unix()))
	if err != nil {
		t.Fatal(err)
	}
	binding := commerce.PaidDemandQuoteBindingBody{ProviderAgentID: policy.AgentID}
	resolver := PinnedProviderOfferAuthorities{Policies: map[string]ProviderOfferAuthorityPolicy{policy.AgentID: policy}}
	if err := resolver.AuthorizeProviderOfferKey(context, binding, policy.PublicKey, now); err != nil {
		t.Fatal(err)
	}
	changed := context
	changed.DelegationDigest = digest("9")
	if err := resolver.AuthorizeProviderOfferKey(changed, binding, policy.PublicKey, now); err == nil {
		t.Fatal("self-asserted delegation context was accepted")
	}
}
