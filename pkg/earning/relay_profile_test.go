package earning

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

func TestRelayProfileRequiresSignedIntentAndOwnerNetworkPolicy(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	intent := relayProfileIntent(t, fixture.profile, fixture.providerKey, fixture.now)
	mutatedProfile := fixture.profile
	mutatedProfile.Endpoints.SubmitURL = "https://attacker.example/submit"
	mutatedContent, err := codec.Marshal(mutatedProfile)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(mutatedContent)
	intent.Body.Payload.DetailDescriptor.InlineContent = mutatedContent
	intent.Body.Payload.DetailDescriptor.ContentSize = uint64(len(mutatedContent))
	intent.Body.Payload.DetailDescriptor.ContentDigest = "sha256:" + hex.EncodeToString(digest[:])
	policy := RelayOwnerPolicy{NetworkDomains: []agentrelay.NetworkDomain{fixture.network},
		Modes: []agentrelay.Mode{agentrelay.ModeRelayExact}, TransactionProfiles: []agentrelay.TransactionProfile{fixture.transaction},
		FinalityProfiles: []agentrelay.FinalityProfile{fixture.finality}, MaximumSignedBytes: agentrelay.MaxSignedTransactionBytes,
		MaximumServiceFees: []agentrelay.AssetAmount{{Asset: fixture.asset, AmountAtomic: "10"}}}
	if _, err := VerifyDiscoveredRelayServiceProfile(intent, fixture.resolver, policy, fixture.now); err == nil {
		t.Fatal("mutated profile bytes borrowed the original Intent signature")
	}

	foreign := fixture.network
	foreign.ZeroStateRootHash = relayTestDigest("9")
	policy.NetworkDomains = []agentrelay.NetworkDomain{foreign}
	validIntent := relayProfileIntent(t, fixture.profile, fixture.providerKey, fixture.now)
	if _, err := VerifyDiscoveredRelayServiceProfile(validIntent, fixture.resolver, policy, fixture.now); err == nil {
		t.Fatal("display-identical network with another zero state passed owner policy")
	}

	policy.NetworkDomains = []agentrelay.NetworkDomain{fixture.network}
	weakened := fixture.profile
	weakened.FinalityProfiles = append([]agentrelay.FinalityProfile(nil), fixture.profile.FinalityProfiles...)
	weakened.FinalityProfiles[0].MinimumConfirmationDepth--
	if _, err := VerifyDiscoveredRelayServiceProfile(relayProfileIntent(t, weakened, fixture.providerKey, fixture.now),
		fixture.resolver, policy, fixture.now); err == nil {
		t.Fatal("provider-advertised weak finality replaced the complete owner-pinned descriptor")
	}
}

func TestVerifiedRelayProfileCannotBeMutatedAfterAdmission(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	first := fixture.verified.Profile()
	first.NetworkDomains[0].NetworkID = "tos:attacker"
	first.SupportedModes[0] = agentrelay.ModeSponsorAndRelay
	first.Endpoints.SubmitURL = "https://attacker.example/submit"
	second := fixture.verified.Profile()
	if second.NetworkDomains[0] != fixture.network || second.SupportedModes[0] != agentrelay.ModeRelayExact ||
		second.Endpoints.SubmitURL != fixture.profile.Endpoints.SubmitURL {
		t.Fatal("verified relay profile exposed mutable admitted slices or endpoints")
	}
}
