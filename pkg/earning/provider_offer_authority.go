package earning

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

// ProviderOfferAuthorityPolicy pins the complete off-chain authority context
// that a Provider Offer is allowed to assert. A key match alone is not enough:
// generation, delegation, mandate, scope, and issuance reference are all
// owner-configured facts rather than self-authenticating fields in the offer.
type ProviderOfferAuthorityPolicy struct {
	AgentID                          string
	PublicKey                        ed25519.PublicKey
	AgentGeneration                  uint64
	ControllerPolicyDigest           string
	DelegationDigest                 string
	ScopeBoundsDigest                string
	OwnerMandateDigest               string
	IssuanceAuthorityReferenceDigest string
}

type PinnedProviderOfferAuthorities struct {
	Policies map[string]ProviderOfferAuthorityPolicy
}

type PolicyProviderOfferSigner struct {
	Policy ProviderOfferAuthorityPolicy
	Key    ed25519.PrivateKey
	TTL    time.Duration
}

func (signer PolicyProviderOfferSigner) SignProviderOffer(binding commerce.PaidDemandQuoteBindingBody,
	now time.Time) (commerce.SignedProviderOffer, error) {
	if len(signer.Key) != ed25519.PrivateKeySize || !bytes.Equal(signer.Key.Public().(ed25519.PublicKey), signer.Policy.PublicKey) ||
		binding.ProviderAgentID != signer.Policy.AgentID {
		return commerce.SignedProviderOffer{}, errors.New("Provider Offer signer is not bound to the pinned authority")
	}
	ttl := signer.TTL
	if ttl == 0 {
		ttl = time.Hour
	}
	if ttl < time.Minute || ttl > 24*time.Hour {
		return commerce.SignedProviderOffer{}, errors.New("Provider Offer proof lifetime is invalid")
	}
	validFrom := now.UTC().Add(-commerce.MaxIntentClockSkew)
	expires := now.UTC().Add(ttl)
	if accept := time.Unix(int64(binding.AcceptByUnix), 0).UTC(); !expires.After(accept) {
		expires = accept.Add(time.Minute)
	}
	context, err := signer.Policy.ProofContext(binding.NetworkContext, uint64(validFrom.Unix()), uint64(expires.Unix()))
	if err != nil {
		return commerce.SignedProviderOffer{}, err
	}
	return commerce.SignProviderOffer(binding, context, signer.Key)
}

func (resolver PinnedProviderOfferAuthorities) AuthorizeProviderOfferKey(context commerce.ProviderProofContext,
	binding commerce.PaidDemandQuoteBindingBody, key ed25519.PublicKey, now time.Time) error {
	policy, found := resolver.Policies[binding.ProviderAgentID]
	if !found || policy.AgentID != binding.ProviderAgentID || len(policy.PublicKey) != ed25519.PublicKeySize ||
		!bytes.Equal(policy.PublicKey, key) || context.ProviderAgentID != policy.AgentID ||
		context.AgentGeneration != policy.AgentGeneration || context.ControllerPolicyDigest != policy.ControllerPolicyDigest ||
		context.DelegationDigest != policy.DelegationDigest || context.ScopeBoundsDigest != policy.ScopeBoundsDigest ||
		context.OwnerMandateDigest != policy.OwnerMandateDigest ||
		context.IssuanceAuthorityReferenceDigest != policy.IssuanceAuthorityReferenceDigest ||
		now.UTC().Before(time.Unix(int64(context.ValidFromUnix), 0).UTC()) ||
		!now.UTC().Before(time.Unix(int64(context.ExpiresAtUnix), 0).UTC()) {
		return errors.New("Provider Offer authority context is not owner-pinned or current")
	}
	return nil
}

func (policy ProviderOfferAuthorityPolicy) ProofContext(network string, validFrom, expiresAt uint64) (commerce.ProviderProofContext, error) {
	if policy.AgentID == "" || len(policy.PublicKey) != ed25519.PublicKeySize || validFrom == 0 || expiresAt <= validFrom {
		return commerce.ProviderProofContext{}, errors.New("invalid Provider Offer authority policy")
	}
	return commerce.ProviderProofContext{SchemaVersion: 1, NetworkContext: network, ProviderAgentID: policy.AgentID,
		Purpose: "provider-offer.sign", PublicKey: "ed25519:" + encodeLowerHex(policy.PublicKey),
		AgentGeneration: policy.AgentGeneration, ControllerPolicyDigest: policy.ControllerPolicyDigest,
		DelegationDigest: policy.DelegationDigest, ScopeBoundsDigest: policy.ScopeBoundsDigest,
		OwnerMandateDigest:               policy.OwnerMandateDigest,
		IssuanceAuthorityReferenceDigest: policy.IssuanceAuthorityReferenceDigest,
		ValidFromUnix:                    validFrom, ExpiresAtUnix: expiresAt}, nil
}

func encodeLowerHex(value []byte) string {
	const alphabet = "0123456789abcdef"
	output := make([]byte, len(value)*2)
	for index, item := range value {
		output[index*2], output[index*2+1] = alphabet[item>>4], alphabet[item&15]
	}
	return string(output)
}

var _ commerce.ProviderOfferKeyResolver = PinnedProviderOfferAuthorities{}
