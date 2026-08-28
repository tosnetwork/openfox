package earning

import (
	"errors"
	"math/big"
	"sort"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

// RelayOwnerPolicy is the local allow-list applied after an ordinary signed
// OFFER Intent has authenticated a relay profile. Provider identity and
// endpoints deliberately do not live here: selecting either from a static
// global list would turn local policy into a central service registry.
type RelayOwnerPolicy struct {
	NetworkDomains      []agentrelay.NetworkDomain
	Modes               []agentrelay.Mode
	TransactionProfiles []agentrelay.TransactionProfile
	FinalityProfiles    []agentrelay.FinalityProfile
	MaximumSignedBytes  uint32
	MaximumServiceFees  []agentrelay.AssetAmount
}

// VerifiedRelayServiceProfile can only be produced by verifying both the
// signed discovery Intent and the owner's local network policy. Keeping the
// canonical profile bytes private prevents a caller from mutating slices after
// verification and then redirecting a relay request to another endpoint.
type VerifiedRelayServiceProfile struct {
	canonicalProfile []byte
	intentDigest     string
	policy           RelayOwnerPolicy
}

func (verified VerifiedRelayServiceProfile) Profile() agentrelay.RelayServiceProfile {
	var profile agentrelay.RelayServiceProfile
	_ = codec.Unmarshal(verified.canonicalProfile, &profile)
	return profile
}

func (verified VerifiedRelayServiceProfile) IntentDigest() string { return verified.intentDigest }

// VerifyDiscoveredRelayServiceProfile authenticates an inline profile carried
// by a normal signed OFFER Intent. Carrier identity/order is not consulted;
// finalized Agent authority, exact content bytes, and owner policy are the
// complete admission boundary.
func VerifyDiscoveredRelayServiceProfile(intent commerce.SignedAgentIntent, resolver commerce.IntentAuthorityResolver,
	policy RelayOwnerPolicy, now time.Time) (VerifiedRelayServiceProfile, error) {
	if err := validateRelayOwnerPolicy(policy); err != nil {
		return VerifiedRelayServiceProfile{}, err
	}
	if err := commerce.VerifyIntent(intent, resolver, now.UTC()); err != nil {
		return VerifiedRelayServiceProfile{}, err
	}
	descriptor := intent.Body.Payload.DetailDescriptor
	if descriptor.ContentType != agentrelay.ServiceProfileContentType || len(descriptor.InlineContent) == 0 {
		return VerifiedRelayServiceProfile{}, errors.New("relay service profile is not inline in the signed Intent")
	}
	var profile agentrelay.RelayServiceProfile
	if err := codec.Unmarshal(descriptor.InlineContent, &profile); err != nil {
		return VerifiedRelayServiceProfile{}, errors.New("relay service profile is not canonical")
	}
	if err := agentrelay.ValidateRelayServiceProfile(profile, now.UTC()); err != nil ||
		profile.ProviderAgentID != intent.Body.IssuerAgentID || profile.ExpiresAtUnix > intent.Body.ExpiresAtUnix ||
		!intentOffersRelayService(intent.Body) {
		return VerifiedRelayServiceProfile{}, errors.New("relay service profile conflicts with its signed OFFER Intent")
	}
	if !policyIntersectsProfile(policy, profile) {
		return VerifiedRelayServiceProfile{}, errors.New("relay service profile is outside owner network policy")
	}
	intentDigest, err := commerce.IntentBodyDigest(intent.Body)
	if err != nil {
		return VerifiedRelayServiceProfile{}, err
	}
	canonical, err := codec.Marshal(profile)
	if err != nil {
		return VerifiedRelayServiceProfile{}, err
	}
	return VerifiedRelayServiceProfile{canonicalProfile: canonical, intentDigest: intentDigest,
		policy: cloneRelayOwnerPolicy(policy)}, nil
}

func (verified VerifiedRelayServiceProfile) authorizeQuoteRequest(request agentrelay.SignedRelayQuoteRequest, now time.Time) error {
	if len(verified.canonicalProfile) == 0 {
		return errors.New("relay profile has not been verified")
	}
	profile := verified.Profile()
	transaction, transactionFound := relayTransactionProfile(profile.TransactionProfiles,
		request.Body.TransactionProfileURI, request.Body.TransactionProfileDigest)
	relayFinality, relayFinalityFound := relayFinalityProfile(profile.FinalityProfiles,
		request.Body.RelayFinalityProfileURI, request.Body.RelayFinalityProfileDigest)
	sponsorshipFinality, sponsorshipFinalityFound := relayFinalityProfile(profile.FinalityProfiles,
		request.Body.SponsorshipTerminalProfileURI, request.Body.SponsorshipTerminalProfileDigest)
	if err := agentrelay.ValidateRelayServiceProfile(profile, now.UTC()); err != nil ||
		request.Body.ProviderAgentID != profile.ProviderAgentID ||
		request.Body.SignedTransactionSize > verified.policy.MaximumSignedBytes ||
		!transactionFound || request.Body.SignedTransactionSize > transaction.MaximumSignedBytes ||
		!containsRelayTransactionProfile(verified.policy.TransactionProfiles, transaction) ||
		request.Body.Mode != agentrelay.ModeSponsorOnly && (!relayFinalityFound ||
			!containsRelayFinalityProfile(verified.policy.FinalityProfiles, relayFinality) ||
			relayFinality.TerminalEvidenceClass != request.Body.RelayTerminalEvidenceClass) ||
		request.Body.Mode != agentrelay.ModeRelayExact && (!sponsorshipFinalityFound ||
			!containsRelayFinalityProfile(verified.policy.FinalityProfiles, sponsorshipFinality) ||
			sponsorshipFinality.TerminalEvidenceClass != request.Body.SponsorshipTerminalEvidenceClass) ||
		!containsRelayNetwork(verified.policy.NetworkDomains, request.Body.Network) ||
		!containsRelayMode(verified.policy.Modes, request.Body.Mode) ||
		!withinOwnerServiceFee(verified.policy.MaximumServiceFees, request.Body.MaximumServiceFee) {
		return errors.New("relay quote request is outside the verified profile or owner policy")
	}
	return nil
}

func validateRelayOwnerPolicy(policy RelayOwnerPolicy) error {
	if len(policy.NetworkDomains) == 0 || len(policy.NetworkDomains) > 64 || len(policy.Modes) == 0 || len(policy.Modes) > 3 ||
		len(policy.TransactionProfiles) == 0 || len(policy.TransactionProfiles) > 32 ||
		len(policy.FinalityProfiles) == 0 || len(policy.FinalityProfiles) > 16 ||
		policy.MaximumSignedBytes == 0 || policy.MaximumSignedBytes > agentrelay.MaxSignedTransactionBytes ||
		len(policy.MaximumServiceFees) == 0 || len(policy.MaximumServiceFees) > 16 {
		return errors.New("relay owner policy is incomplete or unbounded")
	}
	for index, network := range policy.NetworkDomains {
		if _, err := agentrelay.NetworkDomainDigest(network); err != nil || index > 0 && relayNetworkKey(policy.NetworkDomains[index-1]) >= relayNetworkKey(network) {
			return errors.New("relay owner network policy is invalid or unsorted")
		}
	}
	for index, mode := range policy.Modes {
		if !knownRelayMode(mode) || index > 0 && policy.Modes[index-1] >= mode {
			return errors.New("relay owner mode policy is invalid or unsorted")
		}
	}
	for index, profile := range policy.TransactionProfiles {
		if len(profile.ProfileURI) == 0 || len(profile.ProfileURI) > 256 || !canonicalSHA256(profile.ProfileDigest) ||
			profile.MaximumSignedBytes == 0 || profile.MaximumSignedBytes > policy.MaximumSignedBytes ||
			!profile.InspectableSourceSequence || !profile.InspectableTransactionExpiry ||
			index > 0 && relayTransactionProfileKey(policy.TransactionProfiles[index-1]) >= relayTransactionProfileKey(profile) {
			return errors.New("relay owner transaction-profile policy is invalid or unsorted")
		}
	}
	for index, profile := range policy.FinalityProfiles {
		if len(profile.ProfileURI) == 0 || len(profile.ProfileURI) > 256 || !canonicalSHA256(profile.ProfileDigest) ||
			!knownRelayTerminalEvidenceClass(profile.TerminalEvidenceClass) ||
			profile.MinimumConfirmationDepth == 0 || profile.MinimumObservers == 0 || profile.MinimumOperatorDomains == 0 ||
			profile.MinimumOperatorDomains > profile.MinimumObservers || profile.MaximumResolutionSeconds == 0 ||
			profile.MaximumResolutionSeconds > 24*60*60 || profile.ReorgWindowSeconds > profile.MaximumResolutionSeconds ||
			index > 0 && relayFinalityProfileKey(policy.FinalityProfiles[index-1]) >= relayFinalityProfileKey(profile) {
			return errors.New("relay owner finality-profile policy is invalid or unsorted")
		}
	}
	previousAsset := ""
	for _, maximum := range policy.MaximumServiceFees {
		key := relayAssetKey(maximum.Asset)
		if key <= previousAsset || !canonicalRelayAtomic(maximum.AmountAtomic) {
			return errors.New("relay owner service-fee policy is invalid or unsorted")
		}
		previousAsset = key
	}
	return nil
}

func knownRelayTerminalEvidenceClass(class agentrelay.TerminalEvidenceClass) bool {
	return class == agentrelay.RelayTerminalValidatorFinality ||
		class == agentrelay.RelayTerminalProviderCorroborated ||
		class == agentrelay.SponsorshipTerminalClientCorroborated
}

func intentOffersRelayService(body commerce.AgentIntentBody) bool {
	offer, service, extension := false, false, false
	for _, mode := range body.Payload.DiscoveryCard.IntentModes {
		offer = offer || mode == commerce.IntentOffer
	}
	for _, class := range body.Payload.DiscoveryCard.SubjectClasses {
		service = service || class == commerce.SubjectService
	}
	for _, candidate := range body.Payload.RequiredExtensions {
		extension = extension || candidate == agentrelay.ProfileURI
	}
	return offer && service && extension
}

func policyIntersectsProfile(policy RelayOwnerPolicy, profile agentrelay.RelayServiceProfile) bool {
	network, mode, transaction, finality, fee := false, false, false, false, false
	for _, candidate := range profile.NetworkDomains {
		network = network || containsRelayNetwork(policy.NetworkDomains, candidate)
	}
	for _, candidate := range profile.SupportedModes {
		mode = mode || containsRelayMode(policy.Modes, candidate)
	}
	for _, candidate := range profile.TransactionProfiles {
		transaction = transaction || containsRelayTransactionProfile(policy.TransactionProfiles, candidate)
	}
	for _, candidate := range profile.FinalityProfiles {
		finality = finality || containsRelayFinalityProfile(policy.FinalityProfiles, candidate)
	}
	for _, candidate := range profile.FeeAssets {
		for _, maximum := range policy.MaximumServiceFees {
			fee = fee || candidate == maximum.Asset
		}
	}
	return network && mode && transaction && finality && fee && profile.MaximumRequestBytes <= policy.MaximumSignedBytes
}

func withinOwnerServiceFee(maxima []agentrelay.AssetAmount, requested agentrelay.AssetAmount) bool {
	for _, maximum := range maxima {
		if maximum.Asset != requested.Asset {
			continue
		}
		left, leftOK := new(big.Int).SetString(requested.AmountAtomic, 10)
		right, rightOK := new(big.Int).SetString(maximum.AmountAtomic, 10)
		return leftOK && rightOK && left.Sign() >= 0 && left.Cmp(right) <= 0
	}
	return false
}

func containsRelayNetwork(values []agentrelay.NetworkDomain, wanted agentrelay.NetworkDomain) bool {
	for _, candidate := range values {
		if candidate == wanted {
			return true
		}
	}
	return false
}

func containsRelayMode(values []agentrelay.Mode, wanted agentrelay.Mode) bool {
	index := sort.Search(len(values), func(index int) bool { return values[index] >= wanted })
	return index < len(values) && values[index] == wanted
}

func containsRelayTransactionProfile(values []agentrelay.TransactionProfile, wanted agentrelay.TransactionProfile) bool {
	index := sort.Search(len(values), func(index int) bool {
		return relayTransactionProfileKey(values[index]) >= relayTransactionProfileKey(wanted)
	})
	return index < len(values) && values[index] == wanted
}

func containsRelayFinalityProfile(values []agentrelay.FinalityProfile, wanted agentrelay.FinalityProfile) bool {
	index := sort.Search(len(values), func(index int) bool {
		return relayFinalityProfileKey(values[index]) >= relayFinalityProfileKey(wanted)
	})
	return index < len(values) && values[index] == wanted
}

func relayTransactionProfile(values []agentrelay.TransactionProfile, uri, digest string) (agentrelay.TransactionProfile, bool) {
	for _, candidate := range values {
		if candidate.ProfileURI == uri && candidate.ProfileDigest == digest {
			return candidate, true
		}
	}
	return agentrelay.TransactionProfile{}, false
}

func relayFinalityProfile(values []agentrelay.FinalityProfile, uri, digest string) (agentrelay.FinalityProfile, bool) {
	for _, candidate := range values {
		if candidate.ProfileURI == uri && candidate.ProfileDigest == digest {
			return candidate, true
		}
	}
	return agentrelay.FinalityProfile{}, false
}

func knownRelayMode(mode agentrelay.Mode) bool {
	return mode == agentrelay.ModeRelayExact || mode == agentrelay.ModeSponsorOnly || mode == agentrelay.ModeSponsorAndRelay
}

func relayNetworkKey(network agentrelay.NetworkDomain) string {
	digest, _ := agentrelay.NetworkDomainDigest(network)
	return network.NetworkID + "\x00" + digest
}

func relayAssetKey(asset agentrelay.AssetIdentity) string {
	return asset.AssetNamespace + "\x00" + asset.AssetIdentifier + "\x00" + asset.Unit
}

func relayTransactionProfileKey(profile agentrelay.TransactionProfile) string {
	return profile.ProfileURI + "\x00" + profile.ProfileDigest
}

func relayFinalityProfileKey(profile agentrelay.FinalityProfile) string {
	return profile.ProfileURI + "\x00" + profile.ProfileDigest
}

func canonicalRelayAtomic(value string) bool {
	if value == "0" {
		return true
	}
	if len(value) == 0 || len(value) > 78 || value[0] == '0' {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func cloneRelayOwnerPolicy(policy RelayOwnerPolicy) RelayOwnerPolicy {
	policy.NetworkDomains = append([]agentrelay.NetworkDomain(nil), policy.NetworkDomains...)
	policy.Modes = append([]agentrelay.Mode(nil), policy.Modes...)
	policy.TransactionProfiles = append([]agentrelay.TransactionProfile(nil), policy.TransactionProfiles...)
	policy.FinalityProfiles = append([]agentrelay.FinalityProfile(nil), policy.FinalityProfiles...)
	policy.MaximumServiceFees = append([]agentrelay.AssetAmount(nil), policy.MaximumServiceFees...)
	return policy
}
