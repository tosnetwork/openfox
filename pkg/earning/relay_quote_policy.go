package earning

import (
	"context"
	"errors"
	"math/big"
	"strings"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
)

const maximumRelayQuoteLifetime = 5 * time.Minute

// BoundedRelayQuotePolicy is the production fixed-price quote boundary. Fees,
// asset identity, lifetime, and the signed discovery Intent digest are all
// owner configuration; no request, model output, or remote service can alter
// them. ReserveQuote remains the atomic availability/exposure boundary.
type BoundedRelayQuotePolicy struct {
	offerIntentDigest string
	relayFee          agentrelay.AssetAmount
	sponsorshipFee    agentrelay.AssetAmount
	lifetime          time.Duration
}

func NewBoundedRelayQuotePolicy(offerIntentDigest string, relayFee,
	sponsorshipFee agentrelay.AssetAmount, lifetime time.Duration) (*BoundedRelayQuotePolicy, error) {
	if !canonicalSHA256(offerIntentDigest) || lifetime < time.Second || lifetime > maximumRelayQuoteLifetime ||
		!validFixedRelayFee(relayFee) || !validFixedRelayFee(sponsorshipFee) || relayFee.Asset != sponsorshipFee.Asset {
		return nil, errors.New("bounded relay quote policy is invalid")
	}
	return &BoundedRelayQuotePolicy{offerIntentDigest: offerIntentDigest, relayFee: relayFee,
		sponsorshipFee: sponsorshipFee, lifetime: lifetime}, nil
}

func (policy *BoundedRelayQuotePolicy) Quote(ctx context.Context, profile agentrelay.RelayServiceProfile,
	request agentrelay.SignedRelayQuoteRequest, now time.Time) (agentrelay.ProviderRelayQuoteBody, error) {
	var zero agentrelay.ProviderRelayQuoteBody
	if policy == nil || ctx == nil || now.IsZero() {
		return zero, errors.New("bounded relay quote policy is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	nowSeconds := now.UTC().Unix()
	if nowSeconds <= 0 || request.Body.CreatedAtUnix > uint64(nowSeconds) ||
		request.Body.ProviderAgentID != profile.ProviderAgentID ||
		!relayProfileSupportsAssurance(profile, request.Body.AssuranceLevel) ||
		request.Body.MaximumServiceFee.Asset != policy.relayFee.Asset || !relayProfileContainsFeeAsset(profile,
		policy.relayFee.Asset) {
		return zero, errors.New("relay quote request conflicts with fixed owner pricing")
	}
	requestDigest, err := agentrelay.RelayQuoteRequestDigest(request.Body)
	if err != nil {
		return zero, err
	}
	profileDigest, err := agentrelay.RelayServiceProfileDigest(profile)
	if err != nil {
		return zero, err
	}
	var relayFinality, sponsorshipFinality *agentrelay.FinalityProfile
	if request.Body.Mode != agentrelay.ModeSponsorOnly {
		selected, found := relayFinalityProfile(profile.FinalityProfiles,
			request.Body.RelayFinalityProfileURI, request.Body.RelayFinalityProfileDigest)
		if !found || selected.TerminalEvidenceClass != request.Body.RelayTerminalEvidenceClass {
			return zero, errors.New("relay quote selects an unsupported relay terminal profile")
		}
		relayFinality = &selected
	}
	if request.Body.Mode != agentrelay.ModeRelayExact {
		selected, found := relayFinalityProfile(profile.FinalityProfiles,
			request.Body.SponsorshipTerminalProfileURI, request.Body.SponsorshipTerminalProfileDigest)
		if !found || selected.TerminalEvidenceClass != request.Body.SponsorshipTerminalEvidenceClass {
			return zero, errors.New("relay quote selects an unsupported sponsorship terminal profile")
		}
		sponsorshipFinality = &selected
	}
	fees := make([]agentrelay.FeeLine, 0, 2)
	switch request.Body.Mode {
	case agentrelay.ModeRelayExact:
		fees = append(fees, agentrelay.FeeLine{Kind: agentrelay.ObligationRelayFee, Amount: policy.relayFee})
	case agentrelay.ModeSponsorOnly:
		fees = append(fees, agentrelay.FeeLine{Kind: agentrelay.ObligationSponsorshipFee, Amount: policy.sponsorshipFee})
	case agentrelay.ModeSponsorAndRelay:
		// Protocol canonical order is sponsorship fee followed by relay fee.
		fees = append(fees,
			agentrelay.FeeLine{Kind: agentrelay.ObligationSponsorshipFee, Amount: policy.sponsorshipFee},
			agentrelay.FeeLine{Kind: agentrelay.ObligationRelayFee, Amount: policy.relayFee})
	default:
		return zero, errors.New("relay quote mode is unsupported")
	}
	if !fixedRelayFeesWithinMaximum(fees, request.Body.MaximumServiceFee) {
		return zero, errors.New("fixed relay fee exceeds the requester maximum")
	}
	expires := uint64(now.Add(policy.lifetime).UTC().Unix())
	if expires > request.Body.ExpiresAtUnix {
		expires = request.Body.ExpiresAtUnix
	}
	if request.Body.TransactionValidUntilUnix == 0 {
		return zero, errors.New("relay transaction validity is missing")
	}
	if expires >= request.Body.TransactionValidUntilUnix {
		expires = request.Body.TransactionValidUntilUnix - 1
	}
	if expires <= uint64(nowSeconds) {
		return zero, errors.New("relay quote has no safe signed validity window")
	}
	body := agentrelay.ProviderRelayQuoteBody{SchemaVersion: 1,
		QuoteID: "quote:" + requestDigest[len("sha256:"):], QuoteRequestDigest: requestDigest,
		ServiceProfileDigest: profileDigest, ProviderAgentID: profile.ProviderAgentID, Mode: request.Body.Mode,
		AssuranceLevel:                   request.Body.AssuranceLevel,
		SponsorshipReleaseEvidenceClass:  request.Body.SponsorshipReleaseEvidenceClass,
		SponsorshipReleaseProfileURI:     request.Body.SponsorshipReleaseProfileURI,
		SponsorshipReleaseProfileDigest:  request.Body.SponsorshipReleaseProfileDigest,
		RelayTerminalEvidenceClass:       request.Body.RelayTerminalEvidenceClass,
		SponsorshipTerminalEvidenceClass: request.Body.SponsorshipTerminalEvidenceClass,
		FeeLines:                         fees, MaximumNetworkFeeAtomic: request.Body.MaximumNetworkFeeAtomic,
		MaximumTransactionValueAtomic: request.Body.MaximumTransactionValueAtomic,
		MaximumRequestBytes:           profile.MaximumRequestBytes, RelayFinalityProfile: relayFinality,
		SponsorshipTerminalProfile: sponsorshipFinality,
		StatusEndpoint:             profile.Endpoints.ResolveURL, ProviderPolicyRevision: profile.PolicyRevision,
		OfferIntentDigest: policy.offerIntentDigest, ValidFromUnix: uint64(nowSeconds), ExpiresAtUnix: expires}
	if request.Body.RequestedSponsorship != nil {
		reserved := *request.Body.RequestedSponsorship
		body.ReservedSponsorship = &reserved
	}
	return body, nil
}

func validFixedRelayFee(amount agentrelay.AssetAmount) bool {
	return boundedRelayQuoteIdentifier(amount.Asset.AssetNamespace, 128) &&
		boundedRelayQuoteIdentifier(amount.Asset.AssetIdentifier, 256) && boundedRelayQuoteIdentifier(amount.Asset.Unit, 128) &&
		canonicalRelayAtomic(amount.AmountAtomic)
}

func boundedRelayQuoteIdentifier(value string, maximum int) bool {
	return len(value) > 0 && len(value) <= maximum && strings.TrimSpace(value) == value &&
		!strings.ContainsAny(value, "\x00\r\n")
}

func relayProfileContainsFeeAsset(profile agentrelay.RelayServiceProfile, asset agentrelay.AssetIdentity) bool {
	for _, candidate := range profile.FeeAssets {
		if candidate == asset {
			return true
		}
	}
	return false
}

func fixedRelayFeesWithinMaximum(fees []agentrelay.FeeLine, maximum agentrelay.AssetAmount) bool {
	wanted, ok := new(big.Int).SetString(maximum.AmountAtomic, 10)
	if !ok || wanted.Sign() < 0 {
		return false
	}
	total := new(big.Int)
	for _, fee := range fees {
		value, valid := new(big.Int).SetString(fee.Amount.AmountAtomic, 10)
		if !valid || value.Sign() < 0 || fee.Amount.Asset != maximum.Asset {
			return false
		}
		total.Add(total, value)
	}
	return total.Cmp(wanted) <= 0
}

var _ agentrelay.QuotePolicy = (*BoundedRelayQuotePolicy)(nil)
