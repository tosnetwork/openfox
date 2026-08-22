package nativeimpl

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/tosnetwork/openfox/pkg/opportunity"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/buyersdk"
	"github.com/tosnetwork/tos-service-protocol/pkg/gatewayfederation"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
)

type OpportunityCoordinatorConfig struct {
	Federation       *gatewayfederation.Federation
	Gateways         []gatewayfederation.Gateway
	Verifier         *buyersdk.CapabilityVerifier
	Network          *nativev1.NetworkDomain
	RegistryCodeHash string
	CallerID         string
	Now              func() time.Time
}

type OpportunityCoordinator struct {
	federation *gatewayfederation.Federation
	gateways   []gatewayfederation.Gateway
	verifier   *buyersdk.CapabilityVerifier
	network    opportunity.Network
	callerID   string
	now        func() time.Time
}

func NewOpportunityCoordinator(config OpportunityCoordinatorConfig) (*OpportunityCoordinator, error) {
	if config.Federation == nil || len(config.Gateways) < 2 || len(config.Gateways) > 32 || config.Verifier == nil ||
		config.Network == nil || config.Network.NetworkId == "" || config.RegistryCodeHash == "" ||
		config.CallerID == "" || len(config.CallerID) > 128 {
		return nil, errors.New("nativeimpl: opportunity coordinator authority is incomplete")
	}
	root := strings.TrimPrefix(config.Network.GenesisRootHash, "sha256:")
	file := strings.TrimPrefix(config.Network.GenesisFileHash, "sha256:")
	if len(root) != 64 || len(file) != 64 {
		return nil, errors.New("nativeimpl: opportunity coordinator network is invalid")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &OpportunityCoordinator{federation: config.Federation,
		gateways: append([]gatewayfederation.Gateway(nil), config.Gateways...), verifier: config.Verifier,
		network:  opportunity.Network{ID: config.Network.NetworkId, GenesisRootHash: root, GenesisFileHash: file},
		callerID: config.CallerID, now: config.Now}, nil
}

func (c *OpportunityCoordinator) Search(ctx context.Context, request opportunity.SearchRequest) ([]opportunity.CandidateHint, error) {
	if c == nil || ctx == nil || request.RequestID == "" || request.Query == "" || request.PageSize == 0 ||
		request.PageSize > 100 || request.MaxCandidates == 0 || request.MaxCandidates > 1000 || request.DeadlineUnixMS <= c.now().UnixMilli() {
		return nil, errors.New("nativeimpl: invalid bounded opportunity search")
	}
	pageSize := request.PageSize
	if request.MaxCandidates < pageSize {
		pageSize = request.MaxCandidates
	}
	candidates, _, err := c.federation.Search(ctx, c.gateways, &nativev1.SearchCapabilitiesRequest{
		Context: &nativev1.RequestContext{RequestId: request.RequestID, CallerId: c.callerID,
			DeadlineUnixMillis: request.DeadlineUnixMS}, Query: request.Query, PageSize: pageSize,
	})
	if err != nil {
		return nil, err
	}
	type aggregate struct {
		hint opportunity.CandidateHint
		seen map[string]struct{}
	}
	byKey := make(map[opportunity.CandidateKey]*aggregate)
	for _, candidate := range candidates {
		state := candidate.Result.GetCapability()
		capability := state.GetCapability()
		key := opportunity.CandidateKey{Network: c.network, CapabilityID: capability.GetCapabilityId(),
			Version: candidate.Result.GetCapabilityVersion(), ManifestDigest: candidate.Result.GetManifestDigest(),
			ProviderAgentID: capability.GetOwnerAgentId()}
		entry := byKey[key]
		if entry == nil {
			local := candidate.Result.GetGatewayLocal()
			entry = &aggregate{hint: opportunity.CandidateHint{Key: key, HintCheckpoint: state.GetReference().GetFinalizedCheckpoint(),
				DisplayName: safeDisplay(local.GetName(), 128), DisplayDescription: safeDisplay(local.GetDescription(), 2048),
				OperationHint: safeToken(local.GetOperation(), 64), GatewayMatchScore: local.GetMatchScore()}, seen: map[string]struct{}{}}
			byKey[key] = entry
		}
		if state.GetReference().GetFinalizedCheckpoint() > entry.hint.HintCheckpoint {
			entry.hint.HintCheckpoint = state.GetReference().GetFinalizedCheckpoint()
		}
		if local := candidate.Result.GetGatewayLocal(); local.GetMatchScore() > entry.hint.GatewayMatchScore {
			entry.hint.GatewayMatchScore = local.GetMatchScore()
		}
		entry.seen[candidate.GatewayID] = struct{}{}
	}
	hints := make([]opportunity.CandidateHint, 0, len(byKey))
	for _, entry := range byKey {
		for gateway := range entry.seen {
			entry.hint.GatewayIDs = append(entry.hint.GatewayIDs, gateway)
		}
		sort.Strings(entry.hint.GatewayIDs)
		hints = append(hints, entry.hint)
	}
	sort.Slice(hints, func(i, j int) bool {
		if hints[i].GatewayMatchScore != hints[j].GatewayMatchScore {
			return hints[i].GatewayMatchScore > hints[j].GatewayMatchScore
		}
		return hints[i].Key.CapabilityID < hints[j].Key.CapabilityID
	})
	limit := request.MaxCandidates
	if pageSize < limit {
		limit = pageSize
	}
	if len(hints) > int(limit) {
		hints = hints[:limit]
	}
	return hints, nil
}

func (c *OpportunityCoordinator) Verify(ctx context.Context, hint opportunity.CandidateHint) (opportunity.VerifiedCandidate, error) {
	if c == nil || ctx == nil || hint.Key.Network != c.network {
		return opportunity.VerifiedCandidate{}, &opportunity.Rejection{Reason: "candidate network differs from configured authority"}
	}
	observation, err := c.verifier.Verify(ctx, buyersdk.CapabilityExpectation{CapabilityID: hint.Key.CapabilityID,
		OwnerAgentID: hint.Key.ProviderAgentID, Version: hint.Key.Version, ManifestDigest: hint.Key.ManifestDigest})
	if err != nil {
		if errors.Is(err, buyersdk.ErrCapabilityRejected) {
			return opportunity.VerifiedCandidate{}, &opportunity.Rejection{Reason: "Capability failed finalized owner/version/manifest verification"}
		}
		return opportunity.VerifiedCandidate{}, err
	}
	requestID, err := coordinatorRequestID()
	if err != nil {
		return opportunity.VerifiedCandidate{}, err
	}
	now := c.now().UTC()
	raw, _, _, err := c.federation.FetchManifest(ctx, c.gateways, &nativev1.GetSoftwareWorkManifestRequest{
		Context: &nativev1.RequestContext{RequestId: requestID, CallerId: c.callerID,
			DeadlineUnixMillis: now.Add(time.Minute).UnixMilli()}, ManifestDigest: hint.Key.ManifestDigest,
	})
	if err != nil {
		return opportunity.VerifiedCandidate{}, err
	}
	manifest, err := nativecore.DecodeCanonicalSoftwareWorkManifestCBOR(raw)
	if err != nil {
		return opportunity.VerifiedCandidate{}, &opportunity.Rejection{Reason: "manifest is not canonical software-work evidence"}
	}
	return opportunity.VerifiedCandidate{Key: hint.Key, FinalizedCheckpoint: observation.FinalizedCheckpoint,
		TVMStateHash: observation.State.GetTvmStateHash(), Operation: manifest.Operation,
		ManifestName: manifest.Name, VerifiedAtUnix: now.Unix()}, nil
}

func coordinatorRequestID() (string, error) {
	var material [16]byte
	if _, err := rand.Read(material[:]); err != nil {
		return "", errors.New("nativeimpl: generate opportunity coordinator request")
	}
	return hex.EncodeToString(material[:]), nil
}

func safeDisplay(value string, max int) string {
	if len(value) > max || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\x00\r") {
		return ""
	}
	return value
}

func safeToken(value string, max int) string {
	value = safeDisplay(value, max)
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || strings.ContainsRune("._-", r)) {
			return ""
		}
	}
	return value
}

var _ opportunity.Coordinator = (*OpportunityCoordinator)(nil)
