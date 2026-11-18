package servicebridge

import (
	"context"
	"errors"
	"fmt"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/nativeclient"
	"github.com/tosnetwork/ai/protocol/pkg/serviceactor"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
)

// GatewayQuotes asks a gateway's discovery service for a Quote Proposal.
// The package carries no authority; the buyer validates it and re-verifies
// every rail field against finalized state.
//
// A gateway may serve the provider's encryption key card next to the
// package. The card is a hint like an offer file: with Cards set it is
// learned only after it verifies against finalized state as a card of the
// requested Capability's finalized owner, exactly as an offer-file or
// result-carried card is. A card that fails is discarded and does not
// invalidate the Quote; Report, when set, is told why.
type GatewayQuotes struct {
	Client   *nativeclient.Client
	CallerID string
	Cards    *PeerCards
	Report   func(stage string, err error)
}

// learnQuoteCard takes the key card a gateway served next to a package for
// request. The Agent it is learned for is the proposal's provider, and the
// card must also be of the Capability's finalized owner, read from chain by
// Learn itself, so neither the response nor the proposal is trusted.
func (g GatewayQuotes) learnQuoteCard(
	ctx context.Context,
	request *nativev1.RequestQuoteProposalRequest,
	pkg *nativev1.QuoteProposalPackageV1,
	card []byte,
) error {
	if len(card) == 0 || g.Cards == nil {
		return nil
	}
	proposal := pkg.GetProposal()
	if proposal == nil || proposal.GetCapabilityId() != request.GetCapabilityId() ||
		!agentIDPattern.MatchString(proposal.GetProviderAgentId()) {
		return fmt.Errorf("%w: the Quote names no provider of the requested Capability", ErrCardRefused)
	}
	return g.Cards.Learn(ctx, card, proposal.GetProviderAgentId(), request.GetCapabilityId())
}

// Quote implements QuoteSource.
func (g GatewayQuotes) Quote(
	ctx context.Context,
	request *nativev1.RequestQuoteProposalRequest,
) (*nativev1.QuoteProposalPackageV1, error) {
	if g.Client == nil || request == nil || g.CallerID == "" {
		return nil, errors.New("servicebridge: the gateway quote source is not configured")
	}
	deadline := gatewayQuoteDeadline(ctx, time.Now())
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	stamped := &nativev1.RequestQuoteProposalRequest{
		CapabilityId: request.GetCapabilityId(), CapabilityVersion: request.GetCapabilityVersion(),
		BuyerAddress: request.GetBuyerAddress(), Context: &nativev1.RequestContext{
			RequestId:          request.GetCapabilityId() + "/" + request.GetCapabilityVersion(),
			CallerId:           g.CallerID,
			DeadlineUnixMillis: deadline.UnixMilli(),
		},
	}
	response, err := g.Client.RequestQuoteProposal(ctx, stamped)
	if err != nil {
		return nil, fmt.Errorf("servicebridge: gateway quote: %w", err)
	}
	if response == nil || response.GetPackage() == nil {
		return nil, errors.New("servicebridge: the gateway returned no Quote package")
	}
	if err := g.learnQuoteCard(ctx, request, response.GetPackage(), response.GetProviderKeyCardPacketJson()); err != nil &&
		g.Report != nil {
		g.Report("buyer.quote_card", fmt.Errorf("the provider key card served with the Quote was discarded: %w", err))
	}
	return response.GetPackage(), nil
}

// GatewayQuoteTimeout bounds one gateway Quote request. A gateway refuses
// a discovery request whose context carries no future deadline, or one more
// than 15 minutes ahead.
const GatewayQuoteTimeout = time.Minute

// gatewayQuoteDeadline is the deadline a gateway Quote request carries: the
// caller's context deadline when it is sooner, otherwise GatewayQuoteTimeout
// from now.
func gatewayQuoteDeadline(ctx context.Context, now time.Time) time.Time {
	deadline := now.Add(GatewayQuoteTimeout)
	if own, ok := ctx.Deadline(); ok && own.Before(deadline) {
		return own
	}
	return deadline
}

// FixedQuote serves one Quote package the owner obtained out of band, for
// the request it was issued for.
type FixedQuote struct {
	Package *nativev1.QuoteProposalPackageV1
}

// Quote implements QuoteSource.
func (f FixedQuote) Quote(
	_ context.Context,
	request *nativev1.RequestQuoteProposalRequest,
) (*nativev1.QuoteProposalPackageV1, error) {
	if f.Package == nil || f.Package.GetProposal() == nil || request == nil ||
		f.Package.GetProposal().
			GetCapabilityId() !=
			request.GetCapabilityId() || f.Package.GetProposal().GetCapabilityVersion() != request.GetCapabilityVersion() {
		return nil, errors.New("servicebridge: the Quote package is for another Capability or version")
	}
	return f.Package, nil
}

// ChainSessions adapts a finalized Service Actor reader to the session
// interfaces the rail parts use.
type ChainSessions struct {
	Reader *toschain.ServiceActorReader
}

// BeginRegistrySession implements RegistrySessions.
func (c ChainSessions) BeginRegistrySession(ctx context.Context) (serviceactor.Session, error) {
	if c.Reader == nil {
		return nil, errors.New("servicebridge: no finalized reader")
	}
	return c.Reader.Begin(ctx)
}
