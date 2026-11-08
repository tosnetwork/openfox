package servicebridge

import (
	"context"
	"errors"
	"fmt"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativeclient"
	"github.com/tosnetwork/tos-service-protocol/pkg/serviceactor"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
)

// GatewayQuotes asks a gateway's discovery service for a Quote Proposal.
// The package carries no authority; the buyer validates it and re-verifies
// every rail field against finalized state.
type GatewayQuotes struct {
	Client   *nativeclient.Client
	CallerID string
}

// Quote implements QuoteSource.
func (g GatewayQuotes) Quote(
	ctx context.Context,
	request *nativev1.RequestQuoteProposalRequest,
) (*nativev1.QuoteProposalPackageV1, error) {
	if g.Client == nil || request == nil || g.CallerID == "" {
		return nil, errors.New("servicebridge: the gateway quote source is not configured")
	}
	stamped := &nativev1.RequestQuoteProposalRequest{
		CapabilityId: request.GetCapabilityId(), CapabilityVersion: request.GetCapabilityVersion(),
		BuyerAddress: request.GetBuyerAddress(), Context: &nativev1.RequestContext{
			RequestId: request.GetCapabilityId() + "/" + request.GetCapabilityVersion(),
			CallerId:  g.CallerID,
		},
	}
	response, err := g.Client.RequestQuoteProposal(ctx, stamped)
	if err != nil {
		return nil, fmt.Errorf("servicebridge: gateway quote: %w", err)
	}
	if response == nil || response.GetPackage() == nil {
		return nil, errors.New("servicebridge: the gateway returned no Quote package")
	}
	return response.GetPackage(), nil
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
