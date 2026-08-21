package nativeimpl

import (
	"context"
	"errors"
	"strings"

	"github.com/tosnetwork/tos-service-protocol/pkg/buyersdk"

	"github.com/tosnetwork/openfox/pkg/actionauth"
	"github.com/tosnetwork/openfox/pkg/servicebridge"
)

// The production capability validator is a *buyersdk.Buyer, which exposes
// ValidateCapability as the single finalized-capability authority.
var _ CapabilityValidator = (*buyersdk.Buyer)(nil)

// CapabilityValidator verifies a finalized Capability matches the expected
// owner, version, and manifest. buyersdk owns this authority; exposing it as an
// interface lets the buyer resolver delegate the check instead of re-deriving
// it, so capability validation lives in exactly one place. A *buyersdk.Buyer
// satisfies this once it exposes a ValidateCapability method with this shape;
// until then the seam is honoured by any equivalent validator.
type CapabilityValidator interface {
	ValidateCapability(ctx context.Context, capabilityID, ownerAgentID, version, manifestDigest string) error
}

// NativeBuyerResolver implements servicebridge.NativeResolver from finalized state:
// capability validation delegates to the single CapabilityValidator authority,
// and the escrow view comes from the one finalized escrow read.
type NativeBuyerResolver struct {
	capability CapabilityValidator
	escrow     *EscrowSettlementReader
}

// NewNativeBuyerResolver composes the capability validator with the escrow read.
func NewNativeBuyerResolver(
	capability CapabilityValidator,
	escrow *EscrowSettlementReader,
) (*NativeBuyerResolver, error) {
	if capability == nil || escrow == nil {
		return nil, errors.New("nativeimpl: native buyer resolver needs a capability validator and an escrow reader")
	}
	return &NativeBuyerResolver{capability: capability, escrow: escrow}, nil
}

// ResolveCapability delegates to the finalized capability authority.
func (r *NativeBuyerResolver) ResolveCapability(ctx context.Context, ref servicebridge.CapabilityRef) error {
	return r.capability.ValidateCapability(ctx, ref.CapabilityID, ref.AgentID, ref.Version, ref.ManifestDigest)
}

// ResolveEscrow returns the finalized escrow funding view.
func (r *NativeBuyerResolver) ResolveEscrow(ctx context.Context, address string) (servicebridge.EscrowState, error) {
	return r.escrow.ResolveEscrow(ctx, address)
}

var _ servicebridge.NativeResolver = (*NativeBuyerResolver)(nil)

// BuyerReceiptVerifier implements servicebridge.ReceiptVerifier for the buyer.
// Settlement is read from finalized escrow; a receipt is never built here,
// because the provider — not the buyer — builds and signs the Receipt.
type BuyerReceiptVerifier struct {
	escrow *EscrowSettlementReader
}

// NewBuyerReceiptVerifier wraps the escrow reader for settlement verification.
func NewBuyerReceiptVerifier(escrow *EscrowSettlementReader) (*BuyerReceiptVerifier, error) {
	if escrow == nil {
		return nil, errors.New("nativeimpl: buyer receipt verifier needs an escrow reader")
	}
	return &BuyerReceiptVerifier{escrow: escrow}, nil
}

// BuildReceipt refuses: the buyer never builds a Receipt.
func (v *BuyerReceiptVerifier) BuildReceipt(
	context.Context,
	servicebridge.AcceptedQuote,
	servicebridge.Outcome,
) (servicebridge.Receipt, error) {
	return servicebridge.Receipt{}, errors.New("nativeimpl: the buyer does not build receipts; the provider does")
}

// VerifySettlement reads the finalized settlement outcome.
func (v *BuyerReceiptVerifier) VerifySettlement(
	ctx context.Context,
	aq servicebridge.AcceptedQuote,
) (servicebridge.Settlement, error) {
	return v.escrow.VerifySettlement(ctx, aq)
}

var _ servicebridge.ReceiptVerifier = (*BuyerReceiptVerifier)(nil)

// NativeBuyerConfig ties the buyer stack together: the owner spending policy,
// the shared finalized escrow reader (funding + settlement views), the
// capability validator, the buyersdk-backed quote/funding session, the task
// transport, the crash-safe purchase journal, and an optional manual confirmer.
type NativeBuyerConfig struct {
	Policy     servicebridge.SpendingPolicy
	Escrow     *EscrowSettlementReader
	Capability CapabilityValidator
	Session    *BuyerSession
	Transport  servicebridge.TaskTransport
	Journal    servicebridge.PurchaseJournal
	Confirm    servicebridge.Confirmer
	// Authorizer and MandateID are mandatory: production composition must not
	// expose the custody session directly to the Buyer.
	Authorizer actionauth.Authorizer
	// QuoteVerifier is the Messenger runtime client. It independently resolves
	// the funded Accepted Quote before the Buyer may dispatch a task.
	QuoteVerifier servicebridge.FinalizedQuoteVerifier
	MandateID     string
}

// NewNativeBuyer assembles a bridge Buyer from the chain-backed components. The
// same escrow reader backs both the funding check and the settlement read, so
// the buyer's authority is one finalized source; quote and funding delegate to
// buyersdk through the session; the journal keeps funding at-most-once.
func NewNativeBuyer(c NativeBuyerConfig) (*servicebridge.Buyer, error) {
	if c.Escrow == nil || c.Capability == nil || c.Session == nil || c.Transport == nil || c.Journal == nil ||
		c.Authorizer == nil || c.QuoteVerifier == nil || strings.TrimSpace(c.MandateID) == "" {
		return nil, errors.New(
			"nativeimpl: native buyer needs escrow, capability, session, transport, journal, Messenger authority, finalized Quote verification, and a mandate",
		)
	}
	resolver, err := NewNativeBuyerResolver(c.Capability, c.Escrow)
	if err != nil {
		return nil, err
	}
	receipts, err := NewBuyerReceiptVerifier(c.Escrow)
	if err != nil {
		return nil, err
	}
	return &servicebridge.Buyer{
		Policy:   c.Policy,
		Resolver: resolver,
		Quotes:   c.Session,
		Journal:  c.Journal,
		Signer: servicebridge.AuthorizedCustodySigner{
			Signer: c.Session, Authorizer: c.Authorizer, MandateID: c.MandateID,
		},
		QuoteVerifier: c.QuoteVerifier,
		Transport:     c.Transport,
		Receipts:      receipts,
		Confirm:       c.Confirm,
	}, nil
}
