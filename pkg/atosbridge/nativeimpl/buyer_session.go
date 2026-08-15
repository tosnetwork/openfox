package nativeimpl

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/tosnetwork/openfox/pkg/atosbridge"
	nativev1 "github.com/tosnetwork/tos-protocol/gen/atos/native/v1"
	"github.com/tosnetwork/tos-protocol/pkg/buyersdk"
	"github.com/tosnetwork/tos-protocol/pkg/toschain"
)

// purchasePreparer is the narrow behaviour of *buyersdk.Buyer the session
// delegates to. The chain-authoritative validation — capability ownership,
// asset route, exact-escrow, funding idempotency — lives entirely in buyersdk;
// this package never re-derives it. Keeping it an interface makes the delegation
// unit-testable without a live node.
type purchasePreparer interface {
	PreparePurchase(ctx context.Context, input buyersdk.PurchaseInput) (*buyersdk.PreparedPurchase, error)
	FundPurchase(ctx context.Context, purchase *buyersdk.PreparedPurchase, requestKey string) (*toschain.FinalizedEscrowV1, error)
}

// BuyerSession implements the bridge's QuoteClient and CustodySigner by
// delegating to buyersdk. It carries the off-chain quote material negotiated
// with the provider (the buyersdk.PurchaseInput) and remembers the
// PreparedPurchase between BuildAcceptedQuote and SignAndFundEscrow, keyed by the
// canonical Quote commitment, so funding acts on exactly the prepared purchase
// buyersdk validated. One session serves one purchase negotiation.
type BuyerSession struct {
	preparer purchasePreparer
	input    buyersdk.PurchaseInput

	mu       sync.Mutex
	prepared map[string]*buyersdk.PreparedPurchase
}

// NewBuyerSession validates the negotiated input and returns a session.
func NewBuyerSession(preparer purchasePreparer, input buyersdk.PurchaseInput) (*BuyerSession, error) {
	if preparer == nil || input.Proposal == nil || input.Proposal.GetCapabilityId() == "" ||
		input.Proposal.GetMaximumPrice() == nil {
		return nil, errors.New("nativeimpl: buyer session needs a preparer and a complete quote proposal")
	}
	return &BuyerSession{preparer: preparer, input: input, prepared: map[string]*buyersdk.PreparedPurchase{}}, nil
}

// RequestQuote returns the non-canonical proposal projected from the negotiated
// input. It refuses a proposal that does not match the requested capability so a
// mismatched negotiation can never reach policy or funding.
func (s *BuyerSession) RequestQuote(_ context.Context, ref atosbridge.CapabilityRef) (atosbridge.QuoteProposal, error) {
	prop := s.input.Proposal
	if prop.GetCapabilityId() != ref.CapabilityID {
		return atosbridge.QuoteProposal{}, errors.New("nativeimpl: negotiated proposal does not match the requested capability")
	}
	money := prop.GetMaximumPrice()
	amount, err := atomicUint64(money.GetAtomicAmount())
	if err != nil {
		return atosbridge.QuoteProposal{}, err
	}
	return atosbridge.QuoteProposal{
		Capability: atosbridge.CapabilityRef{
			AgentID: prop.GetProviderAgentId(), CapabilityID: prop.GetCapabilityId(),
			Version: prop.GetCapabilityVersion(), ManifestDigest: prop.GetManifestDigest(),
		},
		Asset: atosbridge.AssetIdentity{
			Master: contractAddress(money.GetAsset().GetMaster()), WalletCodeHash: money.GetAsset().GetWalletCodeHash(),
		},
		MaxAtomicAmount: amount,
		Expiry:          time.Unix(int64(prop.GetExpiresAtUnixSeconds()), 0).UTC(),
		ExecutionSigner: hex.EncodeToString(s.input.ExecutionSignerEd25519),
	}, nil
}

// BuildAcceptedQuote delegates to buyersdk.PreparePurchase, which validates the
// capability, asset route, and escrow derivation against finalized state and
// returns the canonical Quote commitment and deterministic escrow. The prepared
// purchase is remembered so funding operates on exactly it.
func (s *BuyerSession) BuildAcceptedQuote(ctx context.Context, _ atosbridge.QuoteProposal) (atosbridge.AcceptedQuote, error) {
	prepared, err := s.preparer.PreparePurchase(ctx, s.input)
	if err != nil {
		return atosbridge.AcceptedQuote{}, err
	}
	if prepared == nil || prepared.QuoteCommitment == "" || prepared.Escrow.Address == "" {
		return atosbridge.AcceptedQuote{}, errors.New("nativeimpl: prepared purchase is missing its commitment or escrow")
	}
	s.mu.Lock()
	s.prepared[prepared.QuoteCommitment] = prepared
	s.mu.Unlock()

	proposal, err := s.RequestQuote(ctx, atosbridge.CapabilityRef{CapabilityID: s.input.Proposal.GetCapabilityId()})
	if err != nil {
		return atosbridge.AcceptedQuote{}, err
	}
	return atosbridge.AcceptedQuote{
		Proposal:        proposal,
		QuoteCommitment: prepared.QuoteCommitment,
		EscrowAddress:   prepared.Escrow.Address,
		EscrowStateInit: []byte(prepared.Escrow.StateInitBOC),
	}, nil
}

// SignAndFundEscrow funds exactly the prepared purchase buyersdk validated. The
// request key is the purchase's canonical (commitment, escrow) identity, so
// buyersdk's own budget journal makes funding idempotent: a retry never
// double-funds. It fails closed if BuildAcceptedQuote has not prepared this
// purchase.
func (s *BuyerSession) SignAndFundEscrow(ctx context.Context, aq atosbridge.AcceptedQuote) error {
	s.mu.Lock()
	prepared, ok := s.prepared[aq.QuoteCommitment]
	s.mu.Unlock()
	if !ok {
		return errors.New("nativeimpl: no prepared purchase for this accepted quote; build it before funding")
	}
	requestKey := aq.QuoteCommitment + ":" + aq.EscrowAddress
	if _, err := s.preparer.FundPurchase(ctx, prepared, requestKey); err != nil {
		return err
	}
	return nil
}

// SignSettlementIntent is a provider-side action; a buyer never signs the escrow
// release. It is present only to satisfy the CustodySigner interface and always
// refuses.
func (s *BuyerSession) SignSettlementIntent(context.Context, string) ([]byte, error) {
	return nil, errors.New("nativeimpl: the buyer does not sign settlement intents; the provider releases escrow")
}

var (
	_ atosbridge.QuoteClient   = (*BuyerSession)(nil)
	_ atosbridge.CustodySigner = (*BuyerSession)(nil)
)

// contractAddress formats a TOS contract identity as the canonical
// "<workchain>:<hex account id>" address buyersdk uses.
func contractAddress(id *nativev1.TOSContractIdentityV1) string {
	if id == nil {
		return ""
	}
	return fmt.Sprintf("%d:%s", id.GetWorkchain(), hex.EncodeToString(id.GetAccountId()))
}
