package servicebridge

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/tosnetwork/openfox/pkg/actionauth"
)

var ErrIncompletePurchaseAuthority = errors.New("servicebridge: purchase lacks exact Messenger authority terms")

// AuthorizedCustodySigner places the Messenger firewall immediately in front
// of custody. The wrapped signer is unreachable until Messenger has allowed
// and, where necessary, atomically consumed the one-shot authorization.
type AuthorizedCustodySigner struct {
	Signer     CustodySigner
	Authorizer actionauth.Authorizer
	MandateID  string
}

func (s AuthorizedCustodySigner) SignAndFundEscrow(ctx context.Context, quote AcceptedQuote) error {
	if s.Signer == nil || s.Authorizer == nil || strings.TrimSpace(s.MandateID) == "" {
		return ErrIncompletePurchaseAuthority
	}
	invocation, ok := actionauth.InvocationFrom(ctx)
	if !ok || !invocation.LineageComplete {
		return ErrIncompletePurchaseAuthority
	}
	terms, err := messengerPurchaseTerms(quote.Proposal)
	if err != nil {
		return err
	}
	action := actionauth.Action{
		Effect:      actionauth.EffectSpend,
		Summary:     "fund accepted quote " + quote.QuoteCommitment,
		DerivedFrom: invocation.DerivedFrom,
		MandateID:   s.MandateID,
		Terms:       &terms,
	}
	if err := s.Authorizer.Authorize(ctx, action); err != nil {
		return err
	}
	return s.Signer.SignAndFundEscrow(ctx, quote)
}

func (s AuthorizedCustodySigner) SignSettlementIntent(ctx context.Context, intentHash string) ([]byte, error) {
	if s.Signer == nil || s.Authorizer == nil {
		return nil, ErrIncompletePurchaseAuthority
	}
	invocation, ok := actionauth.InvocationFrom(ctx)
	if !ok || !invocation.LineageComplete {
		return nil, ErrIncompletePurchaseAuthority
	}
	if err := s.Authorizer.Authorize(ctx, actionauth.Action{
		Effect: actionauth.EffectKeyUse, Summary: "sign TOS settlement intent " + intentHash,
		DerivedFrom: invocation.DerivedFrom,
	}); err != nil {
		return nil, err
	}
	return s.Signer.SignSettlementIntent(ctx, intentHash)
}

func messengerPurchaseTerms(proposal QuoteProposal) (actionauth.PurchaseTerms, error) {
	atomic := strings.TrimSpace(proposal.AtomicAmount)
	if atomic == "" && proposal.MaxAtomicAmount > 0 {
		atomic = strconv.FormatUint(proposal.MaxAtomicAmount, 10)
	}
	terms := actionauth.PurchaseTerms{
		CapabilityID:           proposal.Capability.CapabilityID,
		CapabilityVersion:      proposal.Capability.Version,
		CapabilityClass:        proposal.Capability.CapabilityClass,
		ProviderAgentID:        proposal.Capability.AgentID,
		ManifestDigest:         proposal.Capability.ManifestDigest,
		TransportBindingDigest: proposal.TransportBindingDigest,
		Asset: actionauth.AssetIdentity{
			NetworkID:       proposal.Asset.Network.ID,
			GenesisRootHash: proposal.Asset.Network.GenesisRootHash,
			GenesisFileHash: proposal.Asset.Network.GenesisFileHash,
			Workchain:       proposal.Asset.Workchain,
			AccountID:       proposal.Asset.Master,
			MasterCodeHash:  proposal.Asset.MasterCodeHash,
			WalletCodeHash:  proposal.Asset.WalletCodeHash,
			Decimals:        proposal.Asset.Decimals,
		},
		PriceAtomic:         atomic,
		EscrowTermsDigest:   proposal.EscrowTermsDigest,
		DisputePolicyDigest: proposal.DisputeTerms,
		NotAfterUnix:        uint64(proposal.Expiry.Unix()),
	}
	if terms.CapabilityID == "" || terms.CapabilityVersion == "" || terms.CapabilityClass == "" ||
		terms.ProviderAgentID == "" || terms.ManifestDigest == "" || terms.TransportBindingDigest == "" ||
		terms.Asset.NetworkID == "" || terms.Asset.GenesisRootHash == "" || terms.Asset.GenesisFileHash == "" ||
		terms.Asset.AccountID == "" || terms.Asset.MasterCodeHash == "" || terms.Asset.WalletCodeHash == "" ||
		terms.PriceAtomic == "" || terms.EscrowTermsDigest == "" || terms.DisputePolicyDigest == "" ||
		proposal.Expiry.IsZero() || proposal.Expiry.Unix() <= 0 {
		return actionauth.PurchaseTerms{}, ErrIncompletePurchaseAuthority
	}
	return terms, nil
}

var _ CustodySigner = AuthorizedCustodySigner{}
