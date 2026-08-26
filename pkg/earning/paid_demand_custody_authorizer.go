package earning

import (
	"context"
	"errors"
	"strings"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/buyersdk"
)

// PaidDemandCustodyAuthorizer adapts the Paid Demand buyer SDK to the same
// owner-scoped Authority used for every other OpenFox economic side effect.
// It deliberately stores no custody or signing key.
type PaidDemandCustodyAuthorizer struct {
	Engine         *Engine
	Fence          commerce.WriterFence
	FenceSource    WriterFenceProvider
	PolicyRevision uint64
	ApprovalDigest string
	NetworkDomain  *commerce.CustodyNetworkDomain
}

func (authorizer PaidDemandCustodyAuthorizer) AuthorizeCustodyEffect(ctx context.Context,
	request buyersdk.CustodyEffectRequest) (commerce.CustodyEffectAuthorization, error) {
	if authorizer.Engine == nil || authorizer.Engine.Authority == nil ||
		!authorizer.Engine.permits("tos-escrow", authorizer.Engine.Gates.TOSEscrow, false) ||
		request.ActionKind != "escrow.accept" && request.ActionKind != "escrow.fund" &&
			request.ActionKind != "escrow.release" && request.ActionKind != "escrow.refund" ||
		request.SourceAccount == "" || request.NetworkID == "" || request.NetworkGlobalID == 0 ||
		authorizer.NetworkDomain == nil || commerce.ValidateCustodyNetworkDomain(*authorizer.NetworkDomain) != nil ||
		authorizer.NetworkDomain.NetworkID != request.NetworkID ||
		authorizer.NetworkDomain.GlobalID != request.NetworkGlobalID ||
		request.Destination == "" || request.AmountNanoTOS == 0 || request.ExpiresAtUnix == 0 ||
		!strings.HasPrefix(request.BodyHash, "tvm-cell-sha256:") {
		return commerce.CustodyEffectAuthorization{}, errors.New("Paid Demand custody effect is disabled or incomplete")
	}
	fence := authorizer.Fence
	if authorizer.FenceSource != nil {
		var err error
		fence, err = authorizer.FenceSource(ctx)
		if err != nil {
			return commerce.CustodyEffectAuthorization{}, err
		}
	}
	if fence.Body.WriterGeneration == 0 {
		return commerce.CustodyEffectAuthorization{}, errors.New("Paid Demand custody has no current writer fence")
	}
	action, err := commerce.BuildAuthorizedAction(authorizer.Engine.OwnerID, authorizer.Engine.AgentID,
		"escrow.transition", request.SemanticFields, request.CanonicalRequest, fence,
		authorizer.PolicyRevision, authorizer.Engine.MandateDigest, authorizer.ApprovalDigest,
		request.ActionKind, minUint64(request.ExpiresAtUnix, fence.Body.ExpiresAtUnix))
	if err != nil {
		return commerce.CustodyEffectAuthorization{}, err
	}
	action, err = authorizer.Engine.Authority.SignAction(action, fence)
	if err != nil {
		return commerce.CustodyEffectAuthorization{}, err
	}
	resolution, err := authorizer.Engine.Authority.Admit(action, request.SemanticFields,
		request.CanonicalRequest, fence, nil)
	if err != nil || resolution.State != commerce.ActionPrepared {
		if err == nil {
			err = errors.New("Paid Demand custody effect is not prepared")
		}
		return commerce.CustodyEffectAuthorization{}, err
	}
	domain := *authorizer.NetworkDomain
	template := commerce.CustodyEffectAuthorization{SchemaVersion: 2, SourceAccount: request.SourceAccount,
		NetworkID: request.NetworkID, NetworkGlobalID: request.NetworkGlobalID, NetworkDomain: &domain,
		ActionKind:          request.ActionKind,
		AgreementBodyDigest: request.AgreementDigest, ObligationID: request.ObligationID,
		Destination: request.Destination, AmountNanoTOS: request.AmountNanoTOS,
		BodyHash: request.BodyHash, StateInitHashOrZero: request.StateInitHashOrZero,
		ExpiresAtUnix: minUint64(request.ExpiresAtUnix, fence.Body.ExpiresAtUnix)}
	return authorizer.Engine.Authority.AuthorizeCustodyEffect(action, request.SemanticFields,
		request.CanonicalRequest, fence, template)
}

var _ buyersdk.CustodyEffectAuthorizer = PaidDemandCustodyAuthorizer{}
