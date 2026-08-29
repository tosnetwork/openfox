// Package agentgift orchestrates private Agent Gifts without making model
// output, chat rendering, or gateway data authoritative for addresses,
// wallets, signed BOCs, or finality.
package agentgift

import (
	"context"
	"errors"
	"time"
)

type Role string

const (
	RoleSender    Role = "sender"
	RoleRecipient Role = "recipient"
)

type State string

const (
	StateDraft                      State = "draft"
	StateRecipientResolved          State = "recipient-resolved"
	StateAddressRequested           State = "address-requested"
	StateAddressReceived            State = "address-received"
	StateOwnerAuthorizationRequired State = "owner-authorization-required"
	StateOwnerAuthorized            State = "owner-authorized"
	StateBOCSigned                  State = "boc-signed"
	StateOfferDelivered             State = "offer-delivered"
	StateAddressRequestObserved     State = "address-request-observed"
	StateAddressResponseSent        State = "address-response-sent"
	StateSignedOfferObserved        State = "signed-offer-observed"
	StateVerified                   State = "verified"
	StateBroadcastSubmitted         State = "broadcast-submitted"
	StateCurrentlyExecutable        State = "currently-executable"
	StateCurrentlyUnexecutable      State = "currently-unexecutable"
	StateInsufficientFunds          State = "insufficient-funds"
	StateFinalizedPaid              State = "finalized-paid"
	StateExpiredUnpaid              State = "expired-unpaid"
	StateInvalidatedUnpaid          State = "invalidated-unpaid"
	StateFinalityUnknown            State = "finality-unknown"
)

type PendingEffect string

const (
	EffectNone                PendingEffect = ""
	EffectSendAddressRequest  PendingEffect = "send-address-request"
	EffectSendAddressResponse PendingEffect = "send-address-response"
	EffectSignBOC             PendingEffect = "sign-boc"
	EffectSendOffer           PendingEffect = "send-offer"
	EffectBroadcast           PendingEffect = "broadcast"
	EffectPrepareCancel       PendingEffect = "prepare-cancel"
	EffectCancel              PendingEffect = "cancel"
)

// ModelProposal is the complete model-accessible surface. In particular it
// has no address, wallet, BOC, seqno, fee, signature, or finality fields.
type ModelProposal struct {
	Recipient           string
	AmountAtomic        string
	RequestedValidUntil uint32
	Greeting            string
}

func (v ModelProposal) Validate(now time.Time) error {
	if v.Recipient == "" || len(v.Recipient) > 255 || !validCanonicalAmount(v.AmountAtomic) || v.RequestedValidUntil <= uint32(now.Unix()) || len(v.Greeting) > 512 {
		return errors.New("invalid bounded model Gift proposal")
	}
	return nil
}

func validCanonicalAmount(value string) bool {
	if value == "" || len(value) > 20 {
		return false
	}
	for index, r := range value {
		if r < '0' || r > '9' || index == 0 && r == '0' {
			return false
		}
	}
	return true
}

type RequestIntent struct {
	Network                                                                     string
	GlobalID                                                                    int32
	IntentID, SenderAgentID, RecipientAgentID, SenderAgentAccount, AmountAtomic string
	RequestedValidUntil                                                         uint32
}
type ResponseTerms struct {
	DestinationAddress            string
	ResponseNotAfter              uint32
	RequestDigest, ResponseDigest string
}
type SignedTerms struct {
	SignedGiftID, ExactBOCDigest, SenderAgentAccount, DestinationAddress, AmountAtomic, DeploymentID, FeeReserveAtomic string
	Seqno, ValidUntil                                                                                                  uint32
	ControllerEpoch                                                                                                    uint64
	ExactSignedBOC                                                                                                     []byte
}
type FinalityResult struct{ State State }

type Protocol interface {
	CreateAddressRequest(context.Context, RequestIntent) ([]byte, string, error)
	InspectAddressRequest(context.Context, []byte) (RequestIntent, string, error)
	CreateAddressResponse(context.Context, []byte, string, uint32) ([]byte, ResponseTerms, error)
	ValidateAddressResponse(context.Context, []byte, []byte) (ResponseTerms, error)
	CreateSignedOffer(context.Context, []byte, []byte, []byte, string) ([]byte, string, error)
	VerifySignedOffer(context.Context, []byte, []byte, []byte) (SignedTerms, error)
}
type Resolver interface {
	ResolveRecipient(context.Context, string) (string, error)
	ResolveFinality(context.Context, Record) (FinalityResult, error)
}
type Messenger interface {
	SendEstablishedDirect(context.Context, string, string, []byte, string) (string, error)
}
type Custody interface {
	SenderAccount(context.Context) (string, error)
	PrepareNativeGift(context.Context, SignRequest) (CustodyReview, error)
	SignNativeGift(context.Context, SignRequest) ([]byte, error)
	ResolveNativeGift(context.Context, ResolveRequest) error
	CancelSeqno(context.Context, CancelRequest) ([]byte, error)
}
type Broadcaster interface {
	BroadcastExactBOC(context.Context, []byte) error
}
type AddressAuthority interface {
	SelectDestination(context.Context, string) (string, error)
}
type OwnerAuthorizer interface {
	Authorize(context.Context, OwnerReview) (string, error)
}

type SignRequest struct {
	IntentID                            string
	CanonicalRequest, CanonicalResponse []byte
	OwnerAuthorizationDigest            string
	UnsignedTransferDigest              string
}
type CancelRequest struct {
	IntentID, SignedGiftID, OwnerAuthorizationDigest, SenderAgentAccount string
	GlobalID                                                             int32
	Seqno, ValidUntil                                                    uint32
}
type ResolveRequest struct {
	IntentID, SenderAgentAccount, DestinationAddress, AmountAtomic, ExactBOCDigest string
}
type CustodyReview struct {
	Network, RecipientAgentID, SenderAgentAccount, OwnerWallet, ControllerKeyID, DeploymentID string
	DestinationAddress, AmountAtomic, FeeReserveAtomic                                        string
	RequestDigest, ResponseDigest, UnsignedTransferDigest                                     string
	GlobalID                                                                                  int32
	ControllerEpoch                                                                           uint64
	Seqno, ValidUntil                                                                         uint32
}
type OwnerReview struct {
	Action, IntentID, SignedGiftID, RecipientAgentID, Network, AmountAtomic, DestinationAddress, SenderAgentAccount, OwnerWallet, ControllerKeyID, DeploymentID string
	FeeReserveAtomic, RequestDigest, ResponseDigest, UnsignedTransferDigest                                                                                     string
	GlobalID                                                                                                                                                    int32
	ControllerEpoch                                                                                                                                             uint64
	Seqno, ValidUntil, RequestedValidUntil, ResponseNotAfter                                                                                                    uint32
	FundsLocked                                                                                                                                                 bool
}
