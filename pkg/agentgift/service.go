package agentgift

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

const (
	maxActiveGiftRecords       = 128
	maxActiveGiftsPerPeer      = 16
	maxGiftRecords             = 4096
	initialBroadcastRetryDelay = 30 * time.Second
	maxBroadcastRetryDelay     = 5 * time.Minute
)

type Service struct {
	journal     *Journal
	protocol    Protocol
	resolver    Resolver
	messenger   Messenger
	custody     Custody
	broadcaster Broadcaster
	addresses   AddressAuthority
	owner       OwnerAuthorizer
	now         func() time.Time
	admissionMu sync.Mutex
	intentMu    [4096]sync.Mutex
}

func NewService(j *Journal, p Protocol, r Resolver, m Messenger, c Custody, b Broadcaster, a AddressAuthority, o OwnerAuthorizer) (*Service, error) {
	if j == nil || p == nil || r == nil || m == nil || c == nil || b == nil || a == nil || o == nil {
		return nil, errors.New("Agent Gift service requires every authority boundary")
	}
	return &Service{journal: j, protocol: p, resolver: r, messenger: m, custody: c, broadcaster: b, addresses: a, owner: o, now: time.Now}, nil
}

func (s *Service) StartSender(ctx context.Context, proposal ModelProposal, network string, globalID int32, senderAgentID string) (Record, error) {
	now := s.now().UTC()
	if ctx == nil || proposal.Validate(now) != nil || network == "" || globalID == 0 || senderAgentID == "" {
		return Record{}, errors.New("invalid sender Gift start")
	}
	recipient, err := s.resolver.ResolveRecipient(ctx, proposal.Recipient)
	if err != nil {
		return Record{}, err
	}
	account, err := s.custody.SenderAccount(ctx)
	if err != nil {
		return Record{}, err
	}
	intentID, err := newIntentID()
	if err != nil {
		return Record{}, err
	}
	intent := RequestIntent{Network: network, GlobalID: globalID, IntentID: intentID, SenderAgentID: senderAgentID, RecipientAgentID: recipient, SenderAgentAccount: account, AmountAtomic: proposal.AmountAtomic, RequestedValidUntil: proposal.RequestedValidUntil}
	canonical, digest, err := s.protocol.CreateAddressRequest(ctx, intent)
	if err != nil {
		return Record{}, err
	}
	record := Record{IntentID: intentID, Role: RoleSender, State: StateDraft, Network: network, GlobalID: globalID,
		SenderAgentID: senderAgentID, RecipientAgentID: recipient, SenderAgentAccount: account, AmountAtomic: proposal.AmountAtomic,
		RequestedValidUntil: proposal.RequestedValidUntil, RequestDigest: digest, CanonicalRequest: canonical,
		DisplayMessage: proposal.Greeting, CreatedAtUnix: now.Unix(), UpdatedAtUnix: now.Unix()}
	s.admissionMu.Lock()
	records := s.journal.List()
	if activeGiftCount(records, "") >= maxActiveGiftRecords {
		s.admissionMu.Unlock()
		return Record{}, errors.New("Agent Gift journal capacity reached")
	}
	_, err = s.journal.Create(record)
	s.admissionMu.Unlock()
	if err != nil {
		return Record{}, err
	}
	return s.journal.Update(intentID, func(v *Record) error { v.State = StateRecipientResolved; v.UpdatedAtUnix = now.Unix(); return nil })
}

// ResumeSenderDraft completes the only journal transition that can be left
// unfinished if StartSender stops after durably creating its record. It never
// creates an intent and accepts only the original sender Draft (or the exact
// already-completed transition), so callers cannot use recovery to replace or
// rewrite a Gift.
func (s *Service) ResumeSenderDraft(ctx context.Context, intent string) (Record, error) {
	if s == nil || ctx == nil || intent == "" {
		return Record{}, errors.New("invalid sender Gift draft recovery")
	}
	unlock := s.lockIntent(intent)
	defer unlock()
	record, found := s.journal.Get(intent)
	if !found || record.Role != RoleSender ||
		(record.State != StateDraft && record.State != StateRecipientResolved) {
		return Record{}, errors.New("Gift is not a recoverable sender draft")
	}
	if record.PendingEffect != EffectNone {
		return Record{}, errors.New("sender Gift draft has an unexpected side effect")
	}
	request, requestDigest, err := s.protocol.InspectAddressRequest(ctx, record.CanonicalRequest)
	if err != nil || request.Network != record.Network || request.GlobalID != record.GlobalID ||
		request.IntentID != record.IntentID || request.SenderAgentID != record.SenderAgentID ||
		request.RecipientAgentID != record.RecipientAgentID || request.SenderAgentAccount != record.SenderAgentAccount ||
		request.AmountAtomic != record.AmountAtomic || request.RequestedValidUntil != record.RequestedValidUntil ||
		requestDigest != record.RequestDigest {
		return Record{}, errors.New("sender Gift draft canonical request conflicts with its journal identity")
	}
	if record.State == StateRecipientResolved {
		return record, nil
	}
	if record.RequestedValidUntil <= uint32(s.now().UTC().Unix()) {
		return Record{}, errors.New("sender Gift draft is expired")
	}
	now := s.now().UTC().Unix()
	return s.journal.Update(intent, func(v *Record) error {
		if v.State != StateDraft || v.PendingEffect != EffectNone {
			return errors.New("sender Gift draft changed during recovery")
		}
		v.State = StateRecipientResolved
		v.UpdatedAtUnix = now
		return nil
	})
}

func (s *Service) RequestAddress(ctx context.Context, intent string) (Record, error) {
	unlock := s.lockIntent(intent)
	defer unlock()
	record, found := s.journal.Get(intent)
	if !found || record.Role != RoleSender || (record.State != StateRecipientResolved && !(record.State == StateAddressRequested && record.PendingEffect == EffectSendAddressRequest)) {
		return Record{}, errors.New("Gift is not ready for an address request")
	}
	now := s.now().UTC().Unix()
	if record.RequestedValidUntil <= uint32(now) {
		return Record{}, errors.New("Gift address request validity expired")
	}
	record, err := s.journal.Update(intent, func(v *Record) error {
		v.State = StateAddressRequested
		v.PendingEffect = EffectSendAddressRequest
		v.UpdatedAtUnix = now
		return nil
	})
	if err != nil {
		return Record{}, err
	}
	eventID, err := s.messenger.SendEstablishedDirect(ctx, record.RecipientAgentID, "agent.gift.address-request", record.CanonicalRequest, intent)
	if err != nil {
		return Record{}, err
	}
	return s.journal.Update(intent, func(v *Record) error {
		v.PendingEffect = EffectNone
		v.RequestEventID = eventID
		v.UpdatedAtUnix = s.now().UTC().Unix()
		return nil
	})
}

func (s *Service) ObserveAddressResponse(ctx context.Context, intent string, canonical []byte) (Record, error) {
	unlock := s.lockIntent(intent)
	defer unlock()
	record, found := s.journal.Get(intent)
	if found && record.Role == RoleSender && len(record.CanonicalResponse) != 0 {
		if string(record.CanonicalResponse) != string(canonical) {
			return Record{}, errors.New("changed Gift address response conflicts with durable response")
		}
		return record, nil
	}
	if !found || record.Role != RoleSender || record.State != StateAddressRequested || record.PendingEffect != EffectNone {
		return Record{}, errors.New("unexpected Gift address response")
	}
	terms, err := s.protocol.ValidateAddressResponse(ctx, record.CanonicalRequest, canonical)
	if err != nil {
		return Record{}, err
	}
	return s.journal.Update(intent, func(v *Record) error {
		v.State = StateAddressReceived
		v.CanonicalResponse = append([]byte(nil), canonical...)
		v.DestinationAddress = terms.DestinationAddress
		v.ResponseNotAfter = terms.ResponseNotAfter
		v.ResponseDigest = terms.ResponseDigest
		v.UpdatedAtUnix = s.now().UTC().Unix()
		return nil
	})
}

func (s *Service) Authorize(ctx context.Context, intent string) (Record, error) {
	unlock := s.lockIntent(intent)
	defer unlock()
	record, found := s.journal.Get(intent)
	if found && record.Role == RoleSender && record.State == StateOwnerAuthorized {
		return record, nil
	}
	if !found || record.Role != RoleSender || (record.State != StateAddressReceived && record.State != StateOwnerAuthorizationRequired) {
		return Record{}, errors.New("Gift is not ready for owner authorization")
	}
	if record.State == StateAddressReceived {
		prepared, err := s.custody.PrepareNativeGift(ctx, SignRequest{IntentID: intent, CanonicalRequest: record.CanonicalRequest, CanonicalResponse: record.CanonicalResponse})
		if err != nil {
			return Record{}, err
		}
		if prepared.Network != record.Network || prepared.GlobalID != record.GlobalID || prepared.RecipientAgentID != record.RecipientAgentID || prepared.SenderAgentAccount != record.SenderAgentAccount || prepared.DestinationAddress != record.DestinationAddress || prepared.AmountAtomic != record.AmountAtomic || prepared.RequestDigest != record.RequestDigest || prepared.ResponseDigest != record.ResponseDigest || prepared.Seqno == ^uint32(0) || prepared.ValidUntil == 0 || prepared.ValidUntil > record.RequestedValidUntil || prepared.ValidUntil > record.ResponseNotAfter || prepared.FeeReserveAtomic == "" || prepared.OwnerWallet == "" || prepared.ControllerKeyID == "" || prepared.DeploymentID == "" || prepared.UnsignedTransferDigest == "" {
			return Record{}, errors.New("custody review does not bind the complete Gift")
		}
		record, err = s.journal.Update(intent, func(v *Record) error {
			v.State = StateOwnerAuthorizationRequired
			v.OwnerWallet = prepared.OwnerWallet
			v.ControllerKeyID = prepared.ControllerKeyID
			v.DeploymentID = prepared.DeploymentID
			v.ControllerEpoch = prepared.ControllerEpoch
			v.FeeReserveAtomic = prepared.FeeReserveAtomic
			v.UnsignedTransferDigest = prepared.UnsignedTransferDigest
			v.Seqno = prepared.Seqno
			v.ValidUntil = prepared.ValidUntil
			v.UpdatedAtUnix = s.now().UTC().Unix()
			return nil
		})
		if err != nil {
			return Record{}, err
		}
	}
	digest, err := s.owner.Authorize(ctx, OwnerReview{Action: "send", IntentID: intent, RecipientAgentID: record.RecipientAgentID, Network: record.Network, GlobalID: record.GlobalID, AmountAtomic: record.AmountAtomic, DestinationAddress: record.DestinationAddress, SenderAgentAccount: record.SenderAgentAccount, OwnerWallet: record.OwnerWallet, ControllerKeyID: record.ControllerKeyID, DeploymentID: record.DeploymentID, FeeReserveAtomic: record.FeeReserveAtomic, ControllerEpoch: record.ControllerEpoch, Seqno: record.Seqno, ValidUntil: record.ValidUntil, RequestDigest: record.RequestDigest, ResponseDigest: record.ResponseDigest, UnsignedTransferDigest: record.UnsignedTransferDigest, RequestedValidUntil: record.RequestedValidUntil, ResponseNotAfter: record.ResponseNotAfter, FundsLocked: false})
	if err != nil {
		return Record{}, err
	}
	if digest == "" {
		return Record{}, errors.New("owner authorization returned no digest")
	}
	return s.journal.Update(intent, func(v *Record) error {
		v.State = StateOwnerAuthorized
		v.OwnerAuthorizationDigest = digest
		v.UpdatedAtUnix = s.now().UTC().Unix()
		return nil
	})
}

func (s *Service) Sign(ctx context.Context, intent, greeting string) (Record, error) {
	unlock := s.lockIntent(intent)
	defer unlock()
	record, found := s.journal.Get(intent)
	if found && record.Role == RoleSender && record.State == StateBOCSigned {
		if record.DisplayMessage != greeting {
			return Record{}, errors.New("changed Gift greeting conflicts with the durable signed offer")
		}
		return record, nil
	}
	if !found || record.Role != RoleSender || (record.State != StateOwnerAuthorized && !(record.PendingEffect == EffectSignBOC && record.State == StateOwnerAuthorized)) {
		return Record{}, errors.New("Gift is not ready for custody signing")
	}
	if len(greeting) > 512 {
		return Record{}, errors.New("Gift greeting exceeds limit")
	}
	record, err := s.journal.Update(intent, func(v *Record) error {
		v.PendingEffect = EffectSignBOC
		v.UpdatedAtUnix = s.now().UTC().Unix()
		return nil
	})
	if err != nil {
		return Record{}, err
	}
	boc, err := s.custody.SignNativeGift(ctx, SignRequest{IntentID: intent, CanonicalRequest: record.CanonicalRequest, CanonicalResponse: record.CanonicalResponse, OwnerAuthorizationDigest: record.OwnerAuthorizationDigest, UnsignedTransferDigest: record.UnsignedTransferDigest})
	if err != nil {
		return Record{}, err
	}
	offer, signedID, err := s.protocol.CreateSignedOffer(ctx, record.CanonicalRequest, record.CanonicalResponse, boc, greeting)
	if err != nil {
		return Record{}, err
	}
	terms, err := s.protocol.VerifySignedOffer(ctx, record.CanonicalRequest, record.CanonicalResponse, offer)
	if err != nil || terms.SignedGiftID != signedID || terms.ControllerEpoch != record.ControllerEpoch || terms.Seqno != record.Seqno || terms.ValidUntil != record.ValidUntil || terms.DeploymentID != record.DeploymentID || terms.SenderAgentAccount != record.SenderAgentAccount || terms.DestinationAddress != record.DestinationAddress || terms.AmountAtomic != record.AmountAtomic || terms.FeeReserveAtomic != record.FeeReserveAtomic {
		return Record{}, errors.New("custody BOC failed independent Gift verification")
	}
	return s.journal.Update(intent, func(v *Record) error {
		v.State = StateBOCSigned
		v.PendingEffect = EffectNone
		v.ExactSignedBOC = append([]byte(nil), boc...)
		v.CanonicalOffer = append([]byte(nil), offer...)
		v.SignedGiftID = terms.SignedGiftID
		v.ExactBOCDigest = terms.ExactBOCDigest
		v.ControllerEpoch = terms.ControllerEpoch
		v.Seqno = terms.Seqno
		v.ValidUntil = terms.ValidUntil
		v.DisplayMessage = greeting
		v.UpdatedAtUnix = s.now().UTC().Unix()
		return nil
	})
}

func (s *Service) DeliverOffer(ctx context.Context, intent string) (Record, error) {
	unlock := s.lockIntent(intent)
	defer unlock()
	record, found := s.journal.Get(intent)
	if found && record.Role == RoleSender && record.State == StateOfferDelivered {
		return record, nil
	}
	if !found || record.Role != RoleSender || record.State != StateBOCSigned || (record.PendingEffect != EffectNone && record.PendingEffect != EffectSendOffer) {
		return Record{}, errors.New("Gift offer is not ready")
	}
	record, err := s.journal.Update(intent, func(v *Record) error {
		v.PendingEffect = EffectSendOffer
		v.UpdatedAtUnix = s.now().UTC().Unix()
		return nil
	})
	if err != nil {
		return Record{}, err
	}
	eventID, err := s.messenger.SendEstablishedDirect(ctx, record.RecipientAgentID, "agent.gift.signed-boc-offer", record.CanonicalOffer, record.SignedGiftID)
	if err != nil {
		return Record{}, err
	}
	return s.journal.Update(intent, func(v *Record) error {
		v.State = StateOfferDelivered
		v.PendingEffect = EffectNone
		v.OfferEventID = eventID
		v.UpdatedAtUnix = s.now().UTC().Unix()
		return nil
	})
}

func (s *Service) ObserveRecipientRequest(ctx context.Context, canonical []byte, localAgentID, authenticatedSender string) (Record, error) {
	intent, digest, err := s.protocol.InspectAddressRequest(ctx, canonical)
	if err != nil {
		return Record{}, err
	}
	if intent.RecipientAgentID != localAgentID || intent.SenderAgentID != authenticatedSender {
		return Record{}, errors.New("Gift request E2EE participants mismatch")
	}
	unlock := s.lockIntent(intent.IntentID)
	defer unlock()
	now := s.now().UTC().Unix()
	record := Record{IntentID: intent.IntentID, Role: RoleRecipient, State: StateAddressRequestObserved, Network: intent.Network, GlobalID: intent.GlobalID, SenderAgentID: intent.SenderAgentID, RecipientAgentID: intent.RecipientAgentID, SenderAgentAccount: intent.SenderAgentAccount, AmountAtomic: intent.AmountAtomic, RequestedValidUntil: intent.RequestedValidUntil, RequestDigest: digest, CanonicalRequest: append([]byte(nil), canonical...), CreatedAtUnix: now, UpdatedAtUnix: now}
	s.admissionMu.Lock()
	defer s.admissionMu.Unlock()
	if existing, found := s.journal.Get(intent.IntentID); found {
		if existing.RequestDigest != digest || string(existing.CanonicalRequest) != string(canonical) {
			return Record{}, errors.New("Gift intent conflict")
		}
		return existing, nil
	}
	records := s.journal.List()
	if activeGiftCount(records, "") >= maxActiveGiftRecords || activeGiftCount(records, authenticatedSender) >= maxActiveGiftsPerPeer {
		return Record{}, errors.New("active inbound Agent Gift limit reached")
	}
	return s.journal.Create(record)
}

func (s *Service) RespondAddress(ctx context.Context, intent string, responseNotAfter uint32) (Record, error) {
	unlock := s.lockIntent(intent)
	defer unlock()
	record, found := s.journal.Get(intent)
	if !found || record.Role != RoleRecipient || record.State != StateAddressRequestObserved ||
		(record.PendingEffect != EffectNone && record.PendingEffect != EffectSendAddressResponse) {
		return Record{}, errors.New("Gift request is not ready for response")
	}
	canonical := record.CanonicalResponse
	if record.PendingEffect == EffectNone {
		destination, err := s.addresses.SelectDestination(ctx, intent)
		if err != nil {
			return Record{}, err
		}
		var terms ResponseTerms
		canonical, terms, err = s.protocol.CreateAddressResponse(ctx, record.CanonicalRequest, destination, responseNotAfter)
		if err != nil {
			return Record{}, err
		}
		record, err = s.journal.Update(intent, func(v *Record) error {
			v.PendingEffect = EffectSendAddressResponse
			v.CanonicalResponse = append([]byte(nil), canonical...)
			v.DestinationAddress = terms.DestinationAddress
			v.ResponseNotAfter = terms.ResponseNotAfter
			v.ResponseDigest = terms.ResponseDigest
			v.UpdatedAtUnix = s.now().UTC().Unix()
			return nil
		})
		if err != nil {
			return Record{}, err
		}
	} else if responseNotAfter != record.ResponseNotAfter {
		return Record{}, errors.New("changed response validity conflicts with durable response")
	}
	eventID, err := s.messenger.SendEstablishedDirect(ctx, record.SenderAgentID, "agent.gift.address-response", canonical, intent)
	if err != nil {
		return Record{}, err
	}
	return s.journal.Update(intent, func(v *Record) error {
		v.State = StateAddressResponseSent
		v.PendingEffect = EffectNone
		v.ResponseEventID = eventID
		v.UpdatedAtUnix = s.now().UTC().Unix()
		return nil
	})
}

func (s *Service) ObserveAndBroadcastOffer(ctx context.Context, intent string, offer []byte) (Record, error) {
	unlock := s.lockIntent(intent)
	defer unlock()
	record, found := s.journal.Get(intent)
	offerDigest := canonicalBytesDigest(offer)
	if found && record.Role == RoleRecipient && record.CanonicalOfferDigest != "" {
		if record.CanonicalOfferDigest != offerDigest {
			return Record{}, errors.New("changed signed Gift offer conflicts with durable offer")
		}
		if record.State != StateSignedOfferObserved && record.State != StateVerified && record.State != StateCurrentlyExecutable {
			return record, nil
		}
	}
	if found && record.PendingEffect == EffectBroadcast {
		return Record{}, errors.New("ambiguous Gift broadcast requires finalized refresh before resubmission")
	}
	if found && record.RetryNotBeforeUnix > s.now().UTC().Unix() {
		return Record{}, errors.New("exact Gift broadcast retry is rate limited")
	}
	if !found || record.Role != RoleRecipient || (record.State != StateAddressResponseSent && record.State != StateSignedOfferObserved && record.State != StateVerified && record.State != StateCurrentlyExecutable) {
		return Record{}, errors.New("unexpected signed Gift offer")
	}
	if record.State != StateAddressResponseSent && string(record.CanonicalOffer) != string(offer) {
		return Record{}, errors.New("changed signed Gift offer conflicts with durable observation")
	}
	var err error
	if record.State == StateAddressResponseSent {
		record, err = s.journal.Update(intent, func(v *Record) error {
			v.State = StateSignedOfferObserved
			v.CanonicalOffer = append([]byte(nil), offer...)
			v.CanonicalOfferDigest = offerDigest
			v.UpdatedAtUnix = s.now().UTC().Unix()
			return nil
		})
		if err != nil {
			return Record{}, err
		}
	}
	terms, err := s.protocol.VerifySignedOffer(ctx, record.CanonicalRequest, record.CanonicalResponse, offer)
	if err != nil {
		if record.State == StateSignedOfferObserved {
			_, rollbackErr := s.journal.Update(intent, func(v *Record) error {
				if v.State == StateSignedOfferObserved && v.CanonicalOfferDigest == offerDigest {
					v.State = StateAddressResponseSent
					v.CanonicalOffer = nil
					v.CanonicalOfferDigest = ""
					v.UpdatedAtUnix = s.now().UTC().Unix()
				}
				return nil
			})
			if rollbackErr != nil {
				return Record{}, errors.Join(err, rollbackErr)
			}
		}
		return Record{}, err
	}
	if record.State == StateSignedOfferObserved {
		record, err = s.journal.Update(intent, func(v *Record) error {
			v.State = StateVerified
			v.SignedGiftID = terms.SignedGiftID
			v.ExactBOCDigest = terms.ExactBOCDigest
			v.SenderAgentAccount = terms.SenderAgentAccount
			v.DestinationAddress = terms.DestinationAddress
			v.AmountAtomic = terms.AmountAtomic
			v.Seqno = terms.Seqno
			v.ValidUntil = terms.ValidUntil
			v.DeploymentID = terms.DeploymentID
			v.ControllerEpoch = terms.ControllerEpoch
			v.FeeReserveAtomic = terms.FeeReserveAtomic
			v.ExactSignedBOC = nil
			v.UpdatedAtUnix = s.now().UTC().Unix()
			return nil
		})
		if err != nil {
			return Record{}, err
		}
	}
	if len(terms.ExactSignedBOC) == 0 {
		return Record{}, errors.New("protocol boundary did not expose exact BOC for broadcast")
	}
	record, err = s.journal.Update(intent, func(v *Record) error {
		v.ExactSignedBOC = append([]byte(nil), terms.ExactSignedBOC...)
		v.UpdatedAtUnix = s.now().UTC().Unix()
		return nil
	})
	if err != nil {
		return Record{}, err
	}
	record, err = s.journal.Update(intent, func(v *Record) error {
		v.PendingEffect = EffectBroadcast
		v.BroadcastAttempts++
		v.RetryNotBeforeUnix = 0
		v.UpdatedAtUnix = s.now().UTC().Unix()
		return nil
	})
	if err != nil {
		return Record{}, err
	}
	if err := s.broadcaster.BroadcastExactBOC(ctx, record.ExactSignedBOC); err != nil {
		return Record{}, err
	}
	return s.journal.Update(intent, func(v *Record) error {
		v.State = StateBroadcastSubmitted
		v.PendingEffect = EffectNone
		v.RetryNotBeforeUnix = s.now().UTC().Add(broadcastRetryDelay(v.BroadcastAttempts)).Unix()
		v.UpdatedAtUnix = s.now().UTC().Unix()
		return nil
	})
}

func (s *Service) Refresh(ctx context.Context, intent string) (Record, error) {
	unlock := s.lockIntent(intent)
	defer unlock()
	record, found := s.journal.Get(intent)
	if !found {
		return Record{}, errors.New("Gift not found")
	}
	if len(record.ExactSignedBOC) == 0 || !refreshableRecordState(record) {
		return Record{}, errors.New("Gift is not ready for finalized refresh")
	}
	result, err := s.resolver.ResolveFinality(ctx, record)
	if err != nil {
		return s.journal.Update(intent, func(v *Record) error {
			v.State = StateFinalityUnknown
			v.UpdatedAtUnix = s.now().UTC().Unix()
			return nil
		})
	}
	switch result.State {
	case StateFinalizedPaid, StateExpiredUnpaid, StateInvalidatedUnpaid, StateFinalityUnknown, StateCurrentlyExecutable, StateCurrentlyUnexecutable, StateInsufficientFunds:
	default:
		return record, nil
	}
	if result.State == StateFinalizedPaid && record.Role == RoleSender {
		if err := s.custody.ResolveNativeGift(ctx, ResolveRequest{
			IntentID: record.IntentID, SignedGiftID: record.SignedGiftID,
			SenderAgentAccount: record.SenderAgentAccount,
			DestinationAddress: record.DestinationAddress, AmountAtomic: record.AmountAtomic,
			ExactBOCDigest: record.ExactBOCDigest, GlobalID: record.GlobalID,
			ControllerEpoch: record.ControllerEpoch, Seqno: record.Seqno, ValidUntil: record.ValidUntil,
			ExactSignedBOC: append([]byte(nil), record.ExactSignedBOC...),
		}); err != nil {
			unknown, updateErr := s.journal.Update(intent, func(v *Record) error {
				v.State = StateFinalityUnknown
				v.UpdatedAtUnix = s.now().UTC().Unix()
				return nil
			})
			if updateErr != nil {
				return record, errors.Join(err, updateErr)
			}
			return unknown, err
		}
	}
	return s.journal.Update(intent, func(v *Record) error {
		v.State = result.State
		if result.State == StateFinalizedPaid || result.State == StateExpiredUnpaid || result.State == StateInvalidatedUnpaid {
			v.PendingEffect = EffectNone
			v.RetryNotBeforeUnix = 0
			compactTerminalRecord(v)
		} else if (result.State == StateCurrentlyExecutable || result.State == StateCurrentlyUnexecutable || result.State == StateInsufficientFunds) && (v.PendingEffect == EffectBroadcast || v.PendingEffect == EffectCancel) {
			// The finalized resolver proved that neither exact BOC consumed this
			// sequence. Release only the side-effect retry gate; custody retains
			// the sequence claim and any retry must use the persisted exact bytes.
			wasCancel := v.PendingEffect == EffectCancel
			v.PendingEffect = EffectNone
			attempts := v.BroadcastAttempts
			if wasCancel {
				attempts = v.CancellationAttempts
			}
			v.RetryNotBeforeUnix = s.now().UTC().Add(broadcastRetryDelay(attempts)).Unix()
		}
		v.UpdatedAtUnix = s.now().UTC().Unix()
		return nil
	})
}

func (s *Service) Cancel(ctx context.Context, intent string) (Record, error) {
	unlock := s.lockIntent(intent)
	defer unlock()
	record, found := s.journal.Get(intent)
	if !found || record.Role != RoleSender || (record.State != StateBOCSigned && record.State != StateOfferDelivered && record.State != StateCurrentlyExecutable && record.State != StateCurrentlyUnexecutable && record.State != StateInsufficientFunds && record.State != StateFinalityUnknown) {
		return Record{}, errors.New("Gift is not cancellable")
	}
	if record.PendingEffect == EffectCancel {
		return Record{}, errors.New("ambiguous cancellation requires finalized refresh")
	}
	if record.RetryNotBeforeUnix > s.now().UTC().Unix() {
		return Record{}, errors.New("exact cancellation retry is rate limited")
	}
	if record.PendingEffect != EffectNone && record.PendingEffect != EffectPrepareCancel {
		return Record{}, errors.New("Gift has another unresolved side effect")
	}
	var err error
	if record.PendingEffect == EffectNone && len(record.ExactCancellationBOC) == 0 {
		digest, err := s.owner.Authorize(ctx, OwnerReview{Action: "cancel", IntentID: intent, SignedGiftID: record.SignedGiftID, RecipientAgentID: record.RecipientAgentID, Network: record.Network, GlobalID: record.GlobalID, AmountAtomic: record.AmountAtomic, DestinationAddress: record.DestinationAddress, SenderAgentAccount: record.SenderAgentAccount, DeploymentID: record.DeploymentID, ControllerEpoch: record.ControllerEpoch, Seqno: record.Seqno, ValidUntil: record.ValidUntil, RequestDigest: record.RequestDigest, ResponseDigest: record.ResponseDigest, RequestedValidUntil: record.RequestedValidUntil, ResponseNotAfter: record.ResponseNotAfter, FundsLocked: false})
		if err != nil || digest == "" {
			return Record{}, errors.New("owner cancellation authorization failed")
		}
		record, err = s.journal.Update(intent, func(v *Record) error {
			v.PendingEffect = EffectPrepareCancel
			v.CancellationAuthorizationDigest = digest
			v.UpdatedAtUnix = s.now().UTC().Unix()
			return nil
		})
		if err != nil {
			return Record{}, err
		}
	}
	if len(record.ExactCancellationBOC) == 0 {
		boc, err := s.custody.CancelSeqno(ctx, CancelRequest{IntentID: intent, SignedGiftID: record.SignedGiftID, OwnerAuthorizationDigest: record.CancellationAuthorizationDigest, SenderAgentAccount: record.SenderAgentAccount, GlobalID: record.GlobalID, Seqno: record.Seqno, ValidUntil: record.ValidUntil})
		if err != nil {
			return Record{}, err
		}
		if len(boc) == 0 {
			return Record{}, errors.New("custody returned no exact cancellation BOC")
		}
		record, err = s.journal.Update(intent, func(v *Record) error {
			v.ExactCancellationBOC = append([]byte(nil), boc...)
			v.UpdatedAtUnix = s.now().UTC().Unix()
			return nil
		})
		if err != nil {
			return Record{}, err
		}
	}
	record, err = s.journal.Update(intent, func(v *Record) error {
		v.PendingEffect = EffectCancel
		v.CancellationAttempts++
		v.RetryNotBeforeUnix = 0
		v.UpdatedAtUnix = s.now().UTC().Unix()
		return nil
	})
	if err != nil {
		return Record{}, err
	}
	if err := s.broadcaster.BroadcastExactBOC(ctx, record.ExactCancellationBOC); err != nil {
		return Record{}, err
	}
	// Cancellation and Gift race on the same seqno. Neither a custody ack nor
	// local time selects the winner; Refresh must resolve finalized state.
	return record, nil
}

func newIntentID() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

// ListRecords returns a private snapshot for the owner-runtime reconciler. It
// deliberately does not project records into model or logging surfaces.
func (s *Service) ListRecords() []Record {
	if s == nil || s.journal == nil {
		return nil
	}
	return s.journal.List()
}

func activeGiftCount(records []Record, peer string) int {
	count := 0
	for _, record := range records {
		if terminalState(record.State) || peer != "" && record.SenderAgentID != peer {
			continue
		}
		count++
	}
	return count
}

func refreshableRecordState(record Record) bool {
	if record.Role == RoleSender {
		return record.State == StateBOCSigned || record.State == StateOfferDelivered || record.State == StateCurrentlyExecutable || record.State == StateCurrentlyUnexecutable || record.State == StateInsufficientFunds || record.State == StateFinalityUnknown
	}
	return record.State == StateVerified || record.State == StateBroadcastSubmitted || record.State == StateCurrentlyExecutable || record.State == StateCurrentlyUnexecutable || record.State == StateInsufficientFunds || record.State == StateFinalityUnknown
}

func compactTerminalRecord(record *Record) {
	record.CanonicalOffer = nil
	record.ExactSignedBOC = nil
	record.ExactCancellationBOC = nil
}

func canonicalBytesDigest(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func (s *Service) lockIntent(intent string) func() {
	digest := sha256.Sum256([]byte(intent))
	index := (int(digest[0])<<8 | int(digest[1])) % len(s.intentMu)
	mutex := &s.intentMu[index]
	mutex.Lock()
	return mutex.Unlock
}

func broadcastRetryDelay(attempts uint32) time.Duration {
	delay := initialBroadcastRetryDelay
	for index := uint32(1); index < attempts && delay < maxBroadcastRetryDelay; index++ {
		delay *= 2
		if delay > maxBroadcastRetryDelay {
			delay = maxBroadcastRetryDelay
		}
	}
	return delay
}
