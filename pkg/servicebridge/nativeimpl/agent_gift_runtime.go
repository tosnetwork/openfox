package nativeimpl

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	openfoxgift "github.com/tosnetwork/openfox/pkg/agentgift"
	"github.com/tosnetwork/tos-messenger/pkg/envelope"
	"github.com/tosnetwork/tos-messenger/pkg/fault"
	"github.com/tosnetwork/tos-messenger/pkg/localapi"
	protocolgift "github.com/tosnetwork/tos-service-protocol/pkg/agentgift"
)

type AgentGiftRuntimeConfig struct {
	LocalAgentID         string
	Network              string
	GlobalID             int32
	ResponseLifetime     time.Duration
	PollInterval         time.Duration
	ApplicationLease     time.Duration
	FinalityPollInterval time.Duration
}

// AgentGiftRuntime is the production reconciliation loop between the private
// OpenFox journal and tos-messengerd's authenticated application inbox. It
// claims and completes daemon Events, and every retry delegates to the durable
// state machine so exact canonical bytes are reused after process death.
type AgentGiftRuntime struct {
	service *openfoxgift.Service
	client  AgentGiftMessengerCaller
	config  AgentGiftRuntimeConfig
	now     func() time.Time
	faultMu sync.Mutex
	faults  map[AgentGiftRuntimeFault]uint64
}

type AgentGiftRuntimeFault string

const (
	AgentGiftFaultRecordReconcile AgentGiftRuntimeFault = "record-reconcile"
	AgentGiftFaultPendingCorrupt  AgentGiftRuntimeFault = "pending-event-corrupt"
	AgentGiftFaultInboundRejected AgentGiftRuntimeFault = "inbound-event-rejected"
	AgentGiftFaultInfrastructure  AgentGiftRuntimeFault = "messenger-infrastructure"
)

func NewAgentGiftRuntime(service *openfoxgift.Service, client AgentGiftMessengerCaller, config AgentGiftRuntimeConfig) (*AgentGiftRuntime, error) {
	if service == nil || client == nil || !canonicalGiftAgentID(config.LocalAgentID) || config.Network == "" || config.GlobalID == 0 {
		return nil, errors.New("nativeimpl: incomplete Agent Gift runtime")
	}
	if config.ResponseLifetime == 0 {
		config.ResponseLifetime = time.Hour
	}
	if config.PollInterval == 0 {
		config.PollInterval = time.Second
	}
	if config.ApplicationLease == 0 {
		config.ApplicationLease = time.Minute
	}
	if config.FinalityPollInterval == 0 {
		config.FinalityPollInterval = 15 * time.Second
	}
	if config.ResponseLifetime < time.Minute || config.ResponseLifetime > 24*time.Hour ||
		config.PollInterval < 100*time.Millisecond || config.PollInterval > time.Minute ||
		config.ApplicationLease < 30*time.Second || config.ApplicationLease > 10*time.Minute ||
		config.FinalityPollInterval < time.Second || config.FinalityPollInterval > 10*time.Minute {
		return nil, errors.New("nativeimpl: invalid bounded Agent Gift runtime policy")
	}
	return &AgentGiftRuntime{service: service, client: client, config: config, now: time.Now, faults: make(map[AgentGiftRuntimeFault]uint64)}, nil
}

func (r *AgentGiftRuntime) Run(ctx context.Context) error {
	if r == nil || ctx == nil {
		return errors.New("nativeimpl: invalid Agent Gift runtime")
	}
	ticker := time.NewTicker(r.config.PollInterval)
	defer ticker.Stop()
	for {
		if err := r.RunOnce(ctx); err != nil {
			r.recordFault(AgentGiftFaultInfrastructure)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (r *AgentGiftRuntime) RunOnce(ctx context.Context) error {
	if r == nil || r.service == nil || r.client == nil || ctx == nil {
		return errors.New("nativeimpl: invalid Agent Gift runtime")
	}
	for _, record := range r.service.ListRecords() {
		if err := r.advance(ctx, record); err != nil {
			r.recordFault(AgentGiftFaultRecordReconcile)
		}
	}
	pending, err := r.client.Call(ctx, localapi.Request{Op: localapi.OpPendingAgentGifts, Limit: localapi.MaxEventsPerResponse})
	if err != nil {
		return err
	}
	for _, candidate := range pending.Events {
		event, decodeErr := envelope.DecodeEventJSON(candidate.Event)
		if decodeErr != nil {
			r.recordFault(AgentGiftFaultPendingCorrupt)
			continue
		}
		if !giftApplicationKind(event.Kind) {
			continue
		}
		leaseID, err := newGiftLeaseID()
		if err != nil {
			return err
		}
		claimed, err := r.client.Call(ctx, localapi.Request{Op: localapi.OpClaimAgentGift, EventID: candidate.EventID, LeaseID: leaseID, LeaseSeconds: uint64(r.config.ApplicationLease / time.Second)})
		if err != nil {
			return err
		}
		if claimed.Event == nil {
			r.recordFault(AgentGiftFaultInboundRejected)
			if _, err := r.client.Call(ctx, localapi.Request{Op: localapi.OpReject, EventID: candidate.EventID, LeaseID: leaseID, Code: fault.CodePayloadMalformed}); err != nil {
				return err
			}
			continue
		}
		inbound, err := DecodeClaimedAgentGift(*claimed.Event)
		if err != nil {
			r.recordFault(AgentGiftFaultInboundRejected)
			if _, rejectErr := r.client.Call(ctx, localapi.Request{Op: localapi.OpReject, EventID: candidate.EventID, LeaseID: leaseID, Code: fault.CodePayloadMalformed}); rejectErr != nil {
				return rejectErr
			}
			continue
		}
		durable, applyErr := r.applyInbound(ctx, inbound)
		if applyErr != nil {
			r.recordFault(AgentGiftFaultInboundRejected)
			if !durable {
				if _, err := r.client.Call(ctx, localapi.Request{Op: localapi.OpReject, EventID: inbound.EventID, LeaseID: leaseID, Code: fault.CodePayloadMalformed}); err != nil {
					return err
				}
				continue
			}
		}
		if _, err := r.client.Call(ctx, localapi.Request{Op: localapi.OpComplete, EventID: inbound.EventID, LeaseID: leaseID}); err != nil {
			return err
		}
	}
	return nil
}

func (r *AgentGiftRuntime) applyInbound(ctx context.Context, inbound AgentGiftInbound) (bool, error) {
	switch inbound.Kind {
	case "agent.gift.address-request":
		request, err := protocolgift.DecodeAddressRequest(inbound.Canonical)
		if err != nil {
			return false, err
		}
		if request.Network != r.config.Network || request.GlobalID != r.config.GlobalID {
			return false, errors.New("nativeimpl: Gift request conflicts with fixed runtime network")
		}
		record, err := r.service.ObserveRecipientRequest(ctx, inbound.Canonical, r.config.LocalAgentID, inbound.SenderAgentID)
		if err != nil {
			return false, err
		}
		return true, r.advance(ctx, record)
	case "agent.gift.address-response":
		response, err := protocolgift.DecodeAddressResponse(inbound.Canonical)
		if err != nil {
			return false, err
		}
		existing, found := r.findRecord(response.GiftIntentID)
		if !found || existing.Role != openfoxgift.RoleSender || existing.RecipientAgentID != inbound.SenderAgentID {
			return false, errors.New("nativeimpl: Gift response sender conflicts with durable intent")
		}
		record, err := r.service.ObserveAddressResponse(ctx, response.GiftIntentID, inbound.Canonical)
		if err != nil {
			return false, err
		}
		return true, r.advance(ctx, record)
	case "agent.gift.signed-boc-offer":
		offer, err := protocolgift.DecodeSignedBOCOffer(inbound.Canonical)
		if err != nil {
			return false, err
		}
		existing, found := r.findRecord(offer.GiftIntentID)
		if !found || existing.Role != openfoxgift.RoleRecipient || existing.SenderAgentID != inbound.SenderAgentID {
			return false, errors.New("nativeimpl: Gift offer sender conflicts with durable intent")
		}
		_, err = r.service.ObserveAndBroadcastOffer(ctx, offer.GiftIntentID, inbound.Canonical)
		return r.offerDurable(offer.GiftIntentID, inbound.Canonical), err
	default:
		return false, errors.New("nativeimpl: unsupported Agent Gift application kind")
	}
}

func (r *AgentGiftRuntime) advance(ctx context.Context, record openfoxgift.Record) error {
	var err error
	switch record.Role {
	case openfoxgift.RoleSender:
		switch {
		case record.PendingEffect == openfoxgift.EffectCancel && r.shouldRefresh(record):
			record, err = r.service.Refresh(ctx, record.IntentID)
		case record.PendingEffect == openfoxgift.EffectPrepareCancel:
			_, err = r.service.Cancel(ctx, record.IntentID)
		case record.State == openfoxgift.StateRecipientResolved || record.State == openfoxgift.StateAddressRequested && record.PendingEffect == openfoxgift.EffectSendAddressRequest:
			_, err = r.service.RequestAddress(ctx, record.IntentID)
		case record.State == openfoxgift.StateOwnerAuthorized:
			_, err = r.service.Sign(ctx, record.IntentID, record.DisplayMessage)
		case record.State == openfoxgift.StateBOCSigned:
			_, err = r.service.DeliverOffer(ctx, record.IntentID)
		case len(record.ExactCancellationBOC) != 0 && record.PendingEffect == openfoxgift.EffectNone &&
			(record.State == openfoxgift.StateCurrentlyExecutable || record.State == openfoxgift.StateCurrentlyUnexecutable || record.State == openfoxgift.StateInsufficientFunds) && r.retryReady(record):
			_, err = r.service.Cancel(ctx, record.IntentID)
		case refreshableGiftState(record.State) && r.shouldRefresh(record):
			_, err = r.service.Refresh(ctx, record.IntentID)
		}
	case openfoxgift.RoleRecipient:
		switch {
		case record.State == openfoxgift.StateAddressRequestObserved:
			notAfter := record.ResponseNotAfter
			if notAfter == 0 {
				now := r.now().UTC()
				deadline := now.Add(r.config.ResponseLifetime).Unix()
				if deadline <= now.Unix() || deadline > int64(record.RequestedValidUntil) {
					deadline = int64(record.RequestedValidUntil)
				}
				if deadline <= now.Unix() {
					return errors.New("nativeimpl: Gift address request expired before response")
				}
				notAfter = uint32(deadline)
			}
			_, err = r.service.RespondAddress(ctx, record.IntentID, notAfter)
		case record.PendingEffect == openfoxgift.EffectBroadcast && r.shouldRefresh(record):
			record, err = r.service.Refresh(ctx, record.IntentID)
		case (record.State == openfoxgift.StateSignedOfferObserved || record.State == openfoxgift.StateVerified) && len(record.CanonicalOffer) != 0:
			_, err = r.service.ObserveAndBroadcastOffer(ctx, record.IntentID, record.CanonicalOffer)
		case record.State == openfoxgift.StateCurrentlyExecutable && len(record.CanonicalOffer) != 0 && r.retryReady(record):
			_, err = r.service.ObserveAndBroadcastOffer(ctx, record.IntentID, record.CanonicalOffer)
		case refreshableGiftState(record.State) && r.shouldRefresh(record):
			_, err = r.service.Refresh(ctx, record.IntentID)
		}
	default:
		return errors.New("nativeimpl: invalid Agent Gift runtime role")
	}
	return err
}

func (r *AgentGiftRuntime) findRecord(intent string) (openfoxgift.Record, bool) {
	for _, record := range r.service.ListRecords() {
		if record.IntentID == intent {
			return record, true
		}
	}
	return openfoxgift.Record{}, false
}

func (r *AgentGiftRuntime) shouldRefresh(record openfoxgift.Record) bool {
	return r.now().UTC().Unix()-record.UpdatedAtUnix >= int64(r.config.FinalityPollInterval/time.Second)
}

func (r *AgentGiftRuntime) retryReady(record openfoxgift.Record) bool {
	return record.RetryNotBeforeUnix == 0 || r.now().UTC().Unix() >= record.RetryNotBeforeUnix
}

func (r *AgentGiftRuntime) offerDurable(intent string, canonical []byte) bool {
	for _, record := range r.service.ListRecords() {
		if record.IntentID == intent && record.Role == openfoxgift.RoleRecipient && record.State != openfoxgift.StateSignedOfferObserved &&
			(bytes.Equal(record.CanonicalOffer, canonical) || record.CanonicalOfferDigest == giftCanonicalDigest(canonical)) {
			return true
		}
	}
	return false
}

func giftCanonicalDigest(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func (r *AgentGiftRuntime) recordFault(code AgentGiftRuntimeFault) {
	r.faultMu.Lock()
	defer r.faultMu.Unlock()
	r.faults[code]++
}

// FaultCounts exposes only bounded category counters to the owner runtime. It
// contains no Event IDs, AgentIDs, addresses, amounts, digests, or BOC bytes.
func (r *AgentGiftRuntime) FaultCounts() map[AgentGiftRuntimeFault]uint64 {
	r.faultMu.Lock()
	defer r.faultMu.Unlock()
	out := make(map[AgentGiftRuntimeFault]uint64, len(r.faults))
	for code, count := range r.faults {
		out[code] = count
	}
	return out
}

func refreshableGiftState(state openfoxgift.State) bool {
	return state == openfoxgift.StateOfferDelivered || state == openfoxgift.StateBroadcastSubmitted ||
		state == openfoxgift.StateCurrentlyExecutable || state == openfoxgift.StateCurrentlyUnexecutable ||
		state == openfoxgift.StateInsufficientFunds || state == openfoxgift.StateFinalityUnknown
}

func giftApplicationKind(kind string) bool {
	return kind == "agent.gift.address-request" || kind == "agent.gift.address-response" || kind == "agent.gift.signed-boc-offer"
}

func canonicalGiftAgentID(value string) bool {
	if len(value) != 70 || value[:6] != "agent_" {
		return false
	}
	_, err := hex.DecodeString(value[6:])
	return err == nil
}

func newGiftLeaseID() (string, error) {
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", errors.New("nativeimpl: create Agent Gift application lease")
	}
	return "lease_" + hex.EncodeToString(value[:]), nil
}
