package servicebridge

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/tosnetwork/tos-ai/pkg/railgate"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
)

// Operator states of one provider request. They are local projections of
// local records and finalized chain facts, not contract states.
const (
	OperatorAdmitted        = "admitted"
	OperatorExecuting       = "executing"
	OperatorResultAvailable = "result_available"
	OperatorResponded       = "responded"
	OperatorRefunded        = "refunded"
	OperatorSwept           = "swept"
	OperatorOutcomeUnknown  = "outcome_unknown"
)

// Finalized chain facts about one request, as read at one checkpoint.
const (
	ChainFactNotRead       = "not_read"
	ChainFactPending       = "pending"
	ChainFactRefundable    = "refundable"
	ChainFactResponded     = "responded"
	ChainFactOtherResponse = "responded_with_another_hash"
	ChainFactRefundClaimed = "refund_claimed"
	ChainFactSwept         = "swept"
	ChainFactNotFound      = "not_found"
	// ChainFactUnmatchedResponse is a finalized respond for a request the
	// node holds no attested result for, so its hash cannot be compared.
	ChainFactUnmatchedResponse = "responded_without_local_result"
	// ChainFactHistoryIncomplete is a request neither pending nor refundable
	// whose terminal transaction could not be looked for: the history read
	// failed or stopped at its bound.
	ChainFactHistoryIncomplete = "history_incomplete"
	// ChainFactActorInactive is a request of an actor that is not an active
	// account at the checkpoint.
	ChainFactActorInactive = "actor_not_active"
)

// Where a listed request comes from.
const (
	RequestSourceRecord = "record"
	RequestSourceSlot   = "slot"
)

// ProviderStatusSchema names the status report; ProviderStatusVersion
// changes only when a field changes meaning or is removed.
const (
	ProviderStatusSchema  = "tos.openfox.provider-status"
	ProviderStatusVersion = 1
)

// RequestStatus is one provider request with its operator state. The
// embedded record keeps every field the earlier listing printed.
type RequestStatus struct {
	ProviderRecord
	// Source is "record" for a provider record, or "slot" for a request the
	// rail gate admitted that has no provider record yet; a slot entry
	// carries no record schema.
	Source        string `json:"source"`
	SlotState     string `json:"slot_state,omitempty"`
	OperatorState string `json:"operator_state"`
	ChainFact     string `json:"chain_fact"`
	StateReason   string `json:"state_reason"`
}

// ActorSummary is the actor's finalized accounting. Credited revenue is a
// contract balance the owner may later withdraw; it is not money received
// in a wallet.
type ActorSummary struct {
	Address                    string `json:"address"`
	Read                       bool   `json:"read"`
	Error                      string `json:"error,omitempty"`
	Checkpoint                 uint64 `json:"checkpoint,omitempty"`
	ChainTimeUnix              int64  `json:"chain_time_unix,omitempty"`
	Active                     *bool  `json:"active,omitempty"`
	PendingCount               uint32 `json:"pending_count,omitempty"`
	LiveCount                  uint32 `json:"live_count,omitempty"`
	BalanceNanoTOS             string `json:"actor_balance_nanotos,omitempty"`
	CreditedRevenueNanoTOS     string `json:"credited_revenue_nanotos,omitempty"`
	PendingLiabilityNanoTOS    string `json:"pending_liability_nanotos,omitempty"`
	RefundableLiabilityNanoTOS string `json:"refundable_liability_nanotos,omitempty"`
	LockedStorageFeesNanoTOS   string `json:"locked_storage_fees_nanotos,omitempty"`
	RevenueNote                string `json:"revenue_note"`
	WalletReceipt              string `json:"wallet_receipt"`
}

// ProviderStatus is the operator's view of a provider node.
type ProviderStatus struct {
	Schema        string          `json:"schema"`
	Version       int             `json:"version"`
	GeneratedUnix int64           `json:"generated_unix"`
	Admission     AdmissionStatus `json:"admission"`
	Actor         *ActorSummary   `json:"actor,omitempty"`
	Requests      []RequestStatus `json:"requests"`
}

// AdmissionStatus says whether new requests are admitted.
type AdmissionStatus struct {
	Paused     bool   `json:"paused"`
	PausedUnix int64  `json:"paused_unix,omitempty"`
	Reason     string `json:"reason,omitempty"`
	Error      string `json:"error,omitempty"`
}

const (
	revenueNote = "credited to the actor's withdrawable_revenue; not received until withdraw_revenue " +
		"finalizes and the wallet credit is verified"
	walletReceiptNotTracked = "not_tracked"
)

// StatusSession is the part of a finalized reader session status reads.
type StatusSession interface {
	Checkpoint() uint64
	ChainTime() time.Time
	ReadActor(ctx context.Context, actor string) (*toschain.ActorAccount, bool, error)
	History(ctx context.Context, actor string, anchor *toschain.ActorTxID) (*toschain.ActorHistory, error)
}

// StatusChain opens finalized sessions for the status report.
type StatusChain interface {
	BeginStatus(ctx context.Context) (StatusSession, error)
}

type unavailableStatusChain struct{ err error }

func (c unavailableStatusChain) BeginStatus(context.Context) (StatusSession, error) {
	return nil, c.err
}

// UnavailableStatusChain stands for a reader that could not be opened: the
// report is the offline one, with err in the actor summary, rather than no
// report at all.
func UnavailableStatusChain(err error) StatusChain {
	if err == nil {
		err = errors.New("servicebridge: the finalized reader is unavailable")
	}
	return unavailableStatusChain{err: err}
}

// ReaderStatusChain adapts the finalized Service Actor reader.
type ReaderStatusChain struct{ Reader *toschain.ServiceActorReader }

// BeginStatus implements StatusChain.
func (c ReaderStatusChain) BeginStatus(ctx context.Context) (StatusSession, error) {
	if c.Reader == nil {
		return nil, errors.New("servicebridge: no chain reader")
	}
	return c.Reader.Begin(ctx)
}

// OpenStatusChain opens the configuration's finalized reader. Its
// checkpoint fences are the node's own, so a status read never accepts a
// checkpoint older than one `serve` already acted on.
func OpenStatusChain(config NodeConfig) (StatusChain, error) {
	reader, err := openServiceActorReader(config, networkOf(config), config.StateDir)
	if err != nil {
		return nil, err
	}
	return ReaderStatusChain{Reader: reader}, nil
}

func networkOf(config NodeConfig) *nativev1.NetworkDomain {
	return &nativev1.NetworkDomain{
		NetworkId: config.Network.NetworkID, GenesisRootHash: config.Network.GenesisRootHash,
		GenesisFileHash: config.Network.GenesisFileHash,
	}
}

var slotFilePattern = regexp.MustCompile(`^[0-9a-f]{64}\.json$`)

const railgateSlotSchema = "tos.ai.railgate-slot.v1"

// readSlots lists the rail gate's slots without taking the gate's ownership.
// A missing directory means nothing was ever admitted.
func readSlots(stateDir string) ([]railgate.Slot, error) {
	directory := filepath.Join(stateDir, "slots")
	if _, err := os.Lstat(directory); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err := checkPrivateDirectory(directory); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, errors.New("servicebridge: read the slot directory")
	}
	var slots []railgate.Slot
	for _, entry := range entries {
		if !slotFilePattern.MatchString(entry.Name()) {
			continue
		}
		raw, err := readPrivateFile(filepath.Join(directory, entry.Name()), 4<<10)
		if err != nil {
			return nil, fmt.Errorf("servicebridge: slot %s: %w", entry.Name(), err)
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		var slot railgate.Slot
		if err := decoder.Decode(&slot); err != nil {
			return nil, fmt.Errorf("servicebridge: slot %s does not decode", entry.Name())
		}
		var trailing any
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("servicebridge: slot %s has trailing data", entry.Name())
		}
		if slot.Schema != railgateSlotSchema || !rawAddressPattern.MatchString(slot.Actor) {
			return nil, fmt.Errorf("servicebridge: slot %s is not a rail gate slot", entry.Name())
		}
		slots = append(slots, slot)
	}
	return slots, nil
}

// actorFacts is what one finalized session says about an actor.
type actorFacts struct {
	read    bool
	err     string
	account *toschain.ActorAccount
	found   bool
	history *toschain.ActorHistory
}

type requestKey struct {
	actor string
	id    uint64
}

// requestFact is what the finalized read says about one request.
// responseHash is the locally attested response hash, empty when the node
// holds no attested result for the request.
func (f *actorFacts) requestFact(requestID uint64, responseHash string) (string, string) {
	if f == nil || !f.read {
		return ChainFactNotRead, ""
	}
	complete := f.history != nil && f.history.Result == toschain.HistoryComplete
	if complete {
		// Terminal transactions are matched newest first; a request has at
		// most one terminal resolution.
		for _, transaction := range f.history.Transactions {
			if transaction.RequestID != requestID {
				continue
			}
			switch transaction.Kind {
			case toschain.ActorTxSweep:
				return ChainFactSwept, ""
			case toschain.ActorTxClaim:
				return ChainFactRefundClaimed, ""
			case toschain.ActorTxRespond:
				switch {
				case responseHash == "":
					return ChainFactUnmatchedResponse, transaction.ResponseHash
				case transaction.ResponseHash != responseHash:
					return ChainFactOtherResponse, transaction.ResponseHash
				default:
					return ChainFactResponded, transaction.ResponseHash
				}
			}
		}
	}
	if !f.found || f.account == nil || f.account.Data == nil {
		return ChainFactActorInactive, ""
	}
	if _, ok := f.account.Data.Pending[requestID]; ok {
		return ChainFactPending, ""
	}
	if _, ok := f.account.Data.Refunds[requestID]; ok {
		return ChainFactRefundable, ""
	}
	if !complete {
		return ChainFactHistoryIncomplete, ""
	}
	return ChainFactNotFound, ""
}

// projectRequest derives one request's operator state. It never reports
// success it cannot see: anything it cannot determine is outcome_unknown.
func projectRequest(record *ProviderRecord, slot *railgate.Slot, fact string) (string, string) {
	switch fact {
	case ChainFactSwept:
		return OperatorSwept, "finalized sweep_expired_request returned the price to the caller"
	case ChainFactRefundClaimed:
		return OperatorRefunded, "finalized claim_refund paid the price to the caller"
	case ChainFactRefundable:
		return OperatorRefunded, "finalized expire made the price refundable; the caller has not claimed it yet"
	case ChainFactResponded:
		return OperatorResponded, "finalized respond with this request's attested response hash"
	case ChainFactOtherResponse:
		return OperatorOutcomeUnknown, "finalized respond carries another response hash than the local record"
	case ChainFactUnmatchedResponse:
		return OperatorOutcomeUnknown, "a finalized respond exists but the node holds no attested result to " +
			"compare its response hash with"
	case ChainFactNotFound:
		return OperatorOutcomeUnknown, "the request is neither pending nor refundable and no terminal " +
			"transaction was found in the complete finalized history"
	case ChainFactPending, ChainFactNotRead, ChainFactHistoryIncomplete, ChainFactActorInactive:
		// The chain did not settle the request at this checkpoint: the local
		// state decides, and never more than it saw itself.
	default:
		return OperatorOutcomeUnknown, "unrecognized chain fact"
	}
	pending := fact == ChainFactPending
	if record != nil {
		switch record.State {
		case ProviderExecuted:
			return OperatorResultAvailable, "executed and attested locally; respond not yet sent"
		case ProviderResponding:
			if pending {
				return OperatorResultAvailable, "respond sent; the request is still pending at the checkpoint"
			}
			return OperatorOutcomeUnknown, "respond sent; its finality is not established"
		case ProviderDelivering, ProviderAcked, ProviderExpired:
			if pending {
				return OperatorOutcomeUnknown, "the local record saw a finalized respond but the chain shows the request pending"
			}
			return OperatorResponded, "the provider observed the finalized respond before delivering " +
				"(not re-established at this checkpoint)"
		case ProviderFailed:
			return OperatorOutcomeUnknown, "execution failed and is never attested; the request resolves by " +
				"expire and claim_refund or by sweep"
		case ProviderAbandoned:
			return OperatorOutcomeUnknown, "the request left its window before it could execute or respond; it " +
				"resolves by expire and claim_refund or by sweep"
		default:
			return OperatorOutcomeUnknown, "unrecognized local record state"
		}
	}
	if slot != nil {
		switch slot.State {
		case railgate.SlotAdmitted:
			return OperatorAdmitted, "admitted by the rail gate; execution has not started"
		case railgate.SlotStarted:
			return OperatorExecuting, "the execution was handed to the executor"
		case railgate.SlotAmbiguous:
			return OperatorOutcomeUnknown, "the execution started and has no recorded outcome; it is never attested"
		case railgate.SlotFailed, railgate.SlotAbandoned:
			return OperatorOutcomeUnknown, "the gate recorded no result; the request resolves by refund or sweep"
		case railgate.SlotCompleted:
			return OperatorOutcomeUnknown, "the gate recorded a result but the provider record is missing"
		}
	}
	return OperatorOutcomeUnknown, "no local record of this request"
}

// projectProviderStatus composes the operator view from local records, rail
// gate slots and, when given, finalized facts per actor.
func projectProviderStatus(
	records []ProviderRecord,
	slots []railgate.Slot,
	facts map[string]*actorFacts,
) []RequestStatus {
	slotByKey := map[requestKey]*railgate.Slot{}
	for index := range slots {
		slotByKey[requestKey{slots[index].Actor, slots[index].RequestID}] = &slots[index]
	}
	seen := map[requestKey]bool{}
	out := make([]RequestStatus, 0, len(records)+len(slots))
	for index := range records {
		record := records[index]
		key := requestKey{record.Actor, record.RequestID}
		seen[key] = true
		slot := slotByKey[key]
		fact, _ := facts[record.Actor].requestFact(record.RequestID, record.ResponseHash)
		state, reason := projectRequest(&record, slot, fact)
		status := RequestStatus{
			ProviderRecord: record, Source: RequestSourceRecord, OperatorState: state, ChainFact: fact,
			StateReason: reason,
		}
		if slot != nil {
			status.SlotState = string(slot.State)
		}
		out = append(out, status)
	}
	for index := range slots {
		slot := slots[index]
		key := requestKey{slot.Actor, slot.RequestID}
		if seen[key] {
			continue
		}
		// Only a completed slot holds an attested response hash.
		fact, _ := facts[slot.Actor].requestFact(slot.RequestID, slot.ResponseHash)
		state, reason := projectRequest(nil, &slot, fact)
		out = append(out, RequestStatus{
			ProviderRecord: ProviderRecord{
				QuoteCommitment: slot.QuoteCommitment, Actor: slot.Actor, RequestID: slot.RequestID,
				RequestHash: slot.RequestHash, ResponseHash: slot.ResponseHash, UpdatedUnix: slot.UpdatedUnix,
			},
			Source: RequestSourceSlot, SlotState: string(slot.State), OperatorState: state, ChainFact: fact,
			StateReason: reason,
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].UpdatedUnix > out[j].UpdatedUnix })
	return out
}

func nanoText(value *big.Int) string {
	if value == nil {
		return ""
	}
	return value.String()
}

func summarize(actor string, facts *actorFacts, session StatusSession) *ActorSummary {
	summary := &ActorSummary{Address: actor, RevenueNote: revenueNote, WalletReceipt: walletReceiptNotTracked}
	if facts == nil || !facts.read {
		summary.Error = "the actor was not read"
		if facts != nil && facts.err != "" {
			summary.Error = facts.err
		}
		return summary
	}
	summary.Read = true
	if session != nil {
		summary.Checkpoint, summary.ChainTimeUnix = session.Checkpoint(), session.ChainTime().Unix()
	}
	if !facts.found || facts.account == nil || facts.account.Data == nil {
		inactive := false
		summary.Active = &inactive
		summary.Error = "the actor account is not active at the checkpoint"
		return summary
	}
	data := facts.account.Data
	active := data.Active
	summary.Active = &active
	summary.PendingCount, summary.LiveCount = data.PendingCount, data.LiveCount
	summary.BalanceNanoTOS = new(big.Int).SetUint64(facts.account.BalanceNano).String()
	summary.CreditedRevenueNanoTOS = nanoText(data.Accounting.WithdrawableRevenue)
	summary.PendingLiabilityNanoTOS = nanoText(data.Accounting.PendingLiability)
	summary.RefundableLiabilityNanoTOS = nanoText(data.Accounting.RefundableLiability)
	summary.LockedStorageFeesNanoTOS = nanoText(data.Accounting.LockedStorageFees)
	if facts.err != "" {
		summary.Error = facts.err
	}
	return summary
}

// providerActor is the actor manifest key 21 names in the local manifest.
func providerActor(config NodeConfig) (string, error) {
	if config.Provider == nil {
		return "", errors.New("servicebridge: the rail configuration has no provider section")
	}
	raw, err := os.ReadFile(config.Provider.ManifestFile)
	if err != nil || len(raw) == 0 || len(raw) > 1<<20 {
		return "", errors.New("servicebridge: read the provider manifest")
	}
	manifest, err := nativecore.DecodeCanonicalSoftwareWorkManifestCBOR(raw)
	if err != nil {
		return "", fmt.Errorf("servicebridge: the provider manifest does not decode: %w", err)
	}
	if len(manifest.Settlement.ActorAccountID) != 32 {
		return "", errors.New("servicebridge: the provider manifest names no actor")
	}
	return "0:" + hex.EncodeToString(manifest.Settlement.ActorAccountID), nil
}

// ReadProviderStatus builds the operator view. chain may be nil for an
// offline report, in which case chain-dependent states stay unknown or come
// only from what `serve` already recorded. A chain read failure is reported
// in the actor summary; it never turns into a guessed state.
func ReadProviderStatus(
	ctx context.Context,
	config NodeConfig,
	chain StatusChain,
	now time.Time,
) (*ProviderStatus, error) {
	records, err := ReadProviderRecords(config.StateDir)
	if err != nil {
		return nil, err
	}
	slots, err := readSlots(config.StateDir)
	if err != nil {
		return nil, err
	}
	status := &ProviderStatus{Schema: ProviderStatusSchema, Version: ProviderStatusVersion, GeneratedUnix: now.Unix()}
	if pause, pauseErr := ReadAdmissionPause(config.StateDir); pauseErr != nil {
		status.Admission = AdmissionStatus{Paused: true, Error: pauseErr.Error()}
	} else if pause != nil {
		status.Admission = AdmissionStatus{Paused: true, PausedUnix: pause.PausedUnix, Reason: pause.Reason}
	}
	actor, err := providerActor(config)
	if err != nil {
		return nil, err
	}
	actors := map[string]bool{actor: true}
	for _, record := range records {
		actors[record.Actor] = true
	}
	for _, slot := range slots {
		actors[slot.Actor] = true
	}
	facts := map[string]*actorFacts{}
	var session StatusSession
	if chain != nil {
		session, err = chain.BeginStatus(ctx)
		if err != nil {
			session = nil
			facts[actor] = &actorFacts{err: "finalized read failed: " + err.Error()}
		} else {
			names := make([]string, 0, len(actors))
			for name := range actors {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				facts[name] = readActorFacts(ctx, session, name)
			}
		}
	}
	// Chain errors can quote an endpoint URL, whose path may carry a token.
	for _, value := range facts {
		value.err = redactEndpoints(value.err, config.RPCEndpoints)
	}
	status.Actor = summarize(actor, facts[actor], session)
	status.Requests = projectProviderStatus(records, slots, facts)
	return status, nil
}

func readActorFacts(ctx context.Context, session StatusSession, actor string) *actorFacts {
	account, found, err := session.ReadActor(ctx, actor)
	if err != nil {
		return &actorFacts{err: "read the actor: " + err.Error()}
	}
	facts := &actorFacts{read: true, account: account, found: found}
	if !found {
		return facts
	}
	history, err := session.History(ctx, actor, nil)
	if err != nil {
		facts.err = "read the actor history: " + err.Error()
		return facts
	}
	facts.history = history
	if history.Result != toschain.HistoryComplete {
		facts.err = "the actor history is not complete; terminal transactions are not matched"
	}
	return facts
}
