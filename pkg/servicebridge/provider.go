package servicebridge

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/tosnetwork/ai/execution/pkg/railgate"
	"github.com/tosnetwork/ai/execution/pkg/softwarework"
	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/railwork"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
	"google.golang.org/protobuf/proto"
)

// Provider request states.
const (
	// ProviderExecuting: admitted and handed to the executor service, whose
	// outcome the node does not hold yet.
	ProviderExecuting = "executing"
	// ProviderUnknown: the executor service cannot account for the
	// execution; it is never attested.
	ProviderUnknown    = "unknown"
	ProviderExecuted   = "executed"
	ProviderResponding = "responding"
	ProviderDelivering = "delivering"
	ProviderAcked      = "acked"
	ProviderFailed     = "failed"
	ProviderAbandoned  = "abandoned"
	ProviderExpired    = "retention-ended"
)

const providerRecordSchema = "tos.openfox.rail-provider-request.v1"

// Redelivery backoff of an unacknowledged result.
const (
	FirstRedelivery = time.Minute
	MaxRedelivery   = time.Hour
)

// ProviderRecord is the provider's durable view of one admitted request.
type ProviderRecord struct {
	Schema           string `json:"schema"`
	State            string `json:"state"`
	BuyerAgentID     string `json:"buyer_agent_id"`
	CapabilityID     string `json:"capability_id"`
	QuoteCommitment  string `json:"quote_commitment"`
	Actor            string `json:"actor"`
	RequestID        uint64 `json:"request_id"`
	RequestHash      string `json:"request_hash"`
	ResponseHash     string `json:"response_hash,omitempty"`
	ReceiptBOCBase64 string `json:"receipt_boc_base64,omitempty"`
	ArtifactDigest   string `json:"artifact_digest,omitempty"`
	RetentionEndUnix uint64 `json:"retention_end_unix,omitempty"`
	ResponseDeadline uint64 `json:"response_deadline,omitempty"`
	RespondedAtUnix  int64  `json:"respond_attempt_unix,omitempty"`
	// The claim and the verified values the fresh pre-respond check needs.
	PackageBase64 string `json:"package_base64,omitempty"`
	BuyerWallet   string `json:"buyer_wallet,omitempty"`
	ExecutionID   string `json:"execution_id,omitempty"`
	InputDigest   string `json:"input_digest,omitempty"`
	CallLT        uint64 `json:"call_lt,omitempty"`
	CallHash      string `json:"call_hash,omitempty"`
	PriceNanoTOS  string `json:"price_nanotos,omitempty"`
	// What a restarted node needs to send an executing request to the
	// executor service again and attest its outcome.
	SourceDigest    string `json:"source_digest,omitempty"`
	ToolchainDigest string `json:"toolchain_digest,omitempty"`
	SandboxDigest   string `json:"sandbox_digest,omitempty"`
	// ExecutionLimits are the admitted manifest's limits, sent to the
	// executor service unchanged every time the request is sent.
	ExecutionLimits *ExecutionLimits `json:"execution_limits,omitempty"`
	// Detail says why a request ended in a state that is never attested,
	// when the reason is not the state itself.
	Detail           string `json:"detail,omitempty"`
	NextDeliveryUnix int64  `json:"next_delivery_unix,omitempty"`
	BackoffSeconds   int64  `json:"backoff_seconds,omitempty"`
	Deliveries       int    `json:"deliveries"`
	// ResultRequestUnix is when a buyer's result request last moved the
	// next delivery forward.
	ResultRequestUnix int64 `json:"result_request_unix,omitempty"`
	UpdatedUnix       int64 `json:"updated_unix"`
}

// ErrExecutorNotReady reports a task that was not admitted because the
// executor service could not run it at that moment. Nothing was claimed,
// verified or spent for it. Only the readiness question in front of
// admission returns it.
var ErrExecutorNotReady = errors.New(
	"servicebridge: the executor service cannot run work now; the task is not admitted",
)

// ExecutionLimits are a manifest's limits as a provider record keeps them.
type ExecutionLimits struct {
	CPUMillis       uint64 `json:"cpu_millis"`
	MemoryBytes     uint64 `json:"memory_bytes"`
	ScratchBytes    uint64 `json:"scratch_bytes"`
	OutputBytes     uint64 `json:"output_bytes"`
	WallClockMillis uint64 `json:"wall_clock_millis"`
}

// WorkRunner executes one bound software-work request at most once and
// returns its content-addressed outcome (tos-ai softwarework semantics).
type WorkRunner interface {
	Execute(ctx context.Context, request softwarework.Request) (softwarework.Outcome, error)
}

// ArtifactSource returns stored artifact bytes by digest.
type ArtifactSource interface {
	Get(ctx context.Context, digest string) ([]byte, error)
}

// ProviderConfig wires a provider worker. Exactly one of Runner and Service
// executes the work.
type ProviderConfig struct {
	AgentID      string
	CapabilityID string
	Version      string
	Network      *nativev1.NetworkDomain
	Gate         *railgate.Gate
	// Runner executes as part of this process: an execution that has no
	// outcome when the node restarts is ambiguous for good.
	Runner WorkRunner
	// Service executes through a service that owns the run. It needs
	// RespondBudget, the time kept for respond after an outcome arrives.
	Service            ServiceRunner
	RespondBudget      time.Duration
	Store              ArtifactSource
	Lifecycle          LifecycleSender
	AttestorController string
	Courier            *Courier
	// Cards, when the node has a relay carrier, takes the buyer's key card
	// from an admitted task so results can be sealed back to it.
	Cards *PeerCards
	// RelayKeys, when the node has a relay carrier, supplies the provider's
	// own key card for each result delivery.
	RelayKeys *RelayKeys
	History   railgate.Reader
	Directory string
	// StateDir holds the owner's admission pause marker. Empty means the
	// provider has no pause control; OpenNode always sets it.
	StateDir string
	Now      func() time.Time
}

// preRespondChecker is the part of the gate the delivery loop uses to recheck
// a request before it responds.
type preRespondChecker interface {
	Lookup(key railgate.SlotKey) (railgate.Slot, bool, error)
	Recheck(ctx context.Context, slot railgate.Slot, claim railgate.Claim, verified *railgate.Verified) error
}

// Provider executes admitted tasks, attests them and delivers results.
type Provider struct {
	config ProviderConfig
	// checker replaces the gate's pre-respond check when set.
	checker   preRespondChecker
	mutex     sync.Mutex
	lastSweep time.Time
}

func (p *Provider) preRespond() preRespondChecker {
	if p.checker != nil {
		return p.checker
	}
	if p.config.Gate != nil {
		return p.config.Gate
	}
	return nil
}

// NewProvider refuses an incomplete configuration.
func NewProvider(config ProviderConfig) (*Provider, error) {
	if !agentIDPattern.MatchString(config.AgentID) ||
		!capabilityPattern.MatchString(config.CapabilityID) ||
		config.Version == "" ||
		config.Network == nil ||
		config.Gate == nil ||
		(config.Runner == nil) == (config.Service == nil) ||
		(config.Service != nil && config.RespondBudget <= 0) ||
		config.Store == nil ||
		config.Lifecycle == nil ||
		!walletNamePattern.MatchString(config.AttestorController) ||
		config.Courier == nil ||
		config.History == nil ||
		!filepath.IsAbs(config.Directory) {
		return nil, errors.New("servicebridge: invalid provider configuration")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if err := ensurePrivateDirectory(config.Directory); err != nil {
		return nil, err
	}
	return &Provider{config: config}, nil
}

func (p *Provider) recordPath(key railgate.SlotKey) string {
	digest := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%d", key.QuoteCommitment, key.Actor, key.RequestID)))
	return filepath.Join(p.config.Directory, hex.EncodeToString(digest[:])+".json")
}

func (p *Provider) load(key railgate.SlotKey) (ProviderRecord, bool, error) {
	var record ProviderRecord
	err := readJSON(p.recordPath(key), 64<<10, &record)
	if errors.Is(err, os.ErrNotExist) {
		return ProviderRecord{}, false, nil
	}
	if err != nil || record.Schema != providerRecordSchema {
		return ProviderRecord{}, false, errors.New("servicebridge: invalid provider record")
	}
	return record, true, nil
}

func (p *Provider) store(key railgate.SlotKey, record ProviderRecord, create bool) error {
	record.Schema, record.UpdatedUnix = providerRecordSchema, p.config.Now().Unix()
	return writeJSON(p.recordPath(key), record, create)
}

// claimFor builds the railgate claim of a task and refuses work the quoted
// transport does not admit, before anything is admitted or executed. It
// runs the shared admission checks (SERVICE_ACTOR_RAIL_WORK_FRAMES_V1
// section 7.1 items 1 to 4), then requires the task's packets to name this
// Capability and the task's Accepted Quote (section 2.1) and its frames to
// carry the request hash and actor the task and its Quote derive (item 6
// against the derived request). Both happen before the gate claims a slot,
// so a task whose packets or frames are bound wrongly never consumes one.
func (p *Provider) claimFor(message Message) (railgate.Claim, *railwork.Admission, error) {
	admission, err := railwork.Provider{
		Network: p.config.Network, AgentID: p.config.AgentID,
		CapabilityID: p.config.CapabilityID, Version: p.config.Version,
	}.CheckTask(message.shared())
	if err != nil {
		return railgate.Claim{}, nil, err
	}
	if err = packetFieldsError(admission.CheckPacketFields(message.Packet.CapabilityID,
		message.Packet.QuoteCommitment)); err != nil {
		return railgate.Claim{}, nil, err
	}
	if !admission.FrameBindingMatchesQuote() {
		return railgate.Claim{}, nil, errors.New(
			"servicebridge: the task frames are bound to another request than the task and its Quote derive",
		)
	}
	header := admission.Task.Header
	claim := railgate.Claim{
		Package: admission.Package, BuyerWallet: header.BuyerWallet, ExecutionID: admission.ExecutionID,
		InputDigest: admission.InputDigest, RequestID: header.RequestID,
		Call: toschain.ActorTxID{LT: header.CallLT, Hash: header.CallHash},
	}
	return claim, admission, nil
}

// resultRetentionEnd is when result delivery stops. It runs from the end of
// the response window, not from admission, so a request that executes and
// finalizes its respond late still has the full retention interval left for
// delivery.
func resultRetentionEnd(responseDeadline, retentionSeconds uint64) (uint64, error) {
	if retentionSeconds == 0 {
		return 0, errors.New("servicebridge: the manifest retains no result")
	}
	end := responseDeadline + retentionSeconds
	if end < responseDeadline {
		return 0, errors.New("servicebridge: the result retention overflows")
	}
	return end, nil
}

// HandleTask runs one complete task message. It never executes a request
// twice, never attests a failed or unverifiable execution, and never
// responds outside the request's response window.
func (p *Provider) HandleTask(ctx context.Context, message Message) error {
	if p == nil || ctx == nil || message.Kind != FrameTask {
		return errors.New("servicebridge: invalid task handling")
	}
	p.mutex.Lock()
	defer p.mutex.Unlock()
	claim, admission, err := p.claimFor(message)
	if err != nil {
		return err
	}
	task := Task{Header: admission.Task.Header, Package: admission.Task.Package, Archive: admission.Task.Archive}
	pkg := admission.Package
	if pauseErr := p.admissionOpen(); pauseErr != nil {
		return pauseErr
	}
	if p.config.Service != nil {
		// Asked before the claim takes its slot. A task refused here is
		// reported as ErrExecutorNotReady, which the dispatcher holds
		// without counting a failed handling, so it is admitted once the
		// service can run it.
		if readyErr := p.config.Service.Ready(ctx); readyErr != nil {
			return fmt.Errorf("%w: %w", ErrExecutorNotReady, readyErr)
		}
	}
	slot, verified, err := p.config.Gate.Admit(ctx, claim)
	if errors.Is(err, railgate.ErrSlotTaken) {
		// The buyer resent the task: it is never executed again. A result
		// already attested is redelivered by the delivery loop, sealed to
		// the newest buyer card a resend brought.
		return p.learnBuyerCard(ctx, message, task)
	}
	if err != nil {
		return err
	}
	// The card is taken only from a task the gate admitted, so storing
	// cards costs a paid call. A card that is not taken is recorded and a
	// resend of the task can bring it again.
	cardErr := p.learnBuyerCard(ctx, message, task)
	if err = admission.CheckVerifiedBinding(verified.Actor, verified.RequestHash); err != nil {
		return err
	}
	key := slot.Key()
	retentionEnd, err := resultRetentionEnd(verified.ResponseDeadline, verified.Manifest.RetentionSeconds)
	if err != nil {
		return err
	}
	record := ProviderRecord{
		BuyerAgentID: task.Header.BuyerAgentID, CapabilityID: task.Header.CapabilityID,
		QuoteCommitment: verified.QuoteCommitment, Actor: verified.Actor, RequestID: verified.RequestID,
		RequestHash:      hex.EncodeToString(verified.RequestHash[:]),
		RetentionEndUnix: retentionEnd,
		ResponseDeadline: verified.ResponseDeadline, PackageBase64: base64.StdEncoding.EncodeToString(task.Package),
		BuyerWallet: claim.BuyerWallet, ExecutionID: hex.EncodeToString(claim.ExecutionID[:]),
		InputDigest: hex.EncodeToString(claim.InputDigest[:]), CallLT: claim.Call.LT, CallHash: claim.Call.Hash,
		PriceNanoTOS: verified.Price.String(),
	}
	if cardErr != nil {
		record.Detail = "the buyer's encryption key card was not taken: " + cardErr.Error()
	}
	binding := ReceiptBinding{
		QuoteCommitment: verified.QuoteCommitment, ExecutionID: verified.ExecutionID,
		InputDigest: verified.InputDigest, SourceDigest: task.Header.SourceDigest, Price: verified.Price,
		ProviderAgentID: verified.ProviderAgentID, ToolchainDigest: verified.Manifest.ToolchainDigest,
		SandboxDigest: pkg.GetProposal().GetManifestDigest(),
	}
	if p.config.Service != nil {
		record.SourceDigest, record.ToolchainDigest = task.Header.SourceDigest, verified.Manifest.ToolchainDigest
		record.SandboxDigest = pkg.GetProposal().GetManifestDigest()
		limits := verified.Manifest.Limits
		record.ExecutionLimits = &ExecutionLimits{
			CPUMillis: limits.CPUMillis, MemoryBytes: limits.MemoryBytes, ScratchBytes: limits.ScratchBytes,
			OutputBytes: limits.OutputBytes, WallClockMillis: limits.WallClockMillis,
		}
		return p.startService(ctx, key, record, task.Archive)
	}
	var outcome softwarework.Outcome
	runErr := p.config.Gate.Run(ctx, slot, claim, func(runCtx context.Context, _ *railgate.Verified) error {
		var executeErr error
		outcome, executeErr = p.config.Runner.Execute(runCtx, softwarework.Request{
			QuoteCommitment: verified.QuoteCommitment,
			ExecutionID:     sha256Text(verified.ExecutionID), InputDigest: sha256Text(verified.InputDigest),
			SourceDigest: task.Header.SourceDigest, SourceArchive: task.Archive,
		})
		return executeErr
	})
	if errors.Is(runErr, railgate.ErrNotPendingNow) {
		record.State = ProviderAbandoned
		return errors.Join(runErr, p.store(key, record, true))
	}
	if runErr != nil {
		record.State = ProviderFailed
		return errors.Join(runErr, p.config.Gate.Fail(key), p.store(key, record, true))
	}
	receipt, responseHash, err := BuildReceipt(binding, outcome)
	if err != nil {
		record.State = ProviderFailed
		return errors.Join(err, p.config.Gate.Fail(key), p.store(key, record, true))
	}
	boc := receipt.ToBOC()
	if _, err := CheckAttestable(boc, binding, outcome); err != nil {
		record.State = ProviderFailed
		return errors.Join(err, p.config.Gate.Fail(key), p.store(key, record, true))
	}
	if err := p.config.Gate.Complete(key, hex.EncodeToString(responseHash[:])); err != nil {
		return err
	}
	record.State, record.ResponseHash = ProviderExecuted, hex.EncodeToString(responseHash[:])
	record.ReceiptBOCBase64, record.ArtifactDigest = base64.StdEncoding.EncodeToString(boc), outcome.Artifact.Digest
	if err := p.store(key, record, true); err != nil {
		return err
	}
	if err := p.config.Gate.Recheck(ctx, slot, claim, verified); err != nil {
		// The record stays executed: the delivery loop repeats the check
		// while the window is open and responds once it passes, without
		// executing again. A request that left its window is never attested.
		return fmt.Errorf("servicebridge: not responding yet: %w", err)
	}
	record.State, record.RespondedAtUnix = ProviderResponding, p.config.Now().Unix()
	if err := p.store(key, record, false); err != nil {
		return err
	}
	if err := p.config.Lifecycle.Respond(
		ctx,
		verified.Actor,
		verified.RequestID,
		responseHash,
		p.config.AttestorController,
	); err != nil {
		// Ambiguous: the delivery loop reads finalized history for it.
		return err
	}
	return nil
}

// ResultRequestInterval bounds how often a buyer's result requests move a
// request's next delivery forward; requests in between only refresh the card.
const ResultRequestInterval = 10 * time.Minute

// ErrResultRequestRefused reports a result request this provider does not
// act on: from another Agent than the request's buyer, or for a request it
// has not responded to or no longer retains.
var ErrResultRequestRefused = errors.New("servicebridge: the result request is refused")

// HandleResultRequest takes a buyer's request to deliver a responded
// request's result again. It only refreshes the buyer's key card and moves
// the next delivery forward; it never admits, executes or responds.
func (p *Provider) HandleResultRequest(ctx context.Context, message Message) error {
	if p == nil || ctx == nil || message.Kind != FrameResultRequest {
		return errors.New("servicebridge: invalid result request handling")
	}
	request, err := DecodeResultRequest(message.Body)
	if err != nil {
		return err
	}
	p.mutex.Lock()
	defer p.mutex.Unlock()
	records, err := p.records()
	if err != nil {
		return err
	}
	now := p.config.Now()
	for path, record := range records {
		if record.Actor != "0:"+hex.EncodeToString(message.ActorAccount[:]) || record.RequestID != message.RequestID ||
			record.RequestHash != hex.EncodeToString(message.RequestHash[:]) {
			continue
		}
		if record.BuyerAgentID != message.SenderAgentID {
			return fmt.Errorf("%w: it is not from this request's buyer", ErrResultRequestRefused)
		}
		if err := checkPacketFields(message, record.CapabilityID, record.QuoteCommitment); err != nil {
			return fmt.Errorf("%w: %w", ErrResultRequestRefused, err)
		}
		switch record.State {
		case ProviderResponding, ProviderDelivering:
		case ProviderAcked:
			// The buyer already acknowledged this result; nothing to do.
			return nil
		default:
			return fmt.Errorf("%w: the request has no response to deliver", ErrResultRequestRefused)
		}
		if uint64(now.Unix()) >= record.RetentionEndUnix {
			return fmt.Errorf("%w: the result is no longer retained", ErrResultRequestRefused)
		}
		changed := false
		if cardErr := p.learnCard(ctx, message.SenderAgentID, request.BuyerKeyCard); cardErr != nil {
			if !errors.Is(cardErr, ErrCardRefused) {
				return cardErr
			}
			record.Detail, changed = "the buyer's encryption key card was not taken: "+cardErr.Error(), true
		}
		if record.State == ProviderDelivering && record.NextDeliveryUnix > now.Unix() &&
			now.Unix()-record.ResultRequestUnix >= int64(ResultRequestInterval/time.Second) {
			record.NextDeliveryUnix, record.ResultRequestUnix, changed = now.Unix(), now.Unix(), true
		}
		if changed {
			record.Schema, record.UpdatedUnix = providerRecordSchema, now.Unix()
			return writeJSON(path, record, false)
		}
		return nil
	}
	return fmt.Errorf("%w: it names no request of this provider", ErrResultRequestRefused)
}

// learnBuyerCard verifies the buyer's key card a task carries against
// finalized state and keeps it. The card must be of the Agent that signed
// the task packets, which claimFor already required to be the buyer.
func (p *Provider) learnBuyerCard(ctx context.Context, message Message, task Task) error {
	return p.learnCard(ctx, message.SenderAgentID, task.Header.BuyerKeyCard)
}

// learnCard verifies a buyer's key card, standard base64 of its packet
// JSON, against finalized state and keeps it when its Agent is sender.
func (p *Provider) learnCard(ctx context.Context, sender, encoded string) error {
	if encoded == "" || p.config.Cards == nil {
		return nil
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("%w: the buyer key card does not decode", ErrCardRefused)
	}
	return p.config.Cards.Learn(ctx, raw, sender, "")
}

// admissionOpen refuses new admission while the owner's pause marker exists.
// An unreadable marker counts as paused: the owner asked for a stop and an
// unreadable answer is not permission to start work.
func (p *Provider) admissionOpen() error {
	if p.config.StateDir == "" {
		return nil
	}
	pause, err := ReadAdmissionPause(p.config.StateDir)
	if err != nil {
		return errors.Join(ErrAdmissionPaused, err)
	}
	if pause != nil {
		return ErrAdmissionPaused
	}
	return nil
}

// respondFinalized reports whether finalized history holds this provider's
// respond for the request with the response hash.
func (p *Provider) respondFinalized(ctx context.Context, record ProviderRecord) (bool, error) {
	session, err := p.config.History.BeginSession(ctx)
	if err != nil {
		return false, err
	}
	history, err := session.History(ctx, record.Actor, nil)
	if err != nil {
		return false, err
	}
	if history.Result != toschain.HistoryComplete {
		return false, errors.New("servicebridge: the actor history is not complete")
	}
	for _, transaction := range history.Transactions {
		if transaction.Kind == toschain.ActorTxRespond && transaction.RequestID == record.RequestID {
			if transaction.ResponseHash != record.ResponseHash {
				return false, errors.New("servicebridge: the request was answered with another response hash")
			}
			return true, nil
		}
	}
	return false, nil
}

// HandleAck records a buyer's acknowledgement of a delivered result.
func (p *Provider) HandleAck(ctx context.Context, message Message) error {
	if p == nil || ctx == nil || message.Kind != FrameResultAck {
		return errors.New("servicebridge: invalid acknowledgement handling")
	}
	ack, err := DecodeAck(message.Body)
	if err != nil {
		return err
	}
	p.mutex.Lock()
	defer p.mutex.Unlock()
	records, err := p.records()
	if err != nil {
		return err
	}
	for path, record := range records {
		if record.Actor == "0:"+hex.EncodeToString(message.ActorAccount[:]) && record.RequestID == message.RequestID &&
			record.RequestHash == hex.EncodeToString(message.RequestHash[:]) {
			if record.BuyerAgentID != message.SenderAgentID || record.ResponseHash != ack.ResponseHash {
				return errors.New("servicebridge: the acknowledgement is not from this request's buyer for its result")
			}
			if err := checkPacketFields(message, record.CapabilityID, record.QuoteCommitment); err != nil {
				return err
			}
			// The acknowledgement is tied to this request's buyer and result,
			// so its card refreshes the buyer's card in band. A card finalized
			// state refuses is noted; one it cannot check now is retried.
			changed := false
			if cardErr := p.learnCard(ctx, message.SenderAgentID, ack.BuyerKeyCard); cardErr != nil {
				if !errors.Is(cardErr, ErrCardRefused) {
					return cardErr
				}
				record.Detail, changed = "the buyer's encryption key card was not taken: "+cardErr.Error(), true
			}
			if record.State == ProviderDelivering {
				record.State, changed = ProviderAcked, true
			}
			if changed {
				record.Schema, record.UpdatedUnix = providerRecordSchema, p.config.Now().Unix()
				return writeJSON(path, record, false)
			}
			return nil
		}
	}
	return errors.New("servicebridge: the acknowledgement names no delivered request")
}

func (p *Provider) records() (map[string]ProviderRecord, error) {
	entries, err := os.ReadDir(p.config.Directory)
	if err != nil {
		return nil, errors.New("servicebridge: read provider records")
	}
	out := map[string]ProviderRecord{}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(p.config.Directory, entry.Name())
		var record ProviderRecord
		if err := readJSON(path, 64<<10, &record); err != nil || record.Schema != providerRecordSchema {
			return nil, errors.New("servicebridge: invalid provider record")
		}
		out[path] = record
	}
	return out, nil
}

// Records lists the provider's requests, newest first.
func (p *Provider) Records() ([]ProviderRecord, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	records, err := p.records()
	if err != nil {
		return nil, err
	}
	out := make([]ProviderRecord, 0, len(records))
	for _, record := range records {
		out = append(out, record)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedUnix > out[j].UpdatedUnix })
	return out, nil
}

// Tick advances delivery: it confirms finalized responds, delivers results
// in fresh generations with capped backoff until acknowledged or retention
// ends, and retries journaled packets.
func (p *Provider) Tick(ctx context.Context) error {
	if p == nil || ctx == nil {
		return errors.New("servicebridge: invalid provider tick")
	}
	p.mutex.Lock()
	defer p.mutex.Unlock()
	records, err := p.records()
	if err != nil {
		return err
	}
	now := p.config.Now()
	var failures []error
	for path, record := range records {
		switch record.State {
		case ProviderExecuting:
			if p.config.Service == nil {
				failures = append(failures, errors.New(
					"servicebridge: a request is executing but this node has no executor service",
				))
			} else if err := p.advanceExecuting(ctx, path, record); err != nil {
				failures = append(failures, err)
			}
			continue
		case ProviderExecuted:
			if err := p.resumeExecuted(ctx, path, record, now); err != nil {
				failures = append(failures, err)
			}
			continue
		case ProviderResponding:
			done, err := p.respondFinalized(ctx, record)
			if err != nil {
				failures = append(failures, err)
				continue
			}
			if !done {
				// A respond whose send was ambiguous is sent again, with the
				// same attested response hash, while the window is open;
				// the contract refuses it once the request is no longer
				// pending.
				if uint64(now.Unix()) < record.ResponseDeadline &&
					now.Unix()-record.RespondedAtUnix >= int64(FirstRedelivery/time.Second) {
					var responseHash [32]byte
					if err := decodeHex32(record.ResponseHash, &responseHash); err != nil {
						failures = append(failures, err)
						continue
					}
					record.RespondedAtUnix = now.Unix()
					// The attestor is invoked again only after the same fresh
					// railgate check as the first respond: still pending,
					// unchanged, with the configured respond budget ahead.
					if err := p.recheck(ctx, record); err != nil {
						failures = append(failures, err)
					} else if err := p.config.Lifecycle.Respond(ctx, record.Actor, record.RequestID, responseHash,
						p.config.AttestorController); err != nil {
						failures = append(failures, err)
					}
					record.Schema, record.UpdatedUnix = providerRecordSchema, now.Unix()
					if err := writeJSON(path, record, false); err != nil {
						failures = append(failures, err)
					}
				}
				continue
			}
			record.State, record.NextDeliveryUnix, record.BackoffSeconds = ProviderDelivering, now.Unix(), 0
		case ProviderDelivering:
		default:
			continue
		}
		if uint64(now.Unix()) >= record.RetentionEndUnix {
			record.State = ProviderExpired
		} else if now.Unix() >= record.NextDeliveryUnix {
			if err := p.deliver(ctx, record); err != nil && !errors.Is(err, ErrGenerationExpired) {
				failures = append(failures, err)
			}
			record.Deliveries++
			backoff := time.Duration(record.BackoffSeconds) * time.Second * 2
			if backoff < FirstRedelivery {
				backoff = FirstRedelivery
			}
			if backoff > MaxRedelivery {
				backoff = MaxRedelivery
			}
			record.BackoffSeconds, record.NextDeliveryUnix = int64(backoff/time.Second), now.Add(backoff).Unix()
		}
		record.Schema, record.UpdatedUnix = providerRecordSchema, now.Unix()
		if err := writeJSON(path, record, false); err != nil {
			failures = append(failures, err)
		}
	}
	if err := p.config.Courier.Resume(ctx); err != nil && !errors.Is(err, ErrGenerationExpired) {
		failures = append(failures, err)
	}
	if err := p.sweepObjects(ctx, now); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}

// resumeExecuted advances work that ran and was attested locally but whose
// pre-respond check did not pass, for example during an RPC outage. The check
// is repeated while the response window is open; once it passes the record
// moves to responding before the respond is sent, so an ambiguous send is
// retried by the responding path. The work is never executed again.
func (p *Provider) resumeExecuted(ctx context.Context, path string, record ProviderRecord, now time.Time) error {
	if uint64(now.Unix()) >= record.ResponseDeadline {
		record.State = ProviderAbandoned
		record.Schema, record.UpdatedUnix = providerRecordSchema, now.Unix()
		return writeJSON(path, record, false)
	}
	var responseHash [32]byte
	if err := decodeHex32(record.ResponseHash, &responseHash); err != nil {
		return err
	}
	if err := p.recheck(ctx, record); err != nil {
		return fmt.Errorf("servicebridge: not responding yet: %w", err)
	}
	record.State, record.RespondedAtUnix = ProviderResponding, now.Unix()
	record.Schema, record.UpdatedUnix = providerRecordSchema, now.Unix()
	if err := writeJSON(path, record, false); err != nil {
		return err
	}
	// Ambiguous: the responding path reads finalized history for it.
	return p.config.Lifecycle.Respond(ctx, record.Actor, record.RequestID, responseHash, p.config.AttestorController)
}

func (p *Provider) deliver(ctx context.Context, record ProviderRecord) error {
	artifact, err := p.config.Store.Get(ctx, record.ArtifactDigest)
	if err != nil {
		return err
	}
	receipt, err := base64.StdEncoding.Strict().DecodeString(record.ReceiptBOCBase64)
	if err != nil {
		return errors.New("servicebridge: invalid stored Receipt")
	}
	var responseHash, requestHash, actor [32]byte
	if err = decodeHex32(record.ResponseHash, &responseHash); err != nil {
		return err
	}
	if err = decodeHex32(record.RequestHash, &requestHash); err != nil {
		return err
	}
	if err = decodeHex32(record.Actor[2:], &actor); err != nil {
		return err
	}
	var card []byte
	if p.config.RelayKeys != nil {
		// The card covers the redelivery window, so the buyer can still
		// acknowledge a result delivered near its end.
		key, keyErr := p.config.RelayKeys.Current(ctx, record.RetentionEndUnix)
		if keyErr != nil {
			return keyErr
		}
		card = key.CardJSON
	}
	body, err := EncodeResultWithCard(responseHash, receipt, artifact, card)
	if err != nil {
		return err
	}
	_, err = p.config.Courier.Deliver(ctx, Envelope{
		RecipientAgentID: record.BuyerAgentID, CapabilityID: record.CapabilityID,
		QuoteCommitment: record.QuoteCommitment, Kind: FrameResult, ActorAccount: actor, RequestID: record.RequestID,
		RequestHash: requestHash, NotAfterUnix: record.RetentionEndUnix,
	}, body)
	return err
}

func decodeHex32(text string, out *[32]byte) error {
	raw, err := hex.DecodeString(text)
	if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != text {
		return errors.New("servicebridge: invalid 32-byte hex value")
	}
	copy(out[:], raw)
	return nil
}

// claimOf rebuilds the claim of a record and the verified values a fresh
// check must reproduce.
func claimOf(record ProviderRecord) (railgate.Claim, *railgate.Verified, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(record.PackageBase64)
	if err != nil || len(raw) == 0 {
		return railgate.Claim{}, nil, errors.New("servicebridge: the record holds no Quote package to recheck")
	}
	pkg := &nativev1.QuoteProposalPackageV1{}
	if err = proto.Unmarshal(raw, pkg); err != nil {
		return railgate.Claim{}, nil, errors.New("servicebridge: the recorded Quote package does not decode")
	}
	claim := railgate.Claim{
		Package: pkg, BuyerWallet: record.BuyerWallet, RequestID: record.RequestID,
		Call: toschain.ActorTxID{LT: record.CallLT, Hash: record.CallHash},
	}
	if err = decodeHex32(record.ExecutionID, &claim.ExecutionID); err != nil {
		return railgate.Claim{}, nil, err
	}
	if err = decodeHex32(record.InputDigest, &claim.InputDigest); err != nil {
		return railgate.Claim{}, nil, err
	}
	expected := &railgate.Verified{
		Actor: record.Actor, RequestID: record.RequestID, QuoteCommitment: record.QuoteCommitment,
		ResponseDeadline: record.ResponseDeadline,
	}
	if err = decodeHex32(record.RequestHash, &expected.RequestHash); err != nil {
		return railgate.Claim{}, nil, err
	}
	price, ok := new(big.Int).SetString(record.PriceNanoTOS, 10)
	if !ok || price.Sign() <= 0 {
		return railgate.Claim{}, nil, errors.New("servicebridge: the record holds no request price")
	}
	expected.Price = price
	return claim, expected, nil
}

// recheck rebuilds a record's claim and runs the gate's pre-respond check.
func (p *Provider) recheck(ctx context.Context, record ProviderRecord) error {
	claim, expected, err := claimOf(record)
	if err != nil {
		return err
	}
	checker := p.preRespond()
	if checker == nil {
		return errors.New("servicebridge: no gate to recheck the request with")
	}
	slot, found, err := checker.Lookup(expected.SlotKey())
	if err != nil {
		return err
	}
	if !found {
		return errors.New("servicebridge: the request has no execution slot")
	}
	return checker.Recheck(ctx, slot, claim, expected)
}
