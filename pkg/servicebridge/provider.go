package servicebridge

import (
	"bytes"
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

	"github.com/tosnetwork/tos-ai/pkg/railgate"
	"github.com/tosnetwork/tos-ai/pkg/softwarework"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/quoteexchange"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
	"google.golang.org/protobuf/proto"
)

// Provider request states.
const (
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
	PackageBase64    string `json:"package_base64,omitempty"`
	BuyerWallet      string `json:"buyer_wallet,omitempty"`
	ExecutionID      string `json:"execution_id,omitempty"`
	InputDigest      string `json:"input_digest,omitempty"`
	CallLT           uint64 `json:"call_lt,omitempty"`
	CallHash         string `json:"call_hash,omitempty"`
	PriceNanoTOS     string `json:"price_nanotos,omitempty"`
	NextDeliveryUnix int64  `json:"next_delivery_unix,omitempty"`
	BackoffSeconds   int64  `json:"backoff_seconds,omitempty"`
	Deliveries       int    `json:"deliveries"`
	UpdatedUnix      int64  `json:"updated_unix"`
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

// ProviderConfig wires a provider worker.
type ProviderConfig struct {
	AgentID            string
	CapabilityID       string
	Version            string
	Network            *nativev1.NetworkDomain
	Gate               *railgate.Gate
	Runner             WorkRunner
	Store              ArtifactSource
	Lifecycle          LifecycleSender
	AttestorController string
	Courier            *Courier
	History            railgate.Reader
	Directory          string
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
	checker preRespondChecker
	mutex   sync.Mutex
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
		config.Runner == nil ||
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
// transport does not admit, before anything is admitted or executed.
func (p *Provider) claimFor(
	message Message,
	task Task,
) (railgate.Claim, *nativev1.QuoteProposalPackageV1, nativecore.TransportBindingV1, error) {
	var none nativecore.TransportBindingV1
	if message.SenderAgentID != task.Header.BuyerAgentID {
		return railgate.Claim{}, nil, none, errors.New(
			"servicebridge: the task comes from another Agent than its buyer",
		)
	}
	if message.RequestID != task.Header.RequestID {
		return railgate.Claim{}, nil, none, errors.New("servicebridge: the task frames name another request")
	}
	pkg := &nativev1.QuoteProposalPackageV1{}
	if err := proto.Unmarshal(task.Package, pkg); err != nil || pkg.GetProposal() == nil {
		return railgate.Claim{}, nil, none, errors.New("servicebridge: the task Quote package does not decode")
	}
	validated, err := quoteexchange.ValidatePortable(p.config.Network, &nativev1.RequestQuoteProposalRequest{
		CapabilityId:      task.Header.CapabilityID,
		CapabilityVersion: task.Header.CapabilityVersion,
		BuyerAddress:      task.Header.BuyerWallet,
	}, pkg)
	if err != nil {
		return railgate.Claim{}, nil, none, err
	}
	recipient, err := validated.TransportBinding.AgentPacketRecipient()
	if err != nil || recipient != p.config.AgentID {
		return railgate.Claim{}, nil, none, errors.New(
			"servicebridge: the Quote does not deliver work to this Agent as Agent Packets",
		)
	}
	if uint64(len(task.Archive)) > uint64(validated.TransportBinding.MaxRequestBytes) ||
		len(task.Archive) > MaxInlineInputBytes {
		return railgate.Claim{}, nil, none, errors.New(
			"servicebridge: the source archive exceeds the quoted inline input bound",
		)
	}
	executionID, err := hex.DecodeString(task.Header.ExecutionID)
	if err != nil || len(executionID) != 32 {
		return railgate.Claim{}, nil, none, errors.New("servicebridge: invalid execution id")
	}
	// The paid call carries the execution id, so this ties the Agent the
	// result returns to, which signed the frames, to the paying wallet.
	var executionNonce [32]byte
	if err = decodeHex32(task.Header.ExecutionNonce, &executionNonce); err != nil {
		return railgate.Claim{}, nil, none, errors.New("servicebridge: invalid execution nonce")
	}
	committed := ExecutionIDFor(task.Header.BuyerAgentID, executionNonce)
	if !bytes.Equal(committed[:], executionID) {
		return railgate.Claim{}, nil, none, errors.New(
			"servicebridge: the paid execution id does not commit to the task's buyer Agent",
		)
	}
	sourceDigest := sha256.Sum256(task.Archive)
	claim := railgate.Claim{
		Package: pkg, BuyerWallet: task.Header.BuyerWallet, InputDigest: InputDigest(sourceDigest),
		RequestID: task.Header.RequestID, Call: toschain.ActorTxID{LT: task.Header.CallLT, Hash: task.Header.CallHash},
	}
	copy(claim.ExecutionID[:], executionID)
	return claim, pkg, validated.TransportBinding, nil
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
	task, err := DecodeTask(message.Body)
	if err != nil {
		return err
	}
	claim, pkg, _, err := p.claimFor(message, task)
	if err != nil {
		return err
	}
	if pauseErr := p.admissionOpen(); pauseErr != nil {
		return pauseErr
	}
	slot, verified, err := p.config.Gate.Admit(ctx, claim)
	if errors.Is(err, railgate.ErrSlotTaken) {
		// The buyer resent the task: it is never executed again. A result
		// already attested is redelivered by the delivery loop.
		return nil
	}
	if err != nil {
		return err
	}
	if verified.RequestHash != message.RequestHash ||
		verified.Actor != "0:"+hex.EncodeToString(message.ActorAccount[:]) {
		return errors.New("servicebridge: the task frames are bound to another request than the verified one")
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
	binding := ReceiptBinding{
		QuoteCommitment: verified.QuoteCommitment, ExecutionID: verified.ExecutionID,
		InputDigest: verified.InputDigest, SourceDigest: task.Header.SourceDigest, Price: verified.Price,
		ProviderAgentID: verified.ProviderAgentID, ToolchainDigest: verified.Manifest.ToolchainDigest,
		SandboxDigest: pkg.GetProposal().GetManifestDigest(),
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
func (p *Provider) HandleAck(message Message) error {
	if p == nil || message.Kind != FrameResultAck {
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
			if record.State == ProviderDelivering {
				record.State = ProviderAcked
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
	body, err := EncodeResult(responseHash, receipt, artifact)
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

// recheck rebuilds a record's claim and runs the gate's pre-respond check.
func (p *Provider) recheck(ctx context.Context, record ProviderRecord) error {
	raw, err := base64.StdEncoding.Strict().DecodeString(record.PackageBase64)
	if err != nil || len(raw) == 0 {
		return errors.New("servicebridge: the record holds no Quote package to recheck")
	}
	pkg := &nativev1.QuoteProposalPackageV1{}
	if err = proto.Unmarshal(raw, pkg); err != nil {
		return errors.New("servicebridge: the recorded Quote package does not decode")
	}
	claim := railgate.Claim{
		Package: pkg, BuyerWallet: record.BuyerWallet, RequestID: record.RequestID,
		Call: toschain.ActorTxID{LT: record.CallLT, Hash: record.CallHash},
	}
	if err = decodeHex32(record.ExecutionID, &claim.ExecutionID); err != nil {
		return err
	}
	if err = decodeHex32(record.InputDigest, &claim.InputDigest); err != nil {
		return err
	}
	expected := &railgate.Verified{
		Actor: record.Actor, RequestID: record.RequestID, QuoteCommitment: record.QuoteCommitment,
		ResponseDeadline: record.ResponseDeadline,
	}
	if err = decodeHex32(record.RequestHash, &expected.RequestHash); err != nil {
		return err
	}
	price, ok := new(big.Int).SetString(record.PriceNanoTOS, 10)
	if !ok || price.Sign() <= 0 {
		return errors.New("servicebridge: the record holds no request price")
	}
	expected.Price = price
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
