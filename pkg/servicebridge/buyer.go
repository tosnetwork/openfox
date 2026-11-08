package servicebridge

import (
	"context"
	"crypto/rand"
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

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/buyersdk"
	"github.com/tosnetwork/tos-service-protocol/pkg/quoteexchange"
	"github.com/tosnetwork/tos-service-protocol/pkg/serviceactor"
)

// Purchase phases. Terminal phases are final.
const (
	PurchaseCalled          = "called"
	PurchaseNotCalled       = "not-called"
	PurchaseTaskSent        = "task-sent"
	PurchaseCompleted       = "completed"
	PurchaseReceiptMismatch = "receipt-mismatch"
	PurchaseExpireSent      = "expire-sent"
	PurchaseClaimSent       = "claim-sent"
	PurchaseRefunded        = "refunded"
	PurchaseLapsed          = "lapsed"
	PurchaseSwept           = "swept"
	PurchaseRefused         = "refused"
)

const purchaseRecordSchema = "tos.openfox.rail-purchase.v1"

func terminalPurchase(phase string) bool {
	switch phase {
	case PurchaseCompleted,
		PurchaseReceiptMismatch,
		PurchaseRefunded,
		PurchaseLapsed,
		PurchaseSwept,
		PurchaseRefused,
		PurchaseNotCalled:
		return true
	}
	return false
}

// PurchaseRecord is the buyer's durable view of one purchase.
type PurchaseRecord struct {
	Schema            string  `json:"schema"`
	Phase             string  `json:"phase"`
	RequestHash       string  `json:"request_hash"`
	Actor             string  `json:"actor"`
	RequestID         *uint64 `json:"request_id,omitempty"`
	CallLT            uint64  `json:"call_lt,omitempty"`
	CallHash          string  `json:"call_hash,omitempty"`
	CapabilityID      string  `json:"capability_id"`
	CapabilityVersion string  `json:"capability_version"`
	ProviderAgentID   string  `json:"provider_agent_id"`
	QuoteCommitment   string  `json:"quote_commitment"`
	ExecutionID       string  `json:"execution_id"`
	InputDigest       string  `json:"input_digest"`
	SourceDigest      string  `json:"source_digest"`
	PriceNanoTOS      string  `json:"price_nanotos"`
	CommittedNanoTOS  string  `json:"committed_nanotos"`
	ToolchainDigest   string  `json:"toolchain_digest"`
	ManifestDigest    string  `json:"manifest_digest"`
	Status            string  `json:"status,omitempty"`
	RequiredAction    string  `json:"required_action,omitempty"`
	ResponseDeadline  uint64  `json:"response_deadline,omitempty"`
	RefundDeadline    uint64  `json:"refund_claim_deadline,omitempty"`
	ResponseHash      string  `json:"response_hash,omitempty"`
	Disclosure        string  `json:"cost_disclosure"`
	LastActionUnix    int64   `json:"last_action_unix,omitempty"`
	Failure           string  `json:"failure,omitempty"`
	CreatedUnix       int64   `json:"created_unix"`
	UpdatedUnix       int64   `json:"updated_unix"`
}

// QuoteSource fetches a non-canonical Quote Proposal package.
type QuoteSource interface {
	Quote(ctx context.Context, request *nativev1.RequestQuoteProposalRequest) (*nativev1.QuoteProposalPackageV1, error)
}

// Confirmer asks the owner to confirm one purchase after showing its costs.
type Confirmer func(ctx context.Context, costs Costs) error

// BuyerConfig wires a buyer.
type BuyerConfig struct {
	AgentID string
	Wallet  string
	Network *nativev1.NetworkDomain
	Buyer   *buyersdk.ServiceActorBuyer
	Quotes  QuoteSource
	Policy  SpendingPolicy
	Confirm Confirmer
	// Disclose is shown every purchase's costs before the call, whether or
	// not the policy routes it to the owner.
	Disclose  func(Costs)
	Courier   *Courier
	Lifecycle LifecycleSender
	Directory string
	Now       func() time.Time
	Random    func([]byte) error
}

// Buyer runs discovery-started purchases and their result and refund duties.
type Buyer struct {
	config BuyerConfig
	mutex  sync.Mutex
}

// NewBuyer refuses an incomplete configuration.
func NewBuyer(config BuyerConfig) (*Buyer, error) {
	if !agentIDPattern.MatchString(config.AgentID) ||
		!rawAddressPattern.MatchString(config.Wallet) ||
		config.Network == nil ||
		config.Buyer == nil ||
		config.Quotes == nil ||
		config.Courier == nil ||
		config.Lifecycle == nil ||
		!filepath.IsAbs(config.Directory) ||
		config.Policy.Validate() != nil {
		return nil, errors.New("servicebridge: invalid buyer configuration")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Random == nil {
		config.Random = func(value []byte) error { _, err := rand.Read(value); return err }
	}
	if err := ensurePrivateDirectory(config.Directory); err != nil {
		return nil, err
	}
	return &Buyer{config: config}, nil
}

// ErrInputTooLarge reports input over the quoted inline bound; nothing was
// reserved or paid.
var ErrInputTooLarge = errors.New(
	"servicebridge: the input exceeds the advertised 1 MiB inline limit; nothing was reserved or paid",
)

// CheckPurchaseQuote refuses a Quote that does not deliver work to its
// provider as Agent Packets, and input over the quoted inline bound, before
// anything is reserved or paid.
func CheckPurchaseQuote(validated *quoteexchange.Validated, archiveBytes int) error {
	if validated == nil || validated.Proposal == nil {
		return errors.New("servicebridge: no validated Quote")
	}
	// Validation already bound a mode-2 recipient to the Quote's provider.
	if _, err := validated.TransportBinding.AgentPacketRecipient(); err != nil {
		return errors.New("servicebridge: the Quote does not deliver work to its provider as Agent Packets")
	}
	if archiveBytes <= 0 || archiveBytes > MaxInlineInputBytes ||
		uint64(archiveBytes) > uint64(validated.TransportBinding.MaxRequestBytes) {
		return ErrInputTooLarge
	}
	return nil
}

func (b *Buyer) purchaseDir(requestHash string) string {
	return filepath.Join(b.config.Directory, requestHash)
}

func (b *Buyer) loadPurchase(requestHash string) (PurchaseRecord, error) {
	var record PurchaseRecord
	if !hex64Pattern.MatchString(requestHash) {
		return record, errors.New("servicebridge: invalid request hash")
	}
	if err := readJSON(filepath.Join(b.purchaseDir(requestHash), "record.json"), 64<<10, &record); err != nil {
		return record, err
	}
	if record.Schema != purchaseRecordSchema || record.RequestHash != requestHash {
		return record, errors.New("servicebridge: invalid purchase record")
	}
	return record, nil
}

func (b *Buyer) savePurchase(record PurchaseRecord, create bool) error {
	record.Schema, record.UpdatedUnix = purchaseRecordSchema, b.config.Now().Unix()
	return writeJSON(filepath.Join(b.purchaseDir(record.RequestHash), "record.json"), record, create)
}

// Purchases lists every purchase, newest first.
func (b *Buyer) Purchases() ([]PurchaseRecord, error) {
	entries, err := os.ReadDir(b.config.Directory)
	if err != nil {
		return nil, errors.New("servicebridge: read purchases")
	}
	var out []PurchaseRecord
	for _, entry := range entries {
		if !hex64Pattern.MatchString(entry.Name()) {
			continue
		}
		if err := checkPrivateDirectory(filepath.Join(b.config.Directory, entry.Name())); err != nil {
			return nil, err
		}
		record, err := b.loadPurchase(entry.Name())
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedUnix > out[j].CreatedUnix })
	return out, nil
}

func (b *Buyer) accounting(now time.Time) (*big.Int, int, error) {
	records, err := b.Purchases()
	if err != nil {
		return nil, 0, err
	}
	committed, open := new(big.Int), 0
	for _, record := range records {
		if !terminalPurchase(record.Phase) {
			open++
		}
		if now.Sub(time.Unix(record.CreatedUnix, 0)) < b.config.Policy.Window && record.Phase != PurchaseNotCalled {
			value, ok := new(big.Int).SetString(record.CommittedNanoTOS, 10)
			if !ok {
				return nil, 0, errors.New("servicebridge: invalid purchase accounting")
			}
			committed.Add(committed, value)
		}
	}
	return committed, open, nil
}

// Buy starts a purchase from a published Capability: discover and verify
// the offer, take and validate a Quote, refuse input over the quoted inline
// bound, show the costs and apply the owner policy, prepare, and call. The
// archive is kept to deliver once the call is admitted.
func (b *Buyer) Buy(ctx context.Context, capabilityID, version string, archive []byte) (PurchaseRecord, error) {
	if b == nil || ctx == nil || !capabilityPattern.MatchString(capabilityID) || version == "" {
		return PurchaseRecord{}, errors.New("servicebridge: invalid purchase")
	}
	if len(archive) == 0 || len(archive) > MaxInlineInputBytes {
		return PurchaseRecord{}, ErrInputTooLarge
	}
	b.mutex.Lock()
	defer b.mutex.Unlock()
	// The Quote comes first only so its manifest bytes are at hand;
	// discovery then verifies the offer at a finalized checkpoint, checking
	// those bytes against the finalized manifest digest.
	request := &nativev1.RequestQuoteProposalRequest{
		CapabilityId:      capabilityID,
		CapabilityVersion: version,
		BuyerAddress:      b.config.Wallet,
	}
	pkg, err := b.config.Quotes.Quote(ctx, request)
	if err != nil {
		return PurchaseRecord{}, fmt.Errorf("servicebridge: quote: %w", err)
	}
	offer, err := b.config.Buyer.Discover(ctx, capabilityID, version)
	if err != nil {
		return PurchaseRecord{}, fmt.Errorf("servicebridge: discovery: %w", err)
	}
	now := b.config.Now()
	validated, err := quoteexchange.Validate(b.config.Network, request, pkg, now)
	if err != nil {
		return PurchaseRecord{}, err
	}
	if offer == nil {
		return PurchaseRecord{}, errors.New("servicebridge: discovery returned no offer")
	}
	if err = CheckPurchaseQuote(validated, len(archive)); err != nil {
		return PurchaseRecord{}, err
	}
	provider := validated.Proposal.GetProviderAgentId()
	if offer.ProviderAgentID != provider || offer.TermsHash != hex.EncodeToString(validated.Rail.TermsHash[:]) {
		return PurchaseRecord{}, errors.New("servicebridge: the Quote differs from the finalized offer")
	}
	costs, err := QuoteCosts(
		validated.Rail.Price,
		validated.Rail.StorageFee,
		offer.ResponseSLASeconds,
		offer.RefundWindowSeconds,
		b.config.Policy.RefundReserve,
	)
	if err != nil {
		return PurchaseRecord{}, err
	}
	if err = b.authorize(ctx, provider, costs); err != nil {
		return PurchaseRecord{}, err
	}
	var executionID [32]byte
	if err = b.config.Random(executionID[:]); err != nil || executionID == ([32]byte{}) {
		return PurchaseRecord{}, errors.New("servicebridge: draw execution id")
	}
	sourceDigest := sha256.Sum256(archive)
	inputDigest := InputDigest(sourceDigest)
	call, err := b.config.Buyer.Prepare(ctx, request, pkg, executionID, inputDigest)
	if err != nil {
		return PurchaseRecord{}, err
	}
	record := PurchaseRecord{
		Phase:             PurchaseCalled,
		RequestHash:       call.RequestHash,
		Actor:             call.Actor,
		CapabilityID:      capabilityID,
		CapabilityVersion: version,
		ProviderAgentID:   provider,
		QuoteCommitment:   call.QuoteCommitment,
		ExecutionID:       hex.EncodeToString(executionID[:]),
		InputDigest:       hex.EncodeToString(inputDigest[:]),
		SourceDigest: sha256Text(
			sourceDigest,
		),
		PriceNanoTOS:     costs.Price.String(),
		CommittedNanoTOS: costs.Committed.String(),
		ToolchainDigest:  validated.Manifest.ToolchainDigest,
		ManifestDigest:   validated.Proposal.GetManifestDigest(),
		Disclosure:       costs.Disclosure(),
		CreatedUnix:      now.Unix(),
	}
	if err = ensurePrivateDirectory(b.purchaseDir(call.RequestHash)); err != nil {
		return PurchaseRecord{}, err
	}
	if err = writeSynced(filepath.Join(b.purchaseDir(call.RequestHash), "source"), archive); err != nil {
		return PurchaseRecord{}, err
	}
	packageBytes, err := base64.StdEncoding.Strict().DecodeString(call.PackageBase64)
	if err != nil {
		return PurchaseRecord{}, errors.New("servicebridge: the journaled Quote package does not decode")
	}
	if err = writeSynced(filepath.Join(b.purchaseDir(call.RequestHash), "quote-package"), packageBytes); err != nil {
		return PurchaseRecord{}, err
	}
	if err = b.savePurchase(record, true); err != nil {
		return PurchaseRecord{}, err
	}
	// The policy is applied again at the send instant.
	if err = b.authorizeAgain(provider, costs, call.RequestHash); err != nil {
		record.Phase, record.Failure = PurchaseNotCalled, err.Error()
		return record, errors.Join(err, b.savePurchase(record, false))
	}
	called, err := b.config.Buyer.Call(ctx, call.RequestHash)
	if called.Phase == buyersdk.PhasePrepared {
		record.Phase, record.Failure = PurchaseNotCalled, fmt.Sprint(err)
		return record, errors.Join(err, b.savePurchase(record, false))
	}
	if err != nil {
		record.Failure = err.Error()
	}
	return record, errors.Join(err, b.savePurchase(record, false))
}

func (b *Buyer) authorize(ctx context.Context, provider string, costs Costs) error {
	committed, open, err := b.accounting(b.config.Now())
	if err != nil {
		return err
	}
	err = b.config.Policy.Authorize(provider, costs, committed, open)
	if (err == nil || errors.Is(err, ErrNeedsConfirmation)) && b.config.Disclose != nil {
		b.config.Disclose(costs)
	}
	if errors.Is(err, ErrNeedsConfirmation) {
		if b.config.Confirm == nil {
			return err
		}
		return b.config.Confirm(ctx, costs)
	}
	return err
}

// authorizeAgain re-applies the hard bounds with the just-created record
// excluded, so a concurrent change to the policy or journal is caught.
func (b *Buyer) authorizeAgain(provider string, costs Costs, self string) error {
	records, err := b.Purchases()
	if err != nil {
		return err
	}
	committed, open := new(big.Int), 0
	now := b.config.Now()
	for _, record := range records {
		if record.RequestHash == self {
			continue
		}
		if !terminalPurchase(record.Phase) {
			open++
		}
		if now.Sub(time.Unix(record.CreatedUnix, 0)) < b.config.Policy.Window && record.Phase != PurchaseNotCalled {
			value, ok := new(big.Int).SetString(record.CommittedNanoTOS, 10)
			if !ok {
				return errors.New("servicebridge: invalid purchase accounting")
			}
			committed.Add(committed, value)
		}
	}
	err = b.config.Policy.Authorize(provider, costs, committed, open)
	if errors.Is(err, ErrNeedsConfirmation) {
		return nil
	}
	return err
}

func (b *Buyer) binding(record PurchaseRecord) (ReceiptBinding, error) {
	var executionID, inputDigest [32]byte
	if err := decodeHex32(record.ExecutionID, &executionID); err != nil {
		return ReceiptBinding{}, err
	}
	if err := decodeHex32(record.InputDigest, &inputDigest); err != nil {
		return ReceiptBinding{}, err
	}
	price, ok := new(big.Int).SetString(record.PriceNanoTOS, 10)
	if !ok || price.Sign() <= 0 {
		return ReceiptBinding{}, errors.New("servicebridge: invalid purchase price")
	}
	return ReceiptBinding{
		QuoteCommitment: record.QuoteCommitment, ExecutionID: executionID, InputDigest: inputDigest,
		SourceDigest: record.SourceDigest, Price: price, ProviderAgentID: record.ProviderAgentID,
		ToolchainDigest: record.ToolchainDigest, SandboxDigest: record.ManifestDigest,
	}, nil
}

func envelopeFor(record PurchaseRecord, recipient string, kind byte, notAfter uint64) (Envelope, error) {
	var actor, requestHash [32]byte
	if len(record.Actor) != 66 || record.RequestID == nil {
		return Envelope{}, errors.New("servicebridge: the purchase is not admitted")
	}
	if err := decodeHex32(record.Actor[2:], &actor); err != nil {
		return Envelope{}, err
	}
	if err := decodeHex32(record.RequestHash, &requestHash); err != nil {
		return Envelope{}, err
	}
	return Envelope{
		RecipientAgentID: recipient, CapabilityID: record.CapabilityID, QuoteCommitment: record.QuoteCommitment,
		Kind: kind, ActorAccount: actor, RequestID: *record.RequestID, RequestHash: requestHash, NotAfterUnix: notAfter,
	}, nil
}

// HandleResult stores a result from the purchase's provider. Validation
// waits for the finalized respond, in Advance. A result for a completed
// purchase is acknowledged again with fresh packets.
func (b *Buyer) HandleResult(ctx context.Context, message Message) error {
	if b == nil || message.Kind != FrameResult {
		return errors.New("servicebridge: invalid result handling")
	}
	if _, err := DecodeResult(message.Body); err != nil {
		return err
	}
	b.mutex.Lock()
	defer b.mutex.Unlock()
	requestHash := hex.EncodeToString(message.RequestHash[:])
	record, err := b.loadPurchase(requestHash)
	if err != nil {
		return errors.New("servicebridge: the result names no purchase of this buyer")
	}
	if record.ProviderAgentID != message.SenderAgentID || record.RequestID == nil ||
		*record.RequestID != message.RequestID ||
		record.Actor != "0:"+hex.EncodeToString(message.ActorAccount[:]) {
		return errors.New("servicebridge: the result is not from this purchase's provider for its request")
	}
	path := filepath.Join(b.purchaseDir(requestHash), "result")
	if err := writeSynced(path, message.Body); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if record.Phase == PurchaseCompleted {
		return b.acknowledge(ctx, record)
	}
	return nil
}

func (b *Buyer) acknowledge(ctx context.Context, record PurchaseRecord) error {
	var responseHash [32]byte
	if err := decodeHex32(record.ResponseHash, &responseHash); err != nil {
		return err
	}
	body, err := EncodeAck(responseHash)
	if err != nil {
		return err
	}
	envelope, err := envelopeFor(record, record.ProviderAgentID, FrameResultAck, 0)
	if err != nil {
		return err
	}
	_, err = b.config.Courier.Deliver(ctx, envelope, body)
	return err
}

// Advance moves every open purchase by one step from finalized state:
// deliver the task once admitted, validate an attested result, or run the
// refund duty (expire, then claim_refund) when the provider did not answer.
func (b *Buyer) Advance(ctx context.Context) error {
	if b == nil || ctx == nil {
		return errors.New("servicebridge: invalid buyer advance")
	}
	b.mutex.Lock()
	defer b.mutex.Unlock()
	records, err := b.Purchases()
	if err != nil {
		return err
	}
	var failures []error
	for _, record := range records {
		if terminalPurchase(record.Phase) {
			continue
		}
		if err := b.advance(ctx, record); err != nil {
			failures = append(failures, fmt.Errorf("purchase %s: %w", record.RequestHash, err))
		}
	}
	if err := b.config.Courier.Resume(ctx); err != nil && !errors.Is(err, ErrGenerationExpired) {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}

// actionInterval spaces repeated lifecycle sends while finality catches up.
const actionInterval = time.Minute

// TaskRedelivery spaces fresh deliveries of a task still awaiting an answer.
const TaskRedelivery = 10 * time.Minute

func (b *Buyer) advance(ctx context.Context, record PurchaseRecord) error {
	report, err := b.config.Buyer.Resolve(ctx, record.RequestHash)
	if err != nil {
		return err
	}
	now := b.config.Now()
	if report.Phase == buyersdk.PhaseRefused {
		record.Phase, record.Failure = PurchaseRefused, fmt.Sprintf(
			"the call failed with exit code %d",
			report.ExitCode,
		)
		return b.savePurchase(record, false)
	}
	if !report.Found || report.RequestID == nil || report.CallTransaction == nil {
		return nil
	}
	record.RequestID, record.CallLT, record.CallHash = report.RequestID, report.CallTransaction.LT, report.CallTransaction.Hash
	record.Status, record.RequiredAction = string(report.Status), report.RequiredAction
	record.ResponseDeadline, record.RefundDeadline = report.ResponseDeadline, report.RefundClaimDeadline
	recent := now.Unix()-record.LastActionUnix < int64(actionInterval/time.Second)
	switch report.Status {
	case serviceactor.StatusPending:
		// The task goes out once admitted, and again in a fresh generation
		// while no attested response has finalized, in case the provider
		// lost it before admitting it; the provider executes it at most once.
		if record.Phase == PurchaseCalled ||
			(record.Phase == PurchaseTaskSent && now.Unix()-record.LastActionUnix >= int64(TaskRedelivery/time.Second)) {
			record.LastActionUnix = now.Unix()
			if err := b.sendTask(ctx, record); err != nil {
				return errors.Join(err, b.savePurchase(record, false))
			}
			record.Phase = PurchaseTaskSent
		}
	case serviceactor.StatusResponded:
		record.ResponseHash = report.ResponseHash
		return b.complete(ctx, record)
	case serviceactor.StatusOverdue:
		if !recent {
			record.LastActionUnix = now.Unix()
			if err := b.config.Lifecycle.Expire(ctx, record.Actor, *record.RequestID); err != nil {
				return errors.Join(err, b.savePurchase(record, false))
			}
			record.Phase = PurchaseExpireSent
		}
	case serviceactor.StatusRefundable:
		if !recent || record.Phase != PurchaseClaimSent {
			record.LastActionUnix = now.Unix()
			if err := b.config.Lifecycle.ClaimRefund(
				ctx,
				record.Actor,
				*record.RequestID,
				b.config.Wallet,
			); err != nil {
				return errors.Join(err, b.savePurchase(record, false))
			}
			record.Phase = PurchaseClaimSent
		}
	case serviceactor.StatusRefunded:
		record.Phase = PurchaseRefunded
	case serviceactor.StatusSwept:
		record.Phase = PurchaseSwept
	case serviceactor.StatusLapsed:
		record.Phase = PurchaseLapsed
	}
	return b.savePurchase(record, false)
}

func (b *Buyer) sendTask(ctx context.Context, record PurchaseRecord) error {
	archive, err := readPrivateFile(filepath.Join(b.purchaseDir(record.RequestHash), "source"), MaxInlineInputBytes)
	if err != nil {
		return err
	}
	pkg, err := readPrivateFile(
		filepath.Join(b.purchaseDir(record.RequestHash), "quote-package"),
		quoteexchange.MaxPackageBytes+64<<10,
	)
	if err != nil {
		return err
	}
	body, err := EncodeTask(Task{Header: TaskHeader{
		BuyerAgentID: b.config.AgentID, BuyerWallet: b.config.Wallet,
		CapabilityID: record.CapabilityID, CapabilityVersion: record.CapabilityVersion, ExecutionID: record.ExecutionID,
		RequestID: *record.RequestID, CallLT: record.CallLT, CallHash: record.CallHash,
	}, Package: pkg, Archive: archive})
	if err != nil {
		return err
	}
	envelope, err := envelopeFor(record, record.ProviderAgentID, FrameTask, record.ResponseDeadline)
	if err != nil {
		return err
	}
	_, err = b.config.Courier.Deliver(ctx, envelope, body)
	return err
}

func (b *Buyer) complete(ctx context.Context, record PurchaseRecord) error {
	raw, err := readPrivateFile(filepath.Join(b.purchaseDir(record.RequestHash), "result"), maxResultMessageBytes)
	if errors.Is(err, os.ErrNotExist) {
		// Attested on chain; the result packets are still on their way.
		return b.savePurchase(record, false)
	}
	if err != nil {
		return err
	}
	result, err := DecodeResult(raw)
	if err != nil {
		return err
	}
	binding, err := b.binding(record)
	if err != nil {
		return err
	}
	var finalized [32]byte
	if err := decodeHex32(record.ResponseHash, &finalized); err != nil {
		return err
	}
	if err := ValidateResult(result, binding, finalized); err != nil {
		record.Phase, record.Failure = PurchaseReceiptMismatch, err.Error()
		return b.savePurchase(record, false)
	}
	if err := writeSynced(
		filepath.Join(b.purchaseDir(record.RequestHash), "artifact.tar"),
		result.Artifact,
	); err != nil &&
		!errors.Is(err, os.ErrExist) {
		return err
	}
	record.Phase, record.Failure = PurchaseCompleted, ""
	if err := b.savePurchase(record, false); err != nil {
		return err
	}
	return b.acknowledge(ctx, record)
}

// SetConfirmer sets how the owner confirms a purchase the policy routes to
// them.
func (b *Buyer) SetConfirmer(confirm Confirmer) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	b.config.Confirm = confirm
}

// SetDisclosure sets where every purchase's costs are shown before the call.
func (b *Buyer) SetDisclosure(disclose func(Costs)) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	b.config.Disclose = disclose
}
