package earning

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

const tosQuorumEvidenceProfile = "tos://settlement/native-agent-account-quorum/v1"

// TOSCTLPaymentSink is the production boundary between OpenFox's Owner
// Economic Action Authority and tosctl custody. OpenFox never passes a private
// wallet key to the command. Custody receives one short-lived, exact,
// Agreement-bound proof and independently enforces its pinned authority key,
// writer-generation high-water mark, Agent Account limits, sequence and
// finalized-chain evidence.
type TOSCTLPaymentSink struct {
	Authority           EconomicAuthority
	Executable          string
	ConfigPath          string
	Wallet              string
	SourceAccount       string
	NetworkGlobalID     int32
	FeeReserveNanoTOS   uint64
	QuorumConfigPaths   []string
	MaximumTransactions uint32
	VaultURL            string
	EvidenceDirectory   string
	ResolveAttempts     uint32
	ResolveInterval     time.Duration
	Run                 func(context.Context, []string, []string) ([]byte, error)
}

type tosctlPaymentPrepared struct {
	Schema               string `json:"schema"`
	StableActionID       string `json:"stable_action_id"`
	AgreementBodyDigest  string `json:"agreement_body_digest"`
	ObligationInstanceID string `json:"obligation_instance_id"`
	Account              string `json:"account"`
	Target               string `json:"target"`
	AmountNanoTOS        uint64 `json:"amount_nanotos"`
	ControllerEpoch      uint64 `json:"controller_epoch"`
	Seqno                uint32 `json:"seqno"`
	NetworkGlobalID      int32  `json:"network_global_id"`
	ValidUntil           uint32 `json:"valid_until"`
	ExactSignedBOC       string `json:"exact_signed_boc"`
	ExactSignedBOCDigest string `json:"exact_signed_boc_digest"`
}

type tosctlPaymentBroadcast struct {
	Schema               string `json:"schema"`
	StableActionID       string `json:"stable_action_id"`
	Account              string `json:"account"`
	ExactSignedBOCDigest string `json:"exact_signed_boc_digest"`
	State                string `json:"state"`
}

type tosctlPaymentFinalized struct {
	Schema               string          `json:"schema"`
	StableActionID       string          `json:"stable_action_id"`
	AgreementBodyDigest  string          `json:"agreement_body_digest"`
	ObligationInstanceID string          `json:"obligation_instance_id"`
	SourceAccount        string          `json:"source_account"`
	Destination          string          `json:"destination"`
	AmountNanoTOS        uint64          `json:"amount_nanotos"`
	NetworkGlobalID      int32           `json:"network_global_id"`
	Quorum               tosctlQuorum    `json:"quorum"`
	Evidence             json.RawMessage `json:"evidence"`
	Observations         json.RawMessage `json:"observations"`
	Failures             []string        `json:"failures"`
	State                string          `json:"state"`
}

type tosctlQuorum struct {
	Members   uint32 `json:"members"`
	Threshold uint32 `json:"threshold"`
	Agreeing  uint32 `json:"agreeing"`
}

type tosctlPaymentObservation struct {
	Endpoint                 string `json:"endpoint"`
	TransactionHash          string `json:"transaction_hash"`
	TransactionLT            uint64 `json:"transaction_lt"`
	TransactionUTime         uint64 `json:"transaction_utime"`
	TransactionBOCDigest     string `json:"transaction_boc_digest"`
	BlockWorkchain           int32  `json:"block_workchain"`
	BlockShard               int64  `json:"block_shard"`
	BlockSeqno               uint32 `json:"block_seqno"`
	BlockRootHash            string `json:"block_root_hash"`
	BlockFileHash            string `json:"block_file_hash"`
	ObservedMasterchainSeqno uint32 `json:"observed_masterchain_seqno"`
}

func (sink *TOSCTLPaymentSink) SubmitPayment(ctx context.Context, action commerce.AuthorizedAction,
	fence commerce.WriterFence, fields map[string]commerce.SemanticValue, canonicalRequest []byte,
	request commerce.AgreementPaymentRequest) (commerce.AgreementPaymentEvidence, error) {
	if err := sink.validate(); err != nil {
		return commerce.AgreementPaymentEvidence{}, err
	}
	if request.NetworkID == "" || string(request.Destination) == "" || action.StableActionID != request.StableActionID {
		return commerce.AgreementPaymentEvidence{}, errors.New("TOS payment request is incomplete")
	}
	authorization, err := sink.Authority.AuthorizeCustodyPayment(action, fields, canonicalRequest, fence,
		request, sink.SourceAccount, sink.NetworkGlobalID)
	if err != nil {
		return commerce.AgreementPaymentEvidence{}, err
	}
	authorizationPath, cleanup, err := sink.writeAuthorization(authorization)
	if err != nil {
		return commerce.AgreementPaymentEvidence{}, err
	}
	defer cleanup()
	amount, err := strconv.ParseUint(request.Amount.AmountAtomic, 10, 64)
	if err != nil || amount == 0 {
		return commerce.AgreementPaymentEvidence{}, errors.New("TOS payment amount is invalid")
	}
	preparedRaw, err := sink.run(ctx, []string{"agent", "account", "economic-payment-prepare",
		"--wallet", sink.Wallet, "--target", string(request.Destination), "--amount-nanotos", strconv.FormatUint(amount, 10),
		"--fee-reserve-nanotos", strconv.FormatUint(sink.FeeReserveNanoTOS, 10), "--valid-until", strconv.FormatUint(request.ExpiresAtUnix, 10),
		"--authorization-file", authorizationPath, "--yes", "-c", sink.ConfigPath})
	if err != nil {
		return commerce.AgreementPaymentEvidence{}, fmt.Errorf("prepare Agreement payment: %w", err)
	}
	var prepared tosctlPaymentPrepared
	if err := decodeStrictJSON(preparedRaw, &prepared); err != nil {
		return commerce.AgreementPaymentEvidence{}, fmt.Errorf("decode tosctl prepared payment: %w", err)
	}
	if prepared.Schema != "tosctl.agent-account.agreement-payment-prepared.v1" ||
		prepared.StableActionID != request.StableActionID || prepared.AgreementBodyDigest != request.AgreementBodyDigest ||
		prepared.ObligationInstanceID != request.ObligationInstanceID || prepared.Account != sink.SourceAccount ||
		prepared.Target != string(request.Destination) || prepared.AmountNanoTOS != amount || prepared.ExactSignedBOCDigest == "" {
		return commerce.AgreementPaymentEvidence{}, fmt.Errorf("tosctl returned an unrelated prepared payment: schema=%q action=%q agreement=%q obligation=%q account=%q target=%q amount=%d digest=%q",
			prepared.Schema, prepared.StableActionID, prepared.AgreementBodyDigest, prepared.ObligationInstanceID,
			prepared.Account, prepared.Target, prepared.AmountNanoTOS, prepared.ExactSignedBOCDigest)
	}
	broadcastRaw, err := sink.run(ctx, []string{"agent", "account", "economic-payment-broadcast", "--wallet", sink.Wallet,
		"--stable-action-id", request.StableActionID, "--yes", "-c", sink.ConfigPath})
	if err != nil {
		// A transport error after submission is deliberately ambiguous. Resolve
		// the same stable action; never prepare or broadcast a replacement.
		return sink.ResolvePayment(ctx, request)
	}
	var broadcast tosctlPaymentBroadcast
	if err := decodeStrictJSON(broadcastRaw, &broadcast); err != nil || broadcast.Schema != "tosctl.agent-account.agreement-payment-broadcast.v1" ||
		broadcast.StableActionID != request.StableActionID || broadcast.Account != sink.SourceAccount ||
		broadcast.ExactSignedBOCDigest != prepared.ExactSignedBOCDigest || broadcast.State != "broadcasting" {
		return commerce.AgreementPaymentEvidence{}, errors.New("tosctl returned an unrelated broadcast result")
	}
	return sink.ResolvePayment(ctx, request)
}

func (sink *TOSCTLPaymentSink) ResolvePayment(ctx context.Context,
	request commerce.AgreementPaymentRequest) (commerce.AgreementPaymentEvidence, error) {
	if err := sink.validate(); err != nil {
		return commerce.AgreementPaymentEvidence{}, err
	}
	attempts := sink.ResolveAttempts
	if attempts == 0 {
		attempts = 30
	}
	interval := sink.ResolveInterval
	if interval <= 0 {
		interval = 2 * time.Second
	}
	args := []string{"agent", "account", "economic-payment-resolve", "--wallet", sink.Wallet,
		"--stable-action-id", request.StableActionID, "--max-transactions", strconv.FormatUint(uint64(sink.maximumTransactions()), 10),
		"--quorum-config"}
	args = append(args, sink.QuorumConfigPaths...)
	args = append(args, "-c", sink.ConfigPath)
	var lastErr error
	for attempt := uint32(0); attempt < attempts; attempt++ {
		raw, err := sink.run(ctx, args)
		if err == nil {
			return sink.evidence(request, raw)
		}
		lastErr = err
		if attempt+1 == attempts {
			break
		}
		select {
		case <-ctx.Done():
			return commerce.AgreementPaymentEvidence{}, ctx.Err()
		case <-time.After(interval):
		}
	}
	return commerce.AgreementPaymentEvidence{}, fmt.Errorf("resolve Agreement payment from TOS quorum: %w", lastErr)
}

func (sink *TOSCTLPaymentSink) evidence(request commerce.AgreementPaymentRequest, raw []byte) (commerce.AgreementPaymentEvidence, error) {
	var result tosctlPaymentFinalized
	if err := decodeStrictJSON(raw, &result); err != nil || result.Schema != "tosctl.agent-account.agreement-payment-finalized.v1" ||
		result.StableActionID != request.StableActionID || result.AgreementBodyDigest != request.AgreementBodyDigest ||
		result.ObligationInstanceID != request.ObligationInstanceID || result.SourceAccount != sink.SourceAccount ||
		result.Destination != string(request.Destination) || result.NetworkGlobalID != sink.NetworkGlobalID || result.State != "finalized" ||
		result.Quorum.Members < 3 || result.Quorum.Threshold < 2 || result.Quorum.Agreeing < result.Quorum.Threshold || len(result.Evidence) == 0 {
		return commerce.AgreementPaymentEvidence{}, errors.New("tosctl returned unrelated or insufficient finality evidence")
	}
	amount, err := strconv.ParseUint(request.Amount.AmountAtomic, 10, 64)
	if err != nil || result.AmountNanoTOS != amount {
		return commerce.AgreementPaymentEvidence{}, errors.New("tosctl finality evidence has the wrong amount")
	}
	requestDigest, err := commerce.AgreementPaymentRequestDigest(request)
	if err != nil {
		return commerce.AgreementPaymentEvidence{}, err
	}
	var observation tosctlPaymentObservation
	if err := decodeStrictJSON(result.Evidence, &observation); err != nil || observation.TransactionHash == "" || observation.BlockRootHash == "" || observation.TransactionUTime == 0 {
		return commerce.AgreementPaymentEvidence{}, errors.New("tosctl finality observation is incomplete")
	}
	return commerce.AgreementPaymentEvidence{PaymentRequestDigest: requestDigest, StableActionID: request.StableActionID,
		ExactTransferReference: observation.TransactionHash, AdapterEvidenceProfile: tosQuorumEvidenceProfile,
		ResolvedState: "finalized", ResolvedAtUnix: observation.TransactionUTime,
		FinalityReference: observation.BlockRootHash, Evidence: append([]byte(nil), raw...)}, nil
}

// VerifyPaymentEvidence independently re-parses the complete quorum artifact
// instead of trusting the evidence fields returned by SubmitPayment.
func (sink *TOSCTLPaymentSink) VerifyPaymentEvidence(request commerce.AgreementPaymentRequest,
	evidence commerce.AgreementPaymentEvidence, now time.Time) error {
	if evidence.ResolvedAtUnix > uint64(now.UTC().Unix()) {
		return errors.New("TOS payment evidence is from the future")
	}
	rebuilt, err := sink.evidence(request, evidence.Evidence)
	if err != nil || rebuilt.PaymentRequestDigest != evidence.PaymentRequestDigest || rebuilt.StableActionID != evidence.StableActionID ||
		rebuilt.ExactTransferReference != evidence.ExactTransferReference || rebuilt.AdapterEvidenceProfile != evidence.AdapterEvidenceProfile ||
		rebuilt.ResolvedState != evidence.ResolvedState || rebuilt.ResolvedAtUnix != evidence.ResolvedAtUnix || rebuilt.FinalityReference != evidence.FinalityReference {
		return errors.New("TOS payment evidence fields differ from the verified quorum artifact")
	}
	return nil
}

func (sink *TOSCTLPaymentSink) validate() error {
	if sink == nil || sink.Authority == nil || !filepath.IsAbs(sink.Executable) || !filepath.IsAbs(sink.ConfigPath) ||
		!filepath.IsAbs(sink.EvidenceDirectory) || sink.Wallet == "" || sink.SourceAccount == "" || sink.NetworkGlobalID == 0 ||
		sink.FeeReserveNanoTOS == 0 || len(sink.QuorumConfigPaths) < 2 {
		return errors.New("TOS custody payment Adapter configuration is invalid")
	}
	seen := map[string]bool{filepath.Clean(sink.ConfigPath): true}
	for _, path := range sink.QuorumConfigPaths {
		if !filepath.IsAbs(path) || seen[filepath.Clean(path)] {
			return errors.New("TOS custody quorum configs must be distinct absolute paths")
		}
		seen[filepath.Clean(path)] = true
	}
	return nil
}

func (sink *TOSCTLPaymentSink) maximumTransactions() uint32 {
	if sink.MaximumTransactions == 0 {
		return 1000
	}
	return sink.MaximumTransactions
}

func (sink *TOSCTLPaymentSink) writeAuthorization(authorization commerce.CustodyActionAuthorization) (string, func(), error) {
	if err := os.MkdirAll(sink.EvidenceDirectory, 0o700); err != nil {
		return "", func() {}, err
	}
	info, err := os.Lstat(sink.EvidenceDirectory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return "", func() {}, errors.New("custody evidence directory must be private")
	}
	file, err := os.CreateTemp(sink.EvidenceDirectory, ".economic-authorization-*.json")
	if err != nil {
		return "", func() {}, err
	}
	path := file.Name()
	cleanup := func() { _ = os.Remove(path) }
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		cleanup()
		return "", func() {}, err
	}
	encoder := json.NewEncoder(file)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(authorization); err != nil {
		_ = file.Close()
		cleanup()
		return "", func() {}, err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		cleanup()
		return "", func() {}, err
	}
	if err := file.Close(); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return path, cleanup, nil
}

func (sink *TOSCTLPaymentSink) run(ctx context.Context, args []string) ([]byte, error) {
	env := os.Environ()
	if sink.VaultURL != "" {
		env = append(env, "VAULT_URL="+sink.VaultURL)
	}
	if sink.Run != nil {
		return sink.Run(ctx, append([]string(nil), args...), env)
	}
	command := exec.CommandContext(ctx, sink.Executable, args...)
	command.Env = env
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	if stderr.Len() != 0 {
		return nil, errors.New("tosctl emitted unexpected stderr")
	}
	return stdout.Bytes(), nil
}
