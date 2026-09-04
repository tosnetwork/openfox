package earning

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentgift"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
	"github.com/tosnetwork/tosutils-go/tvm/cell"

	"github.com/tosnetwork/openfox/pkg/prediction"
)

const maximumPredictionBuilderInputBytes = 256 << 10

type PredictionEffectRequest struct {
	ActionKind            string
	SemanticFields        map[string]commerce.SemanticValue
	MarketDefinitionJSON  []byte
	OperationJSON         []byte
	AmountNanoTOS         uint64
	ValidUntil            uint32
	PolicyRevision        uint64
	ApprovalDigest        string
	SourceCursor          prediction.AccountCursor
	MasterchainCheckpoint prediction.BlockIdentity
}

type PreparedPredictionEffect struct {
	AuthorizedAction commerce.AuthorizedAction
	RelayRecord      prediction.PredictionRelayRecord
}

type tosctlPredictionOperationArtifact struct {
	Schema                     string  `json:"schema"`
	Operation                  string  `json:"operation"`
	CustodyActionKind          *string `json:"custody_action_kind"`
	GlobalID                   int32   `json:"global_id"`
	WorkchainID                int32   `json:"workchain_id"`
	MarketAddress              string  `json:"market_address"`
	MarketID                   string  `json:"market_id"`
	MarketConfigHash           string  `json:"market_config_hash"`
	MarketCodeHash             string  `json:"market_code_hash"`
	SourceAgentAccountCodeHash string  `json:"source_agent_account_code_hash"`
	RiskIncreasing             bool    `json:"risk_increasing"`
	CreditedAmount             uint64  `json:"credited_amount"`
	StateContribution          uint64  `json:"state_contribution"`
	MinimumValue               uint64  `json:"minimum_value"`
	BodyHash                   string  `json:"body_hash"`
	BodyBOCBase64              string  `json:"body_boc_base64"`
	OutputBOC                  *string `json:"output_boc"`
}

type tosctlPredictionAgentPrepared struct {
	Schema                     string                   `json:"schema"`
	StableActionID             string                   `json:"stable_action_id"`
	ActionKind                 string                   `json:"action_kind"`
	Source                     string                   `json:"source"`
	SourceAgentAccountCodeHash string                   `json:"source_agent_account_code_hash"`
	Destination                string                   `json:"destination"`
	MarketID                   string                   `json:"market_id"`
	MarketConfigHash           string                   `json:"market_config_hash"`
	MarketCodeHash             string                   `json:"market_code_hash"`
	AmountNanoTOS              uint64                   `json:"amount_nanotos"`
	BodyHash                   string                   `json:"body_hash"`
	ControllerEpoch            uint64                   `json:"controller_epoch"`
	Seqno                      uint32                   `json:"seqno"`
	ValidUntil                 uint32                   `json:"valid_until"`
	NetworkDomain              agentrelay.NetworkDomain `json:"network_domain"`
	ExactSignedBOC             string                   `json:"exact_signed_boc"`
	ExactSignedBOCDigest       string                   `json:"exact_signed_boc_digest"`
	OutputBOC                  string                   `json:"output_boc"`
	Broadcast                  bool                     `json:"broadcast"`
}

// PreparePredictionEffect is the production Owner-authority-to-Agent-Account
// boundary. It first asks the pinned tosctl binary for a pure canonical body,
// admits that exact body as an AuthorizedAction, obtains a dedicated Prediction
// custody signature, and finally journals the exact external BOC before any
// caller can broadcast it.
func (engine *Engine) PreparePredictionEffect(ctx context.Context, sink *TOSCTLPaymentSink,
	request PredictionEffectRequest, fence commerce.WriterFence,
) (PreparedPredictionEffect, error) {
	if engine == nil || engine.Authority == nil || sink == nil || ctx == nil ||
		!engine.permits("prediction", engine.Gates.Prediction, true) ||
		!commerce.IsPredictionCustodyEffectKind(request.ActionKind) || request.PolicyRevision == 0 ||
		request.ValidUntil == 0 || uint64(request.ValidUntil) > fence.Body.ExpiresAtUnix ||
		predictionEffectNow(
			engine,
		).Unix() <
			0 || uint64(predictionEffectNow(engine).Unix()) >= uint64(request.ValidUntil) {
		return PreparedPredictionEffect{}, errors.New("prediction effect execution is disabled or incomplete")
	}
	artifact, bodyBOC, err := sink.buildPredictionOperation(ctx, request)
	if err != nil {
		return PreparedPredictionEffect{}, err
	}
	if domainErr := validatePredictionSemanticDomain(engine, sink, request, artifact); domainErr != nil {
		return PreparedPredictionEffect{}, domainErr
	}
	expiresAt := minUint64(uint64(request.ValidUntil), fence.Body.ExpiresAtUnix)
	action, err := commerce.BuildAuthorizedAction(
		engine.OwnerID, engine.AgentID, request.ActionKind, request.SemanticFields, bodyBOC, fence,
		request.PolicyRevision, engine.MandateDigest, request.ApprovalDigest,
		"prediction-effect-unsubmitted", expiresAt,
	)
	if err == nil {
		action, err = engine.Authority.SignAction(action, fence)
	}
	if err != nil {
		return PreparedPredictionEffect{}, err
	}
	resolution, err := engine.Authority.Admit(action, request.SemanticFields, bodyBOC, fence, nil)
	if err != nil {
		return PreparedPredictionEffect{}, err
	}
	expected, err := prediction.NewExpectedContractCall(
		request.ActionKind, action.StableActionID, artifact.MarketAddress, request.AmountNanoTOS, bodyBOC,
	)
	if err != nil {
		return PreparedPredictionEffect{}, err
	}
	if resolution.State == commerce.ActionSubmitted {
		record, found := sink.PredictionRelayJournal.Get(action.StableActionID)
		if !found || record.Expected != expected || record.ExactSignedBOCBase64 == "" {
			return PreparedPredictionEffect{}, errors.New("submitted prediction action lost its exact relay material")
		}
		return PreparedPredictionEffect{AuthorizedAction: action, RelayRecord: record}, nil
	}
	if resolution.State != commerce.ActionPrepared {
		return PreparedPredictionEffect{}, errors.New("prediction action is not at an executable authority boundary")
	}
	record, err := sink.prepareAuthorizedPredictionEffect(ctx, action, fence, request, artifact, bodyBOC, expected)
	if err != nil {
		return PreparedPredictionEffect{}, err
	}
	return PreparedPredictionEffect{AuthorizedAction: action, RelayRecord: record}, nil
}

func (sink *TOSCTLPaymentSink) buildPredictionOperation(ctx context.Context,
	request PredictionEffectRequest,
) (tosctlPredictionOperationArtifact, []byte, error) {
	if err := sink.validatePredictionAdapter(ctx); err != nil {
		return tosctlPredictionOperationArtifact{}, nil, err
	}
	if len(request.MarketDefinitionJSON) == 0 ||
		len(request.MarketDefinitionJSON) > maximumPredictionBuilderInputBytes ||
		len(request.OperationJSON) == 0 ||
		len(request.OperationJSON) > maximumPredictionBuilderInputBytes ||
		request.AmountNanoTOS == 0 ||
		request.ValidUntil == 0 {
		return tosctlPredictionOperationArtifact{}, nil, errors.New(
			"prediction builder input is invalid or exceeds its bound",
		)
	}
	definitionPath, definitionCleanup, err := sink.writePrivateBytes(
		".prediction-definition-*.json", request.MarketDefinitionJSON,
	)
	if err != nil {
		return tosctlPredictionOperationArtifact{}, nil, err
	}
	defer definitionCleanup()
	operationPath, operationCleanup, err := sink.writePrivateBytes(
		".prediction-operation-*.json", request.OperationJSON,
	)
	if err != nil {
		return tosctlPredictionOperationArtifact{}, nil, err
	}
	defer operationCleanup()
	raw, err := sink.run(ctx, []string{
		"agent", "prediction", "build-operation", "--definition", definitionPath,
		"--operation", operationPath, "-c", sink.ConfigPath,
	})
	if err != nil {
		return tosctlPredictionOperationArtifact{}, nil, fmt.Errorf("build Prediction operation: %w", err)
	}
	var artifact tosctlPredictionOperationArtifact
	if decodeErr := decodeStrictJSON(raw, &artifact); decodeErr != nil {
		return tosctlPredictionOperationArtifact{}, nil,
			fmt.Errorf("decode Prediction operation artifact: %w", decodeErr)
	}
	bodyBOC, err := base64.StdEncoding.Strict().DecodeString(artifact.BodyBOCBase64)
	if err != nil || len(bodyBOC) == 0 || len(bodyBOC) > maximumPredictionBuilderInputBytes {
		return tosctlPredictionOperationArtifact{}, nil, errors.New("tosctl returned an invalid Prediction body BOC")
	}
	root, err := cell.FromBOC(bodyBOC)
	if err != nil || root == nil || !bytes.Equal(bodyBOC, root.ToBOCWithFlags(false)) ||
		artifact.BodyHash != "tvm-cell-sha256:"+hex.EncodeToString(root.Hash()) {
		return tosctlPredictionOperationArtifact{}, nil, errors.New("tosctl returned a noncanonical Prediction body")
	}
	return artifact, append([]byte(nil), bodyBOC...), nil
}

func validatePredictionSemanticDomain(engine *Engine, sink *TOSCTLPaymentSink,
	request PredictionEffectRequest, artifact tosctlPredictionOperationArtifact,
) error {
	profile, ok := sink.PredictionRelayJournal.Profile()
	if !ok || sink.RelayNetworkDomain == nil {
		return errors.New("prediction relay trust domain is unavailable")
	}
	networkDigest, err := agentrelay.NetworkDomainDigest(*sink.RelayNetworkDomain)
	if err != nil || profile.NetworkDomainHash != networkDigest || profile.SourceAgentAccount != sink.SourceAccount ||
		artifact.Schema != "tos.prediction-operation-artifact.v1" || artifact.OutputBOC != nil ||
		artifact.CustodyActionKind == nil || *artifact.CustodyActionKind != request.ActionKind ||
		artifact.GlobalID != sink.RelayNetworkDomain.GlobalID ||
		artifact.WorkchainID != sink.RelayNetworkDomain.WorkchainID ||
		artifact.MarketAddress != profile.MarketAddress || artifact.MarketID != profile.MarketID ||
		artifact.MarketConfigHash != profile.MarketConfigHash || artifact.MarketCodeHash != profile.MarketCodeHash ||
		artifact.SourceAgentAccountCodeHash != profile.SourceAgentAccountCodeHash ||
		request.AmountNanoTOS < artifact.MinimumValue || !validTVMCellSHA256(artifact.BodyHash) {
		return errors.New("tosctl Prediction artifact conflicts with the owner-pinned relay profile")
	}
	wireFields, err := commerce.ExportSemanticFields(request.ActionKind, request.SemanticFields)
	if err != nil {
		return err
	}
	wanted := map[string]string{
		"owner_id": engine.OwnerID, "agent_id": engine.AgentID,
		"network_domain_digest": networkDigest, "market_id": profile.MarketID,
	}
	for _, field := range wireFields {
		if expected, common := wanted[field.Name]; common && (field.Number != nil || field.Text != expected) {
			return errors.New("prediction semantic action conflicts with its owner, network, or market")
		}
		delete(wanted, field.Name)
	}
	if len(wanted) != 0 {
		return errors.New("prediction semantic action omits its common custody domain")
	}
	return nil
}

func (sink *TOSCTLPaymentSink) prepareAuthorizedPredictionEffect(ctx context.Context,
	action commerce.AuthorizedAction, fence commerce.WriterFence, request PredictionEffectRequest,
	artifact tosctlPredictionOperationArtifact, bodyBOC []byte, expected prediction.ExpectedContractCall,
) (prediction.PredictionRelayRecord, error) {
	authority, ok := sink.Authority.(PredictionCustodyEffectAuthority)
	if !ok {
		return prediction.PredictionRelayRecord{}, errors.New("owner authority has no Prediction custody capability")
	}
	domain := commerce.CustodyNetworkDomain{
		NetworkID: sink.RelayNetworkDomain.NetworkID, GlobalID: sink.RelayNetworkDomain.GlobalID,
		ZeroStateRootHash: sink.RelayNetworkDomain.ZeroStateRootHash,
		ZeroStateFileHash: sink.RelayNetworkDomain.ZeroStateFileHash,
		WorkchainID:       sink.RelayNetworkDomain.WorkchainID,
	}
	authorization, err := authority.AuthorizePredictionCustodyEffect(
		action, request.SemanticFields, bodyBOC, fence,
		commerce.PredictionCustodyEffectAuthorizationV1{
			SourceAccount: sink.SourceAccount, SourceAgentAccountCodeHash: artifact.SourceAgentAccountCodeHash,
			NetworkDomain: domain, ActionKind: request.ActionKind, EffectKind: request.ActionKind,
			MarketID: artifact.MarketID, MarketAddress: artifact.MarketAddress,
			MarketConfigHash: artifact.MarketConfigHash, MarketCodeHash: artifact.MarketCodeHash,
			AmountNanoTOS: request.AmountNanoTOS, BodyHash: artifact.BodyHash,
			ExpiresAtUnix: uint64(request.ValidUntil),
		},
	)
	if err != nil {
		return prediction.PredictionRelayRecord{}, err
	}
	authorizationJSON, err := json.Marshal(authorization)
	if err != nil {
		return prediction.PredictionRelayRecord{}, err
	}
	authorizationPath, authorizationCleanup, err := sink.writePrivateBytes(
		".prediction-authorization-*.json", authorizationJSON,
	)
	if err != nil {
		return prediction.PredictionRelayRecord{}, err
	}
	defer authorizationCleanup()
	definitionPath, definitionCleanup, err := sink.writePrivateBytes(
		".prediction-definition-*.json", request.MarketDefinitionJSON,
	)
	if err != nil {
		return prediction.PredictionRelayRecord{}, err
	}
	defer definitionCleanup()
	operationPath, operationCleanup, err := sink.writePrivateBytes(
		".prediction-operation-*.json", request.OperationJSON,
	)
	if err != nil {
		return prediction.PredictionRelayRecord{}, err
	}
	defer operationCleanup()
	outputPath, outputCleanup, err := sink.vacantPredictionOutputPath()
	if err != nil {
		return prediction.PredictionRelayRecord{}, err
	}
	defer outputCleanup()
	raw, err := sink.run(ctx, []string{
		"agent", "prediction", "prepare-agent", "--definition", definitionPath,
		"--operation", operationPath, "--wallet", sink.Wallet,
		"--amount-nanotos", strconv.FormatUint(request.AmountNanoTOS, 10),
		"--fee-reserve-nanotos", strconv.FormatUint(sink.FeeReserveNanoTOS, 10),
		"--valid-until", strconv.FormatUint(uint64(request.ValidUntil), 10),
		"--authorization-file", authorizationPath, "--output-boc", outputPath,
		"--yes", "-c", sink.ConfigPath,
	})
	if err != nil {
		return prediction.PredictionRelayRecord{}, fmt.Errorf("prepare Prediction Agent Account effect: %w", err)
	}
	var prepared tosctlPredictionAgentPrepared
	if decodeErr := decodeStrictJSON(raw, &prepared); decodeErr != nil {
		return prediction.PredictionRelayRecord{}, fmt.Errorf("decode prepared Prediction effect: %w", decodeErr)
	}
	exactBOC, err := validatePreparedPredictionEffect(
		prepared, action, request, artifact, outputPath, sink.SourceAccount, *sink.RelayNetworkDomain,
	)
	if err != nil {
		return prediction.PredictionRelayRecord{}, err
	}
	record, err := sink.PredictionRelayJournal.Prepare(
		action.StableActionID, exactBOC, expected, request.SourceCursor, request.MasterchainCheckpoint,
	)
	if err != nil {
		return prediction.PredictionRelayRecord{}, err
	}
	if _, err := sink.Authority.Transition(
		action.StableActionID, action.ExactRequestDigest, commerce.ActionSubmitted, "", nil,
	); err != nil {
		return prediction.PredictionRelayRecord{}, errors.New("establish durable Prediction submission boundary")
	}
	return record, nil
}

func validatePreparedPredictionEffect(prepared tosctlPredictionAgentPrepared,
	action commerce.AuthorizedAction, request PredictionEffectRequest,
	artifact tosctlPredictionOperationArtifact, outputPath, sourceAccount string, network agentrelay.NetworkDomain,
) ([]byte, error) {
	exactBOC, decodeErr := base64.StdEncoding.Strict().DecodeString(prepared.ExactSignedBOC)
	digest := sha256.Sum256(exactBOC)
	if prepared.Schema != "tosctl.prediction-agent-effect-prepared.v1" ||
		prepared.StableActionID != action.StableActionID || prepared.ActionKind != request.ActionKind ||
		prepared.Source != sourceAccount || prepared.Destination != artifact.MarketAddress ||
		prepared.SourceAgentAccountCodeHash != artifact.SourceAgentAccountCodeHash ||
		prepared.MarketID != artifact.MarketID || prepared.MarketConfigHash != artifact.MarketConfigHash ||
		prepared.MarketCodeHash != artifact.MarketCodeHash || prepared.AmountNanoTOS != request.AmountNanoTOS ||
		prepared.BodyHash != artifact.BodyHash || prepared.ValidUntil != request.ValidUntil ||
		prepared.NetworkDomain != network || prepared.OutputBOC != outputPath ||
		prepared.Broadcast || decodeErr != nil || len(exactBOC) == 0 ||
		prepared.ExactSignedBOCDigest != "sha256:"+hex.EncodeToString(digest[:]) {
		return nil, errors.New("tosctl returned an unrelated prepared Prediction effect")
	}
	onDisk, err := os.ReadFile(outputPath)
	if err != nil || !bytes.Equal(onDisk, exactBOC) {
		return nil, errors.New("prepared Prediction output file differs from stdout exact BOC")
	}
	root, err := cell.FromBOC(exactBOC)
	if err != nil || root == nil || !bytes.Equal(exactBOC, root.ToBOCWithFlags(false)) {
		return nil, errors.New("prepared Prediction external message is not one canonical cell")
	}
	parsed, err := agentgift.VerifyPreparedAgentCheckedContractCallV2(
		exactBOC,
		agentgift.ExpectedCheckedContractCallV2{
			SenderAgentAccount: sourceAccount, GlobalID: network.GlobalID,
			ControllerEpoch: prepared.ControllerEpoch, Seqno: prepared.Seqno,
			ValidUntil: prepared.ValidUntil, DestinationAddress: artifact.MarketAddress,
			AmountAtomic: request.AmountNanoTOS, BodyBOC: base64Body(artifact.BodyBOCBase64),
		},
	)
	if err != nil || parsed.BodyHash != artifact.BodyHash {
		return nil, errors.New("prepared Prediction BOC differs from its authorized checked call")
	}
	return append([]byte(nil), exactBOC...), nil
}

func base64Body(encoded string) []byte {
	raw, _ := base64.StdEncoding.Strict().DecodeString(encoded)
	return raw
}

func (sink *TOSCTLPaymentSink) validatePredictionAdapter(ctx context.Context) error {
	if sink == nil || sink.Authority == nil || sink.PredictionRelayJournal == nil || ctx == nil ||
		!filepath.IsAbs(sink.Executable) || !filepath.IsAbs(sink.ConfigPath) ||
		!filepath.IsAbs(sink.EvidenceDirectory) || sink.Wallet == "" || sink.SourceAccount == "" ||
		sink.RelayNetworkDomain == nil || sink.NetworkGlobalID != sink.RelayNetworkDomain.GlobalID ||
		sink.FeeReserveNanoTOS == 0 {
		return errors.New("TOS Prediction custody Adapter configuration is invalid")
	}
	if err := sink.verifyRelayNetworkDomain(ctx, *sink.RelayNetworkDomain); err != nil {
		return err
	}
	if err := sink.freezeVaultCapability(); err != nil {
		return errors.New("TOS Prediction custody Adapter vault capability is invalid")
	}
	if sink.Run == nil {
		if err := sink.pinTOSCTLExecutable(); err != nil {
			return errors.New("TOS Prediction custody Adapter executable is untrusted")
		}
	}
	return nil
}

func (sink *TOSCTLPaymentSink) vacantPredictionOutputPath() (string, func(), error) {
	file, err := os.CreateTemp(filepath.Clean(sink.EvidenceDirectory), ".prediction-exact-*.boc")
	if err != nil {
		return "", func() {}, err
	}
	path := file.Name()
	chmodErr := file.Chmod(0o600)
	closeErr := file.Close()
	if chmodErr != nil || closeErr != nil {
		_ = os.Remove(path)
		return "", func() {}, errors.New("create private Prediction output capability")
	}
	if err := os.Remove(path); err != nil {
		return "", func() {}, err
	}
	return path, func() { _ = os.Remove(path) }, nil
}

func predictionEffectNow(engine *Engine) time.Time {
	if engine != nil && engine.Now != nil {
		return engine.Now().UTC()
	}
	return time.Now().UTC()
}
