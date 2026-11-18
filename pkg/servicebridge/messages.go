package servicebridge

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"regexp"

	"github.com/tosnetwork/ai/protocol/pkg/railwork"
)

const (
	maxMessageHeaderBytes = railwork.MaxMessageHeaderBytes
	maxTaskMessageBytes   = railwork.MaxTaskMessageBytes
	maxResultMessageBytes = railwork.MaxResultMessageBytes
	maxAckMessageBytes    = railwork.MaxAckMessageBytes
	maxResultRequestBytes = railwork.MaxResultRequestMessageBytes

	taskSchema          = railwork.TaskSchema
	resultSchema        = railwork.ResultSchema
	ackSchema           = railwork.AckSchema
	resultRequestSchema = railwork.ResultRequestSchema
)

var (
	agentIDPattern    = regexp.MustCompile(`^agent_[0-9a-f]{64}$`)
	capabilityPattern = regexp.MustCompile(`^cap_[0-9a-f]{64}$`)
	rawAddressPattern = regexp.MustCompile(`^0:[0-9a-f]{64}$`)
	hex64Pattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	sha256Pattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// InputDigest is the request input commitment for a source archive digest.
func InputDigest(sourceDigest [32]byte) [32]byte {
	return railwork.InputDigest(sourceDigest)
}

// TaskHeader describes one paid request's work. Every field is a claim the
// provider re-proves from finalized state.
type TaskHeader = railwork.TaskHeader

// Task is a decoded task message. Header.BuyerKeyCard carries the buyer's
// key card as its Base64 text.
type Task struct {
	Header  TaskHeader
	Package []byte
	Archive []byte
}

// ResultHeader names the attested Receipt of a request.
type ResultHeader = railwork.ResultHeader

// Result is a decoded result message: the Receipt and the artifact.
type Result struct {
	Header   ResultHeader
	Receipt  []byte
	Artifact []byte
}

// AckHeader acknowledges a validated result.
type AckHeader = railwork.AckHeader

// ResultRequestHeader asks for a responded request's result again. The
// request is named by the frame binding (actor, request id, request hash);
// the header holds only the buyer's current key card.
type ResultRequestHeader = railwork.ResultRequestHeader

// EncodeTask builds a task message. A key card in Header.BuyerKeyCard must
// be canonical Base64; the schema, package and source digest are set from
// the task's bytes.
func EncodeTask(task Task) ([]byte, error) {
	header := task.Header
	var card []byte
	if header.BuyerKeyCard != "" {
		decoded, err := base64.StdEncoding.Strict().DecodeString(header.BuyerKeyCard)
		if err != nil || base64.StdEncoding.EncodeToString(decoded) != header.BuyerKeyCard {
			return nil, errors.New("servicebridge: the buyer key card is not canonical Base64")
		}
		card = decoded
	}
	header.Schema, header.BuyerKeyCard, header.PackageBase64, header.SourceDigest = "", "", "", ""
	return railwork.EncodeTask(railwork.Task{Header: header, Package: task.Package, Archive: task.Archive, BuyerKeyCard: card})
}

// DecodeTask parses a task message and checks the archive against its
// digest and the inline input bound.
func DecodeTask(raw []byte) (Task, error) {
	task, err := railwork.DecodeTask(raw)
	if err != nil {
		return Task{}, err
	}
	return Task{Header: task.Header, Package: task.Package, Archive: task.Archive}, nil
}

// ExecutionIDFor commits an execution id to the Agent the result returns to.
// The buyer's wallet pays a call carrying this id, so a task naming another
// return Agent than the one committed cannot open it: without the binding,
// anyone who knows the source could resend the paid task as their own Agent,
// take the result and consume the provider's single execution.
func ExecutionIDFor(buyerAgentID string, nonce [32]byte) ([32]byte, error) {
	return railwork.ExecutionID(buyerAgentID, nonce)
}

// EncodeResult builds a result message.
func EncodeResult(responseHash [32]byte, receiptBOC, artifact []byte) ([]byte, error) {
	return EncodeResultWithCard(responseHash, receiptBOC, artifact, nil)
}

// EncodeResultWithCard builds a result message carrying the provider's key
// card packet JSON, or none when card is empty.
func EncodeResultWithCard(responseHash [32]byte, receiptBOC, artifact, card []byte) ([]byte, error) {
	return railwork.EncodeResult(responseHash, receiptBOC, artifact, card)
}

// DecodeResult parses a result message.
func DecodeResult(raw []byte) (Result, error) {
	result, err := railwork.DecodeResult(raw)
	if err != nil {
		return Result{}, err
	}
	return Result{Header: result.Header, Receipt: result.Receipt, Artifact: result.Artifact}, nil
}

// EncodeAck builds a result acknowledgement.
func EncodeAck(responseHash [32]byte) ([]byte, error) {
	return EncodeAckWithCard(responseHash, nil)
}

// EncodeAckWithCard builds a result acknowledgement carrying the buyer's
// key card packet JSON, or none when card is empty.
func EncodeAckWithCard(responseHash [32]byte, card []byte) ([]byte, error) {
	return railwork.EncodeAck(responseHash, card)
}

// DecodeAck parses a result acknowledgement.
func DecodeAck(raw []byte) (AckHeader, error) {
	ack, err := railwork.DecodeAck(raw)
	if err != nil {
		return AckHeader{}, err
	}
	return ack.Header, nil
}

func sha256Sum(value []byte) [32]byte { return sha256.Sum256(value) }

// EncodeResultRequest builds a result request carrying the buyer's key card
// packet JSON, or none when card is empty.
func EncodeResultRequest(card []byte) ([]byte, error) {
	return railwork.EncodeResultRequest(card)
}

// DecodeResultRequest parses a result request.
func DecodeResultRequest(raw []byte) (ResultRequestHeader, error) {
	request, err := railwork.DecodeResultRequest(raw)
	if err != nil {
		return ResultRequestHeader{}, err
	}
	return request.Header, nil
}
