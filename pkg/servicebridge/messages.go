package servicebridge

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
)

const (
	maxMessageHeaderBytes = 64 << 10
	maxTaskMessageBytes   = 4 + maxMessageHeaderBytes + MaxInlineInputBytes
	maxResultMessageBytes = 4 + maxMessageHeaderBytes + MaxResultBytes
	maxAckMessageBytes    = 4 + 4<<10

	taskSchema   = "tos.openfox.rail-task.v1"
	resultSchema = "tos.openfox.rail-result.v1"
	ackSchema    = "tos.openfox.rail-result-ack.v1"

	// inputDomain separates the request's input digest from the raw
	// source digest it commits to.
	inputDomain = "tos.openfox.rail-input.v1\x00"
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
	return sha256.Sum256(append([]byte(inputDomain), sourceDigest[:]...))
}

// TaskHeader describes one paid request's work. Every field is a claim the
// provider re-proves from finalized state.
type TaskHeader struct {
	Schema            string `json:"schema"`
	BuyerAgentID      string `json:"buyer_agent_id"`
	BuyerWallet       string `json:"buyer_wallet"`
	CapabilityID      string `json:"capability_id"`
	CapabilityVersion string `json:"capability_version"`
	PackageBase64     string `json:"package_base64"`
	ExecutionID       string `json:"execution_id"`
	SourceDigest      string `json:"source_digest"`
	RequestID         uint64 `json:"request_id"`
	CallLT            uint64 `json:"call_lt"`
	CallHash          string `json:"call_hash"`
}

// Task is a decoded task message.
type Task struct {
	Header  TaskHeader
	Package []byte
	Archive []byte
}

// ResultHeader names the attested Receipt of a request.
type ResultHeader struct {
	Schema           string `json:"schema"`
	ResponseHash     string `json:"response_hash"`
	ReceiptBOCBase64 string `json:"receipt_boc_base64"`
}

// Result is a decoded result message: the Receipt and the artifact.
type Result struct {
	Header   ResultHeader
	Receipt  []byte
	Artifact []byte
}

// AckHeader acknowledges a validated result.
type AckHeader struct {
	Schema       string `json:"schema"`
	ResponseHash string `json:"response_hash"`
}

func encodeMessage(header any, body []byte, bound int) ([]byte, error) {
	encoded, err := json.Marshal(header)
	if err != nil {
		return nil, errors.New("servicebridge: encode message header")
	}
	if len(encoded) > maxMessageHeaderBytes {
		return nil, errors.New("servicebridge: message header is oversized")
	}
	out := binary.BigEndian.AppendUint32(make([]byte, 0, 4+len(encoded)+len(body)), uint32(len(encoded)))
	out = append(append(out, encoded...), body...)
	if len(out) > bound {
		return nil, errors.New("servicebridge: message is oversized")
	}
	return out, nil
}

func decodeMessage(raw []byte, bound int, header any) ([]byte, error) {
	if len(raw) < 4 || len(raw) > bound {
		return nil, errors.New("servicebridge: message is outside its bounds")
	}
	length := binary.BigEndian.Uint32(raw[:4])
	if length == 0 || length > maxMessageHeaderBytes || uint64(length) > uint64(len(raw)-4) {
		return nil, errors.New("servicebridge: message header length is invalid")
	}
	headerBytes := raw[4 : 4+length]
	decoder := json.NewDecoder(bytes.NewReader(headerBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(header); err != nil {
		return nil, errors.New("servicebridge: message header does not decode")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("servicebridge: message header has trailing data")
	}
	reencoded, err := json.Marshal(header)
	if err != nil || !bytes.Equal(reencoded, headerBytes) {
		return nil, errors.New("servicebridge: message header is not canonical")
	}
	return raw[4+length:], nil
}

// EncodeTask builds a task message.
func EncodeTask(task Task) ([]byte, error) {
	header := task.Header
	header.Schema = taskSchema
	header.PackageBase64 = base64.StdEncoding.EncodeToString(task.Package)
	sourceDigest := sha256.Sum256(task.Archive)
	header.SourceDigest = "sha256:" + hex.EncodeToString(sourceDigest[:])
	if err := validateTaskHeader(header, len(task.Archive)); err != nil {
		return nil, err
	}
	return encodeMessage(header, task.Archive, maxTaskMessageBytes)
}

// DecodeTask parses a task message and checks the archive against its
// digest and the inline input bound.
func DecodeTask(raw []byte) (Task, error) {
	var header TaskHeader
	archive, err := decodeMessage(raw, maxTaskMessageBytes, &header)
	if err != nil {
		return Task{}, err
	}
	if err = validateTaskHeader(header, len(archive)); err != nil {
		return Task{}, err
	}
	digest := sha256.Sum256(archive)
	if header.SourceDigest != "sha256:"+hex.EncodeToString(digest[:]) {
		return Task{}, errors.New("servicebridge: the source archive does not match its digest")
	}
	pkg, err := base64.StdEncoding.Strict().DecodeString(header.PackageBase64)
	if err != nil || len(pkg) == 0 {
		return Task{}, errors.New("servicebridge: the task Quote package does not decode")
	}
	return Task{Header: header, Package: pkg, Archive: append([]byte(nil), archive...)}, nil
}

func validateTaskHeader(header TaskHeader, archiveBytes int) error {
	if header.Schema != taskSchema || !agentIDPattern.MatchString(header.BuyerAgentID) ||
		!rawAddressPattern.MatchString(header.BuyerWallet) || !capabilityPattern.MatchString(header.CapabilityID) ||
		header.CapabilityVersion == "" || len(header.CapabilityVersion) > 128 || header.PackageBase64 == "" ||
		!hex64Pattern.MatchString(header.ExecutionID) || !sha256Pattern.MatchString(header.SourceDigest) ||
		!hex64Pattern.MatchString(header.CallHash) || header.CallLT == 0 {
		return errors.New("servicebridge: the task header is incomplete")
	}
	if archiveBytes == 0 || archiveBytes > MaxInlineInputBytes {
		return errors.New("servicebridge: the source archive exceeds the advertised 1 MiB inline input or is empty")
	}
	return nil
}

// EncodeResult builds a result message.
func EncodeResult(responseHash [32]byte, receiptBOC, artifact []byte) ([]byte, error) {
	header := ResultHeader{
		Schema: resultSchema, ResponseHash: hex.EncodeToString(responseHash[:]),
		ReceiptBOCBase64: base64.StdEncoding.EncodeToString(receiptBOC),
	}
	if len(receiptBOC) == 0 || len(artifact) == 0 || len(artifact) > MaxResultBytes {
		return nil, errors.New("servicebridge: the result is empty or oversized")
	}
	return encodeMessage(header, artifact, maxResultMessageBytes)
}

// DecodeResult parses a result message.
func DecodeResult(raw []byte) (Result, error) {
	var header ResultHeader
	artifact, err := decodeMessage(raw, maxResultMessageBytes, &header)
	if err != nil {
		return Result{}, err
	}
	if header.Schema != resultSchema || !hex64Pattern.MatchString(header.ResponseHash) ||
		len(artifact) == 0 || len(artifact) > MaxResultBytes {
		return Result{}, errors.New("servicebridge: the result header is incomplete")
	}
	receipt, err := base64.StdEncoding.Strict().DecodeString(header.ReceiptBOCBase64)
	if err != nil || len(receipt) == 0 {
		return Result{}, errors.New("servicebridge: the result Receipt does not decode")
	}
	return Result{Header: header, Receipt: receipt, Artifact: append([]byte(nil), artifact...)}, nil
}

// EncodeAck builds a result acknowledgement.
func EncodeAck(responseHash [32]byte) ([]byte, error) {
	return encodeMessage(
		AckHeader{Schema: ackSchema, ResponseHash: hex.EncodeToString(responseHash[:])},
		nil,
		maxAckMessageBytes,
	)
}

// DecodeAck parses a result acknowledgement.
func DecodeAck(raw []byte) (AckHeader, error) {
	var header AckHeader
	rest, err := decodeMessage(raw, maxAckMessageBytes, &header)
	if err != nil {
		return AckHeader{}, err
	}
	if len(rest) != 0 || header.Schema != ackSchema || !hex64Pattern.MatchString(header.ResponseHash) {
		return AckHeader{}, errors.New("servicebridge: invalid result acknowledgement")
	}
	return header, nil
}

func sha256Sum(value []byte) [32]byte { return sha256.Sum256(value) }
