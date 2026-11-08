package servicebridge

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"math/big"

	"github.com/tosnetwork/tos-ai/pkg/softwarework"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

// ReceiptBinding is everything a Receipt must bind for one request, taken
// from finalized state and the Quote, never from the counterparty.
type ReceiptBinding struct {
	QuoteCommitment string
	ExecutionID     [32]byte
	InputDigest     [32]byte
	SourceDigest    string
	Price           *big.Int
	ProviderAgentID string
	ToolchainDigest string
	SandboxDigest   string
}

func sha256Text(value [32]byte) string { return "sha256:" + hex.EncodeToString(value[:]) }

// BuildReceipt builds the SoftwareWorkReceiptV1 of a successful execution;
// response_hash is the cell hash of the Receipt.
func BuildReceipt(binding ReceiptBinding, outcome softwarework.Outcome) (*cell.Cell, [32]byte, error) {
	var responseHash [32]byte
	if binding.Price == nil || binding.Price.Sign() <= 0 {
		return nil, responseHash, errors.New("servicebridge: the Receipt needs the request price")
	}
	root, _, err := nativecore.BuildSoftwareWorkReceiptCellV1(nativecore.SoftwareWorkReceiptV1{
		QuoteCommitment:     binding.QuoteCommitment,
		ExecutionID:         sha256Text(binding.ExecutionID),
		InputDigest:         sha256Text(binding.InputDigest),
		ResultDigest:        outcome.ResultDigest,
		ArtifactDigest:      outcome.Artifact.Digest,
		ReportDigest:        outcome.Report.Digest,
		SourceDigest:        binding.SourceDigest,
		ToolchainDigest:     binding.ToolchainDigest,
		SandboxDigest:       binding.SandboxDigest,
		ChargedAtomicAmount: binding.Price.String(),
		ProviderAgentID:     binding.ProviderAgentID,
		CompletedAt:         outcome.CompletedAtUnix,
		ExitCode:            int32(outcome.ExitCode),
	})
	if err != nil {
		return nil, responseHash, err
	}
	copy(responseHash[:], root.Hash())
	return root, responseHash, nil
}

// decodeReceipt parses a canonical single-root Receipt BOC and returns its
// fields and cell hash.
func decodeReceipt(boc []byte) (nativecore.SoftwareWorkReceiptV1, [32]byte, error) {
	var hash [32]byte
	if len(boc) == 0 || len(boc) > 4<<10 {
		return nativecore.SoftwareWorkReceiptV1{}, hash, errors.New("servicebridge: the Receipt is outside its bounds")
	}
	root, err := cell.FromBOC(boc)
	if err != nil {
		return nativecore.SoftwareWorkReceiptV1{}, hash, errors.New("servicebridge: the Receipt BOC does not decode")
	}
	receipt, err := nativecore.DecodeSoftwareWorkReceiptCellV1(root)
	if err != nil {
		return nativecore.SoftwareWorkReceiptV1{}, hash, err
	}
	rebuilt, _, err := nativecore.BuildSoftwareWorkReceiptCellV1(receipt)
	if err != nil || !bytes.Equal(rebuilt.Hash(), root.Hash()) {
		return nativecore.SoftwareWorkReceiptV1{}, hash, errors.New("servicebridge: the Receipt is not canonical")
	}
	copy(hash[:], root.Hash())
	return receipt, hash, nil
}

// checkBinding requires the Receipt to bind exactly the request, the charge
// and the provider.
func checkBinding(receipt nativecore.SoftwareWorkReceiptV1, binding ReceiptBinding) error {
	switch {
	case binding.Price == nil:
		return errors.New("servicebridge: no request price to check the Receipt against")
	case receipt.QuoteCommitment != binding.QuoteCommitment:
		return errors.New("servicebridge: the Receipt binds another Quote commitment")
	case receipt.ExecutionID != sha256Text(binding.ExecutionID):
		return errors.New("servicebridge: the Receipt binds another execution")
	case receipt.InputDigest != sha256Text(binding.InputDigest):
		return errors.New("servicebridge: the Receipt binds another input")
	case receipt.SourceDigest != binding.SourceDigest:
		return errors.New("servicebridge: the Receipt binds another source")
	case receipt.ChargedAtomicAmount != binding.Price.String():
		return errors.New("servicebridge: the Receipt charges other than the request price")
	case receipt.ProviderAgentID != binding.ProviderAgentID:
		return errors.New("servicebridge: the Receipt names another provider")
	case receipt.ToolchainDigest != binding.ToolchainDigest || receipt.SandboxDigest != binding.SandboxDigest:
		return errors.New("servicebridge: the Receipt names another toolchain or sandbox than the manifest")
	case receipt.ExitCode != 0 || receipt.CompletedAt == 0:
		return errors.New("servicebridge: the Receipt is not a successful completed execution")
	}
	return nil
}

// CheckAttestable is the attestor policy: the only gate in front of the
// attestor controller. It refuses a Receipt that is not canonical, does not
// bind the verified request exactly, charges other than the price, names
// another provider, or does not describe the runner's actual outcome.
func CheckAttestable(boc []byte, binding ReceiptBinding, outcome softwarework.Outcome) ([32]byte, error) {
	receipt, hash, err := decodeReceipt(boc)
	if err != nil {
		return [32]byte{}, err
	}
	if err := checkBinding(receipt, binding); err != nil {
		return [32]byte{}, err
	}
	if outcome.ExitCode != 0 || receipt.ResultDigest != outcome.ResultDigest ||
		receipt.ArtifactDigest != outcome.Artifact.Digest ||
		receipt.ReportDigest != outcome.Report.Digest ||
		receipt.CompletedAt != outcome.CompletedAtUnix {
		return [32]byte{}, errors.New("servicebridge: the Receipt does not describe the runner's outcome")
	}
	return hash, nil
}

// ValidateResult is the buyer's acceptance: the Receipt hashes to the
// finalized attested response, binds the buyer's own request, and the
// delivered artifact matches every digest the Receipt states.
func ValidateResult(result Result, binding ReceiptBinding, finalizedResponseHash [32]byte) error {
	receipt, hash, err := decodeReceipt(result.Receipt)
	if err != nil {
		return err
	}
	if hash != finalizedResponseHash {
		return errors.New("servicebridge: the Receipt does not hash to the finalized response hash")
	}
	if result.Header.ResponseHash != hex.EncodeToString(hash[:]) {
		return errors.New("servicebridge: the result names another response hash than its Receipt")
	}
	if err = checkBinding(receipt, binding); err != nil {
		return err
	}
	artifact := sha256.Sum256(result.Artifact)
	if receipt.ArtifactDigest != sha256Text(artifact) {
		return errors.New("servicebridge: the artifact does not match the Receipt")
	}
	output, report, err := artifactMembers(result.Artifact)
	if err != nil {
		return err
	}
	if receipt.ResultDigest != sha256Text(sha256.Sum256(output)) ||
		receipt.ReportDigest != sha256Text(sha256.Sum256(report)) {
		return errors.New("servicebridge: the artifact's output or report does not match the Receipt")
	}
	return nil
}

// artifactMembers reads exactly output.log and report.json from the
// software-work artifact tar.
func artifactMembers(artifact []byte) ([]byte, []byte, error) {
	reader := tar.NewReader(bytes.NewReader(artifact))
	members := map[string][]byte{}
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || header.Typeflag != tar.TypeReg || header.Size < 0 || header.Size > MaxResultBytes {
			return nil, nil, errors.New("servicebridge: the artifact is not a bounded tar of regular files")
		}
		if header.Name != "output.log" && header.Name != "report.json" {
			return nil, nil, errors.New("servicebridge: the artifact holds an unexpected member")
		}
		if _, seen := members[header.Name]; seen {
			return nil, nil, errors.New("servicebridge: the artifact repeats a member")
		}
		body, err := io.ReadAll(io.LimitReader(reader, header.Size+1))
		if err != nil || int64(len(body)) != header.Size {
			return nil, nil, errors.New("servicebridge: the artifact member does not read")
		}
		members[header.Name] = body
	}
	output, okOutput := members["output.log"]
	report, okReport := members["report.json"]
	if !okOutput || !okReport {
		return nil, nil, errors.New("servicebridge: the artifact lacks its output or report")
	}
	return output, report, nil
}
