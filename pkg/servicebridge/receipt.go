package servicebridge

import (
	"encoding/hex"

	"github.com/tosnetwork/ai/execution/pkg/softwarework"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/railwork"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

// ReceiptBinding is everything a Receipt must bind for one request, taken
// from finalized state and the Quote, never from the counterparty.
type ReceiptBinding = railwork.ReceiptBinding

func sha256Text(value [32]byte) string { return "sha256:" + hex.EncodeToString(value[:]) }

func outcomeOf(outcome softwarework.Outcome) railwork.Outcome {
	return railwork.Outcome{
		ResultDigest: outcome.ResultDigest, ArtifactDigest: outcome.Artifact.Digest,
		ReportDigest: outcome.Report.Digest, CompletedAtUnix: outcome.CompletedAtUnix, ExitCode: outcome.ExitCode,
	}
}

// BuildReceipt builds the SoftwareWorkReceiptV1 of a successful execution;
// response_hash is the cell hash of the Receipt.
func BuildReceipt(binding ReceiptBinding, outcome softwarework.Outcome) (*cell.Cell, [32]byte, error) {
	return railwork.BuildReceipt(binding, outcomeOf(outcome))
}

// decodeReceipt parses a canonical single-root Receipt BOC and returns its
// fields and cell hash.
func decodeReceipt(boc []byte) (nativecore.SoftwareWorkReceiptV1, [32]byte, error) {
	return railwork.DecodeReceipt(boc)
}

// CheckAttestable is the attestor policy: the only gate in front of the
// attestor controller. It refuses a Receipt that is not canonical, does not
// bind the verified request exactly, charges other than the price, names
// another provider, or does not describe the runner's actual outcome.
func CheckAttestable(boc []byte, binding ReceiptBinding, outcome softwarework.Outcome) ([32]byte, error) {
	return railwork.CheckAttestable(boc, binding, outcomeOf(outcome))
}

// ValidateResult is the buyer's acceptance: the Receipt hashes to the
// finalized attested response, binds the buyer's own request, and the
// delivered artifact matches every digest the Receipt states.
func ValidateResult(result Result, binding ReceiptBinding, finalizedResponseHash [32]byte) error {
	return railwork.ValidateResult(railwork.Result{Header: result.Header, Receipt: result.Receipt,
		Artifact: result.Artifact}, binding, finalizedResponseHash)
}

// artifactMembers reads exactly output.log and report.json from the
// software-work artifact tar.
func artifactMembers(artifact []byte) ([]byte, []byte, error) {
	return railwork.ArtifactMembers(artifact)
}
