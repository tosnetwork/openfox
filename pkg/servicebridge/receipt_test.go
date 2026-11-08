package servicebridge

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/tosnetwork/tos-ai/pkg/artifactstore"
	"github.com/tosnetwork/tos-ai/pkg/softwarework"
)

func testArtifact(t *testing.T, members map[string][]byte, order []string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, name := range order {
		body := members[name]
		if err := writer.WriteHeader(
			&tar.Header{Name: name, Mode: 0o444, Size: int64(len(body)), Format: tar.FormatUSTAR},
		); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func digestText(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

type receiptCase struct {
	binding  ReceiptBinding
	outcome  softwarework.Outcome
	artifact []byte
	boc      []byte
	hash     [32]byte
}

func newReceiptCase(t *testing.T) receiptCase {
	t.Helper()
	output, report := []byte("ok  ./...\n"), []byte(`{"schema":"tos.service.software-work-report.v1"}`)
	artifact := testArtifact(
		t,
		map[string][]byte{"output.log": output, "report.json": report},
		[]string{"output.log", "report.json"},
	)
	binding := ReceiptBinding{
		QuoteCommitment: "tvm-cell-sha256:" + strings.Repeat("aa", 32),
		ExecutionID:     [32]byte{1},
		InputDigest:     [32]byte{2},
		SourceDigest:    "sha256:" + strings.Repeat("33", 32),
		Price:           big.NewInt(300_000_000),
		ProviderAgentID: testSeller,
		ToolchainDigest: "sha256:" + strings.Repeat("44", 32),
		SandboxDigest:   "sha256:" + strings.Repeat("55", 32),
	}
	outcome := softwarework.Outcome{
		ResultDigest: digestText(output), Artifact: artifactstore.Descriptor{Digest: digestText(artifact)},
		Report: artifactstore.Descriptor{Digest: digestText(report)}, ExitCode: 0, CompletedAtUnix: 2_000_000_000,
	}
	root, hash, err := BuildReceipt(binding, outcome)
	if err != nil {
		t.Fatal(err)
	}
	return receiptCase{binding: binding, outcome: outcome, artifact: artifact, boc: root.ToBOC(), hash: hash}
}

func TestTheAttestorPolicyAdmitsOnlyAReceiptOfTheVerifiedRequestAndItsOutcome(t *testing.T) {
	c := newReceiptCase(t)
	hash, err := CheckAttestable(c.boc, c.binding, c.outcome)
	if err != nil || hash != c.hash {
		t.Fatalf("attestable: %v", err)
	}
	for name, edit := range map[string]func(*ReceiptBinding, *softwarework.Outcome){
		"other quote": func(b *ReceiptBinding, _ *softwarework.Outcome) {
			b.QuoteCommitment = "tvm-cell-sha256:" + strings.Repeat("ab", 32)
		},
		"other execution": func(b *ReceiptBinding, _ *softwarework.Outcome) { b.ExecutionID = [32]byte{9} },
		"other input":     func(b *ReceiptBinding, _ *softwarework.Outcome) { b.InputDigest = [32]byte{9} },
		"other source": func(b *ReceiptBinding, _ *softwarework.Outcome) {
			b.SourceDigest = "sha256:" + strings.Repeat("34", 32)
		},
		"other price":    func(b *ReceiptBinding, _ *softwarework.Outcome) { b.Price = big.NewInt(300_000_001) },
		"other provider": func(b *ReceiptBinding, _ *softwarework.Outcome) { b.ProviderAgentID = testBuyer },
		"other toolchain": func(b *ReceiptBinding, _ *softwarework.Outcome) {
			b.ToolchainDigest = "sha256:" + strings.Repeat("45", 32)
		},
		"other sandbox": func(b *ReceiptBinding, _ *softwarework.Outcome) {
			b.SandboxDigest = "sha256:" + strings.Repeat("56", 32)
		},
		"failed run": func(_ *ReceiptBinding, o *softwarework.Outcome) { o.ExitCode = 1 },
		"other result": func(_ *ReceiptBinding, o *softwarework.Outcome) {
			o.ResultDigest = "sha256:" + strings.Repeat("66", 32)
		},
		"other artifact": func(_ *ReceiptBinding, o *softwarework.Outcome) {
			o.Artifact.Digest = "sha256:" + strings.Repeat("66", 32)
		},
		"other report": func(_ *ReceiptBinding, o *softwarework.Outcome) {
			o.Report.Digest = "sha256:" + strings.Repeat("66", 32)
		},
		"other time": func(_ *ReceiptBinding, o *softwarework.Outcome) { o.CompletedAtUnix++ },
		"no price":   func(b *ReceiptBinding, _ *softwarework.Outcome) { b.Price = nil },
	} {
		binding, outcome := c.binding, c.outcome
		edit(&binding, &outcome)
		if _, err := CheckAttestable(c.boc, binding, outcome); err == nil {
			t.Errorf("%s: attestable", name)
		}
	}
	failed := c.outcome
	failed.ExitCode = 1
	if _, _, err := BuildReceipt(c.binding, failed); err == nil {
		t.Error("a Receipt was built for a failed run")
	}
	if _, err := CheckAttestable(append(c.boc, 0), c.binding, c.outcome); err == nil {
		t.Error("a BOC with trailing bytes was attestable")
	}
}

func TestTheBuyerAcceptsOnlyAResultThatHashesToTheFinalizedResponse(t *testing.T) {
	c := newReceiptCase(t)
	result := Result{
		Header: ResultHeader{Schema: resultSchema, ResponseHash: hex.EncodeToString(c.hash[:])}, Receipt: c.boc,
		Artifact: c.artifact,
	}
	if err := ValidateResult(result, c.binding, c.hash); err != nil {
		t.Fatal(err)
	}
	if err := ValidateResult(
		result,
		c.binding,
		[32]byte{7},
	); err == nil ||
		!strings.Contains(err.Error(), "finalized response hash") {
		t.Fatalf("a Receipt not matching the finalized response hash: %v", err)
	}
	other := c.binding
	other.Price = big.NewInt(1)
	if err := ValidateResult(result, other, c.hash); err == nil {
		t.Error("a Receipt charging other than the quoted price was accepted")
	}
	other = c.binding
	other.ExecutionID = [32]byte{8}
	if err := ValidateResult(result, other, c.hash); err == nil {
		t.Error("a Receipt of another execution was accepted")
	}
	tampered := result
	tampered.Artifact = append([]byte(nil), c.artifact...)
	tampered.Artifact[600] ^= 1
	if err := ValidateResult(tampered, c.binding, c.hash); err == nil {
		t.Error("a tampered artifact was accepted")
	}
	header := result
	header.Header.ResponseHash = strings.Repeat("00", 32)
	if err := ValidateResult(header, c.binding, c.hash); err == nil {
		t.Error("a result naming another response hash was accepted")
	}
	// An artifact with the right digest for its Receipt but an extra member.
	extra := testArtifact(t, map[string][]byte{
		"output.log":  []byte("ok  ./...\n"),
		"report.json": []byte(`{"schema":"tos.service.software-work-report.v1"}`), "x": []byte("x"),
	},
		[]string{"output.log", "report.json", "x"})
	if _, _, err := artifactMembers(extra); err == nil {
		t.Error("an artifact with an unexpected member was read")
	}
}

func TestCostsDiscloseTheAllowanceAndTheNonRefundableStorageFee(t *testing.T) {
	costs, err := QuoteCosts(big.NewInt(300_000_000), big.NewInt(200_000_000), 3600, 3600, big.NewInt(300_000_000))
	if err != nil {
		t.Fatal(err)
	}
	if costs.Attached.Cmp(big.NewInt(700_000_000)) != 0 || costs.Allowance.Cmp(big.NewInt(200_000_000)) != 0 ||
		costs.Committed.Cmp(
			big.NewInt(1_000_000_000),
		) != 0 || costs.LossIfUnanswered.Cmp(big.NewInt(500_000_000)) != 0 {
		t.Fatalf("costs = %+v", costs)
	}
	text := costs.Disclosure()
	for _, want := range []string{"non-refundable", "0.700000000 TOS", "two transactions", "expire then claim_refund", "0.200000000 TOS"} {
		if !strings.Contains(text, want) {
			t.Errorf("the disclosure lacks %q: %s", want, text)
		}
	}
}

func TestSpendingPolicyBoundsEveryPurchase(t *testing.T) {
	policy := SpendingPolicy{
		MaxCommittedPerPurchase: big.NewInt(1_000_000_000), MaxCommittedInWindow: big.NewInt(2_000_000_000),
		Window: 24 * 3600e9, MaxOpenPurchases: 2, ConfirmAbove: big.NewInt(900_000_000),
		AllowedProviders: map[string]bool{testSeller: true}, RefundReserve: big.NewInt(300_000_000),
	}
	costs, err := QuoteCosts(big.NewInt(300_000_000), big.NewInt(200_000_000), 3600, 3600, policy.RefundReserve)
	if err != nil {
		t.Fatal(err)
	}
	small, err := QuoteCosts(big.NewInt(100_000_000), big.NewInt(100_000_000), 3600, 3600, policy.RefundReserve)
	if err != nil {
		t.Fatal(err)
	}
	if err = policy.Authorize(testSeller, small, big.NewInt(0), 0); err != nil {
		t.Fatalf("a purchase within every bound: %v", err)
	}
	for name, check := range map[string]error{
		"confirm":  policy.Authorize(testSeller, costs, big.NewInt(0), 0),
		"provider": policy.Authorize(testBuyer, small, big.NewInt(0), 0),
		"window":   policy.Authorize(testSeller, small, big.NewInt(1_500_000_000), 0),
		"open":     policy.Authorize(testSeller, small, big.NewInt(0), 2),
	} {
		if check == nil {
			t.Errorf("%s: authorized", name)
		}
	}
	over, err := QuoteCosts(big.NewInt(600_000_000), big.NewInt(200_000_000), 3600, 3600, policy.RefundReserve)
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.Authorize(testSeller, over, big.NewInt(0), 0); err != ErrOverPurchaseLimit {
		t.Errorf("over the per-purchase limit: %v", err)
	}
	if (SpendingPolicy{}).Validate() == nil {
		t.Error("an empty policy validated")
	}
}
