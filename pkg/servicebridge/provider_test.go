package servicebridge

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/quoteexchange"
	"google.golang.org/protobuf/proto"
)

var testNetwork = &nativev1.NetworkDomain{
	NetworkId: "tos-testnet", GenesisRootHash: "sha256:" + strings.Repeat("11", 32),
	GenesisFileHash: "sha256:" + strings.Repeat("22", 32),
}

const testWallet = "0:2121212121212121212121212121212121212121212121212121212121212121"

// testPackage is a Quote package for the OpenFox rail manifest; transport
// overrides the quoted binding when non-nil.
func testPackage(t *testing.T, transport *nativecore.TransportBindingV1) *nativev1.QuoteProposalPackageV1 {
	t.Helper()
	return testPackageFor(t, testSeller, transport)
}

func testPackageFor(
	t *testing.T,
	seller string,
	transport *nativecore.TransportBindingV1,
) *nativev1.QuoteProposalPackageV1 {
	t.Helper()
	attestor := "mldsa44:" + strings.Repeat("99", 32)
	manifestCBOR, digest, _, err := BuildManifest(ManifestInput{
		ProviderAgentID: seller,
		Actor:           "0:" + strings.Repeat("77", 32),
		ActorCodeHash: "tvm-cell-sha256:" + strings.Repeat(
			"88",
			32,
		),
		Attestor:         attestor,
		Version:          "1.0.0",
		RetentionSeconds: 86400,
	})
	if err != nil {
		t.Fatal(err)
	}
	binding, _, err := RailTransport(seller)
	if err != nil {
		t.Fatal(err)
	}
	if transport != nil {
		binding = *transport
	}
	root, transportDigest, err := nativecore.BuildTransportBindingCellV1(binding)
	if err != nil {
		t.Fatal(err)
	}
	return &nativev1.QuoteProposalPackageV1{
		Proposal: &nativev1.QuoteProposalV1{
			ProposalId:             "p-1",
			CapabilityId:           "cap_" + strings.Repeat("33", 32),
			CapabilityVersion:      "1.0.0",
			ProviderAgentId:        seller,
			ManifestDigest:         digest,
			TransportBindingDigest: transportDigest,
			ExpiresAtUnixSeconds:   2_000_001_000,
			Actor:                  &nativev1.TOSAccountAddressV1{AccountId: bytes.Repeat([]byte{0x77}, 32)},
			ActorCodeHash: "tvm-cell-sha256:" + strings.Repeat(
				"88",
				32,
			),
			PolicyVersion:     2,
			TermsHash:         strings.Repeat("ab", 32),
			PriceNanotos:      "300000000",
			StorageFeeNanotos: "200000000",
			AttestorKeyId:     attestor,
		},
		CanonicalManifestCbor: manifestCBOR, TransportBindingBoc: root.ToBOC(),
	}
}

func validatedPackage(t *testing.T, pkg *nativev1.QuoteProposalPackageV1) *quoteexchange.Validated {
	t.Helper()
	validated, err := quoteexchange.Validate(testNetwork, &nativev1.RequestQuoteProposalRequest{
		CapabilityId:      pkg.GetProposal().GetCapabilityId(),
		CapabilityVersion: "1.0.0", BuyerAddress: testWallet,
	}, pkg, time.Unix(2_000_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	return validated
}

func TestTheBuyerRefusesInputOverTheQuotedInlineBoundBeforePaying(t *testing.T) {
	validated := validatedPackage(t, testPackage(t, nil))
	if err := CheckPurchaseQuote(validated, MaxInlineInputBytes); err != nil {
		t.Fatalf("exactly 1 MiB was refused: %v", err)
	}
	if err := CheckPurchaseQuote(validated, MaxInlineInputBytes+1); err != ErrInputTooLarge {
		t.Fatalf("1 MiB + 1: %v", err)
	}
	if err := CheckPurchaseQuote(validated, 0); err != ErrInputTooLarge {
		t.Fatalf("empty input: %v", err)
	}
	small, err := nativecore.AgentPacketTransportBinding(testSeller, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckPurchaseQuote(validatedPackage(t, testPackage(t, &small)), 1001); err != ErrInputTooLarge {
		t.Fatalf("over a smaller quoted bound: %v", err)
	}
	https := nativecore.TransportBindingV1{
		SecurityMode:    nativecore.TransportHTTPS,
		MaxRequestBytes: 1 << 20,
		BaseURL:         "https://provider.example",
	}
	if err := CheckPurchaseQuote(validatedPackage(t, testPackage(t, &https)), 10); err == nil {
		t.Fatal("a Quote that does not deliver as Agent Packets was accepted")
	}
}

var (
	testExecutionNonce = [32]byte{0x4e}
	testExecutionID    = ExecutionIDFor(testBuyer, testExecutionNonce)
)

func taskMessage(t *testing.T, pkg *nativev1.QuoteProposalPackageV1, archive []byte, sender string) (Message, Task) {
	t.Helper()
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(pkg)
	if err != nil {
		t.Fatal(err)
	}
	task := Task{Header: TaskHeader{
		BuyerAgentID: testBuyer, BuyerWallet: testWallet, CapabilityID: pkg.GetProposal().GetCapabilityId(),
		CapabilityVersion: "1.0.0", ExecutionID: hex.EncodeToString(testExecutionID[:]),
		ExecutionNonce: hex.EncodeToString(testExecutionNonce[:]), RequestID: 0, CallLT: 10,
		CallHash: strings.Repeat("0a", 32),
	}, Package: raw, Archive: archive}
	body, err := EncodeTask(task)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeTask(body)
	if err != nil {
		t.Fatal(err)
	}
	return Message{SenderAgentID: sender, Kind: FrameTask, RequestID: 0, Body: body}, decoded
}

func TestTheProviderRefusesATaskBeforeAdmissionUnlessTheQuoteDeliversToIt(t *testing.T) {
	provider := &Provider{config: ProviderConfig{AgentID: testSeller, Network: testNetwork}}
	message, task := taskMessage(t, testPackage(t, nil), fill(100, 1), testBuyer)
	claim, _, _, err := provider.claimFor(message, task)
	if err != nil {
		t.Fatalf("a valid task was refused: %v", err)
	}
	source := task.Archive
	if claim.InputDigest != InputDigest(sha256Sum(source)) ||
		hex.EncodeToString(claim.ExecutionID[:]) != task.Header.ExecutionID {
		t.Fatal("the claim does not bind the task")
	}
	wrongSender := message
	wrongSender.SenderAgentID = "agent_" + strings.Repeat("c3", 32)
	if _, _, _, err = provider.claimFor(wrongSender, task); err == nil {
		t.Error("a task from another Agent than its buyer was admitted")
	}
	otherRequest := message
	otherRequest.RequestID = 1
	if _, _, _, err = provider.claimFor(otherRequest, task); err == nil {
		t.Error("frames bound to another request were admitted")
	}
	elsewhere, err := nativecore.AgentPacketTransportBinding("agent_"+strings.Repeat("c3", 32), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	pkg := testPackage(t, &elsewhere)
	if m, tk := taskMessage(t, pkg, fill(100, 1), testBuyer); true {
		if _, _, _, err = provider.claimFor(m, tk); err == nil {
			t.Error("a Quote delivering to another Agent was admitted")
		}
	}
	other := "agent_" + strings.Repeat("c3", 32)
	if m, tk := taskMessage(t, testPackageFor(t, other, nil), fill(100, 1), testBuyer); true {
		if _, _, _, err = provider.claimFor(m, tk); err == nil {
			t.Error("a task under another provider's Quote was admitted")
		}
	}
	small, err := nativecore.AgentPacketTransportBinding(testSeller, 50)
	if err != nil {
		t.Fatal(err)
	}
	if m, tk := taskMessage(t, testPackage(t, &small), fill(100, 1), testBuyer); true {
		if _, _, _, err := provider.claimFor(m, tk); err == nil {
			t.Error("an archive over the quoted bound was admitted")
		}
	}
}
