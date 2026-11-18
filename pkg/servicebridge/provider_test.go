package servicebridge

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/quoteexchange"
	"github.com/tosnetwork/ai/protocol/pkg/railwork"
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
	testExecutionID    = mustExecutionID(testBuyer, testExecutionNonce)
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
	return taskMessageOf(t, task, sender), task
}

// taskMessageOf frames a task as its buyer sends it: bound to the request
// hash and actor the task and its Quote derive, in packets naming its
// Capability and Accepted Quote commitment.
func taskMessageOf(t *testing.T, task Task, sender string) Message {
	t.Helper()
	body, err := EncodeTask(task)
	if err != nil {
		t.Fatal(err)
	}
	message := Message{SenderAgentID: sender, Kind: FrameTask, RequestID: task.Header.RequestID, Body: body}
	pkg := &nativev1.QuoteProposalPackageV1{}
	if proto.Unmarshal(task.Package, pkg) != nil || pkg.GetProposal() == nil {
		return message
	}
	quoteHash, commitment, err := railwork.QuoteCommitment(testNetwork, pkg.GetProposal())
	if err != nil {
		return message
	}
	executionID, okID := decodeHex32Test(task.Header.ExecutionID)
	if !okID {
		return message
	}
	requestHash, err := railwork.RequestHash(quoteHash, executionID, InputDigest(sha256Sum(task.Archive)))
	if err != nil {
		return message
	}
	message.RequestHash = requestHash
	copy(message.ActorAccount[:], pkg.GetProposal().GetActor().GetAccountId())
	message.Packet = PacketFields{CapabilityID: task.Header.CapabilityID, QuoteCommitment: commitment}
	return message
}

func decodeHex32Test(text string) ([32]byte, bool) {
	var out [32]byte
	raw, err := hex.DecodeString(text)
	if err != nil || len(raw) != 32 {
		return out, false
	}
	copy(out[:], raw)
	return out, true
}

// testRailProvider is a provider configured for the test Capability.
func testRailProvider() *Provider {
	return &Provider{config: ProviderConfig{AgentID: testSeller, Network: testNetwork, CapabilityID: gfCapability,
		Version: "1.0.0"}}
}

func TestTheProviderRefusesATaskBeforeAdmissionUnlessTheQuoteDeliversToIt(t *testing.T) {
	provider := testRailProvider()
	message, task := taskMessage(t, testPackage(t, nil), fill(100, 1), testBuyer)
	claim, _, err := provider.claimFor(message)
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
	if _, _, err = provider.claimFor(wrongSender); err == nil {
		t.Error("a task from another Agent than its buyer was admitted")
	}
	otherRequest := message
	otherRequest.RequestID = 1
	if _, _, err = provider.claimFor(otherRequest); err == nil {
		t.Error("frames bound to another request were admitted")
	}
	elsewhere, err := nativecore.AgentPacketTransportBinding("agent_"+strings.Repeat("c3", 32), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	pkg := testPackage(t, &elsewhere)
	if m, _ := taskMessage(t, pkg, fill(100, 1), testBuyer); true {
		if _, _, err = provider.claimFor(m); err == nil {
			t.Error("a Quote delivering to another Agent was admitted")
		}
	}
	other := "agent_" + strings.Repeat("c3", 32)
	if m, _ := taskMessage(t, testPackageFor(t, other, nil), fill(100, 1), testBuyer); true {
		if _, _, err = provider.claimFor(m); err == nil {
			t.Error("a task under another provider's Quote was admitted")
		}
	}
	small, err := nativecore.AgentPacketTransportBinding(testSeller, 50)
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := taskMessage(t, testPackage(t, &small), fill(100, 1), testBuyer); true {
		if _, _, err := provider.claimFor(m); err == nil {
			t.Error("an archive over the quoted bound was admitted")
		}
	}
}

// mustExecutionID is ExecutionIDFor for the fixed, valid test Agents.
func mustExecutionID(agentID string, nonce [32]byte) [32]byte {
	id, err := ExecutionIDFor(agentID, nonce)
	if err != nil {
		panic(err)
	}
	return id
}

// testPacket is the packet fields a buyer sets for the default test
// purchase: the test Capability and the Accepted Quote of testPackage.
func testPacket(t *testing.T) PacketFields {
	t.Helper()
	_, commitment, err := railwork.QuoteCommitment(testNetwork, testPackage(t, nil).GetProposal())
	if err != nil {
		t.Fatal(err)
	}
	return PacketFields{CapabilityID: gfCapability, QuoteCommitment: commitment}
}
