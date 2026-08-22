package nativeimpl

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/buyersdk"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
	"google.golang.org/protobuf/proto"
)

func artifactPreparedPurchase(t *testing.T) *buyersdk.PreparedPurchase {
	t.Helper()
	manifest := []byte{0xa1, 0x61, 0x61, 0x01}
	manifestHash := sha256.Sum256(manifest)
	manifestDigest := "sha256:" + hex.EncodeToString(manifestHash[:])
	network := &nativev1.NetworkDomain{
		NetworkId:       "tos-local",
		GenesisRootHash: "sha256:" + strings.Repeat("1", 64), GenesisFileHash: "sha256:" + strings.Repeat("2", 64),
	}
	walletCode := cell.BeginCell().MustStoreUInt(0xaaaa, 16).EndCell()
	escrowCode := cell.BeginCell().MustStoreUInt(0xeeee, 16).EndCell()
	terms := nativecore.EscrowTermsV1{
		BuyerAddress:    "0:" + strings.Repeat("3", 64),
		ProviderAddress: "0:" + strings.Repeat("4", 64), FundingDeadline: uint64(time.Now().Add(time.Hour).Unix()),
		RefundAvailableAt: uint64(time.Now().Add(2 * time.Hour).Unix()),
	}
	termsCell, err := nativecore.BuildEscrowTermsCellV1(terms)
	if err != nil {
		t.Fatal(err)
	}
	transport := nativecore.TransportBindingV1{
		SecurityMode: 0, MaxRequestBytes: 1 << 20,
		BaseURL: "http://127.0.0.1:18080",
	}
	_, transportDigest, err := nativecore.BuildTransportBindingCellV1(transport)
	if err != nil {
		t.Fatal(err)
	}
	_, disputeDigest := nativecore.BuildObjectiveDisputePolicyCellV1()
	asset := &nativev1.TOSAssetIdentityV1{
		Master: &nativev1.TOSContractIdentityV1{
			Workchain: 0,
			AccountId: bytes.Repeat([]byte{0x55}, 32), CodeHash: "tvm-cell-sha256:" + strings.Repeat("6", 64),
		},
		WalletCodeHash: cellHashDigest(walletCode), Decimals: 9,
	}
	proposal := &nativev1.QuoteProposalV1{
		ProposalId: "proposal-artifact", CapabilityId: "cap_" + strings.Repeat("7", 64),
		CapabilityVersion: "1.0.0", ProviderAgentId: "agent_" + strings.Repeat("8", 64), ManifestDigest: manifestDigest,
		TransportBindingDigest: transportDigest, EscrowTermsDigest: "sha256:" + hex.EncodeToString(termsCell.Hash()),
		DisputePolicyDigest: disputeDigest, ExpiresAtUnixSeconds: terms.FundingDeadline,
		MaximumPrice: &nativev1.MoneyV1{Asset: asset, AtomicAmount: "25000000"},
	}
	signer := bytes.Repeat([]byte{0xbb}, 32)
	authorization, err := nativecore.BuildEscrowAuthorizationCellV1(signer)
	if err != nil {
		t.Fatal(err)
	}
	quote, commitment, err := nativecore.BuildAcceptedQuoteCommitment(network, proposal,
		"sha256:"+hex.EncodeToString(authorization.Hash()))
	if err != nil {
		t.Fatal(err)
	}
	master := "0:" + hex.EncodeToString(asset.Master.AccountId)
	identity, err := nativecore.BuildEscrowStateInitV1(0, escrowCode, nativecore.EscrowInitV1{
		AcceptedQuote: quote, Terms: terms, ExecutionSignerEd25519: signer,
		TransportBinding: transport, AssetMasterAddress: master, AssetWalletCode: walletCode,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &buyersdk.PreparedPurchase{
		Proposal: proposal, ManifestCBOR: manifest, ManifestDigest: manifestDigest,
		QuoteCommitment: commitment, QuoteBOCBase64: identityQuoteBOC(quote), Escrow: identity,
		AssetMasterAddress: master, BuyerWalletAddress: "0:" + strings.Repeat("9", 64), AmountAtomic: "25000000",
	}
}

func identityQuoteBOC(quote *cell.Cell) string {
	return base64.StdEncoding.EncodeToString(quote.ToBOC())
}

func TestPreparedPurchaseArtifactRoundTrip(t *testing.T) {
	want := artifactPreparedPurchase(t)
	encoded, err := MarshalPreparedPurchase(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalPreparedPurchase(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(got.Proposal, want.Proposal) || !bytes.Equal(got.ManifestCBOR, want.ManifestCBOR) ||
		got.QuoteCommitment != want.QuoteCommitment || got.Escrow.Address != want.Escrow.Address ||
		!bytes.Equal(got.Escrow.Data.Hash(), want.Escrow.Data.Hash()) {
		t.Fatalf("round trip changed purchase: %+v", got)
	}
}

func TestPurchaseInputFromPreparedPurchaseUsesTypedEscrowPreimage(t *testing.T) {
	purchase := artifactPreparedPurchase(t)
	input, err := PurchaseInputFromPreparedPurchase(purchase)
	if err != nil {
		t.Fatal(err)
	}
	state, err := nativecore.DecodeEscrowDataV1(purchase.Escrow.Data)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(input.Proposal, purchase.Proposal) || !bytes.Equal(input.ManifestCBOR, purchase.ManifestCBOR) ||
		input.EscrowTerms.BuyerAddress != state.BuyerAddress || input.EscrowTerms.ProviderAddress != state.ProviderAddress ||
		!bytes.Equal(
			input.ExecutionSignerEd25519,
			state.ExecutionSignerEd25519,
		) || input.TransportBinding != state.TransportBinding {
		t.Fatalf("input = %+v", input)
	}
}

func TestPreparedPurchaseArtifactRejectsIntegrityAndLinkedSubstitution(t *testing.T) {
	encoded, err := MarshalPreparedPurchase(artifactPreparedPurchase(t))
	if err != nil {
		t.Fatal(err)
	}
	changed := bytes.Replace(encoded, []byte(`"amount_atomic": "25000000"`), []byte(`"amount_atomic": "25000001"`), 1)
	if _, err := UnmarshalPreparedPurchase(changed); err == nil {
		t.Fatal("artifact accepted bytes changed without a new integrity digest")
	}

	var envelope preparedPurchaseEnvelope
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		t.Fatal(err)
	}
	var payload preparedPurchasePayload
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	payload.AssetMasterAddress = "0:" + strings.Repeat("a", 64)
	envelope.Payload, _ = json.Marshal(payload)
	envelope.IntegrityDigest, _ = preparedPayloadDigest(envelope.Payload)
	forged, _ := json.Marshal(envelope)
	if _, err := UnmarshalPreparedPurchase(forged); err == nil {
		t.Fatal("artifact accepted a re-digested linked asset substitution")
	}
}

func TestPreparedPurchaseArtifactRejectsUnknownEnvelopeField(t *testing.T) {
	encoded, err := MarshalPreparedPurchase(artifactPreparedPurchase(t))
	if err != nil {
		t.Fatal(err)
	}
	encoded = bytes.Replace(encoded, []byte("{\n"), []byte("{\n  \"authority\": true,\n"), 1)
	if _, err := UnmarshalPreparedPurchase(encoded); err == nil {
		t.Fatal("artifact accepted an unknown authority field")
	}
}

func TestPreparedEscrowDeploymentArtifactRoundTripAndIntegrity(t *testing.T) {
	deployment := &buyersdk.PreparedEscrowDeployment{
		Schema:        "tos.service.escrow-deployment.v1",
		EscrowAddress: "0:" + strings.Repeat("1", 64), QuoteCommitment: "tvm-cell-sha256:" + strings.Repeat("2", 64),
		StateInitBOCBase64: "te6ccgEBAQEAAgAAAA==", StateInitHash: "tvm-cell-sha256:" + strings.Repeat("3", 64),
		AttachedNanoTOS: 100_000_000, MessageBOCBase64: "te6ccgEBAQEAAgAAAA==",
		MessageHash: "tvm-cell-sha256:" + strings.Repeat("4", 64),
	}
	encoded, err := MarshalPreparedEscrowDeployment(deployment)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalPreparedEscrowDeployment(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if *got != *deployment {
		t.Fatalf("deployment = %+v", got)
	}
	changed := bytes.Replace(encoded, []byte("100000000"), []byte("100000001"), 1)
	if _, err := UnmarshalPreparedEscrowDeployment(changed); err == nil {
		t.Fatal("deployment artifact accepted changed attached value")
	}
}
