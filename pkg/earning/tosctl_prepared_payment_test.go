package earning

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
)

func TestValidateTOSCTLPreparedPaymentBindsFullNetworkDomain(t *testing.T) {
	digest := "sha256:" + strings.Repeat("1", 64)
	boc := []byte("prepared-payment-boc")
	bocDigest := sha256.Sum256(boc)
	network := commerce.CustodyNetworkDomain{NetworkID: "tos:local", GlobalID: 3,
		ZeroStateRootHash: "sha256:" + strings.Repeat("2", 64),
		ZeroStateFileHash: "sha256:" + strings.Repeat("3", 64), WorkchainID: 0}
	request := commerce.AgreementPaymentRequest{StableActionID: digest, AgreementBodyDigest: digest,
		ObligationInstanceID: digest, Destination: []byte("0:destination"), ExpiresAtUnix: 1_800_000_000}
	prepared := tosctlPaymentPrepared{Schema: "tosctl.agent-account.agreement-payment-prepared.v1",
		StableActionID: digest, AgreementBodyDigest: digest, ObligationInstanceID: digest,
		Account: "0:source", Target: "0:destination", AmountNanoTOS: 7, NetworkGlobalID: 3,
		NetworkDomain: agentrelay.NetworkDomain{NetworkID: network.NetworkID, GlobalID: network.GlobalID,
			ZeroStateRootHash: network.ZeroStateRootHash, ZeroStateFileHash: network.ZeroStateFileHash,
			WorkchainID: network.WorkchainID}, ValidUntil: uint32(request.ExpiresAtUnix),
		ActionKind: "agent-native-send", ExactSignedBOC: base64.StdEncoding.EncodeToString(boc),
		ExactSignedBOCDigest: "sha256:" + hex.EncodeToString(bocDigest[:])}
	if err := validateTOSCTLPreparedPayment(prepared, request, network, "0:source", 7, false); err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*tosctlPaymentPrepared){
		"network ID":          func(value *tosctlPaymentPrepared) { value.NetworkDomain.NetworkID = "tos:other" },
		"global ID":           func(value *tosctlPaymentPrepared) { value.NetworkDomain.GlobalID++ },
		"zero-state root":     func(value *tosctlPaymentPrepared) { value.NetworkDomain.ZeroStateRootHash = digest },
		"zero-state file":     func(value *tosctlPaymentPrepared) { value.NetworkDomain.ZeroStateFileHash = digest },
		"workchain":           func(value *tosctlPaymentPrepared) { value.NetworkDomain.WorkchainID++ },
		"legacy missing pin":  func(value *tosctlPaymentPrepared) { value.NetworkDomain = agentrelay.NetworkDomain{} },
		"changed valid-until": func(value *tosctlPaymentPrepared) { value.ValidUntil++ },
		"changed BOC": func(value *tosctlPaymentPrepared) {
			value.ExactSignedBOC = base64.StdEncoding.EncodeToString([]byte("other"))
		},
		"invalid BOC encoding": func(value *tosctlPaymentPrepared) {
			value.ExactSignedBOC = "not-base64"
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := prepared
			mutate(&changed)
			if err := validateTOSCTLPreparedPayment(changed, request, network, "0:source", 7, false); err == nil {
				t.Fatal("mutated prepared payment was accepted")
			}
		})
	}
}

func TestValidateTOSCTLPreparedPaymentSeparatesSponsoredActions(t *testing.T) {
	digest := "sha256:" + strings.Repeat("4", 64)
	boc := []byte("sponsored-payment-boc")
	bocDigest := sha256.Sum256(boc)
	network := commerce.CustodyNetworkDomain{NetworkID: "tos:local", GlobalID: 3,
		ZeroStateRootHash: digest, ZeroStateFileHash: "sha256:" + strings.Repeat("5", 64)}
	request := commerce.AgreementPaymentRequest{StableActionID: digest, AgreementBodyDigest: digest,
		ObligationInstanceID: digest, Destination: []byte("0:destination"), ExpiresAtUnix: 1_800_000_000}
	commitment := "tvm-cell-sha256:" + strings.Repeat("6", 64)
	prepared := tosctlPaymentPrepared{Schema: "tosctl.agent-account.agreement-payment-prepared.v1",
		StableActionID: digest, AgreementBodyDigest: digest, ObligationInstanceID: digest,
		Account: "0:source", Target: "0:destination", AmountNanoTOS: 7, NetworkGlobalID: 3,
		NetworkDomain: agentrelay.NetworkDomain{NetworkID: network.NetworkID, GlobalID: network.GlobalID,
			ZeroStateRootHash: network.ZeroStateRootHash, ZeroStateFileHash: network.ZeroStateFileHash},
		ValidUntil: uint32(request.ExpiresAtUnix), ActionKind: "agent-task-send",
		SponsorshipCommitmentBodyHash: &commitment, ExactSignedBOC: base64.StdEncoding.EncodeToString(boc),
		ExactSignedBOCDigest: "sha256:" + hex.EncodeToString(bocDigest[:])}
	if err := validateTOSCTLPreparedPayment(prepared, request, network, "0:source", 7, true); err != nil {
		t.Fatal(err)
	}
	if err := validateTOSCTLPreparedPayment(prepared, request, network, "0:source", 7, false); err == nil {
		t.Fatal("sponsored action was accepted as an ordinary payment")
	}
	invalidCommitment := prepared
	invalid := "tvm-cell-sha256:1"
	invalidCommitment.SponsorshipCommitmentBodyHash = &invalid
	if err := validateTOSCTLPreparedPayment(invalidCommitment, request, network, "0:source", 7, true); err == nil {
		t.Fatal("non-canonical sponsorship commitment was accepted")
	}
}
