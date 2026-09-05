package earning

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
	protocol "github.com/tosnetwork/tos-service-protocol/pkg/predictionmarket"

	"github.com/tosnetwork/openfox/pkg/prediction"
)

type predictionContextTestAuthority struct{ EconomicAuthority }

func predictionContextHash(value byte) protocol.Hash32 {
	var result protocol.Hash32
	for index := range result {
		result[index] = value
	}
	return result
}

func predictionContextDigest(prefix string, value byte) string {
	return prefix + strings.Repeat(hex.EncodeToString([]byte{value}), 32)
}

func normalPredictionContextView(t *testing.T, profile prediction.OracleProfile,
	relay prediction.PredictionRelayProfile,
) []byte {
	t.Helper()
	marketID, err := protocol.ParseHash32(profile.MarketID)
	if err != nil {
		t.Fatal(err)
	}
	rulesHash, err := protocol.ParseHash32(profile.RulesHash)
	if err != nil {
		t.Fatal(err)
	}
	contextCell, err := protocol.BuildPredictionNormalContextCell(protocol.PredictionNormalContextV1{
		MarketID: marketID, RulesHash: rulesHash, NormalRoundNonce: predictionContextHash(0x44),
		NormalRoundOpenedAt: 1_800_000_100, ResolveNotBefore: 1_800_000_000,
		OracleVoteDeadline: 1_800_000_300,
	})
	if err != nil {
		t.Fatal(err)
	}
	contextBOC := contextCell.ToBOCWithFlags(false)
	contextHash := oracleCellHash(contextCell)
	encoded := base64.StdEncoding.EncodeToString(contextBOC)
	view := tosctlPredictionMarketChainView{
		Schema: predictionMarketChainViewSchema, Address: profile.MarketAddress,
		GlobalVersion: 14, CodeHashVerified: true, ConfigHashVerified: true,
		Activated: true, ActivatedAt: 1_799_999_000, Status: "reporting",
		MarketID: hex.EncodeToString(marketID[:]), MarketConfigHash: trimCellHash(relay.MarketConfigHash),
		CurrentContextHash: hex.EncodeToString(contextHash[:]), CurrentContextBOCBase64: &encoded,
		ReviewBaseContextHash: strings.Repeat("0", 64), NextDeadline: 1_800_000_300,
		ProposedStatementHash: strings.Repeat("0", 64),
	}
	view.Checkpoint.Seqno = 77
	view.Checkpoint.RootHash = strings.Repeat("a1", 32)
	view.Checkpoint.FileHash = strings.Repeat("a2", 32)
	raw, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func predictionContextObserverFixture(t *testing.T) (*TOSCTLPaymentSink,
	prediction.OracleProfile, []byte, func(),
) {
	t.Helper()
	directory := privateTempDir(t)
	configs := []string{
		filepath.Join(directory, "node-1.json"),
		filepath.Join(directory, "node-2.json"),
		filepath.Join(directory, "node-3.json"),
	}
	network := agentrelay.NetworkDomain{
		NetworkID: "tos:prediction-context-test", GlobalID: 42,
		ZeroStateRootHash: predictionContextDigest("sha256:", 0x11),
		ZeroStateFileHash: predictionContextDigest("sha256:", 0x12), WorkchainID: 0,
	}
	networkDigest, err := agentrelay.NetworkDomainDigest(network)
	if err != nil {
		t.Fatal(err)
	}
	marketID := predictionContextHash(0x21)
	rulesHash := predictionContextHash(0x22)
	market := "0:" + strings.Repeat("2", 64)
	relayProfile := prediction.PredictionRelayProfile{
		NetworkDomainHash:          networkDigest,
		SourceAgentAccount:         "0:" + strings.Repeat("1", 64),
		SourceAgentAccountCodeHash: predictionContextDigest("tvm-cell-sha256:", 0x31),
		MarketAddress:              market, MarketID: marketID.SHA256String(),
		MarketCodeHash:   predictionContextDigest("tvm-cell-sha256:", 0x32),
		MarketConfigHash: predictionContextDigest("tvm-cell-sha256:", 0x33),
		ObserverIDs: []string{
			predictionContextDigest("sha256:", 0x41),
			predictionContextDigest("sha256:", 0x42),
			predictionContextDigest("sha256:", 0x43),
		},
		QuorumThreshold: 2, MaximumOutstanding: 8, MaximumSignedBOCBytes: 64 << 10,
		MinimumNoBounceMCBlocks: 8,
	}
	journal, err := prediction.OpenPredictionRelayJournal(
		filepath.Join(directory, "relay"), relayProfile,
	)
	if err != nil {
		t.Fatal(err)
	}
	profile := prediction.OracleProfile{
		GlobalID: 42, MarketAddress: market, MarketID: marketID.CellHashString(),
		RulesHash: rulesHash.SHA256String(), RoundPolicyHash: predictionContextHash(0x23).CellHashString(),
		ReporterAddress: relayProfile.SourceAgentAccount, Round: protocol.RoundNormal,
		ClaimDeadline: 1_800_001_000, AuditRetention: 86_400,
	}
	valid := normalPredictionContextView(t, profile, relayProfile)
	tampered := append([]byte(nil), valid...)
	var tamperedView tosctlPredictionMarketChainView
	if err := json.Unmarshal(tampered, &tamperedView); err != nil {
		t.Fatal(err)
	}
	tamperedView.CurrentContextHash = strings.Repeat("9", 64)
	tampered, _ = json.Marshal(tamperedView)
	sink := &TOSCTLPaymentSink{
		Authority: &predictionContextTestAuthority{}, Executable: "/trusted/tosctl",
		ConfigPath: configs[0], Wallet: "oracle-agent", SourceAccount: relayProfile.SourceAgentAccount,
		NetworkGlobalID: 42, RelayNetworkDomain: &network, PredictionRelayJournal: journal,
		FeeReserveNanoTOS: 1, QuorumConfigPaths: configs[1:], EvidenceDirectory: directory,
		RelayNetworkPreflight: func(_ context.Context, config string, expected agentrelay.NetworkDomain) error {
			if !slices.Contains(configs, config) || expected != network {
				return errors.New("unexpected network observer")
			}
			return nil
		},
		Run: func(_ context.Context, args []string, _ []string) ([]byte, error) {
			if len(args) < 2 || args[len(args)-2] != "-c" || !slices.Contains(configs, args[len(args)-1]) {
				return nil, errors.New("unexpected tosctl invocation")
			}
			if args[len(args)-1] == configs[2] {
				return append([]byte(nil), tampered...), nil
			}
			return append([]byte(nil), valid...), nil
		},
	}
	return sink, profile, valid, func() { _ = journal.Close() }
}

func TestPredictionOracleContextRequiresTwoIndependentExactViews(t *testing.T) {
	sink, profile, valid, closeFixture := predictionContextObserverFixture(t)
	defer closeFixture()
	observation, err := sink.ObservePredictionOracleContext(
		context.Background(), []byte(`{"global_id":42}`), profile,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(observation.RoundContextBOC) == 0 || len(observation.ReviewBaseContextBOC) != 0 ||
		len(observation.AgreeingObserverIDs) != 2 || len(observation.Checkpoints) != 2 ||
		observation.Status != "reporting" || observation.NextDeadline != 1_800_000_300 {
		t.Fatalf("unexpected context quorum: %+v", observation)
	}
	var wire tosctlPredictionMarketChainView
	if err := json.Unmarshal(valid, &wire); err != nil {
		t.Fatal(err)
	}
	expected, _ := base64.StdEncoding.DecodeString(*wire.CurrentContextBOCBase64)
	if !slices.Equal(observation.RoundContextBOC, expected) ||
		observation.RoundContextHash != "tvm-cell-sha256:"+wire.CurrentContextHash {
		t.Fatal("quorum result did not preserve the exact contract context")
	}
}

func TestPredictionOracleContextFailsClosedWithoutAValidMajority(t *testing.T) {
	sink, profile, valid, closeFixture := predictionContextObserverFixture(t)
	defer closeFixture()
	digest := sha256.Sum256(valid)
	sink.Run = func(_ context.Context, args []string, _ []string) ([]byte, error) {
		mutated := append([]byte(nil), valid...)
		var wire tosctlPredictionMarketChainView
		_ = json.Unmarshal(mutated, &wire)
		wire.CurrentContextHash = hex.EncodeToString(digest[:])
		mutated, _ = json.Marshal(wire)
		return mutated, nil
	}
	if _, err := sink.ObservePredictionOracleContext(
		context.Background(), []byte(`{"global_id":42}`), profile,
	); err == nil {
		t.Fatal("accepted a quorum whose claimed context hash did not match its BOC")
	}
}

func TestPredictionOracleAppealRequiresExactReviewBase(t *testing.T) {
	_, normalProfile, raw, closeFixture := predictionContextObserverFixture(t)
	defer closeFixture()
	var relay prediction.PredictionRelayProfile
	// Only the fields consumed by the strict view verifier are needed here.
	relay.MarketAddress = normalProfile.MarketAddress
	relay.MarketConfigHash = predictionContextDigest("tvm-cell-sha256:", 0x33)
	appeal := normalProfile
	appeal.Round = protocol.RoundAppeal
	var wire tosctlPredictionMarketChainView
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	wire.Status = "reviewing"
	raw, _ = json.Marshal(wire)
	if _, err := verifyPredictionOracleChainView(raw, appeal, relay); err == nil {
		t.Fatal("accepted an appellate context without the exact review base")
	}
}
