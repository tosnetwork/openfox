package earning

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentgift"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
	"github.com/tosnetwork/tosutils-go/address"
	"github.com/tosnetwork/tosutils-go/tlb"
	"github.com/tosnetwork/tosutils-go/tvm/cell"

	"github.com/tosnetwork/openfox/pkg/prediction"
)

type predictionCustodyKeyResolver struct {
	authorityID string
	ownerID     string
	agentID     string
	key         ed25519.PublicKey
}

func (resolver predictionCustodyKeyResolver) AuthorizeCustodyKey(authorityID, ownerID, agentID string,
	key ed25519.PublicKey, _ time.Time,
) error {
	if authorityID != resolver.authorityID || ownerID != resolver.ownerID || agentID != resolver.agentID ||
		!resolver.key.Equal(key) {
		return errors.New("unexpected Prediction custody key")
	}
	return nil
}

func TestPredictionTOSCTLSinkAuthorizesAndJournalsExactBOCBeforeSubmission(t *testing.T) {
	fixed := time.Unix(1_800_000_000, 0).UTC()
	ownerID, agentID, authorityID := "owner:prediction", "agent:prediction", "authority:prediction"
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x71}, ed25519.SeedSize))
	authority, err := OpenPersonalAuthority(
		privateTempDir(t), ownerID, agentID, authorityID, key, PortfolioLimits{},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = authority.Close() }()
	authority.now = func() time.Time { return fixed }
	actionKind := "prediction.market.advance-phase"
	fence, err := authority.AcquireWriter(t.Context(), "runtime:prediction", []string{actionKind}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	digest := func(prefix string, value byte) string {
		return prefix + strings.Repeat(hex.EncodeToString([]byte{value}), 32)
	}
	source := "0:" + strings.Repeat("1", 64)
	market := "0:" + strings.Repeat("2", 64)
	network := agentrelay.NetworkDomain{
		NetworkID: "tos:test", GlobalID: 42,
		ZeroStateRootHash: digest("sha256:", 0x31), ZeroStateFileHash: digest("sha256:", 0x32),
		WorkchainID: 0,
	}
	networkDigest, err := agentrelay.NetworkDomainDigest(network)
	if err != nil {
		t.Fatal(err)
	}
	profile := prediction.PredictionRelayProfile{
		NetworkDomainHash: networkDigest, SourceAgentAccount: source,
		SourceAgentAccountCodeHash: digest("tvm-cell-sha256:", 0x33),
		MarketAddress:              market, MarketID: digest("sha256:", 0x34),
		MarketCodeHash:   digest("tvm-cell-sha256:", 0x35),
		MarketConfigHash: digest("tvm-cell-sha256:", 0x36),
		ObserverIDs:      []string{digest("sha256:", 0x41), digest("sha256:", 0x42), digest("sha256:", 0x43)},
		QuorumThreshold:  2, MaximumOutstanding: 8, MaximumSignedBOCBytes: 64 << 10,
		MinimumNoBounceMCBlocks: 8,
	}
	relay, err := prediction.OpenPredictionRelayJournal(filepath.Join(privateTempDir(t), "relay"), profile)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = relay.Close() }()
	body := cell.BeginCell().MustStoreUInt(0x504d000f, 32).MustStoreUInt(7, 64).EndCell()
	bodyBOC := body.ToBOCWithFlags(false)
	bodyHash := "tvm-cell-sha256:" + hex.EncodeToString(body.Hash())
	external := predictionCheckedCallTestBOC(t, source, market, 42, 0, 0, 1_800_000_600, 2_000_000, body)
	externalDigest := sha256.Sum256(external)
	evidenceDirectory := privateTempDir(t)
	configPath := filepath.Join(privateTempDir(t), "tosctl.json")
	if writeErr := os.WriteFile(configPath, []byte("{}"), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	artifact := tosctlPredictionOperationArtifact{
		Schema: "tos.prediction-operation-artifact.v1", Operation: "advance_phase",
		CustodyActionKind: &actionKind, GlobalID: 42, WorkchainID: 0,
		MarketAddress: market, MarketID: profile.MarketID, MarketConfigHash: profile.MarketConfigHash,
		MarketCodeHash: profile.MarketCodeHash, SourceAgentAccountCodeHash: profile.SourceAgentAccountCodeHash,
		MinimumValue: 1_000_000, BodyHash: bodyHash,
		BodyBOCBase64: base64.StdEncoding.EncodeToString(bodyBOC),
	}
	calls := 0
	sink := &TOSCTLPaymentSink{
		Authority: authority, Executable: "/trusted/tosctl", ConfigPath: configPath,
		Wallet: "prediction-agent", SourceAccount: source, NetworkGlobalID: 42,
		RelayNetworkDomain: &network, FeeReserveNanoTOS: 100_000,
		EvidenceDirectory: evidenceDirectory, PredictionRelayJournal: relay,
		RelayNetworkPreflight: func(_ context.Context, path string, wanted agentrelay.NetworkDomain) error {
			if path != configPath || wanted != network {
				return errors.New("wrong network preflight")
			}
			return nil
		},
	}
	sink.Run = func(_ context.Context, args, _ []string) ([]byte, error) {
		calls++
		if argumentValue(args, "build-operation") != "" {
			return json.Marshal(artifact)
		}
		if argumentValue(args, "economic-effect-broadcast") != "" {
			if argumentValue(args, "--stable-action-id") == "" ||
				argumentValue(args, "--wallet") != "prediction-agent" {
				return nil, errors.New("incomplete Prediction broadcast command")
			}
			return json.Marshal(tosctlPredictionEffectBroadcast{
				Schema:         "tosctl.agent-account.economic-effect-broadcast.v1",
				StableActionID: argumentValue(args, "--stable-action-id"),
				ActionKind:     actionKind, Account: source,
				ExactSignedBOCDigest: "sha256:" + hex.EncodeToString(externalDigest[:]),
				State:                "broadcasting",
			})
		}
		if argumentValue(args, "prepare-agent") == "" {
			return nil, errors.New("unexpected tosctl command")
		}
		authorizationPath := argumentValue(args, "--authorization-file")
		rawAuthorization, readErr := os.ReadFile(authorizationPath)
		if readErr != nil {
			return nil, readErr
		}
		authorization, decodeErr := commerce.DecodePredictionCustodyEffectAuthorizationV1JSON(rawAuthorization)
		if decodeErr != nil {
			return nil, decodeErr
		}
		resolver := predictionCustodyKeyResolver{
			authorityID: authorityID, ownerID: ownerID, agentID: agentID,
			key: key.Public().(ed25519.PublicKey),
		}
		if verifyErr := commerce.VerifyPredictionCustodyEffectAuthorizationV1(
			authorization, resolver, fixed,
		); verifyErr != nil {
			return nil, verifyErr
		}
		outputPath := argumentValue(args, "--output-boc")
		if writeErr := os.WriteFile(outputPath, external, 0o600); writeErr != nil {
			return nil, writeErr
		}
		return json.Marshal(tosctlPredictionAgentPrepared{
			Schema:         "tosctl.prediction-agent-effect-prepared.v1",
			StableActionID: authorization.StableActionID, ActionKind: actionKind,
			Source: source, SourceAgentAccountCodeHash: profile.SourceAgentAccountCodeHash,
			Destination: market, MarketID: profile.MarketID,
			MarketConfigHash: profile.MarketConfigHash, MarketCodeHash: profile.MarketCodeHash,
			AmountNanoTOS: 2_000_000, BodyHash: bodyHash, ValidUntil: 1_800_000_600,
			NetworkDomain: network, ExactSignedBOC: base64.StdEncoding.EncodeToString(external),
			ExactSignedBOCDigest: "sha256:" + hex.EncodeToString(externalDigest[:]),
			OutputBOC:            outputPath,
		})
	}
	engine := &Engine{
		OwnerID: ownerID, AgentID: agentID, MandateDigest: digest("sha256:", 0x51),
		Authority: authority, Gates: FeatureGates{Prediction: true}, Now: func() time.Time { return fixed },
	}
	request := PredictionEffectRequest{
		ActionKind: actionKind,
		SemanticFields: map[string]commerce.SemanticValue{
			"owner_id": commerce.ID(ownerID), "agent_id": commerce.ID(agentID),
			"network_domain_digest": commerce.Digest32(networkDigest), "market_id": commerce.Digest32(profile.MarketID),
			"expected_phase_state_digest": commerce.Digest32(digest("sha256:", 0x61)),
			"authority_instance_id":       commerce.Digest32(digest("sha256:", 0x62)),
		},
		MarketDefinitionJSON: []byte(`{"global_id":42}`),
		OperationJSON:        []byte(`{"operation":"advance_phase","query_id":7}`),
		AmountNanoTOS:        2_000_000, ValidUntil: 1_800_000_600, PolicyRevision: 1,
		SourceCursor: prediction.AccountCursor{
			AccountAddress: source, LastLogicalTime: 90,
			LastTransactionHash: digest("sha256:", 0x71),
		},
		MasterchainCheckpoint: prediction.BlockIdentity{
			WorkchainID: -1, Shard: -1, SequenceNumber: 100,
			RootHash: digest("sha256:", 0x72), FileHash: digest("sha256:", 0x73), MasterchainSequence: 100,
		},
	}
	badCursor := request
	badCursor.SourceCursor.AccountAddress = market
	if _, prepareErr := engine.PreparePredictionEffect(t.Context(), sink, badCursor, fence); prepareErr == nil ||
		calls != 2 {
		t.Fatalf("invalid pre-broadcast cursor crossed the relay journal: calls=%d err=%v", calls, prepareErr)
	}
	stableActionID, _, err := commerce.DeriveStableActionID(actionKind, request.SemanticFields)
	if err != nil {
		t.Fatal(err)
	}
	exactRequestDigest, err := commerce.ExactRequestDigest(bodyBOC)
	if err != nil {
		t.Fatal(err)
	}
	resolution := authority.Resolve(stableActionID, exactRequestDigest)
	if resolution.State != commerce.ActionPrepared {
		t.Fatalf("failed relay durability step advanced authority prematurely: %+v", resolution)
	}
	prepared, err := engine.PreparePredictionEffect(t.Context(), sink, request, fence)
	if err != nil || prepared.RelayRecord.State != prediction.RelaySigned || calls != 4 {
		t.Fatalf("Prediction custody preparation failed: calls=%d record=%+v err=%v", calls, prepared.RelayRecord, err)
	}
	if resolution := authority.Resolve(
		prepared.AuthorizedAction.StableActionID, prepared.AuthorizedAction.ExactRequestDigest,
	); resolution.State != commerce.ActionSubmitted {
		t.Fatalf("authority was not advanced after durable relay preparation: %+v", resolution)
	}
	retried, err := engine.PreparePredictionEffect(t.Context(), sink, request, fence)
	if err != nil || retried.RelayRecord.ExactSignedBOCDigest != prepared.RelayRecord.ExactSignedBOCDigest ||
		calls != 5 {
		t.Fatalf("submitted retry did not recover exact relay material: calls=%d err=%v", calls, err)
	}
	broadcasting, err := engine.ResumePredictionEffectBroadcast(t.Context(), sink, prepared)
	if err != nil || broadcasting.State != prediction.RelayBroadcasting ||
		broadcasting.BroadcastAttempts != 1 || calls != 6 {
		t.Fatalf("Prediction exact broadcast failed: calls=%d record=%+v err=%v", calls, broadcasting, err)
	}
	rebroadcast, err := engine.ResumePredictionEffectBroadcast(t.Context(), sink, prepared)
	if err != nil || rebroadcast.State != prediction.RelayBroadcasting ||
		rebroadcast.BroadcastAttempts != 2 || calls != 7 {
		t.Fatalf("Prediction exact rebroadcast was not crash-safe: calls=%d record=%+v err=%v", calls, rebroadcast, err)
	}
}

func argumentValue(args []string, name string) string {
	for index, value := range args {
		if value == name {
			if strings.HasPrefix(name, "--") && index+1 < len(args) {
				return args[index+1]
			}
			return value
		}
	}
	return ""
}

func predictionCheckedCallTestBOC(t *testing.T, source, target string, globalID int32, epoch uint64,
	seqno, validUntil uint32, amount uint64, callBody *cell.Cell,
) []byte {
	t.Helper()
	sourceAddress, err := address.ParseRawAddr(source)
	if err != nil {
		t.Fatal(err)
	}
	targetAddress, err := address.ParseRawAddr(target)
	if err != nil {
		t.Fatal(err)
	}
	payload := cell.BeginCell().MustStoreUInt(agentgift.AgentCheckedContractCallV2Opcode, 32).
		MustStoreInt(int64(globalID), 32).MustStoreUInt(epoch, 64).MustStoreUInt(uint64(seqno), 32).
		MustStoreUInt(uint64(validUntil), 32).MustStoreAddr(targetAddress).MustStoreCoins(amount).
		MustStoreUInt(agentgift.AgentCheckedContractCallV2Flags, 8).MustStoreRef(callBody).EndCell()
	body := cell.BeginCell().MustStoreSlice(make([]byte, ed25519.SignatureSize), 512).
		MustStoreBuilder(payload.ToBuilder()).EndCell()
	external, err := (&tlb.ExternalMessage{
		SrcAddr: address.NewAddressNone(), DstAddr: sourceAddress, ImportFee: tlb.ZeroCoins, Body: body,
	}).ToCell()
	if err != nil {
		t.Fatal(err)
	}
	return external.ToBOCWithFlags(false)
}
