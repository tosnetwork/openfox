package earning

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

func TestRelaySponsorshipProofBundleCrossLanguageVector(t *testing.T) {
	proof := map[string]any{
		"schema":                           tosctlRelaySponsorshipProofSchema,
		"agreement_payment_request_digest": "sha256:" + strings.Repeat("1", 64),
		"sponsorship_stable_action_id":     "sha256:" + strings.Repeat("2", 64),
		"confirmation_depth":               uint64(1),
		"observations": []any{map[string]any{
			"endpoint":            "https://rpc-a.example/jsonRPC",
			"operator_provenance": "sha256:" + strings.Repeat("3", 64),
			"transaction_hash":    "sha256:" + strings.Repeat("4", 64),
		}},
	}
	encoded, err := codec.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := agentrelay.RelaySponsorshipProofBundleDigest(encoded)
	if err != nil || len(encoded) != 544 ||
		digest != "sha256:d9d2f6b7da5ab45c817a2296b2890b8cee44e0c18a39c556e2c0a4ad51e09da7" {
		t.Fatalf("Go sponsorship proof bundle diverged from the Rust vector: len=%d digest=%s err=%v",
			len(encoded), digest, err)
	}
}

func TestVerifiedSponsorshipObservationCacheIsBoundedAndExpiresFailClosed(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	sink := &TOSCTLPaymentSink{Now: func() time.Time { return now }}
	digests := make([]string, maximumVerifiedSponsorshipObservationRefs+32)
	for index := range digests {
		digests[index] = sha256Digest([]byte(fmt.Sprintf("observation-%04d", index)))
		sink.rememberVerifiedSponsorshipObservation(digests[index],
			uint64(now.Add(time.Duration(index+1)*time.Second).Unix()))
	}
	sink.verifiedSponsorshipMu.Lock()
	retained := len(sink.verifiedSponsorshipObservations)
	sink.verifiedSponsorshipMu.Unlock()
	if retained != maximumVerifiedSponsorshipObservationRefs {
		t.Fatalf("verified observation cache grew without bound: got %d want %d",
			retained, maximumVerifiedSponsorshipObservationRefs)
	}
	if sink.hasVerifiedSponsorshipObservation(digests[0]) {
		t.Fatal("oldest verified observation survived bounded eviction")
	}
	last := digests[len(digests)-1]
	if !sink.hasVerifiedSponsorshipObservation(last) {
		t.Fatal("newest active verified observation was unexpectedly evicted")
	}
	now = now.Add(time.Duration(len(digests)+1) * time.Second)
	if sink.hasVerifiedSponsorshipObservation(last) {
		t.Fatal("expired verified observation remained authoritative")
	}
}

func TestTOSCTLSponsorshipProfileDigestMatchesNormativeRustVector(t *testing.T) {
	network := agentrelay.NetworkDomain{NetworkID: "tos:testnet", GlobalID: 42,
		ZeroStateRootHash: "sha256:" + strings.Repeat("1", 64),
		ZeroStateFileHash: "sha256:" + strings.Repeat("2", 64), WorkchainID: 0}
	raws := [][]byte{
		tosctlProfileConfig(t, "https://rpc-c.example/jsonRPC", "sha256:"+strings.Repeat("c", 64)),
		tosctlProfileConfig(t, "https://rpc-a.example/jsonRPC", "sha256:"+strings.Repeat("a", 64)),
		tosctlProfileConfig(t, "https://rpc-b.example/jsonRPC", "sha256:"+strings.Repeat("b", 64)),
	}
	policy, profile, err := buildTOSCTLSponsorshipEvidenceProfileFromRaw(raws, network, 1000)
	if err != nil {
		t.Fatal(err)
	}
	const rustDigest = "sha256:4459ac77b6fc656fb34f44de3aaedf6ac6a4d717b725fb2f1ee56026786d6e89"
	if policy.ProfileDigest != rustDigest || profile.Members[0].Endpoint != "https://rpc-a.example/jsonRPC" ||
		profile.Threshold != 2 {
		t.Fatalf("Go profile bytes differ from the fixed Rust vector: policy=%+v profile=%+v", policy, profile)
	}
}

func TestTOSCTLSponsorshipCorroborationReconstructsStrictMajorityAndDigests(t *testing.T) {
	policy, result := tosctlCorroborationFixture(t)
	if err := verifyTOSCTLSponsorshipCorroboration(result, policy); err != nil {
		t.Fatalf("exact two-of-three nonterminal corroboration failed: %v", err)
	}

	for name, mutate := range map[string]func(*tosctlRelaySponsorshipObserved, *RelaySponsorshipReleasePolicy){
		"forged profile digest": func(value *tosctlRelaySponsorshipObserved, _ *RelaySponsorshipReleasePolicy) {
			value.EvidenceProfileDigest = "sha256:" + strings.Repeat("f", 64)
		},
		"forged observation": func(value *tosctlRelaySponsorshipObserved, _ *RelaySponsorshipReleasePolicy) {
			value.Observations[0].TransactionBOCDigest = "sha256:" + strings.Repeat("e", 64)
		},
		"minority winner mix": func(value *tosctlRelaySponsorshipObserved, _ *RelaySponsorshipReleasePolicy) {
			value.Observations[1].TransactionHash = "sha256:" + strings.Repeat("8", 64)
		},
		"duplicate member operator": func(value *tosctlRelaySponsorshipObserved, selected *RelaySponsorshipReleasePolicy) {
			value.EvidenceProfile.Members[2].OperatorProvenance = value.EvidenceProfile.Members[1].OperatorProvenance
			digest, err := tosctlRustFramedDigest(tosctlSponsorshipProfileDomain,
				tosctlProfileDigestValue(value.EvidenceProfile))
			if err != nil {
				t.Fatal(err)
			}
			value.EvidenceProfileDigest, selected.ProfileDigest = digest, digest
		},
	} {
		t.Run(name, func(t *testing.T) {
			copyResult := result
			copyResult.EvidenceProfile.Members = append([]tosctlRelaySponsorshipEvidenceProfileMember(nil),
				result.EvidenceProfile.Members...)
			copyResult.Observations = append([]tosctlPaymentObservation(nil), result.Observations...)
			copyResult.ObservationDigests = append([]string(nil), result.ObservationDigests...)
			selected := policy
			mutate(&copyResult, &selected)
			if err := verifyTOSCTLSponsorshipCorroboration(copyResult, selected); err == nil {
				t.Fatal("forged tosctl corroboration was accepted")
			}
		})
	}
}

func tosctlCorroborationFixture(t *testing.T) (RelaySponsorshipReleasePolicy,
	tosctlRelaySponsorshipObserved) {
	t.Helper()
	network := agentrelay.NetworkDomain{NetworkID: "tos:testnet", GlobalID: -3,
		ZeroStateRootHash: "sha256:" + strings.Repeat("a", 64),
		ZeroStateFileHash: "sha256:" + strings.Repeat("b", 64), WorkchainID: 0}
	raws := [][]byte{
		tosctlProfileConfig(t, "https://a.example/rpc", "sha256:"+strings.Repeat("1", 64)),
		tosctlProfileConfig(t, "https://b.example/rpc", "sha256:"+strings.Repeat("2", 64)),
		tosctlProfileConfig(t, "https://c.example/rpc", "sha256:"+strings.Repeat("3", 64)),
	}
	policy, profile, err := buildTOSCTLSponsorshipEvidenceProfileFromRaw(raws, network, 1000)
	if err != nil {
		t.Fatal(err)
	}
	observation := func(index int, winner bool) tosctlPaymentObservation {
		transaction := "4"
		transactionBOC := "6"
		if !winner {
			transaction = "5"
			transactionBOC = "7"
		}
		return tosctlPaymentObservation{Endpoint: profile.Members[index].Endpoint,
			OperatorProvenance: profile.Members[index].OperatorProvenance,
			TransactionHash:    "sha256:" + strings.Repeat(transaction, 64), TransactionLT: 77,
			TransactionUTime: 100, TransactionBOCDigest: "sha256:" + strings.Repeat(transactionBOC, 64),
			SourceOutboundMessageHash:  "tvm-cell-sha256:" + strings.Repeat("e", 64),
			DestinationCreditReference: "sha256:" + strings.Repeat("7", 64),
			DestinationTransactionHash: "sha256:" + strings.Repeat("7", 64),
			DestinationTransactionLT:   78, DestinationTransactionUTime: 100,
			DestinationTransactionBOCDigest: "sha256:" + strings.Repeat("f", 64),
			DestinationBlockWorkchain:       0, DestinationBlockShard: -1, DestinationBlockSeqno: 10,
			DestinationBlockRootHash: "sha256:" + strings.Repeat("a", 64),
			DestinationBlockFileHash: "sha256:" + strings.Repeat("b", 64),
			DestinationCreditAtomic:  "25", DestinationCreditFirst: true,
			DestinationTransactionAborted: false, DestinationBouncePresent: false,
			DestinationCreditObservedExact: true,
			BlockWorkchain:                 0, BlockShard: -1, BlockSeqno: 9,
			BlockRootHash: "sha256:" + strings.Repeat("8", 64),
			BlockFileHash: "sha256:" + strings.Repeat("9", 64), NetworkGlobalID: -3,
			ZeroStateWorkchain: -1, ZeroStateShard: -1, ZeroStateSeqno: 0,
			ZeroStateRootHash: network.ZeroStateRootHash, ZeroStateFileHash: network.ZeroStateFileHash,
			ObservedMasterchainWorkchain: -1, ObservedMasterchainShard: -1, ObservedMasterchainSeqno: 12,
			ObservedMasterchainRootHash: "sha256:" + strings.Repeat("c", 64),
			ObservedMasterchainFileHash: "sha256:" + strings.Repeat("d", 64),
			ObservedMasterchainGenUTime: 101, FinalityProven: false}
	}
	observations := []tosctlPaymentObservation{observation(0, true), observation(1, true), observation(2, false)}
	digests := make([]string, 0, 2)
	for _, item := range observations[:2] {
		digest, err := tosctlRustFramedDigest(tosctlSponsorshipObservationDomain, item)
		if err != nil {
			t.Fatal(err)
		}
		digests = append(digests, digest)
	}
	sort.Strings(digests)
	return policy, tosctlRelaySponsorshipObserved{NetworkGlobalID: network.GlobalID, NetworkDomain: network,
		EvidenceProfileURI: policy.ProfileURI, EvidenceProfileDigest: policy.ProfileDigest,
		EvidenceProfile: profile, ObservationDigests: digests,
		Quorum: tosctlQuorum{Members: 3, Threshold: 2, Agreeing: 2}, Evidence: observations[0],
		Observations: observations}
}

func tosctlProfileConfig(t *testing.T, endpoint, operator string) []byte {
	t.Helper()
	value := map[string]any{"chain_rpc": map[string]any{
		"urls": []any{endpoint}, "operator_provenance": operator,
	}}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestTOSCTLSponsorshipProfileSnapshotSurvivesOwnerConfigRotation(t *testing.T) {
	network := agentrelay.NetworkDomain{NetworkID: "tos:testnet", GlobalID: -3,
		ZeroStateRootHash: "sha256:" + strings.Repeat("a", 64),
		ZeroStateFileHash: "sha256:" + strings.Repeat("b", 64), WorkchainID: 0}
	root := privateTempDir(t)
	paths := make([]string, 3)
	for index := range paths {
		paths[index] = root + "/rpc-" + string(rune('a'+index)) + ".json"
		raw := tosctlProfileConfig(t, "https://"+string(rune('a'+index))+".example/rpc",
			"sha256:"+strings.Repeat(string(rune('1'+index)), 64))
		if err := writeRelayJournalAtomic(root, paths[index], raw); err != nil {
			t.Fatal(err)
		}
	}
	policy, _, err := buildTOSCTLSponsorshipEvidenceProfile(paths, network, 1000)
	if err != nil {
		t.Fatal(err)
	}
	sink := &TOSCTLPaymentSink{ConfigPath: paths[0], QuorumConfigPaths: paths[1:],
		EvidenceDirectory: root, RelayNetworkDomain: &network, MaximumTransactions: 1000,
		RelaySponsorshipReleasePolicy: policy}
	sink.Run = func(_ context.Context, _ []string, _ []string) ([]byte, error) {
		return tosctlSnapshotCapability(t, root, paths, network, 1000), nil
	}
	first, err := sink.ensureCurrentRelaySponsorshipSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	rotated := tosctlProfileConfig(t, "https://rotated.example/rpc", "sha256:"+strings.Repeat("f", 64))
	if err := writeRelayJournalAtomic(root, paths[0], rotated); err != nil {
		t.Fatal(err)
	}
	rotatedNetwork := network
	rotatedNetwork.NetworkID = "tos:rotated-testnet"
	rotatedNetwork.GlobalID = -4
	rotatedNetwork.ZeroStateRootHash = relayTestDigest("c")
	rotatedNetwork.ZeroStateFileHash = relayTestDigest("d")
	restarted := &TOSCTLPaymentSink{ConfigPath: paths[0], QuorumConfigPaths: paths[1:],
		EvidenceDirectory: root, RelayNetworkDomain: &rotatedNetwork, MaximumTransactions: 1000,
		RelaySponsorshipReleasePolicy: policy}
	restarted.Run = sink.Run
	if capabilities := restarted.RelaySponsorshipEvidenceCapabilities(); len(capabilities.SupportedReleasePolicies) != 0 {
		t.Fatalf("rotated current config remained ready for new Quotes: %+v", capabilities)
	}
	first.custodyWallet, first.providerSource, first.feeReserveNanoTOS = "provider-a", "0:provider-a", 1
	frozen := first.frozenProvider()
	if err := restarted.ValidateRelaySponsorshipEvidenceSnapshot(
		agentrelay.SponsorshipReleaseProfile{EvidenceClass: policy.EvidenceClass,
			ProfileURI: policy.ProfileURI, ProfileDigest: policy.ProfileDigest}, frozen); err != nil {
		t.Fatalf("old funded action did not recover through its per-action frozen snapshot: %v", err)
	}
	terminal := agentrelay.FinalityProfile{ProfileURI: RelayClientCorroboratedTerminalProfileURI,
		ProfileDigest: relayTestDigest("4"), TerminalEvidenceClass: agentrelay.SponsorshipTerminalClientCorroborated,
		MinimumConfirmationDepth: 1, MinimumObservers: 3, MinimumOperatorDomains: 2,
		ReorgWindowSeconds: 10, MaximumResolutionSeconds: 30}
	if restarted.SupportsRelaySponsorshipTerminalFinalityProfile(terminal, nil) {
		t.Fatal("rotated current config was accepted for a new sponsorship Quote")
	}
	if !restarted.SupportsRelaySponsorshipTerminalFinalityProfile(terminal, &frozen) {
		t.Fatal("old sponsorship terminal predicate was stranded after config rotation")
	}
}

func TestTOSCTLSponsorshipTerminalCapabilityIsExactProfileAndProviderLocalOnly(t *testing.T) {
	network := agentrelay.NetworkDomain{NetworkID: "tos:testnet", GlobalID: -3,
		ZeroStateRootHash: "sha256:" + strings.Repeat("a", 64),
		ZeroStateFileHash: "sha256:" + strings.Repeat("b", 64), WorkchainID: 0}
	root := privateTempDir(t)
	paths := make([]string, 3)
	for index := range paths {
		paths[index] = filepath.Join(root, "rpc-"+string(rune('a'+index))+".json")
		if err := writeRelayJournalAtomic(root, paths[index], tosctlProfileConfig(t,
			"https://"+string(rune('a'+index))+".example/rpc",
			"sha256:"+strings.Repeat(string(rune('1'+index)), 64))); err != nil {
			t.Fatal(err)
		}
	}
	policy, _, err := buildTOSCTLSponsorshipEvidenceProfile(paths, network, 1000)
	if err != nil {
		t.Fatal(err)
	}
	depthOne := agentrelay.FinalityProfile{ProfileURI: RelayClientCorroboratedTerminalProfileURI, ProfileDigest: relayTestDigest("4"),
		MinimumConfirmationDepth: 1, MinimumObservers: 3, MinimumOperatorDomains: 2,
		ReorgWindowSeconds: 10, MaximumResolutionSeconds: 30}
	sink := &TOSCTLPaymentSink{ConfigPath: paths[0], QuorumConfigPaths: paths[1:], EvidenceDirectory: root,
		RelayNetworkDomain: &network, MaximumTransactions: 1000, RelaySponsorshipReleasePolicy: policy,
		RelayTerminalFinalityProfiles: []agentrelay.FinalityProfile{depthOne}}
	sink.Run = func(_ context.Context, _ []string, _ []string) ([]byte, error) {
		return tosctlSnapshotCapability(t, root, paths, network, 1000), nil
	}
	if !sink.SupportsRelaySponsorshipTerminalFinalityProfile(depthOne, nil) {
		t.Fatal("provider-local terminal resolver did not advertise its exact depth-one profile")
	}
	depthTwo := depthOne
	depthTwo.MinimumConfirmationDepth = 2
	if sink.SupportsRelaySponsorshipTerminalFinalityProfile(depthTwo, nil) {
		t.Fatal("depth-one terminal adapter advertised an unsatisfiable depth-two profile")
	}
	if !sink.SupportsRelaySponsorshipTransactionEvidence(agentrelay.AssuranceAuthorizedSingleProvider,
		policy, depthOne) {
		t.Fatal("client-owned frozen RPC re-query verifier did not advertise its exact lower-assurance profile")
	}
}

func tosctlSnapshotCapability(t *testing.T, root string, paths []string, network agentrelay.NetworkDomain,
	maximumTransactions uint32) []byte {
	t.Helper()
	raws := make([][]byte, len(paths))
	digests := make([]string, len(paths))
	for index, path := range paths {
		var err error
		raws[index], err = os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		digests[index] = sha256Digest(raws[index])
	}
	policy, profile, err := buildTOSCTLSponsorshipEvidenceProfileFromRaw(raws, network, maximumTransactions)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := tosctlRustFramedDigest(tosctlSponsorshipSnapshotDomain,
		map[string]any{"evidence_profile_digest": policy.ProfileDigest, "config_content_digests": digests})
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "relay-sponsorship-corroboration", "corroboration-"+
		strings.TrimPrefix(identity, "sha256:"))
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	members := make([]tosctlRelaySponsorshipSnapshotMember, len(paths))
	for index := range paths {
		path := filepath.Join(directory, "member-"+strconv.Itoa(index)+".json")
		if err := writeRelayJournalAtomic(directory, path, raws[index]); err != nil {
			t.Fatal(err)
		}
		endpoint, operator, err := tosctlRPCProfileMember(raws[index])
		if err != nil {
			t.Fatal(err)
		}
		members[index] = tosctlRelaySponsorshipSnapshotMember{ConfigPath: path,
			ConfigContentDigest: digests[index], Endpoint: endpoint, OperatorProvenance: operator}
	}
	manifest := tosctlRelaySponsorshipSnapshotManifest{Schema: "tosctl.agent-account.agreement-payment-rpc-corroboration-snapshot.v1",
		SnapshotIdentity: identity, EvidenceProfileURI: policy.ProfileURI,
		EvidenceProfileDigest: policy.ProfileDigest, NetworkDomain: network,
		MaximumHistoryTransactions: maximumTransactions, EvidenceProfile: profile, Members: members}
	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(directory, "manifest.json")
	if err := writeRelayJournalAtomic(directory, manifestPath, manifestRaw); err != nil {
		t.Fatal(err)
	}
	capability := tosctlRelaySponsorshipCapability{Schema: "tosctl.agent-account.agreement-payment-rpc-corroboration-capability.v1",
		EvidenceClass: string(policy.EvidenceClass), EvidenceProfileURI: policy.ProfileURI,
		EvidenceProfileDigest: policy.ProfileDigest, EvidenceProfile: profile,
		CorroborationSnapshot: manifestPath, CorroborationSnapshotIdentity: identity,
		NetworkDomain: network, MaximumHistoryTransactions: maximumTransactions,
		MemberCount: uint32(len(members)), SideEffect: false}
	encoded, err := json.Marshal(capability)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
