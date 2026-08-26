package earning

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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
			"endpoint":                "https://rpc-a.example",
			"locator_identity_digest": "sha256:7852a333f799e340dd1ca5f6080532fc4d78fc0decb0293569235f7c2d553e52",
			"operator_provenance":     "sha256:" + strings.Repeat("3", 64),
			"transaction_hash":        "sha256:" + strings.Repeat("4", 64),
		}},
	}
	encoded, err := codec.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := agentrelay.RelaySponsorshipProofBundleDigest(encoded)
	if err != nil || len(encoded) != 632 ||
		digest != "sha256:61280872b5cc6f30fabe301020d7a8f7c29e86a0c806bec61d3bb51bbb36414f" {
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
	profile := tosctlRelaySponsorshipEvidenceProfile{
		ProfileURI: agentrelay.RPCCorroborationEvidenceProfileURI, NetworkDomain: network,
		Members: []tosctlRelaySponsorshipEvidenceProfileMember{
			{Endpoint: "https://rpc-a.example", LocatorIdentityDigest: tosctlTestLocatorIdentity(t, "https://rpc-a.example/jsonRPC"),
				OperatorProvenance: "sha256:" + strings.Repeat("a", 64)},
			{Endpoint: "https://rpc-b.example", LocatorIdentityDigest: tosctlTestLocatorIdentity(t, "https://rpc-b.example/jsonRPC"),
				OperatorProvenance: "sha256:" + strings.Repeat("b", 64)},
			{Endpoint: "https://rpc-c.example", LocatorIdentityDigest: tosctlTestLocatorIdentity(t, "https://rpc-c.example/jsonRPC"),
				OperatorProvenance: "sha256:" + strings.Repeat("c", 64)},
		},
		Threshold: 2, MaximumHistoryTransactions: 1000, StrictMajority: true,
		ExactSubmittedMessage: true, ExactDestinationCredit: true,
	}
	digest, err := tosctlRustFramedDigest(tosctlSponsorshipProfileDomain, tosctlProfileDigestValue(profile))
	if err != nil {
		t.Fatal(err)
	}
	const rustDigest = "sha256:bdc62291e5dde10074b58a5c5ba2c017fc2a4a89a51c8233d951105ff1d5c8f0"
	if digest != rustDigest {
		t.Fatalf("Go profile bytes differ from the fixed Rust vector: digest=%s profile=%+v", digest, profile)
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
		"observation locator mismatch": func(value *tosctlRelaySponsorshipObserved, _ *RelaySponsorshipReleasePolicy) {
			value.Observations[0].LocatorIdentityDigest = "sha256:" + strings.Repeat("f", 64)
		},
		"observation locator path": func(value *tosctlRelaySponsorshipObserved, _ *RelaySponsorshipReleasePolicy) {
			value.Observations[0].Endpoint += "/private/token"
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

func TestTOSCTLSponsorshipPublicMemberShapeAndOriginAreStrict(t *testing.T) {
	digest := "sha256:" + strings.Repeat("1", 64)
	operator := "sha256:" + strings.Repeat("2", 64)
	valid := `{"endpoint":"https://rpc.example","locator_identity_digest":"` + digest +
		`","operator_provenance":"` + operator + `"}`
	for name, raw := range map[string]string{
		"unknown":   strings.TrimSuffix(valid, "}") + `,"locator":"https://rpc.example/private"}`,
		"duplicate": strings.TrimSuffix(valid, "}") + `,"endpoint":"https://other.example"}`,
	} {
		t.Run(name, func(t *testing.T) {
			var member tosctlRelaySponsorshipEvidenceProfileMember
			if err := decodeStrictJSON([]byte(raw), &member); err == nil {
				t.Fatal("non-exact public member JSON was accepted")
			}
		})
	}

	for name, endpoint := range map[string]string{
		"credentials":    "https://user:secret@rpc.example",
		"path":           "https://rpc.example/private/token",
		"query":          "https://rpc.example?token=secret",
		"fragment":       "https://rpc.example#secret",
		"unicode":        "https://rüp.example",
		"uppercase":      "HTTPS://RPC.EXAMPLE",
		"default port":   "https://rpc.example:443",
		"trailing slash": "https://rpc.example/",
		"dot host":       "https://rpc.example.",
		"double slash":   "https://rpc.example/a//b",
		"dot segment":    "https://rpc.example/a/./b",
		"dotdot segment": "https://rpc.example/a/../b",
		"backslash path": `https://rpc.example/a\b`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := canonicalTOSCTLRPCEndpoint(endpoint); err == nil {
				t.Fatalf("unsafe public endpoint %q was accepted", endpoint)
			}
		})
	}

	profile := tosctlRelaySponsorshipEvidenceProfile{
		ProfileURI: agentrelay.RPCCorroborationEvidenceProfileURI,
		NetworkDomain: agentrelay.NetworkDomain{NetworkID: "tos:testnet", GlobalID: 1,
			ZeroStateRootHash: relayTestDigest("a"), ZeroStateFileHash: relayTestDigest("b")},
		Members: []tosctlRelaySponsorshipEvidenceProfileMember{
			{Endpoint: "https://a.example", LocatorIdentityDigest: digest, OperatorProvenance: operator},
			{Endpoint: "https://b.example", LocatorIdentityDigest: relayTestDigest("3"), OperatorProvenance: relayTestDigest("4")},
			{Endpoint: "https://c.example", LocatorIdentityDigest: relayTestDigest("5"), OperatorProvenance: relayTestDigest("6")},
		},
		Threshold: 2, MaximumHistoryTransactions: 1, StrictMajority: true,
		ExactSubmittedMessage: true, ExactDestinationCredit: true,
	}
	if err := validateTOSCTLSponsorshipEvidenceProfile(profile); err != nil {
		t.Fatalf("exact public profile rejected: %v", err)
	}
	profile.Members[0].LocatorIdentityDigest = ""
	if err := validateTOSCTLSponsorshipEvidenceProfile(profile); err == nil {
		t.Fatal("public profile accepted a missing locator_identity_digest")
	}
}

func TestTOSCTLSponsorshipProfileIgnoresPrivateCredentialsAndFormatting(t *testing.T) {
	network := agentrelay.NetworkDomain{NetworkID: "tos:testnet", GlobalID: 42,
		ZeroStateRootHash: relayTestDigest("1"), ZeroStateFileHash: relayTestDigest("2")}
	first, second := make([][]byte, 3), make([][]byte, 3)
	for index := range first {
		endpoint := fmt.Sprintf("https://rpc-%d.example/private/jsonRPC", index)
		operator := fmt.Sprintf("sha256:%064x", index+1)
		first[index] = []byte(fmt.Sprintf(
			`{"chain_rpc":{"urls":[{"url":%q,"api_key":"provider-secret-%d"}],"operator_provenance":%q}}`,
			endpoint, index, operator))
		second[index] = []byte(fmt.Sprintf(
			"{\n  \"chain_rpc\": {\n    \"operator_provenance\": %q,\n    \"urls\": [{\"api_key\": \"client-secret-%d\", \"url\": %q}]\n  }\n}\n",
			operator, index, endpoint))
	}
	firstPolicy, firstProfile, err := buildTOSCTLSponsorshipEvidenceProfileFromRaw(first, network, 1000)
	if err != nil {
		t.Fatal(err)
	}
	secondPolicy, secondProfile, err := buildTOSCTLSponsorshipEvidenceProfileFromRaw(second, network, 1000)
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, _ := json.Marshal(firstProfile)
	secondJSON, _ := json.Marshal(secondProfile)
	if firstPolicy != secondPolicy || !bytes.Equal(firstJSON, secondJSON) {
		t.Fatalf("private credentials or formatting changed the public profile:\n%s\n%s", firstJSON, secondJSON)
	}
	for index := range first {
		_, firstLocator, firstConfig, _, firstErr := tosctlRPCProfileMember(first[index])
		_, secondLocator, secondConfig, _, secondErr := tosctlRPCProfileMember(second[index])
		if firstErr != nil || secondErr != nil || firstLocator != secondLocator || firstConfig == secondConfig {
			t.Fatalf("member %d did not separate public locator identity from private bytes", index)
		}
	}
	if strings.Contains(string(firstJSON), "private/jsonRPC") || strings.Contains(string(firstJSON), "secret") {
		t.Fatalf("public profile leaked a private locator or credential: %s", firstJSON)
	}
}

func TestTOSCTLCorroborationSnapshotHandleIsRelativeAndStrict(t *testing.T) {
	root := privateTempDir(t)
	identity := relayTestDigest("a")
	handle := "corroboration-" + strings.TrimPrefix(identity, "sha256:") + "/manifest.json"
	want := filepath.Join(root, filepath.FromSlash(handle))
	if got, err := resolveTOSCTLCorroborationSnapshotHandle(root, handle, identity); err != nil || got != want {
		t.Fatalf("valid snapshot handle was rejected: got=%q err=%v", got, err)
	}
	for name, invalid := range map[string]string{
		"absolute":  filepath.Join(root, "manifest.json"),
		"traversal": "../corroboration-" + strings.TrimPrefix(identity, "sha256:") + "/manifest.json",
		"backslash": "corroboration-" + strings.TrimPrefix(identity, "sha256:") + `\manifest.json`,
		"mismatch":  "corroboration-" + strings.Repeat("b", 64) + "/manifest.json",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := resolveTOSCTLCorroborationSnapshotHandle(root, invalid, identity); err == nil {
				t.Fatalf("unsafe snapshot handle %q was accepted", invalid)
			}
		})
	}
}

func TestTOSCTLCorroborationCapabilityAndManifestDoNotLeakHostPaths(t *testing.T) {
	network := agentrelay.NetworkDomain{NetworkID: "tos:testnet", GlobalID: 42,
		ZeroStateRootHash: relayTestDigest("1"), ZeroStateFileHash: relayTestDigest("2")}
	root := privateTempDir(t)
	paths := make([]string, 3)
	for index := range paths {
		paths[index] = filepath.Join(root, fmt.Sprintf("source-%d.json", index))
		if err := os.WriteFile(paths[index], tosctlProfileConfig(t,
			fmt.Sprintf("https://rpc-%d.example/private/jsonRPC", index),
			fmt.Sprintf("sha256:%064x", index+1)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	raw := tosctlSnapshotCapability(t, root, paths, network, 1000)
	if strings.Contains(string(raw), root) || strings.Contains(string(raw), "snapshot_nonce") ||
		strings.Contains(string(raw), "/private/jsonRPC") {
		t.Fatalf("public capability leaked a host path, private nonce, or locator: %s", raw)
	}
	var capability tosctlRelaySponsorshipCapability
	if err := decodeStrictJSON(raw, &capability); err != nil {
		t.Fatal(err)
	}
	registry := filepath.Join(root, "relay-sponsorship-corroboration")
	manifestPath, err := resolveTOSCTLCorroborationSnapshotHandle(registry,
		capability.CorroborationSnapshotHandle, capability.CorroborationSnapshotIdentity)
	if err != nil {
		t.Fatal(err)
	}
	manifestRaw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(manifestRaw), root) {
		t.Fatalf("private manifest leaked its absolute host root: %s", manifestRaw)
	}
	var manifest tosctlRelaySponsorshipSnapshotManifest
	if err := decodeStrictJSON(manifestRaw, &manifest); err != nil || !validTOSCTLSnapshotNonce(manifest.SnapshotNonce) {
		t.Fatalf("private snapshot nonce or manifest is invalid: %+v err=%v", manifest, err)
	}
	for _, member := range manifest.Members {
		if !validTOSCTLSnapshotMemberBasename(member.ConfigPath) {
			t.Fatalf("manifest member path is not a relative basename: %q", member.ConfigPath)
		}
	}
}

func TestTOSCTLCorroborationSnapshotRejectsDirectorySymlinkReplacement(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic-link replacement test requires Unix")
	}
	network := agentrelay.NetworkDomain{NetworkID: "tos:testnet", GlobalID: 42,
		ZeroStateRootHash: relayTestDigest("1"), ZeroStateFileHash: relayTestDigest("2")}
	root := privateTempDir(t)
	paths := make([]string, 3)
	for index := range paths {
		paths[index] = filepath.Join(root, fmt.Sprintf("source-%d.json", index))
		if err := os.WriteFile(paths[index], tosctlProfileConfig(t,
			fmt.Sprintf("https://rpc-%d.example/private/jsonRPC", index),
			fmt.Sprintf("sha256:%064x", index+1)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	raw := tosctlSnapshotCapability(t, root, paths, network, 1000)
	var capability tosctlRelaySponsorshipCapability
	if err := decodeStrictJSON(raw, &capability); err != nil {
		t.Fatal(err)
	}
	registry := filepath.Join(root, "relay-sponsorship-corroboration")
	manifestPath, err := resolveTOSCTLCorroborationSnapshotHandle(registry,
		capability.CorroborationSnapshotHandle, capability.CorroborationSnapshotIdentity)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := tosctlRelaySponsorshipSnapshot{policy: RelaySponsorshipReleasePolicy{
		EvidenceClass: agentrelay.SponsorshipReleaseObservedUnproven,
		ProfileURI:    capability.EvidenceProfileURI, ProfileDigest: capability.EvidenceProfileDigest},
		maximumTransactions: capability.MaximumHistoryTransactions, registryRoot: registry,
		manifestPath: manifestPath, identity: capability.CorroborationSnapshotIdentity}
	sink := &TOSCTLPaymentSink{}
	if err := sink.validateRelaySponsorshipSnapshot(snapshot); err != nil {
		t.Fatalf("valid rooted snapshot rejected: %v", err)
	}
	directory := filepath.Dir(manifestPath)
	relocated := directory + "-relocated"
	if err := os.Rename(directory, relocated); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(relocated, directory); err != nil {
		t.Fatal(err)
	}
	if err := sink.validateRelaySponsorshipSnapshot(snapshot); err == nil {
		t.Fatal("snapshot directory symlink replacement was accepted")
	}
}

func TestTOSCTLSponsorshipPrivateLocatorPublishesOnlyOrigin(t *testing.T) {
	raw := tosctlProfileConfig(t, "https://rpc.example/tenant/private-token/jsonRPC",
		"sha256:"+strings.Repeat("a", 64))
	endpoint, locatorDigest, contentDigest, _, err := tosctlRPCProfileMember(raw)
	if err != nil {
		t.Fatal(err)
	}
	if endpoint != "https://rpc.example" || locatorDigest != tosctlTestLocatorIdentity(t,
		"https://rpc.example/tenant/private-token/jsonRPC") || contentDigest != sha256Digest(raw) ||
		strings.Contains(endpoint, "private-token") || strings.Contains(endpoint, "/tenant/") {
		t.Fatalf("private locator leaked into public member: endpoint=%q digest=%q", endpoint, contentDigest)
	}
	for name, invalid := range map[string]string{
		"uppercase":      "HTTPS://RPC.EXAMPLE/private/jsonRPC",
		"default port":   "https://rpc.example:443/private/jsonRPC",
		"trailing slash": "https://rpc.example/private/jsonRPC/",
		"dot host":       "https://rpc.example./private/jsonRPC",
		"double slash":   "https://rpc.example/private//jsonRPC",
		"dot segment":    "https://rpc.example/private/./jsonRPC",
		"dotdot segment": "https://rpc.example/private/../jsonRPC",
		"backslash":      `https://rpc.example/private\jsonRPC`,
		"unicode":        "https://rpc.example/私有/jsonRPC",
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := canonicalTOSCTLRPCConfigLocator(invalid); err == nil {
				t.Fatalf("non-canonical private locator %q was accepted", invalid)
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
			LocatorIdentityDigest: profile.Members[index].LocatorIdentityDigest,
			OperatorProvenance:    profile.Members[index].OperatorProvenance,
			TransactionHash:       "sha256:" + strings.Repeat(transaction, 64), TransactionLT: 77,
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
	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		t.Fatal(err)
	}
	nonce := hex.EncodeToString(nonceBytes)
	identity, err := tosctlRustFramedDigest(tosctlSponsorshipSnapshotDomain,
		map[string]any{"evidence_profile_digest": policy.ProfileDigest,
			"config_content_digests": digests, "snapshot_nonce": nonce})
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
		endpoint, locatorDigest, contentDigest, operator, err := tosctlRPCProfileMember(raws[index])
		if err != nil {
			t.Fatal(err)
		}
		members[index] = tosctlRelaySponsorshipSnapshotMember{ConfigPath: filepath.Base(path),
			ConfigContentDigest: contentDigest, Endpoint: endpoint,
			LocatorIdentityDigest: locatorDigest, OperatorProvenance: operator}
	}
	manifest := tosctlRelaySponsorshipSnapshotManifest{Schema: "tosctl.agent-account.agreement-payment-rpc-corroboration-snapshot.v1",
		SnapshotIdentity: identity, SnapshotNonce: nonce, EvidenceProfileURI: policy.ProfileURI,
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
		CorroborationSnapshotHandle:   filepath.ToSlash(filepath.Join(filepath.Base(directory), "manifest.json")),
		CorroborationSnapshotIdentity: identity,
		NetworkDomain:                 network, MaximumHistoryTransactions: maximumTransactions,
		MemberCount: uint32(len(members)), SideEffect: false}
	encoded, err := json.Marshal(capability)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func tosctlTestLocatorIdentity(t *testing.T, locator string) string {
	t.Helper()
	canonical, _, err := canonicalTOSCTLRPCConfigLocator(locator)
	if err != nil {
		t.Fatal(err)
	}
	return tosctlFramedBytesDigest(tosctlRPCLocatorIdentityDomain, []byte(canonical))
}
