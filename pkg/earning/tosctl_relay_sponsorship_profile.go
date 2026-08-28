package earning

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
)

const (
	tosctlSponsorshipProfileDomain     = "tosctl.agreement-payment-rpc-corroboration-profile.v1\x00"
	tosctlRPCLocatorIdentityDomain     = "tosctl.agreement-payment-rpc-locator-identity.v1\x00"
	tosctlSponsorshipObservationDomain = "tosctl.agreement-payment-rpc-observation.v1\x00"
	tosctlSponsorshipSnapshotDomain    = "tosctl.agreement-payment-rpc-corroboration-snapshot.v1\x00"
	tosctlMaximumConfigBytes           = 4 << 20
	tosctlSponsorshipPreflightTimeout  = 30 * time.Second
)

type tosctlRelaySponsorshipCapability struct {
	Schema                        string                                `json:"schema"`
	EvidenceClass                 string                                `json:"evidence_class"`
	EvidenceProfileURI            string                                `json:"evidence_profile_uri"`
	EvidenceProfileDigest         string                                `json:"evidence_profile_digest"`
	EvidenceProfile               tosctlRelaySponsorshipEvidenceProfile `json:"evidence_profile"`
	CorroborationSnapshotHandle   string                                `json:"corroboration_snapshot_handle"`
	CorroborationSnapshotIdentity string                                `json:"corroboration_snapshot_identity"`
	NetworkDomain                 agentrelay.NetworkDomain              `json:"network_domain"`
	MaximumHistoryTransactions    uint32                                `json:"maximum_history_transactions"`
	MemberCount                   uint32                                `json:"member_count"`
	SideEffect                    bool                                  `json:"side_effect"`
}

type tosctlRelaySponsorshipSnapshot struct {
	policy              RelaySponsorshipReleasePolicy
	maximumTransactions uint32
	registryRoot        string
	custodyWallet       string
	providerSource      string
	feeReserveNanoTOS   uint64
	manifestPath        string
	identity            string
}

type tosctlRelaySponsorshipSnapshotMember struct {
	ConfigPath            string `json:"config_path"`
	ConfigContentDigest   string `json:"config_content_digest"`
	Endpoint              string `json:"endpoint"`
	LocatorIdentityDigest string `json:"locator_identity_digest"`
	OperatorProvenance    string `json:"operator_provenance"`
}

type tosctlRelaySponsorshipSnapshotManifest struct {
	Schema                     string                                 `json:"schema"`
	SnapshotIdentity           string                                 `json:"snapshot_identity"`
	SnapshotNonce              string                                 `json:"snapshot_nonce"`
	EvidenceProfileURI         string                                 `json:"evidence_profile_uri"`
	EvidenceProfileDigest      string                                 `json:"evidence_profile_digest"`
	NetworkDomain              agentrelay.NetworkDomain               `json:"network_domain"`
	MaximumHistoryTransactions uint32                                 `json:"maximum_history_transactions"`
	EvidenceProfile            tosctlRelaySponsorshipEvidenceProfile  `json:"evidence_profile"`
	Members                    []tosctlRelaySponsorshipSnapshotMember `json:"members"`
}

type tosctlChainRPCConfigFile struct {
	ChainRPC struct {
		URLs               []json.RawMessage `json:"urls"`
		LegacyURL          *string           `json:"url"`
		OperatorProvenance *string           `json:"operator_provenance"`
	} `json:"chain_rpc"`
}

func (sink *TOSCTLPaymentSink) ensureCurrentRelaySponsorshipSnapshot() (tosctlRelaySponsorshipSnapshot, error) {
	if sink == nil || sink.RelaySponsorshipReleasePolicy.EvidenceClass !=
		agentrelay.SponsorshipReleaseObservedUnproven || sink.RelayNetworkDomain == nil ||
		sink.maximumTransactions() > 10_000 {
		return tosctlRelaySponsorshipSnapshot{}, errors.New("observed sponsorship release is not owner-enabled")
	}
	sink.sponsorshipSnapshotMu.Lock()
	defer sink.sponsorshipSnapshotMu.Unlock()
	policy := sink.RelaySponsorshipReleasePolicy
	directory := filepath.Join(sink.EvidenceDirectory, "relay-sponsorship-corroboration")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return tosctlRelaySponsorshipSnapshot{}, err
	}
	if err := validateRelayJournalDirectorySecurity(directory); err != nil {
		return tosctlRelaySponsorshipSnapshot{}, errors.New("tosctl corroboration snapshot directory is not owner-private")
	}
	network := *sink.RelayNetworkDomain
	args := []string{"agent", "account", "economic-payment-corroboration-profile",
		"--network-id", network.NetworkID, "--global-id", fmt.Sprint(network.GlobalID),
		"--zero-state-root-hash", network.ZeroStateRootHash,
		"--zero-state-file-hash", network.ZeroStateFileHash,
		"--workchain-id", fmt.Sprint(network.WorkchainID), "--quorum-config"}
	args = append(args, sink.QuorumConfigPaths...)
	args = append(args, "--max-transactions", fmt.Sprint(sink.maximumTransactions()),
		"--snapshot-directory", directory, "-c", sink.ConfigPath)
	ctx, cancel := context.WithTimeout(context.Background(), tosctlSponsorshipPreflightTimeout)
	defer cancel()
	raw, err := sink.run(ctx, args)
	if err != nil {
		return tosctlRelaySponsorshipSnapshot{}, fmt.Errorf("preflight tosctl sponsorship corroboration profile: %w", err)
	}
	var capability tosctlRelaySponsorshipCapability
	if decodeStrictJSON(raw, &capability) != nil ||
		capability.Schema != "tosctl.agent-account.agreement-payment-rpc-corroboration-capability.v1" ||
		capability.EvidenceClass != string(policy.EvidenceClass) || capability.EvidenceProfileURI != policy.ProfileURI ||
		capability.EvidenceProfileDigest != policy.ProfileDigest || capability.NetworkDomain != network ||
		capability.MaximumHistoryTransactions != sink.maximumTransactions() || capability.MemberCount < 3 ||
		capability.MemberCount != uint32(len(capability.EvidenceProfile.Members)) || capability.SideEffect {
		return tosctlRelaySponsorshipSnapshot{}, errors.New("tosctl corroboration preflight conflicts with owner configuration")
	}
	manifestPath, handleErr := resolveTOSCTLCorroborationSnapshotHandle(directory,
		capability.CorroborationSnapshotHandle, capability.CorroborationSnapshotIdentity)
	if handleErr != nil {
		return tosctlRelaySponsorshipSnapshot{}, errors.New("tosctl corroboration preflight returned an invalid snapshot handle")
	}
	snapshot := tosctlRelaySponsorshipSnapshot{policy: policy,
		maximumTransactions: capability.MaximumHistoryTransactions,
		registryRoot:        directory,
		custodyWallet:       sink.Wallet,
		providerSource:      sink.SourceAccount,
		feeReserveNanoTOS:   sink.FeeReserveNanoTOS,
		manifestPath:        manifestPath,
		identity:            capability.CorroborationSnapshotIdentity}
	if err := sink.validateRelaySponsorshipSnapshot(snapshot); err != nil {
		return tosctlRelaySponsorshipSnapshot{}, err
	}
	return snapshot, nil
}

func (sink *TOSCTLPaymentSink) validateRelaySponsorshipSnapshot(snapshot tosctlRelaySponsorshipSnapshot) error {
	if sink == nil || snapshot.policy.EvidenceClass != agentrelay.SponsorshipReleaseObservedUnproven ||
		snapshot.policy.ProfileURI != agentrelay.RPCCorroborationEvidenceProfileURI ||
		!validSHA256Digest(snapshot.policy.ProfileDigest) || !validSHA256Digest(snapshot.identity) ||
		!filepath.IsAbs(snapshot.registryRoot) || filepath.Clean(snapshot.registryRoot) != snapshot.registryRoot ||
		!filepath.IsAbs(snapshot.manifestPath) || filepath.Clean(snapshot.manifestPath) != snapshot.manifestPath ||
		filepath.Base(snapshot.manifestPath) != "manifest.json" {
		return errors.New("tosctl corroboration snapshot identity is invalid")
	}
	root := snapshot.registryRoot
	expectedHandle := "corroboration-" + strings.TrimPrefix(snapshot.identity, "sha256:") + "/manifest.json"
	expectedPath, expectedErr := resolveTOSCTLCorroborationSnapshotHandle(root, expectedHandle, snapshot.identity)
	if expectedErr != nil || snapshot.manifestPath != expectedPath {
		return errors.New("tosctl corroboration snapshot path does not match its identity")
	}
	directory := filepath.Dir(snapshot.manifestPath)
	relative, err := filepath.Rel(root, directory)
	if err != nil || relative == "." || strings.HasPrefix(relative, "..") || strings.Contains(relative, string(os.PathSeparator)) ||
		!strings.HasPrefix(relative, "corroboration-") || validateRelayJournalDirectorySecurity(root) != nil ||
		validateRelayJournalDirectorySecurity(directory) != nil {
		return errors.New("tosctl corroboration snapshot escaped its owner-private registry")
	}
	rootHandle, err := openRelayPinnedDirectory(root)
	if err != nil {
		return errors.New("open tosctl corroboration snapshot registry")
	}
	defer rootHandle.close()
	directoryHandle, err := openRelayPinnedDirectory(directory)
	if err != nil || rootHandle.ensureChild(relative, directoryHandle) != nil {
		if directoryHandle != nil {
			_ = directoryHandle.close()
		}
		return errors.New("pin tosctl corroboration snapshot directory")
	}
	defer directoryHandle.close()
	raw, err := readBoundedPinnedFile(directoryHandle, "manifest.json", 1<<20)
	if err != nil {
		return errors.New("read tosctl corroboration snapshot manifest")
	}
	var manifest tosctlRelaySponsorshipSnapshotManifest
	if decodeStrictJSON(raw, &manifest) != nil ||
		manifest.Schema != "tosctl.agent-account.agreement-payment-rpc-corroboration-snapshot.v1" ||
		manifest.SnapshotIdentity != snapshot.identity || manifest.EvidenceProfileURI != snapshot.policy.ProfileURI ||
		!validTOSCTLSnapshotNonce(manifest.SnapshotNonce) ||
		manifest.EvidenceProfileDigest != snapshot.policy.ProfileDigest ||
		manifest.MaximumHistoryTransactions != snapshot.maximumTransactions || len(manifest.Members) < 3 ||
		manifest.EvidenceProfile.ProfileURI != snapshot.policy.ProfileURI ||
		manifest.EvidenceProfile.NetworkDomain != manifest.NetworkDomain ||
		manifest.EvidenceProfile.MaximumHistoryTransactions != snapshot.maximumTransactions {
		return errors.New("tosctl corroboration snapshot conflicts with its signed profile")
	}
	if err := validateTOSCTLSponsorshipEvidenceProfile(manifest.EvidenceProfile); err != nil {
		return err
	}
	profileDigest, err := tosctlRustFramedDigest(tosctlSponsorshipProfileDomain,
		tosctlProfileDigestValue(manifest.EvidenceProfile))
	if err != nil || profileDigest != snapshot.policy.ProfileDigest {
		return errors.New("tosctl corroboration snapshot profile digest cannot be reproduced")
	}
	contentDigests := make([]string, 0, len(manifest.Members))
	profileMembers := make(map[string]bool, len(manifest.EvidenceProfile.Members))
	for _, member := range manifest.EvidenceProfile.Members {
		profileMembers[tosctlSponsorshipMemberKey(member.Endpoint, member.LocatorIdentityDigest,
			member.OperatorProvenance)] = true
	}
	seen := map[string]bool{}
	for _, member := range manifest.Members {
		memberKey := tosctlSponsorshipMemberKey(member.Endpoint, member.LocatorIdentityDigest,
			member.OperatorProvenance)
		if !validTOSCTLSnapshotMemberBasename(member.ConfigPath) ||
			!validSHA256Digest(member.ConfigContentDigest) || !validSHA256Digest(member.LocatorIdentityDigest) ||
			!validSHA256Digest(member.OperatorProvenance) ||
			!profileMembers[memberKey] || seen[memberKey] {
			return errors.New("tosctl corroboration snapshot member is not in the frozen profile")
		}
		memberRaw, readErr := readBoundedPinnedFile(directoryHandle, member.ConfigPath, tosctlMaximumConfigBytes)
		endpoint, locatorDigest, contentDigest, operator, deriveErr := tosctlRPCProfileMember(memberRaw)
		if readErr != nil || deriveErr != nil || endpoint != member.Endpoint ||
			locatorDigest != member.LocatorIdentityDigest || contentDigest != member.ConfigContentDigest ||
			operator != member.OperatorProvenance {
			return errors.New("tosctl corroboration snapshot member bytes changed")
		}
		seen[memberKey] = true
		contentDigests = append(contentDigests, member.ConfigContentDigest)
	}
	if len(seen) != len(profileMembers) {
		return errors.New("tosctl corroboration snapshot omits a profile member")
	}
	identity, err := tosctlRustFramedDigest(tosctlSponsorshipSnapshotDomain,
		map[string]any{"evidence_profile_digest": manifest.EvidenceProfileDigest,
			"config_content_digests": contentDigests, "snapshot_nonce": manifest.SnapshotNonce})
	if err != nil || identity != snapshot.identity {
		return errors.New("tosctl corroboration snapshot identity cannot be reproduced")
	}
	return nil
}

func resolveTOSCTLCorroborationSnapshotHandle(registryRoot, handle, identity string) (string, error) {
	if !filepath.IsAbs(registryRoot) || filepath.Clean(registryRoot) != registryRoot ||
		!validSHA256Digest(identity) || strings.Contains(handle, "\\") {
		return "", errors.New("tosctl corroboration snapshot handle is invalid")
	}
	directory := "corroboration-" + strings.TrimPrefix(identity, "sha256:")
	expected := path.Join(directory, "manifest.json")
	if handle != expected || path.Clean(handle) != handle {
		return "", errors.New("tosctl corroboration snapshot handle is invalid")
	}
	return filepath.Join(registryRoot, filepath.FromSlash(handle)), nil
}

func validTOSCTLSnapshotMemberBasename(value string) bool {
	return value != "" && len(value) <= 128 && value != "." && value != ".." &&
		filepath.IsLocal(value) && filepath.Base(value) == value &&
		!strings.ContainsAny(value, `/\\`)
}

func validTOSCTLSnapshotNonce(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func readBoundedPinnedFile(directory *relayPinnedDirectory, name string, maximum int64) ([]byte, error) {
	file, err := directory.openFile(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Size() <= 0 || info.Size() > maximum {
		return nil, errors.New("rooted snapshot file is not bounded")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(raw) == 0 || int64(len(raw)) > maximum || directory.ensureAttached() != nil {
		return nil, errors.New("read rooted bounded snapshot file")
	}
	return raw, nil
}

func readPinnedTOSCTLSnapshotManifest(snapshot tosctlRelaySponsorshipSnapshot) ([]byte, error) {
	if !validSHA256Digest(snapshot.identity) {
		return nil, errors.New("tosctl corroboration snapshot identity is invalid")
	}
	handle := "corroboration-" + strings.TrimPrefix(snapshot.identity, "sha256:") + "/manifest.json"
	expected, err := resolveTOSCTLCorroborationSnapshotHandle(snapshot.registryRoot, handle, snapshot.identity)
	if err != nil || expected != snapshot.manifestPath {
		return nil, errors.New("tosctl corroboration snapshot handle is inconsistent")
	}
	directory := filepath.Dir(expected)
	child := filepath.Base(directory)
	rootHandle, err := openRelayPinnedDirectory(snapshot.registryRoot)
	if err != nil {
		return nil, err
	}
	defer rootHandle.close()
	directoryHandle, err := openRelayPinnedDirectory(directory)
	if err != nil {
		return nil, err
	}
	defer directoryHandle.close()
	if err := rootHandle.ensureChild(child, directoryHandle); err != nil {
		return nil, err
	}
	return readBoundedPinnedFile(directoryHandle, "manifest.json", 1<<20)
}

func (snapshot tosctlRelaySponsorshipSnapshot) frozenProvider() RelaySponsorshipEvidenceSnapshot {
	return RelaySponsorshipEvidenceSnapshot{SchemaVersion: 2,
		EvidenceClass: string(snapshot.policy.EvidenceClass), ProfileURI: snapshot.policy.ProfileURI,
		ProfileDigest: snapshot.policy.ProfileDigest, MaximumTransactions: snapshot.maximumTransactions,
		RegistryRoot: snapshot.registryRoot, CustodyWallet: snapshot.custodyWallet,
		ProviderSourceAccount: snapshot.providerSource, FeeReserveNanoTOS: snapshot.feeReserveNanoTOS,
		SnapshotPath:     snapshot.manifestPath,
		SnapshotIdentity: snapshot.identity}
}

func (snapshot tosctlRelaySponsorshipSnapshot) frozenClient() RelaySponsorshipEvidenceSnapshot {
	return RelaySponsorshipEvidenceSnapshot{SchemaVersion: 2,
		EvidenceClass: string(snapshot.policy.EvidenceClass), ProfileURI: snapshot.policy.ProfileURI,
		ProfileDigest: snapshot.policy.ProfileDigest, MaximumTransactions: snapshot.maximumTransactions,
		RegistryRoot: snapshot.registryRoot, SnapshotPath: snapshot.manifestPath, SnapshotIdentity: snapshot.identity}
}

func relayTOSCTLSponsorshipSnapshot(profile agentrelay.SponsorshipReleaseProfile,
	frozen RelaySponsorshipEvidenceSnapshot) tosctlRelaySponsorshipSnapshot {
	return tosctlRelaySponsorshipSnapshot{policy: RelaySponsorshipReleasePolicy{
		EvidenceClass: profile.EvidenceClass, ProfileURI: profile.ProfileURI, ProfileDigest: profile.ProfileDigest},
		maximumTransactions: frozen.MaximumTransactions, registryRoot: frozen.RegistryRoot,
		custodyWallet: frozen.CustodyWallet, providerSource: frozen.ProviderSourceAccount,
		feeReserveNanoTOS: frozen.FeeReserveNanoTOS,
		manifestPath:      frozen.SnapshotPath, identity: frozen.SnapshotIdentity}
}

// relaySponsorshipSnapshotNetwork returns the immutable network committed by
// the per-action snapshot. Recovery must never compare an admitted action with
// the sink's mutable current-network configuration: rotating the latter only
// affects new quotes.
func (sink *TOSCTLPaymentSink) relaySponsorshipSnapshotNetwork(
	frozen RelaySponsorshipEvidenceSnapshot) (agentrelay.NetworkDomain, error) {
	profile := agentrelay.SponsorshipReleaseProfile{
		EvidenceClass: agentrelay.SponsorshipReleaseEvidenceClass(frozen.EvidenceClass),
		ProfileURI:    frozen.ProfileURI, ProfileDigest: frozen.ProfileDigest,
	}
	if err := sink.ValidateRelaySponsorshipEvidenceSnapshot(profile, frozen); err != nil {
		return agentrelay.NetworkDomain{}, err
	}
	raw, err := readPinnedTOSCTLSnapshotManifest(relayTOSCTLSponsorshipSnapshot(profile, frozen))
	if err != nil {
		return agentrelay.NetworkDomain{}, errors.New("read frozen corroboration snapshot network")
	}
	var manifest tosctlRelaySponsorshipSnapshotManifest
	if decodeStrictJSON(raw, &manifest) != nil {
		return agentrelay.NetworkDomain{}, errors.New("decode frozen corroboration snapshot network")
	}
	if _, err := agentrelay.NetworkDomainDigest(manifest.NetworkDomain); err != nil {
		return agentrelay.NetworkDomain{}, errors.New("frozen corroboration snapshot network is invalid")
	}
	return manifest.NetworkDomain, nil
}

func (sink *TOSCTLPaymentSink) relaySponsorshipSnapshotPrimaryConfig(
	frozen RelaySponsorshipEvidenceSnapshot) (string, error) {
	policy := RelaySponsorshipReleasePolicy{EvidenceClass: agentrelay.SponsorshipReleaseEvidenceClass(frozen.EvidenceClass),
		ProfileURI: frozen.ProfileURI, ProfileDigest: frozen.ProfileDigest}
	snapshot := relayTOSCTLSponsorshipSnapshot(agentrelay.SponsorshipReleaseProfile{
		EvidenceClass: policy.EvidenceClass, ProfileURI: policy.ProfileURI, ProfileDigest: policy.ProfileDigest}, frozen)
	if err := sink.validateRelaySponsorshipSnapshot(snapshot); err != nil {
		return "", err
	}
	raw, err := readPinnedTOSCTLSnapshotManifest(snapshot)
	if err != nil {
		return "", err
	}
	var manifest tosctlRelaySponsorshipSnapshotManifest
	if decodeStrictJSON(raw, &manifest) != nil || len(manifest.Members) < 3 {
		return "", errors.New("frozen corroboration snapshot has no primary custody config")
	}
	if !validTOSCTLSnapshotMemberBasename(manifest.Members[0].ConfigPath) {
		return "", errors.New("frozen corroboration snapshot primary config handle is invalid")
	}
	return filepath.Join(filepath.Dir(snapshot.manifestPath), manifest.Members[0].ConfigPath), nil
}

func buildTOSCTLSponsorshipEvidenceProfile(paths []string, network agentrelay.NetworkDomain,
	maximumTransactions uint32) (RelaySponsorshipReleasePolicy, [][]byte, error) {
	if len(paths) < 3 {
		return RelaySponsorshipReleasePolicy{}, nil, errors.New("at least three tosctl quorum configurations are required")
	}
	raws := make([][]byte, len(paths))
	for index, path := range paths {
		raw, err := readBoundedRegularFile(path, tosctlMaximumConfigBytes, false)
		if err != nil {
			return RelaySponsorshipReleasePolicy{}, nil, err
		}
		raws[index] = raw
	}
	profile, _, err := buildTOSCTLSponsorshipEvidenceProfileFromRaw(raws, network, maximumTransactions)
	return profile, raws, err
}

func buildTOSCTLSponsorshipEvidenceProfileFromRaw(raws [][]byte, network agentrelay.NetworkDomain,
	maximumTransactions uint32) (RelaySponsorshipReleasePolicy, tosctlRelaySponsorshipEvidenceProfile, error) {
	if len(raws) < 3 || maximumTransactions == 0 || maximumTransactions > 10_000 {
		return RelaySponsorshipReleasePolicy{}, tosctlRelaySponsorshipEvidenceProfile{},
			errors.New("tosctl sponsorship profile bounds are invalid")
	}
	members := make([]tosctlRelaySponsorshipEvidenceProfileMember, 0, len(raws))
	endpoints, operators := map[string]bool{}, map[string]bool{}
	for _, raw := range raws {
		endpoint, locatorDigest, _, operator, err := tosctlRPCProfileMember(raw)
		if err != nil || endpoints[endpoint] || operators[operator] {
			return RelaySponsorshipReleasePolicy{}, tosctlRelaySponsorshipEvidenceProfile{},
				errors.New("tosctl sponsorship profile lacks distinct endpoint/operator failure domains")
		}
		endpoints[endpoint], operators[operator] = true, true
		members = append(members, tosctlRelaySponsorshipEvidenceProfileMember{Endpoint: endpoint,
			LocatorIdentityDigest: locatorDigest, OperatorProvenance: operator})
	}
	sort.Slice(members, func(left, right int) bool {
		if members[left].Endpoint != members[right].Endpoint {
			return members[left].Endpoint < members[right].Endpoint
		}
		if members[left].LocatorIdentityDigest != members[right].LocatorIdentityDigest {
			return members[left].LocatorIdentityDigest < members[right].LocatorIdentityDigest
		}
		return members[left].OperatorProvenance < members[right].OperatorProvenance
	})
	profile := tosctlRelaySponsorshipEvidenceProfile{ProfileURI: agentrelay.RPCCorroborationEvidenceProfileURI,
		NetworkDomain: network, Members: members, Threshold: uint32(len(members)/2 + 1),
		MaximumHistoryTransactions: maximumTransactions, StrictMajority: true,
		ExactSubmittedMessage: true, ExactDestinationCredit: true, ValidatorFinalityProven: false}
	digest, err := tosctlRustFramedDigest(tosctlSponsorshipProfileDomain, tosctlProfileDigestValue(profile))
	if err != nil {
		return RelaySponsorshipReleasePolicy{}, tosctlRelaySponsorshipEvidenceProfile{}, err
	}
	return RelaySponsorshipReleasePolicy{EvidenceClass: agentrelay.SponsorshipReleaseObservedUnproven,
		ProfileURI: profile.ProfileURI, ProfileDigest: digest}, profile, nil
}

func tosctlRPCProfileMember(raw []byte) (string, string, string, string, error) {
	var config tosctlChainRPCConfigFile
	if rejectDuplicateJSONKeys(raw) != nil || json.Unmarshal(raw, &config) != nil {
		return "", "", "", "", errors.New("decode tosctl chain-rpc config")
	}
	values := make([]string, 0, len(config.ChainRPC.URLs)+1)
	if config.ChainRPC.LegacyURL != nil {
		values = append(values, *config.ChainRPC.LegacyURL)
	}
	for _, encoded := range config.ChainRPC.URLs {
		var value string
		if err := json.Unmarshal(encoded, &value); err != nil {
			var object struct {
				URL    string `json:"url"`
				APIKey string `json:"api_key"`
			}
			if json.Unmarshal(encoded, &object) != nil || object.URL == "" || object.APIKey == "" {
				return "", "", "", "", errors.New("tosctl chain-rpc endpoint entry is invalid")
			}
			value = object.URL
		}
		if value != "" && !containsTOSCTLString(values, value) {
			values = append(values, value)
		}
	}
	if len(values) == 0 {
		values = []string{"http://127.0.0.1:3301"}
	}
	if len(values) != 1 || config.ChainRPC.OperatorProvenance == nil ||
		!validSHA256Digest(*config.ChainRPC.OperatorProvenance) {
		return "", "", "", "", errors.New("tosctl quorum config must pin one endpoint and one operator")
	}
	locator, endpoint, err := canonicalTOSCTLRPCConfigLocator(values[0])
	if err != nil {
		return "", "", "", "", err
	}
	locatorDigest := tosctlFramedBytesDigest(tosctlRPCLocatorIdentityDomain, []byte(locator))
	return endpoint, locatorDigest, sha256Digest(raw), *config.ChainRPC.OperatorProvenance, nil
}

func canonicalTOSCTLRPCEndpoint(value string) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil || (parsed.EscapedPath() != "" && parsed.EscapedPath() != "/") {
		return "", errors.New("public tosctl chain-rpc endpoint must be an origin")
	}
	_, origin, err := canonicalTOSCTLRPCConfigLocator(value)
	return origin, err
}

// canonicalTOSCTLRPCConfigLocator derives the canonical private locator and
// its origin-only public projection. Public profiles commit the former only
// through locator_identity_digest; they never disclose its path.
func canonicalTOSCTLRPCConfigLocator(value string) (string, string, error) {
	if value == "" || value != strings.TrimSpace(value) {
		return "", "", errors.New("unsafe tosctl chain-rpc endpoint")
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x21 || value[index] > 0x7e {
			return "", "", errors.New("tosctl chain-rpc endpoint must use printable ASCII")
		}
	}
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || strings.Contains(parsed.EscapedPath(), "%") {
		return "", "", errors.New("unsafe tosctl chain-rpc endpoint")
	}
	if strings.Contains(parsed.Path, `\`) || strings.Contains(parsed.Path, "//") {
		return "", "", errors.New("tosctl chain-rpc endpoint path is not canonical")
	}
	for _, segment := range strings.Split(parsed.Path, "/") {
		if segment == "." || segment == ".." {
			return "", "", errors.New("tosctl chain-rpc endpoint path is not canonical")
		}
	}
	hostname := strings.TrimSuffix(parsed.Hostname(), ".")
	hostname = strings.ToLower(hostname)
	if hostname == "" {
		return "", "", errors.New("tosctl chain-rpc endpoint has no host")
	}
	port := parsed.Port()
	if (parsed.Scheme == "http" && port == "80") || (parsed.Scheme == "https" && port == "443") {
		port = ""
	}
	if parsed.Scheme == "http" && !strings.EqualFold(hostname, "localhost") {
		address := net.ParseIP(hostname)
		if address == nil || !address.IsLoopback() {
			return "", "", errors.New("remote tosctl chain-rpc endpoint must use HTTPS")
		}
	}
	if strings.Contains(hostname, ":") {
		parsed.Host = "[" + hostname + "]"
	} else {
		parsed.Host = hostname
	}
	if port != "" {
		parsed.Host = net.JoinHostPort(hostname, port)
	}
	origin := url.URL{Scheme: strings.ToLower(parsed.Scheme), Host: parsed.Host}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.User, parsed.RawQuery, parsed.Fragment = nil, "", ""
	canonicalLocator := strings.TrimRight(parsed.String(), "/")
	if strings.HasSuffix(canonicalLocator, ":") {
		canonicalLocator += "/"
	}
	if canonicalLocator != value {
		return "", "", errors.New("tosctl chain-rpc endpoint is not in canonical form")
	}
	return canonicalLocator, strings.TrimRight(origin.String(), "/"), nil
}

func tosctlProfileDigestValue(profile tosctlRelaySponsorshipEvidenceProfile) map[string]any {
	members := make([]map[string]any, 0, len(profile.Members))
	for _, member := range profile.Members {
		members = append(members, map[string]any{"endpoint": member.Endpoint,
			"locator_identity_digest": member.LocatorIdentityDigest,
			"operator_provenance":     member.OperatorProvenance})
	}
	network := map[string]any{"network_id": profile.NetworkDomain.NetworkID,
		"global_id": profile.NetworkDomain.GlobalID, "zero_state_root_hash": profile.NetworkDomain.ZeroStateRootHash,
		"zero_state_file_hash": profile.NetworkDomain.ZeroStateFileHash, "workchain_id": profile.NetworkDomain.WorkchainID}
	// serde_json's default object map is recursively lexicographic. Go's map
	// encoder produces the same compact ordering for this frozen cross-language
	// descriptor; observation digests remain declaration-order Rust structs.
	return map[string]any{"profile_uri": profile.ProfileURI, "network_domain": network,
		"members": members, "threshold": profile.Threshold,
		"maximum_history_transactions": profile.MaximumHistoryTransactions,
		"strict_majority":              profile.StrictMajority, "exact_submitted_message": profile.ExactSubmittedMessage,
		"exact_destination_credit":  profile.ExactDestinationCredit,
		"validator_finality_proven": profile.ValidatorFinalityProven}
}

func tosctlRustFramedDigest(domain string, value any) (string, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return "", err
	}
	encoded := bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'})
	hash := sha256.New()
	_, _ = hash.Write([]byte(domain))
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(encoded)))
	_, _ = hash.Write(length[:])
	_, _ = hash.Write(encoded)
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func tosctlFramedBytesDigest(domain string, value []byte) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(domain))
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = hash.Write(length[:])
	_, _ = hash.Write(value)
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

type tosctlPaymentObservationQuorumKey struct {
	TransactionHash                 string
	TransactionLT                   uint64
	TransactionUTime                uint64
	TransactionBOCDigest            string
	SourceOutboundMessageHash       string
	DestinationCreditReference      string
	DestinationTransactionHash      string
	DestinationTransactionLT        uint64
	DestinationTransactionUTime     uint64
	DestinationTransactionBOCDigest string
	DestinationBlockWorkchain       int32
	DestinationBlockShard           int64
	DestinationBlockSeqno           uint32
	DestinationBlockRootHash        string
	DestinationBlockFileHash        string
	DestinationCreditAtomic         string
	DestinationCreditFirst          bool
	DestinationTransactionAborted   bool
	DestinationBouncePresent        bool
	DestinationCreditObservedExact  bool
	BlockWorkchain                  int32
	BlockShard                      int64
	BlockSeqno                      uint32
	BlockRootHash                   string
	BlockFileHash                   string
	NetworkGlobalID                 int32
	ZeroStateWorkchain              int32
	ZeroStateShard                  int64
	ZeroStateSeqno                  uint32
	ZeroStateRootHash               string
	ZeroStateFileHash               string
	ObservedMasterchainWorkchain    int32
	ObservedMasterchainShard        int64
	ObservedMasterchainSeqno        uint32
	ObservedMasterchainRootHash     string
	ObservedMasterchainFileHash     string
	ObservedMasterchainGenUTime     uint64
}

func (observation tosctlPaymentObservation) quorumKey() tosctlPaymentObservationQuorumKey {
	return tosctlPaymentObservationQuorumKey{TransactionHash: observation.TransactionHash,
		TransactionLT: observation.TransactionLT, TransactionUTime: observation.TransactionUTime,
		TransactionBOCDigest:            observation.TransactionBOCDigest,
		SourceOutboundMessageHash:       observation.SourceOutboundMessageHash,
		DestinationCreditReference:      observation.DestinationCreditReference,
		DestinationTransactionHash:      observation.DestinationTransactionHash,
		DestinationTransactionLT:        observation.DestinationTransactionLT,
		DestinationTransactionUTime:     observation.DestinationTransactionUTime,
		DestinationTransactionBOCDigest: observation.DestinationTransactionBOCDigest,
		DestinationBlockWorkchain:       observation.DestinationBlockWorkchain,
		DestinationBlockShard:           observation.DestinationBlockShard,
		DestinationBlockSeqno:           observation.DestinationBlockSeqno,
		DestinationBlockRootHash:        observation.DestinationBlockRootHash,
		DestinationBlockFileHash:        observation.DestinationBlockFileHash,
		DestinationCreditAtomic:         observation.DestinationCreditAtomic,
		DestinationCreditFirst:          observation.DestinationCreditFirst,
		DestinationTransactionAborted:   observation.DestinationTransactionAborted,
		DestinationBouncePresent:        observation.DestinationBouncePresent,
		DestinationCreditObservedExact:  observation.DestinationCreditObservedExact,
		BlockWorkchain:                  observation.BlockWorkchain, BlockShard: observation.BlockShard,
		BlockSeqno: observation.BlockSeqno, BlockRootHash: observation.BlockRootHash,
		BlockFileHash: observation.BlockFileHash, NetworkGlobalID: observation.NetworkGlobalID,
		ZeroStateWorkchain: observation.ZeroStateWorkchain, ZeroStateShard: observation.ZeroStateShard,
		ZeroStateSeqno: observation.ZeroStateSeqno, ZeroStateRootHash: observation.ZeroStateRootHash,
		ZeroStateFileHash:            observation.ZeroStateFileHash,
		ObservedMasterchainWorkchain: observation.ObservedMasterchainWorkchain,
		ObservedMasterchainShard:     observation.ObservedMasterchainShard,
		ObservedMasterchainSeqno:     observation.ObservedMasterchainSeqno,
		ObservedMasterchainRootHash:  observation.ObservedMasterchainRootHash,
		ObservedMasterchainFileHash:  observation.ObservedMasterchainFileHash,
		ObservedMasterchainGenUTime:  observation.ObservedMasterchainGenUTime}
}

func verifyTOSCTLSponsorshipCorroboration(result tosctlRelaySponsorshipObserved,
	policy RelaySponsorshipReleasePolicy) error {
	if validateTOSCTLSponsorshipEvidenceProfile(result.EvidenceProfile) != nil ||
		result.EvidenceProfile.ProfileURI != policy.ProfileURI ||
		result.EvidenceProfile.NetworkDomain != result.NetworkDomain ||
		result.EvidenceProfile.MaximumHistoryTransactions == 0 ||
		result.EvidenceProfile.MaximumHistoryTransactions > 10_000 ||
		!result.EvidenceProfile.StrictMajority || !result.EvidenceProfile.ExactSubmittedMessage ||
		!result.EvidenceProfile.ExactDestinationCredit || result.EvidenceProfile.ValidatorFinalityProven {
		return errors.New("tosctl sponsorship evidence profile has unsafe semantics")
	}
	profileDigest, err := tosctlRustFramedDigest(tosctlSponsorshipProfileDomain,
		tosctlProfileDigestValue(result.EvidenceProfile))
	if err != nil || profileDigest != policy.ProfileDigest || profileDigest != result.EvidenceProfileDigest {
		return errors.New("tosctl sponsorship evidence profile digest is not reproducible")
	}
	members := result.EvidenceProfile.Members
	if len(members) != int(result.Quorum.Members) || len(members) < 3 ||
		result.Quorum.Threshold != uint32(len(members)/2+1) ||
		result.EvidenceProfile.Threshold != result.Quorum.Threshold ||
		len(result.Observations)+len(result.Failures) != len(members) {
		return errors.New("tosctl sponsorship quorum does not match the frozen profile")
	}
	pairs := make(map[string]bool, len(members))
	profileEndpoints, profileOperators := make(map[string]bool, len(members)), make(map[string]bool, len(members))
	for index, member := range members {
		canonicalEndpoint, endpointErr := canonicalTOSCTLRPCEndpoint(member.Endpoint)
		if endpointErr != nil || canonicalEndpoint != member.Endpoint ||
			!validSHA256Digest(member.LocatorIdentityDigest) || !validSHA256Digest(member.OperatorProvenance) {
			return errors.New("tosctl sponsorship profile member is incomplete")
		}
		pair := tosctlSponsorshipMemberKey(member.Endpoint, member.LocatorIdentityDigest,
			member.OperatorProvenance)
		if pairs[pair] || profileEndpoints[member.Endpoint] || profileOperators[member.OperatorProvenance] {
			return errors.New("tosctl sponsorship profile repeats an endpoint or operator failure domain")
		}
		if index > 0 {
			previous := members[index-1]
			if member.Endpoint < previous.Endpoint ||
				(member.Endpoint == previous.Endpoint && member.LocatorIdentityDigest < previous.LocatorIdentityDigest) ||
				(member.Endpoint == previous.Endpoint && member.LocatorIdentityDigest == previous.LocatorIdentityDigest &&
					member.OperatorProvenance <= previous.OperatorProvenance) {
				return errors.New("tosctl sponsorship profile members are not canonically sorted")
			}
		}
		pairs[pair] = true
		profileEndpoints[member.Endpoint], profileOperators[member.OperatorProvenance] = true, true
	}
	seenEndpoints, seenOperators := map[string]bool{}, map[string]bool{}
	profileOperatorByEndpoint := make(map[string]string, len(members))
	for _, member := range members {
		profileOperatorByEndpoint[member.Endpoint] = member.OperatorProvenance
	}
	groups := make(map[tosctlPaymentObservationQuorumKey][]tosctlPaymentObservation)
	for _, observation := range result.Observations {
		pair := tosctlSponsorshipMemberKey(observation.Endpoint, observation.LocatorIdentityDigest,
			observation.OperatorProvenance)
		if !pairs[pair] || seenEndpoints[observation.Endpoint] || seenOperators[observation.OperatorProvenance] ||
			!validTOSCTLPaymentObservation(observation, result.NetworkDomain, result.NetworkGlobalID) {
			return errors.New("tosctl sponsorship corroboration contains an unauthorized observation")
		}
		seenEndpoints[observation.Endpoint], seenOperators[observation.OperatorProvenance] = true, true
		key := observation.quorumKey()
		groups[key] = append(groups[key], observation)
	}
	for _, failure := range result.Failures {
		endpoint, failureErr := tosctlSponsorshipFailureEndpoint(failure)
		operator, authorized := profileOperatorByEndpoint[endpoint]
		if failureErr != nil || !authorized || seenEndpoints[endpoint] || seenOperators[operator] {
			return errors.New("tosctl sponsorship corroboration contains an unauthorized failure")
		}
		seenEndpoints[endpoint], seenOperators[operator] = true, true
	}
	var winner []tosctlPaymentObservation
	for _, group := range groups {
		if len(group) >= int(result.Quorum.Threshold) {
			if winner != nil {
				return errors.New("tosctl sponsorship corroboration has multiple quorum winners")
			}
			winner = group
		}
	}
	if len(winner) < int(result.Quorum.Threshold) || result.Quorum.Agreeing != uint32(len(winner)) ||
		!reflectTOSCTLObservationEqual(result.Evidence, winner[0]) {
		return errors.New("tosctl sponsorship corroboration has no reproducible strict-majority winner")
	}
	digests := make([]string, 0, len(winner))
	for _, observation := range winner {
		digest, digestErr := tosctlRustFramedDigest(tosctlSponsorshipObservationDomain, observation)
		if digestErr != nil {
			return digestErr
		}
		digests = append(digests, digest)
	}
	sort.Strings(digests)
	for index := 1; index < len(digests); index++ {
		if digests[index] == digests[index-1] {
			return errors.New("tosctl sponsorship winner repeats an observation digest")
		}
	}
	if !equalStrings(digests, result.ObservationDigests) {
		return errors.New("tosctl sponsorship observation digest set is not the strict-majority winner")
	}
	return nil
}

func validateTOSCTLSponsorshipEvidenceProfile(profile tosctlRelaySponsorshipEvidenceProfile) error {
	if profile.ProfileURI != agentrelay.RPCCorroborationEvidenceProfileURI || len(profile.Members) < 3 ||
		profile.Threshold != uint32(len(profile.Members)/2+1) || profile.MaximumHistoryTransactions == 0 ||
		profile.MaximumHistoryTransactions > 10_000 || !profile.StrictMajority ||
		!profile.ExactSubmittedMessage || !profile.ExactDestinationCredit || profile.ValidatorFinalityProven {
		return errors.New("tosctl sponsorship evidence profile has unsafe bounds")
	}
	endpoints, operators := map[string]bool{}, map[string]bool{}
	for index, member := range profile.Members {
		canonicalEndpoint, endpointErr := canonicalTOSCTLRPCEndpoint(member.Endpoint)
		if endpointErr != nil || canonicalEndpoint != member.Endpoint ||
			!validSHA256Digest(member.LocatorIdentityDigest) || !validSHA256Digest(member.OperatorProvenance) ||
			endpoints[member.Endpoint] || operators[member.OperatorProvenance] {
			return errors.New("tosctl sponsorship evidence profile repeats a failure domain")
		}
		if index > 0 {
			previous := profile.Members[index-1]
			if member.Endpoint < previous.Endpoint ||
				(member.Endpoint == previous.Endpoint && member.LocatorIdentityDigest < previous.LocatorIdentityDigest) ||
				(member.Endpoint == previous.Endpoint && member.LocatorIdentityDigest == previous.LocatorIdentityDigest &&
					member.OperatorProvenance <= previous.OperatorProvenance) {
				return errors.New("tosctl sponsorship evidence profile is not canonically sorted")
			}
		}
		endpoints[member.Endpoint], operators[member.OperatorProvenance] = true, true
	}
	return nil
}

func validTOSCTLPaymentObservation(value tosctlPaymentObservation, network agentrelay.NetworkDomain,
	globalID int32) bool {
	canonicalEndpoint, endpointErr := canonicalTOSCTLRPCEndpoint(value.Endpoint)
	return endpointErr == nil && canonicalEndpoint == value.Endpoint &&
		validSHA256Digest(value.LocatorIdentityDigest) && validSHA256Digest(value.OperatorProvenance) &&
		validSHA256Digest(value.TransactionHash) && value.TransactionLT > 0 && value.TransactionUTime > 0 &&
		validSHA256Digest(value.TransactionBOCDigest) && validTVMCellSHA256(value.SourceOutboundMessageHash) &&
		validSHA256Digest(value.DestinationCreditReference) && validSHA256Digest(value.DestinationTransactionHash) &&
		value.DestinationTransactionLT > 0 && value.DestinationTransactionUTime > 0 &&
		validSHA256Digest(value.DestinationTransactionBOCDigest) && value.DestinationBlockSeqno > 0 &&
		validSHA256Digest(value.DestinationBlockRootHash) && validSHA256Digest(value.DestinationBlockFileHash) &&
		value.DestinationCreditAtomic != "" && value.DestinationCreditFirst &&
		!value.DestinationBouncePresent && value.DestinationCreditObservedExact &&
		value.BlockWorkchain == network.WorkchainID && value.BlockSeqno > 0 &&
		validSHA256Digest(value.BlockRootHash) && validSHA256Digest(value.BlockFileHash) &&
		value.NetworkGlobalID == globalID && value.ZeroStateRootHash == network.ZeroStateRootHash &&
		value.ZeroStateFileHash == network.ZeroStateFileHash && value.ObservedMasterchainSeqno > 0 &&
		validSHA256Digest(value.ObservedMasterchainRootHash) && validSHA256Digest(value.ObservedMasterchainFileHash) &&
		value.ObservedMasterchainGenUTime > 0 && !value.FinalityProven
}

func tosctlSponsorshipMemberKey(endpoint, configContentDigest, operatorProvenance string) string {
	return endpoint + "\x00" + configContentDigest + "\x00" + operatorProvenance
}

func tosctlSponsorshipFailureEndpoint(value string) (string, error) {
	const marker = ": rpc_failure_category="
	endpoint, category, found := strings.Cut(value, marker)
	if !found || (category != "not_found" && category != "temporarily_unavailable" &&
		category != "invalid_or_conflicting_response") {
		return "", errors.New("tosctl sponsorship failure diagnostic is invalid")
	}
	canonical, err := canonicalTOSCTLRPCEndpoint(endpoint)
	if err != nil || canonical != endpoint {
		return "", errors.New("tosctl sponsorship failure diagnostic exposes a non-public endpoint")
	}
	return endpoint, nil
}

func reflectTOSCTLObservationEqual(left, right tosctlPaymentObservation) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func readBoundedRegularFile(path string, maximum int64, ownerOnly bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 ||
		info.Size() > maximum || ownerOnly && info.Mode().Perm() != 0o600 {
		return nil, errors.New("file is not a bounded regular owner-approved file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("open bounded owner-approved file")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() ||
		opened.Size() <= 0 || opened.Size() > maximum || ownerOnly && opened.Mode().Perm() != 0o600 {
		return nil, errors.New("owner-approved file changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(raw) == 0 || int64(len(raw)) > maximum {
		return nil, errors.New("read bounded owner-approved file")
	}
	return raw, nil
}

func sha256Digest(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func validSHA256Digest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func containsTOSCTLString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
