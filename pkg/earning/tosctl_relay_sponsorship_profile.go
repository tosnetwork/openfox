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
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
)

const (
	tosctlSponsorshipProfileDomain     = "tosctl.agreement-payment-rpc-corroboration-profile.v1\x00"
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
	CorroborationSnapshot         string                                `json:"corroboration_snapshot"`
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
	ConfigPath          string `json:"config_path"`
	ConfigContentDigest string `json:"config_content_digest"`
	Endpoint            string `json:"endpoint"`
	OperatorProvenance  string `json:"operator_provenance"`
}

type tosctlRelaySponsorshipSnapshotManifest struct {
	Schema                     string                                 `json:"schema"`
	SnapshotIdentity           string                                 `json:"snapshot_identity"`
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
	snapshot := tosctlRelaySponsorshipSnapshot{policy: policy,
		maximumTransactions: capability.MaximumHistoryTransactions,
		registryRoot:        directory,
		custodyWallet:       sink.Wallet,
		providerSource:      sink.SourceAccount,
		feeReserveNanoTOS:   sink.FeeReserveNanoTOS,
		manifestPath:        capability.CorroborationSnapshot,
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
	directory := filepath.Dir(snapshot.manifestPath)
	relative, err := filepath.Rel(root, directory)
	if err != nil || relative == "." || strings.HasPrefix(relative, "..") || strings.Contains(relative, string(os.PathSeparator)) ||
		!strings.HasPrefix(relative, "corroboration-") || validateRelayJournalDirectorySecurity(root) != nil ||
		validateRelayJournalDirectorySecurity(directory) != nil {
		return errors.New("tosctl corroboration snapshot escaped its owner-private registry")
	}
	raw, err := readBoundedRegularFile(snapshot.manifestPath, 1<<20, true)
	if err != nil {
		return errors.New("read tosctl corroboration snapshot manifest")
	}
	var manifest tosctlRelaySponsorshipSnapshotManifest
	if decodeStrictJSON(raw, &manifest) != nil ||
		manifest.Schema != "tosctl.agent-account.agreement-payment-rpc-corroboration-snapshot.v1" ||
		manifest.SnapshotIdentity != snapshot.identity || manifest.EvidenceProfileURI != snapshot.policy.ProfileURI ||
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
		profileMembers[member.Endpoint+"\x00"+member.OperatorProvenance] = true
	}
	seen := map[string]bool{}
	for _, member := range manifest.Members {
		if !filepath.IsAbs(member.ConfigPath) || filepath.Dir(member.ConfigPath) != directory ||
			!validSHA256Digest(member.ConfigContentDigest) || !validSHA256Digest(member.OperatorProvenance) ||
			!profileMembers[member.Endpoint+"\x00"+member.OperatorProvenance] ||
			seen[member.Endpoint+"\x00"+member.OperatorProvenance] {
			return errors.New("tosctl corroboration snapshot member is not in the frozen profile")
		}
		memberRaw, readErr := readBoundedRegularFile(member.ConfigPath, tosctlMaximumConfigBytes, true)
		if readErr != nil || sha256Digest(memberRaw) != member.ConfigContentDigest {
			return errors.New("tosctl corroboration snapshot member bytes changed")
		}
		seen[member.Endpoint+"\x00"+member.OperatorProvenance] = true
		contentDigests = append(contentDigests, member.ConfigContentDigest)
	}
	if len(seen) != len(profileMembers) {
		return errors.New("tosctl corroboration snapshot omits a profile member")
	}
	identity, err := tosctlRustFramedDigest(tosctlSponsorshipSnapshotDomain,
		map[string]any{"evidence_profile_digest": manifest.EvidenceProfileDigest,
			"config_content_digests": contentDigests})
	if err != nil || identity != snapshot.identity {
		return errors.New("tosctl corroboration snapshot identity cannot be reproduced")
	}
	return nil
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
	raw, err := readBoundedRegularFile(frozen.SnapshotPath, 1<<20, true)
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
	raw, err := readBoundedRegularFile(snapshot.manifestPath, 1<<20, true)
	if err != nil {
		return "", err
	}
	var manifest tosctlRelaySponsorshipSnapshotManifest
	if decodeStrictJSON(raw, &manifest) != nil || len(manifest.Members) < 3 {
		return "", errors.New("frozen corroboration snapshot has no primary custody config")
	}
	return manifest.Members[0].ConfigPath, nil
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
		endpoint, operator, err := tosctlRPCProfileMember(raw)
		if err != nil || endpoints[endpoint] || operators[operator] {
			return RelaySponsorshipReleasePolicy{}, tosctlRelaySponsorshipEvidenceProfile{},
				errors.New("tosctl sponsorship profile lacks distinct endpoint/operator failure domains")
		}
		endpoints[endpoint], operators[operator] = true, true
		members = append(members, tosctlRelaySponsorshipEvidenceProfileMember{Endpoint: endpoint,
			OperatorProvenance: operator})
	}
	sort.Slice(members, func(left, right int) bool {
		if members[left].Endpoint != members[right].Endpoint {
			return members[left].Endpoint < members[right].Endpoint
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

func tosctlRPCProfileMember(raw []byte) (string, string, error) {
	var config tosctlChainRPCConfigFile
	if err := json.Unmarshal(raw, &config); err != nil {
		return "", "", errors.New("decode tosctl chain-rpc config")
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
				return "", "", errors.New("tosctl chain-rpc endpoint entry is invalid")
			}
			value = object.URL
		}
		value = strings.TrimSpace(value)
		if value != "" && !containsTOSCTLString(values, value) {
			values = append(values, value)
		}
	}
	if len(values) == 0 {
		values = []string{"http://127.0.0.1:3301/"}
	}
	if len(values) != 1 || config.ChainRPC.OperatorProvenance == nil ||
		!validSHA256Digest(*config.ChainRPC.OperatorProvenance) {
		return "", "", errors.New("tosctl quorum config must pin one endpoint and one operator")
	}
	endpoint, err := canonicalTOSCTLRPCEndpoint(values[0])
	if err != nil {
		return "", "", err
	}
	return endpoint, *config.ChainRPC.OperatorProvenance, nil
}

func canonicalTOSCTLRPCEndpoint(value string) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || strings.Contains(parsed.EscapedPath(), "%") {
		return "", errors.New("unsafe tosctl chain-rpc endpoint")
	}
	hostname := strings.TrimSuffix(parsed.Hostname(), ".")
	hostname = strings.ToLower(hostname)
	if hostname == "" {
		return "", errors.New("tosctl chain-rpc endpoint has no host")
	}
	port := parsed.Port()
	if (parsed.Scheme == "http" && port == "80") || (parsed.Scheme == "https" && port == "443") {
		port = ""
	}
	if parsed.Scheme == "http" && !strings.EqualFold(hostname, "localhost") {
		address := net.ParseIP(hostname)
		if address == nil || !address.IsLoopback() {
			return "", errors.New("remote tosctl chain-rpc endpoint must use HTTPS")
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
	parsed.RawQuery, parsed.Fragment = "", ""
	canonical := strings.TrimRight(parsed.String(), "/")
	if strings.HasSuffix(canonical, ":") {
		canonical += "/"
	}
	return canonical, nil
}

func tosctlProfileDigestValue(profile tosctlRelaySponsorshipEvidenceProfile) map[string]any {
	members := make([]map[string]any, 0, len(profile.Members))
	for _, member := range profile.Members {
		members = append(members, map[string]any{"endpoint": member.Endpoint,
			"operator_provenance": member.OperatorProvenance})
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
		if member.Endpoint == "" || !validSHA256Digest(member.OperatorProvenance) {
			return errors.New("tosctl sponsorship profile member is incomplete")
		}
		pair := member.Endpoint + "\x00" + member.OperatorProvenance
		if pairs[pair] || profileEndpoints[member.Endpoint] || profileOperators[member.OperatorProvenance] {
			return errors.New("tosctl sponsorship profile repeats an endpoint or operator failure domain")
		}
		if index > 0 {
			previous := members[index-1]
			if member.Endpoint < previous.Endpoint ||
				(member.Endpoint == previous.Endpoint && member.OperatorProvenance <= previous.OperatorProvenance) {
				return errors.New("tosctl sponsorship profile members are not canonically sorted")
			}
		}
		pairs[pair] = true
		profileEndpoints[member.Endpoint], profileOperators[member.OperatorProvenance] = true, true
	}
	seenEndpoints, seenOperators := map[string]bool{}, map[string]bool{}
	groups := make(map[tosctlPaymentObservationQuorumKey][]tosctlPaymentObservation)
	for _, observation := range result.Observations {
		pair := observation.Endpoint + "\x00" + observation.OperatorProvenance
		if !pairs[pair] || seenEndpoints[observation.Endpoint] || seenOperators[observation.OperatorProvenance] ||
			!validTOSCTLPaymentObservation(observation, result.NetworkDomain, result.NetworkGlobalID) {
			return errors.New("tosctl sponsorship corroboration contains an unauthorized observation")
		}
		seenEndpoints[observation.Endpoint], seenOperators[observation.OperatorProvenance] = true, true
		key := observation.quorumKey()
		groups[key] = append(groups[key], observation)
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
		if member.Endpoint == "" || !validSHA256Digest(member.OperatorProvenance) ||
			endpoints[member.Endpoint] || operators[member.OperatorProvenance] {
			return errors.New("tosctl sponsorship evidence profile repeats a failure domain")
		}
		if index > 0 {
			previous := profile.Members[index-1]
			if member.Endpoint < previous.Endpoint ||
				(member.Endpoint == previous.Endpoint && member.OperatorProvenance <= previous.OperatorProvenance) {
				return errors.New("tosctl sponsorship evidence profile is not canonically sorted")
			}
		}
		endpoints[member.Endpoint], operators[member.OperatorProvenance] = true, true
	}
	return nil
}

func validTOSCTLPaymentObservation(value tosctlPaymentObservation, network agentrelay.NetworkDomain,
	globalID int32) bool {
	return value.Endpoint != "" && validSHA256Digest(value.OperatorProvenance) &&
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
	return os.ReadFile(path)
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
