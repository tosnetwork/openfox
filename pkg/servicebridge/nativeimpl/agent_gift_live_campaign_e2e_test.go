package nativeimpl

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	openfoxgift "github.com/tosnetwork/openfox/pkg/agentgift"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/chainactionpublisher"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
)

const liveGiftCampaignSchema = "tos.openfox.six-agent-live-gift-campaign.v1"

type liveGiftManifest struct {
	Agents []struct {
		Name    string `json:"name"`
		AgentID string `json:"agent_id"`
		Wallet  string `json:"wallet"`
		Target  string `json:"target"`
	} `json:"agents"`
}

type liveGiftAlias struct {
	Name, Alias string
}

type liveGiftAliasEvidence struct {
	Alias, AgentAccount string
	NodeResults         []string
}

type liveGiftEvent struct {
	EventID, Recipient, Kind, SemanticKey string
	CanonicalBytes                        int
}

type liveGiftWire struct {
	mu     sync.Mutex
	latest []byte
	events []liveGiftEvent
}

func (w *liveGiftWire) SendEstablishedDirect(_ context.Context, recipient, kind string, canonical []byte, semanticKey string) (string, error) {
	if len(canonical) == 0 || recipient == "" || kind == "" || semanticKey == "" {
		return "", errors.New("incomplete live Gift event")
	}
	digest := sha256.Sum256(append(append(append([]byte(recipient+"\x00"+kind+"\x00"+semanticKey+"\x00"), canonical...), byte(len(w.events))), 0))
	eventID := "evt_" + hex.EncodeToString(digest[:])
	w.mu.Lock()
	w.latest = append([]byte(nil), canonical...)
	w.events = append(w.events, liveGiftEvent{EventID: eventID, Recipient: recipient, Kind: kind, SemanticKey: semanticKey, CanonicalBytes: len(canonical)})
	w.mu.Unlock()
	return eventID, nil
}

func (w *liveGiftWire) body() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.latest...)
}

type liveGiftRecipientAuthority struct{ aliases map[string]string }

func (a liveGiftRecipientAuthority) ResolveCanonicalAgent(_ context.Context, input string) (string, error) {
	input = strings.ToLower(strings.TrimSpace(input))
	if value := a.aliases[input]; value != "" {
		return value, nil
	}
	if len(input) == 70 && strings.HasPrefix(input, "agent_") {
		if _, err := hex.DecodeString(input[6:]); err == nil {
			return input, nil
		}
	}
	return "", errors.New("recipient is not a finalized campaign alias or canonical AgentID")
}

type liveGiftOwnerPolicy struct {
	sender, recipient string
	maximum           uint64
}

func (p liveGiftOwnerPolicy) ConfirmAgentGift(_ context.Context, review openfoxgift.OwnerReview) error {
	amount, err := strconv.ParseUint(review.AmountAtomic, 10, 64)
	if err != nil || review.Action != "send" || review.SenderAgentAccount != p.sender ||
		review.RecipientAgentID != p.recipient || amount == 0 || amount > p.maximum || review.FundsLocked {
		return errors.New("live Gift exceeds the frozen owner policy")
	}
	return nil
}

type liveGiftResult struct {
	Sender, Recipient, SenderAlias, RecipientAlias string
	IntentID, SignedGiftID                         string
	AmountAtomic                                   string
	SenderFinalState, RecipientFinalState          openfoxgift.State
	RequestDigest, ResponseDigest, ExactBOCDigest  string
	RequestEventID, ResponseEventID, OfferEventID  string
}

type liveGiftReport struct {
	Schema, StartedAt, CompletedAt string
	Network                        *nativev1.NetworkDomain
	Aliases                        []liveGiftAliasEvidence
	Results                        []liveGiftResult
	Events                         []liveGiftEvent
}

// TestSixAgentLiveGiftRing is an explicitly gated local-network acceptance
// campaign. It uses the released Agent Gift protocol and service state machine,
// real Agent Account custody signing, exact-BOC broadcast, and three-node
// finalized reads. The in-process wire carries only the same canonical opaque
// payloads that production Messenger carries; it is not represented as a
// production transport test.
func TestSixAgentLiveGiftRing(t *testing.T) {
	if os.Getenv("OPENFOX_SIX_AGENT_LIVE_GIFT_CAMPAIGN") != "1" {
		t.Skip("set OPENFOX_SIX_AGENT_LIVE_GIFT_CAMPAIGN=1")
	}
	root := liveGiftEnv(t, "OPENFOX_SIX_AGENT_CAMPAIGN_ROOT")
	configPath := liveGiftEnv(t, "OPENFOX_TOSCTL_PRIMARY_CONFIG")
	quorumConfigs := []string{configPath, liveGiftEnv(t, "OPENFOX_TOSCTL_QUORUM_CONFIG_2"), liveGiftEnv(t, "OPENFOX_TOSCTL_QUORUM_CONFIG_3")}
	tosctlBinary := liveGiftEnv(t, "OPENFOX_TOSCTL")
	vaultURL := liveGiftEnv(t, "OPENFOX_TOS_VAULT_URL")
	rootHash := liveGiftEnv(t, "OPENFOX_TOS_ZERO_STATE_ROOT_HASH")
	fileHash := liveGiftEnv(t, "OPENFOX_TOS_ZERO_STATE_FILE_HASH")
	genesisRootBase64 := liveGiftEnv(t, "OPENFOX_TOS_ZERO_STATE_ROOT_BASE64")
	genesisFileBase64 := liveGiftEnv(t, "OPENFOX_TOS_ZERO_STATE_FILE_BASE64")
	dnsRoot := liveGiftEnv(t, "OPENFOX_TOS_DNS_ROOT")
	var manifest liveGiftManifest
	raw, err := os.ReadFile(filepath.Join(root, "six-agent-manifest.json"))
	if err != nil || json.Unmarshal(raw, &manifest) != nil || len(manifest.Agents) != 6 {
		t.Fatal("invalid live Gift campaign manifest")
	}
	aliases := []liveGiftAlias{
		{Name: "security-auditor", Alias: "alice.tos"},
		{Name: "software-builder", Alias: "bobby.tos"},
		{Name: "evidence-verifier", Alias: "carol.tos"},
		{Name: "storage-provider", Alias: "dave.tos"},
		{Name: "transaction-operator", Alias: "erin.tos"},
		{Name: "guarantor-analyst", Alias: "frank.tos"},
	}
	byName := make(map[string]int, len(manifest.Agents))
	aliasToAgent := make(map[string]string, len(aliases))
	for index, agent := range manifest.Agents {
		if len(agent.AgentID) != 70 || agent.AgentID != "agent_"+strings.TrimPrefix(agent.Target, "0:") {
			t.Fatalf("%s does not bind canonical AgentID to Agent Account", agent.Name)
		}
		byName[agent.Name] = index
	}
	for _, item := range aliases {
		index, ok := byName[item.Name]
		if !ok {
			t.Fatalf("missing alias owner %s", item.Name)
		}
		aliasToAgent[item.Alias] = manifest.Agents[index].AgentID
	}
	network := &nativev1.NetworkDomain{NetworkId: "tos:local-three-node",
		GenesisRootHash: rootHash, GenesisFileHash: fileHash}
	chain, err := toschain.New(toschain.Config{Network: network.NetworkId,
		PinnedNetworkDomain: &toschain.PinnedNetworkDomain{NetworkID: network.NetworkId, GlobalID: 3,
			ZeroStateRootHash: rootHash, ZeroStateFileHash: fileHash, WorkchainID: 0},
		Endpoints: []string{"http://127.0.0.1:19761/jsonRPC", "http://127.0.0.1:19762/jsonRPC", "http://127.0.0.1:19763/jsonRPC"}, Quorum: 2})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := toschain.NewAgentGiftReader(chain, network)
	if err != nil {
		t.Fatal(err)
	}
	finalized, err := NewAgentGiftChainAdapter(reader)
	if err != nil {
		t.Fatal(err)
	}
	protocol, err := NewAgentGiftProtocol(finalized, 50_000_000, 60)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := NewAgentGiftResolver(finalized, liveGiftRecipientAuthority{aliases: aliasToAgent})
	if err != nil {
		t.Fatal(err)
	}
	wire := &liveGiftWire{}
	services := make([]*openfoxgift.Service, len(manifest.Agents))
	workchain := int32(0)
	publisherWallets := map[string]string{
		"security-auditor": "dns-alice", "software-builder": "dns-bob",
		"evidence-verifier": "dns-carol", "storage-provider": "dns-dave",
		"transaction-operator": "dns-erin", "guarantor-analyst": "dns-frank",
	}
	for index, agent := range manifest.Agents {
		ownerAddress := liveGiftOwnerAddress(t, configPath, agent.Wallet)
		controllerKey := liveGiftControllerKey(t, configPath, agent.Wallet)
		custody, custodyErr := NewTOSCTLGiftCustody(TOSCTLGiftCustodyConfig{
			BinaryPath: tosctlBinary, ConfigPath: configPath, VaultURL: vaultURL, WalletName: agent.Wallet,
			OwnerWallet: ownerAddress, ControllerKeyID: controllerKey,
			AgentAccountWorkchain: &workchain, QuorumConfigPaths: quorumConfigs[1:],
			FeeReserveAtomic: 50_000_000, MinimumInclusionMargin: 60, Timeout: 90 * time.Second,
		}, finalized)
		if custodyErr != nil {
			t.Fatal(custodyErr)
		}
		publisher, publisherErr := chainactionpublisher.NewTosctlBackend(chainactionpublisher.TosctlBackendConfig{
			Network: network.NetworkId, Binary: tosctlBinary, ConfigPath: configPath, VaultURL: vaultURL,
			RPCURL: "http://127.0.0.1:19761/", GenesisRootHash: genesisRootBase64,
			GenesisFileHash: genesisFileBase64, WalletName: publisherWallets[agent.Name],
			Payer: ownerAddress,
		})
		if publisherErr != nil {
			t.Fatal(publisherErr)
		}
		if readyErr := publisher.CheckReady(t.Context()); readyErr != nil {
			t.Fatal(readyErr)
		}
		broadcaster, _ := NewAgentGiftBroadcaster(publisher)
		address, _ := NewStaticAgentGiftAddressAuthority(agent.Target)
		next := manifest.Agents[(index+1)%len(manifest.Agents)]
		owner, _ := NewAgentGiftOwnerAuthorizer(liveGiftOwnerPolicy{sender: agent.Target, recipient: next.AgentID, maximum: 100_000_000})
		journalDirectory := filepath.Join(root, "gifts", agent.Name)
		if mkdirErr := os.MkdirAll(journalDirectory, 0o700); mkdirErr != nil {
			t.Fatal(mkdirErr)
		}
		journal, journalErr := openfoxgift.OpenJournal(journalDirectory)
		if journalErr != nil {
			t.Fatal(journalErr)
		}
		t.Cleanup(func() { _ = journal.Close() })
		services[index], err = openfoxgift.NewService(journal, protocol, resolver, wire, custody, broadcaster, address, owner)
		if err != nil {
			t.Fatal(err)
		}
	}
	report := liveGiftReport{Schema: liveGiftCampaignSchema, StartedAt: time.Now().UTC().Format(time.RFC3339Nano), Network: network}
	for _, item := range aliases {
		account := manifest.Agents[byName[item.Name]].Target
		evidence := liveGiftAliasEvidence{Alias: item.Alias, AgentAccount: account}
		for node, config := range quorumConfigs {
			liveGiftVerifyAlias(t, config, dnsRoot, item.Alias, account)
			evidence.NodeResults = append(evidence.NodeResults, fmt.Sprintf("node-%d:found-safe", node+1))
		}
		report.Aliases = append(report.Aliases, evidence)
	}
	for index, sender := range manifest.Agents {
		recipientIndex := (index + 1) % len(manifest.Agents)
		recipient := manifest.Agents[recipientIndex]
		validUntil := uint32(time.Now().UTC().Add(15 * time.Minute).Unix())
		record, runErr := services[index].StartSender(t.Context(), openfoxgift.ModelProposal{
			Recipient: aliases[recipientIndex].Alias, AmountAtomic: "100000000",
			RequestedValidUntil: validUntil, Greeting: "A small thank-you from " + aliases[index].Alias,
		}, network.NetworkId, 3, sender.AgentID)
		if runErr != nil {
			t.Fatal(runErr)
		}
		record, runErr = services[index].RequestAddress(t.Context(), record.IntentID)
		if runErr != nil {
			t.Fatal(runErr)
		}
		recipientRecord, runErr := services[recipientIndex].ObserveRecipientRequest(t.Context(), wire.body(), recipient.AgentID, sender.AgentID)
		if runErr != nil {
			t.Fatal(runErr)
		}
		recipientRecord, runErr = services[recipientIndex].RespondAddress(t.Context(), recipientRecord.IntentID, validUntil)
		if runErr != nil {
			t.Fatal(runErr)
		}
		record, runErr = services[index].ObserveAddressResponse(t.Context(), record.IntentID, wire.body())
		if runErr != nil {
			t.Fatal(runErr)
		}
		record, runErr = services[index].Authorize(t.Context(), record.IntentID)
		if runErr == nil {
			record, runErr = services[index].Sign(t.Context(), record.IntentID, "A small thank-you from "+aliases[index].Alias)
		}
		if runErr == nil {
			record, runErr = services[index].DeliverOffer(t.Context(), record.IntentID)
		}
		if runErr == nil {
			recipientRecord, runErr = services[recipientIndex].ObserveAndBroadcastOffer(t.Context(), recipientRecord.IntentID, wire.body())
		}
		if runErr != nil {
			t.Fatalf("Gift %s -> %s: %v", sender.Name, recipient.Name, runErr)
		}
		deadline := time.Now().Add(90 * time.Second)
		for time.Now().Before(deadline) {
			record, runErr = services[index].Refresh(t.Context(), record.IntentID)
			if runErr == nil && record.State == openfoxgift.StateFinalizedPaid {
				break
			}
			time.Sleep(time.Second)
		}
		recipientRecord, runErr = services[recipientIndex].Refresh(t.Context(), recipientRecord.IntentID)
		if runErr != nil || record.State != openfoxgift.StateFinalizedPaid || recipientRecord.State != openfoxgift.StateFinalizedPaid {
			t.Fatalf("Gift %s -> %s did not finalize: sender=%s recipient=%s err=%v", sender.Name, recipient.Name, record.State, recipientRecord.State, runErr)
		}
		report.Results = append(report.Results, liveGiftResult{Sender: sender.Name, Recipient: recipient.Name,
			SenderAlias: aliases[index].Alias, RecipientAlias: aliases[recipientIndex].Alias,
			IntentID: record.IntentID, SignedGiftID: record.SignedGiftID, AmountAtomic: record.AmountAtomic,
			SenderFinalState: record.State, RecipientFinalState: recipientRecord.State,
			RequestDigest: record.RequestDigest, ResponseDigest: record.ResponseDigest, ExactBOCDigest: record.ExactBOCDigest,
			RequestEventID: record.RequestEventID, ResponseEventID: recipientRecord.ResponseEventID, OfferEventID: record.OfferEventID})
		t.Logf("finalized Agent Gift %s -> %s signed_id=%s", aliases[index].Alias, aliases[recipientIndex].Alias, record.SignedGiftID)
	}
	report.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
	wire.mu.Lock()
	report.Events = append([]liveGiftEvent(nil), wire.events...)
	wire.mu.Unlock()
	encoded, _ := json.MarshalIndent(report, "", "  ")
	path := filepath.Join(root, "reports", "six-agent-live-gift-ring.json")
	if err := os.WriteFile(path, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func liveGiftOwnerAddress(t *testing.T, configPath, wallet string) string {
	t.Helper()
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		AgentWallets map[string]struct {
			Wallet struct {
				Workchain   int32  `json:"workchain"`
				SubwalletID uint32 `json:"subwallet_id"`
				Key         struct {
					Name string `json:"name"`
				} `json:"key"`
			} `json:"wallet"`
			ControllerKey struct {
				Name string `json:"name"`
			} `json:"controller_key"`
		} `json:"agent_wallets"`
	}
	if json.Unmarshal(raw, &document) != nil || document.AgentWallets[wallet].Wallet.Key.Name == "" {
		t.Fatalf("missing owner wallet for %s", wallet)
	}
	// The exact address is already frozen in the campaign manifest's wallet
	// profile and returned by tosctl status. Read it from the matching DNS
	// wallet evidence rather than deriving cryptography in this harness.
	ownerProfile := document.AgentWallets[wallet]
	_ = ownerProfile
	output, runErr := liveGiftTOSCTL(t, configPath, "agent", "account", "status", "--wallet", wallet, "--workchain", "0", "--format", "json")
	if runErr != nil {
		t.Fatal(runErr)
	}
	var status struct {
		Owner string `json:"owner"`
	}
	if json.Unmarshal(output, &status) != nil || status.Owner == "" {
		t.Fatalf("invalid Agent Account owner for %s", wallet)
	}
	return status.Owner
}

func liveGiftControllerKey(t *testing.T, configPath, wallet string) string {
	t.Helper()
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		AgentWallets map[string]struct {
			ControllerKey struct {
				Name string `json:"name"`
			} `json:"controller_key"`
		} `json:"agent_wallets"`
	}
	if json.Unmarshal(raw, &document) != nil || document.AgentWallets[wallet].ControllerKey.Name == "" {
		t.Fatalf("missing controller key for %s", wallet)
	}
	return document.AgentWallets[wallet].ControllerKey.Name
}

func liveGiftVerifyAlias(t *testing.T, configPath, root, alias, wantAccount string) {
	t.Helper()
	output, err := liveGiftTOSCTL(t, configPath, "domain", "resolve", alias, "--root", root, "--category", "agent", "--format", "json")
	if err != nil {
		t.Fatalf("resolve %s through %s: %v", alias, configPath, err)
	}
	var evidence struct {
		CanonicalName       string `json:"canonical_name"`
		Result              string `json:"result"`
		RecordType          string `json:"record_type"`
		RecordValue         string `json:"record_value"`
		RootResolverAddress string `json:"root_resolver_address"`
		ProvenanceClass     string `json:"provenance_class"`
		Item                *struct {
			SafeToResolve bool `json:"safe_to_resolve"`
		} `json:"item"`
	}
	if json.Unmarshal(output, &evidence) != nil || evidence.CanonicalName != alias ||
		evidence.Result != "found" || evidence.RecordType != "dns_smc_address" ||
		normalizeDNSRecordValue(evidence.RecordType, evidence.RecordValue) != wantAccount ||
		evidence.ProvenanceClass != "evaluated" || evidence.Item == nil || !evidence.Item.SafeToResolve {
		t.Fatalf("%s did not resolve to the safe finalized Agent Account through %s", alias, configPath)
	}
}

// tosctl's structured DNS response preserves the historic human-readable
// value (for example, "dns_smc_address 0:...") alongside record_type. Consume
// only the matching, exact type prefix; never trim arbitrary text into an
// address because aliases are an authorization input for Gift custody.
func normalizeDNSRecordValue(recordType, value string) string {
	prefix := recordType + " "
	if recordType != "" && strings.HasPrefix(value, prefix) {
		return strings.TrimPrefix(value, prefix)
	}
	return value
}

func TestNormalizeDNSRecordValueRequiresMatchingType(t *testing.T) {
	address := "0:" + strings.Repeat("a", 64)
	if got := normalizeDNSRecordValue("dns_smc_address", "dns_smc_address "+address); got != address {
		t.Fatalf("typed DNS presentation was not normalized: %q", got)
	}
	if got := normalizeDNSRecordValue("dns_smc_address", "dns_next_resolver "+address); got == address {
		t.Fatal("a mismatched DNS record type was normalized")
	}
}

func liveGiftTOSCTL(t *testing.T, configPath string, args ...string) ([]byte, error) {
	t.Helper()
	// Owner address lookup uses the same pinned binary/config/vault boundary as
	// custody. The executable path is an explicit campaign input.
	binary := liveGiftEnv(t, "OPENFOX_TOSCTL")
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, append(args, "-c", configPath)...)
	command.Env = os.Environ()
	return command.Output()
}

func liveGiftEnv(t *testing.T, name string) string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		t.Fatalf("%s is required", name)
	}
	return value
}
