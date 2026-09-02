package nativeimpl

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	openfoxgift "github.com/tosnetwork/openfox/pkg/agentgift"
	openfoxfile "github.com/tosnetwork/openfox/pkg/fileutil"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/chainactionpublisher"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
)

const (
	capabilityGiftManifestSchema  = "tos.openfox.eight-agent-market-campaign.v1"
	capabilityGiftPublisherSchema = "tos.openfox.eight-agent-gift-publishers.v1"
	capabilityGiftReportSchema    = "tos.openfox.eight-agent-capability-market-gift.v1"
	capabilityGiftProgressSchema  = "tos.openfox.eight-agent-capability-market-gift-progress.v1"
	capabilityGiftMaximumNanoTOS  = uint64(100_000_000)
	capabilityGiftProgressPlanned = "planned"
	capabilityGiftProgressActive  = "in-progress"
	capabilityGiftProgressFinal   = "finalized"
)

type capabilityGiftAgent struct {
	Name                       string   `json:"name"`
	TOSName                    string   `json:"tos_name"`
	OwnerID                    string   `json:"owner_id"`
	AgentID                    string   `json:"agent_id"`
	AuthorityID                string   `json:"authority_id"`
	Wallet                     string   `json:"wallet"`
	Target                     string   `json:"target"`
	Capability                 string   `json:"capability"`
	Taxonomy                   string   `json:"taxonomy"`
	ModelKind                  string   `json:"model_kind"`
	ConfigDirectory            string   `json:"config_directory"`
	AuthorityPin               string   `json:"authority_pin"`
	IdentityPin                string   `json:"identity_pin"`
	MinimumPriceNanoTOS        uint64   `json:"minimum_price_nanotos"`
	PriceNanoTOS               uint64   `json:"price_nanotos"`
	MaximumInternalCostNanoTOS uint64   `json:"maximum_internal_cost_nanotos"`
	MaximumLossNanoTOS         uint64   `json:"maximum_loss_nanotos"`
	Tasks                      []string `json:"tasks"`
}

type capabilityGiftManifest struct {
	Schema    string                `json:"schema"`
	CreatedAt string                `json:"created_at"`
	Agents    []capabilityGiftAgent `json:"agents"`
}

type capabilityGiftKeyProfile struct {
	Name string `json:"name"`
}

// capabilityGiftWalletProfile intentionally accepts only vault-backed owner
// keys. Inline private-key material cannot participate in automatic publisher
// discovery, and no key value is ever included in an error or report.
type capabilityGiftWalletProfile struct {
	Key         capabilityGiftKeyProfile `json:"key"`
	Version     string                   `json:"version"`
	SubwalletID uint32                   `json:"subwallet_id"`
	Workchain   int32                    `json:"workchain"`
}

type capabilityGiftAgentWalletProfile struct {
	Wallet        capabilityGiftWalletProfile `json:"wallet"`
	ControllerKey capabilityGiftKeyProfile    `json:"controller_key"`
}

type capabilityGiftTOSCTLDocument struct {
	Wallets      map[string]capabilityGiftWalletProfile      `json:"wallets"`
	AgentWallets map[string]capabilityGiftAgentWalletProfile `json:"agent_wallets"`
	ChainRPC     struct {
		URLs   []json.RawMessage `json:"urls"`
		URL    string            `json:"url"`
		APIKey *string           `json:"api_key"`
	} `json:"chain_rpc"`
}

type capabilityGiftPublisherDocument struct {
	Schema  string            `json:"schema"`
	Wallets map[string]string `json:"wallets"`
}

type capabilityGiftEvent struct {
	EventID        string `json:"event_id"`
	Recipient      string `json:"recipient"`
	Kind           string `json:"kind"`
	SemanticKey    string `json:"semantic_key"`
	CanonicalBytes int    `json:"canonical_bytes"`
}

// capabilityGiftWire transports the exact opaque protocol payloads in this
// acceptance harness. It deliberately is not claimed as a production
// Messenger or cross-host transport test.
type capabilityGiftWire struct {
	mu     sync.Mutex
	latest []byte
	events []capabilityGiftEvent
}

func (w *capabilityGiftWire) SendEstablishedDirect(_ context.Context, recipient, kind string, canonical []byte, semanticKey string) (string, error) {
	if len(canonical) == 0 || recipient == "" || kind == "" || semanticKey == "" {
		return "", errors.New("incomplete capability Gift event")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	digest := sha256.New()
	for _, value := range [][]byte{[]byte("tos.openfox.capability-gift-wire.v1"), []byte(recipient), []byte(kind), []byte(semanticKey), canonical, []byte(strconv.Itoa(len(w.events)))} {
		digest.Write([]byte{byte(len(value) >> 24), byte(len(value) >> 16), byte(len(value) >> 8), byte(len(value))})
		digest.Write(value)
	}
	eventID := "evt_" + hex.EncodeToString(digest.Sum(nil))
	w.latest = append([]byte(nil), canonical...)
	w.events = append(w.events, capabilityGiftEvent{EventID: eventID, Recipient: recipient, Kind: kind,
		SemanticKey: semanticKey, CanonicalBytes: len(canonical)})
	return eventID, nil
}

func (w *capabilityGiftWire) body() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.latest...)
}

type capabilityGiftRecipientAuthority struct{ aliases map[string]string }

func (a capabilityGiftRecipientAuthority) ResolveCanonicalAgent(_ context.Context, input string) (string, error) {
	input = strings.ToLower(strings.TrimSpace(input))
	if value := a.aliases[input]; value != "" {
		return value, nil
	}
	if capabilityGiftCanonicalAgentID(input) {
		return input, nil
	}
	return "", errors.New("recipient is not a finalized campaign alias or canonical AgentID")
}

type capabilityGiftOwnerPolicy struct {
	sender, recipient string
	maximum           uint64
}

func (p capabilityGiftOwnerPolicy) ConfirmAgentGift(_ context.Context, review openfoxgift.OwnerReview) error {
	amount, err := strconv.ParseUint(review.AmountAtomic, 10, 64)
	if err != nil || review.Action != "send" || review.SenderAgentAccount != p.sender ||
		review.RecipientAgentID != p.recipient || amount == 0 || amount > p.maximum || review.FundsLocked {
		return errors.New("capability Gift exceeds the frozen owner policy")
	}
	return nil
}

type capabilityGiftAliasEvidence struct {
	Alias        string   `json:"alias"`
	AgentAccount string   `json:"agent_account"`
	NodeResults  []string `json:"node_results"`
}

type capabilityGiftAccountingEvidence struct {
	EntryID                    string                       `json:"entry_id"`
	Body                       capabilityGiftAccountingBody `json:"body"`
	AgreementSettlementApplied bool                         `json:"agreement_settlement_applied"`
}

// capabilityGiftAccountingBody is the wire-compatible projection of
// earning.AccountingEntryBody. Keeping it local avoids making this deliberately
// narrow nativeimpl submodule depend on the full autonomous earning runtime.
type capabilityGiftAccountingBody struct {
	SchemaVersion         uint16                    `json:"schema_version"`
	OwnerID               string                    `json:"owner_id"`
	AgentID               string                    `json:"agent_id"`
	Classification        string                    `json:"classification"`
	AgreementBodyDigest   string                    `json:"agreement_body_digest,omitempty"`
	AgreementObligationID string                    `json:"agreement_obligation_id,omitempty"`
	ObligationInstanceID  string                    `json:"obligation_instance_id,omitempty"`
	Amount                *commerce.AgreementAmount `json:"amount,omitempty"`
	ComputeUnits          uint64                    `json:"compute_units,omitempty"`
	SourceReference       string                    `json:"source_reference"`
	EvidenceRefs          []string                  `json:"evidence_refs"`
	ObservedAtUnix        uint64                    `json:"observed_at_unix"`
}

type capabilityGiftResult struct {
	EdgeID              string                           `json:"edge_id"`
	Sender              string                           `json:"sender"`
	Recipient           string                           `json:"recipient"`
	SenderAlias         string                           `json:"sender_alias"`
	RecipientAlias      string                           `json:"recipient_alias"`
	IntentID            string                           `json:"intent_id"`
	SignedGiftID        string                           `json:"signed_gift_id"`
	AmountAtomic        string                           `json:"amount_atomic"`
	SenderFinalState    openfoxgift.State                `json:"sender_final_state"`
	RecipientFinalState openfoxgift.State                `json:"recipient_final_state"`
	RequestDigest       string                           `json:"request_digest"`
	ResponseDigest      string                           `json:"response_digest"`
	ExactBOCDigest      string                           `json:"exact_boc_digest"`
	RequestEventID      string                           `json:"request_event_id"`
	ResponseEventID     string                           `json:"response_event_id"`
	OfferEventID        string                           `json:"offer_event_id"`
	PublisherResolution string                           `json:"publisher_resolution"`
	Accounting          capabilityGiftAccountingEvidence `json:"accounting"`
}

type capabilityGiftReport struct {
	Schema               string                        `json:"schema"`
	StartedAt            string                        `json:"started_at"`
	CompletedAt          string                        `json:"completed_at"`
	Network              *nativev1.NetworkDomain       `json:"network"`
	AgentCount           int                           `json:"agent_count"`
	ChainEndpointCount   int                           `json:"chain_endpoint_count"`
	ChainQuorum          int                           `json:"chain_quorum"`
	RealChainComponents  []string                      `json:"real_chain_components"`
	TestOnlyComponents   []string                      `json:"test_only_components"`
	AccountingDurability string                        `json:"accounting_durability"`
	CampaignID           string                        `json:"campaign_id"`
	ProgressFile         string                        `json:"progress_file"`
	Aliases              []capabilityGiftAliasEvidence `json:"aliases"`
	Results              []capabilityGiftResult        `json:"results"`
	Events               []capabilityGiftEvent         `json:"events"`
}

// capabilityGiftProgress is the owner-private restart fence for this bounded
// acceptance ring. Production Agent Gift journals remain authoritative for
// protocol state and finalized chain observations. This file only binds each
// deterministic campaign edge to the random production IntentID and retains a
// completed result after every finalized Gift.
type capabilityGiftProgress struct {
	Schema         string                       `json:"schema"`
	CampaignID     string                       `json:"campaign_id"`
	ManifestDigest string                       `json:"manifest_digest"`
	StartedAt      string                       `json:"started_at"`
	UpdatedAt      string                       `json:"updated_at"`
	CompletedAt    string                       `json:"completed_at,omitempty"`
	Network        *nativev1.NetworkDomain      `json:"network"`
	AmountAtomic   string                       `json:"amount_atomic"`
	Edges          []capabilityGiftProgressEdge `json:"edges"`
	Events         []capabilityGiftEvent        `json:"events"`
}

type capabilityGiftProgressEdge struct {
	EdgeID                string                `json:"edge_id"`
	Sender                string                `json:"sender"`
	Recipient             string                `json:"recipient"`
	SenderAlias           string                `json:"sender_alias"`
	RecipientAlias        string                `json:"recipient_alias"`
	SenderAgentID         string                `json:"sender_agent_id"`
	RecipientAgentID      string                `json:"recipient_agent_id"`
	SenderOwnerID         string                `json:"sender_owner_id"`
	SenderAgentAccount    string                `json:"sender_agent_account"`
	RecipientAgentAccount string                `json:"recipient_agent_account"`
	AmountAtomic          string                `json:"amount_atomic"`
	Greeting              string                `json:"greeting"`
	IntentID              string                `json:"intent_id,omitempty"`
	Status                string                `json:"status"`
	Result                *capabilityGiftResult `json:"result,omitempty"`
}

// capabilityGiftFinalityService deliberately exposes only the two read/reconcile
// operations needed after an edge has expired. Keeping the expired path behind
// this narrow interface makes it structurally unable to request, sign, deliver,
// or broadcast a Gift.
type capabilityGiftFinalityService interface {
	ListRecords() []openfoxgift.Record
	Refresh(context.Context, string) (openfoxgift.Record, error)
}

type capabilityGiftFinalityStub struct {
	records      []openfoxgift.Record
	nextState    openfoxgift.State
	refreshErr   error
	refreshCalls int
}

func (s *capabilityGiftFinalityStub) ListRecords() []openfoxgift.Record {
	return append([]openfoxgift.Record(nil), s.records...)
}

func (s *capabilityGiftFinalityStub) Refresh(_ context.Context, intentID string) (openfoxgift.Record, error) {
	s.refreshCalls++
	if s.refreshErr != nil {
		return openfoxgift.Record{}, s.refreshErr
	}
	for index := range s.records {
		if s.records[index].IntentID != intentID {
			continue
		}
		if s.nextState != "" {
			s.records[index].State = s.nextState
		}
		return s.records[index], nil
	}
	return openfoxgift.Record{}, errors.New("stub Gift record not found")
}

// TestEightAgentCapabilityMarketLiveGiftRing is an opt-in local-chain
// acceptance harness for the current eight-agent capability-market manifest.
// It exercises production Agent Gift protocol/state, Agent Account custody,
// exact-BOC submission, and finalized quorum reads. The wire between services
// remains an in-process test double; production Messenger coverage belongs to
// the giftd integration suite.
func TestEightAgentCapabilityMarketLiveGiftRing(t *testing.T) {
	if os.Getenv("OPENFOX_EIGHT_AGENT_CAPABILITY_GIFT") != "1" {
		t.Skip("set OPENFOX_EIGHT_AGENT_CAPABILITY_GIFT=1")
	}
	root := capabilityGiftRequiredEnv(t, "OPENFOX_EIGHT_AGENT_GIFT_ROOT")
	tosctlBinary := capabilityGiftRequiredEnv(t, "OPENFOX_EIGHT_AGENT_GIFT_TOSCTL")
	vaultURL := capabilityGiftRequiredEnv(t, "OPENFOX_EIGHT_AGENT_GIFT_VAULT_URL")
	rootHash := capabilityGiftRequiredEnv(t, "OPENFOX_EIGHT_AGENT_GIFT_ZERO_STATE_ROOT_HASH")
	fileHash := capabilityGiftRequiredEnv(t, "OPENFOX_EIGHT_AGENT_GIFT_ZERO_STATE_FILE_HASH")
	genesisRootBase64 := capabilityGiftRequiredEnv(t, "OPENFOX_EIGHT_AGENT_GIFT_ZERO_STATE_ROOT_BASE64")
	genesisFileBase64 := capabilityGiftRequiredEnv(t, "OPENFOX_EIGHT_AGENT_GIFT_ZERO_STATE_FILE_BASE64")
	dnsRoot := capabilityGiftRequiredEnv(t, "OPENFOX_EIGHT_AGENT_GIFT_DNS_ROOT")
	endpoints := capabilityGiftStringArrayEnv(t, "OPENFOX_EIGHT_AGENT_GIFT_RPC_ENDPOINTS", false)
	configPaths := capabilityGiftStringArrayEnv(t, "OPENFOX_EIGHT_AGENT_GIFT_TOSCTL_CONFIGS", true)
	if len(endpoints) < 3 || len(configPaths) != len(endpoints) {
		t.Fatal("Gift RPC endpoints and tosctl configs must identify the same three-or-more nodes")
	}
	quorum := len(endpoints)/2 + 1
	if raw := strings.TrimSpace(os.Getenv("OPENFOX_EIGHT_AGENT_GIFT_CHAIN_QUORUM")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= len(endpoints)/2 || parsed > len(endpoints) {
			t.Fatal("OPENFOX_EIGHT_AGENT_GIFT_CHAIN_QUORUM must be a strict majority")
		}
		quorum = parsed
	}
	amount := capabilityGiftMaximumNanoTOS
	if raw := strings.TrimSpace(os.Getenv("OPENFOX_EIGHT_AGENT_GIFT_AMOUNT_NANOTOS")); raw != "" {
		parsed, err := strconv.ParseUint(raw, 10, 64)
		if err != nil || strconv.FormatUint(parsed, 10) != raw || parsed == 0 || parsed > capabilityGiftMaximumNanoTOS {
			t.Fatal("OPENFOX_EIGHT_AGENT_GIFT_AMOUNT_NANOTOS must be canonical and at most 100000000")
		}
		amount = parsed
	}
	if !secureExecutable(tosctlBinary) {
		t.Fatal("OPENFOX_EIGHT_AGENT_GIFT_TOSCTL is not a trusted executable")
	}
	for _, path := range configPaths {
		if !secureConfigFile(path) {
			t.Fatal("a Gift tosctl config is not an owner-private absolute regular file")
		}
	}
	manifest := capabilityGiftLoadManifest(t, filepath.Join(root, "eight-agent-manifest.json"))
	primaryDocument := capabilityGiftLoadTOSCTLDocument(t, configPaths[0])
	publisherRPC, err := capabilityGiftPublisherRPC(primaryDocument)
	if err != nil {
		t.Fatal(err)
	}
	publisherWallets, publisherSources, err := capabilityGiftPublisherWallets(
		primaryDocument, manifest.Agents, strings.TrimSpace(os.Getenv("OPENFOX_EIGHT_AGENT_GIFT_PUBLISHER_WALLETS_FILE")))
	if err != nil {
		t.Fatal(err)
	}

	aliases := make(map[string]string, len(manifest.Agents))
	for _, agent := range manifest.Agents {
		aliases[agent.TOSName] = agent.AgentID
	}
	network := &nativev1.NetworkDomain{NetworkId: "tos:local-three-node", GenesisRootHash: rootHash, GenesisFileHash: fileHash}
	progressDirectory := filepath.Join(root, "capability-gifts")
	if directoryErr := capabilityGiftEnsurePrivateDirectory(progressDirectory); directoryErr != nil {
		t.Fatal(directoryErr)
	}
	plannedProgress, planErr := capabilityGiftPlanProgress(manifest, network, amount, publisherWallets, publisherSources, time.Now().UTC())
	if planErr != nil {
		t.Fatal(planErr)
	}
	progressPath := filepath.Join(progressDirectory, "ring-progress.json")
	progress, progressErr := capabilityGiftLoadOrCreateProgress(progressPath, plannedProgress)
	if progressErr != nil {
		t.Fatal(progressErr)
	}
	chain, err := toschain.New(toschain.Config{Network: network.NetworkId,
		PinnedNetworkDomain: &toschain.PinnedNetworkDomain{NetworkID: network.NetworkId, GlobalID: 3,
			ZeroStateRootHash: rootHash, ZeroStateFileHash: fileHash, WorkchainID: 0},
		Endpoints: endpoints, Quorum: quorum})
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
	resolver, err := NewAgentGiftResolver(finalized, capabilityGiftRecipientAuthority{aliases: aliases})
	if err != nil {
		t.Fatal(err)
	}

	wire := &capabilityGiftWire{events: append([]capabilityGiftEvent(nil), progress.Events...)}
	services := make([]*openfoxgift.Service, len(manifest.Agents))
	workchain := int32(0)
	for index, agent := range manifest.Agents {
		profile, found := primaryDocument.AgentWallets[agent.Wallet]
		if !found || !capabilityGiftSafeWalletProfile(profile.Wallet) || !capabilityGiftSafeKeyName(profile.ControllerKey.Name) {
			t.Fatalf("%s has no safe owner/controller wallet profile", agent.Name)
		}
		ownerAddress, statusErr := capabilityGiftOwnerAddress(t, tosctlBinary, configPaths[0], vaultURL, agent)
		if statusErr != nil {
			t.Fatalf("resolve %s Agent Account owner: %v", agent.Name, statusErr)
		}
		custody, custodyErr := NewTOSCTLGiftCustody(TOSCTLGiftCustodyConfig{
			BinaryPath: tosctlBinary, ConfigPath: configPaths[0], VaultURL: vaultURL, WalletName: agent.Wallet,
			OwnerWallet: ownerAddress, ControllerKeyID: profile.ControllerKey.Name,
			AgentAccountWorkchain: &workchain, QuorumConfigPaths: configPaths[1:],
			FeeReserveAtomic: 50_000_000, MinimumInclusionMargin: 60, Timeout: 90 * time.Second,
		}, finalized)
		if custodyErr != nil {
			t.Fatalf("construct %s Gift custody: %v", agent.Name, custodyErr)
		}
		publisherConfigPath := configPaths[0]
		if publisherSources[agent.Name] == "derived-agent-owner-overlay" {
			publisherConfigDirectory := filepath.Join(root, "capability-gifts", "publisher-configs")
			if directoryErr := capabilityGiftEnsurePrivateDirectory(publisherConfigDirectory); directoryErr != nil {
				t.Fatal(directoryErr)
			}
			publisherConfigPath = filepath.Join(publisherConfigDirectory, agent.Name+".json")
			if overlayErr := capabilityGiftWritePublisherOverlay(configPaths[0], publisherConfigPath,
				publisherWallets[agent.Name], profile.Wallet); overlayErr != nil {
				t.Fatalf("derive %s owner publisher config: %v", agent.Name, overlayErr)
			}
		}
		publisher, publisherErr := chainactionpublisher.NewTosctlBackend(chainactionpublisher.TosctlBackendConfig{
			Network: network.NetworkId, Binary: tosctlBinary, ConfigPath: publisherConfigPath, VaultURL: vaultURL,
			RPCURL: publisherRPC, GenesisRootHash: genesisRootBase64, GenesisFileHash: genesisFileBase64,
			WalletName: publisherWallets[agent.Name], Payer: ownerAddress,
		})
		if publisherErr != nil {
			t.Fatalf("construct %s Gift publisher: %v", agent.Name, publisherErr)
		}
		t.Cleanup(func() { _ = publisher.Close() })
		if readyErr := publisher.CheckReady(t.Context()); readyErr != nil {
			t.Fatalf("%s Gift publisher is not ready: %v", agent.Name, readyErr)
		}
		broadcaster, broadcasterErr := NewAgentGiftBroadcaster(publisher)
		if broadcasterErr != nil {
			t.Fatal(broadcasterErr)
		}
		address, addressErr := NewStaticAgentGiftAddressAuthority(agent.Target)
		if addressErr != nil {
			t.Fatal(addressErr)
		}
		next := manifest.Agents[(index+1)%len(manifest.Agents)]
		owner, ownerErr := NewAgentGiftOwnerAuthorizer(capabilityGiftOwnerPolicy{
			sender: agent.Target, recipient: next.AgentID, maximum: capabilityGiftMaximumNanoTOS,
		})
		if ownerErr != nil {
			t.Fatal(ownerErr)
		}
		journalDirectory := filepath.Join(root, "capability-gifts", agent.Name)
		if directoryErr := capabilityGiftEnsurePrivateDirectory(journalDirectory); directoryErr != nil {
			t.Fatal(directoryErr)
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

	report := capabilityGiftReport{Schema: capabilityGiftReportSchema,
		StartedAt: progress.StartedAt, Network: network,
		AgentCount: len(manifest.Agents), ChainEndpointCount: len(endpoints), ChainQuorum: quorum,
		RealChainComponents:  []string{"agent-gift-protocol", "agent-account-custody", "exact-boc-broadcast", "finalized-quorum-read"},
		TestOnlyComponents:   []string{"in-process-established-direct-wire"},
		AccountingDurability: "owner-private per-edge restart progress plus production Agent Gift journals; canonical AccountingEntryBody-compatible validation",
		CampaignID:           progress.CampaignID, ProgressFile: progressPath,
	}
	for _, agent := range manifest.Agents {
		evidence := capabilityGiftAliasEvidence{Alias: agent.TOSName, AgentAccount: agent.Target}
		for node, config := range configPaths {
			if verifyErr := capabilityGiftVerifyAlias(t, tosctlBinary, config, vaultURL, dnsRoot, agent.TOSName, agent.Target); verifyErr != nil {
				t.Fatalf("verify %s on node %d: %v", agent.TOSName, node+1, verifyErr)
			}
			evidence.NodeResults = append(evidence.NodeResults, fmt.Sprintf("node-%d:found-safe", node+1))
		}
		report.Aliases = append(report.Aliases, evidence)
	}

	persistProgress := func() error {
		progress.Events = capabilityGiftWireEvents(wire)
		progress.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		return capabilityGiftWriteProgress(progressPath, progress, plannedProgress)
	}
	for index := range manifest.Agents {
		result, resumed, runErr := capabilityGiftRunOrResumeEdge(t.Context(), services, index, manifest.Agents,
			&progress, publisherSources, persistProgress)
		if runErr != nil {
			t.Fatalf("Gift edge %s: %v", progress.Edges[index].EdgeID, runErr)
		}
		report.Results = append(report.Results, result)
		t.Logf("finalized capability-market Agent Gift %s -> %s signed_id=%s resumed=%t",
			result.SenderAlias, result.RecipientAlias, result.SignedGiftID, resumed)
	}
	if progress.CompletedAt == "" {
		progress.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if err := persistProgress(); err != nil {
		t.Fatal(err)
	}
	report.CompletedAt = progress.CompletedAt
	report.Events = append([]capabilityGiftEvent(nil), progress.Events...)
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	reportDirectory := filepath.Join(root, "reports")
	if err := capabilityGiftEnsurePrivateDirectory(reportDirectory); err != nil {
		t.Fatal(err)
	}
	if err := openfoxfile.WriteFileAtomic(filepath.Join(reportDirectory, "eight-agent-capability-market-gift.json"), append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func capabilityGiftPlanProgress(manifest capabilityGiftManifest, network *nativev1.NetworkDomain, amount uint64,
	publisherWallets, publisherSources map[string]string, startedAt time.Time) (capabilityGiftProgress, error) {
	if capabilityGiftValidateManifest(manifest) != nil || network == nil || network.NetworkId == "" ||
		network.GenesisRootHash == "" || network.GenesisFileHash == "" || amount == 0 ||
		amount > capabilityGiftMaximumNanoTOS || startedAt.IsZero() {
		return capabilityGiftProgress{}, errors.New("invalid capability Gift progress plan")
	}
	manifestDigest, err := codec.Digest("tos.openfox.eight-agent-capability-market-manifest.v1", manifest)
	if err != nil {
		return capabilityGiftProgress{}, err
	}
	type publisherBinding struct {
		Agent      string `cbor:"agent"`
		Wallet     string `cbor:"wallet"`
		Resolution string `cbor:"resolution"`
	}
	bindings := make([]publisherBinding, 0, len(manifest.Agents))
	for _, agent := range manifest.Agents {
		wallet, source := publisherWallets[agent.Name], publisherSources[agent.Name]
		if wallet == "" || source == "" {
			return capabilityGiftProgress{}, errors.New("capability Gift progress lacks a publisher binding")
		}
		bindings = append(bindings, publisherBinding{Agent: agent.Name, Wallet: wallet, Resolution: source})
	}
	campaignID, err := codec.Digest("tos.openfox.eight-agent-capability-market-gift-run.v1", struct {
		ManifestDigest string                  `cbor:"manifest_digest"`
		Network        *nativev1.NetworkDomain `cbor:"network"`
		GlobalID       int32                   `cbor:"global_id"`
		AmountAtomic   string                  `cbor:"amount_atomic"`
		Publishers     []publisherBinding      `cbor:"publishers"`
	}{ManifestDigest: manifestDigest, Network: network, GlobalID: 3,
		AmountAtomic: strconv.FormatUint(amount, 10), Publishers: bindings})
	if err != nil {
		return capabilityGiftProgress{}, err
	}
	now := startedAt.UTC().Format(time.RFC3339Nano)
	progress := capabilityGiftProgress{Schema: capabilityGiftProgressSchema, CampaignID: campaignID,
		ManifestDigest: manifestDigest, StartedAt: now, UpdatedAt: now,
		Network: &nativev1.NetworkDomain{NetworkId: network.NetworkId, GenesisRootHash: network.GenesisRootHash,
			GenesisFileHash: network.GenesisFileHash}, AmountAtomic: strconv.FormatUint(amount, 10)}
	for index, sender := range manifest.Agents {
		recipient := manifest.Agents[(index+1)%len(manifest.Agents)]
		edgeID, digestErr := codec.Digest("tos.openfox.eight-agent-capability-market-gift-edge.v1", struct {
			CampaignID            string `cbor:"campaign_id"`
			SenderAgentID         string `cbor:"sender_agent_id"`
			RecipientAgentID      string `cbor:"recipient_agent_id"`
			SenderAgentAccount    string `cbor:"sender_agent_account"`
			RecipientAgentAccount string `cbor:"recipient_agent_account"`
		}{CampaignID: campaignID, SenderAgentID: sender.AgentID, RecipientAgentID: recipient.AgentID,
			SenderAgentAccount: sender.Target, RecipientAgentAccount: recipient.Target})
		if digestErr != nil {
			return capabilityGiftProgress{}, digestErr
		}
		progress.Edges = append(progress.Edges, capabilityGiftProgressEdge{EdgeID: edgeID,
			Sender: sender.Name, Recipient: recipient.Name, SenderAlias: sender.TOSName, RecipientAlias: recipient.TOSName,
			SenderAgentID: sender.AgentID, RecipientAgentID: recipient.AgentID,
			SenderOwnerID:      sender.OwnerID,
			SenderAgentAccount: sender.Target, RecipientAgentAccount: recipient.Target,
			AmountAtomic: progress.AmountAtomic, Greeting: capabilityGiftEdgeGreeting(edgeID, sender.TOSName),
			Status: capabilityGiftProgressPlanned})
	}
	return progress, nil
}

func capabilityGiftEdgeGreeting(edgeID, senderAlias string) string {
	return "Capability-market thank-you gratuity from " + senderAlias + " [edge " + edgeID + "]; not Agreement consideration or settlement."
}

func capabilityGiftLoadOrCreateProgress(path string, expected capabilityGiftProgress) (capabilityGiftProgress, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return capabilityGiftProgress{}, errors.New("Gift progress path must be canonical and absolute")
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := capabilityGiftWriteProgress(path, expected, expected); err != nil {
			return capabilityGiftProgress{}, err
		}
		return expected, nil
	}
	if err != nil {
		return capabilityGiftProgress{}, errors.New("inspect Gift progress")
	}
	raw, err := capabilityGiftReadStableProgress(path, info)
	if err != nil {
		return capabilityGiftProgress{}, err
	}
	progress, decodeErr := capabilityGiftDecodeCanonicalProgress(raw)
	if decodeErr != nil || capabilityGiftValidateProgress(progress, expected) != nil {
		return capabilityGiftProgress{}, errors.New("Gift progress conflicts with the deterministic ring plan")
	}
	return progress, nil
}

func capabilityGiftReadStableProgress(path string, lstat os.FileInfo) ([]byte, error) {
	if lstat == nil || !secureConfigFile(path) || !lstat.Mode().IsRegular() ||
		lstat.Mode()&os.ModeSymlink != 0 || lstat.Mode().Perm() != 0o600 ||
		lstat.Size() <= 0 || lstat.Size() > 2<<20 {
		return nil, errors.New("Gift progress is not a bounded owner-private regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("open Gift progress")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(lstat, opened) || !opened.Mode().IsRegular() ||
		opened.Mode().Perm() != 0o600 || opened.Size() != lstat.Size() {
		return nil, errors.New("Gift progress changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, (2<<20)+1))
	closedOver, statErr := file.Stat()
	if err != nil || statErr != nil || len(raw) == 0 || len(raw) > 2<<20 ||
		!os.SameFile(opened, closedOver) || closedOver.Size() != opened.Size() ||
		closedOver.ModTime() != opened.ModTime() || int64(len(raw)) != opened.Size() {
		return nil, errors.New("Gift progress changed while reading")
	}
	return raw, nil
}

func capabilityGiftDecodeCanonicalProgress(raw []byte) (capabilityGiftProgress, error) {
	var progress capabilityGiftProgress
	if len(raw) == 0 || len(raw) > 2<<20 || decodeStrictJSON(raw, &progress) != nil {
		return capabilityGiftProgress{}, errors.New("decode bounded Gift progress")
	}
	canonical, err := json.MarshalIndent(progress, "", "  ")
	if err != nil {
		return capabilityGiftProgress{}, errors.New("encode canonical Gift progress")
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(raw, canonical) {
		return capabilityGiftProgress{}, errors.New("Gift progress JSON is not the stable canonical encoding")
	}
	return progress, nil
}

func capabilityGiftWriteProgress(path string, progress, expected capabilityGiftProgress) error {
	if capabilityGiftValidateProgress(progress, expected) != nil {
		return errors.New("refuse to persist conflicting Gift progress")
	}
	encoded, err := json.MarshalIndent(progress, "", "  ")
	if err != nil || len(encoded) == 0 || len(encoded) > 2<<20 {
		return errors.New("encode bounded Gift progress")
	}
	if err := openfoxfile.WriteFileAtomic(path, append(encoded, '\n'), 0o600); err != nil {
		return err
	}
	if !secureConfigFile(path) {
		return errors.New("persisted Gift progress is not owner-private")
	}
	return nil
}

func capabilityGiftValidateProgress(progress, expected capabilityGiftProgress) error {
	if progress.Schema != capabilityGiftProgressSchema || progress.CampaignID != expected.CampaignID ||
		progress.ManifestDigest != expected.ManifestDigest || progress.AmountAtomic != expected.AmountAtomic ||
		!capabilityGiftSameNetwork(progress.Network, expected.Network) || len(progress.Edges) != len(expected.Edges) ||
		len(progress.Events) > 256 || !capabilityGiftCanonicalSHA256(progress.CampaignID) ||
		!capabilityGiftCanonicalSHA256(progress.ManifestDigest) {
		return errors.New("Gift progress identity changed")
	}
	started, startErr := time.Parse(time.RFC3339Nano, progress.StartedAt)
	updated, updateErr := time.Parse(time.RFC3339Nano, progress.UpdatedAt)
	if startErr != nil || updateErr != nil || updated.Before(started) {
		return errors.New("Gift progress timestamps are invalid")
	}
	completedSet := progress.CompletedAt != ""
	if completedSet {
		completed, err := time.Parse(time.RFC3339Nano, progress.CompletedAt)
		if err != nil || completed.Before(started) || updated.Before(completed) {
			return errors.New("Gift progress completion is invalid")
		}
	}
	seenIntents, seenSignedGifts := map[string]bool{}, map[string]bool{}
	finalizedEdges := 0
	for index := range progress.Edges {
		edge, wanted := progress.Edges[index], expected.Edges[index]
		if edge.EdgeID != wanted.EdgeID || edge.Sender != wanted.Sender || edge.Recipient != wanted.Recipient ||
			edge.SenderAlias != wanted.SenderAlias || edge.RecipientAlias != wanted.RecipientAlias ||
			edge.SenderAgentID != wanted.SenderAgentID || edge.RecipientAgentID != wanted.RecipientAgentID ||
			edge.SenderOwnerID != wanted.SenderOwnerID ||
			edge.SenderAgentAccount != wanted.SenderAgentAccount || edge.RecipientAgentAccount != wanted.RecipientAgentAccount ||
			edge.AmountAtomic != wanted.AmountAtomic || edge.Greeting != wanted.Greeting ||
			!capabilityGiftCanonicalSHA256(edge.EdgeID) {
			return errors.New("Gift progress edge identity changed")
		}
		switch edge.Status {
		case capabilityGiftProgressPlanned:
			if edge.IntentID != "" || edge.Result != nil || edge.Greeting != wanted.Greeting {
				return errors.New("planned Gift edge contains execution state")
			}
		case capabilityGiftProgressActive:
			if !capabilityGiftCanonicalIntentID(edge.IntentID) || edge.Result != nil || seenIntents[edge.IntentID] {
				return errors.New("active Gift edge is not bound to one intent")
			}
			seenIntents[edge.IntentID] = true
		case capabilityGiftProgressFinal:
			if !capabilityGiftCanonicalIntentID(edge.IntentID) || edge.Result == nil ||
				capabilityGiftValidateResult(edge, *edge.Result) != nil || seenIntents[edge.IntentID] ||
				seenSignedGifts[edge.Result.SignedGiftID] {
				return errors.New("finalized Gift edge lacks exact evidence")
			}
			seenIntents[edge.IntentID], seenSignedGifts[edge.Result.SignedGiftID] = true, true
			finalizedEdges++
		default:
			return errors.New("unknown Gift progress status")
		}
	}
	if completedSet && finalizedEdges != len(progress.Edges) {
		return errors.New("Gift progress completed before every edge finalized")
	}
	seenEvents := map[string]bool{}
	for _, event := range progress.Events {
		if len(event.EventID) != 68 || !strings.HasPrefix(event.EventID, "evt_") ||
			!capabilityGiftCanonicalHex(event.EventID[4:], 64) || event.Recipient == "" || event.Kind == "" ||
			event.SemanticKey == "" || event.CanonicalBytes <= 0 || event.CanonicalBytes > 64<<10 || seenEvents[event.EventID] {
			return errors.New("invalid persisted Gift wire event")
		}
		seenEvents[event.EventID] = true
	}
	return nil
}

func capabilityGiftSameNetwork(left, right *nativev1.NetworkDomain) bool {
	return left != nil && right != nil && left.NetworkId == right.NetworkId &&
		left.GenesisRootHash == right.GenesisRootHash && left.GenesisFileHash == right.GenesisFileHash
}

func capabilityGiftCanonicalIntentID(value string) bool { return capabilityGiftCanonicalHex(value, 64) }

func capabilityGiftCanonicalHex(value string, length int) bool {
	if len(value) != length || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func capabilityGiftWireEvents(wire *capabilityGiftWire) []capabilityGiftEvent {
	if wire == nil {
		return nil
	}
	wire.mu.Lock()
	defer wire.mu.Unlock()
	return append([]capabilityGiftEvent(nil), wire.events...)
}

func capabilityGiftFindSenderRecord(records []openfoxgift.Record, edge capabilityGiftProgressEdge,
	network string) (openfoxgift.Record, bool, error) {
	currentGreeting := capabilityGiftEdgeGreeting(edge.EdgeID, edge.SenderAlias)
	var found openfoxgift.Record
	count := 0
	for _, record := range records {
		base := record.Role == openfoxgift.RoleSender && record.Network == network && record.GlobalID == 3 &&
			record.SenderAgentID == edge.SenderAgentID && record.RecipientAgentID == edge.RecipientAgentID &&
			record.SenderAgentAccount == edge.SenderAgentAccount
		marked := record.DisplayMessage == currentGreeting
		if !marked {
			if base && strings.HasPrefix(record.DisplayMessage, "Capability-market thank-you gratuity from ") {
				return openfoxgift.Record{}, false, errors.New("existing capability Gift journal lacks the current deterministic edge marker")
			}
			continue
		}
		if !base {
			if record.DisplayMessage == currentGreeting {
				return openfoxgift.Record{}, false, errors.New("deterministic Gift edge marker binds another journal record")
			}
			continue
		}
		if record.AmountAtomic != edge.AmountAtomic {
			return openfoxgift.Record{}, false, errors.New("existing capability Gift edge conflicts with the deterministic plan")
		}
		found, count = record, count+1
	}
	if count > 1 {
		return openfoxgift.Record{}, false, errors.New("multiple production Gift intents claim one deterministic edge")
	}
	return found, count == 1, nil
}

func capabilityGiftFindRecipientRecord(records []openfoxgift.Record, edge capabilityGiftProgressEdge,
	intentID, network string) (openfoxgift.Record, bool, error) {
	for _, record := range records {
		if record.IntentID != intentID {
			continue
		}
		if record.Role != openfoxgift.RoleRecipient || record.Network != network || record.GlobalID != 3 ||
			record.SenderAgentID != edge.SenderAgentID || record.RecipientAgentID != edge.RecipientAgentID ||
			record.SenderAgentAccount != edge.SenderAgentAccount || record.AmountAtomic != edge.AmountAtomic {
			return openfoxgift.Record{}, false, errors.New("recipient Gift journal conflicts with the deterministic edge")
		}
		return record, true, nil
	}
	return openfoxgift.Record{}, false, nil
}

func capabilityGiftRunOrResumeEdge(ctx context.Context, services []*openfoxgift.Service, index int,
	agents []capabilityGiftAgent, progress *capabilityGiftProgress, publisherSources map[string]string,
	persist func() error) (capabilityGiftResult, bool, error) {
	if ctx == nil || progress == nil || persist == nil || len(services) != len(agents) || len(agents) != len(progress.Edges) ||
		index < 0 || index >= len(agents) || progress.Network == nil {
		return capabilityGiftResult{}, false, errors.New("invalid Gift edge resume request")
	}
	edge := &progress.Edges[index]
	sender, recipientIndex := agents[index], (index+1)%len(agents)
	recipient := agents[recipientIndex]
	record, found, err := capabilityGiftFindSenderRecord(services[index].ListRecords(), *edge, progress.Network.NetworkId)
	if err != nil {
		return capabilityGiftResult{}, false, err
	}
	resumed := found || edge.Status != capabilityGiftProgressPlanned
	if edge.Status == capabilityGiftProgressFinal {
		if !found || record.IntentID != edge.IntentID || edge.Result == nil {
			return capabilityGiftResult{}, true, errors.New("finalized Gift progress has no matching sender journal")
		}
		recipientRecord, recipientFound, findErr := capabilityGiftFindRecipientRecord(
			services[recipientIndex].ListRecords(), *edge, edge.IntentID, progress.Network.NetworkId)
		if findErr != nil || !recipientFound || capabilityGiftValidateFinalRecords(*edge, record, recipientRecord, *edge.Result) != nil {
			return capabilityGiftResult{}, true, errors.New("finalized Gift progress conflicts with production journals")
		}
		return *edge.Result, true, nil
	}
	if found {
		if edge.IntentID != "" && edge.IntentID != record.IntentID {
			return capabilityGiftResult{}, true, errors.New("Gift progress IntentID conflicts with the unique journal edge")
		}
	} else {
		if edge.Status != capabilityGiftProgressPlanned || edge.IntentID != "" {
			return capabilityGiftResult{}, true, errors.New("active Gift progress lost its production sender journal")
		}
		validUntil := time.Now().UTC().Add(15 * time.Minute)
		if validUntil.Unix() <= 0 || validUntil.Unix() > int64(^uint32(0)) {
			return capabilityGiftResult{}, false, errors.New("Gift validity exceeds uint32")
		}
		record, err = services[index].StartSender(ctx, openfoxgift.ModelProposal{Recipient: edge.RecipientAlias,
			AmountAtomic: edge.AmountAtomic, RequestedValidUntil: uint32(validUntil.Unix()), Greeting: edge.Greeting},
			progress.Network.NetworkId, 3, edge.SenderAgentID)
		if err != nil {
			return capabilityGiftResult{}, false, err
		}
		if !capabilityGiftSenderRecordMatches(record, *edge, progress.Network.NetworkId) {
			return capabilityGiftResult{}, false, errors.New("new production Gift intent differs from its deterministic edge")
		}
	}
	if edge.IntentID == "" {
		edge.IntentID = record.IntentID
		edge.Status = capabilityGiftProgressActive
		if err := persist(); err != nil {
			return capabilityGiftResult{}, resumed, err
		}
	} else if edge.Status != capabilityGiftProgressActive {
		return capabilityGiftResult{}, resumed, errors.New("Gift edge has an invalid resumable status")
	}
	if record.IntentID != edge.IntentID || !capabilityGiftSenderRecordMatches(record, *edge, progress.Network.NetworkId) {
		return capabilityGiftResult{}, resumed, errors.New("production Gift sender journal changed after progress binding")
	}
	if record.State == openfoxgift.StateExpiredUnpaid || record.State == openfoxgift.StateInvalidatedUnpaid {
		return capabilityGiftResult{}, resumed, errors.New("deterministic Gift edge terminated unpaid and cannot be replaced")
	}
	if capabilityGiftValidityExpired(record, time.Now().UTC()) {
		result, reconcileErr := capabilityGiftCompleteExpiredEdge(ctx, services[index], services[recipientIndex],
			edge, sender, progress.Network.NetworkId, publisherSources[sender.Name], persist)
		return result, resumed, reconcileErr
	}
	record, err = capabilityGiftResumeDraft(ctx, services[index], record)
	if err != nil {
		return capabilityGiftResult{}, resumed, err
	}
	if !capabilityGiftSenderRecordMatches(record, *edge, progress.Network.NetworkId) {
		return capabilityGiftResult{}, resumed, errors.New("recovered sender Gift draft changed its deterministic edge")
	}
	if record.State == openfoxgift.StateRecipientResolved ||
		record.State == openfoxgift.StateAddressRequested && record.PendingEffect == openfoxgift.EffectSendAddressRequest {
		record, err = services[index].RequestAddress(ctx, record.IntentID)
		if err != nil {
			return capabilityGiftResult{}, resumed, err
		}
		if err := persist(); err != nil {
			return capabilityGiftResult{}, resumed, err
		}
	}
	if record.State == openfoxgift.StateAddressRequested && record.PendingEffect != openfoxgift.EffectNone {
		return capabilityGiftResult{}, resumed, errors.New("address request retains an ambiguous side effect")
	}
	recipientRecord, recipientFound, err := capabilityGiftFindRecipientRecord(
		services[recipientIndex].ListRecords(), *edge, record.IntentID, progress.Network.NetworkId)
	if err != nil {
		return capabilityGiftResult{}, resumed, err
	}
	if !recipientFound {
		if len(record.CanonicalRequest) == 0 {
			return capabilityGiftResult{}, resumed, errors.New("sender journal cannot reconstruct the recipient request")
		}
		recipientRecord, err = services[recipientIndex].ObserveRecipientRequest(ctx, record.CanonicalRequest,
			recipient.AgentID, sender.AgentID)
		if err != nil {
			return capabilityGiftResult{}, resumed, err
		}
	} else if len(record.CanonicalRequest) != 0 {
		if _, err := services[recipientIndex].ObserveRecipientRequest(ctx, record.CanonicalRequest,
			recipient.AgentID, sender.AgentID); err != nil {
			return capabilityGiftResult{}, resumed, err
		}
	}
	if recipientRecord.State == openfoxgift.StateAddressRequestObserved {
		responseNotAfter := record.RequestedValidUntil
		if recipientRecord.PendingEffect == openfoxgift.EffectSendAddressResponse {
			responseNotAfter = recipientRecord.ResponseNotAfter
		}
		if responseNotAfter <= uint32(time.Now().UTC().Unix()) {
			return capabilityGiftResult{}, resumed, errors.New("recipient response validity expired")
		}
		recipientRecord, err = services[recipientIndex].RespondAddress(ctx, recipientRecord.IntentID, responseNotAfter)
		if err != nil {
			return capabilityGiftResult{}, resumed, err
		}
		if err := persist(); err != nil {
			return capabilityGiftResult{}, resumed, err
		}
	}
	if len(recipientRecord.CanonicalResponse) == 0 {
		return capabilityGiftResult{}, resumed, errors.New("recipient journal has no durable address response")
	}
	record, err = services[index].ObserveAddressResponse(ctx, record.IntentID, recipientRecord.CanonicalResponse)
	if err != nil {
		return capabilityGiftResult{}, resumed, err
	}
	if record.State == openfoxgift.StateAddressReceived || record.State == openfoxgift.StateOwnerAuthorizationRequired ||
		record.State == openfoxgift.StateOwnerAuthorized {
		record, err = services[index].Authorize(ctx, record.IntentID)
		if err != nil {
			return capabilityGiftResult{}, resumed, err
		}
	}
	if record.State == openfoxgift.StateOwnerAuthorized || record.State == openfoxgift.StateBOCSigned {
		record, err = services[index].Sign(ctx, record.IntentID, edge.Greeting)
		if err != nil {
			return capabilityGiftResult{}, resumed, err
		}
	}
	if record.State == openfoxgift.StateBOCSigned || record.State == openfoxgift.StateOfferDelivered {
		record, err = services[index].DeliverOffer(ctx, record.IntentID)
		if err != nil {
			return capabilityGiftResult{}, resumed, err
		}
		if err := persist(); err != nil {
			return capabilityGiftResult{}, resumed, err
		}
	}
	recipientRecord, _, err = capabilityGiftFindRecipientRecord(
		services[recipientIndex].ListRecords(), *edge, record.IntentID, progress.Network.NetworkId)
	if err != nil {
		return capabilityGiftResult{}, resumed, err
	}
	offer := record.CanonicalOffer
	if len(offer) == 0 {
		offer = recipientRecord.CanonicalOffer
	}
	deadline := time.Now().Add(90 * time.Second)
	lastErr := capabilityGiftAdvanceBroadcast(ctx, services[recipientIndex], &recipientRecord, offer)
	for time.Now().Before(deadline) {
		record, found, err = capabilityGiftFindSenderRecord(services[index].ListRecords(), *edge, progress.Network.NetworkId)
		if err != nil || !found || record.IntentID != edge.IntentID {
			return capabilityGiftResult{}, resumed, errors.New("sender Gift journal disappeared during finality")
		}
		recipientRecord, recipientFound, err = capabilityGiftFindRecipientRecord(
			services[recipientIndex].ListRecords(), *edge, edge.IntentID, progress.Network.NetworkId)
		if err != nil || !recipientFound {
			return capabilityGiftResult{}, resumed, errors.New("recipient Gift journal disappeared during finality")
		}
		if record.State == openfoxgift.StateFinalizedPaid && recipientRecord.State == openfoxgift.StateFinalizedPaid {
			result, resultErr := capabilityGiftBuildResult(*edge, sender, record, recipientRecord, publisherSources[sender.Name])
			if resultErr != nil {
				return capabilityGiftResult{}, resumed, resultErr
			}
			edge.Status, edge.Result = capabilityGiftProgressFinal, &result
			if err := persist(); err != nil {
				return capabilityGiftResult{}, resumed, err
			}
			return result, resumed, nil
		}
		if capabilityGiftUnpaidTerminal(record.State) || capabilityGiftUnpaidTerminal(recipientRecord.State) {
			return capabilityGiftResult{}, resumed, errors.New("Gift finalized unpaid and cannot be replaced")
		}
		if capabilityGiftRefreshable(record) {
			if _, refreshErr := services[index].Refresh(ctx, record.IntentID); refreshErr != nil {
				lastErr = refreshErr
			}
		}
		if capabilityGiftRefreshable(recipientRecord) {
			if refreshed, refreshErr := services[recipientIndex].Refresh(ctx, recipientRecord.IntentID); refreshErr == nil {
				recipientRecord = refreshed
			} else {
				lastErr = refreshErr
			}
		}
		if len(offer) == 0 {
			offer = recipientRecord.CanonicalOffer
		}
		if broadcastErr := capabilityGiftAdvanceBroadcast(ctx, services[recipientIndex], &recipientRecord, offer); broadcastErr != nil {
			lastErr = broadcastErr
		}
		time.Sleep(time.Second)
	}
	return capabilityGiftResult{}, resumed, fmt.Errorf("Gift finality deadline elapsed: last_error=%v", lastErr)
}

func capabilityGiftValidityExpired(record openfoxgift.Record, now time.Time) bool {
	expiresAt := record.RequestedValidUntil
	if record.ValidUntil != 0 && (expiresAt == 0 || record.ValidUntil < expiresAt) {
		expiresAt = record.ValidUntil
	}
	nowUnix := now.UTC().Unix()
	return expiresAt == 0 || nowUnix < 0 || uint64(nowUnix) >= uint64(expiresAt)
}

// capabilityGiftCompleteExpiredEdge is a refresh-only terminal convergence
// path. Once the signed Gift validity has expired it may observe and reconcile
// an already-submitted exact BOC, but it must never fall through to any of the
// request, authorization, signing, delivery, or broadcast operations below.
func capabilityGiftCompleteExpiredEdge(ctx context.Context, senderService, recipientService capabilityGiftFinalityService,
	edge *capabilityGiftProgressEdge, sender capabilityGiftAgent, network, publisherResolution string,
	persist func() error) (capabilityGiftResult, error) {
	if ctx == nil || senderService == nil || recipientService == nil || edge == nil || edge.IntentID == "" ||
		network == "" || publisherResolution == "" || persist == nil {
		return capabilityGiftResult{}, errors.New("invalid expired Gift finality reconciliation")
	}
	deadline := time.Now().UTC().Add(90 * time.Second)
	var lastErr error
	for {
		stateChanged := false
		senderRecord, senderFound, findErr := capabilityGiftFindSenderRecord(senderService.ListRecords(), *edge, network)
		if findErr != nil || !senderFound || senderRecord.IntentID != edge.IntentID {
			return capabilityGiftResult{}, errors.New("expired Gift sender journal conflicts with its deterministic edge")
		}
		recipientRecord, recipientFound, findErr := capabilityGiftFindRecipientRecord(
			recipientService.ListRecords(), *edge, edge.IntentID, network)
		if findErr != nil || !recipientFound {
			return capabilityGiftResult{}, errors.New("expired Gift recipient journal conflicts with its deterministic edge")
		}
		if capabilityGiftUnpaidTerminal(senderRecord.State) || capabilityGiftUnpaidTerminal(recipientRecord.State) {
			return capabilityGiftResult{}, errors.New("expired Gift finalized unpaid and cannot be replaced")
		}
		if senderRecord.State == openfoxgift.StateFinalizedPaid && recipientRecord.State == openfoxgift.StateFinalizedPaid {
			result, resultErr := capabilityGiftBuildResult(*edge, sender, senderRecord, recipientRecord, publisherResolution)
			if resultErr != nil {
				return capabilityGiftResult{}, resultErr
			}
			edge.Status, edge.Result = capabilityGiftProgressFinal, &result
			if persistErr := persist(); persistErr != nil {
				return capabilityGiftResult{}, persistErr
			}
			return result, nil
		}
		if !time.Now().UTC().Before(deadline) {
			return capabilityGiftResult{}, fmt.Errorf("expired Gift finality deadline elapsed without replacement: last_error=%v", lastErr)
		}
		if senderRecord.State != openfoxgift.StateFinalizedPaid {
			if !capabilityGiftRefreshable(senderRecord) || len(senderRecord.ExactSignedBOC) == 0 {
				return capabilityGiftResult{}, errors.New("expired Gift sender is not in a refresh-only post-signing state")
			}
			refreshed, refreshErr := senderService.Refresh(ctx, senderRecord.IntentID)
			if refreshErr != nil {
				lastErr = refreshErr
			} else if refreshed.IntentID != edge.IntentID || refreshed.Role != openfoxgift.RoleSender {
				return capabilityGiftResult{}, errors.New("expired Gift sender refresh changed its journal identity")
			} else {
				stateChanged = refreshed.State != senderRecord.State
			}
		}
		if recipientRecord.State != openfoxgift.StateFinalizedPaid {
			if !capabilityGiftRefreshable(recipientRecord) || len(recipientRecord.ExactSignedBOC) == 0 {
				return capabilityGiftResult{}, errors.New("expired Gift recipient is not in a refresh-only post-verification state")
			}
			refreshed, refreshErr := recipientService.Refresh(ctx, recipientRecord.IntentID)
			if refreshErr != nil {
				lastErr = refreshErr
			} else if refreshed.IntentID != edge.IntentID || refreshed.Role != openfoxgift.RoleRecipient {
				return capabilityGiftResult{}, errors.New("expired Gift recipient refresh changed its journal identity")
			} else {
				stateChanged = stateChanged || refreshed.State != recipientRecord.State
			}
		}
		if stateChanged {
			continue
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return capabilityGiftResult{}, ctx.Err()
		case <-timer.C:
		}
	}
}

func capabilityGiftResumeDraft(ctx context.Context, service *openfoxgift.Service,
	record openfoxgift.Record) (openfoxgift.Record, error) {
	if record.State != openfoxgift.StateDraft {
		return record, nil
	}
	if service == nil {
		return openfoxgift.Record{}, errors.New("sender Gift draft has no production service")
	}
	recovered, err := service.ResumeSenderDraft(ctx, record.IntentID)
	if err != nil {
		return openfoxgift.Record{}, err
	}
	if recovered.IntentID != record.IntentID || recovered.State != openfoxgift.StateRecipientResolved {
		return openfoxgift.Record{}, errors.New("production sender Gift draft recovery changed its intent")
	}
	return recovered, nil
}

func capabilityGiftSenderRecordMatches(record openfoxgift.Record, edge capabilityGiftProgressEdge, network string) bool {
	return record.Role == openfoxgift.RoleSender && record.Network == network && record.GlobalID == 3 &&
		record.SenderAgentID == edge.SenderAgentID && record.RecipientAgentID == edge.RecipientAgentID &&
		record.SenderAgentAccount == edge.SenderAgentAccount && record.AmountAtomic == edge.AmountAtomic &&
		record.DisplayMessage == edge.Greeting && record.IntentID != ""
}

func capabilityGiftAdvanceBroadcast(ctx context.Context, service *openfoxgift.Service, record *openfoxgift.Record, offer []byte) error {
	if service == nil || record == nil {
		return errors.New("invalid Gift broadcast resume")
	}
	if record.State == openfoxgift.StateFinalizedPaid || capabilityGiftUnpaidTerminal(record.State) {
		return nil
	}
	if record.PendingEffect == openfoxgift.EffectBroadcast {
		refreshed, err := service.Refresh(ctx, record.IntentID)
		if err != nil {
			return err
		}
		*record = refreshed
	}
	ready := record.State == openfoxgift.StateAddressResponseSent || record.State == openfoxgift.StateSignedOfferObserved ||
		record.State == openfoxgift.StateVerified || record.State == openfoxgift.StateCurrentlyExecutable
	if !ready || record.PendingEffect != openfoxgift.EffectNone || record.RetryNotBeforeUnix > time.Now().UTC().Unix() {
		return nil
	}
	if len(offer) == 0 {
		return errors.New("Gift broadcast resume has no durable canonical offer")
	}
	updated, err := service.ObserveAndBroadcastOffer(ctx, record.IntentID, offer)
	if err != nil {
		return err
	}
	*record = updated
	return nil
}

func capabilityGiftRefreshable(record openfoxgift.Record) bool {
	if record.Role == openfoxgift.RoleSender {
		return record.State == openfoxgift.StateBOCSigned || record.State == openfoxgift.StateOfferDelivered ||
			record.State == openfoxgift.StateCurrentlyExecutable || record.State == openfoxgift.StateCurrentlyUnexecutable ||
			record.State == openfoxgift.StateInsufficientFunds || record.State == openfoxgift.StateFinalityUnknown
	}
	return record.State == openfoxgift.StateVerified || record.State == openfoxgift.StateBroadcastSubmitted ||
		record.State == openfoxgift.StateCurrentlyExecutable || record.State == openfoxgift.StateCurrentlyUnexecutable ||
		record.State == openfoxgift.StateInsufficientFunds || record.State == openfoxgift.StateFinalityUnknown
}

func capabilityGiftUnpaidTerminal(state openfoxgift.State) bool {
	return state == openfoxgift.StateExpiredUnpaid || state == openfoxgift.StateInvalidatedUnpaid
}

func capabilityGiftBuildResult(edge capabilityGiftProgressEdge, sender capabilityGiftAgent, record,
	recipientRecord openfoxgift.Record, publisherResolution string) (capabilityGiftResult, error) {
	accounting, err := capabilityGiftAccounting(sender, record, time.Now().UTC())
	if err != nil {
		return capabilityGiftResult{}, err
	}
	result := capabilityGiftResult{EdgeID: edge.EdgeID, Sender: edge.Sender, Recipient: edge.Recipient,
		SenderAlias: edge.SenderAlias, RecipientAlias: edge.RecipientAlias, IntentID: record.IntentID,
		SignedGiftID: record.SignedGiftID, AmountAtomic: record.AmountAtomic,
		SenderFinalState: record.State, RecipientFinalState: recipientRecord.State,
		RequestDigest: record.RequestDigest, ResponseDigest: record.ResponseDigest, ExactBOCDigest: record.ExactBOCDigest,
		RequestEventID: record.RequestEventID, ResponseEventID: recipientRecord.ResponseEventID,
		OfferEventID: record.OfferEventID, PublisherResolution: publisherResolution, Accounting: accounting}
	// Validate both finalized journals against each other and the deterministic
	// edge before a caller can persist the result. A valid sender projection is
	// not sufficient evidence for a conflicting recipient journal.
	if err := capabilityGiftValidateFinalRecords(edge, record, recipientRecord, result); err != nil {
		return capabilityGiftResult{}, err
	}
	return result, nil
}

func capabilityGiftValidateResult(edge capabilityGiftProgressEdge, result capabilityGiftResult) error {
	entryID, err := capabilityGiftAccountingEntryID(result.Accounting.Body)
	amount := result.Accounting.Body.Amount
	evidence := map[string]bool{}
	for _, value := range result.Accounting.Body.EvidenceRefs {
		evidence[value] = true
	}
	if result.EdgeID != edge.EdgeID || result.Sender != edge.Sender || result.Recipient != edge.Recipient ||
		result.SenderAlias != edge.SenderAlias || result.RecipientAlias != edge.RecipientAlias ||
		result.IntentID != edge.IntentID || result.AmountAtomic != edge.AmountAtomic ||
		result.SenderFinalState != openfoxgift.StateFinalizedPaid || result.RecipientFinalState != openfoxgift.StateFinalizedPaid ||
		!capabilityGiftCanonicalSHA256(result.SignedGiftID) || !capabilityGiftCanonicalSHA256(result.RequestDigest) ||
		!capabilityGiftCanonicalSHA256(result.ResponseDigest) || !capabilityGiftCanonicalSHA256(result.ExactBOCDigest) ||
		result.RequestEventID == "" || result.ResponseEventID == "" || result.OfferEventID == "" ||
		result.PublisherResolution == "" || err != nil || entryID != result.Accounting.EntryID ||
		result.Accounting.AgreementSettlementApplied || result.Accounting.Body.OwnerID != edge.SenderOwnerID ||
		result.Accounting.Body.AgentID != edge.SenderAgentID ||
		result.Accounting.Body.Classification != "gratuity" || amount == nil || amount.AssetNamespace != "tos.asset" ||
		amount.AssetIdentifier != "native" || amount.AmountAtomic != edge.AmountAtomic || amount.Unit != "nanotos" ||
		!evidence[result.SignedGiftID] || !evidence[result.ExactBOCDigest] {
		return errors.New("finalized Gift result does not bind its deterministic edge")
	}
	return nil
}

func capabilityGiftValidateFinalRecords(edge capabilityGiftProgressEdge, senderRecord, recipientRecord openfoxgift.Record,
	result capabilityGiftResult) error {
	if !capabilityGiftSenderRecordMatches(senderRecord, edge, senderRecord.Network) ||
		recipientRecord.Role != openfoxgift.RoleRecipient || recipientRecord.IntentID != senderRecord.IntentID ||
		recipientRecord.Network != senderRecord.Network || recipientRecord.GlobalID != senderRecord.GlobalID ||
		recipientRecord.SenderAgentID != edge.SenderAgentID || recipientRecord.RecipientAgentID != edge.RecipientAgentID ||
		recipientRecord.SenderAgentAccount != edge.SenderAgentAccount || recipientRecord.AmountAtomic != edge.AmountAtomic ||
		senderRecord.State != openfoxgift.StateFinalizedPaid || recipientRecord.State != openfoxgift.StateFinalizedPaid ||
		result.IntentID != senderRecord.IntentID || result.SignedGiftID != senderRecord.SignedGiftID ||
		result.RequestDigest != senderRecord.RequestDigest || result.ResponseDigest != senderRecord.ResponseDigest ||
		result.ExactBOCDigest != senderRecord.ExactBOCDigest || result.RequestEventID != senderRecord.RequestEventID ||
		result.ResponseEventID != recipientRecord.ResponseEventID || result.OfferEventID != senderRecord.OfferEventID ||
		recipientRecord.SignedGiftID != senderRecord.SignedGiftID ||
		recipientRecord.ExactBOCDigest != senderRecord.ExactBOCDigest ||
		recipientRecord.RequestDigest != senderRecord.RequestDigest || recipientRecord.ResponseDigest != senderRecord.ResponseDigest ||
		senderRecord.DestinationAddress != edge.RecipientAgentAccount ||
		recipientRecord.DestinationAddress != edge.RecipientAgentAccount ||
		recipientRecord.DestinationAddress != senderRecord.DestinationAddress || recipientRecord.Seqno != senderRecord.Seqno ||
		recipientRecord.ValidUntil != senderRecord.ValidUntil ||
		recipientRecord.RequestedValidUntil != senderRecord.RequestedValidUntil ||
		recipientRecord.ResponseNotAfter != senderRecord.ResponseNotAfter ||
		recipientRecord.ControllerEpoch != senderRecord.ControllerEpoch ||
		recipientRecord.DeploymentID != senderRecord.DeploymentID ||
		recipientRecord.FeeReserveAtomic != senderRecord.FeeReserveAtomic ||
		capabilityGiftValidateResult(edge, result) != nil {
		return errors.New("finalized Gift journals conflict with persisted edge result")
	}
	return nil
}

func capabilityGiftLoadManifest(t *testing.T, path string) capabilityGiftManifest {
	t.Helper()
	if !secureConfigFile(path) {
		t.Fatal("eight-agent Gift manifest must be an owner-private absolute regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 || len(raw) > 2<<20 {
		t.Fatal("read bounded eight-agent Gift manifest")
	}
	var manifest capabilityGiftManifest
	if decodeStrictJSON(raw, &manifest) != nil || capabilityGiftValidateManifest(manifest) != nil {
		t.Fatal("invalid eight-agent Gift manifest")
	}
	return manifest
}

func capabilityGiftValidateManifest(manifest capabilityGiftManifest) error {
	if manifest.Schema != capabilityGiftManifestSchema || len(manifest.Agents) != 8 {
		return errors.New("unexpected capability Gift manifest")
	}
	expected := map[string]bool{"security-auditor": true, "software-builder": true, "evidence-verifier": true,
		"storage-provider": true, "data-curator": true, "localization-writer": true,
		"transaction-operator": true, "guarantor-analyst": true}
	seenNames, seenAliases, seenIDs, seenWallets := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, agent := range manifest.Agents {
		if !expected[agent.Name] || seenNames[agent.Name] || !capabilityGiftCanonicalAgentID(agent.AgentID) ||
			!capabilityGiftCanonicalAccount(agent.Target) || agent.AgentID != "agent_"+strings.TrimPrefix(agent.Target, "0:") || !capabilityGiftCanonicalAlias(agent.TOSName) ||
			seenAliases[agent.TOSName] || seenIDs[agent.AgentID] || agent.Wallet == "" || strings.TrimSpace(agent.Wallet) != agent.Wallet ||
			len(agent.Wallet) > 128 || seenWallets[agent.Wallet] || agent.OwnerID == "" || agent.AuthorityID == "" ||
			agent.Capability == "" || agent.Taxonomy == "" || agent.ModelKind == "" || agent.AuthorityPin == "" || agent.IdentityPin == "" || agent.ConfigDirectory == "" ||
			!filepath.IsAbs(agent.ConfigDirectory) || filepath.Clean(agent.ConfigDirectory) != agent.ConfigDirectory ||
			agent.MinimumPriceNanoTOS == 0 || agent.PriceNanoTOS < agent.MinimumPriceNanoTOS ||
			agent.MaximumLossNanoTOS < capabilityGiftMaximumNanoTOS || len(agent.Tasks) == 0 {
			return errors.New("invalid or duplicate capability Gift agent")
		}
		seenNames[agent.Name], seenAliases[agent.TOSName], seenIDs[agent.AgentID], seenWallets[agent.Wallet] = true, true, true, true
		delete(expected, agent.Name)
	}
	if len(expected) != 0 {
		return errors.New("capability Gift role set is incomplete")
	}
	return nil
}

func capabilityGiftCanonicalAgentID(value string) bool {
	if len(value) != 70 || !strings.HasPrefix(value, "agent_") || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value[6:])
	return err == nil
}

func capabilityGiftCanonicalAccount(value string) bool {
	if len(value) != 66 || !strings.HasPrefix(value, "0:") || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value[2:])
	return err == nil
}

func capabilityGiftCanonicalAlias(value string) bool {
	if value != strings.ToLower(strings.TrimSpace(value)) || !strings.HasSuffix(value, ".tos") || len(value) < 5 || len(value) > 128 {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(value, ".tos"), ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func capabilityGiftLoadTOSCTLDocument(t *testing.T, path string) capabilityGiftTOSCTLDocument {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 || len(raw) > 2<<20 {
		t.Fatal("read bounded primary tosctl config")
	}
	var document capabilityGiftTOSCTLDocument
	if json.Unmarshal(raw, &document) != nil || len(document.AgentWallets) == 0 {
		t.Fatal("decode primary tosctl owner wallet profiles")
	}
	return document
}

func capabilityGiftSafeWalletProfile(profile capabilityGiftWalletProfile) bool {
	if !capabilityGiftSafeKeyName(profile.Key.Name) || (profile.Workchain != -1 && profile.Workchain != 0) {
		return false
	}
	switch profile.Version {
	case "V1R3", "V3R2", "V4R2", "V5R1":
		return true
	default:
		return false
	}
}

func capabilityGiftSafeKeyName(value string) bool {
	if value == "" || len(value) > 256 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && !strings.ContainsRune("-_.:", character) {
			return false
		}
	}
	return true
}

func capabilityGiftPublisherWallets(document capabilityGiftTOSCTLDocument, agents []capabilityGiftAgent, overridePath string) (map[string]string, map[string]string, error) {
	selected, sources := make(map[string]string, len(agents)), make(map[string]string, len(agents))
	if overridePath != "" {
		if !secureConfigFile(overridePath) {
			return nil, nil, errors.New("publisher wallet map must be an owner-private absolute regular file")
		}
		raw, err := os.ReadFile(overridePath)
		if err != nil || len(raw) == 0 || len(raw) > 64<<10 {
			return nil, nil, errors.New("read bounded publisher wallet map")
		}
		var override capabilityGiftPublisherDocument
		if decodeStrictJSON(raw, &override) != nil || override.Schema != capabilityGiftPublisherSchema || len(override.Wallets) != len(agents) {
			return nil, nil, errors.New("invalid publisher wallet map")
		}
		for _, agent := range agents {
			wallet := override.Wallets[agent.Name]
			profile, exists := document.Wallets[wallet]
			if !exists || !capabilityGiftSafeKeyName(wallet) || len(wallet) > 128 || !capabilityGiftSafeWalletProfile(profile) {
				return nil, nil, errors.New("publisher wallet map does not resolve every agent to a safe configured wallet")
			}
			selected[agent.Name], sources[agent.Name] = wallet, "owner-private-override"
		}
		for name := range override.Wallets {
			found := false
			for _, agent := range agents {
				found = found || agent.Name == name
			}
			if !found {
				return nil, nil, errors.New("publisher wallet map contains an unknown agent")
			}
		}
		return selected, sources, nil
	}
	for _, agent := range agents {
		agentProfile, exists := document.AgentWallets[agent.Wallet]
		if !exists || !capabilityGiftSafeWalletProfile(agentProfile.Wallet) {
			return nil, nil, errors.New("cannot derive publisher from an unsafe Agent owner wallet profile")
		}
		matches := make([]string, 0, 1)
		for wallet, profile := range document.Wallets {
			if capabilityGiftSafeWalletProfile(profile) && profile == agentProfile.Wallet {
				matches = append(matches, wallet)
			}
		}
		if len(matches) > 1 {
			return nil, nil, fmt.Errorf("%s needs exactly one regular wallet alias for its Agent owner profile or an explicit publisher map", agent.Name)
		}
		if len(matches) == 1 {
			selected[agent.Name], sources[agent.Name] = matches[0], "derived-owner-wallet-profile"
			continue
		}
		wallet := "openfox-capability-gift-owner-" + agent.Name
		if _, collision := document.Wallets[wallet]; collision || len(wallet) > 128 {
			return nil, nil, errors.New("derived publisher wallet alias collides with tosctl config")
		}
		selected[agent.Name], sources[agent.Name] = wallet, "derived-agent-owner-overlay"
	}
	return selected, sources, nil
}

func capabilityGiftWritePublisherOverlay(sourcePath, destinationPath, wallet string, profile capabilityGiftWalletProfile) error {
	if !secureConfigFile(sourcePath) || !filepath.IsAbs(destinationPath) || filepath.Clean(destinationPath) != destinationPath ||
		!capabilityGiftSafeKeyName(wallet) || len(wallet) > 128 || !capabilityGiftSafeWalletProfile(profile) {
		return errors.New("invalid derived publisher config request")
	}
	raw, err := os.ReadFile(sourcePath)
	if err != nil || len(raw) == 0 || len(raw) > 2<<20 {
		return errors.New("read bounded source publisher config")
	}
	var document map[string]json.RawMessage
	if json.Unmarshal(raw, &document) != nil || len(document) == 0 {
		return errors.New("decode source publisher config")
	}
	var wallets map[string]json.RawMessage
	if rawWallets := document["wallets"]; len(rawWallets) != 0 && string(rawWallets) != "null" {
		if json.Unmarshal(rawWallets, &wallets) != nil {
			return errors.New("decode source publisher wallets")
		}
	}
	if wallets == nil {
		wallets = map[string]json.RawMessage{}
	}
	if _, collision := wallets[wallet]; collision {
		return errors.New("derived publisher wallet alias already exists")
	}
	encodedProfile, err := json.Marshal(profile)
	if err != nil {
		return err
	}
	wallets[wallet] = encodedProfile
	document["wallets"], err = json.Marshal(wallets)
	if err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil || len(encoded) > 2<<20 {
		return errors.New("encode bounded derived publisher config")
	}
	return openfoxfile.WriteFileAtomic(destinationPath, append(encoded, '\n'), 0o600)
}

func capabilityGiftPublisherRPC(document capabilityGiftTOSCTLDocument) (string, error) {
	if document.ChainRPC.APIKey != nil {
		return "", errors.New("Gift publisher does not accept a keyed tosctl RPC endpoint")
	}
	resolved, seen := make([]string, 0, len(document.ChainRPC.URLs)+1), map[string]bool{}
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			resolved = append(resolved, value)
		}
	}
	add(document.ChainRPC.URL)
	for _, raw := range document.ChainRPC.URLs {
		var direct string
		if json.Unmarshal(raw, &direct) == nil {
			add(direct)
			continue
		}
		var entry struct {
			URL    string  `json:"url"`
			APIKey *string `json:"api_key"`
		}
		if json.Unmarshal(raw, &entry) != nil || entry.URL == "" || entry.APIKey != nil {
			return "", errors.New("invalid or keyed tosctl RPC endpoint")
		}
		add(entry.URL)
	}
	if len(resolved) != 1 {
		return "", errors.New("primary tosctl config must resolve to exactly one publisher RPC endpoint")
	}
	return resolved[0], nil
}

func capabilityGiftOwnerAddress(t *testing.T, binary, configPath, vaultURL string, agent capabilityGiftAgent) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "agent", "--config", configPath, "account", "status", "--wallet", agent.Wallet, "--workchain", "0", "--format", "json")
	command.Env = []string{"VAULT_URL=" + vaultURL}
	output, err := command.Output()
	if err != nil || len(output) == 0 || len(output) > 1<<20 {
		return "", errors.New("tosctl Agent Account status failed")
	}
	var status agentAccountStatus
	if decodeStrictJSON(output, &status) != nil || status.Wallet != agent.Wallet || status.Address != agent.Target || status.Owner == "" {
		return "", errors.New("tosctl returned a conflicting Agent Account owner")
	}
	owner, err := toschain.CanonicalAddress(status.Owner)
	if err != nil {
		return "", errors.New("tosctl returned a non-canonical Agent Account owner")
	}
	return owner, nil
}

func capabilityGiftVerifyAlias(t *testing.T, binary, configPath, vaultURL, root, alias, wantAccount string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "domain", "resolve", alias, "--root", root, "--category", "agent", "--format", "json", "-c", configPath)
	command.Env = []string{"VAULT_URL=" + vaultURL}
	output, err := command.Output()
	if err != nil || len(output) == 0 || len(output) > 1<<20 {
		return errors.New("tosctl alias resolution failed")
	}
	var evidence struct {
		CanonicalName   string `json:"canonical_name"`
		Result          string `json:"result"`
		RecordType      string `json:"record_type"`
		RecordValue     string `json:"record_value"`
		ProvenanceClass string `json:"provenance_class"`
		Item            *struct {
			SafeToResolve bool `json:"safe_to_resolve"`
		} `json:"item"`
	}
	if json.Unmarshal(output, &evidence) != nil || evidence.CanonicalName != alias || evidence.Result != "found" ||
		evidence.RecordType != "dns_smc_address" || capabilityGiftDNSValue(evidence.RecordType, evidence.RecordValue) != wantAccount ||
		evidence.ProvenanceClass != "evaluated" || evidence.Item == nil || !evidence.Item.SafeToResolve {
		return errors.New("alias did not resolve to the safe finalized Agent Account")
	}
	return nil
}

func capabilityGiftDNSValue(recordType, value string) string {
	prefix := recordType + " "
	if recordType != "" && strings.HasPrefix(value, prefix) {
		return strings.TrimPrefix(value, prefix)
	}
	return value
}

func capabilityGiftAccounting(agent capabilityGiftAgent, record openfoxgift.Record, observedAt time.Time) (capabilityGiftAccountingEvidence, error) {
	if record.State != openfoxgift.StateFinalizedPaid || record.SignedGiftID == "" || record.ExactBOCDigest == "" ||
		record.AmountAtomic == "" || observedAt.IsZero() {
		return capabilityGiftAccountingEvidence{}, errors.New("Gift lacks finalized accounting evidence")
	}
	evidence := []string{record.SignedGiftID, record.ExactBOCDigest}
	sort.Strings(evidence)
	amount := commerce.AgreementAmount{AssetNamespace: "tos.asset", AssetIdentifier: "native",
		AmountAtomic: record.AmountAtomic, Unit: "nanotos"}
	body := capabilityGiftAccountingBody{SchemaVersion: 1, OwnerID: agent.OwnerID, AgentID: agent.AgentID,
		Classification: "gratuity", Amount: &amount, SourceReference: "agent-gift",
		EvidenceRefs: evidence, ObservedAtUnix: uint64(observedAt.UTC().Unix())}
	entryID, err := capabilityGiftAccountingEntryID(body)
	if err != nil {
		return capabilityGiftAccountingEvidence{}, err
	}
	return capabilityGiftAccountingEvidence{EntryID: entryID, Body: body, AgreementSettlementApplied: false}, nil
}

func capabilityGiftAccountingEntryID(body capabilityGiftAccountingBody) (string, error) {
	if body.SchemaVersion != 1 || body.OwnerID == "" || body.AgentID == "" || body.Classification != "gratuity" ||
		body.SourceReference != "agent-gift" || body.ObservedAtUnix == 0 || body.Amount == nil || body.ComputeUnits != 0 ||
		body.AgreementBodyDigest != "" || body.AgreementObligationID != "" || body.ObligationInstanceID != "" ||
		commerce.ValidateAgreementAmount(*body.Amount) != nil || len(body.EvidenceRefs) != 2 ||
		!sort.StringsAreSorted(body.EvidenceRefs) || body.EvidenceRefs[0] == body.EvidenceRefs[1] {
		return "", errors.New("Gift gratuity accounting body is invalid or attributed to an Agreement")
	}
	for _, evidence := range body.EvidenceRefs {
		if !capabilityGiftCanonicalSHA256(evidence) {
			return "", errors.New("Gift gratuity accounting evidence is invalid")
		}
	}
	return codec.Digest("tos.openfox.accounting-entry-body.v1", body)
}

func capabilityGiftCanonicalSHA256(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value[7:])
	return err == nil
}

func capabilityGiftStringArrayEnv(t *testing.T, name string, paths bool) []string {
	t.Helper()
	raw := capabilityGiftRequiredEnv(t, name)
	var values []string
	if decodeStrictJSON([]byte(raw), &values) != nil || len(values) == 0 || len(values) > 16 {
		t.Fatalf("%s must be a bounded JSON string array", name)
	}
	seen := map[string]bool{}
	for _, value := range values {
		if value == "" || strings.TrimSpace(value) != value || seen[value] {
			t.Fatalf("%s contains an empty, non-canonical, or duplicate value", name)
		}
		seen[value] = true
		if paths {
			if !filepath.IsAbs(value) || filepath.Clean(value) != value {
				t.Fatalf("%s contains a non-canonical path", name)
			}
			continue
		}
		parsed, err := url.Parse(value)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" ||
			parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			t.Fatalf("%s contains an unsafe RPC endpoint", name)
		}
	}
	return values
}

func capabilityGiftRequiredEnv(t *testing.T, name string) string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		t.Fatalf("%s is required", name)
	}
	return value
}

func capabilityGiftEnsurePrivateDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("Gift state directory must be canonical and absolute")
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errors.New("Gift state directory must be owner-private")
	}
	return nil
}

func TestCapabilityGiftPublisherWalletResolution(t *testing.T) {
	profile := capabilityGiftWalletProfile{Key: capabilityGiftKeyProfile{Name: "owner-key-a"}, Version: "V4R2", SubwalletID: 7, Workchain: 0}
	document := capabilityGiftTOSCTLDocument{Wallets: map[string]capabilityGiftWalletProfile{"owner-wallet-a": profile},
		AgentWallets: map[string]capabilityGiftAgentWalletProfile{"agent-wallet-a": {Wallet: profile, ControllerKey: capabilityGiftKeyProfile{Name: "controller-a"}}}}
	agents := []capabilityGiftAgent{{Name: "agent-a", Wallet: "agent-wallet-a"}}
	withoutAlias := document
	withoutAlias.Wallets = map[string]capabilityGiftWalletProfile{}
	wallets, sources, err := capabilityGiftPublisherWallets(withoutAlias, agents, "")
	if err != nil || wallets["agent-a"] != "openfox-capability-gift-owner-agent-a" || sources["agent-a"] != "derived-agent-owner-overlay" {
		t.Fatalf("wallets=%v sources=%v err=%v", wallets, sources, err)
	}
	wallets, sources, err = capabilityGiftPublisherWallets(document, agents, "")
	if err != nil || wallets["agent-a"] != "owner-wallet-a" || sources["agent-a"] != "derived-owner-wallet-profile" {
		t.Fatalf("wallets=%v sources=%v err=%v", wallets, sources, err)
	}
	document.Wallets["ambiguous-owner-wallet"] = profile
	if _, _, err := capabilityGiftPublisherWallets(document, agents, ""); err == nil {
		t.Fatal("ambiguous owner wallet aliases were accepted")
	}
	document.Wallets["override-wallet"] = capabilityGiftWalletProfile{Key: capabilityGiftKeyProfile{Name: "other-owner"}, Version: "V4R2", Workchain: 0}
	directory := t.TempDir()
	path := filepath.Join(directory, "publishers.json")
	raw, _ := json.Marshal(capabilityGiftPublisherDocument{Schema: capabilityGiftPublisherSchema, Wallets: map[string]string{"agent-a": "override-wallet"}})
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	wallets, sources, err = capabilityGiftPublisherWallets(document, agents, path)
	if err != nil || wallets["agent-a"] != "override-wallet" || sources["agent-a"] != "owner-private-override" {
		t.Fatalf("wallets=%v sources=%v err=%v", wallets, sources, err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := capabilityGiftPublisherWallets(document, agents, path); err == nil {
		t.Fatal("world-readable publisher wallet map was accepted")
	}
	source := filepath.Join(directory, "tosctl.json")
	destination := filepath.Join(directory, "derived.json")
	sourceDocument := map[string]any{"wallets": map[string]any{}, "agent_wallets": map[string]any{"agent-wallet-a": map[string]any{"wallet": profile}}}
	sourceRaw, _ := json.Marshal(sourceDocument)
	if err := os.WriteFile(source, sourceRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := capabilityGiftWritePublisherOverlay(source, destination, "derived-owner", profile); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(destination)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("derived publisher config mode=%v err=%v", info, err)
	}
	derivedRaw, err := os.ReadFile(destination)
	var derived map[string]json.RawMessage
	var derivedWallets map[string]capabilityGiftWalletProfile
	if err != nil || json.Unmarshal(derivedRaw, &derived) != nil || json.Unmarshal(derived["wallets"], &derivedWallets) != nil || derivedWallets["derived-owner"] != profile {
		t.Fatal("derived publisher config did not retain the exact safe owner profile")
	}
}

func TestCapabilityGiftAccountingCannotSettleAgreement(t *testing.T) {
	agent := capabilityGiftAgent{Name: "security-auditor", OwnerID: "owner:test", AgentID: "agent_" + strings.Repeat("a", 64)}
	record := openfoxgift.Record{State: openfoxgift.StateFinalizedPaid, AmountAtomic: "100000000",
		SignedGiftID: "sha256:" + strings.Repeat("b", 64), ExactBOCDigest: "sha256:" + strings.Repeat("c", 64)}
	evidence, err := capabilityGiftAccounting(agent, record, time.Unix(1, 0).UTC())
	if err != nil || evidence.Body.Classification != "gratuity" || evidence.AgreementSettlementApplied ||
		evidence.Body.AgreementBodyDigest != "" || evidence.Body.AgreementObligationID != "" || evidence.Body.ObligationInstanceID != "" {
		t.Fatalf("evidence=%+v err=%v", evidence, err)
	}
	bad := evidence.Body
	bad.AgreementBodyDigest = "sha256:" + strings.Repeat("d", 64)
	if _, err := capabilityGiftAccountingEntryID(bad); err == nil {
		t.Fatal("Gift gratuity was accepted as Agreement settlement")
	}
}

func TestCapabilityGiftManifestRequiresCurrentEightRoles(t *testing.T) {
	manifest := capabilityGiftTestManifest(t)
	if err := capabilityGiftValidateManifest(manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Agents[7].TOSName = manifest.Agents[0].TOSName
	if err := capabilityGiftValidateManifest(manifest); err == nil {
		t.Fatal("duplicate capability-market alias was accepted")
	}
}

func TestCapabilityGiftManifestAcceptsCurrentMinimumPriceShape(t *testing.T) {
	manifest := capabilityGiftTestManifest(t)
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var decoded capabilityGiftManifest
	if err := decodeStrictJSON(raw, &decoded); err != nil || capabilityGiftValidateManifest(decoded) != nil ||
		decoded.Agents[0].MinimumPriceNanoTOS != 1 || decoded.Agents[0].PriceNanoTOS != 2 {
		t.Fatalf("current manifest shape was rejected: decoded=%+v err=%v", decoded.Agents[0], err)
	}
	var document map[string]any
	if json.Unmarshal(raw, &document) != nil {
		t.Fatal("decode current manifest JSON fixture")
	}
	agents, ok := document["agents"].([]any)
	if !ok || len(agents) != 8 {
		t.Fatal("current manifest JSON fixture lost its agents")
	}
	first, ok := agents[0].(map[string]any)
	if !ok {
		t.Fatal("current manifest JSON fixture has an invalid Agent")
	}
	delete(first, "minimum_price_nanotos")
	missingRaw, _ := json.Marshal(document)
	decoded = capabilityGiftManifest{}
	if decodeStrictJSON(missingRaw, &decoded) != nil || capabilityGiftValidateManifest(decoded) == nil {
		t.Fatal("manifest without minimum_price_nanotos did not fail closed")
	}
	manifest = capabilityGiftTestManifest(t)
	manifest.Agents[0].MinimumPriceNanoTOS = manifest.Agents[0].PriceNanoTOS + 1
	if capabilityGiftValidateManifest(manifest) == nil {
		t.Fatal("manifest minimum price above advertised price was accepted")
	}
}

func TestCapabilityGiftProgressBindsAndResumesOneFinalizedEdge(t *testing.T) {
	manifest := capabilityGiftTestManifest(t)
	network := &nativev1.NetworkDomain{NetworkId: "tos:local-three-node",
		GenesisRootHash: "sha256:" + strings.Repeat("a", 64), GenesisFileHash: "sha256:" + strings.Repeat("b", 64)}
	wallets, sources := map[string]string{}, map[string]string{}
	for _, agent := range manifest.Agents {
		wallets[agent.Name], sources[agent.Name] = "publisher-"+agent.Name, "owner-private-override"
	}
	started := time.Unix(1_800_000_000, 0).UTC()
	planned, err := capabilityGiftPlanProgress(manifest, network, 100_000_000, wallets, sources, started)
	if err != nil || len(planned.Edges) != 8 {
		t.Fatalf("plan=%+v err=%v", planned, err)
	}
	replannedNetwork := &nativev1.NetworkDomain{NetworkId: network.NetworkId,
		GenesisRootHash: network.GenesisRootHash, GenesisFileHash: network.GenesisFileHash}
	replanned, err := capabilityGiftPlanProgress(manifest, replannedNetwork, 100_000_000, wallets, sources, started.Add(time.Hour))
	if err != nil || replanned.CampaignID != planned.CampaignID {
		t.Fatalf("same immutable ring produced another campaign ID: first=%s second=%s err=%v",
			planned.CampaignID, replanned.CampaignID, err)
	}
	seen := map[string]bool{}
	for index, edge := range planned.Edges {
		if seen[edge.EdgeID] || edge.EdgeID != replanned.Edges[index].EdgeID ||
			!strings.Contains(edge.Greeting, edge.EdgeID) || edge.Status != capabilityGiftProgressPlanned {
			t.Fatal("deterministic Gift edges are missing or duplicated")
		}
		seen[edge.EdgeID] = true
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "ring-progress.json")
	progress, err := capabilityGiftLoadOrCreateProgress(path, planned)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("progress mode=%v err=%v", info, err)
	}
	edge := &progress.Edges[0]
	edge.IntentID = strings.Repeat("1", 64)
	edge.Status = capabilityGiftProgressActive
	senderRecord := openfoxgift.Record{IntentID: edge.IntentID, Role: openfoxgift.RoleSender,
		State: openfoxgift.StateFinalizedPaid, Network: network.NetworkId, GlobalID: 3,
		SenderAgentID: edge.SenderAgentID, RecipientAgentID: edge.RecipientAgentID,
		SenderAgentAccount: edge.SenderAgentAccount, DestinationAddress: edge.RecipientAgentAccount,
		AmountAtomic: edge.AmountAtomic, DisplayMessage: edge.Greeting,
		SignedGiftID: "sha256:" + strings.Repeat("c", 64), RequestDigest: "sha256:" + strings.Repeat("d", 64),
		ResponseDigest: "sha256:" + strings.Repeat("e", 64), ExactBOCDigest: "sha256:" + strings.Repeat("f", 64),
		RequestEventID: "request-event", OfferEventID: "offer-event"}
	recipientRecord := openfoxgift.Record{IntentID: edge.IntentID, Role: openfoxgift.RoleRecipient,
		State: openfoxgift.StateFinalizedPaid, Network: network.NetworkId, GlobalID: 3,
		SenderAgentID: edge.SenderAgentID, RecipientAgentID: edge.RecipientAgentID,
		SenderAgentAccount: edge.SenderAgentAccount, DestinationAddress: edge.RecipientAgentAccount,
		AmountAtomic: edge.AmountAtomic, ResponseEventID: "response-event",
		SignedGiftID: senderRecord.SignedGiftID, RequestDigest: senderRecord.RequestDigest,
		ResponseDigest: senderRecord.ResponseDigest, ExactBOCDigest: senderRecord.ExactBOCDigest}
	result, err := capabilityGiftBuildResult(*edge, manifest.Agents[0], senderRecord, recipientRecord, sources[edge.Sender])
	if err != nil {
		t.Fatal(err)
	}
	edge.Status, edge.Result = capabilityGiftProgressFinal, &result
	progress.UpdatedAt = started.Add(time.Second).Format(time.RFC3339Nano)
	if err := capabilityGiftWriteProgress(path, progress, planned); err != nil {
		t.Fatal(err)
	}
	reloaded, err := capabilityGiftLoadOrCreateProgress(path, planned)
	if err != nil || reloaded.Edges[0].Status != capabilityGiftProgressFinal ||
		reloaded.Edges[0].Result == nil || reloaded.Edges[0].Result.SignedGiftID != senderRecord.SignedGiftID ||
		capabilityGiftValidateFinalRecords(reloaded.Edges[0], senderRecord, recipientRecord, *reloaded.Edges[0].Result) != nil {
		t.Fatalf("finalized edge was not safely resumable: progress=%+v err=%v", reloaded.Edges[0], err)
	}
	found, ok, err := capabilityGiftFindSenderRecord([]openfoxgift.Record{senderRecord}, reloaded.Edges[0], network.NetworkId)
	if err != nil || !ok || found.IntentID != edge.IntentID {
		t.Fatalf("unique edge lookup failed: found=%+v ok=%v err=%v", found, ok, err)
	}
	duplicate := senderRecord
	duplicate.IntentID = strings.Repeat("2", 64)
	if _, _, err := capabilityGiftFindSenderRecord([]openfoxgift.Record{senderRecord, duplicate}, reloaded.Edges[0], network.NetworkId); err == nil {
		t.Fatal("multiple sender intents for one deterministic edge were accepted")
	}
	legacy := senderRecord
	legacy.DisplayMessage = "Capability-market thank-you gratuity from " + edge.SenderAlias + "; not Agreement consideration or settlement."
	if _, _, err := capabilityGiftFindSenderRecord([]openfoxgift.Record{legacy}, reloaded.Edges[0], network.NetworkId); err == nil {
		t.Fatal("legacy Gift greeting without the current edge ID was adopted")
	}
	changedPlan, err := capabilityGiftPlanProgress(manifest, network, 99_999_999, wallets, sources, started)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := capabilityGiftLoadOrCreateProgress(path, changedPlan); err == nil {
		t.Fatal("changed amount reused an existing Gift ring progress file")
	}
}

func TestCapabilityGiftExpiredEdgeUsesStickyRefreshOnlyConvergence(t *testing.T) {
	manifest := capabilityGiftTestManifest(t)
	network := &nativev1.NetworkDomain{NetworkId: "tos:local-three-node",
		GenesisRootHash: "sha256:" + strings.Repeat("a", 64), GenesisFileHash: "sha256:" + strings.Repeat("b", 64)}
	wallets, sources := map[string]string{}, map[string]string{}
	for _, agent := range manifest.Agents {
		wallets[agent.Name], sources[agent.Name] = "publisher-"+agent.Name, "owner-private-override"
	}
	progress, err := capabilityGiftPlanProgress(manifest, network, 100_000_000, wallets, sources, time.Unix(1_800_000_000, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	edge := &progress.Edges[0]
	edge.IntentID, edge.Status = strings.Repeat("1", 64), capabilityGiftProgressActive
	senderRecord := openfoxgift.Record{IntentID: edge.IntentID, Role: openfoxgift.RoleSender,
		State: openfoxgift.StateFinalityUnknown, Network: network.NetworkId, GlobalID: 3,
		SenderAgentID: edge.SenderAgentID, RecipientAgentID: edge.RecipientAgentID,
		SenderAgentAccount: edge.SenderAgentAccount, DestinationAddress: edge.RecipientAgentAccount,
		AmountAtomic: edge.AmountAtomic, DisplayMessage: edge.Greeting,
		RequestedValidUntil: 1, ValidUntil: 1, ExactSignedBOC: []byte{1, 2, 3},
		SignedGiftID: "sha256:" + strings.Repeat("c", 64), RequestDigest: "sha256:" + strings.Repeat("d", 64),
		ResponseDigest: "sha256:" + strings.Repeat("e", 64), ExactBOCDigest: "sha256:" + strings.Repeat("f", 64),
		RequestEventID: "request-event", OfferEventID: "offer-event"}
	recipientRecord := openfoxgift.Record{IntentID: edge.IntentID, Role: openfoxgift.RoleRecipient,
		State: openfoxgift.StateFinalizedPaid, Network: network.NetworkId, GlobalID: 3,
		SenderAgentID: edge.SenderAgentID, RecipientAgentID: edge.RecipientAgentID,
		SenderAgentAccount: edge.SenderAgentAccount, DestinationAddress: edge.RecipientAgentAccount,
		AmountAtomic: edge.AmountAtomic, RequestedValidUntil: 1, ValidUntil: 1,
		SignedGiftID: senderRecord.SignedGiftID, RequestDigest: senderRecord.RequestDigest,
		ResponseDigest: senderRecord.ResponseDigest, ExactBOCDigest: senderRecord.ExactBOCDigest,
		ResponseEventID: "response-event"}
	senderService := &capabilityGiftFinalityStub{records: []openfoxgift.Record{senderRecord}, nextState: openfoxgift.StateFinalizedPaid}
	recipientService := &capabilityGiftFinalityStub{records: []openfoxgift.Record{recipientRecord}, nextState: openfoxgift.StateFinalizedPaid}
	persistCalls := 0
	result, err := capabilityGiftCompleteExpiredEdge(context.Background(), senderService, recipientService,
		edge, manifest.Agents[0], network.NetworkId, sources[edge.Sender], func() error { persistCalls++; return nil })
	if err != nil || result.SenderFinalState != openfoxgift.StateFinalizedPaid ||
		result.RecipientFinalState != openfoxgift.StateFinalizedPaid || senderService.refreshCalls != 1 ||
		recipientService.refreshCalls != 0 || persistCalls != 1 || edge.Status != capabilityGiftProgressFinal {
		t.Fatalf("expired finality-only convergence: result=%+v err=%v sender_refresh=%d recipient_refresh=%d persist=%d edge=%+v",
			result, err, senderService.refreshCalls, recipientService.refreshCalls, persistCalls, edge)
	}

	unsafeSender := senderRecord
	unsafeSender.State, unsafeSender.ExactSignedBOC = openfoxgift.StateOwnerAuthorized, nil
	unsafeSenderService := &capabilityGiftFinalityStub{records: []openfoxgift.Record{unsafeSender}, nextState: openfoxgift.StateFinalizedPaid}
	unsafeRecipientService := &capabilityGiftFinalityStub{records: []openfoxgift.Record{recipientRecord}, nextState: openfoxgift.StateFinalizedPaid}
	unsafeEdge := progress.Edges[1]
	unsafeEdge = *edge
	unsafeEdge.Status, unsafeEdge.Result = capabilityGiftProgressActive, nil
	if _, err := capabilityGiftCompleteExpiredEdge(context.Background(), unsafeSenderService, unsafeRecipientService,
		&unsafeEdge, manifest.Agents[0], network.NetworkId, sources[edge.Sender], func() error { return nil }); err == nil || unsafeSenderService.refreshCalls != 0 || unsafeRecipientService.refreshCalls != 0 {
		t.Fatalf("expired pre-broadcast sender escaped refresh-only gate: err=%v sender_refresh=%d recipient_refresh=%d",
			err, unsafeSenderService.refreshCalls, unsafeRecipientService.refreshCalls)
	}

	finalSender := senderRecord
	finalSender.State = openfoxgift.StateFinalizedPaid
	unsafeRecipient := recipientRecord
	unsafeRecipient.State, unsafeRecipient.ExactSignedBOC = openfoxgift.StateSignedOfferObserved, []byte{1, 2, 3}
	finalSenderService := &capabilityGiftFinalityStub{records: []openfoxgift.Record{finalSender}, nextState: openfoxgift.StateFinalizedPaid}
	unsafeRecipientService = &capabilityGiftFinalityStub{records: []openfoxgift.Record{unsafeRecipient}, nextState: openfoxgift.StateFinalizedPaid}
	unsafeEdge.Status, unsafeEdge.Result = capabilityGiftProgressActive, nil
	if _, err := capabilityGiftCompleteExpiredEdge(context.Background(), finalSenderService, unsafeRecipientService,
		&unsafeEdge, manifest.Agents[0], network.NetworkId, sources[edge.Sender], func() error { return nil }); err == nil || finalSenderService.refreshCalls != 0 || unsafeRecipientService.refreshCalls != 0 {
		t.Fatalf("expired pre-broadcast recipient escaped refresh-only gate: err=%v sender_refresh=%d recipient_refresh=%d",
			err, finalSenderService.refreshCalls, unsafeRecipientService.refreshCalls)
	}

	conflictingRecipient := recipientRecord
	conflictingRecipient.SignedGiftID = "sha256:" + strings.Repeat("9", 64)
	conflictSenderService := &capabilityGiftFinalityStub{records: []openfoxgift.Record{finalSender}}
	conflictRecipientService := &capabilityGiftFinalityStub{records: []openfoxgift.Record{conflictingRecipient}}
	conflictPersistCalls := 0
	unsafeEdge.Status, unsafeEdge.Result = capabilityGiftProgressActive, nil
	if _, err := capabilityGiftCompleteExpiredEdge(context.Background(), conflictSenderService, conflictRecipientService,
		&unsafeEdge, manifest.Agents[0], network.NetworkId, sources[edge.Sender], func() error { conflictPersistCalls++; return nil }); err == nil || conflictPersistCalls != 0 {
		t.Fatalf("conflicting finalized recipient journal was persisted: err=%v persist=%d", err, conflictPersistCalls)
	}

	wrongDestination := "0:" + strings.Repeat("9", 64)
	wrongSender, wrongRecipient := finalSender, recipientRecord
	wrongSender.DestinationAddress, wrongRecipient.DestinationAddress = wrongDestination, wrongDestination
	wrongSenderService := &capabilityGiftFinalityStub{records: []openfoxgift.Record{wrongSender}}
	wrongRecipientService := &capabilityGiftFinalityStub{records: []openfoxgift.Record{wrongRecipient}}
	wrongPersistCalls := 0
	unsafeEdge.Status, unsafeEdge.Result = capabilityGiftProgressActive, nil
	if _, err := capabilityGiftCompleteExpiredEdge(context.Background(), wrongSenderService, wrongRecipientService,
		&unsafeEdge, manifest.Agents[0], network.NetworkId, sources[edge.Sender], func() error { wrongPersistCalls++; return nil }); err == nil || wrongPersistCalls != 0 {
		t.Fatalf("wrong finalized destination was persisted: err=%v persist=%d", err, wrongPersistCalls)
	}
}

func TestCapabilityGiftValidityUsesEarliestSignedBoundary(t *testing.T) {
	record := openfoxgift.Record{RequestedValidUntil: 200, ValidUntil: 100}
	if !capabilityGiftValidityExpired(record, time.Unix(150, 0)) {
		t.Fatal("earlier signed BOC validity was ignored")
	}
	record.ValidUntil = 0
	if capabilityGiftValidityExpired(record, time.Unix(199, 0)) || !capabilityGiftValidityExpired(record, time.Unix(200, 0)) {
		t.Fatal("request validity boundary was not enforced exactly")
	}
}

func TestCapabilityGiftProgressRequiresCanonicalUniqueKeyJSON(t *testing.T) {
	manifest := capabilityGiftTestManifest(t)
	network := &nativev1.NetworkDomain{NetworkId: "tos:local-three-node",
		GenesisRootHash: "sha256:" + strings.Repeat("a", 64), GenesisFileHash: "sha256:" + strings.Repeat("b", 64)}
	wallets, sources := map[string]string{}, map[string]string{}
	for _, agent := range manifest.Agents {
		wallets[agent.Name], sources[agent.Name] = "publisher-"+agent.Name, "owner-private-override"
	}
	planned, err := capabilityGiftPlanProgress(manifest, network, 100_000_000, wallets, sources, time.Unix(1_800_000_000, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "ring-progress.json")
	if _, err := capabilityGiftLoadOrCreateProgress(path, planned); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	schemaLine := []byte(`  "schema": "` + capabilityGiftProgressSchema + `",`)
	duplicate := bytes.Replace(raw, schemaLine, append(append([]byte(nil), schemaLine...), append([]byte{'\n'}, schemaLine...)...), 1)
	if bytes.Equal(raw, duplicate) {
		t.Fatal("failed to construct duplicate-key progress fixture")
	}
	if err := os.WriteFile(path, duplicate, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := capabilityGiftLoadOrCreateProgress(path, planned); err == nil {
		t.Fatal("progress JSON with a duplicate key was accepted")
	}
	if err := capabilityGiftWriteProgress(path, planned, planned); err != nil {
		t.Fatal(err)
	}
	compact, err := json.Marshal(planned)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, compact, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := capabilityGiftLoadOrCreateProgress(path, planned); err == nil {
		t.Fatal("non-canonical progress JSON encoding was accepted")
	}
	legacyProgress := planned
	legacyProgress.Edges = append([]capabilityGiftProgressEdge(nil), planned.Edges...)
	legacyProgress.Edges[0].Greeting = "Capability-market thank-you gratuity from " +
		legacyProgress.Edges[0].SenderAlias + "; not Agreement consideration or settlement."
	if capabilityGiftValidateProgress(legacyProgress, planned) == nil {
		t.Fatal("progress downgraded to a legacy greeting without an edge ID")
	}
}

func TestCapabilityGiftHarnessResumesDurableSenderDraftIntent(t *testing.T) {
	manifest := capabilityGiftTestManifest(t)
	network := &nativev1.NetworkDomain{NetworkId: "tos:local-three-node",
		GenesisRootHash: "sha256:" + strings.Repeat("a", 64), GenesisFileHash: "sha256:" + strings.Repeat("b", 64)}
	wallets, sources := map[string]string{}, map[string]string{}
	for _, agent := range manifest.Agents {
		wallets[agent.Name], sources[agent.Name] = "publisher-"+agent.Name, "owner-private-override"
	}
	progress, err := capabilityGiftPlanProgress(manifest, network, 100_000_000, wallets, sources, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	edge := &progress.Edges[0]
	chain := fixtureChain(t)
	protocol, err := NewAgentGiftProtocol(chain, 1_000_000, 60)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := NewAgentGiftResolver(chain, fixtureRecipientAuthority{})
	if err != nil {
		t.Fatal(err)
	}
	wire := &capabilityGiftWire{}
	journal := fixtureJournal(t, "capability-draft-crash")
	service, err := openfoxgift.NewService(journal, protocol, resolver, wire,
		&fixtureGiftCustody{chain: chain}, &fixtureGiftBroadcaster{},
		fixtureGiftAddress{address: edge.RecipientAgentAccount}, mustOwner(t))
	if err != nil {
		t.Fatal(err)
	}
	intentID := strings.Repeat("9", 64)
	validUntil := uint32(time.Now().UTC().Add(15 * time.Minute).Unix())
	request := openfoxgift.RequestIntent{Network: network.NetworkId, GlobalID: 3, IntentID: intentID,
		SenderAgentID: edge.SenderAgentID, RecipientAgentID: edge.RecipientAgentID,
		SenderAgentAccount: edge.SenderAgentAccount, AmountAtomic: edge.AmountAtomic, RequestedValidUntil: validUntil}
	canonical, requestDigest, err := protocol.CreateAddressRequest(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Unix()
	draft, err := journal.Create(openfoxgift.Record{IntentID: intentID, Role: openfoxgift.RoleSender,
		State: openfoxgift.StateDraft, Network: request.Network, GlobalID: request.GlobalID,
		SenderAgentID: request.SenderAgentID, RecipientAgentID: request.RecipientAgentID,
		SenderAgentAccount: request.SenderAgentAccount, AmountAtomic: request.AmountAtomic,
		RequestedValidUntil: request.RequestedValidUntil, RequestDigest: requestDigest,
		CanonicalRequest: canonical, DisplayMessage: edge.Greeting, CreatedAtUnix: now, UpdatedAtUnix: now})
	if err != nil {
		t.Fatal(err)
	}
	found, ok, err := capabilityGiftFindSenderRecord(journal.List(), *edge, network.NetworkId)
	if err != nil || !ok || found.IntentID != intentID || found.State != openfoxgift.StateDraft {
		t.Fatalf("harness did not rediscover injected durable Draft: record=%+v ok=%v err=%v", found, ok, err)
	}
	edge.IntentID, edge.Status = intentID, capabilityGiftProgressActive
	recovered, err := capabilityGiftResumeDraft(t.Context(), service, draft)
	if err != nil || recovered.IntentID != intentID || recovered.State != openfoxgift.StateRecipientResolved || len(journal.List()) != 1 {
		t.Fatalf("harness did not recover the same Draft Intent: record=%+v err=%v count=%d", recovered, err, len(journal.List()))
	}
	again, err := capabilityGiftResumeDraft(t.Context(), service, draft)
	if err != nil || again.IntentID != intentID || again.State != openfoxgift.StateRecipientResolved || len(journal.List()) != 1 {
		t.Fatalf("harness Draft recovery was not idempotent: record=%+v err=%v count=%d", again, err, len(journal.List()))
	}
	requested, err := service.RequestAddress(t.Context(), intentID)
	if err != nil || requested.IntentID != intentID || requested.State != openfoxgift.StateAddressRequested || len(journal.List()) != 1 {
		t.Fatalf("recovered Draft could not continue on the same Intent: record=%+v err=%v count=%d", requested, err, len(journal.List()))
	}
}

func capabilityGiftTestManifest(t *testing.T) capabilityGiftManifest {
	t.Helper()
	names := []string{"security-auditor", "software-builder", "evidence-verifier", "storage-provider", "data-curator", "localization-writer", "transaction-operator", "guarantor-analyst"}
	manifest := capabilityGiftManifest{Schema: capabilityGiftManifestSchema, CreatedAt: "2026-09-01T00:00:00Z"}
	directory := t.TempDir()
	for index, name := range names {
		hexID := fmt.Sprintf("%064x", index+1)
		manifest.Agents = append(manifest.Agents, capabilityGiftAgent{Name: name, TOSName: fmt.Sprintf("agent%d.tos", index),
			OwnerID: "owner:" + name, AgentID: "agent_" + hexID, AuthorityID: "authority:" + name,
			Wallet: "wallet-" + name, Target: "0:" + hexID, Capability: "capability", Taxonomy: "taxonomy", ModelKind: "test",
			AuthorityPin: "ed25519:test", IdentityPin: "ed25519:test",
			ConfigDirectory: filepath.Join(directory, name), MinimumPriceNanoTOS: 1, PriceNanoTOS: 2,
			MaximumInternalCostNanoTOS: 1, MaximumLossNanoTOS: capabilityGiftMaximumNanoTOS,
			Tasks: []string{"bounded task"}})
	}
	return manifest
}
