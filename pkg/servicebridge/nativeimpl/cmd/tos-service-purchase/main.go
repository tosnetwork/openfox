// Command tos-service-purchase runs the production buyer as explicit,
// reviewable prepare, deploy, fund, dispatch, settlement, and inspect stages.
// It never combines a custody signature with its one-way broadcast in one
// invocation.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2aclient"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/tosnetwork/openfox/pkg/actionauth"
	"github.com/tosnetwork/openfox/pkg/messengerauth"
	"github.com/tosnetwork/openfox/pkg/servicebridge"
	nativeimpl "github.com/tosnetwork/openfox/pkg/servicebridge/nativeimpl"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/buyersdk"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"google.golang.org/protobuf/encoding/protojson"
)

type purchaseInputDocument struct {
	Schema                 string                   `json:"schema"`
	Proposal               json.RawMessage          `json:"proposal"`
	ManifestCBORPath       string                   `json:"manifest_cbor_path"`
	EscrowTerms            escrowTermsDocument      `json:"escrow_terms"`
	ExecutionSignerEd25519 string                   `json:"execution_signer_ed25519_hex"`
	TransportBinding       transportBindingDocument `json:"transport_binding"`
}

type escrowTermsDocument struct {
	BuyerAddress      string `json:"buyer_address"`
	ProviderAddress   string `json:"provider_address"`
	FundingDeadline   uint64 `json:"funding_deadline"`
	RefundAvailableAt uint64 `json:"refund_available_at"`
}

type transportBindingDocument struct {
	SecurityMode    uint8  `json:"security_mode"`
	MaxRequestBytes uint32 `json:"max_request_bytes"`
	BaseURL         string `json:"base_url"`
}

type dispatchTaskDocument struct {
	Schema          string `json:"schema"`
	EscrowAddress   string `json:"escrow_address"`
	QuoteCommitment string `json:"quote_commitment"`
	ExecutionID     string `json:"execution_id"`
	InputDigest     string `json:"input_digest"`
	SourceDigest    string `json:"source_digest"`
	SourceArchive   string `json:"source_archive"`
}

type finalizedFundingDocument struct {
	Schema              string `json:"schema"`
	Verdict             string `json:"verdict"`
	EscrowAddress       string `json:"escrow_address"`
	QuoteCommitment     string `json:"quote_commitment"`
	AmountAtomic        string `json:"amount_atomic"`
	FinalizedCheckpoint uint64 `json:"finalized_checkpoint"`
	ContractCodeHash    string `json:"contract_code_hash"`
	FinalizedAt         string `json:"finalized_at"`
}

type bearerRoundTripper struct {
	base  http.RoundTripper
	token string
}

func (t bearerRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	clone.Header.Set("Authorization", "Bearer "+t.token)
	return t.base.RoundTrip(clone)
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("stage must be prepare, inspect, deploy-prepare, deploy-broadcast, fund, or dispatch")
	}
	switch args[0] {
	case "prepare":
		return runPrepare(args[1:])
	case "inspect":
		return runInspect(args[1:])
	case "deploy-prepare":
		return runDeployPrepare(args[1:])
	case "deploy-broadcast":
		return runDeployBroadcast(args[1:])
	case "fund":
		return runFund(args[1:])
	case "dispatch":
		return runDispatch(args[1:])
	default:
		return errors.New("unknown purchase stage")
	}
}

func runPrepare(args []string) error {
	flags := flag.NewFlagSet("prepare", flag.ContinueOnError)
	config := flags.String("config", "", "owner-private chain buyer config")
	input := flags.String("input", "", "owner-private purchase input")
	output := flags.String("output", "", "new owner-private prepared purchase artifact")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *config == "" || *input == "" || *output == "" {
		return errors.New("prepare requires --config, --input, and --output")
	}
	stack, err := nativeimpl.LoadChainBuyerStack(*config)
	if err != nil {
		return err
	}
	purchaseInput, err := loadPurchaseInput(*input)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	prepared, err := stack.SDK.PreparePurchase(ctx, purchaseInput)
	if err != nil {
		return err
	}
	encoded, err := nativeimpl.MarshalPreparedPurchase(prepared)
	if err != nil {
		return err
	}
	if err := writePrivateNew(*output, encoded); err != nil {
		return err
	}
	return printReview("PREPARED_REVIEW_REQUIRED", prepared)
}

func runInspect(args []string) error {
	flags := flag.NewFlagSet("inspect", flag.ContinueOnError)
	purchasePath := flags.String("purchase", "", "prepared purchase artifact")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *purchasePath == "" {
		return errors.New("inspect requires --purchase")
	}
	purchase, err := loadPreparedPurchase(*purchasePath)
	if err != nil {
		return err
	}
	return printReview("REVIEW_ONLY_NO_ACTION", purchase)
}

func runDeployPrepare(args []string) error {
	flags := flag.NewFlagSet("deploy-prepare", flag.ContinueOnError)
	config := flags.String("config", "", "owner-private chain buyer config")
	purchasePath := flags.String("purchase", "", "reviewed prepared purchase")
	output := flags.String("output", "", "new owner-private signed deployment artifact")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *config == "" || *purchasePath == "" || *output == "" {
		return errors.New("deploy-prepare requires --config, --purchase, and --output")
	}
	stack, err := nativeimpl.LoadChainBuyerStack(*config)
	if err != nil {
		return err
	}
	purchase, err := loadPreparedPurchase(*purchasePath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	deployment, err := stack.Deployer.PrepareEscrowDeployment(ctx, purchase)
	if err != nil {
		return err
	}
	encoded, err := nativeimpl.MarshalPreparedEscrowDeployment(deployment)
	if err != nil {
		return err
	}
	if err := writePrivateNew(*output, encoded); err != nil {
		return err
	}
	return printJSON(map[string]any{"verdict": "SIGNED_DEPLOYMENT_REVIEW_REQUIRED",
		"escrow_address": deployment.EscrowAddress, "quote_commitment": deployment.QuoteCommitment,
		"state_init_hash": deployment.StateInitHash, "message_hash": deployment.MessageHash,
		"attached_nanotos": deployment.AttachedNanoTOS, "artifact": *output})
}

func runDeployBroadcast(args []string) error {
	flags := flag.NewFlagSet("deploy-broadcast", flag.ContinueOnError)
	config := flags.String("config", "", "owner-private chain buyer config")
	deploymentPath := flags.String("deployment", "", "reviewed signed deployment artifact")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *config == "" || *deploymentPath == "" {
		return errors.New("deploy-broadcast requires --config and --deployment")
	}
	stack, err := nativeimpl.LoadChainBuyerStack(*config)
	if err != nil {
		return err
	}
	raw, err := readPrivateFile(*deploymentPath, 4<<20)
	if err != nil {
		return err
	}
	deployment, err := nativeimpl.UnmarshalPreparedEscrowDeployment(raw)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := stack.Deployer.BroadcastEscrowDeployment(ctx, deployment); err != nil {
		return err
	}
	return printJSON(map[string]any{"verdict": "DEPLOYMENT_SUBMITTED_REQUIRES_FINALIZED_REVIEW",
		"escrow_address": deployment.EscrowAddress, "quote_commitment": deployment.QuoteCommitment,
		"message_hash": deployment.MessageHash})
}

func runFund(args []string) error {
	flags := flag.NewFlagSet("fund", flag.ContinueOnError)
	config := flags.String("config", "", "owner-private chain buyer config")
	purchasePath := flags.String("purchase", "", "reviewed prepared purchase")
	requestKey := flags.String("request-key", "", "durable funding idempotency key")
	evidencePath := flags.String("evidence", "", "new owner-private finalized funding evidence")
	messengerSocket := flags.String("messenger-socket", "", "tos-messengerd runtime socket")
	mandateID := flags.String("mandate-id", "", "owner-approved spend mandate")
	capabilityClass := flags.String("capability-class", "", "reviewed Capability class")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *config == "" || *purchasePath == "" ||
		*requestKey == "" || len(*requestKey) > 256 || *evidencePath == "" || *messengerSocket == "" ||
		*mandateID == "" || *capabilityClass == "" {
		return errors.New("fund requires --config, --purchase, --request-key, --evidence, --messenger-socket, --mandate-id, and --capability-class")
	}
	stack, err := nativeimpl.LoadChainBuyerStack(*config)
	if err != nil {
		return err
	}
	purchase, err := loadPreparedPurchase(*purchasePath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	input, err := nativeimpl.PurchaseInputFromPreparedPurchase(purchase)
	if err != nil {
		return err
	}
	session, err := nativeimpl.NewBuyerSession(stack.SDK, input)
	if err != nil {
		return err
	}
	ref := servicebridge.CapabilityRef{AgentID: purchase.Proposal.GetProviderAgentId(),
		CapabilityID: purchase.Proposal.GetCapabilityId(), Version: purchase.Proposal.GetCapabilityVersion(),
		ManifestDigest: purchase.Proposal.GetManifestDigest(), RegistryCodeHash: stack.RegistryCodeHash,
		Network: stack.Network, CapabilityClass: *capabilityClass}
	proposal, err := session.RequestQuote(ctx, ref)
	if err != nil {
		return err
	}
	amount, err := strconv.ParseUint(purchase.AmountAtomic, 10, 64)
	if err != nil || amount == 0 {
		return errors.New("purchase amount is outside the OpenFox policy range")
	}
	key := servicebridge.PurchaseKey{QuoteCommitment: purchase.QuoteCommitment, EscrowAddress: purchase.Escrow.Address}
	if _, err := stack.Journal.Begin(servicebridge.PurchaseRecord{Key: key,
		AssetMaster: purchase.AssetMasterAddress, AtomicAmount: amount}, time.Now().UTC()); err != nil {
		return err
	}
	acquired, record, err := stack.Journal.AcquireFundingLease(key)
	if err != nil {
		return err
	}
	var fundedStateAmount string
	var finalizedCheckpoint uint64
	var contractCodeHash string
	var finalizedAt time.Time
	if acquired {
		terms, err := servicebridge.PurchaseTermsForProposal(proposal)
		if err != nil {
			return err
		}
		messenger, err := messengerauth.NewClient(*messengerSocket, 30*time.Second)
		if err != nil {
			return err
		}
		if err := messenger.Authorize(ctx, actionauth.Action{Effect: actionauth.EffectSpend,
			Summary: "fund accepted quote " + purchase.QuoteCommitment, MandateID: *mandateID, Terms: &terms}); err != nil {
			return err
		}
		funded, err := stack.SDK.FundPurchase(ctx, purchase, *requestKey)
		if err != nil {
			return err
		}
		if funded == nil || funded.State == nil || funded.Reference == nil {
			return errors.New("funding returned incomplete finalized evidence")
		}
		fundedStateAmount, finalizedCheckpoint, contractCodeHash, finalizedAt = funded.State.FundedAtomicAmount,
			funded.Reference.FinalizedCheckpoint, funded.Reference.ContractCodeHash, funded.FinalizedAt
	} else {
		if record.Phase.Order() < servicebridge.PhaseFundingLease.Order() {
			return errors.New("funding lease was not durably acquired")
		}
		resolved, found, err := stack.Escrow.ResolveFinalizedExact(ctx, purchase.Escrow.Address)
		if err != nil {
			return err
		}
		if !found || resolved == nil || resolved.State == nil || resolved.Reference == nil ||
			resolved.State.FundedAtomicAmount != purchase.AmountAtomic {
			return servicebridge.ErrFundingAmbiguous
		}
		fundedStateAmount, finalizedCheckpoint, contractCodeHash, finalizedAt = resolved.State.FundedAtomicAmount,
			resolved.Reference.FinalizedCheckpoint, resolved.Reference.ContractCodeHash, resolved.FinalizedAt
	}
	if finalizedCheckpoint == 0 || contractCodeHash != purchase.Escrow.CodeHash || finalizedAt.IsZero() ||
		fundedStateAmount != purchase.AmountAtomic {
		return errors.New("funding evidence is not an exact finalized purchase")
	}
	if err := stack.Journal.Advance(key, servicebridge.PhaseFunded); err != nil && !errors.Is(err, servicebridge.ErrJournalPhase) {
		return err
	}
	evidence := map[string]any{"schema": "tos.openfox.finalized-funding.v1", "verdict": "PASS_FINALIZED_EXACT_FUNDING",
		"escrow_address": purchase.Escrow.Address, "quote_commitment": purchase.QuoteCommitment,
		"amount_atomic": fundedStateAmount, "finalized_checkpoint": finalizedCheckpoint,
		"contract_code_hash": contractCodeHash, "finalized_at": finalizedAt.UTC().Format(time.RFC3339Nano)}
	encoded, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return err
	}
	if err := writePrivateNew(*evidencePath, append(encoded, '\n')); err != nil {
		return err
	}
	return printJSON(evidence)
}

func runDispatch(args []string) error {
	flags := flag.NewFlagSet("dispatch", flag.ContinueOnError)
	config := flags.String("config", "", "owner-private chain buyer config")
	policyPath := flags.String("policy", "", "owner-signed spending policy")
	purchasePath := flags.String("purchase", "", "reviewed prepared purchase")
	fundingPath := flags.String("funding-evidence", "", "finalized exact-funding evidence")
	taskPath := flags.String("task", "", "owner-private exact task document")
	evidencePath := flags.String("evidence", "", "new terminal settlement evidence")
	messengerSocket := flags.String("messenger-socket", "", "tos-messengerd runtime socket")
	mandateID := flags.String("mandate-id", "", "owner-approved spend mandate")
	capabilityClass := flags.String("capability-class", "", "reviewed Capability class")
	transportName := flags.String("transport", "", "a2a, mcp, or agent_packet")
	endpoint := flags.String("endpoint", "", "exact provider endpoint committed by the Quote")
	caPath := flags.String("ca", "", "reviewed private CA certificate for HTTPS")
	tokenPath := flags.String("bearer-token-file", "", "owner-private provider bearer token")
	senderAgent := flags.String("sender-agent-id", "", "live sender Native Agent ID")
	recipientAgent := flags.String("recipient-agent-id", "", "provider Native Agent ID")
	capabilityID := flags.String("capability-id", "", "target Native Capability ID")
	signingSeedPath := flags.String("agent-signing-seed", "", "owner-private raw Agent Packet signing seed")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *config == "" || *policyPath == "" ||
		*purchasePath == "" || *fundingPath == "" || *taskPath == "" || *evidencePath == "" ||
		*messengerSocket == "" || *mandateID == "" || *capabilityClass == "" || *transportName == "" ||
		*endpoint == "" || *tokenPath == "" {
		return errors.New("dispatch configuration is incomplete")
	}
	stack, err := nativeimpl.LoadChainBuyerStack(*config)
	if err != nil {
		return err
	}
	policy, ownerKey, err := nativeimpl.LoadSignedSpendingPolicy(*policyPath)
	if err != nil {
		return err
	}
	if policy.ConfirmationMode != servicebridge.ConfirmAuto {
		return errors.New("manual spending policy requires the interactive OpenFox runtime, not the stock dispatch command")
	}
	purchase, err := loadPreparedPurchase(*purchasePath)
	if err != nil {
		return err
	}
	input, err := nativeimpl.PurchaseInputFromPreparedPurchase(purchase)
	if err != nil {
		return err
	}
	if *endpoint != input.TransportBinding.BaseURL {
		return errors.New("provider endpoint differs from the reviewed transport binding")
	}
	funding, err := loadFundingEvidence(*fundingPath, purchase)
	if err != nil {
		return err
	}
	_ = funding // finalized chain state remains authoritative; this is a stage handoff check.
	taskDocument, archive, err := loadDispatchTask(*taskPath, purchase)
	if err != nil {
		return err
	}
	httpClient, err := newPinnedHTTPClient(*endpoint, *caPath, *tokenPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	dispatch, closeTransport, err := newDispatchTransport(ctx, *transportName, *endpoint, *signingSeedPath,
		*senderAgent, *recipientAgent, *capabilityID, httpClient)
	if err != nil {
		return err
	}
	if closeTransport != nil {
		defer closeTransport()
	}
	messenger, err := messengerauth.NewClient(*messengerSocket, 30*time.Second)
	if err != nil {
		return err
	}
	buyer, err := nativeimpl.NewChainNativeBuyer(nativeimpl.ChainNativeBuyerConfig{Stack: stack, Input: input,
		Policy: policy, OwnerPublicKey: ownerKey, Transport: dispatch, Authorizer: messenger,
		QuoteVerifier: messenger, MandateID: *mandateID})
	if err != nil {
		return err
	}
	ref := servicebridge.CapabilityRef{AgentID: purchase.Proposal.GetProviderAgentId(),
		CapabilityID: purchase.Proposal.GetCapabilityId(), Version: purchase.Proposal.GetCapabilityVersion(),
		ManifestDigest: purchase.Proposal.GetManifestDigest(), RegistryCodeHash: stack.RegistryCodeHash,
		Network: stack.Network, CapabilityClass: *capabilityClass}
	transport := servicebridge.Transport(*transportName)
	settlement, err := buyer.Purchase(ctx, ref, transport, func(accepted servicebridge.AcceptedQuote) (servicebridge.Task, error) {
		if accepted.QuoteCommitment != taskDocument.QuoteCommitment || accepted.EscrowAddress != taskDocument.EscrowAddress {
			return servicebridge.Task{}, errors.New("task differs from the accepted purchase")
		}
		return servicebridge.Task{EscrowAddress: taskDocument.EscrowAddress,
			QuoteCommitment: taskDocument.QuoteCommitment, ExecutionID: taskDocument.ExecutionID,
			InputDigest: taskDocument.InputDigest, SourceDigest: taskDocument.SourceDigest,
			SourceArchive: append([]byte(nil), archive...)}, nil
	})
	if err != nil {
		return err
	}
	evidence := map[string]any{"schema": "tos.openfox.terminal-settlement.v1", "verdict": "PASS_TERMINAL_SETTLEMENT",
		"transport": *transportName, "escrow_address": purchase.Escrow.Address,
		"quote_commitment": purchase.QuoteCommitment, "execution_id": taskDocument.ExecutionID,
		"released": settlement.Released, "refunded": settlement.Refunded,
		"provider_credit_atomic": settlement.ProviderCreditAtomic, "buyer_balance_atomic": settlement.BuyerBalanceAtomic,
		"finalized_checkpoint": settlement.Checkpoint}
	encoded, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return err
	}
	if err := writePrivateNew(*evidencePath, append(encoded, '\n')); err != nil {
		return err
	}
	return printJSON(evidence)
}

func loadFundingEvidence(path string, purchase *buyersdk.PreparedPurchase) (finalizedFundingDocument, error) {
	raw, err := readPrivateFile(path, 1<<20)
	if err != nil {
		return finalizedFundingDocument{}, err
	}
	var evidence finalizedFundingDocument
	if err := decodeStrict(raw, &evidence); err != nil || evidence.Schema != "tos.openfox.finalized-funding.v1" ||
		evidence.Verdict != "PASS_FINALIZED_EXACT_FUNDING" || evidence.EscrowAddress != purchase.Escrow.Address ||
		evidence.QuoteCommitment != purchase.QuoteCommitment || evidence.AmountAtomic != purchase.AmountAtomic ||
		evidence.FinalizedCheckpoint == 0 || evidence.ContractCodeHash != purchase.Escrow.CodeHash || evidence.FinalizedAt == "" {
		return finalizedFundingDocument{}, errors.New("invalid or mismatched finalized funding evidence")
	}
	if _, err := time.Parse(time.RFC3339Nano, evidence.FinalizedAt); err != nil {
		return finalizedFundingDocument{}, errors.New("invalid finalized funding time")
	}
	return evidence, nil
}

func loadDispatchTask(path string, purchase *buyersdk.PreparedPurchase) (dispatchTaskDocument, []byte, error) {
	raw, err := readPrivateFile(path, 1<<20)
	if err != nil {
		return dispatchTaskDocument{}, nil, err
	}
	var document dispatchTaskDocument
	if err := decodeStrict(raw, &document); err != nil || document.Schema != "tos.service.local-funded-task.v1" ||
		document.EscrowAddress != purchase.Escrow.Address || document.QuoteCommitment != purchase.QuoteCommitment ||
		document.ExecutionID == "" || document.InputDigest == "" || document.SourceDigest == "" || document.SourceArchive == "" {
		return dispatchTaskDocument{}, nil, errors.New("invalid or mismatched dispatch task")
	}
	archive, err := readReviewedFile(document.SourceArchive, 64<<20)
	if err != nil {
		return dispatchTaskDocument{}, nil, err
	}
	digest := sha256.Sum256(archive)
	if document.SourceDigest != "sha256:"+hex.EncodeToString(digest[:]) {
		return dispatchTaskDocument{}, nil, errors.New("source archive digest mismatch")
	}
	return document, archive, nil
}

func newPinnedHTTPClient(endpoint, caPath, tokenPath string) (*http.Client, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return nil, errors.New("invalid provider endpoint")
	}
	if parsed.Scheme == "http" {
		host := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return nil, errors.New("plaintext provider endpoint must be loopback")
		}
	}
	token, err := readPrivateFile(tokenPath, 16<<10)
	if err != nil || len(strings.TrimSpace(string(token))) < 32 {
		return nil, errors.New("read provider bearer token")
	}
	transport := &http.Transport{Proxy: nil}
	if parsed.Scheme == "https" {
		ca, err := readReviewedFile(caPath, 1<<20)
		if err != nil {
			return nil, err
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(ca) {
			return nil, errors.New("parse provider CA")
		}
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}
	}
	return &http.Client{Transport: bearerRoundTripper{token: strings.TrimSpace(string(token)), base: transport}}, nil
}

func newDispatchTransport(ctx context.Context, name, endpoint, seedPath, senderAgent, recipientAgent, capabilityID string,
	client *http.Client) (servicebridge.TaskTransport, func() error, error) {
	switch name {
	case "a2a":
		wire := a2aclient.NewJSONRPCTransport(endpoint, client)
		transport, err := nativeimpl.NewA2ATaskTransport(wire)
		return transport, func() error { wire.Destroy(); return nil }, err
	case "mcp":
		mcpClient := mcp.NewClient(&mcp.Implementation{Name: "tos-service-production-buyer", Version: "1.0.0"}, nil)
		session, err := mcpClient.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: endpoint, HTTPClient: client,
			DisableStandaloneSSE: true, MaxRetries: -1}, nil)
		if err != nil {
			return nil, nil, err
		}
		transport, err := nativeimpl.NewMCPTaskTransport(session)
		if err != nil {
			session.Close()
			return nil, nil, err
		}
		return transport, session.Close, nil
	case "agent_packet":
		seed, err := readPrivateFile(seedPath, ed25519.SeedSize)
		if err != nil || len(seed) != ed25519.SeedSize {
			return nil, nil, errors.New("read Agent Packet signing seed")
		}
		key := ed25519.NewKeyFromSeed(seed)
		for index := range seed {
			seed[index] = 0
		}
		transport, err := nativeimpl.NewAgentPacketTaskTransport(nativeimpl.AgentPacketTransportConfig{
			SenderAgentID: senderAgent, RecipientAgentID: recipientAgent, CapabilityID: capabilityID,
			SigningKey: key, Endpoint: endpoint, Client: client})
		return transport, nil, err
	default:
		return nil, nil, errors.New("transport must be a2a, mcp, or agent_packet")
	}
}

func loadPurchaseInput(path string) (buyersdk.PurchaseInput, error) {
	raw, err := readPrivateFile(path, 1<<20)
	if err != nil {
		return buyersdk.PurchaseInput{}, err
	}
	var document purchaseInputDocument
	if err := decodeStrict(raw, &document); err != nil || document.Schema != "tos.openfox.purchase-input.v1" ||
		len(document.Proposal) == 0 || document.ManifestCBORPath == "" || document.ExecutionSignerEd25519 == "" {
		return buyersdk.PurchaseInput{}, errors.New("invalid purchase input document")
	}
	var proposal nativev1.QuoteProposalV1
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(document.Proposal, &proposal); err != nil {
		return buyersdk.PurchaseInput{}, errors.New("invalid Quote Proposal")
	}
	manifest, err := readReviewedFile(document.ManifestCBORPath, 1<<20)
	if err != nil {
		return buyersdk.PurchaseInput{}, err
	}
	signer, err := hex.DecodeString(document.ExecutionSignerEd25519)
	if err != nil || len(signer) != 32 || bytes.Equal(signer, make([]byte, 32)) {
		return buyersdk.PurchaseInput{}, errors.New("invalid execution signer public key")
	}
	return buyersdk.PurchaseInput{Proposal: &proposal, ManifestCBOR: manifest, EscrowTerms: nativecore.EscrowTermsV1{
		BuyerAddress: document.EscrowTerms.BuyerAddress, ProviderAddress: document.EscrowTerms.ProviderAddress,
		FundingDeadline: document.EscrowTerms.FundingDeadline, RefundAvailableAt: document.EscrowTerms.RefundAvailableAt,
	}, ExecutionSignerEd25519: signer, TransportBinding: nativecore.TransportBindingV1{
		SecurityMode: document.TransportBinding.SecurityMode, MaxRequestBytes: document.TransportBinding.MaxRequestBytes,
		BaseURL: document.TransportBinding.BaseURL,
	}}, nil
}

func loadPreparedPurchase(path string) (*buyersdk.PreparedPurchase, error) {
	raw, err := readPrivateFile(path, 4<<20)
	if err != nil {
		return nil, err
	}
	return nativeimpl.UnmarshalPreparedPurchase(raw)
}

func printReview(verdict string, purchase *buyersdk.PreparedPurchase) error {
	return printJSON(map[string]any{"verdict": verdict, "manifest_digest": purchase.ManifestDigest,
		"quote_commitment": purchase.QuoteCommitment, "escrow_address": purchase.Escrow.Address,
		"escrow_code_hash": purchase.Escrow.CodeHash, "asset_master_address": purchase.AssetMasterAddress,
		"buyer_wallet_address": purchase.BuyerWalletAddress, "amount_atomic": purchase.AmountAtomic})
}

func printJSON(value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(encoded))
	return nil
}

func readPrivateFile(path string, maximum int) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("private input path must be clean and absolute")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		return nil, errors.New("private input must be an owner-only regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 || len(raw) > maximum {
		return nil, errors.New("read private input")
	}
	return raw, nil
}

func readReviewedFile(path string, maximum int) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("reviewed input path must be clean and absolute")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("reviewed input must be a non-writable regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 || len(raw) > maximum {
		return nil, errors.New("read reviewed input")
	}
	return raw, nil
}

func writePrivateNew(path string, raw []byte) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(raw) == 0 {
		return errors.New("output path must be clean and absolute")
	}
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return errors.New("output directory must already be owner-private")
	}
	temporary, err := os.CreateTemp(parent, ".tos-service-purchase-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(raw); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Link(temporaryPath, path); err != nil {
		return errors.New("output already exists or cannot be linked")
	}
	directory, err := os.Open(parent)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func decodeStrict(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}
