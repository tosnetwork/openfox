// Command tos-service-purchase runs the production buyer as explicit,
// reviewable prepare, deploy, fund, and inspect stages. It never combines a
// custody signature with its one-way broadcast in one invocation.
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

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

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("stage must be prepare, inspect, deploy-prepare, deploy-broadcast, or fund")
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
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *config == "" || *purchasePath == "" ||
		*requestKey == "" || len(*requestKey) > 256 || *evidencePath == "" {
		return errors.New("fund requires --config, --purchase, --request-key, and --evidence")
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
	funded, err := stack.SDK.FundPurchase(ctx, purchase, *requestKey)
	if err != nil {
		return err
	}
	if funded == nil || funded.State == nil || funded.Reference == nil {
		return errors.New("funding returned incomplete finalized evidence")
	}
	evidence := map[string]any{"schema": "tos.openfox.finalized-funding.v1", "verdict": "PASS_FINALIZED_EXACT_FUNDING",
		"escrow_address": purchase.Escrow.Address, "quote_commitment": purchase.QuoteCommitment,
		"amount_atomic": funded.State.FundedAtomicAmount, "finalized_checkpoint": funded.Reference.FinalizedCheckpoint,
		"contract_code_hash": funded.Reference.ContractCodeHash, "finalized_at": funded.FinalizedAt.UTC().Format(time.RFC3339Nano)}
	encoded, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return err
	}
	if err := writePrivateNew(*evidencePath, append(encoded, '\n')); err != nil {
		return err
	}
	return printJSON(evidence)
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
