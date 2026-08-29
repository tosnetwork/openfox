package nativeimpl

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	openfoxgift "github.com/tosnetwork/openfox/pkg/agentgift"
	"github.com/tosnetwork/tos-messenger/pkg/envelope"
	"github.com/tosnetwork/tos-messenger/pkg/localapi"
	"github.com/tosnetwork/tos-messenger/pkg/payload"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	protocolgift "github.com/tosnetwork/tos-service-protocol/pkg/agentgift"
	"google.golang.org/protobuf/proto"
)

// AgentGiftFinalizedChain is the narrow finalized-chain authority needed by
// Gift encoding, independent BOC verification, and lifecycle resolution.
// Implementations must derive both values from one finalized checkpoint.
type AgentGiftFinalizedChain interface {
	FinalizedAgentAccount(context.Context, string) (protocolgift.FinalizedAgentAccount, uint32, error)
	ResolveFinalizedGift(context.Context, openfoxgift.Record) (protocolgift.FinalizedGiftObservation, error)
}

type AgentGiftChainReader interface {
	FinalizedAgentAccount(context.Context, string) (protocolgift.FinalizedAgentAccount, uint32, error)
	ResolveGift(context.Context, string, string, []byte, uint32, uint32, string, uint64, int64) (protocolgift.FinalizedGiftObservation, error)
}

// AgentGiftChainAdapter maps OpenFox's durable record onto the protocol
// module's quorum-finalized TOS reader without exposing journal types there.
type AgentGiftChainAdapter struct{ reader AgentGiftChainReader }

func NewAgentGiftChainAdapter(reader AgentGiftChainReader) (*AgentGiftChainAdapter, error) {
	if reader == nil {
		return nil, errors.New("nativeimpl: Agent Gift chain reader is required")
	}
	return &AgentGiftChainAdapter{reader: reader}, nil
}

func (a *AgentGiftChainAdapter) FinalizedAgentAccount(ctx context.Context, account string) (protocolgift.FinalizedAgentAccount, uint32, error) {
	return a.reader.FinalizedAgentAccount(ctx, account)
}

func (a *AgentGiftChainAdapter) ResolveFinalizedGift(ctx context.Context, record openfoxgift.Record) (protocolgift.FinalizedGiftObservation, error) {
	feeReserve, err := strconv.ParseUint(record.FeeReserveAtomic, 10, 64)
	if err != nil || feeReserve == 0 {
		return protocolgift.FinalizedGiftObservation{}, errors.New("nativeimpl: Gift record has no canonical fee reserve")
	}
	return a.reader.ResolveGift(ctx, record.SenderAgentAccount, record.DestinationAddress, record.ExactSignedBOC, record.Seqno, record.ValidUntil, record.DeploymentID, feeReserve, record.CreatedAtUnix)
}

type AgentGiftProtocol struct {
	chain      AgentGiftFinalizedChain
	feeReserve uint64
	margin     uint32
}

func NewAgentGiftProtocol(chain AgentGiftFinalizedChain, feeReserve uint64, minimumInclusionMargin uint32) (*AgentGiftProtocol, error) {
	if chain == nil || feeReserve == 0 || minimumInclusionMargin == 0 {
		return nil, errors.New("nativeimpl: finalized Gift chain, fee reserve, and inclusion margin are required")
	}
	return &AgentGiftProtocol{chain: chain, feeReserve: feeReserve, margin: minimumInclusionMargin}, nil
}

func (p *AgentGiftProtocol) CreateAddressRequest(_ context.Context, v openfoxgift.RequestIntent) ([]byte, string, error) {
	request := protocolgift.GiftAddressRequestV1{
		Schema: protocolgift.SchemaAddressRequest, Network: v.Network, GlobalID: v.GlobalID,
		GiftIntentID: v.IntentID, SenderAgentID: v.SenderAgentID, RecipientAgentID: v.RecipientAgentID,
		SenderAgentAccount: v.SenderAgentAccount, AssetKind: protocolgift.AssetNativeTOS,
		AmountAtomic: v.AmountAtomic, RequestedValidUntil: v.RequestedValidUntil,
	}
	encoded, err := protocolgift.Encode(request)
	if err != nil {
		return nil, "", err
	}
	digest, err := protocolgift.RequestDigest(request)
	return encoded, digest, err
}

func (p *AgentGiftProtocol) InspectAddressRequest(_ context.Context, raw []byte) (openfoxgift.RequestIntent, string, error) {
	request, err := protocolgift.DecodeAddressRequest(raw)
	if err != nil {
		return openfoxgift.RequestIntent{}, "", err
	}
	digest, err := protocolgift.RequestDigest(request)
	return openfoxgift.RequestIntent{Network: request.Network, GlobalID: request.GlobalID, IntentID: request.GiftIntentID, SenderAgentID: request.SenderAgentID, RecipientAgentID: request.RecipientAgentID, SenderAgentAccount: request.SenderAgentAccount, AmountAtomic: request.AmountAtomic, RequestedValidUntil: request.RequestedValidUntil}, digest, err
}

func (p *AgentGiftProtocol) CreateAddressResponse(_ context.Context, requestRaw []byte, destination string, responseNotAfter uint32) ([]byte, openfoxgift.ResponseTerms, error) {
	request, err := protocolgift.DecodeAddressRequest(requestRaw)
	if err != nil {
		return nil, openfoxgift.ResponseTerms{}, err
	}
	requestDigest, err := protocolgift.RequestDigest(request)
	if err != nil {
		return nil, openfoxgift.ResponseTerms{}, err
	}
	response := protocolgift.GiftAddressResponseV1{
		Schema: protocolgift.SchemaAddressResponse, Network: request.Network, GlobalID: request.GlobalID,
		GiftIntentID: request.GiftIntentID, RequestDigest: requestDigest, SenderAgentID: request.SenderAgentID,
		RecipientAgentID: request.RecipientAgentID, AssetKind: request.AssetKind, AmountAtomic: request.AmountAtomic,
		DestinationAddress: destination, ResponseNotAfter: responseNotAfter,
	}
	if err := protocolgift.BindResponse(request, response); err != nil {
		return nil, openfoxgift.ResponseTerms{}, err
	}
	encoded, err := protocolgift.Encode(response)
	if err != nil {
		return nil, openfoxgift.ResponseTerms{}, err
	}
	responseDigest, err := protocolgift.ResponseDigest(response)
	return encoded, openfoxgift.ResponseTerms{DestinationAddress: destination, ResponseNotAfter: responseNotAfter, RequestDigest: requestDigest, ResponseDigest: responseDigest}, err
}

func (p *AgentGiftProtocol) ValidateAddressResponse(_ context.Context, requestRaw, responseRaw []byte) (openfoxgift.ResponseTerms, error) {
	request, response, err := decodeBoundExchange(requestRaw, responseRaw)
	if err != nil {
		return openfoxgift.ResponseTerms{}, err
	}
	requestDigest, err := protocolgift.RequestDigest(request)
	if err != nil {
		return openfoxgift.ResponseTerms{}, err
	}
	responseDigest, err := protocolgift.ResponseDigest(response)
	return openfoxgift.ResponseTerms{DestinationAddress: response.DestinationAddress, ResponseNotAfter: response.ResponseNotAfter, RequestDigest: requestDigest, ResponseDigest: responseDigest}, err
}

func (p *AgentGiftProtocol) CreateSignedOffer(_ context.Context, requestRaw, responseRaw, boc []byte, greeting string) ([]byte, string, error) {
	request, response, err := decodeBoundExchange(requestRaw, responseRaw)
	if err != nil {
		return nil, "", err
	}
	requestDigest, _ := protocolgift.RequestDigest(request)
	responseDigest, _ := protocolgift.ResponseDigest(response)
	signedID := protocolgift.SignedGiftID(boc)
	offer := protocolgift.GiftSignedBOCOfferV1{Schema: protocolgift.SchemaSignedBOCOffer, GiftIntentID: request.GiftIntentID, AddressRequestDigest: requestDigest, AddressResponseDigest: responseDigest, SignedGiftID: signedID, ExactSignedBOC: append([]byte(nil), boc...), DisplayMessage: greeting}
	encoded, err := protocolgift.Encode(offer)
	return encoded, signedID, err
}

func (p *AgentGiftProtocol) VerifySignedOffer(ctx context.Context, requestRaw, responseRaw, offerRaw []byte) (openfoxgift.SignedTerms, error) {
	if p == nil || p.chain == nil || ctx == nil {
		return openfoxgift.SignedTerms{}, errors.New("nativeimpl: invalid Gift verifier")
	}
	request, response, err := decodeBoundExchange(requestRaw, responseRaw)
	if err != nil {
		return openfoxgift.SignedTerms{}, err
	}
	offer, err := protocolgift.DecodeSignedBOCOffer(offerRaw)
	if err != nil {
		return openfoxgift.SignedTerms{}, err
	}
	requestDigest, _ := protocolgift.RequestDigest(request)
	responseDigest, _ := protocolgift.ResponseDigest(response)
	if offer.GiftIntentID != request.GiftIntentID || offer.AddressRequestDigest != requestDigest || offer.AddressResponseDigest != responseDigest {
		return openfoxgift.SignedTerms{}, errors.New("nativeimpl: signed Gift offer exchange binding mismatch")
	}
	account, chainTime, err := p.chain.FinalizedAgentAccount(ctx, request.SenderAgentAccount)
	if err != nil {
		return openfoxgift.SignedTerms{}, err
	}
	parsed, err := protocolgift.VerifyAgentNativeSend(protocolgift.VerifyNativeSendInput{
		ExactSignedBOC: offer.ExactSignedBOC, Request: request, Response: response, Account: account,
		ExpectedSignedGiftID: offer.SignedGiftID, FeeReserveAtomic: p.feeReserve,
		FinalizedChainTime: chainTime, MinimumInclusionMargin: p.margin,
	})
	if err != nil {
		return openfoxgift.SignedTerms{}, err
	}
	return openfoxgift.SignedTerms{SignedGiftID: parsed.SignedGiftID, ExactBOCDigest: parsed.ExactBOCDigest, SenderAgentAccount: parsed.SenderAgentAccount, DestinationAddress: parsed.DestinationAddress, AmountAtomic: strconv.FormatUint(parsed.AmountAtomic, 10), DeploymentID: account.DeploymentID, FeeReserveAtomic: strconv.FormatUint(p.feeReserve, 10), ControllerEpoch: parsed.ControllerEpoch, Seqno: parsed.Seqno, ValidUntil: parsed.ValidUntil, ExactSignedBOC: append([]byte(nil), offer.ExactSignedBOC...)}, nil
}

type AgentGiftRecipientAuthority interface {
	ResolveCanonicalAgent(context.Context, string) (string, error)
}

type AgentGiftResolver struct {
	chain      AgentGiftFinalizedChain
	recipients AgentGiftRecipientAuthority
}

func NewAgentGiftResolver(chain AgentGiftFinalizedChain, recipients AgentGiftRecipientAuthority) (*AgentGiftResolver, error) {
	if chain == nil || recipients == nil {
		return nil, errors.New("nativeimpl: finalized Gift chain and recipient authority are required")
	}
	return &AgentGiftResolver{chain: chain, recipients: recipients}, nil
}

func (r *AgentGiftResolver) ResolveRecipient(ctx context.Context, recipient string) (string, error) {
	return r.recipients.ResolveCanonicalAgent(ctx, recipient)
}

// AgentGiftDNSRecipientAuthority resolves a .tos discovery input exactly once
// from quorum-bound finalized evidence. Canonical AgentIDs pass through after
// strict validation; aliases never become an ongoing routing authority.
type AgentGiftDNSRecipientAuthority struct {
	client  DNSAliasClient
	network *nativev1.NetworkDomain
	caller  string
	now     func() time.Time
}

func NewAgentGiftDNSRecipientAuthority(client DNSAliasClient, network *nativev1.NetworkDomain, caller string) (*AgentGiftDNSRecipientAuthority, error) {
	if client == nil || network == nil || network.NetworkId == "" || network.GenesisRootHash == "" || network.GenesisFileHash == "" || caller == "" {
		return nil, errors.New("nativeimpl: incomplete Agent Gift recipient authority")
	}
	return &AgentGiftDNSRecipientAuthority{client: client, network: proto.Clone(network).(*nativev1.NetworkDomain), caller: caller, now: time.Now}, nil
}

func (a *AgentGiftDNSRecipientAuthority) ResolveCanonicalAgent(ctx context.Context, input string) (string, error) {
	if a == nil || ctx == nil {
		return "", errors.New("nativeimpl: invalid Agent Gift recipient resolution")
	}
	if strings.HasPrefix(input, "agent_") {
		if len(input) != 70 || input != strings.ToLower(input) {
			return "", errors.New("nativeimpl: invalid canonical AgentID")
		}
		if _, err := hex.DecodeString(input[6:]); err != nil {
			return "", errors.New("nativeimpl: invalid canonical AgentID")
		}
		return input, nil
	}
	response, err := ResolveDNSNameInput(ctx, a.client, a.network, input, a.caller, nativev1.DNSAliasKindV1_DNS_ALIAS_KIND_V1_AGENT, a.now().UTC())
	if err != nil {
		return "", err
	}
	return response.NativeObjectId, nil
}

func (r *AgentGiftResolver) ResolveFinality(ctx context.Context, record openfoxgift.Record) (openfoxgift.FinalityResult, error) {
	observation, err := r.chain.ResolveFinalizedGift(ctx, record)
	if err != nil {
		return openfoxgift.FinalityResult{}, err
	}
	resolution, err := protocolgift.ResolveFinalizedGift(observation)
	if err != nil {
		return openfoxgift.FinalityResult{}, err
	}
	switch resolution {
	case protocolgift.ResolutionPending:
		// The exact sender execution is finalized but its corresponding
		// destination credit is not yet finalized. OpenFox has no paid-pending
		// terminal state, so retain the explicitly unresolved state.
		return openfoxgift.FinalityResult{State: openfoxgift.StateFinalityUnknown}, nil
	case protocolgift.ResolutionCurrentlyExecutable:
		return openfoxgift.FinalityResult{State: openfoxgift.StateCurrentlyExecutable}, nil
	case protocolgift.ResolutionCurrentlyUnexecutable:
		return openfoxgift.FinalityResult{State: openfoxgift.StateCurrentlyUnexecutable}, nil
	case protocolgift.ResolutionInsufficientFunds:
		return openfoxgift.FinalityResult{State: openfoxgift.StateInsufficientFunds}, nil
	case protocolgift.ResolutionFinalizedPaid:
		return openfoxgift.FinalityResult{State: openfoxgift.StateFinalizedPaid}, nil
	case protocolgift.ResolutionExpiredUnpaid:
		return openfoxgift.FinalityResult{State: openfoxgift.StateExpiredUnpaid}, nil
	case protocolgift.ResolutionInvalidatedUnpaid:
		return openfoxgift.FinalityResult{State: openfoxgift.StateInvalidatedUnpaid}, nil
	case protocolgift.ResolutionFinalityUnknown:
		return openfoxgift.FinalityResult{State: openfoxgift.StateFinalityUnknown}, nil
	default:
		return openfoxgift.FinalityResult{}, errors.New("nativeimpl: unknown finalized Gift resolution")
	}
}

type TOSCTLGiftCustodyConfig struct {
	BinaryPath      string `json:"binary_path"`
	ConfigPath      string `json:"config_path"`
	VaultURL        string `json:"vault_url"`
	WalletName      string `json:"wallet_name"`
	OwnerWallet     string `json:"owner_wallet"`
	ControllerKeyID string `json:"controller_key_id"`
	// AgentAccountWorkchain selects the workchain used when resolving the
	// configured Agent Wallet profile. Nil preserves the historical masterchain
	// default; a pointer is required so workchain zero is not confused with an
	// omitted JSON field.
	AgentAccountWorkchain  *int32        `json:"agent_account_workchain,omitempty"`
	QuorumConfigPaths      []string      `json:"quorum_config_paths"`
	MaxTransactions        uint32        `json:"max_transactions,omitempty"`
	FeeReserveAtomic       uint64        `json:"fee_reserve_atomic,omitempty"`
	MinimumInclusionMargin uint32        `json:"minimum_inclusion_margin_seconds,omitempty"`
	Timeout                time.Duration `json:"timeout_nanoseconds,omitempty"`
}

type TOSCTLGiftCustody struct {
	config TOSCTLGiftCustodyConfig
	chain  AgentGiftFinalizedChain
	runner releaseCommandRunner
}

func NewTOSCTLGiftCustody(config TOSCTLGiftCustodyConfig, chain AgentGiftFinalizedChain) (*TOSCTLGiftCustody, error) {
	if chain == nil || !secureExecutable(config.BinaryPath) || !secureConfigFile(config.ConfigPath) || config.VaultURL == "" || config.WalletName == "" || config.OwnerWallet == "" || config.ControllerKeyID == "" || len(config.QuorumConfigPaths) < 2 || config.FeeReserveAtomic == 0 || config.MinimumInclusionMargin == 0 {
		return nil, errors.New("nativeimpl: invalid tosctl Gift custody configuration")
	}
	seenConfigs := map[string]bool{config.ConfigPath: true}
	for _, path := range config.QuorumConfigPaths {
		if !secureConfigFile(path) || seenConfigs[path] {
			return nil, errors.New("nativeimpl: invalid tosctl Gift custody quorum configuration")
		}
		seenConfigs[path] = true
	}
	if config.MaxTransactions == 0 {
		config.MaxTransactions = 1000
	}
	if config.MaxTransactions > 10_000 {
		return nil, errors.New("nativeimpl: invalid tosctl Gift custody transaction bound")
	}
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.Timeout < time.Second || config.Timeout > 2*time.Minute {
		return nil, errors.New("nativeimpl: invalid tosctl Gift custody timeout")
	}
	runner, err := newPinnedReleaseRunnerWithVault(config.BinaryPath, config.ConfigPath, config.VaultURL)
	if err != nil {
		return nil, err
	}
	return &TOSCTLGiftCustody{config: config, chain: chain, runner: runner}, nil
}

func (c *TOSCTLGiftCustody) SenderAccount(ctx context.Context) (string, error) {
	call, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()
	workchain := int32(-1)
	if c.config.AgentAccountWorkchain != nil {
		workchain = *c.config.AgentAccountWorkchain
	}
	if workchain != -1 && workchain != 0 {
		return "", errors.New("nativeimpl: unsupported Agent Account workchain")
	}
	raw, err := c.runner.run(call, c.config.BinaryPath, "agent", "--config", c.config.ConfigPath, "account", "status", "--wallet", c.config.WalletName, "--workchain", strconv.FormatInt(int64(workchain), 10), "--format", "json")
	if err != nil {
		return "", errors.New("nativeimpl: tosctl could not resolve the Agent Account")
	}
	var value agentAccountStatus
	if decodeStrictJSON(raw, &value) != nil || value.Wallet != c.config.WalletName || value.Address == "" || value.State != "active" || value.CodeHash != strings.TrimPrefix(protocolgift.AgentAccountCodeHash, "tvm-cell-sha256:") || value.TemplateMatches == nil || !*value.TemplateMatches || value.MatchesProfile == nil || !*value.MatchesProfile || value.Owner != c.config.OwnerWallet || value.DeploymentID == "" || value.ControllerEpoch == nil || value.Seqno == nil {
		return "", errors.New("nativeimpl: invalid tosctl Agent Account status")
	}
	return value.Address, nil
}

type agentAccountStatus struct {
	Wallet                 string  `json:"wallet"`
	Address                string  `json:"address"`
	State                  string  `json:"state"`
	Balance                string  `json:"balance"`
	CodeHash               string  `json:"code_hash"`
	TemplateMatches        *bool   `json:"template_matches"`
	Owner                  string  `json:"owner"`
	ControllerPublicKey    string  `json:"controller_pubkey"`
	DeploymentID           string  `json:"deployment_id"`
	ControllerEpoch        *uint64 `json:"controller_epoch"`
	Seqno                  *uint32 `json:"seqno"`
	MaxPerTx               *uint64 `json:"max_per_tx"`
	DailyLimit             *uint64 `json:"daily_limit"`
	SpendDay               *uint32 `json:"spend_day"`
	SpentToday             *uint64 `json:"spent_today"`
	DefaultTaskTimeoutSecs *uint64 `json:"default_task_timeout_secs"`
	MetadataHash           *string `json:"metadata_hash"`
	ServiceEndpointHash    *string `json:"service_endpoint_hash"`
	MatchesProfile         *bool   `json:"matches_profile"`
}

func (c *TOSCTLGiftCustody) PrepareNativeGift(ctx context.Context, request openfoxgift.SignRequest) (openfoxgift.CustodyReview, error) {
	addressRequest, response, err := decodeBoundExchange(request.CanonicalRequest, request.CanonicalResponse)
	if err != nil || addressRequest.GiftIntentID != request.IntentID {
		return openfoxgift.CustodyReview{}, errors.New("nativeimpl: custody exchange identity mismatch")
	}
	account, chainTime, err := c.chain.FinalizedAgentAccount(ctx, addressRequest.SenderAgentAccount)
	if err != nil {
		return openfoxgift.CustodyReview{}, err
	}
	validUntil := addressRequest.RequestedValidUntil
	if response.ResponseNotAfter < validUntil {
		validUntil = response.ResponseNotAfter
	}
	if validUntil <= chainTime || validUntil-chainTime < c.config.MinimumInclusionMargin || account.Seqno == ^uint32(0) || account.DefaultTaskTimeoutSecs == 0 || account.DefaultTaskTimeoutSecs < uint64(validUntil-chainTime) {
		return openfoxgift.CustodyReview{}, errors.New("nativeimpl: Gift validity is too short at finalized chain time")
	}
	requestDigest, _ := protocolgift.RequestDigest(addressRequest)
	responseDigest, _ := protocolgift.ResponseDigest(response)
	unsigned := protocolgift.UnsignedTransferV1{Network: addressRequest.Network, GlobalID: addressRequest.GlobalID, SenderAgentAccount: addressRequest.SenderAgentAccount, DeploymentID: account.DeploymentID, ControllerEpoch: account.ControllerEpoch, Seqno: account.Seqno, ValidUntil: validUntil, DestinationAddress: response.DestinationAddress, AmountAtomic: addressRequest.AmountAtomic, SendMode: protocolgift.AgentNativeSendMode, Bounce: false}
	unsignedDigest, err := protocolgift.UnsignedTransferDigest(unsigned)
	if err != nil {
		return openfoxgift.CustodyReview{}, err
	}
	if account.OwnerAddress != c.config.OwnerWallet {
		return openfoxgift.CustodyReview{}, errors.New("nativeimpl: finalized Agent Account owner mismatch")
	}
	return openfoxgift.CustodyReview{Network: addressRequest.Network, GlobalID: addressRequest.GlobalID, RecipientAgentID: addressRequest.RecipientAgentID, SenderAgentAccount: addressRequest.SenderAgentAccount, OwnerWallet: c.config.OwnerWallet, ControllerKeyID: c.config.ControllerKeyID, DeploymentID: account.DeploymentID, DestinationAddress: response.DestinationAddress, AmountAtomic: addressRequest.AmountAtomic, FeeReserveAtomic: strconv.FormatUint(c.config.FeeReserveAtomic, 10), RequestDigest: requestDigest, ResponseDigest: responseDigest, UnsignedTransferDigest: unsignedDigest, ControllerEpoch: account.ControllerEpoch, Seqno: account.Seqno, ValidUntil: validUntil}, nil
}

func (c *TOSCTLGiftCustody) SignNativeGift(ctx context.Context, request openfoxgift.SignRequest) ([]byte, error) {
	review, err := c.PrepareNativeGift(ctx, request)
	if err != nil {
		return nil, err
	}
	if request.UnsignedTransferDigest != review.UnsignedTransferDigest {
		return nil, errors.New("nativeimpl: changed unsigned transfer after owner review")
	}
	authorization := protocolgift.OwnerAuthorizationV1{Network: review.Network, GlobalID: review.GlobalID, GiftIntentID: request.IntentID, RecipientAgentID: review.RecipientAgentID, SenderAgentAccount: review.SenderAgentAccount, OwnerWallet: review.OwnerWallet, ControllerKeyID: review.ControllerKeyID, DeploymentID: review.DeploymentID, ControllerEpoch: review.ControllerEpoch, DestinationAddress: review.DestinationAddress, AmountAtomic: review.AmountAtomic, Seqno: review.Seqno, ValidUntil: review.ValidUntil, FeeReserveAtomic: review.FeeReserveAtomic, AddressRequestDigest: review.RequestDigest, AddressResponseDigest: review.ResponseDigest}
	wantAuthorization, err := protocolgift.OwnerAuthorizationDigest(authorization)
	if err != nil || request.OwnerAuthorizationDigest != wantAuthorization {
		return nil, errors.New("nativeimpl: owner authorization does not bind the prepared Gift")
	}
	raw, err := c.run(ctx, "native-prepare", "--wallet", c.config.WalletName, "--target", review.DestinationAddress, "--amount-nanotos", review.AmountAtomic, "--fee-reserve-nanotos", review.FeeReserveAtomic, "--valid-until", strconv.FormatUint(uint64(review.ValidUntil), 10), "--action-id", request.IntentID, "--request-digest", review.RequestDigest, "--response-digest", review.ResponseDigest, "--owner-authorization-digest", request.OwnerAuthorizationDigest, "--unsigned-transfer-digest", review.UnsignedTransferDigest, "--yes")
	if err != nil {
		return nil, err
	}
	return decodePreparedAction(raw, request.IntentID, "agent-native-send", review.SenderAgentAccount, review.DeploymentID, review.ControllerEpoch, review.Seqno, review.GlobalID, review.ValidUntil)
}

func (c *TOSCTLGiftCustody) ResolveNativeGift(ctx context.Context, request openfoxgift.ResolveRequest) error {
	amount, err := strconv.ParseUint(request.AmountAtomic, 10, 64)
	if err != nil || request.IntentID == "" || request.SenderAgentAccount == "" ||
		request.DestinationAddress == "" || amount == 0 || request.ExactBOCDigest == "" {
		return errors.New("nativeimpl: incomplete finalized Gift custody resolution")
	}
	arguments := []string{"--wallet", c.config.WalletName, "--action-id", request.IntentID, "--quorum-config"}
	arguments = append(arguments, c.config.QuorumConfigPaths...)
	arguments = append(arguments, "--max-transactions", strconv.FormatUint(uint64(c.config.MaxTransactions), 10))
	raw, err := c.run(ctx, "native-resolve", arguments...)
	if err != nil {
		return err
	}
	var result struct {
		Schema               string          `json:"schema"`
		Wallet               string          `json:"wallet"`
		ActionID             string          `json:"action_id"`
		SourceAccount        string          `json:"source_account"`
		Destination          string          `json:"destination"`
		AmountNanoTOS        uint64          `json:"amount_nanotos"`
		ExactSignedBOCDigest string          `json:"exact_signed_boc_digest"`
		NetworkDomain        json.RawMessage `json:"network_domain"`
		Quorum               json.RawMessage `json:"quorum"`
		Transaction          json.RawMessage `json:"transaction"`
		State                string          `json:"state"`
	}
	if decodeStrictJSON(raw, &result) != nil || result.Schema != "tos.agent-account.native-action-finalized.v1" ||
		result.Wallet != c.config.WalletName || result.ActionID != request.IntentID ||
		result.SourceAccount != request.SenderAgentAccount || result.Destination != request.DestinationAddress ||
		result.AmountNanoTOS != amount || result.ExactSignedBOCDigest != request.ExactBOCDigest ||
		len(result.NetworkDomain) == 0 || len(result.Quorum) == 0 || len(result.Transaction) == 0 || result.State != "finalized" {
		return errors.New("nativeimpl: tosctl returned a conflicting Gift custody resolution")
	}
	return nil
}

func (c *TOSCTLGiftCustody) CancelSeqno(ctx context.Context, request openfoxgift.CancelRequest) ([]byte, error) {
	if request.IntentID == "" || request.OwnerAuthorizationDigest == "" || request.SenderAgentAccount == "" || request.GlobalID == 0 || request.Seqno == ^uint32(0) || request.ValidUntil == 0 {
		return nil, errors.New("nativeimpl: incomplete Gift cancellation")
	}
	raw, err := c.run(ctx, "cancel-prepare", "--wallet", c.config.WalletName, "--action-id", request.IntentID, "--owner-authorization-digest", request.OwnerAuthorizationDigest, "--valid-until", strconv.FormatUint(uint64(request.ValidUntil), 10), "--yes")
	if err != nil {
		return nil, err
	}
	account, chainTime, err := c.chain.FinalizedAgentAccount(ctx, request.SenderAgentAccount)
	if err != nil {
		return nil, err
	}
	boc, err := decodePreparedAction(raw, request.IntentID, "agent-cancel-seqno", request.SenderAgentAccount, account.DeploymentID, account.ControllerEpoch, request.Seqno, request.GlobalID, request.ValidUntil)
	if err != nil {
		return nil, err
	}
	if _, err := protocolgift.VerifyAgentCancelSeqno(protocolgift.VerifyCancelSeqnoInput{ExactSignedBOC: boc, Account: account, ExpectedGlobalID: request.GlobalID, ExpectedSeqno: request.Seqno, ExpectedValidUntil: request.ValidUntil, FinalizedChainTime: chainTime}); err != nil {
		return nil, errors.New("nativeimpl: custody cancellation failed independent verification")
	}
	return boc, nil
}

func (c *TOSCTLGiftCustody) run(ctx context.Context, action string, arguments ...string) ([]byte, error) {
	call, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()
	args := []string{"agent", "--config", c.config.ConfigPath, "account", action}
	args = append(args, arguments...)
	raw, err := c.runner.run(call, c.config.BinaryPath, args...)
	if err != nil {
		return nil, errors.New("nativeimpl: tosctl Gift custody action failed")
	}
	return raw, nil
}

type PreparedBOCSubmitter interface {
	BroadcastPreparedContractCell(context.Context, string, string) error
}

type AgentGiftMessengerCaller interface {
	Call(context.Context, localapi.Request) (localapi.Response, error)
}

type AgentGiftMessenger struct {
	client AgentGiftMessengerCaller
	ttl    time.Duration
	now    func() time.Time
}

type AgentGiftInbound struct {
	EventID, SenderAgentID, Kind string
	Canonical                    []byte
}

// DecodeClaimedAgentGift unwraps only a daemon-admitted local API event. The
// caller must pass the PendingEvent returned by an authenticated runtime claim;
// raw Relay envelopes are not accepted at this boundary.
func DecodeClaimedAgentGift(claim localapi.PendingEvent) (AgentGiftInbound, error) {
	if claim.EventID == "" || len(claim.Event) == 0 {
		return AgentGiftInbound{}, errors.New("nativeimpl: incomplete claimed Messenger Event")
	}
	event, err := envelope.DecodeEventJSON(claim.Event)
	if err != nil || event.EventID != claim.EventID || event.RoomID != "" || !envelope.RequiresEstablishedDirect(event.Kind) {
		return AgentGiftInbound{}, errors.New("nativeimpl: claimed Event is not an established-direct Gift")
	}
	decoded, err := payload.Decode(event.Kind, event.Content)
	if err != nil {
		return AgentGiftInbound{}, err
	}
	var canonical []byte
	switch value := decoded.(type) {
	case payload.GiftAddressRequest:
		canonical = value.CanonicalRequest
	case payload.GiftAddressResponse:
		canonical = value.CanonicalResponse
	case payload.GiftSignedBOCOffer:
		canonical = value.CanonicalOffer
	default:
		return AgentGiftInbound{}, errors.New("nativeimpl: claimed Event is not an Agent Gift payload")
	}
	return AgentGiftInbound{EventID: event.EventID, SenderAgentID: event.SenderAgentID, Kind: event.Kind, Canonical: append([]byte(nil), canonical...)}, nil
}

func NewAgentGiftMessenger(client AgentGiftMessengerCaller, eventTTL time.Duration) (*AgentGiftMessenger, error) {
	if client == nil || eventTTL < time.Minute || eventTTL > 30*24*time.Hour {
		return nil, errors.New("nativeimpl: invalid Agent Gift Messenger configuration")
	}
	return &AgentGiftMessenger{client: client, ttl: eventTTL, now: time.Now}, nil
}

func (m *AgentGiftMessenger) SendEstablishedDirect(ctx context.Context, recipient, kind string, canonical []byte, semanticKey string) (string, error) {
	if m == nil || m.client == nil || ctx == nil || len(recipient) != 70 || recipient[:6] != "agent_" || len(canonical) == 0 || len(canonical) > payload.MaxGiftCanonicalBytes || semanticKey == "" {
		return "", errors.New("nativeimpl: invalid established-direct Gift send")
	}
	if _, err := hex.DecodeString(recipient[6:]); err != nil {
		return "", errors.New("nativeimpl: invalid Gift recipient AgentID")
	}
	idempotency := sha256.New()
	idempotency.Write([]byte("tos.openfox.agent-gift.messenger-send.v1\x00"))
	for _, value := range [][]byte{[]byte(recipient), []byte(kind), []byte(semanticKey), canonical} {
		idempotency.Write([]byte{byte(len(value) >> 24), byte(len(value) >> 16), byte(len(value) >> 8), byte(len(value))})
		idempotency.Write(value)
	}
	response, err := m.client.Call(ctx, localapi.Request{Op: localapi.OpSendDirectApplication,
		Recipient: recipient, ApplicationKind: kind, ApplicationBody: append([]byte(nil), canonical...),
		IdempotencyKey: "idem_" + hex.EncodeToString(idempotency.Sum(nil)),
		ExpiresAtUnix:  uint64(m.now().UTC().Add(m.ttl).Unix())})
	if err != nil {
		return "", err
	}
	if response.AgentID != recipient || response.EventID == "" || response.Readiness != "queued" {
		return "", errors.New("nativeimpl: Messenger returned a conflicting Gift send result")
	}
	return response.EventID, nil
}

type AgentGiftBroadcaster struct{ submitter PreparedBOCSubmitter }

func NewAgentGiftBroadcaster(submitter PreparedBOCSubmitter) (*AgentGiftBroadcaster, error) {
	if submitter == nil {
		return nil, errors.New("nativeimpl: Gift BOC submitter is required")
	}
	return &AgentGiftBroadcaster{submitter: submitter}, nil
}

func (b *AgentGiftBroadcaster) BroadcastExactBOC(ctx context.Context, boc []byte) error {
	if len(boc) == 0 || len(boc) > protocolgift.MaxSignedBOCBytes {
		return errors.New("nativeimpl: invalid exact Gift BOC")
	}
	digest := sha256.Sum256(boc)
	return b.submitter.BroadcastPreparedContractCell(ctx, base64.StdEncoding.EncodeToString(boc), "sha256:"+hex.EncodeToString(digest[:]))
}

type AgentGiftOwnerConfirmer interface {
	ConfirmAgentGift(context.Context, openfoxgift.OwnerReview) error
}

type AgentGiftOwnerAuthorizer struct {
	confirmer AgentGiftOwnerConfirmer
	mu        sync.Mutex
}

func NewAgentGiftOwnerAuthorizer(confirmer AgentGiftOwnerConfirmer) (*AgentGiftOwnerAuthorizer, error) {
	if confirmer == nil {
		return nil, errors.New("nativeimpl: explicit Agent Gift owner confirmer is required")
	}
	return &AgentGiftOwnerAuthorizer{confirmer: confirmer}, nil
}

func (a *AgentGiftOwnerAuthorizer) Authorize(ctx context.Context, review openfoxgift.OwnerReview) (string, error) {
	if a == nil || a.confirmer == nil || ctx == nil || review.FundsLocked {
		return "", errors.New("nativeimpl: invalid Agent Gift owner review")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.confirmer.ConfirmAgentGift(ctx, review); err != nil {
		return "", err
	}
	switch review.Action {
	case "send":
		return protocolgift.OwnerAuthorizationDigest(protocolgift.OwnerAuthorizationV1{
			Network: review.Network, GlobalID: review.GlobalID, GiftIntentID: review.IntentID,
			RecipientAgentID: review.RecipientAgentID, SenderAgentAccount: review.SenderAgentAccount,
			OwnerWallet: review.OwnerWallet, ControllerKeyID: review.ControllerKeyID,
			DeploymentID: review.DeploymentID, ControllerEpoch: review.ControllerEpoch,
			DestinationAddress: review.DestinationAddress, AmountAtomic: review.AmountAtomic,
			Seqno: review.Seqno, ValidUntil: review.ValidUntil, FeeReserveAtomic: review.FeeReserveAtomic,
			AddressRequestDigest: review.RequestDigest, AddressResponseDigest: review.ResponseDigest,
		})
	case "cancel":
		return protocolgift.OwnerCancellationAuthorizationDigest(protocolgift.OwnerCancellationAuthorizationV1{
			Network: review.Network, GlobalID: review.GlobalID, GiftIntentID: review.IntentID,
			SignedGiftID: review.SignedGiftID, RecipientAgentID: review.RecipientAgentID,
			SenderAgentAccount: review.SenderAgentAccount, DestinationAddress: review.DestinationAddress,
			DeploymentID: review.DeploymentID, ControllerEpoch: review.ControllerEpoch,
			AmountAtomic: review.AmountAtomic, Seqno: review.Seqno, ValidUntil: review.ValidUntil,
			AddressRequestDigest: review.RequestDigest, AddressResponseDigest: review.ResponseDigest,
		})
	default:
		return "", errors.New("nativeimpl: unknown Agent Gift owner action")
	}
}

func decodeBoundExchange(requestRaw, responseRaw []byte) (protocolgift.GiftAddressRequestV1, protocolgift.GiftAddressResponseV1, error) {
	request, err := protocolgift.DecodeAddressRequest(requestRaw)
	if err != nil {
		return request, protocolgift.GiftAddressResponseV1{}, err
	}
	response, err := protocolgift.DecodeAddressResponse(responseRaw)
	if err == nil {
		err = protocolgift.BindResponse(request, response)
	}
	return request, response, err
}

type preparedAction struct {
	Schema               string `json:"schema"`
	ActionID             string `json:"action_id"`
	Action               string `json:"action"`
	Account              string `json:"account"`
	DeploymentID         string `json:"deployment_id"`
	ControllerEpoch      uint64 `json:"controller_epoch"`
	Seqno                uint32 `json:"seqno"`
	NetworkGlobalID      int32  `json:"network_global_id"`
	ValidUntil           uint32 `json:"valid_until"`
	ExactSignedBOC       string `json:"exact_signed_boc"`
	ExactSignedBOCDigest string `json:"exact_signed_boc_digest"`
}

func decodePreparedAction(raw []byte, actionID, action, account, deploymentID string, controllerEpoch uint64, seqno uint32, globalID int32, validUntil uint32) ([]byte, error) {
	var value preparedAction
	if decodeStrictJSON(raw, &value) != nil || value.Account != account || value.DeploymentID != deploymentID || value.ControllerEpoch != controllerEpoch || value.Seqno != seqno || value.NetworkGlobalID != globalID || value.ValidUntil != validUntil {
		return nil, errors.New("nativeimpl: tosctl prepared action conflicts with owner review")
	}
	return validatePreparedAction(value, actionID, action)
}

func validatePreparedAction(value preparedAction, actionID, action string) ([]byte, error) {
	if value.Schema != "tosctl.agent-account.prepared-action.v1" || value.ActionID != actionID || value.Action != action || value.Account == "" || value.DeploymentID == "" || value.ValidUntil == 0 {
		return nil, errors.New("nativeimpl: invalid tosctl prepared action identity")
	}
	boc, err := base64.StdEncoding.DecodeString(value.ExactSignedBOC)
	if err != nil || len(boc) == 0 || len(boc) > protocolgift.MaxSignedBOCBytes || base64.StdEncoding.EncodeToString(boc) != value.ExactSignedBOC {
		return nil, errors.New("nativeimpl: invalid exact signed BOC from tosctl")
	}
	digest := sha256.Sum256(boc)
	if value.ExactSignedBOCDigest != "sha256:"+hex.EncodeToString(digest[:]) {
		return nil, errors.New("nativeimpl: tosctl exact BOC digest mismatch")
	}
	return boc, nil
}

var (
	_ openfoxgift.Protocol        = (*AgentGiftProtocol)(nil)
	_ openfoxgift.Resolver        = (*AgentGiftResolver)(nil)
	_ openfoxgift.Custody         = (*TOSCTLGiftCustody)(nil)
	_ openfoxgift.Broadcaster     = (*AgentGiftBroadcaster)(nil)
	_ openfoxgift.Messenger       = (*AgentGiftMessenger)(nil)
	_ openfoxgift.OwnerAuthorizer = (*AgentGiftOwnerAuthorizer)(nil)
)
