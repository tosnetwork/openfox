package nativeimpl

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/buyersdk"
	"github.com/tosnetwork/tos-service-protocol/pkg/quoteexchange"
	"google.golang.org/protobuf/proto"

	"github.com/tosnetwork/openfox/pkg/fileutil"
	"github.com/tosnetwork/openfox/pkg/messengerauth"
	"github.com/tosnetwork/openfox/pkg/opportunity"
	"github.com/tosnetwork/openfox/pkg/servicebridge"
)

type QuoteGateway interface {
	RequestQuoteProposal(context.Context, *nativev1.RequestQuoteProposalRequest) (*nativev1.RequestQuoteProposalResponse, error)
}

type NamedQuoteGateway struct {
	ID     string
	Client QuoteGateway
}

type DispatchPlan struct {
	Transport servicebridge.Transport
	Sender    servicebridge.TaskTransport
	BuildTask servicebridge.TaskBuilder
	Close     func() error
}

type DispatchPlanner interface {
	Plan(context.Context, *buyersdk.PreparedPurchase) (DispatchPlan, error)
}

type ChainOpportunityPurchaseBackendConfig struct {
	StateDir        string
	Stack           *ChainBuyerStack
	Network         *nativev1.NetworkDomain
	Gateways        []NamedQuoteGateway
	Policy          servicebridge.SpendingPolicy
	OwnerPublicKey  ed25519.PublicKey
	BuyerAddress    string
	Messenger       *messengerauth.Client
	MandateID       string
	CapabilityClass string
	ExecutionSigner ed25519.PublicKey
	Planner         DispatchPlanner
	QuoteTimeout    time.Duration
	Now             func() time.Time
}

type ChainOpportunityPurchaseBackend struct {
	stateDir, mandateID, capabilityClass, buyerAddress string
	stack                                              *ChainBuyerStack
	network                                            *nativev1.NetworkDomain
	gateways                                           []NamedQuoteGateway
	policy                                             servicebridge.SpendingPolicy
	owner                                              ed25519.PublicKey
	messenger                                          *messengerauth.Client
	executionSigner                                    ed25519.PublicKey
	planner                                            DispatchPlanner
	quoteTimeout                                       time.Duration
	now                                                func() time.Time
}

func NewChainOpportunityPurchaseBackend(config ChainOpportunityPurchaseBackendConfig) (*ChainOpportunityPurchaseBackend, error) {
	if !ownerDirectory(config.StateDir) || config.Stack == nil || config.Stack.SDK == nil || config.Stack.Journal == nil ||
		config.Stack.Deployer == nil || config.Network == nil || len(config.Gateways) < 2 || len(config.Gateways) > 8 ||
		config.Messenger == nil || config.MandateID == "" || strings.TrimSpace(config.MandateID) != config.MandateID || len(config.MandateID) > 256 ||
		config.CapabilityClass == "" || len(config.CapabilityClass) > 128 ||
		!isRawWorkchainZero(config.BuyerAddress) || len(config.ExecutionSigner) != ed25519.PublicKeySize || config.Planner == nil {
		return nil, errors.New("nativeimpl: chain opportunity purchase backend is incomplete")
	}
	if err := servicebridge.VerifySpendingPolicySignature(config.Policy, config.OwnerPublicKey); err != nil {
		return nil, err
	}
	stackNetwork := servicebridge.Network{ID: config.Network.GetNetworkId(),
		GenesisRootHash: strings.TrimPrefix(config.Network.GetGenesisRootHash(), "sha256:"),
		GenesisFileHash: strings.TrimPrefix(config.Network.GetGenesisFileHash(), "sha256:")}
	if stackNetwork != config.Stack.Network || config.Policy.Asset.Network != config.Stack.Network ||
		config.BuyerAddress != config.Stack.BuyerAddress || config.Stack.BuyerAgentID == "" {
		return nil, errors.New("nativeimpl: policy, buyer stack, and opportunity network authority differ")
	}
	if config.Policy.ConfirmationMode != servicebridge.ConfirmAuto {
		return nil, errors.New("nativeimpl: autonomous purchase requires an exact owner-signed auto policy")
	}
	if config.QuoteTimeout == 0 {
		config.QuoteTimeout = 15 * time.Second
	}
	if config.QuoteTimeout < time.Second || config.QuoteTimeout > time.Minute {
		return nil, errors.New("nativeimpl: invalid opportunity Quote timeout")
	}
	previous := ""
	ownedGateways := append([]NamedQuoteGateway(nil), config.Gateways...)
	for _, gateway := range ownedGateways {
		if gateway.ID == "" || gateway.ID <= previous || gateway.Client == nil {
			return nil, errors.New("nativeimpl: Quote Gateways must be sorted, unique, and configured")
		}
		previous = gateway.ID
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	policy := config.Policy
	policy.OwnerSignature = append([]byte(nil), config.Policy.OwnerSignature...)
	policy.CapabilityAllow = make(map[string]bool, len(config.Policy.CapabilityAllow))
	for capability, allowed := range config.Policy.CapabilityAllow {
		policy.CapabilityAllow[capability] = allowed
	}
	return &ChainOpportunityPurchaseBackend{stateDir: config.StateDir, stack: config.Stack,
		network: proto.Clone(config.Network).(*nativev1.NetworkDomain), gateways: ownedGateways, policy: policy,
		owner: append(ed25519.PublicKey(nil), config.OwnerPublicKey...), messenger: config.Messenger,
		mandateID: config.MandateID, capabilityClass: config.CapabilityClass,
		buyerAddress:    config.BuyerAddress,
		executionSigner: append(ed25519.PublicKey(nil), config.ExecutionSigner...), planner: config.Planner,
		quoteTimeout: config.QuoteTimeout, now: config.Now}, nil
}

func (b *ChainOpportunityPurchaseBackend) Prepare(ctx context.Context, intent string, candidate opportunity.VerifiedCandidate) (PreparedOpportunityQuote, error) {
	if b == nil || ctx == nil || !safeIntent(intent) {
		return PreparedOpportunityQuote{}, errors.New("nativeimpl: invalid autonomous Quote request")
	}
	expectedNetwork := opportunity.Network{ID: b.stack.Network.ID, GenesisRootHash: b.stack.Network.GenesisRootHash,
		GenesisFileHash: b.stack.Network.GenesisFileHash}
	if candidate.Key.Network != expectedNetwork || candidate.FinalizedCheckpoint == 0 || candidate.Operation == "" {
		return PreparedOpportunityQuote{}, errors.Join(ErrPurchasePolicyRejected,
			errors.New("candidate differs from the configured buyer network authority"))
	}
	if existing, err := b.loadPurchase(intent, ""); err == nil {
		return b.projectPrepared(existing, candidate.Key, intent)
	} else if !errors.Is(err, os.ErrNotExist) {
		return PreparedOpportunityQuote{}, err
	}
	requestID, err := purchaseRequestID()
	if err != nil {
		return PreparedOpportunityQuote{}, err
	}
	request := &nativev1.RequestQuoteProposalRequest{Context: &nativev1.RequestContext{RequestId: requestID,
		CallerId: b.stack.BuyerAgentID, DeadlineUnixMillis: b.now().Add(b.quoteTimeout).UnixMilli()},
		CapabilityId: candidate.Key.CapabilityID, CapabilityVersion: candidate.Key.Version,
		BuyerAddress: b.buyerAddress}

	var input buyersdk.PurchaseInput
	var failures []error
	for _, gateway := range b.gateways {
		call, cancel := context.WithTimeout(ctx, b.quoteTimeout)
		response, requestErr := gateway.Client.RequestQuoteProposal(call, proto.Clone(request).(*nativev1.RequestQuoteProposalRequest))
		cancel()
		if requestErr != nil || response == nil || response.Package == nil {
			if requestErr == nil {
				requestErr = errors.New("empty Quote package")
			}
			failures = append(failures, fmt.Errorf("%s: %w", gateway.ID, requestErr))
			continue
		}
		validated, validateErr := quoteexchange.Validate(b.network, request, response.Package, b.now())
		proposal := response.Package.GetProposal()
		if validateErr != nil || proposal.GetProviderAgentId() != candidate.Key.ProviderAgentID ||
			proposal.GetManifestDigest() != candidate.Key.ManifestDigest || proposal.GetCapabilityId() != candidate.Key.CapabilityID ||
			proposal.GetCapabilityVersion() != candidate.Key.Version {
			failures = append(failures, fmt.Errorf("%s: Quote package conflicts with finalized candidate", gateway.ID))
			continue
		}
		input = buyersdk.PurchaseInput{Proposal: proto.Clone(proposal).(*nativev1.QuoteProposalV1),
			ManifestCBOR: append([]byte(nil), response.Package.CanonicalManifestCbor...), EscrowTerms: validated.EscrowTerms,
			ExecutionSignerEd25519: append([]byte(nil), b.executionSigner...), TransportBinding: validated.TransportBinding}
		break
	}
	if input.Proposal == nil {
		return PreparedOpportunityQuote{}, errors.Join(append([]error{errors.New("nativeimpl: every Gateway Quote failed closed")}, failures...)...)
	}
	purchase, err := b.stack.SDK.PreparePurchase(ctx, input)
	if err != nil {
		return PreparedOpportunityQuote{}, err
	}
	encoded, err := MarshalPreparedPurchase(purchase)
	if err != nil {
		return PreparedOpportunityQuote{}, err
	}
	path := b.purchasePath(intent)
	if err := writePrivateExact(path, encoded); err != nil {
		return PreparedOpportunityQuote{}, err
	}
	return b.projectPrepared(purchase, candidate.Key, intent)
}

func (b *ChainOpportunityPurchaseBackend) Authorize(ctx context.Context, intent string, prepared PreparedOpportunityQuote) error {
	purchase, err := b.loadPurchase(intent, prepared.ArtifactDigest)
	if err != nil {
		return err
	}
	input, err := PurchaseInputFromPreparedPurchase(purchase)
	if err != nil {
		return err
	}
	session, err := NewBuyerSession(b.stack.SDK, input)
	if err != nil {
		return err
	}
	proposal, err := session.RequestQuote(ctx, b.capabilityRef(purchase))
	if err != nil {
		return err
	}
	spent := b.stack.Journal.SpentInWindow(b.now(), b.policy.Window)
	if err := (servicebridge.PolicyEngine{}).Authorize(b.policy, proposal, spent, b.now()); err != nil {
		return errors.Join(ErrPurchasePolicyRejected, err)
	}
	return nil
}

func (b *ChainOpportunityPurchaseBackend) Reference(ctx context.Context, intent string, prepared PreparedOpportunityQuote) (opportunity.PurchaseKey, string, error) {
	purchase, err := b.loadPurchase(intent, prepared.ArtifactDigest)
	if err != nil {
		return opportunity.PurchaseKey{}, "", err
	}
	amount, err := atomicUint64(purchase.AmountAtomic)
	if err != nil {
		return opportunity.PurchaseKey{}, "", errors.Join(ErrPurchasePolicyRejected, err)
	}
	key := servicebridge.PurchaseKey{QuoteCommitment: purchase.QuoteCommitment, EscrowAddress: purchase.Escrow.Address}
	if _, err := b.stack.Journal.Begin(servicebridge.PurchaseRecord{Key: key, AssetMaster: purchase.AssetMasterAddress,
		AtomicAmount: amount}, b.now()); err != nil {
		return opportunity.PurchaseKey{}, "", err
	}
	if _, err := os.Lstat(b.deploymentPath(intent)); errors.Is(err, os.ErrNotExist) {
		deployment, prepareErr := b.stack.Deployer.PrepareEscrowDeployment(ctx, purchase)
		if prepareErr != nil {
			return opportunity.PurchaseKey{}, "", prepareErr
		}
		encoded, marshalErr := MarshalPreparedEscrowDeployment(deployment)
		if marshalErr != nil {
			return opportunity.PurchaseKey{}, "", marshalErr
		}
		if writeErr := writePrivateExact(b.deploymentPath(intent), encoded); writeErr != nil {
			return opportunity.PurchaseKey{}, "", writeErr
		}
	} else if err != nil {
		return opportunity.PurchaseKey{}, "", err
	} else {
		raw, readErr := readPrivateBytes(b.deploymentPath(intent), 4<<20)
		deployment, decodeErr := UnmarshalPreparedEscrowDeployment(raw)
		if readErr != nil || decodeErr != nil || deployment.EscrowAddress != purchase.Escrow.Address ||
			deployment.QuoteCommitment != purchase.QuoteCommitment {
			return opportunity.PurchaseKey{}, "", errors.New("nativeimpl: prepared deployment conflicts with purchase")
		}
	}
	return opportunity.PurchaseKey{QuoteCommitment: key.QuoteCommitment, EscrowAddress: key.EscrowAddress}, string(servicebridge.PhasePrepared), nil
}

func (b *ChainOpportunityPurchaseBackend) Reconcile(ctx context.Context, intent string, prepared PreparedOpportunityQuote, key opportunity.PurchaseKey) (PurchaseSettlement, error) {
	purchase, err := b.loadPurchase(intent, prepared.ArtifactDigest)
	if err != nil || purchase.QuoteCommitment != key.QuoteCommitment || purchase.Escrow.Address != key.EscrowAddress {
		return PurchaseSettlement{}, errors.New("nativeimpl: purchase artifact conflicts with immutable PurchaseKey")
	}
	resolved, found, err := b.stack.Escrow.ResolveFinalizedExact(ctx, purchase.Escrow.Address)
	if err != nil {
		return PurchaseSettlement{}, err
	}
	if !found {
		if _, leaseErr := os.Lstat(b.deploymentLeasePath(intent)); leaseErr == nil {
			return PurchaseSettlement{}, errors.New("nativeimpl: escrow deployment outcome is ambiguous; awaiting finalized state")
		} else if !errors.Is(leaseErr, os.ErrNotExist) {
			return PurchaseSettlement{}, leaseErr
		}
		if err := createPrivateLease(b.deploymentLeasePath(intent)); err != nil {
			return PurchaseSettlement{}, err
		}
		raw, err := readPrivateBytes(b.deploymentPath(intent), 4<<20)
		if err != nil {
			return PurchaseSettlement{}, err
		}
		deployment, err := UnmarshalPreparedEscrowDeployment(raw)
		if err != nil {
			return PurchaseSettlement{}, err
		}
		if err := b.stack.Deployer.BroadcastEscrowDeployment(ctx, deployment); err != nil {
			return PurchaseSettlement{}, err
		}
		return PurchaseSettlement{AuthoritativePhase: string(servicebridge.PhasePrepared)}, nil
	}
	if resolved == nil || resolved.State == nil || resolved.State.QuoteCommitment != purchase.QuoteCommitment {
		return PurchaseSettlement{}, errors.New("nativeimpl: finalized escrow conflicts with prepared purchase")
	}
	input, err := PurchaseInputFromPreparedPurchase(purchase)
	if err != nil {
		return PurchaseSettlement{}, err
	}
	plan, err := b.planner.Plan(ctx, purchase)
	if err != nil {
		return PurchaseSettlement{}, err
	}
	if plan.Close != nil {
		defer plan.Close()
	}
	buyer, err := NewChainNativeBuyer(ChainNativeBuyerConfig{Stack: b.stack, Input: input, Policy: b.policy,
		OwnerPublicKey: b.owner, Transport: plan.Sender, Authorizer: b.messenger, QuoteVerifier: b.messenger,
		MandateID: b.mandateID})
	if err != nil {
		return PurchaseSettlement{}, err
	}
	settlement, err := buyer.Purchase(ctx, b.capabilityRef(purchase), plan.Transport, plan.BuildTask)
	if err != nil {
		if record, ok := b.stack.Journal.Get(servicebridge.PurchaseKey{QuoteCommitment: key.QuoteCommitment, EscrowAddress: key.EscrowAddress}); ok {
			return PurchaseSettlement{AuthoritativePhase: string(record.Phase)}, err
		}
		return PurchaseSettlement{}, err
	}
	return PurchaseSettlement{AuthoritativePhase: string(servicebridge.PhaseResolved),
		FinalizedCheckpoint: settlement.Checkpoint, Released: settlement.Released, Refunded: settlement.Refunded}, nil
}

func (b *ChainOpportunityPurchaseBackend) capabilityRef(purchase *buyersdk.PreparedPurchase) servicebridge.CapabilityRef {
	return servicebridge.CapabilityRef{AgentID: purchase.Proposal.GetProviderAgentId(),
		CapabilityID: purchase.Proposal.GetCapabilityId(), Version: purchase.Proposal.GetCapabilityVersion(),
		ManifestDigest: purchase.Proposal.GetManifestDigest(), RegistryCodeHash: b.stack.RegistryCodeHash,
		Network: b.stack.Network, CapabilityClass: b.capabilityClass}
}

func (b *ChainOpportunityPurchaseBackend) projectPrepared(purchase *buyersdk.PreparedPurchase, candidate opportunity.CandidateKey, intent string) (PreparedOpportunityQuote, error) {
	if purchase == nil || purchase.Proposal == nil || purchase.Proposal.GetCapabilityId() != candidate.CapabilityID ||
		purchase.Proposal.GetCapabilityVersion() != candidate.Version || purchase.Proposal.GetProviderAgentId() != candidate.ProviderAgentID ||
		purchase.ManifestDigest != candidate.ManifestDigest {
		return PreparedOpportunityQuote{}, errors.New("nativeimpl: prepared purchase conflicts with finalized candidate")
	}
	raw, err := readPrivateBytes(b.purchasePath(intent), 4<<20)
	if err != nil {
		return PreparedOpportunityQuote{}, err
	}
	digest := sha256.Sum256(raw)
	return PreparedOpportunityQuote{Candidate: candidate, ArtifactDigest: "sha256:" + hex.EncodeToString(digest[:]),
		AssetMaster: purchase.AssetMasterAddress, AtomicAmount: purchase.AmountAtomic,
		QuoteExpiryUnix: int64(purchase.Proposal.GetExpiresAtUnixSeconds())}, nil
}

func (b *ChainOpportunityPurchaseBackend) loadPurchase(intent, expectedDigest string) (*buyersdk.PreparedPurchase, error) {
	raw, err := readPrivateBytes(b.purchasePath(intent), 4<<20)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(raw)
	if expectedDigest != "" && expectedDigest != "sha256:"+hex.EncodeToString(digest[:]) {
		return nil, errors.New("nativeimpl: prepared purchase artifact digest changed")
	}
	return UnmarshalPreparedPurchase(raw)
}

func (b *ChainOpportunityPurchaseBackend) purchasePath(intent string) string {
	return filepath.Join(b.stateDir, intent+".purchase.json")
}
func (b *ChainOpportunityPurchaseBackend) deploymentPath(intent string) string {
	return filepath.Join(b.stateDir, intent+".deployment.json")
}
func (b *ChainOpportunityPurchaseBackend) deploymentLeasePath(intent string) string {
	return filepath.Join(b.stateDir, intent+".deployment.lease")
}

func writePrivateExact(path string, raw []byte) error {
	if len(raw) == 0 || !ownerDirectory(filepath.Dir(path)) {
		return errors.New("nativeimpl: invalid private artifact output")
	}
	if existing, err := readPrivateBytes(path, 4<<20); err == nil {
		if string(existing) != string(raw) {
			return errors.New("nativeimpl: durable purchase artifact conflicts with retry")
		}
		return nil
	} else if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
		return err
	}
	return fileutil.WriteFileAtomic(path, raw, 0o600)
}

func createPrivateLease(path string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write([]byte("leased\n")); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func safeIntent(value string) bool {
	if len(value) != len("opp_")+64 || !strings.HasPrefix(value, "opp_") {
		return false
	}
	_, err := hex.DecodeString(value[len("opp_"):])
	return err == nil && value == strings.ToLower(value)
}

func purchaseRequestID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return "purchase-" + hex.EncodeToString(value[:]), nil
}

var _ OpportunityPurchaseBackend = (*ChainOpportunityPurchaseBackend)(nil)
