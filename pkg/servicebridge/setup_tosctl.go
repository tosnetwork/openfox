package servicebridge

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/address"
)

// Values the setup commands attach to chain messages, in nanoTOS.
const (
	// RegistryMessageValueNano funds one Native Registry message (an Agent
	// or Capability registration), as the reference provider sequence does.
	RegistryMessageValueNano uint64 = 2 * NanoPerTOS
	// MinimumDeployFundingNano is the least tosctl accepts for a Service
	// Actor deployment: the 1 TOS operating reserve plus a 0.2 TOS margin.
	MinimumDeployFundingNano uint64 = 1_200_000_000
	// PolicyMessageValueNano is what tosctl attaches to update-policy.
	PolicyMessageValueNano uint64 = 10_000_000
	// PayoutMessageValueNano is what tosctl attaches to withdraw-revenue so
	// the payout's fees do not reduce the payout.
	PayoutMessageValueNano uint64 = 200_000_000
	// AdmissionAllowanceNano is what a buyer attaches to a call on top of
	// the price and the storage fee.
	AdmissionAllowanceNano uint64 = 200_000_000
	// walletFeeMarginNano covers the wallet's own fees for a few messages.
	walletFeeMarginNano uint64 = 50_000_000
)

// Service Actor policy bounds the contract enforces; an offer outside them
// is refused before anything is sent.
const (
	MinCleanupBountyNano  uint64 = 100_000_000
	MaxCleanupBountyNano  uint64 = 1_000_000_000
	MinStorageFeeBaseNano uint64 = 100_000_000
	MinPolicyWindowSecs   uint32 = 3_600
	MaxPolicyWindowSecs   uint32 = 2_592_000
	// MinTestProfileWindowSecs is the window lower bound of the
	// TEST-NETWORK-ONLY Service Actor build.
	MinTestProfileWindowSecs uint32 = nativecore.ServiceActorTestProfileMinimumWindowSeconds
)

// TestProfileActorCodeHash is the code hash of the TEST-NETWORK-ONLY
// Service Actor build, whose minimum response SLA and refund-claim window are
// 600 seconds. `offer --test-profile-actor` deploys it, and only when the
// rail configuration pins this hash; a production configuration pins the
// release hash and never deploys it.
var TestProfileActorCodeHash = "tvm-cell-sha256:" + hex.EncodeToString(nativecore.ServiceActorTestProfileCodeHash[:])

const zeroHash64 = "0000000000000000000000000000000000000000000000000000000000000000"

// ControllerKey is the public half of a vault controller.
type ControllerKey struct {
	Name      string
	KeyID     [mldsa44.KeyIDSize]byte
	PublicKey []byte
}

// Text is mldsa44:<key id>.
func (k ControllerKey) Text() string { return mldsa44.KeyIDText(k.KeyID) }

// tosctlOps are the typed tosctl commands the setup commands run. Each one
// names exactly the flags the command takes; none takes a free-form
// argument from the owner.
type tosctlOps struct {
	runner       TOSCTLRunner
	globalConfig string
	networkLabel string
}

type controllerAnswer struct {
	Name      string `json:"name"`
	Suite     string `json:"suite"`
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

func (a controllerAnswer) key(name string) (ControllerKey, error) {
	if a.Name != name || a.Suite != "ML-DSA-44" || !hex64Pattern.MatchString(a.KeyID) {
		return ControllerKey{}, fmt.Errorf("servicebridge: tosctl returned a malformed answer for controller %q", name)
	}
	publicKey, err := hex.DecodeString(a.PublicKey)
	if err != nil || len(publicKey) != mldsa44.PublicKeySize {
		return ControllerKey{}, fmt.Errorf("servicebridge: tosctl returned a malformed public key for controller %q",
			name)
	}
	derived, err := mldsa44.KeyID(publicKey)
	if err != nil || hex.EncodeToString(derived[:]) != a.KeyID {
		return ControllerKey{}, fmt.Errorf("servicebridge: controller %q: the public key does not derive the stated "+
			"key ID", name)
	}
	return ControllerKey{Name: name, KeyID: derived, PublicKey: publicKey}, nil
}

func (o tosctlOps) controllerCommand(ctx context.Context, verb, name string) (ControllerKey, error) {
	if !walletNamePattern.MatchString(name) {
		return ControllerKey{}, errors.New("servicebridge: invalid controller name")
	}
	var answer controllerAnswer
	if err := runTOSCTLJSON(ctx, o.runner, TOSCTLCall{
		Label: "agent native-registry " + verb,
		Args:  []string{"agent", "native-registry", verb, "--name", name, "--format", "json"},
	}, false, &answer); err != nil {
		return ControllerKey{}, err
	}
	return answer.key(name)
}

// controller reads an existing controller's public key; nothing is signed.
func (o tosctlOps) controller(ctx context.Context, name string) (ControllerKey, error) {
	return o.controllerCommand(ctx, "controller", name)
}

// newController creates a controller. tosctl stores it only if no
// controller of that name exists, so an existing key is never replaced.
func (o tosctlOps) newController(ctx context.Context, name string) (ControllerKey, error) {
	return o.controllerCommand(ctx, "new-controller", name)
}

// WalletView is what tosctl reports about a configured wallet.
type WalletView struct {
	Name    string
	Address string
	// StateKnown is false when tosctl could not read the chain.
	StateKnown bool
	State      string
	// BalanceNano is the balance tosctl displayed, which it rounds to
	// 0.0001 TOS; it only guides the funding check.
	BalanceNano uint64
	// Type is the wallet contract version tosctl reads from the deployed
	// account (for example V3R2); empty when it could not be read.
	Type string
}

// ErrWalletTypeUnsupported reports an owner wallet whose signed messages
// carry no expiry.
var ErrWalletTypeUnsupported = errors.New("servicebridge: the owner wallet's type is not supported")

// expiringWalletTypes are the wallet versions whose messages tosctl signs
// with an expiry two minutes ahead. Every "the earlier message can no
// longer be included" decision of init, offer and withdraw rests on that
// expiry. A V1R3 message carries none: it stays valid until its sequence
// number is used, so it could land long after a second one was sent.
var expiringWalletTypes = map[string]bool{"V3R2": true, "V4R2": true, "V5R1": true}

// requireExpiringWallet refuses to send from a wallet whose messages do
// not expire, or whose type tosctl could not read.
func requireExpiringWallet(wallet WalletView) error {
	switch {
	case expiringWalletTypes[wallet.Type]:
		return nil
	case wallet.Type == "":
		return fmt.Errorf("%w: tosctl did not report the type of wallet %q (%s), so it is not known that its "+
			"messages expire; nothing was sent. Check chain_rpc in the tosctl configuration and that the wallet "+
			"is an active V3R2, V4R2 or V5R1 wallet", ErrWalletTypeUnsupported, wallet.Name, wallet.Address)
	default:
		return fmt.Errorf("%w: wallet %q (%s) is a %s wallet, whose messages carry no expiry: a message that "+
			"seemed lost could still be included later and be paid twice. Nothing was sent; use a V3R2, V4R2 or "+
			"V5R1 wallet", ErrWalletTypeUnsupported, wallet.Name, wallet.Address, wallet.Type)
	}
}

type walletAnswer struct {
	Name       string  `json:"name"`
	Address    *string `json:"address"`
	Balance    *string `json:"balance"`
	State      *string `json:"state"`
	WalletType *string `json:"wallet_type"`
	Seqno      *uint32 `json:"seqno"`
}

// errWalletMissing reports a wallet name the tosctl configuration lacks.
var errWalletMissing = errors.New("servicebridge: the wallet is not in the tosctl configuration")

// rawWalletAddress converts the address tosctl lists into the raw
// workchain 0 form the rail uses.
func rawWalletAddress(text string) (string, error) {
	if rawAddressPattern.MatchString(text) {
		return text, nil
	}
	parsed, err := address.ParseAddr(text)
	if err != nil || parsed == nil {
		return "", errors.New("servicebridge: tosctl listed an undecodable wallet address")
	}
	raw := parsed.StringRaw()
	if !rawAddressPattern.MatchString(raw) {
		return "", errors.New("servicebridge: the wallet is not a workchain 0 account")
	}
	return raw, nil
}

// wallet resolves one configured wallet with `wallet ls`.
func (o tosctlOps) wallet(ctx context.Context, name string) (WalletView, error) {
	if !walletNamePattern.MatchString(name) {
		return WalletView{}, errors.New("servicebridge: invalid wallet name")
	}
	var answers []walletAnswer
	if err := runTOSCTLJSON(ctx, o.runner, TOSCTLCall{
		Label: "wallet ls", Args: []string{"wallet", "ls", "--format", "json"}, MaxOutput: maxTOSCTLJSONOutput,
	}, false, &answers); err != nil {
		return WalletView{}, err
	}
	for _, answer := range answers {
		if answer.Name != name {
			continue
		}
		if answer.Address == nil {
			return WalletView{}, fmt.Errorf("servicebridge: tosctl could not derive the address of wallet %q "+
				"(its key is not in the vault)", name)
		}
		raw, err := rawWalletAddress(*answer.Address)
		if err != nil {
			return WalletView{}, err
		}
		view := WalletView{Name: name, Address: raw}
		if answer.State == nil || answer.Balance == nil {
			return view, nil
		}
		balance, err := ParseTOSAmount(*answer.Balance)
		if err != nil {
			return WalletView{}, errors.New("servicebridge: tosctl listed an undecodable wallet balance")
		}
		view.StateKnown, view.State, view.BalanceNano = true, *answer.State, balance
		if answer.WalletType != nil {
			view.Type = *answer.WalletType
		}
		return view, nil
	}
	return WalletView{}, errWalletMissing
}

// RegistryDomain is the identity domain tosctl derives from the chain's
// global configuration and the network label.
type RegistryDomain struct {
	GenesisRootHash string
	GenesisFileHash string
	CodeHash        string
}

func (o tosctlOps) domainFlags() []string {
	return []string{"--global-config", o.globalConfig, "--network-label", o.networkLabel}
}

// domain runs `native-registry domain`, which reads only the global
// configuration file, and checks that it answers for the label given.
func (o tosctlOps) domain(ctx context.Context) (RegistryDomain, error) {
	var answer struct {
		NetworkLabel string `json:"network_label"`
		GenesisRoot  string `json:"genesis_root"`
		GenesisFile  string `json:"genesis_file"`
		NetworkHash  string `json:"network_hash"`
		CodeHash     string `json:"code_hash"`
	}
	args := append([]string{"agent", "native-registry", "domain"}, o.domainFlags()...)
	if err := runTOSCTLJSON(ctx, o.runner, TOSCTLCall{
		Label: "agent native-registry domain", Args: append(args, "--format", "json"),
	}, false, &answer); err != nil {
		return RegistryDomain{}, err
	}
	labelHash := sha256.Sum256([]byte(o.networkLabel))
	if answer.NetworkLabel != o.networkLabel || answer.NetworkHash != hex.EncodeToString(labelHash[:]) ||
		!hex64Pattern.MatchString(answer.GenesisRoot) || !hex64Pattern.MatchString(answer.GenesisFile) ||
		!hex64Pattern.MatchString(answer.CodeHash) {
		return RegistryDomain{}, errors.New("servicebridge: tosctl returned a domain that does not answer for the " +
			"network label")
	}
	return RegistryDomain{
		GenesisRootHash: "sha256:" + answer.GenesisRoot, GenesisFileHash: "sha256:" + answer.GenesisFile,
		CodeHash: "tvm-cell-sha256:" + answer.CodeHash,
	}, nil
}

// SignedRegistryMessage is a Native Registry message tosctl built and
// signed with a controller. It is public data: a wallet still has to send
// it.
type SignedRegistryMessage struct {
	ObjectID     string `json:"object_id,omitempty"`
	Destination  string `json:"destination"`
	FinalTarget  string `json:"final_target"`
	ActionHash   string `json:"action_hash"`
	StateInitBOC string `json:"state_init_boc,omitempty"`
	BodyBOC      string `json:"body_boc"`
}

func validBOCText(value string, allowEmpty bool) bool {
	if value == "" {
		return allowEmpty
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(value)
	return err == nil && len(raw) > 0
}

func (m SignedRegistryMessage) validate(needsStateInit bool) error {
	if !rawAddressPattern.MatchString(m.Destination) || !rawAddressPattern.MatchString(m.FinalTarget) ||
		!hex64Pattern.MatchString(m.ActionHash) || !validBOCText(m.BodyBOC, false) ||
		!validBOCText(m.StateInitBOC, !needsStateInit) {
		return errors.New("servicebridge: tosctl returned a malformed registry message")
	}
	return nil
}

// registerAgent builds and signs an Agent registration. Nothing is sent.
func (o tosctlOps) registerAgent(ctx context.Context, policyPath, nonce, signer string) (SignedRegistryMessage, error) {
	if !hex64Pattern.MatchString(nonce) || !walletNamePattern.MatchString(signer) {
		return SignedRegistryMessage{}, errors.New("servicebridge: invalid Agent registration")
	}
	var answer struct {
		Kind         string `json:"kind"`
		ObjectID     string `json:"object_id"`
		Destination  string `json:"destination"`
		FinalTarget  string `json:"final_target"`
		ActionHash   string `json:"action_hash"`
		Generation   uint64 `json:"generation"`
		Sequence     uint64 `json:"sequence"`
		StateInitBOC string `json:"state_init_boc"`
		BodyBOC      string `json:"body_boc"`
	}
	args := append([]string{"agent", "native-registry", "register-agent"}, o.domainFlags()...)
	args = append(args, "--policy", policyPath, "--nonce", nonce, "--signer", signer, "--format", "json")
	if err := runTOSCTLJSON(ctx, o.runner, TOSCTLCall{
		Label: "agent native-registry register-agent", Args: args, MaxOutput: maxTOSCTLJSONOutput,
	}, false, &answer); err != nil {
		return SignedRegistryMessage{}, err
	}
	message := SignedRegistryMessage{
		ObjectID: answer.ObjectID, Destination: answer.Destination, FinalTarget: answer.FinalTarget,
		ActionHash: answer.ActionHash, StateInitBOC: answer.StateInitBOC, BodyBOC: answer.BodyBOC,
	}
	if answer.Kind != "register-agent" || !hex64Pattern.MatchString(answer.ObjectID) ||
		answer.Destination != answer.FinalTarget {
		return SignedRegistryMessage{}, errors.New("servicebridge: tosctl returned a malformed Agent registration")
	}
	return message, message.validate(true)
}

// registerCapability builds and signs a Capability registration under the
// owner Agent. Nothing is sent.
func (o tosctlOps) registerCapability(
	ctx context.Context,
	agentAddress, nonce, objectNonce, version, manifestHex, signer string,
) (SignedRegistryMessage, error) {
	if !rawAddressPattern.MatchString(agentAddress) || !hex64Pattern.MatchString(nonce) ||
		!hex64Pattern.MatchString(objectNonce) || !hex64Pattern.MatchString(manifestHex) || version == "" ||
		strings.HasPrefix(version, "-") || !walletNamePattern.MatchString(signer) {
		return SignedRegistryMessage{}, errors.New("servicebridge: invalid Capability registration")
	}
	var answer struct {
		Kind        string `json:"kind"`
		KindCode    uint64 `json:"kind_code"`
		TargetID    string `json:"target_id"`
		Destination string `json:"destination"`
		FinalTarget string `json:"final_target"`
		ActionHash  string `json:"action_hash"`
		Generation  uint64 `json:"generation"`
		Sequence    uint64 `json:"sequence"`
		Predecessor string `json:"predecessor"`
		ChainTime   uint64 `json:"chain_time"`
		BodyBOC     string `json:"body_boc"`
	}
	args := append([]string{"agent", "native-registry", "action"}, o.domainFlags()...)
	args = append(args, "--kind", "register-capability", "--agent", agentAddress, "--nonce", nonce,
		"--object-nonce", objectNonce, "--version", version, "--manifest", manifestHex, "--signer", signer,
		"--format", "json")
	if err := runTOSCTLJSON(ctx, o.runner, TOSCTLCall{
		Label: "agent native-registry action", Args: args, MaxOutput: maxTOSCTLJSONOutput,
	}, false, &answer); err != nil {
		return SignedRegistryMessage{}, err
	}
	message := SignedRegistryMessage{
		ObjectID: answer.TargetID, Destination: answer.Destination, FinalTarget: answer.FinalTarget,
		ActionHash: answer.ActionHash, BodyBOC: answer.BodyBOC,
	}
	if answer.Kind != "register-capability" {
		return SignedRegistryMessage{}, errors.New("servicebridge: tosctl returned another action than the " +
			"Capability registration")
	}
	return message, message.validate(false)
}

// walletSend signs and broadcasts one wallet message carrying exactly the
// given body (and StateInit) with an exact nanoTOS value. tosctl returns
// success only after the wallet's sequence number moved.
func (o tosctlOps) walletSend(
	ctx context.Context,
	wallet string,
	valueNano uint64,
	message SignedRegistryMessage,
) error {
	if !walletNamePattern.MatchString(wallet) || valueNano == 0 || message.validate(false) != nil {
		return errors.New("servicebridge: invalid wallet send")
	}
	args := []string{
		"wallet", "send", "--from", wallet, "--to", message.Destination,
		"--amount-nanotos", strconv.FormatUint(valueNano, 10), "--body-boc", message.BodyBOC,
	}
	if message.StateInitBOC != "" {
		args = append(args, "--state-init-boc", message.StateInitBOC)
	}
	_, err := o.runner.Run(ctx, TOSCTLCall{Label: "wallet send", Args: append(args, "--yes")})
	return err
}

// ActorTerms are the owner-chosen terms of a Service Actor, in nanoTOS and
// seconds.
type ActorTerms struct {
	PriceNano         uint64 `json:"price_nanotos,string"`
	StorageFeeNano    uint64 `json:"storage_fee_nanotos,string"`
	CleanupBountyNano uint64 `json:"cleanup_bounty_nanotos,string"`
	ResponseSLA       uint32 `json:"response_sla_seconds"`
	RefundClaimWindow uint32 `json:"refund_claim_window_seconds"`
}

// Validate applies the release contract's own bounds, so nothing the
// contract would refuse is ever signed.
func (t ActorTerms) Validate() error {
	return t.ValidateFor(false)
}

// ValidateFor applies the bounds of the Service Actor build that will run
// these terms: the release, or with testProfile the test-network-only build
// whose window lower bound is MinTestProfileWindowSecs.
func (t ActorTerms) ValidateFor(testProfile bool) error {
	minWindow := MinPolicyWindowSecs
	if testProfile {
		minWindow = MinTestProfileWindowSecs
	}
	if t.PriceNano == 0 {
		return errors.New("servicebridge: the price must be greater than zero")
	}
	if t.CleanupBountyNano < MinCleanupBountyNano || t.CleanupBountyNano > MaxCleanupBountyNano {
		return fmt.Errorf("servicebridge: the cleanup bounty must be between %s and %s TOS",
			FormatTOSAmount(MinCleanupBountyNano), FormatTOSAmount(MaxCleanupBountyNano))
	}
	floor, err := checkedAdd(MinStorageFeeBaseNano, t.CleanupBountyNano)
	if err != nil {
		return err
	}
	if t.StorageFeeNano < floor {
		return fmt.Errorf("servicebridge: the storage fee must be at least %s TOS (%s TOS plus the cleanup bounty)",
			FormatTOSAmount(floor), FormatTOSAmount(MinStorageFeeBaseNano))
	}
	if t.ResponseSLA < minWindow || t.ResponseSLA > MaxPolicyWindowSecs {
		return fmt.Errorf("servicebridge: the response SLA must be between %d and %d seconds", minWindow,
			MaxPolicyWindowSecs)
	}
	if t.RefundClaimWindow < minWindow || t.RefundClaimWindow > MaxPolicyWindowSecs {
		return fmt.Errorf("servicebridge: the refund-claim window must be between %d and %d seconds",
			minWindow, MaxPolicyWindowSecs)
	}
	for name, value := range map[string]uint64{
		"the price": t.PriceNano, "the storage fee": t.StorageFeeNano,
	} {
		if _, amountErr := tosctlAmount(value, name, false); amountErr != nil {
			return amountErr
		}
	}
	// What a buyer attaches to one call must itself be representable.
	if _, err := checkedAdd(t.PriceNano, t.StorageFeeNano); err != nil {
		return err
	}
	return nil
}

func (t ActorTerms) flags() []string {
	return []string{
		"--price-per-call", FormatTOSAmount(t.PriceNano), "--storage-fee", FormatTOSAmount(t.StorageFeeNano),
		"--cleanup-bounty", FormatTOSAmount(t.CleanupBountyNano),
		"--response-sla", strconv.FormatUint(uint64(t.ResponseSLA), 10),
		"--refund-claim-window", strconv.FormatUint(uint64(t.RefundClaimWindow), 10),
		"--rate-limit-per-day", "0",
	}
}

// codeProfileFlags selects tosctl's TEST-NETWORK-ONLY Service Actor build.
// The release build takes no flag, so a release deployment runs the same
// tosctl command as before.
func codeProfileFlags(testProfile bool) []string {
	if testProfile {
		return []string{"--code-profile", "test"}
	}
	return nil
}

// actorAddress computes the address a deployment with these terms, owner
// and attestor creates, with `agent service build-state`. It signs nothing
// and reads neither the vault nor the chain.
func (o tosctlOps) actorAddress(
	ctx context.Context,
	owner string,
	terms ActorTerms,
	attestor ControllerKey,
	testProfile bool,
) (string, error) {
	if !rawAddressPattern.MatchString(owner) || len(attestor.PublicKey) != mldsa44.PublicKeySize {
		return "", errors.New("servicebridge: invalid Service Actor identity")
	}
	var answer struct {
		Address string `json:"address"`
	}
	args := append([]string{"agent", "service", "build-state", "--owner", owner, "--open-access"}, terms.flags()...)
	args = append(args, "--metadata-hash", zeroHash64, "--proof-scheme-hash", zeroHash64,
		"--attestor-pubkey", hex.EncodeToString(attestor.PublicKey), "--workchain", "0", "--format", "json")
	args = append(args, codeProfileFlags(testProfile)...)
	if err := runTOSCTLJSON(ctx, o.runner, TOSCTLCall{Label: "agent service build-state", Args: args}, false,
		&answer); err != nil {
		return "", err
	}
	if !rawAddressPattern.MatchString(answer.Address) {
		return "", errors.New("servicebridge: tosctl returned a malformed Service Actor address")
	}
	return answer.Address, nil
}

// deployActor deploys and funds the Service Actor with zero metadata and
// the attestor controller's key, and returns the address tosctl deployed.
func (o tosctlOps) deployActor(
	ctx context.Context,
	wallet, owner, recordName string,
	terms ActorTerms,
	attestorController string,
	fundingNano uint64,
	testProfile bool,
) (string, error) {
	funding, err := tosctlAmount(fundingNano, "the deploy funding", false)
	if err != nil {
		return "", err
	}
	if !walletNamePattern.MatchString(wallet) || !rawAddressPattern.MatchString(owner) ||
		!walletNamePattern.MatchString(recordName) || !walletNamePattern.MatchString(attestorController) {
		return "", errors.New("servicebridge: invalid Service Actor deployment")
	}
	var answer struct {
		Name    string `json:"name"`
		Address string `json:"address"`
		Status  string `json:"status"`
		Owner   string `json:"owner"`
	}
	args := append([]string{
		"agent", "service", "deploy", "--name", recordName, "--owner", owner, "--open-access",
	}, terms.flags()...)
	args = append(args, "--metadata-hash", zeroHash64, "--proof-scheme-hash", zeroHash64,
		"--attestor-controller", attestorController, "--from", wallet, "--amount", funding, "--workchain", "0",
		"--yes", "--format", "json")
	args = append(args, codeProfileFlags(testProfile)...)
	// tosctl prints its progress before the one-line JSON result.
	if err := runTOSCTLJSON(ctx, o.runner, TOSCTLCall{Label: "agent service deploy", Args: args}, true,
		&answer); err != nil {
		return "", err
	}
	if !rawAddressPattern.MatchString(answer.Address) || answer.Owner != owner {
		return "", errors.New("servicebridge: tosctl returned a malformed deployment answer")
	}
	return answer.Address, nil
}

// updatePolicy sends update-policy with every policy field, so no field
// keeps a value the owner did not state.
func (o tosctlOps) updatePolicy(
	ctx context.Context,
	wallet, actor string,
	terms ActorTerms,
	metadataHex, proofHex string,
) error {
	if !walletNamePattern.MatchString(wallet) || !rawAddressPattern.MatchString(actor) ||
		!hex64Pattern.MatchString(metadataHex) || !hex64Pattern.MatchString(proofHex) {
		return errors.New("servicebridge: invalid policy update")
	}
	args := append([]string{
		"agent", "service", "send", "--operation", "update-policy", "--address", actor, "--from", wallet,
	}, terms.flags()...)
	args = append(args, "--active", "true", "--open-access", "--metadata-hash", metadataHex,
		"--proof-scheme-hash", proofHex, "--yes")
	_, err := o.runner.Run(ctx, TOSCTLCall{Label: "agent service send update-policy", Args: args})
	return err
}

// withdrawRevenue sends withdraw-revenue for exactly amountNano, tagged
// with queryID so its finalized transaction can be told from any other.
func (o tosctlOps) withdrawRevenue(ctx context.Context, wallet, actor string, amountNano, queryID uint64) error {
	amount, err := tosctlAmount(amountNano, "the withdrawal", false)
	if err != nil {
		return err
	}
	if !walletNamePattern.MatchString(wallet) || !rawAddressPattern.MatchString(actor) || queryID == 0 {
		return errors.New("servicebridge: invalid withdrawal")
	}
	_, err = o.runner.Run(ctx, TOSCTLCall{Label: "agent service send withdraw-revenue", Args: []string{
		"agent", "service", "send", "--operation", "withdraw-revenue", "--address", actor, "--from", wallet,
		"--query-id", strconv.FormatUint(queryID, 10), "--withdraw-amount", amount, "--yes",
	}})
	return err
}
