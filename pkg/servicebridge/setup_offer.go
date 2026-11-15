package servicebridge

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
)

// OfferInput is what the owner chooses for an offer.
type OfferInput struct {
	RailConfigPath     string     `json:"rail_config"`
	Terms              ActorTerms `json:"terms"`
	Version            string     `json:"version"`
	RetentionSeconds   uint64     `json:"retention_seconds"`
	AttestorController string     `json:"attestor_controller"`
	ExecutorBinary     string     `json:"executor_binary"`
	// ExecutorSHA256 pins the executor; empty pins the binary found.
	ExecutorSHA256       string `json:"executor_sha256"`
	ContainerdSocket     string `json:"containerd_socket"`
	FIFODir              string `json:"fifo_dir"`
	RespondBudgetSeconds int    `json:"respond_budget_seconds"`
	DeployFundingNano    uint64 `json:"deploy_funding_nanotos"`
	// OfferPath is where the offer file for buyers is written.
	OfferPath string `json:"offer_path"`
	Yes       bool   `json:"yes"`
}

// Offer defaults.
const (
	DefaultOfferVersion       = "1.0.0"
	DefaultAttestorController = "service-attestor"
	DefaultRetentionSeconds   = 86400
	DefaultRespondBudget      = 120
)

// OfferIdentity holds the inputs that determine the actor's address and
// the Capability's id.
type OfferIdentity struct {
	AgentID            string     `json:"agent_id"`
	WalletAddress      string     `json:"wallet_address"`
	AttestorController string     `json:"attestor_controller"`
	AttestorKeyID      string     `json:"attestor_key_id"`
	Terms              ActorTerms `json:"terms"`
	Version            string     `json:"version"`
	RetentionSeconds   uint64     `json:"retention_seconds"`
	ActorCodeHash      string     `json:"actor_code_hash"`
}

// OfferJournal is the durable state of `offer`.
type OfferJournal struct {
	Identity          OfferIdentity `json:"identity"`
	Actor             string        `json:"actor,omitempty"`
	DeployFundingNano uint64        `json:"deploy_funding_nanotos,string,omitempty"`
	Deploy            ChainStep     `json:"deploy"`
	ManifestDigest    string        `json:"manifest_digest,omitempty"`
	// The nonces are stored before the registration is built.
	CapabilityNonce       string                 `json:"capability_nonce,omitempty"`
	CapabilityObjectNonce string                 `json:"capability_object_nonce,omitempty"`
	CapabilityID          string                 `json:"capability_id,omitempty"`
	CapabilityAddress     string                 `json:"capability_address,omitempty"`
	Registration          *SignedRegistryMessage `json:"registration,omitempty"`
	Capability            ChainStep              `json:"capability"`
	MetadataHash          string                 `json:"metadata_hash,omitempty"`
	Policy                ChainStep              `json:"policy"`
	// Stopped is set when a sent message contradicted the plan. Every later
	// run refuses until the owner has inspected what happened and removed
	// it.
	Stopped string `json:"stopped,omitempty"`
}

func (j *OfferJournal) sent() bool {
	return j.Deploy.sent() || j.Capability.sent() || j.Policy.sent()
}

// OfferPreview is everything `offer` signs or sends, shown before the
// first send.
type OfferPreview struct {
	OwnerWallet        string     `json:"owner_wallet"`
	ProviderAgentID    string     `json:"provider_agent_id"`
	ProviderAgent      string     `json:"provider_agent_address"`
	Actor              string     `json:"actor"`
	ActorCodeHash      string     `json:"actor_code_hash"`
	AttestorController string     `json:"attestor_controller"`
	AttestorKeyID      string     `json:"attestor_key_id"`
	Terms              ActorTerms `json:"terms"`
	Version            string     `json:"version"`
	ManifestDigest     string     `json:"manifest_digest"`
	CapabilityID       string     `json:"capability_id"`
	CapabilityAddress  string     `json:"capability_address"`
	MetadataHash       string     `json:"metadata_hash"`
	ProofSchemeHash    string     `json:"proof_scheme_hash"`
	DeployFundingNano  string     `json:"deploy_funding_nanotos"`
	RegistryValueNano  string     `json:"capability_registration_attached_nanotos"`
	PolicyValueNano    string     `json:"update_policy_attached_nanotos"`
	TotalAttachedNano  string     `json:"total_attached_nanotos"`
	BuyerAttachesNano  string     `json:"buyer_attaches_per_call_nanotos"`
	Note               string     `json:"note"`
	// ToBeCreated lists what the run with --yes creates before it can
	// state the fields left empty here: the attestor key does not exist
	// yet, and the actor address, the manifest digest, the Capability id
	// and address and the metadata hash all derive from it.
	ToBeCreated []string `json:"to_be_created,omitempty"`
}

// OfferResult is the report of `offer`.
type OfferResult struct {
	Schema     string        `json:"schema"`
	Confirmed  bool          `json:"confirmed"`
	RailConfig string        `json:"rail_config"`
	Preview    *OfferPreview `json:"preview,omitempty"`
	OfferFile  string        `json:"offer_file,omitempty"`
	// ExecutorSHA256 and ExecutorPin say how the executor was pinned.
	ExecutorSHA256 string           `json:"executor_sha256,omitempty"`
	ExecutorPin    string           `json:"executor_pin,omitempty"`
	Verification   []PreflightCheck `json:"verification,omitempty"`
	Steps          []SetupStep      `json:"steps"`
	NextSteps      []string         `json:"next_steps,omitempty"`
}

// OfferResultSchema names the offer report.
const OfferResultSchema = "tos.openfox.rail-offer-setup.v1"

const offerPreviewNote = "tosctl signs each message with keys in its custody. The deploy funding stays in the " +
	"actor as its operating reserve. Fees are paid from the owner wallet on top of the attached values."

func validVersion(version string) bool {
	if version == "" || len(version) > 128 || strings.HasPrefix(version, "-") {
		return false
	}
	for _, b := range []byte(version) {
		if b < 0x21 || b > 0x7e {
			return false
		}
	}
	return true
}

func (in *OfferInput) fill(stateDir string) {
	if in.Version == "" {
		in.Version = DefaultOfferVersion
	}
	if in.AttestorController == "" {
		in.AttestorController = DefaultAttestorController
	}
	if in.RetentionSeconds == 0 {
		in.RetentionSeconds = DefaultRetentionSeconds
	}
	if in.RespondBudgetSeconds == 0 {
		in.RespondBudgetSeconds = DefaultRespondBudget
	}
	if in.DeployFundingNano == 0 {
		in.DeployFundingNano = MinimumDeployFundingNano
	}
	if in.FIFODir == "" {
		in.FIFODir = filepath.Join(stateDir, "fifo")
	}
	if in.OfferPath == "" {
		in.OfferPath = filepath.Join(stateDir, setupDirectory, "offer.json")
	}
}

// validate applies every bound before tosctl or the chain is touched.
func (in *OfferInput) validate() error {
	var problems []string
	if err := in.Terms.Validate(); err != nil {
		problems = append(problems, strings.TrimPrefix(err.Error(), "servicebridge: "))
	}
	if !validVersion(in.Version) {
		problems = append(problems, "the version must be 1 to 128 printable bytes without spaces")
	}
	if !walletNamePattern.MatchString(in.AttestorController) {
		problems = append(problems, "the attestor controller name is not a valid controller name")
	}
	if in.RetentionSeconds == 0 || in.RetentionSeconds > 366*86400 {
		problems = append(problems, "the retention must be between 1 second and 366 days")
	}
	if in.RespondBudgetSeconds <= 0 || in.RespondBudgetSeconds > 3600 {
		problems = append(problems, "the respond budget must be between 1 and 3600 seconds")
	}
	if in.DeployFundingNano < MinimumDeployFundingNano {
		problems = append(problems, fmt.Sprintf("the deploy funding must be at least %s TOS",
			FormatTOSAmount(MinimumDeployFundingNano)))
	} else if _, err := tosctlAmount(in.DeployFundingNano, "the deploy funding", false); err != nil {
		problems = append(problems, strings.TrimPrefix(err.Error(), "servicebridge: "))
	}
	if in.ExecutorSHA256 != "" && !hex64Pattern.MatchString(in.ExecutorSHA256) {
		problems = append(problems, "--executor-sha256 must be 64 lowercase hex digits")
	}
	for name, path := range map[string]string{
		"the executor binary": in.ExecutorBinary, "the containerd socket": in.ContainerdSocket,
		"the FIFO directory": in.FIFODir, "the offer file path": in.OfferPath,
	} {
		if !cleanAbsolute(path) {
			problems = append(problems, name+" must be an absolute clean path")
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return errors.New("servicebridge: offer: " + strings.Join(problems, "; "))
	}
	return nil
}

// actorEffect reports whether the actor is deployed in finalized state as
// planned: the pinned code, this owner, this attestor snapshot.
func actorEffect(ctx context.Context, actor, codeHash, owner string, attestor ControllerKey) effectFunc {
	return func(session RailSession) (bool, error) {
		account, found, err := session.ReadActor(ctx, actor)
		if err != nil {
			return false, fmt.Errorf("servicebridge: read actor %s: %w", actor, err)
		}
		if !found || account == nil || account.Data == nil {
			return false, nil
		}
		policy := account.Data.Policy
		switch {
		case account.CodeHash != codeHash:
			return false, fmt.Errorf("servicebridge: the account at %s runs %s, not the pinned actor code %s", actor,
				account.CodeHash, codeHash)
		case account.Data.Owner.Text() != owner:
			return false, fmt.Errorf("servicebridge: the actor at %s is owned by %s, not the owner wallet %s", actor,
				account.Data.Owner.Text(), owner)
		case !policy.HasAttestor || policy.AttestorKeyID != attestor.KeyID:
			return false, fmt.Errorf("servicebridge: the actor at %s does not hold attestor %s", actor,
				attestor.Text())
		}
		derived, err := mldsa44.KeyID(policy.AttestorKey)
		if err != nil || derived != attestor.KeyID {
			return false, fmt.Errorf("servicebridge: the actor at %s stores an attestor key that does not derive "+
				"its key id", actor)
		}
		return true, nil
	}
}

// capabilityEffect reports whether the Capability version is registered in
// finalized state, owned by the Agent and committed to the manifest.
func capabilityEffect(ctx context.Context, capabilityID, agentID, version, digest string) effectFunc {
	return func(session RailSession) (bool, error) {
		state, found, err := session.ResolveRegistry(ctx, capabilityID)
		if err != nil {
			return false, fmt.Errorf("servicebridge: read Capability %s: %w", capabilityID, err)
		}
		if !found {
			return false, nil
		}
		capability := state.GetCapability()
		switch {
		case capability == nil || capability.GetCapabilityId() != capabilityID:
			return false, fmt.Errorf("servicebridge: the registry object at %s is not that Capability", capabilityID)
		case capability.GetTombstoned():
			return false, fmt.Errorf("servicebridge: Capability %s is revoked", capabilityID)
		case capability.GetOwnerAgentId() != agentID:
			return false, fmt.Errorf("servicebridge: Capability %s is owned by %s, not %s", capabilityID,
				capability.GetOwnerAgentId(), agentID)
		}
		for _, candidate := range capability.GetVersions() {
			if candidate.GetVersion() != version {
				continue
			}
			if candidate.GetRevoked() || candidate.GetManifestDigest() != digest {
				return false, fmt.Errorf("servicebridge: Capability %s version %q is revoked or commits to another "+
					"manifest", capabilityID, version)
			}
			return true, nil
		}
		return false, fmt.Errorf("servicebridge: Capability %s has no version %q", capabilityID, version)
	}
}

func sameNano(value *big.Int, want uint64) bool {
	return value != nil && value.IsUint64() && value.Uint64() == want
}

// policyEffect reports whether the actor's finalized policy states exactly
// the offer: every term, open access, active, the metadata hash and the
// software-work proof scheme.
func policyEffect(ctx context.Context, actor string, terms ActorTerms, metadata [32]byte) effectFunc {
	return func(session RailSession) (bool, error) {
		account, found, err := session.ReadActor(ctx, actor)
		if err != nil {
			return false, fmt.Errorf("servicebridge: read actor %s: %w", actor, err)
		}
		if !found || account == nil || account.Data == nil {
			return false, fmt.Errorf("servicebridge: the actor %s is not in finalized state", actor)
		}
		policy := account.Data.Policy
		return account.Data.Active && policy.OpenAccess && !policy.HasAuthorizedCaller &&
			policy.RateLimitPerDay == 0 && sameNano(policy.PricePerCall, terms.PriceNano) &&
			sameNano(policy.StorageFee, terms.StorageFeeNano) &&
			sameNano(policy.CleanupBounty, terms.CleanupBountyNano) && policy.ResponseSLA == terms.ResponseSLA &&
			policy.RefundClaimWindow == terms.RefundClaimWindow && policy.MetadataHash == metadata &&
			policy.ProofSchemeHash == nativecore.ServiceActorSoftwareWorkProofScheme, nil
	}
}

func offerIdentityDifference(a, b OfferIdentity) string {
	switch {
	case a.AgentID != b.AgentID:
		return "the provider Agent"
	case a.WalletAddress != b.WalletAddress:
		return "the owner wallet"
	case a.AttestorController != b.AttestorController || a.AttestorKeyID != b.AttestorKeyID:
		return "the attestor controller"
	case a.Terms.PriceNano != b.Terms.PriceNano:
		return "the price"
	case a.Terms.StorageFeeNano != b.Terms.StorageFeeNano:
		return "the storage fee"
	case a.Terms.CleanupBountyNano != b.Terms.CleanupBountyNano:
		return "the cleanup bounty"
	case a.Terms.ResponseSLA != b.Terms.ResponseSLA:
		return "the response SLA"
	case a.Terms.RefundClaimWindow != b.Terms.RefundClaimWindow:
		return "the refund-claim window"
	case a.Version != b.Version:
		return "the version"
	case a.RetentionSeconds != b.RetentionSeconds:
		return "the retention"
	case a.ActorCodeHash != b.ActorCodeHash:
		return "the actor code hash"
	default:
		return ""
	}
}

// pinExecutor decides the executor pin the same way init pins tosctl.
func pinExecutor(in OfferInput, earlier *ProviderNode) (pin, how string, err error) {
	actual, err := HashTOSCTL(in.ExecutorBinary)
	if err != nil {
		return "", "", errors.New("servicebridge: the executor binary is not a bounded regular file at an " +
			"absolute clean path")
	}
	switch {
	case in.ExecutorSHA256 != "":
		if actual != in.ExecutorSHA256 {
			return "", "", fmt.Errorf("servicebridge: the executor hashes to %s, not the --executor-sha256 given",
				actual)
		}
		return actual, PinGivenByOwner, nil
	case earlier != nil && earlier.ExecutorBinary == in.ExecutorBinary && earlier.ExecutorSHA256 != "" &&
		earlier.ExecutorSHA256 != actual:
		return "", "", fmt.Errorf("servicebridge: the executor binary changed since it was pinned (pinned %s, now "+
			"%s); if you replaced it, pass --executor-sha256 %s to accept it", earlier.ExecutorSHA256, actual, actual)
	case earlier != nil && earlier.ExecutorSHA256 == actual:
		return actual, PinKept, nil
	default:
		return actual, PinTrustOnFirstUse, nil
	}
}

// offerValues returns what the owner wallet attaches in total and what a
// buyer attaches to one call.
func offerValues(deployFundingNano uint64, terms ActorTerms) (total, perCall uint64, err error) {
	if total, err = checkedAdd(deployFundingNano, RegistryMessageValueNano); err != nil {
		return 0, 0, err
	}
	if total, err = checkedAdd(total, PolicyMessageValueNano); err != nil {
		return 0, 0, err
	}
	if perCall, err = checkedAdd(terms.PriceNano, terms.StorageFeeNano); err != nil {
		return 0, 0, err
	}
	if perCall, err = checkedAdd(perCall, AdmissionAllowanceNano); err != nil {
		return 0, 0, err
	}
	return total, perCall, nil
}

// offerPreviewBeforeKey is the preview of an offer whose attestor
// controller does not exist yet: every term, value and total, and a list of
// what is created first. The fields that derive from the key stay empty.
func offerPreviewBeforeKey(config NodeConfig, in OfferInput, agentAddress string) (*OfferPreview, error) {
	total, perCall, err := offerValues(in.DeployFundingNano, in.Terms)
	if err != nil {
		return nil, err
	}
	proof := nativecore.ServiceActorSoftwareWorkProofScheme
	return &OfferPreview{
		OwnerWallet: config.WalletAddress, ProviderAgentID: config.AgentID, ProviderAgent: agentAddress,
		ActorCodeHash: config.ActorCodeHash, AttestorController: in.AttestorController, Terms: in.Terms,
		Version: in.Version, ProofSchemeHash: hex.EncodeToString(proof[:]),
		DeployFundingNano: fmt.Sprint(in.DeployFundingNano), RegistryValueNano: fmt.Sprint(RegistryMessageValueNano),
		PolicyValueNano: fmt.Sprint(PolicyMessageValueNano), TotalAttachedNano: fmt.Sprint(total),
		BuyerAttachesNano: fmt.Sprint(perCall), Note: offerPreviewNote,
		ToBeCreated: []string{
			fmt.Sprintf("attestor controller %q: a new ML-DSA-44 key in the tosctl vault", in.AttestorController),
			"a Service Actor at an address derived from the owner wallet, these terms and that key",
			"a manifest naming that actor and key, and a Capability whose id derives from its digest",
		},
	}, nil
}

// reportOfferPreview prints a preview. Every line the owner needs in order
// to decide is printed whether or not the attestor key exists yet.
func reportOfferPreview(env SetupEnv, preview *OfferPreview) {
	parse := func(value string) string {
		nano, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return value + " nanoTOS"
		}
		return FormatTOSAmount(nano) + " TOS"
	}
	pending := func(value string) string {
		if value == "" {
			return "(derived once the attestor key exists)"
		}
		return value
	}
	env.reportf("offer.preview: owner wallet %s; provider Agent %s", preview.OwnerWallet, preview.ProviderAgentID)
	for _, created := range preview.ToBeCreated {
		env.reportf("offer.preview: to be created: %s", created)
	}
	env.reportf("offer.preview: deploy Service Actor %s (code %s, attestor %s) funded with %s",
		pending(preview.Actor), preview.ActorCodeHash, pending(preview.AttestorKeyID), parse(preview.DeployFundingNano))
	env.reportf("offer.preview: terms: price %s TOS, storage fee %s TOS, cleanup bounty %s TOS, response SLA %d s, "+
		"refund-claim window %d s", FormatTOSAmount(preview.Terms.PriceNano),
		FormatTOSAmount(preview.Terms.StorageFeeNano), FormatTOSAmount(preview.Terms.CleanupBountyNano),
		preview.Terms.ResponseSLA, preview.Terms.RefundClaimWindow)
	env.reportf("offer.preview: register Capability %s version %q at %s with manifest %s, attaching %s",
		pending(preview.CapabilityID), preview.Version, pending(preview.CapabilityAddress),
		pending(preview.ManifestDigest), parse(preview.RegistryValueNano))
	env.reportf("offer.preview: update-policy with metadata hash %s and proof scheme %s, attaching %s",
		pending(preview.MetadataHash), preview.ProofSchemeHash, parse(preview.PolicyValueNano))
	env.reportf("offer.preview: total attached %s plus wallet fees; a buyer attaches %s to each call",
		parse(preview.TotalAttachedNano), parse(preview.BuyerAttachesNano))
}

// RunOffer publishes a provider's offer: attestor, Service Actor,
// manifest, Capability and policy, each verified from finalized state. It
// is idempotent and resumes after a crash at any step.
func RunOffer(ctx context.Context, in OfferInput, env SetupEnv) (*OfferResult, error) {
	env.fill()
	if ctx == nil {
		return nil, errors.New("servicebridge: no context")
	}
	result := &OfferResult{Schema: OfferResultSchema, RailConfig: in.RailConfigPath, Steps: []SetupStep{}}
	// One run at a time per state directory, from before the journal is
	// read: two runs would draw two Capability nonces and overwrite each
	// other's step records.
	config, release, err := loadConfigLocked(in.RailConfigPath)
	if errors.Is(err, ErrSetupBusy) {
		return result, err
	}
	if err != nil {
		return result, fmt.Errorf("%w; run `openfox earning service init` first", err)
	}
	defer release()
	in.fill(config.StateDir)
	if err = in.validate(); err != nil {
		return result, err
	}
	if !agentIDPattern.MatchString(config.AgentID) || !rawAddressPattern.MatchString(config.WalletAddress) ||
		!cleanAbsolute(config.GlobalConfigFile) || !cleanAbsolute(config.StateDir) ||
		!walletNamePattern.MatchString(config.PacketController) {
		return result, errors.New("servicebridge: the rail configuration lacks the Agent, wallet address or chain " +
			"global configuration `init` records; run `openfox earning service init` first")
	}
	executorPin, executorHow, err := pinExecutor(in, config.Provider)
	if err != nil {
		return result, err
	}
	result.ExecutorSHA256, result.ExecutorPin = executorPin, executorHow
	journal, err := loadSetupJournal(config.StateDir)
	if err != nil {
		return result, err
	}
	run := &setupRun{
		ctx: ctx, env: env, stateDir: config.StateDir, journal: journal, yes: in.Yes,
		endpoints: append([]string(nil), config.RPCEndpoints...),
	}
	defer func() { result.Steps = run.steps }()
	run.notef("executor.pin", SetupDone, "the executor is pinned to SHA-256 %s (%s)", executorPin,
		pinNoteFor(executorHow, "--executor-sha256"))
	runner, err := env.Runner(config.TOSCTL, env.vaultURL(config.TOSCTL))
	if err != nil {
		return result, err
	}
	ops := tosctlOps{runner: runner, globalConfig: config.GlobalConfigFile, networkLabel: config.Network.NetworkID}
	network := networkOf(config)
	code, err := os.ReadFile(config.RegistryCodeBOC)
	if err != nil || len(code) == 0 || len(code) > 1<<20 {
		return result, errors.New("servicebridge: the registry code file cannot be read")
	}
	locator, err := nativecore.NewLocator(network, 0, strings.Join(strings.Fields(string(code)), ""),
		config.RegistryCodeHash)
	if err != nil {
		return result, err
	}
	agent, err := locator.Locate(config.AgentID)
	if err != nil {
		return result, err
	}
	run.chain, err = env.OpenChain(config)
	if err != nil {
		return result, fmt.Errorf("servicebridge: open the finalized reader: %s",
			redactEndpoints(err.Error(), run.endpoints))
	}

	attestor, err := run.ensureController(ops, "controller.attestor", in.AttestorController)
	if err != nil {
		if errors.Is(err, ErrConfirmationRequired) {
			// The attestor key does not exist, so nothing that derives
			// from it can be shown. Everything the owner decides or pays
			// can: the run with --yes sends right after it creates the
			// key, so this preview is the one the owner confirms.
			preview, previewErr := offerPreviewBeforeKey(config, in, agent.Address)
			if previewErr != nil {
				return result, previewErr
			}
			result.Preview = preview
			reportOfferPreview(env, preview)
			run.notef("offer.preview", SetupPlanned, "the actor address, the manifest digest and the Capability id "+
				"derive from the attestor key, which does not exist yet; the run with --yes creates controller %q, "+
				"prints them and then sends the three messages above", in.AttestorController)
		}
		return result, err
	}
	identity := OfferIdentity{
		AgentID: config.AgentID, WalletAddress: config.WalletAddress, AttestorController: in.AttestorController,
		AttestorKeyID: attestor.Text(), Terms: in.Terms, Version: in.Version, RetentionSeconds: in.RetentionSeconds,
		ActorCodeHash: config.ActorCodeHash,
	}
	switch {
	case journal.Offer == nil:
		journal.Offer = &OfferJournal{Identity: identity}
	case journal.Offer.Identity != identity:
		if journal.Offer.sent() {
			return result, fmt.Errorf("%w: %s differs from the offer already sent for actor %s. Publishing it "+
				"would deploy a second Service Actor and register a second Capability. Re-run with the earlier "+
				"value to finish that offer; to change the terms of the published actor use `tosctl agent service "+
				"send --operation update-policy`", ErrSetupInputChanged,
				offerIdentityDifference(journal.Offer.Identity, identity), journal.Offer.Actor)
		}
		journal.Offer = &OfferJournal{Identity: identity}
	}
	state := journal.Offer
	if state.Stopped != "" {
		return result, fmt.Errorf("servicebridge: this offer was stopped and nothing more will be sent: %s. Inspect "+
			"the wallet's transactions and the tosctl service records; to continue, remove the \"stopped\" field "+
			"from %s", state.Stopped, setupJournalPath(config.StateDir))
	}

	// Everything that determines an identity is derived and durable before
	// anything is signed.
	actor, err := ops.actorAddress(ctx, config.WalletAddress, in.Terms, attestor)
	if err != nil {
		return result, fmt.Errorf("servicebridge: derive the Service Actor address: %w", err)
	}
	if state.Actor != "" && state.Actor != actor {
		return result, fmt.Errorf("%w: these inputs now derive actor %s, but the journal planned %s",
			ErrSetupInputChanged, actor, state.Actor)
	}
	state.Actor = actor
	if !state.Deploy.sent() {
		state.DeployFundingNano = in.DeployFundingNano
	}
	manifestCBOR, digest, _, err := BuildManifest(ManifestInput{
		ProviderAgentID: config.AgentID, Actor: actor, ActorCodeHash: config.ActorCodeHash, Attestor: attestor.Text(),
		Version: in.Version, RetentionSeconds: in.RetentionSeconds,
	})
	if err != nil {
		return result, err
	}
	state.ManifestDigest = digest
	if state.CapabilityNonce == "" || state.CapabilityObjectNonce == "" {
		if state.CapabilityNonce, err = env.nonce(); err != nil {
			return result, err
		}
		if state.CapabilityObjectNonce, err = env.nonce(); err != nil {
			return result, err
		}
	}
	objectNonce, err := hex.DecodeString(state.CapabilityObjectNonce)
	if err != nil {
		return result, errors.New("servicebridge: the journal holds an invalid Capability nonce")
	}
	capabilityID, err := nativecore.DeriveCapabilityID(network, objectNonce, config.AgentID,
		&nativev1.CapabilityVersionV1{Version: in.Version, ManifestDigest: digest})
	if err != nil {
		return result, err
	}
	capability, err := locator.Locate(capabilityID)
	if err != nil {
		return result, err
	}
	state.CapabilityID, state.CapabilityAddress = capabilityID, capability.Address
	metadata, err := nativecore.ServiceActorMetadataHash(nativecore.ServiceActorMetadataInputV1{
		Network: network, CapabilityID: capabilityID, ProviderAgentID: config.AgentID, CapabilityVersion: in.Version,
		ManifestDigest: digest,
	})
	if err != nil {
		return result, err
	}
	state.MetadataHash = hex.EncodeToString(metadata[:])
	if err = run.save(); err != nil {
		return result, err
	}

	total, perCall, err := offerValues(state.DeployFundingNano, in.Terms)
	if err != nil {
		return result, err
	}
	proof := nativecore.ServiceActorSoftwareWorkProofScheme
	result.Preview = &OfferPreview{
		OwnerWallet: config.WalletAddress, ProviderAgentID: config.AgentID, ProviderAgent: agent.Address,
		Actor: actor, ActorCodeHash: config.ActorCodeHash, AttestorController: in.AttestorController,
		AttestorKeyID: attestor.Text(), Terms: in.Terms, Version: in.Version, ManifestDigest: digest,
		CapabilityID: capabilityID, CapabilityAddress: capability.Address, MetadataHash: state.MetadataHash,
		ProofSchemeHash:   hex.EncodeToString(proof[:]),
		DeployFundingNano: fmt.Sprint(state.DeployFundingNano), RegistryValueNano: fmt.Sprint(RegistryMessageValueNano),
		PolicyValueNano: fmt.Sprint(PolicyMessageValueNano), TotalAttachedNano: fmt.Sprint(total),
		BuyerAttachesNano: fmt.Sprint(perCall), Note: offerPreviewNote,
	}
	reportOfferPreview(env, result.Preview)

	wallet, err := ops.wallet(ctx, config.WalletName)
	if err != nil {
		return result, err
	}
	if wallet.Address != config.WalletAddress {
		return result, fmt.Errorf("servicebridge: tosctl wallet %q is now %s, not the wallet_address %s of the rail "+
			"configuration", config.WalletName, wallet.Address, config.WalletAddress)
	}
	run.wallet = &wallet

	err = run.runStep("actor.deploy", "the deployment of Service Actor "+actor, &state.Deploy,
		actorEffect(ctx, actor, config.ActorCodeHash, config.WalletAddress, attestor), func() error {
			needed, addErr := checkedAdd(total, 3*walletFeeMarginNano)
			if addErr != nil {
				return notSent(addErr)
			}
			if fundErr := requireFundedWallet(wallet, needed, "publishing the offer"); fundErr != nil {
				return notSent(fundErr)
			}
			deployed, deployErr := ops.deployActor(ctx, config.WalletName, config.WalletAddress,
				"openfox-"+actor[2:10], in.Terms, in.AttestorController, state.DeployFundingNano)
			if deployErr != nil {
				return deployErr
			}
			if deployed != actor {
				return &contradictionError{err: fmt.Errorf("tosctl deployed and funded %s, not the planned actor %s",
					deployed, actor)}
			}
			return nil
		})
	var contradiction *contradictionError
	if errors.As(err, &contradiction) {
		state.Stopped = contradiction.Error()
		return result, errors.Join(fmt.Errorf("servicebridge: %w; the offer is stopped and nothing more will be sent",
			err), run.save())
	}
	if err != nil {
		return result, err
	}

	manifestDir := filepath.Join(config.StateDir, "manifests")
	if err = ensurePrivateDirectory(manifestDir); err != nil {
		return result, err
	}
	manifestFile := filepath.Join(manifestDir, strings.TrimPrefix(digest, "sha256:")+".cbor")
	if err = replaceSynced(manifestFile, manifestCBOR); err != nil {
		return result, err
	}

	err = run.runStep("capability.register", "the registration of Capability "+capabilityID, &state.Capability,
		capabilityEffect(ctx, capabilityID, config.AgentID, in.Version, digest), func() error {
			message, buildErr := ops.registerCapability(ctx, agent.Address, state.CapabilityNonce,
				state.CapabilityObjectNonce, in.Version, strings.TrimPrefix(digest, "sha256:"),
				config.PacketController)
			if buildErr != nil {
				return notSent(fmt.Errorf("servicebridge: build the Capability registration: %w", buildErr))
			}
			if message.FinalTarget != capability.Address || message.Destination != agent.Address {
				return notSent(errors.New("servicebridge: tosctl built a registration for another Capability or " +
					"Agent address than the ones derived here; nothing was sent"))
			}
			state.Registration = &message
			// Building and signing the registration took time the wallet
			// message's lifetime does not include: the window starts now.
			if saveErr := run.handoff(&state.Capability); saveErr != nil {
				return notSent(saveErr)
			}
			return ops.walletSend(ctx, config.WalletName, RegistryMessageValueNano, message)
		})
	if err != nil {
		return result, err
	}

	err = run.runStep("actor.policy", "the policy of actor "+actor+" for this Capability version", &state.Policy,
		policyEffect(ctx, actor, in.Terms, metadata), func() error {
			return ops.updatePolicy(ctx, config.WalletName, actor, in.Terms, state.MetadataHash,
				hex.EncodeToString(proof[:]))
		})
	if err != nil {
		return result, err
	}

	config.Provider = &ProviderNode{
		CapabilityID: capabilityID, Version: in.Version, ManifestFile: manifestFile,
		AttestorController: in.AttestorController, RespondBudgetSecond: in.RespondBudgetSeconds,
		ExecutorBinary: in.ExecutorBinary, ExecutorSHA256: executorPin, ContainerdSocket: in.ContainerdSocket,
		FIFODir: in.FIFODir,
	}
	session, err := run.begin()
	if err != nil {
		return result, err
	}
	checks, verified := verifyProviderOffer(ctx, config, session)
	result.Verification = checks
	if !verified {
		var failed []string
		for _, check := range checks {
			if check.Status != CheckPass {
				failed = append(failed, check.ID+": "+check.Message)
			}
		}
		return result, fmt.Errorf("servicebridge: the published offer does not pass the preflight's chain checks, "+
			"so the configuration was not changed: %s", strings.Join(failed, "; "))
	}
	run.notef("offer.verify", SetupDone, "the offer passes the preflight's manifest, Capability, actor, attestor and "+
		"admission checks at checkpoint %d", session.Checkpoint())
	// `status` lists the provider's records from this directory; it exists
	// from the moment the node is a provider, not only once `serve` ran.
	if err = ensurePrivateDirectory(filepath.Join(config.StateDir, "provider")); err != nil {
		return result, err
	}
	if err = writeNodeConfig(in.RailConfigPath, config); err != nil {
		return result, err
	}
	run.notef("config.write", SetupDone, "wrote the provider section of %s", in.RailConfigPath)
	if err = writeOfferFile(in.OfferPath, Offer{
		CapabilityID: capabilityID, Version: in.Version, ProviderAgentID: config.AgentID, ManifestDigest: digest,
		ManifestCBOR: manifestCBOR,
	}, env.Now()); err != nil {
		return result, err
	}
	result.OfferFile = in.OfferPath
	run.notef("offer.file", SetupDone, "wrote the offer file %s; give it to buyers (it holds nothing secret)",
		in.OfferPath)
	result.Confirmed = true
	result.NextSteps = []string{
		"openfox earning service preflight --rail-config " + in.RailConfigPath,
		"openfox earning service serve --rail-config " + in.RailConfigPath,
	}
	return result, nil
}
