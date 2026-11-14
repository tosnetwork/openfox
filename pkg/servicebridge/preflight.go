package servicebridge

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/serviceactor"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
)

// The preflight report schema. PreflightVersion changes only when a field
// changes meaning or is removed; new checks may appear within a version.
const (
	PreflightSchema  = "tos.openfox.provider-preflight"
	PreflightVersion = 1
)

// Check outcomes. Only fail makes the report fail.
const (
	CheckPass    = "pass"
	CheckFail    = "fail"
	CheckWarn    = "warn"
	CheckUnknown = "unknown"
)

// Thresholds the preflight states in its messages.
const (
	// MinStateDirFreeBytes is the free space the state directory needs:
	// room for the inbox bounds, the executor's artifact store and records.
	MinStateDirFreeBytes uint64 = 1 << 30
	// ClockSkewWarning is the distance from the finalized checkpoint's
	// chain time above which the local clock is reported. It includes the
	// checkpoint block's age, so it is a bound, not a precise skew.
	ClockSkewWarning = 30 * time.Second
)

// PreflightCheck is one check's outcome.
type PreflightCheck struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

// PreflightReport is the machine-readable provider preflight result. OK is
// false when any check failed.
type PreflightReport struct {
	Schema          string           `json:"schema"`
	Version         int              `json:"version"`
	GeneratedUnix   int64            `json:"generated_unix"`
	OK              bool             `json:"ok"`
	AdmissionPaused bool             `json:"admission_paused"`
	Checks          []PreflightCheck `json:"checks"`
}

// PreflightChain is the read-only chain access the preflight needs.
type PreflightChain interface {
	Endpoints() []string
	CheckEndpointGenesis(ctx context.Context, endpoint string) error
	BeginPreflight(ctx context.Context) (serviceactor.Session, error)
}

// ReaderPreflightChain adapts the finalized Service Actor reader.
type ReaderPreflightChain struct{ Reader *toschain.ServiceActorReader }

// Endpoints implements PreflightChain.
func (c ReaderPreflightChain) Endpoints() []string { return c.Reader.Endpoints() }

// CheckEndpointGenesis implements PreflightChain.
func (c ReaderPreflightChain) CheckEndpointGenesis(ctx context.Context, endpoint string) error {
	return c.Reader.CheckEndpointGenesis(ctx, endpoint)
}

// BeginPreflight implements PreflightChain.
func (c ReaderPreflightChain) BeginPreflight(ctx context.Context) (serviceactor.Session, error) {
	return c.Reader.Begin(ctx)
}

// PreflightEnv supplies the preflight's effects; zero fields take the real
// implementations.
type PreflightEnv struct {
	Now func() time.Time
	// OpenChain opens a reader whose checkpoint fences live in
	// checkpointDir, a private scratch directory, so the preflight writes
	// nothing into state_dir.
	OpenChain func(config NodeConfig, checkpointDir string) (PreflightChain, error)
	// ProbeController resolves a vault controller's key ID without signing.
	ProbeController func(ctx context.Context, config NodeConfig, controller string) ([32]byte, error)
	FreeBytes       func(path string) (uint64, error)
	Euid            func() int
	Getenv          func(name string) string
}

func (e *PreflightEnv) fill() {
	if e.Now == nil {
		e.Now = time.Now
	}
	if e.Getenv == nil {
		e.Getenv = os.Getenv
	}
	if e.OpenChain == nil {
		e.OpenChain = func(config NodeConfig, checkpointDir string) (PreflightChain, error) {
			reader, err := openServiceActorReader(config, networkOf(config), checkpointDir)
			if err != nil {
				return nil, err
			}
			return ReaderPreflightChain{Reader: reader}, nil
		}
	}
	if e.ProbeController == nil {
		getenv := e.Getenv
		e.ProbeController = func(ctx context.Context, config NodeConfig, controller string) ([32]byte, error) {
			vault := ""
			if config.TOSCTL.VaultURLEnv != "" {
				vault = getenv(config.TOSCTL.VaultURLEnv)
			}
			return ProbeControllerKeyID(ctx, config.TOSCTL, vault, controller)
		}
	}
	if e.FreeBytes == nil {
		e.FreeBytes = freeBytes
	}
	if e.Euid == nil {
		e.Euid = os.Geteuid
	}
}

type preflight struct {
	ctx       context.Context
	env       PreflightEnv
	report    *PreflightReport
	config    NodeConfig
	endpoints []string
	passed    map[string]bool
	// From the local manifest.
	manifestDigest string
	actor          string
	attestor       [32]byte
	// From the chain.
	chain   PreflightChain
	session serviceactor.Session
	account *toschain.ActorAccount
}

func (p *preflight) addf(id, status, format string, arguments ...any) {
	message := p.redact(fmt.Sprintf(format, arguments...))
	p.report.Checks = append(p.report.Checks, PreflightCheck{ID: id, Status: status, Message: message})
	if status == CheckFail {
		p.report.OK = false
	}
	p.passed[id] = status == CheckPass || status == CheckWarn
}

// requires records id as not run unless every dependency passed.
func (p *preflight) requires(id string, dependencies ...string) bool {
	for _, dependency := range dependencies {
		if !p.passed[dependency] {
			p.addf(id, CheckUnknown, "not run: %s did not pass", dependency)
			return false
		}
	}
	return true
}

// redact replaces configured endpoint URLs, whose paths may carry access
// tokens, with their positions.
func (p *preflight) redact(message string) string {
	for index, endpoint := range p.endpoints {
		if endpoint != "" {
			message = strings.ReplaceAll(message, endpoint, fmt.Sprintf("rpc_endpoints[%d]", index))
		}
	}
	return message
}

// RunPreflight checks that a provider node is ready to admit paid work. It
// reads the configuration, local files and finalized chain state; it sends
// nothing to the chain, signs nothing and writes nothing into state_dir.
func RunPreflight(ctx context.Context, configPath string, env PreflightEnv) *PreflightReport {
	env.fill()
	p := &preflight{ctx: ctx, env: env, passed: map[string]bool{}, report: &PreflightReport{
		Schema: PreflightSchema, Version: PreflightVersion, GeneratedUnix: env.Now().Unix(), OK: true,
		Checks: []PreflightCheck{},
	}}
	if ctx == nil {
		p.addf("preflight", CheckFail, "no context")
		return p.report
	}
	config, err := LoadNodeConfig(configPath)
	if err != nil {
		p.addf(
			"config.parse",
			CheckFail,
			"%v; the file must be owner-only (0600) strict JSON with no unknown fields",
			err,
		)
		return p.report
	}
	p.config, p.endpoints = config, append([]string(nil), config.RPCEndpoints...)
	p.addf("config.parse", CheckPass, "the rail configuration parses strictly")
	p.checkProviderConfig()
	p.checkStateDir()
	p.checkPause()
	p.checkUser()
	p.checkTOSCTL()
	p.checkExecutor()
	p.checkContainerd()
	p.checkManifest()
	p.checkEndpoints()
	p.checkChain()
	p.checkSigners()
	return p.report
}

const providerSection = "config.provider section"

func (p *preflight) checkProviderConfig() {
	provider := p.config.Provider
	if provider == nil {
		p.addf("config.provider", CheckFail, "the rail configuration has no provider section")
		return
	}
	// Checks that only need the section to exist depend on this marker, so
	// one bad field does not hide every other finding.
	p.passed[providerSection] = true
	var problems []string
	if !agentIDPattern.MatchString(p.config.AgentID) {
		problems = append(problems, "agent_id is not agent_<64 hex>")
	}
	if !capabilityPattern.MatchString(provider.CapabilityID) {
		problems = append(problems, "provider.capability_id is not cap_<64 hex>")
	}
	if provider.Version == "" {
		problems = append(problems, "provider.version is empty")
	}
	if !walletNamePattern.MatchString(provider.AttestorController) {
		problems = append(problems, "provider.attestor_controller is not a valid controller name")
	}
	if !walletNamePattern.MatchString(p.config.PacketController) {
		problems = append(problems, "packet_controller is not a valid controller name")
	}
	if _, err := mldsa44.ParseKeyIDText(p.config.PacketKeyID); err != nil {
		problems = append(problems, "packet_key_id is not mldsa44:<key id>")
	}
	if !walletNamePattern.MatchString(p.config.WalletName) {
		problems = append(problems, "wallet_name is not a valid wallet name")
	}
	if provider.RespondBudgetSecond <= 0 {
		problems = append(problems, "provider.respond_budget_seconds must be positive")
	}
	for name, path := range map[string]string{
		"provider.manifest_file": provider.ManifestFile, "provider.fifo_dir": provider.FIFODir,
		"messenger_socket": p.config.MessengerSocket, "receiver_socket": p.config.ReceiverSocket,
		"registry_code_boc_file": p.config.RegistryCodeBOC,
	} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			problems = append(problems, name+" must be an absolute clean path")
		}
	}
	if len(problems) > 0 {
		p.addf("config.provider", CheckFail, "%s", strings.Join(problems, "; "))
		return
	}
	p.addf("config.provider", CheckPass, "the provider section names a Capability, controllers and paths")
}

func (p *preflight) checkStateDir() {
	directory := p.config.StateDir
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		p.addf("state_dir.private", CheckFail, "state_dir must be an absolute clean path")
		p.addf("state_dir.disk_free", CheckUnknown, "not run: state_dir.private did not pass")
		return
	}
	info, err := os.Lstat(directory)
	switch {
	case errors.Is(err, os.ErrNotExist):
		p.addf("state_dir.private", CheckFail, "state_dir %s does not exist; create it with mode 0700", directory)
	case err != nil:
		p.addf("state_dir.private", CheckFail, "state_dir %s cannot be inspected", directory)
	case info.Mode()&os.ModeSymlink != 0:
		p.addf("state_dir.private", CheckFail, "state_dir %s is a symbolic link; use the real directory", directory)
	case !info.IsDir():
		p.addf("state_dir.private", CheckFail, "state_dir %s is not a directory", directory)
	case info.Mode().Perm() != 0o700:
		p.addf("state_dir.private", CheckFail, "state_dir %s has mode %04o; run chmod 0700", directory,
			info.Mode().Perm())
	default:
		owned, ownerErr := ownedByCurrentUser(info)
		switch {
		case ownerErr != nil:
			p.addf("state_dir.private", CheckFail, "state_dir %s: %v", directory, ownerErr)
		case !owned:
			p.addf("state_dir.private", CheckFail, "state_dir %s is owned by another user; run the node as its owner",
				directory)
		default:
			p.addf("state_dir.private", CheckPass, "state_dir is an owner-only (0700) directory owned by this user")
		}
	}
	if !p.requires("state_dir.disk_free", "state_dir.private") {
		return
	}
	free, err := p.env.FreeBytes(directory)
	if err != nil {
		p.addf("state_dir.disk_free", CheckFail, "free space under state_dir cannot be measured: %v", err)
		return
	}
	if free < MinStateDirFreeBytes {
		p.addf("state_dir.disk_free", CheckFail, "%d bytes free under state_dir, below the required %d; free space",
			free, MinStateDirFreeBytes)
		return
	}
	p.addf("state_dir.disk_free", CheckPass, "%d bytes free under state_dir (at least %d required)", free,
		MinStateDirFreeBytes)
}

func (p *preflight) checkPause() {
	if !p.requires("admission.pause", "state_dir.private") {
		return
	}
	pause, err := ReadAdmissionPause(p.config.StateDir)
	if err != nil {
		p.report.AdmissionPaused = true
		p.addf("admission.pause", CheckFail, "%v; the node treats it as paused: remove it with "+
			"`openfox earning service resume` or fix its mode to 0600", err)
		return
	}
	if pause != nil {
		p.report.AdmissionPaused = true
		p.addf("admission.pause", CheckWarn, "new admissions are paused since %s; admitted work still completes; "+
			"run `openfox earning service resume` to admit again",
			time.Unix(pause.PausedUnix, 0).UTC().Format(time.RFC3339))
		return
	}
	p.addf("admission.pause", CheckPass, "new admissions are open")
}

func (p *preflight) checkUser() {
	if p.env.Euid() == 0 {
		p.addf("process.user", CheckWarn, "running as root; run the provider node as an unprivileged owner user")
		return
	}
	p.addf("process.user", CheckPass, "running as an unprivileged user")
}

func (p *preflight) checkTOSCTL() {
	if _, err := readPinnedBinary(p.config.TOSCTL.Binary, p.config.TOSCTL.SHA256, "tosctl"); err != nil {
		p.addf("tosctl.pin", CheckFail, "%v; set tosctl.binary and tosctl.sha256 to the installed release", err)
	} else {
		p.addf("tosctl.pin", CheckPass, "tosctl matches its pinned SHA-256")
	}
	path := p.config.TOSCTL.ConfigPath
	info, err := os.Stat(path)
	switch {
	case !filepath.IsAbs(path) || filepath.Clean(path) != path:
		p.addf("tosctl.config", CheckFail, "tosctl.config_path must be an absolute clean path")
	case err != nil || !info.Mode().IsRegular():
		p.addf("tosctl.config", CheckFail, "tosctl.config_path %s is not a readable regular file", path)
	case info.Mode().Perm()&0o007 != 0:
		p.addf("tosctl.config", CheckFail, "tosctl.config_path %s is accessible to every user; run chmod o-rwx", path)
	default:
		p.addf("tosctl.config", CheckPass, "the tosctl configuration file exists and is not world-accessible")
	}
	switch name := p.config.TOSCTL.VaultURLEnv; {
	case name == "":
		p.addf(
			"tosctl.vault_env",
			CheckWarn,
			"tosctl.vault_url_env is empty; tosctl uses the vault its configuration names",
		)
	case p.env.Getenv(name) == "":
		p.addf(
			"tosctl.vault_env",
			CheckFail,
			"the environment variable %s named by tosctl.vault_url_env is not set",
			name,
		)
	default:
		p.addf("tosctl.vault_env", CheckPass, "the vault URL environment variable %s is set (value not shown)", name)
	}
}

func (p *preflight) checkExecutor() {
	if !p.requires("executor.pin", providerSection) {
		return
	}
	provider := p.config.Provider
	if _, err := readPinnedBinary(provider.ExecutorBinary, provider.ExecutorSHA256, "executor"); err != nil {
		p.addf("executor.pin", CheckFail, "%v; set provider.executor_binary and provider.executor_sha256", err)
		return
	}
	p.addf("executor.pin", CheckPass, "the executor matches its pinned SHA-256")
}

// checkContainerd inspects the socket without connecting to it.
func (p *preflight) checkContainerd() {
	if !p.requires("containerd.socket", providerSection) {
		return
	}
	path := p.config.Provider.ContainerdSocket
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		p.addf("containerd.socket", CheckFail, "provider.containerd_socket must be an absolute clean path")
		return
	}
	info, err := os.Lstat(path)
	switch {
	case err != nil:
		p.addf(
			"containerd.socket",
			CheckFail,
			"the container runtime socket %s is not present; start the runtime",
			path,
		)
	case info.Mode()&os.ModeSocket == 0:
		p.addf(
			"containerd.socket",
			CheckFail,
			"%s is not a socket (a symbolic link is refused; name the socket itself)",
			path,
		)
	case info.Mode().Perm()&0o007 != 0:
		p.addf("containerd.socket", CheckFail, "the container runtime socket %s is accessible to every user "+
			"(mode %04o); restrict it to its group", path, info.Mode().Perm())
	default:
		p.addf("containerd.socket", CheckPass, "the container runtime socket is present and not world-accessible "+
			"(not connected to)")
	}
}

func (p *preflight) checkManifest() {
	if !p.requires("manifest.local", providerSection) {
		return
	}
	raw, err := os.ReadFile(p.config.Provider.ManifestFile)
	if err != nil || len(raw) == 0 || len(raw) > 1<<20 {
		p.addf("manifest.local", CheckFail, "provider.manifest_file cannot be read; build it with "+
			"`openfox earning service manifest`")
		return
	}
	manifest, err := nativecore.DecodeCanonicalSoftwareWorkManifestCBOR(raw)
	if err != nil {
		p.addf("manifest.local", CheckFail, "provider.manifest_file is not a canonical software-work manifest: %v", err)
		return
	}
	canonical, digest, err := nativecore.CanonicalSoftwareWorkManifest(manifest)
	if err != nil || !bytes.Equal(canonical, raw) {
		p.addf("manifest.local", CheckFail, "provider.manifest_file is not in canonical encoding")
		return
	}
	settlement := manifest.Settlement
	var problems []string
	if settlement.Rail != nativecore.ServiceActorRail || settlement.ActorWorkchain != 0 ||
		len(settlement.ActorAccountID) != 32 {
		problems = append(problems, "manifest key 21 does not name a workchain 0 Service Actor")
	}
	if "tvm-cell-sha256:"+hex.EncodeToString(settlement.ActorCodeHash) != p.config.ActorCodeHash {
		problems = append(problems, "manifest key 21 actor code hash differs from actor_code_hash")
	}
	attestor, attestorErr := mldsa44.ParseKeyIDText(settlement.AttestorKey)
	if attestorErr != nil {
		problems = append(problems, "manifest key 21 attestor is not mldsa44:<key id>")
	}
	if manifest.Version != p.config.Provider.Version {
		problems = append(problems, "the manifest version differs from provider.version")
	}
	if _, transport, transportErr := RailTransport(p.config.AgentID); transportErr != nil ||
		manifest.EndpointCommitment != transport {
		problems = append(problems, "manifest key 17 does not commit to Agent Packets to agent_id")
	}
	if len(problems) > 0 {
		p.addf("manifest.local", CheckFail, "%s", strings.Join(problems, "; "))
		return
	}
	p.manifestDigest, p.attestor = digest, attestor
	p.actor = "0:" + hex.EncodeToString(settlement.ActorAccountID)
	p.addf("manifest.local", CheckPass, "the local manifest %s names actor %s and attestor %s", digest, p.actor,
		mldsa44.KeyIDText(attestor))
}

func endpointHost(endpoint string) string {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return "unparseable"
	}
	return parsed.Host
}

func (p *preflight) checkEndpoints() {
	if _, err := newChainAdapter(p.config); err != nil {
		p.addf("rpc.endpoints", CheckFail, "%v; configure 3 to 8 distinct endpoints (HTTPS unless loopback) and a "+
			"strict-majority quorum", err)
	} else {
		p.addf("rpc.endpoints", CheckPass, "%d endpoints with quorum %d (a strict majority)",
			len(p.config.RPCEndpoints), effectiveQuorum(p.config))
	}
	p.addf("rpc.independence", CheckUnknown, "endpoints have distinct authorities, but whether distinct operators "+
		"run them is not verified; a quorum of one operator's endpoints is one point of trust")
}

func (p *preflight) checkChain() {
	if !p.requires("chain.open", "rpc.endpoints", providerSection) {
		p.skipChain("chain.open")
		return
	}
	scratch, err := os.MkdirTemp("", "openfox-preflight-")
	if err != nil {
		p.addf("chain.open", CheckFail, "create a private scratch directory for checkpoint fences")
		p.skipChain("chain.open")
		return
	}
	defer os.RemoveAll(scratch)
	if chmodErr := os.Chmod(scratch, 0o700); chmodErr != nil {
		p.addf("chain.open", CheckFail, "protect the scratch directory")
		p.skipChain("chain.open")
		return
	}
	p.chain, err = p.env.OpenChain(p.config, scratch)
	if err != nil {
		p.addf("chain.open", CheckFail, "%v; check registry_code_boc_file, registry_code_hash and actor_code_hash", err)
		p.skipChain("chain.open")
		return
	}
	p.addf("chain.open", CheckPass, "the finalized reader is configured")
	p.checkGenesis()
	p.session, err = p.chain.BeginPreflight(p.ctx)
	if err != nil {
		p.addf("chain.finalized", CheckFail, "no finalized checkpoint by strict majority: %v", err)
		p.skipChain("chain.finalized")
		return
	}
	p.addf("chain.finalized", CheckPass, "finalized checkpoint %d read by a strict majority", p.session.Checkpoint())
	p.checkClock()
	p.checkRegistry()
	p.checkActor()
	p.checkAdmission()
}

var chainChecks = []string{
	"rpc.genesis", "chain.finalized", "clock.skew", "chain.registry", "chain.capability", "chain.actor",
	"chain.attestor", "chain.admission",
}

func (p *preflight) skipChain(cause string) {
	for _, id := range chainChecks {
		if _, done := p.passed[id]; !done {
			p.addf(id, CheckUnknown, "not run: %s did not pass", cause)
		}
	}
}

func (p *preflight) checkGenesis() {
	endpoints := p.chain.Endpoints()
	matched, wrongNetwork := 0, false
	var failures []string
	for index, endpoint := range endpoints {
		if err := p.chain.CheckEndpointGenesis(p.ctx, endpoint); err != nil {
			var protocolErr *nativecore.ProtocolError
			if errors.As(err, &protocolErr) && protocolErr.Code == nativecore.ErrWrongNetwork {
				wrongNetwork = true
				failures = append(failures, fmt.Sprintf("rpc_endpoints[%d] (%s) serves another network: %v", index,
					endpointHost(endpoint), err))
				continue
			}
			failures = append(failures, fmt.Sprintf("rpc_endpoints[%d] (%s) unreachable: %v", index,
				endpointHost(endpoint), err))
			continue
		}
		matched++
	}
	quorum := effectiveQuorum(p.config)
	switch {
	case len(failures) == 0:
		p.addf("rpc.genesis", CheckPass, "every endpoint serves genesis root %s and file %s (network label %q is "+
			"bound only by these hashes)", p.config.Network.GenesisRootHash, p.config.Network.GenesisFileHash,
			p.config.Network.NetworkID)
	case wrongNetwork || matched < quorum:
		p.addf("rpc.genesis", CheckFail, "%d of %d endpoints match the configured genesis (quorum %d): %s", matched,
			len(endpoints), quorum, strings.Join(failures, "; "))
	default:
		p.addf("rpc.genesis", CheckWarn, "%d of %d endpoints match the configured genesis, still a quorum of %d: %s",
			matched, len(endpoints), quorum, strings.Join(failures, "; "))
	}
}

func (p *preflight) checkClock() {
	skew := p.env.Now().Sub(p.session.ChainTime())
	if skew < 0 {
		skew = -skew
	}
	if skew > ClockSkewWarning {
		p.addf("clock.skew", CheckWarn, "the local clock is %s from the finalized checkpoint time (warning above %s); "+
			"check time synchronization", skew.Round(time.Second), ClockSkewWarning)
		return
	}
	p.addf("clock.skew", CheckPass, "the local clock is within %s of the finalized checkpoint time (warning above %s)",
		skew.Round(time.Second), ClockSkewWarning)
}

func (p *preflight) checkRegistry() {
	provider := p.config.Provider
	state, found, err := p.session.ResolveRegistry(p.ctx, provider.CapabilityID)
	if err != nil {
		p.addf("chain.registry", CheckFail, "the Native Registry read failed (a code hash other than "+
			"registry_code_hash is refused): %v", err)
		p.addf("chain.capability", CheckUnknown, "not run: chain.registry did not pass")
		return
	}
	p.addf(
		"chain.registry",
		CheckPass,
		"the Native Registry account reads at the checkpoint under the pinned code hash",
	)
	capability := state.GetCapability()
	if !found || capability == nil {
		p.addf("chain.capability", CheckFail, "Capability %s is not in finalized state; register it first",
			provider.CapabilityID)
		return
	}
	var version *nativev1.CapabilityVersionV1
	for _, candidate := range capability.GetVersions() {
		if candidate.GetVersion() == provider.Version {
			version = candidate
		}
	}
	switch {
	case capability.GetTombstoned():
		p.addf("chain.capability", CheckFail, "Capability %s is tombstoned", provider.CapabilityID)
	case capability.GetOwnerAgentId() != p.config.AgentID:
		p.addf("chain.capability", CheckFail, "Capability %s is owned by %s, not agent_id %s", provider.CapabilityID,
			capability.GetOwnerAgentId(), p.config.AgentID)
	case version == nil:
		p.addf(
			"chain.capability",
			CheckFail,
			"Capability %s has no version %q",
			provider.CapabilityID,
			provider.Version,
		)
	case version.GetRevoked():
		p.addf("chain.capability", CheckFail, "Capability %s version %q is revoked", provider.CapabilityID,
			provider.Version)
	case p.manifestDigest == "":
		p.addf("chain.capability", CheckUnknown, "not run: manifest.local did not pass")
	case version.GetManifestDigest() != p.manifestDigest:
		p.addf("chain.capability", CheckFail, "the finalized manifest of version %q is %s, but provider.manifest_file "+
			"is %s", provider.Version, version.GetManifestDigest(), p.manifestDigest)
	default:
		p.addf("chain.capability", CheckPass, "Capability %s version %q is live, owned by agent_id and commits to the "+
			"local manifest", provider.CapabilityID, provider.Version)
	}
}

func (p *preflight) checkActor() {
	if p.actor == "" {
		p.addf("chain.actor", CheckUnknown, "not run: manifest.local did not pass")
		p.addf("chain.attestor", CheckUnknown, "not run: manifest.local did not pass")
		return
	}
	account, found, err := p.session.ReadActor(p.ctx, p.actor)
	if err != nil {
		p.addf("chain.actor", CheckFail, "the actor %s did not read (a code hash other than actor_code_hash is "+
			"refused): %v", p.actor, err)
		p.addf("chain.attestor", CheckUnknown, "not run: chain.actor did not pass")
		return
	}
	if !found || account == nil || account.Data == nil {
		p.addf("chain.actor", CheckFail, "the actor %s is not an active account at the checkpoint; deploy it", p.actor)
		p.addf("chain.attestor", CheckUnknown, "not run: chain.actor did not pass")
		return
	}
	p.account = account
	switch {
	case account.CodeHash != p.config.ActorCodeHash:
		p.addf("chain.actor", CheckFail, "the actor runs %s, not actor_code_hash %s", account.CodeHash,
			p.config.ActorCodeHash)
	case !account.Data.Active:
		p.addf("chain.actor", CheckFail, "the actor %s is deactivated; it admits no calls", p.actor)
	default:
		p.addf("chain.actor", CheckPass, "the actor %s is active and runs the pinned code hash", p.actor)
	}
	policy := account.Data.Policy
	switch {
	case !policy.HasAttestor:
		p.addf("chain.attestor", CheckFail, "the actor has no attestor (has_attestor = 0); the product refuses "+
			"attestor-less actors: rotate an attestor in with the owner wallet")
	case policy.AttestorKeyID != p.attestor:
		p.addf("chain.attestor", CheckFail, "the actor's attestor %s is not the manifest attestor %s",
			mldsa44.KeyIDText(policy.AttestorKeyID), mldsa44.KeyIDText(p.attestor))
	default:
		derived, err := mldsa44.KeyID(policy.AttestorKey)
		if err != nil || derived != policy.AttestorKeyID {
			p.addf("chain.attestor", CheckFail, "the actor's stored attestor key does not derive its key id")
			return
		}
		p.addf("chain.attestor", CheckPass, "the actor's attestor is the manifest attestor %s",
			mldsa44.KeyIDText(p.attestor))
	}
}

// checkAdmission runs the protocol's own admission verification (the binding
// steps plus actor policy, metadata, proof scheme and bounds), as a buyer
// would before calling.
func (p *preflight) checkAdmission() {
	for _, dependency := range []string{"chain.capability", "chain.actor", "chain.attestor"} {
		if !p.passed[dependency] {
			p.addf("chain.admission", CheckUnknown, "not run: %s did not pass", dependency)
			return
		}
	}
	raw, err := os.ReadFile(p.config.Provider.ManifestFile)
	if err != nil {
		p.addf("chain.admission", CheckFail, "provider.manifest_file cannot be read again")
		return
	}
	manifests := &MemoryManifests{}
	manifests.Put(p.manifestDigest, raw)
	evidence, err := serviceactor.Gather(p.ctx, p.session, networkOf(p.config), manifests,
		p.config.Provider.CapabilityID, p.config.Provider.Version)
	if err != nil {
		p.addf("chain.admission", CheckFail, "the admission evidence did not gather: %v", err)
		return
	}
	pinned, err := digestBytes32(p.config.ActorCodeHash, "tvm-cell-sha256:")
	if err != nil {
		p.addf("chain.admission", CheckFail, "actor_code_hash is not tvm-cell-sha256:<hex>")
		return
	}
	if _, err := serviceactor.VerifyAdmission(evidence, pinned, nil, nil, ""); err != nil {
		p.addf("chain.admission", CheckFail, "a buyer's admission check would refuse this offer: %v", err)
		return
	}
	p.addf("chain.admission", CheckPass, "the offer passes the protocol's admission verification at checkpoint %d",
		evidence.Checkpoint)
}

func digestBytes32(value, prefix string) ([32]byte, error) {
	var out [32]byte
	if !strings.HasPrefix(value, prefix) {
		return out, errors.New("invalid digest prefix")
	}
	return out, decodeHex32(strings.TrimPrefix(value, prefix), &out)
}

func (p *preflight) checkSigners() {
	if p.requires("signer.attestor", providerSection, "tosctl.pin", "tosctl.config") {
		keyID, err := p.env.ProbeController(p.ctx, p.config, p.config.Provider.AttestorController)
		switch {
		case err != nil:
			p.addf(
				"signer.attestor",
				CheckFail,
				"%v; create or restore the attestor controller in the tosctl vault",
				err,
			)
		case p.actor == "":
			p.addf("signer.attestor", CheckWarn, "controller %q resolves to %s, but the manifest attestor is unknown",
				p.config.Provider.AttestorController, mldsa44.KeyIDText(keyID))
		case keyID != p.attestor:
			p.addf("signer.attestor", CheckFail, "controller %q resolves to %s, not the manifest attestor %s; respond "+
				"would be refused", p.config.Provider.AttestorController, mldsa44.KeyIDText(keyID),
				mldsa44.KeyIDText(p.attestor))
		default:
			p.addf("signer.attestor", CheckPass, "controller %q resolves in the vault to the manifest attestor "+
				"(nothing was signed)", p.config.Provider.AttestorController)
		}
	}
	if p.requires("signer.packet", providerSection, "tosctl.pin", "tosctl.config") {
		expected, _ := mldsa44.ParseKeyIDText(p.config.PacketKeyID)
		keyID, err := p.env.ProbeController(p.ctx, p.config, p.config.PacketController)
		switch {
		case err != nil:
			p.addf("signer.packet", CheckFail, "%v; create or restore the packet controller in the tosctl vault", err)
		case keyID != expected:
			p.addf("signer.packet", CheckFail, "controller %q resolves to %s, not packet_key_id %s",
				p.config.PacketController, mldsa44.KeyIDText(keyID), p.config.PacketKeyID)
		default:
			p.addf("signer.packet", CheckPass, "controller %q resolves in the vault to packet_key_id (nothing was "+
				"signed)", p.config.PacketController)
		}
	}
	p.addf("signer.wallet", CheckUnknown, "tosctl offers no way to resolve wallet %q without signing, so the respond "+
		"wallet is not checked; preflight never signs", p.config.WalletName)
}
