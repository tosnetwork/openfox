// Command openfox-messenger-lab-deploy installs a reproducible, same-host
// seven-service systemd-user deployment for the encrypted three-OpenFox lab.
// It writes no plaintext conversation data and never prints Relay credentials.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	aliceID = "agent_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	bobID   = "agent_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	carolID = "agent_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

var (
	safePathPattern  = regexp.MustCompile(`^/[A-Za-z0-9_./-]+$`)
	safeLabelPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	safeTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
)

type options struct {
	unitDir, envFile, stateDir                     string
	relayBin, proxyBin, driverBin, openfoxAgentBin string
	roomLabel                                      string
	replaceUnits, check                            bool
}

type installResult struct {
	Schema               string     `json:"schema"`
	CheckOnly            bool       `json:"check_only"`
	EnvironmentCreated   bool       `json:"environment_created"`
	CredentialsCreated   []string   `json:"credentials_created"`
	CredentialsUnchanged []string   `json:"credentials_unchanged"`
	UnitsChanged         []string   `json:"units_changed"`
	UnitsUnchanged       []string   `json:"units_unchanged"`
	BootstrapRequired    bool       `json:"bootstrap_required"`
	BootstrapArgs        []string   `json:"bootstrap_args,omitempty"`
	ActivationArgs       [][]string `json:"activation_args"`
}

func main() {
	unitDir := flag.String("unit-dir", "", "absolute systemd user unit directory")
	envFile := flag.String("env-file", "", "absolute mode-0600 Relay credential file")
	stateDir := flag.String("state-dir", "", "absolute private Messenger/OpenFox lab state directory")
	relayBin := flag.String("relay-bin", "", "absolute tos-messenger-lab-group executable")
	proxyBin := flag.String("proxy-bin", "", "absolute tos-messenger-openfox-mls executable")
	driverBin := flag.String("driver-bin", "", "absolute tos-openmls-driver executable")
	openfoxAgentBin := flag.String("openfox-agent-bin", "", "absolute openfox-messenger-lab-agent executable")
	roomLabel := flag.String("room-label", "encrypted-builders", "safe deterministic room label")
	replaceUnits := flag.Bool("replace-units", false, "atomically replace differing regular unit files")
	check := flag.Bool("check", false, "validate inputs and planned output without writing")
	flag.Parse()
	result, err := install(options{
		unitDir: *unitDir, envFile: *envFile, stateDir: *stateDir,
		relayBin: *relayBin, proxyBin: *proxyBin, driverBin: *driverBin,
		openfoxAgentBin: *openfoxAgentBin, roomLabel: *roomLabel,
		replaceUnits: *replaceUnits, check: *check,
	}, rand.Reader)
	if err != nil {
		fmt.Fprintln(os.Stderr, "openfox-messenger-lab-deploy:", err)
		os.Exit(1)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, "openfox-messenger-lab-deploy:", err)
		os.Exit(1)
	}
}

func install(config options, random io.Reader) (installResult, error) {
	result := installResult{
		Schema: "openfox.messenger-lab-deploy.v1", CheckOnly: config.check,
		ActivationArgs: [][]string{
			{"systemctl", "--user", "daemon-reload"},
			{
				"systemctl", "--user", "enable", "--now", "tos-messenger-openfox-mls-relay.service",
				"tos-messenger-openfox-mls-alice.service", "tos-messenger-openfox-mls-bob.service",
				"tos-messenger-openfox-mls-carol.service", "openfox-messenger-agent-alice.service",
				"openfox-messenger-agent-bob.service", "openfox-messenger-agent-carol.service",
			},
		},
	}
	if err := validateOptions(config); err != nil {
		return result, err
	}
	for _, executable := range []string{config.relayBin, config.proxyBin, config.driverBin, config.openfoxAgentBin} {
		if err := validateExecutable(executable); err != nil {
			return result, err
		}
	}
	tokens, found, err := readTokens(config.envFile)
	if err != nil {
		return result, err
	}
	if !found {
		tokens, err = generateTokens(random)
		if err != nil {
			return result, err
		}
		result.EnvironmentCreated = true
	}
	agentCredentials := map[string][]byte{
		config.envFile + ".alice": []byte("ALICE_TOKEN=" + tokens["ALICE_TOKEN"] + "\n"),
		config.envFile + ".bob":   []byte("BOB_TOKEN=" + tokens["BOB_TOKEN"] + "\n"),
		config.envFile + ".carol": []byte("CAROL_TOKEN=" + tokens["CAROL_TOKEN"] + "\n"),
	}
	for path, body := range agentCredentials {
		changed, planErr := planFile(path, body, 0o600, false)
		if planErr != nil {
			return result, fmt.Errorf("Agent credential boundary: %w", planErr)
		}
		if changed {
			result.CredentialsCreated = append(result.CredentialsCreated, path)
		} else {
			result.CredentialsUnchanged = append(result.CredentialsUnchanged, path)
		}
	}
	units := renderUnits(config)
	for name, body := range units {
		changed, planErr := planFile(filepath.Join(config.unitDir, name), []byte(body), 0o644, config.replaceUnits)
		if planErr != nil {
			return result, planErr
		}
		if changed {
			result.UnitsChanged = append(result.UnitsChanged, name)
		} else {
			result.UnitsUnchanged = append(result.UnitsUnchanged, name)
		}
	}
	sort.Strings(result.UnitsChanged)
	sort.Strings(result.UnitsUnchanged)
	sort.Strings(result.CredentialsCreated)
	sort.Strings(result.CredentialsUnchanged)
	bootstrap, err := bootstrapState(config)
	if err != nil {
		return result, err
	}
	result.BootstrapRequired = bootstrap
	if bootstrap {
		result.BootstrapArgs = []string{
			config.proxyBin, "-mode", "bootstrap", "-driver", config.driverBin,
			"-state-dir", filepath.Join(config.stateDir, "agents"), "-creator", aliceID,
			"-label", config.roomLabel, "-member", aliceID, "-member", bobID, "-member", carolID,
		}
	}
	if config.check {
		return result, nil
	}
	for _, directory := range privateDirectories(config.stateDir) {
		if err := ensurePrivateDirectory(directory); err != nil {
			return result, err
		}
	}
	if !found {
		if err := writeNewFile(config.envFile, encodeTokens(tokens), 0o600); err != nil {
			return result, err
		}
	}
	for path, body := range agentCredentials {
		if contains(result.CredentialsCreated, path) {
			if err := writeNewFile(path, body, 0o600); err != nil {
				return result, err
			}
		}
	}
	if err := os.MkdirAll(config.unitDir, 0o755); err != nil {
		return result, fmt.Errorf("create unit directory: %w", err)
	}
	for name, body := range units {
		path := filepath.Join(config.unitDir, name)
		changed := contains(result.UnitsChanged, name)
		if changed {
			if err := writeAtomic(path, []byte(body), 0o644, config.replaceUnits); err != nil {
				return result, err
			}
		}
	}
	return result, nil
}

func validateOptions(config options) error {
	for name, value := range map[string]string{
		"unit-dir": config.unitDir, "env-file": config.envFile,
		"state-dir": config.stateDir, "relay-bin": config.relayBin, "proxy-bin": config.proxyBin,
		"driver-bin": config.driverBin, "openfox-agent-bin": config.openfoxAgentBin,
	} {
		if !safeAbsolutePath(value) {
			return fmt.Errorf("%s must be a safe clean absolute path", name)
		}
	}
	if !safeLabelPattern.MatchString(config.roomLabel) {
		return errors.New("room-label must contain only safe non-whitespace characters")
	}
	if filepath.Dir(config.envFile) == config.stateDir ||
		strings.HasPrefix(config.envFile, config.stateDir+string(os.PathSeparator)) {
		return errors.New("credential file must be outside the writable service state tree")
	}
	for _, directory := range []string{
		config.unitDir, filepath.Dir(config.envFile), config.stateDir,
		filepath.Dir(config.relayBin), filepath.Dir(config.proxyBin), filepath.Dir(config.driverBin), filepath.Dir(config.openfoxAgentBin),
	} {
		if err := rejectSymlinkDirectoryComponents(directory); err != nil {
			return err
		}
	}
	return nil
}

func safeAbsolutePath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && safePathPattern.MatchString(path) &&
		!strings.Contains(path, "//")
}

func validateExecutable(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("executable is not a regular executable file: %s", path)
	}
	return nil
}

func rejectSymlinkDirectoryComponents(path string) error {
	separator := string(os.PathSeparator)
	current := separator
	for _, component := range strings.Split(strings.TrimPrefix(filepath.Clean(path), separator), separator) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("deployment directory component is not a real directory: %s", current)
		}
	}
	return nil
}

func readTokens(path string) (map[string]string, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 ||
		info.Size() > 4096 {
		return nil, false, errors.New("existing credential file must be a bounded regular mode-0600 file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(lines) != 3 || !strings.HasSuffix(string(raw), "\n") {
		return nil, false, errors.New("credential file must contain exactly three newline-terminated entries")
	}
	tokens := make(map[string]string, 3)
	for _, line := range lines {
		name, value, ok := strings.Cut(line, "=")
		if !ok || !safeTokenPattern.MatchString(value) || tokens[name] != "" {
			return nil, false, errors.New("credential file contains an invalid entry")
		}
		tokens[name] = value
	}
	if tokens["ALICE_TOKEN"] == "" || tokens["BOB_TOKEN"] == "" || tokens["CAROL_TOKEN"] == "" ||
		tokens["ALICE_TOKEN"] == tokens["BOB_TOKEN"] || tokens["ALICE_TOKEN"] == tokens["CAROL_TOKEN"] ||
		tokens["BOB_TOKEN"] == tokens["CAROL_TOKEN"] {
		return nil, false, errors.New("credential file must contain three distinct Agent tokens")
	}
	return tokens, true, nil
}

func generateTokens(random io.Reader) (map[string]string, error) {
	tokens := make(map[string]string, 3)
	for _, name := range []string{"ALICE_TOKEN", "BOB_TOKEN", "CAROL_TOKEN"} {
		raw := make([]byte, 32)
		if _, err := io.ReadFull(random, raw); err != nil {
			return nil, errors.New("generate Relay credentials")
		}
		tokens[name] = hex.EncodeToString(raw)
	}
	if tokens["ALICE_TOKEN"] == tokens["BOB_TOKEN"] || tokens["ALICE_TOKEN"] == tokens["CAROL_TOKEN"] ||
		tokens["BOB_TOKEN"] == tokens["CAROL_TOKEN"] {
		return nil, errors.New("random source produced duplicate Relay credentials")
	}
	return tokens, nil
}

func encodeTokens(tokens map[string]string) []byte {
	return []byte("ALICE_TOKEN=" + tokens["ALICE_TOKEN"] + "\nBOB_TOKEN=" + tokens["BOB_TOKEN"] +
		"\nCAROL_TOKEN=" + tokens["CAROL_TOKEN"] + "\n")
}

func bootstrapState(config options) (bool, error) {
	paths := []string{
		filepath.Join(config.stateDir, "agents", aliceID+".json"),
		filepath.Join(
			config.stateDir,
			"agents",
			bobID+".json",
		),
		filepath.Join(config.stateDir, "agents", carolID+".json"),
	}
	found := 0
	for _, path := range paths {
		info, err := os.Lstat(path)
		if err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 &&
			info.Mode().Perm() == 0o600 && info.Size() <= 64<<20 {
			found++
			continue
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
		if err == nil {
			return false, errors.New("Agent MLS state path is not a regular file")
		}
	}
	if found != 0 && found != len(paths) {
		return false, errors.New("partial Agent MLS bootstrap state is refused")
	}
	return found == 0, nil
}

func privateDirectories(root string) []string {
	processes := filepath.Join(root, "openfox-processes")
	return []string{
		root, filepath.Join(root, "agents"), processes,
		filepath.Join(processes, "alice-agent-workspace"), filepath.Join(processes, "bob-agent-workspace"),
		filepath.Join(processes, "carol-agent-workspace"),
	}
}

func ensurePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if mkdirErr := os.MkdirAll(path, 0o700); mkdirErr != nil {
			return mkdirErr
		}
		return nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return fmt.Errorf("private state directory must be a real mode-0700 directory: %s", path)
	}
	return nil
}

func planFile(path string, want []byte, mode os.FileMode, replace bool) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("deployment target is not a regular file: %s", path)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	if string(got) == string(want) && info.Mode().Perm() == mode {
		return false, nil
	}
	if !replace {
		return false, fmt.Errorf("deployment target differs; use -replace-units: %s", path)
	}
	return true, nil
}

func writeNewFile(path string, body []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err = file.Write(body); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		_ = os.Remove(path)
		return err
	}
	if closeErr != nil {
		_ = os.Remove(path)
		return closeErr
	}
	return syncDirectory(filepath.Dir(path))
}

func writeAtomic(path string, body []byte, mode os.FileMode, replace bool) error {
	changed, err := planFile(path, body, mode, replace)
	if err != nil {
		return err
	}
	if !changed {
		return nil
	}
	if _, statErr := os.Lstat(path); errors.Is(statErr, os.ErrNotExist) {
		// O_EXCL preserves the no-substitution boundary if another writer creates
		// the target after planning. Only an explicitly authorized replacement
		// of an existing regular file uses rename below.
		return writeNewFile(path, body, mode)
	} else if statErr != nil {
		return statErr
	}
	temporary := filepath.Join(
		filepath.Dir(path),
		fmt.Sprintf(".%s.%d.%d.tmp", filepath.Base(path), os.Getpid(), time.Now().UnixNano()),
	)
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	cleanup := true
	defer func() {
		_ = file.Close()
		if cleanup {
			_ = os.Remove(temporary)
		}
	}()
	if _, err := file.Write(body); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	cleanup = false
	return syncDirectory(filepath.Dir(path))
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	err = directory.Sync()
	closeErr := directory.Close()
	return errors.Join(err, closeErr)
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func renderUnits(config options) map[string]string {
	values := map[string]string{
		"{{ENV}}": config.envFile, "{{STATE}}": config.stateDir,
		"{{RELAY}}": config.relayBin, "{{PROXY}}": config.proxyBin, "{{DRIVER}}": config.driverBin,
		"{{OPENFOX}}": config.openfoxAgentBin, "{{LABEL}}": config.roomLabel,
		"{{ALICE}}": aliceID, "{{BOB}}": bobID, "{{CAROL}}": carolID,
	}
	render := func(template string) string {
		for old, value := range values {
			template = strings.ReplaceAll(template, old, value)
		}
		return template
	}
	units := map[string]string{
		"tos-messenger-openfox-mls-relay.service": render(relayUnit),
	}
	for _, agent := range []struct{ name, id, token string }{{"alice", aliceID, "ALICE_TOKEN"}, {"bob", bobID, "BOB_TOKEN"}, {"carol", carolID, "CAROL_TOKEN"}} {
		unit := strings.ReplaceAll(proxyUnit, "{{NAME}}", agent.name)
		unit = strings.ReplaceAll(unit, "{{AGENT}}", agent.id)
		unit = strings.ReplaceAll(unit, "{{TOKEN}}", agent.token)
		unit = strings.ReplaceAll(unit, "{{AGENT_ENV}}", config.envFile+"."+agent.name)
		units["tos-messenger-openfox-mls-"+agent.name+".service"] = render(unit)
		agentTemplate := strings.ReplaceAll(openfoxUnit, "{{NAME}}", agent.name)
		agentTemplate = strings.ReplaceAll(agentTemplate, "{{AGENT}}", agent.id)
		agentTemplate = strings.ReplaceAll(agentTemplate, "{{TOKEN}}", agent.token)
		agentTemplate = strings.ReplaceAll(agentTemplate, "{{AGENT_ENV}}", config.envFile+"."+agent.name)
		creator := ""
		dependencies := ""
		if agent.name == "alice" {
			creator = " -create-room"
		} else {
			dependencies = " openfox-messenger-agent-alice.service"
		}
		agentTemplate = strings.ReplaceAll(agentTemplate, "{{CREATOR}}", creator)
		agentTemplate = strings.ReplaceAll(agentTemplate, "{{DEPENDENCY}}", dependencies)
		units["openfox-messenger-agent-"+agent.name+".service"] = render(agentTemplate)
	}
	return units
}

const relayUnit = `[Unit]
Description=Opaque local Relay for encrypted OpenFox MLS acceptance
After=default.target

[Service]
Type=simple
EnvironmentFile={{ENV}}
ExecStart={{RELAY}} --socket %t/tos-messenger-openfox-mls-relay.sock --state {{STATE}}/relay.json --agent {{ALICE}}=${ALICE_TOKEN} --agent {{BOB}}=${BOB_TOKEN} --agent {{CAROL}}=${CAROL_TOKEN}
Restart=on-failure
RestartSec=2s
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictAddressFamilies=AF_UNIX
ReadWritePaths={{STATE}} %t

[Install]
WantedBy=default.target
`

const proxyUnit = `[Unit]
Description=Private OpenMLS proxy for OpenFox Agent {{NAME}}
Requires=tos-messenger-openfox-mls-relay.service
After=tos-messenger-openfox-mls-relay.service

[Service]
Type=simple
EnvironmentFile={{AGENT_ENV}}
ExecStart={{PROXY}} -mode serve -driver {{DRIVER}} -state {{STATE}}/agents/{{AGENT}}.json -agent-id {{AGENT}} -token ${` + "{{TOKEN}}" + `} -socket %t/tos-messenger-openfox-mls-{{NAME}}.sock -relay-socket %t/tos-messenger-openfox-mls-relay.sock
Restart=on-failure
RestartSec=2s
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictAddressFamilies=AF_UNIX
ReadWritePaths={{STATE}} %t

[Install]
WantedBy=default.target
`

const openfoxUnit = `[Unit]
Description=Independent OpenFox Messenger lab Agent {{NAME}}
Requires=tos-messenger-openfox-mls-{{NAME}}.service{{DEPENDENCY}}
After=tos-messenger-openfox-mls-{{NAME}}.service{{DEPENDENCY}}

[Service]
Type=simple
EnvironmentFile={{AGENT_ENV}}
ExecStart={{OPENFOX}} -agent-id {{AGENT}} -token ${` + "{{TOKEN}}" + `} -socket %t/tos-messenger-openfox-mls-{{NAME}}.sock -cursor {{STATE}}/openfox-processes/{{NAME}}-cursor.json -state {{STATE}}/openfox-processes/{{NAME}}-state.json -control-socket %t/openfox-messenger-agent-{{NAME}}.sock -room-label {{LABEL}} -member {{ALICE}} -member {{BOB}} -member {{CAROL}}{{CREATOR}} -trigger-prefix process-probe: -reply-prefix ack-from- -reply-mode agent-loop -agent-workspace {{STATE}}/openfox-processes/{{NAME}}-agent-workspace
Restart=on-failure
RestartSec=2s
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictAddressFamilies=AF_UNIX
ReadWritePaths={{STATE}}/openfox-processes %t

[Install]
WantedBy=default.target
`
