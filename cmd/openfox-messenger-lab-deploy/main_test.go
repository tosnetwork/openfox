package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallCreatesPrivateIdempotentDeployment(t *testing.T) {
	config := deploymentFixture(t)
	random := deploymentRandom()
	result, installErr := install(config, random)
	if installErr != nil {
		t.Fatal(installErr)
	}
	if result.Schema != "openfox.messenger-lab-deploy.v1" || !result.EnvironmentCreated ||
		len(result.CredentialsCreated) != 3 || len(result.CredentialsUnchanged) != 0 ||
		len(result.UnitsChanged) != 7 || len(result.UnitsUnchanged) != 0 || !result.BootstrapRequired {
		t.Fatalf("unexpected fresh install result: %#v", result)
	}
	if len(result.BootstrapArgs) != 17 || result.BootstrapArgs[0] != config.proxyBin ||
		result.BootstrapArgs[6] != filepath.Join(config.stateDir, "agents") {
		t.Fatalf("unexpected bootstrap command: %#v", result.BootstrapArgs)
	}
	credentialInfo, statErr := os.Lstat(config.envFile)
	if statErr != nil || credentialInfo.Mode().Perm() != 0o600 || !credentialInfo.Mode().IsRegular() {
		t.Fatalf("credential file mode: info=%v err=%v", credentialInfo, statErr)
	}
	credentials, readErr := os.ReadFile(config.envFile)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if bytes.Count(credentials, []byte("\n")) != 3 || !bytes.Contains(credentials, []byte(strings.Repeat("11", 32))) {
		t.Fatalf("unexpected generated credential shape: %q", credentials)
	}
	for _, name := range []string{"alice", "bob", "carol"} {
		path := config.envFile + "." + name
		body, readErr := os.ReadFile(path)
		info, statErr := os.Lstat(path)
		if readErr != nil || statErr != nil || info.Mode().Perm() != 0o600 || bytes.Count(body, []byte("=")) != 1 {
			t.Fatalf(
				"least-privilege credential %s: body=%q info=%v read=%v stat=%v",
				name, body, info, readErr, statErr,
			)
		}
	}
	for _, directory := range privateDirectories(config.stateDir) {
		info, statErr := os.Lstat(directory)
		if statErr != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
			t.Fatalf("private directory %s: info=%v err=%v", directory, info, statErr)
		}
	}
	for _, name := range append(result.UnitsChanged[:0:0], result.UnitsChanged...) {
		body, readErr := os.ReadFile(filepath.Join(config.unitDir, name))
		if readErr != nil {
			t.Fatal(readErr)
		}
		containsSecret := bytes.Contains(body, []byte(strings.Repeat("11", 32))) ||
			bytes.Contains(body, []byte(strings.Repeat("22", 32))) ||
			bytes.Contains(body, []byte(strings.Repeat("33", 32)))
		if containsSecret || !bytes.Contains(body, []byte("NoNewPrivileges=true")) ||
			!bytes.Contains(body, []byte("ProtectSystem=strict")) ||
			!bytes.Contains(body, []byte("UMask=0077")) {
			t.Fatalf("unsafe or secret-bearing unit %s", name)
		}
		agentUnit := strings.HasPrefix(name, "openfox-messenger-agent-") ||
			strings.HasPrefix(name, "tos-messenger-openfox-mls-a") ||
			strings.HasPrefix(name, "tos-messenger-openfox-mls-b") ||
			strings.HasPrefix(name, "tos-messenger-openfox-mls-c")
		if agentUnit {
			if bytes.Contains(body, []byte("EnvironmentFile="+config.envFile+"\n")) {
				t.Fatalf("Agent unit inherited the Relay-wide credential file: %s", name)
			}
		}
	}
	second, retryErr := install(config, bytes.NewReader(nil))
	if retryErr != nil {
		t.Fatal(retryErr)
	}
	if second.EnvironmentCreated || len(second.UnitsChanged) != 0 || len(second.UnitsUnchanged) != 7 {
		t.Fatalf("exact retry was not idempotent: %#v", second)
	}
	if len(second.CredentialsCreated) != 0 || len(second.CredentialsUnchanged) != 3 {
		t.Fatalf("Agent credentials were not idempotent: %#v", second)
	}
	after, _ := os.ReadFile(config.envFile)
	if !bytes.Equal(after, credentials) {
		t.Fatal("exact retry rotated credentials")
	}
	for _, id := range []string{aliceID, bobID, carolID} {
		if err := os.WriteFile(
			filepath.Join(config.stateDir, "agents", id+".json"),
			[]byte("{}\n"),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
	}
	complete, err := install(config, bytes.NewReader(nil))
	if err != nil || complete.BootstrapRequired || len(complete.BootstrapArgs) != 0 {
		t.Fatalf("complete bootstrap was not recognized: result=%#v err=%v", complete, err)
	}
}

func TestInstallRefusesSubstitutionAndPartialState(t *testing.T) {
	config := deploymentFixture(t)
	if _, err := install(config, deploymentRandom()); err != nil {
		t.Fatal(err)
	}
	unit := filepath.Join(config.unitDir, "openfox-messenger-agent-alice.service")
	if err := os.WriteFile(unit, []byte("substituted\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := install(config, bytes.NewReader(nil)); err == nil || !strings.Contains(err.Error(), "differs") {
		t.Fatalf("unit substitution accepted: %v", err)
	}
	config.replaceUnits = true
	if _, err := install(config, bytes.NewReader(nil)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(unit); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(config.envFile, unit); err != nil {
		t.Fatal(err)
	}
	if _, err := install(
		config,
		bytes.NewReader(nil),
	); err == nil ||
		!strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("unit symlink accepted: %v", err)
	}
	if err := os.Remove(unit); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unit, []byte(renderUnits(config)[filepath.Base(unit)]), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.envFile+".bob", []byte("BOB_TOKEN=substituted-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := install(
		config,
		bytes.NewReader(nil),
	); err == nil ||
		!strings.Contains(err.Error(), "Agent credential boundary") {
		t.Fatalf("Agent credential substitution accepted: %v", err)
	}
	if err := os.Remove(config.envFile + ".bob"); err != nil {
		t.Fatal(err)
	}
	master, _, readErr := readTokens(config.envFile)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if err := writeNewFile(config.envFile+".bob", []byte("BOB_TOKEN="+master["BOB_TOKEN"]+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(config.stateDir, "agents", aliceID+".json"),
		[]byte("{}\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := install(config, bytes.NewReader(nil)); err == nil || !strings.Contains(err.Error(), "partial") {
		t.Fatalf("partial MLS state accepted: %v", err)
	}
}

func TestInstallRefusesCredentialAndInputWeakening(t *testing.T) {
	config := deploymentFixture(t)
	if err := os.MkdirAll(filepath.Dir(config.envFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		config.envFile,
		[]byte("ALICE_TOKEN=same-token-value\nBOB_TOKEN=same-token-value\nCAROL_TOKEN=other-token-value\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := install(config, bytes.NewReader(nil)); err == nil || !strings.Contains(err.Error(), "distinct") {
		t.Fatalf("duplicate credentials accepted: %v", err)
	}
	if err := os.Chmod(config.envFile, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := install(config, bytes.NewReader(nil)); err == nil || !strings.Contains(err.Error(), "mode-0600") {
		t.Fatalf("public credential file accepted: %v", err)
	}
	if err := os.Remove(config.envFile); err != nil {
		t.Fatal(err)
	}
	config.roomLabel = "unsafe label"
	if _, err := install(config, deploymentRandom()); err == nil {
		t.Fatal("unsafe room label accepted")
	}
	config.roomLabel = "safe-label"
	config.openfoxAgentBin += " missing"
	if _, err := install(config, deploymentRandom()); err == nil {
		t.Fatal("unsafe executable path accepted")
	}
}

func TestCheckMakesNoChanges(t *testing.T) {
	config := deploymentFixture(t)
	config.check = true
	result, installErr := install(config, deploymentRandom())
	if installErr != nil {
		t.Fatal(installErr)
	}
	if !result.CheckOnly || !result.EnvironmentCreated || len(result.CredentialsCreated) != 3 ||
		len(result.UnitsChanged) != 7 || !result.BootstrapRequired {
		t.Fatalf("unexpected check result: %#v", result)
	}
	for _, path := range []string{config.unitDir, config.envFile, config.stateDir} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("check wrote %s: %v", path, err)
		}
	}
}

func TestInstallRefusesSymlinkDirectoryBoundary(t *testing.T) {
	config := deploymentFixture(t)
	realUnits := filepath.Join(filepath.Dir(config.unitDir), "real-units")
	if err := os.Mkdir(realUnits, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realUnits, config.unitDir); err != nil {
		t.Fatal(err)
	}
	if _, err := install(
		config,
		deploymentRandom(),
	); err == nil ||
		!strings.Contains(err.Error(), "not a real directory") {
		t.Fatalf("symlink unit directory accepted: %v", err)
	}
}

func TestWriteAtomicPreservesCreateAndReplaceBoundaries(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "unit.service")
	if err := writeAtomic(target, []byte("first\n"), 0o644, false); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(target, []byte("first\n"), 0o644, false); err != nil {
		t.Fatalf("identical retry failed: %v", err)
	}
	if err := writeAtomic(target, []byte("substitute\n"), 0o644, false); err == nil {
		t.Fatal("unauthorized replacement succeeded")
	}
	if err := writeAtomic(target, []byte("replacement\n"), 0o644, true); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(target)
	if err != nil || string(body) != "replacement\n" {
		t.Fatalf("authorized replacement: body=%q err=%v", body, err)
	}
}

func deploymentFixture(t *testing.T) options {
	t.Helper()
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	executables := make([]string, 4)
	for index, name := range []string{"relay", "proxy", "driver", "openfox-agent"} {
		executables[index] = filepath.Join(bin, name)
		if err := os.WriteFile(executables[index], []byte("fixture\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return options{
		unitDir: filepath.Join(root, "units"), envFile: filepath.Join(root, "config", "lab.env"),
		stateDir: filepath.Join(root, "state"), relayBin: executables[0], proxyBin: executables[1],
		driverBin: executables[2], openfoxAgentBin: executables[3], roomLabel: "encrypted-builders",
	}
}

func deploymentRandom() *bytes.Reader {
	return bytes.NewReader(append(append(bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x22}, 32)...),
		bytes.Repeat([]byte{0x33}, 32)...))
}
