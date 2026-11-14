package servicebridge

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44/mldsa44test"
)

// TestControllerProbeRequiresAndUsesTheRealPinnedTOSCTL runs the probe the
// preflight uses against the real helper named by TOS_SERVICE_TOSCTL and
// TOS_SERVICE_TOSCTL_SHA256. It fails, rather than skips, without them: the
// probe's whole value is that the real helper resolves the real key.
func TestControllerProbeRequiresAndUsesTheRealPinnedTOSCTL(t *testing.T) {
	binary, pin := os.Getenv(mldsa44test.BinaryEnvironment), os.Getenv(mldsa44test.SHA256Environment)
	if binary == "" || pin == "" {
		t.Fatalf("set %s and %s to the pinned tosctl helper", mldsa44test.BinaryEnvironment,
			mldsa44test.SHA256Environment)
	}
	directory, err := os.MkdirTemp("", "openfox-probe-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if chmodErr := os.Chmod(directory, 0o700); chmodErr != nil {
		t.Fatal(chmodErr)
	}
	master := make([]byte, 32)
	if _, randErr := rand.Read(master); randErr != nil {
		t.Fatal(randErr)
	}
	vault := "file://" + filepath.Join(directory, "vault.json") + "?master_key=" + hex.EncodeToString(master)
	config := TOSCTLConfig{Binary: binary, SHA256: pin, ConfigPath: filepath.Join(directory, "tosctl-config.json")}
	run := func(args ...string) []byte {
		command := exec.Command(binary, args...)
		command.Env, command.Dir = []string{"VAULT_URL=" + vault}, "/"
		output, runErr := command.Output()
		if runErr != nil {
			t.Fatalf("tosctl %s failed: %v", strings.Join(args[:2], " "), runErr)
		}
		return output
	}
	run("config", "generate", "--output="+config.ConfigPath)
	var created struct {
		KeyID string `json:"key_id"`
	}
	if decodeErr := json.Unmarshal(run("agent", "native-registry", "new-controller", "--config", config.ConfigPath,
		"--name", "service-attestor", "--format", "json"), &created); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	keyID, err := ProbeControllerKeyID(context.Background(), config, vault, "service-attestor")
	if err != nil {
		t.Fatalf("the real helper did not resolve the controller: %v", err)
	}
	if hex.EncodeToString(keyID[:]) != created.KeyID {
		t.Fatalf("probe resolved %x, the vault holds %s", keyID, created.KeyID)
	}
	_, err = ProbeControllerKeyID(context.Background(), config, vault, "absent-controller")
	if err == nil || !strings.Contains(err.Error(), "could not resolve") {
		t.Fatalf("an absent controller was not reported as unresolvable: %v", err)
	}
	if strings.Contains(err.Error(), hex.EncodeToString(master)) || strings.Contains(err.Error(), directory) {
		t.Fatalf("the probe error leaks custody details: %v", err)
	}
	wrong := config
	wrong.SHA256 = strings.Repeat("0", 64)
	if _, err := ProbeControllerKeyID(context.Background(), wrong, vault, "service-attestor"); err == nil {
		t.Fatal("a helper with another SHA-256 was run")
	}
}
