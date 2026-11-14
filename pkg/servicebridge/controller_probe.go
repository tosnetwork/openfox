package servicebridge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
)

const controllerProbeTimeout = 30 * time.Second

// readPinnedBinary reads a bounded regular file and requires its SHA-256 to
// equal pin.
func readPinnedBinary(path, pin, name string) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("the %s path must be absolute and clean", name)
	}
	if !hex64Pattern.MatchString(pin) {
		return nil, fmt.Errorf("the %s SHA-256 pin must be 64 lowercase hex digits", name)
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("the %s binary does not exist or cannot be read", name)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxTOSCTLBytes {
		return nil, fmt.Errorf("the %s binary is not a bounded regular file", name)
	}
	binary, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read the %s binary", name)
	}
	digest := sha256.Sum256(binary)
	if hex.EncodeToString(digest[:]) != pin {
		return nil, fmt.Errorf("the %s binary does not have the pinned SHA-256", name)
	}
	return binary, nil
}

// ProbeControllerKeyID asks the pinned tosctl for a vault controller's
// public key with `agent native-registry controller`, which prints the
// public key and key ID and never signs or prints the secret. The answer is
// accepted only if the public key derives the key ID it states. tosctl's
// diagnostics are not echoed: they can name custody.
func ProbeControllerKeyID(
	ctx context.Context,
	tosctl TOSCTLConfig,
	vaultURL, controller string,
) ([32]byte, error) {
	var none [32]byte
	if ctx == nil || !walletNamePattern.MatchString(controller) {
		return none, errors.New("invalid controller name")
	}
	if !filepath.IsAbs(tosctl.ConfigPath) || filepath.Clean(tosctl.ConfigPath) != tosctl.ConfigPath {
		return none, errors.New("the tosctl configuration path must be absolute and clean")
	}
	binary, err := readPinnedBinary(tosctl.Binary, tosctl.SHA256, "tosctl")
	if err != nil {
		return none, err
	}
	executable, err := sealedExecutable(binary)
	if err != nil {
		return none, err
	}
	defer executable.Close()
	call, cancel := context.WithTimeout(ctx, controllerProbeTimeout)
	defer cancel()
	command := exec.CommandContext(call, fmt.Sprintf("/proc/self/fd/%d", executable.Fd()),
		"agent", "native-registry", "controller", "--config", tosctl.ConfigPath, "--name", controller,
		"--format", "json")
	command.Env, command.Dir = []string{}, "/"
	if vaultURL != "" {
		command.Env = []string{"VAULT_URL=" + vaultURL}
	}
	var stdout, stderr limitedBuffer
	stdout.limit, stderr.limit = maxLifecycleOutput, maxLifecycleOutput
	command.Stdout, command.Stderr = &stdout, &stderr
	if runErr := command.Run(); runErr != nil {
		return none, fmt.Errorf("tosctl could not resolve controller %q from the vault (%s)", controller,
			exitStatus(runErr))
	}
	decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	decoder.DisallowUnknownFields()
	var answer struct {
		Name      string `json:"name"`
		Suite     string `json:"suite"`
		KeyID     string `json:"key_id"`
		PublicKey string `json:"public_key"`
	}
	if decodeErr := decoder.Decode(&answer); decodeErr != nil || answer.Name != controller ||
		answer.Suite != "ML-DSA-44" ||
		!hex64Pattern.MatchString(answer.KeyID) {
		return none, fmt.Errorf("tosctl returned a malformed answer for controller %q", controller)
	}
	var trailing any
	if trailingErr := decoder.Decode(&trailing); !errors.Is(trailingErr, io.EOF) {
		return none, fmt.Errorf("tosctl returned trailing data for controller %q", controller)
	}
	publicKey, err := hex.DecodeString(answer.PublicKey)
	if err != nil || len(publicKey) != mldsa44.PublicKeySize {
		return none, fmt.Errorf("tosctl returned a malformed public key for controller %q", controller)
	}
	derived, err := mldsa44.KeyID(publicKey)
	if err != nil || hex.EncodeToString(derived[:]) != answer.KeyID {
		return none, fmt.Errorf("controller %q: the public key does not derive the stated key ID", controller)
	}
	return derived, nil
}
