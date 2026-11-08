package earning

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
	"regexp"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
)

const (
	maximumControllerOutputBytes = 16 << 10
	controllerReadTimeout        = time.Minute
)

var controllerKeyIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// TOSCTLAuthorityHelper names the pinned tosctl helper. ConfigPath and
// VaultURL are required only to sign; VaultURL names custody and is handed to
// tosctl as its only environment variable.
type TOSCTLAuthorityHelper struct {
	Binary     string
	SHA256     string
	ConfigPath string
	VaultURL   string
}

// OpenTOSCTLAuthorityKeys builds the personal authority's pinned keys: it
// reads the public keys of the Action Authority and custody authorization
// controllers from custody and requires each to derive its configured key
// ID. No private key leaves custody.
func OpenTOSCTLAuthorityKeys(
	ctx context.Context,
	helper TOSCTLAuthorityHelper,
	actionKeyID, custodyKeyID string,
) (AuthorityKeys, error) {
	if _, err := commerce.ParseActionAuthorityKeyID(actionKeyID); err != nil {
		return AuthorityKeys{}, err
	}
	if _, err := commerce.ParseCustodyAuthorizationKeyID(custodyKeyID); err != nil {
		return AuthorityKeys{}, err
	}
	if helper.ConfigPath == "" || helper.VaultURL == "" {
		return AuthorityKeys{}, errors.New("personal authority custody needs a tosctl configuration and vault")
	}
	custody, err := mldsa44.NewTosctl(mldsa44.TosctlConfig{
		Binary: helper.Binary, SHA256: helper.SHA256,
		ConfigPath: helper.ConfigPath, VaultURL: helper.VaultURL,
	})
	if err != nil {
		return AuthorityKeys{}, err
	}
	actionKey, err := readControllerPublicKey(ctx, helper, ActionAuthorityController, actionKeyID)
	if err != nil {
		return AuthorityKeys{}, err
	}
	custodyKey, err := readControllerPublicKey(ctx, helper, CustodyAuthorizationController, custodyKeyID)
	if err != nil {
		return AuthorityKeys{}, err
	}
	keys := AuthorityKeys{
		Custody: custody, ActionKeyID: actionKeyID, ActionPublicKey: actionKey,
		CustodyKeyID: custodyKeyID, CustodyPublicKey: custodyKey,
	}
	if err := keys.validate(); err != nil {
		return AuthorityKeys{}, err
	}
	return keys, nil
}

// OpenTOSCTLVerifier returns the verify-only pinned helper a shared
// authority client checks signatures with.
func OpenTOSCTLVerifier(helper TOSCTLAuthorityHelper) (mldsa44.Verifier, error) {
	if helper.ConfigPath != "" || helper.VaultURL != "" {
		return nil, errors.New("a verify-only tosctl helper cannot name custody")
	}
	return mldsa44.NewTosctl(mldsa44.TosctlConfig{Binary: helper.Binary, SHA256: helper.SHA256})
}

// readControllerPublicKey runs `tosctl agent native-registry controller`,
// which prints a controller's public key and key ID and never its secret. The
// binary must hash to its pin; the answer is trusted only because the key
// must derive the configured key ID.
func readControllerPublicKey(
	ctx context.Context,
	helper TOSCTLAuthorityHelper,
	controller, expectedKeyID string,
) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("controller key read has no context")
	}
	expected, err := mldsa44.ParseKeyIDText(expectedKeyID)
	if err != nil {
		return nil, errors.New("configured controller key ID is not canonical")
	}
	if pinErr := checkPinnedBinary(helper.Binary, helper.SHA256); pinErr != nil {
		return nil, pinErr
	}
	if !filepath.IsAbs(helper.ConfigPath) || filepath.Clean(helper.ConfigPath) != helper.ConfigPath {
		return nil, errors.New("tosctl configuration path must be absolute and clean")
	}
	call, cancel := context.WithTimeout(ctx, controllerReadTimeout)
	defer cancel()
	command := exec.CommandContext(call, helper.Binary, "agent", "native-registry", "controller",
		"--config", helper.ConfigPath, "--name", controller, "--format", "json")
	command.Env = []string{"VAULT_URL=" + helper.VaultURL}
	command.Dir = "/"
	var stdout, stderr boundedOutput
	stdout.limit, stderr.limit = maximumControllerOutputBytes, maximumControllerOutputBytes
	command.Stdout, command.Stderr = &stdout, &stderr
	if runErr := command.Run(); runErr != nil || stdout.overflow {
		// tosctl diagnostics may name custody; they are not echoed.
		return nil, fmt.Errorf("tosctl could not read the %s controller key", controller)
	}
	decoder := json.NewDecoder(bytes.NewReader(stdout.buffer.Bytes()))
	var answer struct {
		Name      string `json:"name"`
		Suite     string `json:"suite"`
		KeyID     string `json:"key_id"`
		PublicKey string `json:"public_key"`
	}
	if decodeErr := decoder.Decode(&answer); decodeErr != nil || answer.Name != controller ||
		!controllerKeyIDPattern.MatchString(answer.KeyID) {
		return nil, fmt.Errorf("tosctl returned a malformed %s controller key", controller)
	}
	publicKey, err := hex.DecodeString(answer.PublicKey)
	if err != nil || len(publicKey) != mldsa44.PublicKeySize {
		return nil, fmt.Errorf("tosctl returned a malformed %s controller key", controller)
	}
	derived, err := mldsa44.KeyID(publicKey)
	if err != nil || derived != expected || hex.EncodeToString(derived[:]) != answer.KeyID {
		return nil, fmt.Errorf("the %s controller key does not derive the configured key ID", controller)
	}
	return publicKey, nil
}

func checkPinnedBinary(path, pin string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(pin) != 64 {
		return errors.New("tosctl helper must be an absolute binary with a SHA-256 pin")
	}
	file, err := os.Open(path)
	if err != nil {
		return errors.New("open the tosctl helper")
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, io.LimitReader(file, 1<<30)); err != nil {
		return errors.New("read the tosctl helper")
	}
	if hex.EncodeToString(digest.Sum(nil)) != pin {
		return errors.New("the tosctl helper does not have the pinned SHA-256")
	}
	return nil
}

type boundedOutput struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

func (output *boundedOutput) Write(value []byte) (int, error) {
	remaining := output.limit - output.buffer.Len()
	if len(value) > remaining {
		output.overflow = true
		if remaining > 0 {
			output.buffer.Write(value[:remaining])
		}
		return len(value), nil
	}
	return output.buffer.Write(value)
}
