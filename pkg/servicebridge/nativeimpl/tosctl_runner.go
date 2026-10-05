package nativeimpl

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/tosnetwork/tosutils-go/address"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

// releaseCommandRunner runs a pinned tosctl binary with a pinned config.
type releaseCommandRunner interface {
	run(context.Context, string, ...string) ([]byte, error)
}

type releaseExecutableIdentity struct {
	device, inode uint64
	size          int64
	digest        [sha256.Size]byte
}

type execReleaseRunner struct {
	identity releaseExecutableIdentity
	config   []byte
	env      []string
}

func newPinnedReleaseRunner(binaryPath, configPath string) (*execReleaseRunner, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("nativeimpl: descriptor-pinned tosctl custody is supported only on Linux")
	}
	executable, identity, err := openReleaseExecutable(binaryPath)
	if err != nil {
		return nil, err
	}
	_ = executable.Close()
	config, err := os.ReadFile(configPath)
	if err != nil || len(config) == 0 || len(config) > 2<<20 {
		return nil, errors.New("nativeimpl: read bounded tosctl custody configuration")
	}
	return &execReleaseRunner{identity: identity, config: append([]byte(nil), config...)}, nil
}

func newPinnedReleaseRunnerWithVault(binaryPath, configPath, vaultURL string) (*execReleaseRunner, error) {
	if vaultURL == "" || strings.TrimSpace(vaultURL) != vaultURL || len(vaultURL) > 4096 ||
		strings.ContainsAny(vaultURL, "\x00\r\n") {
		return nil, errors.New("nativeimpl: invalid explicit tosctl vault URL")
	}
	runner, err := newPinnedReleaseRunner(binaryPath, configPath)
	if err != nil {
		return nil, err
	}
	runner.env = []string{"VAULT_URL=" + vaultURL}
	return runner, nil
}

func (r *execReleaseRunner) run(ctx context.Context, binary string, args ...string) ([]byte, error) {
	if r == nil {
		return nil, errors.New("nativeimpl: tosctl custody runner is unavailable")
	}
	executable, identity, err := openReleaseExecutable(binary)
	if err != nil || identity != r.identity {
		if executable != nil {
			_ = executable.Close()
		}
		return nil, errors.New("nativeimpl: enrolled tosctl executable identity changed")
	}
	defer executable.Close()
	config, err := pinnedReleaseDescriptor(r.config)
	if err != nil {
		return nil, err
	}
	defer config.Close()
	args = append(args, "--config-fd", "3", "--config-format", "json")
	command := exec.CommandContext(ctx, "/proc/self/fd/4", args...)
	command.ExtraFiles = []*os.File{config, executable}
	command.Env = append([]string(nil), r.env...)
	output := releaseCappedBuffer{limit: 1 << 20}
	command.Stdout, command.Stderr = &output, &output
	err = command.Run()
	return output.Bytes(), err
}

func openReleaseExecutable(path string) (*os.File, releaseExecutableIdentity, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || !pathInfo.Mode().IsRegular() ||
		pathInfo.Mode()&os.ModeSymlink != 0 || pathInfo.Mode().Perm()&0o111 == 0 || pathInfo.Mode().Perm()&0o022 != 0 {
		return nil, releaseExecutableIdentity{}, errors.New("nativeimpl: invalid tosctl executable")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, releaseExecutableIdentity{}, err
	}
	info, err := file.Stat()
	stat, ok := info.Sys().(*syscall.Stat_t)
	if err != nil || !ok || !os.SameFile(pathInfo, info) || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
		file.Close()
		return nil, releaseExecutableIdentity{}, errors.New("nativeimpl: tosctl executable identity is untrusted")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		file.Close()
		return nil, releaseExecutableIdentity{}, err
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	identity := releaseExecutableIdentity{device: uint64(stat.Dev), inode: stat.Ino, size: info.Size(), digest: digest}
	if _, err := file.Seek(0, 0); err != nil {
		file.Close()
		return nil, releaseExecutableIdentity{}, err
	}
	return file, identity, nil
}

func pinnedReleaseDescriptor(raw []byte) (*os.File, error) {
	file, err := os.CreateTemp("", "openfox-tosctl-config-*")
	if err != nil {
		return nil, err
	}
	if err := os.Remove(file.Name()); err != nil {
		file.Close()
		return nil, err
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return nil, err
	}
	if _, err := file.Write(raw); err != nil {
		file.Close()
		return nil, err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return nil, err
	}
	if _, err := file.Seek(0, 0); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

type releaseCappedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *releaseCappedBuffer) Write(value []byte) (int, error) {
	remaining := b.limit - b.Len()
	if remaining <= 0 {
		return 0, errors.New("tosctl output exceeded limit")
	}
	if len(value) > remaining {
		written, _ := b.Buffer.Write(value[:remaining])
		return written, errors.New("tosctl output exceeded limit")
	}
	return b.Buffer.Write(value)
}

func secureExecutable(path string) bool {
	info, err := os.Lstat(path)
	if err != nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return filepath.IsAbs(path) && filepath.Clean(path) == path && info.Mode().IsRegular() &&
		info.Mode().Perm()&0o022 == 0 && info.Mode().Perm()&0o111 != 0 && ok &&
		(stat.Uid == 0 || stat.Uid == uint32(os.Geteuid()))
}

func secureConfigFile(path string) bool {
	info, err := os.Lstat(path)
	if err != nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return filepath.IsAbs(path) && filepath.Clean(path) == path && info.Mode().IsRegular() &&
		info.Mode().Perm()&0o077 == 0 && ok && stat.Uid == uint32(os.Geteuid())
}

func isRawWorkchainZero(value string) bool {
	parsed, err := address.ParseRawAddr(value)
	return err == nil && parsed != nil && parsed.Workchain() == 0 && parsed.StringRaw() == value
}

func sameAddress(left, right string) bool {
	a, errA := parseAnyAddress(left)
	b, errB := parseAnyAddress(right)
	return errA == nil && errB == nil && a.Workchain() == b.Workchain() && bytes.Equal(a.Data(), b.Data())
}

func parseAnyAddress(value string) (*address.Address, error) {
	if parsed, err := address.ParseRawAddr(value); err == nil {
		return parsed, nil
	}
	return address.ParseAddr(value)
}

func decodeStrictJSON(encoded []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

func readReviewedCode(path string) (*cell.Cell, string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, "", errors.New("reviewed code path must be clean and absolute")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return nil, "", errors.New("reviewed code must be a non-writable regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 || len(raw) > 2<<20 {
		return nil, "", errors.New("read reviewed code")
	}
	encoded := strings.Join(strings.Fields(string(raw)), "")
	boc, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(boc) == 0 || base64.StdEncoding.EncodeToString(boc) != encoded {
		return nil, "", errors.New("reviewed code is not canonical Base64")
	}
	code, err := cell.FromBOC(boc)
	if err != nil {
		return nil, "", errors.New("reviewed code is not a cell BOC")
	}
	return code, encoded, nil
}

func atomicUint64(value string) (uint64, error) {
	if value == "" {
		return 0, nil
	}
	amount, ok := new(big.Int).SetString(value, 10)
	if !ok || amount.Sign() < 0 || !amount.IsUint64() {
		return 0, errors.New("nativeimpl: escrow amount is not a canonical atomic uint64")
	}
	return amount.Uint64(), nil
}

func cellHashDigest(value *cell.Cell) string {
	return "tvm-cell-sha256:" + hex.EncodeToString(value.Hash())
}
