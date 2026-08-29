//go:build linux

package mcp

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// sealExecutable copies verified bytes into an anonymous kernel object and
// applies irreversible seals. The child executes fd 3, not a mutable pathname.
func sealExecutable(source *os.File, expectedDigest []byte) (*os.File, error) {
	if source == nil || len(expectedDigest) != sha256.Size {
		return nil, errors.New("verified executable handle is unavailable")
	}
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	fd, err := unix.MemfdCreate("openfox-mcp", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, err
	}
	sealed := os.NewFile(uintptr(fd), "openfox-mcp-sealed")
	ok := false
	defer func() {
		if !ok {
			_ = sealed.Close()
		}
	}()
	hash := sha256.New()
	if _, err := io.Copy(io.MultiWriter(sealed, hash), io.LimitReader(source, (64<<20)+1)); err != nil {
		return nil, err
	}
	info, err := sealed.Stat()
	if err != nil || info.Size() <= 0 || info.Size() > 64<<20 {
		return nil, errors.New("MCP executable is empty or exceeds sealed limit")
	}
	if !bytes.Equal(hash.Sum(nil), expectedDigest) {
		return nil, errors.New("MCP executable handle bytes differ from the admitted manifest")
	}
	if err := sealed.Chmod(0o500); err != nil {
		return nil, err
	}
	if _, err := unix.FcntlInt(sealed.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_SEAL|unix.F_SEAL_SHRINK|unix.F_SEAL_GROW|unix.F_SEAL_WRITE); err != nil {
		return nil, err
	}
	if _, err := sealed.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	ok = true
	return sealed, nil
}
