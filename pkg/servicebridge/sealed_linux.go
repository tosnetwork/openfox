//go:build linux

package servicebridge

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// sealedExecutable copies the pinned binary into an anonymous memory file
// sealed against every change, so the bytes executed are exactly the bytes
// whose digest was checked, whatever happens to the file on disk.
func sealedExecutable(binary []byte) (*os.File, error) {
	descriptor, err := unix.MemfdCreate("tosctl", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, errors.New("servicebridge: create the tosctl snapshot")
	}
	file := os.NewFile(uintptr(descriptor), "tosctl")
	if _, err := file.Write(binary); err != nil {
		_ = file.Close()
		return nil, errors.New("servicebridge: write the tosctl snapshot")
	}
	seals := unix.F_SEAL_SEAL | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_WRITE
	if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, seals); err != nil {
		_ = file.Close()
		return nil, errors.New("servicebridge: seal the tosctl snapshot")
	}
	return file, nil
}
