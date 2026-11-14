//go:build linux

package servicebridge

import (
	"errors"
	"math/bits"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// freeBytes is the space available to an unprivileged writer on the file
// system holding path, saturated at the largest uint64.
func freeBytes(path string) (uint64, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return 0, errors.New("statfs failed")
	}
	if stat.Bsize <= 0 {
		return 0, errors.New("statfs reported no block size")
	}
	high, low := bits.Mul64(stat.Bavail, uint64(stat.Bsize))
	if high != 0 {
		return ^uint64(0), nil
	}
	return low, nil
}

// ownedByCurrentUser reports whether the effective user owns info's file.
func ownedByCurrentUser(info os.FileInfo) (bool, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false, errors.New("file owner is not available")
	}
	return int64(stat.Uid) == int64(os.Geteuid()), nil
}
