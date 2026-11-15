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

// fileOwnerID returns the user that owns info's file.
func fileOwnerID(info os.FileInfo) (int, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("file owner is not available")
	}
	return int(stat.Uid), nil
}

// fileGroupID returns the group that owns info's file.
func fileGroupID(info os.FileInfo) (int, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(stat.Gid), true
}

// errPeerUserUnsupported is never returned on Linux.
var errPeerUserUnsupported = errors.New("peer credentials are only read on Linux")

// errOwnerUnsupported is never returned on Linux.
var errOwnerUnsupported = errors.New("file ownership is only checked on Linux")
