//go:build !windows

package earning

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

func acquireAuthorityLock(directory string) (*os.File, error) {
	path := filepath.Join(directory, authorityLock)
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, errors.New("open economic authority lock")
	}
	lock := os.NewFile(uintptr(fd), path)
	info, statErr := lock.Stat()
	if statErr != nil || !unixOwnerOnlyRegularFileInfo(info) {
		_ = lock.Close()
		return nil, errors.New("economic authority lock is not an owner-only regular file")
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = lock.Close()
		return nil, errors.New("economic authority is already open by another process")
	}
	return lock, nil
}

func acquireAuthorityLockRoot(root *os.Root) (*os.File, error) {
	return acquireRootedUnixLock(root, authorityLock, "economic authority")
}

func acquireRootedUnixLock(root *os.Root, name, label string) (*os.File, error) {
	if root == nil {
		return nil, errors.New(label + " root is unavailable")
	}
	if before, err := root.Lstat(name); err == nil && before.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New(label + " lock is a symlink")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("inspect " + label + " lock")
	}
	lock, err := root.OpenFile(name, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, errors.New("open " + label + " lock through retained root")
	}
	opened, statErr := lock.Stat()
	linked, linkErr := root.Lstat(name)
	if statErr != nil || linkErr != nil || !os.SameFile(opened, linked) ||
		!unixOwnerOnlyRegularFileInfo(opened) || !unixOwnerOnlyRegularFileInfo(linked) ||
		linked.Mode()&os.ModeSymlink != 0 {
		_ = lock.Close()
		return nil, errors.New(label + " lock is not an owner-only regular file")
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = lock.Close()
		return nil, errors.New(label + " is already open by another process")
	}
	return lock, nil
}

func releaseAuthorityLock(lock *os.File) error {
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_UN); err != nil {
		_ = lock.Close()
		return errors.New("unlock economic authority")
	}
	if err := lock.Close(); err != nil {
		return errors.New("close economic authority lock")
	}
	return nil
}

func validateAuthorityJournalFile(_ *os.File, info os.FileInfo) error {
	if !unixOwnerOnlyRegularFileInfo(info) {
		return errors.New("economic authority journal is not owner-only")
	}
	return nil
}

// unixFileInfoOwnedByEffectiveUser is deliberately evaluated against the
// effective UID that performs the economic side effect. Permission bits alone
// do not prove ownership: an attacker-controlled 0600/0700 inode can otherwise
// be made to look "private" to an elevated or credential-switched process.
func unixFileInfoOwnedByEffectiveUser(info os.FileInfo) bool {
	if info == nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && uint64(stat.Uid) == uint64(os.Geteuid())
}

func unixOwnerPrivateDirectoryInfo(info os.FileInfo) bool {
	return info != nil && info.IsDir() && info.Mode().Perm() == 0o700 &&
		unixFileInfoOwnedByEffectiveUser(info)
}

// A journal or lock inode with multiple hard links has an additional mutable
// namespace outside the retained directory capability. Require exactly one
// link for both the pathname observation and the opened descriptor.
func unixOwnerOnlyRegularFileInfo(info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 ||
		!unixFileInfoOwnedByEffectiveUser(info) {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1
}
