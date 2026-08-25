//go:build !windows

package earning

import (
	"errors"
	"os"
	"path/filepath"

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
	if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		_ = lock.Close()
		return nil, errors.New("economic authority lock is not an owner-only regular file")
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = lock.Close()
		return nil, errors.New("economic authority is already open by another process")
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
