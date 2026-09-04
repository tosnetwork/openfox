//go:build !windows

package prediction

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func acquireBookLock(directory string) (*os.File, error) {
	path := filepath.Join(directory, ".lock")
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, errors.New("open prediction order-book lock")
	}
	lock := os.NewFile(uintptr(fd), path)
	info, statErr := lock.Stat()
	if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		_ = lock.Close()
		return nil, errors.New("prediction order-book lock is not owner-private")
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = lock.Close()
		return nil, errors.New("prediction order book is already open")
	}
	return lock, nil
}

func releaseBookLock(lock *os.File) error {
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_UN); err != nil {
		_ = lock.Close()
		return err
	}
	return lock.Close()
}
