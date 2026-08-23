//go:build !windows

package agentgift

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func acquireJournalLock(directory string) (*os.File, error) {
	path := filepath.Join(directory, journalLockFile)
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, errors.New("open Agent Gift journal lock")
	}
	lock := os.NewFile(uintptr(fd), path)
	info, statErr := lock.Stat()
	if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		_ = lock.Close()
		return nil, errors.New("Agent Gift journal lock is not an owner-only regular file")
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = lock.Close()
		return nil, errors.New("Agent Gift journal is already open by another process")
	}
	return lock, nil
}

func releaseJournalLock(lock *os.File) error {
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_UN); err != nil {
		_ = lock.Close()
		return errors.New("unlock Agent Gift journal")
	}
	if err := lock.Close(); err != nil {
		return errors.New("close Agent Gift journal lock")
	}
	return nil
}
