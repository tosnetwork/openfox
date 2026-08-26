//go:build !windows

package earning

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

func validateRelayJournalDirectorySecurity(directory string) error {
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errors.New("relay journal directory is not owner-private")
	}
	return nil
}

func acquireRelayJournalLock(directory string) (*os.File, error) {
	path := filepath.Join(directory, relayJournalLockFile)
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, errors.New("open relay journal process lock")
	}
	lock := os.NewFile(uintptr(fd), path)
	info, statErr := lock.Stat()
	if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		_ = lock.Close()
		return nil, errors.New("relay journal lock is not an owner-only regular file")
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = lock.Close()
		return nil, errors.New("relay journal is already open by another process")
	}
	return lock, nil
}

func releaseRelayJournalLock(lock *os.File) error {
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_UN); err != nil {
		_ = lock.Close()
		return errors.New("unlock relay journal")
	}
	if err := lock.Close(); err != nil {
		return errors.New("close relay journal lock")
	}
	return nil
}

func openRelayJournalFile(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, os.ErrNotExist
		}
		return nil, errors.New("open relay journal")
	}
	return os.NewFile(uintptr(fd), path), nil
}

func writeRelayJournalAtomic(directory, path string, data []byte) error {
	temporary := filepath.Join(directory, fmt.Sprintf(".agent-relay-%d-%d.tmp", os.Getpid(), time.Now().UnixNano()))
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("create relay journal temporary file")
	}
	cleanup := true
	defer func() {
		_ = file.Close()
		if cleanup {
			_ = os.Remove(temporary)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return errors.New("write relay journal temporary file")
	}
	if err := file.Sync(); err != nil {
		return errors.New("fsync relay journal temporary file")
	}
	if err := file.Chmod(0o600); err != nil {
		return errors.New("protect relay journal temporary file")
	}
	if err := file.Close(); err != nil {
		return errors.New("close relay journal temporary file")
	}
	if err := os.Rename(temporary, path); err != nil {
		return errors.New("atomically replace relay journal")
	}
	cleanup = false
	directoryFile, err := os.Open(directory)
	if err != nil {
		return errors.New("open relay journal directory for fsync")
	}
	defer directoryFile.Close()
	if err := directoryFile.Sync(); err != nil {
		return errors.New("fsync relay journal directory")
	}
	return nil
}
