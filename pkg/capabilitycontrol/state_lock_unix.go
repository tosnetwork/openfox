//go:build !windows

package capabilitycontrol

import (
	"os"

	"golang.org/x/sys/unix"
)

type stateLock struct{ file *os.File }

func acquireStateLock(path string) (*stateLock, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, err
	}
	return &stateLock{file}, nil
}

func (lock *stateLock) close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	_ = unix.Flock(int(lock.file.Fd()), unix.LOCK_UN)
	return lock.file.Close()
}
