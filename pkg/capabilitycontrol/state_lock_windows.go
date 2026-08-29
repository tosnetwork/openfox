//go:build windows

package capabilitycontrol

import (
	"os"

	"golang.org/x/sys/windows"
)

type stateLock struct{ file *os.File }

func acquireStateLock(path string) (*stateLock, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	overlapped := new(windows.Overlapped)
	if err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, overlapped); err != nil {
		_ = file.Close()
		return nil, err
	}
	return &stateLock{file}, nil
}

func (lock *stateLock) close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	_ = windows.UnlockFileEx(windows.Handle(lock.file.Fd()), 0, 1, 0, new(windows.Overlapped))
	return lock.file.Close()
}
