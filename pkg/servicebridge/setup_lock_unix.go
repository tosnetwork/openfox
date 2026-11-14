//go:build !windows

package servicebridge

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func acquireRunLock(path string) (*os.File, error) {
	descriptor, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, errors.New("servicebridge: open the state directory's run lock")
	}
	lock := os.NewFile(uintptr(descriptor), path)
	if info, statErr := lock.Stat(); lockFileProblem(info, statErr) {
		_ = lock.Close()
		return nil, errors.New("servicebridge: the state directory's run lock is not an owner-only regular file")
	}
	if err := unix.Flock(descriptor, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = lock.Close()
		return nil, ErrSetupBusy
	}
	return lock, nil
}

func releaseRunLock(lock *os.File) {
	_ = unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	_ = lock.Close()
}
