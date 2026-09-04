//go:build windows

package prediction

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func acquireBookLock(directory string) (*os.File, error) {
	path, err := windows.UTF16PtrFromString(filepath.Join(directory, ".lock"))
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(path, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, errors.New("open prediction order-book lock")
	}
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(handle, &info) != nil || info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("prediction order-book lock is not a regular file")
	}
	var overlapped windows.Overlapped
	if windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlapped) != nil {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("prediction order book is already open")
	}
	lock := os.NewFile(uintptr(handle), filepath.Join(directory, ".lock"))
	if lock == nil {
		var release windows.Overlapped
		_ = windows.UnlockFileEx(handle, 0, 1, 0, &release)
		_ = windows.CloseHandle(handle)
		return nil, errors.New("wrap prediction order-book lock")
	}
	return lock, nil
}

func releaseBookLock(lock *os.File) error {
	var overlapped windows.Overlapped
	if err := windows.UnlockFileEx(windows.Handle(lock.Fd()), 0, 1, 0, &overlapped); err != nil {
		_ = lock.Close()
		return err
	}
	return lock.Close()
}
