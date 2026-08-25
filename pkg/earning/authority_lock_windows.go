//go:build windows

package earning

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func acquireAuthorityLock(directory string) (*os.File, error) {
	path := filepath.Join(directory, authorityLock)
	pathUTF16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, errors.New("encode economic authority lock path")
	}
	handle, err := windows.CreateFile(pathUTF16, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, errors.New("open economic authority lock")
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil ||
		info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("economic authority lock is not a regular file")
	}
	overlapped := new(windows.Overlapped)
	if err := windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, overlapped); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("economic authority is already open by another process")
	}
	lock := os.NewFile(uintptr(handle), path)
	if lock == nil {
		_ = windows.UnlockFileEx(handle, 0, 1, 0, overlapped)
		_ = windows.CloseHandle(handle)
		return nil, errors.New("wrap economic authority lock")
	}
	return lock, nil
}

func releaseAuthorityLock(lock *os.File) error {
	handle := windows.Handle(lock.Fd())
	var overlapped windows.Overlapped
	if err := windows.UnlockFileEx(handle, 0, 1, 0, &overlapped); err != nil {
		_ = lock.Close()
		return errors.New("unlock economic authority")
	}
	if err := lock.Close(); err != nil {
		return errors.New("close economic authority lock")
	}
	return nil
}
