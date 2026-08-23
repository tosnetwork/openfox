//go:build windows

package agentgift

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func acquireJournalLock(directory string) (*os.File, error) {
	path := filepath.Join(directory, journalLockFile)
	pathUTF16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, errors.New("encode Agent Gift journal lock path")
	}
	handle, err := windows.CreateFile(
		pathUTF16,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, errors.New("open Agent Gift journal lock")
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil ||
		info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("Agent Gift journal lock is not a regular file")
	}
	overlapped := new(windows.Overlapped)
	if err := windows.LockFileEx(
		handle,
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0,
		1,
		0,
		overlapped,
	); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("Agent Gift journal is already open by another process")
	}
	lock := os.NewFile(uintptr(handle), path)
	if lock == nil {
		_ = windows.UnlockFileEx(handle, 0, 1, 0, overlapped)
		_ = windows.CloseHandle(handle)
		return nil, errors.New("wrap Agent Gift journal lock")
	}
	return lock, nil
}

func releaseJournalLock(lock *os.File) error {
	handle := windows.Handle(lock.Fd())
	var overlapped windows.Overlapped
	if err := windows.UnlockFileEx(handle, 0, 1, 0, &overlapped); err != nil {
		_ = lock.Close()
		return errors.New("unlock Agent Gift journal")
	}
	if err := lock.Close(); err != nil {
		return errors.New("close Agent Gift journal lock")
	}
	return nil
}
