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
	if err := protectRelayWindowsHandle(handle, false); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("economic authority lock DACL is not owner-only")
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

func acquireAuthorityLockRoot(root *os.Root) (*os.File, error) {
	return acquireRootedWindowsLock(root, authorityLock, "economic authority")
}

func acquireRootedWindowsLock(root *os.Root, name, label string) (*os.File, error) {
	if root == nil {
		return nil, errors.New(label + " root is unavailable")
	}
	if before, err := root.Lstat(name); err == nil && before.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New(label + " lock is a reparse point")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("inspect " + label + " lock")
	}
	lock, err := root.OpenFile(name, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, errors.New("open " + label + " lock through retained root")
	}
	opened, statErr := lock.Stat()
	linked, linkErr := root.Lstat(name)
	if statErr != nil || linkErr != nil || !os.SameFile(opened, linked) || !opened.Mode().IsRegular() ||
		linked.Mode()&os.ModeSymlink != 0 || validateRelayWindowsHandle(windows.Handle(lock.Fd()), false) != nil {
		_ = lock.Close()
		return nil, errors.New(label + " lock is not a regular non-reparse file")
	}
	if err := protectRelayWindowsPath(filepath.Join(root.Name(), name), false); err != nil {
		_ = lock.Close()
		return nil, errors.New(label + " lock DACL is not owner-only")
	}
	var overlapped windows.Overlapped
	if err := windows.LockFileEx(windows.Handle(lock.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlapped); err != nil {
		_ = lock.Close()
		return nil, errors.New(label + " is already open by another process")
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

func validateAuthorityJournalFile(file *os.File, _ os.FileInfo) error {
	if file == nil || validateRelayWindowsHandle(windows.Handle(file.Fd()), false) != nil ||
		verifyRelayWindowsHandleProtection(windows.Handle(file.Fd()), false) != nil {
		return errors.New("economic authority journal DACL is not owner-only")
	}
	return nil
}
