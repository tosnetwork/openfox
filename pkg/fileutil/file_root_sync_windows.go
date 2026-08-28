//go:build windows

package fileutil

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func syncRootDirectory(root *os.Root, directory string) error {
	before, err := root.Stat(directory)
	if err != nil || !before.IsDir() {
		return errors.New("rooted directory for flush is invalid")
	}
	path := filepath.Join(root.Name(), directory)
	encoded, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("failed to encode rooted directory for flush: %w", err)
	}
	handle, err := windows.CreateFile(encoded, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return fmt.Errorf("failed to open rooted directory for flush: %w", err)
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return errors.New("failed to wrap rooted directory for flush")
	}
	after, statErr := file.Stat()
	var handleInfo windows.ByHandleFileInformation
	handleErr := windows.GetFileInformationByHandle(handle, &handleInfo)
	if statErr != nil || handleErr != nil || !after.IsDir() || !os.SameFile(before, after) ||
		handleInfo.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		_ = file.Close()
		return errors.New("rooted directory changed while opening for flush")
	}
	if err := windows.FlushFileBuffers(handle); err != nil {
		_ = file.Close()
		return fmt.Errorf("failed to flush rooted directory: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("failed to close rooted directory after flush: %w", err)
	}
	return nil
}
