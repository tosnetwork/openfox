//go:build windows

package earning

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func relayPinnedDirectoryOwnerSecure(info os.FileInfo) bool {
	// The opened-handle owner and DACL checks are performed by
	// secureRelayPinnedDirectory. Unix permission bits have no Windows meaning.
	return info != nil && info.IsDir()
}

func protectRelayPinnedDirectory(root *os.Root, name string) error {
	before, err := root.Stat(name)
	if err != nil || !before.IsDir() {
		return errors.New("rooted relay journal directory is invalid")
	}
	if err := protectRelayWindowsPath(filepath.Join(root.Name(), name), true); err != nil {
		return err
	}
	file, err := root.Open(name)
	if err != nil {
		return err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		return errors.New("rooted relay journal directory changed while protecting")
	}
	handle := windows.Handle(file.Fd())
	if err := validateRelayWindowsHandle(handle, true); err != nil {
		return err
	}
	return verifyRelayWindowsHandleProtection(handle, true)
}

func secureRelayPinnedDirectory(root *os.Root, name string) error {
	file, err := root.Open(name)
	if err != nil {
		return err
	}
	defer file.Close()
	handle := windows.Handle(file.Fd())
	if err := validateRelayWindowsHandle(handle, true); err != nil {
		return err
	}
	return verifyRelayWindowsHandleProtection(handle, true)
}
