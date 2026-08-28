//go:build !windows

package earning

import "os"

func relayPinnedDirectoryOwnerSecure(info os.FileInfo) bool {
	return unixOwnerPrivateDirectoryInfo(info)
}

func secureRelayPinnedDirectory(root *os.Root, name string) error {
	info, err := root.Stat(name)
	if err != nil || !relayPinnedDirectoryInfoSecure(info) {
		return os.ErrPermission
	}
	return nil
}

func protectRelayPinnedDirectory(root *os.Root, name string) error {
	return secureRelayPinnedDirectory(root, name)
}
