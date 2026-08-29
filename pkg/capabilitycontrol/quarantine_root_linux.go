//go:build linux

package capabilitycontrol

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

type quarantineRootHandle struct {
	file        *os.File
	device      uint64
	inode       uint64
	storagePath string
}

func openQuarantineRootHandle(path string) (*quarantineRootHandle, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("open quarantine root handle")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		_ = file.Close()
		return nil, fmt.Errorf("stat quarantine root handle")
	}
	return &quarantineRootHandle{file: file, device: uint64(stat.Dev), inode: stat.Ino, storagePath: fmt.Sprintf("/proc/self/fd/%d", fd)}, nil
}

func (handle *quarantineRootHandle) close() error {
	if handle == nil || handle.file == nil {
		return nil
	}
	err := handle.file.Close()
	handle.file = nil
	return err
}

func (handle *quarantineRootHandle) fd() int {
	if handle == nil || handle.file == nil {
		return -1
	}
	return int(handle.file.Fd())
}

func (handle *quarantineRootHandle) matchesPath(path string) bool {
	if handle == nil || handle.file == nil {
		return false
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return false
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	return unix.Fstat(fd, &stat) == nil && uint64(stat.Dev) == handle.device && stat.Ino == handle.inode
}
