//go:build !linux

package capabilitycontrol

import "errors"

type quarantineRootHandle struct {
	device, inode uint64
	storagePath   string
}

func openQuarantineRootHandle(string) (*quarantineRootHandle, error) {
	return nil, errors.New("trusted quarantine root pinning requires Linux")
}

func (*quarantineRootHandle) close() error            { return nil }
func (*quarantineRootHandle) fd() int                 { return -1 }
func (*quarantineRootHandle) matchesPath(string) bool { return false }
