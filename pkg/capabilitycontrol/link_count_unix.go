//go:build !windows

package capabilitycontrol

import (
	"os"
	"syscall"
)

func fileLinkCount(info os.FileInfo) uint64 {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(stat.Nlink)
	}
	return 0
}
