//go:build !windows

package fileutil

import (
	"fmt"
	"os"
)

func syncRootDirectory(root *os.Root, directory string) error {
	file, err := root.Open(directory)
	if err != nil {
		return fmt.Errorf("failed to open rooted directory for sync: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("failed to sync rooted directory: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("failed to close rooted directory: %w", err)
	}
	return nil
}
