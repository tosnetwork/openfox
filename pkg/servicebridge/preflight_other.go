//go:build !linux

package servicebridge

import (
	"errors"
	"os"
)

func freeBytes(string) (uint64, error) {
	return 0, errors.New("free space is only measured on Linux")
}

func ownedByCurrentUser(os.FileInfo) (bool, error) {
	return false, errors.New("file ownership is only checked on Linux")
}
