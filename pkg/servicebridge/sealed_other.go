//go:build !linux

package servicebridge

import (
	"errors"
	"os"
)

func sealedExecutable([]byte) (*os.File, error) {
	return nil, errors.New("servicebridge: pinned tosctl custody is supported only on Linux")
}
