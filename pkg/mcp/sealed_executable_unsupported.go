//go:build !linux

package mcp

import (
	"errors"
	"os"
)

func sealExecutable(*os.File, []byte) (*os.File, error) {
	return nil, errors.New("sealed consequential MCP executable launch is not implemented on this platform")
}
