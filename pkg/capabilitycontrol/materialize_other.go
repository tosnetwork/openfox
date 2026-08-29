//go:build !linux

package capabilitycontrol

import "errors"

// Non-Linux production installation remains fail-closed until the platform
// supplies an equivalent handle-relative no-follow materializer (for example,
// NtCreateFile relative to a pinned directory on Windows).
func secureMaterializeTree(string, string) error {
	return errors.New("trusted capability installation is unsupported without a handle-relative no-follow materializer")
}
