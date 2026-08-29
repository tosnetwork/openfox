//go:build windows

package capabilitycontrol

import "os"

// Windows object materialization uses exclusive creation and rejects reparse
// points. Go's portable FileInfo does not expose the link count there.
func fileLinkCount(os.FileInfo) uint64 { return 1 }
