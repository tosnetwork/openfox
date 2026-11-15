//go:build !linux

package servicebridge

import (
	"errors"
	"net"
)

// errPeerUserUnsupported reports a platform without peer credentials; the
// direct transport then relies on the socket's owner and directory alone.
var errPeerUserUnsupported = errors.New("peer credentials are only read on Linux")

func peerUserID(net.Conn) (int, error) { return 0, errPeerUserUnsupported }
