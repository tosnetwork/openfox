//go:build linux

package servicebridge

import (
	"errors"
	"net"
	"syscall"
)

// peerUserID returns the user of the process at the other end of a
// connected Unix socket, as the kernel recorded it when the peer bound it.
func peerUserID(connection net.Conn) (int, error) {
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return 0, errors.New("not a Unix socket connection")
	}
	raw, err := unixConnection.SyscallConn()
	if err != nil {
		return 0, errors.New("the connection's descriptor is not available")
	}
	var credentials *syscall.Ucred
	var optionErr error
	if controlErr := raw.Control(func(descriptor uintptr) {
		credentials, optionErr = syscall.GetsockoptUcred(int(descriptor), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); controlErr != nil || optionErr != nil || credentials == nil {
		return 0, errors.New("the peer's credentials are not available")
	}
	return int(credentials.Uid), nil
}
