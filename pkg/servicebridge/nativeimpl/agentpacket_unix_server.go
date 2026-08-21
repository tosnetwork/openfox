package nativeimpl

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AgentPacketUnixServer exposes the independently verifying Agent Packet HTTP
// handler on an owner-private Unix socket for tos-messengerd delivery.
type AgentPacketUnixServer struct {
	server   *http.Server
	listener net.Listener
	path     string
	once     sync.Once
}

func OpenAgentPacketUnixServer(path string, handler http.Handler) (*AgentPacketUnixServer, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || handler == nil {
		return nil, errors.New("invalid Agent Packet Unix server configuration")
	}
	parent := filepath.Dir(path)
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 ||
		parentInfo.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("Agent Packet Unix socket directory must be existing and owner-private")
	}
	if info, statErr := os.Lstat(path); statErr == nil {
		if info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("Agent Packet Unix socket path is occupied by a non-socket")
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return nil, statErr
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, err
	}
	return &AgentPacketUnixServer{
		server: &http.Server{
			Handler: handler, ReadHeaderTimeout: 2 * time.Second,
			ReadTimeout: 5 * time.Minute, WriteTimeout: 5 * time.Minute, MaxHeaderBytes: 8 << 10,
		},
		listener: listener, path: path,
	}, nil
}

func (s *AgentPacketUnixServer) Serve() error {
	if s == nil || s.server == nil || s.listener == nil {
		return errors.New("invalid Agent Packet Unix server")
	}
	return s.server.Serve(s.listener)
}

func (s *AgentPacketUnixServer) Shutdown(ctx context.Context) error {
	if s == nil || s.server == nil || ctx == nil {
		return errors.New("invalid Agent Packet Unix server shutdown")
	}
	var combined error
	s.once.Do(func() {
		combined = s.server.Shutdown(ctx)
		if err := s.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			combined = errors.Join(combined, err)
		}
		if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			combined = errors.Join(combined, err)
		}
	})
	return combined
}
