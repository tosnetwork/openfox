package nativeimpl

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAgentPacketUnixServerIsPrivateAndServesHandler(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "agent-packet.sock")
	server, err := OpenAgentPacketUnixServer(path, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/agent-packet" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve() }()
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		t.Fatalf("private socket info=%v err=%v", info, err)
	}
	client := &http.Client{
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		}},
	}
	response, err := client.Post("http://unix/v1/agent-packet", "application/json", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("status=%d", response.StatusCode)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("serve error=%v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket survived shutdown: %v", err)
	}
}

func TestAgentPacketUnixServerRefusesUnsafePaths(t *testing.T) {
	private := t.TempDir()
	if err := os.Chmod(private, 0o700); err != nil {
		t.Fatal(err)
	}
	occupied := filepath.Join(private, "occupied.sock")
	if err := os.WriteFile(occupied, []byte("do not replace"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenAgentPacketUnixServer(occupied, http.NotFoundHandler()); err == nil {
		t.Fatal("regular file was replaced")
	}
	public := filepath.Join(t.TempDir(), "public")
	if err := os.Mkdir(public, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenAgentPacketUnixServer(filepath.Join(public, "packet.sock"), http.NotFoundHandler()); err == nil {
		t.Fatal("non-private socket directory was accepted")
	}
	if _, err := OpenAgentPacketUnixServer("relative.sock", http.NotFoundHandler()); err == nil {
		t.Fatal("relative socket was accepted")
	}
}
