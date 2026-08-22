// Command tos-service-opportunity-coordinator isolates Gateway discovery and
// finalized chain verification from the OpenFox AgentLoop on a private socket.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tosnetwork/openfox/pkg/opportunity"
	"github.com/tosnetwork/openfox/pkg/servicebridge/nativeimpl"
)

func main() {
	configPath := flag.String("config", "", "owner-private opportunity coordinator configuration")
	check := flag.Bool("check", false, "validate configuration and exit without network reads")
	flag.Parse()
	if err := run(*configPath, *check); err != nil {
		fmt.Fprintln(os.Stderr, "tos-service-opportunity-coordinator:", err)
		os.Exit(1)
	}
}

func run(configPath string, checkOnly bool) error {
	if configPath == "" {
		return errors.New("configuration is required")
	}
	resources, err := nativeimpl.LoadOpportunityCoordinator(configPath)
	if err != nil {
		return err
	}
	if checkOnly {
		fmt.Println("opportunity coordinator configuration is structurally valid; live Gateway and finalized chain reads were not claimed")
		return nil
	}
	handler, err := opportunity.NewHandler(resources.Coordinator)
	if err != nil {
		return err
	}
	server, err := opportunity.ListenUnix(resources.SocketPath, handler)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- server.Serve() }()
	fmt.Printf("opportunity_socket=%s\n", resources.SocketPath)
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			return err
		}
		err := <-done
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}
