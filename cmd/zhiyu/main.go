package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"zhiyu.local/zhiyu-go/internal/platform"
	"zhiyu.local/zhiyu-go/internal/transport/httpapi"
)

func run(ctx context.Context, args []string, out io.Writer, logger *slog.Logger, getenv func(string) string) error {
	if len(args) > 1 {
		opts, err := options(args)
		if err != nil {
			return err
		}
		if opts.Config == "" && opts.Command == "api" {
			return runEnvironment(ctx, "api", opts.WebRoot, out, logger, getenv)
		}
		return runConfigured(ctx, args, out, logger)
	}
	if len(args) != 1 || (args[0] != "doctor" && args[0] != "api") {
		return fmt.Errorf("usage: zhiyu <doctor|api|worker|standing|migrate|seed|demo-income> [-config role-runtime.json]")
	}
	return runEnvironment(ctx, args[0], "", out, logger, getenv)
}

func runEnvironment(ctx context.Context, command, webRoot string, out io.Writer, logger *slog.Logger, getenv func(string) string) error {
	c, err := platform.Load(getenv)
	if err != nil {
		return err
	}
	if command == "doctor" {
		return json.NewEncoder(out).Encode(map[string]any{"environment": c.Environment, "listen_addr": c.ListenAddr, "simulation": true, "go": runtime.Version(), "database_configured": c.DatabaseURL != "", "database_verified": false, "financial_operations_enabled": false, "mode": "CONFIG_ONLY_NO_IO"})
	}
	server := httpapi.Server(c, logger)
	handler, closeWeb, err := optionalStaticWeb(server.Handler, webRoot)
	if err != nil {
		return err
	}
	server.Handler = handler
	defer closeWeb()
	listener, err := net.Listen("tcp", c.ListenAddr)
	if err != nil {
		return err
	}
	logger.Info("api_start", "environment", c.Environment, "listen_addr", c.ListenAddr, "simulation", true, "stage", "R1_FOUNDATION")
	return serve(ctx, server, listener)
}

// Wait for Shutdown itself, not just Serve, before letting the process exit.
func serve(ctx context.Context, server *http.Server, listener net.Listener) error {
	result := make(chan error, 1)
	go func() { result <- server.Serve(listener) }()
	select {
	case err := <-result:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := server.Shutdown(stop)
		if err != nil {
			_ = server.Close()
		}
		<-result
		return err
	}
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stdout, logger, os.Getenv); err != nil {
		logger.Error("command_failed", "error", err.Error())
		os.Exit(1)
	}
}
