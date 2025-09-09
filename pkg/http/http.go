package http

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"k8s.io/klog/v2"

	"github.com/containers/kubernetes-mcp-server/pkg/config"
	"github.com/containers/kubernetes-mcp-server/pkg/mcp"
)

const (
	healthEndpoint     = "/healthz"
	mcpEndpoint        = "/mcp"
	sseEndpoint        = "/sse"
	sseMessageEndpoint = "/message"
)

func Serve(ctx context.Context, mcpServer *mcp.Server, staticConfig *config.StaticConfig, oidcProvider *oidc.Provider) error {
	mux := http.NewServeMux()

	wrappedMux := RequestMiddleware(
		AuthorizationMiddleware(staticConfig, oidcProvider, mcpServer)(mux),
	)

	httpServer := &http.Server{
		Addr:    ":" + staticConfig.Port,
		Handler: wrappedMux,
	}

	sseServer := mcpServer.ServeSse(staticConfig.SSEBaseURL, httpServer)
	streamableHttpServer := mcpServer.ServeHTTP(httpServer)
	// Compliant SSE handler with CORS support
	mux.HandleFunc(sseEndpoint, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		// Delegate to the original SSE server
		sseServer.ServeHTTP(w, r)
	})
	mux.Handle(sseMessageEndpoint, sseServer)
	mux.Handle(mcpEndpoint, streamableHttpServer)
	mux.HandleFunc(healthEndpoint, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.Handle("/.well-known/", WellKnownHandler(staticConfig))

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM)

	serverErr := make(chan error, 1)
	go func() {
		klog.V(0).Infof("Streaming and SSE HTTP servers starting on port %s and paths /mcp, /sse, /message", staticConfig.Port)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	select {
	case sig := <-sigChan:
		klog.V(0).Infof("Received signal %v, initiating graceful shutdown", sig)
		cancel()
	case <-ctx.Done():
		klog.V(0).Infof("Context cancelled, initiating graceful shutdown")
	case err := <-serverErr:
		klog.Errorf("HTTP server error: %v", err)
		return err
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	klog.V(0).Infof("Shutting down HTTP server gracefully...")
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		klog.Errorf("HTTP server shutdown error: %v", err)
		return err
	}

	klog.V(0).Infof("HTTP server shutdown complete")
	return nil
}
