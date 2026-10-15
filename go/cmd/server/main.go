package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Sma-Das/ZScaler-MDR-MCP/go/internal/mcpserver"
	"github.com/Sma-Das/ZScaler-MDR-MCP/go/internal/redcanary"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func run() error {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println("zscaler-mdr-mcp", mcpserver.Version)
		return nil
	}
	port, e := strconv.Atoi(env("PORT", "3000"))
	if e != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid PORT")
	}
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		c := http.Client{Timeout: 3 * time.Second}
		r, e := c.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz", port))
		if e != nil {
			return fmt.Errorf("healthcheck failed")
		}
		r.Body.Close()
		if r.StatusCode != 200 {
			return fmt.Errorf("healthcheck failed")
		}
		return nil
	}
	if p := env("MDR_PROVIDER", "zscaler-mdr"); p != "zscaler-mdr" && p != "redcanary" {
		return fmt.Errorf("unsupported MDR_PROVIDER; implemented: zscaler-mdr, redcanary")
	}
	base, e := redcanary.NormalizeBase(os.Getenv("MDR_BASE_URL"))
	if e != nil {
		return e
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	budget := &redcanary.Budget{}
	if len(os.Args) > 1 {
		if os.Args[1] != "stdio" {
			return fmt.Errorf("usage: zscaler-mdr-mcp [stdio|version|healthcheck]")
		}
		c, e := redcanary.New(base, os.Getenv("MDR_API_KEY"), budget)
		if e != nil {
			return e
		}
		return mcpserver.New(c).Run(ctx, &mcp.StdioTransport{})
	}
	mux := newHandler(base, budget)

	server := &http.Server{Addr: net.JoinHostPort(env("HOST", "127.0.0.1"), strconv.Itoa(port)), Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 50 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	ch := make(chan error, 1)
	go func() { ch <- server.ListenAndServe() }()
	select {
	case e := <-ch:
		if !errors.Is(e, http.ErrServerClosed) {
			return fmt.Errorf("HTTP server failed")
		}
	case <-ctx.Done():
	}
	drain, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return server.Shutdown(drain)
}

func newHandler(base string, budget *redcanary.Budget) http.Handler {
	// Fixed upstream origin and per-caller keys. Never accept provider URLs,
	// credentials or transport settings in tool arguments.
	mcpHandler := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		c, _ := redcanary.New(base, r.Header.Get("X-API-Key"), budget)
		return mcpserver.New(c)
	}, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true, MaxRequestBodyBytes: 64 << 10, PropagateRequestCancellation: true})
	allowed := strings.Split(env("ALLOWED_HOSTS", "localhost,127.0.0.1,::1"), ",")
	semaphore := make(chan struct{}, 4)
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		host := r.Host
		if h, _, e := net.SplitHostPort(host); e == nil {
			host = h
		}
		ok := false
		for _, h := range allowed {
			if strings.EqualFold(strings.TrimSpace(h), host) {
				ok = true
			}
		}
		if !ok {
			http.Error(w, "Host is not allowed", 403)
			return
		}
		keys := r.Header.Values("X-API-Key")
		if len(keys) != 1 {
			http.Error(w, "Provide one X-API-Key", 401)
			return
		}
		if e := redcanary.ValidateKey(keys[0]); e != nil {
			http.Error(w, "Invalid X-API-Key", 401)
			return
		}
		select {
		case semaphore <- struct{}{}:
			defer func() { <-semaphore }()
		default:
			http.Error(w, "MDR concurrency limit reached", 429)
			return
		}
		mcpHandler.ServeHTTP(w, r)
	})
	origin := http.NewCrossOriginProtection()
	mux := http.NewServeMux()
	mux.Handle("/mcp", origin.Handler(protected))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": mcpserver.Version})
	})
	return mux
}
