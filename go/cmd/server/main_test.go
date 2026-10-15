package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Sma-Das/ZScaler-MDR-MCP/go/internal/redcanary"
)

func TestHTTPAdmissionAndInitialize(t *testing.T) {
	h := newHandler("https://example.my.redcanary.co", &redcanary.Budget{})
	for _, tt := range []struct {
		name, host, origin, key string
		want                    int
	}{
		{"missing key", "localhost", "", "", 401},
		{"untrusted host", "evil.example", "", "synthetic-key", 403},
		{"untrusted origin", "localhost", "https://evil.example", "synthetic-key", 403},
		{"bad key", "localhost", "", "bad,key", 401},
		{"initialize", "localhost", "", "synthetic-key", 200},
	} {
		t.Run(tt.name, func(t *testing.T) {
			body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`
			r := httptest.NewRequest(http.MethodPost, "http://localhost/mcp", strings.NewReader(body))
			r.Host = tt.host
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Accept", "application/json, text/event-stream")
			if tt.key != "" {
				r.Header.Set("X-API-Key", tt.key)
			}
			if tt.origin != "" {
				r.Header.Set("Origin", tt.origin)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tt.want {
				t.Fatalf("status %d want %d: %s", w.Code, tt.want, w.Body.String())
			}
			if strings.Contains(w.Body.String(), tt.key) && tt.key != "" {
				t.Fatal("key leaked")
			}
		})
	}
}

func TestHealthHasNoSecrets(t *testing.T) {
	h := newHandler("https://example.my.redcanary.co", &redcanary.Budget{})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "http://localhost/healthz", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"status":"ok"`) {
		t.Fatal("health failed")
	}
}
