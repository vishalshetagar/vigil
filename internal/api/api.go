// Package api serves bounded read-only queries over an owner-only Unix socket.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"vigil/internal/store"
)

type Server struct {
	server   *http.Server
	listener net.Listener
}

func Start(socket string, s *store.Store, status func() any) (*Server, error) {
	if err := os.MkdirAll(filepath.Dir(socket), 0700); err != nil {
		return nil, err
	}
	// Never unlink an existing socket: it may belong to a running sensor.
	l, err := net.Listen("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("listen (remove stale socket only after checking no sensor is running): %w", err)
	}
	if err = os.Chmod(socket, 0600); err != nil {
		l.Close()
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) { write(w, status()) })
	for _, kind := range []string{"events", "alerts", "processes"} {
		mux.HandleFunc("GET /v1/"+kind, func(w http.ResponseWriter, r *http.Request) {
			n := 100
			if raw := r.URL.Query().Get("limit"); raw != "" {
				var err error
				n, err = strconv.Atoi(raw)
				if err != nil || n < 1 || n > 10000 {
					http.Error(w, "limit must be 1..10000", 400)
					return
				}
			}
			q := store.Query{Process: r.URL.Query().Get("process"), Type: r.URL.Query().Get("type"), Limit: n}
			rows, err := s.Query(r.Context(), kind, q)
			if err != nil {
				http.Error(w, "history query failed", 500)
				return
			}
			write(w, rows)
		})
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8192}
	a := &Server{srv, l}
	go func() { _ = srv.Serve(l) }()
	return a, nil
}

func write(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
func (s *Server) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := s.server.Shutdown(ctx); err != nil {
		_ = s.server.Close()
	}
}

func Get(ctx context.Context, socket, endpoint string) (json.RawMessage, error) {
	t := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	defer t.CloseIdleConnections()
	c := &http.Client{Transport: t, Timeout: 5 * time.Second}
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://vigil/v1/"+endpoint, nil)
	if err != nil {
		return nil, err
	}
	res, err := c.Do(r)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("API status %d: %s", res.StatusCode, b)
	}
	if !json.Valid(b) {
		return nil, fmt.Errorf("invalid or oversized API response")
	}
	return b, nil
}
