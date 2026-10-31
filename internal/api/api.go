// Package api serves Intel's public read API (PRD I-5,
// schemas/openapi/intel.v1.yaml): entity signals and the published signed
// snapshots. It uses only net/http and reads through the Store interface.
//
// Public output is an allowlist: response types mirror the JSON Schemas field
// for field, internal verdict levels are mapped by signal.ToPublic, and text
// comes only from the wording renderer (fail closed: facts without prose).
// Errors are a machine-readable code and never echo request input. Logs carry
// the route pattern, status and timing, never paths, bodies or addresses.
// Rate limiting is the gateway's job (v1 cut list).
package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/entity"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/monitoring"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/store"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/wording"
)

// Store is what the API reads. *store.Postgres implements it.
type Store interface {
	LookupEntities(ctx context.Context, keys []store.LookupKey) ([]store.LookupResult, error)
	// Snapshot returns the recorded row for version, or the latest when version is 0.
	Snapshot(ctx context.Context, network entity.Network, version uint64) (store.SnapshotRecord, error)
}

var _ Store = (*store.Postgres)(nil)

const (
	// MaxBatch is the batchGet limit (maxItems in the OpenAPI document).
	MaxBatch = store.MaxLookupKeys
	// MaxBodyBytes caps a request body; 100 entities fit with a wide margin.
	MaxBodyBytes = 64 << 10
	// DefaultMaxSnapshotBytes caps a snapshot file the API will serve.
	DefaultMaxSnapshotBytes = 64 << 20
	// DefaultRequestTimeout bounds the store work of one request.
	DefaultRequestTimeout = 5 * time.Second
)

type Config struct {
	Store       Store
	Renderer    *wording.Renderer
	SnapshotDir string // where cmd/intel-worker writes the signed snapshot files
	// Now gives as_of for entities without a verdict. Defaults to time.Now.
	Now              func() time.Time
	Log              *slog.Logger
	RequestTimeout   time.Duration
	MaxSnapshotBytes int64
}

type Server struct {
	cfg  Config
	mux  *http.ServeMux
	snap snapshotCache
}

func New(cfg Config) (*Server, error) {
	if cfg.Store == nil || cfg.Renderer == nil || cfg.SnapshotDir == "" {
		return nil, errors.New("api: store, renderer and snapshot directory are required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = DefaultRequestTimeout
	}
	if cfg.MaxSnapshotBytes <= 0 {
		cfg.MaxSnapshotBytes = DefaultMaxSnapshotBytes
	}
	s := &Server{cfg: cfg, mux: http.NewServeMux()}
	// Methods are checked in the handlers so 404 and 405 are JSON too.
	s.mux.HandleFunc("/v1/entities/{type}/{id}", s.only(http.MethodGet, s.getEntity))
	s.mux.HandleFunc("/v1/entities:batchGet", s.only(http.MethodPost, s.batchGet))
	s.mux.HandleFunc("/v1/snapshots/latest", s.only(http.MethodGet, s.getLatestSnapshot))
	s.mux.HandleFunc("/v1/snapshots/{version}", s.only(http.MethodGet, s.getSnapshot))
	s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, codeNotFound)
	})
	return s, nil
}

// Handler returns the API with its middleware.
func (s *Server) Handler() http.Handler {
	return s.recoverer(s.logRequests(securityHeaders(s.withTimeout(s.mux))))
}

// HTTPServer returns a server with timeouts suitable for hostile clients.
// TLS terminates at the gateway.
func HTTPServer(addr string, h http.Handler, log *slog.Logger) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
}

// Error codes. They are the whole error body: {"error": "<code>"}.
const (
	codeNotFound         = "not_found"
	codeMethodNotAllowed = "method_not_allowed"
	codeInvalidQuery     = "invalid_query"
	codeInvalidVersion   = "invalid_version"
	codeInvalidBody      = "invalid_body"
	codeBodyTooLarge     = "body_too_large"
	codeUnsupportedMedia = "unsupported_media_type"
	codeTooManyEntities  = "too_many_entities"
	codeInternal         = "internal"
	codeUnavailable      = "unavailable"
)

type errorBody struct {
	Error string `json:"error"`
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, errorBody{Error: code})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		status, body = http.StatusInternalServerError, []byte(`{"error":"`+codeInternal+`"}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(append(body, '\n')) //nolint:errcheck // the client may have gone
}

// storeFailed maps a store error to 503 (timeout) or 500. A failed lookup is
// always an error response, never a no_signals result.
func (s *Server) storeFailed(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(r.Context().Err(), context.DeadlineExceeded) {
		writeError(w, http.StatusServiceUnavailable, codeUnavailable)
		return
	}
	s.cfg.Log.Error("store read failed", "route", r.Pattern, "err", err)
	writeError(w, http.StatusInternalServerError, codeInternal)
}

func (s *Server) only(method string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			w.Header().Set("Allow", method)
			writeError(w, http.StatusMethodNotAllowed, codeMethodNotAllowed)
			return
		}
		h(w, r)
	}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Resource-Policy", "same-site")
		h.Set("Strict-Transport-Security", "max-age=31536000")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) withTimeout(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), s.cfg.RequestTimeout)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

// logRequests logs the matched route pattern (never the path, which holds
// addresses), status, size and duration.
func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		var pattern string
		defer func() {
			s.cfg.Log.Info("request", "request_id", newRequestID(), "method", r.Method, "route", pattern,
				"status", sw.status, "bytes", sw.bytes, "duration_ms", time.Since(start).Milliseconds())
		}()
		_, pattern = s.mux.Handler(r)
		next.ServeHTTP(sw, r)
	})
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				// The panic value may hold request data; it is not logged.
				s.cfg.Log.Error("handler panic", monitoring.AlertFields(monitoring.ApiPanic)...)
				writeError(w, http.StatusInternalServerError, codeInternal)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func newRequestID() string {
	b := make([]byte, 8)
	rand.Read(b) //nolint:errcheck // crypto/rand.Read does not fail on supported platforms
	return hex.EncodeToString(b)
}
