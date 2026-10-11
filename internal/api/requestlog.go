package api

import (
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/RsNest/auditdsec/internal/logging"
)

// slowRequest is how long a request may take before it is logged for being slow.
const slowRequest = time.Second

// statusWriter remembers the status code a handler sent.
type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.wrote {
		w.status, w.wrote = code, true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(p []byte) (int, error) {
	if !w.wrote {
		w.status, w.wrote = http.StatusOK, true
	}
	return w.ResponseWriter.Write(p)
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// withRequestLog gives every request an ID, returns it in X-Request-ID, turns a
// panic into a logged 500, and writes one record to api.jsonl for what a person
// debugging would want: every failure (4xx, 5xx), every request that changes
// something, and every slow one. Ordinary reads that went well are not logged;
// the panel polls, and a log of that would bury the rest.
//
// An ID sent by the browser in X-Request-ID is kept when it has the shape of
// one (16 to 32 lower-case hex characters) and replaced otherwise, so what ends
// up in a log is never text a client chose. The query string is never logged.
func (s *Server) withRequestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if !logging.ValidID(id) {
			id = logging.NewID()
		}
		ctx := logging.WithRequestID(r.Context(), id)
		r = r.WithContext(ctx)
		w.Header().Set("X-Request-ID", id)

		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		start := s.now()
		defer func() {
			rec := recover()
			if rec != nil {
				stack := string(debug.Stack())
				if len(stack) > 4000 {
					stack = stack[:4000] + "...[truncated]"
				}
				s.apiLog.LogAttrs(ctx, slog.LevelError, "request handler panicked",
					slog.String("event", "panic"), slog.String("method", r.Method), slog.String("path", r.URL.Path),
					slog.Any("panic", rec), slog.String("stack", stack))
				if !sw.wrote {
					fail(sw, http.StatusInternalServerError, "internal", "internal error; see the log with request id "+id)
				}
				sw.status = http.StatusInternalServerError
			}
			elapsed := s.now().Sub(start)
			mutating := r.Method != http.MethodGet && r.Method != http.MethodHead
			if sw.status < 400 && !mutating && elapsed < slowRequest {
				return
			}
			level := slog.LevelInfo
			switch {
			case sw.status >= 500:
				level = slog.LevelError
			case sw.status >= 400, elapsed >= slowRequest:
				level = slog.LevelWarn
			}
			s.apiLog.LogAttrs(ctx, level, "request",
				slog.String("event", "request"), slog.String("method", r.Method), slog.String("path", r.URL.Path),
				slog.Int("status", sw.status), slog.Int64("duration_ms", elapsed.Milliseconds()),
				slog.String("client", s.clientIP(r)))
		}()
		next.ServeHTTP(sw, r)
	})
}
