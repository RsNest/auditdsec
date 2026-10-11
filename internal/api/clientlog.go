package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/RsNest/auditdsec/internal/logging"
)

// The panel reports its own errors here, so a failure that only exists in a
// browser reaches the same place as every other log. The endpoint is for
// signed-in sessions, needs the same marker header as any change, takes a small
// body, caps and cleans every field, counts what a session and the whole panel
// may send, and does not log the same error twice in a few minutes. A browser
// clock is not trusted: the record carries the server's time, and the client's
// only as text.
const (
	clientLogBody       = 8 << 10
	clientLogPerSession = 30  // reports a minute
	clientLogGlobal     = 120 // reports a minute, whoever sends them
	clientLogDedup      = 5 * time.Minute
	clientLogDedupKeep  = 512
)

var clientKinds = map[string]slog.Level{
	"error":              slog.LevelError,
	"unhandledrejection": slog.LevelError,
	"render":             slog.LevelError,
	"api":                slog.LevelWarn,
	"resource":           slog.LevelWarn,
}

type clientReport struct {
	Kind       string `json:"kind"`
	Message    string `json:"message"`
	Stack      string `json:"stack"`
	Source     string `json:"source"`
	Line       int    `json:"line"`
	Col        int    `json:"col"`
	Route      string `json:"route"`
	Build      string `json:"build"`
	UserAgent  string `json:"user_agent"`
	ClientTime string `json:"client_time"`
	RequestID  string `json:"request_id"` // the id of the API call that failed, if any
	Status     int    `json:"status"`
	Count      int    `json:"count"` // how many times the page saw it before sending
}

// clientLogState holds what the limits need.
type clientLogState struct {
	mu       sync.Mutex
	window   time.Time
	global   int
	sessions map[string]int
	seen     map[string]*seenError
	order    []string
}

type seenError struct {
	at         time.Time
	suppressed int
}

// allow counts one report against the session and the whole panel in the
// current minute.
func (c *clientLogState) allow(now time.Time, session string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if now.Sub(c.window) >= time.Minute || c.sessions == nil {
		c.window, c.global, c.sessions = now, 0, map[string]int{}
	}
	if c.global >= clientLogGlobal || c.sessions[session] >= clientLogPerSession {
		return false
	}
	c.global++
	c.sessions[session]++
	return true
}

// duplicate reports whether this error was already logged recently. When it
// was not, or the window passed, it returns how many identical reports were
// held back since, so the next record can say so.
func (c *clientLogState) duplicate(now time.Time, key string) (dup bool, suppressed int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen == nil {
		c.seen = map[string]*seenError{}
	}
	if e, ok := c.seen[key]; ok {
		if now.Sub(e.at) < clientLogDedup {
			e.suppressed++
			return true, 0
		}
		suppressed = e.suppressed
		e.at, e.suppressed = now, 0
		return false, suppressed
	}
	if len(c.order) >= clientLogDedupKeep {
		delete(c.seen, c.order[0])
		c.order = c.order[1:]
	}
	c.seen[key] = &seenError{at: now}
	c.order = append(c.order, key)
	return false, 0
}

// clean caps a text field, drops control characters, and cuts the query string
// and fragment off anything that is a URL or a route: addresses of pages can
// carry things (a filter, an address) that do not belong in a log.
func clean(s string, max int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if r < 0x20 && r != '\n' && r != '\t' || r == 0x7f {
			continue
		}
		b.WriteRune(r)
		if n++; n >= max {
			break
		}
	}
	return b.String()
}

func stripQuery(s string, max int) string {
	if i := strings.IndexAny(s, "?"); i >= 0 {
		s = s[:i]
	}
	return clean(s, max)
}

func (s *Server) handleClientLog(w http.ResponseWriter, r *http.Request) {
	var rep clientReport
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&rep); err != nil {
		code := http.StatusBadRequest
		if strings.Contains(err.Error(), "too large") {
			code = http.StatusRequestEntityTooLarge
		}
		fail(w, code, "bad_request", "the report is not valid or is too large")
		return
	}
	level, ok := clientKinds[rep.Kind]
	if !ok {
		fail(w, http.StatusBadRequest, "bad_request", "unknown report kind")
		return
	}
	now := s.now()
	session := sessionKey(bearer(r))
	if !s.clientLog.allow(now, session) {
		w.Header().Set("Retry-After", "60")
		fail(w, http.StatusTooManyRequests, "rate_limited", "too many reports; try again in a minute")
		return
	}
	rep.Message = clean(rep.Message, 500)
	rep.Stack = clean(rep.Stack, 2000)
	rep.Source = stripQuery(rep.Source, 300)
	rep.Route = stripQuery(rep.Route, 200)
	rep.Build = clean(rep.Build, 40)
	rep.UserAgent = clean(rep.UserAgent, 200)
	rep.ClientTime = clean(rep.ClientTime, 40)
	if !logging.ValidID(rep.RequestID) {
		rep.RequestID = ""
	}
	if rep.Count < 1 {
		rep.Count = 1
	}
	if rep.Count > 1000000 {
		rep.Count = 1000000
	}

	sum := sha256.Sum256([]byte(rep.Kind + "|" + rep.Message + "|" + rep.Source + "|" + itoa(rep.Line)))
	dup, held := s.clientLog.duplicate(now, hex.EncodeToString(sum[:8]))
	if dup {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// The record joins the request that carried it; when the report is about a
	// failed API call, that call's own ID is kept too, so the two logs meet.
	attrs := []slog.Attr{
		slog.String("event", "frontend_"+rep.Kind), slog.String("kind", rep.Kind),
		slog.String("source", rep.Source), slog.Int("line", rep.Line), slog.Int("col", rep.Col),
		slog.String("route", rep.Route), slog.String("build", rep.Build), slog.String("user_agent", rep.UserAgent),
		slog.String("client_time", rep.ClientTime), slog.Int("count", rep.Count),
	}
	if rep.Stack != "" {
		attrs = append(attrs, slog.String("stack", rep.Stack))
	}
	if rep.Status != 0 {
		attrs = append(attrs, slog.Int("status", rep.Status))
	}
	trace := rep.RequestID
	if trace != "" {
		attrs = append(attrs, slog.String("failed_request_id", rep.RequestID))
	} else {
		trace = logging.RequestID(r.Context())
	}
	// The trace of a report about a failed call is that call's ID, so looking
	// the ID up finds the request and the browser's report side by side.
	r = r.WithContext(logging.WithTrace(r.Context(), trace))
	if held > 0 {
		attrs = append(attrs, slog.Int("suppressed_duplicates", held))
	}
	s.frontLog.LogAttrs(r.Context(), level, rep.Message, attrs...)
	w.WriteHeader(http.StatusNoContent)
}

func sessionKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:6])
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
