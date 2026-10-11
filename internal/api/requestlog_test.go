package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RsNest/auditdsec/internal/config"
	"github.com/RsNest/auditdsec/internal/logging"
	"github.com/RsNest/auditdsec/internal/store"
)

// loggedServer is a panel whose api.jsonl and frontend.jsonl are real files.
func loggedServer(t *testing.T) (*Server, string, *time.Time) {
	t.Helper()
	dir := t.TempDir()
	logDir := filepath.Join(dir, "logs")
	logs, err := logging.Open(logging.Options{Dir: logDir, Stderr: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { logs.Close() })
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	clock := &now
	st, err := store.Open(store.Options{Dir: dir, MaxRecent: 50, Now: func() time.Time { return *clock }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cfg := config.Defaults(config.ProfileSimple)
	cfg.AuditLog = dir + "/audit.log"
	cfg.Web.Enabled = true
	cfg.Web.Login = "admin"
	cfg.Web.Password = testPassword
	cfg.Web.SessionTTL = time.Hour
	cfg.StateDir = dir
	cfg.Telegram.Token = "x"
	cfg.Telegram.ChatIDs = []int64{1}
	srv, err := New(Options{
		Config: cfg, Store: st, Host: "h", Version: "test", Started: now,
		Logger: logs.Main, APILog: logs.Stream("api"), FrontendLog: logs.Stream("frontend"),
		Now: func() time.Time { return *clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	return srv, logDir, clock
}

func records(t *testing.T, logDir, name string) []map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(logDir, name))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatal(err)
	}
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("%s: not JSON: %q", name, l)
		}
		out = append(out, m)
	}
	return out
}

func postRaw(t *testing.T, s *Server, path, token string, body string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.RemoteAddr = "198.51.100.9:5555"
	req.Header.Set("X-Requested-With", "auditdsec")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func TestRequestIDIsReturnedAndLoggedForFailures(t *testing.T) {
	s, logDir, _ := loggedServer(t)
	rec := do(t, s, http.MethodGet, "/api/v1/status", "", nil) // 401
	id := rec.Header().Get("X-Request-ID")
	if !logging.ValidID(id) {
		t.Fatalf("X-Request-ID = %q", id)
	}
	rows := records(t, logDir, "api.jsonl")
	if len(rows) != 1 || rows[0]["request_id"] != id || rows[0]["status"] != float64(401) || rows[0]["event"] != "request" {
		t.Fatalf("rows = %v", rows)
	}
	if rows[0]["level"] != "warn" || rows[0]["service"] != "api" {
		t.Errorf("record = %v", rows[0])
	}
}

func TestSuccessfulReadsAreNotLoggedButChangesAre(t *testing.T) {
	s, logDir, _ := loggedServer(t)
	tok := signIn(t, s) // a POST: logged
	before := len(records(t, logDir, "api.jsonl"))
	if before != 1 {
		t.Fatalf("the sign-in should be logged once, got %d", before)
	}
	do(t, s, http.MethodGet, "/api/v1/status", tok, nil)
	do(t, s, http.MethodGet, "/api/v1/events", tok, nil)
	if got := len(records(t, logDir, "api.jsonl")); got != before {
		t.Errorf("ordinary reads were logged: %d records", got)
	}
}

func TestClientRequestIDIsKeptOnlyWhenItLooksLikeOne(t *testing.T) {
	s, _, _ := loggedServer(t)
	good := "0123456789abcdef0123456789abcdef"
	rec := postRaw(t, s, "/api/v1/logout", "", "", map[string]string{"X-Request-ID": good})
	if rec.Header().Get("X-Request-ID") != good {
		t.Errorf("a valid id must be kept, got %q", rec.Header().Get("X-Request-ID"))
	}
	rec = postRaw(t, s, "/api/v1/logout", "", "", map[string]string{"X-Request-ID": "x\"; drop"})
	if got := rec.Header().Get("X-Request-ID"); got == "x\"; drop" || !logging.ValidID(got) {
		t.Errorf("an invalid id must be replaced, got %q", got)
	}
}

func TestClientLogNeedsASessionAndTheMarkerHeader(t *testing.T) {
	s, logDir, _ := loggedServer(t)
	body := `{"kind":"error","message":"boom"}`
	if rec := postRaw(t, s, "/api/v1/client-log", "", body, nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous: %d", rec.Code)
	}
	tok := signIn(t, s)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/client-log", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("without X-Requested-With: %d", rec.Code)
	}
	if n := len(records(t, logDir, "frontend.jsonl")); n != 0 {
		t.Errorf("refused reports were logged: %d", n)
	}
}

func TestClientLogCorrelatesAndCleans(t *testing.T) {
	s, logDir, _ := loggedServer(t)
	tok := signIn(t, s)
	failed := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	rep := map[string]any{
		"kind": "api", "message": "GET /api/v1/status failed: 502 password=hunter2",
		"source": "https://panel.example/app.js?token=SECRET#frag", "line": 10, "col": 3,
		"route": "#/events?ip=203.0.113.9&session=SECRET", "build": "v1", "user_agent": "UA\x01\x02",
		"client_time": "1999-01-01T00:00:00Z", "request_id": failed, "status": 502, "count": 3,
	}
	b, _ := json.Marshal(rep)
	rec := postRaw(t, s, "/api/v1/client-log", tok, string(b), nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	rows := records(t, logDir, "frontend.jsonl")
	if len(rows) != 1 {
		t.Fatalf("rows = %v", rows)
	}
	r := rows[0]
	if r["trace_id"] != failed || r["failed_request_id"] != failed || r["service"] != "frontend" || r["level"] != "warn" {
		t.Errorf("record = %v", r)
	}
	raw, _ := os.ReadFile(filepath.Join(logDir, "frontend.jsonl"))
	for _, bad := range []string{"hunter2", "SECRET", "203.0.113.9", "#frag"} {
		if bytes.Contains(raw, []byte(bad)) {
			t.Errorf("%q reached the log: %s", bad, raw)
		}
	}
	if strings.HasPrefix(r["ts"].(string), "1999") {
		t.Errorf("the record must carry the server's time, got %v", r["ts"])
	}
	if r["client_time"] != "1999-01-01T00:00:00Z" {
		t.Errorf("the client's time is kept as text only, got %v", r["client_time"])
	}
}

func TestClientLogCapsFieldsAndBody(t *testing.T) {
	s, logDir, _ := loggedServer(t)
	tok := signIn(t, s)
	rep := map[string]any{"kind": "error", "message": strings.Repeat("m", 5000), "stack": strings.Repeat("s", 7000)}
	b, _ := json.Marshal(rep)
	if len(b) <= clientLogBody {
		t.Fatalf("test body is only %d bytes", len(b))
	}
	// 7000+5000 > 8 KiB: refused as too large.
	if rec := postRaw(t, s, "/api/v1/client-log", tok, string(b), nil); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized body: %d", rec.Code)
	}
	rep["message"], rep["stack"] = strings.Repeat("m", 3000), strings.Repeat("s", 3000)
	b, _ = json.Marshal(rep)
	if rec := postRaw(t, s, "/api/v1/client-log", tok, string(b), nil); rec.Code != http.StatusNoContent {
		t.Fatalf("body within the limit: %d", rec.Code)
	}
	rows := records(t, logDir, "frontend.jsonl")
	if len(rows) != 1 {
		t.Fatalf("rows = %d", len(rows))
	}
	if len(rows[0]["message"].(string)) != 500 || len(rows[0]["stack"].(string)) != 2000 {
		t.Errorf("fields were not capped: message %d, stack %d", len(rows[0]["message"].(string)), len(rows[0]["stack"].(string)))
	}
	if rec := postRaw(t, s, "/api/v1/client-log", tok, `{"kind":"nonsense","message":"x"}`, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown kind: %d", rec.Code)
	}
	if rec := postRaw(t, s, "/api/v1/client-log", tok, `not json`, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("not JSON: %d", rec.Code)
	}
}

func TestClientLogDeduplicatesAndRateLimits(t *testing.T) {
	s, logDir, clock := loggedServer(t)
	tok := signIn(t, s)
	one := `{"kind":"error","message":"same error","source":"app.js","line":1}`
	for i := 0; i < 5; i++ {
		if rec := postRaw(t, s, "/api/v1/client-log", tok, one, nil); rec.Code != http.StatusNoContent {
			t.Fatalf("repeat %d: %d", i, rec.Code)
		}
	}
	if n := len(records(t, logDir, "frontend.jsonl")); n != 1 {
		t.Errorf("a repeated error was logged %d times", n)
	}
	*clock = clock.Add(clientLogDedup + time.Second)
	postRaw(t, s, "/api/v1/client-log", tok, one, nil)
	rows := records(t, logDir, "frontend.jsonl")
	if len(rows) != 2 || rows[1]["suppressed_duplicates"] != float64(4) {
		t.Errorf("after the window the record should say how many were held back: %v", rows)
	}

	// A session may send 30 different reports a minute, no more.
	*clock = clock.Add(2 * time.Minute)
	limited := 0
	for i := 0; i < clientLogPerSession+10; i++ {
		b, _ := json.Marshal(map[string]any{"kind": "error", "message": "distinct " + itoa(i)})
		if postRaw(t, s, "/api/v1/client-log", tok, string(b), nil).Code == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited < 10 {
		t.Errorf("only %d reports were refused", limited)
	}
}

func TestPanicBecomesALoggedInternalError(t *testing.T) {
	s, logDir, _ := loggedServer(t)
	s.mux.HandleFunc("GET /boom", func(http.ResponseWriter, *http.Request) { panic("kaboom password=hunter2") })
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/boom?token=SECRET", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", rec.Code)
	}
	id := rec.Header().Get("X-Request-ID")
	if !strings.Contains(rec.Body.String(), id) {
		t.Errorf("the error should name the request id %q: %s", id, rec.Body.String())
	}
	raw, _ := os.ReadFile(filepath.Join(logDir, "api.jsonl"))
	text := string(raw)
	if !strings.Contains(text, `"event":"panic"`) || !strings.Contains(text, "stack") {
		t.Errorf("the panic was not logged: %s", text)
	}
	if strings.Contains(text, "hunter2") || strings.Contains(text, "SECRET") {
		t.Errorf("a secret reached the log: %s", text)
	}
}
