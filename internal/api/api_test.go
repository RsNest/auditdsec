package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/RsNest/auditdsec/internal/config"
	"github.com/RsNest/auditdsec/internal/model"
	"github.com/RsNest/auditdsec/internal/store"
)

const testPassword = "correct horse battery"

func newServer(t *testing.T) (*Server, *store.Store, *time.Time) {
	t.Helper()
	dir := t.TempDir()
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
	cfg.Telegram.Token = "x"
	cfg.Telegram.ChatIDs = []int64{1}

	srv, err := New(Options{
		Config: cfg, Store: st, Host: "test-host", Version: "test",
		Started: now.Add(-time.Hour),
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:     func() time.Time { return *clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	return srv, st, clock
}

func do(t *testing.T, s *Server, method, target, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, target, r)
	req.RemoteAddr = "198.51.100.9:5555"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if method != http.MethodGet {
		req.Header.Set("X-Requested-With", "auditdsec")
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func signIn(t *testing.T, s *Server) string {
	t.Helper()
	rec := do(t, s, http.MethodPost, "/api/v1/login", "", map[string]string{"login": "admin", "password": testPassword})
	if rec.Code != http.StatusOK {
		t.Fatalf("login: %d %s", rec.Code, rec.Body.String())
	}
	var out struct{ Token string }
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.Token == "" {
		t.Fatalf("no token in %s", rec.Body.String())
	}
	return out.Token
}

// Everything but the sign-in endpoint must refuse an anonymous caller: the
// panel lists who logged in from where, which is exactly what an attacker
// probing the host wants.
func TestEveryEndpointNeedsASession(t *testing.T) {
	s, _, _ := newServer(t)
	cases := []struct{ method, path string }{
		{http.MethodGet, "/api/v1/status"},
		{http.MethodGet, "/api/v1/events"},
		{http.MethodGet, "/api/v1/explain/sudo"},
		{http.MethodGet, "/api/v1/bans"},
		{http.MethodPost, "/api/v1/bans"},
		{http.MethodDelete, "/api/v1/bans/198.51.100.1"},
		{http.MethodGet, "/api/v1/allowlist"},
		{http.MethodPost, "/api/v1/allowlist"},
		{http.MethodDelete, "/api/v1/allowlist/198.51.100.1"},
		{http.MethodPost, "/api/v1/mute"},
		{http.MethodDelete, "/api/v1/mute"},
		{http.MethodGet, "/api/v1/config"},
		{http.MethodGet, "/api/v1/diagnostics"},
	}
	for _, c := range cases {
		rec := do(t, s, c.method, c.path, "", nil)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s: status = %d, want 401", c.method, c.path, rec.Code)
		}
	}
	if rec := do(t, s, http.MethodGet, "/api/v1/status", "forged-token", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("a forged token was accepted: %d", rec.Code)
	}
}

func TestWrongCredentialsAreRefusedAndThrottled(t *testing.T) {
	s, _, _ := newServer(t)
	for i := 0; i < failLimit; i++ {
		rec := do(t, s, http.MethodPost, "/api/v1/login", "", map[string]string{"login": "admin", "password": "wrong"})
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status = %d, want 401", i, rec.Code)
		}
	}
	rec := do(t, s, http.MethodPost, "/api/v1/login", "", map[string]string{"login": "admin", "password": testPassword})
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 once the limit is reached", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("no Retry-After on a throttled response")
	}
}

// A wrong login name with the right password must fail: the decoy hash exists
// to equalize timing, not to accept anything.
func TestWrongLoginNameIsRefused(t *testing.T) {
	s, _, _ := newServer(t)
	rec := do(t, s, http.MethodPost, "/api/v1/login", "", map[string]string{"login": "root", "password": testPassword})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestSessionExpires(t *testing.T) {
	s, _, clock := newServer(t)
	token := signIn(t, s)
	if rec := do(t, s, http.MethodGet, "/api/v1/status", token, nil); rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	*clock = clock.Add(2 * time.Hour)
	if rec := do(t, s, http.MethodGet, "/api/v1/status", token, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("an expired session still works: %d", rec.Code)
	}
}

func TestLogoutRevokes(t *testing.T) {
	s, _, _ := newServer(t)
	token := signIn(t, s)
	if rec := do(t, s, http.MethodPost, "/api/v1/logout", token, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("logout: %d", rec.Code)
	}
	if rec := do(t, s, http.MethodGet, "/api/v1/status", token, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("the token still works after logout: %d", rec.Code)
	}
}

// Without the marker header a form on another site could post to the panel
// using the browser's credentials.
func TestMutationNeedsTheMarkerHeader(t *testing.T) {
	s, _, _ := newServer(t)
	token := signIn(t, s)
	body, _ := json.Marshal(map[string]any{"hours": 1})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mute", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestCrossOriginIsRefused(t *testing.T) {
	s, _, _ := newServer(t)
	token := signIn(t, s)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestStatusAndEvents(t *testing.T) {
	s, st, clock := newServer(t)
	for i := 0; i < 3; i++ {
		sev := model.SevInfo
		if i == 2 {
			sev = model.SevCritical
		}
		if err := st.AppendEvent(model.Event{
			Time: clock.Add(-time.Duration(i) * time.Hour), Host: "test-host",
			Kind: model.KindSSHLoginFail, Severity: sev, User: "root", SrcIP: "198.51.100.7",
			SummaryKey: "event." + string(model.KindSSHLoginFail),
			Args:       map[string]string{"user": "root", "ip": "198.51.100.7", "count": "1"},
		}); err != nil {
			t.Fatal(err)
		}
	}
	token := signIn(t, s)

	var status struct {
		Host     string         `json:"host"`
		Counters map[string]int `json:"counters"`
		ByKind   map[string]int `json:"by_kind"`
		Hourly   []any          `json:"hourly"`
	}
	rec := do(t, s, http.MethodGet, "/api/v1/status", token, nil)
	if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.Host != "test-host" {
		t.Errorf("host = %q", status.Host)
	}
	if status.Counters["events_24h"] != 3 || status.Counters["critical_24h"] != 1 {
		t.Errorf("counters = %v", status.Counters)
	}
	if status.ByKind[string(model.KindSSHLoginFail)] != 3 {
		t.Errorf("by_kind = %v", status.ByKind)
	}
	if len(status.Hourly) != 24 {
		t.Errorf("hourly has %d buckets, want 24", len(status.Hourly))
	}

	var page struct {
		Items []eventJSON `json:"items"`
		Next  *string     `json:"next"`
	}
	rec = do(t, s, http.MethodGet, "/api/v1/events?limit=2", token, nil)
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 2 {
		t.Fatalf("got %d events, want 2", len(page.Items))
	}
	if page.Next == nil {
		t.Fatal("no cursor on a truncated page")
	}
	if page.Items[0].Summary == "" || strings.Contains(page.Items[0].Summary, "event.") {
		t.Errorf("summary is not rendered: %q", page.Items[0].Summary)
	}
	// The cursor must not repeat an item already shown.
	first := page.Items[1].ID
	rec = do(t, s, http.MethodGet, "/api/v1/events?limit=2&before="+*page.Next, token, nil)
	var second struct {
		Items []eventJSON `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &second); err != nil {
		t.Fatal(err)
	}
	for _, it := range second.Items {
		if it.ID == first {
			t.Errorf("the cursor repeated event %s", it.ID)
		}
	}

	rec = do(t, s, http.MethodGet, "/api/v1/events?severity=critical", token, nil)
	var crit struct {
		Items []eventJSON `json:"items"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &crit)
	if len(crit.Items) != 1 {
		t.Errorf("severity filter returned %d events, want 1", len(crit.Items))
	}

	for _, bad := range []string{"?severity=nope", "?kind=nope", "?since=yesterday", "?limit=0"} {
		if rec := do(t, s, http.MethodGet, "/api/v1/events"+bad, token, nil); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", bad, rec.Code)
		}
	}
}

func TestBanRules(t *testing.T) {
	s, st, _ := newServer(t)
	token := signIn(t, s)

	rec := do(t, s, http.MethodPost, "/api/v1/bans", token, map[string]string{"ip": "198.51.100.5", "duration": "24h", "reason": "manual"})
	if rec.Code != http.StatusOK {
		t.Fatalf("ban: %d %s", rec.Code, rec.Body.String())
	}
	if len(st.Bans()) != 1 {
		t.Fatalf("the ban was not recorded")
	}

	// An allowlisted address must be refused with its own code, so the panel
	// can say why rather than showing a generic failure.
	if err := st.Allow("203.0.113.9", "test"); err != nil {
		t.Fatal(err)
	}
	rec = do(t, s, http.MethodPost, "/api/v1/bans", token, map[string]string{"ip": "203.0.113.9", "duration": "1h"})
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "allowlisted") {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	// Banning the address you are connecting from would lock you out.
	rec = do(t, s, http.MethodPost, "/api/v1/bans", token, map[string]string{"ip": "198.51.100.9", "duration": "1h"})
	if rec.Code != http.StatusConflict {
		t.Errorf("self-ban: status = %d, want 409", rec.Code)
	}

	for _, bad := range []map[string]string{
		{"ip": "127.0.0.1", "duration": "1h"},
		{"ip": "not-an-ip", "duration": "1h"},
		{"ip": "198.51.100.6", "duration": "5 minutes"},
		{"ip": "198.51.100.0/24", "duration": "1h"},
	} {
		rec := do(t, s, http.MethodPost, "/api/v1/bans", token, bad)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%v: status = %d, want 400", bad, rec.Code)
		}
	}

	rec = do(t, s, http.MethodDelete, "/api/v1/bans/198.51.100.5", token, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("unban: %d", rec.Code)
	}
	if len(st.Bans()) != 0 {
		t.Error("the ban is still recorded")
	}
}

func TestAllowlistAndMute(t *testing.T) {
	s, st, _ := newServer(t)
	token := signIn(t, s)

	if rec := do(t, s, http.MethodPost, "/api/v1/allowlist", token, map[string]string{"ip": "203.0.113.4"}); rec.Code != http.StatusOK {
		t.Fatalf("allow: %d %s", rec.Code, rec.Body.String())
	}
	if !st.IsAllowed("203.0.113.4") {
		t.Fatal("the address was not allowlisted")
	}
	if rec := do(t, s, http.MethodDelete, "/api/v1/allowlist/203.0.113.4", token, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("unallow: %d", rec.Code)
	}

	if rec := do(t, s, http.MethodPost, "/api/v1/mute", token, map[string]int{"hours": 8}); rec.Code != http.StatusOK {
		t.Fatalf("mute: %d", rec.Code)
	}
	if st.MutedUntil().IsZero() {
		t.Fatal("mute was not stored")
	}
	if rec := do(t, s, http.MethodPost, "/api/v1/mute", token, map[string]int{"hours": 500}); rec.Code != http.StatusBadRequest {
		t.Errorf("an absurd mute was accepted")
	}
	if rec := do(t, s, http.MethodDelete, "/api/v1/mute", token, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("unmute: %d", rec.Code)
	}
	if !st.MutedUntil().IsZero() {
		t.Error("mute was not lifted")
	}
}

// The panel shows the configuration, so the token must never be in it.
func TestConfigHidesSecrets(t *testing.T) {
	s, _, _ := newServer(t)
	token := signIn(t, s)
	rec := do(t, s, http.MethodGet, "/api/v1/config", token, nil)
	body := rec.Body.String()
	if strings.Contains(body, testPassword) || strings.Contains(body, "password_hash") {
		t.Errorf("the config response leaks the panel password: %s", body)
	}
	if !strings.Contains(body, `"token":"***"`) {
		t.Errorf("the telegram token is not masked: %s", body)
	}
}

// The panel itself is served from the same origin, which is what makes
// connect-src 'self' enough in the content policy.
func TestPanelIsServedAlongsideTheAPI(t *testing.T) {
	s, _, _ := newServer(t)
	rec := do(t, s, http.MethodGet, "/", "", nil)
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("the panel is not served: %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	if rec.Header().Get("Content-Security-Policy") == "" {
		t.Error("no content policy on the panel")
	}
	if rec := do(t, s, http.MethodGet, "/api/v1/nope", "", nil); rec.Code != http.StatusNotFound {
		t.Errorf("an unknown endpoint fell through to the panel: %d", rec.Code)
	}
}

func TestNoStoreOnAPIResponses(t *testing.T) {
	s, _, _ := newServer(t)
	token := signIn(t, s)
	rec := do(t, s, http.MethodGet, "/api/v1/status", token, nil)
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

func TestPasswordHashing(t *testing.T) {
	hash, err := HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(hash, testPassword) {
		t.Fatal("the hash contains the password")
	}
	p, err := parseHash(hash)
	if err != nil {
		t.Fatal(err)
	}
	if !p.verify(testPassword) {
		t.Error("the right password does not verify")
	}
	if p.verify(testPassword + "x") {
		t.Error("a wrong password verifies")
	}
	// Two hashes of the same password must differ: the salt is random.
	other, _ := HashPassword(testPassword)
	if other == hash {
		t.Error("the salt is not random")
	}
	for _, bad := range []string{"", "plain", "md5$1$a$b", "pbkdf2-sha256$1$a$b", "pbkdf2-sha256$310000$!!$!!"} {
		if _, err := parseHash(bad); err == nil {
			t.Errorf("parseHash accepted %q", bad)
		}
	}
}

// newDefaultServer starts a panel with no configured password: the admin/admin
// account that may only replace itself.
func newDefaultServer(t *testing.T) (*Server, string) {
	t.Helper()
	cfg := config.Defaults(config.ProfileSimple)
	cfg.Web.Enabled = true
	cfg.StateDir = t.TempDir()
	st, err := store.Open(store.Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	s, err := New(Options{Config: cfg, Store: st, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	return s, cfg.StateDir
}

func tokenOf(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var out struct {
		Token      string `json:"token"`
		MustChange bool   `json:"must_change"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.Token == "" {
		t.Fatalf("no token in %d %s", rec.Code, rec.Body)
	}
	return out.Token
}

// With no password configured the panel opens with admin/admin, and that
// account can do nothing except change itself.
func TestDefaultAccountMustChangeBeforeAnythingElse(t *testing.T) {
	s, dir := newDefaultServer(t)
	rec := do(t, s, "POST", "/api/v1/login", "", map[string]string{"login": "admin", "password": "admin"})
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"must_change":true`) {
		t.Fatalf("login: %d %s", rec.Code, rec.Body)
	}
	tok := tokenOf(t, rec)
	for _, p := range []string{"/api/v1/status", "/api/v1/events", "/api/v1/bans", "/api/v1/config", "/api/v1/diagnostics", "/api/v1/allowlist"} {
		r := do(t, s, "GET", p, tok, nil)
		if r.Code != 403 || !strings.Contains(r.Body.String(), "password_change_required") {
			t.Errorf("GET %s before the change = %d %s, want 403 password_change_required", p, r.Code, r.Body)
		}
	}
	if r := do(t, s, "POST", "/api/v1/bans", tok, map[string]string{"ip": "203.0.113.5"}); r.Code != 403 {
		t.Errorf("POST bans before the change = %d", r.Code)
	}

	bad := []map[string]string{
		{"current_password": "admin", "login": "admin", "password": "a-long-new-password"},
		{"current_password": "admin", "login": "ADMIN", "password": "a-long-new-password"},
		{"current_password": "admin", "login": "owner", "password": "admin"},
		{"current_password": "admin", "login": "owner", "password": "short"},
		{"current_password": "admin", "login": "owner", "password": "owner"},
		{"current_password": "admin", "login": "my owner", "password": "a-long-new-password"},
		{"current_password": "admin", "login": "", "password": "a-long-new-password"},
	}
	for _, b := range bad {
		if r := do(t, s, "POST", "/api/v1/account", tok, b); r.Code != 400 {
			t.Errorf("account %v = %d %s, want 400", b, r.Code, r.Body)
		}
	}
	if r := do(t, s, "POST", "/api/v1/account", tok, map[string]string{"current_password": "nope", "login": "owner", "password": "a-long-new-password"}); r.Code != 400 || !strings.Contains(r.Body.String(), "wrong_password") {
		t.Errorf("wrong current password = %d %s", r.Code, r.Body)
	}
	if _, err := os.Stat(dir + "/" + credFile); err == nil {
		t.Fatal("a refused change was saved")
	}

	good := map[string]string{"current_password": "admin", "login": "owner", "password": "a-long-new-password"}
	if r := do(t, s, "POST", "/api/v1/account", tok, good); r.Code != 204 {
		t.Fatalf("change = %d %s", r.Code, r.Body)
	}
	// The old session and the old account are gone.
	if r := do(t, s, "GET", "/api/v1/status", tok, nil); r.Code != 401 {
		t.Errorf("old session after change = %d, want 401", r.Code)
	}
	if r := do(t, s, "POST", "/api/v1/login", "", map[string]string{"login": "admin", "password": "admin"}); r.Code != 401 {
		t.Errorf("admin/admin after change = %d, want 401", r.Code)
	}
	rec = do(t, s, "POST", "/api/v1/login", "", map[string]string{"login": "owner", "password": "a-long-new-password"})
	if rec.Code != 200 || strings.Contains(rec.Body.String(), `"must_change":true`) {
		t.Fatalf("new login: %d %s", rec.Code, rec.Body)
	}
	if r := do(t, s, "GET", "/api/v1/status", tokenOf(t, rec), nil); r.Code != 200 {
		t.Errorf("status after the change = %d", r.Code)
	}

	// The file holds a hash only, with owner-only access.
	raw, err := os.ReadFile(dir + "/" + credFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "a-long-new-password") || !strings.Contains(string(raw), "pbkdf2-sha256$") {
		t.Errorf("credentials file = %s", raw)
	}
	if fi, _ := os.Stat(dir + "/" + credFile); fi.Mode().Perm() != 0o600 {
		t.Errorf("credentials file mode = %v", fi.Mode().Perm())
	}
}

// A restart keeps the chosen credentials, and the default does not come back.
func TestChangedCredentialsSurviveRestart(t *testing.T) {
	s, dir := newDefaultServer(t)
	tok := tokenOf(t, do(t, s, "POST", "/api/v1/login", "", map[string]string{"login": "admin", "password": "admin"}))
	if r := do(t, s, "POST", "/api/v1/account", tok, map[string]string{"current_password": "admin", "login": "owner", "password": "a-long-new-password"}); r.Code != 204 {
		t.Fatal(r.Code)
	}
	cfg := s.opt.Config
	cfg.StateDir = dir
	s2, err := New(Options{Config: cfg, Store: s.opt.Store, Logger: s.log})
	if err != nil {
		t.Fatal(err)
	}
	if r := do(t, s2, "POST", "/api/v1/login", "", map[string]string{"login": "admin", "password": "admin"}); r.Code != 401 {
		t.Errorf("default after restart = %d", r.Code)
	}
	if r := do(t, s2, "POST", "/api/v1/login", "", map[string]string{"login": "owner", "password": "a-long-new-password"}); r.Code != 200 {
		t.Errorf("chosen account after restart = %d", r.Code)
	}
}

// A configured password is not the default account: no forced change.
func TestConfiguredPasswordIsNotForcedToChange(t *testing.T) {
	s, _, _ := newServer(t)
	rec := do(t, s, "POST", "/api/v1/login", "", map[string]string{"login": "admin", "password": testPassword})
	if rec.Code != 200 || strings.Contains(rec.Body.String(), `"must_change":true`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if do(t, s, "GET", "/api/v1/status", tokenOf(t, rec), nil).Code != 200 {
		t.Error("status refused")
	}
	if do(t, s, "POST", "/api/v1/login", "", map[string]string{"login": "admin", "password": "admin"}).Code != 401 {
		t.Error("admin/admin accepted next to a configured password")
	}
}

func TestClientIPIgnoresForwardedHeaderUnlessTrusted(t *testing.T) {
	s, _, _ := newServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.RemoteAddr = "198.51.100.9:5555"
	req.Header.Set("X-Forwarded-For", "203.0.113.1")
	if got := s.clientIP(req); got != "198.51.100.9" {
		t.Errorf("clientIP = %q, want the socket address when the proxy is not trusted", got)
	}
	s.opt.Config.Web.TrustedProxies = []string{"198.51.100.0/24"}
	s.proxies, _ = parseProxies(s.opt.Config.Web.TrustedProxies)
	if got := s.clientIP(req); got != "203.0.113.1" {
		t.Errorf("clientIP = %q, want the forwarded address once the peer is a trusted proxy", got)
	}
}

func TestShortDur(t *testing.T) {
	cases := map[time.Duration]string{
		10 * time.Minute: "10m", 6 * time.Hour: "6h", 90 * time.Second: "1m30s",
		0: "0s", 24 * time.Hour: "24h",
	}
	for in, want := range cases {
		if got := shortDur(in); got != want {
			t.Errorf("shortDur(%s) = %q, want %q", in, got, want)
		}
	}
}
