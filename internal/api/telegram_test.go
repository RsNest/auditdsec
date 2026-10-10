package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/RsNest/auditdsec/internal/model"
	"github.com/RsNest/auditdsec/internal/notify/telegram"
)

func TestTelegramSettingsSaveAndReadNeverExposeToken(t *testing.T) {
	s, st, now := newServer(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":true,"result":{"is_bot":true,"username":"settings_bot"}}`))
	}))
	defer ts.Close()
	m, err := telegram.NewManaged(telegram.Options{APIBase: ts.URL, Store: st, Now: func() time.Time { return *now }, QuietFrom: -1, QuietTo: -1}, s.opt.Config.StateDir, false)
	if err != nil {
		t.Fatal(err)
	}
	s.opt.Telegram = m
	tok := signIn(t, s)
	draft := telegram.Settings{Enabled: true, Token: "123:secret", ChatIDs: []int64{42}, Kinds: []model.Kind{model.KindSudo}, MinSeverity: "info", RatePerMinute: 10}
	r := do(t, s, "PUT", "/api/v1/settings/telegram", tok, draft)
	if r.Code != 200 || strings.Contains(r.Body.String(), "123:secret") {
		t.Fatal(r.Code, r.Body)
	}
	r = do(t, s, "GET", "/api/v1/settings/telegram", tok, nil)
	if r.Code != 200 || strings.Contains(r.Body.String(), "123:secret") || !strings.Contains(r.Body.String(), `"has_token":true`) {
		t.Fatal(r.Code, r.Body)
	}
	r = do(t, s, "GET", "/api/v1/config", tok, nil)
	if !strings.Contains(r.Body.String(), `"rate_per_minute":10`) {
		t.Fatal("config returns stale policy", r.Body)
	}
}
