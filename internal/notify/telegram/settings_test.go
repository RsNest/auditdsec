package telegram

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RsNest/auditdsec/internal/model"
)

func TestManagedPersistenceAndSecret(t *testing.T) {
	var sends atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "bad-secret") {
			w.Write([]byte(`{"ok":false,"description":"bad-secret"}`))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/sendMessage") {
			sends.Add(1)
		}
		w.Write([]byte(`{"ok":true,"result":{"is_bot":true,"username":"test_bot"}}`))
	}))
	defer ts.Close()
	dir := t.TempDir()
	now := time.Now()
	o := Options{APIBase: ts.URL, Now: func() time.Time { return now }, QuietFrom: -1, QuietTo: -1}
	m, err := NewManaged(o, dir, false)
	if err != nil {
		t.Fatal(err)
	}
	if m.View().Status != "unconfigured" {
		t.Fatal(m.View())
	}
	s := Settings{Enabled: true, Token: "123:secret", ChatIDs: []int64{42, -100}, Kinds: []model.Kind{model.KindSudo}, MinSeverity: "warn", RatePerMinute: 20, Bans: true}
	v, err := m.Apply(context.Background(), s, "save")
	if err != nil {
		t.Fatal(err)
	}
	if sends.Load() != 0 {
		t.Fatal("saving sent an unsolicited message")
	}
	if err := m.Notify(context.Background(), model.Event{Kind: model.KindConfigChange, Severity: model.SevCritical}); err != nil {
		t.Fatal(err)
	}
	if sends.Load() != 0 {
		t.Fatal("disabled category was sent")
	}
	if err := m.Notify(context.Background(), model.Event{Kind: model.KindSudo, Severity: model.SevCritical}); err != nil {
		t.Fatal(err)
	}
	if sends.Load() != 2 || m.View().LastDelivery.IsZero() {
		t.Fatal("enabled category did not update delivery status")
	}
	sends.Store(0)
	b, _ := json.Marshal(v)
	if strings.Contains(string(b), "secret") {
		t.Fatal("view leaked the secret")
	}
	info, err := os.Stat(filepath.Join(dir, "telegram-settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0077 != 0 && os.PathSeparator != '\\' {
		t.Fatal("settings are not private")
	}
	m2, err := NewManaged(o, dir, false)
	if err != nil || !m2.View().HasToken {
		t.Fatal("restart lost managed settings", err)
	}
	now = now.Add(4 * time.Second)
	s.Token = "bad-secret"
	_, err = m.Apply(context.Background(), s, "save")
	if err == nil || strings.Contains(err.Error(), "bad-secret") {
		t.Fatal("verification failed to redact token", err)
	}
	if m.settings.Token != "123:secret" {
		t.Fatal("failed verification replaced active token")
	}
	now = now.Add(4 * time.Second)
	s.Token = ""
	_, err = m.Apply(context.Background(), s, "test")
	if err != nil || sends.Load() != 2 {
		t.Fatal("test did not reuse stored token for both recipients", err)
	}
	now = now.Add(4 * time.Second)
	m.path = filepath.Join(dir, "missing", "settings.json")
	s.Enabled = false
	_, err = m.Apply(context.Background(), s, "save")
	if err == nil || !m.View().Enabled {
		t.Fatal("persistence failure changed live settings", err)
	}
}

func TestManagedCorruptSettingsFailClosed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "telegram-settings.json"), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	m, err := NewManaged(Options{Token: "old-secret", ChatIDs: []int64{42}}, dir, true)
	if err != nil {
		t.Fatal(err)
	}
	if m.View().Enabled || m.View().HasToken || m.View().Status != "error" {
		t.Fatal("corrupt file reactivated env credentials")
	}
	if err := m.Notify(context.Background(), model.Event{Kind: model.KindSudo}); err != nil {
		t.Fatal(err)
	}
}
