package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RsNest/auditdsec/internal/i18n"
	"github.com/RsNest/auditdsec/internal/model"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "auditdsec.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// clearEnv removes every AUDITDSEC_* variable for the duration of a test, so a
// developer's own shell cannot change the result.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, kv := range os.Environ() {
		if k := strings.SplitN(kv, "=", 2)[0]; strings.HasPrefix(k, "AUDITDSEC_") {
			t.Setenv(k, "")
			os.Unsetenv(k)
		}
	}
}

func TestLoadFullFile(t *testing.T) {
	clearEnv(t)
	path := writeConfig(t, `
# auditdsec configuration
profile: pro
lang: en
host: web01
audit_log: /var/log/audit/audit.log
state_dir: /var/lib/auditdsec
read_from_start: true

log:
  file: /var/log/auditdsec/agent.log
  level: debug
  max_size_mb: 20
  max_backups: 5
  stdout: false

telegram:
  token: "123456789:AAEhBOweik6ad"
  chat_ids:
    - 111222333
    - -100444555666
  min_severity: warn
  dedup_window: 3m
  rate_per_minute: 15
  quiet_from: "23:00"
  quiet_to: "07:30"
  startup_notice: false

store:
  retention_days: 60
  max_recent: 500

heartbeat:
  enabled: true
  stale_after: 4h
  check_every: 30s

detect:
  enabled: true
  window: 15m
  fail_threshold: 7

crowdsec:
  enabled: true
  mode: both
  lapi_url: http://127.0.0.1:8080
  api_key: secretkey
`)
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if c.Profile != ProfilePro {
		t.Errorf("Profile = %q", c.Profile)
	}
	if c.Language() != i18n.LangEN {
		t.Errorf("Language = %q", c.Language())
	}
	if c.Host != "web01" || !c.ReadFromStart {
		t.Errorf("host/read_from_start = %q/%t", c.Host, c.ReadFromStart)
	}
	if c.Log.Level != "debug" || c.Log.MaxSizeMB != 20 || c.Log.MaxBackups != 5 || c.Log.Stdout {
		t.Errorf("log = %+v", c.Log)
	}
	if len(c.Telegram.ChatIDs) != 2 || c.Telegram.ChatIDs[1] != -100444555666 {
		t.Errorf("chat_ids = %v", c.Telegram.ChatIDs)
	}
	if c.MinSeverity() != model.SevWarn {
		t.Errorf("MinSeverity = %v", c.MinSeverity())
	}
	if c.Telegram.DedupWindow != 3*time.Minute || c.Telegram.RatePerMinute != 15 {
		t.Errorf("telegram = %+v", c.Telegram)
	}
	from, to, ok := c.QuietHours()
	if !ok || from != 23*60 || to != 7*60+30 {
		t.Errorf("QuietHours = %d, %d, %v", from, to, ok)
	}
	if c.Store.RetentionDays != 60 || c.Store.MaxRecent != 500 {
		t.Errorf("store = %+v", c.Store)
	}
	if c.Heartbeat.StaleAfter != 4*time.Hour || c.Heartbeat.CheckEvery != 30*time.Second {
		t.Errorf("heartbeat = %+v", c.Heartbeat)
	}
	if !c.Detect.Enabled || c.Detect.FailThreshold != 7 {
		t.Errorf("detect = %+v", c.Detect)
	}
	if c.CrowdSec.Mode != "both" {
		t.Errorf("crowdsec = %+v", c.CrowdSec)
	}
	if c.Telegram.StartupNotice {
		t.Error("startup_notice should be false")
	}
}

func TestProfilePresets(t *testing.T) {
	simple := Defaults(ProfileSimple)
	pro := Defaults(ProfilePro)
	if simple.Telegram.MinSeverity != "warn" || pro.Telegram.MinSeverity != "info" {
		t.Errorf("min_severity presets: simple=%q pro=%q", simple.Telegram.MinSeverity, pro.Telegram.MinSeverity)
	}
	if !(pro.Store.RetentionDays > simple.Store.RetentionDays) {
		t.Error("the pro profile should keep events longer")
	}
	if !(pro.Telegram.RatePerMinute > simple.Telegram.RatePerMinute) {
		t.Error("the pro profile should allow more messages per minute")
	}
}

func TestEnvOverridesFile(t *testing.T) {
	clearEnv(t)
	path := writeConfig(t, `
telegram:
  token: from-file
  chat_ids: [1]
lang: ru
`)
	t.Setenv("AUDITDSEC_TG_TOKEN", "from-env")
	t.Setenv("AUDITDSEC_TG_CHAT_ID", "42, 43")
	t.Setenv("AUDITDSEC_LANG", "en")
	t.Setenv("AUDITDSEC_AUDIT_LOG", "/tmp/audit.log")
	t.Setenv("AUDITDSEC_RETENTION_DAYS", "7")

	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Telegram.Token != "from-env" {
		t.Errorf("token = %q", c.Telegram.Token)
	}
	if len(c.Telegram.ChatIDs) != 2 || c.Telegram.ChatIDs[0] != 42 {
		t.Errorf("chat_ids = %v", c.Telegram.ChatIDs)
	}
	if c.Language() != i18n.LangEN {
		t.Errorf("lang = %q", c.Language())
	}
	if c.AuditLog != "/tmp/audit.log" || c.Store.RetentionDays != 7 {
		t.Errorf("env overrides not applied: %q %d", c.AuditLog, c.Store.RetentionDays)
	}
}

// Debug mode must be switchable three ways, and must raise the log level with
// it: a debug mode that stayed at info would print nothing new.
func TestDebugMode(t *testing.T) {
	t.Run("off by default", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("AUDITDSEC_TG_TOKEN", "t")
		t.Setenv("AUDITDSEC_TG_CHAT_ID", "1")
		c, err := Load("")
		if err != nil {
			t.Fatal(err)
		}
		if c.Debug || c.Log.Level != "info" {
			t.Errorf("Debug = %v, level = %q", c.Debug, c.Log.Level)
		}
	})

	t.Run("from the file", func(t *testing.T) {
		clearEnv(t)
		c, err := Load(writeConfig(t, "debug: true\ntelegram:\n  token: t\n  chat_ids: [1]\n"))
		if err != nil {
			t.Fatal(err)
		}
		if !c.Debug || c.Log.Level != "debug" {
			t.Errorf("Debug = %v, level = %q", c.Debug, c.Log.Level)
		}
	})

	t.Run("from the environment", func(t *testing.T) {
		for _, v := range []string{"1", "true", "yes", "on"} {
			clearEnv(t)
			t.Setenv("AUDITDSEC_TG_TOKEN", "t")
			t.Setenv("AUDITDSEC_TG_CHAT_ID", "1")
			t.Setenv("AUDITDSEC_DEBUG", v)
			c, err := Load("")
			if err != nil {
				t.Fatal(err)
			}
			if !c.Debug || c.Log.Level != "debug" {
				t.Errorf("AUDITDSEC_DEBUG=%s gave Debug = %v, level = %q", v, c.Debug, c.Log.Level)
			}
		}
	})

	t.Run("the environment can also switch it off", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("AUDITDSEC_DEBUG", "0")
		c, err := Load(writeConfig(t, "debug: true\ntelegram:\n  token: t\n  chat_ids: [1]\n"))
		if err != nil {
			t.Fatal(err)
		}
		if c.Debug {
			t.Error("AUDITDSEC_DEBUG=0 should win over the file")
		}
	})

	t.Run("a nonsense value is an error, not a silent no", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("AUDITDSEC_TG_TOKEN", "t")
		t.Setenv("AUDITDSEC_TG_CHAT_ID", "1")
		t.Setenv("AUDITDSEC_DEBUG", "maybe")
		if _, err := Load(""); err == nil || !strings.Contains(err.Error(), "AUDITDSEC_DEBUG") {
			t.Errorf("error = %v, want it to name AUDITDSEC_DEBUG", err)
		}
	})
}

func TestLoadWithoutFile(t *testing.T) {
	clearEnv(t)
	t.Setenv("AUDITDSEC_TG_TOKEN", "t")
	t.Setenv("AUDITDSEC_TG_CHAT_ID", "7")
	c, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Profile != ProfileSimple || !c.AllowedChat(7) {
		t.Errorf("got %+v", c.Telegram)
	}
}

func TestProfileFromEnv(t *testing.T) {
	clearEnv(t)
	t.Setenv("AUDITDSEC_TG_TOKEN", "t")
	t.Setenv("AUDITDSEC_TG_CHAT_ID", "7")
	t.Setenv("AUDITDSEC_PROFILE", "pro")
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if c.Profile != ProfilePro || c.MinSeverity() != model.SevInfo {
		t.Errorf("profile = %q, min severity = %v", c.Profile, c.MinSeverity())
	}
}

// The bot must refuse to start without an allowlist: a bot with a token but no
// chat id would answer whoever found it.
func TestValidationRequiresTokenAndChat(t *testing.T) {
	clearEnv(t)
	_, err := Load(writeConfig(t, "profile: simple\n"))
	if err == nil {
		t.Fatal("expected validation to fail")
	}
	for _, want := range []string{"telegram.token", "telegram.chat_ids"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %s, got: %v", want, err)
		}
	}
}

func TestValidationErrors(t *testing.T) {
	clearEnv(t)
	tests := map[string]string{
		"unknown profile":  "profile: paranoid\n",
		"bad lang":         "lang: de\ntelegram:\n  token: t\n  chat_ids: [1]\n",
		"bad severity":     "telegram:\n  token: t\n  chat_ids: [1]\n  min_severity: loud\n",
		"half quiet hours": "telegram:\n  token: t\n  chat_ids: [1]\n  quiet_from: \"23:00\"\n",
		"bad clock":        "telegram:\n  token: t\n  chat_ids: [1]\n  quiet_from: \"25:00\"\n  quiet_to: \"07:00\"\n",
		"bad duration":     "telegram:\n  token: t\n  chat_ids: [1]\n  dedup_window: soon\n",
		"bad number":       "telegram:\n  token: t\n  chat_ids: [1]\n  rate_per_minute: many\n",
		"bad bool":         "read_from_start: maybe\ntelegram:\n  token: t\n  chat_ids: [1]\n",
		"unknown setting":  "telegram:\n  token: t\n  chat_ids: [1]\n  chat_id: 5\n",
		"bad log level":    "telegram:\n  token: t\n  chat_ids: [1]\nlog:\n  level: chatty\n",
		"negative rate":    "telegram:\n  token: t\n  chat_ids: [1]\n  rate_per_minute: 0\n",
		"bad crowdsec":     "telegram:\n  token: t\n  chat_ids: [1]\ncrowdsec:\n  enabled: true\n  mode: sideways\n",
		"chat id not num":  "telegram:\n  token: t\n  chat_ids: [abc]\n",
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeConfig(t, body)); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

func TestLoadMissingFile(t *testing.T) {
	clearEnv(t)
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Error("expected an error for a missing file")
	}
}

func TestRedactedHidesSecrets(t *testing.T) {
	clearEnv(t)
	c, err := Load(writeConfig(t, `
telegram:
  token: "123456789:AAEhBOweik6ad"
  chat_ids: [1]
crowdsec:
  api_key: supersecret
`))
	if err != nil {
		t.Fatal(err)
	}
	out := c.Redacted()
	for _, secret := range []string{"AAEhBOweik6ad", "supersecret"} {
		if strings.Contains(out, secret) {
			t.Errorf("Redacted leaked %q:\n%s", secret, out)
		}
	}
	if !strings.Contains(out, "123456789:***") {
		t.Errorf("Redacted should keep the bot id visible:\n%s", out)
	}
}

func TestAllowedChat(t *testing.T) {
	c := &Config{Telegram: TelegramConfig{ChatIDs: []int64{1, -100}}}
	if !c.AllowedChat(1) || !c.AllowedChat(-100) || c.AllowedChat(2) {
		t.Error("AllowedChat is wrong")
	}
}

func TestPanelURLAndReachability(t *testing.T) {
	cases := []struct {
		listen, public string
		wantURL        string
		wantLoopback   bool
	}{
		{"127.0.0.1:9477", "", "http://127.0.0.1:9477", true},
		{"localhost:9477", "", "http://localhost:9477", true},
		{"0.0.0.0:9477", "", "http://127.0.0.1:9477", false},
		{"127.0.0.1:9477", "https://panel.example.com", "https://panel.example.com", false},
		{"127.0.0.1:9477", "https://panel.example.com/", "https://panel.example.com", false},
		{"[::1]:9477", "", "http://[::1]:9477", true},
	}
	for _, c := range cases {
		cfg := Defaults(ProfileSimple)
		cfg.Web.Listen, cfg.Web.PublicURL = c.listen, c.public
		if got := cfg.PanelURL(); got != c.wantURL {
			t.Errorf("listen %q public %q: url = %q, want %q", c.listen, c.public, got, c.wantURL)
		}
		if got := cfg.PanelIsLoopbackOnly(); got != c.wantLoopback {
			t.Errorf("listen %q public %q: loopback = %t, want %t", c.listen, c.public, got, c.wantLoopback)
		}
	}
}

// A panel on a public address speaks plain HTTP, so the password would cross
// the network readable. The agent must refuse rather than warn.
func TestPublicListenAddressIsRefused(t *testing.T) {
	base := func() *Config {
		c := Defaults(ProfileSimple)
		c.Telegram.Token, c.Telegram.ChatIDs = "t", []int64{1}
		c.Web.Enabled, c.Web.Password = true, "a-long-test-password"
		return c
	}
	for _, listen := range []string{"203.0.113.4:9477", "[2001:db8::1]:9477"} {
		c := base()
		c.Web.Listen = listen
		if err := c.validate(); err == nil {
			t.Errorf("listen %q was accepted", listen)
		}
	}
	for _, listen := range []string{"127.0.0.1:9477", "0.0.0.0:9477", "192.168.1.5:9477"} {
		c := base()
		c.Web.Listen = listen
		if err := c.validate(); err != nil {
			t.Errorf("listen %q was refused: %v", listen, err)
		}
	}
	c := base()
	c.Web.PublicURL = "not a url"
	if err := c.validate(); err == nil {
		t.Error("a malformed public_url was accepted")
	}
}
