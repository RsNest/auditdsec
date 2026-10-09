// Package config loads the agent's settings from a YAML file, applies the
// profile presets and lets environment variables override anything, which is
// how secrets stay out of the file in a Docker setup.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/RsNest/auditdsec/internal/i18n"
	"github.com/RsNest/auditdsec/internal/model"
	"github.com/RsNest/auditdsec/internal/redact"
)

// Profiles.
const (
	ProfileSimple = "simple"
	ProfilePro    = "pro"
)

// LogConfig controls the agent's own log file.
type LogConfig struct {
	File       string
	Level      string
	MaxSizeMB  int
	MaxBackups int
	Stdout     bool
}

// TelegramConfig controls the bot.
type TelegramConfig struct {
	Token         string
	ChatIDs       []int64
	APIBase       string
	MinSeverity   string
	DedupWindow   time.Duration
	RatePerMinute int
	QuietFrom     string
	QuietTo       string
	StartupNotice bool
}

// StoreConfig controls retention.
type StoreConfig struct {
	RetentionDays int
	MaxRecent     int
}

// HeartbeatConfig controls the "is auditd still alive" check. Silence from a
// compromised host looks exactly like silence from a quiet one, so this is not
// optional in spirit even though it can be switched off.
type HeartbeatConfig struct {
	Enabled    bool
	StaleAfter time.Duration
	CheckEvery time.Duration
}

// DetectConfig is the brute-force detector, which lands in v0.2. The settings
// are parsed now so an existing config file keeps working then.
type DetectConfig struct {
	Enabled       bool
	Window        time.Duration
	FailThreshold int
}

// CrowdSecConfig is the CrowdSec integration, which lands in v0.3.
type CrowdSecConfig struct {
	Enabled bool
	Mode    string
	LAPIURL string
	APIKey  string
}

// Config is the whole configuration.
type Config struct {
	Profile       string
	Lang          string
	Host          string
	AuditLog      string
	StateDir      string
	ReadFromStart bool
	Log           LogConfig
	Telegram      TelegramConfig
	Store         StoreConfig
	Heartbeat     HeartbeatConfig
	Detect        DetectConfig
	CrowdSec      CrowdSecConfig

	// Filled by validate.
	lang      i18n.Lang
	minSev    model.Severity
	quietFrom int // minutes from midnight, -1 when disabled
	quietTo   int
	badChatID string // a malformed chat id from the environment, reported by validate
}

// Defaults returns the preset for a profile. The simple profile is tuned for
// one VPS and a person who does not want to be paged over routine sudo; the pro
// profile reports everything and keeps data longer.
func Defaults(profile string) *Config {
	c := &Config{
		Profile:       profile,
		Lang:          string(i18n.Default),
		AuditLog:      "/var/log/audit/audit.log",
		StateDir:      "/var/lib/auditdsec",
		ReadFromStart: false,
		Log: LogConfig{
			File:       "/var/log/auditdsec/auditdsec.log",
			Level:      "info",
			MaxSizeMB:  10,
			MaxBackups: 3,
			Stdout:     true,
		},
		Telegram: TelegramConfig{
			APIBase:       "https://api.telegram.org",
			MinSeverity:   "warn",
			DedupWindow:   10 * time.Minute,
			RatePerMinute: 10,
			StartupNotice: true,
		},
		Store:     StoreConfig{RetentionDays: 14, MaxRecent: 200},
		Heartbeat: HeartbeatConfig{Enabled: true, StaleAfter: 6 * time.Hour, CheckEvery: time.Minute},
		Detect:    DetectConfig{Enabled: false, Window: 10 * time.Minute, FailThreshold: 10},
		CrowdSec:  CrowdSecConfig{Enabled: false, Mode: "push", LAPIURL: "http://127.0.0.1:8080"},
	}
	if profile == ProfilePro {
		c.Telegram.MinSeverity = "info"
		c.Telegram.DedupWindow = 5 * time.Minute
		c.Telegram.RatePerMinute = 30
		c.Store.RetentionDays = 90
		c.Heartbeat.StaleAfter = 2 * time.Hour
	}
	return c
}

// Load reads the config file, applies the profile preset and the environment,
// and validates the result. An empty path means "defaults and environment
// only", which is how the Docker image runs with nothing but two variables.
func Load(path string) (*Config, error) {
	var root *node
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("config: %w", err)
		}
		root, err = parseYAML(data)
		if err != nil {
			return nil, fmt.Errorf("config %s: %w", path, err)
		}
	}

	profile := ProfileSimple
	if root != nil {
		if n, ok := root.child("profile"); ok && n.kind == nodeScalar && n.str != "" {
			profile = n.str
		}
	}
	if v := os.Getenv("AUDITDSEC_PROFILE"); v != "" {
		profile = v
	}
	if profile != ProfileSimple && profile != ProfilePro {
		return nil, fmt.Errorf("config: unknown profile %q (want %s or %s)", profile, ProfileSimple, ProfilePro)
	}

	c := Defaults(profile)
	if root != nil {
		if err := c.decode(root); err != nil {
			return nil, fmt.Errorf("config %s: %w", path, err)
		}
	}
	c.applyEnv()
	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) decode(root *node) error {
	d := &dec{}
	d.strict(root, "", "profile", "lang", "host", "audit_log", "state_dir",
		"read_from_start", "log", "telegram", "store", "heartbeat", "detect", "crowdsec")

	d.str(root, "lang", &c.Lang)
	d.str(root, "host", &c.Host)
	d.str(root, "audit_log", &c.AuditLog)
	d.str(root, "state_dir", &c.StateDir)
	d.boolean(root, "read_from_start", &c.ReadFromStart)

	if n := d.section(root, "log"); n != nil {
		d.strict(n, "log", "file", "level", "max_size_mb", "max_backups", "stdout")
		d.str(n, "file", &c.Log.File)
		d.str(n, "level", &c.Log.Level)
		d.integer(n, "max_size_mb", &c.Log.MaxSizeMB)
		d.integer(n, "max_backups", &c.Log.MaxBackups)
		d.boolean(n, "stdout", &c.Log.Stdout)
	}

	if n := d.section(root, "telegram"); n != nil {
		d.strict(n, "telegram", "token", "chat_ids", "api_base", "min_severity",
			"dedup_window", "rate_per_minute", "quiet_from", "quiet_to", "startup_notice")
		d.str(n, "token", &c.Telegram.Token)
		d.int64List(n, "chat_ids", &c.Telegram.ChatIDs)
		d.str(n, "api_base", &c.Telegram.APIBase)
		d.str(n, "min_severity", &c.Telegram.MinSeverity)
		d.duration(n, "dedup_window", &c.Telegram.DedupWindow)
		d.integer(n, "rate_per_minute", &c.Telegram.RatePerMinute)
		d.str(n, "quiet_from", &c.Telegram.QuietFrom)
		d.str(n, "quiet_to", &c.Telegram.QuietTo)
		d.boolean(n, "startup_notice", &c.Telegram.StartupNotice)
	}

	if n := d.section(root, "store"); n != nil {
		d.strict(n, "store", "retention_days", "max_recent")
		d.integer(n, "retention_days", &c.Store.RetentionDays)
		d.integer(n, "max_recent", &c.Store.MaxRecent)
	}

	if n := d.section(root, "heartbeat"); n != nil {
		d.strict(n, "heartbeat", "enabled", "stale_after", "check_every")
		d.boolean(n, "enabled", &c.Heartbeat.Enabled)
		d.duration(n, "stale_after", &c.Heartbeat.StaleAfter)
		d.duration(n, "check_every", &c.Heartbeat.CheckEvery)
	}

	if n := d.section(root, "detect"); n != nil {
		d.strict(n, "detect", "enabled", "window", "fail_threshold")
		d.boolean(n, "enabled", &c.Detect.Enabled)
		d.duration(n, "window", &c.Detect.Window)
		d.integer(n, "fail_threshold", &c.Detect.FailThreshold)
	}

	if n := d.section(root, "crowdsec"); n != nil {
		d.strict(n, "crowdsec", "enabled", "mode", "lapi_url", "api_key")
		d.boolean(n, "enabled", &c.CrowdSec.Enabled)
		d.str(n, "mode", &c.CrowdSec.Mode)
		d.str(n, "lapi_url", &c.CrowdSec.LAPIURL)
		d.str(n, "api_key", &c.CrowdSec.APIKey)
	}

	return d.err()
}

// applyEnv lets the environment win over the file. Secrets belong here rather
// than in a file that ends up in a git repository.
func (c *Config) applyEnv() {
	envStr("AUDITDSEC_LANG", &c.Lang)
	envStr("AUDITDSEC_HOST", &c.Host)
	envStr("AUDITDSEC_AUDIT_LOG", &c.AuditLog)
	envStr("AUDITDSEC_STATE_DIR", &c.StateDir)
	envStr("AUDITDSEC_LOG_FILE", &c.Log.File)
	envStr("AUDITDSEC_LOG_LEVEL", &c.Log.Level)
	envStr("AUDITDSEC_TG_TOKEN", &c.Telegram.Token)
	envStr("AUDITDSEC_TG_API_BASE", &c.Telegram.APIBase)
	envStr("AUDITDSEC_MIN_SEVERITY", &c.Telegram.MinSeverity)

	if v := os.Getenv("AUDITDSEC_TG_CHAT_ID"); v != "" {
		var ids []int64
		for _, part := range strings.Split(v, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			id, err := strconv.ParseInt(part, 10, 64)
			if err != nil {
				// Reported by validate as "no chat ids", with this detail.
				c.Telegram.ChatIDs = nil
				c.badChatID = part
				return
			}
			ids = append(ids, id)
		}
		c.Telegram.ChatIDs = ids
	}
	if v := os.Getenv("AUDITDSEC_RETENTION_DAYS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.Store.RetentionDays = n
		}
	}
}

func envStr(key string, dst *string) {
	if v := os.Getenv(key); v != "" {
		*dst = v
	}
}

func (c *Config) validate() error {
	var errs []string
	add := func(format string, a ...any) { errs = append(errs, fmt.Sprintf(format, a...)) }

	lang, err := i18n.ParseLang(c.Lang)
	if err != nil {
		add("lang: %v", err)
	}
	c.lang = lang

	if c.AuditLog == "" {
		add("audit_log: must not be empty")
	}
	if c.StateDir == "" {
		add("state_dir: must not be empty")
	}
	if c.Telegram.Token == "" {
		add("telegram.token: required (set it in the file or in AUDITDSEC_TG_TOKEN)")
	}
	if c.badChatID != "" {
		add("telegram.chat_ids: %q is not a number", c.badChatID)
	}
	if len(c.Telegram.ChatIDs) == 0 {
		add("telegram.chat_ids: at least one chat id is required; the bot answers nobody else")
	}
	if c.Telegram.APIBase == "" {
		add("telegram.api_base: must not be empty")
	}
	sev, err := model.ParseSeverity(c.Telegram.MinSeverity)
	if err != nil {
		add("telegram.min_severity: %v", err)
	}
	c.minSev = sev
	if c.Telegram.DedupWindow <= 0 {
		add("telegram.dedup_window: must be positive")
	}
	if c.Telegram.RatePerMinute <= 0 {
		add("telegram.rate_per_minute: must be positive")
	}

	c.quietFrom, c.quietTo = -1, -1
	switch {
	case c.Telegram.QuietFrom == "" && c.Telegram.QuietTo == "":
	case c.Telegram.QuietFrom == "" || c.Telegram.QuietTo == "":
		add("telegram.quiet_from/quiet_to: set both or neither")
	default:
		from, ferr := parseClock(c.Telegram.QuietFrom)
		to, terr := parseClock(c.Telegram.QuietTo)
		if ferr != nil {
			add("telegram.quiet_from: %v", ferr)
		}
		if terr != nil {
			add("telegram.quiet_to: %v", terr)
		}
		if ferr == nil && terr == nil {
			c.quietFrom, c.quietTo = from, to
		}
	}

	if c.Store.RetentionDays < 0 {
		add("store.retention_days: must not be negative")
	}
	if c.Store.MaxRecent <= 0 {
		add("store.max_recent: must be positive")
	}
	if c.Heartbeat.Enabled {
		if c.Heartbeat.StaleAfter <= 0 {
			add("heartbeat.stale_after: must be positive")
		}
		if c.Heartbeat.CheckEvery <= 0 {
			add("heartbeat.check_every: must be positive")
		}
	}
	if c.Log.MaxSizeMB <= 0 {
		add("log.max_size_mb: must be positive")
	}
	if c.Log.MaxBackups < 0 {
		add("log.max_backups: must not be negative")
	}
	switch strings.ToLower(c.Log.Level) {
	case "debug", "info", "warn", "error":
	default:
		add("log.level: unknown level %q (want debug, info, warn or error)", c.Log.Level)
	}
	if c.CrowdSec.Enabled {
		switch c.CrowdSec.Mode {
		case "push", "pull", "both":
		default:
			add("crowdsec.mode: unknown mode %q (want push, pull or both)", c.CrowdSec.Mode)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("config is not valid:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}

// Language returns the validated UI language.
func (c *Config) Language() i18n.Lang { return c.lang }

// MinSeverity returns the validated alert threshold.
func (c *Config) MinSeverity() model.Severity { return c.minSev }

// QuietHours returns the quiet window in minutes from midnight, local time.
func (c *Config) QuietHours() (from, to int, enabled bool) {
	return c.quietFrom, c.quietTo, c.quietFrom >= 0 && c.quietTo >= 0
}

// AllowedChat reports whether a chat is allowed to talk to the bot.
func (c *Config) AllowedChat(id int64) bool {
	for _, want := range c.Telegram.ChatIDs {
		if want == id {
			return true
		}
	}
	return false
}

// Redacted renders the resolved configuration for `check-config`, with the
// token and the CrowdSec key masked so the output is safe to paste into an
// issue report.
func (c *Config) Redacted() string {
	var b strings.Builder
	fmt.Fprintf(&b, "profile:          %s\n", c.Profile)
	fmt.Fprintf(&b, "lang:             %s\n", c.Lang)
	fmt.Fprintf(&b, "host:             %s\n", orDefault(c.Host, "(system host name)"))
	fmt.Fprintf(&b, "audit_log:        %s\n", c.AuditLog)
	fmt.Fprintf(&b, "state_dir:        %s\n", c.StateDir)
	fmt.Fprintf(&b, "read_from_start:  %t\n", c.ReadFromStart)
	fmt.Fprintf(&b, "log:              %s (level %s, %d MB x %d)\n", c.Log.File, c.Log.Level, c.Log.MaxSizeMB, c.Log.MaxBackups)
	fmt.Fprintf(&b, "telegram.token:   %s\n", redact.Token(c.Telegram.Token))
	fmt.Fprintf(&b, "telegram.chats:   %v\n", c.Telegram.ChatIDs)
	fmt.Fprintf(&b, "telegram.alerts:  from %s, dedup %s, %d msg/min\n", c.Telegram.MinSeverity, c.Telegram.DedupWindow, c.Telegram.RatePerMinute)
	if _, _, ok := c.QuietHours(); ok {
		fmt.Fprintf(&b, "telegram.quiet:   %s-%s\n", c.Telegram.QuietFrom, c.Telegram.QuietTo)
	}
	fmt.Fprintf(&b, "store:            %d days, %d recent\n", c.Store.RetentionDays, c.Store.MaxRecent)
	fmt.Fprintf(&b, "heartbeat:        enabled=%t stale_after=%s every=%s\n", c.Heartbeat.Enabled, c.Heartbeat.StaleAfter, c.Heartbeat.CheckEvery)
	fmt.Fprintf(&b, "detect:           enabled=%t (v0.2)\n", c.Detect.Enabled)
	fmt.Fprintf(&b, "crowdsec:         enabled=%t mode=%s key=%s (v0.3)\n", c.CrowdSec.Enabled, c.CrowdSec.Mode, redact.Token(c.CrowdSec.APIKey))
	return b.String()
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// parseClock reads "HH:MM" into minutes from midnight.
func parseClock(s string) (int, error) {
	parts := strings.Split(strings.TrimSpace(s), ":")
	if len(parts) != 2 {
		return 0, fmt.Errorf("expected HH:MM, got %q", s)
	}
	h, err := strconv.Atoi(parts[0])
	if err != nil || h < 0 || h > 23 {
		return 0, fmt.Errorf("expected an hour between 00 and 23, got %q", parts[0])
	}
	m, err := strconv.Atoi(parts[1])
	if err != nil || m < 0 || m > 59 {
		return 0, fmt.Errorf("expected minutes between 00 and 59, got %q", parts[1])
	}
	return h*60 + m, nil
}
