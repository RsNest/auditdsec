package telegram

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/RsNest/auditdsec/internal/model"
	"github.com/RsNest/auditdsec/internal/store"
)

// Settings is the persisted notification policy. Token is only accepted on
// writes; View deliberately has a separate shape without a token field.
type Settings struct {
	Version       int          `json:"version"`
	Enabled       bool         `json:"enabled"`
	Token         string       `json:"token"`
	ChatIDs       []int64      `json:"chat_ids"`
	Kinds         []model.Kind `json:"kinds"`
	MinSeverity   string       `json:"min_severity"`
	QuietFrom     string       `json:"quiet_from"`
	QuietTo       string       `json:"quiet_to"`
	RatePerMinute int          `json:"rate_per_minute"`
	Bans          bool         `json:"bans"`
	StartupNotice bool         `json:"startup_notice"`
}

type SettingsView struct {
	Enabled        bool         `json:"enabled"`
	HasToken       bool         `json:"has_token"`
	ChatIDs        []int64      `json:"chat_ids"`
	Kinds          []model.Kind `json:"kinds"`
	AvailableKinds []model.Kind `json:"available_kinds"`
	MinSeverity    string       `json:"min_severity"`
	QuietFrom      string       `json:"quiet_from"`
	QuietTo        string       `json:"quiet_to"`
	RatePerMinute  int          `json:"rate_per_minute"`
	Bans           bool         `json:"bans"`
	StartupNotice  bool         `json:"startup_notice"`
	Status         string       `json:"status"`
	BotUsername    string       `json:"bot_username"`
	LastDelivery   time.Time    `json:"last_delivery"`
	LastError      string       `json:"last_error"`
}

// Managed swaps immutable clients, draining old sends and bot commands before
// applying new credentials. The pipeline keeps running without a bot configured.
type Managed struct {
	mu        sync.RWMutex
	edit      sync.Mutex
	base      Options
	path      string
	settings  Settings
	client    *Client
	ctx       context.Context
	cancel    context.CancelFunc
	done      chan struct{}
	diag      DiagFunc
	username  string
	last      time.Time
	lastError string
	attempt   time.Time
}

func NewManaged(o Options, stateDir string, startup bool) (*Managed, error) {
	// New normalizes transport, clock and policy defaults, but is only called
	// for a configured client below (the original strict constructor is retained).
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.RatePerMinute <= 0 {
		o.RatePerMinute = 20
	}
	s := Settings{Version: 1, Enabled: o.Token != "" && len(o.ChatIDs) > 0,
		Token: o.Token, ChatIDs: o.ChatIDs, Kinds: append([]model.Kind{}, model.AllKinds...),
		MinSeverity: o.MinSeverity.String(), RatePerMinute: o.RatePerMinute,
		Bans: true, StartupNotice: startup}
	if o.QuietFrom >= 0 && o.QuietTo >= 0 {
		s.QuietFrom = fmt.Sprintf("%02d:%02d", o.QuietFrom/60, o.QuietFrom%60)
		s.QuietTo = fmt.Sprintf("%02d:%02d", o.QuietTo/60, o.QuietTo%60)
	}
	m := &Managed{base: o, path: filepath.Join(stateDir, "telegram-settings.json"), settings: s}
	raw, err := os.ReadFile(m.path)
	if err == nil {
		var saved Settings
		if json.Unmarshal(raw, &saved) != nil || saved.Version != 1 || validateSettings(saved) != nil {
			m.settings.Enabled = false
			m.settings.Token = ""
			m.lastError = "saved_settings_invalid"
		} else {
			m.settings = saved
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		m.settings.Enabled = false
		m.settings.Token = ""
		m.lastError = "saved_settings_unreadable"
	}
	if m.settings.Enabled {
		m.client, err = m.build(m.settings)
		if err != nil {
			return nil, err
		}
		// Preserve the existing bot's cursor on the first migration from env.
		if raw == nil && o.Store != nil && o.Store.GetMeta(m.client.opt.OffsetKey) == "" {
			if legacy := o.Store.GetMeta(metaOffsetKey); legacy != "" {
				if err := o.Store.SetMeta(m.client.opt.OffsetKey, legacy); err != nil {
					return nil, err
				}
			}
		}
	}
	return m, nil
}

func clockMinutes(v string) (int, error) {
	if v == "" {
		return -1, nil
	}
	if !regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`).MatchString(v) {
		return 0, errors.New("invalid quiet hours: use HH:MM")
	}
	var h, n int
	_, err := fmt.Sscanf(v, "%d:%d", &h, &n)
	return h*60 + n, err
}

func validateSettings(s Settings) error {
	if s.Enabled && (s.Token == "" || len(s.ChatIDs) == 0) {
		return errors.New("token and at least one recipient are required when enabled")
	}
	if len(s.Token) > 256 || strings.ContainsAny(s.Token, "\r\n/ ?#") {
		return errors.New("invalid bot token")
	}
	if len(s.ChatIDs) > 16 {
		return errors.New("at most 16 recipients")
	}
	seen := map[int64]bool{}
	for _, id := range s.ChatIDs {
		if id == 0 || seen[id] {
			return errors.New("recipient IDs must be nonzero and unique")
		}
		seen[id] = true
	}
	seenKinds := map[model.Kind]bool{}
	for _, k := range s.Kinds {
		if !model.ValidKind(k) || seenKinds[k] {
			return errors.New("invalid or duplicate alert category")
		}
		seenKinds[k] = true
	}
	if _, err := model.ParseSeverity(s.MinSeverity); err != nil {
		return errors.New("invalid minimum severity")
	}
	if s.RatePerMinute < 1 || s.RatePerMinute > 1000 {
		return errors.New("message limit must be between 1 and 1000 per minute")
	}
	if (s.QuietFrom == "") != (s.QuietTo == "") {
		return errors.New("set both quiet hours or neither")
	}
	if _, err := clockMinutes(s.QuietFrom); err != nil {
		return err
	}
	_, err := clockMinutes(s.QuietTo)
	return err
}

func (m *Managed) build(s Settings) (*Client, error) {
	o := m.base
	o.Token, o.ChatIDs = s.Token, append([]int64{}, s.ChatIDs...)
	o.OffsetKey = fmt.Sprintf("tg_update_offset_%x", sha256.Sum256([]byte(s.Token)))
	o.MinSeverity, _ = model.ParseSeverity(s.MinSeverity)
	o.QuietFrom, _ = clockMinutes(s.QuietFrom)
	o.QuietTo, _ = clockMinutes(s.QuietTo)
	o.RatePerMinute = s.RatePerMinute
	c, err := New(o)
	if err == nil {
		c.SetDiag(m.diag)
	}
	return c, err
}

func (m *Managed) View() SettingsView {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s := m.settings
	status := "unconfigured"
	if s.Token != "" && len(s.ChatIDs) > 0 {
		status = "configured"
		if !s.Enabled {
			status = "disabled"
		}
	}
	if m.lastError != "" {
		status = "error"
	}
	last, lastError := m.last, m.lastError
	if m.client != nil {
		m.client.mu.Lock()
		last, lastError = m.client.lastDelivery, m.client.lastError
		m.client.mu.Unlock()
		if lastError != "" {
			status = "error"
		} else if !last.IsZero() {
			status = "connected"
		}
	}
	return SettingsView{Enabled: s.Enabled, HasToken: s.Token != "", ChatIDs: append([]int64{}, s.ChatIDs...),
		Kinds: append([]model.Kind{}, s.Kinds...), AvailableKinds: append([]model.Kind{}, model.AllKinds...),
		MinSeverity: s.MinSeverity, QuietFrom: s.QuietFrom, QuietTo: s.QuietTo, RatePerMinute: s.RatePerMinute,
		Bans: s.Bans, StartupNotice: s.StartupNotice, Status: status, BotUsername: m.username,
		LastDelivery: last, LastError: lastError}
}

// Apply validates a draft; only the test operation sends a message. Saving never sends
// an unsolicited test message. A blank token retains the stored secret.
func (m *Managed) Apply(ctx context.Context, s Settings, operation string) (SettingsView, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if !m.edit.TryLock() {
		return m.View(), errors.New("another Telegram operation is in progress")
	}
	defer m.edit.Unlock()
	if m.base.Now().Sub(m.attempt) < 3*time.Second {
		return m.View(), errors.New("wait 3 seconds before another Telegram operation")
	}
	m.attempt = m.base.Now()
	m.mu.RLock()
	if s.Token == "" {
		s.Token = m.settings.Token
	}
	m.mu.RUnlock()
	s.Version = 1
	if err := validateSettings(s); err != nil {
		return m.View(), err
	}
	sev, _ := model.ParseSeverity(s.MinSeverity)
	s.MinSeverity = sev.String()
	var username string
	if operation != "save" || s.Enabled {
		if s.Token == "" {
			return m.View(), errors.New("bot token is required")
		}
		candidate := s
		if len(candidate.ChatIDs) == 0 {
			candidate.ChatIDs = []int64{1}
		} // getMe requires no recipient
		c, err := m.build(candidate)
		if err != nil {
			return m.View(), err
		}
		var me struct {
			Username string `json:"username"`
			IsBot    bool   `json:"is_bot"`
		}
		if err := c.call(ctx, c.send, "getMe", nil, &me); err != nil {
			return m.View(), err
		}
		if !me.IsBot {
			return m.View(), errors.New("Telegram did not return a bot account")
		}
		username = me.Username
		if operation == "test" {
			if len(s.ChatIDs) == 0 {
				return m.View(), errors.New("at least one recipient is required")
			}
			for _, id := range s.ChatIDs {
				if err := c.SendTo(ctx, id, "auditdsec: test notification / тестовое уведомление", nil); err != nil {
					m.recordTest(s, err)
					return m.View(), err
				}
			}
			m.recordTest(s, nil)
		}
	}
	if operation != "save" {
		view := m.View()
		view.BotUsername = username
		return view, nil
	}
	var client *Client
	var err error
	if s.Enabled {
		client, err = m.build(s)
		if err != nil {
			return m.View(), err
		}
	}
	// No live state changes if durable storage fails.
	if err := writeSettings(m.path, s); err != nil {
		return m.View(), errors.New("cannot persist Telegram settings; previous settings remain active")
	}
	m.mu.Lock()
	m.stopLocked()
	if client != nil && m.client != nil && s.Token == m.settings.Token && slices.Equal(s.ChatIDs, m.settings.ChatIDs) {
		m.client.mu.Lock()
		client.lastDelivery, client.lastError = m.client.lastDelivery, m.client.lastError
		m.client.mu.Unlock()
	}
	m.settings, m.client, m.username, m.lastError = s, client, username, ""
	m.last = time.Time{}
	m.startLocked(false)
	m.mu.Unlock()
	return m.View(), nil
}

func (m *Managed) recordTest(s Settings, err error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	// Testing an unsaved bot or different recipient list is not proof that
	// the configured delivery path works.
	if m.client == nil || s.Token != m.settings.Token || !slices.Equal(s.ChatIDs, m.settings.ChatIDs) {
		return
	}
	m.client.mu.Lock()
	defer m.client.mu.Unlock()
	if err == nil {
		m.client.lastDelivery, m.client.lastError = m.base.Now(), ""
	} else {
		m.client.lastError = "delivery_failed"
	}
}

func writeSettings(path string, s Settings) error {
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".telegram-settings-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), path)
}

func (m *Managed) SetDiag(f DiagFunc) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.diag = f
	if m.client != nil {
		m.client.SetDiag(f)
	}
}

func (m *Managed) startLocked(startup bool) {
	if m.ctx == nil || m.client == nil {
		return
	}
	ctx, cancel := context.WithCancel(m.ctx)
	m.cancel, m.done = cancel, make(chan struct{})
	c, done, notice := m.client, m.done, startup && m.settings.StartupNotice
	go func() {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _ = c.RunBot(ctx) }()
		go func() { defer wg.Done(); c.RunGrouper(ctx) }()
		if notice {
			_ = c.SendStartupNotice(ctx)
		}
		wg.Wait()
		close(done)
	}()
}

func (m *Managed) stopLocked() {
	if m.cancel != nil {
		m.cancel()
		<-m.done
		m.cancel = nil
	}
}

func (m *Managed) Run(ctx context.Context) {
	m.mu.Lock()
	m.ctx = ctx
	m.startLocked(true)
	m.mu.Unlock()
	<-ctx.Done()
	m.mu.Lock()
	m.stopLocked()
	m.ctx = nil
	m.mu.Unlock()
}

func (m *Managed) Notify(ctx context.Context, ev model.Event) error {
	m.mu.RLock()
	allowed := false
	for _, k := range m.settings.Kinds {
		if ev.Kind == k {
			allowed = true
			break
		}
	}
	if m.client == nil || !allowed {
		m.mu.RUnlock()
		return nil
	}
	err := m.client.Notify(ctx, ev)
	m.mu.RUnlock()
	return err
}

func (m *Managed) NotifyBan(ctx context.Context, b store.Ban, applyErr error) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.client == nil || !m.settings.Bans {
		return nil
	}
	return m.client.NotifyBan(ctx, b, applyErr)
}

func (m *Managed) NotifyMessage(ctx context.Context, key string, args map[string]string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.client == nil || !m.settings.Bans {
		return nil
	}
	return m.client.NotifyMessage(ctx, key, args)
}
