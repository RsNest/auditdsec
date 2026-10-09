// Package telegram delivers alerts to a Telegram chat and serves the bot
// commands. It talks to the HTTP API directly: one dependency-free file is
// easier to audit than a bot framework, and the agent only needs four methods.
//
// Two rules are not configurable. The bot answers only the chat ids in the
// allowlist, because a bot token that leaks would otherwise hand a stranger the
// command set. And the token is never written to a log or an error message.
package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/RsNest/auditdsec/internal/i18n"
	"github.com/RsNest/auditdsec/internal/model"
	"github.com/RsNest/auditdsec/internal/store"
)

const (
	defaultAPIBase = "https://api.telegram.org"
	sendTimeout    = 15 * time.Second
	pollTimeout    = 30 // seconds, Telegram long polling
	metaOffsetKey  = "tg_update_offset"
)

// Options configures the client.
type Options struct {
	Token    string
	ChatIDs  []int64
	APIBase  string
	Lang     i18n.Lang
	Host     string
	Profile  string
	BanHint  string // what to say about enforcement not being wired up yet
	Store    *store.Store
	Logger   *slog.Logger
	HTTP     *http.Client
	Now      func() time.Time
	Started  time.Time
	Location *time.Location

	// Debug reports whether the agent runs in debug mode, and LogLevel the
	// level its own log is written at. Both are shown by /debug.
	Debug    bool
	LogLevel string

	MinSeverity   model.Severity
	DedupWindow   time.Duration
	RatePerMinute int
	// QuietFrom and QuietTo are minutes from midnight; -1 disables quiet hours.
	QuietFrom int
	QuietTo   int
}

// Client is a Telegram bot client plus the alert policy (severity threshold,
// mute, quiet hours, grouping and rate limiting).
type Client struct {
	opt  Options
	log  *slog.Logger
	now  func() time.Time
	loc  *time.Location
	send *http.Client
	poll *http.Client

	mu         sync.Mutex
	diag       DiagFunc
	groups     map[string]*group
	tokens     float64
	lastRefill time.Time
	dropped    int
}

// group tracks repeats of one kind of event inside the dedup window.
type group struct {
	ev     model.Event
	sentAt time.Time
	extra  int
}

// New returns a client. It fails when the token or the chat allowlist is
// missing, so a misconfigured agent cannot start half-deaf.
func New(o Options) (*Client, error) {
	if o.Token == "" {
		return nil, fmt.Errorf("telegram: token is required")
	}
	if len(o.ChatIDs) == 0 {
		return nil, fmt.Errorf("telegram: at least one chat id is required")
	}
	if o.APIBase == "" {
		o.APIBase = defaultAPIBase
	}
	if o.Lang == "" {
		o.Lang = i18n.Default
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if o.DedupWindow <= 0 {
		o.DedupWindow = 5 * time.Minute
	}
	if o.RatePerMinute <= 0 {
		o.RatePerMinute = 20
	}
	if o.Started.IsZero() {
		o.Started = o.Now()
	}
	if o.Location == nil {
		o.Location = time.Local
	}
	send := o.HTTP
	if send == nil {
		send = &http.Client{Timeout: sendTimeout}
	}
	poll := &http.Client{Timeout: (pollTimeout + 15) * time.Second}
	if o.HTTP != nil {
		// Tests inject one client; reuse it for both paths.
		poll = o.HTTP
	}
	return &Client{
		opt:        o,
		log:        o.Logger,
		now:        o.Now,
		loc:        o.Location,
		send:       send,
		poll:       poll,
		groups:     map[string]*group{},
		tokens:     float64(o.RatePerMinute),
		lastRefill: o.Now(),
	}, nil
}

type apiResponse struct {
	OK          bool            `json:"ok"`
	Result      json.RawMessage `json:"result"`
	Description string          `json:"description"`
	ErrorCode   int             `json:"error_code"`
}

// call performs one API request. The token appears only in the URL and is
// never included in a returned error.
func (c *Client) call(ctx context.Context, hc *http.Client, method string, req, out any) error {
	var body io.Reader
	if req != nil {
		b, err := json.Marshal(req)
		if err != nil {
			return fmt.Errorf("telegram %s: encode request: %w", method, err)
		}
		body = bytes.NewReader(b)
	}
	url := fmt.Sprintf("%s/bot%s/%s", c.opt.APIBase, c.opt.Token, method)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if err != nil {
		return fmt.Errorf("telegram %s: build request: %w", method, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := hc.Do(httpReq)
	if err != nil {
		// A transport error can quote the URL, which carries the token.
		return fmt.Errorf("telegram %s: request failed", method)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return fmt.Errorf("telegram %s: read response: %w", method, err)
	}
	var ar apiResponse
	if err := json.Unmarshal(raw, &ar); err != nil {
		return fmt.Errorf("telegram %s: bad response (http %d)", method, resp.StatusCode)
	}
	if !ar.OK {
		return fmt.Errorf("telegram %s: %s (code %d)", method, ar.Description, ar.ErrorCode)
	}
	if out != nil && len(ar.Result) > 0 {
		if err := json.Unmarshal(ar.Result, out); err != nil {
			return fmt.Errorf("telegram %s: decode result: %w", method, err)
		}
	}
	return nil
}

type inlineButton struct {
	Text string `json:"text"`
	Data string `json:"callback_data"`
}

type inlineKeyboard struct {
	Rows [][]inlineButton `json:"inline_keyboard"`
}

type sendMessageRequest struct {
	ChatID      int64           `json:"chat_id"`
	Text        string          `json:"text"`
	ParseMode   string          `json:"parse_mode,omitempty"`
	ReplyMarkup *inlineKeyboard `json:"reply_markup,omitempty"`
	NoPreview   bool            `json:"disable_web_page_preview,omitempty"`
}

// SendTo sends one message to one chat.
func (c *Client) SendTo(ctx context.Context, chatID int64, text string, kb *inlineKeyboard) error {
	return c.call(ctx, c.send, "sendMessage", sendMessageRequest{
		ChatID:      chatID,
		Text:        text,
		ParseMode:   "HTML",
		ReplyMarkup: kb,
		NoPreview:   true,
	}, nil)
}

// Broadcast sends one message to every allowlisted chat, returning the first
// failure but still trying the rest: one blocked chat must not silence others.
func (c *Client) Broadcast(ctx context.Context, text string, kb *inlineKeyboard) error {
	var firstErr error
	for _, id := range c.opt.ChatIDs {
		if err := c.SendTo(ctx, id, text, kb); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// DiagItem is one line of the /debug report: an i18n key for the label and the
// value to show beside it.
type DiagItem struct {
	Key   string
	Value string
}

// DiagFunc supplies the lines that only the pipeline knows, such as how many
// events have been processed.
type DiagFunc func() []DiagItem

// SetDiag attaches the pipeline's diagnostics to the /debug command. It is a
// setter because the pipeline is built after the client it reports to.
func (c *Client) SetDiag(f DiagFunc) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.diag = f
}

// OpenGroups reports how many dedup windows are currently open, for /debug.
func (c *Client) OpenGroups() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.groups)
}

// Dropped reports how many alerts the rate limiter discarded, for /status.
func (c *Client) Dropped() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dropped
}
