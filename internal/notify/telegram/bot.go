package telegram

import (
	"context"
	"fmt"
	"html"
	"strconv"
	"strings"
	"time"

	"github.com/RsNest/auditdsec/internal/i18n"
	"github.com/RsNest/auditdsec/internal/model"
)

// manualBanDuration is how long a ban pressed by hand lasts. A day is long
// enough to stop a brute force and short enough that a mistake heals itself;
// permanent bans are reserved for repeat offenders in v0.2.
const manualBanDuration = 24 * time.Hour

type tgChat struct {
	ID int64 `json:"id"`
}

type tgUser struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
}

type tgMessage struct {
	MessageID int64   `json:"message_id"`
	Chat      tgChat  `json:"chat"`
	Text      string  `json:"text"`
	From      *tgUser `json:"from"`
}

type callbackQuery struct {
	ID      string     `json:"id"`
	Data    string     `json:"data"`
	Message *tgMessage `json:"message"`
	From    *tgUser    `json:"from"`
}

type update struct {
	UpdateID int64          `json:"update_id"`
	Message  *tgMessage     `json:"message"`
	Callback *callbackQuery `json:"callback_query"`
}

type getUpdatesRequest struct {
	Offset         int64    `json:"offset,omitempty"`
	Timeout        int      `json:"timeout"`
	AllowedUpdates []string `json:"allowed_updates,omitempty"`
}

type answerCallbackRequest struct {
	ID   string `json:"callback_query_id"`
	Text string `json:"text,omitempty"`
}

// RunBot polls for commands until the context is cancelled. Polling rather
// than a webhook keeps the agent usable on a host with no public HTTP port.
func (c *Client) RunBot(ctx context.Context) error {
	offset := int64(0)
	if v := c.opt.Store.GetMeta(c.opt.OffsetKey); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			offset = n
		}
	}

	for {
		if ctx.Err() != nil {
			return nil
		}
		started := c.now()
		ups, err := c.getUpdates(ctx, offset)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			c.log.Warn("cannot fetch Telegram updates", "error", err)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(5 * time.Second):
			}
			continue
		}
		for _, u := range ups {
			if ctx.Err() != nil {
				return nil
			}
			if u.UpdateID >= offset {
				offset = u.UpdateID + 1
			}
			c.handleUpdate(ctx, u)
		}
		if len(ups) > 0 {
			if err := c.opt.Store.SetMeta(c.opt.OffsetKey, strconv.FormatInt(offset, 10)); err != nil {
				c.log.Warn("cannot persist the Telegram offset", "error", err)
			}
			continue
		}

		// Telegram normally holds a long poll open for pollTimeout seconds, so
		// the loop paces itself. An endpoint that answers "nothing" instantly
		// — a proxy, a stub, a misconfigured api_base — would otherwise spin
		// this goroutine at full speed.
		if c.now().Sub(started) < time.Second {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(pollIdlePause):
			}
		}
	}
}

func (c *Client) getUpdates(ctx context.Context, offset int64) ([]update, error) {
	var ups []update
	err := c.call(ctx, c.poll, "getUpdates", getUpdatesRequest{
		Offset:         offset,
		Timeout:        pollTimeout,
		AllowedUpdates: []string{"message", "callback_query"},
	}, &ups)
	return ups, err
}

// handleUpdate dispatches one update. Anything from a chat outside the
// allowlist is logged and dropped without a reply: a stranger who finds the
// bot must not even learn that it is alive.
func (c *Client) handleUpdate(ctx context.Context, u update) {
	switch {
	case u.Message != nil:
		if !c.opt.allowed(u.Message.Chat.ID) {
			c.logRejected("message", u.Message.Chat.ID, u.Message.From)
			return
		}
		c.handleCommand(ctx, u.Message)
	case u.Callback != nil:
		chatID := int64(0)
		if u.Callback.Message != nil {
			chatID = u.Callback.Message.Chat.ID
		}
		if !c.opt.allowed(chatID) {
			c.logRejected("callback", chatID, u.Callback.From)
			return
		}
		c.handleCallback(ctx, u.Callback, chatID)
	}
}

func (c *Client) logRejected(kind string, chatID int64, from *tgUser) {
	user := ""
	if from != nil {
		user = from.Username
	}
	c.log.Warn("ignoring Telegram traffic from a chat that is not allowlisted",
		"kind", kind, "chat_id", chatID, "username", user)
}

func (o Options) allowed(chatID int64) bool {
	for _, id := range o.ChatIDs {
		if id == chatID {
			return true
		}
	}
	return false
}

func (c *Client) reply(ctx context.Context, chatID int64, text string) {
	if err := c.SendTo(ctx, chatID, text, nil); err != nil {
		c.log.Warn("cannot send a reply", "error", err)
	}
}

func (c *Client) handleCommand(ctx context.Context, m *tgMessage) {
	fields := strings.Fields(strings.TrimSpace(m.Text))
	if len(fields) == 0 {
		return
	}
	cmd := fields[0]
	if i := strings.IndexByte(cmd, '@'); i > 0 { // /status@my_bot
		cmd = cmd[:i]
	}
	args := fields[1:]
	chat := m.Chat.ID

	switch strings.ToLower(cmd) {
	case "/start":
		c.reply(ctx, chat, c.tr("ui.start", map[string]string{"host": c.opt.Host}))
	case "/help":
		c.reply(ctx, chat, c.tr("ui.help", nil))
	case "/status":
		c.reply(ctx, chat, c.statusText())
	case "/last":
		c.reply(ctx, chat, c.lastText(args))
	case "/ban":
		if len(args) == 0 {
			c.reply(ctx, chat, c.tr("ui.err.need_arg", map[string]string{"usage": "/ban 198.51.100.7"}))
			return
		}
		c.reply(ctx, chat, c.applyBan(ctx, chat, args[0]))
	case "/allow":
		c.cmdAllow(ctx, chat, args)
	case "/unallow":
		c.cmdUnallow(ctx, chat, args)
	case "/allowlist":
		c.reply(ctx, chat, c.allowlistText())
	case "/bans":
		c.reply(ctx, chat, c.bansText())
	case "/unban":
		c.cmdUnban(ctx, chat, args)
	case "/mute":
		c.cmdMute(ctx, chat, args)
	case "/unmute":
		if err := c.opt.Store.Mute(time.Time{}); err != nil {
			c.log.Warn("cannot clear the mute", "error", err)
		}
		c.reply(ctx, chat, c.tr("ui.mute.off", nil))
	case "/explain":
		c.cmdExplain(ctx, chat, args)
	case "/debug":
		c.reply(ctx, chat, c.debugText())
	case "/score":
		c.reply(ctx, chat, c.tr("ui.not_available", nil))
	default:
		c.reply(ctx, chat, c.tr("ui.err.unknown_cmd", nil))
	}
}

func (c *Client) handleCallback(ctx context.Context, q *callbackQuery, chat int64) {
	kind, arg, _ := strings.Cut(q.Data, ":")
	var answer string

	switch kind {
	case "ban":
		answer = c.applyBan(ctx, chat, arg)
	case "unban":
		answer = c.applyUnban(ctx, chat, arg)
	case "allow":
		answer = c.applyAllow(ctx, chat, arg)
	case "mute":
		hours, err := strconv.Atoi(arg)
		if err != nil || hours <= 0 {
			hours = 24
		}
		until := c.now().Add(time.Duration(hours) * time.Hour)
		if err := c.opt.Store.Mute(until); err != nil {
			c.log.Warn("cannot mute", "error", err)
		}
		answer = c.tr("ui.mute.on", map[string]string{"until": c.fmtTime(until)})
	default:
		answer = c.tr("ui.err.unknown_cmd", nil)
	}

	// Stop the button's spinner first, then post the outcome as a message so it
	// stays in the chat history.
	if err := c.call(ctx, c.send, "answerCallbackQuery", answerCallbackRequest{
		ID: q.ID, Text: stripTags(answer),
	}, nil); err != nil {
		c.log.Warn("cannot answer the callback query", "error", err)
	}
	c.reply(ctx, chat, answer)
}

func (c *Client) cmdAllow(ctx context.Context, chat int64, args []string) {
	if len(args) == 0 {
		c.reply(ctx, chat, c.tr("ui.err.need_arg", map[string]string{"usage": "/allow 203.0.113.9"}))
		return
	}
	c.reply(ctx, chat, c.applyAllow(ctx, chat, args[0]))
}

func (c *Client) cmdUnallow(ctx context.Context, chat int64, args []string) {
	if len(args) == 0 {
		c.reply(ctx, chat, c.tr("ui.err.need_arg", map[string]string{"usage": "/unallow 203.0.113.9"}))
		return
	}
	ip := args[0]
	removed, err := c.decisions().Unallow(ip, c.actor(chat))
	if err != nil {
		if text, ok := c.refusalText(ip, err); ok {
			c.reply(ctx, chat, text)
			return
		}
		c.log.Warn("cannot update the allowlist", "error", err)
	}
	key := "ui.allow.missing"
	if removed {
		key = "ui.allow.removed"
	}
	c.reply(ctx, chat, c.tr(key, map[string]string{"ip": ip}))
}

func (c *Client) cmdUnban(ctx context.Context, chat int64, args []string) {
	if len(args) == 0 {
		c.reply(ctx, chat, c.tr("ui.err.need_arg", map[string]string{"usage": "/unban 203.0.113.9"}))
		return
	}
	c.reply(ctx, chat, c.applyUnban(ctx, chat, args[0]))
}

func (c *Client) cmdMute(ctx context.Context, chat int64, args []string) {
	hours := 24
	if len(args) > 0 {
		if n, err := strconv.Atoi(args[0]); err == nil && n > 0 {
			hours = n
		}
	}
	until := c.now().Add(time.Duration(hours) * time.Hour)
	if err := c.opt.Store.Mute(until); err != nil {
		c.log.Warn("cannot mute", "error", err)
	}
	c.reply(ctx, chat, c.tr("ui.mute.on", map[string]string{"until": c.fmtTime(until)}))
}

func (c *Client) cmdExplain(ctx context.Context, chat int64, args []string) {
	kinds := make([]string, 0, len(model.AllKinds))
	for _, k := range model.AllKinds {
		kinds = append(kinds, string(k))
	}
	if len(args) == 0 {
		c.reply(ctx, chat, c.tr("ui.err.need_arg", map[string]string{"usage": "/explain " + kinds[0]}))
		return
	}
	kind := model.Kind(strings.ToLower(args[0]))
	if !model.ValidKind(kind) {
		c.reply(ctx, chat, c.tr("ui.err.unknown_kind", map[string]string{
			"kind": args[0], "kinds": strings.Join(kinds, ", "),
		}))
		return
	}
	c.reply(ctx, chat, c.tr("explain."+string(kind), nil))
}

// debugText reports the agent's internal state and, more importantly, says how
// debug mode is switched on. A diagnostic the user cannot enable is useless.
func (c *Client) debugText() string {
	state := c.tr("ui.debug.off", nil)
	if c.opt.Debug {
		state = c.tr("ui.debug.on", nil)
	}
	level := c.opt.LogLevel
	if level == "" {
		level = "info"
	}
	muted := c.tr("ui.not_muted", nil)
	if until := c.opt.Store.MutedUntil(); !until.IsZero() {
		muted = c.tr("ui.muted_until", map[string]string{"until": c.fmtTime(until)})
	}

	var b strings.Builder
	b.WriteString(c.tr("ui.debug", map[string]string{
		"debug":   state,
		"level":   level,
		"uptime":  humanDuration(c.now().Sub(c.opt.Started)),
		"groups":  strconv.Itoa(c.OpenGroups()),
		"dropped": strconv.Itoa(c.Dropped()),
		"muted":   muted,
	}))

	c.mu.Lock()
	diag := c.diag
	c.mu.Unlock()
	if diag != nil {
		for _, item := range diag() {
			fmt.Fprintf(&b, "\n%s: %s", c.tr(item.Key, nil), html.EscapeString(item.Value))
		}
	}

	b.WriteString("\n\n")
	b.WriteString(c.tr("ui.debug.hint", nil))
	return b.String()
}

func (c *Client) statusText() string {
	st, err := c.opt.Store.Stats(24 * time.Hour)
	if err != nil {
		c.log.Warn("cannot read the statistics", "error", err)
	}
	last := c.tr("ui.never", nil)
	if !st.Last.IsZero() {
		last = c.fmtTime(st.Last)
	}
	muted := c.tr("ui.not_muted", nil)
	if until := c.opt.Store.MutedUntil(); !until.IsZero() {
		muted = c.tr("ui.muted_until", map[string]string{"until": c.fmtTime(until)})
	}
	return c.tr("ui.status", map[string]string{
		"host":     c.opt.Host,
		"profile":  c.opt.Profile,
		"uptime":   humanDuration(c.now().Sub(c.opt.Started)),
		"events":   strconv.Itoa(st.Total),
		"critical": strconv.Itoa(st.Critical),
		"last":     last,
		"allow":    strconv.Itoa(len(c.opt.Store.Allowlist())),
		"muted":    muted,
	})
}

func (c *Client) lastText(args []string) string {
	n := 10
	if len(args) > 0 {
		if v, err := strconv.Atoi(args[0]); err == nil && v > 0 {
			n = v
		}
	}
	if n > 50 {
		n = 50
	}
	evs := c.opt.Store.Recent(n)
	if len(evs) == 0 {
		return c.tr("ui.last.empty", nil)
	}
	var b strings.Builder
	b.WriteString(c.tr("ui.last.header", map[string]string{"count": strconv.Itoa(len(evs))}))
	for i := len(evs) - 1; i >= 0; i-- { // newest first
		b.WriteString("\n")
		b.WriteString(c.renderEventLine(evs[i]))
	}
	return b.String()
}

func (c *Client) allowlistText() string {
	list := c.opt.Store.Allowlist()
	if len(list) == 0 {
		return c.tr("ui.allow.empty", nil)
	}
	var b strings.Builder
	b.WriteString(c.tr("ui.allow.header", map[string]string{"count": strconv.Itoa(len(list))}))
	for _, e := range list {
		fmt.Fprintf(&b, "\n<code>%s</code> — %s", e.IP, c.fmtTime(e.AddedAt))
	}
	return b.String()
}

func (c *Client) bansText() string {
	bans := c.opt.Store.Bans()
	if len(bans) == 0 {
		return c.tr("ui.ban.empty", nil)
	}
	var b strings.Builder
	b.WriteString(c.tr("ui.ban.header", map[string]string{"count": strconv.Itoa(len(bans))}))
	for _, ban := range bans {
		until := i18n.T(c.opt.Lang, "ui.never", nil)
		if !ban.Permanent() {
			until = c.fmtTime(ban.Until)
		}
		mark := "·"
		if ban.Applied {
			mark = "✓"
		}
		fmt.Fprintf(&b, "\n%s <code>%s</code> — %s, ×%d", mark, ban.IP, until, ban.Count)
	}
	return b.String()
}

// stripTags removes the HTML markup for contexts that take plain text only,
// such as the little toast shown when a button is pressed.
func stripTags(s string) string {
	var b strings.Builder
	depth := 0
	for _, r := range s {
		switch {
		case r == '<':
			depth++
		case r == '>' && depth > 0:
			depth--
		case depth == 0:
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}
