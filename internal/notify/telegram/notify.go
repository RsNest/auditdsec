package telegram

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/RsNest/auditdsec/internal/model"
	"github.com/RsNest/auditdsec/internal/store"
)

// Notify delivers one event, applying the alert policy in this order: severity
// threshold, mute, quiet hours, grouping of repeats, then the rate limit.
// Critical events ignore mute and quiet hours — the whole point of the agent is
// that a compromise reaches you at 3am.
func (c *Client) Notify(ctx context.Context, ev model.Event) error {
	if ev.Severity < c.opt.MinSeverity {
		c.decided(ev, "held", fmt.Sprintf("severity %s is below min_severity=%s",
			ev.Severity, c.opt.MinSeverity))
		return nil
	}
	critical := ev.Severity >= model.SevCritical
	now := c.now()

	if !critical {
		if until := c.opt.Store.MutedUntil(); !until.IsZero() {
			c.decided(ev, "held", "alerts are muted until "+c.fmtTime(until))
			return nil
		}
		if c.inQuietHours(now) {
			c.decided(ev, "held", "inside quiet hours")
			return nil
		}
	}

	if n, repeat := c.suppressAsRepeat(ev, now); repeat {
		c.decided(ev, "grouped", fmt.Sprintf("repeat %d inside the %s dedup window",
			n, humanDuration(c.opt.DedupWindow)))
		return nil
	}
	if !c.allowRate(now) {
		c.mu.Lock()
		c.dropped++
		dropped := c.dropped
		c.mu.Unlock()
		c.log.Warn("alert dropped by the rate limit",
			"kind", ev.Kind, "per_minute", c.opt.RatePerMinute, "dropped_total", dropped)
		return nil
	}
	if err := c.Broadcast(ctx, c.renderEvent(ev), c.eventKeyboard(ev)); err != nil {
		return err
	}
	c.decided(ev, "sent", "")
	return nil
}

// decided records what happened to an event. These lines are the trail that
// answers "why did no alert arrive", so debug mode turns them on by raising the
// log level rather than by a switch of its own.
func (c *Client) decided(ev model.Event, verdict, reason string) {
	args := []any{"verdict", verdict, "kind", string(ev.Kind), "severity", ev.Severity.String()}
	if ev.User != "" {
		args = append(args, "user", ev.User)
	}
	if ev.SrcIP != "" {
		args = append(args, "ip", ev.SrcIP)
	}
	if reason != "" {
		args = append(args, "reason", reason)
	}
	c.log.Debug("alert decision", args...)
}

// suppressAsRepeat reports whether the event is a repeat inside the dedup
// window, counting it so FlushGroups can report "and 46 more" in one message
// instead of 47 separate ones. The count is returned for the debug trail.
func (c *Client) suppressAsRepeat(ev model.Event, now time.Time) (int, bool) {
	key := ev.DedupKey()
	c.mu.Lock()
	defer c.mu.Unlock()
	if g, ok := c.groups[key]; ok && now.Sub(g.sentAt) < c.opt.DedupWindow {
		g.extra++
		g.ev = ev
		return g.extra, true
	}
	c.groups[key] = &group{ev: ev, sentAt: now}
	return 0, false
}

// FlushGroups sends the tail of each closed dedup window and forgets it.
func (c *Client) FlushGroups(ctx context.Context) {
	now := c.now()
	type pending struct {
		ev    model.Event
		extra int
		win   time.Duration
	}
	var out []pending

	c.mu.Lock()
	for key, g := range c.groups {
		if now.Sub(g.sentAt) < c.opt.DedupWindow {
			continue
		}
		if g.extra > 0 {
			out = append(out, pending{ev: g.ev, extra: g.extra, win: c.opt.DedupWindow})
		}
		delete(c.groups, key)
	}
	c.mu.Unlock()

	for _, p := range out {
		tail := c.tr("ui.grouped", map[string]string{
			"window": humanDuration(p.win),
			"count":  strconv.Itoa(p.extra),
		})
		text := c.renderEvent(p.ev) + "\n\n" + tail
		if err := c.Broadcast(ctx, text, c.eventKeyboard(p.ev)); err != nil {
			c.log.Warn("cannot send the grouped alert", "error", err)
		}
	}
}

// RunGrouper flushes closed dedup windows until the context is cancelled.
func (c *Client) RunGrouper(ctx context.Context) {
	interval := c.opt.DedupWindow / 2
	if interval < time.Second {
		interval = time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.FlushGroups(ctx)
		}
	}
}

// inQuietHours reports whether now falls inside the configured quiet window,
// which may wrap past midnight.
func (c *Client) inQuietHours(now time.Time) bool {
	from, to := c.opt.QuietFrom, c.opt.QuietTo
	if from < 0 || to < 0 {
		return false
	}
	local := now.In(c.loc)
	cur := local.Hour()*60 + local.Minute()
	if from == to {
		return false
	}
	if from < to {
		return cur >= from && cur < to
	}
	return cur >= from || cur < to
}

// allowRate implements a token bucket, so a storm of events cannot get the bot
// throttled by Telegram itself.
func (c *Client) allowRate(now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	rate := float64(c.opt.RatePerMinute)
	elapsed := now.Sub(c.lastRefill).Seconds()
	if elapsed > 0 {
		c.tokens += elapsed * rate / 60
		if c.tokens > rate {
			c.tokens = rate
		}
		c.lastRefill = now
	}
	if c.tokens < 1 {
		return false
	}
	c.tokens--
	return true
}

// NotifyBan reports a ban. The message says plainly whether the address is
// actually blocked or the decision was only recorded, because the difference
// is the whole point: a ban nobody applied protects nothing.
func (c *Client) NotifyBan(ctx context.Context, b store.Ban, applyErr error) error {
	text, kb := c.banMessage(b, applyErr)
	return c.Broadcast(ctx, text, kb)
}

func (c *Client) banMessage(b store.Ban, applyErr error) (string, *inlineKeyboard) {
	args := map[string]string{
		"ip":     b.IP,
		"reason": b.Reason,
		"until":  c.fmtTime(b.Until),
	}
	key := "ui.ban.auto"
	if b.Permanent() {
		key = "ui.ban.auto_permanent"
	}
	text := "🚫 " + c.tr(key, args)
	if applyErr != nil {
		text += "\n\n" + c.tr("ui.ban.not_applied", map[string]string{
			"ip": b.IP, "error": applyErr.Error(),
		})
	} else if !c.opt.Enforcing {
		text += "\n\n" + c.tr("ui.ban.no_backend", nil)
	}
	kb := &inlineKeyboard{Rows: [][]inlineButton{{
		{Text: c.tr("ui.btn.unban", map[string]string{"ip": b.IP}), Data: "unban:" + b.IP},
		{Text: c.tr("ui.btn.me", nil), Data: "allow:" + b.IP},
	}}}
	return text, kb
}

// NotifyMessage sends a plain localized notice.
func (c *Client) NotifyMessage(ctx context.Context, key string, args map[string]string) error {
	return c.Broadcast(ctx, c.tr(key, args), nil)
}

// SendStartupNotice tells the chat the agent is alive, which doubles as the
// proof that the token and the chat id are correct.
func (c *Client) SendStartupNotice(ctx context.Context) error {
	return c.Broadcast(ctx, c.tr("ui.started", map[string]string{
		"host":    c.opt.Host,
		"profile": c.opt.Profile,
	}), nil)
}
