package telegram

import (
	"context"
	"strconv"
	"time"

	"github.com/RsNest/auditdsec/internal/model"
)

// Notify delivers one event, applying the alert policy in this order: severity
// threshold, mute, quiet hours, grouping of repeats, then the rate limit.
// Critical events ignore mute and quiet hours — the whole point of the agent is
// that a compromise reaches you at 3am.
func (c *Client) Notify(ctx context.Context, ev model.Event) error {
	if ev.Severity < c.opt.MinSeverity {
		return nil
	}
	critical := ev.Severity >= model.SevCritical
	now := c.now()

	if !critical {
		if until := c.opt.Store.MutedUntil(); !until.IsZero() {
			c.log.Debug("alert muted", "kind", ev.Kind, "until", until)
			return nil
		}
		if c.inQuietHours(now) {
			c.log.Debug("alert held back by quiet hours", "kind", ev.Kind)
			return nil
		}
	}

	if c.suppressAsRepeat(ev, now) {
		return nil
	}
	if !c.allowRate(now) {
		c.mu.Lock()
		c.dropped++
		c.mu.Unlock()
		c.log.Warn("alert dropped by the rate limit", "kind", ev.Kind, "per_minute", c.opt.RatePerMinute)
		return nil
	}
	return c.Broadcast(ctx, c.renderEvent(ev), c.eventKeyboard(ev))
}

// suppressAsRepeat reports whether the event is a repeat inside the dedup
// window, counting it so FlushGroups can report "and 46 more" in one message
// instead of 47 separate ones.
func (c *Client) suppressAsRepeat(ev model.Event, now time.Time) bool {
	key := ev.DedupKey()
	c.mu.Lock()
	defer c.mu.Unlock()
	if g, ok := c.groups[key]; ok && now.Sub(g.sentAt) < c.opt.DedupWindow {
		g.extra++
		g.ev = ev
		return true
	}
	c.groups[key] = &group{ev: ev, sentAt: now}
	return false
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

// SendStartupNotice tells the chat the agent is alive, which doubles as the
// proof that the token and the chat id are correct.
func (c *Client) SendStartupNotice(ctx context.Context) error {
	return c.Broadcast(ctx, c.tr("ui.started", map[string]string{
		"host":    c.opt.Host,
		"profile": c.opt.Profile,
	}), nil)
}
