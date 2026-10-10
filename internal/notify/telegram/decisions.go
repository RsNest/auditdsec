package telegram

import (
	"context"
	"strconv"

	"github.com/RsNest/auditdsec/internal/action"
	"github.com/RsNest/auditdsec/internal/decision"
	"github.com/RsNest/auditdsec/internal/store"
)

// enforcerBanner lets the bot's narrow Enforcer stand in for a banner when no
// shared decision service was given (tests, and embedders that only have an
// Enforcer). It cannot list, so it is never reconciled.
type enforcerBanner struct{ Enforcer }

func (enforcerBanner) List(context.Context) ([]action.Decision, error) { return nil, nil }
func (enforcerBanner) Name() string                                    { return "enforcer" }

// decisions returns the service the bot asks. The panel and the detector use
// the same one, so an address gets the same answer from every interface.
func (c *Client) decisions() *decision.Service {
	return c.opt.Decisions
}

func (c *Client) actor(chat int64) decision.Actor {
	return decision.Actor{Origin: decision.FromTelegram, Who: strconv.FormatInt(chat, 10)}
}

// refusalText turns a policy refusal into a message.
func (c *Client) refusalText(ip string, err error) (string, bool) {
	r, ok := decision.IsRefusal(err)
	if !ok {
		return "", false
	}
	switch r.Reason {
	case decision.ReasonInvalid:
		return c.tr("ui.err.bad_ip", map[string]string{"value": ip}), true
	case decision.ReasonAllowlisted:
		return c.tr("ui.ban.allowlisted", map[string]string{"ip": ip}), true
	case decision.ReasonSelf:
		return c.tr("ui.ban.self", nil), true
	case decision.ReasonOver:
		return c.tr("ui.ban.over", map[string]string{"ip": ip}), true
	case decision.ReasonNotBannable:
		return c.tr("ui.ban.not_bannable", map[string]string{"ip": ip, "class": c.tr("ui.class."+string(r.Class), nil)}), true
	}
	return c.tr("ui.err.unknown_cmd", nil), true
}

// applyBan records a ban pressed by hand and, when a backend is configured,
// blocks the address. The reply says which of the two happened: "banned" and
// "noted that it should be banned" are very different outcomes.
func (c *Client) applyBan(ctx context.Context, chat int64, ip string) string {
	res, err := c.decisions().Ban(ctx, decision.BanRequest{
		IP: ip, Until: c.now().Add(manualBanDuration), Reason: "manual ban from Telegram", Actor: c.actor(chat),
	})
	if err != nil {
		if text, ok := c.refusalText(ip, err); ok {
			return text
		}
		c.log.Warn("cannot record the ban", "error", err)
		return c.tr("ui.err.unknown_cmd", nil)
	}
	return c.banText(res.Ban)
}

// banText says truthfully what is known of a ban: blocked only when the
// firewall has accepted it.
func (c *Client) banText(b store.Ban) string {
	args := map[string]string{"ip": b.IP, "until": c.fmtTime(b.Until)}
	switch b.State {
	case store.StateApplied:
		if b.Permanent() {
			return c.tr("ui.ban.recorded_permanent", args)
		}
		return c.tr("ui.ban.recorded", args)
	}
	text := c.tr("ui.ban.decided", args)
	if b.Permanent() {
		text = c.tr("ui.ban.decided_permanent", args)
	}
	switch b.State {
	case store.StateDryRun:
		return text + "\n\n" + c.tr("ui.ban.dry_run", nil)
	case store.StateFailed:
		return text + "\n\n" + c.tr("ui.ban.not_applied", map[string]string{"ip": b.IP, "error": b.LastError})
	case store.StateUnknown:
		return text + "\n\n" + c.tr("ui.ban.no_backend", nil)
	}
	// pending: enforcement is not confirmed yet and will be retried
	return text + "\n\n" + c.tr("ui.ban.not_applied", map[string]string{"ip": b.IP, "error": "pending"})
}

// applyUnban lifts a ban. When the firewall does not confirm the unblock, the
// record is still removed and the reply says the unblock is not complete; it
// is retried.
func (c *Client) applyUnban(ctx context.Context, chat int64, ip string) string {
	res, err := c.decisions().Unban(ctx, ip, c.actor(chat))
	if err != nil {
		if text, ok := c.refusalText(ip, err); ok {
			return text
		}
		c.log.Warn("cannot lift the ban", "error", err)
		return c.tr("ui.err.unknown_cmd", nil)
	}
	if res.Pending {
		return c.tr("ui.unban.pending", map[string]string{"ip": ip, "error": errText(res.Err)})
	}
	key := "ui.ban.missing"
	if res.Removed {
		key = "ui.ban.removed"
	}
	return c.tr(key, map[string]string{"ip": ip})
}

// applyAllow protects an address or a network. It also lifts any ban on it:
// "that was me" has to restore access, not just stop the next ban.
func (c *Client) applyAllow(ctx context.Context, chat int64, entry string) string {
	res, err := c.decisions().Allow(ctx, entry, "confirmed by the owner in Telegram", c.actor(chat))
	if err != nil {
		if text, ok := c.refusalText(entry, err); ok {
			return text
		}
		c.log.Warn("cannot allowlist the address", "error", err)
		return c.tr("ui.err.unknown_cmd", nil)
	}
	text := c.tr("ui.allow.ok", map[string]string{"ip": res.Key})
	if len(res.Pending) > 0 {
		text += "\n\n" + c.tr("ui.allow.pending", map[string]string{"ip": res.Pending[0], "error": errText(res.Err)})
	}
	return text
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return s
}
