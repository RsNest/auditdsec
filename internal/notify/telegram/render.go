package telegram

import (
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/RsNest/auditdsec/internal/i18n"
	"github.com/RsNest/auditdsec/internal/model"
)

const timeLayout = "2006-01-02 15:04:05"

// tr renders a catalog entry. Argument values are HTML-escaped but the template
// is not, so the markup in the UI strings survives while a file path or a
// command from the log can never inject tags.
func (c *Client) tr(key string, args map[string]string) string {
	if len(args) == 0 {
		return i18n.T(c.opt.Lang, key, nil)
	}
	safe := make(map[string]string, len(args))
	for k, v := range args {
		if v == "" {
			v = i18n.T(c.opt.Lang, "val.unknown", nil)
		}
		safe[k] = html.EscapeString(v)
	}
	return i18n.T(c.opt.Lang, key, safe)
}

func sevEmoji(s model.Severity) string {
	switch s {
	case model.SevCritical:
		return "🚨"
	case model.SevWarn:
		return "⚠️"
	default:
		return "ℹ️"
	}
}

// renderEvent builds the alert message: who, what, where and when, in that
// order, so the first line already answers "do I need to act".
func (c *Client) renderEvent(ev model.Event) string {
	host := ev.Host
	if host == "" {
		host = c.opt.Host
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s <b>%s</b> · %s\n", sevEmoji(ev.Severity), html.EscapeString(host),
		c.tr("sev."+ev.Severity.String(), nil))
	b.WriteString(c.tr(ev.SummaryKey, ev.Args))
	if line := c.contextLine(ev); line != "" {
		b.WriteString("\n" + line)
	}
	fmt.Fprintf(&b, "\n<code>%s</code>", c.fmtTime(ev.Time))
	return b.String()
}

// renderEventLine is the compact form used by /last.
func (c *Client) renderEventLine(ev model.Event) string {
	return fmt.Sprintf("%s <code>%s</code> %s",
		sevEmoji(ev.Severity), c.fmtTime(ev.Time), c.tr(ev.SummaryKey, ev.Args))
}

// humanDuration prints a duration the way a person would read it: "10m"
// rather than Go's "10m0s".
func humanDuration(d time.Duration) string {
	s := d.Round(time.Second).String()
	if strings.HasSuffix(s, "m0s") {
		s = s[:len(s)-2] // 10m0s -> 10m
	}
	if strings.HasSuffix(s, "h0m") {
		s = s[:len(s)-2] // 1h0m -> 1h
	}
	return s
}

func (c *Client) fmtTime(t time.Time) string {
	if t.IsZero() {
		t = c.now()
	}
	return t.In(c.loc).Format(timeLayout)
}

// eventKeyboard offers the actions that make sense for the event: banning and
// allowlisting only when a real source address is known.
func (c *Client) eventKeyboard(ev model.Event) *inlineKeyboard {
	var rows [][]inlineButton
	if ev.SrcIP != "" {
		rows = append(rows, []inlineButton{
			{Text: c.tr("ui.btn.ban", map[string]string{"ip": ev.SrcIP}), Data: "ban:" + ev.SrcIP},
			{Text: c.tr("ui.btn.me", nil), Data: "allow:" + ev.SrcIP},
		})
	}
	if ev.Severity >= model.SevWarn {
		rows = append(rows, []inlineButton{
			{Text: c.tr("ui.btn.mute", nil), Data: "mute:24"},
		})
	}
	if len(rows) == 0 {
		return nil
	}
	return &inlineKeyboard{Rows: rows}
}

// contextLine says who was really behind the event in one short line: the
// identity that logged in, the identity the action ran as, and the SSH session
// address with its confidence. Unknown parts are said to be unknown, nothing is
// guessed, and the line is left out when the event carries no context.
func (c *Client) contextLine(ev model.Event) string {
	x := ev.Context
	if x == nil {
		return ""
	}
	name := func(n, uid string) string {
		if n != "" {
			return n
		}
		if uid != "" {
			return "uid " + uid
		}
		return ""
	}
	login, eff := name(x.LoginUser, x.LoginUID), name(x.EffectiveUser, x.EffectiveUID)
	var parts []string
	switch {
	case login != "" && eff != "" && login != eff:
		parts = append(parts, html.EscapeString(login)+" → "+html.EscapeString(eff))
	case login != "":
		parts = append(parts, html.EscapeString(login))
	case eff != "":
		parts = append(parts, html.EscapeString(eff))
	}
	if s := x.Session; s != nil {
		var p string
		switch {
		case s.Addr != "" && s.Confidence == model.ConfCorrelated:
			p = c.tr("ui.ctx.ssh_inferred", map[string]string{"addr": html.EscapeString(s.Addr)})
		case s.Addr != "":
			p = c.tr("ui.ctx.ssh", map[string]string{"addr": html.EscapeString(s.Addr)})
		default:
			p = c.tr("ui.ctx.ssh_unknown", nil)
		}
		if s.Ended {
			p += " (" + c.tr("ui.ctx.ended", nil) + ")"
		}
		parts = append(parts, p)
	}
	if len(parts) == 0 {
		return ""
	}
	return "🔑 " + strings.Join(parts, " · ")
}
