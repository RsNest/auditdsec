package telegram

import (
	"context"
	"html"
	"strconv"
	"strings"

	"github.com/RsNest/auditdsec/internal/incident"
	"github.com/RsNest/auditdsec/internal/store"
)

const maxIncidentsShown = 5

// reasonText renders an incident's reason; the arguments come from audit
// records, so they are escaped for HTML.
func (c *Client) reasonText(in incident.Incident) string {
	args := make(map[string]string, len(in.ReasonArgs))
	for k, v := range in.ReasonArgs {
		args[k] = html.EscapeString(v)
	}
	return c.tr(in.ReasonKey, args)
}

// cmdIncidents lists open incidents, each with the buttons to acknowledge or
// resolve it. Only the state changes; the evidence stays in the journal.
func (c *Client) cmdIncidents(ctx context.Context, chat int64) {
	open := c.opt.Store.Incidents("open")
	if len(open) == 0 {
		c.reply(ctx, chat, c.tr("ui.inc.none", nil))
		return
	}
	for i, in := range open {
		if i == maxIncidentsShown {
			c.reply(ctx, chat, c.tr("ui.inc.more", map[string]string{"n": strconv.Itoa(len(open) - i)}))
			return
		}
		text := c.tr("ui.inc.line", map[string]string{
			"id": html.EscapeString(in.ID), "sev": c.tr("sev."+in.Severity.String(), nil), "state": c.tr("ui.inc.state."+in.State, nil),
			"reason": c.reasonText(in), "total": strconv.Itoa(in.Total), "last": c.fmtTime(in.LastSeen),
		})
		row := []inlineButton{}
		if in.State == incident.New {
			row = append(row, inlineButton{Text: c.tr("ui.inc.btn.ack", nil), Data: "inc:ack:" + in.ID})
		}
		row = append(row, inlineButton{Text: c.tr("ui.inc.btn.resolve", nil), Data: "inc:resolve:" + in.ID})
		if err := c.SendTo(ctx, chat, text, &inlineKeyboard{Rows: [][]inlineButton{row}}); err != nil {
			c.log.Warn("cannot send an incident", "error", err)
		}
	}
}

// applyIncident handles an "inc:<action>:<id>" button.
func (c *Client) applyIncident(arg string, chat int64) string {
	action, id, _ := strings.Cut(arg, ":")
	state := map[string]string{"ack": incident.Acknowledged, "resolve": incident.Resolved}[action]
	if state == "" || id == "" {
		return c.tr("ui.err.unknown_cmd", nil)
	}
	got, err := c.opt.Store.SetIncidentState(id, state, "telegram:"+strconv.FormatInt(chat, 10))
	if err == store.ErrNoIncident {
		cur, ok := c.opt.Store.Incident(id)
		if !ok {
			return c.tr("ui.inc.missing", map[string]string{"id": html.EscapeString(id)})
		}
		got = cur // already in that state
	} else if err != nil {
		c.log.Warn("cannot update the incident", "error", err)
		return c.tr("ui.err.unknown_cmd", nil)
	}
	return c.tr("ui.inc.done", map[string]string{"id": html.EscapeString(got.ID), "state": c.tr("ui.inc.state."+got.State, nil)})
}
