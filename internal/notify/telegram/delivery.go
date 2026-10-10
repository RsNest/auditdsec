package telegram

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/RsNest/auditdsec/internal/delivery"
	"github.com/RsNest/auditdsec/internal/model"
	"github.com/RsNest/auditdsec/internal/store"
)

func route(token string) string { return fmt.Sprintf("%x", sha256.Sum256([]byte(token))) }
func clip(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}
func boundedArgs(args map[string]string) map[string]string {
	out := make(map[string]string, len(args))
	for k, v := range args {
		out[k] = clip(v, 160)
	}
	return out
}

var markup = regexp.MustCompile(`<[^>]*>`)

// prepare only snapshots settings and renders a request; it performs no HTTP.
// One job per recipient makes retry progress independent across the fanout.
func (m *Managed) prepare(id, category string, sev model.Severity, text string, kb *inlineKeyboard, dedup string) delivery.Plan {
	c := m.client
	if c == nil {
		return delivery.Plan{Suppressed: "disabled"}
	}
	priority := delivery.Routine
	if sev >= model.SevCritical {
		priority = delivery.Critical
	}
	parseMode := "HTML"
	if len([]rune(text)) > 3500 {
		text = clip(html.UnescapeString(markup.ReplaceAllString(text, "")), 3400)
		parseMode = ""
	}
	now := m.base.Now()
	fingerprint := route(m.settings.Token)
	plan := delivery.Plan{}
	for _, chat := range m.settings.ChatIDs {
		destination := strconv.FormatInt(chat, 10)
		payload, _ := json.Marshal(sendMessageRequest{ChatID: chat, Text: text, ParseMode: parseMode, ReplyMarkup: kb, NoPreview: true})
		in := delivery.Intent{ID: delivery.ID(id, fingerprint, destination, category), Channel: "telegram", Route: fingerprint, Destination: destination,
			Category: category, Severity: int(sev), Priority: priority, Created: now, Payload: payload}
		if dedup != "" {
			in.DedupKey = delivery.ID(dedup)
			in.DedupWindow = min(c.opt.DedupWindow, 24*time.Hour)
			in.GroupSummary = c.tr("ui.grouped", map[string]string{"window": humanDuration(in.DedupWindow), "count": "{count}"})
		}
		plan.Intents = append(plan.Intents, in)
	}
	return plan
}

func (m *Managed) PlanEvent(ev model.Event) delivery.Plan {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.client == nil {
		return delivery.Plan{Suppressed: "disabled"}
	}
	if !slices.Contains(m.settings.Kinds, ev.Kind) {
		return delivery.Plan{Suppressed: "category"}
	}
	if reason := m.policyReason(string(ev.Kind), ev.Severity); reason != "" {
		return delivery.Plan{Suppressed: reason}
	}
	bounded := ev
	bounded.Host = clip(ev.Host, 80)
	bounded.Args = boundedArgs(ev.Args)
	return m.prepare(ev.ID, string(ev.Kind), ev.Severity, m.client.renderEvent(bounded), m.client.eventKeyboard(ev), ev.DedupKey())
}

func (m *Managed) PlanBan(b store.Ban, applyErr error) delivery.Plan {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.client == nil || !m.settings.Bans {
		return delivery.Plan{Suppressed: "bans_disabled"}
	}
	bounded := b
	bounded.Reason = clip(b.Reason, 160)
	// Operational errors can contain command output; retain a bounded message.
	if applyErr != nil {
		applyErr = errors.New(clip(applyErr.Error(), 160))
	}
	text, kb := m.client.banMessage(bounded, applyErr)
	return m.prepare(delivery.ID(b.IP, b.CreatedAt.Format(time.RFC3339Nano), strconv.Itoa(b.Count)), "_ban", model.SevCritical, text, kb, "")
}

func (m *Managed) PlanMessage(key string, args map[string]string) delivery.Plan {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.client == nil || !m.settings.Bans {
		return delivery.Plan{Suppressed: "bans_disabled"}
	}
	id := delivery.ID(key, m.base.Now().Format(time.RFC3339Nano), fmt.Sprint(args))
	return m.prepare(id, "_notice", model.SevInfo, m.client.tr(key, boundedArgs(args)), nil, "")
}

func (m *Managed) PlanStartup() delivery.Plan {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.client == nil || !m.settings.StartupNotice {
		return delivery.Plan{}
	}
	return m.prepare(delivery.ID("startup", m.base.Now().Format(time.RFC3339Nano)), "_startup", model.SevInfo,
		m.client.tr("ui.started", boundedArgs(map[string]string{"host": m.base.Host, "profile": m.base.Profile})), nil, "")
}

// policyReason requires m.mu and performs no external work. Critical alerts
// bypass mute and quiet hours, but still respect an explicitly disabled category.
func (m *Managed) policyReason(category string, sev model.Severity) string {
	if m.client == nil {
		return "disabled"
	}
	if model.ValidKind(model.Kind(category)) {
		if !slices.Contains(m.settings.Kinds, model.Kind(category)) {
			return "category"
		}
		if sev < m.client.opt.MinSeverity {
			return "severity"
		}
	}
	if sev < model.SevCritical {
		if m.base.Store != nil && !m.base.Store.MutedUntil().IsZero() {
			return "muted"
		}
		if m.client.inQuietHours(m.base.Now()) {
			return "quiet_hours"
		}
	}
	return ""
}

func (m *Managed) deliveryPolicy(in delivery.Intent) delivery.Policy {
	p := delivery.Policy{RatePerMinute: m.settings.RatePerMinute}
	switch {
	case m.client == nil:
		p.CancelReason = "disabled"
	case in.Channel != "telegram" || in.Route != route(m.settings.Token):
		p.CancelReason = "route_changed"
	default:
		id, err := strconv.ParseInt(in.Destination, 10, 64)
		if err != nil || !slices.Contains(m.settings.ChatIDs, id) {
			p.CancelReason = "recipient_removed"
			break
		}
		if (in.Category == "_ban" || in.Category == "_notice") && !m.settings.Bans {
			p.CancelReason = "bans_disabled"
			break
		}
		if in.Category == "_startup" && !m.settings.StartupNotice {
			p.CancelReason = "startup_disabled"
			break
		}
		p.CancelReason = m.policyReason(in.Category, model.Severity(in.Severity))
	}
	return p
}

func (m *Managed) DeliveryPolicy(in delivery.Intent) delivery.Policy {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.deliveryPolicy(in)
}

func (m *Managed) SendDelivery(ctx context.Context, in delivery.Intent) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	// Revalidate while holding the settings read lock through the request.
	// Applying a new token drains old requests before it becomes active.
	if p := m.deliveryPolicy(in); p.CancelReason != "" {
		return &delivery.SendError{Code: "policy_changed", Cancelled: true}
	}
	var req sendMessageRequest
	if json.Unmarshal(in.Payload, &req) != nil || strconv.FormatInt(req.ChatID, 10) != in.Destination {
		return &delivery.SendError{Code: "invalid_payload", Permanent: true}
	}
	if in.GroupedCount > 0 {
		req.Text += "\n\n" + strings.ReplaceAll(in.GroupSummary, "{count}", strconv.Itoa(in.GroupedCount))
	}
	err := m.client.call(ctx, m.client.send, "sendMessage", req, nil)
	m.client.mu.Lock()
	if err == nil {
		m.client.lastDelivery, m.client.lastError = m.base.Now(), ""
	} else {
		m.client.lastError = "delivery_failed"
	}
	m.client.mu.Unlock()
	if err == nil {
		return nil
	}
	var ae *apiError
	if errors.As(err, &ae) {
		return &delivery.SendError{Code: fmt.Sprintf("telegram_%d", ae.code), Permanent: ae.code >= 400 && ae.code < 500 && ae.code != 408 && ae.code != 429, RetryAfter: ae.retryAfter}
	}
	return &delivery.SendError{Code: "telegram_unavailable"}
}
