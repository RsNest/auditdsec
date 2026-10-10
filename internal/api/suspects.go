package api

import (
	"net/http"
	"sort"
	"time"

	"github.com/RsNest/auditdsec/internal/i18n"
	"github.com/RsNest/auditdsec/internal/model"
)

type suspectJSON struct {
	IP       string    `json:"ip"`
	Attempts int       `json:"attempts"`
	First    time.Time `json:"first"`
	Last     time.Time `json:"last"`
	State    string    `json:"state"`
	Event    eventJSON `json:"event"`
}

// handleSuspects aggregates the detection window independently of the latest
// event page. A busy source cannot fill that page and hide quieter addresses.
// Confirmed active bans and protected addresses are excluded; unapplied
// decisions remain visible as needs_attention rather than a successful block.
func (s *Server) handleSuspects(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	window := s.opt.Config.Detect.Window
	if window <= 0 {
		window = 10 * time.Minute
	}
	threshold := s.opt.Config.Detect.FailThreshold
	if threshold <= 0 {
		threshold = 6
	}
	capIPs := min(max(s.opt.Config.Detect.MaxTracked, 1), 10000)
	blocked := make(map[string]bool)
	pending := make(map[string]bool)
	for _, b := range s.opt.Store.Bans() {
		if s.opt.Enforcer != nil && b.Applied && b.Active(now) {
			blocked[b.IP] = true
		} else if b.Active(now) {
			pending[b.IP] = true
		}
	}
	protected := make(map[string]bool)
	for _, a := range s.opt.Store.Allowlist() {
		protected[a.IP] = true
	}
	byIP := make(map[string]*suspectJSON)
	truncated := false
	lang := s.lang(r)
	err := s.opt.Store.WalkEvents(now.Add(-window), now, func(ev model.Event) bool {
		if ev.Kind != model.KindSSHLoginFail {
			return true
		}
		ip, ok := parseIP(ev.SrcIP)
		if !ok || ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() ||
			ip.IsLinkLocalUnicast() || ip.IsMulticast() {
			return true
		}
		key := ip.String()
		if blocked[key] || protected[key] {
			return true
		}
		item := byIP[key]
		if item == nil {
			if len(byIP) >= capIPs {
				truncated = true
				return true
			}
			item = &suspectJSON{IP: key, First: ev.Time.UTC(), State: "review"}
			byIP[key] = item
		}
		item.Attempts++
		if ev.Time.Before(item.First) {
			item.First = ev.Time.UTC()
		}
		if !ev.Time.Before(item.Last) {
			item.Last = ev.Time.UTC()
			item.Event = eventJSON{
				ID: "suspect:" + key, EventID: ev.ID, Time: ev.Time.UTC(), Host: ev.Host,
				Kind: ev.Kind, Severity: ev.Severity.String(), User: ev.User, SrcIP: key,
				Summary: i18n.T(lang, ev.SummaryKey, ev.Args),
			}
		}
		if item.Attempts >= threshold || pending[key] {
			item.State = "needs_attention"
		}
		return true
	})
	if err != nil {
		s.log.Error("cannot read suspicious addresses", "error", err)
		fail(w, http.StatusInternalServerError, "internal", "cannot read suspicious addresses")
		return
	}
	items := make([]suspectJSON, 0, len(byIP))
	for _, item := range byIP {
		items = append(items, *item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].State != items[j].State {
			return items[i].State == "needs_attention"
		}
		// Low-frequency sources come first in the manual review list.
		if items[i].Attempts != items[j].Attempts {
			return items[i].Attempts < items[j].Attempts
		}
		if !items[i].Last.Equal(items[j].Last) {
			return items[i].Last.After(items[j].Last)
		}
		return items[i].IP < items[j].IP
	})
	if len(items) > 100 {
		items = items[:100]
		truncated = true
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": items, "threshold": threshold, "window_seconds": int64(window / time.Second),
		"auto_enforcing": s.opt.Config.Detect.Enabled && s.opt.Enforcer != nil,
		"truncated":      truncated,
	})
}
