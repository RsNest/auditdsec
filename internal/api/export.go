package api

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/RsNest/auditdsec/internal/incident"
	"github.com/RsNest/auditdsec/internal/model"
)

// exportLimit bounds one export. The file is streamed, so memory does not
// depend on it; the limit keeps a single request from reading the whole store.
var exportLimit = 50000

// csvSafe stops a spreadsheet from running a cell as a formula: the values
// come from audit records and usernames, which an attacker can influence.
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

func exportFormat(w http.ResponseWriter, r *http.Request, allowed ...string) (string, bool) {
	f := r.URL.Query().Get("format")
	if f == "" {
		return allowed[0], true
	}
	for _, a := range allowed {
		if f == a {
			return f, true
		}
	}
	fail(w, http.StatusBadRequest, "bad_request", "format must be "+strings.Join(allowed, " or "))
	return "", false
}

func attachment(w http.ResponseWriter, name, mime string) {
	w.Header().Set("Content-Type", mime)
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

// handleExportEvents streams the events matching the same filters as the list,
// masked like the list, as JSON lines or CSV. Without "since" it exports the
// last 24 hours. The unmasking of old stored evidence never happens here.
func (s *Server) handleExportEvents(w http.ResponseWriter, r *http.Request) {
	format, ok := exportFormat(w, r, "jsonl", "csv")
	if !ok {
		return
	}
	f, ok := s.parseEventQuery(w, r)
	if !ok {
		return
	}
	if f.since.IsZero() {
		f.since = s.now().Add(-24 * time.Hour)
	}
	stamp := s.now().UTC().Format("20060102-150405")
	var (
		rows      int
		truncated bool
		cw        *csv.Writer
		enc       *json.Encoder
		started   bool
	)
	start := func() {
		started = true
		if format == "csv" {
			attachment(w, "auditdsec-events-"+stamp+".csv", "text/csv; charset=utf-8")
			cw = csv.NewWriter(w)
			_ = cw.Write([]string{"time", "host", "kind", "severity", "user", "src_ip", "summary", "login_user", "effective_user",
				"session_addr", "session_confidence", "suppressed_by", "event_id"})
		} else {
			attachment(w, "auditdsec-events-"+stamp+".jsonl", "application/x-ndjson")
			enc = json.NewEncoder(w)
		}
	}
	err := s.opt.Store.Scan(f.since, f.until, func(id string, ev model.Event) bool {
		ev, summary, ok := f.accept(id, ev)
		if !ok {
			return true
		}
		if rows == exportLimit {
			truncated = true
			return false
		}
		if !started {
			start()
		}
		rows++
		if format == "jsonl" {
			_ = enc.Encode(toEventJSON(id, ev, summary))
			return true
		}
		var login, eff, addr, conf string
		if c := ev.Context; c != nil {
			login, eff = firstNonEmpty(c.LoginUser, c.LoginUID), firstNonEmpty(c.EffectiveUser, c.EffectiveUID)
			if c.Session != nil {
				addr, conf = c.Session.Addr, c.Session.Confidence
			}
		}
		_ = cw.Write([]string{ev.Time.UTC().Format(time.RFC3339), ev.Host, string(ev.Kind), ev.Severity.String(), csvSafe(ev.User),
			ev.SrcIP, csvSafe(summary), csvSafe(login), csvSafe(eff), addr, conf, ev.Suppressed, ev.ID})
		return true
	})
	if !started {
		if err != nil {
			s.log.Error("cannot export events", "error", err)
			fail(w, http.StatusInternalServerError, "internal", "cannot read events")
			return
		}
		start()
	}
	switch {
	case err != nil:
		s.log.Error("export stopped early", "error", err)
		note := "export stopped early: a read error occurred"
		if format == "csv" {
			_ = cw.Write([]string{"# " + note})
		} else {
			_ = enc.Encode(map[string]any{"export": map[string]any{"rows": rows, "complete": false, "error": note}})
		}
	case format == "jsonl":
		_ = enc.Encode(map[string]any{"export": map[string]any{"rows": rows, "complete": !truncated, "limit": exportLimit}})
	case truncated:
		_ = cw.Write([]string{"# export limit of " + strconv.Itoa(exportLimit) + " rows reached; narrow the time range"})
	}
	if cw != nil {
		cw.Flush()
	}
	s.log.Info("panel: export", "what", "events", "rows", rows, "format", format, "by", s.clientIP(r))
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// handleExportIncidents exports incidents (any state, default all) with their
// event references and notes as JSON, or a summary table as CSV.
func (s *Server) handleExportIncidents(w http.ResponseWriter, r *http.Request) {
	format, ok := exportFormat(w, r, "json", "csv")
	if !ok {
		return
	}
	state := r.URL.Query().Get("state")
	switch state {
	case "", "all":
		state = ""
	case "open", incident.New, incident.Acknowledged, incident.Resolved:
	default:
		fail(w, http.StatusBadRequest, "bad_request", "bad state")
		return
	}
	lang := s.lang(r)
	list := s.opt.Store.Incidents(state)
	stamp := s.now().UTC().Format("20060102-150405")
	if format == "json" {
		attachment(w, "auditdsec-incidents-"+stamp+".json", "application/json")
		items := make([]incidentJSON, 0, len(list))
		for _, in := range list {
			items = append(items, incidentView(lang, in, true))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"items": items})
	} else {
		attachment(w, "auditdsec-incidents-"+stamp+".csv", "text/csv; charset=utf-8")
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"id", "state", "severity", "opened", "last_seen", "src_ip", "reason", "events", "bans", "notes"})
		for _, in := range list {
			v := incidentView(lang, in, false)
			_ = cw.Write([]string{v.ID, v.State, v.Severity, v.Opened.Format(time.RFC3339), v.LastSeen.Format(time.RFC3339), v.SrcIP,
				csvSafe(v.Reason), strconv.Itoa(v.Total), strings.Join(v.Bans, " "), fmt.Sprint(len(in.Notes))})
		}
		cw.Flush()
	}
	s.log.Info("panel: export", "what", "incidents", "rows", len(list), "format", format, "by", s.clientIP(r))
}
