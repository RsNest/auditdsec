package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/RsNest/auditdsec/internal/i18n"
	"github.com/RsNest/auditdsec/internal/incident"
	"github.com/RsNest/auditdsec/internal/model"
	"github.com/RsNest/auditdsec/internal/store"
)

type incidentJSON struct {
	ID       string          `json:"id"`
	State    string          `json:"state"`
	Reason   string          `json:"reason"`
	Severity string          `json:"severity"`
	Opened   time.Time       `json:"opened"`
	LastSeen time.Time       `json:"last_seen"`
	SrcIP    string          `json:"src_ip,omitempty"`
	Total    int             `json:"total"`
	Kinds    map[string]int  `json:"kinds,omitempty"`
	Bans     []string        `json:"bans,omitempty"`
	Events   []incidentRef   `json:"events,omitempty"`
	Notes    []incident.Note `json:"notes,omitempty"`
}

type incidentRef struct {
	ID       string     `json:"id,omitempty"`
	Time     time.Time  `json:"time"`
	Kind     model.Kind `json:"kind"`
	Severity string     `json:"severity"`
	User     string     `json:"user,omitempty"`
	Via      string     `json:"via,omitempty"`
}

func incidentView(lang i18n.Lang, in incident.Incident, detail bool) incidentJSON {
	out := incidentJSON{
		ID: in.ID, State: in.State, Reason: i18n.T(lang, in.ReasonKey, in.ReasonArgs), Severity: in.Severity.String(),
		Opened: in.Opened.UTC(), LastSeen: in.LastSeen.UTC(), SrcIP: in.SrcIP, Total: in.Total, Kinds: in.Kinds, Bans: in.Bans,
	}
	if detail {
		for i := len(in.Events) - 1; i >= 0; i-- { // newest first
			e := in.Events[i]
			out.Events = append(out.Events, incidentRef{ID: e.ID, Time: e.Time.UTC(), Kind: e.Kind, Severity: e.Severity.String(), User: e.User, Via: e.Via})
		}
		out.Notes = in.Notes
	}
	return out
}

// handleIncidents lists incidents; ?state=open (default), all, new,
// acknowledged or resolved.
func (s *Server) handleIncidents(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	switch state {
	case "", "open":
		state = "open"
	case "all":
		state = ""
	case incident.New, incident.Acknowledged, incident.Resolved:
	default:
		fail(w, http.StatusBadRequest, "bad_request", "bad state")
		return
	}
	lang := s.lang(r)
	items := []incidentJSON{}
	for _, in := range s.opt.Store.Incidents(state) {
		items = append(items, incidentView(lang, in, false))
		if len(items) == 200 {
			break
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleIncident(w http.ResponseWriter, r *http.Request) {
	in, ok := s.opt.Store.Incident(r.PathValue("id"))
	if !ok {
		fail(w, http.StatusNotFound, "not_found", "no such incident")
		return
	}
	writeJSON(w, http.StatusOK, incidentView(s.lang(r), in, true))
}

// handleIncidentAction moves an incident between new, acknowledged and
// resolved. Nothing else about it can be edited: the evidence is the journal.
func (s *Server) handleIncidentAction(w http.ResponseWriter, r *http.Request) {
	var in struct{ Action string }
	if !decode(w, r, &in) {
		return
	}
	state := map[string]string{"ack": incident.Acknowledged, "resolve": incident.Resolved, "reopen": incident.New}[in.Action]
	if state == "" {
		fail(w, http.StatusBadRequest, "bad_request", "action must be ack, resolve or reopen")
		return
	}
	got, err := s.opt.Store.SetIncidentState(r.PathValue("id"), state, "panel:"+s.clientIP(r))
	switch {
	case errors.Is(err, store.ErrNoIncident):
		if _, ok := s.opt.Store.Incident(r.PathValue("id")); !ok {
			fail(w, http.StatusNotFound, "not_found", "no such incident")
			return
		}
		got, _ = s.opt.Store.Incident(r.PathValue("id")) // already in that state
	case err != nil:
		s.log.Error("cannot update the incident", "error", err)
		fail(w, http.StatusInternalServerError, "internal", "cannot save")
		return
	}
	s.log.Info("panel: incident", "id", got.ID, "state", got.State, "by", s.clientIP(r))
	writeJSON(w, http.StatusOK, incidentView(s.lang(r), got, true))
}
