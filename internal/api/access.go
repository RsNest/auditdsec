package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/RsNest/auditdsec/internal/access"
	"github.com/RsNest/auditdsec/internal/logging"
)

// How the panel is reached, and how that is changed.
//
// The panel never edits Compose or the proxy and the agent has no root or
// Docker access. A change is carried out by the installer; this file only
// validates what the person typed, shows the plan, and asks the local control
// service (cmd/auditdsec-ctl) to run the installer with structured parameters.
// Without that service the panel says so and gives the exact command to run on
// the server. It never reports a change it did not make.

const (
	metaDraft   = "access_draft"
	metaCheck   = "access_check"
	checkMaxAge = 30 * time.Minute
)

// AccessControl is what the panel needs from the control service.
type AccessControl interface {
	Ping(ctx context.Context) error
	Status(ctx context.Context) (json.RawMessage, error)
	Start(ctx context.Context, p access.Params) (access.Task, error)
	Task(ctx context.Context, id string) (access.Task, error)
	Tasks(ctx context.Context) ([]access.Task, error)
}

func (s *Server) control() AccessControl {
	if s.opt.Control == nil {
		return nil
	}
	return s.opt.Control
}

type currentAccess struct {
	Mode      string `json:"mode,omitempty"`
	Site      string `json:"site,omitempty"`
	URL       string `json:"url,omitempty"`
	HTTPSPort string `json:"https_port,omitempty"`
	ACME      string `json:"acme,omitempty"`
	Issuer    string `json:"issuer,omitempty"`
	NotAfter  string `json:"not_after,omitempty"`
	Renewal   string `json:"renewal,omitempty"`
	Running   string `json:"running,omitempty"`
	// Source says who reported this: "installer" (complete) or "agent" (only
	// what the agent itself knows, derived from its public URL).
	Source string `json:"source"`
}

// derivedAccess is all the agent can say without the installer.
func (s *Server) derivedAccess() currentAccess {
	u := s.opt.Config.PanelURL()
	c := currentAccess{URL: u, Source: "agent"}
	parsed, err := url.Parse(u)
	if err != nil || parsed.Host == "" {
		return c
	}
	host := parsed.Hostname()
	c.Site, c.HTTPSPort = host, parsed.Port()
	switch {
	case parsed.Scheme == "http":
		c.Mode = "tunnel"
	default:
		if _, err := netip.ParseAddr(host); err == nil {
			c.Mode = "ip"
		} else {
			c.Mode = "domain"
		}
	}
	return c
}

func (s *Server) currentAccess(ctx context.Context) (currentAccess, string) {
	ctl := s.control()
	if ctl == nil {
		return s.derivedAccess(), "the local control service is not set up"
	}
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	raw, err := ctl.Status(cctx)
	if err != nil {
		return s.derivedAccess(), "the local control service does not answer"
	}
	var st struct {
		Mode, Site, URL, ACME, Issuer, Renewal, Running string
		HTTPSPort                                       string `json:"https_port"`
		NotAfter                                        string `json:"not_after"`
	}
	if json.Unmarshal(raw, &st) != nil {
		return s.derivedAccess(), "the installer's report could not be read"
	}
	return currentAccess{Mode: st.Mode, Site: st.Site, URL: st.URL, HTTPSPort: st.HTTPSPort, ACME: st.ACME,
		Issuer: st.Issuer, NotAfter: st.NotAfter, Renewal: st.Renewal, Running: st.Running, Source: "installer"}, ""
}

func (s *Server) handleAccess(w http.ResponseWriter, r *http.Request) {
	cur, reason := s.currentAccess(r.Context())
	out := map[string]any{
		"current":        cur,
		"control":        map[string]any{"available": reason == "", "reason": reason},
		"update_command": "./install.sh",
	}
	if v := s.opt.Store.GetMeta(metaDraft); v != "" {
		var d access.Params
		if json.Unmarshal([]byte(v), &d) == nil {
			out["draft"] = d
		}
	}
	if v := s.opt.Store.GetMeta(metaCheck); v != "" {
		var c access.Preflight
		if json.Unmarshal([]byte(v), &c) == nil {
			out["last_check"] = c
		}
	}
	if ctl := s.control(); ctl != nil && reason == "" {
		if tasks, err := ctl.Tasks(r.Context()); err == nil && len(tasks) > 0 {
			out["last_task"] = tasks[0]
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// accessParams reads and validates the request body.
func (s *Server) accessParams(w http.ResponseWriter, r *http.Request, extra any) (access.Params, bool) {
	var in struct {
		Action    string `json:"action"`
		Site      string `json:"site"`
		Email     string `json:"email"`
		HTTPSPort string `json:"https_port"`
		PlanID    string `json:"plan_id"`
		Confirm   bool   `json:"confirm"`
	}
	if !decode(w, r, &in) {
		return access.Params{}, false
	}
	if e, ok := extra.(*struct {
		PlanID  string
		Confirm bool
	}); ok {
		e.PlanID, e.Confirm = in.PlanID, in.Confirm
	}
	p, err := access.Validate(access.Params{Action: in.Action, Site: in.Site, Email: in.Email, HTTPSPort: in.HTTPSPort, Lang: string(s.lang(r)), TraceID: logging.RequestID(r.Context())})
	if err != nil {
		fail(w, http.StatusBadRequest, "bad_access", err.Error())
		return access.Params{}, false
	}
	return p, true
}

func (s *Server) handleAccessDraft(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodDelete {
		if err := s.opt.Store.SetMeta(metaDraft, ""); err != nil {
			fail(w, http.StatusInternalServerError, "internal", "cannot save")
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	p, ok := s.accessParams(w, r, nil)
	if !ok {
		return
	}
	b, _ := json.Marshal(p)
	if err := s.opt.Store.SetMeta(metaDraft, string(b)); err != nil {
		fail(w, http.StatusInternalServerError, "internal", "cannot save")
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) preflightDeps() access.Deps {
	if s.opt.PreflightDeps != nil {
		return *s.opt.PreflightDeps
	}
	return access.DefaultDeps()
}

// handleAccessCheck runs the preliminary checks for a domain and returns the
// plan the person will be asked to confirm. It changes nothing.
func (s *Server) handleAccessCheck(w http.ResponseWriter, r *http.Request) {
	p, ok := s.accessParams(w, r, nil)
	if !ok {
		return
	}
	cur, _ := s.currentAccess(r.Context())
	resp := map[string]any{"plan": access.BuildPlan(p, cur.URL)}
	if p.Action == access.ActionDomain {
		ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
		defer cancel()
		pre, err := access.CheckDomain(ctx, p.Site, s.preflightDeps())
		if err != nil {
			fail(w, http.StatusBadRequest, "bad_access", err.Error())
			return
		}
		pre.At = s.now().UTC() // the panel's clock decides how fresh a check is
		b, _ := json.Marshal(pre)
		_ = s.opt.Store.SetMeta(metaCheck, string(b))
		resp["preflight"] = pre
	}
	writeJSON(w, http.StatusOK, resp)
}

func writeAccessConflict(w http.ResponseWriter, slug, msg, command string) {
	writeJSON(w, http.StatusConflict, map[string]string{"error": slug, "message": msg, "command": command})
}

// handleAccessApply starts the change. It requires the confirmation of the
// exact plan that was shown, a fresh successful DNS check for a domain, and a
// control service; otherwise it refuses and, where useful, gives the command
// to run on the server.
func (s *Server) handleAccessApply(w http.ResponseWriter, r *http.Request) {
	var extra struct {
		PlanID  string
		Confirm bool
	}
	p, ok := s.accessParams(w, r, &extra)
	if !ok {
		return
	}
	cur, reason := s.currentAccess(r.Context())
	command := access.Command(p)
	if !extra.Confirm || extra.PlanID != access.PlanID(p, cur.URL) {
		fail(w, http.StatusBadRequest, "not_confirmed", "confirm the plan that was shown; the address or the parameters changed since")
		return
	}
	if p.Action == access.ActionDomain {
		var pre access.Preflight
		v := s.opt.Store.GetMeta(metaCheck)
		if v == "" || json.Unmarshal([]byte(v), &pre) != nil || pre.Domain != p.Site || !pre.DNSOK || s.now().Sub(pre.At) > checkMaxAge {
			fail(w, http.StatusConflict, "check_required", "run the check for this domain first: its DNS records must lead to this server")
			return
		}
	}
	ctl := s.control()
	if ctl == nil || reason != "" {
		writeAccessConflict(w, "control_unavailable",
			"This panel cannot apply the change itself: the local control service is not running. Run the command on the server; it applies the same checks and rollback.", command)
		return
	}
	task, err := ctl.Start(r.Context(), p)
	switch {
	case errors.Is(err, access.ErrBusy):
		writeAccessConflict(w, "busy", "Another change is running (from the panel or the installer). Wait for it to finish.", "")
		return
	case errors.Is(err, access.ErrInvalid):
		fail(w, http.StatusBadRequest, "bad_access", err.Error())
		return
	case err != nil:
		s.log.Error("cannot start the change", "error", err)
		writeAccessConflict(w, "control_unavailable", "The local control service did not accept the change.", command)
		return
	}
	_ = s.opt.Store.SetMeta(metaDraft, "")
	s.log.Info("panel: access change started", "id", task.ID, "action", p.Action, "by", s.clientIP(r))
	writeJSON(w, http.StatusAccepted, task)
}

func (s *Server) handleAccessTask(w http.ResponseWriter, r *http.Request) {
	ctl := s.control()
	if ctl == nil {
		fail(w, http.StatusNotFound, "not_found", "no control service")
		return
	}
	t, err := ctl.Task(r.Context(), strings.TrimSpace(r.PathValue("id")))
	switch {
	case errors.Is(err, access.ErrUnavailable):
		fail(w, http.StatusBadGateway, "control_unavailable", "the control service does not answer; the panel may be restarting")
	case err != nil:
		fail(w, http.StatusNotFound, "not_found", "no such change")
	default:
		writeJSON(w, http.StatusOK, t)
	}
}
