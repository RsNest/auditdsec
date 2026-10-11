package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/RsNest/auditdsec/internal/access"
	"github.com/RsNest/auditdsec/internal/logging"
	"github.com/RsNest/auditdsec/internal/sanitize"
	"github.com/RsNest/auditdsec/internal/update"
)

// UpdateSource is what the panel needs from the update checker.
type UpdateSource interface {
	View() update.View
	Request() error
}

// Menu items of the installer, by language; they must read exactly as in the
// installer's menu (deploy/installer.messages) so that the instruction in the
// panel matches what the person sees in the terminal.
const (
	updateMenuEN = "Update auditdsec — agent and web panel"
	updateMenuRU = "Обновить auditdsec — агент и веб-панель"
)

type changeJSON struct {
	ID      string   `json:"id"`
	Date    string   `json:"date"`
	Title   string   `json:"title"`
	Added   []string `json:"added,omitempty"`
	Fixed   []string `json:"fixed,omitempty"`
	Changed []string `json:"changed,omitempty"`
	Actions []string `json:"actions,omitempty"`
}

type updateJSON struct {
	Control     map[string]bool   `json:"control"`
	Task        *access.Task      `json:"task,omitempty"`
	State       string            `json:"state"`
	Channel     string            `json:"channel,omitempty"`
	Installed   *update.Installed `json:"installed,omitempty"`
	Latest      *latestJSON       `json:"latest,omitempty"`
	LastChecked *time.Time        `json:"last_checked,omitempty"`
	LastSuccess *time.Time        `json:"last_success,omitempty"`
	NextCheck   *time.Time        `json:"next_check,omitempty"`
	Error       string            `json:"error,omitempty"`
	Changes     []changeJSON      `json:"changes"`
	Breaking    []string          `json:"breaking"`
	Requires    update.Requires   `json:"requires"`
	Truncated   bool              `json:"truncated"`
	Message     string            `json:"message,omitempty"`
	// Pending is true when an update is known, even if the last check failed
	// afterwards: the indicator stays, the state says the source is down.
	Pending  bool   `json:"pending"`
	Command  string `json:"command"`
	MenuItem string `json:"menu_item"`
}

type latestJSON struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Published string `json:"published"`
}

func (s *Server) updateView(lang string) updateJSON {
	out := updateJSON{State: "disabled", Changes: []changeJSON{}, Breaking: []string{}, Command: "./install.sh", MenuItem: updateMenuEN}
	if lang == "ru" {
		out.MenuItem = updateMenuRU
	}
	if s.opt.Update == nil {
		return out
	}
	v := s.opt.Update.View()
	out.State, out.Channel = v.State, v.Channel
	inst := v.Installed
	out.Installed = &inst
	set := func(t time.Time) *time.Time {
		if t.IsZero() {
			return nil
		}
		u := t.UTC()
		return &u
	}
	out.LastChecked, out.LastSuccess, out.NextCheck = set(v.LastChecked), set(v.LastSuccess), set(v.NextCheck)
	out.Error = v.Error
	r := v.Result
	if r == nil {
		return out
	}
	out.Message, out.Truncated, out.Requires = r.Message, r.Truncated, r.Requires
	// Offer the newest version only when the comparison said something can be
	// done with it: a version for another architecture or without an image is
	// information, not an update.
	if r.State == update.StateAvailable || r.State == update.StateUpToDate || r.State == update.StateUnknownInstalled {
		out.Latest = &latestJSON{Version: r.Latest.Version, Commit: r.Latest.Commit, Published: r.Latest.Published}
	}
	out.Pending = r.State == update.StateAvailable
	// The text comes from a signed or HTTPS-fetched document; it passes the
	// same masking as everything else the panel shows.
	for _, e := range r.Entries {
		c := changeJSON{ID: e.ID, Date: e.Date, Title: sanitize.Text(e.Title.Lang(lang)),
			Added: mask(e.Added.Lang(lang)), Fixed: mask(e.Fixed.Lang(lang)), Changed: mask(e.Changed.Lang(lang)), Actions: mask(e.Actions.Lang(lang))}
		out.Changes = append(out.Changes, c)
	}
	for _, b := range r.Breaking {
		out.Breaking = append(out.Breaking, sanitize.Text(b.Lang(lang)))
	}
	return out
}

func mask(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, sanitize.Text(s))
	}
	return out
}

func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request) {
	out := s.updateView(string(s.lang(r)))
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	available := s.updateControlAvailable(ctx)
	out.Control = map[string]bool{"available": available}
	if available {
		if tasks, err := s.control().Tasks(ctx); err == nil {
			for _, task := range tasks {
				if task.Params.Action == access.ActionUpdate && task.Params.Commit != "" {
					out.Task = &task
					break
				}
			}
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) updateControlAvailable(ctx context.Context) bool {
	ctl := s.control()
	if ctl == nil {
		return false
	}
	if c, ok := ctl.(interface{ SupportsUpdates(context.Context) bool }); ok {
		return c.SupportsUpdates(ctx)
	}
	return ctl.Ping(ctx) == nil
}

// Only the commit evaluated by the checker may be installed. Arbitrary image
// references, scripts and client-supplied installer arguments are never accepted.
func (s *Server) handleUpdateApply(w http.ResponseWriter, r *http.Request) {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	var in struct {
		Commit string `json:"commit"`
	}
	if !decode(w, r, &in) {
		return
	}
	if s.opt.Update == nil {
		fail(w, http.StatusConflict, "disabled", "update checks are disabled")
		return
	}
	v := s.opt.Update.View()
	if v.State != update.StateAvailable || v.Result == nil || v.Result.State != update.StateAvailable ||
		in.Commit != v.Result.Latest.Commit || v.LastSuccess.IsZero() || s.now().Sub(v.LastSuccess) > 24*time.Hour {
		fail(w, http.StatusConflict, "update_changed", "check for updates again: the selected build is no longer available")
		return
	}
	if v.Result.Requires.Migration == "irreversible" {
		fail(w, http.StatusConflict, "manual_required", "this release requires an irreversible migration; update from the server")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if !s.updateControlAvailable(ctx) {
		fail(w, http.StatusConflict, "control_unavailable", "enable or upgrade the local control service: sudo ./install.sh --enable-panel-control")
		return
	}
	p, err := access.Validate(access.Params{Action: access.ActionUpdate, Commit: in.Commit, Lang: string(s.lang(r)), TraceID: logging.RequestID(r.Context())})
	if err != nil {
		fail(w, http.StatusBadRequest, "bad_update", "invalid update commit")
		return
	}
	previous := s.opt.Store.GetMeta(updateSessionKey)
	if err := s.checkpointUpdateSession(bearer(r)); err != nil {
		fail(w, http.StatusInternalServerError, "session_checkpoint_failed", "cannot save the update session; no update was started")
		return
	}
	task, err := s.control().Start(ctx, p)
	if err != nil {
		_ = s.opt.Store.SetMeta(updateSessionKey, previous)
	}
	if errors.Is(err, access.ErrBusy) {
		fail(w, http.StatusConflict, "busy", "another operation is running")
		return
	}
	if err != nil {
		fail(w, http.StatusBadGateway, "control_unavailable", "the control service could not start the update")
		return
	}
	s.log.Info("panel: update started", "id", task.ID, "commit", p.Commit, "by", s.clientIP(r))
	writeJSON(w, http.StatusAccepted, task)
}

func (s *Server) handleUpdateTask(w http.ResponseWriter, r *http.Request) {
	ctl := s.control()
	if ctl == nil {
		fail(w, http.StatusNotFound, "not_found", "no control service")
		return
	}
	task, err := ctl.Task(r.Context(), r.PathValue("id"))
	if err != nil {
		fail(w, http.StatusBadGateway, "control_unavailable", "the panel or the control service may be restarting")
		return
	}
	if task.Params.Action != access.ActionUpdate {
		fail(w, http.StatusNotFound, "not_found", "no such update")
		return
	}
	writeJSON(w, http.StatusOK, task)
}

// handleUpdateCheck is the "Check for updates" button. The request is made by
// the agent, not the browser, at most once a minute.
func (s *Server) handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	if s.opt.Update == nil {
		fail(w, http.StatusConflict, "disabled", "update checks are turned off in the configuration")
		return
	}
	err := s.opt.Update.Request()
	code := http.StatusAccepted
	if errors.Is(err, update.ErrTooSoon) {
		code = http.StatusTooManyRequests
	}
	writeJSON(w, code, s.updateView(string(s.lang(r))))
}
