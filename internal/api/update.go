package api

import (
	"errors"
	"net/http"
	"time"

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
	writeJSON(w, http.StatusOK, s.updateView(string(s.lang(r))))
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
