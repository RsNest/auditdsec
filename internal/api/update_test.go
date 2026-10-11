package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/RsNest/auditdsec/internal/update"
)

type fakeUpdate struct {
	view update.View
	err  error
	n    int
}

func (f *fakeUpdate) View() update.View { return f.view }
func (f *fakeUpdate) Request() error    { f.n++; return f.err }

func availableView() update.View {
	e := update.Entry{
		ID: "2026-10-11-update-notices", Date: "2026-10-11",
		Title:    update.Text{EN: "Update notices", RU: "Уведомления об обновлениях"},
		Added:    update.Lists{EN: []string{"The panel tells you about new versions."}, RU: []string{"Панель сообщает о новых версиях."}},
		Actions:  update.Lists{EN: []string{"Run ./install.sh."}, RU: []string{"Запустите ./install.sh."}},
		Breaking: []update.Text{{EN: "The key a was renamed (token=abcdef1234567890SECRET).", RU: "Ключ a переименован."}},
		Requires: update.Requires{InstallerUpdate: true, Migration: "reversible"},
	}
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	return update.View{
		State: "available", Channel: "main",
		Installed:   update.Installed{Version: "0.3.0-dev+aaaaaaaaaaaa", Commit: strings.Repeat("a", 40), Date: "2026-10-01T00:00:00Z"},
		LastChecked: now, LastSuccess: now, NextCheck: now.Add(6 * time.Hour),
		Result: &update.Result{
			State:   update.StateAvailable,
			Latest:  update.Build{Seq: 2, Version: "0.3.0-dev+bbbbbbbbbbbb", Commit: strings.Repeat("b", 40), Published: "2026-10-11T10:00:00Z"},
			Entries: []update.Entry{e}, Breaking: e.Breaking, Requires: e.Requires,
		},
	}
}

func TestUpdateEndpointStates(t *testing.T) {
	s, _, _ := newServer(t)
	token := signIn(t, s)
	if rec := do(t, s, http.MethodGet, "/api/v1/update", "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("needs a session: %d", rec.Code)
	}

	// Off: nothing is claimed.
	var out updateJSON
	rec := do(t, s, http.MethodGet, "/api/v1/update", token, nil)
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out.State != "disabled" || out.Pending || out.Latest != nil {
		t.Errorf("%+v", out)
	}
	if rec := do(t, s, http.MethodPost, "/api/v1/update/check", token, nil); rec.Code != http.StatusConflict {
		t.Errorf("a check with the feature off: %d", rec.Code)
	}

	f := &fakeUpdate{view: availableView()}
	s.opt.Update = f
	rec = do(t, s, http.MethodGet, "/api/v1/update", token, nil)
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.State != "available" || !out.Pending || out.Latest == nil || out.Latest.Version != "0.3.0-dev+bbbbbbbbbbbb" ||
		out.Installed.Version != "0.3.0-dev+aaaaaaaaaaaa" || out.LastSuccess == nil || out.Command != "./install.sh" {
		t.Fatalf("%+v", out)
	}
	if len(out.Changes) != 1 || len(out.Breaking) != 1 || !out.Requires.InstallerUpdate || out.Requires.Migration != "reversible" {
		t.Errorf("%+v", out)
	}
	if strings.Contains(rec.Body.String(), "abcdef1234567890SECRET") {
		t.Errorf("the notes are masked like everything else: %s", rec.Body)
	}
	// The language is the reader's; the menu item names the installer's entry.
	if !strings.Contains(out.MenuItem, "Update auditdsec") || out.Changes[0].Title != "Update notices" {
		t.Errorf("english: %+v", out)
	}
	rec = do(t, s, http.MethodGet, "/api/v1/update?lang=ru", token, nil)
	var ru updateJSON
	_ = json.Unmarshal(rec.Body.Bytes(), &ru)
	if ru.MenuItem != "Обновить auditdsec — агент и веб-панель" || ru.Changes[0].Title != "Уведомления об обновлениях" {
		t.Errorf("russian: %+v", ru)
	}
}

// A failed check keeps the indicator (an update was known) but never says "current".
func TestFailedCheckKeepsWhatWasKnownAndSaysItIsStale(t *testing.T) {
	s, _, _ := newServer(t)
	token := signIn(t, s)
	v := availableView()
	v.State, v.Error = "unavailable", "the update source answered 503"
	s.opt.Update = &fakeUpdate{view: v}
	var out updateJSON
	rec := do(t, s, http.MethodGet, "/api/v1/update", token, nil)
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out.State != "unavailable" || !out.Pending || out.Error == "" || out.LastSuccess == nil {
		t.Errorf("%+v", out)
	}

	// A first check that failed has no last success to show.
	s.opt.Update = &fakeUpdate{view: update.View{State: "unavailable", Error: "x", Installed: update.Installed{Version: "v"}}}
	out = updateJSON{}
	rec = do(t, s, http.MethodGet, "/api/v1/update", token, nil)
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out.State != "unavailable" || out.Pending || out.LastSuccess != nil || out.Latest != nil {
		t.Errorf("%+v", out)
	}
}

func TestUnusableVersionIsNotOffered(t *testing.T) {
	s, _, _ := newServer(t)
	token := signIn(t, s)
	v := availableView()
	v.State, v.Result.State = update.StateUnsupportedArch, update.StateUnsupportedArch
	v.Result.Message = "the newest version is not published for this CPU architecture (arm64)"
	s.opt.Update = &fakeUpdate{view: v}
	var out updateJSON
	rec := do(t, s, http.MethodGet, "/api/v1/update", token, nil)
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out.Pending || out.Latest != nil || out.Message == "" {
		t.Errorf("an update that cannot be installed here must not be offered: %+v", out)
	}
}

func TestManualCheckButton(t *testing.T) {
	s, _, _ := newServer(t)
	token := signIn(t, s)
	f := &fakeUpdate{view: update.View{State: "checking", Installed: update.Installed{Version: "v"}}}
	s.opt.Update = f
	if rec := do(t, s, http.MethodPost, "/api/v1/update/check", token, nil); rec.Code != http.StatusAccepted || f.n != 1 {
		t.Errorf("%d %d", rec.Code, f.n)
	}
	f.err = update.ErrTooSoon
	if rec := do(t, s, http.MethodPost, "/api/v1/update/check", token, nil); rec.Code != http.StatusTooManyRequests {
		t.Errorf("pressed again at once: %d", rec.Code)
	}
}
