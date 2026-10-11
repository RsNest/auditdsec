package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/RsNest/auditdsec/internal/access"
	"github.com/RsNest/auditdsec/internal/update"
)

type fakeUpdate struct {
	view update.View
	err  error
	n    int
}

func TestUpdateApplyPinsTheCheckedBuildAndGuardsMutations(t *testing.T) {
	s, _, clock := newServer(t)
	token := signIn(t, s)
	v := availableView()
	v.LastSuccess = *clock
	f := &fakeUpdate{view: v}
	s.opt.Update = f
	ctl := &fakeControl{status: statusJSON}
	s.opt.Control = ctl
	payload := map[string]string{"commit": v.Result.Latest.Commit}
	if rec := do(t, s, http.MethodPost, "/api/v1/update/apply", "", payload); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated update: %d", rec.Code)
	}
	if rec := do(t, s, http.MethodPost, "/api/v1/update/apply", token, map[string]string{"commit": strings.Repeat("c", 40)}); rec.Code != http.StatusConflict {
		t.Fatalf("arbitrary build accepted: %d", rec.Code)
	}
	for _, state := range []string{"unavailable", "checking", "up_to_date"} {
		f.view.State = state
		if rec := do(t, s, http.MethodPost, "/api/v1/update/apply", token, payload); rec.Code != http.StatusConflict {
			t.Fatalf("state %s was installable: %d", state, rec.Code)
		}
	}
	f.view.State = update.StateAvailable
	f.view.Result.Requires.Migration = "irreversible"
	if rec := do(t, s, http.MethodPost, "/api/v1/update/apply", token, payload); rec.Code != http.StatusConflict {
		t.Fatalf("irreversible migration accepted: %d", rec.Code)
	}
	f.view.Result.Requires.Migration = "reversible"
	f.view.LastSuccess = clock.Add(-25 * time.Hour)
	if rec := do(t, s, http.MethodPost, "/api/v1/update/apply", token, payload); rec.Code != http.StatusConflict {
		t.Fatalf("stale build accepted: %d", rec.Code)
	}
	f.view.LastSuccess = *clock
	ctl.err = access.ErrBusy
	if rec := do(t, s, http.MethodPost, "/api/v1/update/apply", token, payload); rec.Code != http.StatusConflict {
		t.Fatalf("concurrent update accepted: %d", rec.Code)
	}
	ctl.err = nil
	if rec := do(t, s, http.MethodPost, "/api/v1/update/apply", token, payload); rec.Code != http.StatusAccepted {
		t.Fatalf("update: %d %s", rec.Code, rec.Body)
	}
	if len(ctl.started) != 1 || ctl.started[0].Action != access.ActionUpdate || ctl.started[0].Commit != payload["commit"] || ctl.started[0].TraceID == "" {
		t.Fatalf("not a pinned, traced update: %+v", ctl.started)
	}
	var out updateJSON
	rec := do(t, s, http.MethodGet, "/api/v1/update", token, nil)
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.Task == nil || !out.Control["available"] {
		t.Fatalf("cannot resume: %v %s", err, rec.Body)
	}
	if rec := do(t, s, http.MethodGet, "/api/v1/update/tasks/chg-1", token, nil); rec.Code != http.StatusOK {
		t.Fatalf("polling failed: %d", rec.Code)
	}
	ctl.tasks[0].Params.Action = access.ActionDomain
	if rec := do(t, s, http.MethodGet, "/api/v1/update/tasks/chg-1", token, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("another operation shown as an update: %d", rec.Code)
	}
}

type oldUpdateControl struct{ fakeControl }

func (*oldUpdateControl) SupportsUpdates(context.Context) bool { return false }

func TestOldOrMissingControlCannotOfferOneClickUpdate(t *testing.T) {
	s, _, clock := newServer(t)
	token := signIn(t, s)
	v := availableView()
	v.LastSuccess = *clock
	s.opt.Update = &fakeUpdate{view: v}
	for _, ctl := range []AccessControl{nil, &oldUpdateControl{}} {
		s.opt.Control = ctl
		rec := do(t, s, http.MethodPost, "/api/v1/update/apply", token, map[string]string{"commit": v.Result.Latest.Commit})
		if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "enable-panel-control") {
			t.Fatalf("old control: %d %s", rec.Code, rec.Body)
		}
	}
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
