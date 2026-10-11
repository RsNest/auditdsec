package api

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RsNest/auditdsec/internal/access"
	"github.com/RsNest/auditdsec/internal/netcheck"
)

type fakeDNS struct {
	v4, v6 []string
}

func (f fakeDNS) Name() string { return "fake" }
func (f fakeDNS) LookupIP(_ context.Context, network, _ string) ([]netip.Addr, error) {
	src := f.v4
	if network == "ip6" {
		src = f.v6
	}
	var out []netip.Addr
	for _, s := range src {
		out = append(out, netip.MustParseAddr(s))
	}
	if len(out) == 0 {
		return nil, &net.DNSError{IsNotFound: true}
	}
	return out, nil
}
func (f fakeDNS) LookupCNAME(context.Context, string) (string, error) { return "", nil }

func depsFor(v4 ...string) *access.Deps {
	return &access.Deps{
		Resolvers: []netcheck.Resolver{fakeDNS{v4: v4}, fakeDNS{v4: v4}},
		Server: func(context.Context) netcheck.Server {
			return netcheck.Server{Global: []netip.Addr{netip.MustParseAddr("203.0.113.9")}}
		},
		Attempts: 1,
	}
}

type fakeControl struct {
	mu      sync.Mutex
	started []access.Params
	err     error
	status  string
	tasks   []access.Task
	ping    error
}

func (f *fakeControl) Ping(context.Context) error { return f.ping }
func (f *fakeControl) Status(context.Context) (json.RawMessage, error) {
	if f.ping != nil {
		return nil, f.ping
	}
	return json.RawMessage(f.status), nil
}
func (f *fakeControl) Start(_ context.Context, p access.Params) (access.Task, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return access.Task{}, f.err
	}
	f.started = append(f.started, p)
	t := access.Task{ID: "chg-1", Params: p, State: access.StateRunning}
	f.tasks = []access.Task{t}
	return t, nil
}
func (f *fakeControl) Task(_ context.Context, id string) (access.Task, error) {
	for _, t := range f.tasks {
		if t.ID == id {
			return t, nil
		}
	}
	return access.Task{}, errors.New("none")
}
func (f *fakeControl) Tasks(context.Context) ([]access.Task, error) { return f.tasks, nil }

const statusJSON = `{"installed":true,"mode":"ip","site":"203.0.113.9","https_port":"443","url":"https://203.0.113.9","acme":"production","issuer":"C=US, O=Let's Encrypt, CN=E5","not_after":"Nov  1 00:00:00 2026 GMT","renewal":"automatic","running":"yes"}`

func accessRig(t *testing.T, ctl *fakeControl, v4 ...string) (*Server, string, *time.Time) {
	t.Helper()
	s, _, clock := newServer(t)
	if ctl != nil {
		s.opt.Control = ctl
	}
	s.opt.PreflightDeps = depsFor(v4...)
	return s, signIn(t, s), clock
}

func post(t *testing.T, s *Server, token, path string, body any) (int, map[string]any) {
	t.Helper()
	rec := do(t, s, http.MethodPost, path, token, body)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func plan(t *testing.T, s *Server, token string, body map[string]any) string {
	t.Helper()
	code, out := post(t, s, token, "/api/v1/access/check", body)
	if code != http.StatusOK {
		t.Fatalf("check: %d %v", code, out)
	}
	return out["plan"].(map[string]any)["plan_id"].(string)
}

func TestAccessStateWithAndWithoutControl(t *testing.T) {
	s, token, _ := accessRig(t, nil)
	rec := do(t, s, http.MethodGet, "/api/v1/access", token, nil)
	var out struct {
		Current struct{ Source, URL string }
		Control struct {
			Available bool
			Reason    string
		}
		UpdateCommand string `json:"update_command"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Control.Available || out.Control.Reason == "" || out.Current.Source != "agent" || out.UpdateCommand != "./install.sh" {
		t.Errorf("without the control service the panel must say so: %+v", out)
	}
	if rec := do(t, s, http.MethodGet, "/api/v1/access", "", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("access needs a session: %d", rec.Code)
	}

	ctl := &fakeControl{status: statusJSON}
	s, token, _ = accessRig(t, ctl)
	rec = do(t, s, http.MethodGet, "/api/v1/access", token, nil)
	var full struct {
		Current struct{ Mode, Source, Issuer string }
		Control struct{ Available bool }
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &full)
	if !full.Control.Available || full.Current.Source != "installer" || full.Current.Mode != "ip" || !strings.Contains(full.Current.Issuer, "Let's Encrypt") {
		t.Errorf("%s", rec.Body.String())
	}
	// A control service that stops answering is reported, not hidden.
	ctl.ping = access.ErrUnavailable
	rec = do(t, s, http.MethodGet, "/api/v1/access", token, nil)
	_ = json.Unmarshal(rec.Body.Bytes(), &full)
	if full.Control.Available {
		t.Error("an unreachable control service was reported as available")
	}
}

func TestDomainCheckSeparatesDNSFromEverythingElse(t *testing.T) {
	s, token, _ := accessRig(t, &fakeControl{status: statusJSON}, "203.0.113.9")
	code, out := post(t, s, token, "/api/v1/access/check", map[string]any{"action": "domain", "site": "Panel.Example.com", "email": "me@example.com"})
	if code != http.StatusOK {
		t.Fatalf("%d %v", code, out)
	}
	pre := out["preflight"].(map[string]any)
	if pre["domain"] != "panel.example.com" || pre["dns_ok"] != true {
		t.Fatalf("%v", pre)
	}
	byID := map[string]string{}
	for _, c := range pre["checks"].([]any) {
		m := c.(map[string]any)
		byID[m["id"].(string)] = m["status"].(string)
	}
	if byID["dns"] != "ok" || byID["ports"] != "unchecked" || byID["issuance"] != "unchecked" || byID["reachable"] != "unchecked" {
		t.Errorf("DNS must be the only thing reported as checked: %v", byID)
	}
	if recs := pre["records"].([]any); len(recs) == 0 || recs[0].(map[string]any)["value"] != "203.0.113.9" {
		t.Errorf("the records to create must show the server address: %v", pre["records"])
	}
	pl := out["plan"].(map[string]any)
	if pl["command"] != "./install.sh --action domain --site panel.example.com --email me@example.com" || !strings.Contains(pl["interruption"].(string), "interruption") ||
		!strings.Contains(pl["rollback"].(string), "restored") {
		t.Errorf("%v", pl)
	}

	// DNS that points elsewhere fails the check and says what is wrong.
	s2, token2, _ := accessRig(t, &fakeControl{status: statusJSON}, "198.51.100.5")
	_, out = post(t, s2, token2, "/api/v1/access/check", map[string]any{"action": "domain", "site": "panel.example.com"})
	pre = out["preflight"].(map[string]any)
	if pre["dns_ok"] != false || len(pre["problems"].([]any)) == 0 {
		t.Errorf("%v", pre)
	}
}

func TestApplyNeedsConfirmationAndAFreshSuccessfulCheck(t *testing.T) {
	ctl := &fakeControl{status: statusJSON}
	s, token, clock := accessRig(t, ctl, "203.0.113.9")
	body := map[string]any{"action": "domain", "site": "panel.example.com", "email": "me@example.com"}

	apply := func(planID string, confirm bool) (int, map[string]any) {
		b := map[string]any{"action": "domain", "site": "panel.example.com", "email": "me@example.com", "plan_id": planID, "confirm": confirm}
		return post(t, s, token, "/api/v1/access/apply", b)
	}
	// No check yet.
	if code, out := apply("whatever", true); code != http.StatusBadRequest {
		t.Errorf("a wrong plan: %d %v", code, out)
	}
	id := plan(t, s, token, body)
	delete(body, "x")
	_ = id
	// The plan id from the check is accepted only with the confirmation.
	if code, _ := apply(id, false); code != http.StatusBadRequest {
		t.Errorf("unconfirmed: %d", code)
	}
	if len(ctl.started) != 0 {
		t.Fatal("a refused request started a change")
	}
	// The check is stale after half an hour.
	*clock = clock.Add(31 * time.Minute)
	if code, out := apply(id, true); code != http.StatusConflict || out["error"] != "check_required" {
		t.Errorf("stale check: %d %v", code, out)
	}
	*clock = clock.Add(-31 * time.Minute)
	// A check for another domain does not count.
	other := map[string]any{"action": "domain", "site": "other.example.com"}
	plan(t, s, token, other)
	if code, out := apply(id, true); code != http.StatusConflict || out["error"] != "check_required" {
		t.Errorf("another domain was checked last: %d %v", code, out)
	}
	// Now the real thing.
	id = plan(t, s, token, body)
	code, out := apply(id, true)
	if code != http.StatusAccepted || out["id"] != "chg-1" {
		t.Fatalf("%d %v", code, out)
	}
	if len(ctl.started) != 1 || ctl.started[0].Action != "domain" || ctl.started[0].Site != "panel.example.com" || ctl.started[0].Email != "me@example.com" {
		t.Errorf("the control service must receive the validated parameters: %+v", ctl.started)
	}
	// The task can be read back (after a reload of the page).
	rec := do(t, s, http.MethodGet, "/api/v1/access/tasks/chg-1", token, nil)
	if rec.Code != http.StatusOK {
		t.Errorf("%d", rec.Code)
	}
	rec = do(t, s, http.MethodGet, "/api/v1/access", token, nil)
	if !strings.Contains(rec.Body.String(), `"last_task"`) {
		t.Errorf("the running change must survive a page reload: %s", rec.Body.String())
	}
}

func TestFailedDNSBlocksApply(t *testing.T) {
	ctl := &fakeControl{status: statusJSON}
	s, token, _ := accessRig(t, ctl, "198.51.100.5") // does not lead here
	body := map[string]any{"action": "domain", "site": "panel.example.com"}
	id := plan(t, s, token, body)
	code, out := post(t, s, token, "/api/v1/access/apply", map[string]any{"action": "domain", "site": "panel.example.com", "plan_id": id, "confirm": true})
	if code != http.StatusConflict || out["error"] != "check_required" || len(ctl.started) != 0 {
		t.Errorf("wrong DNS must stop the change: %d %v", code, out)
	}
}

// Without the control service nothing is applied and nothing is pretended: the
// answer is the command for the server.
func TestApplyWithoutControlGivesTheCommand(t *testing.T) {
	s, token, _ := accessRig(t, nil, "203.0.113.9")
	body := map[string]any{"action": "domain", "site": "panel.example.com", "email": "me@example.com"}
	id := plan(t, s, token, body)
	code, out := post(t, s, token, "/api/v1/access/apply", map[string]any{"action": "domain", "site": "panel.example.com", "email": "me@example.com", "plan_id": id, "confirm": true})
	if code != http.StatusConflict || out["error"] != "control_unavailable" || out["command"] != "./install.sh --action domain --site panel.example.com --email me@example.com" {
		t.Errorf("%d %v", code, out)
	}
	if rec := do(t, s, http.MethodGet, "/api/v1/access/tasks/chg-1", token, nil); rec.Code != http.StatusNotFound {
		t.Errorf("there is no task to show: %d", rec.Code)
	}
}

func TestConcurrentChangeIsRefused(t *testing.T) {
	ctl := &fakeControl{status: statusJSON, err: access.ErrBusy}
	s, token, _ := accessRig(t, ctl, "203.0.113.9")
	id := plan(t, s, token, map[string]any{"action": "tunnel"})
	code, out := post(t, s, token, "/api/v1/access/apply", map[string]any{"action": "tunnel", "plan_id": id, "confirm": true})
	if code != http.StatusConflict || out["error"] != "busy" {
		t.Errorf("%d %v", code, out)
	}
}

func TestOtherActionsAndInvalidInput(t *testing.T) {
	ctl := &fakeControl{status: statusJSON}
	s, token, _ := accessRig(t, ctl)
	// Switching to the tunnel or the IP needs no DNS, but still the plan.
	for _, a := range []string{"ip", "tunnel", "update", "check"} {
		id := plan(t, s, token, map[string]any{"action": a})
		if code, out := post(t, s, token, "/api/v1/access/apply", map[string]any{"action": a, "plan_id": id, "confirm": true}); code != http.StatusAccepted {
			t.Errorf("%s: %d %v", a, code, out)
		}
		ctl.tasks = nil
	}
	for _, bad := range []map[string]any{
		{"action": "domain", "site": "-oProxyCommand=a.example.com"}, {"action": "domain", "site": "a.example.com; id"},
		{"action": "domain", "site": "203.0.113.9"}, {"action": "reset-everything"}, {"action": "domain", "site": "a.example.com", "https_port": "99999"},
	} {
		if code, _ := post(t, s, token, "/api/v1/access/check", bad); code != http.StatusBadRequest {
			t.Errorf("%v: %d", bad, code)
		}
		if code, _ := post(t, s, token, "/api/v1/access/apply", bad); code != http.StatusBadRequest {
			t.Errorf("apply %v: %d", bad, code)
		}
	}
}

func TestDraftIsSavedAndCleared(t *testing.T) {
	s, token, _ := accessRig(t, nil)
	rec := do(t, s, http.MethodPut, "/api/v1/access/draft", token, map[string]any{"action": "domain", "site": "Panel.Example.com", "email": "me@example.com"})
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	rec = do(t, s, http.MethodGet, "/api/v1/access", token, nil)
	if !strings.Contains(rec.Body.String(), `"draft":{"action":"domain","site":"panel.example.com"`) {
		t.Errorf("the draft must come back normalized: %s", rec.Body)
	}
	if rec := do(t, s, http.MethodPut, "/api/v1/access/draft", token, map[string]any{"action": "domain", "site": "bad;name"}); rec.Code != http.StatusBadRequest {
		t.Errorf("%d", rec.Code)
	}
	if rec := do(t, s, http.MethodDelete, "/api/v1/access/draft", token, nil); rec.Code != http.StatusNoContent {
		t.Errorf("%d", rec.Code)
	}
	rec = do(t, s, http.MethodGet, "/api/v1/access", token, nil)
	if strings.Contains(rec.Body.String(), `"draft"`) {
		t.Errorf("the draft was not cleared: %s", rec.Body)
	}
}
