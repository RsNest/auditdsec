package access

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RsNest/auditdsec/internal/logging"
)

func TestValidateParams(t *testing.T) {
	good := []Params{
		{Action: ActionDomain, Site: "Panel.Example.com.", Email: "me@example.com", HTTPSPort: "auto"},
		{Action: ActionDomain, Site: "xn--e1afmkfd.xn--p1ai", HTTPSPort: "8443"},
		{Action: ActionIP}, {Action: ActionIP, Site: "203.0.113.9"}, {Action: ActionIP, Site: "[2001:db8::1]"},
		{Action: ActionTunnel}, {Action: ActionCheck}, {Action: ActionUpdate, Lang: "ru"},
		{Action: ActionUpdate, Commit: strings.Repeat("a", 40)},
	}
	for _, p := range good {
		if _, err := Validate(p); err != nil {
			t.Errorf("%+v: %v", p, err)
		}
	}
	got, _ := Validate(Params{Action: ActionDomain, Site: " Panel.Example.com. "})
	if got.Site != "panel.example.com" {
		t.Errorf("normalization: %q", got.Site)
	}
	// Everything that could become an option, a second argument or a shell
	// fragment is refused before it is used anywhere.
	bad := []Params{
		{Action: "rm -rf /"}, {Action: ""}, {Action: "Domain"},
		{Action: ActionDomain}, {Action: ActionDomain, Site: "-oProxyCommand=x.example.com"},
		{Action: ActionDomain, Site: "a.example.com --restore"}, {Action: ActionDomain, Site: "a.example.com;id"},
		{Action: ActionDomain, Site: "$(id).example.com"}, {Action: ActionDomain, Site: "localhost"},
		{Action: ActionDomain, Site: "203.0.113.9"}, {Action: ActionDomain, Site: "*.example.com"},
		{Action: ActionDomain, Site: "панель.рф"}, {Action: ActionDomain, Site: "a..example.com"},
		{Action: ActionDomain, Site: "a.example.com:8443"}, {Action: ActionDomain, Site: "https://a.example.com/"},
		{Action: ActionDomain, Site: strings.Repeat("a", 64) + ".example.com"},
		{Action: ActionDomain, Site: "a.example.com", Email: "x@y.z;id"}, {Action: ActionDomain, Site: "a.example.com", Email: "-x@example.com --yes"},
		{Action: ActionDomain, Site: "a.example.com", HTTPSPort: "0"}, {Action: ActionDomain, Site: "a.example.com", HTTPSPort: "65536"},
		{Action: ActionDomain, Site: "a.example.com", HTTPSPort: "08443"}, {Action: ActionDomain, Site: "a.example.com", HTTPSPort: "80 --x"},
		{Action: ActionIP, Site: "not-an-ip"}, {Action: ActionIP, Site: "fe80::1%eth0"},
		{Action: ActionTunnel, Site: "a.example.com"}, {Action: ActionCheck, Email: "a@b.cc"},
		{Action: ActionUpdate, HTTPSPort: "443"}, {Action: ActionCheck, Lang: "de"},
		{Action: ActionUpdate, Commit: "main"}, {Action: ActionUpdate, Commit: "--upload-pack=id"},
		{Action: ActionUpdate, Commit: strings.Repeat("A", 40)}, {Action: ActionCheck, Commit: strings.Repeat("a", 40)},
	}
	for _, p := range bad {
		if _, err := Validate(p); !errors.Is(err, ErrInvalid) {
			t.Errorf("%+v was accepted (%v)", p, err)
		}
	}
}

func TestArgsAreATemplate(t *testing.T) {
	p, _ := Validate(Params{Action: ActionDomain, Site: "panel.example.com", Email: "me@example.com", HTTPSPort: "8443", Lang: "ru"})
	got := strings.Join(Args(p, "/tmp/e.jsonl"), " ")
	want := "--yes --lang ru --action domain --site panel.example.com --email me@example.com --https-port 8443 --events-file /tmp/e.jsonl"
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
	if cmd := Command(p); cmd != "./install.sh --action domain --site panel.example.com --email me@example.com --https-port 8443" {
		t.Errorf("%q", cmd)
	}
	if a, b := PlanID(p, "https://x"), PlanID(p, "https://y"); a == b || len(a) != 16 {
		t.Errorf("the plan must depend on the current address: %s %s", a, b)
	}
}

// fakeInstaller scripts what the installer would do.
type fakeInstaller struct {
	mu       sync.Mutex
	runs     [][]string
	script   func(args []string, events string, log io.Writer) int
	released chan struct{}
}

func (f *fakeInstaller) exec(_ context.Context, _ string, args []string, log io.Writer) (int, error) {
	f.mu.Lock()
	f.runs = append(f.runs, args)
	f.mu.Unlock()
	events := ""
	for i, a := range args {
		if a == "--events-file" {
			events = args[i+1]
		}
	}
	if f.released != nil {
		<-f.released
	}
	return f.script(args, events, log), nil
}

func ev(t *testing.T, path string, kind, state, code, text, fix string) {
	t.Helper()
	b, _ := json.Marshal(Event{At: time.Now(), Kind: kind, State: state, Code: code, Text: text, Fix: fix})
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	_, _ = f.Write(append(b, '\n'))
}

func newRunner(t *testing.T, f *fakeInstaller) *Runner {
	t.Helper()
	r, err := NewRunner(t.TempDir(), t.TempDir(), f.exec)
	if err != nil {
		t.Fatal(err)
	}
	r.Poll = 5 * time.Millisecond
	return r
}

func wait(t *testing.T, r *Runner, id string) Task {
	t.Helper()
	r.Wait()
	task, ok := r.Get(id)
	if !ok {
		t.Fatal("task vanished")
	}
	return task
}

func TestSuccessfulChangeReportsStages(t *testing.T) {
	f := &fakeInstaller{script: func(_ []string, events string, log io.Writer) int {
		ev(t, events, "stage", "running", "dns", "checking the address", "")
		ev(t, events, "stage", "running", "apply", "", "")
		ev(t, events, "result", "ok", "", "https://panel.example.com", "")
		_, _ = io.WriteString(log, "done\n")
		return 0
	}}
	r := newRunner(t, f)
	task, err := r.Start(Params{Action: ActionDomain, Site: "panel.example.com", Email: "me@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	got := wait(t, r, task.ID)
	if got.State != StateSucceeded || got.Stage != "apply" || got.ExitCode != 0 || len(got.Events) != 3 || !strings.Contains(got.LogTail, "done") {
		t.Errorf("%+v", got)
	}
	// The installer received exactly the template, nothing more.
	if len(f.runs) != 1 || f.runs[0][4] != "domain" {
		t.Errorf("%v", f.runs)
	}
}

func TestFailureAndRollbackAreDistinct(t *testing.T) {
	f := &fakeInstaller{script: func(_ []string, events string, _ io.Writer) int {
		ev(t, events, "failure", "failed", "dns_mismatch", "the name does not lead to this server", "fix the A record")
		ev(t, events, "result", "failed", "dns_mismatch", "dns_mismatch: ...", "")
		return 13
	}}
	r := newRunner(t, f)
	a, _ := r.Start(Params{Action: ActionDomain, Site: "panel.example.com"})
	got := wait(t, r, a.ID)
	if got.State != StateFailed || got.Code != "dns_mismatch" || got.Fix != "fix the A record" || got.ExitCode != 13 {
		t.Errorf("%+v", got)
	}

	f.script = func(_ []string, events string, _ io.Writer) int {
		ev(t, events, "stage", "running", "apply", "", "")
		ev(t, events, "failure", "failed", "certificate_issuance_failed", "the CA refused", "wait and retry")
		ev(t, events, "stage", "running", "rollback", "", "")
		ev(t, events, "result", "rolled_back", "certificate_issuance_failed", "restored", "")
		return 15
	}
	b, _ := r.Start(Params{Action: ActionDomain, Site: "panel.example.com"})
	got = wait(t, r, b.ID)
	if got.State != StateRolledBack || got.Code != "certificate_issuance_failed" || got.Stage != "rollback" {
		t.Errorf("a rolled-back change must say so: %+v", got)
	}
}

// Without a result event the exit status settles the task, and the lock held
// by a person at the terminal (exit 20) is reported as such.
func TestExitStatusSettlesAnUnreportedTask(t *testing.T) {
	status := 0
	f := &fakeInstaller{script: func([]string, string, io.Writer) int { return status }}
	r := newRunner(t, f)
	for _, c := range []struct {
		status int
		state  string
		code   string
	}{{0, StateSucceeded, ""}, {20, StateFailed, "operation_in_progress"}, {1, StateFailed, ""}} {
		status = c.status
		task, err := r.Start(Params{Action: ActionCheck})
		if err != nil {
			t.Fatal(err)
		}
		got := wait(t, r, task.ID)
		if got.State != c.state || got.Code != c.code || (c.state == StateFailed && got.Cause == "") {
			t.Errorf("exit %d: %+v", c.status, got)
		}
	}
}

func TestOnlyOneChangeAtATime(t *testing.T) {
	f := &fakeInstaller{released: make(chan struct{}), script: func([]string, string, io.Writer) int { return 0 }}
	r := newRunner(t, f)
	first, err := r.Start(Params{Action: ActionCheck})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Start(Params{Action: ActionTunnel}); !errors.Is(err, ErrBusy) {
		t.Fatalf("a second change while one runs: %v", err)
	}
	close(f.released)
	wait(t, r, first.ID)
	if _, err := r.Start(Params{Action: ActionCheck}); err != nil {
		t.Errorf("after the first finished: %v", err)
	}
	r.Wait()
	if _, err := r.Start(Params{Action: "bogus"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("invalid parameters must not start anything: %v", err)
	}
}

// A task that was running when the service stopped is not reported as done.
func TestInterruptedTaskIsNotAssumedDone(t *testing.T) {
	dir, state := t.TempDir(), t.TempDir()
	block := make(chan struct{})
	f := &fakeInstaller{released: block, script: func([]string, string, io.Writer) int { return 0 }}
	r, _ := NewRunner(dir, state, f.exec)
	task, _ := r.Start(Params{Action: ActionTunnel})
	// The service "dies" with the change in flight: a new runner reads the file.
	r2, err := NewRunner(dir, state, f.exec)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := r2.Get(task.ID)
	if !ok || got.State != StateInterrupted || !strings.Contains(got.Cause, "check the panel") {
		t.Errorf("%+v", got)
	}
	if _, err := r2.Start(Params{Action: ActionCheck}); err != nil {
		t.Errorf("an interrupted task must not block new ones: %v", err)
	}
	close(block)
	r.Wait()
	r2.Wait()
}

func TestSecretsInOutputAreMasked(t *testing.T) {
	f := &fakeInstaller{script: func(_ []string, events string, log io.Writer) int {
		_, _ = io.WriteString(log, "running mysql -u root -pHUNTER2secret\n")
		ev(t, events, "failure", "failed", "x", "token=abcdef1234567890SECRET", "")
		ev(t, events, "result", "failed", "x", "", "")
		return 1
	}}
	r := newRunner(t, f)
	task, _ := r.Start(Params{Action: ActionCheck})
	got := wait(t, r, task.ID)
	blob, _ := json.Marshal(got)
	if strings.Contains(string(blob), "HUNTER2secret") || strings.Contains(string(blob), "abcdef1234567890SECRET") {
		t.Errorf("a secret reached the task record: %s", blob)
	}
}

func TestStatusMustBeJSON(t *testing.T) {
	f := &fakeInstaller{script: func(_ []string, _ string, log io.Writer) int {
		_, _ = io.WriteString(log, `{"installed":true,"mode":"domain"}`+"\n")
		return 0
	}}
	r := newRunner(t, f)
	st, err := r.Status(context.Background())
	if err != nil || !strings.Contains(string(st), `"mode":"domain"`) {
		t.Fatalf("%s %v", st, err)
	}
	f.script = func(_ []string, _ string, log io.Writer) int { _, _ = io.WriteString(log, "not json"); return 0 }
	if _, err := r.Status(context.Background()); err == nil {
		t.Error("garbage must not pass as a status")
	}
	f.script = func([]string, string, io.Writer) int { return 3 }
	if _, err := r.Status(context.Background()); err == nil {
		t.Error("a failing status must be an error")
	}
}

func TestControlHandlerAuthAndValidation(t *testing.T) {
	f := &fakeInstaller{script: func([]string, string, io.Writer) int { return 0 }}
	r := newRunner(t, f)
	h := ControlHandler(r, "tok")
	do := func(method, path, token, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	for _, path := range []string{"/v1/health", "/v1/status", "/v1/tasks"} {
		if rec := do(http.MethodGet, path, "", ""); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s without a token: %d", path, rec.Code)
		}
		if rec := do(http.MethodGet, path, "wrong", ""); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s with a wrong token: %d", path, rec.Code)
		}
	}
	if rec := do(http.MethodPost, "/v1/tasks", "", `{"action":"check"}`); rec.Code != http.StatusUnauthorized {
		t.Errorf("start without a token: %d", rec.Code)
	}
	for _, body := range []string{`{"action":"rm -rf /"}`, `{"action":"domain","site":"a.example.com","command":"id"}`, `not json`, `{"action":"domain","site":"-x.example.com"}`} {
		if rec := do(http.MethodPost, "/v1/tasks", "tok", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", body, rec.Code)
		}
	}
	if len(f.runs) != 0 {
		t.Fatalf("a rejected request started the installer: %v", f.runs)
	}
	rec := do(http.MethodPost, "/v1/tasks", "tok", `{"action":"check"}`)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var task Task
	_ = json.Unmarshal(rec.Body.Bytes(), &task)
	r.Wait()
	if rec = do(http.MethodGet, "/v1/tasks/"+task.ID, "tok", ""); rec.Code != http.StatusOK {
		t.Errorf("%d", rec.Code)
	}
	if rec = do(http.MethodGet, "/v1/tasks/nope", "tok", ""); rec.Code != http.StatusNotFound {
		t.Errorf("%d", rec.Code)
	}
}

// The agent-side client against the real handler over a real Unix socket.
func TestClientOverUnixSocket(t *testing.T) {
	f := &fakeInstaller{script: func(_ []string, events string, _ io.Writer) int {
		ev(t, events, "result", "ok", "", "", "")
		return 0
	}}
	r := newRunner(t, f)
	dir, err := os.MkdirTemp("", "ctl")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "s")
	l, err := Listen(sock, 0o660)
	if err != nil {
		t.Skipf("no unix sockets here: %v", err)
	}
	srv := &http.Server{Handler: ControlHandler(r, "secret-token")}
	go srv.Serve(l)
	defer srv.Close()
	tokenFile := filepath.Join(dir, "token")
	_ = os.WriteFile(tokenFile, []byte("secret-token\n"), 0o600)

	c := &Client{Socket: sock, TokenFile: tokenFile}
	ctx := context.Background()
	if err := c.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	task, err := c.Start(ctx, Params{Action: ActionCheck})
	if err != nil {
		t.Fatal(err)
	}
	r.Wait()
	got, err := c.Task(ctx, task.ID)
	if err != nil || got.State != StateSucceeded {
		t.Errorf("%+v %v", got, err)
	}
	if list, err := c.Tasks(ctx); err != nil || len(list) != 1 {
		t.Errorf("%v %v", list, err)
	}
	if _, err := c.Start(ctx, Params{Action: "x"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("%v", err)
	}
	// A wrong token, a missing token file and a missing socket are all
	// "unavailable or refused", never a silent success.
	if err := (&Client{Socket: sock, TokenFile: filepath.Join(dir, "none")}).Ping(ctx); !errors.Is(err, ErrUnavailable) {
		t.Errorf("%v", err)
	}
	_ = os.WriteFile(filepath.Join(dir, "bad"), []byte("nope"), 0o600)
	if err := (&Client{Socket: sock, TokenFile: filepath.Join(dir, "bad")}).Ping(ctx); !errors.Is(err, ErrRefused) {
		t.Errorf("%v", err)
	}
	if err := (&Client{Socket: filepath.Join(dir, "gone"), TokenFile: tokenFile}).Ping(ctx); !errors.Is(err, ErrUnavailable) {
		t.Errorf("%v", err)
	}
	if err := (&Client{}).Ping(ctx); !errors.Is(err, ErrUnavailable) {
		t.Errorf("an unconfigured client: %v", err)
	}
}

func TestDefaultExecRunsOnlyInstallSh(t *testing.T) {
	dir := t.TempDir()
	var sink strings.Builder
	if _, err := DefaultExec(context.Background(), dir, []string{"--status"}, &sink); err == nil {
		t.Error("a directory without install.sh must fail")
	}
	script := filepath.Join(dir, "install.sh")
	_ = os.WriteFile(script, []byte("#!/bin/sh\necho \"args=$*\"\necho \"secret=${SECRET_FROM_PARENT:-unset}\"\nexit 7\n"), 0o755)
	t.Setenv("SECRET_FROM_PARENT", "leak")
	code, err := DefaultExec(context.Background(), dir, []string{"--action", "check; id"}, &sink)
	if err != nil || code != 7 {
		t.Skipf("cannot run scripts here: %d %v", code, err)
	}
	out := sink.String()
	if !strings.Contains(out, "args=--action check; id") || !strings.Contains(out, "secret=unset") {
		t.Errorf("arguments must reach the script as data and the environment must be scrubbed: %q", out)
	}
}

// The trace ID of the request that asked for a change reaches the installer's
// environment, so the panel's log, the control service's log and the
// installer's log can be followed with one ID.
func TestTraceIDReachesTheInstaller(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "install.sh")
	_ = os.WriteFile(script, []byte("#!/bin/sh\necho \"trace=${AUDITDSEC_TRACE_ID:-none}\"\n"), 0o755)
	var sink strings.Builder
	id := "0123456789abcdef0123456789abcdef"
	if code, err := DefaultExec(logging.WithTrace(context.Background(), id), dir, nil, &sink); err != nil || code != 0 {
		t.Skipf("cannot run scripts here: %d %v", code, err)
	}
	if !strings.Contains(sink.String(), "trace="+id) {
		t.Errorf("the installer did not get the trace: %q", sink.String())
	}
	sink.Reset()
	_, _ = DefaultExec(logging.WithTrace(context.Background(), "x; rm -rf /"), dir, nil, &sink)
	if !strings.Contains(sink.String(), "trace=none") {
		t.Errorf("an invalid ID must not reach the environment: %q", sink.String())
	}
}

func TestParamsKeepAValidTraceAndReplaceAnInvalidOne(t *testing.T) {
	good := "fedcba9876543210fedcba9876543210"
	p, err := Validate(Params{Action: ActionCheck, TraceID: good})
	if err != nil || p.TraceID != good {
		t.Errorf("a valid trace must be kept: %+v %v", p, err)
	}
	p, err = Validate(Params{Action: ActionCheck, TraceID: "bad id;"})
	if err != nil || !logging.ValidID(p.TraceID) || p.TraceID == "bad id;" {
		t.Errorf("an invalid trace must be replaced: %+v %v", p, err)
	}
}
