package pipeline

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RsNest/auditdsec/internal/action"
	"github.com/RsNest/auditdsec/internal/detect"
	"github.com/RsNest/auditdsec/internal/model"
	"github.com/RsNest/auditdsec/internal/store"
)

type fakeNotifier struct {
	mu       sync.Mutex
	events   []model.Event
	bans     []store.Ban
	banErrs  []error
	messages []string
}

func (f *fakeNotifier) Notify(_ context.Context, ev model.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, ev)
	return nil
}

func (f *fakeNotifier) NotifyBan(_ context.Context, b store.Ban, applyErr error) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bans = append(f.bans, b)
	f.banErrs = append(f.banErrs, applyErr)
	return nil
}

func (f *fakeNotifier) NotifyMessage(_ context.Context, key string, _ map[string]string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.messages = append(f.messages, key)
	return nil
}

func (f *fakeNotifier) allBans() []store.Ban {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]store.Ban(nil), f.bans...)
}

func (f *fakeNotifier) allMessages() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.messages...)
}

// fakeBanner records what the firewall was asked to do, and can refuse.
type fakeBanner struct {
	mu       sync.Mutex
	banned   []action.Decision
	unbanned []string
	err      error
}

func (f *fakeBanner) Ban(_ context.Context, d action.Decision) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.banned = append(f.banned, d)
	return nil
}

func (f *fakeBanner) Unban(_ context.Context, ip string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unbanned = append(f.unbanned, ip)
	return nil
}

func (f *fakeBanner) List(context.Context) ([]action.Decision, error) { return nil, nil }
func (f *fakeBanner) Name() string                                    { return "fake" }

func (f *fakeBanner) allBanned() []action.Decision {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]action.Decision(nil), f.banned...)
}

func (f *fakeNotifier) all() []model.Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]model.Event, len(f.events))
	copy(out, f.events)
	return out
}

func (f *fakeNotifier) waitFor(t *testing.T, kind model.Kind) model.Event {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		for _, ev := range f.all() {
			if ev.Kind == kind {
				return ev
			}
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for a %s event, got %+v", kind, f.all())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func appendLines(t *testing.T, path string, lines ...string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, l := range lines {
		if _, err := f.WriteString(l + "\n"); err != nil {
			t.Fatal(err)
		}
	}
}

func startPipeline(t *testing.T, o Options) (*Pipeline, *fakeNotifier, *store.Store, context.CancelFunc) {
	t.Helper()
	notifier := &fakeNotifier{}
	st := o.Store
	if st == nil {
		var err error
		st, err = store.Open(store.Options{Dir: filepath.Join(t.TempDir(), "state")})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { st.Close() })
	}
	o.Store = st
	o.Notifier = notifier
	if o.Host == "" {
		o.Host = "web01"
	}
	p, err := New(o)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := p.Run(ctx); err != nil {
			t.Errorf("Run: %v", err)
		}
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("the pipeline did not stop")
		}
	})
	return p, notifier, st, cancel
}

func TestPipelineEndToEnd(t *testing.T) {
	dir := t.TempDir()
	auditLog := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(auditLog, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	p, notifier, st, _ := startPipeline(t, Options{
		AuditLog:      auditLog,
		StateDir:      filepath.Join(dir, "state"),
		ReadFromStart: true,
	})

	appendLines(t, auditLog,
		`type=USER_LOGIN msg=audit(1760000000.000:1): pid=1 uid=0 auid=0 msg='op=login acct="root" exe="/usr/sbin/sshd" addr=198.51.100.7 terminal=ssh res=failed'`,
		`type=EOE msg=audit(1760000000.000:1): `,
		`type=SYSCALL msg=audit(1760000001.000:2): syscall=257 success=yes auid=0 uid=0 comm="tee" exe="/usr/bin/tee" key="ads_sshkeys"`,
		`type=PATH msg=audit(1760000001.000:2): item=0 name="/root/.ssh/authorized_keys"`,
		`type=EOE msg=audit(1760000001.000:2): `,
	)

	fail := notifier.waitFor(t, model.KindSSHLoginFail)
	if fail.SrcIP != "198.51.100.7" || fail.User != "root" || fail.Host != "web01" {
		t.Errorf("login failure = %+v", fail)
	}
	keys := notifier.waitFor(t, model.KindAuthorizedKeysChange)
	if keys.Severity != model.SevCritical || keys.Arg("path") != "/root/.ssh/authorized_keys" {
		t.Errorf("authorized_keys event = %+v", keys)
	}

	// Everything alerted on must also be on disk for /last and /status.
	deadline := time.After(5 * time.Second)
	for len(st.Recent(0)) < 2 {
		select {
		case <-deadline:
			t.Fatalf("the store holds %d events, want 2", len(st.Recent(0)))
		case <-time.After(10 * time.Millisecond):
		}
	}
	if processed, reported, _ := p.Counters(); processed < 2 || reported < 2 {
		t.Errorf("counters = %d processed, %d reported", processed, reported)
	}
}

// Noise must not reach the chat: a pipeline that reported session bookkeeping
// would train its user to ignore it.
func TestPipelineDropsNoise(t *testing.T) {
	dir := t.TempDir()
	auditLog := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(auditLog, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	_, notifier, _, _ := startPipeline(t, Options{
		AuditLog: auditLog, StateDir: filepath.Join(dir, "state"), ReadFromStart: true,
	})

	appendLines(t, auditLog,
		`type=CRED_ACQ msg=audit(1760000000.000:1): pid=1 uid=0 msg='op=PAM:setcred acct="root" res=success'`,
		`type=CRED_DISP msg=audit(1760000001.000:2): pid=1 uid=0 msg='op=PAM:setcred acct="root" res=success'`,
		`not an audit line at all`,
		`type=USER_LOGIN msg=audit(1760000002.000:3): pid=1 uid=0 auid=1000 msg='op=login acct="ruslan" addr=203.0.113.9 terminal=ssh res=success'`,
		`type=EOE msg=audit(1760000002.000:3): `,
	)

	ev := notifier.waitFor(t, model.KindSSHLoginOK)
	if ev.User != "ruslan" {
		t.Errorf("login = %+v", ev)
	}
	if got := notifier.all(); len(got) != 1 {
		t.Errorf("reported %d events, want only the login: %+v", len(got), got)
	}
}

// A missing audit log is the silence that matters, so it must produce an alert.
func TestPipelineHeartbeatAlertsOnMissingLog(t *testing.T) {
	dir := t.TempDir()
	_, notifier, st, _ := startPipeline(t, Options{
		AuditLog:         filepath.Join(dir, "gone", "audit.log"),
		StateDir:         filepath.Join(dir, "state"),
		HeartbeatEnabled: true,
		HeartbeatEvery:   20 * time.Millisecond,
	})

	ev := notifier.waitFor(t, model.KindAuditdStopped)
	if ev.Severity != model.SevCritical {
		t.Errorf("heartbeat event = %+v", ev)
	}
	if ev.Arg("state") != "audit_unavailable" {
		t.Errorf("a missing log is audit_unavailable: %+v", ev)
	}

	// The alert must not repeat every tick.
	time.Sleep(200 * time.Millisecond)
	count := 0
	for _, e := range notifier.all() {
		if e.Kind == model.KindAuditdStopped {
			count++
		}
	}
	if count != 1 {
		t.Errorf("the heartbeat alerted %d times, want 1 inside the cooldown", count)
	}
	if len(st.Recent(0)) == 0 {
		t.Error("the heartbeat event should also be stored")
	}
}

// A log that exists but has not been written for too long is the same signal.
func TestPipelineHeartbeatAlertsOnStaleLog(t *testing.T) {
	dir := t.TempDir()
	auditLog := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(auditLog, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(auditLog, old, old); err != nil {
		t.Fatal(err)
	}

	_, notifier, _, _ := startPipeline(t, Options{
		AuditLog:         auditLog,
		StateDir:         filepath.Join(dir, "state"),
		HeartbeatEnabled: true,
		HeartbeatEvery:   20 * time.Millisecond,
		HeartbeatStale:   time.Hour,
	})

	ev := notifier.waitFor(t, model.KindAuditdStopped)
	if ev.Arg("detail") == "" {
		t.Errorf("the alert should say why: %+v", ev)
	}
	if ev.Arg("state") != "audit_silent" || ev.Severity != model.SevWarn {
		t.Errorf("a stale log is audit_silent, a warning and not a claim of failure: %+v", ev)
	}
}

func TestPipelineHeartbeatStaysQuietWhenHealthy(t *testing.T) {
	dir := t.TempDir()
	auditLog := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(auditLog, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, notifier, _, _ := startPipeline(t, Options{
		AuditLog:         auditLog,
		StateDir:         filepath.Join(dir, "state"),
		HeartbeatEnabled: true,
		HeartbeatEvery:   20 * time.Millisecond,
		HeartbeatStale:   time.Hour,
	})
	time.Sleep(200 * time.Millisecond)
	if got := notifier.all(); len(got) != 0 {
		t.Errorf("a healthy log must produce no alerts, got %+v", got)
	}
}

func TestNewValidatesOptions(t *testing.T) {
	st, err := store.Open(store.Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if _, err := New(Options{Store: st, Notifier: &fakeNotifier{}}); err == nil {
		t.Error("an empty AuditLog should fail")
	}
	if _, err := New(Options{AuditLog: "/x", Notifier: &fakeNotifier{}}); err == nil {
		t.Error("a missing Store should fail")
	}
	if _, err := New(Options{AuditLog: "/x", Store: st}); err == nil {
		t.Error("a missing Notifier should fail")
	}
}

// logTime stamps a synthetic record a few seconds ago, the way a live auditd
// would. Timestamps matter: the pipeline refuses to act on a burst whose window
// has already closed, so a test written against a fixed date in the past would
// be testing the stale-log path by accident.
func logTime(serial int) int64 {
	return time.Now().Add(-30 * time.Second).Add(time.Duration(serial) * time.Second).Unix()
}

// failLine builds a failed-login audit record from the given address.
func failLine(serial int, ip string) []string {
	ts := logTime(serial)
	return []string{
		fmt.Sprintf(`type=USER_LOGIN msg=audit(%d.000:%d): pid=1 uid=0 auid=4294967295 msg='op=login acct="root" exe="/usr/sbin/sshd" addr=%s terminal=ssh res=failed'`, ts, serial, ip),
		fmt.Sprintf(`type=EOE msg=audit(%d.000:%d): `, ts, serial),
	}
}

// staleFailLine is the same record, but old enough that acting on it would be
// pointless.
func staleFailLine(serial int, ip string) []string {
	ts := time.Now().Add(-72 * time.Hour).Add(time.Duration(serial) * time.Second).Unix()
	return []string{
		fmt.Sprintf(`type=USER_LOGIN msg=audit(%d.000:%d): pid=1 uid=0 auid=4294967295 msg='op=login acct="root" exe="/usr/sbin/sshd" addr=%s terminal=ssh res=failed'`, ts, serial, ip),
		fmt.Sprintf(`type=EOE msg=audit(%d.000:%d): `, ts, serial),
	}
}

func okLine(serial int, ip, user string) []string {
	ts := logTime(serial)
	return []string{
		fmt.Sprintf(`type=USER_LOGIN msg=audit(%d.000:%d): pid=1 uid=0 auid=0 msg='op=login acct="%s" exe="/usr/sbin/sshd" addr=%s terminal=ssh res=success'`, ts, serial, user, ip),
		fmt.Sprintf(`type=EOE msg=audit(%d.000:%d): `, ts, serial),
	}
}

func newAuditLog(t *testing.T) (dir, path string) {
	t.Helper()
	dir = t.TempDir()
	path = filepath.Join(dir, "audit.log")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir, path
}

func (f *fakeNotifier) waitForBan(t *testing.T, ip string) store.Ban {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		for _, b := range f.allBans() {
			if b.IP == ip {
				return b
			}
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for a ban of %s, got %+v", ip, f.allBans())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// The whole point of v0.2: a burst of failures gets the address blocked, the
// owner is told, and the firewall is actually asked to do it.
func TestPipelineBansAfterABurstOfFailures(t *testing.T) {
	dir, auditLog := newAuditLog(t)
	banner := &fakeBanner{}
	_, notifier, st, _ := startPipeline(t, Options{
		AuditLog:      auditLog,
		StateDir:      filepath.Join(dir, "state"),
		ReadFromStart: true,
		Banner:        banner,
		Detector: detect.NewBruteForce(detect.Options{
			Window: 10 * time.Minute, FailThreshold: 3, Host: "web01",
		}),
	})

	for i := 1; i <= 3; i++ {
		appendLines(t, auditLog, failLine(i, "198.51.100.7")...)
	}

	ban := notifier.waitForBan(t, "198.51.100.7")
	if ban.Count != 1 || ban.Permanent() {
		t.Errorf("first ban = %+v, want count 1 and an expiry", ban)
	}
	if got := banner.allBanned(); len(got) != 1 || got[0].IP != "198.51.100.7" {
		t.Errorf("the firewall was asked for %+v", got)
	}
	if got := st.Bans(); len(got) != 1 || !got[0].Applied {
		t.Errorf("the store should record the ban as applied: %+v", got)
	}
}

// A firewall that refuses must not be hidden: the owner has to know the ban
// was only written down.
func TestPipelineReportsAFirewallFailure(t *testing.T) {
	dir, auditLog := newAuditLog(t)
	banner := &fakeBanner{err: errors.New("Operation not permitted")}
	_, notifier, st, _ := startPipeline(t, Options{
		AuditLog:      auditLog,
		StateDir:      filepath.Join(dir, "state"),
		ReadFromStart: true,
		Banner:        banner,
		Detector: detect.NewBruteForce(detect.Options{
			Window: time.Minute, FailThreshold: 2,
		}),
	})

	for i := 1; i <= 2; i++ {
		appendLines(t, auditLog, failLine(i, "198.51.100.8")...)
	}
	notifier.waitForBan(t, "198.51.100.8")

	notifier.mu.Lock()
	errs := append([]error(nil), notifier.banErrs...)
	notifier.mu.Unlock()
	if len(errs) == 0 || errs[0] == nil {
		t.Fatalf("the report should carry the firewall error, got %v", errs)
	}
	if got := st.Bans(); len(got) != 1 || got[0].Applied {
		t.Errorf("a refused ban must not be marked applied: %+v", got)
	}
}

// The first successful login is the person installing the agent, and their
// address must be protected or the detector can lock them out.
func TestPipelineAllowlistsTheFirstLogin(t *testing.T) {
	dir, auditLog := newAuditLog(t)
	_, notifier, st, _ := startPipeline(t, Options{
		AuditLog:                auditLog,
		StateDir:                filepath.Join(dir, "state"),
		ReadFromStart:           true,
		AutoAllowlistFirstLogin: true,
	})

	appendLines(t, auditLog, okLine(1, "203.0.113.9", "ruslan")...)
	notifier.waitFor(t, model.KindSSHLoginOK)

	deadline := time.After(5 * time.Second)
	for !st.IsAllowed("203.0.113.9") {
		select {
		case <-deadline:
			t.Fatal("the first login was not allowlisted")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if msgs := notifier.allMessages(); len(msgs) == 0 || msgs[0] != "ui.allow.auto" {
		t.Errorf("the owner should be told: %v", msgs)
	}

	// Only the first one: a later login from somewhere else is not the owner.
	appendLines(t, auditLog, okLine(2, "198.51.100.200", "root")...)
	time.Sleep(300 * time.Millisecond)
	if st.IsAllowed("198.51.100.200") {
		t.Error("only the first login should be allowlisted")
	}
}

// With the allowlist in place, the same burst that would ban a stranger must
// leave the owner alone.
func TestPipelineNeverBansAnAllowlistedAddress(t *testing.T) {
	dir, auditLog := newAuditLog(t)
	st, err := store.Open(store.Options{Dir: filepath.Join(dir, "state")})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Allow("203.0.113.9", "owner"); err != nil {
		t.Fatal(err)
	}

	banner := &fakeBanner{}
	_, notifier, _, _ := startPipeline(t, Options{
		AuditLog:      auditLog,
		StateDir:      filepath.Join(dir, "state"),
		ReadFromStart: true,
		Store:         st,
		Banner:        banner,
		Detector: detect.NewBruteForce(detect.Options{
			Window: time.Minute, FailThreshold: 2, Allowed: st.IsAllowed,
		}),
	})

	for i := 1; i <= 6; i++ {
		appendLines(t, auditLog, failLine(i, "203.0.113.9")...)
	}
	notifier.waitFor(t, model.KindSSHLoginFail)
	time.Sleep(300 * time.Millisecond)

	if bans := notifier.allBans(); len(bans) != 0 {
		t.Errorf("an allowlisted address was banned: %+v", bans)
	}
	if got := banner.allBanned(); len(got) != 0 {
		t.Errorf("the firewall was asked to block the owner: %+v", got)
	}
}

// A success right after a burst of failures is the compromise signal, and it
// has to reach the chat as a critical event.
func TestPipelineReportsLoginAfterBruteForce(t *testing.T) {
	dir, auditLog := newAuditLog(t)
	_, notifier, _, _ := startPipeline(t, Options{
		AuditLog:      auditLog,
		StateDir:      filepath.Join(dir, "state"),
		ReadFromStart: true,
		Detector: detect.NewBruteForce(detect.Options{
			Window: 10 * time.Minute, FailThreshold: 100, // no ban in the way
			SuccessAfterFailures: 3, Host: "web01",
		}),
	})

	for i := 1; i <= 3; i++ {
		appendLines(t, auditLog, failLine(i, "198.51.100.7")...)
	}
	appendLines(t, auditLog, okLine(9, "198.51.100.7", "root")...)

	ev := notifier.waitFor(t, model.KindLoginAfterBruteForce)
	if ev.Severity != model.SevCritical || ev.SrcIP != "198.51.100.7" {
		t.Errorf("event = %+v", ev)
	}
	if ev.Arg("fails") != "3" {
		t.Errorf("the count of failures should be reported: %q", ev.Arg("fails"))
	}
}

// The firewall is rebuilt from scratch at startup, so the store's active bans
// have to be pushed back into it or a restart would quietly unblock everyone.
func TestPipelineReappliesBansOnStart(t *testing.T) {
	dir, auditLog := newAuditLog(t)
	st, err := store.Open(store.Options{Dir: filepath.Join(dir, "state")})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.RecordBan("198.51.100.7", "earlier burst", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.RecordBan("198.51.100.8", "long gone", time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.RecordBan("203.0.113.9", "then forgiven", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := st.Allow("203.0.113.9", "that was me"); err != nil {
		t.Fatal(err)
	}

	banner := &fakeBanner{}
	startPipeline(t, Options{
		AuditLog: auditLog,
		StateDir: filepath.Join(dir, "state"),
		Store:    st,
		Banner:   banner,
	})

	deadline := time.After(5 * time.Second)
	for len(banner.allBanned()) == 0 {
		select {
		case <-deadline:
			t.Fatal("the active ban was not reapplied")
		case <-time.After(10 * time.Millisecond):
		}
	}
	got := banner.allBanned()
	if len(got) != 1 || got[0].IP != "198.51.100.7" {
		t.Errorf("reapplied %+v; expired and allowlisted bans must be skipped", got)
	}
}

// Without a backend the decision is still recorded and reported — that is the
// default setup, and it must not look like a failure.
func TestPipelineWithoutABackendStillRecords(t *testing.T) {
	dir, auditLog := newAuditLog(t)
	_, notifier, st, _ := startPipeline(t, Options{
		AuditLog:      auditLog,
		StateDir:      filepath.Join(dir, "state"),
		ReadFromStart: true,
		Detector: detect.NewBruteForce(detect.Options{
			Window: time.Minute, FailThreshold: 2,
		}),
	})

	for i := 1; i <= 2; i++ {
		appendLines(t, auditLog, failLine(i, "198.51.100.9")...)
	}
	notifier.waitForBan(t, "198.51.100.9")
	if got := st.Bans(); len(got) != 1 || got[0].Applied {
		t.Errorf("with no backend the ban is recorded but not applied: %+v", got)
	}
}

// Reading an audit log that was written before the agent started must not ban
// anybody: those bursts are history. Without this, a first start with
// read_from_start would flood the chat and block addresses over attacks that
// ended days ago.
func TestPipelineSkipsBansFromOldLogLines(t *testing.T) {
	dir, auditLog := newAuditLog(t)
	banner := &fakeBanner{}
	_, notifier, st, _ := startPipeline(t, Options{
		AuditLog:      auditLog,
		StateDir:      filepath.Join(dir, "state"),
		ReadFromStart: true,
		Banner:        banner,
		Detector: detect.NewBruteForce(detect.Options{
			Window: 10 * time.Minute, FailThreshold: 3,
		}),
	})

	for i := 1; i <= 3; i++ {
		appendLines(t, auditLog, staleFailLine(i, "198.51.100.77")...)
	}
	// The events themselves are still reported — only the ban is pointless.
	notifier.waitFor(t, model.KindSSHLoginFail)
	time.Sleep(300 * time.Millisecond)

	if bans := notifier.allBans(); len(bans) != 0 {
		t.Errorf("a stale burst should not produce a ban: %+v", bans)
	}
	if got := banner.allBanned(); len(got) != 0 {
		t.Errorf("the firewall should not be touched: %+v", got)
	}
	if got := st.Bans(); len(got) != 0 {
		t.Errorf("nothing should be recorded: %+v", got)
	}
}

// A permanent decision has no window, so it is applied whatever the age of the
// line that produced it.
func TestPipelineAppliesPermanentBansRegardless(t *testing.T) {
	dir, auditLog := newAuditLog(t)
	st, err := store.Open(store.Options{Dir: filepath.Join(dir, "state")})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	// Three earlier bans put the address at the end of the ladder.
	for i := 0; i < 3; i++ {
		if _, err := st.RecordBan("198.51.100.78", "earlier", time.Now().Add(-time.Hour)); err != nil {
			t.Fatal(err)
		}
	}

	banner := &fakeBanner{}
	_, notifier, _, _ := startPipeline(t, Options{
		AuditLog:      auditLog,
		StateDir:      filepath.Join(dir, "state"),
		ReadFromStart: true,
		Store:         st,
		Banner:        banner,
		Detector: detect.NewBruteForce(detect.Options{
			Window: 10 * time.Minute, FailThreshold: 2,
			BanCount: func(ip string) int { return banCountOf(st, ip) },
		}),
	})

	for i := 1; i <= 2; i++ {
		appendLines(t, auditLog, failLine(i, "198.51.100.78")...)
	}
	ban := notifier.waitForBan(t, "198.51.100.78")
	if !ban.Permanent() {
		t.Errorf("a fourth offence should be permanent: %+v", ban)
	}
}

func banCountOf(st *store.Store, ip string) int {
	for _, b := range st.Bans() {
		if b.IP == ip {
			return b.Count
		}
	}
	return 0
}

// The certificate the panel serves is watched: one that does not verify is
// reported once per cooldown and shown in the diagnostics; with only the
// expiry watched (staging, a private CA) the same certificate is fine.
func TestPanelCertificateIsWatched(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	for _, trust := range []bool{true, false} {
		dir := t.TempDir()
		log := filepath.Join(dir, "audit.log")
		appendLines(t, log)
		p, notifier, _, _ := startPipeline(t, Options{
			AuditLog: log, StateDir: filepath.Join(dir, "state"),
			PanelURL: srv.URL, PanelCertEvery: 20 * time.Millisecond, PanelCertTrust: trust,
		})
		deadline := time.Now().Add(5 * time.Second)
		for p.PanelCertStatus() == "not checked yet" && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		time.Sleep(200 * time.Millisecond)
		alerts := 0
		for _, e := range notifier.all() {
			if e.Kind == model.KindPanelCert {
				alerts++
			}
		}
		status := p.PanelCertStatus()
		if trust && (alerts != 1 || !strings.HasPrefix(status, "PROBLEM: does not verify")) {
			t.Errorf("trust checked: %d alerts, status %q; want 1 and a problem", alerts, status)
		}
		if !trust && (alerts != 0 || !strings.HasPrefix(status, "ok, valid until")) {
			t.Errorf("expiry only: %d alerts, status %q; want none and ok", alerts, status)
		}
	}
}

// A silent log that then disappears is a different, worse state and is reported
// at once, not after the cooldown of the first alert.
func TestPipelineHeartbeatReportsAStateChangeImmediately(t *testing.T) {
	dir := t.TempDir()
	auditLog := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(auditLog, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(auditLog, old, old); err != nil {
		t.Fatal(err)
	}
	_, notifier, _, _ := startPipeline(t, Options{
		AuditLog:         auditLog,
		StateDir:         filepath.Join(dir, "state"),
		HeartbeatEnabled: true,
		HeartbeatEvery:   20 * time.Millisecond,
		HeartbeatStale:   time.Hour,
	})
	if ev := notifier.waitFor(t, model.KindAuditdStopped); ev.Arg("state") != "audit_silent" {
		t.Fatalf("first state: %+v", ev)
	}
	if err := os.Remove(auditLog); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, e := range notifier.all() {
			if e.Arg("state") == "audit_unavailable" {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("the change from silent to unavailable was not reported")
}
