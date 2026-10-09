package pipeline

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/RsNest/auditdsec/internal/model"
	"github.com/RsNest/auditdsec/internal/store"
)

type fakeNotifier struct {
	mu     sync.Mutex
	events []model.Event
}

func (f *fakeNotifier) Notify(_ context.Context, ev model.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, ev)
	return nil
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
	st, err := store.Open(store.Options{Dir: filepath.Join(t.TempDir(), "state")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	notifier := &fakeNotifier{}
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
