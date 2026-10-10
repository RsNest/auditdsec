package pipeline

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RsNest/auditdsec/internal/model"
	"github.com/RsNest/auditdsec/internal/source"
	"github.com/RsNest/auditdsec/internal/store"
)

func TestHeldCursorReplaysInterleavedEventsWithoutDuplicateSideEffects(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(store.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	n := &fakeNotifier{}
	o := Options{AuditLog: filepath.Join(dir, "audit.log"), StateDir: dir, Store: st, Notifier: n, Host: "recovery"}
	p, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	base := source.Cursor{Version: 2, Path: o.AuditLog, FileID: "test-file", Generation: strings.Repeat("a", 32)}
	if err := p.feedSource(context.Background(), source.Line{Boundary: true, Start: base, End: base}); err != nil {
		t.Fatal(err)
	}
	position := base
	feed := func(p *Pipeline, text string) {
		t.Helper()
		start := position
		position.Offset += int64(len(text) + 1)
		if err := p.feedSource(context.Background(), source.Line{Text: text, Start: start, End: position}); err != nil {
			t.Fatal(err)
		}
	}
	open := `type=SYSCALL msg=audit(1760000000.000:1): syscall=257 success=yes auid=0 uid=0 comm="tee" exe="/usr/bin/tee" key="ads_sshkeys"`
	closed := `type=USER_LOGIN msg=audit(1760000001.000:2): pid=1 uid=0 auid=0 msg='op=login acct="root" addr=198.51.100.7 terminal=ssh res=failed'`
	feed(p, open)
	feed(p, closed)
	if p.tailer.LastOffset() != 0 || len(n.all()) != 1 {
		t.Fatal("cursor crossed an open event or closed event was lost")
	}
	p2, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	if err := p2.feedSource(context.Background(), source.Line{Boundary: true, Start: base, End: base}); err != nil {
		t.Fatal(err)
	}
	position = base
	feed(p2, open)
	feed(p2, closed)
	if len(n.all()) != 1 {
		t.Fatal("replay repeated a completed event")
	}
	feed(p2, `type=PATH msg=audit(1760000000.000:1): item=0 name="/root/.ssh/authorized_keys"`)
	feed(p2, `type=EOE msg=audit(1760000000.000:1):`)
	if p2.tailer.LastOffset() != position.Offset || len(n.all()) != 2 {
		t.Fatal("cursor did not release after durable completion")
	}
	evs := st.Recent(0)
	if len(evs) != 2 || evs[0].ID == "" || evs[1].ID == "" || evs[1].Incomplete != "" {
		t.Fatal("recovery lost stable IDs or persisted a fragment", evs)
	}
}

func TestStoreFailureDoesNotAcknowledgeInput(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(store.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	p, err := New(Options{AuditLog: filepath.Join(dir, "audit.log"), StateDir: dir, Store: st, Notifier: &fakeNotifier{}})
	if err != nil {
		t.Fatal(err)
	}
	c := source.Cursor{Version: 2, Path: p.opt.AuditLog, FileID: "test", Generation: strings.Repeat("b", 32)}
	if err := p.feedSource(context.Background(), source.Line{Boundary: true, Start: c, End: c}); err != nil {
		t.Fatal(err)
	}
	// A regular file where the day-file directory belongs forces a real write error.
	if err := os.Remove(filepath.Join(dir, "events")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "events"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	text := `type=USER_LOGIN msg=audit(1760000001.000:2): pid=1 uid=0 auid=0 msg='op=login acct="root" addr=198.51.100.7 terminal=ssh res=failed'`
	end := c
	end.Offset = int64(len(text) + 1)
	if err := p.feedSource(context.Background(), source.Line{Text: text, Start: c, End: end}); err == nil {
		t.Fatal("failed storage was acknowledged")
	}
	if p.tailer.LastOffset() != 0 || len(st.Recent(0)) != 0 {
		t.Fatal("failed event changed cursor or recent storage")
	}
}

func TestShutdownLeavesOpenEventRecoverable(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "audit.log")
	text := `type=SYSCALL msg=audit(1760000000.000:1): syscall=257 success=yes auid=0 uid=0 comm="tee" exe="/usr/bin/tee" key="ads_sshkeys"` + "\n"
	if err := os.WriteFile(log, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(store.Options{Dir: filepath.Join(dir, "state")})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	n := &fakeNotifier{}
	o := Options{AuditLog: log, StateDir: filepath.Join(dir, "state"), Store: st, Notifier: n, ReadFromStart: true}
	p, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()
	deadline := time.Now().Add(time.Second)
	for p.tailer.LastOffset() == 0 && time.Now().Before(deadline) {
		if _, err := os.Stat(filepath.Join(o.StateDir, "tail.json")); err == nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("pipeline did not stop")
	}
	if len(st.Recent(0)) != 0 || p.tailer.LastOffset() != 0 {
		t.Fatal("shutdown committed an incomplete audit event")
	}
	appendLines(t, log, `type=PATH msg=audit(1760000000.000:1): item=0 name="/root/.ssh/authorized_keys"`, `type=EOE msg=audit(1760000000.000:1):`)
	p2, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	done2 := make(chan error, 1)
	go func() { done2 <- p2.Run(ctx2) }()
	ev := n.waitFor(t, model.KindAuthorizedKeysChange)
	if ev.Incomplete != "" {
		t.Fatal("restart returned a shutdown fragment", ev)
	}
	cancel2()
	select {
	case err := <-done2:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("restarted pipeline did not stop")
	}
}
