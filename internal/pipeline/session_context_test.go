package pipeline

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/RsNest/auditdsec/internal/detect"
	"github.com/RsNest/auditdsec/internal/model"
	"github.com/RsNest/auditdsec/internal/parse"
	"github.com/RsNest/auditdsec/internal/session"
	"github.com/RsNest/auditdsec/internal/source"
	"github.com/RsNest/auditdsec/internal/store"
)

type sessionProc struct {
	p  *Pipeline
	st *store.Store
	n  *fakeNotifier
}

func bootSession(t *testing.T, dir, auditLog string) *sessionProc {
	t.Helper()
	st, err := store.Open(store.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	n := &fakeNotifier{}
	p, err := New(Options{
		AuditLog: auditLog, StateDir: dir, Store: st, Notifier: n,
		Detector: detect.NewBruteForce(detect.Options{}),
		Sessions: session.New(session.Options{}, "boot-1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	p.current = source.Cursor{Path: auditLog, Generation: "gen-1"}
	return &sessionProc{p: p, st: st, n: n}
}

func (s *sessionProc) crash() { _ = s.p.Close(); _ = s.st.Close() }

func assemble(t *testing.T, lines ...string) []*parse.Event {
	t.Helper()
	a := parse.NewAssembler(time.Second)
	var out []*parse.Event
	for _, l := range lines {
		done, _ := a.Add(l, time.Unix(1760000000, 0))
		out = append(out, done...)
	}
	return append(out, a.Flush()...)
}

const (
	startRec = `type=USER_START msg=audit(1760000000.100:201): pid=2001 uid=0 auid=1000 ses=5 msg='op=PAM:session_open acct="alice" exe="/usr/sbin/sshd" hostname=203.0.113.9 addr=203.0.113.9 terminal=ssh res=success'`
	sudo1    = `type=USER_CMD msg=audit(1760000060.100:210): pid=3001 uid=1000 auid=1000 ses=5 msg='cwd="/home/alice" cmd="systemctl restart nginx" acct="root" exe="/usr/bin/sudo" terminal=pts/0 res=success'`
	sudo2    = `type=USER_CMD msg=audit(1760000090.100:215): pid=3002 uid=1000 auid=1000 ses=5 msg='cwd="/home/alice" cmd="mysql -u root -pHUNTER2secret" acct="root" exe="/usr/bin/sudo" terminal=pts/0 res=success'`
)

func storedSudo(st *store.Store) []model.Event {
	var out []model.Event
	for _, ev := range st.Recent(50) {
		if ev.Kind == model.KindSudo {
			out = append(out, ev)
		}
	}
	return out
}

// End to end through the pipeline: the stored event carries the context, the
// session survives a restart, a replayed record neither duplicates the event
// nor changes it, and no secret or session address leaks into detection input.
func TestSessionContextSurvivesRestartAndReplay(t *testing.T) {
	dir, auditLog := newAuditLog(t)
	a := bootSession(t, dir, auditLog)
	ctx := context.Background()
	if err := a.p.emit(ctx, assemble(t, startRec)); err != nil {
		t.Fatal(err)
	}
	if err := a.p.emit(ctx, assemble(t, sudo1)); err != nil {
		t.Fatal(err)
	}
	a.p.saveSessions() // what acknowledge does before the cursor moves
	got := storedSudo(a.st)
	if len(got) != 1 || got[0].Context == nil {
		t.Fatalf("no stored context: %+v", got)
	}
	c := got[0].Context
	if c.LoginUser != "alice" || c.EffectiveUser != "root" || c.Session == nil ||
		c.Session.Addr != "203.0.113.9" || c.Session.Confidence != model.ConfObserved {
		t.Fatalf("context: %+v session=%+v", c, c.Session)
	}
	if got[0].SrcIP != "" {
		t.Errorf("the session address must stay out of SrcIP: %q", got[0].SrcIP)
	}
	firstID := got[0].ID
	a.crash()

	// Restart: the login records are not read again (the cursor is past them),
	// only the later command is; the session must come from the saved table.
	b := bootSession(t, dir, auditLog)
	defer b.crash()
	if err := b.p.emit(ctx, assemble(t, sudo2)); err != nil {
		t.Fatal(err)
	}
	all := storedSudo(b.st)
	if len(all) == 0 {
		t.Fatal("no events after the restart")
	}
	var second model.Event
	for _, ev := range all {
		if ev.ID != firstID {
			second = ev
		}
	}
	if second.Context == nil || second.Context.Session == nil || second.Context.Session.Addr != "203.0.113.9" {
		t.Fatalf("the session was lost across the restart: %+v", second.Context)
	}
	for _, text := range []string{second.Context.Command, second.Raw} {
		if strings.Contains(text, "HUNTER2secret") {
			t.Errorf("secret stored: %q", text)
		}
	}

	// Replay of the first command after the restart (held cursor): same ID,
	// so nothing new is stored and the stored event is unchanged.
	before := len(storedSudo(b.st))
	if err := b.p.emit(ctx, assemble(t, sudo1)); err != nil {
		t.Fatal(err)
	}
	if after := len(storedSudo(b.st)); after != before {
		t.Errorf("replay added events: %d -> %d", before, after)
	}
	// Nothing about a session ever reached the detector: no bans, no tracked IPs.
	if len(b.st.Bans()) != 0 || b.p.opt.Detector.(*detect.BruteForce).Tracked() != 0 {
		t.Errorf("process activity influenced detection")
	}
}

// An event written before the field existed still decodes.
func TestOldEventsWithoutContextStillDecode(t *testing.T) {
	var ev model.Event
	if err := json.Unmarshal([]byte(`{"time":"2026-01-01T00:00:00Z","host":"h","kind":"sudo","severity":1,"summary_key":"event.sudo"}`), &ev); err != nil {
		t.Fatal(err)
	}
	if ev.Context != nil {
		t.Errorf("%+v", ev.Context)
	}
}
