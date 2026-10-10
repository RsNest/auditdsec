package session_test

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RsNest/auditdsec/internal/detect"
	"github.com/RsNest/auditdsec/internal/model"
	"github.com/RsNest/auditdsec/internal/parse"
	"github.com/RsNest/auditdsec/internal/semantic"
	"github.com/RsNest/auditdsec/internal/session"
)

var t0 = time.Unix(1760000000, 0)

// feed assembles audit lines into events, the way the pipeline does.
func feed(t *testing.T, lines ...string) []*parse.Event {
	t.Helper()
	a := parse.NewAssembler(time.Second)
	var out []*parse.Event
	for _, l := range lines {
		done, err := a.Add(l, t0)
		if err != nil && !strings.Contains(err.Error(), "no record") {
			t.Fatalf("%q: %v", l, err)
		}
		out = append(out, done...)
	}
	return append(out, a.Flush()...)
}

type rig struct {
	t  *testing.T
	tr *session.Tracker
	m  *semantic.Mapper
	n  int
}

func newRig(t *testing.T) *rig {
	return &rig{t: t, tr: session.New(session.Options{Now: func() time.Time { return t0.Add(time.Hour) }}, "boot-1"), m: semantic.New("web01")}
}

func (r *rig) serial() int { r.n++; return 100 + r.n }

func ts(sec int) string { return fmt.Sprintf("%d.000", t0.Unix()+int64(sec)) }

// login feeds the records of a successful sshd login.
func (r *rig) login(at int, user string, uid, ses int, pid int, addr string) {
	s := r.serial()
	r.observe(
		fmt.Sprintf(`type=LOGIN msg=audit(%s:%d): pid=%d uid=0 old-auid=4294967295 auid=%d tty=(none) old-ses=4294967295 ses=%d res=1`, ts(at), s, pid, uid, ses),
	)
	s = r.serial()
	r.observe(fmt.Sprintf(`type=USER_START msg=audit(%s:%d): pid=%d uid=0 auid=%d ses=%d msg='op=PAM:session_open acct="%s" exe="/usr/sbin/sshd" hostname=%s addr=%s terminal=ssh res=success'`,
		ts(at), s, pid, uid, ses, user, addr, addr))
}

func (r *rig) logout(at int, user string, uid, ses, pid int) {
	r.observe(fmt.Sprintf(`type=USER_END msg=audit(%s:%d): pid=%d uid=0 auid=%d ses=%d msg='op=PAM:session_close acct="%s" exe="/usr/sbin/sshd" hostname=? addr=? terminal=ssh res=success'`,
		ts(at), r.serial(), pid, uid, ses, user))
}

func (r *rig) observe(lines ...string) {
	for _, ev := range feed(r.t, lines...) {
		r.tr.Observe(ev)
	}
}

// sudo maps a USER_CMD through the mapper and the tracker.
func (r *rig) sudo(at int, uid, ses int, target, cmd string) model.Event {
	r.t.Helper()
	acct := ""
	if target != "" {
		acct = fmt.Sprintf(`acct="%s" `, target)
	}
	line := fmt.Sprintf(`type=USER_CMD msg=audit(%s:%d): pid=3001 uid=%d auid=%d ses=%d msg='cwd="/home/u" cmd="%s" %sexe="/usr/bin/sudo" terminal=pts/0 res=success'`,
		ts(at), r.serial(), uid, uid, ses, cmd, acct)
	evs := feed(r.t, line)
	if len(evs) != 1 {
		r.t.Fatalf("want 1 event, got %d", len(evs))
	}
	r.tr.Observe(evs[0])
	ev, why, ok := r.m.MapVerbose(evs[0])
	if !ok {
		r.t.Fatalf("dropped: %s", why)
	}
	if ev.Context == nil {
		r.t.Fatalf("no context on %+v", ev)
	}
	r.tr.Attribute(ev.Context, evs[0].Time)
	return ev
}

// Two concurrent SSH logins of different users; each sudo is tied to its own
// session and address, and the original identity stays separate from root.
func TestConcurrentSessionsAndSudoAttribution(t *testing.T) {
	r := newRig(t)
	r.login(0, "alice", 1000, 5, 2001, "203.0.113.9")
	r.login(5, "bob", 1001, 6, 2002, "198.51.100.4")

	a := r.sudo(60, 1000, 5, "root", "systemctl restart nginx").Context
	if a.LoginUID != "1000" || a.LoginUser != "alice" || a.EffectiveUser != "root" || a.EffectiveUID != "0" {
		t.Errorf("identities: %+v", a)
	}
	if s := a.Session; s == nil || s.Addr != "203.0.113.9" || s.Confidence != model.ConfObserved || s.Source != "audit" || s.Ended {
		t.Errorf("alice's session: %+v", a.Session)
	}
	b := r.sudo(61, 1001, 6, "root", "id").Context
	if b.LoginUser != "bob" || b.Session == nil || b.Session.Addr != "198.51.100.4" {
		t.Errorf("bob's session: %+v / %+v", b, b.Session)
	}
	if a.Command == "" || a.SessionID != "5" || a.PID != "3001" {
		t.Errorf("process context: %+v", a)
	}
}

// Missing evidence is stated, never filled in from the user name or timing.
func TestUnknownIsExplicit(t *testing.T) {
	r := newRig(t)
	r.login(0, "alice", 1000, 5, 2001, "203.0.113.9")

	// The same user, but a session ID the agent never saw: no address, even
	// though alice has a session with an address.
	c := r.sudo(10, 1000, 9, "root", "id").Context
	if c.Session == nil || c.Session.Confidence != model.ConfUnknown || c.Session.Addr != "" || c.Session.Note == "" {
		t.Errorf("an unseen session must be unknown: %+v", c.Session)
	}
	// An action with no session at all (a daemon) has no session reference.
	ev := r.sudo(11, 1000, 4294967295, "root", "id")
	if ev.Context.Session != nil || ev.Context.SessionID != "" {
		t.Errorf("unset session: %+v", ev.Context)
	}
}

// Session ID reuse: a new login with the same ID must not inherit the old
// address, and a stale action must not be attached to the new login.
func TestIdentifierReuse(t *testing.T) {
	r := newRig(t)
	r.login(0, "alice", 1000, 5, 2001, "203.0.113.9")
	r.logout(100, "alice", 1000, 5, 2001)
	r.login(500, "carol", 1002, 5, 2400, "192.0.2.77") // same ID, later, another user

	got := r.sudo(520, 1002, 5, "root", "id").Context.Session
	if got == nil || got.Addr != "192.0.2.77" || got.Confidence != model.ConfObserved {
		t.Errorf("the new login: %+v", got)
	}
	// An action by alice's uid carrying the reused ID is not carol's session.
	old := r.sudo(530, 1000, 5, "root", "id").Context.Session
	if old == nil || old.Confidence != model.ConfUnknown || old.Addr != "" {
		t.Errorf("a different login uid must not match: %+v", old)
	}
}

// A process that outlives its login is still attributed, and marked.
func TestActionAfterLogoutIsMarkedEnded(t *testing.T) {
	r := newRig(t)
	r.login(0, "alice", 1000, 5, 2001, "203.0.113.9")
	r.logout(100, "alice", 1000, 5, 2001)
	s := r.sudo(400, 1000, 5, "root", "id").Context.Session
	if s == nil || !s.Ended || s.Addr != "203.0.113.9" {
		t.Errorf("%+v", s)
	}
	before := r.sudo(50, 1000, 5, "root", "id").Context.Session
	if before == nil || before.Ended {
		t.Errorf("an action during the session is not 'ended': %+v", before)
	}
}

// An action stamped before the recorded session started cannot belong to it.
func TestActionBeforeSessionStartIsUnknown(t *testing.T) {
	r := newRig(t)
	r.login(300, "alice", 1000, 5, 2001, "203.0.113.9")
	s := r.sudo(10, 1000, 5, "root", "id").Context.Session
	if s == nil || s.Confidence != model.ConfUnknown {
		t.Errorf("%+v", s)
	}
}

// A console login is a session, but not an SSH one.
func TestNonSSHSessionIsNotShownAsSSH(t *testing.T) {
	r := newRig(t)
	r.observe(fmt.Sprintf(`type=USER_START msg=audit(%s:%d): pid=900 uid=0 auid=1000 ses=7 msg='op=PAM:session_open acct="alice" exe="/usr/bin/login" hostname=? addr=? terminal=tty1 res=success'`, ts(0), r.serial()))
	s := r.sudo(10, 1000, 7, "root", "id").Context.Session
	if s == nil || s.Confidence != model.ConfUnknown || s.Addr != "" || !strings.Contains(s.Note, "not shown as an SSH login") {
		t.Errorf("%+v", s)
	}
}

// An sshd session whose audit records carry no address stays unknown unless a
// journal line joins it uniquely.
func TestJournalJoinIsConservative(t *testing.T) {
	r := newRig(t)
	r.observe(fmt.Sprintf(`type=USER_START msg=audit(%s:%d): pid=2001 uid=0 auid=1000 ses=5 msg='op=PAM:session_open acct="alice" exe="/usr/sbin/sshd" hostname=? addr=? terminal=ssh res=success'`, ts(0), r.serial()))
	at := func() *model.SessionRef { return r.sudo(30, 1000, 5, "root", "id").Context.Session }

	if s := at(); s.Confidence != model.ConfUnknown || s.Addr != "" {
		t.Fatalf("without journal evidence: %+v", s)
	}
	// Wrong user, wrong PID, too far in time: none of them may attribute.
	r.tr.AddAccepted([]session.Accepted{
		{Time: t0, PID: "2001", User: "bob", Addr: "198.51.100.4", Port: "1"},
		{Time: t0, PID: "2002", User: "alice", Addr: "198.51.100.5", Port: "2"},
		{Time: t0.Add(time.Hour), PID: "2001", User: "alice", Addr: "198.51.100.6", Port: "3"},
	})
	if s := at(); s.Confidence != model.ConfUnknown || s.Addr != "" {
		t.Fatalf("near misses must not attribute: %+v", s)
	}
	r.tr.AddAccepted([]session.Accepted{{Time: t0.Add(time.Second), PID: "2001", User: "alice", Addr: "203.0.113.9", Port: "51234"}})
	s := at()
	if s.Confidence != model.ConfCorrelated || s.Source != "journald" || s.Addr != "203.0.113.9" || s.Port != "51234" {
		t.Fatalf("unique join: %+v", s)
	}
	// A second, different candidate makes it ambiguous again.
	r.tr.AddAccepted([]session.Accepted{{Time: t0.Add(2 * time.Second), PID: "2001", User: "alice", Addr: "192.0.2.50", Port: "4"}})
	if s := at(); s.Confidence != model.ConfUnknown || !strings.Contains(s.Note, "ambiguous") {
		t.Fatalf("ambiguous: %+v", s)
	}
}

// The table survives a restart, is dropped across a reboot, and replaying the
// same records changes nothing.
func TestRestartRebootAndReplay(t *testing.T) {
	r := newRig(t)
	r.login(0, "alice", 1000, 5, 2001, "203.0.113.9")
	path := filepath.Join(t.TempDir(), "sessions.json")
	if err := r.tr.Save(path); err != nil {
		t.Fatal(err)
	}

	again := session.New(session.Options{Now: func() time.Time { return t0.Add(time.Hour) }}, "boot-1")
	if discarded, err := again.Load(path); err != nil || discarded {
		t.Fatalf("load: %v %v", discarded, err)
	}
	c := &model.Context{LoginUID: "1000", SessionID: "5"}
	again.Attribute(c, t0.Add(60*time.Second))
	if c.Session == nil || c.Session.Addr != "203.0.113.9" || c.LoginUser != "alice" {
		t.Fatalf("after restart: %+v %+v", c, c.Session)
	}
	// Replay of the login records (held cursor) is idempotent.
	rr := &rig{t: t, tr: again, m: r.m, n: 50}
	rr.login(0, "alice", 1000, 5, 2001, "203.0.113.9")
	if s, _, _ := again.Len(); s != 1 {
		t.Errorf("replay duplicated the session: %d", s)
	}

	// Another boot: the IDs mean nothing.
	rebooted := session.New(session.Options{}, "boot-2")
	if discarded, err := rebooted.Load(path); err != nil || !discarded {
		t.Fatalf("reboot must discard: %v %v", discarded, err)
	}
	c = &model.Context{LoginUID: "1000", SessionID: "5"}
	rebooted.Attribute(c, t0)
	if c.Session.Confidence != model.ConfUnknown {
		t.Errorf("a pre-reboot session was applied after the reboot: %+v", c.Session)
	}
	// A SYSTEM_BOOT record does the same without a boot ID.
	r.observe(fmt.Sprintf(`type=SYSTEM_BOOT msg=audit(%s:%d): pid=1 uid=0 auid=4294967295 ses=4294967295 msg=' comm="systemd-update-utmp" exe="/usr/lib/systemd/systemd-update-utmp" res=success'`, ts(900), r.serial()))
	if s, n, _ := r.tr.Len(); s != 0 || n != 0 {
		t.Errorf("SYSTEM_BOOT did not clear the table: %d %d", s, n)
	}
}

// The tables stay inside their limits whatever the log contains.
func TestTablesAreBounded(t *testing.T) {
	tr := session.New(session.Options{MaxSessions: 5, MaxJournal: 4, MaxNames: 3, Now: func() time.Time { return t0 }}, "b")
	r := &rig{t: t, tr: tr, m: semantic.New("h")}
	for i := 1; i <= 40; i++ {
		r.login(i, fmt.Sprintf("user%d", i), 2000+i, 100+i, 3000+i, "203.0.113.9")
	}
	if s, n, _ := tr.Len(); s > 5 || n > 3 {
		t.Errorf("sessions=%d names=%d exceed the limits", s, n)
	}
	var list []session.Accepted
	for i := 0; i < 50; i++ {
		list = append(list, session.Accepted{Time: t0.Add(time.Duration(i) * time.Second), PID: fmt.Sprint(100 + i), User: "u", Addr: "198.51.100.1", Port: "1"})
	}
	tr.AddAccepted(list)
	if _, _, j := tr.Len(); j > 4 {
		t.Errorf("journal lines=%d exceed the limit", j)
	}
	// Expired lines are dropped.
	old := session.New(session.Options{JournalTTL: time.Minute, Now: func() time.Time { return t0.Add(time.Hour) }}, "b")
	old.AddAccepted([]session.Accepted{{Time: t0, PID: "1", User: "u", Addr: "198.51.100.1"}})
	if _, _, j := old.Len(); j != 0 {
		t.Errorf("an expired line was kept")
	}
}

// The command is sanitized, and nothing here reaches detection: the session
// address never becomes SrcIP, so no amount of sudo activity can ban anyone.
func TestContextIsSanitizedAndIsNotDetectionInput(t *testing.T) {
	r := newRig(t)
	r.login(0, "alice", 1000, 5, 2001, "203.0.113.9")
	ev := r.sudo(20, 1000, 5, "root", "mysql -u root -pHUNTER2secret")
	if strings.Contains(ev.Context.Command, "HUNTER2secret") {
		t.Errorf("secret in the context command: %q", ev.Context.Command)
	}
	if ev.SrcIP != "" {
		t.Errorf("the session address leaked into SrcIP: %q", ev.SrcIP)
	}

	bf := detect.NewBruteForce(detect.Options{})
	for i := 0; i < 20; i++ {
		e := r.sudo(30+i, 1000, 5, "root", "id")
		if res := bf.Feed(e); !res.Empty() {
			t.Fatalf("process activity produced a detection result: %+v", res)
		}
	}
}
