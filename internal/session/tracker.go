// Package session explains which login session an audited action belongs to.
//
// The evidence comes in two strengths. The audit log itself is explicit: sshd's
// PAM records (USER_START, LOGIN, USER_LOGIN) carry the kernel session ID
// (ses=), the login UID and, usually, the remote address, and every later
// record of a process in that session carries the same ses= and auid=. That
// join is exact and is reported as "observed". When the audit records of a
// session do not carry the address, an optional, read-only journal reader can
// supply it from sshd's "Accepted ... from <ip> port <n>" line; that is joined
// by sshd's PID, the user and a narrow time window, only when it is unique, and
// is reported as "correlated". Anything else is "unknown", with a reason.
//
// Nothing here is used to detect or ban: the result is context for a person.
package session

import (
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/RsNest/auditdsec/internal/model"
	"github.com/RsNest/auditdsec/internal/netaddr"
	"github.com/RsNest/auditdsec/internal/parse"
)

const unsetID = "4294967295"

// Options bound the tracker. Zero values take the defaults.
type Options struct {
	// MaxSessions caps the table; the least recently used entry is evicted.
	MaxSessions int
	// EndedGrace is how long a closed session stays attributable, for
	// processes that outlive their login.
	EndedGrace time.Duration
	// MaxIdle drops a session nothing has referred to for this long.
	MaxIdle time.Duration
	// MaxNames caps the uid → name table.
	MaxNames int
	// JoinWindow is how far apart sshd's journal line and the audit session
	// start may be to be joined.
	JoinWindow time.Duration
	// MaxJournal caps the remembered journal lines.
	MaxJournal int
	// JournalTTL expires remembered journal lines.
	JournalTTL time.Duration
	// Skew tolerates clock/ordering jitter between records of one login.
	Skew time.Duration
	Now  func() time.Time
}

func (o *Options) defaults() {
	if o.MaxSessions <= 0 {
		o.MaxSessions = 2048
	}
	if o.EndedGrace <= 0 {
		o.EndedGrace = 24 * time.Hour
	}
	if o.MaxIdle <= 0 {
		o.MaxIdle = 30 * 24 * time.Hour
	}
	if o.MaxNames <= 0 {
		o.MaxNames = 1024
	}
	if o.JoinWindow <= 0 {
		o.JoinWindow = 30 * time.Second
	}
	if o.MaxJournal <= 0 {
		o.MaxJournal = 1024
	}
	if o.JournalTTL <= 0 {
		o.JournalTTL = 48 * time.Hour
	}
	if o.Skew <= 0 {
		o.Skew = 2 * time.Second
	}
	if o.Now == nil {
		o.Now = time.Now
	}
}

// entry is what is known of one audit session ID.
type entry struct {
	Ses      string    `json:"ses"`
	LoginUID string    `json:"login_uid"`
	User     string    `json:"user,omitempty"`
	SSH      bool      `json:"ssh"`
	SSHPid   string    `json:"sshd_pid,omitempty"`
	Addr     string    `json:"addr,omitempty"`
	Port     string    `json:"port,omitempty"`
	Started  time.Time `json:"started"`
	Ended    bool      `json:"ended,omitempty"`
	EndedAt  time.Time `json:"ended_at,omitempty"`
	LastUsed time.Time `json:"last_used"`
}

// accepted is one sshd "Accepted" line read from the journal.
type accepted struct {
	Time time.Time
	PID  string
	User string
	Addr string
	Port string
}

// Tracker is the bounded session table. It is safe for concurrent use; every
// method is in-memory and never blocks on I/O.
type Tracker struct {
	opt Options

	mu       sync.Mutex
	bootID   string
	sessions map[string]*entry
	names    map[string]string
	journal  []accepted
	dirty    bool
}

// New returns an empty tracker for the given boot.
func New(o Options, bootID string) *Tracker {
	o.defaults()
	return &Tracker{opt: o, bootID: bootID, sessions: map[string]*entry{}, names: map[string]string{}}
}

// BootID is the boot the table belongs to.
func (t *Tracker) BootID() string { t.mu.Lock(); defer t.mu.Unlock(); return t.bootID }

// Len reports the table sizes, for tests and diagnostics.
func (t *Tracker) Len() (sessions, names, journal int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.sessions), len(t.names), len(t.journal)
}

// Reset forgets every session: audit session IDs restart at a reboot, so an ID
// from before it must never be applied to a process after it.
func (t *Tracker) Reset(bootID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.bootID = bootID
	t.sessions = map[string]*entry{}
	t.names = map[string]string{}
	t.journal = nil
	t.dirty = true
}

func validID(s string) bool {
	if s == "" || s == unsetID || s == "-1" || s == "?" || s == "unset" || len(s) > 10 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func baseExe(exe string) string {
	exe = strings.Trim(exe, `"`)
	if exe == "" || exe == "?" || exe == "(null)" {
		return ""
	}
	return path.Base(exe)
}

func isSSHD(exe string) bool { return strings.HasPrefix(baseExe(exe), "sshd") }

func validAddr(s string) string {
	a, err := netaddr.Parse(s)
	if err != nil || a.IsUnspecified() {
		return ""
	}
	return a.String()
}

func cleanName(s string) string {
	s = strings.Trim(s, `"`)
	if s == "" || s == "?" || s == "(null)" || len(s) > 64 {
		return ""
	}
	for _, r := range s {
		if r < 33 || r == 127 {
			return ""
		}
	}
	return s
}

// Observe learns from one assembled audit event. It is called for every event,
// including those the agent never reports, and is idempotent: reading the same
// records again after a restart changes nothing.
func (t *Tracker) Observe(ev *parse.Event) {
	if ev.HasAny("SYSTEM_BOOT") {
		t.Reset(t.BootID())
		return
	}
	for _, r := range ev.Records {
		switch r.Type {
		case "USER_START", "LOGIN", "USER_LOGIN", "CRED_ACQ":
			t.observeStart(ev, r)
		case "USER_END", "USER_LOGOUT":
			t.observeEnd(ev, r)
		}
	}
}

func (t *Tracker) observeStart(ev *parse.Event, r parse.Record) {
	f := r.Fields
	ses := f["ses"]
	if !validID(ses) {
		return
	}
	uid := f["auid"]
	if !validID(uid) {
		return
	}
	if r.Type == "USER_LOGIN" && f["res"] != "success" && f["res"] != "1" {
		return
	}
	if r.Type == "USER_START" && f["res"] != "" && f["res"] != "success" {
		return
	}
	if r.Type == "LOGIN" && f["res"] != "" && f["res"] != "1" {
		return
	}
	// A LOGIN record has no exe; the same login's USER_START does. LOGIN only
	// opens the entry (a PID and a session ID); sshd-ness comes from USER_START.
	ssh := isSSHD(f["exe"])
	at := ev.Time
	addr := validAddr(f["addr"])
	if addr == "" {
		addr = validAddr(f["hostname"])
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.sessions[ses]
	if e != nil && (e.LoginUID != uid ||
		(e.Ended && at.After(e.EndedAt)) ||
		(r.Type != "USER_LOGIN" && e.SSHPid != "" && validID(f["pid"]) && e.SSHPid != f["pid"])) {
		// The same ID with another login, after the previous one closed, or
		// from another sshd process: the ID was reused. The old entry is over.
		e = nil
	}
	if e == nil {
		e = &entry{Ses: ses, LoginUID: uid, Started: at}
		t.sessions[ses] = e
	}
	if at.Before(e.Started) {
		e.Started = at
	}
	if ssh {
		e.SSH = true
		if p := f["pid"]; validID(p) && e.SSHPid == "" {
			e.SSHPid = p
		}
		if e.Addr == "" && addr != "" {
			e.Addr = addr
			if p := f["port"]; validID(p) {
				e.Port = p
			}
		}
		if n := cleanName(f["acct"]); n != "" && r.Type != "USER_LOGIN" {
			e.User = n
			t.learnName(uid, n)
		}
	} else if e.SSHPid == "" {
		if p := f["pid"]; validID(p) {
			e.SSHPid = p
		}
	}
	e.LastUsed = t.opt.Now()
	t.dirty = true
	t.evict()
}

func (t *Tracker) observeEnd(ev *parse.Event, r parse.Record) {
	ses := r.Fields["ses"]
	if !validID(ses) || !isSSHD(r.Fields["exe"]) {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.sessions[ses]
	if e == nil || e.Ended || r.Fields["auid"] != e.LoginUID || ev.Time.Before(e.Started) {
		return
	}
	e.Ended, e.EndedAt = true, ev.Time
	t.dirty = true
}

func (t *Tracker) learnName(uid, name string) {
	if t.names[uid] == name {
		return
	}
	if len(t.names) >= t.opt.MaxNames {
		for k := range t.names { // arbitrary victim: the table is a convenience
			delete(t.names, k)
			break
		}
	}
	t.names[uid] = name
}

// evict keeps the table inside its limits: expired entries first, then the
// least recently used. The caller holds the lock.
func (t *Tracker) evict() {
	now := t.opt.Now()
	for k, e := range t.sessions {
		if (e.Ended && now.Sub(e.EndedAt) > t.opt.EndedGrace) || now.Sub(e.LastUsed) > t.opt.MaxIdle {
			delete(t.sessions, k)
		}
	}
	for len(t.sessions) > t.opt.MaxSessions {
		var oldest string
		var at time.Time
		for k, e := range t.sessions {
			if oldest == "" || e.LastUsed.Before(at) {
				oldest, at = k, e.LastUsed
			}
		}
		delete(t.sessions, oldest)
	}
}

// Name returns the account name learned for a uid, "root" for 0, else "".
func (t *Tracker) Name(uid string) string {
	if uid == "0" {
		return "root"
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.names[uid]
}

// Attribute fills the session part of a context built from explicit audit
// fields and resolves account names. It never overwrites explicit evidence
// and never invents: a session it cannot place is marked unknown with a reason.
func (t *Tracker) Attribute(c *model.Context, at time.Time) {
	if c == nil {
		return
	}
	if c.LoginUID != "" && c.LoginUser == "" {
		c.LoginUser = t.Name(c.LoginUID)
	}
	if c.EffectiveUID != "" && c.EffectiveUser == "" {
		c.EffectiveUser = t.Name(c.EffectiveUID)
	}
	if c.SessionID == "" {
		return
	}
	c.Session = t.lookup(c.SessionID, c.LoginUID, at)
}

func unknown(note string) *model.SessionRef {
	return &model.SessionRef{Confidence: model.ConfUnknown, Note: note}
}

func (t *Tracker) lookup(ses, loginUID string, at time.Time) *model.SessionRef {
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.sessions[ses]
	switch {
	case e == nil:
		return unknown("session not seen by the agent (it began before the agent or before the audit log it read)")
	case loginUID != "" && e.LoginUID != loginUID:
		return unknown("the session ID belongs to a different login user (identifier reuse)")
	case !at.IsZero() && at.Add(t.opt.Skew).Before(e.Started):
		return unknown("the action predates the recorded session with this ID (identifier reuse)")
	case !e.SSH:
		return unknown("no sshd record for this session: not shown as an SSH login")
	}
	e.LastUsed = t.opt.Now()
	ended := e.Ended && !at.IsZero() && at.After(e.EndedAt.Add(t.opt.Skew))
	if e.Addr != "" {
		return &model.SessionRef{Addr: e.Addr, Port: e.Port, Source: "audit", Confidence: model.ConfObserved, Ended: ended}
	}
	return t.joinJournal(e, ended)
}

// joinJournal places a session whose audit records carry no address using
// sshd's journal line. The join needs the same sshd PID, the same user and a
// start within the window, and it must be unique.
func (t *Tracker) joinJournal(e *entry, ended bool) *model.SessionRef {
	if e.SSHPid == "" || e.User == "" {
		return unknown("sshd session without a recorded address and without enough identity to look it up")
	}
	var hits []accepted
	for _, a := range t.journal {
		if a.PID != e.SSHPid || a.User != e.User {
			continue
		}
		d := a.Time.Sub(e.Started)
		if d < 0 {
			d = -d
		}
		if d <= t.opt.JoinWindow {
			hits = append(hits, a)
		}
	}
	if len(hits) == 0 {
		return unknown("sshd session without a recorded address")
	}
	first := hits[0]
	for _, h := range hits[1:] {
		if h.Addr != first.Addr || h.Port != first.Port {
			return unknown("ambiguous: several journal entries fit this session")
		}
	}
	return &model.SessionRef{Addr: first.Addr, Port: first.Port, Source: "journald", Confidence: model.ConfCorrelated, Ended: ended}
}

// AddAccepted remembers sshd "Accepted" lines from the journal, bounded in
// number and age. Duplicates (the same line read twice) are ignored.
func (t *Tracker) AddAccepted(list []Accepted) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.opt.Now()
	for _, a := range list {
		addr := validAddr(a.Addr)
		if addr == "" || !validID(a.PID) || cleanName(a.User) == "" {
			continue
		}
		rec := accepted{Time: a.Time, PID: a.PID, User: a.User, Addr: addr, Port: a.Port}
		dup := false
		for _, old := range t.journal {
			if old == rec {
				dup = true
				break
			}
		}
		if !dup {
			t.journal = append(t.journal, rec)
		}
	}
	keep := t.journal[:0]
	for _, a := range t.journal {
		if now.Sub(a.Time) <= t.opt.JournalTTL {
			keep = append(keep, a)
		}
	}
	t.journal = keep
	if len(t.journal) > t.opt.MaxJournal {
		sort.Slice(t.journal, func(i, j int) bool { return t.journal[i].Time.Before(t.journal[j].Time) })
		t.journal = append([]accepted(nil), t.journal[len(t.journal)-t.opt.MaxJournal:]...)
	}
}

// Accepted is one parsed sshd login line, as handed over by a journal reader.
type Accepted struct {
	Time time.Time
	PID  string
	User string
	Addr string
	Port string
}
