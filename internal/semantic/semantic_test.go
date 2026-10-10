package semantic

import (
	"strings"
	"testing"
	"time"

	"github.com/RsNest/auditdsec/internal/auditlog"
	"github.com/RsNest/auditdsec/internal/i18n"
	"github.com/RsNest/auditdsec/internal/model"
	"github.com/RsNest/auditdsec/internal/parse"
)

func build(t *testing.T, lines ...string) *parse.Event {
	t.Helper()
	a := parse.NewAssembler(time.Second)
	now := time.Unix(1760000000, 0)
	var evs []*parse.Event
	for _, l := range lines {
		done, err := a.Add(l, now)
		if err != nil && !strings.Contains(err.Error(), "no record") {
			t.Fatalf("Add(%q): %v", l, err)
		}
		evs = append(evs, done...)
	}
	evs = append(evs, a.Flush()...)
	if len(evs) != 1 {
		t.Fatalf("want 1 assembled event, got %d", len(evs))
	}
	return evs[0]
}

func TestMap(t *testing.T) {
	tests := []struct {
		name     string
		lines    []string
		wantOK   bool
		wantKind model.Kind
		wantSev  model.Severity
		wantUser string
		wantIP   string
		wantArgs map[string]string
	}{
		{
			name:     "root login is critical",
			lines:    []string{`type=USER_LOGIN msg=audit(1760000000.000:1): pid=1 uid=0 auid=0 msg='op=login acct="root" exe="/usr/sbin/sshd" addr=203.0.113.9 terminal=ssh res=success'`},
			wantOK:   true,
			wantKind: model.KindSSHLoginOK,
			wantSev:  model.SevCritical,
			wantUser: "root",
			wantIP:   "203.0.113.9",
		},
		{
			name:     "ordinary login is info",
			lines:    []string{`type=USER_LOGIN msg=audit(1760000000.000:2): pid=1 uid=0 auid=1000 msg='op=login acct="ruslan" exe="/usr/sbin/sshd" addr=203.0.113.9 terminal=ssh res=success'`},
			wantOK:   true,
			wantKind: model.KindSSHLoginOK,
			wantSev:  model.SevInfo,
			wantUser: "ruslan",
			wantIP:   "203.0.113.9",
		},
		{
			name:     "failed login",
			lines:    []string{`type=USER_LOGIN msg=audit(1760000000.000:3): pid=1 uid=0 auid=4294967295 msg='op=login acct="root" exe="/usr/sbin/sshd" addr=198.51.100.7 terminal=ssh res=failed'`},
			wantOK:   true,
			wantKind: model.KindSSHLoginFail,
			wantSev:  model.SevWarn,
			wantUser: "root",
			wantIP:   "198.51.100.7",
		},
		{
			name:     "failed auth",
			lines:    []string{`type=USER_AUTH msg=audit(1760000000.000:4): pid=1 uid=0 msg='op=PAM:authentication acct="admin" exe="/usr/sbin/sshd" hostname=? addr=198.51.100.8 terminal=ssh res=failed'`},
			wantOK:   true,
			wantKind: model.KindSSHLoginFail,
			wantSev:  model.SevWarn,
			wantUser: "admin",
			wantIP:   "198.51.100.8",
		},
		{
			name:   "successful auth is left to USER_LOGIN",
			lines:  []string{`type=USER_AUTH msg=audit(1760000000.000:5): pid=1 uid=0 msg='op=PAM:authentication acct="root" addr=203.0.113.9 res=success'`},
			wantOK: false,
		},
		{
			name:     "sudo command with a masked password",
			lines:    []string{`type=USER_CMD msg=audit(1760000000.000:6): pid=2000 uid=1000 auid=1000 msg='cwd="/home/ruslan" cmd=6D7973716C202D7068756E74657232 terminal=pts/0 res=success'`},
			wantOK:   true,
			wantKind: model.KindSudo,
			wantSev:  model.SevInfo,
			wantUser: "uid=1000",
			wantArgs: map[string]string{"cmd": "mysql -p***", "cwd": "/home/ruslan"},
		},
		{
			name:     "new user",
			lines:    []string{`type=ADD_USER msg=audit(1760000000.000:7): pid=3000 uid=0 auid=0 msg='op=add-user id=1001 exe="/usr/sbin/useradd" res=success'`},
			wantOK:   true,
			wantKind: model.KindUserChange,
			wantSev:  model.SevCritical,
			wantUser: "uid=0",
			wantArgs: map[string]string{"detail": "add-user id=1001 (/usr/sbin/useradd)"},
		},
		{
			name:     "user added to sudo group",
			lines:    []string{`type=USER_MGMT msg=audit(1760000000.000:8): pid=3100 uid=0 auid=0 msg='op=add-user-to-group grp="sudo" acct="backdoor" exe="/usr/sbin/usermod" res=success'`},
			wantOK:   true,
			wantKind: model.KindUserChange,
			wantSev:  model.SevCritical,
			wantUser: "backdoor",
			wantArgs: map[string]string{"detail": "add-user-to-group backdoor group=sudo (/usr/sbin/usermod)"},
		},
		{
			name: "watched identity file",
			lines: []string{
				`type=SYSCALL msg=audit(1760000000.000:9): syscall=257 success=yes auid=1000 uid=0 comm="vim" exe="/usr/bin/vim" key="ads_identity"`,
				`type=PATH msg=audit(1760000000.000:9): item=0 name="/etc/passwd"`,
			},
			wantOK:   true,
			wantKind: model.KindUserChange,
			wantSev:  model.SevCritical,
			wantUser: "uid=1000",
			wantArgs: map[string]string{"path": "/etc/passwd", "exe": "/usr/bin/vim"},
		},
		{
			name: "authorized_keys change",
			lines: []string{
				`type=SYSCALL msg=audit(1760000000.000:10): syscall=257 success=yes auid=0 uid=0 comm="tee" exe="/usr/bin/tee" key="ads_sshkeys"`,
				`type=PATH msg=audit(1760000000.000:10): item=0 name="/root/.ssh/authorized_keys"`,
			},
			wantOK:   true,
			wantKind: model.KindAuthorizedKeysChange,
			wantSev:  model.SevCritical,
			wantUser: "uid=0",
			wantArgs: map[string]string{"path": "/root/.ssh/authorized_keys"},
		},
		{
			name: "cron persistence",
			lines: []string{
				`type=SYSCALL msg=audit(1760000000.000:11): syscall=257 success=yes auid=0 uid=0 comm="sh" key="ads_persist"`,
				`type=PATH msg=audit(1760000000.000:11): item=0 name="/etc/cron.d/backdoor"`,
			},
			wantOK:   true,
			wantKind: model.KindPersistence,
			wantSev:  model.SevWarn,
			wantArgs: map[string]string{"path": "/etc/cron.d/backdoor"},
		},
		{
			name: "sshd config change",
			lines: []string{
				`type=SYSCALL msg=audit(1760000000.000:12): syscall=257 success=yes auid=0 uid=0 key="ads_sshd"`,
				`type=PATH msg=audit(1760000000.000:12): item=0 name="/etc/ssh/sshd_config"`,
			},
			wantOK:   true,
			wantKind: model.KindConfigChange,
			wantSev:  model.SevWarn,
		},
		{
			name: "log tampering",
			lines: []string{
				`type=SYSCALL msg=audit(1760000000.000:13): syscall=87 success=yes auid=0 uid=0 comm="rm" key="ads_logs"`,
				`type=PATH msg=audit(1760000000.000:13): item=0 name="/var/log/auth.log"`,
			},
			wantOK:   true,
			wantKind: model.KindLogTamper,
			wantSev:  model.SevCritical,
		},
		{
			name: "execution from tmp",
			lines: []string{
				`type=SYSCALL msg=audit(1760000000.000:14): syscall=59 success=yes auid=1000 uid=1000 comm="xmrig" key="ads_exec_tmp"`,
				`type=PATH msg=audit(1760000000.000:14): item=0 name="/tmp/xmrig"`,
			},
			wantOK:   true,
			wantKind: model.KindSuspiciousExec,
			wantSev:  model.SevWarn,
			wantArgs: map[string]string{"path": "/tmp/xmrig"},
		},
		{
			name: "failed access to a watched file is noise",
			lines: []string{
				`type=SYSCALL msg=audit(1760000000.000:15): syscall=257 success=no exit=-13 auid=1000 uid=1000 key="ads_identity"`,
				`type=PATH msg=audit(1760000000.000:15): item=0 name="/etc/shadow"`,
			},
			wantOK: false,
		},
		{
			name:     "audit disabled",
			lines:    []string{`type=CONFIG_CHANGE msg=audit(1760000000.000:16): auid=0 ses=7 op=set audit_enabled=0 old=1 res=1`},
			wantOK:   true,
			wantKind: model.KindLogTamper,
			wantSev:  model.SevCritical,
			wantArgs: map[string]string{"detail": "audit_enabled=0"},
		},
		{
			name:     "auditd stopped",
			lines:    []string{`type=DAEMON_END msg=audit(1760000000.000:17): op=terminate auid=0 pid=1 res=success`},
			wantOK:   true,
			wantKind: model.KindAuditdStopped,
			wantSev:  model.SevCritical,
			wantArgs: map[string]string{"detail": "terminate"},
		},
		{
			name:   "session bookkeeping is ignored",
			lines:  []string{`type=CRED_ACQ msg=audit(1760000000.000:18): pid=1 uid=0 msg='op=PAM:setcred acct="root" res=success'`},
			wantOK: false,
		},
		{
			name:   "unknown audit key is ignored",
			lines:  []string{`type=SYSCALL msg=audit(1760000000.000:19): syscall=257 success=yes auid=0 key="somebody_elses_rule"`},
			wantOK: false,
		},
		{
			name: "the most severe matching rule wins",
			lines: []string{
				"type=SYSCALL msg=audit(1760000000.000:20): syscall=257 success=yes auid=0 uid=0 key=\"ads_sshd\x01ads_sshkeys\"",
				`type=PATH msg=audit(1760000000.000:20): item=0 name="/root/.ssh/authorized_keys"`,
			},
			wantOK:   true,
			wantKind: model.KindAuthorizedKeysChange,
			wantSev:  model.SevCritical,
		},
	}

	m := New("web01")
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := m.Map(build(t, tc.lines...))
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (event: %+v)", ok, tc.wantOK, got)
			}
			if !ok {
				return
			}
			if got.Kind != tc.wantKind {
				t.Errorf("Kind = %q, want %q", got.Kind, tc.wantKind)
			}
			if got.Severity != tc.wantSev {
				t.Errorf("Severity = %v, want %v", got.Severity, tc.wantSev)
			}
			if tc.wantUser != "" && got.User != tc.wantUser {
				t.Errorf("User = %q, want %q", got.User, tc.wantUser)
			}
			if tc.wantIP != "" && got.SrcIP != tc.wantIP {
				t.Errorf("SrcIP = %q, want %q", got.SrcIP, tc.wantIP)
			}
			for k, want := range tc.wantArgs {
				if got.Args[k] != want {
					t.Errorf("Args[%q] = %q, want %q", k, got.Args[k], want)
				}
			}
			if got.Host != "web01" {
				t.Errorf("Host = %q", got.Host)
			}
			if !model.ValidKind(got.Kind) {
				t.Errorf("Kind %q is not registered in model.AllKinds", got.Kind)
			}
			// Every produced event must render completely in both languages:
			// a leftover {placeholder} means the mapper forgot an argument.
			for _, lang := range i18n.Langs() {
				s := i18n.T(lang, got.SummaryKey, got.Args)
				if strings.Contains(s, "{") {
					t.Errorf("lang %s: unrendered placeholder in %q", lang, s)
				}
				if s == got.SummaryKey {
					t.Errorf("lang %s: no template for %q", lang, got.SummaryKey)
				}
			}
		})
	}
}

// Debug mode has to explain why an event was dropped, so every dropped event
// must come back with a reason a person can act on.
func TestMapVerboseExplainsEveryDrop(t *testing.T) {
	tests := []struct {
		name  string
		lines []string
		want  string
	}{
		{
			name:  "session bookkeeping",
			lines: []string{`type=CRED_ACQ msg=audit(1760000000.000:1): pid=1 uid=0 msg='op=PAM:setcred acct="root" res=success'`},
			want:  "no rule for record types [CRED_ACQ]",
		},
		{
			name:  "successful auth",
			lines: []string{`type=USER_AUTH msg=audit(1760000000.000:2): pid=1 msg='acct="root" addr=203.0.113.9 res=success'`},
			want:  "USER_LOGIN",
		},
		{
			name:  "somebody else's audit rule",
			lines: []string{`type=SYSCALL msg=audit(1760000000.000:3): syscall=257 success=yes auid=0 key="their_own_rule"`},
			want:  `no rule for audit key "their_own_rule"`,
		},
		{
			name: "failed access",
			lines: []string{
				`type=SYSCALL msg=audit(1760000000.000:4): syscall=257 success=no exit=-13 auid=1000 key="ads_identity"`,
				`type=PATH msg=audit(1760000000.000:4): item=0 name="/etc/shadow"`,
			},
			want: "exit=-13",
		},
	}
	m := New("web01")
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, reason, ok := m.MapVerbose(build(t, tc.lines...))
			if ok {
				t.Fatal("the event should have been dropped")
			}
			if !strings.Contains(reason, tc.want) {
				t.Errorf("reason = %q, want it to mention %q", reason, tc.want)
			}
		})
	}
}

// An unknown audit key is almost always a rules file that disagrees with the
// build, so the reason must list what the build does know.
func TestMapVerboseListsKnownKeys(t *testing.T) {
	_, reason, _ := New("h").MapVerbose(build(t,
		`type=SYSCALL msg=audit(1760000000.000:1): syscall=257 success=yes auid=0 key="typo_in_rules"`))
	for _, k := range []string{KeyIdentity, KeySSHKeys, KeyLogs} {
		if !strings.Contains(reason, k) {
			t.Errorf("reason should list %q: %q", k, reason)
		}
	}
}

func TestMapVerboseGivesNoReasonOnSuccess(t *testing.T) {
	_, reason, ok := New("h").MapVerbose(build(t,
		`type=USER_LOGIN msg=audit(1760000000.000:1): auid=0 msg='acct="root" addr=203.0.113.9 res=success'`))
	if !ok || reason != "" {
		t.Errorf("ok = %v, reason = %q", ok, reason)
	}
}

// The stored evidence must not contain the hex form of a command that carried a
// secret, because hex is trivially reversible.
func TestMapRedactsRawSudoCommand(t *testing.T) {
	ev := build(t, `type=USER_CMD msg=audit(1760000000.000:1): pid=2000 uid=1000 auid=1000 msg='cwd="/home/ruslan" cmd=6D7973716C202D7068756E74657232 terminal=pts/0 res=success'`)
	got, ok := New("h").Map(ev)
	if !ok {
		t.Fatal("event was dropped")
	}
	if strings.Contains(got.Raw, "6D7973716C202D7068756E74657232") {
		t.Error("raw evidence still contains the hex encoded command")
	}
	if !strings.Contains(got.Raw, "mysql -p***") {
		t.Errorf("raw evidence should carry the masked command, got %q", got.Raw)
	}
}

func TestIPIsOnlyKeptWhenItIsAnAddress(t *testing.T) {
	// auditd writes hostname=? addr=? for local logins.
	ev := build(t, `type=USER_LOGIN msg=audit(1760000000.000:1): pid=1 uid=0 auid=0 msg='op=login acct="root" hostname=? addr=? terminal=tty1 res=success'`)
	got, _ := New("h").Map(ev)
	if got.SrcIP != "" {
		t.Errorf("SrcIP = %q, want empty for a local login", got.SrcIP)
	}

	ev = build(t, `type=USER_LOGIN msg=audit(1760000000.000:2): pid=1 uid=0 auid=0 msg='op=login acct="root" hostname=mail.example.com addr=? terminal=ssh res=success'`)
	got, _ = New("h").Map(ev)
	if got.SrcIP != "" {
		t.Errorf("SrcIP = %q, want empty when only a host name is known", got.SrcIP)
	}
}

func TestDedupKeyGroupsRepeats(t *testing.T) {
	m := New("h")
	a, _ := m.Map(build(t, `type=USER_LOGIN msg=audit(1760000000.000:1): msg='acct="root" addr=198.51.100.7 res=failed'`))
	b, _ := m.Map(build(t, `type=USER_LOGIN msg=audit(1760000001.000:2): msg='acct="root" addr=198.51.100.7 res=failed'`))
	c, _ := m.Map(build(t, `type=USER_LOGIN msg=audit(1760000002.000:3): msg='acct="root" addr=203.0.113.9 res=failed'`))
	if a.DedupKey() != b.DedupKey() {
		t.Error("the same failure from the same address must share a dedup key")
	}
	if a.DedupKey() == c.DedupKey() {
		t.Error("a different address must not be grouped")
	}
}

func TestAuditHealthStates(t *testing.T) {
	ev := AuditHealth("web01", auditlog.Unavailable, "audit.log not readable")
	if ev.Kind != model.KindAuditdStopped || ev.Severity != model.SevCritical {
		t.Fatalf("got %+v", ev)
	}
	for _, lang := range i18n.Langs() {
		if s := i18n.T(lang, ev.SummaryKey, ev.Args); strings.Contains(s, "{") {
			t.Errorf("lang %s: unrendered placeholder in %q", lang, s)
		}
	}
}

// A silent log is a warning with its own wording, not the claim that the
// service is down.
func TestAuditSilentIsAWarningWithItsOwnText(t *testing.T) {
	ev := AuditHealth("web01", auditlog.Silent, "no new records for 7h0m")
	if ev.Severity != model.SevWarn || ev.SummaryKey != "event.audit_silent" || ev.Args["state"] != "audit_silent" {
		t.Fatalf("got %+v", ev)
	}
	for _, lang := range i18n.Langs() {
		s := i18n.T(lang, ev.SummaryKey, ev.Args)
		if strings.Contains(s, "{") || !strings.Contains(s, "7h0m") {
			t.Errorf("lang %s: %q", lang, s)
		}
	}
	if un := AuditHealth("web01", auditlog.Unavailable, "x"); un.Severity != model.SevCritical || un.Args["state"] != "audit_unavailable" {
		t.Errorf("unavailable: %+v", un)
	}
}
