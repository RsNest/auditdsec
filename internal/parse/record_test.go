package parse

import (
	"errors"
	"testing"
	"time"
)

func TestParseLine(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		wantTyp string
		wantSer int64
		wantSec int64
		want    map[string]string
	}{
		{
			name:    "USER_LOGIN success with nested msg",
			line:    `type=USER_LOGIN msg=audit(1760000000.123:456): pid=1234 uid=0 auid=0 ses=3 msg='op=login id=0 exe="/usr/sbin/sshd" hostname=203.0.113.9 addr=203.0.113.9 terminal=ssh res=success'`,
			wantTyp: "USER_LOGIN",
			wantSer: 456,
			wantSec: 1760000000,
			want: map[string]string{
				"pid": "1234", "uid": "0", "auid": "0", "ses": "3",
				"op": "login", "id": "0", "exe": "/usr/sbin/sshd",
				"addr": "203.0.113.9", "hostname": "203.0.113.9",
				"terminal": "ssh", "res": "success",
			},
		},
		{
			name:    "USER_AUTH failed",
			line:    `type=USER_AUTH msg=audit(1760000001.000:450): pid=1230 uid=0 auid=4294967295 ses=4294967295 msg='op=PAM:authentication grantors=? acct="root" exe="/usr/sbin/sshd" hostname=? addr=198.51.100.7 terminal=ssh res=failed'`,
			wantTyp: "USER_AUTH",
			wantSer: 450,
			wantSec: 1760000001,
			want: map[string]string{
				"acct": "root", "addr": "198.51.100.7", "res": "failed",
				"op": "PAM:authentication", "hostname": "?",
			},
		},
		{
			name:    "USER_CMD with hex encoded command",
			line:    `type=USER_CMD msg=audit(1760000100.200:600): pid=2000 uid=1000 auid=1000 ses=5 msg='cwd="/home/ruslan" cmd=6D7973716C202D7068756E74657232 terminal=pts/0 res=success'`,
			wantTyp: "USER_CMD",
			wantSer: 600,
			wantSec: 1760000100,
			want: map[string]string{
				"cwd": "/home/ruslan", "cmd": "mysql -phunter2",
				"terminal": "pts/0", "res": "success", "auid": "1000",
			},
		},
		{
			name:    "ADD_USER",
			line:    `type=ADD_USER msg=audit(1760000200.300:700): pid=3000 uid=0 auid=0 ses=6 msg='op=add-user id=1001 exe="/usr/sbin/useradd" hostname=? addr=? terminal=pts/0 res=success'`,
			wantTyp: "ADD_USER",
			wantSer: 700,
			wantSec: 1760000200,
			want:    map[string]string{"op": "add-user", "id": "1001", "exe": "/usr/sbin/useradd", "res": "success"},
		},
		{
			name:    "USER_MGMT with quoted acct",
			line:    `type=USER_MGMT msg=audit(1760000210.000:701): pid=3100 uid=0 auid=0 ses=6 msg='op=add-user-to-group grp="sudo" acct="backdoor" exe="/usr/sbin/usermod" res=success'`,
			wantTyp: "USER_MGMT",
			wantSer: 701,
			wantSec: 1760000210,
			want:    map[string]string{"op": "add-user-to-group", "grp": "sudo", "acct": "backdoor", "res": "success"},
		},
		{
			name:    "SYSCALL with audit key",
			line:    `type=SYSCALL msg=audit(1760000300.400:800): arch=c000003e syscall=257 success=yes exit=3 items=1 ppid=1 pid=4000 auid=1000 uid=0 comm="vim" exe="/usr/bin/vim" key="ads_identity"`,
			wantTyp: "SYSCALL",
			wantSer: 800,
			wantSec: 1760000300,
			want: map[string]string{
				"syscall": "257", "success": "yes", "comm": "vim",
				"exe": "/usr/bin/vim", "key": "ads_identity", "auid": "1000",
			},
		},
		{
			name:    "PATH record",
			line:    `type=PATH msg=audit(1760000300.400:800): item=0 name="/etc/passwd" inode=131 dev=fd:01 mode=0100644 ouid=0 ogid=0`,
			wantTyp: "PATH",
			wantSer: 800,
			wantSec: 1760000300,
			want:    map[string]string{"item": "0", "name": "/etc/passwd", "mode": "0100644"},
		},
		{
			name:    "CONFIG_CHANGE disabling audit",
			line:    `type=CONFIG_CHANGE msg=audit(1760000400.500:900): auid=0 ses=7 op=set audit_enabled=0 old=1 res=1`,
			wantTyp: "CONFIG_CHANGE",
			wantSer: 900,
			wantSec: 1760000400,
			want:    map[string]string{"op": "set", "audit_enabled": "0", "old": "1", "res": "1"},
		},
		{
			name:    "DAEMON_END",
			line:    `type=DAEMON_END msg=audit(1760000500.600:901): op=terminate auid=0 pid=1 res=success`,
			wantTyp: "DAEMON_END",
			wantSer: 901,
			wantSec: 1760000500,
			want:    map[string]string{"op": "terminate", "res": "success"},
		},
		{
			name:    "node prefix is kept",
			line:    `node=web01 type=USER_LOGIN msg=audit(1760000600.000:902): pid=1 uid=0 msg='res=success'`,
			wantTyp: "USER_LOGIN",
			wantSer: 902,
			wantSec: 1760000600,
			want:    map[string]string{"node": "web01", "res": "success"},
		},
		{
			name:    "proctitle with NUL separators",
			line:    `type=PROCTITLE msg=audit(1760000700.000:903): proctitle=2F62696E2F736800002D63`,
			wantTyp: "PROCTITLE",
			wantSer: 903,
			wantSec: 1760000700,
			want:    map[string]string{"proctitle": "/bin/sh  -c"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec, err := ParseLine(tc.line)
			if err != nil {
				t.Fatalf("ParseLine: %v", err)
			}
			if rec.Type != tc.wantTyp {
				t.Errorf("Type = %q, want %q", rec.Type, tc.wantTyp)
			}
			if rec.Serial != tc.wantSer {
				t.Errorf("Serial = %d, want %d", rec.Serial, tc.wantSer)
			}
			if rec.Time.Unix() != tc.wantSec {
				t.Errorf("Time = %v (unix %d), want unix %d", rec.Time, rec.Time.Unix(), tc.wantSec)
			}
			for k, want := range tc.want {
				if got := rec.Field(k); got != want {
					t.Errorf("field %q = %q, want %q", k, got, want)
				}
			}
		})
	}
}

func TestParseLineMillis(t *testing.T) {
	rec, err := ParseLine(`type=X msg=audit(1760000000.123:1): a=b`)
	if err != nil {
		t.Fatal(err)
	}
	if got := rec.Time.UTC().Nanosecond() / int(time.Millisecond); got != 123 {
		t.Errorf("millis = %d, want 123", got)
	}
}

func TestParseLineSkips(t *testing.T) {
	for _, line := range []string{"", "   ", "# comment", "garbage without marker"} {
		_, err := ParseLine(line)
		if !errors.Is(err, ErrSkip) {
			t.Errorf("ParseLine(%q) error = %v, want ErrSkip", line, err)
		}
	}
}

func TestParseLineErrors(t *testing.T) {
	for _, line := range []string{
		`type=X msg=audit(1760000000.123:notanumber): a=b`,
		`type=X msg=audit(abc:1): a=b`,
		`type=X msg=audit(1760000000.123:1 a=b`,
	} {
		if _, err := ParseLine(line); err == nil {
			t.Errorf("ParseLine(%q) = nil error, want failure", line)
		}
	}
}

func TestAuditKeysSplitsMultipleRules(t *testing.T) {
	rec, err := ParseLine("type=SYSCALL msg=audit(1760000000.000:1): key=\"ads_identity\x01ads_sudoers\"")
	if err != nil {
		t.Fatal(err)
	}
	got := rec.AuditKeys()
	if len(got) != 2 || got[0] != "ads_identity" || got[1] != "ads_sudoers" {
		t.Errorf("AuditKeys = %v", got)
	}
}

func TestAuditKeysEmpty(t *testing.T) {
	rec, _ := ParseLine(`type=SYSCALL msg=audit(1760000000.000:1): key=(null)`)
	if got := rec.AuditKeys(); got != nil {
		t.Errorf("AuditKeys = %v, want nil", got)
	}
}

func TestLooksHexEncoded(t *testing.T) {
	yes := []string{"6D7973716C", "2F62696E2F736800002D63"}
	no := []string{"DEAD", "CAFE", "abc", "6d7973716c", "123", "", "ZZZZ"}
	for _, s := range yes {
		if !looksHexEncoded(s) {
			t.Errorf("looksHexEncoded(%q) = false, want true", s)
		}
	}
	for _, s := range no {
		if looksHexEncoded(s) {
			t.Errorf("looksHexEncoded(%q) = true, want false", s)
		}
	}
}

// A quoted value must never be hex-decoded, even if it happens to be hex.
func TestQuotedValueNotHexDecoded(t *testing.T) {
	rec, err := ParseLine(`type=SYSCALL msg=audit(1760000000.000:1): comm="6D7973716C"`)
	if err != nil {
		t.Fatal(err)
	}
	if got := rec.Field("comm"); got != "6D7973716C" {
		t.Errorf("comm = %q, want the literal quoted value", got)
	}
}
