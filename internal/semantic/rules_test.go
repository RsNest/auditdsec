package semantic

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RsNest/auditdsec/internal/auditlog"
)

func shippedRules(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "deploy", "auditdsec.rules"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The rules the project ships and the keys the mapper acts on must agree in
// both directions: a key in the rules that the mapper does not know is dropped
// as noise, and a key the mapper expects but the rules lack is a silent hole.
func TestShippedRulesMatchTheKeysTheMapperActsOn(t *testing.T) {
	text := shippedRules(t)
	have := map[string]bool{}
	for _, k := range auditlog.KeysIn(text) {
		have[k] = true
		if _, ok := keyRules[k]; !ok {
			t.Errorf("deploy/auditdsec.rules uses key %q that the mapper ignores", k)
		}
	}
	for _, k := range RequiredKeys() {
		if !have[k] {
			t.Errorf("deploy/auditdsec.rules has no rule with key %q", k)
		}
	}
}

// Log tampering is more than writes to a few files: deleting, renaming and
// truncating anything under /var/log must be watched, without touching
// /var/log/audit with a write watch (auditd would record its own writes).
func TestShippedRulesWatchDestructiveLogOperations(t *testing.T) {
	text := shippedRules(t)
	for _, call := range []string{"unlink", "unlinkat", "rename", "renameat", "renameat2", "truncate"} {
		found := false
		for _, line := range strings.Split(text, "\n") {
			l := strings.TrimSpace(line)
			if strings.HasPrefix(l, "-a ") && strings.Contains(l, "dir=/var/log ") &&
				strings.Contains(l, "-k ads_logs") && containsSyscall(l, call) {
				found = true
			}
		}
		if !found {
			t.Errorf("no ads_logs rule covers %s under /var/log", call)
		}
	}
	for _, line := range strings.Split(text, "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "-w /var/log/audit") {
			t.Errorf("a write watch on the audit log directory feeds itself: %q", l)
		}
		if strings.HasPrefix(l, "-a ") && strings.Contains(l, "dir=/var/log ") && !strings.Contains(l, "auid>=1000") {
			t.Errorf("a /var/log syscall rule must exclude daemons (auditd rotation): %q", l)
		}
	}
}

func containsSyscall(rule, name string) bool {
	f := strings.Fields(rule)
	for i, w := range f {
		if w == "-S" && i+1 < len(f) {
			for _, s := range strings.Split(f[i+1], ",") {
				if s == name {
					return true
				}
			}
		}
	}
	return false
}

// A destructive call on a log shows up as the tamper kind, critical, with the
// path, and a failed attempt is not reported.
func TestLogDeletionIsReportedAsTampering(t *testing.T) {
	ok := build(t,
		`type=SYSCALL msg=audit(1760000000.000:20): arch=c000003e syscall=263 success=yes exit=0 auid=1000 uid=0 exe="/usr/bin/rm" key="ads_logs"`,
		`type=CWD msg=audit(1760000000.000:20): cwd="/var/log"`,
		`type=PATH msg=audit(1760000000.000:20): item=0 name="/var/log/" nametype=PARENT`,
		`type=PATH msg=audit(1760000000.000:20): item=1 name="/var/log/auth.log" nametype=DELETE`,
	)
	out, why, mapped := New("h").MapVerbose(ok)
	if !mapped {
		t.Fatalf("dropped: %s", why)
	}
	if out.Kind != "log_tamper" || out.Severity != 2 || out.Args["path"] != "/var/log/auth.log" {
		t.Errorf("got %s/%v path=%q", out.Kind, out.Severity, out.Args["path"])
	}

	failed := build(t,
		`type=SYSCALL msg=audit(1760000001.000:21): arch=c000003e syscall=263 success=no exit=-13 auid=1000 uid=1000 exe="/usr/bin/rm" key="ads_logs"`,
		`type=PATH msg=audit(1760000001.000:21): item=0 name="/var/log/auth.log" nametype=NORMAL`,
	)
	if _, _, mapped := New("h").MapVerbose(failed); mapped {
		t.Error("a refused deletion changed nothing and must not be reported")
	}
}
