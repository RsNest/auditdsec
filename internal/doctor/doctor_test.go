package doctor

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RsNest/auditdsec/internal/config"
	"github.com/RsNest/auditdsec/internal/i18n"
	"github.com/RsNest/auditdsec/internal/semantic"
)

type env struct {
	t     *testing.T
	dir   string
	cfg   *config.Config
	rules string
	o     Options
	cmds  []string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Defaults(config.ProfileSimple)
	cfg.AuditLog = filepath.Join(dir, "audit.log")
	cfg.StateDir = filepath.Join(dir, "state")
	cfg.Telegram.Token = "123:abc"
	cfg.Telegram.ChatIDs = []int64{1}
	if err := os.MkdirAll(cfg.StateDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.AuditLog, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rules := filepath.Join(dir, "rules.d")
	if err := os.MkdirAll(rules, 0o750); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, k := range semantic.RequiredKeys() {
		b.WriteString("-w /x -p wa -k " + k + "\n")
	}
	if err := os.WriteFile(filepath.Join(rules, "50.rules"), []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, dir: dir, cfg: cfg, rules: rules}
	e.o = Options{
		Config: cfg, RulesPaths: []string{rules},
		LookPath: func(string) (string, error) { return "/usr/sbin/nft", nil },
		Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			e.cmds = append(e.cmds, name+" "+strings.Join(args, " "))
			return []byte("table inet auditdsec {}"), nil
		},
		Get: func(context.Context, string) (int, error) { return 200, nil },
	}
	return e
}

func (e *env) run() Report { return Run(context.Background(), e.o) }

func find(r Report, area string) []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if strings.Contains(f.Area, area) {
			out = append(out, f)
		}
	}
	return out
}

func levelOf(t *testing.T, r Report, area string) Level {
	t.Helper()
	fs := find(r, area)
	if len(fs) == 0 {
		t.Fatalf("no finding for %q in %+v", area, r.Findings)
	}
	w := OK
	for _, f := range fs {
		if f.Level > w {
			w = f.Level
		}
	}
	return w
}

func TestHealthyHostHasNoWarnings(t *testing.T) {
	e := newEnv(t)
	r := e.run()
	if w := r.Worst(); w > Info {
		t.Fatalf("a healthy setup reported %v: %+v", w, r.Findings)
	}
	if levelOf(t, r, "Audit log") != OK || levelOf(t, r, "Audit rules") != OK {
		t.Errorf("%+v", r.Findings)
	}
}

func TestDoctorChangesNothing(t *testing.T) {
	e := newEnv(t)
	e.cfg.Ban.Backend = config.BanBackendNftables
	list := func() string {
		var names []string
		_ = filepath.Walk(e.dir, func(p string, fi os.FileInfo, _ error) error {
			names = append(names, p+"|"+fi.Mode().String())
			if !fi.IsDir() {
				names[len(names)-1] += "|" + fi.ModTime().String()
			}
			return nil
		})
		return strings.Join(names, "\n")
	}
	before := list()
	e.run()
	if after := list(); after != before {
		t.Errorf("doctor modified files:\n%s\n--- vs ---\n%s", before, after)
	}
	for _, c := range e.cmds {
		if !strings.HasPrefix(c, "nft list ") {
			t.Errorf("a command that is not read-only was run: %q", c)
		}
	}
}

func TestAuditLogProblemsAreExplained(t *testing.T) {
	e := newEnv(t)
	os.Remove(e.cfg.AuditLog)
	f := find(e.run(), "Audit log")[0]
	if f.Level != Fail || !strings.Contains(f.Fix, "systemctl status auditd") {
		t.Errorf("unavailable: %+v", f)
	}

	e = newEnv(t)
	old := time.Now().Add(-48 * time.Hour)
	os.Chtimes(e.cfg.AuditLog, old, old)
	f = find(e.run(), "Audit log")[0]
	if f.Level != Warn || !strings.Contains(f.What, "silent") || !strings.Contains(f.Fix, "auditctl -s") {
		t.Errorf("silent must be a warning that does not claim a failure: %+v", f)
	}
}

func TestMissingRuleKeysAreAFailureWithAFix(t *testing.T) {
	e := newEnv(t)
	os.WriteFile(filepath.Join(e.rules, "50.rules"), []byte("-w /etc/passwd -k ads_identity\n"), 0o600)
	f := find(e.run(), "Audit rules")[0]
	if f.Level != Fail || !strings.Contains(f.What, "ads_logs") || !strings.Contains(f.Fix, "augenrules --load") {
		t.Errorf("%+v", f)
	}
	// Invisible rules (a container) are not a failure.
	e = newEnv(t)
	e.o.RulesPaths = []string{filepath.Join(e.dir, "nowhere")}
	if f := find(e.run(), "Audit rules")[0]; f.Level != Info {
		t.Errorf("%+v", f)
	}
}

func TestFirewallStates(t *testing.T) {
	e := newEnv(t)
	if f := find(e.run(), "Firewall")[0]; f.Level != Info || !strings.Contains(f.What, "nothing is blocked") {
		t.Errorf("backend none: %+v", f)
	}
	e = newEnv(t)
	e.cfg.Ban.Backend = config.BanBackendNftables
	e.o.LookPath = func(string) (string, error) { return "", errors.New("not found") }
	if f := find(e.run(), "Firewall")[0]; f.Level != Fail || !strings.Contains(f.Fix, "nftables") {
		t.Errorf("no nft: %+v", f)
	}
	e = newEnv(t)
	e.cfg.Ban.Backend = config.BanBackendNftables
	e.o.Run = func(context.Context, string, ...string) ([]byte, error) {
		return []byte("Operation not permitted"), errors.New("exit status 1")
	}
	if f := find(e.run(), "Firewall")[0]; f.Level != Warn || !strings.Contains(f.Fix, "NET_ADMIN") {
		t.Errorf("nft refused: %+v", f)
	}
	e = newEnv(t)
	e.cfg.Ban.Backend = config.BanBackendNftables
	e.cfg.Ban.DryRun = true
	if f := find(e.run(), "Firewall")[0]; f.Level != Info || !strings.Contains(f.What, "dry_run") {
		t.Errorf("a dry run must never read as protection: %+v", f)
	}
}

func TestStateAndBanProblems(t *testing.T) {
	e := newEnv(t)
	state := `{"allowlist":{},"bans":{"198.51.100.7":{"ip":"198.51.100.7","count":1,"state":"failed","last_error":"nft: busy"}},` +
		`"releases":{"203.0.113.1":{"ip":"203.0.113.1"}}}`
	os.WriteFile(filepath.Join(e.cfg.StateDir, "state.json"), []byte(state), 0o600)
	r := e.run()
	if levelOf(t, r, "Ban decisions") != Warn {
		t.Fatalf("%+v", r.Findings)
	}
	var sawRelease bool
	for _, f := range find(r, "Ban decisions") {
		if strings.Contains(f.What, "unblock") {
			sawRelease = true
		}
	}
	if !sawRelease {
		t.Error("an unconfirmed unblock was not reported")
	}

	os.WriteFile(filepath.Join(e.cfg.StateDir, "state.json"), []byte("{broken"), 0o600)
	if levelOf(t, e.run(), "Ban decisions") != Fail {
		t.Error("a damaged state file must be a failure")
	}
}

func TestPanelAndQueue(t *testing.T) {
	e := newEnv(t)
	e.cfg.Web.Enabled = true
	e.cfg.Web.Listen = "127.0.0.1:8080"
	e.o.Get = func(context.Context, string) (int, error) { return 0, errors.New("connection refused") }
	if f := find(e.run(), "Web panel")[0]; f.Level != Fail || !strings.Contains(f.Fix, "systemctl status") {
		t.Errorf("%+v", f)
	}

	e = newEnv(t)
	os.MkdirAll(filepath.Join(e.cfg.StateDir, "outbox"), 0o700)
	os.WriteFile(filepath.Join(e.cfg.StateDir, "outbox", "outbox.wal"), []byte("not a wal\n"), 0o600)
	if f := find(e.run(), "Notification queue")[0]; f.Level != Fail || !strings.Contains(f.Fix, "backup") {
		t.Errorf("damaged queue: %+v", f)
	}

	e = newEnv(t)
	e.cfg.Telegram.Token = ""
	if f := find(e.run(), "Notification queue")[0]; f.Level != Info || !strings.Contains(f.What, "not configured") {
		t.Errorf("%+v", f)
	}
}

func TestReportIsReadableInBothLanguages(t *testing.T) {
	e := newEnv(t)
	os.Remove(e.cfg.AuditLog)
	r := e.run()
	var en, ru bytes.Buffer
	Write(&en, i18n.LangEN, r)
	Write(&ru, i18n.LangRU, r)
	if !strings.Contains(en.String(), "[FAIL]") || !strings.Contains(en.String(), "→") {
		t.Errorf("english:\n%s", en.String())
	}
	if !strings.Contains(ru.String(), "Итог") {
		t.Errorf("russian:\n%s", ru.String())
	}
}

func TestConfigFailureIsAFinding(t *testing.T) {
	r := ConfigFailure(i18n.LangEN, errors.New("line 3: bad"))
	if r.Worst() != Fail || !strings.Contains(r.Findings[0].What, "line 3") {
		t.Errorf("%+v", r)
	}
}
