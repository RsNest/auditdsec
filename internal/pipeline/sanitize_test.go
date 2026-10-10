package pipeline

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RsNest/auditdsec/internal/delivery"
	"github.com/RsNest/auditdsec/internal/model"
	"github.com/RsNest/auditdsec/internal/parse"
	"github.com/RsNest/auditdsec/internal/semantic"
	"github.com/RsNest/auditdsec/internal/store"
)

// payloadNotifier puts the whole event into the notification plan, as a
// channel that renders the evidence would.
type payloadNotifier struct{ plannedNotifier }

func (f *payloadNotifier) PlanEvent(ev model.Event) delivery.Plan {
	b, _ := json.Marshal(ev)
	return delivery.Plan{Intents: []delivery.Intent{{ID: delivery.ID(ev.ID), Channel: "telegram", Route: "fake",
		Destination: "1", Priority: delivery.Routine, Created: time.Now(), Payload: b}}}
}

func up(s string) string { return strings.ToUpper(hex.EncodeToString([]byte(s))) }

// A secret must not reach any file the agent writes, whichever way auditd
// encoded it: hex PROCTITLE with NUL-separated arguments, EXECVE arguments
// that split "-p" from its password, a hex sudo command, terminal input.
func TestSecretsNeverReachPersistentFiles(t *testing.T) {
	secrets := []string{"hunter2-proc", "hunter2-exec", "hunter2-sudo", "hunter2-tty", "tok-abc-header"}
	lines := []string{
		// execution from /tmp: SYSCALL + EXECVE (split) + PROCTITLE (hex)
		`type=SYSCALL msg=audit(1760000000.100:10): arch=c000003e syscall=59 success=yes exit=0 auid=1000 uid=0 comm="sshpass" exe="/tmp/sshpass" key="ads_exec_tmp"`,
		`type=EXECVE msg=audit(1760000000.100:10): argc=5 a0="sshpass" a1="-p" a2=` + up("hunter2-exec") + ` a3="ssh" a4="root@host"`,
		`type=PROCTITLE msg=audit(1760000000.100:10): proctitle=` + up("mysql\x00-u\x00root\x00-phunter2-proc"),
		`type=EOE msg=audit(1760000000.100:10): `,
		// the same shape with a header in the next argument
		`type=SYSCALL msg=audit(1760000000.200:11): arch=c000003e syscall=59 success=yes exit=0 auid=1000 uid=0 comm="curl" exe="/tmp/curl" key="ads_exec_tmp"`,
		`type=EXECVE msg=audit(1760000000.200:11): argc=4 a0="curl" a1="-H" a2=` + up("Authorization: Bearer tok-abc-header") + ` a3="https://x"`,
		`type=EOE msg=audit(1760000000.200:11): `,
		// sudo
		`type=USER_CMD msg=audit(1760000000.300:12): pid=2000 uid=1000 auid=1000 msg='cwd="/root" cmd=` + up("mysql -phunter2-sudo -e 'x'") + ` terminal=pts/0 res=success'`,
	}

	dir := t.TempDir()
	audit := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(audit, nil, 0600); err != nil {
		t.Fatal(err)
	}
	store1, err := store.Open(store.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer store1.Close()
	f := &payloadNotifier{}
	p, err := New(Options{AuditLog: audit, StateDir: dir, Store: store1, Notifier: f, Debug: true})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	asm := parse.NewAssembler(time.Second)
	mapper := semantic.New("web01")
	var mapped []model.Event
	for _, l := range lines {
		evs, err := asm.Add(l, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		for _, ae := range evs {
			if ev, _, ok := mapper.MapVerbose(ae); ok {
				mapped = append(mapped, ev)
			}
		}
	}
	for _, ae := range asm.Flush() {
		if ev, _, ok := mapper.MapVerbose(ae); ok {
			mapped = append(mapped, ev)
		}
	}
	if len(mapped) != 3 {
		t.Fatalf("mapped %d events, want 3", len(mapped))
	}
	// An event built by something other than the mapper (a detector, a
	// heartbeat) is held to the same rule by the pipeline.
	raw := mapped[0]
	raw.Raw = lines[1] + "\n" + lines[2]
	raw.ID = "forced"
	mapped = append(mapped, raw)

	for _, ev := range mapped {
		if err := p.handle(context.Background(), ev); err != nil {
			t.Fatal(err)
		}
	}

	var scanned int
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil // a file held open exclusively is not a leak
		}
		scanned++
		for _, s := range secrets {
			if bytes.Contains(b, []byte(s)) || bytes.Contains(bytes.ToUpper(b), []byte(up(s))) {
				t.Errorf("secret %q found in %s", s, path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned < 2 {
		t.Fatalf("only %d files scanned: the journal and the outbox should both exist", scanned)
	}

	// The evidence is still useful: structure and non-secret arguments stay.
	var exec model.Event
	for _, ev := range store1.Recent(10) {
		if ev.Kind == model.KindSuspiciousExec && strings.Contains(ev.Raw, "sshpass") {
			exec = ev
		}
	}
	if !strings.Contains(exec.Raw, `a1="-p" a2="***" a3="ssh"`) || !strings.Contains(exec.Raw, `proctitle="mysql -u root -p***"`) {
		t.Errorf("evidence lost its structure:\n%s", exec.Raw)
	}
	if exec.Incomplete != "" {
		t.Errorf("completeness metadata changed: %q", exec.Incomplete)
	}
}
