package access

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Exercise the real Git checkout and executable boundary without fetching
// from the network or invoking Docker/the production installer.
func TestPinnedUpdateExec(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the installer is a Linux executable")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("Git is required")
	}
	for _, dirty := range []bool{false, true} {
		t.Run(map[bool]string{false: "exact commit", true: "tracked edit"}[dirty], func(t *testing.T) {
			dir := t.TempDir()
			script := filepath.Join(dir, "install.sh")
			if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf 'executed %s\\n' \"$@\"\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			git := func(args ...string) string {
				t.Helper()
				cmd := exec.Command("git", args...)
				cmd.Dir = dir
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("git %v: %v %s", args, err, out)
				}
				return strings.TrimSpace(string(out))
			}
			git("init", "-q")
			git("add", "install.sh")
			git("-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-qm", "fixture")
			commit := git("rev-parse", "HEAD")
			if dirty {
				if err := os.WriteFile(script, []byte("#!/bin/sh\necho modified-installer\n"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			events := filepath.Join(dir, "events.jsonl")
			var log bytes.Buffer
			code, err := DefaultExec(context.Background(), dir, Args(Params{Action: ActionUpdate, Commit: commit, Lang: "en"}, events), &log)
			if dirty {
				if err == nil || code != -1 || !strings.Contains(err.Error(), "local changes") || strings.Contains(log.String(), "modified-installer") {
					t.Fatalf("modified tracked installer executed: code=%d err=%v log=%s", code, err, &log)
				}
				return
			}
			if err != nil || code != 0 || !strings.Contains(log.String(), "executed update") || strings.Contains(log.String(), "--update-commit") {
				t.Fatalf("exact pin not executed: code=%d err=%v log=%s", code, err, &log)
			}
			b, err := os.ReadFile(events)
			var event Event
			if err != nil || json.Unmarshal(b, &event) != nil || event.Code != "source" {
				t.Fatalf("source progress missing: %s %v", b, err)
			}
		})
	}
}
