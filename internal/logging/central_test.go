package logging

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func readLines(t *testing.T, path string) []map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("not JSON: %q: %v", l, err)
		}
		out = append(out, m)
	}
	return out
}

func TestRecordShapeAndMasking(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(Options{Dir: dir, Level: "info", Version: "1.2.3", Commit: "abc", Stderr: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	ctx := WithRequestID(WithTrace(context.Background(), "0123456789abcdef0123456789abcdef"), "fedcba9876543210")
	l.Main.InfoContext(ctx, "login with password=hunter2 and token: abc", "event", "x",
		"url", "https://user:pw@host/p", "err", errors.New("Authorization: Bearer sekret"))
	l.Close()

	rows := readLines(t, filepath.Join(dir, "agent.jsonl"))
	if len(rows) != 1 {
		t.Fatalf("rows = %d", len(rows))
	}
	r := rows[0]
	for _, k := range []string{"ts", "level", "message", "service", "version", "commit", "event", "trace_id", "request_id"} {
		if _, ok := r[k]; !ok {
			t.Errorf("missing key %q in %v", k, r)
		}
	}
	if r["service"] != "agent" || r["level"] != "info" || r["trace_id"] != "0123456789abcdef0123456789abcdef" || r["request_id"] != "fedcba9876543210" {
		t.Errorf("unexpected record %v", r)
	}
	if _, err := time.Parse("2006-01-02T15:04:05.000Z", r["ts"].(string)); err != nil {
		t.Errorf("ts is not UTC with milliseconds: %v", r["ts"])
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "agent.jsonl"))
	for _, secret := range []string{"hunter2", "sekret", "pw@"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Errorf("secret %q reached the log: %s", secret, raw)
		}
	}
	fi, _ := os.Stat(filepath.Join(dir, "agent.jsonl"))
	if fi.Mode().Perm() != 0o640 {
		t.Errorf("file mode = %v, want 0640", fi.Mode().Perm())
	}
}

func TestStreamsAreSeparateFiles(t *testing.T) {
	dir := t.TempDir()
	l, _ := Open(Options{Dir: dir, Stderr: io.Discard})
	l.Main.Info("a")
	l.Stream("api").Info("b")
	l.Stream("frontend").Info("c")
	if l.Stream("api") != l.Stream("api") {
		t.Error("a stream is built once")
	}
	l.Close()
	for _, n := range []string{"agent.jsonl", "api.jsonl", "frontend.jsonl"} {
		rows := readLines(t, filepath.Join(dir, n))
		if len(rows) != 1 || rows[0]["service"] != strings.TrimSuffix(n, ".jsonl") {
			t.Errorf("%s = %v", n, rows)
		}
	}
}

func TestStreamWithoutDirectoryUsesMainLogger(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.log")
	l, _ := Open(Options{File: path, Stderr: io.Discard})
	l.Stream("api").Info("hello")
	l.Close()
	rows := readLines(t, path)
	if len(rows) != 1 || rows[0]["service"] != "api" {
		t.Errorf("rows = %v", rows)
	}
}

func TestRotationCompressesOlderArchives(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "api.jsonl")
	r, err := NewRotatingFile(path, 1, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	r.maxBytes, r.compress = 100, true
	for i := 0; i < 20; i++ {
		if _, err := r.Write([]byte(strings.Repeat("z", 60) + "\n")); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range []string{"api.jsonl", "api.jsonl.1", "api.jsonl.2.gz", "api.jsonl.3.gz"} {
		if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
			t.Errorf("%s should exist: %v", n, err)
		}
	}
	for _, n := range []string{"api.jsonl.2", "api.jsonl.3", "api.jsonl.4", "api.jsonl.4.gz"} {
		if _, err := os.Stat(filepath.Join(dir, n)); !os.IsNotExist(err) {
			t.Errorf("%s should not exist", n)
		}
	}
	f, _ := os.Open(filepath.Join(dir, "api.jsonl.2.gz"))
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(zr)
	if !strings.HasPrefix(string(b), "zzzz") {
		t.Errorf("archive content = %q", b)
	}
}

// A file removed or replaced under the process (logrotate, a person) must not
// leave it writing into an unlinked inode.
func TestWriterReopensAfterTheFileIsMoved(t *testing.T) {
	skipOnWindows(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "a.jsonl")
	r, err := NewRotatingFile(path, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	now := time.Now()
	r.now = func() time.Time { return now }
	r.Write([]byte("one\n"))
	if err := os.Rename(path, path+".moved"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	r.Write([]byte("two\n"))
	b, _ := os.ReadFile(path)
	if string(b) != "two\n" {
		t.Errorf("new file = %q, want the record written after the move", b)
	}
	old, _ := os.ReadFile(path + ".moved")
	if string(old) != "one\n" {
		t.Errorf("moved file = %q", old)
	}
}

type failingWriter struct{ fail bool }

func (f *failingWriter) Write(p []byte) (int, error) {
	if f.fail {
		return 0, errors.New("no space left on device")
	}
	return len(p), nil
}

// A log that cannot be written is reported once, never stops the caller, and
// returns by itself.
func TestDegradedWriterReportsOnceAndRecovers(t *testing.T) {
	var stderr bytes.Buffer
	fw := &failingWriter{fail: true}
	d := &degradedWriter{w: fw, label: "api", stderr: &stderr}
	for i := 0; i < 5; i++ {
		if n, err := d.Write([]byte("x")); n != 1 || err != nil {
			t.Fatalf("Write = %d, %v: a failing log must not fail the caller", n, err)
		}
	}
	if strings.Count(stderr.String(), "cannot be written") != 1 {
		t.Errorf("stderr = %q, want one report", stderr.String())
	}
	fw.fail = false
	d.Write([]byte("x"))
	if !strings.Contains(stderr.String(), "writable again (5 records were dropped)") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

type countSync struct {
	bytes.Buffer
	syncs int
}

func (c *countSync) Sync() error { c.syncs++; return nil }

func TestErrorRecordsAreSynced(t *testing.T) {
	cs := &countSync{}
	log := slog.New(newHandler(&cs.Buffer, slog.LevelInfo, cs))
	log.Info("fine")
	log.Warn("careful")
	if cs.syncs != 0 {
		t.Errorf("syncs = %d before an error", cs.syncs)
	}
	log.Error("boom")
	if cs.syncs != 1 {
		t.Errorf("syncs = %d after an error, want 1", cs.syncs)
	}
}

func TestUnusableDirectoryFallsBackToStdout(t *testing.T) {
	skipOnWindows(t)
	file := filepath.Join(t.TempDir(), "afile")
	os.WriteFile(file, nil, 0o600)
	l, err := Open(Options{Dir: filepath.Join(file, "sub"), Stderr: io.Discard})
	if err != nil {
		t.Fatalf("Open must not fail: %v", err)
	}
	defer l.Close()
	l.Main.Info("still logging")
	l.Stream("api").Info("and the other streams too")
}

func TestValidID(t *testing.T) {
	for _, ok := range []string{"0123456789abcdef", "0123456789abcdef0123456789abcdef", NewID()} {
		if !ValidID(ok) {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"", "short", "0123456789ABCDEF", "0123456789abcdeg", "0123456789abcdef0123456789abcdef0", "x;rm -rf /", "0123456789abcdef\n"} {
		if ValidID(bad) {
			t.Errorf("%q should be refused", bad)
		}
	}
	if NewID() == NewID() {
		t.Error("IDs must differ")
	}
}

func TestSweepRemovesOnlyArchives(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	write := func(name string, size int, age time.Duration) {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, bytes.Repeat([]byte("x"), size), 0o640); err != nil {
			t.Fatal(err)
		}
		os.Chtimes(p, now.Add(-age), now.Add(-age))
	}
	day := 24 * time.Hour
	write("agent.jsonl", 100, 40*day) // active: never removed, however old
	write("agent.jsonl.1", 100, 20*day)
	write("agent.jsonl.2.gz", 100, 30*day)
	write("api.jsonl.1", 100, 2*day)
	write("installer-commands.log.1", 100, 1*day)
	write("caddy-2026-01-01T00-00-00.000.log", 100, 90*day) // not ours to judge
	write("notes.txt", 100, 90*day)
	if err := os.Mkdir(filepath.Join(dir, "sub.jsonl.1"), 0o750); err != nil {
		t.Fatal(err)
	}

	removed, err := Sweep(SweepOptions{Dir: dir, MaxAge: 14 * day, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(sorted(removed), ",") != "agent.jsonl.1,agent.jsonl.2.gz" {
		t.Errorf("age sweep removed %v", removed)
	}
	for _, keep := range []string{"agent.jsonl", "api.jsonl.1", "installer-commands.log.1", "notes.txt", "sub.jsonl.1"} {
		if _, err := os.Stat(filepath.Join(dir, keep)); err != nil {
			t.Errorf("%s must stay: %v", keep, err)
		}
	}

	// Budget: the oldest archive goes first, active files are never touched.
	removed, _ = Sweep(SweepOptions{Dir: dir, BudgetBytes: 450, Now: now})
	if len(removed) != 1 || removed[0] != "installer-commands.log.1" && removed[0] != "api.jsonl.1" {
		t.Errorf("budget sweep removed %v", removed)
	}
	removed, _ = Sweep(SweepOptions{Dir: dir, BudgetBytes: 1, Now: now})
	for _, r := range removed {
		if r == "agent.jsonl" || r == "notes.txt" {
			t.Errorf("budget sweep removed %s", r)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "agent.jsonl")); err != nil {
		t.Error("the active file must survive any budget")
	}
}

func sorted(s []string) []string {
	out := append([]string(nil), s...)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func TestSweepMissingDirectory(t *testing.T) {
	if _, err := Sweep(SweepOptions{Dir: filepath.Join(t.TempDir(), "nope"), MaxAge: time.Hour}); err != nil {
		t.Errorf("a missing directory is not an error: %v", err)
	}
}

func TestFindTraceAcrossStreamsAndArchives(t *testing.T) {
	dir := t.TempDir()
	id := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	other := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	line := func(ts, svc, id, msg string) string {
		return fmt.Sprintf(`{"ts":%q,"level":"info","service":%q,"message":%q,"trace_id":%q}`, ts, svc, msg, id) + "\n"
	}
	os.WriteFile(filepath.Join(dir, "installer.jsonl"), []byte(line("2026-01-01T00:00:03.000Z", "installer", id, "third")+line("2026-01-01T00:00:00.500Z", "installer", other, "not mine")), 0o640)
	os.WriteFile(filepath.Join(dir, "api.jsonl"), []byte(line("2026-01-01T00:00:01.000Z", "api", id, "first")), 0o640)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write([]byte(line("2026-01-01T00:00:02.000Z", "agent", id, "second")))
	zw.Close()
	os.WriteFile(filepath.Join(dir, "agent.jsonl.1.gz"), gz.Bytes(), 0o640)
	os.WriteFile(filepath.Join(dir, "installer-commands.log"), []byte(`"trace_id":"`+id+`" raw output`+"\n"), 0o640)

	lines, truncated, err := FindTrace(dir, id)
	if err != nil {
		t.Fatal(err)
	}
	if truncated || len(lines) != 3 {
		t.Fatalf("lines = %d (truncated %v): %v", len(lines), truncated, lines)
	}
	for i, want := range []string{"first", "second", "third"} {
		if !strings.Contains(lines[i], want) {
			t.Errorf("line %d = %q, want %q (oldest first)", i, lines[i], want)
		}
	}
	if _, _, err := FindTrace(dir, "x;rm"); err == nil {
		t.Error("an invalid ID must be refused")
	}
}

func TestFindTraceIsBounded(t *testing.T) {
	dir := t.TempDir()
	id := "cccccccccccccccccccccccccccccccc"
	var b strings.Builder
	for i := 0; i < TraceMaxLines+50; i++ {
		fmt.Fprintf(&b, `{"ts":"2026-01-01T00:00:00.%06dZ","trace_id":%q}`+"\n", i, id)
	}
	os.WriteFile(filepath.Join(dir, "api.jsonl"), []byte(b.String()), 0o640)
	lines, truncated, err := FindTrace(dir, id)
	if err != nil || !truncated || len(lines) != TraceMaxLines {
		t.Errorf("lines=%d truncated=%v err=%v", len(lines), truncated, err)
	}
}
