package source

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const (
	testPoll = 15 * time.Millisecond
	waitFor  = 3 * time.Second
)

func startTailer(t *testing.T, o Options) (<-chan string, context.CancelFunc, <-chan error) {
	t.Helper()
	if o.Poll == 0 {
		o.Poll = testPoll
	}
	lines := make(chan string, 64)
	errc := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		errc <- New(o).Run(ctx, func(l string) { lines <- l })
		close(done)
	}()
	// Wait for the goroutine to stop before the test's temp directory is
	// removed, otherwise a last state write can recreate it mid-cleanup.
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(waitFor):
			t.Error("the tailer did not stop")
		}
	})
	return lines, cancel, errc
}

func expectLines(t *testing.T, ch <-chan string, want ...string) {
	t.Helper()
	for _, w := range want {
		select {
		case got := <-ch:
			if got != w {
				t.Fatalf("got line %q, want %q", got, w)
			}
		case <-time.After(waitFor):
			t.Fatalf("timed out waiting for line %q", w)
		}
	}
}

func expectNoLine(t *testing.T, ch <-chan string, within time.Duration) {
	t.Helper()
	select {
	case got := <-ch:
		t.Fatalf("unexpected line %q", got)
	case <-time.After(within):
	}
}

func appendLine(t *testing.T, path, line string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(line + "\n"); err != nil {
		t.Fatal(err)
	}
}

func TestTailerFromStart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(path, []byte("one\ntwo\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	lines, _, _ := startTailer(t, Options{Path: path, FromStart: true})
	expectLines(t, lines, "one", "two")

	appendLine(t, path, "three")
	expectLines(t, lines, "three")
}

func TestTailerSkipsHistoryByDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(path, []byte("old1\nold2\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	lines, _, _ := startTailer(t, Options{Path: path})
	expectNoLine(t, lines, 150*time.Millisecond)

	appendLine(t, path, "new")
	expectLines(t, lines, "new")
}

func TestTailerHandlesRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(path, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	lines, _, _ := startTailer(t, Options{Path: path, FromStart: true})
	appendLine(t, path, "before")
	expectLines(t, lines, "before")

	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	appendLine(t, path, "after")
	expectLines(t, lines, "after")
}

func TestTailerHandlesTruncation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(path, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	lines, _, _ := startTailer(t, Options{Path: path, FromStart: true})
	appendLine(t, path, "first-generation")
	expectLines(t, lines, "first-generation")

	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	appendLine(t, path, "second-generation")
	expectLines(t, lines, "second-generation")
}

func TestTailerWaitsForAMissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "not-yet", "audit.log")

	lines, _, _ := startTailer(t, Options{Path: path})
	expectNoLine(t, lines, 100*time.Millisecond)

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	appendLine(t, path, "appeared")
	expectLines(t, lines, "appeared")
}

func TestTailerResumesFromState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	statePath := filepath.Join(dir, "state", "tail.json")
	if err := os.WriteFile(path, []byte("a\nb\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	lines, cancel, errc := startTailer(t, Options{Path: path, StatePath: statePath, FromStart: true})
	expectLines(t, lines, "a", "b")
	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(waitFor):
		t.Fatal("Run did not return after cancel")
	}

	tl := New(Options{Path: path, StatePath: statePath})
	if got := tl.LastOffset(); got != 4 {
		t.Fatalf("persisted offset = %d, want 4", got)
	}

	// A second run with the same state file must not replay "a" and "b".
	lines2, _, _ := startTailer(t, Options{Path: path, StatePath: statePath})
	expectNoLine(t, lines2, 150*time.Millisecond)
	appendLine(t, path, "c")
	expectLines(t, lines2, "c")
}

func TestTailerEmitsOnlyCompleteLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(path, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	lines, _, _ := startTailer(t, Options{Path: path, FromStart: true})

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("partial without newline"); err != nil {
		t.Fatal(err)
	}
	expectNoLine(t, lines, 100*time.Millisecond)

	if _, err := f.WriteString(" finished\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	expectLines(t, lines, "partial without newline finished")
}
