package source

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func startAcknowledged(t *testing.T, o Options) (*Tailer, <-chan Line, func()) {
	t.Helper()
	o.Poll = testPoll
	tailer := New(o)
	ctx, cancel := context.WithCancel(context.Background())
	lines, done := make(chan Line, 64), make(chan error, 1)
	go func() {
		done <- tailer.RunLines(ctx, func(l Line) error {
			select {
			case lines <- l:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(waitFor):
			t.Fatal("reader did not stop")
		}
	}
	t.Cleanup(stop)
	return tailer, lines, stop
}

func nextSourceLine(t *testing.T, ch <-chan Line) Line {
	t.Helper()
	select {
	case l := <-ch:
		return l
	case <-time.After(waitFor):
		t.Fatal("no source line")
		return Line{}
	}
}

func TestReadAheadDoesNotAcknowledge(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	state := filepath.Join(dir, "tail.json")
	if err := os.WriteFile(path, []byte("one\ntwo\npartial"), 0600); err != nil {
		t.Fatal(err)
	}
	o := Options{Path: path, StatePath: state, FromStart: true}
	tailer, ch, stop := startAcknowledged(t, o)
	boundary := nextSourceLine(t, ch)
	first := nextSourceLine(t, ch)
	second := nextSourceLine(t, ch)
	if !boundary.Boundary || first.Start.Offset != 0 || first.End.Offset != 4 || second.Start.Offset != 4 {
		t.Fatal("incorrect byte positions", boundary, first, second)
	}
	if tailer.LastOffset() != 0 {
		t.Fatal("read-ahead advanced the saved cursor")
	}
	if err := tailer.SaveCursor(first.End); err != nil {
		t.Fatal(err)
	}
	stop()
	_, ch2, _ := startAcknowledged(t, o)
	b2 := nextSourceLine(t, ch2)
	replay := nextSourceLine(t, ch2)
	if replay.Text != "two" || b2.Start.Generation != first.Start.Generation {
		t.Fatal("restart did not preserve generation and replay unacknowledged line", b2, replay)
	}
	appendLine(t, path, " end")
	if got := nextSourceLine(t, ch2); got.Text != "partial end" || got.Start.Offset != 8 {
		t.Fatal("partial line was lost or treated as truncation", got)
	}
}

func TestResumeDrainsRotatedFileBeforeNewGeneration(t *testing.T) {
	skipOnWindows(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(path, []byte("saved\nqueued\n"), 0600); err != nil {
		t.Fatal(err)
	}
	o := Options{Path: path, StatePath: filepath.Join(dir, "tail.json"), FromStart: true}
	tailer, ch, stop := startAcknowledged(t, o)
	_ = nextSourceLine(t, ch)
	first := nextSourceLine(t, ch)
	_ = nextSourceLine(t, ch)
	if err := tailer.SaveCursor(first.End); err != nil {
		t.Fatal(err)
	}
	stop()
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("new\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, ch2, _ := startAcknowledged(t, o)
	old := nextSourceLine(t, ch2)
	queued := nextSourceLine(t, ch2)
	fresh := nextSourceLine(t, ch2)
	line := nextSourceLine(t, ch2)
	if old.Start.Generation != first.Start.Generation || queued.Text != "queued" || !fresh.Boundary || fresh.Start.Generation == old.Start.Generation || line.Text != "new" {
		t.Fatal("rotation recovery lost or mixed generations", old, queued, fresh, line)
	}
}

func TestOversizedLineIsDiscardedUntilNewline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", maxLine+3)+"\nok\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, ch, _ := startAcknowledged(t, Options{Path: path, FromStart: true})
	_ = nextSourceLine(t, ch)
	big := nextSourceLine(t, ch)
	normal := nextSourceLine(t, ch)
	if !big.Oversized || big.Start.Offset != 0 || big.End.Offset != maxLine+4 || normal.Text != "ok" || normal.Start.Offset != big.End.Offset {
		t.Fatal("oversized line was fragmented", big, normal)
	}
}
