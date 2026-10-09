// Package source follows a growing log file. It polls instead of using inotify:
// polling costs a stat call per second, works the same on bind mounts and
// network filesystems where inotify is unreliable, and keeps the agent free of
// external dependencies.
package source

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

const (
	// maxLine caps the buffer for a line that never ends, so a corrupt log
	// cannot grow the agent's memory without bound.
	maxLine = 1 << 20
	// headSize is how many leading bytes are fingerprinted to notice a file
	// that was replaced or truncated in place. Appends never change these
	// bytes, so a mismatch means the file is not the one we were reading.
	headSize = 256
)

// Options configures a Tailer.
type Options struct {
	// Path is the log file to follow.
	Path string
	// StatePath is where the read offset is persisted, so a restart does not
	// replay or skip events. Empty disables persistence.
	StatePath string
	// Poll is how often the file is checked. Defaults to one second.
	Poll time.Duration
	// FromStart reads the existing contents on the very first run. The default
	// starts at the end, so installing the agent does not replay months of history.
	FromStart bool
	Logger    *slog.Logger
}

// Tailer follows one file.
type Tailer struct {
	opt Options
	log *slog.Logger
}

// New returns a Tailer. It does not touch the filesystem yet.
func New(o Options) *Tailer {
	if o.Poll <= 0 {
		o.Poll = time.Second
	}
	log := o.Logger
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Tailer{opt: o, log: log}
}

type state struct {
	Offset int64 `json:"offset"`
}

// Run follows the file until ctx is cancelled, calling emit for every complete
// line. A missing file is not an error: the tailer keeps waiting for it, which
// is what happens while auditd is being installed or restarted.
func (t *Tailer) Run(ctx context.Context, emit func(line string)) error {
	r := &reader{t: t, emit: emit, first: true, resume: t.loadState()}
	defer r.close()

	ticker := time.NewTicker(t.opt.Poll)
	defer ticker.Stop()

	for {
		if err := r.step(); err != nil {
			t.log.Warn("tail step failed", "path", t.opt.Path, "error", err)
		}
		select {
		case <-ctx.Done():
			r.persist()
			return nil
		case <-ticker.C:
		}
	}
}

// LastOffset returns the persisted offset, for diagnostics.
func (t *Tailer) LastOffset() int64 {
	if s := t.loadState(); s != nil {
		return s.Offset
	}
	return 0
}

func (t *Tailer) loadState() *state {
	if t.opt.StatePath == "" {
		return nil
	}
	b, err := os.ReadFile(t.opt.StatePath)
	if err != nil {
		return nil
	}
	var s state
	if err := json.Unmarshal(b, &s); err != nil || s.Offset < 0 {
		return nil
	}
	return &s
}

type reader struct {
	t       *Tailer
	emit    func(string)
	f       *os.File
	fi      os.FileInfo
	offset  int64
	partial []byte
	head    []byte
	first   bool
	missing bool // the file was absent on an earlier attempt
	resume  *state
	saved   int64
}

// step performs one poll cycle: open or reopen the file as needed, then read
// whatever has been appended.
func (r *reader) step() error {
	if r.f == nil {
		return r.open()
	}
	cur, err := os.Stat(r.t.opt.Path)
	if err != nil {
		// The file disappeared (rotated away, or auditd removed). Drain what is
		// left and wait for it to come back.
		if derr := r.drain(); derr != nil {
			r.t.log.Debug("drain before reopen failed", "error", derr)
		}
		r.close()
		return fmt.Errorf("stat %s: %w", r.t.opt.Path, err)
	}
	if !os.SameFile(cur, r.fi) {
		// Rotated: finish the old file, then start the new one from the top.
		if derr := r.drain(); derr != nil {
			r.t.log.Debug("drain of rotated file failed", "error", derr)
		}
		r.close()
		r.t.log.Info("log rotated, reopening", "path", r.t.opt.Path)
		return r.open()
	}
	if cur.Size() < r.offset || r.headChanged() {
		// Truncated in place, which is how copytruncate-style rotation and
		// `: > audit.log` look from here.
		r.t.log.Info("log truncated, rereading from the start", "path", r.t.opt.Path)
		if _, err := r.f.Seek(0, io.SeekStart); err != nil {
			return fmt.Errorf("seek after truncate: %w", err)
		}
		r.offset, r.partial = 0, nil
		r.head = r.readHead()
	}
	r.refreshHead()
	return r.drain()
}

// readHead returns the first bytes of the open file. ReadAt is used so the
// sequential read position is left alone.
func (r *reader) readHead() []byte {
	if r.f == nil {
		return nil
	}
	b := make([]byte, headSize)
	n, err := r.f.ReadAt(b, 0)
	if n == 0 && err != nil && err != io.EOF {
		return nil
	}
	return b[:n]
}

// headChanged reports whether the bytes we fingerprinted at the start of the
// file are gone or different, which catches a truncation even when the file has
// already grown back past our read offset.
func (r *reader) headChanged() bool {
	if len(r.head) == 0 {
		return false
	}
	now := r.readHead()
	if len(now) < len(r.head) {
		return true
	}
	return !bytes.Equal(now[:len(r.head)], r.head)
}

// refreshHead extends the fingerprint while the file is still shorter than
// headSize, so a log that was empty when we opened it becomes checkable.
func (r *reader) refreshHead() {
	if len(r.head) >= headSize {
		return
	}
	if h := r.readHead(); len(h) > len(r.head) {
		r.head = h
	}
}

func (r *reader) open() error {
	f, err := os.Open(r.t.opt.Path)
	if err != nil {
		r.missing = true
		return fmt.Errorf("open %s: %w", r.t.opt.Path, err)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return fmt.Errorf("stat %s: %w", r.t.opt.Path, err)
	}

	start := int64(0)
	if r.first {
		switch {
		case r.resume != nil && r.resume.Offset <= fi.Size():
			start = r.resume.Offset // continue where the previous run stopped
		case r.missing:
			start = 0 // the file was created after we started: all of it is new
		case !r.t.opt.FromStart:
			start = fi.Size() // fresh install: only report what happens from now on
		}
		r.first = false
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		f.Close()
		return fmt.Errorf("seek %s: %w", r.t.opt.Path, err)
	}
	r.f, r.fi, r.offset, r.partial = f, fi, start, nil
	r.head = r.readHead()
	r.t.log.Debug("following log", "path", r.t.opt.Path, "offset", start)
	return r.drain()
}

func (r *reader) drain() error {
	if r.f == nil {
		return nil
	}
	buf := make([]byte, 64*1024)
	for {
		n, err := r.f.Read(buf)
		if n > 0 {
			r.consume(buf[:n])
		}
		if err == io.EOF || n == 0 {
			r.persist()
			return nil
		}
		if err != nil {
			return fmt.Errorf("read %s: %w", r.t.opt.Path, err)
		}
	}
}

func (r *reader) consume(b []byte) {
	r.partial = append(r.partial, b...)
	for {
		i := bytes.IndexByte(r.partial, '\n')
		if i < 0 {
			break
		}
		line := string(r.partial[:i])
		r.partial = append([]byte(nil), r.partial[i+1:]...)
		r.offset += int64(i + 1)
		r.emit(line)
	}
	if len(r.partial) > maxLine {
		r.t.log.Warn("dropping oversized log line", "path", r.t.opt.Path, "bytes", len(r.partial))
		r.offset += int64(len(r.partial))
		r.partial = nil
	}
}

// persist writes the offset of the last complete line, atomically. A partial
// line is never counted, so a restart re-reads it instead of losing it.
func (r *reader) persist() {
	if r.t.opt.StatePath == "" || r.offset == r.saved {
		return
	}
	b, err := json.Marshal(state{Offset: r.offset})
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(r.t.opt.StatePath), 0o750); err != nil {
		r.t.log.Warn("cannot create state directory", "error", err)
		return
	}
	tmp := r.t.opt.StatePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		r.t.log.Warn("cannot write tail state", "error", err)
		return
	}
	if err := os.Rename(tmp, r.t.opt.StatePath); err != nil {
		r.t.log.Warn("cannot replace tail state", "error", err)
		return
	}
	r.saved = r.offset
}

func (r *reader) close() {
	if r.f != nil {
		r.persist()
		r.f.Close()
		r.f = nil
		r.fi = nil
	}
}
