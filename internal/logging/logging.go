// Package logging is the project's diagnostic log: JSON lines with the same
// keys in every component, one file per component, size rotation built in
// (the agent runs in a container with no logrotate), a janitor that keeps the
// log directory inside its budget, and a trace ID that follows one operation
// from the panel through the control service to the installer.
//
// Rules this package keeps:
//   - one file is written by one process; components never share a file;
//   - secrets are masked (internal/redact) before a line is written;
//   - a log that cannot be written never stops the program: it says so once on
//     standard error and goes on (see degradedWriter);
//   - only the janitor deletes, and only archives, never an active file.
package logging

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/RsNest/auditdsec/internal/redact"
)

// reopenCheck is how often a file is compared with what is at its path, to
// notice that it was removed or replaced under the running process (logrotate,
// a person tidying up).
const reopenCheck = time.Second

// RotatingFile is an io.WriteCloser that keeps at most MaxBackups previous
// files of at most MaxSizeMB each.
type RotatingFile struct {
	path       string
	maxBytes   int64
	maxBackups int
	compress   bool // archives from .2 on are gzipped

	mu        sync.Mutex
	f         *os.File
	fi        os.FileInfo
	size      int64
	lastCheck time.Time
	now       func() time.Time
}

// NewRotatingFile opens (or creates) the log file, creating its directory.
func NewRotatingFile(path string, maxSizeMB, maxBackups int) (*RotatingFile, error) {
	if path == "" {
		return nil, fmt.Errorf("logging: path is required")
	}
	if maxSizeMB <= 0 {
		maxSizeMB = 10
	}
	if maxBackups < 0 {
		maxBackups = 0
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("logging: create directory: %w", err)
	}
	r := &RotatingFile{
		path:       path,
		maxBytes:   int64(maxSizeMB) << 20,
		maxBackups: maxBackups,
		now:        time.Now,
	}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *RotatingFile) open() error {
	f, err := os.OpenFile(r.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return fmt.Errorf("logging: open %s: %w", r.path, err)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return fmt.Errorf("logging: stat %s: %w", r.path, err)
	}
	r.f, r.fi, r.size = f, fi, fi.Size()
	r.lastCheck = r.now()
	return nil
}

// reopenIfMoved notices a file that was removed or replaced while it was open
// and starts a new one at the path. The caller must hold the mutex.
func (r *RotatingFile) reopenIfMoved() error {
	if r.f != nil && r.now().Sub(r.lastCheck) < reopenCheck {
		return nil
	}
	if r.f == nil {
		return r.open()
	}
	r.lastCheck = r.now()
	cur, err := os.Stat(r.path)
	if err == nil && os.SameFile(cur, r.fi) {
		return nil
	}
	r.f.Close()
	r.f = nil
	return r.open()
}

func (r *RotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil && r.fi == nil {
		return 0, fmt.Errorf("logging: file is closed")
	}
	if err := r.reopenIfMoved(); err != nil {
		return 0, err
	}
	if r.size+int64(len(p)) > r.maxBytes && r.size > 0 {
		if err := r.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

// Sync flushes the file to disk. Records at error level and above call it, so
// the line that explains a crash is the one that survives it.
func (r *RotatingFile) Sync() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	return r.f.Sync()
}

// rotate renames the current file to .1, shifting older ones up and dropping
// the oldest. The caller must hold the mutex.
func (r *RotatingFile) rotate() error {
	if err := r.f.Close(); err != nil {
		return fmt.Errorf("logging: close before rotation: %w", err)
	}
	r.f = nil

	if r.maxBackups == 0 {
		if err := os.Remove(r.path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("logging: discard log: %w", err)
		}
		return r.open()
	}

	for _, suffix := range []string{"", ".gz"} {
		oldest := fmt.Sprintf("%s.%d%s", r.path, r.maxBackups, suffix)
		if err := os.Remove(oldest); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("logging: remove %s: %w", oldest, err)
		}
	}
	for i := r.maxBackups - 1; i >= 1; i-- {
		for _, suffix := range []string{"", ".gz"} {
			from := fmt.Sprintf("%s.%d%s", r.path, i, suffix)
			to := fmt.Sprintf("%s.%d%s", r.path, i+1, suffix)
			if err := os.Rename(from, to); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("logging: rename %s: %w", from, err)
			}
		}
	}
	if err := os.Rename(r.path, r.path+".1"); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("logging: rotate %s: %w", r.path, err)
	}
	err := r.open()
	if r.compress && r.maxBackups >= 2 {
		// A compression failure leaves the plain archive in place; it costs
		// space, not records.
		_ = gzipFile(r.path + ".2")
	}
	return err
}

// gzipFile replaces name with name.gz, keeping its mode. Nothing is removed
// unless the compressed copy was written completely.
func gzipFile(name string) error {
	in, err := os.Open(name)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := name + ".gz.tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	zw := gzip.NewWriter(out)
	_, err = io.Copy(zw, in)
	if cerr := zw.Close(); err == nil {
		err = cerr
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, name+".gz"); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Remove(name)
}

// Close closes the current file.
func (r *RotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f, r.fi = nil, nil
	return err
}

// degradedWriter is what a log writes through. When the file cannot be
// written (full disk, a directory that vanished, a permission change) the
// first failure is reported once on standard error, records are dropped, and
// the file is tried again on the next write: the program goes on, and the log
// returns by itself when the cause is gone. It never logs through the logger it
// belongs to, so it cannot recurse.
type degradedWriter struct {
	w      io.Writer
	label  string
	stderr io.Writer

	mu      sync.Mutex
	failed  bool
	dropped int
}

func (d *degradedWriter) Write(p []byte) (int, error) {
	_, err := d.w.Write(p)
	d.mu.Lock()
	defer d.mu.Unlock()
	if err != nil {
		d.dropped++
		if !d.failed {
			d.failed = true
			fmt.Fprintf(d.stderr, "auditdsec: the %s log cannot be written (%v); records are dropped until it can\n", d.label, err)
		}
		return len(p), nil
	}
	if d.failed {
		d.failed = false
		fmt.Fprintf(d.stderr, "auditdsec: the %s log is writable again (%d records were dropped)\n", d.label, d.dropped)
		d.dropped = 0
	}
	return len(p), nil
}

func (d *degradedWriter) Sync() error {
	if s, ok := d.w.(interface{ Sync() error }); ok {
		return s.Sync()
	}
	return nil
}

// Options configures Open and Setup.
type Options struct {
	File       string // the agent's own file (when Dir is empty)
	Level      string
	MaxSizeMB  int
	MaxBackups int
	Stdout     bool

	// Dir is the central log directory (/var/log/auditseclogs). When it is
	// set, every stream is Dir/<service>.jsonl.
	Dir        string
	Service    string // the name of the first stream, "agent" by default
	Version    string
	Commit     string
	MaxAgeDays int // archives older than this are removed by the janitor
	BudgetMB   int // the directory is kept under this size

	Stderr io.Writer // where a failing log reports itself; os.Stderr by default
}

// Logs is the set of streams one process writes.
type Logs struct {
	Main *slog.Logger

	o       Options
	level   slog.Level
	closers []io.Closer
	mu      sync.Mutex
	streams map[string]*slog.Logger
}

// Open builds the main logger. A log file that cannot be opened (a read-only
// filesystem, a directory that is not mounted) is reported and skipped rather
// than fatal: an agent that cannot write its own log should still be watching
// the host.
func Open(o Options) (*Logs, error) {
	if o.Stderr == nil {
		o.Stderr = os.Stderr
	}
	if o.Service == "" {
		o.Service = "agent"
	}
	l := &Logs{o: o, level: ParseLevel(o.Level), streams: map[string]*slog.Logger{}}
	l.Main = l.build(o.Service, true)
	return l, nil
}

// Setup is Open for callers that only need the main logger.
func Setup(o Options) (*slog.Logger, io.Closer, error) {
	l, err := Open(o)
	if err != nil {
		return nil, nil, err
	}
	if len(l.closers) == 0 {
		return l.Main, nil, nil
	}
	return l.Main, l, nil
}

// Stream returns the logger of another component of this process, with its own
// file in the central directory. Without a directory it is the main logger,
// carrying the service name, so nothing is lost.
func (l *Logs) Stream(service string) *slog.Logger {
	l.mu.Lock()
	defer l.mu.Unlock()
	if s, ok := l.streams[service]; ok {
		return s
	}
	var s *slog.Logger
	if l.o.Dir == "" {
		s = l.Main.With("service", service)
	} else {
		s = l.build(service, false)
	}
	l.streams[service] = s
	return s
}

// Close closes every file the streams opened.
func (l *Logs) Close() error {
	var first error
	for _, c := range l.closers {
		if err := c.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (l *Logs) build(service string, main bool) *slog.Logger {
	o := l.o
	var writers []io.Writer
	var syncer interface{ Sync() error }
	var fileErr error

	path := o.File
	if o.Dir != "" {
		path = filepath.Join(o.Dir, service+".jsonl")
	}
	if path != "" {
		rf, err := NewRotatingFile(path, o.MaxSizeMB, o.MaxBackups)
		if err != nil {
			fileErr = err
		} else {
			rf.compress = o.Dir != ""
			dw := &degradedWriter{w: rf, label: service, stderr: o.Stderr}
			writers = append(writers, dw)
			syncer = dw
			l.closers = append(l.closers, rf)
		}
	}
	// The main stream keeps writing to standard output as well (docker logs).
	// Other streams use it only when they have no file at all.
	if (main && o.Stdout) || len(writers) == 0 {
		writers = append(writers, os.Stdout)
	}

	h := newHandler(io.MultiWriter(writers...), l.level, syncer)
	log := slog.New(h).With("service", service)
	if o.Version != "" {
		log = log.With("version", o.Version)
	}
	if o.Commit != "" {
		log = log.With("commit", o.Commit)
	}
	if fileErr != nil {
		log.Warn("logging to standard output only", "event", "log_degraded", "error", fileErr.Error())
	}
	return log
}

// handler writes the project's record shape: ts (UTC), level (lower case),
// message, then the attributes, with every string passed through redact. It
// adds the IDs carried by the context and syncs records at error level.
type handler struct {
	inner  slog.Handler
	syncer interface{ Sync() error }
}

func newHandler(w io.Writer, level slog.Level, syncer interface{ Sync() error }) *handler {
	return &handler{
		syncer: syncer,
		inner: slog.NewJSONHandler(w, &slog.HandlerOptions{
			Level:       level,
			ReplaceAttr: replaceAttr,
		}),
	}
}

func replaceAttr(groups []string, a slog.Attr) slog.Attr {
	if len(groups) == 0 {
		switch a.Key {
		case slog.TimeKey:
			if t, ok := a.Value.Any().(time.Time); ok {
				return slog.String("ts", t.UTC().Format("2006-01-02T15:04:05.000Z"))
			}
		case slog.LevelKey:
			if lv, ok := a.Value.Any().(slog.Level); ok {
				return slog.String("level", strings.ToLower(lv.String()))
			}
		case slog.MessageKey:
			return slog.String("message", redact.String(a.Value.String()))
		}
	}
	if a.Value.Kind() == slog.KindString {
		return slog.String(a.Key, redact.String(a.Value.String()))
	}
	if a.Value.Kind() == slog.KindAny {
		if err, ok := a.Value.Any().(error); ok {
			return slog.String(a.Key, redact.String(err.Error()))
		}
	}
	return a
}

func (h *handler) Enabled(ctx context.Context, l slog.Level) bool { return h.inner.Enabled(ctx, l) }

func (h *handler) Handle(ctx context.Context, r slog.Record) error {
	if id := TraceID(ctx); id != "" {
		r.AddAttrs(slog.String("trace_id", id))
	}
	if id := RequestID(ctx); id != "" {
		r.AddAttrs(slog.String("request_id", id))
	}
	err := h.inner.Handle(ctx, r)
	if r.Level >= slog.LevelError && h.syncer != nil {
		_ = h.syncer.Sync()
	}
	return err
}

func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &handler{inner: h.inner.WithAttrs(attrs), syncer: h.syncer}
}

func (h *handler) WithGroup(name string) slog.Handler {
	return &handler{inner: h.inner.WithGroup(name), syncer: h.syncer}
}

// ParseLevel maps a config value to a slog level, defaulting to info.
func ParseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
