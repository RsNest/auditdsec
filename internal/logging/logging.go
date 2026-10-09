// Package logging sets up the agent's own structured log with size-based
// rotation. Rotation is built in rather than delegated to logrotate, because
// the agent is expected to run in a container where no logrotate exists.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// RotatingFile is an io.WriteCloser that keeps at most MaxBackups previous
// files of at most MaxSizeMB each.
type RotatingFile struct {
	path       string
	maxBytes   int64
	maxBackups int

	mu   sync.Mutex
	f    *os.File
	size int64
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
	r.f, r.size = f, fi.Size()
	return nil
}

func (r *RotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return 0, fmt.Errorf("logging: file is closed")
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

	oldest := fmt.Sprintf("%s.%d", r.path, r.maxBackups)
	if err := os.Remove(oldest); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("logging: remove %s: %w", oldest, err)
	}
	for i := r.maxBackups - 1; i >= 1; i-- {
		from := fmt.Sprintf("%s.%d", r.path, i)
		to := fmt.Sprintf("%s.%d", r.path, i+1)
		if err := os.Rename(from, to); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("logging: rename %s: %w", from, err)
		}
	}
	if err := os.Rename(r.path, r.path+".1"); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("logging: rotate %s: %w", r.path, err)
	}
	return r.open()
}

// Close closes the current file.
func (r *RotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}

// Options configures Setup.
type Options struct {
	File       string
	Level      string
	MaxSizeMB  int
	MaxBackups int
	Stdout     bool
}

// Setup builds a JSON logger. A log file that cannot be opened (a read-only
// filesystem, a missing volume) is reported and skipped rather than fatal: an
// agent that cannot write its own log should still be watching the host.
func Setup(o Options) (*slog.Logger, io.Closer, error) {
	var writers []io.Writer
	var closer io.Closer
	var fileErr error

	if o.File != "" {
		rf, err := NewRotatingFile(o.File, o.MaxSizeMB, o.MaxBackups)
		if err != nil {
			fileErr = err
		} else {
			writers = append(writers, rf)
			closer = rf
		}
	}
	if o.Stdout || len(writers) == 0 {
		writers = append(writers, os.Stdout)
	}

	h := slog.NewJSONHandler(io.MultiWriter(writers...), &slog.HandlerOptions{Level: ParseLevel(o.Level)})
	log := slog.New(h)
	if fileErr != nil {
		log.Warn("logging to stdout only", "error", fileErr.Error())
	}
	return log, closer, nil
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
