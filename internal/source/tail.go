// Package source follows a growing log file. It polls instead of using inotify:
// polling costs a stat call per second, works the same on bind mounts and
// network filesystems where inotify is unreliable, and keeps the agent free of
// external dependencies.
package source

import (
	"context"
	"io"
	"log/slog"
	"sync"
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
	opt        Options
	log        *slog.Logger
	mu         sync.Mutex
	checkpoint *Cursor
	status     string
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

// Run is the synchronous convenience API. The callback must finish processing
// the line before returning. Queue consumers must use RunLines and SaveCursor.
func (t *Tailer) Run(ctx context.Context, emit func(string)) error {
	return t.RunLines(ctx, func(l Line) error {
		if !l.Boundary && !l.Oversized && !l.Skipped {
			emit(l.Text)
		}
		return t.SaveCursor(l.End)
	})
}

// LastOffset reports the acknowledged position, not read-ahead progress.
func (t *Tailer) LastOffset() int64 {
	t.mu.Lock()
	if t.checkpoint != nil {
		offset := t.checkpoint.Offset
		t.mu.Unlock()
		return offset
	}
	t.mu.Unlock()
	c, err := t.restoreCursor()
	if err == nil && c != nil {
		return c.Offset
	}
	return 0
}
