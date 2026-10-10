package source

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Cursor identifies the file generation as well as the acknowledged byte offset.
// Head and Anchor detect copytruncate even if the file regrows before the next poll.
type Cursor struct {
	Version    int    `json:"version"`
	Path       string `json:"path"`
	FileID     string `json:"file_id"`
	Generation string `json:"generation"`
	Offset     int64  `json:"offset"`
	Head       []byte `json:"head,omitempty"`
	Anchor     []byte `json:"anchor,omitempty"`
}

type Line struct {
	Text      string
	Start     Cursor
	End       Cursor
	Boundary  bool
	Oversized bool
	Skipped   bool
	Gap       string
}

func (t *Tailer) Status() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.status == "" {
		return "ok"
	}
	return t.status
}
func (t *Tailer) setStatus(s string) { t.mu.Lock(); defer t.mu.Unlock(); t.status = s }

// SaveCursor is called by the consumer after durable storage, never by read-ahead.
func (t *Tailer) SaveCursor(c Cursor) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if c.Version != 2 || c.Offset < 0 || len(c.Generation) != 32 || c.Path == "" || c.FileID == "" {
		return errors.New("invalid acknowledged cursor")
	}
	if old := t.checkpoint; old != nil && old.Generation == c.Generation && old.Offset == c.Offset {
		return nil
	}
	if t.opt.StatePath != "" {
		if err := os.MkdirAll(filepath.Dir(t.opt.StatePath), 0750); err != nil {
			return err
		}
		b, err := json.Marshal(c)
		if err != nil {
			return err
		}
		f, err := os.CreateTemp(filepath.Dir(t.opt.StatePath), ".tail-*")
		if err != nil {
			return err
		}
		defer os.Remove(f.Name())
		if err = f.Chmod(0600); err == nil {
			_, err = f.Write(b)
		}
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		if err := os.Rename(f.Name(), t.opt.StatePath); err != nil {
			return err
		}
		marker, err := os.OpenFile(t.opt.StatePath+".initialized", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		if err == nil {
			_, writeErr := marker.WriteString("2\n")
			if writeErr == nil {
				writeErr = marker.Sync()
			}
			closeErr := marker.Close()
			if writeErr != nil {
				return writeErr
			}
			if closeErr != nil {
				return closeErr
			}
		}
		if dir, err := os.Open(filepath.Dir(t.opt.StatePath)); err == nil {
			_ = dir.Sync()
			_ = dir.Close()
		}
	}
	t.checkpoint = &c
	return nil
}

func (t *Tailer) restoreCursor() (*Cursor, error) {
	if t.opt.StatePath == "" {
		return nil, nil
	}
	b, err := os.ReadFile(t.opt.StatePath)
	if errors.Is(err, os.ErrNotExist) {
		if _, markerErr := os.Stat(t.opt.StatePath + ".initialized"); markerErr == nil {
			return nil, errors.New("saved cursor is missing after initialization; restore it or explicitly reset the cursor")
		} else if !errors.Is(markerErr, os.ErrNotExist) {
			return nil, markerErr
		}
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read cursor: %w", err)
	}
	var c Cursor
	if json.Unmarshal(b, &c) != nil || c.Offset < 0 {
		return nil, errors.New("invalid saved cursor; restore it or explicitly reset the cursor")
	}
	if c.Version != 0 && c.Version != 2 {
		return nil, errors.New("unsupported cursor schema")
	}
	if c.Version == 2 && (c.Path == "" || c.FileID == "" || len(c.Generation) != 32 || len(c.Head) > headSize || len(c.Anchor) > headSize || int64(len(c.Anchor)) > c.Offset) {
		return nil, errors.New("invalid saved cursor identity")
	}
	return &c, nil
}

type acknowledgedReader struct {
	t                     *Tailer
	emit                  func(Line) error
	f                     *os.File
	id, generation, path  string
	head, anchor, partial []byte
	offset                int64
	lineStart             int64
	discard               bool
	skip                  bool
	first, missing        bool
	resume                *Cursor
	gap                   string
}

// RunLines delivers positions with each line and leaves acknowledgement to the
// consumer. A restart replays unacknowledged queued lines and open audit events.
func (t *Tailer) RunLines(ctx context.Context, emit func(Line) error) error {
	resume, err := t.restoreCursor()
	if err != nil {
		return err
	}
	r := &acknowledgedReader{t: t, emit: emit, first: true, resume: resume}
	defer func() {
		if r.f != nil {
			_ = r.f.Close()
		}
	}()
	ticker := time.NewTicker(t.opt.Poll)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return nil
		}
		if err := r.step(); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func fingerprint(f *os.File, off int64, n int) []byte {
	if n <= 0 {
		return nil
	}
	b := make([]byte, n)
	count, _ := f.ReadAt(b, off)
	return b[:count]
}

func cursorMatches(f *os.File, c Cursor) bool {
	fi, err := f.Stat()
	if err != nil || fi.Size() < c.Offset {
		return false
	}
	id, err := fileIdentity(f)
	return err == nil && id == c.FileID && bytes.Equal(fingerprint(f, 0, len(c.Head)), c.Head) && bytes.Equal(fingerprint(f, c.Offset-int64(len(c.Anchor)), len(c.Anchor)), c.Anchor)
}

func (r *acknowledgedReader) position() Cursor {
	n := headSize
	if r.offset < int64(n) {
		n = int(r.offset)
	}
	return Cursor{Version: 2, Path: r.path, FileID: r.id, Generation: r.generation, Offset: r.offset,
		Head: append([]byte{}, r.head...), Anchor: fingerprint(r.f, r.offset-int64(n), n)}
}

func (r *acknowledgedReader) open() error {
	path, err := filepath.Abs(r.t.opt.Path)
	if err != nil {
		return err
	}
	var f *os.File
	start := int64(0)
	generation := ""
	if r.first && r.resume != nil && r.resume.Version == 2 && r.resume.Path == path {
		// First try the configured path, then uncompressed audit.log.* siblings.
		candidates := []string{path}
		entries, err := os.ReadDir(filepath.Dir(path))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		for _, e := range entries {
			if !e.IsDir() && strings.HasPrefix(e.Name(), filepath.Base(path)+".") {
				candidates = append(candidates, filepath.Join(filepath.Dir(path), e.Name()))
			}
		}
		for _, candidate := range candidates {
			opened, err := os.Open(candidate)
			if err != nil {
				continue
			}
			if cursorMatches(opened, *r.resume) {
				f, start, generation = opened, r.resume.Offset, r.resume.Generation
				break
			}
			_ = opened.Close()
		}
		if f == nil {
			r.gap = "saved file generation is unavailable or was truncated; replaying the current file from byte zero"
		}
	}
	if f == nil {
		f, err = os.Open(path)
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
			r.missing = true
			r.t.setStatus("audit log unavailable: " + err.Error())
			return nil
		}
		if err != nil {
			return err
		}
		fi, err := f.Stat()
		if err != nil {
			_ = f.Close()
			return err
		}
		if r.first && r.resume == nil && !r.missing && !r.t.opt.FromStart {
			start = fi.Size()
		}
		if r.first && r.resume != nil && r.resume.Version == 0 {
			r.gap = "legacy cursor has no file identity; replaying the current file from byte zero"
		}
		if r.first && r.resume != nil && r.resume.Version == 2 && r.resume.Path != path {
			r.gap = "audit log path changed; replaying the new source from byte zero"
		}
	}
	id, err := fileIdentity(f)
	if err != nil {
		_ = f.Close()
		return err
	}
	if generation == "" {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			_ = f.Close()
			return err
		}
		generation = hex.EncodeToString(random[:])
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		_ = f.Close()
		return err
	}
	r.f, r.id, r.generation, r.path, r.offset = f, id, generation, path, start
	r.lineStart = start
	r.head, r.partial, r.discard = fingerprint(f, 0, headSize), nil, false
	r.skip = start > 0 && r.resume == nil && !r.t.opt.FromStart && !bytes.Equal(fingerprint(f, start-1, 1), []byte{'\n'})
	if r.skip {
		r.discard = true
	}
	c := r.position()
	if r.first && r.resume == nil {
		// Persist the initial baseline, including offset zero, before read-ahead.
		if err := r.t.SaveCursor(c); err != nil {
			return fmt.Errorf("persist initial cursor: %w", err)
		}
	}
	r.first = false
	if r.gap != "" {
		r.t.setStatus(r.gap)
		r.t.log.Error("source continuity lost", "reason", r.gap)
	} else if strings.HasPrefix(r.t.Status(), "audit log unavailable:") {
		r.t.setStatus("ok")
	}
	if err := r.emit(Line{Start: c, End: c, Boundary: true, Gap: r.gap}); err != nil {
		return err
	}
	r.gap = ""
	return r.drain()
}

func (r *acknowledgedReader) step() error {
	if r.f == nil {
		return r.open()
	}
	cur, err := os.Open(r.t.opt.Path)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
		return r.drain()
	}
	if err != nil {
		return err
	}
	id, err := fileIdentity(cur)
	_ = cur.Close()
	if err != nil {
		return err
	}
	if id != r.id {
		if err := r.drain(); err != nil {
			return err
		}
		if len(r.partial) != 0 || r.discard {
			r.gap = "rotation discarded an unterminated log line"
		}
		_ = r.f.Close()
		r.f = nil
		return r.open()
	}
	fi, err := r.f.Stat()
	if err != nil {
		return err
	}
	changed := fi.Size() < r.offset || !bytes.Equal(fingerprint(r.f, 0, len(r.head)), r.head)
	if !changed && len(r.anchor) > 0 {
		changed = !bytes.Equal(fingerprint(r.f, r.offset-int64(len(r.anchor)), len(r.anchor)), r.anchor)
	}
	if changed {
		_ = r.f.Close()
		r.f = nil
		r.gap = "copytruncate or in-place replacement detected; starting a new source generation"
		return r.open()
	}
	return r.drain()
}

func (r *acknowledgedReader) drain() error {
	buf := make([]byte, 64*1024)
	for {
		n, err := r.f.Read(buf)
		if n > 0 {
			if err := r.consume(buf[:n]); err != nil {
				return err
			}
		}
		if err == io.EOF || n == 0 {
			if len(r.head) < headSize {
				r.head = fingerprint(r.f, 0, headSize)
			}
			r.anchor = r.position().Anchor
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func (r *acknowledgedReader) consume(b []byte) error {
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		part := b
		if i >= 0 {
			part = b[:i+1]
		}
		if !r.discard {
			if len(r.partial)+len(part) > maxLine {
				r.discard = true
				r.partial = nil
			} else {
				r.partial = append(r.partial, part...)
			}
		}
		if i < 0 {
			r.offset += int64(len(part))
			break
		}
		// offset tracks bytes consumed; lineStart includes chunks from earlier reads.
		end := r.offset + int64(len(part))
		r.offset = r.lineStart
		from := r.position()
		r.offset = end
		to := r.position()
		text := ""
		if !r.discard {
			text = string(r.partial[:len(r.partial)-1])
		}
		if err := r.emit(Line{Text: text, Start: from, End: to, Oversized: r.discard && !r.skip, Skipped: r.skip}); err != nil {
			return err
		}
		r.partial, r.discard = nil, false
		r.skip = false
		r.lineStart = end
		b = b[len(part):]
	}
	return nil
}
