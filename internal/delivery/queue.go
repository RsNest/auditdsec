package delivery

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

var (
	ErrFull = errors.New("delivery: critical outbox is full")
	ErrGap  = errors.New("delivery: journal intake is not contiguous")
)

const maxPayload = 32 << 10
const maxWALRecord = 24 << 20

type Options struct {
	Dir           string
	Now           func() time.Time
	MaxJobs       int
	MaxBytes      int
	CriticalJobs  int
	CriticalBytes int
	CompactAfter  int64
}

type group struct {
	Last  Intent    `json:"last"`
	Due   time.Time `json:"due"`
	Extra int       `json:"extra"`
}

type state struct {
	Jobs     map[string]Job   `json:"jobs"`
	Groups   map[string]group `json:"groups"`
	Cursors  map[string]int64 `json:"cursors"`
	Stats    Stats            `json:"stats"`
	Failures []Failure        `json:"failures,omitempty"`
	Sequence uint64           `json:"sequence"`
}

// Each transaction contains both admitted jobs and the journal intake cursor.
// A completed job needs no permanent receipt index: replay starts after that
// transaction's cursor, never recreating a previously completed notification.
type transaction struct {
	Version     int               `json:"version"`
	Snapshot    *state            `json:"snapshot,omitempty"`
	Upsert      []Job             `json:"upsert,omitempty"`
	Remove      []string          `json:"remove,omitempty"`
	Groups      map[string]*group `json:"groups,omitempty"`
	Cursor      *Position         `json:"cursor,omitempty"`
	Stats       Stats             `json:"stats"`
	Failure     *Failure          `json:"failure,omitempty"`
	Sequence    uint64            `json:"sequence,omitempty"`
	DropCursors []string          `json:"drop_cursors,omitempty"`
}

type Queue struct {
	mu       sync.Mutex
	opt      Options
	s        state
	f        *os.File
	path     string
	err      error
	size     int64
	inflight map[string]bool
	wake     chan struct{}
}

func Open(o Options) (*Queue, error) {
	if o.Dir == "" {
		return nil, errors.New("delivery: state directory is required")
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.MaxJobs <= 0 {
		o.MaxJobs = 2048
	}
	if o.MaxBytes <= 0 {
		o.MaxBytes = 16 << 20
	}
	if o.CriticalJobs <= 0 {
		o.CriticalJobs = max(1, o.MaxJobs/4)
	}
	if o.CriticalBytes <= 0 {
		o.CriticalBytes = max(1, o.MaxBytes/4)
	}
	if o.CriticalJobs >= o.MaxJobs || o.CriticalBytes >= o.MaxBytes {
		return nil, errors.New("delivery: critical reserve must leave capacity for routine jobs")
	}
	if o.CompactAfter <= 0 {
		o.CompactAfter = 8 << 20
	}
	if err := os.MkdirAll(o.Dir, 0o700); err != nil {
		return nil, err
	}
	q := &Queue{opt: o, path: filepath.Join(o.Dir, "outbox.wal"),
		s:        state{Jobs: map[string]Job{}, Groups: map[string]group{}, Cursors: map[string]int64{}},
		inflight: map[string]bool{}, wake: make(chan struct{}, 1)}
	marker := filepath.Join(filepath.Dir(o.Dir), ".outbox.initialized")
	if _, err := os.Stat(q.path); errors.Is(err, os.ErrNotExist) {
		if _, err := os.Stat(marker); err == nil {
			return nil, errors.New("delivery: initialized outbox is missing; restore its state")
		}
	}
	f, err := os.OpenFile(q.path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	q.f = f
	if err := q.load(); err != nil {
		f.Close()
		return nil, err
	}
	if err := q.validateState(); err != nil {
		f.Close()
		return nil, err
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		f.Close()
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	q.size = fi.Size()
	if err := f.Sync(); err != nil {
		f.Close()
		return nil, err
	}
	if err := syncDir(o.Dir); err != nil {
		f.Close()
		return nil, err
	}
	if err := writeMarker(marker); err != nil {
		f.Close()
		return nil, err
	}
	return q, nil
}

func syncDir(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func writeMarker(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, os.ErrExist) {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = f.WriteString("1\n")
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
	return syncDir(filepath.Dir(path))
}

func (q *Queue) load() error {
	r := bufio.NewReaderSize(q.f, 64<<10)
	var line []byte
	var offset int64
	for {
		part, err := r.ReadSlice('\n')
		if len(line)+len(part) > maxWALRecord {
			return errors.New("delivery: oversized WAL record")
		}
		line = append(line, part...)
		if err == bufio.ErrBufferFull {
			continue
		}
		if err == io.EOF {
			if len(line) > 0 {
				if err := q.f.Truncate(offset); err != nil {
					return err
				}
				return q.f.Sync()
			}
			return nil
		}
		if err != nil {
			return err
		}
		var tx transaction
		if json.Unmarshal(line, &tx) != nil || tx.Version != 1 {
			return fmt.Errorf("delivery: corrupt WAL at byte %d", offset)
		}
		q.apply(tx)
		if err := q.validateState(); err != nil {
			return err
		}
		offset += int64(len(line))
		line = nil
	}
}

func validIntent(in Intent) error {
	if in.ID == "" || len(in.ID) > 128 || in.Channel == "" || len(in.Channel) > 32 || in.Route == "" || len(in.Route) > 128 || in.Destination == "" || len(in.Destination) > 32 || len(in.Category) > 64 || len(in.DedupKey) > 128 || len(in.GroupSummary) > 1024 || in.DedupWindow < 0 || in.DedupWindow > 24*time.Hour || in.GroupedCount < 0 ||
		(in.Priority != Routine && in.Priority != Critical) || in.Created.IsZero() ||
		len(in.Payload) > maxPayload || !json.Valid(in.Payload) {
		return errors.New("delivery: invalid notification intent")
	}
	return nil
}

func (q *Queue) validateState() error {
	if q.s.Jobs == nil || q.s.Groups == nil || q.s.Cursors == nil || len(q.s.Cursors) > 4096 {
		return errors.New("delivery: invalid outbox state")
	}
	if len(q.s.Jobs) > q.opt.MaxJobs || q.payloadBytes() > q.opt.MaxBytes || len(q.s.Groups) > 512 {
		return errors.New("delivery: stored outbox exceeds its configured capacity")
	}
	for id, job := range q.s.Jobs {
		if id != job.ID || validIntent(job.Intent) != nil || job.Attempts < 0 || len(job.LastError) > 128 {
			return errors.New("delivery: invalid stored job")
		}
	}
	for _, g := range q.s.Groups {
		if validIntent(g.Last) != nil || g.Extra < 0 || g.Due.IsZero() {
			return errors.New("delivery: invalid stored group")
		}
	}
	for day, offset := range q.s.Cursors {
		if _, err := time.Parse("2006-01-02", day); err != nil || offset < 0 {
			return errors.New("delivery: invalid intake cursor")
		}
	}
	return nil
}

func (q *Queue) apply(tx transaction) {
	if tx.Snapshot != nil {
		q.s = *tx.Snapshot
		return
	}
	for _, id := range tx.Remove {
		delete(q.s.Jobs, id)
		delete(q.inflight, id)
	}
	for _, job := range tx.Upsert {
		q.s.Jobs[job.ID] = job
	}
	for key, g := range tx.Groups {
		if g == nil {
			delete(q.s.Groups, key)
		} else {
			q.s.Groups[key] = *g
		}
	}
	if tx.Cursor != nil {
		q.s.Cursors[tx.Cursor.Day] = tx.Cursor.End
	}
	for _, day := range tx.DropCursors {
		delete(q.s.Cursors, day)
	}
	a, b := &q.s.Stats, tx.Stats
	a.Queued += b.Queued
	a.Delivered += b.Delivered
	a.Suppressed += b.Suppressed
	a.Grouped += b.Grouped
	a.Deferred += b.Deferred
	a.Retries += b.Retries
	a.Failed += b.Failed
	a.Cancelled += b.Cancelled
	a.Overflow += b.Overflow
	if tx.Sequence > q.s.Sequence {
		q.s.Sequence = tx.Sequence
	}
	if tx.Failure != nil {
		q.s.Failures = append(q.s.Failures, *tx.Failure)
		if len(q.s.Failures) > 100 {
			q.s.Failures = q.s.Failures[len(q.s.Failures)-100:]
		}
	}
}

func (q *Queue) commit(tx transaction) error {
	if q.err != nil {
		return q.err
	}
	tx.Version = 1
	raw, err := json.Marshal(tx)
	if err != nil || len(raw)+1 > maxWALRecord {
		return errors.New("delivery: cannot encode WAL transaction")
	}
	// Own all payload bytes rather than retaining mutable caller buffers.
	if err := json.Unmarshal(raw, &tx); err != nil {
		return err
	}
	if _, err := q.f.Write(append(raw, '\n')); err != nil {
		q.err = err
		return err
	}
	if err := q.f.Sync(); err != nil {
		q.err = err
		return err
	}
	q.size += int64(len(raw) + 1)
	q.apply(tx)
	select {
	case q.wake <- struct{}{}:
	default:
	}
	if q.size >= q.opt.CompactAfter {
		if err := q.compact(); err != nil {
			q.err = err
			return err
		}
	}
	return nil
}

func (q *Queue) compact() error {
	raw, err := json.Marshal(transaction{Version: 1, Snapshot: &q.s})
	if err != nil || len(raw)+1 > maxWALRecord {
		return errors.New("delivery: snapshot exceeds WAL limit")
	}
	tmp := q.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(append(raw, '\n'))
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
	if err := q.f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, q.path); err != nil {
		return err
	}
	if err := syncDir(q.opt.Dir); err != nil {
		return err
	}
	q.f, err = os.OpenFile(q.path, os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	_, err = q.f.Seek(0, io.SeekEnd)
	q.size = int64(len(raw) + 1)
	return err
}

func (q *Queue) payloadBytes() int {
	n := 0
	for _, j := range q.s.Jobs {
		n += len(j.Payload)
	}
	for _, g := range q.s.Groups {
		n += len(g.Last.Payload)
	}
	return n
}

// Import atomically admits a journal record and advances its intake cursor.
// Routine overflow is explicitly counted; critical overflow applies backpressure.
func (q *Queue) Import(pos Position, plan Plan) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.err != nil {
		return q.err
	}
	if _, err := time.Parse("2006-01-02", pos.Day); err != nil || pos.Start < 0 || pos.End <= pos.Start {
		return errors.New("delivery: invalid journal position")
	}
	if pos.End <= q.s.Cursors[pos.Day] {
		return nil
	}
	if pos.Start != q.s.Cursors[pos.Day] {
		return ErrGap
	}
	if len(q.s.Cursors) >= 4096 && q.s.Cursors[pos.Day] == 0 {
		return errors.New("delivery: too many journal generations")
	}
	tx := transaction{Cursor: &pos, Sequence: q.s.Sequence}
	if plan.Suppressed != "" {
		tx.Stats.Suppressed++
	}
	count, used := len(q.s.Jobs), q.payloadBytes()
	seen := map[string]bool{}
	for _, intent := range plan.Intents {
		if err := validIntent(intent); err != nil {
			return err
		}
		if seen[intent.ID] {
			return errors.New("delivery: duplicate intent in journal record")
		}
		seen[intent.ID] = true
		if _, ok := q.s.Jobs[intent.ID]; ok {
			return errors.New("delivery: intent ID reused across journal records")
		}
		maxJobs, maxBytes := q.opt.MaxJobs, q.opt.MaxBytes
		if intent.Priority == Routine {
			maxJobs -= q.opt.CriticalJobs
			maxBytes -= q.opt.CriticalBytes
		}
		if count >= maxJobs || used+len(intent.Payload) > maxBytes {
			if intent.Priority == Critical {
				return ErrFull
			}
			tx.Stats.Overflow++
			continue
		}
		tx.Sequence++
		tx.Upsert = append(tx.Upsert, Job{Intent: intent, Sequence: tx.Sequence, NextAttempt: intent.Created})
		count++
		used += len(intent.Payload)
		tx.Stats.Queued++
	}
	return q.commit(tx)
}

func (q *Queue) Cursors() map[string]int64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make(map[string]int64, len(q.s.Cursors))
	for k, v := range q.s.Cursors {
		out[k] = v
	}
	return out
}

func (q *Queue) Stats() Stats {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := q.s.Stats
	out.Pending, out.InFlight, out.PayloadBytes = len(q.s.Jobs), len(q.inflight), q.payloadBytes()
	for _, j := range q.s.Jobs {
		if j.Priority == Critical {
			out.Critical++
		}
	}
	return out
}

func (q *Queue) Failures() []Failure {
	q.mu.Lock()
	defer q.mu.Unlock()
	return append([]Failure{}, q.s.Failures...)
}

func (q *Queue) Close() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.err = errors.New("delivery: outbox is closed")
	return q.f.Close()
}

// Wait is a bounded wakeup for critical intake backpressure, not a busy loop.
func (q *Queue) Wait(ctxDone <-chan struct{}) bool {
	select {
	case <-ctxDone:
		return false
	case <-q.wake:
		return true
	case <-time.After(100 * time.Millisecond):
		return true
	}
}

// PruneCursors removes receipts only for journal files that no longer exist.
// Retained files must keep their cursor, or successful sends could be recreated.
func (q *Queue) PruneCursors(existing map[string]bool) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	tx := transaction{}
	for day := range q.s.Cursors {
		if !existing[day] {
			tx.DropCursors = append(tx.DropCursors, day)
		}
	}
	if len(tx.DropCursors) == 0 {
		return nil
	}
	return q.commit(tx)
}
