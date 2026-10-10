package store

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/RsNest/auditdsec/internal/delivery"
	"github.com/RsNest/auditdsec/internal/model"
	"github.com/RsNest/auditdsec/internal/netaddr"
)

// Detection consumes the event journal. Ingestion (appending an event) and
// consumption (running the detector on it and recording its decisions) are
// separate durable steps: the journal is the queue between them, and the
// detection cursor — a byte offset per journal day — says how far consumption
// has durably got. The cursor lives in the same state file as the decisions,
// so one atomic write both records a decision and moves the cursor past the
// event that caused it. An event stays eligible for detection until that
// write succeeds, however far the audit-log cursor has moved.

// detectionMarker proves that detection was initialized once. If the marker is
// there but the progress is not, the state was lost and starting from the end
// of the journal would silently skip events; that is refused instead.
const detectionMarker = "detection.initialized"

// ErrDetectionLost: the marker exists but the progress record does not.
var ErrDetectionLost = errors.New("store: detection progress is missing although detection was initialized; restore state.json, or delete detection.initialized to accept starting from the end of the journal")

// ErrDetectionCursor: a cursor points beyond its journal file.
var ErrDetectionCursor = errors.New("store: detection cursor is beyond its journal")

// DetectState is the durable progress of detection.
type DetectState struct {
	Initialized bool             `json:"initialized"`
	Since       time.Time        `json:"since"`
	Cursors     map[string]int64 `json:"cursors,omitempty"`
}

// DetectBan is one desired decision produced by a consumed event.
type DetectBan struct {
	IP     string
	Reason string
	Until  time.Time
}

// DetectResult is the outcome of one DetectBan.
type DetectResult struct {
	Ban     Ban
	Created bool
	Err     error // ErrAllowlisted when the address is protected
}

func journalDays(dir string) (map[string]int64, error) {
	entries, err := os.ReadDir(filepath.Join(dir, eventsDirName))
	if err != nil {
		return nil, err
	}
	out := map[string]int64{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		day := strings.TrimSuffix(e.Name(), ".jsonl")
		if _, err := time.Parse(dayLayout, day); err != nil {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			return nil, err
		}
		out[day] = fi.Size()
	}
	return out, nil
}

// InitDetection starts detection tracking. The first time on an installation
// the cursor of every existing journal day is set to its end: events written
// before this version are history and never produce new bans. It returns the
// number of journal days that were skipped that way. Later calls validate the
// stored progress and change nothing; progress that is missing after having
// been initialized, or that points beyond its file, is an error, not a reset.
func (s *Store) InitDetection() (skipped int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	marker := filepath.Join(s.dir, detectionMarker)
	_, markerErr := os.Stat(marker)
	haveMarker := markerErr == nil

	days, err := journalDays(s.dir)
	if err != nil {
		return 0, err
	}
	if d := s.state.Detect; d != nil && d.Initialized {
		if !haveMarker {
			_ = writeFileAtomic(marker, []byte("1\n"), 0o640) // state older than the marker
		}
		if d.Cursors == nil {
			d.Cursors = map[string]int64{}
		}
		for day, off := range d.Cursors {
			size, ok := days[day]
			switch {
			case !ok:
				delete(d.Cursors, day) // the file is gone: nothing left to detect
			case off < 0 || off > size:
				return 0, fmt.Errorf("%w: %s at %d of %d", ErrDetectionCursor, day, off, size)
			}
		}
		s.detecting = true
		s.refreshPendingLocked(days)
		return 0, nil
	}
	if haveMarker {
		return 0, ErrDetectionLost
	}
	d := &DetectState{Initialized: true, Since: s.now(), Cursors: map[string]int64{}}
	for day, size := range days {
		if size > 0 {
			d.Cursors[day] = size
			skipped++
		}
	}
	prev := s.state.Detect
	s.state.Detect = d
	if err := s.saveStateLocked(); err != nil {
		s.state.Detect = prev
		return 0, err
	}
	if err := writeFileAtomic(marker, []byte("1\n"), 0o640); err != nil {
		return 0, fmt.Errorf("store: write detection marker: %w", err)
	}
	s.detecting = true
	s.refreshPendingLocked(days)
	return skipped, nil
}

// DetectionInitialized reports whether detection progress is being tracked.
func (s *Store) DetectionInitialized() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state.Detect != nil && s.state.Detect.Initialized
}

// DetectionCursors returns a copy of the progress.
func (s *Store) DetectionCursors() map[string]int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]int64{}
	if s.state.Detect != nil {
		for k, v := range s.state.Detect.Cursors {
			out[k] = v
		}
	}
	return out
}

func (s *Store) refreshPendingLocked(days map[string]int64) {
	s.pending = map[string]bool{}
	d := s.state.Detect
	for day, size := range days {
		if size > d.Cursors[day] {
			s.pending[day] = true
		}
	}
}

// noteAppendLocked marks a day as having input the detector has not seen.
func (s *Store) noteAppendLocked(day string) {
	if s.state.Detect != nil && s.state.Detect.Initialized {
		if s.pending == nil {
			s.pending = map[string]bool{}
		}
		s.pending[day] = true
	}
}

// ConsumeDetection hands every unconsumed journal record that carries an event
// to handle, in journal order. handle must commit its outcome with
// CommitDetection, which moves the cursor past the record; records without an
// event are skipped here. An error from handle stops consumption with the
// cursor where it was, so the same record is offered again later.
func (s *Store) ConsumeDetection(handle func(pos delivery.Position, ev model.Event) error) error {
	for {
		s.mu.Lock()
		if s.state.Detect == nil || !s.state.Detect.Initialized {
			s.mu.Unlock()
			return errors.New("store: detection is not initialized")
		}
		days := make([]string, 0, len(s.pending))
		for d := range s.pending {
			days = append(days, d)
		}
		s.mu.Unlock()
		if len(days) == 0 {
			return nil
		}
		sort.Strings(days)
		progressed := false
		for _, day := range days {
			n, err := s.consumeDay(day, handle)
			if err != nil {
				return err
			}
			progressed = progressed || n > 0
		}
		if !progressed {
			return nil
		}
		// Records may have been appended meanwhile; look again.
	}
}

func (s *Store) consumeDay(day string, handle func(delivery.Position, model.Event) error) (int, error) {
	s.mu.Lock()
	offset := s.state.Detect.Cursors[day]
	f, err := os.Open(filepath.Join(s.dir, eventsDirName, day+".jsonl"))
	if errors.Is(err, os.ErrNotExist) {
		delete(s.pending, day)
		s.mu.Unlock()
		return 0, nil
	}
	if err != nil {
		s.mu.Unlock()
		return 0, err
	}
	defer f.Close()
	// The file boundary after any append has finished its fsync: a record
	// beyond it may still be half written.
	fi, err := f.Stat()
	s.mu.Unlock()
	if err != nil {
		return 0, err
	}
	size := fi.Size()
	if offset > size {
		return 0, fmt.Errorf("%w: %s at %d of %d", ErrDetectionCursor, day, offset, size)
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return 0, err
	}
	r := bufio.NewReaderSize(io.LimitReader(f, size-offset), 64<<10)
	var (
		line     []byte
		recLen   int64
		oversize bool
		consumed int
	)
	for {
		part, rerr := r.ReadSlice('\n')
		recLen += int64(len(part))
		if !oversize {
			if len(line)+len(part) > maxJournalLine {
				oversize, line = true, nil
			} else {
				line = append(line, part...)
			}
		}
		if rerr == bufio.ErrBufferFull {
			continue
		}
		if rerr != nil {
			if rerr == io.EOF { // a partial tail is not committed
				break
			}
			return consumed, rerr
		}
		pos := delivery.Position{Day: day, Start: offset, End: offset + recLen}
		var rec journalRecord
		if !oversize && json.Unmarshal(line, &rec) == nil && rec.Event.Kind != "" {
			if err := handle(pos, rec.Event); err != nil {
				return consumed, err
			}
			s.mu.Lock()
			cur := s.state.Detect.Cursors[day]
			s.mu.Unlock()
			if cur != pos.End {
				return consumed, fmt.Errorf("store: detection handler did not commit %s@%d", day, pos.Start)
			}
		} else if _, err := s.CommitDetection(pos, nil); err != nil {
			// A record that is not an event (a notice, an unreadable line).
			return consumed, err
		}
		consumed++
		offset = pos.End
		line, recLen, oversize = nil, 0, false
	}
	s.mu.Lock()
	if st, err := os.Stat(filepath.Join(s.dir, eventsDirName, day+".jsonl")); err == nil && s.state.Detect.Cursors[day] >= st.Size() {
		delete(s.pending, day)
	}
	s.mu.Unlock()
	return consumed, nil
}

// CommitDetection records the desired decisions of one consumed event and moves
// the cursor past it in a single atomic state write. It is all or nothing:
// when the write fails nothing is recorded and the cursor stays, so the event
// is offered again. Decisions are the desired state only; enforcing them is
// the caller's job and may fail without affecting the commit. A decision for
// an address that already has an active ban changes nothing, and one for an
// allowlisted address is refused, in both cases with the cursor still moving.
func (s *Store) CommitDetection(pos delivery.Position, bans []DetectBan) ([]DetectResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.state.Detect
	if d == nil || !d.Initialized {
		return nil, errors.New("store: detection is not initialized")
	}
	cur := d.Cursors[pos.Day]
	if pos.End <= cur {
		return nil, nil // already committed
	}
	if pos.Start != cur {
		return nil, fmt.Errorf("store: detection commit is not contiguous: %s %d != %d", pos.Day, pos.Start, cur)
	}
	snapshot := s.snapshotLocked()
	results := make([]DetectResult, 0, len(bans))
	for _, b := range bans {
		a, err := netaddr.Parse(b.IP)
		if err != nil {
			results = append(results, DetectResult{Err: fmt.Errorf("%w: %v", ErrInvalidAddress, err)})
			continue
		}
		key := a.String()
		if s.allowedLocked(a) {
			results = append(results, DetectResult{Err: ErrAllowlisted})
			continue
		}
		if existing, ok := s.state.Bans[key]; ok && existing.Active(s.now()) {
			results = append(results, DetectResult{Ban: existing})
			continue
		}
		results = append(results, DetectResult{Ban: s.applyBanLocked(key, b.Reason, b.Until, "detector", true), Created: true})
	}
	d.Cursors[pos.Day] = pos.End
	if err := s.saveStateLocked(); err != nil {
		s.restoreLocked(snapshot)
		d.Cursors[pos.Day] = cur
		return nil, err
	}
	return results, nil
}

// RestoreConsumed streams the already-consumed events of recent days, oldest
// first, to rebuild bounded correlation memory after a restart. It reads only
// records before the cursor, so an event is never counted twice: once here
// and once when it is consumed.
func (s *Store) RestoreConsumed(since time.Time, fn func(model.Event)) error {
	s.mu.Lock()
	if s.state.Detect == nil {
		s.mu.Unlock()
		return nil
	}
	cursors := make(map[string]int64, len(s.state.Detect.Cursors))
	for k, v := range s.state.Detect.Cursors {
		cursors[k] = v
	}
	s.mu.Unlock()
	first := since.UTC().AddDate(0, 0, -1).Format(dayLayout)
	days := make([]string, 0, len(cursors))
	for d := range cursors {
		if d >= first {
			days = append(days, d)
		}
	}
	sort.Strings(days)
	for _, day := range days {
		if err := s.restoreDay(day, cursors[day], since, fn); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) restoreDay(day string, limit int64, since time.Time, fn func(model.Event)) error {
	f, err := os.Open(filepath.Join(s.dir, eventsDirName, day+".jsonl"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	r := bufio.NewReaderSize(io.LimitReader(f, limit), 64<<10)
	var line []byte
	skip := false
	for {
		part, rerr := r.ReadSlice('\n')
		if !skip {
			if len(line)+len(part) > maxJournalLine {
				skip, line = true, nil
			} else {
				line = append(line, part...)
			}
		}
		if rerr == bufio.ErrBufferFull {
			continue
		}
		if rerr != nil { // EOF: nothing committed beyond the cursor
			return nil
		}
		var rec journalRecord
		if !skip && json.Unmarshal(line, &rec) == nil && rec.Event.Kind != "" && !rec.Event.Time.Before(since) {
			fn(rec.Event)
		}
		line, skip = nil, false
	}
}

// HasNoticeIntent reports whether a journaled notification plan on one of the
// last two days already carries the intent ID. It lets a replayed duty tell
// "never journaled" from "journaled, import interrupted".
func (s *Store) HasNoticeIntent(id string) (bool, error) {
	now := s.now().UTC()
	for _, day := range []string{now.Format(dayLayout), now.AddDate(0, 0, -1).Format(dayLayout)} {
		found, err := s.dayHasIntent(day, id)
		if err != nil || found {
			return found, err
		}
	}
	return false, nil
}

func (s *Store) dayHasIntent(day, id string) (bool, error) {
	f, err := os.Open(filepath.Join(s.dir, eventsDirName, day+".jsonl"))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), maxJournalLine)
	for sc.Scan() {
		var rec journalRecord
		if json.Unmarshal(sc.Bytes(), &rec) != nil || rec.Plan == nil {
			continue
		}
		for _, in := range rec.Plan.Intents {
			if in.ID == id {
				return true, nil
			}
		}
	}
	return false, sc.Err()
}
